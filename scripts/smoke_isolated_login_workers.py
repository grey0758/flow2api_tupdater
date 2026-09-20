#!/usr/bin/env python3
"""Exercise two real non-root desktop workers and two simultaneous RFB links."""

import asyncio
import base64
import json
import os
import struct
from pathlib import Path

import httpx
import websockets

from token_updater.login_worker_protocol import sign_headers


PRIVATE_KEY = os.environ["LOGIN_SLOT_SIGNING_PRIVATE_KEY"]
ROOT = Path(os.environ.get("LOGIN_SMOKE_ROOT", "/tmp/flow-worker-smoke"))
SOCKETS = [
    os.environ.get(f"LOGIN_SMOKE_SOCKET_{slot}")
    or str(ROOT / f"control{slot}" / "worker.sock")
    for slot in (1, 2)
]
PROXY_URL = os.environ.get("LOGIN_SMOKE_PROXY_URL", "direct://")


async def control(slot, generation, profile, method, payload=None):
    path = f"/{method}"
    body = json.dumps(payload or {}, sort_keys=True, separators=(",", ":")).encode()
    headers = sign_headers(
        PRIVATE_KEY, slot=slot, generation=generation, profile_id=profile,
        method="POST", path=path, body=body,
    )
    headers["Content-Type"] = "application/json"
    transport = httpx.AsyncHTTPTransport(uds=SOCKETS[slot - 1])
    async with httpx.AsyncClient(transport=transport, base_url="http://worker", timeout=120) as client:
        response = await client.post(path, content=body, headers=headers)
    response.raise_for_status()
    return response.json()


class RFBStream:
    def __init__(self, websocket):
        self.websocket = websocket
        self.buffer = bytearray()

    async def read(self, size):
        while len(self.buffer) < size:
            message = await self.websocket.recv()
            assert isinstance(message, bytes), "RFB relay returned text data"
            self.buffer.extend(message)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    async def pixel(self, x, y, bytes_per_pixel):
        # Non-incremental one-pixel request.  Raw is the only advertised
        # encoding, which makes the marker comparison deterministic.
        await self.websocket.send(struct.pack("!BBHHHH", 3, 0, x, y, 1, 1))
        while True:
            message_type = (await self.read(1))[0]
            if message_type == 0:
                _, rectangles = struct.unpack("!BH", await self.read(3))
                selected = None
                for _ in range(rectangles):
                    left, top, width, height, encoding = struct.unpack(
                        "!HHHHi", await self.read(12)
                    )
                    assert encoding == 0, f"unexpected RFB encoding {encoding}"
                    payload = await self.read(width * height * bytes_per_pixel)
                    if left <= x < left + width and top <= y < top + height:
                        offset = ((y - top) * width + x - left) * bytes_per_pixel
                        selected = payload[offset:offset + bytes_per_pixel]
                if selected is not None:
                    return selected
            elif message_type == 2:  # Bell
                continue
            elif message_type == 3:  # ServerCutText
                await self.read(3)
                length = struct.unpack("!I", await self.read(4))[0]
                await self.read(length)
            else:
                raise AssertionError(f"unexpected RFB server message {message_type}")


async def rfb(slot, generation, profile, both_connected, input_sent):
    headers = sign_headers(
        PRIVATE_KEY, slot=slot, generation=generation, profile_id=profile,
        method="GET", path="/websockify",
    )
    async with websockets.unix_connect(
        SOCKETS[slot - 1], uri="ws://worker/websockify",
        additional_headers=headers, subprotocols=["binary"],
    ) as websocket:
        stream = RFBStream(websocket)
        version = await stream.read(12)
        assert version.startswith(b"RFB 003.008")
        await websocket.send(version)
        security_count = (await stream.read(1))[0]
        security = await stream.read(security_count)
        assert b"\x01" in security
        await websocket.send(b"\x01")
        result = await stream.read(4)
        assert result == b"\x00\x00\x00\x00"
        await websocket.send(b"\x01")
        server_init = await stream.read(24)
        width, height = struct.unpack("!HH", server_init[:4])
        bits_per_pixel = server_init[4]
        assert bits_per_pixel in {8, 16, 32}
        name_length = struct.unpack("!I", server_init[20:24])[0]
        name = await stream.read(name_length)
        await websocket.send(struct.pack("!BBHi", 2, 0, 1, 0))

        # Keep both sessions alive together; sequential greetings do not
        # establish that two interactive desktops can coexist.  The data URLs
        # used by the harness render distinct solid desktop markers.
        # Stay away from Chromium's top bar and fluxbox decorations.
        marker_x, marker_y = min(width - 1, 100), min(height - 1, 100)
        await asyncio.sleep(1)
        before = await stream.pixel(marker_x, marker_y, bits_per_pixel // 8)
        both_connected[slot - 1].set()
        await asyncio.wait_for(both_connected[2 - slot].wait(), timeout=10)
        if slot == 1:
            # Focus the first browser using RFB PointerEvent, then send an RFB
            # KeyEvent for lowercase 'a'.  Only slot 1's page changes
            # its background in response; slot 2 must remain bit-for-bit the
            # same at the sampled marker pixel.
            await websocket.send(struct.pack("!BBHH", 5, 1, 100, 200))
            await websocket.send(struct.pack("!BBHH", 5, 0, 100, 200))
            await asyncio.sleep(0.2)
            await websocket.send(struct.pack("!BBHI", 4, 1, 0, ord("a")))
            await websocket.send(struct.pack("!BBHI", 4, 0, 0, ord("a")))
            input_sent.set()
        else:
            await asyncio.wait_for(input_sent.wait(), timeout=10)
        await asyncio.sleep(0.5)
        after = await stream.pixel(marker_x, marker_y, bits_per_pixel // 8)
        return width, height, name, before, after


async def main():
    generations = ["smoke-generation-1", "smoke-generation-2"]
    profiles = [901, 902]
    assigned = await asyncio.gather(*[
        control(
            slot, generations[slot - 1], profiles[slot - 1],
            "assign", {"proxy_url": PROXY_URL},
        )
        for slot in (1, 2)
    ])
    assert all(item["state"] == "ready" and item["browser_running"] for item in assigned)
    both_connected = [asyncio.Event(), asyncio.Event()]
    input_sent = asyncio.Event()
    handshakes = await asyncio.gather(*[
        rfb(
            slot, generations[slot - 1], profiles[slot - 1],
            both_connected, input_sent,
        )
        for slot in (1, 2)
    ])
    assert handshakes[0][0:2] == (1365, 768)
    assert handshakes[1][0:2] == (1365, 768)
    assert handshakes[0][2] != handshakes[1][2], "RFB desktops have the same server name"
    assert handshakes[0][4] != handshakes[1][4], "desktop markers are not distinct"
    assert handshakes[0][3] != handshakes[0][4], "slot 1 did not receive its RFB input"
    assert handshakes[1][3] == handshakes[1][4], "slot 1 input affected slot 2"
    print(json.dumps({"workers": assigned, "rfb": [
        [item[0], item[1], base64.b64encode(item[2]).decode()] for item in handshakes
    ]}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
