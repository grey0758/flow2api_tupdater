#!/usr/bin/env python3
"""Exercise both login slots through HTTPS, FastAPI and the RFB relay.

This is a disposable final-topology test.  It uses two empty profiles and
keeps invitation/session capabilities only in memory while an outer harness
restarts the control container.
"""

import asyncio
import base64
import json
import os
import ssl
import struct
from pathlib import Path

import httpx
import websockets


BASE = os.environ.get("LOGIN_SMOKE_HTTPS_BASE", "https://flow-updater.opencodex.uk:38443")
ADMIN_PASSWORD = os.environ["LOGIN_SMOKE_ADMIN_PASSWORD"]
BASIC_USER = os.environ["LOGIN_SMOKE_BASIC_USER"]
BASIC_PASSWORD = os.environ["LOGIN_SMOKE_BASIC_PASSWORD"]
COORD = Path(os.environ.get("LOGIN_SMOKE_COORD", "/coord"))
ORIGIN = BASE
BASIC_HEADER = "Basic " + base64.b64encode(
    f"{BASIC_USER}:{BASIC_PASSWORD}".encode()
).decode()


class RFBStream:
    def __init__(self, websocket):
        self.websocket = websocket
        self.buffer = bytearray()

    async def read(self, size):
        while len(self.buffer) < size:
            message = await self.websocket.recv()
            assert isinstance(message, bytes)
            self.buffer.extend(message)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    async def pixel(self, x, y, bytes_per_pixel):
        await self.websocket.send(struct.pack("!BBHHHH", 3, 0, x, y, 1, 1))
        while True:
            kind = (await self.read(1))[0]
            if kind == 0:
                _, count = struct.unpack("!BH", await self.read(3))
                selected = None
                for _ in range(count):
                    left, top, width, height, encoding = struct.unpack(
                        "!HHHHi", await self.read(12)
                    )
                    assert encoding == 0
                    payload = await self.read(width * height * bytes_per_pixel)
                    if left <= x < left + width and top <= y < top + height:
                        offset = ((y - top) * width + x - left) * bytes_per_pixel
                        selected = payload[offset:offset + bytes_per_pixel]
                if selected is not None:
                    return selected
            elif kind == 2:
                continue
            elif kind == 3:
                await self.read(3)
                await self.read(struct.unpack("!I", await self.read(4))[0])
            else:
                raise AssertionError(f"unexpected RFB message {kind}")


async def rfb(slot, cookie, both_connected, input_sent):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    url = BASE.replace("https://", "wss://") + f"/login-slots/vnc/websockify?slot={slot}"
    async with websockets.connect(
        url, ssl=context, origin=ORIGIN,
        additional_headers={
            "Authorization": BASIC_HEADER,
            "Cookie": f"flow_login_slot={cookie}",
        },
        subprotocols=["binary"],
    ) as websocket:
        stream = RFBStream(websocket)
        version = await stream.read(12)
        assert version.startswith(b"RFB 003.008")
        await websocket.send(version)
        count = (await stream.read(1))[0]
        security = await stream.read(count)
        assert b"\x01" in security
        await websocket.send(b"\x01")
        assert await stream.read(4) == b"\x00\x00\x00\x00"
        await websocket.send(b"\x01")
        server_init = await stream.read(24)
        width, height = struct.unpack("!HH", server_init[:4])
        bits = server_init[4]
        name = await stream.read(struct.unpack("!I", server_init[20:24])[0])
        await websocket.send(struct.pack("!BBHi", 2, 0, 1, 0))
        x, y = min(width - 1, 100), min(height - 1, 100)
        await asyncio.sleep(1)
        before = await stream.pixel(x, y, bits // 8)
        both_connected[slot - 1].set()
        await asyncio.wait_for(both_connected[2 - slot].wait(), 10)
        if slot == 1:
            await websocket.send(struct.pack("!BBHH", 5, 1, 100, 200))
            await websocket.send(struct.pack("!BBHH", 5, 0, 100, 200))
            await websocket.send(struct.pack("!BBHI", 4, 1, 0, ord("a")))
            await websocket.send(struct.pack("!BBHI", 4, 0, 0, ord("a")))
            input_sent.set()
        else:
            await asyncio.wait_for(input_sent.wait(), 10)
        await asyncio.sleep(0.5)
        after = await stream.pixel(x, y, bits // 8)
        return width, height, name, before, after


async def main():
    basic = (BASIC_USER, BASIC_PASSWORD)
    async with httpx.AsyncClient(
        base_url=BASE, verify=False, trust_env=False, timeout=120, auth=basic,
    ) as admin:
        login = await admin.post("/api/login", json={"password": ADMIN_PASSWORD})
        login.raise_for_status()
        headers = {"X-Flow-Updater-Authorization": "Bearer " + login.json()["token"]}
        profiles = []
        for slot in (1, 2):
            response = await admin.post(
                "/api/login-slots/prepare", headers=headers,
                json={
                    "name": f"final-topology-smoke-{slot}",
                    "source_proxy_url": "http://172.19.240.1:18088",
                    "captcha_proxy_url": "http://127.0.0.1:18082",
                },
            )
            response.raise_for_status()
            profiles.append(response.json()["profile_id"])
        starts = []
        for profile in profiles:
            response = await admin.post(f"/api/login-slots/{profile}/start", headers=headers)
            response.raise_for_status()
            starts.append(response.json())

        sessions = []
        for start in starts:
            capability = start["invite_url"].split("#", 1)[1]
            client = httpx.AsyncClient(
                base_url=BASE, verify=False, trust_env=False, timeout=30, auth=basic,
            )
            wrong = await client.post(
                "/login-slots/claim", headers={"Origin": "https://wrong.invalid"},
                json={"capability": capability},
            )
            assert wrong.status_code == 403
            claimed = await client.post(
                "/login-slots/claim", headers={"Origin": ORIGIN},
                json={"capability": capability},
            )
            claimed.raise_for_status()
            cookie = client.cookies.get("flow_login_slot")
            assert cookie and claimed.json()["slot"] == start["slot"]
            replay = await httpx.AsyncClient(
                base_url=BASE, verify=False, trust_env=False, timeout=30, auth=basic,
            ).post(
                "/login-slots/claim", headers={"Origin": ORIGIN},
                json={"capability": capability},
            )
            assert replay.status_code == 409
            session = await client.get("/login-slots/session")
            session.raise_for_status()
            assert session.json()["slot"] == start["slot"]
            asset = await client.get("/login-slots/vnc/vnc.html")
            assert asset.status_code == 200
            sessions.append((client, cookie))

        anonymous = await httpx.AsyncClient(
            base_url=BASE, verify=False, trust_env=False, timeout=30, auth=basic,
        ).get("/login-slots/vnc/vnc.html")
        assert anonymous.status_code == 401

        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        ws_base = BASE.replace("https://", "wss://") + "/login-slots/vnc/websockify"
        rejected = [
            ("anonymous", ws_base + "?slot=1", {}, ORIGIN),
            ("cross-slot", ws_base + "?slot=2", {"Cookie": f"flow_login_slot={sessions[0][1]}"}, ORIGIN),
            ("wrong-origin", ws_base + "?slot=1", {"Cookie": f"flow_login_slot={sessions[0][1]}"}, "https://wrong.invalid"),
        ]
        for label, url, headers, origin in rejected:
            headers["Authorization"] = BASIC_HEADER
            try:
                async with websockets.connect(
                    url, ssl=tls, origin=origin, additional_headers=headers,
                    subprotocols=["binary"],
                ) as connection:
                    message = await asyncio.wait_for(connection.recv(), timeout=3)
            except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidStatus):
                continue
            raise AssertionError(f"{label} WebSocket received application data: {message!r}")

        both = [asyncio.Event(), asyncio.Event()]
        input_sent = asyncio.Event()
        handshakes = await asyncio.gather(*[
            rfb(slot, sessions[slot - 1][1], both, input_sent) for slot in (1, 2)
        ])
        assert all(item[:2] == (1365, 768) for item in handshakes)
        assert handshakes[0][2] != handshakes[1][2]
        assert handshakes[0][3] != handshakes[0][4]
        assert handshakes[1][3] == handshakes[1][4]

        COORD.mkdir(parents=True, exist_ok=True)
        (COORD / "rfb-ready").write_text("ready\n")
        for _ in range(120):
            if (COORD / "control-restarted").exists():
                break
            await asyncio.sleep(0.25)
        else:
            raise AssertionError("outer restart harness did not respond")

        for client, _ in sessions:
            old = await client.get("/login-slots/session")
            assert old.status_code in {401, 404}
            await client.aclose()
        new_login = await admin.post("/api/login", json={"password": ADMIN_PASSWORD})
        new_login.raise_for_status()
        new_headers = {
            "X-Flow-Updater-Authorization": "Bearer " + new_login.json()["token"]
        }
        status = await admin.get("/api/login-slots", headers=new_headers)
        status.raise_for_status()
        assert status.json()["slots"] == [
            {"slot": 1, "state": "quarantined"},
            {"slot": 2, "state": "quarantined"},
        ]

    print(json.dumps({
        "profiles": profiles,
        "slots": [item["slot"] for item in starts],
        "rfb": [[item[0], item[1]] for item in handshakes],
        "restart_reconciled": True,
    }, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
