#!/usr/bin/env python3
"""Disposable HTTPS/Basic-Auth/claim/RFB smoke for the slot1 reissue plane."""

import asyncio
import base64
import json
import os
import ssl

import httpx
import websockets


PUBLIC_HOST = "flow-updater.opencodex.uk"
ORIGIN = f"https://{PUBLIC_HOST}"
DIRECT_BASE = "https://127.0.0.1"
PATH = "/login-slot1-reissue"
CAPABILITY = os.environ["LOGIN_REISSUE_CAPABILITY"]
BASIC_USER = os.environ["LOGIN_REISSUE_BASIC_USER"]
BASIC_PASSWORD = os.environ["LOGIN_REISSUE_BASIC_PASSWORD"]
BASIC = "Basic " + base64.b64encode(
    f"{BASIC_USER}:{BASIC_PASSWORD}".encode()
).decode()


async def main() -> None:
    common = {"Host": PUBLIC_HOST}
    auth = {**common, "Authorization": BASIC}
    async with httpx.AsyncClient(
        base_url=DIRECT_BASE, verify=False, trust_env=False, timeout=20,
    ) as client:
        anonymous = await client.get(PATH + "/", headers=common)
        wrong_auth = await client.get(
            PATH + "/", headers={**common, "Authorization": "Basic eDp5"}
        )
        page = await client.get(PATH + "/", headers=auth)
        wrong_origin = await client.post(
            PATH + "/claim",
            headers={**auth, "Origin": "https://wrong.example"},
            json={"capability": CAPABILITY},
        )
        invalid = await client.post(
            PATH + "/claim",
            headers={**auth, "Origin": ORIGIN},
            json={"capability": "invalid"},
        )
        claimed = await client.post(
            PATH + "/claim",
            headers={**auth, "Origin": ORIGIN},
            json={"capability": CAPABILITY},
        )
        cookie = claimed.cookies.get("flow_login_slot1_reissue")
        session = await client.get(PATH + "/session", headers=auth)
        asset = await client.get(PATH + "/vnc/vnc.html", headers=auth)

    async with httpx.AsyncClient(
        base_url=DIRECT_BASE, verify=False, trust_env=False, timeout=20,
    ) as replay_client:
        replay = await replay_client.post(
            PATH + "/claim",
            headers={**auth, "Origin": ORIGIN},
            json={"capability": CAPABILITY},
        )

    expected = {
        "anonymous": (anonymous.status_code, 401),
        "wrong_auth": (wrong_auth.status_code, 401),
        "page": (page.status_code, 200),
        "wrong_origin": (wrong_origin.status_code, 403),
        "invalid": (invalid.status_code, 404),
        "claimed": (claimed.status_code, 200),
        "session": (session.status_code, 200),
        "asset": (asset.status_code, 200),
        "replay": (replay.status_code, 409),
    }
    for name, (actual, wanted) in expected.items():
        if actual != wanted:
            raise AssertionError(f"{name}: HTTP {actual}, expected {wanted}")
    if not cookie:
        raise AssertionError("owner session cookie missing")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    async with websockets.connect(
        f"wss://{PUBLIC_HOST}{PATH}/vnc/websockify",
        host="127.0.0.1",
        port=443,
        ssl=context,
        origin=ORIGIN,
        additional_headers={
            "Authorization": BASIC,
            "Cookie": f"flow_login_slot1_reissue={cookie}",
        },
        subprotocols=["binary"],
        open_timeout=20,
    ) as websocket:
        banner = await asyncio.wait_for(websocket.recv(), 10)
    if banner != b"RFB 003.008\n":
        raise AssertionError("unexpected RFB banner")

    print(json.dumps({
        "anonymous": 401,
        "wrong_auth": 401,
        "page": 200,
        "wrong_origin": 403,
        "invalid_capability": 404,
        "claim": 200,
        "replay": 409,
        "session": 200,
        "asset": 200,
        "rfb": "003.008",
    }, separators=(",", ":")))


asyncio.run(main())
