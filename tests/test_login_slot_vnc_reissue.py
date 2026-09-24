import asyncio
import importlib
import json
import sys

from fastapi.testclient import TestClient


def _module(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGIN_REISSUE_RUNTIME_DIR", str(tmp_path))
    sys.modules.pop("token_updater.login_slot_vnc_reissue", None)
    return importlib.import_module("token_updater.login_slot_vnc_reissue")


def test_handoff_is_mode_0600_and_contains_fragment_path(monkeypatch, tmp_path):
    module = _module(monkeypatch, tmp_path)
    module._write_handoff_once()
    handoff = tmp_path / "invite"
    assert handoff.stat().st_mode & 0o777 == 0o600
    payload = json.loads(handoff.read_text())
    assert payload["path"].startswith("/login-slot1-reissue/#")
    assert module.invitation.capability not in payload["path"].split("#", 1)[0]


def test_invitation_is_single_claim_and_cookie_is_scoped(monkeypatch, tmp_path):
    module = _module(monkeypatch, tmp_path)
    capability = module.invitation.capability
    with TestClient(module.app, base_url="https://slot.example") as client:
        first = client.post(
            "/login-slot1-reissue/claim",
            json={"capability": capability},
            headers={"origin": "https://slot.example"},
        )
        assert first.status_code == 200
        assert first.cookies.get("flow_login_slot1_reissue")
        assert "HttpOnly" in first.headers["set-cookie"]
        assert "Secure" in first.headers["set-cookie"]
        assert "SameSite=strict" in first.headers["set-cookie"]
        assert "Path=/login-slot1-reissue" in first.headers["set-cookie"]

        second = client.post(
            "/login-slot1-reissue/claim",
            json={"capability": capability},
            headers={"origin": "https://slot.example"},
        )
        assert second.status_code == 409


def test_wrong_origin_and_missing_session_are_rejected(monkeypatch, tmp_path):
    module = _module(monkeypatch, tmp_path)
    capability = module.invitation.capability
    with TestClient(module.app, base_url="https://slot.example") as client:
        wrong = client.post(
            "/login-slot1-reissue/claim",
            json={"capability": capability},
            headers={"origin": "https://wrong.example"},
        )
        assert wrong.status_code == 403
        assert client.get("/login-slot1-reissue/session").status_code == 401
        assert client.get("/login-slot1-reissue/vnc/vnc.html").status_code == 401


def test_rfb_fixture_uses_the_expected_protocol_banner(monkeypatch, tmp_path):
    module = _module(monkeypatch, tmp_path)

    async def exercise():
        received = bytearray()

        async def rfb(reader, writer):
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            received.extend(await reader.readexactly(4))
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(rfb, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(module, "RFB_PORT", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await reader.readexactly(12) == b"RFB 003.008\n"
        writer.write(b"test")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0)
        server.close()
        await server.wait_closed()
        assert received == b"test"

    asyncio.run(exercise())
