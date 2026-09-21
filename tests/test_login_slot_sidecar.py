import importlib
import asyncio
import sys
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient


def _module(monkeypatch, private_key):
    monkeypatch.setenv("LOGIN_SLOT3_SIGNING_PRIVATE_KEY", private_key)
    monkeypatch.setenv("LOGIN_SLOT3_ADMIN_TOKEN", "admin-test-token")
    sys.modules.pop("token_updater.login_slot_sidecar", None)
    return importlib.import_module("token_updater.login_slot_sidecar")


def test_slot3_invitation_is_single_use(monkeypatch, tmp_path):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    module.sidecar.state = "ready"

    capability = module.sidecar.capability
    with TestClient(module.app, base_url="https://slot.example", raise_server_exceptions=False) as client:
        # The startup worker call is expected to fail in this isolated unit
        # test, so restore the synthetic ready state after lifespan startup.
        module.sidecar.state = "ready"
        first = client.post(
            "/login-slot3/claim", json={"capability": capability},
            headers={"origin": "https://slot.example"},
        )
        assert first.status_code == 200
        assert first.cookies.get("flow_login_slot3")
        second = client.post(
            "/login-slot3/claim", json={"capability": capability},
            headers={"origin": "https://slot.example"},
        )
        assert second.status_code == 409


def test_slot3_rejects_wrong_origin(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    module.sidecar.state = "ready"
    with TestClient(module.app, base_url="https://slot.example", raise_server_exceptions=False) as client:
        module.sidecar.state = "ready"
        response = client.post(
            "/login-slot3/claim", json={"capability": module.sidecar.capability},
            headers={"origin": "https://wrong.example"},
        )
        assert response.status_code == 403


def test_slot3_admin_route_hides_without_exact_token(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    with TestClient(module.app, base_url="https://slot.example", raise_server_exceptions=False) as client:
        assert client.get("/__slot3_admin/status").status_code == 404
        assert client.get(
            "/__slot3_admin/status", headers={"X-Slot3-Admin": "admin-test-token"}
        ).status_code == 200


def test_slot3_invite_rotation_reschedules_expiry(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    with TestClient(module.app, base_url="https://slot.example", raise_server_exceptions=False) as client:
        module.sidecar.state = "ready"
        prior_task = module.sidecar.expiry_task
        prior_expiry = module.sidecar.expires_at
        response = client.post(
            "/__slot3_admin/rotate-invite",
            headers={"X-Slot3-Admin": "admin-test-token"},
        )
        assert response.status_code == 200
        assert prior_task.cancelled() or prior_task.cancelling()
        assert module.sidecar.expiry_task is not prior_task
        assert module.sidecar.expires_at >= prior_expiry


def test_slot3_validation_waits_for_owner_input_gate(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "awaiting_check"
        call = AsyncMock(return_value={
            "success": False, "state": "ready",
            "error_code": "auth_required",
        })
        monkeypatch.setattr(module.sidecar, "worker_call", call)
        await module.sidecar.input_gate.acquire()
        task = asyncio.create_task(module.sidecar.validate())
        await asyncio.sleep(0)
        call.assert_not_awaited()
        module.sidecar.input_gate.release()
        result = await task
        call.assert_awaited_once_with("validate", timeout=120)
        assert result["success"] is False
        assert module.sidecar.state == "ready"

    asyncio.run(exercise())
