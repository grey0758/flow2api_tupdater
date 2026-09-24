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
        module.sidecar.state = "ready"
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
        call.assert_awaited_once_with("validate", {}, timeout=180)
        assert result["success"] is False
        assert module.sidecar.state == "ready"

    asyncio.run(exercise())


def test_slot3_validation_returns_only_bounded_probe_diagnostics(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "ready"
        call = AsyncMock(return_value={
            "success": False,
            "state": "ready",
            "error_code": "project_ownership_unverified",
            "probe_counts": {
                "flow_rpc_post": 3,
                "known_status_200": 1001,
                "secret_payload": "must-not-pass",
                "rpc_ids_other": True,
            },
            "candidate_count": 1,
            "candidate_visible": True,
            "identity": "private@example.invalid",
            "project_id": "private-project-id",
            "probe_rpc_ids": ["private-rpc-detail"],
        })
        monkeypatch.setattr(module.sidecar, "worker_call", call)

        result = await module.sidecar.validate()

        assert result == {
            "success": False,
            "state": "ready",
            "has_identity": False,
            "has_project": False,
            "error_code": "project_ownership_unverified",
            "probe_counts": {
                "flow_rpc_post": 3,
                "known_status_200": 999,
            },
            "candidate_count": 1,
            "candidate_visible": True,
        }

    asyncio.run(exercise())


def test_slot3_existing_project_validation_forwards_only_to_worker(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    expected = "c73bdcfe-ef10-464f-b628-890ee76f28ae"

    async def exercise():
        module.sidecar.state = "ready"
        call = AsyncMock(return_value={
            "success": False,
            "state": "ready",
            "error_code": "project_ownership_unverified",
            "candidate_count": 0,
        })
        monkeypatch.setattr(module.sidecar, "worker_call", call)

        result = await module.sidecar.validate(expected)

        call.assert_awaited_once_with(
            "validate",
            {"expected_existing_project_id": expected},
            timeout=180,
        )
        assert expected not in str(result)
        assert result["error_code"] == "project_ownership_unverified"

    asyncio.run(exercise())


def test_slot3_account_project_validation_returns_only_booleans(monkeypatch):
    from test_login_slots import _keypair
    module = _module(monkeypatch, _keypair()[0])
    expected = "c73bdcfe-ef10-464f-b628-890ee76f28ae"

    async def exercise():
        module.sidecar.state = "ready"
        call = AsyncMock(return_value={
            "success": True,
            "state": "validated",
            "is_logged_in": True,
            "has_account_projects": True,
            "existing_project_present": False,
            "identity": "private@example.invalid",
            "private_project_ids": [expected],
        })
        monkeypatch.setattr(module.sidecar, "worker_call", call)
        result = await module.sidecar.validate_account_projects(expected)
        assert result == {
            "success": True,
            "state": "validated",
            "has_identity": True,
            "has_account_projects": True,
            "existing_project_present": False,
            "error_code": None,
        }
        assert expected not in str(result)
        assert "private@example.invalid" not in str(result)

    asyncio.run(exercise())


def test_slot3_existing_account_handoff_never_returns_project(monkeypatch):
    from test_login_slots import _keypair
    monkeypatch.setenv("LOGIN_SLOT3_RECOVER_EXISTING", "1")
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "validated"
        module.sidecar.identity = "private@example.invalid"
        module.sidecar.project_id = "must-not-leave-sidecar"
        module.sidecar.existing_project_present = True
        result = await module.sidecar.account_handoff()
        assert result == {
            "identity": "private@example.invalid",
            "profile_id": module.PROFILE_ID,
            "generation": module.sidecar.generation,
        }
        assert "project" not in result
        assert "must-not-leave-sidecar" not in str(result)

    asyncio.run(exercise())


def test_slot3_existing_account_handoff_requires_validated_state(monkeypatch):
    from fastapi import HTTPException
    from test_login_slots import _keypair
    monkeypatch.setenv("LOGIN_SLOT3_RECOVER_EXISTING", "1")
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "ready"
        module.sidecar.identity = "private@example.invalid"
        module.sidecar.existing_project_present = True
        try:
            await module.sidecar.account_handoff()
        except HTTPException as exc:
            assert exc.status_code == 409
        else:
            raise AssertionError("unvalidated account handoff must be rejected")

    asyncio.run(exercise())


def test_slot3_existing_account_handoff_requires_original_project(monkeypatch):
    from fastapi import HTTPException
    from test_login_slots import _keypair
    monkeypatch.setenv("LOGIN_SLOT3_RECOVER_EXISTING", "1")
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "validated"
        module.sidecar.identity = "private@example.invalid"
        module.sidecar.existing_project_present = False
        try:
            await module.sidecar.account_handoff()
        except HTTPException as exc:
            assert exc.status_code == 409
        else:
            raise AssertionError("unowned original project must reject handoff")

    asyncio.run(exercise())


def test_slot3_existing_profile_uses_recover(monkeypatch, tmp_path):
    from test_login_slots import _keypair
    worker_socket = tmp_path / "worker.sock"
    worker_socket.touch()
    monkeypatch.setenv("LOGIN_SLOT3_WORKER_SOCKET", str(worker_socket))
    monkeypatch.setenv("LOGIN_SLOT3_RECOVER_EXISTING", "1")
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        call = AsyncMock(return_value={"state": "ready", "browser_running": True})
        monkeypatch.setattr(module.sidecar, "worker_call", call)
        await module.sidecar.bootstrap()
        call.assert_awaited_once_with(
            "recover", {"proxy_url": "http://127.0.0.1:18088"}, timeout=120,
        )
        assert module.sidecar.state == "ready"

    asyncio.run(exercise())


def test_slot3_existing_profile_never_cleans(monkeypatch):
    from fastapi import HTTPException
    from test_login_slots import _keypair
    monkeypatch.setenv("LOGIN_SLOT3_RECOVER_EXISTING", "1")
    module = _module(monkeypatch, _keypair()[0])

    async def exercise():
        module.sidecar.state = "validated"
        try:
            await module.sidecar.cleanup()
        except HTTPException as exc:
            assert exc.status_code == 409
        else:
            raise AssertionError("existing Profile cleanup must be rejected")

    asyncio.run(exercise())
