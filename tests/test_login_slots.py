import asyncio
import base64
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from token_updater.login_slots import LoginSlot, LoginSlotError, LoginSlots
from token_updater.login_worker_protocol import ReplayGuard, sign_headers


SOURCE_PROXY = "http://172.19.240.1:18088"


def _keypair():
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return encode(private_raw), encode(public_raw)


def _slot_tree(tmp_path: Path, monkeypatch):
    from token_updater import login_slots as module
    from token_updater.database import profile_db

    profiles = tmp_path / "profiles"
    root = profiles / ".login-slots"
    uid = os.getuid()
    for number in (1, 2):
        stage = root / f"slot{number}" / "profile"
        stage.mkdir(parents=True)
        stage.chmod(0o700)
    monkeypatch.setattr(module.config, "profiles_dir", str(profiles))
    monkeypatch.setattr(module.config, "login_slot_root", str(root))
    monkeypatch.setattr(module.config, "login_slot_worker_ids", (uid, uid))
    monkeypatch.setattr(module.config, "login_slot_worker_sockets", ("/one.sock", "/two.sock"))
    monkeypatch.setattr(module.config, "login_slot_worker_proxy_urls", (
        "http://127.0.0.1:18088", "http://127.0.0.1:18088",
    ))
    monkeypatch.setattr(module.config, "login_slot_expected_source_proxy", SOURCE_PROXY)
    monkeypatch.setattr(module.config, "enable_vnc", True)
    monkeypatch.setattr(profile_db, "claim_login_slot", AsyncMock(return_value=True))
    monkeypatch.setattr(
        profile_db, "rotate_login_slot_generation", AsyncMock(return_value=True)
    )
    return profiles, root


def _profile(profile_id):
    return {
        "id": profile_id,
        "name": f"candidate-{profile_id}",
        "proxy_enabled": True,
        "proxy_url": SOURCE_PROXY,
    }


def _worker_reply(slot, state="ready", browser=True, **extra):
    return {
        "slot": slot.number,
        "generation": slot.generation,
        "profile_id": slot.profile_id,
        "state": state,
        "browser_running": browser,
        **extra,
    }


@pytest.mark.asyncio
async def test_two_profiles_get_distinct_workers(monkeypatch, tmp_path):
    from token_updater.browser import browser_manager
    from token_updater.updater import token_syncer

    _slot_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(browser_manager, "get_active_profile_id", lambda: None)
    monkeypatch.setattr(token_syncer, "is_syncing", lambda: False)
    manager = LoginSlots()
    manager._reconciled = True

    async def worker(slot, method, **kwargs):
        assert method == "assign"
        return _worker_reply(slot)

    monkeypatch.setattr(manager, "_worker", worker)
    first, second = await asyncio.gather(manager.launch(_profile(41)), manager.launch(_profile(42)))
    assert {first.number, second.number} == {1, 2}
    assert first.worker_socket != second.worker_socket
    assert first.staging_dir != second.staging_dir
    assert first.generation != second.generation
    with pytest.raises(LoginSlotError, match="槽位已满"):
        await manager.launch(_profile(43))


@pytest.mark.asyncio
async def test_source_proxy_must_match_fixed_isolated_egress(monkeypatch, tmp_path):
    _slot_tree(tmp_path, monkeypatch)
    manager = LoginSlots()
    manager._reconciled = True
    bad = _profile(51)
    bad["proxy_url"] = "http://example.test:9999"
    with pytest.raises(LoginSlotError, match="固定出口") as error:
        await manager.launch(bad)
    assert error.value.status_code == 400


@pytest.mark.asyncio
async def test_launch_refuses_before_restart_reconciliation(monkeypatch, tmp_path):
    _slot_tree(tmp_path, monkeypatch)
    manager = LoginSlots()
    with pytest.raises(LoginSlotError, match="启动对账") as error:
        await manager.launch(_profile(52))
    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_restart_reconciliation_blocks_claimed_profile_and_dirty_slot(
    monkeypatch, tmp_path,
):
    from token_updater.database import profile_db

    _, root = _slot_tree(tmp_path, monkeypatch)
    (root / "slot2" / "profile" / "retained-state").write_text("quarantined")
    monkeypatch.setattr(profile_db, "get_all_profiles", AsyncMock(return_value=[
        {"id": 53, "login_slot_claimed": 1, "login_slot_handoff_complete": 0},
        {"id": 54, "login_slot_claimed": 1, "login_slot_handoff_complete": 1},
    ]))
    manager = LoginSlots()
    await manager.reconcile()
    assert manager.owns(53) is True
    assert manager.owns(54) is False
    assert manager.any_active() is True
    assert manager.status() == [
        {"slot": 1, "state": "quarantined"},
        {"slot": 2, "state": "quarantined"},
    ]


@pytest.mark.asyncio
async def test_restart_reconciliation_revokes_persisted_worker_generation(
    monkeypatch, tmp_path,
):
    from token_updater.database import profile_db

    _, root = _slot_tree(tmp_path, monkeypatch)
    (root / "slot1" / "profile" / "retained-state").write_text("private")
    monkeypatch.setattr(profile_db, "get_all_profiles", AsyncMock(return_value=[{
        "id": 55,
        "login_slot_claimed": 1,
        "login_slot_handoff_complete": 0,
        "login_slot_number": 1,
        "login_slot_generation": "persisted-generation",
    }]))
    manager = LoginSlots()
    calls = []

    async def worker(slot, method, **kwargs):
        calls.append((slot.number, slot.profile_id, slot.generation, method))
        return _worker_reply(slot, state="quarantined", browser=False)

    monkeypatch.setattr(manager, "_worker", worker)
    await manager.reconcile()

    assert calls == [(1, 55, "persisted-generation", "abort")]
    assert manager.owns(55)
    assert manager.status()[0] == {"slot": 1, "state": "quarantined"}
    assert manager._slots == {}


@pytest.mark.asyncio
async def test_capability_is_single_claim_and_expires():
    manager = LoginSlots()
    valid = LoginSlot(1, 61, "invite", time.time() + 30, state="ready")
    manager._slots[1] = valid
    claimed, session = await manager.claim("invite")
    assert claimed is valid and manager.authorize(session) is valid
    with pytest.raises(LoginSlotError) as reused:
        await manager.claim("invite")
    assert reused.value.status_code == 409
    valid.expires_at = time.time() - 1
    with pytest.raises(LoginSlotError) as expired:
        manager.authorize(session)
    assert expired.value.status_code == 410


def test_signed_worker_request_is_scoped_and_replay_resistant():
    private, public = _keypair()
    headers = sign_headers(
        private, slot=1, generation="generation-a", profile_id=71,
        method="POST", path="/validate", body=b"{}", now=100,
    )
    guard = ReplayGuard(public, 1)
    assert guard.verify(
        headers, method="POST", path="/validate", body=b"{}", now=100
    ) == ("generation-a", 71)
    with pytest.raises(ValueError, match="replayed"):
        guard.verify(headers, method="POST", path="/validate", body=b"{}", now=100)


def test_signed_worker_request_rejects_cross_slot_and_body_change():
    private, public = _keypair()
    headers = sign_headers(
        private, slot=1, generation="generation-a", profile_id=72,
        method="POST", path="/assign", body=b'{"proxy_url":"safe"}', now=100,
    )
    with pytest.raises(ValueError):
        ReplayGuard(public, 2).verify(
            headers, method="POST", path="/assign", body=b'{"proxy_url":"safe"}', now=100
        )
    with pytest.raises(ValueError):
        ReplayGuard(public, 1).verify(
            headers, method="POST", path="/assign", body=b'{"proxy_url":"changed"}', now=100
        )


@pytest.mark.asyncio
async def test_validation_snapshot_is_promoted_then_worker_is_cleaned(monkeypatch, tmp_path):
    from token_updater.browser import browser_manager
    from token_updater.database import profile_db
    from token_updater.updater import token_syncer

    profiles, _ = _slot_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(browser_manager, "get_active_profile_id", lambda: None)
    monkeypatch.setattr(token_syncer, "is_syncing", lambda: False)
    update = AsyncMock()
    monkeypatch.setattr(profile_db, "update_profile", update)
    manager = LoginSlots()
    manager._reconciled = True

    async def worker(slot, method, **kwargs):
        stage = Path(slot.staging_dir)
        if method == "assign":
            (stage / "Default").mkdir()
            (stage / "Default" / "Preferences").write_text('{"signin": {}}')
            return _worker_reply(slot)
        if method == "validate":
            return _worker_reply(
                slot, state="validated", browser=False, success=True,
                is_logged_in=True, has_flow_project=True,
                identity="owner@example.test",
                project_id="0f6ddfcf-11ce-4a79-9792-b23cc4d189aa",
            )
        if method == "cleanup":
            for path in sorted(stage.rglob("*"), reverse=True):
                path.unlink() if path.is_file() else path.rmdir()
            return _worker_reply(slot, state="idle", browser=False)
        raise AssertionError(method)

    monkeypatch.setattr(manager, "_worker", worker)
    slot = await manager.launch(_profile(73))
    assert slot.state == "ready"
    result = await manager.check_owner_login(slot)
    assert result["is_logged_in"] is True
    target = profiles / "profile_73" / "Default" / "Preferences"
    assert target.read_text() == '{"signin": {}}'
    assert not any(Path(slot.staging_dir).iterdir())
    assert not manager.has_slot(slot.number)
    assert update.await_count == 2
    assert update.await_args_list[-1].kwargs == {
        "login_slot_handoff_complete": 1,
        "login_slot_generation": None,
    }


@pytest.mark.asyncio
async def test_failed_validation_keeps_same_worker_generation(monkeypatch, tmp_path):
    from token_updater.browser import browser_manager
    from token_updater.updater import token_syncer

    _slot_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(browser_manager, "get_active_profile_id", lambda: None)
    monkeypatch.setattr(token_syncer, "is_syncing", lambda: False)
    manager = LoginSlots()
    manager._reconciled = True

    async def worker(slot, method, **kwargs):
        if method == "assign":
            return _worker_reply(slot)
        if method == "validate":
            return _worker_reply(
                slot, state="ready", success=False, is_logged_in=False,
                has_flow_project=False, error_code="project_ownership_unverified",
            )
        raise AssertionError(method)

    monkeypatch.setattr(manager, "_worker", worker)
    slot = await manager.launch(_profile(74))
    generation = slot.generation
    assert slot.state == "ready"
    result = await manager.check_owner_login(slot)
    assert result["error_code"] == "project_ownership_unverified"
    assert slot.state == "ready" and slot.generation == generation
    assert manager.has_slot(slot.number)


@pytest.mark.asyncio
async def test_recover_exact_expired_slot_without_reusing_invitation(monkeypatch, tmp_path):
    from token_updater.browser import browser_manager
    from token_updater.updater import token_syncer

    _, root = _slot_tree(tmp_path, monkeypatch)
    (root / "slot1" / "profile" / "retained-state").write_text("private")
    monkeypatch.setattr(browser_manager, "get_active_profile_id", lambda: None)
    monkeypatch.setattr(token_syncer, "is_syncing", lambda: False)
    manager = LoginSlots()
    manager._reconciled = True
    manager._blocked_profiles.add(12)
    manager._quarantined_numbers.add(1)
    old = LoginSlot(1, 12, "revoked", time.time() - 10, state="quarantined")
    old.closed.set()
    manager._slots[1] = old
    calls = []

    async def worker(slot, method, **kwargs):
        calls.append((slot.number, slot.profile_id, method))
        return _worker_reply(slot)

    monkeypatch.setattr(manager, "_worker", worker)
    profile = {
        **_profile(12), "login_slot_claimed": True,
        "login_slot_number": 1,
        "login_slot_generation": "persisted-old-generation",
        "login_slot_handoff_complete": False, "is_active": False,
        "is_logged_in": False, "sync_count": 0,
    }
    with pytest.raises(LoginSlotError):
        await manager.recover(profile, 2)
    assert not calls
    slot = await manager.recover(profile, 1)
    assert slot.state == "ready" and slot.generation != old.generation
    assert slot.capability != old.capability and slot.session_capability == ""
    assert await manager.is_current(old) is False
    assert calls == [(1, 12, "recover")]
    assert 1 not in manager._quarantined_numbers
    manager._expiry_tasks[1].cancel()


@pytest.mark.asyncio
async def test_recover_rejects_unexpired_or_completed_profile(monkeypatch, tmp_path):
    _, root = _slot_tree(tmp_path, monkeypatch)
    (root / "slot1" / "profile" / "retained-state").write_text("private")
    manager = LoginSlots()
    manager._reconciled = True
    manager._blocked_profiles.add(12)
    old = LoginSlot(1, 12, "revoked", time.time() + 10, state="quarantined")
    old.closed.set()
    manager._slots[1] = old
    profile = {
        **_profile(12), "login_slot_claimed": True,
        "login_slot_number": 1,
        "login_slot_generation": "persisted-old-generation",
        "login_slot_handoff_complete": False, "sync_count": 0,
    }
    with pytest.raises(LoginSlotError):
        await manager.recover(profile, 1)
    old.expires_at = time.time() - 10
    profile["login_slot_handoff_complete"] = True
    with pytest.raises(LoginSlotError):
        await manager.recover(profile, 1)


@pytest.mark.asyncio
async def test_cancel_with_profile_data_quarantines_worker(monkeypatch, tmp_path):
    from token_updater.browser import browser_manager
    from token_updater.updater import token_syncer

    _slot_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(browser_manager, "get_active_profile_id", lambda: None)
    monkeypatch.setattr(token_syncer, "is_syncing", lambda: False)
    manager = LoginSlots()
    manager._reconciled = True

    async def worker(slot, method, **kwargs):
        if method == "assign":
            Path(slot.staging_dir, "retained-secret-state").write_text("not reusable")
            return _worker_reply(slot)
        if method == "abort":
            return _worker_reply(slot, state="quarantined", browser=False)
        raise AssertionError(method)

    monkeypatch.setattr(manager, "_worker", worker)
    slot = await manager.launch(_profile(75))
    await manager.release(slot.number, expected=slot)
    assert manager.has_slot(slot.number)
    assert slot.state == "quarantined" and slot.closed.is_set()


@pytest.mark.asyncio
async def test_old_slot_object_cannot_finish_reused_number():
    manager = LoginSlots()
    old = LoginSlot(1, 81, "old", time.time() + 30, state="ready")
    new = LoginSlot(1, 82, "new", time.time() + 30, state="ready")
    manager._slots[1] = new
    with pytest.raises(LoginSlotError, match="已经结束"):
        await manager.finish_owner_login(old)
    assert await manager.is_current(old) is False
    assert await manager.is_current(new) is True


def test_login_surface_has_no_sync_or_cookie_export_controls():
    root = Path(__file__).parents[1]
    page = (root / "token_updater/static/login-slot.html").read_text()
    script = (root / "token_updater/static/login-slot.js").read_text()
    combined = (page + script).lower()
    assert "/sync" not in combined
    assert "export-cookies" not in combined
    assert "我已完成登录" not in combined
    assert "/login-slots/complete" not in combined
    assert 'src="/login-slots/client.js"' in page


def test_final_topology_declares_two_non_root_profile_workers():
    root = Path(__file__).parents[1]
    compose = (root / "docker-compose.login-slots.yml").read_text()
    worker = (root / "token_updater/login_worker.py").read_text()
    dockerfile = (root / "Dockerfile.login-worker").read_text()
    assert "login-worker-1:" in compose and "login-worker-2:" in compose
    assert 'user: "11001:12000"' in compose and 'user: "11002:12000"' in compose
    # The worker anchor applies network_mode:none to both workers; the second
    # literal belongs to the one-shot volume initializer.
    assert compose.count("network_mode: none") >= 2
    assert "read_only: true" in compose and "cap_drop: [ALL]" in compose
    assert "login_profile_1:/slot/profile" in compose
    assert "login_profile_2:/slot/profile" in compose
    worker_one = compose.split("login-worker-1:", 1)[1].split("login-worker-2:", 1)[0]
    assert "./data:/app/data" not in worker_one
    assert "/app/data:ro,nosuid,nodev,noexec" in worker_one
    assert '"--enable-automation", "--no-sandbox", "--disable-dev-shm-usage"' in worker
    assert "--disable-setuid-sandbox" not in worker
    assert "USER ${WORKER_UID}:12000" in dockerfile
    assert "FROM scratch" in dockerfile
    assert "seccomp:deploy/login-worker-seccomp.json" in compose


def test_worker_project_gate_requires_authenticated_provider_response():
    root = Path(__file__).parents[1]
    source = (root / "token_updater/login_worker.py").read_text()
    assert "PROJECT_API_PATH" in source
    assert "PROJECT_DOCUMENT_PATH" in source
    assert "candidates & self.provider_project_ids" in source
    assert "project_ownership_unverified" in source


@pytest.mark.asyncio
async def test_worker_records_modern_project_document_as_access_only(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    worker = module.LoginWorker()
    response = SimpleNamespace(
        url=f"https://flow.google.com/project/{project_id}",
        request=SimpleNamespace(method="GET", resource_type="document"),
        status=200,
        header_value=AsyncMock(return_value="text/html; charset=utf-8"),
        text=AsyncMock(return_value="<html><body>Flow project workspace</body></html>"),
    )

    await worker._record_provider_project_response(response)

    assert worker.accessible_document_ids == {project_id}
    assert worker.provider_project_ids == set()


@pytest.mark.asyncio
async def test_worker_rejects_modern_flow_project_denial_document(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    worker = module.LoginWorker()
    response = SimpleNamespace(
        url=f"https://flow.google.com/project/{project_id}",
        request=SimpleNamespace(method="GET", resource_type="document"),
        status=200,
        header_value=AsyncMock(return_value="text/html"),
        text=AsyncMock(return_value="<html><body>Request access</body></html>"),
    )

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == set()
    assert worker.accessible_document_ids == set()


@pytest.mark.asyncio
async def test_worker_records_project_from_successful_current_user_rpc(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            "?rpcids=OylIJd"
        ),
        request=SimpleNamespace(method="POST", resource_type="xhr"),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf; charset=utf-8"),
        text=AsyncMock(return_value=(
            ")]}'\n"
            '[["wrb.fr","OylIJd","[\\"projects/' + project_id
            + '/workflows/example\\"]",null,null,null,"generic"]]'
        )),
    )
    worker = module.LoginWorker()

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == {project_id}


@pytest.mark.asyncio
async def test_worker_accepts_whitelisted_project_list_read_with_candidate_uuid(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            "?rpcids=bOKtO"
        ),
        request=SimpleNamespace(
            method="POST",
            resource_type="xhr",
            post_data=f'f.req=[[\\"projects/{project_id}\\"]]',
        ),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value='[["wrb.fr","bOKtO","[]"]]'),
    )
    worker = module.LoginWorker()
    worker.validation_candidate_ids.add(project_id)

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == {project_id}


@pytest.mark.asyncio
async def test_worker_ignores_different_uuid_in_whitelisted_project_read(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    candidate = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    other = "0f6ddfcf-11ce-4a79-9792-b23cc4d189aa"
    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            "?rpcids=bOKtO"
        ),
        request=SimpleNamespace(
            method="POST", resource_type="xhr", post_data=f"projects/{other}",
        ),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value='[["wrb.fr","bOKtO","[]"]]'),
    )
    worker = module.LoginWorker()
    worker.validation_candidate_ids.add(candidate)

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == set()


@pytest.mark.asyncio
async def test_worker_project_probe_reports_only_bounded_counts(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    worker = module.LoginWorker()
    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            "?rpcids=OylIJd"
        ),
        request=SimpleNamespace(method="POST", resource_type="xhr"),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value='[["er","OylIJd","private provider detail"]]'),
    )

    await worker._record_provider_project_response(response)

    assert worker.project_probe_counts == {
        "flow_rpc_post": 1, "rpc_ids_known": 1,
        "known_status_200": 1, "known_content_type": 1,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rpc_ids", "payload"),
    [
        ("unrelated", '[["wrb.fr","unrelated","projects/c73bdcfe-ef10-464f-b628-890ee76f28ae"]]'),
        ("OylIJd", '[["er","OylIJd","projects/c73bdcfe-ef10-464f-b628-890ee76f28ae"]]'),
    ],
)
async def test_worker_rejects_unrelated_or_failed_current_user_rpc(
    monkeypatch, rpc_ids, payload,
):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            f"?rpcids={rpc_ids}"
        ),
        request=SimpleNamespace(method="POST", resource_type="xhr"),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value=payload),
    )
    worker = module.LoginWorker()

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("rpc_id", ["rEhmZd", "Zzl0ze", "SIzNd", "ngNC2"])
async def test_worker_records_exact_project_from_successful_scoped_read(
    monkeypatch, rpc_id,
):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            f"?rpcids={rpc_id}"
        ),
        request=SimpleNamespace(
            method="POST",
            resource_type="xhr",
            post_data=f'f.req=projects%2F{project_id}',
        ),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value=f'[["wrb.fr","{rpc_id}","[]"]]'),
    )
    worker = module.LoginWorker()
    worker.validation_candidate_ids.add(project_id)

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == {project_id}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("post_data", "payload"),
    [
        ("f.req=no-project", '[["wrb.fr","SIzNd","[]"]]'),
        (
            "f.req=projects%2Fc73bdcfe-ef10-464f-b628-890ee76f28ae",
            '[["er","SIzNd","permission denied"]]',
        ),
    ],
)
async def test_worker_rejects_unscoped_or_failed_project_read(
    monkeypatch, post_data, payload,
):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    response = SimpleNamespace(
        url=(
            "https://flow.google.com/_/AiSandboxAngularFrontend/data/batchexecute"
            "?rpcids=SIzNd"
        ),
        request=SimpleNamespace(
            method="POST", resource_type="xhr", post_data=post_data,
        ),
        status=200,
        header_value=AsyncMock(return_value="application/json+protobuf"),
        text=AsyncMock(return_value=payload),
    )
    worker = module.LoginWorker()

    await worker._record_provider_project_response(response)

    assert worker.provider_project_ids == set()


@pytest.mark.asyncio
async def test_worker_probes_current_user_membership_in_disposable_home_tab(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    worker = module.LoginWorker()
    page = SimpleNamespace(goto=AsyncMock(), close=AsyncMock())
    worker.context = SimpleNamespace(new_page=AsyncMock(return_value=page))

    async def record_membership(*_args, **_kwargs):
        worker.provider_project_ids.add(project_id)

    page.goto.side_effect = record_membership
    await worker._refresh_current_user_project_membership({project_id})

    page.goto.assert_awaited_once_with(
        module.MODERN_FLOW_HOME_URL,
        wait_until="domcontentloaded",
        timeout=90000,
    )
    page.close.assert_awaited_once()
    assert worker.provider_project_ids == {project_id}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "editor_text",
    [
        "Create with Flow",
        "Start creating or drop media",
        "All media\nImages\nCharacters\nScenes\nUploads\nTools\n"
        "What would you like to\ncreate?",
        "All media\nImages\nCharacters\nScenes\nUploads\nTools\n"
        "What do you want to\ncreate?",
    ],
)
async def test_worker_requires_rendered_project_access(monkeypatch, editor_text):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module
    monkeypatch.setattr(module.asyncio, "sleep", AsyncMock())

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    page = SimpleNamespace(
        url=f"https://flow.google.com/project/{project_id}",
        wait_for_load_state=AsyncMock(),
        locator=lambda _: SimpleNamespace(
            inner_text=AsyncMock(return_value=editor_text)
        ),
    )
    worker = module.LoginWorker()
    worker.context = SimpleNamespace(pages=[page])

    assert await worker._project_page_is_accessible(project_id) is True

    page.locator = lambda _: SimpleNamespace(
        inner_text=AsyncMock(return_value="Your country or region is not supported")
    )
    assert await worker._project_page_is_accessible(project_id) is False

    page.locator = lambda _: SimpleNamespace(
        inner_text=AsyncMock(return_value="Flow project loading")
    )
    assert await worker._project_page_is_accessible(project_id) is False

    page.locator = lambda _: SimpleNamespace(
        inner_text=AsyncMock(return_value="All media\nImages\nCharacters\nScenes")
    )
    assert await worker._project_page_is_accessible(project_id) is False

    page.locator = lambda _: SimpleNamespace(
        inner_text=AsyncMock(return_value=(
            "All media\nCharacters\nScenes\nUploads\nWhat would you like to create?\n"
            "Request access"
        ))
    )
    assert await worker._project_page_is_accessible(project_id) is False


@pytest.mark.asyncio
async def test_worker_waits_for_rendered_media_workspace(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    inner_text = AsyncMock(side_effect=[
        "Loading",
        "All media\nCharacters\nScenes\nUploads\nWhat do you want to create?",
    ])
    page = SimpleNamespace(
        url=f"https://flow.google.com/project/{project_id}",
        wait_for_load_state=AsyncMock(),
        locator=lambda _: SimpleNamespace(inner_text=inner_text),
    )
    worker = module.LoginWorker()
    worker.context = SimpleNamespace(pages=[page])
    monkeypatch.setattr(module.asyncio, "sleep", AsyncMock())

    assert await worker._project_page_is_accessible(project_id) is True
    assert inner_text.await_count == 2


@pytest.mark.asyncio
async def test_worker_reloads_exact_project_document_before_current_identity_gate(monkeypatch):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "3")
    from token_updater import login_worker as module

    project_id = "c73bdcfe-ef10-464f-b628-890ee76f28ae"
    response = SimpleNamespace(
        url=f"https://flow.google.com/project/{project_id}",
        request=SimpleNamespace(method="GET", resource_type="document"),
        status=200,
        header_value=AsyncMock(return_value="text/html"),
        text=AsyncMock(return_value="<html><body>Create with Flow</body></html>"),
    )
    page = SimpleNamespace(
        url=response.url,
        reload=AsyncMock(return_value=response),
    )
    worker = module.LoginWorker()
    worker.context = SimpleNamespace(pages=[page])
    worker.provider_project_ids.add("0f6ddfcf-11ce-4a79-9792-b23cc4d189aa")

    assert await worker._refresh_project_documents() == {project_id}
    assert worker.accessible_document_ids == {project_id}
    assert worker.provider_project_ids == set()
    page.reload.assert_awaited_once()


def test_worker_existing_project_validation_is_database_bound_and_read_only():
    root = Path(__file__).parents[1]
    source = (root / "token_updater/login_worker.py").read_text()
    assert "expected_existing_project_id" in source
    assert 'https://flow.google.com/project/{expected_project_id}' in source
    assert "candidates &= {expected_project_id}" in source
    assert "New project" not in source


def test_worker_account_project_membership_returns_no_project_identifiers():
    root = Path(__file__).parents[1]
    source = (root / "token_updater/login_worker.py").read_text()
    assert "validate_account_projects" in source
    assert '"existing_project_present"' in source
    assert '"has_account_projects"' in source
    assert '"private_project_ids"' not in source


@pytest.mark.asyncio
async def test_worker_opens_flow_and_labs_auth_tabs(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "1")
    from token_updater import login_worker as module

    flow_page = SimpleNamespace(goto=AsyncMock())
    labs_page = SimpleNamespace(goto=AsyncMock())
    context = SimpleNamespace(
        pages=[flow_page],
        new_page=AsyncMock(return_value=labs_page),
        on=MagicMock(),
    )
    chromium = SimpleNamespace(
        launch_persistent_context=AsyncMock(return_value=context),
    )
    worker = module.LoginWorker.__new__(module.LoginWorker)
    worker.context = None
    worker.playwright = SimpleNamespace(chromium=chromium)
    worker.proxy_url = "direct://"
    worker.provider_project_ids = set()
    monkeypatch.setattr(module.LoginWorker, "_safe_profile_dir", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(module, "configure_web_only_profile", lambda _: None)

    await worker._open_browser()

    flow_page.goto.assert_awaited_once_with(
        module.FLOW_URL, wait_until="domcontentloaded", timeout=90000,
    )
    labs_page.goto.assert_awaited_once_with(
        module.LABS_AUTH_URL, wait_until="domcontentloaded", timeout=90000,
    )
    context.on.assert_called_once_with("response", worker._record_provider_project_response)


@pytest.mark.asyncio
async def test_worker_recovery_preserves_existing_project_tab(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "1")
    from token_updater import login_worker as module

    project_page = SimpleNamespace(
        url="https://flow.google.com/project/c73bdcfe-ef10-464f-b628-890ee76f28ae",
        goto=AsyncMock(),
    )
    labs_page = SimpleNamespace(url="https://labs.google/fx", goto=AsyncMock())
    context = SimpleNamespace(
        pages=[project_page, labs_page],
        new_page=AsyncMock(),
        on=MagicMock(),
    )
    chromium = SimpleNamespace(
        launch_persistent_context=AsyncMock(return_value=context),
    )
    worker = module.LoginWorker.__new__(module.LoginWorker)
    worker.context = None
    worker.playwright = SimpleNamespace(chromium=chromium)
    worker.proxy_url = "direct://"
    worker.provider_project_ids = set()
    monkeypatch.setattr(module.LoginWorker, "_safe_profile_dir", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(module, "configure_web_only_profile", lambda _: None)

    await worker._open_browser()

    project_page.goto.assert_not_awaited()
    labs_page.goto.assert_not_awaited()
    context.new_page.assert_not_awaited()


def test_worker_removes_only_top_level_stale_chromium_locks(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "1")
    from token_updater import login_worker as module

    (tmp_path / "SingletonLock").symlink_to("old-container-84")
    (tmp_path / "SingletonCookie").write_text("stale")
    worker = module.LoginWorker()
    monkeypatch.setattr(module.LoginWorker, "_safe_profile_dir", staticmethod(lambda: tmp_path))

    worker._remove_stale_browser_locks()

    assert not (tmp_path / "SingletonLock").is_symlink()
    assert not (tmp_path / "SingletonCookie").exists()


def test_worker_rejects_directory_at_chromium_lock_name(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "1")
    from token_updater import login_worker as module

    (tmp_path / "SingletonLock").mkdir()
    worker = module.LoginWorker()
    monkeypatch.setattr(module.LoginWorker, "_safe_profile_dir", staticmethod(lambda: tmp_path))

    with pytest.raises(RuntimeError, match="singleton artifact"):
        worker._remove_stale_browser_locks()
    assert (tmp_path / "SingletonLock").is_dir()


@pytest.mark.asyncio
async def test_worker_abort_releases_generation_but_retains_quarantined_profile(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", _keypair()[1])
    monkeypatch.setenv("LOGIN_SLOT_NUMBER", "1")
    from token_updater import login_worker as module

    (tmp_path / "retained-state").write_text("private")
    worker = module.LoginWorker()
    worker.state = "ready"
    worker.generation = "old-generation"
    worker.profile_id = 91
    worker.proxy_url = "http://127.0.0.1:18088"
    worker.context = SimpleNamespace(close=AsyncMock())
    worker._stop_vnc = AsyncMock()
    monkeypatch.setattr(
        module.LoginWorker, "_safe_profile_dir", staticmethod(lambda: tmp_path)
    )

    result = await worker.abort("old-generation", 91)

    assert result["state"] == "quarantined"
    assert result["generation"] == ""
    assert result["profile_id"] == 0
    assert worker.context is None
    assert (tmp_path / "retained-state").read_text() == "private"


@pytest.mark.asyncio
async def test_database_login_slot_claim_is_single_use(tmp_path, monkeypatch):
    from token_updater import database
    from token_updater.database import ProfileDB

    path = tmp_path / "profiles.db"
    monkeypatch.setattr(database.config, "db_path", str(path))
    db = ProfileDB()
    await db.init()
    profile_id = await db.add_profile(
        "fresh", proxy_url=SOURCE_PROXY,
        captcha_proxy_url="http://127.0.0.1:18082", is_active=False,
        login_slot_prepared=True,
    )
    assert await db.claim_login_slot(profile_id, 2, "generation-one") is True
    claimed = await db.get_profile(profile_id)
    assert claimed["login_slot_number"] == 2
    assert claimed["login_slot_generation"] == "generation-one"
    assert await db.claim_login_slot(profile_id, 1, "generation-two") is False


@pytest.mark.asyncio
async def test_legacy_profile_cannot_enter_login_slot_api(tmp_path, monkeypatch):
    from token_updater import api, database
    from token_updater.database import ProfileDB

    path = tmp_path / "profiles.db"
    monkeypatch.setattr(database.config, "db_path", str(path))
    db = ProfileDB()
    await db.init()
    legacy_id = await db.add_profile(
        "legacy", proxy_url=SOURCE_PROXY,
        captcha_proxy_url="http://127.0.0.1:18082", is_active=False,
    )
    monkeypatch.setattr(api, "profile_db", db)
    launch = AsyncMock()
    monkeypatch.setattr(api.login_slots, "launch", launch)
    monkeypatch.setattr(api.config, "profiles_dir", str(tmp_path / "profiles"))
    with pytest.raises(HTTPException) as error:
        await api.start_login_slot(legacy_id, token="session")
    assert error.value.status_code == 409
    launch.assert_not_awaited()
