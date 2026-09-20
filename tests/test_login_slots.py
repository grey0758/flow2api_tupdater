import asyncio
import base64
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock

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
    await manager.finish_owner_login(slot)
    result = await manager.check_owner_login(slot)
    assert result["is_logged_in"] is True
    target = profiles / "profile_73" / "Default" / "Preferences"
    assert target.read_text() == '{"signin": {}}'
    assert not any(Path(slot.staging_dir).iterdir())
    assert not manager.has_slot(slot.number)
    assert update.await_count == 2
    assert update.await_args_list[-1].kwargs == {"login_slot_handoff_complete": 1}


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
    await manager.finish_owner_login(slot)
    result = await manager.check_owner_login(slot)
    assert result["error_code"] == "project_ownership_unverified"
    assert slot.state == "ready" and slot.generation == generation
    assert manager.has_slot(slot.number)


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
    assert "candidates & self.provider_project_ids" in source
    assert "project_ownership_unverified" in source


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
    assert await db.claim_login_slot(profile_id) is True
    assert await db.claim_login_slot(profile_id) is False


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
