import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from token_updater.login_slots import LoginSlot, LoginSlotError, LoginSlots


class FakePage:
    async def goto(self, *args, **kwargs):
        return None


class FakeContext:
    def __init__(self):
        self.pages = [FakePage()]
        self.closed = False

    async def close(self):
        self.closed = True


class FakeChromium:
    def __init__(self):
        self.calls = []

    async def launch_persistent_context(self, **kwargs):
        self.calls.append(kwargs)
        return FakeContext()


@pytest.mark.asyncio
async def test_two_profiles_get_isolated_login_desktops(monkeypatch, tmp_path):
    manager = LoginSlots()
    chromium = FakeChromium()
    manager._playwright = SimpleNamespace(chromium=chromium, stop=AsyncMock())
    manager._stack = AsyncMock()
    monkeypatch.setattr("token_updater.login_slots.config.profiles_dir", str(tmp_path))
    monkeypatch.setattr("token_updater.login_slots.config.enable_vnc", True)

    first, second = await asyncio.gather(
        manager.launch({"id": 41, "name": "candidate-a", "proxy_enabled": False}),
        manager.launch({"id": 42, "name": "candidate-b", "proxy_enabled": False}),
    )

    assert {first.number, second.number} == {1, 2}
    assert {call["env"]["DISPLAY"] for call in chromium.calls} == {":101", ":102"}
    assert len({call["user_data_dir"] for call in chromium.calls}) == 2
    assert all(Path(call["user_data_dir"]).is_dir() for call in chromium.calls)

    with pytest.raises(LoginSlotError, match="槽位已满") as error:
        await manager.launch({"id": 43, "name": "candidate-c", "proxy_enabled": False})
    assert error.value.status_code == 409
    await manager.stop()


@pytest.mark.asyncio
async def test_same_profile_cannot_have_two_owners(monkeypatch, tmp_path):
    manager = LoginSlots()
    manager._playwright = SimpleNamespace(chromium=FakeChromium(), stop=AsyncMock())
    manager._stack = AsyncMock()
    monkeypatch.setattr("token_updater.login_slots.config.profiles_dir", str(tmp_path))
    monkeypatch.setattr("token_updater.login_slots.config.enable_vnc", True)
    await manager.launch({"id": 51, "name": "one-owner", "proxy_enabled": False})

    with pytest.raises(LoginSlotError, match="已占用") as error:
        await manager.launch({"id": 51, "name": "one-owner", "proxy_enabled": False})
    assert error.value.status_code == 409
    await manager.stop()


@pytest.mark.asyncio
async def test_capability_is_required_and_expires():
    manager = LoginSlots()
    valid = LoginSlot(1, 61, "unguessable-capability", time.time() + 30, state="ready")
    manager._slots[1] = valid
    claimed, session_capability = await manager.claim("unguessable-capability")
    assert claimed is valid
    assert manager.authorize(session_capability) is valid
    with pytest.raises(LoginSlotError) as reused:
        await manager.claim("unguessable-capability")
    assert reused.value.status_code == 409
    with pytest.raises(LoginSlotError) as wrong:
        manager.authorize("not-the-capability")
    assert wrong.value.status_code == 404
    valid.expires_at = time.time() - 1
    with pytest.raises(LoginSlotError) as expired:
        manager.authorize(session_capability)
    assert expired.value.status_code == 410


def test_login_surface_has_no_sync_or_cookie_export_controls():
    root = Path(__file__).parents[1]
    page = (root / "token_updater/static/login-slot.html").read_text()
    script = (root / "token_updater/static/login-slot.js").read_text()
    combined = (page + script).lower()
    assert "/sync" not in combined
    assert "export-cookies" not in combined
    assert "cookie" in page.lower()


def test_slot_services_are_loopback_only():
    root = Path(__file__).parents[1]
    supervisor = (root / "supervisord.conf").read_text()
    compose = (root / "docker-compose.yml").read_text()
    for number in (1, 2):
        assert f"[program:slot{number}-xvfb]" in supervisor
        assert f"[program:slot{number}-novnc]" in supervisor
        assert f"--listen 127.0.0.1:608{number}" in supervisor
        assert f"-localhost -rfbport 590{number} -nopw" in supervisor
        assert f"608{number}:608{number}" not in compose
    assert '"127.0.0.1:8002:8002"' in compose
    assert '"127.0.0.1:6080:6080"' in compose
    assert "admin123" not in compose
    assert "flow2api}" not in compose


def test_import_page_uses_backend_bearer_auth():
    root = Path(__file__).parents[1]
    script = (root / "token_updater/static/account-import.js").read_text()
    assert '"Authorization": `Bearer ${token}`' in script
    assert "X-Session-Token" not in script
    assert "option.textContent" in script
    assert "item.name" not in script.split("innerHTML")[1].split(";")[0]


@pytest.mark.asyncio
async def test_database_login_slot_claim_is_single_use(tmp_path, monkeypatch):
    from token_updater.database import ProfileDB
    from token_updater import database

    path = tmp_path / "profiles.db"
    monkeypatch.setattr(database.config, "db_path", str(path))
    db = ProfileDB()
    await db.init()
    profile_id = await db.add_profile(
        "fresh", proxy_url="http://proxy.test:8080",
        captcha_proxy_url="http://captcha.test:8080", is_active=False,
        login_slot_prepared=True,
    )
    assert await db.claim_login_slot(profile_id) is True
    assert await db.claim_login_slot(profile_id) is False
    assert (await db.get_profile(profile_id))["login_slot_claimed"] == 1
    assert (await db.get_profile(profile_id))["login_slot_prepared"] == 0


@pytest.mark.asyncio
async def test_legacy_profile_cannot_enter_login_slot_api(tmp_path, monkeypatch):
    from token_updater import api, database
    from token_updater.database import ProfileDB

    path = tmp_path / "profiles.db"
    monkeypatch.setattr(database.config, "db_path", str(path))
    db = ProfileDB()
    await db.init()
    legacy_id = await db.add_profile(
        "legacy-inactive", proxy_url="http://proxy.test:8080",
        captcha_proxy_url="http://captcha.test:8080", is_active=False,
    )
    monkeypatch.setattr(api, "profile_db", db)
    launch = AsyncMock()
    monkeypatch.setattr(api.login_slots, "launch", launch)
    monkeypatch.setattr(api.config, "profiles_dir", str(tmp_path / "profiles"))

    with pytest.raises(HTTPException) as error:
        await api.start_login_slot(legacy_id, token="test-session")

    assert error.value.status_code == 409
    launch.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_during_browser_launch_does_not_reassign_or_leak(monkeypatch, tmp_path):
    manager = LoginSlots()
    entered = asyncio.Event()
    proceed = asyncio.Event()
    chromium = FakeChromium()

    async def delayed(**kwargs):
        entered.set()
        await proceed.wait()
        return await chromium.launch_persistent_context(**kwargs)

    manager._playwright = SimpleNamespace(
        chromium=SimpleNamespace(launch_persistent_context=delayed),
        stop=AsyncMock(),
    )
    manager._stack = AsyncMock(return_value=True)
    monkeypatch.setattr("token_updater.login_slots.config.profiles_dir", str(tmp_path))
    monkeypatch.setattr("token_updater.login_slots.config.enable_vnc", True)
    task = asyncio.create_task(manager.launch({"id": 71, "name": "first", "proxy_enabled": False}))
    await entered.wait()
    cancellation = asyncio.create_task(manager.release(1))
    await asyncio.sleep(0)
    assert manager.owns(71)
    assert manager.has_slot(1)
    proceed.set()
    await task
    await cancellation
    assert not manager.has_slot(1)
    assert manager._stack.await_args_list[-1].args == (1, "stop")
    await manager.stop()


@pytest.mark.asyncio
async def test_failed_stop_quarantines_slot(monkeypatch, tmp_path):
    manager = LoginSlots()
    manager._playwright = SimpleNamespace(chromium=FakeChromium(), stop=AsyncMock())
    async def stack(number, action):
        return False if action == "stop" else True
    manager._stack = stack
    monkeypatch.setattr("token_updater.login_slots.config.profiles_dir", str(tmp_path))
    monkeypatch.setattr("token_updater.login_slots.config.enable_vnc", True)
    slot = await manager.launch({"id": 81, "name": "first", "proxy_enabled": False})
    await manager.release(slot.number)
    assert manager.has_slot(slot.number)
    assert manager.status()[0]["state"] == "quarantined"
    assert slot.closed.is_set()
    with pytest.raises(LoginSlotError):
        manager.authorize("wrong-session")


@pytest.mark.asyncio
async def test_failed_browser_close_quarantines_slot():
    manager = LoginSlots()
    context = SimpleNamespace(close=AsyncMock(side_effect=RuntimeError("close failed")))
    slot = LoginSlot(1, 82, "invite", time.time() + 30, context=context, state="ready")
    manager._slots[1] = slot
    manager._stack = AsyncMock(return_value=True)

    await manager.release(1, expected=slot)

    assert manager.has_slot(1)
    assert slot.state == "quarantined"
    assert slot.closed.is_set()


@pytest.mark.asyncio
async def test_old_slot_object_cannot_finish_reused_number():
    manager = LoginSlots()
    old = LoginSlot(1, 91, "old", time.time() + 30, state="ready")
    new = LoginSlot(1, 92, "new", time.time() + 30, state="ready")
    manager._slots[1] = new

    with pytest.raises(LoginSlotError, match="已经结束"):
        await manager.finish_owner_login(old)

    assert manager._slots[1] is new
    assert new.state == "ready"


@pytest.mark.asyncio
async def test_owner_check_reuses_context_on_failure_and_closes_on_success(monkeypatch):
    from token_updater.browser import browser_manager

    manager = LoginSlots()
    context = FakeContext()
    slot = LoginSlot(
        1, 93, "invite", time.time() + 30,
        session_capability="session", context=context, state="ready",
    )
    manager._slots[1] = slot
    manager._expiry_tasks[1] = asyncio.create_task(asyncio.sleep(30))
    manager._stack = AsyncMock(return_value=True)

    assert await manager.finish_owner_login(slot) == 93
    assert slot.state == "awaiting_check"
    failed = {
        "success": True, "is_logged_in": False,
        "has_flow_project": False, "error_code": "auth_required",
    }
    monkeypatch.setattr(browser_manager, "check_login_slot_status", AsyncMock(return_value=failed))
    assert await manager.check_owner_login(slot) == failed
    assert slot.state == "ready"
    assert manager.has_slot(1)
    assert context.closed is False

    assert await manager.finish_owner_login(slot) == 93
    passed = {"success": True, "is_logged_in": True, "has_flow_project": True}
    browser_manager.check_login_slot_status = AsyncMock(return_value=passed)
    assert await manager.check_owner_login(slot) == passed
    assert context.closed is True
    assert not manager.has_slot(1)


@pytest.mark.asyncio
async def test_project_is_bound_only_after_same_context_authentication(monkeypatch):
    from token_updater.browser import BrowserManager

    manager = BrowserManager()
    context = SimpleNamespace(cookies=AsyncMock(return_value=[
        {"name": "SID", "value": "sid", "domain": ".google.com", "path": "/"},
        {"name": "OSID", "value": "osid", "domain": "flow.google.com", "path": "/"},
    ]))
    profile = {"id": 94, "name": "fresh", "email": ""}
    identity = "owner@example.test"
    project_id = "0f6ddfcf-11ce-4a79-9792-b23cc4d189aa"

    with patch("token_updater.browser.profile_db.get_profile", AsyncMock(return_value=profile)), \
         patch("token_updater.browser.profile_db.update_profile", AsyncMock()) as update, \
         patch.object(manager, "_validate_context_session", AsyncMock(return_value={
             "success": True, "session_token": "session", "email": identity,
         })), \
         patch.object(manager, "_discover_flow_project_id", AsyncMock(return_value=project_id)), \
         patch.object(manager, "_persist_login_state", AsyncMock()):
        result = await manager.check_login_slot_status(94, context)

    assert result["is_logged_in"] is True
    assert result["has_flow_project"] is True
    update.assert_awaited_once_with(
        94,
        observed_flow_project_id=project_id,
        observed_flow_project_verified=1,
        observed_flow_project_identity=identity,
    )
