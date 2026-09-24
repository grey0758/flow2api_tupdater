import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from token_updater.config import config
from token_updater.updater import TokenSyncer

JAR = [{"name": "SID", "value": "root", "domain": ".google.com", "path": "/"},
       {"name": "OSID", "value": "flow", "domain": "flow.google.com", "path": "/"}]
ACK = {"success": True, "cookies_updated": True, "flow_cookies_configured": True,
       "google_session_cookies_configured": True, "proxy_configured": True,
       "oauth_verified": True, "account_active": True, "action": "updated"}
PROFILE = {"id": 1, "name": "test", "email": "user@example.com", "google_cookies": json.dumps(JAR),
           "flow2api_url": "http://server", "connection_token_override": "key"}
PROJECT_ID = "0f6ddfcf-11ce-4a79-9792-b23cc4d189aa"


def test_overdue_check_accepts_timezone_aware_imported_timestamps():
    now = datetime.now(timezone.utc)
    with patch.object(config, "refresh_interval", 60):
        assert TokenSyncer()._is_sync_overdue({"last_sync_time": (now - timedelta(hours=2)).isoformat()}, now)
        assert not TokenSyncer()._is_sync_overdue({"last_sync_time": now.isoformat()}, now)


def client_for(status, data):
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.return_value = SimpleNamespace(status_code=status, json=lambda: data)
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("status,detail,code", [
    (401, "invalid token", "destination_auth"), (403, "disabled", "destination_auth"),
    (404, "Not Found", "destination_endpoint"), (405, "Method Not Allowed", "destination_endpoint"),
    (307, "redirect", "destination_redirect"), (422, "bad input", "destination_rejected"),
    (409, "protected profile", "independent_login"), (429, "busy", "destination_unavailable"),
    (503, "verification temporary", "destination_unavailable"),
    (400, "Invalid captcha_proxy_url", "destination_proxy"),
    (400, "Invalid session token or account proxy unavailable", "verification_unavailable"),
    (400, "Expired Labs session token authorization", "auth_required"),
])
async def test_destination_failures_are_classified_without_body_leak(status, detail, code):
    with patch("token_updater.updater.httpx.AsyncClient", return_value=client_for(status, {"detail": detail + " secret-value"})):
        result = await TokenSyncer()._push_to_flow2api("st", "http://server", "key", google_cookies=JAR)
    assert result["error_code"] == code
    assert result["status_code"] == status
    assert f"HTTP {status}" in result["error"]
    assert "secret-value" not in str(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("changes,code", [({"oauth_verified": False}, "oauth_unconfirmed"),
                                        ({"native_session_verified": False}, "native_session_unverified"),
                                        ({"account_active": False}, "account_disabled"),
                                        ({"account_active": None}, "activation_unconfirmed")])
async def test_saved_or_unverified_is_not_recovered(changes, code):
    with patch("token_updater.updater.httpx.AsyncClient", return_value=client_for(200, {**ACK, **changes})):
        result = await TokenSyncer()._push_to_flow2api("st", "http://server", "key", google_cookies=JAR)
    assert not result["success"]
    assert result["error_code"] == code


@pytest.mark.asyncio
async def test_gemini_ack_stays_compatible():
    with patch("token_updater.updater.httpx.AsyncClient", return_value=client_for(200, {"success": True})):
        assert (await TokenSyncer()._push_to_flow2api("gcu:v1:payload", "http://server", "key"))["success"]


@pytest.mark.asyncio
async def test_modern_flow_ack_requires_future_expiry_and_stable_project_contract():
    complete = {
        **ACK,
        "token_id": 7,
        "email": "user@example.com",
        "current_project_id": PROJECT_ID,
        "project_context_accepted": True,
        "project_owned": True,
        "pending_enable": False,
        "at_expires": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "needs_refresh": False,
    }
    with patch(
        "token_updater.updater.httpx.AsyncClient",
        return_value=client_for(200, complete),
    ):
        accepted = await TokenSyncer()._push_to_flow2api(
            "st", "http://server", "key", google_cookies=JAR,
            project_id=PROJECT_ID,
        )
    assert accepted["success"]
    assert accepted["token_id"] == 7
    assert accepted["project_owned"] is True

    with patch(
        "token_updater.updater.httpx.AsyncClient",
        return_value=client_for(200, {**complete, "at_expires": None}),
    ):
        rejected = await TokenSyncer()._push_to_flow2api(
            "st", "http://server", "key", google_cookies=JAR,
            project_id=PROJECT_ID,
        )
    assert not rejected["success"]
    assert rejected["error_code"] == "destination_contract_incomplete"
    assert rejected["synced"] is True


@pytest.mark.asyncio
async def test_post_write_readback_requires_one_exact_usable_token():
    syncer = TokenSyncer()
    pushed = {"token_id": 7, "account_active": True}
    valid = {
        "id": 7,
        "email": "user@example.com",
        "is_active": True,
        "needs_refresh": False,
        "at_expires": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        "current_project_id": PROJECT_ID,
        "project_owned": True,
    }
    with patch.object(
        syncer,
        "_check_tokens_status",
        AsyncMock(return_value={"success": True, "tokens": [valid]}),
    ):
        accepted = await syncer._verify_destination_session(
            "http://server", "key", expected_email="user@example.com",
            expected_project_id=PROJECT_ID, pushed=pushed,
        )
    assert accepted["success"]

    with patch.object(
        syncer,
        "_check_tokens_status",
        AsyncMock(return_value={"success": True, "tokens": [{**valid, "needs_refresh": True}]}),
    ):
        rejected = await syncer._verify_destination_session(
            "http://server", "key", expected_email="user@example.com",
            expected_project_id=PROJECT_ID, pushed=pushed,
        )
    assert rejected["error_code"] == "destination_session_unusable"
    assert rejected["synced"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["destination_auth", "independent_login", "destination_proxy", "destination_unavailable", "account_disabled", "oauth_unconfirmed", "native_session_unverified"])
async def test_protocol_push_failure_does_not_clear_cookies_or_relogin(code):
    syncer = TokenSyncer()
    with patch.object(config, "protocol_refresh_enabled", True), \
         patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=PROFILE)), \
         patch("token_updater.updater.profile_db.update_profile", AsyncMock()) as save, \
         patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()), \
         patch("token_updater.updater.dashboard_events.publish", AsyncMock()), \
         patch("token_updater.protocol_login.protocol_loginer.login", AsyncMock(return_value={"success": True, "session_token": "st"})), \
         patch.object(syncer, "_extract_token_with_timeout", AsyncMock()) as browser, \
         patch.object(syncer, "_push_to_flow2api", AsyncMock(return_value={"success": False, "error_code": code, "error": "safe"})) as push:
        result = await syncer._sync_profile(1)
    assert not result["success"]
    browser.assert_not_awaited()
    push.assert_awaited_once()
    assert all("google_cookies" not in c.kwargs for c in save.await_args_list)
    assert syncer.get_status()["total_sync_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 404, 405, 429, 503])
async def test_target_check_failure_does_not_force_full_source_login_batch(status):
    syncer = TokenSyncer()
    with patch("token_updater.updater.profile_db.get_active_profiles", AsyncMock(return_value=[PROFILE])), \
         patch("token_updater.updater.profile_db.update_profile", AsyncMock()), \
         patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()), \
         patch("token_updater.updater.dashboard_events.publish", AsyncMock()), \
         patch("token_updater.updater.httpx.AsyncClient", return_value=client_for(status, {"detail":"private-response"})), \
         patch.object(syncer, "_sync_profile", AsyncMock()) as sync:
        result = await syncer.sync_all_profiles()
    sync.assert_not_awaited()
    assert result["error_count"] == 1
    assert result["results"][0]["status_code"] == status
    assert f"HTTP {status}" in result["results"][0]["error"]
    assert "private-response" not in str(result)
    if status in (404, 405):
        assert "/api/plugin/check-tokens" in result["results"][0]["error"]


@pytest.mark.asyncio
async def test_raw_or_missing_cookies_never_submit_bare_flow_st_even_in_protocol_mode():
    syncer = TokenSyncer()
    with patch.object(config, "protocol_refresh_enabled", True), \
         patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value={**PROFILE, "google_cookies": "SID=legacy"})), \
         patch("token_updater.updater.profile_db.update_profile", AsyncMock()), \
         patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()), \
         patch("token_updater.updater.dashboard_events.publish", AsyncMock()), \
         patch("token_updater.protocol_login.protocol_loginer.login", AsyncMock()) as protocol, \
         patch.object(syncer, "_extract_token_with_timeout", AsyncMock(return_value="st")), \
         patch.object(syncer, "_push_to_flow2api", AsyncMock()) as push:
        result = await syncer._sync_profile(1)
    protocol.assert_not_awaited()
    push.assert_not_awaited()
    assert result["error_code"] == "cookies_incomplete"
