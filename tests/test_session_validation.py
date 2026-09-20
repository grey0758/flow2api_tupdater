from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from token_updater.browser import BrowserManager
from token_updater.config import config
from token_updater.session_validation import (
    LABS_SESSION_URL, CREDITS_URL, failure, scoped_google_cookies,
    validate_google_cookies, validate_labs_session, validate_credits,
)

NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
PROFILE = {"id": 1, "name": "test", "email": "user@example.com"}
JAR = [{"name": "SID", "value": "root", "domain": ".google.com", "path": "/"},
       {"name": "OSID", "value": "flow", "domain": "flow.google.com", "path": "/"}]


def session(**changes):
    return {"access_token": "test-at", "expires": "2099-01-01T00:00:00Z",
            "user": {"email": "user@example.com"}, **changes}


@pytest.mark.parametrize("expires", [None, "", "not-a-date", 123, "2026-09-08T12:07:17Z",
                                    "2026-09-09T00:00:30Z", "2026-09-09T08:00:00+08:00"])
def test_missing_expired_or_about_to_expire_session_is_rejected(expires):
    assert validate_labs_session(session(expires=expires), now=NOW)["error_code"] == "auth_required"


@pytest.mark.parametrize("payload", [None, [], {}, session(access_token=""), session(user={}), session(error="RefreshAccessTokenError")])
def test_invalid_session_shape(payload):
    assert not validate_labs_session(payload, now=NOW)["success"]


def test_email_and_expiry_validation():
    assert validate_labs_session(session(), "USER@example.com", now=NOW)["success"]
    assert validate_labs_session(session(expires="2099-01-01T00:00:00"), now=NOW)["success"]
    assert validate_labs_session(session(), "wrong@example.com", now=NOW)["error_code"] == "identity_mismatch"


@pytest.mark.parametrize("status,data,code", [(401, {}, "auth_required"), (429, {}, "verification_unavailable"),
    (503, {}, "verification_unavailable"), (403, {}, "verification_unavailable"),
    (200, {"credits": True}, "verification_unavailable"), (200, {"credits": -1}, "verification_unavailable"),
    (200, {"credits": float("nan")}, "verification_unavailable"), (200, {}, "verification_unavailable")])
def test_credits_validation(status, data, code):
    assert validate_credits(status, data)["error_code"] == code


def test_zero_balance_still_proves_authentication():
    assert validate_credits(200, {"credits": 0})["success"]


def test_observed_zero_balance_may_omit_credits_scalar():
    data={"serviceTier":"SERVICE_TIER_INTERMEDIATE", "sku":"G1_TIER1", "userPaygateTier":"PAYGATE_TIER_ONE"}
    assert validate_credits(200, data)["success"]
    assert "credits" not in data
    for invalid in [{**data, "error":{}}, {**data,"sku":""},
                    {**data,"serviceTier":None}, {**data,"credits":None}]:
        assert not validate_credits(200, invalid)["success"]
    for status in [401,403,429,503]:
        assert not validate_credits(status,data)["success"]


def test_secure_psid_only_snapshot_is_incomplete():
    partial = [{**c, "name": "__Secure-1PSID"} if c["name"] == "SID" else c for c in JAR]
    assert validate_google_cookies(partial)["error_code"] == "cookies_incomplete"


@pytest.mark.parametrize("change", [{"domain": "google.com"}, {"value": ""}, {"path": "/other"},
    {"expires": 1}, {"expires": 0}, {"expires": "bad"}, {"partitionKey": "https://other.test"}])
def test_incomplete_scoped_cookie_snapshot(change):
    jar = scoped_google_cookies([{**JAR[0], **change}, JAR[1]])
    assert not validate_google_cookies(jar)["success"]


def test_cookie_filter_keeps_scopes_and_does_not_revive_expired_values():
    jar = scoped_google_cookies([*JAR, *JAR, None, "bad", {**JAR[0], "domain": ".evil.test"},
                                {"name": "expired", "value": "bad", "domain": ".google.com", "expirationDate": 1}])
    assert jar == JAR
    assert validate_google_cookies(jar)["success"]


def response(status, data):
    return SimpleNamespace(status=status, json=AsyncMock(return_value=data), dispose=AsyncMock())


def context_for(payload, credit_status=200, credit_data=None):
    replies = [response(200, payload), response(credit_status, {"credits": 0} if credit_data is None else credit_data)]
    request = SimpleNamespace(get=AsyncMock(side_effect=replies))
    cookies = AsyncMock(return_value=[{"name": config.session_cookie_name + ".0", "value": "rotated-", "domain": "labs.google"},
                                     {"name": config.session_cookie_name + ".1", "value": "token", "domain": "labs.google"}])
    return SimpleNamespace(request=request, cookies=cookies), replies


@pytest.mark.asyncio
async def test_browser_checks_on_source_context_and_reads_rotated_chunked_st():
    context, replies = context_for(session())
    result = await BrowserManager()._validate_context_session(context, PROFILE["email"])
    assert result == {"success": True, "session_token": "rotated-token", "email": PROFILE["email"]}
    assert [c.args[0] for c in context.request.get.await_args_list] == [LABS_SESSION_URL, CREDITS_URL]
    assert all(c.kwargs["max_redirects"] == 0 for c in context.request.get.await_args_list)
    context.cookies.assert_awaited_once_with(LABS_SESSION_URL)
    for reply in replies:
        reply.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_expired_session_never_reaches_credits_or_cookie_success():
    context, _ = context_for(session(expires="2026-09-08T12:07:17Z"))
    assert (await BrowserManager()._validate_context_session(context))["error_code"] == "auth_required"
    assert context.request.get.await_count == 1
    context.cookies.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status,code", [(401, "auth_required"), (429, "verification_unavailable"), (503, "verification_unavailable")])
async def test_browser_rejects_revoked_at_and_transient_upstream(status, code):
    context, _ = context_for(session(), credit_status=status)
    assert (await BrowserManager()._validate_context_session(context))["error_code"] == code
    context.cookies.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["verification_unavailable", "identity_mismatch"])
async def test_non_auth_failure_does_not_start_reauthorization(code):
    manager = BrowserManager()
    with patch.object(manager, "_validate_context_session", AsyncMock(return_value=failure(code, "safe"))), \
         patch.object(manager, "_start_labs_authorization", AsyncMock()) as start:
        assert not (await manager._ensure_labs_authorization(PROFILE, None, None))["success"]
    start.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_oauth_gets_one_bounded_source_signin():
    manager = BrowserManager()
    valid = {"success": True, "session_token": "fresh", "email": PROFILE["email"]}
    with patch.object(manager, "_validate_context_session", AsyncMock(side_effect=[failure("auth_required", "expired"), valid])) as check, \
         patch.object(manager, "_start_labs_authorization", AsyncMock(return_value=True)) as start, \
         patch.object(manager, "_settle_labs_session", AsyncMock()):
        assert await manager._ensure_labs_authorization(PROFILE, None, None) == valid
    start.assert_awaited_once()
    assert check.await_count == 2


@pytest.mark.asyncio
async def test_reauthorization_does_not_loop_when_still_expired():
    manager = BrowserManager()
    with patch.object(manager, "_validate_context_session", AsyncMock(return_value=failure("auth_required", "expired"))), \
         patch.object(manager, "_start_labs_authorization", AsyncMock(return_value=True)) as start, \
         patch.object(manager, "_settle_labs_session", AsyncMock()):
        assert not (await manager._ensure_labs_authorization(PROFILE, None, None))["success"]
    start.assert_awaited_once()


@pytest.mark.asyncio
async def test_cookie_failure_never_persists_logged_in_success():
    manager = BrowserManager()
    page = SimpleNamespace(url="https://flow.google.com/")
    with patch.object(manager, "_ensure_labs_authorization", AsyncMock(return_value={"success": True, "email": PROFILE["email"]})), \
         patch.object(manager, "_wait_for_flow_cookies", AsyncMock()), \
         patch.object(manager, "_save_google_cookies_from_context", AsyncMock(return_value=False)), \
         patch.object(manager, "_persist_login_state", AsyncMock()) as persist:
        assert await manager._complete_flow_session(PROFILE, None, page) is None
    persist.assert_awaited_once_with(1, None)


@pytest.mark.asyncio
async def test_enabled_but_invalid_proxy_never_falls_back_to_direct():
    with pytest.raises(ValueError, match="代理"):
        await BrowserManager()._get_proxy({**PROFILE, "proxy_enabled": True, "proxy_url": ""})


@pytest.mark.asyncio
async def test_source_errors_do_not_expose_credentials():
    context = SimpleNamespace(request=SimpleNamespace(get=AsyncMock(side_effect=RuntimeError("Bearer secret credential"))))
    result = await BrowserManager()._validate_context_session(context)
    assert "secret" not in str(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("target,allowed", [
    ("https://accounts.google.com/o/oauth2/auth?state=test", True),
    ("https://accounts.google.com.evil.test/auth", False),
    ("http://accounts.google.com/auth", False),
    ("https://user:pass@accounts.google.com/auth", False),
    ("https://accounts.google.com:8443/auth", False),
])
async def test_source_signin_uses_csrf_and_validates_google_redirect(target, allowed):
    context = SimpleNamespace(request=SimpleNamespace(
        get=AsyncMock(return_value=response(200, {"csrfToken": "csrf"})),
        post=AsyncMock(return_value=response(200, {"url": target})),
    ))
    page = SimpleNamespace(goto=AsyncMock())
    assert await BrowserManager()._start_labs_authorization(context, page) is allowed
    assert context.request.post.await_args.kwargs["form"]["csrfToken"] == "csrf"
    assert context.request.post.await_args.kwargs["max_redirects"] == 0
    assert page.goto.await_count == int(allowed)


@pytest.mark.asyncio
async def test_flow_landing_page_is_not_an_authenticated_session():
    manager = BrowserManager()
    with patch.object(manager, "_ensure_labs_authorization", AsyncMock(return_value={"success": True, "email": PROFILE["email"], "session_token": "st"})), \
         patch.object(manager, "_wait_for_flow_cookies", AsyncMock()), \
         patch.object(manager, "_save_google_cookies_from_context", AsyncMock()) as save, \
         patch.object(manager, "_persist_login_state", AsyncMock()):
        assert await manager._complete_flow_session(PROFILE, None, SimpleNamespace(url="https://flow.google.com/about")) is None
    save.assert_not_awaited()
    assert manager.get_session_error(1)["error_code"] == "cookies_incomplete"


@pytest.mark.asyncio
async def test_peek_requires_both_sessions_without_starting_signin():
    manager = BrowserManager()
    context = SimpleNamespace(cookies=AsyncMock(return_value=[JAR[0]]))
    with patch.object(manager, "_validate_context_session", AsyncMock(return_value={"success": True, "email": PROFILE["email"], "session_token": "st"})), \
         patch.object(manager, "_start_labs_authorization", AsyncMock()) as signin:
        assert await manager._peek_context_session(PROFILE, context) is None
    signin.assert_not_awaited()
    assert manager.get_session_error(1)["error_code"] == "cookies_incomplete"


@pytest.mark.asyncio
async def test_flow_navigation_cannot_switch_the_verified_identity():
    manager = BrowserManager()
    with patch.object(manager, "_ensure_labs_authorization", AsyncMock(return_value={"success": True, "email": PROFILE["email"], "session_token": "original"})), \
         patch.object(manager, "_wait_for_flow_cookies", AsyncMock()), \
         patch.object(manager, "_save_google_cookies_from_context", AsyncMock(return_value=True)), \
         patch.object(manager, "_get_session_cookie", AsyncMock(return_value="rotated")), \
         patch.object(manager, "_validate_context_session", AsyncMock(return_value=failure("identity_mismatch", "wrong account"))) as validate, \
         patch.object(manager, "_persist_login_state", AsyncMock()) as persist:
        assert await manager._complete_flow_session(PROFILE, None, SimpleNamespace(url="https://flow.google.com/")) is None
    validate.assert_awaited_once_with(None, PROFILE["email"])
    persist.assert_awaited_once_with(1, None)
