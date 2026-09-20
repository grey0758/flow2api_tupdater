import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from curl_cffi.requests.cookies import Cookies

from token_updater.config import config
from token_updater.protocol_login import ProtocolLogin, _session_token_from_values
from token_updater.session_validation import LABS_SESSION_URL, CREDITS_URL

JAR = [{"name": "SID", "value": "root", "domain": ".google.com", "path": "/", "expires": 4070908800},
       {"name": "OSID", "value": "flow", "domain": "flow.google.com", "path": "/"}]


class FakeSession:
    def __init__(self, payload=None, credits_status=200):
        self.cookies = Cookies()
        self.payload = payload if payload is not None else {"access_token": "at", "expires": "2099-01-01T00:00:00Z", "user": {"email": "user@example.com"}}
        self.credits_status = credits_status
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        data, headers, status = {}, {}, 200
        if url.endswith("/csrf"):
            data = {"csrfToken": "csrf"}
        elif url.startswith("https://accounts.google.com/"):
            headers = {"location": "https://labs.google/fx/api/auth/callback/google?code=private-code"}
            status = 302
        elif "/callback/" in url:
            self.cookies.set(config.session_cookie_name + ".0", "first", domain="labs.google", secure=True)
            self.cookies.set(config.session_cookie_name + ".1", "second", domain="labs.google", secure=True)
            headers = {"location": "https://labs.google/fx"}
            status = 302
        elif url == LABS_SESSION_URL:
            data = self.payload
            self.cookies.set(config.session_cookie_name + ".1", "rotated", domain="labs.google", secure=True)
            self.cookies.set("SID", "rotated-root", domain=".google.com")
        elif url == CREDITS_URL:
            data, status = {"credits": 0}, self.credits_status
        return SimpleNamespace(status_code=status, json=lambda: data, headers=headers, text="")

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return SimpleNamespace(status_code=200, headers={}, json=lambda: {"url": "https://accounts.google.com/o/oauth2/auth"})


@pytest.mark.asyncio
async def test_protocol_verifies_and_exports_rotated_scoped_cookies():
    session = FakeSession()
    with patch("token_updater.protocol_login.AsyncSession", return_value=session) as factory:
        result = await ProtocolLogin().login(json.dumps(JAR), proxy="socks5://127.0.0.1:20020", email="user@example.com")
    assert result["success"]
    assert result["session_token"] == "firstrotated"
    assert any(c["name"] == "SID" and c["value"] == "rotated-root" for c in result["google_cookies"])
    assert any(c["name"] == "OSID" and c["domain"] == "flow.google.com" for c in result["google_cookies"])
    assert factory.call_args.kwargs["proxy"] == "socks5://127.0.0.1:20020"
    assert factory.call_args.kwargs["trust_env"] is False
    assert all("Cookie" not in kwargs.get("headers", {}) for _, kwargs in session.calls)
    assert all(kwargs.get("allow_redirects") is False for _, kwargs in session.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload,status,code", [
    ({"access_token": "at", "expires": "2026-09-08T12:07:17Z", "user": {"email": "user@example.com"}}, 200, "auth_required"),
    (None, 401, "auth_required"), (None, 503, "verification_unavailable"),
    ({"access_token": "at", "expires": "2099-01-01T00:00:00Z", "user": {"email": "other@example.com"}}, 200, "identity_mismatch"),
])
async def test_protocol_st_cookie_is_not_proof_of_valid_authorization(payload, status, code):
    session = FakeSession(payload, status)
    with patch("token_updater.protocol_login.AsyncSession", return_value=session):
        result = await ProtocolLogin().login(json.dumps(JAR), email="user@example.com")
    assert result["error_code"] == code
    assert "session_token" not in result


@pytest.mark.asyncio
async def test_expired_structured_cookies_are_not_revived_as_flat_session_cookies():
    with patch("token_updater.protocol_login.AsyncSession") as factory:
        result = await ProtocolLogin().login(json.dumps([{**JAR[0], "expires": 1}]))
    assert result["error_code"] == "auth_required"
    factory.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_source_proxy_is_not_silently_ignored():
    with patch("token_updater.protocol_login.AsyncSession") as factory:
        result = await ProtocolLogin().login(json.dumps(JAR), proxy="invalid")
    assert result["error_code"] == "source_proxy"
    factory.assert_not_called()


def test_chunked_cookie_requires_contiguous_numeric_chunks():
    name = config.session_cookie_name
    assert _session_token_from_values({name + ".1": "b", name + ".0": "a"}) == "ab"
    assert _session_token_from_values({name + ".1": "b"}) is None
