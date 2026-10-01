import pytest

from token_updater import google_login_automation as module
from token_updater.google_login_automation import totp_code


def test_google_totp_matches_rfc6238_sha1_vector():
    # RFC 6238's 8-digit SHA1 output at 59 seconds is 94287082.
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59) == "287082"


def test_google_totp_rejects_malformed_seed():
    with pytest.raises(ValueError):
        totp_code("not a base32 seed")


@pytest.mark.asyncio
async def test_sms_challenge_remains_visible_without_totp_entry(monkeypatch):
    class Field:
        def __init__(self, page, kind):
            self.page = page
            self.kind = kind
            self.first = self
        async def wait_for(self, **kwargs):
            return None
        async def fill(self, value):
            self.page.filled.append((self.kind, value))
        async def press(self, key):
            self.page.url = (
                "https://accounts.google.com/signin/v2/challenge/pwd"
                if self.kind == "email" else
                "https://accounts.google.com/signin/v2/challenge/ipp"
            )
    class Page:
        url = ""
        def __init__(self):
            self.filled = []
        async def goto(self, url, **kwargs):
            self.url = "https://accounts.google.com/signin/v2/identifier"
        def locator(self, selector):
            return Field(self, "email" if 'type="email"' in selector else
                         "password" if 'type="password"' in selector else "totp")
    page = Page()
    class Context:
        async def new_page(self):
            return page
    async def no_delay(_):
        return None
    monkeypatch.setattr(module.asyncio, "sleep", no_delay)
    result = await module.login_google(
        Context(),
        "owner@example.invalid", "private", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "https://labs.google/fx/api/auth/signin",
    )
    assert result == "manual_action_required"
    assert [kind for kind, _ in page.filled] == ["email", "password"]
    assert page.url.endswith("/challenge/ipp")
