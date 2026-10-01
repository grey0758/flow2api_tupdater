"""Bounded, visible Google password and Authenticator login for one VNC slot.

No screenshots, URLs, credentials, or challenge text are returned to callers.
Unknown challenges stay in the same browser for owner review.
"""

import asyncio
import base64
import hashlib
import hmac
import re
import struct
import time
from urllib.parse import urlparse


GOOGLE_HOST = "accounts.google.com"


def totp_code(seed: str, now: float | None = None) -> str:
    normalized = re.sub(r"[\s-]", "", seed).upper()
    if not re.fullmatch(r"[A-Z2-7]{16,128}", normalized):
        raise ValueError("invalid TOTP seed")
    key = base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    counter = int(time.time() if now is None else now) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


async def _fill_once(page, selector: str, value: str, *, timeout: int = 20000) -> bool:
    field = page.locator(selector).first
    try:
        await field.wait_for(state="visible", timeout=timeout)
        if urlparse(page.url).hostname != GOOGLE_HOST:
            return False
        await field.fill(value)
        await field.press("Enter")
        return True
    except Exception:
        return False


async def login_google(context, email: str, password: str, seed: str, auth_url: str) -> str:
    """Return a safe stage code; never repeat password or TOTP on uncertainty."""
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or not password:
        return "credentials_invalid"
    page = await context.new_page()
    try:
        await page.goto(auth_url, wait_until="domcontentloaded", timeout=90000)
        if urlparse(page.url).hostname != GOOGLE_HOST:
            return "existing_session_or_review"
        if not await _fill_once(page, 'input[type="email"]', email):
            return "manual_action_required"
        if not await _fill_once(page, 'input[type="password"]', password):
            return "manual_action_required"
        for _ in range(30):
            if urlparse(page.url).hostname != GOOGLE_HOST:
                return "credentials_submitted"
            if "/challenge/totp" in urlparse(page.url).path.lower():
                break
            await asyncio.sleep(1)
        else:
            return "manual_action_required"
        # The route, not a generic one-time-code input, establishes that this
        # is Google's Authenticator challenge rather than SMS or a device code.
        selector = 'input[name="totpPin"], input[id="totpPin"]'
        field = page.locator(selector).first
        try:
            await field.wait_for(state="visible", timeout=10000)
            if 30 - (time.time() % 30) < 12:
                await asyncio.sleep(30 - (time.time() % 30) + 1)
            if "/challenge/totp" not in urlparse(page.url).path.lower():
                return "manual_action_required"
            await field.fill(totp_code(seed))
            await field.press("Enter")
        except Exception:
            return "manual_action_required"
        for _ in range(30):
            if urlparse(page.url).hostname != GOOGLE_HOST:
                return "credentials_submitted"
            await asyncio.sleep(1)
        return "manual_action_required"
    except Exception:
        return "login_navigation_review"
