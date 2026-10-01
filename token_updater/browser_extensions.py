"""Launch one reviewed unpacked extension in a visible VNC Chromium context."""

import json
import re
from pathlib import Path


YES_CAPTCHA_ID = "jiofmdifioeejeilfkpegipdjiopiekl"
YES_CAPTCHA_KEY_FILE = Path("/run/yescaptcha/client_key")


async def configure_yescaptcha(context, key_file: Path = YES_CAPTCHA_KEY_FILE) -> None:
    """Install the project key in this Chromium profile and verify the service."""
    # Retained Profiles can remember F11 fullscreen across Chromium launches.
    # Always restore a normal VNC window with tabs and the address bar visible.
    for page in context.pages:
        session = None
        try:
            session = await context.new_cdp_session(page)
            window = await session.send("Browser.getWindowForTarget")
            await session.send("Browser.setWindowBounds", {
                "windowId": window["windowId"], "bounds": {"windowState": "normal"},
            })
            await session.send("Browser.setWindowBounds", {
                "windowId": window["windowId"],
                "bounds": {"left": 8, "top": 8, "width": 1348, "height": 724},
            })
        except Exception:
            # Window-manager support must not block the required extension check.
            pass
        finally:
            if session is not None:
                await session.detach()
    try:
        key = key_file.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError("YesCaptcha runtime key is unavailable") from exc
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", key):
        raise RuntimeError("YesCaptcha runtime key is invalid")

    prefix = f"chrome-extension://{YES_CAPTCHA_ID}/"
    async def find_worker():
        for worker in context.service_workers:
            if worker.url.startswith(prefix):
                return worker
        for _ in range(3):
            worker = await context.wait_for_event("serviceworker", timeout=15000)
            if worker.url.startswith(prefix):
                return worker
        raise RuntimeError("YesCaptcha service worker did not start")

    worker = await find_worker()
    installed = await worker.evaluate("""async key => {
        const {config = {}} = await chrome.storage.local.get('config');
        await chrome.storage.local.set({config: {...config, clientKey: key}});
        const check = await chrome.storage.local.get('config');
        return check.config?.clientKey === key;
    }""", key)
    if not installed:
        raise RuntimeError("YesCaptcha key storage verification failed")
    result = await worker.evaluate("""async key => {
        if (chrome.runtime.id !== 'jiofmdifioeejeilfkpegipdjiopiekl')
            return {storage: false};
        const {config} = await chrome.storage.local.get('config');
        if (config?.clientKey !== key) return {storage: false};
        const response = await fetch('https://api.yescaptcha.com/getBalance', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({clientKey: key})
        });
        if (!response.ok) return {storage: true, api: false};
        const balance = await response.json();
        return {storage: true, api: balance.errorId === 0 &&
            typeof balance.balance === 'number'};
    }""", key)
    if not result.get("storage") or not result.get("api"):
        raise RuntimeError("YesCaptcha extension or key verification failed")


def visible_browser_extension_options(
    args: list[str], ignored_defaults: list[str], extension_dir: Path,
    *, required: bool = False,
) -> tuple[list[str], list[str]]:
    args = [arg for arg in args if arg not in ("--kiosk", "--start-fullscreen")]
    ignored_defaults = list(ignored_defaults)
    if not extension_dir.exists():
        if required:
            raise RuntimeError("required VNC extension mount is missing")
        return args, ignored_defaults
    if not extension_dir.is_dir() or extension_dir.is_symlink():
        raise RuntimeError("VNC extension mount is invalid")
    manifest = extension_dir / "manifest.json"
    if not manifest.exists():
        if required or any(path.name != ".gitkeep" for path in extension_dir.iterdir()):
            raise RuntimeError("VNC extension manifest.json is missing")
        return args, ignored_defaults
    if not manifest.is_file() or manifest.is_symlink():
        raise RuntimeError("VNC extension manifest must be a regular file")
    try:
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("VNC extension manifest is unreadable") from exc
    if not isinstance(metadata, dict) or metadata.get("manifest_version") != 3:
        raise RuntimeError("VNC extension requires a Chromium Manifest V3 bundle")
    if not isinstance(metadata.get("name"), str) or not isinstance(metadata.get("version"), str):
        raise RuntimeError("VNC extension manifest requires name and version")
    args = [arg for arg in args if arg != "--disable-extensions"]
    args.extend((
        f"--disable-extensions-except={extension_dir}",
        f"--load-extension={extension_dir}",
    ))
    if "--disable-extensions" not in ignored_defaults:
        ignored_defaults.append("--disable-extensions")
    return args, ignored_defaults
