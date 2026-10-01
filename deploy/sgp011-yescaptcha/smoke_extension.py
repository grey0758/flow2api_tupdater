"""Prove the pinned extension loads in a disposable headed Chromium profile."""

import asyncio
import os
import subprocess
import tempfile
import time
from pathlib import Path

from playwright.async_api import async_playwright

from token_updater.browser_extensions import configure_yescaptcha, visible_browser_extension_options


EXPECTED_ID = "jiofmdifioeejeilfkpegipdjiopiekl"


async def main() -> None:
    mode = os.environ["YES_CAPTCHA_SMOKE_MODE"]
    extension = Path("/slot-extension" if mode == "worker" else "/vnc-extension")
    display = ":101" if mode == "worker" else ":102"
    xvfb = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1365x768x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            if Path(f"/tmp/.X11-unix/X{display[1:]}").exists():
                break
            if xvfb.poll() is not None:
                raise RuntimeError("Xvfb exited before browser test")
            time.sleep(0.1)
        else:
            raise RuntimeError("Xvfb did not start")

        with tempfile.TemporaryDirectory(prefix="yescaptcha-smoke-") as profile:
            browser_args = ["--disable-extensions", "--no-first-run", "--no-default-browser-check"]
            ignored_args = ["--enable-automation", "--no-sandbox", "--disable-dev-shm-usage"]
            if mode == "main":
                browser_args.extend(("--no-sandbox", "--disable-dev-shm-usage"))
                ignored_args = ["--enable-automation"]
            args, ignored = visible_browser_extension_options(
                browser_args,
                ignored_args,
                extension, required=True,
            )
            proxy = (
                {"server": "http://127.0.0.1:18088"}
                if os.getenv("YES_CAPTCHA_SMOKE_PROXY") == "1" else None
            )
            async with async_playwright() as playwright:
                context = await playwright.chromium.launch_persistent_context(
                    user_data_dir=profile,
                    headless=False,
                    env={"DISPLAY": display, "HOME": os.environ.get("HOME", "/tmp")},
                    args=args,
                    ignore_default_args=ignored,
                    proxy=proxy,
                )
                try:
                    workers = context.service_workers
                    if not workers:
                        workers = [await context.wait_for_event("serviceworker", timeout=15000)]
                    if not any(worker.url.startswith(f"chrome-extension://{EXPECTED_ID}/") for worker in workers):
                        raise RuntimeError("expected YesCaptcha service worker is absent")
                    await configure_yescaptcha(context)
                    print(f"{mode}: extension {EXPECTED_ID} key configured and API verified")
                finally:
                    await context.close()
    finally:
        xvfb.terminate()
        try:
            xvfb.wait(timeout=5)
        except subprocess.TimeoutExpired:
            xvfb.kill()
            xvfb.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())
