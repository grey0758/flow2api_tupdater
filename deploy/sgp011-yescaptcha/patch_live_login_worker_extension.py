"""Add the VNC extension hook to an exact deployed login-worker source file.

The two production workers have different accepted project validators. Patch
each base image in place rather than replacing it with a checkout copy.
"""

import argparse
from pathlib import Path


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected one login-worker anchor, found {source.count(old)}")
    return source.replace(old, new, 1)


def patch(source: str) -> str:
    source = replace_once(
        source,
        "from .browser_profile import configure_web_only_profile\n",
        "from .browser_profile import configure_web_only_profile\n"
        "from .browser_extensions import configure_yescaptcha, visible_browser_extension_options\n",
    )
    source = replace_once(
        source,
        "        self.context = await self.playwright.chromium.launch_persistent_context(\n",
        "        browser_args, ignored_defaults = visible_browser_extension_options(\n"
        "            LOGIN_BROWSER_ARGS,\n"
        "            [\"--enable-automation\", \"--no-sandbox\", \"--disable-dev-shm-usage\"],\n"
        "            Path(\"/slot-extension\"), required=True,\n"
        "        )\n"
        "        self.context = await self.playwright.chromium.launch_persistent_context(\n",
    )
    source = replace_once(source, "            args=LOGIN_BROWSER_ARGS,\n", "            args=browser_args,\n")
    source = replace_once(
        source,
        "            ignore_default_args=[\n"
        "                \"--enable-automation\", \"--no-sandbox\", \"--disable-dev-shm-usage\",\n"
        "            ],\n",
        "            ignore_default_args=ignored_defaults,\n",
    )
    source = replace_once(
        source,
        "        self.context.on(\"response\", self._record_provider_project_response)\n",
        "        try:\n"
        "            await configure_yescaptcha(self.context)\n"
        "        except Exception:\n"
        "            await self.context.close()\n"
        "            self.context = None\n"
        "            raise\n"
        "        self.context.on(\"response\", self._record_provider_project_response)\n",
    )
    compile(source, "login_worker.py", "exec")
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    original = args.source.read_text(encoding="utf-8")
    args.source.write_text(patch(original), encoding="utf-8")


if __name__ == "__main__":
    main()
