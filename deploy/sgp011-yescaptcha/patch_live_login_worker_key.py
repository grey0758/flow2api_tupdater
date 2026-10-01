"""Add key injection to the deployed worker without replacing slot validators."""

import argparse
from pathlib import Path


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"expected one worker anchor, found {source.count(old)}")
    return source.replace(old, new, 1)


def patch(source: str) -> str:
    source = replace_once(
        source,
        "from .browser_extensions import visible_browser_extension_options\n",
        "from .browser_extensions import configure_yescaptcha, visible_browser_extension_options\n",
    )
    source = replace_once(
        source,
        '        self.context.on("response", self._record_provider_project_response)\n',
        "        try:\n"
        "            await configure_yescaptcha(self.context)\n"
        "        except Exception:\n"
        "            await self.context.close()\n"
        "            self.context = None\n"
        "            raise\n"
        '        self.context.on("response", self._record_provider_project_response)\n',
    )
    compile(source, "login_worker.py", "exec")
    return source


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    original = args.source.read_text(encoding="utf-8")
    args.source.write_text(patch(original), encoding="utf-8")
