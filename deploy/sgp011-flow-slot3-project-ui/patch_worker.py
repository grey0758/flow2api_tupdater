"""Patch only the slot3 image's visible editor check for current Flow UI.

The deployed slot3 image contains distinct validators and browser overlays.
Keep its other bytes intact; take the tested editor marker constants and
accessibility method from this source checkout only after matching the pinned
base image file hash.
"""

import hashlib
from pathlib import Path
import sys


BASE_SHA256 = "77a09a4c93792f8c886b5ac18b88f186a14e5677fec8a6811c30d8d8fc0b427c"
SOURCE = Path(__file__).resolve().parents[2] / "token_updater/login_worker.py"


def section(text: str, start: str, end: str) -> str:
    assert text.count(start) == 1, start
    first = text.index(start)
    assert text.count(end, first) == 1, end
    return text[first:text.index(end, first)]


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: patch_worker.py BASE_FILE OUTPUT_FILE")
    original = Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(original).hexdigest() == BASE_SHA256
    old = original.decode("utf-8")
    current = SOURCE.read_text(encoding="utf-8")
    constants = section(
        current, "PROJECT_MEDIA_WORKSPACE_MARKERS = (",
        "GOOGLE_LOGIN_CHALLENGE_HOSTS = ",
    )
    old_method = section(
        old, "    async def _project_page_is_accessible(",
        "    @staticmethod\n    def _normalize_email",
    )
    new_method = section(
        current, "    async def _project_page_is_accessible(",
        "    @staticmethod\n    def _normalize_email",
    )
    assert "PROJECT_MEDIA_WORKSPACE_VI_MARKERS" in constants
    assert "has_vietnamese_workspace" in new_method
    assert "PROJECT_MEDIA_WORKSPACE_MARKERS" not in old
    assert "PROJECT_EDITOR_MARKERS" in old_method
    assert old.count(old_method) == 1
    assert old.count("\n\ndef _project_id_from_url(") == 1
    patched = old.replace(
        "\n\ndef _project_id_from_url(", "\n" + constants + "\ndef _project_id_from_url(", 1
    ).replace(old_method, new_method, 1)
    assert "validate_account_projects" in patched
    assert "_refresh_current_user_project_membership" in patched
    assert "configure_yescaptcha" in patched
    compile(patched, "login_worker.py", "exec")
    Path(sys.argv[2]).write_text(patched, encoding="utf-8")
    print(hashlib.sha256(patched.encode()).hexdigest())


if __name__ == "__main__":
    main()
