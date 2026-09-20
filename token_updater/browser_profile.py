"""Keep dedicated automation profiles web-authenticated, not Chrome-sync accounts.

DICE OAuth outages can leave web cookies without browser refresh tokens. Account
reconciliation after a restart can then remove those cookies. Disable browser
sign-in only for profiles with no existing Chrome account; website login, cookies,
device-bound sessions and reCAPTCHA remain enabled.
"""
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from contextlib import closing


def configure_web_only_profile(profile_dir):
    path = Path(profile_dir) / "Default" / "Preferences"
    state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(state, dict) or not isinstance(state.get("signin", {}), dict):
        raise ValueError("Invalid browser preferences; refusing to overwrite")
    services = state.get("google", {}).get("services", {})
    if state.get("account_info") or services.get("account_id"):
        return "preserved_browser_account"
    web_data = path.parent / "Web Data"
    if web_data.exists():
        with closing(sqlite3.connect(web_data.resolve().as_uri() + "?mode=ro", uri=True)) as database:
            table = database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='token_service'").fetchone()
            if table and database.execute("SELECT 1 FROM token_service LIMIT 1").fetchone():
                return "preserved_browser_account"
    signin = state.setdefault("signin", {})
    if signin.get("allowed") is False and signin.get("allowed_on_next_startup") is False:
        return "unchanged"
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.parent / ".tupdater-browser-signin-backup.json"
    try:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({key: signin[key] for key in ("allowed", "allowed_on_next_startup") if key in signin}, stream)
    signin.update(allowed=False, allowed_on_next_startup=False)
    fd, temporary = tempfile.mkstemp(prefix=".web-only-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return "configured"
