"""Bounded sgp011-only preparation for existing Flow ID11/profile2 login.

Run as root on sgp011 after deploying the reviewed recovery Compose. This
script does not read or copy browser storage, Flow tokens, or NewAPI data.
"""

import base64
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import urllib.request


ROOT = Path("/opt/flow2api-token-updater-v34")
DATABASE = ROOT / "data/profiles.db"
PROFILE = ROOT / "profiles/profile_2"
FLOW_DB = Path("/opt/flow2api/data/flow.db")
ENV = ROOT / ".env.login-slot3-id11"
BACKUPS = Path("/home/grey/backups")
WORKER_IMAGE = "flow2api-token-updater-slot3-worker:id11-recovery-20260921"
SIDECAR_IMAGE = "flow2api-token-updater-slot3-sidecar:id11-recovery-20260921"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def sqlite_ro(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)


def api(path, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:18083{path}", data=data, headers=headers,
        method="GET" if data is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def main():
    require(os.geteuid() == 0, "root required")
    require(not ENV.exists(), "recovery environment already exists")
    require(PROFILE.is_dir() and not PROFILE.is_symlink(), "profile2 path mismatch")
    require(PROFILE.stat().st_uid == 0, "profile2 unexpected owner")
    require(any(PROFILE.iterdir()), "profile2 is unexpectedly empty")
    require(run("lsb_release", "-is").strip() == "Ubuntu", "host is not Ubuntu")
    require(run("uname", "-m").strip() == "x86_64", "unexpected architecture")
    for db_path in (DATABASE, FLOW_DB):
        with sqlite_ro(db_path) as db:
            require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "sqlite integrity failure")
    with sqlite_ro(DATABASE) as db:
        row = db.execute(
            "SELECT name,is_active,is_logged_in,login_slot_claimed,login_slot_handoff_complete "
            "FROM profiles WHERE id=2"
        ).fetchone()
        slots = db.execute(
            "SELECT id,login_slot_claimed,login_slot_handoff_complete "
            "FROM profiles WHERE id IN (12,13) ORDER BY id"
        ).fetchall()
    require(row == ("sgp011-schedulable4-modern", 1, 0, 0, 0), "profile2 state differs")
    require(slots == [(12, 1, 0), (13, 1, 0)], "login slots 1/2 state differs")
    require(PROFILE.stat().st_gid == 0, "profile2 group differs")
    require(not list(PROFILE.glob("Singleton*")), "profile2 browser lock present")
    require(
        not any(
            b"--user-data-dir=/app/profiles/profile_2" in cmdline
            for entry in Path("/proc").iterdir() if entry.name.isdigit()
            for cmdline in [read_cmdline(entry)]
        ), "profile2 may have an active browser",
    )
    # The two preserved owner workers both call their private volume
    # /slot/profile. That generic in-container path must not be mistaken for
    # profile2. Instead fail only if any current container mounts the exact
    # profile2 host source.
    running = run("docker", "ps", "-q").split()
    if running:
        inspected = json.loads(run("docker", "inspect", *running))
        require(
            not any(
                mount.get("Source") == str(PROFILE)
                for container in inspected for mount in container.get("Mounts", [])
            ), "profile2 is already mounted by a container",
        )
    for image in (WORKER_IMAGE, SIDECAR_IMAGE):
        require(run("docker", "image", "inspect", "--format", "{{.Id}}", image).startswith("sha256:"),
                "recovery image unavailable")
    for name in ("flow-login-worker-3", "flow-login-slot3-sidecar", "flow-login-egress-3"):
        require(subprocess.run(["docker", "container", "inspect", name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0,
                "prior slot3 container still present")
    original_container = run("docker", "inspect", "--format", "{{.Id}}", "sgp011-flow2api-token-updater-v34").strip()
    original_workers = {
        name: run("docker", "inspect", "--format", "{{.Id}}", name).strip()
        for name in ("flow-login-worker-1", "flow-login-worker-2")
    }
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUPS / f"sgp011-id11-login-slot3-{timestamp}"
    backup.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(backup, 0o700)
    with sqlite_ro(DATABASE) as source, sqlite3.connect(backup / "profiles.db") as target:
        source.backup(target)
        require(target.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "backup failed")
    os.chmod(backup / "profiles.db", 0o600)
    metadata = {
        "main_container_id": original_container,
        "worker_ids": original_workers,
        "profile2_pre": {"active": True, "logged_in": False},
        "slot_profile_ids": [12, 13],
        "browser_profile_path": str(PROFILE),
        "backup_kind": "updater_sqlite_only_no_browser_storage",
    }
    (backup / "boundary.json").write_text(json.dumps(metadata, sort_keys=True) + "\n")
    os.chmod(backup / "boundary.json", 0o600)
    # Generate a fresh Ed25519 control key in the existing local worker image;
    # capture both values only in process memory and write them to a root-only
    # Compose env file. Never print or log key bytes.
    key_script = (
        "import base64,json;"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
        "from cryptography.hazmat.primitives import serialization as s;"
        "k=Ed25519PrivateKey.generate();"
        "e=lambda v:base64.urlsafe_b64encode(v).decode().rstrip('=');"
        "print(json.dumps({'private':e(k.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption())),"
        "'public':e(k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw))}))"
    )
    keys = json.loads(run("docker", "run", "--rm", "--network", "none", "--entrypoint", "python",
                          WORKER_IMAGE, "-c", key_script))
    admin = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    env_lines = [
        "LOGIN_SLOT3_PROFILE_ID=2", "LOGIN_SLOT3_RECOVER_EXISTING=1",
        "LOGIN_SLOT3_PROFILE_SOURCE=/opt/flow2api-token-updater-v34/profiles/profile_2",
        f"LOGIN_SLOT3_WORKER_IMAGE={WORKER_IMAGE}",
        f"LOGIN_SLOT3_SIDECAR_IMAGE={SIDECAR_IMAGE}",
        f"LOGIN_SLOT3_SIGNING_PRIVATE_KEY={keys['private']}",
        f"LOGIN_SLOT3_SIGNING_PUBLIC_KEY={keys['public']}",
        f"LOGIN_SLOT3_ADMIN_TOKEN={admin}",
    ]
    fd = os.open(ENV, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write("\n".join(env_lines) + "\n")
    os.chmod(ENV, 0o600)
    # The supported Updater API deactivates only profile2. The scheduler will
    # no longer touch its persistent browser state during owner authorization.
    password = run("docker", "exec", "sgp011-flow2api-token-updater-v34", "python", "-c",
                   "import os;print(os.environ['ADMIN_PASSWORD'])").strip()
    token = api("/api/login", {"password": password})["token"]
    try:
        request = urllib.request.Request(
            "http://127.0.0.1:18083/api/profiles/2", data=b'{"is_active":false}',
            method="PUT", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            require(json.loads(response.read()).get("success"), "supported deactivate failed")
    finally:
        api("/api/logout", {}, token)
    with sqlite_ro(DATABASE) as db:
        require(db.execute("SELECT is_active FROM profiles WHERE id=2").fetchone()[0] == 0,
                "profile2 is still active")
    # All existing entries are root-owned, confirmed above. The exact
    # profile2 directory alone becomes worker-owned; no other profile moves.
    run("chown", "-R", "11003:12000", "--", str(PROFILE))
    os.chmod(PROFILE, 0o700)
    require(PROFILE.stat().st_uid == 11003, "profile2 worker ownership failed")
    print("prepared=true backup=" + str(backup) + " profile2_inactive=true slot12_13_untouched=true")


def read_cmdline(entry):
    try:
        return (entry / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return b""


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("prepare_failed=" + type(exc).__name__ + ":" + str(exc), file=sys.stderr)
        raise SystemExit(1)
