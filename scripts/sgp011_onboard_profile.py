#!/usr/bin/env python3
"""Safely bind one completed sgp011 login-slot Profile exactly once.

The command intentionally stops at a disabled Flow token pending an isolated
image gate.  It never enables the account, sends an image, dumps NewAPI, or
prints provider identity, project, cookies, sessions, or service credentials.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


UPDATER_DB = Path("/opt/flow2api-token-updater-v34/data/profiles.db")
FLOW_DB = Path("/opt/flow2api/data/flow.db")
BACKUP_ROOT = Path("/home/grey/backups")
LOCK_PATH = Path("/run/lock/sgp011-flow-onboard.lock")
UPDATER_CONTAINER = "sgp011-flow2api-token-updater-v34"
MYSQL_CONTAINER = "sgp011-video-newapi-mysql"


class OperatorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def open_ro(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def select_profile_id(requested: int | None) -> int:
    connection = open_ro(UPDATER_DB)
    try:
        if requested is not None:
            row = connection.execute(
                "SELECT id FROM profiles WHERE id=?", (requested,)
            ).fetchone()
            if not row:
                raise OperatorError("profile_missing", "指定 Profile 不存在")
            return int(row["id"])
        rows = connection.execute(
            """
            SELECT id FROM profiles
             WHERE is_active=0 AND sync_count=0 AND login_slot_claimed=1
             ORDER BY id
            """
        ).fetchall()
        if len(rows) != 1:
            raise OperatorError(
                "pending_profile_ambiguous",
                "未登录或候选 Profile 不是唯一一个；请显式传入 Profile ID",
            )
        return int(rows[0]["id"])
    finally:
        connection.close()


def profile_state(profile_id: int) -> dict[str, Any]:
    connection = open_ro(UPDATER_DB)
    try:
        row = connection.execute(
            "SELECT * FROM profiles WHERE id=?", (profile_id,)
        ).fetchone()
        if not row:
            raise OperatorError("profile_missing", "指定 Profile 不存在")
        return {
            "profile_id": profile_id,
            "identity": str(row["email"] or "").strip().lower(),
            "project_identity": str(
                row["observed_flow_project_identity"] or ""
            ).strip().lower(),
            "project_id": str(row["observed_flow_project_id"] or "").strip(),
            "active": bool(row["is_active"]),
            "logged_in": bool(row["is_logged_in"]),
            "sync_count": int(row["sync_count"] or 0),
            "error_count": int(row["error_count"] or 0),
            "last_sync_result": str(row["last_sync_result"] or ""),
            "slot_claimed": bool(row["login_slot_claimed"]),
            "handoff_complete": bool(row["login_slot_handoff_complete"]),
            "project_verified": bool(row["observed_flow_project_verified"]),
            "token_present": bool(row["last_token"]),
            "cookies_present": bool(row["google_cookies"]),
        }
    finally:
        connection.close()


def require_fresh_candidate(state: dict[str, Any], *, extracted: bool) -> None:
    if state["active"] or state["sync_count"] != 0 or state["error_count"] != 0:
        raise OperatorError(
            "candidate_not_fresh",
            "Profile 已激活、同步或记录错误；禁止自动重放新账号流程",
        )
    if not state["slot_claimed"]:
        raise OperatorError(
            "candidate_not_slot_bound", "Profile 不是隔离登录槽位创建的候选账号"
        )
    if extracted and not (
        state["handoff_complete"]
        and state["logged_in"]
        and state["project_verified"]
        and state["identity"]
        and state["identity"] == state["project_identity"]
        and state["project_id"]
        and state["token_present"]
        and state["cookies_present"]
    ):
        raise OperatorError(
            "candidate_not_validated",
            "Profile 尚未完成同身份项目验证和会话提取；未向目标写入",
        )


CONTAINER_HELPER = r'''
import json, os, sys, urllib.error, urllib.request
from token_updater.config import config

mode, profile_id = sys.argv[1], int(sys.argv[2])
base = "http://127.0.0.1:8002"
def call(path, method="GET", payload=None, token=None, timeout=360):
    headers = {}; body = None
    if payload is not None:
        body = json.dumps(payload).encode(); headers["content-type"] = "application/json"
    if token: headers["authorization"] = "Bearer " + token
    request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.load(response)

session = None
try:
    _, login = call("/api/login", "POST", {"password": config.admin_password})
    session = login["token"]
    if mode == "check":
        status, result = call(f"/api/profiles/{profile_id}/check-login", "POST", {}, session)
        keys = ("success", "is_logged_in", "has_flow_project", "error_code")
    elif mode == "extract":
        status, result = call(f"/api/profiles/{profile_id}/extract", "POST", {}, session)
        result = {"success": bool(result.get("success")), "token_present": bool(result.get("token_length"))}
        keys = ("success", "token_present")
    elif mode == "onboard":
        status, result = call(
            f"/api/profiles/{profile_id}/onboarding-sync", "POST",
            {"backup_confirmed": True}, session,
        )
        keys = (
            "success", "action", "oauth_verified", "project_context_accepted",
            "project_reused", "project_owned", "pending_enable", "account_active",
            "needs_refresh", "token_id", "error_code", "pending_image_acceptance",
        )
    else:
        raise RuntimeError("unsupported helper mode")
    safe = {key: result.get(key) for key in keys if key in result}
    safe["http"] = status
    print(json.dumps(safe, sort_keys=True))
except urllib.error.HTTPError as error:
    print(json.dumps({"http": error.code, "success": False, "error_code": "api_rejected"}, sort_keys=True))
    raise SystemExit(1)
except Exception:
    print(json.dumps({"http": 0, "success": False, "error_code": "helper_failed"}, sort_keys=True))
    raise SystemExit(1)
finally:
    if session:
        try: call("/api/logout", "POST", {}, session, 10)
        except Exception: pass
'''


def updater_call(mode: str, profile_id: int) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "exec", "-i", UPDATER_CONTAINER, "python", "-", mode, str(profile_id)],
        input=CONTAINER_HELPER,
        text=True,
        capture_output=True,
        timeout=480,
        check=False,
    )
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        raise OperatorError("updater_helper_failed", "Updater 管理操作未返回有效结果")
    if result.returncode != 0 or payload.get("http") != 200:
        raise OperatorError(
            str(payload.get("error_code") or "updater_api_rejected"),
            f"Updater {mode} 操作失败；未自动重试",
        )
    return payload


def dedupe_state(state: dict[str, Any]) -> dict[str, int]:
    connection = open_ro(FLOW_DB)
    try:
        identity_matches = connection.execute(
            "SELECT count(*) FROM tokens WHERE lower(trim(email))=?",
            (state["identity"],),
        ).fetchone()[0]
        token_project_matches = connection.execute(
            "SELECT count(*) FROM tokens WHERE trim(current_project_id)=?",
            (state["project_id"],),
        ).fetchone()[0]
        project_rows = connection.execute(
            "SELECT count(*) FROM projects WHERE trim(project_id)=?",
            (state["project_id"],),
        ).fetchone()[0]
        return {
            "identity_matches": int(identity_matches),
            "token_project_matches": int(token_project_matches),
            "project_rows": int(project_rows),
        }
    finally:
        connection.close()


def newapi_boundary() -> dict[str, int]:
    query = (
        'SELECT COALESCE(MAX(id),0) FROM logs; '
        "SELECT COUNT(*) FROM tasks WHERE status IS NULL OR status NOT IN ('SUCCESS','FAILURE'); "
        'SELECT COUNT(*) FROM tokens WHERE id=67 AND status=1 AND deleted_at IS NULL; '
        'SELECT COUNT(*) FROM channels WHERE id=8 AND status=1;'
    )
    result = subprocess.run(
        [
            "docker", "exec", MYSQL_CONTAINER, "sh", "-lc",
            'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -D newapi -Nse "$1" 2>/dev/null',
            "sh", query,
        ],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise OperatorError("newapi_boundary_failed", "无法读取 NewAPI 只读边界")
    try:
        values = [int(line.strip()) for line in result.stdout.splitlines() if line.strip()]
        max_log, nonterminal_tasks, token_enabled, channel_enabled = values
    except (TypeError, ValueError):
        raise OperatorError("newapi_boundary_invalid", "NewAPI 只读边界格式无效")
    return {
        "max_log": max_log,
        "nonterminal_tasks": nonterminal_tasks,
        "operations_token_enabled": token_enabled,
        "channel_enabled": channel_enabled,
    }


def online_backup(profile_id: int, state: dict[str, Any]) -> tuple[Path, dict[str, int]]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = BACKUP_ROOT / f"sgp011-account-onboard-P{profile_id}-{stamp}"
    backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(backup_dir, 0o700)
    hashes: dict[str, str] = {}
    for name, source_path in (
        ("updater-profiles.db", UPDATER_DB),
        ("flow.db", FLOW_DB),
    ):
        source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
        destination_path = backup_dir / name
        destination = sqlite3.connect(destination_path)
        source.backup(destination)
        destination.close(); source.close()
        check = sqlite3.connect(f"file:{destination_path}?mode=ro", uri=True)
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        check.close()
        if integrity != "ok":
            raise OperatorError("backup_integrity_failed", "SQLite 在线备份完整性检查失败")
        os.chmod(destination_path, 0o600)
        hashes[name] = hashlib.sha256(destination_path.read_bytes()).hexdigest()
    boundary = newapi_boundary()
    prepared = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "profile_id": profile_id,
        "profile_sync_count": state["sync_count"],
        "profile_error_count": state["error_count"],
        "dedupe": dedupe_state(state),
        "newapi": boundary,
        "hashes": hashes,
    }
    path = backup_dir / "prepared.json"
    path.write_text(json.dumps(prepared, sort_keys=True, indent=2) + "\n")
    os.chmod(path, 0o600)
    (backup_dir / "PREPARED").write_text("prepared\n")
    os.chmod(backup_dir / "PREPARED", 0o600)
    return backup_dir, boundary


def verify_pending(
    profile_id: int,
    token_id: int,
    original_state: dict[str, Any],
    boundary: dict[str, int],
) -> dict[str, Any]:
    profile = profile_state(profile_id)
    flow = open_ro(FLOW_DB)
    try:
        token = flow.execute(
            """
            SELECT id,is_active,image_enabled,at_expires,current_project_id,
                   ban_reason,banned_at
              FROM tokens
             WHERE id=? AND lower(trim(email))=?
            """,
            (token_id, original_state["identity"]),
        ).fetchone()
        if not token:
            raise OperatorError("pending_token_missing", "目标 pending Token 读回失败")
        expiry = datetime.fromisoformat(str(token["at_expires"] or "").replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        project_owners = flow.execute(
            "SELECT count(*) FROM projects WHERE trim(project_id)=? AND token_id=?",
            (original_state["project_id"], token_id),
        ).fetchone()[0]
        identity_matches = flow.execute(
            "SELECT count(*) FROM tokens WHERE lower(trim(email))=?",
            (original_state["identity"],),
        ).fetchone()[0]
        project_matches = flow.execute(
            "SELECT count(*) FROM tokens WHERE trim(current_project_id)=?",
            (original_state["project_id"],),
        ).fetchone()[0]
        tasks = flow.execute("SELECT count(*) FROM tasks").fetchone()[0]
        accepted = bool(
            flow.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            and profile["sync_count"] == 1
            and profile["error_count"] == 0
            and profile["last_sync_result"] == "success: added_pending_enable"
            and not profile["active"]
            and profile["logged_in"]
            and not bool(token["is_active"])
            and bool(token["image_enabled"])
            and not bool(token["ban_reason"] or token["banned_at"])
            and str(token["current_project_id"] or "").strip() == original_state["project_id"]
            and expiry > datetime.now(timezone.utc) + timedelta(hours=1)
            and identity_matches == 1
            and project_matches == 1
            and project_owners == 1
            and tasks == 0
        )
        current_boundary = newapi_boundary()
        accepted = accepted and current_boundary == boundary
        if not accepted:
            raise OperatorError(
                "pending_readback_failed",
                "pending Token、Profile 或 NewAPI 只读边界未通过；禁止重试",
            )
        return {
            "profile_id": profile_id,
            "token_id": token_id,
            "profile_active": False,
            "token_active": False,
            "pending_image_acceptance": True,
            "newapi_unchanged": True,
            "flow_tasks": tasks,
        }
    finally:
        flow.close()


def write_outcome(backup_dir: Path, name: str, payload: dict[str, Any]) -> None:
    path = backup_dir / name
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    os.chmod(path, 0o600)


def run(profile_id: int) -> dict[str, Any]:
    before = profile_state(profile_id)
    require_fresh_candidate(before, extracted=False)

    if not (
        before["handoff_complete"]
        and before["logged_in"]
        and before["project_verified"]
    ):
        checked = updater_call("check", profile_id)
        if not (
            checked.get("success")
            and checked.get("is_logged_in")
            and checked.get("has_flow_project")
        ):
            raise OperatorError(
                str(checked.get("error_code") or "login_check_failed"),
                "同上下文登录检查未通过；未执行提取或同步",
            )

    state = profile_state(profile_id)
    if not (state["token_present"] and state["cookies_present"]):
        extracted = updater_call("extract", profile_id)
        if not (extracted.get("success") and extracted.get("token_present")):
            raise OperatorError("extract_failed", "浏览器会话提取失败；未向目标写入")
        state = profile_state(profile_id)
    require_fresh_candidate(state, extracted=True)

    dedupe = dedupe_state(state)
    if any(dedupe.values()):
        raise OperatorError(
            "identity_or_project_duplicate",
            "身份或项目已存在；新账号流程已停止，请转入既有账号恢复分支",
        )

    backup_dir, boundary = online_backup(profile_id, state)
    try:
        result = updater_call("onboard", profile_id)
        if not (
            result.get("success")
            and result.get("action") == "added_pending_enable"
            and result.get("pending_image_acceptance") is True
            and isinstance(result.get("token_id"), int)
        ):
            raise OperatorError(
                str(result.get("error_code") or "sync_contract_failed"),
                "单次绑定未满足 pending 契约；禁止重试",
            )
        accepted = verify_pending(
            profile_id,
            int(result["token_id"]),
            state,
            boundary,
        )
        accepted["backup"] = str(backup_dir)
        write_outcome(backup_dir, "pending-acceptance.json", accepted)
        (backup_dir / "PENDING_IMAGE_ACCEPTANCE").write_text("pending\n")
        os.chmod(backup_dir / "PENDING_IMAGE_ACCEPTANCE", 0o600)
        return accepted
    except Exception as exc:
        code = exc.code if isinstance(exc, OperatorError) else "unexpected_failure"
        write_outcome(
            backup_dir,
            "FAILED_NO_RETRY.json",
            {"profile_id": profile_id, "error_code": code, "retry_allowed": False},
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind one completed sgp011 Flow login and stop pending image acceptance"
    )
    parser.add_argument("profile_id", nargs="?", type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(json.dumps({"success": False, "error_code": "root_required"}))
        return 1
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"success": False, "error_code": "onboarding_busy"}))
            return 1
        try:
            profile_id = select_profile_id(args.profile_id)
            result = run(profile_id)
            print(json.dumps({"success": True, **result}, sort_keys=True))
            return 0
        except OperatorError as exc:
            print(json.dumps({
                "success": False,
                "error_code": exc.code,
                "message": exc.message,
            }, sort_keys=True))
            return 1
        except Exception:
            print(json.dumps({
                "success": False,
                "error_code": "unexpected_failure",
                "message": "操作意外失败；已停止且不会自动重试",
            }, sort_keys=True))
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
