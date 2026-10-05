#!/usr/bin/env python3
"""Operate the guarded sgp011 Flow account onboarding pipeline.

Passwords and TOTP seeds move from OpenBao to the assigned browser worker in
memory over stdin and authenticated local sockets. Unknown Google challenges
remain visible in that worker for the owner.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin


BAO_BASE = "http://127.0.0.1:8200/v1"
BAO_ROOT = "/projects/data/opencodex/prod/flow-login-accounts"
OP = "/home/grey/.local/bin/op"
WECOM_SENDER = Path(
    "/home/grey/.agents/skills/send-personal-wecom/scripts/send_personal_wecom.sh"
)
PUBLIC_UPDATER = "https://flow-updater.opencodex.uk"
SOURCE_PROXY = "http://172.19.240.1:18088"
CAPTCHA_PROXY = "http://127.0.0.1:18082"
RECORD_RE = re.compile(r"account-[0-9]{3}\Z")
CAPABILITY_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class PipelineError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def run(
    command: list[str], *, input_text: str | None = None, timeout: int = 300
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def parse_last_json(text: str) -> dict[str, Any]:
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise PipelineError("response_invalid")


def validate_record_id(value: str) -> str:
    if not RECORD_RE.fullmatch(value):
        raise PipelineError("record_id_invalid")
    return value


class OpenBao:
    def __init__(self) -> None:
        role = run([OP, "read", "op://OpenClaw/openbao-codex-gpl001/username"])
        secret = run([OP, "read", "op://OpenClaw/openbao-codex-gpl001/password"])
        if role.returncode or secret.returncode:
            raise PipelineError("openbao_bootstrap_failed")
        reply = self._request(
            "POST",
            "/auth/approle/login",
            {"role_id": role.stdout.strip(), "secret_id": secret.stdout.strip()},
            token="",
        )
        self.token = str((reply.get("auth") or {}).get("client_token") or "")
        if not self.token:
            raise PipelineError("openbao_login_failed")

    @staticmethod
    def _request(
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        token: str,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        payload = None if body is None else json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode()
        request = urllib.request.Request(
            BAO_BASE + path, data=payload, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise PipelineError(f"openbao_http_{exc.code}") from exc
        return json.loads(raw) if raw else {}

    def get(self, record_id: str) -> tuple[dict[str, Any], int]:
        validate_record_id(record_id)
        reply = self._request(
            "GET", f"{BAO_ROOT}/{record_id}", token=self.token
        )
        wrapped = reply.get("data") or {}
        data = wrapped.get("data")
        version = (wrapped.get("metadata") or {}).get("version")
        if not isinstance(data, dict) or not isinstance(version, int):
            raise PipelineError("openbao_record_invalid")
        return data, version

    def index(self) -> list[str]:
        reply = self._request("GET", f"{BAO_ROOT}/index", token=self.token)
        wrapped = reply.get("data") or {}
        data = wrapped.get("data") or {}
        try:
            record_ids = json.loads(str(data["RECORD_IDS_JSON"]))
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PipelineError("openbao_index_invalid") from exc
        if not isinstance(record_ids, list):
            raise PipelineError("openbao_index_invalid")
        return [validate_record_id(str(item)) for item in record_ids]

    def update(self, record_id: str, fields: dict[str, str]) -> int:
        data, version = self.get(record_id)
        data.update(fields)
        reply = self._request(
            "POST",
            f"{BAO_ROOT}/{record_id}",
            {"options": {"cas": version}, "data": data},
            token=self.token,
        )
        next_version = (reply.get("data") or {}).get("version")
        if not isinstance(next_version, int):
            raise PipelineError("openbao_update_invalid")
        return next_version

    def transition(self, record_id: str, expected: str, fields: dict[str, str]) -> int:
        data, version = self.get(record_id)
        if data.get("STATUS") != expected:
            raise PipelineError("record_stage_mismatch")
        data.update(fields)
        reply = self._request(
            "POST", f"{BAO_ROOT}/{record_id}",
            {"options": {"cas": version}, "data": data}, token=self.token,
        )
        next_version = (reply.get("data") or {}).get("version")
        if not isinstance(next_version, int):
            raise PipelineError("openbao_update_invalid")
        return next_version


def safe_record(record_id: str, data: dict[str, Any], version: int) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "version": version,
        "status": str(data.get("STATUS") or ""),
        "profile_id": int(data["PROFILE_ID"]) if str(data.get("PROFILE_ID") or "").isdigit() else None,
        "slot": int(data["LOGIN_SLOT"]) if str(data.get("LOGIN_SLOT") or "").isdigit() else None,
        "flow_token_id": int(data["FLOW_TOKEN_ID"]) if str(data.get("FLOW_TOKEN_ID") or "").isdigit() else None,
    }


def require_record_binding(
    record_id: str,
    data: dict[str, Any],
    *,
    status: str,
    profile_id: int,
    token_id: int | None = None,
) -> str:
    """Fail before a remote mutation if a stage targets the wrong inventory row."""
    if data.get("RECORD_ID") != record_id or data.get("STATUS") != status:
        raise PipelineError("record_stage_mismatch")
    if str(data.get("PROFILE_ID") or "") != str(profile_id):
        raise PipelineError("record_profile_mismatch")
    if token_id is not None and str(data.get("FLOW_TOKEN_ID") or "") != str(token_id):
        raise PipelineError("record_token_mismatch")
    identity = str(data.get("EMAIL") or "").strip()
    if not identity or len(identity) > 320 or "\n" in identity or "\r" in identity:
        raise PipelineError("record_identity_invalid")
    return identity


def command_status(_: argparse.Namespace) -> dict[str, Any]:
    bao = OpenBao()
    records = []
    for record_id in bao.index():
        data, version = bao.get(record_id)
        records.append(safe_record(record_id, data, version))
    return {"success": True, "record_count": len(records), "records": records}


PREPARE_HELPER = r'''
import json, os, sys, urllib.error, urllib.request
name = sys.argv[1]
base = "http://127.0.0.1:8002"
def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["X-Flow-Updater-Authorization"] = "Bearer " + token
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.load(response)
session = call("POST", "/api/login", {"password": os.environ["ADMIN_PASSWORD"]})["token"]
try:
    profiles = call("GET", "/api/profiles", token=session)
    matches = [item for item in profiles if item.get("name") == name]
    if matches:
        if len(matches) != 1:
            raise RuntimeError("profile_name_ambiguous")
        candidate = matches[0]
        clean = bool(
            candidate.get("login_slot_prepared")
            and not candidate.get("is_active")
            and not candidate.get("is_logged_in")
            and not candidate.get("is_browser_active")
            and int(candidate.get("sync_count") or 0) == 0
            and int(candidate.get("error_count") or 0) == 0
            and not candidate.get("has_google_cookies")
            and not candidate.get("has_login_credentials")
            and not candidate.get("login_slot_claimed")
        )
        if not clean:
            raise RuntimeError("existing_profile_not_fresh")
        profile_id = int(candidate["id"])
    else:
        profile_id = int(call("POST", "/api/login-slots/prepare", {
            "name": name,
            "source_proxy_url": "http://172.19.240.1:18088",
            "captcha_proxy_url": "http://127.0.0.1:18082",
        }, session)["profile_id"])
    started = call("POST", f"/api/login-slots/{profile_id}/start", token=session)
    print(json.dumps({
        "profile_id": profile_id,
        "slot": int(started["slot"]),
        "invite_url": str(started["invite_url"]),
        "expires_at": started["expires_at"],
    }, separators=(",", ":")))
finally:
    try: call("POST", "/api/logout", token=session)
    except Exception: pass
'''


def prepare_remote(profile_name: str) -> dict[str, Any]:
    result = run(
        [
            "ssh-1p", "sgp011", "sudo", "docker", "exec", "-i",
            "sgp011-flow2api-token-updater-v34", "python", "-", profile_name,
        ],
        input_text=PREPARE_HELPER,
        timeout=420,
    )
    if result.returncode:
        raise PipelineError("prepare_or_start_failed")
    reply = parse_last_json(result.stdout)
    relative = str(reply.get("invite_url") or "")
    parts = relative.split("#", 1)
    if len(parts) != 2 or parts[0] != "/login-slots" or not CAPABILITY_RE.fullmatch(parts[1]):
        raise PipelineError("invitation_shape_invalid")
    reply["invite_url"] = urljoin(PUBLIC_UPDATER, relative)
    return reply


def auto_login_remote(profile_id: int, data: dict[str, Any]) -> dict[str, Any]:
    secret = {"email": data["EMAIL"], "password": data["PASSWORD"],
              "totp_seed": data["TOTP_SECRET"]}
    result = run(
        ["ssh-1p", "sgp011", "sudo", "docker", "exec", "-i",
         "sgp011-flow2api-token-updater-v34", "python", "-m",
         "token_updater.account_auto_login_remote", str(profile_id)],
        input_text=json.dumps(secret, separators=(",", ":")), timeout=900,
    )
    secret.clear()
    if result.returncode:
        raise PipelineError("auto_login_transport_review")
    reply = parse_last_json(result.stdout)
    if reply.get("profile_id") != profile_id:
        raise PipelineError("auto_login_scope_invalid")
    return reply


def send_invitation(
    record_id: str, profile_id: int, slot: int, invite_url: str
) -> dict[str, Any]:
    body = (
        "sgp011 Flow 新账号登录槽（四小时、单次领取）\n"
        f"slot{slot}：Profile {profile_id} / OpenBao {record_id}\n"
        f"邀请链接：{invite_url}\n"
        "链接内含一次性登录 token，打开后可直接进入专属 VNC 桌面，无需输入账号密码。\n"
        "请在独立桌面完成 Google/Flow 与 Labs 可见授权；遇到 CAPTCHA、设备确认或恢复挑战请人工处理。\n"
        "YesCaptcha 扩展已预装并自动配置；系统会保留该 Profile/VNC，人工完成后继续无成本检查。"
    )
    result = run([str(WECOM_SENDER)], input_text=body, timeout=300)
    reply = parse_last_json(result.stdout)
    provider = reply.get("result") or {}
    accepted = bool(
        result.returncode == 0
        and reply.get("http_status") == 200
        and provider.get("ok") is True
        and provider.get("provider_accepted") is True
        and provider.get("invalid_recipient") is False
        and provider.get("message_id_present") is True
    )
    if not accepted:
        raise PipelineError("wecom_delivery_failed_no_retry")
    return {
        "http_status": 200,
        "provider_accepted": True,
        "recipient_alias": provider.get("recipient_alias"),
        "message_id_present": True,
        "reconciliation_attempted": bool(provider.get("reconciliation_attempted")),
    }


def command_prepare_invite(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    required = {"EMAIL", "PASSWORD", "TOTP_SECRET", "STATUS", "RECORD_ID"}
    if not required.issubset(data) or data.get("RECORD_ID") != record_id:
        raise PipelineError("openbao_record_fields_missing")
    if data.get("STATUS") != "pending":
        raise PipelineError("record_not_pending")
    bao.transition(record_id, "pending", {"STATUS": "preparing"})
    invitation = prepare_remote(args.profile_name)
    delivered = send_invitation(
        record_id,
        int(invitation["profile_id"]),
        int(invitation["slot"]),
        str(invitation["invite_url"]),
    )
    version = bao.transition(
        record_id, "preparing",
        {
            "STATUS": "login_invited",
            "PROFILE_ID": str(invitation["profile_id"]),
            "LOGIN_SLOT": str(invitation["slot"]),
            "INVITED_AT": utc_now(),
        },
    )
    return {
        "success": True,
        "record_id": record_id,
        "openbao_version": version,
        "profile_id": invitation["profile_id"],
        "slot": invitation["slot"],
        "wecom": delivered,
    }


def command_onboard(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    prior_status = str(data.get("STATUS") or "")
    if prior_status != "pro_verified":
        raise PipelineError("record_stage_mismatch")
    expected_identity = require_record_binding(
        record_id,
        data,
        status=prior_status,
        profile_id=args.profile_id,
    )
    bao.transition(record_id, prior_status, {"STATUS": "onboarding_running"})
    result = run(
        [
            "ssh-1p", "sgp011", "sudo",
            "/usr/local/sbin/sgp011-flow-onboard-profile",
            "--expected-identity-stdin", str(args.profile_id),
        ],
        input_text=expected_identity + "\n",
        timeout=900,
    )
    expected_identity = ""
    try:
        reply = parse_last_json(result.stdout)
    except PipelineError:
        reply = {}
    if result.returncode or reply.get("success") is not True:
        bao.transition(record_id, "onboarding_running", {"STATUS": "onboarding_review"})
        raise PipelineError(str(reply.get("error_code") or "onboard_failed_no_retry"))
    if reply.get("pending_image_acceptance") is not True or not isinstance(
        reply.get("token_id"), int
    ):
        bao.transition(record_id, "onboarding_running", {"STATUS": "onboarding_review"})
        raise PipelineError("onboard_pending_contract_failed")
    version = bao.transition(
        record_id, "onboarding_running",
        {
            "STATUS": "pending_image_acceptance",
            "PROFILE_ID": str(args.profile_id),
            "FLOW_TOKEN_ID": str(reply["token_id"]),
            "ONBOARDED_AT": utc_now(),
        },
    )
    return {
        "success": True,
        "record_id": record_id,
        "openbao_version": version,
        "profile_id": args.profile_id,
        "flow_token_id": reply["token_id"],
        "pending_image_acceptance": True,
        "backup": reply.get("backup"),
    }


ACCEPTANCE_EVIDENCE_HELPER = r'''
import glob, json, sys
from pathlib import Path

profile_id, token_id = map(int, sys.argv[1:3])
accepted = []
for name in glob.glob("/home/grey/backups/sgp011-flow-account-health-*/result.json"):
    path = Path(name)
    if not (path.parent / "COMPLETE").is_file():
        continue
    try:
        report = json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        continue
    if report.get("success") is not True or report.get("mode") != "pending_image_acceptance":
        continue
    for item in report.get("results") or []:
        if not isinstance(item, dict):
            continue
        if item.get("profile_id") != profile_id or item.get("flow_token_id") != token_id:
            continue
        required = (
            item.get("success") is True
            and item.get("stage") == "complete"
            and item.get("newapi_http") == 200
            and item.get("media_http") == 200
            and item.get("image_format") == "JPEG"
            and isinstance(item.get("width"), int) and item["width"] > 0
            and isinstance(item.get("height"), int) and item["height"] > 0
            and isinstance(item.get("bytes"), int) and item["bytes"] > 0
            and isinstance(item.get("flow_log_id"), int)
            and isinstance(item.get("newapi_log_id"), int)
            # The host checker already requires exactly one relevant paid
            # request ID. This field counts every concurrent NewAPI log row.
            and isinstance(item.get("newapi_log_rows"), int)
            and item["newapi_log_rows"] >= 1
        )
        if required:
            accepted.append((path.parent.name, item))
if len(accepted) != 1:
    print(json.dumps({"success": False, "error": "accepted_report_not_unique"}))
    raise SystemExit(1)
name, item = accepted[0]
safe = {key: item[key] for key in (
    "profile_id", "flow_token_id", "flow_log_id", "newapi_log_id",
    "media_http", "width", "height",
)}
safe["success"] = True
print(json.dumps({"success": True, "mode": "pending_image_acceptance",
                  "evidence": name, "results": [safe]}, separators=(",", ":")))
'''


def command_accept(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    require_record_binding(
        record_id,
        data,
        status="pending_image_acceptance",
        profile_id=args.profile_id,
        token_id=args.token_id,
    )
    # Record the paid-attempt boundary before invoking the host wrapper.  A
    # caller crash or output parsing error must never submit a second image.
    bao.transition(
        record_id, "pending_image_acceptance",
        {"STATUS": "image_acceptance_running", "IMAGE_ACCEPTANCE_STARTED_AT": utc_now()},
    )
    result = run(
        [
            "ssh-1p", "sgp011", "sudo",
            "/usr/local/sbin/sgp011-flow-account-health-run",
            "--pending-token-id", str(args.token_id),
        ],
        timeout=1200,
    )
    # The maintenance wrapper writes the complete report to a root-only file;
    # its stdout is an inner summary and is not the acceptance contract.
    evidence = run(
        ["ssh-1p", "sgp011", "sudo", "python3", "-", str(args.profile_id), str(args.token_id)],
        input_text=ACCEPTANCE_EVIDENCE_HELPER,
        timeout=120,
    )
    try:
        reply = parse_last_json(evidence.stdout)
    except PipelineError:
        reply = {}
    if result.returncode or evidence.returncode or reply.get("success") is not True:
        bao.transition(record_id, "image_acceptance_running", {"STATUS": "image_acceptance_review"})
        raise PipelineError("image_acceptance_failed_no_retry")
    results = reply.get("results") or []
    matches = [
        item for item in results
        if isinstance(item, dict)
        and item.get("flow_token_id") == args.token_id
        and item.get("profile_id") == args.profile_id
        and item.get("success") is True
    ]
    if reply.get("mode") != "pending_image_acceptance" or len(matches) != 1:
        bao.transition(record_id, "image_acceptance_running", {"STATUS": "image_acceptance_review"})
        raise PipelineError("image_acceptance_contract_failed")
    item = matches[0]
    version = bao.transition(
        record_id, "image_acceptance_running",
        {
            "STATUS": "image_accepted",
            "IMAGE_ACCEPTED_AT": utc_now(),
            "IMAGE_ACCEPTANCE_EVIDENCE": str(reply["evidence"]),
        },
    )
    return {
        "success": True,
        "record_id": record_id,
        "openbao_version": version,
        "profile_id": args.profile_id,
        "flow_token_id": args.token_id,
        "flow_log_id": item.get("flow_log_id"),
        "newapi_log_id": item.get("newapi_log_id"),
        "media_http": item.get("media_http"),
        "width": item.get("width"),
        "height": item.get("height"),
    }


ENABLE_HELPER = r'''
import glob, json, os, sqlite3, subprocess, sys, urllib.request
from pathlib import Path
profile_id, token_id = map(int, sys.argv[1:3])

def call(base, method, path, body=None, token="", header="Authorization"):
    headers = {"Content-Type": "application/json"}
    if token: headers[header] = "Bearer " + token
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)

accepted = []
for raw_path in glob.glob("/home/grey/backups/sgp011-flow-account-health-*/result.json"):
    path = Path(raw_path)
    if not (path.parent / "COMPLETE").is_file():
        continue
    try: report = json.loads(path.read_text(encoding="ascii"))
    except Exception: continue
    if report.get("success") is not True or report.get("mode") != "pending_image_acceptance":
        continue
    for item in report.get("results") or []:
        if (
            isinstance(item, dict) and item.get("success") is True
            and item.get("flow_token_id") == token_id
            and item.get("profile_id") == profile_id
        ):
            accepted.append(path)
if len(accepted) != 1:
    raise SystemExit("accepted_pending_evidence_not_unique")

flow = sqlite3.connect("file:/opt/flow2api/data/flow.db?mode=ro", uri=True)
flow.row_factory = sqlite3.Row
updater = sqlite3.connect("file:/opt/flow2api-token-updater-v34/data/profiles.db?mode=ro", uri=True)
updater.row_factory = sqlite3.Row
token = flow.execute("select id,email,is_active,image_enabled from tokens where id=?", (token_id,)).fetchone()
profile = updater.execute("select id,email,is_active,is_logged_in,sync_count,error_count,last_sync_result from profiles where id=?", (profile_id,)).fetchone()
if not token or not profile or str(token["email"]).strip().lower() != str(profile["email"]).strip().lower():
    raise SystemExit("identity_mapping_invalid")
if (int(token["is_active"]), int(token["image_enabled"])) != (0, 1):
    raise SystemExit("pending_token_state_invalid")
if (
    (int(profile["is_active"]), int(profile["is_logged_in"])) != (0, 1)
    or int(profile["sync_count"] or 0) != 1
    or int(profile["error_count"] or 0) != 0
    or str(profile["last_sync_result"] or "") != "success: added_pending_enable"
):
    raise SystemExit("pending_profile_state_invalid")
username, password = flow.execute("select username,password from admin_config where id=1").fetchone()
flow.close(); updater.close()

flow_token = call("http://127.0.0.1:18081", "POST", "/api/admin/login", {"username": username, "password": password})["token"]
enabled = False
try:
    reply = call("http://127.0.0.1:18081", "POST", f"/api/tokens/{token_id}/enable", token=flow_token)
    if reply.get("success") is not True: raise RuntimeError("flow_enable_failed")
    enabled = True

    updater_helper = r"""import json,os,sys,urllib.request
profile_id=int(sys.argv[1]);base="http://127.0.0.1:8002"
def q(method,path,body=None,token=""):
 h={"Content-Type":"application/json"}
 if token:h["X-Flow-Updater-Authorization"]="Bearer "+token
 request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=h,method=method)
 with urllib.request.urlopen(request,timeout=60) as response:return json.load(response)
t=q("POST","/api/login",{"password":os.environ["ADMIN_PASSWORD"]})["token"]
try:
 r=q("PUT",f"/api/profiles/{profile_id}",{"is_active":True},t)
 if r.get("success") is not True:raise RuntimeError("profile_enable_failed")
finally:
 try:q("POST","/api/logout",token=t)
 except Exception:pass
"""
    child = subprocess.run(
        ["docker", "exec", "-i", "sgp011-flow2api-token-updater-v34", "python", "-", str(profile_id)],
        input=updater_helper, text=True, capture_output=True, timeout=120,
    )
    if child.returncode:
        raise RuntimeError("profile_enable_failed")
finally:
    if enabled:
        verify = sqlite3.connect("file:/opt/flow2api-token-updater-v34/data/profiles.db?mode=ro", uri=True)
        active = verify.execute("select is_active from profiles where id=?", (profile_id,)).fetchone()
        verify.close()
        if not active or int(active[0]) != 1:
            try: call("http://127.0.0.1:18081", "POST", f"/api/tokens/{token_id}/disable", token=flow_token)
            except Exception: pass
            enabled = False
    try: call("http://127.0.0.1:18081", "POST", "/api/admin/logout", token=flow_token)
    except Exception: pass
if not enabled:
    raise SystemExit("enable_transaction_failed")
check = sqlite3.connect("file:/opt/flow2api/data/flow.db?mode=ro", uri=True)
state = check.execute("select is_active,image_enabled from tokens where id=?", (token_id,)).fetchone(); check.close()
if tuple(map(int, state or ())) != (1, 1): raise SystemExit("enabled_token_readback_failed")
print(json.dumps({"success": True, "profile_id": profile_id, "flow_token_id": token_id}, separators=(",", ":")))
'''


def command_enable(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    require_record_binding(
        record_id,
        data,
        status="image_accepted",
        profile_id=args.profile_id,
        token_id=args.token_id,
    )
    bao.transition(record_id, "image_accepted", {"STATUS": "enable_running"})
    result = run(
        ["ssh-1p", "sgp011", "sudo", "python3", "-", str(args.profile_id), str(args.token_id)],
        input_text=ENABLE_HELPER,
        timeout=300,
    )
    try:
        reply = parse_last_json(result.stdout)
    except PipelineError:
        reply = {}
    if result.returncode or reply.get("success") is not True:
        bao.transition(record_id, "enable_running", {"STATUS": "enable_review"})
        raise PipelineError("explicit_enable_failed")
    version = bao.transition(
        record_id, "enable_running",
        {"STATUS": "imported", "ENABLED_AT": utc_now()},
    )
    return {
        "success": True,
        "record_id": record_id,
        "openbao_version": version,
        "profile_id": args.profile_id,
        "flow_token_id": args.token_id,
        "schedulable": True,
    }


SLOT_CAPACITY_HELPER = r'''
import json, os, urllib.request
base = "http://127.0.0.1:8002"
def call(method, path, body=None, token=""):
    headers = {"Content-Type": "application/json"}
    if token: headers["X-Flow-Updater-Authorization"] = "Bearer " + token
    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response: return json.load(response)
session = call("POST", "/api/login", {"password": os.environ["ADMIN_PASSWORD"]})["token"]
try:
    slots = call("GET", "/api/login-slots", token=session)["slots"]
    print(json.dumps({"free": sum(item.get("state") == "free" for item in slots),
                      "total": len(slots)}))
finally:
    try: call("POST", "/api/logout", token=session)
    except Exception: pass
'''


def slot_capacity_remote() -> dict[str, int]:
    result = run(["ssh-1p", "sgp011", "sudo", "docker", "exec", "-i",
                  "sgp011-flow2api-token-updater-v34", "python", "-"],
                 input_text=SLOT_CAPACITY_HELPER, timeout=90)
    if result.returncode:
        raise PipelineError("slot_capacity_unavailable")
    reply = parse_last_json(result.stdout)
    if not all(isinstance(reply.get(key), int) for key in ("free", "total")):
        raise PipelineError("slot_capacity_invalid")
    return reply


RECOVER_HELPER = r'''
import json, os, sys, urllib.request
number, profile_id = map(int, sys.argv[1:])
base = "http://127.0.0.1:8002"
def call(method, path, body=None, token=""):
    headers = {"Content-Type": "application/json"}
    if token: headers["X-Flow-Updater-Authorization"] = "Bearer " + token
    payload = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=180) as response: return json.load(response)
session = call("POST", "/api/login", {"password": os.environ["ADMIN_PASSWORD"]})["token"]
try:
    result = call("POST", f"/api/login-slots/{number}/recover/{profile_id}", token=session)
    print(json.dumps({"slot": number, "profile_id": profile_id,
                      "invite_url": result["invite_url"],
                      "expires_at": result["expires_at"]}, separators=(",", ":")))
finally:
    try: call("POST", "/api/logout", token=session)
    except Exception: pass
'''


def command_recover_login(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    require_record_binding(record_id, data, status="login_invited",
                           profile_id=args.profile_id)
    slot = int(data.get("LOGIN_SLOT") or 0)
    if slot not in range(1, 6):
        raise PipelineError("record_slot_invalid")
    result = run(
        ["ssh-1p", "sgp011", "sudo", "docker", "exec", "-i",
         "sgp011-flow2api-token-updater-v34", "python", "-",
         str(slot), str(args.profile_id)],
        input_text=RECOVER_HELPER, timeout=240,
    )
    if result.returncode:
        raise PipelineError("slot_recovery_review")
    reply = parse_last_json(result.stdout)
    relative = str(reply.get("invite_url") or "")
    parts = relative.split("#", 1)
    if (reply.get("slot") != slot or reply.get("profile_id") != args.profile_id
            or len(parts) != 2 or parts[0] != "/login-slots"
            or not CAPABILITY_RE.fullmatch(parts[1])):
        raise PipelineError("slot_recovery_reply_invalid")
    delivered = send_invitation(record_id, args.profile_id, slot,
                                urljoin(PUBLIC_UPDATER, relative))
    return {"success": True, "record_id": record_id,
            "profile_id": args.profile_id, "slot": slot,
            "invitation_delivered": delivered["provider_accepted"]}


def _batch_record(record_id: str, _admission_lock: threading.Lock) -> dict[str, Any]:
    profile_id = None
    try:
        bao = OpenBao()
        data, _ = bao.get(record_id)
        if data.get("RECORD_ID") != record_id or data.get("STATUS") != "pending":
            raise PipelineError("record_not_fresh_pending")
        if not all(isinstance(data.get(key), str) and data[key] for key in
                   ("EMAIL", "PASSWORD", "TOTP_SECRET")):
            raise PipelineError("openbao_record_fields_missing")
        bao.transition(record_id, "pending", {"STATUS": "preparing"})
        invitation = prepare_remote(f"flow-auto-{record_id}")
        profile_id = int(invitation["profile_id"])
        bao.transition(record_id, "preparing", {
            "STATUS": "login_invited", "PROFILE_ID": str(profile_id),
            "LOGIN_SLOT": str(invitation["slot"]), "INVITED_AT": utc_now(),
        })
        result = auto_login_remote(profile_id, data)
        data.clear()
        if result.get("success") is not True:
            code = str(result.get("error_code") or "login_review")[:64]
            bao.transition(record_id, "login_invited", {"LOGIN_ERROR_CODE": code})
            delivered = send_invitation(record_id, profile_id, int(invitation["slot"]),
                                        str(invitation["invite_url"]))
            return {"record_id": record_id, "profile_id": profile_id,
                    "status": "manual_review", "error_code": code,
                    "invitation_delivered": delivered["provider_accepted"]}
        bao.transition(record_id, "login_invited", {
            "STATUS": "ready_for_pro_redemption", "LOGIN_VALIDATED_AT": utc_now(),
        })
        return {"record_id": record_id, "profile_id": profile_id,
                "status": "ready_for_pro_redemption"}
    except PipelineError as exc:
        return {"record_id": record_id, "profile_id": profile_id,
                "status": "review", "error_code": exc.code}
    except Exception:
        return {"record_id": record_id, "profile_id": profile_id,
                "status": "review", "error_code": "unexpected_failure"}


def command_batch(args: argparse.Namespace) -> dict[str, Any]:
    record_ids = [validate_record_id(item) for item in args.record_ids]
    if len(record_ids) != len(set(record_ids)) or not 1 <= args.parallel <= 5:
        raise PipelineError("batch_arguments_invalid")
    capacity = slot_capacity_remote()
    parallel = min(args.parallel, capacity["free"], 5)
    if parallel < 1:
        raise PipelineError("no_free_login_slots")
    admission_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {pool.submit(_batch_record, item, admission_lock): item
                   for item in record_ids}
        results = [future.result() for future in as_completed(futures)]
    results.sort(key=lambda item: item["record_id"])
    return {"success": all(item["status"] in {"ready_for_pro_redemption", "imported"}
                           for item in results),
            "requested_parallel": args.parallel, "active_parallel": parallel,
            "results": results}


def command_resume_login(args: argparse.Namespace) -> dict[str, Any]:
    """Resume an existing invitation without rotating its owner capability."""
    record_id = validate_record_id(args.record_id)
    bao = OpenBao()
    data, _ = bao.get(record_id)
    require_record_binding(record_id, data, status="login_invited",
                           profile_id=args.profile_id)
    result = auto_login_remote(args.profile_id, data)
    data.clear()
    if result.get("success") is not True:
        code = str(result.get("error_code") or "login_review")[:64]
        bao.transition(record_id, "login_invited", {"LOGIN_ERROR_CODE": code})
        return {"success": False, "record_id": record_id,
                "profile_id": args.profile_id, "error_code": code}
    bao.transition(record_id, "login_invited", {
        "STATUS": "ready_for_pro_redemption", "LOGIN_VALIDATED_AT": utc_now(),
    })
    return {"success": True, "record_id": record_id,
            "profile_id": args.profile_id, "status": "ready_for_pro_redemption"}


def command_confirm_pro(args: argparse.Namespace) -> dict[str, Any]:
    """Record operator-observed Google One and Flow PRO gates before sync."""
    record_id = validate_record_id(args.record_id)
    if not args.google_one_confirmed or not args.flow_pro_confirmed:
        raise PipelineError("pro_evidence_incomplete")
    bao = OpenBao()
    data, _ = bao.get(record_id)
    require_record_binding(record_id, data, status="ready_for_pro_redemption",
                           profile_id=args.profile_id)
    if not str(data.get("PRO_REDEMPTION_URL") or "").startswith("https://"):
        raise PipelineError("pro_redemption_url_missing")
    now = utc_now()
    version = bao.transition(record_id, "ready_for_pro_redemption", {
        "STATUS": "pro_verified", "PRO_GOOGLE_ONE_VERIFIED_AT": now,
        "PRO_FLOW_VERIFIED_AT": now,
    })
    return {"success": True, "record_id": record_id,
            "profile_id": args.profile_id, "openbao_version": version,
            "status": "pro_verified"}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description=(
            "Automate guarded sgp011 Flow onboarding through isolated visible slots; "
            "stop for unknown Google challenges"
        )
    )
    commands = root.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status", help="show sanitized OpenBao record states")
    status.set_defaults(handler=command_status)

    prepare = commands.add_parser(
        "prepare-invite", help="prepare one fresh Profile and deliver one invitation"
    )
    prepare.add_argument("--record-id", required=True)
    prepare.add_argument("--profile-name", required=True)
    prepare.set_defaults(handler=command_prepare_invite)

    onboard = commands.add_parser(
        "onboard", help="perform the single no-cost check/extract/pending sync"
    )
    onboard.add_argument("--record-id", required=True)
    onboard.add_argument("--profile-id", required=True, type=int)
    onboard.set_defaults(handler=command_onboard)

    accept = commands.add_parser(
        "accept", help="run exactly one paid pending-token image acceptance"
    )
    accept.add_argument("--record-id", required=True)
    accept.add_argument("--profile-id", required=True, type=int)
    accept.add_argument("--token-id", required=True, type=int)
    accept.set_defaults(handler=command_accept)

    enable = commands.add_parser(
        "enable", help="explicitly enable an image-accepted token/Profile pair"
    )
    enable.add_argument("--record-id", required=True)
    enable.add_argument("--profile-id", required=True, type=int)
    enable.add_argument("--token-id", required=True, type=int)
    enable.set_defaults(handler=command_enable)

    resume = commands.add_parser(
        "resume-login", help="resume an existing invited Profile without issuing another link"
    )
    resume.add_argument("--record-id", required=True)
    resume.add_argument("--profile-id", required=True, type=int)
    resume.set_defaults(handler=command_resume_login)

    recover = commands.add_parser(
        "recover-login", help="reopen an original quarantined slot and send its rotated invitation"
    )
    recover.add_argument("--record-id", required=True)
    recover.add_argument("--profile-id", required=True, type=int)
    recover.set_defaults(handler=command_recover_login)

    pro = commands.add_parser(
        "confirm-pro", help="record visually verified Google One and Flow PRO"
    )
    pro.add_argument("--record-id", required=True)
    pro.add_argument("--profile-id", required=True, type=int)
    pro.add_argument("--google-one-confirmed", action="store_true")
    pro.add_argument("--flow-pro-confirmed", action="store_true")
    pro.set_defaults(handler=command_confirm_pro)

    batch = commands.add_parser(
        "batch", help="automate distinct fresh accounts with at most five visible slots"
    )
    batch.add_argument("--parallel", type=int, default=5)
    batch.add_argument("record_ids", nargs="+")
    batch.set_defaults(handler=command_batch)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        result = args.handler(args)
    except PipelineError as exc:
        print(json.dumps({"success": False, "error": exc.code}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"success": False, "error": "unexpected_failure"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
