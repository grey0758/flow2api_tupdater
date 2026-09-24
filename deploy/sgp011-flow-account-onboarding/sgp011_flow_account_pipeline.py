#!/usr/bin/env python3
"""Operate the non-provider-secret sgp011 Flow account onboarding pipeline.

Google identity selection, password, MFA/TOTP, CAPTCHA, device/recovery
challenges and consent remain visible owner actions in the isolated VNC. This
tool never reads those OpenBao fields into an argument or environment variable.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import subprocess
import sys
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


def safe_record(record_id: str, data: dict[str, Any], version: int) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "version": version,
        "status": str(data.get("STATUS") or ""),
        "profile_id": int(data["PROFILE_ID"]) if str(data.get("PROFILE_ID") or "").isdigit() else None,
        "slot": int(data["LOGIN_SLOT"]) if str(data.get("LOGIN_SLOT") or "").isdigit() else None,
        "flow_token_id": int(data["FLOW_TOKEN_ID"]) if str(data.get("FLOW_TOKEN_ID") or "").isdigit() else None,
    }


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


def read_basic_password(use_stdin: bool) -> str:
    value = sys.stdin.readline().rstrip("\r\n") if use_stdin else getpass.getpass(
        "VNC Basic Auth password: "
    )
    if not value or len(value) > 256 or "\n" in value or "\r" in value:
        raise PipelineError("basic_password_invalid")
    return value


def send_invitation(
    record_id: str, profile_id: int, slot: int, invite_url: str, password: str
) -> dict[str, Any]:
    body = (
        "sgp011 Flow 新账号登录槽（四小时、单次领取）\n"
        f"slot{slot}：Profile {profile_id} / OpenBao {record_id}\n"
        f"邀请链接：{invite_url}\n"
        "VNC Basic Auth 用户名：flowlogin\n"
        f"VNC Basic Auth 密码：{password}\n"
        "请在独立桌面完成 Google/Flow 与 Labs 可见授权；遇到 CAPTCHA、设备确认或恢复挑战请人工处理。"
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
    password = read_basic_password(args.basic_password_stdin)
    invitation = prepare_remote(args.profile_name)
    delivered = send_invitation(
        record_id,
        int(invitation["profile_id"]),
        int(invitation["slot"]),
        str(invitation["invite_url"]),
        password,
    )
    password = ""
    version = bao.update(
        record_id,
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
    result = run(
        [
            "ssh-1p", "sgp011", "sudo",
            "/usr/local/sbin/sgp011-flow-onboard-profile", str(args.profile_id),
        ],
        timeout=900,
    )
    reply = parse_last_json(result.stdout)
    if result.returncode or reply.get("success") is not True:
        raise PipelineError(str(reply.get("error_code") or "onboard_failed_no_retry"))
    if reply.get("pending_image_acceptance") is not True or not isinstance(
        reply.get("token_id"), int
    ):
        raise PipelineError("onboard_pending_contract_failed")
    bao = OpenBao()
    version = bao.update(
        record_id,
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


def command_accept(args: argparse.Namespace) -> dict[str, Any]:
    record_id = validate_record_id(args.record_id)
    result = run(
        [
            "ssh-1p", "sgp011", "sudo",
            "/usr/local/sbin/sgp011-flow-account-health-run",
            "--pending-token-id", str(args.token_id),
        ],
        timeout=1200,
    )
    reply = parse_last_json(result.stdout)
    if result.returncode or reply.get("success") is not True:
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
        raise PipelineError("image_acceptance_contract_failed")
    item = matches[0]
    bao = OpenBao()
    version = bao.update(
        record_id,
        {"STATUS": "image_accepted", "IMAGE_ACCEPTED_AT": utc_now()},
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
    result = run(
        ["ssh-1p", "sgp011", "sudo", "python3", "-", str(args.profile_id), str(args.token_id)],
        input_text=ENABLE_HELPER,
        timeout=300,
    )
    reply = parse_last_json(result.stdout)
    if result.returncode or reply.get("success") is not True:
        raise PipelineError("explicit_enable_failed")
    bao = OpenBao()
    version = bao.update(
        record_id,
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


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description=(
            "Operate sgp011 Flow onboarding around the visible owner-login boundary; "
            "never automate Google credentials or MFA"
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
    prepare.add_argument(
        "--basic-password-stdin", action="store_true",
        help="read the established VNC Basic Auth password from stdin",
    )
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
