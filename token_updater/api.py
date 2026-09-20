"""Token Updater API v3.3"""
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .browser import browser_manager
from .config import config
from .database import profile_db
from .events import dashboard_events
from .execution import execution_gate
from .logger import logger
from .proxy_utils import validate_proxy_format
from .updater import token_syncer


APP_VERSION = "3.3.0"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DASHBOARD_HOURS_OPTIONS = (6, 24, 72, 168)
RECENT_ACTIVITY_LIMIT = 12

app = FastAPI(title="Flow2API Token Updater", version=APP_VERSION)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_sessions: dict[str, float] = {}

MAX_PROFILE_NAME_LEN = 64
MAX_REMARK_LEN = 200
MAX_PROXY_LEN = 512
MAX_FLOW2API_URL_LEN = 512
MAX_CONNECTION_TOKEN_LEN = 2048
MAX_LOGIN_ACCOUNT_LEN = 320
MAX_LOGIN_PASSWORD_LEN = 512
MAX_IMPORT_CONTENT_LEN = 100_000


def _session_ttl_seconds() -> int:
    ttl = config.session_ttl_minutes
    return max(60, ttl * 60) if ttl > 0 else 0


def _prune_sessions(now: float | None = None) -> None:
    now = now or time.time()
    expired = [token for token, exp in active_sessions.items() if exp and exp <= now]
    for token in expired:
        active_sessions.pop(token, None)


def _validate_session_token(session_token: str | None) -> str:
    if not session_token:
        raise HTTPException(401, "未登录")

    now = time.time()
    _prune_sessions(now)
    expiry = active_sessions.get(session_token)
    if expiry is None or (expiry and expiry <= now):
        active_sessions.pop(session_token, None)
        raise HTTPException(401, "登录已过期")
    return session_token

def _mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


def _validate_name(name: str) -> str:
    clean = name.strip()
    if not clean:
        raise HTTPException(400, "名称不能为空")
    if len(clean) > MAX_PROFILE_NAME_LEN:
        raise HTTPException(400, "名称过长")
    return clean


def _validate_remark(remark: str) -> str:
    clean = remark.strip()
    if len(clean) > MAX_REMARK_LEN:
        raise HTTPException(400, "备注过长")
    return clean


def _validate_proxy(proxy_url: str) -> str:
    clean = proxy_url.strip()
    if not clean:
        return ""
    if len(clean) > MAX_PROXY_LEN:
        raise HTTPException(400, "代理地址过长")
    valid, msg = validate_proxy_format(clean)
    if not valid:
        raise HTTPException(400, f"代理格式错误: {msg}")
    return clean


def _validate_flow2api_url(flow2api_url: str, *, required: bool = False) -> str:
    clean = flow2api_url.strip()
    if not clean:
        if required:
            raise HTTPException(400, "Flow2API 地址不能为空")
        return ""
    if len(clean) > MAX_FLOW2API_URL_LEN:
        raise HTTPException(400, "Flow2API 地址过长")

    parsed = urlparse(clean)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(400, "Flow2API 地址格式错误，需为 http(s)://host[:port]")
    return clean.rstrip("/")


def _validate_connection_token(connection_token: str) -> str:
    clean = connection_token.strip()
    if len(clean) > MAX_CONNECTION_TOKEN_LEN:
        raise HTTPException(400, "连接 Token 过长")
    return clean


def _validate_login_account(login_account: str) -> str:
    clean = login_account.strip()
    if len(clean) > MAX_LOGIN_ACCOUNT_LEN:
        raise HTTPException(400, "登录账号过长")
    return clean


def _validate_login_password(login_password: str) -> str:
    clean = login_password.strip()
    if len(clean) > MAX_LOGIN_PASSWORD_LEN:
        raise HTTPException(400, "登录密码过长")
    return clean


def _normalize_login_credentials(login_account: str, login_password: str) -> tuple[str, str]:
    account = _validate_login_account(login_account or "")
    password = _validate_login_password(login_password or "")
    if bool(account) != bool(password):
        raise HTTPException(400, "登录账号和登录密码需要同时提供")
    return account, password


def _resolve_login_credentials(
    current_account: str,
    current_password: str,
    next_account: str | None,
    next_password: str | None,
    *,
    clear: bool = False,
) -> tuple[str, str]:
    if clear:
        return "", ""

    merged_account = current_account or ""
    merged_password = current_password or ""
    if next_account is not None:
        merged_account = next_account
    if next_password is not None:
        merged_password = next_password
    return _normalize_login_credentials(merged_account, merged_password)


def _split_import_line(line: str) -> tuple[str, str, str]:
    for delimiter in ("----", "\t", ",", "|"):
        if delimiter not in line:
            continue
        parts = [part.strip() for part in line.split(delimiter, 2)]
        if len(parts) == 2:
            return parts[0], parts[0], parts[1]
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
    raise HTTPException(400, f"导入格式错误：{line}")


def _parse_account_import_content(content: str) -> List[Dict[str, str]]:
    raw = str(content or "")
    if len(raw) > MAX_IMPORT_CONTENT_LEN:
        raise HTTPException(400, "导入内容过大")

    items: List[Dict[str, str]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            name, login_account, login_password = _split_import_line(text)
            name = _validate_name(name)
            login_account, login_password = _normalize_login_credentials(login_account, login_password)
        except HTTPException as exc:
            raise HTTPException(exc.status_code, f"第 {line_number} 行：{exc.detail}") from exc
        items.append(
            {
                "name": name,
                "login_account": login_account,
                "login_password": login_password,
            }
        )

    if not items:
        raise HTTPException(400, "没有可导入的账号，请按行粘贴账号密码")
    return items

def _normalize_dashboard_hours(hours: int | None) -> int:
    if hours in DASHBOARD_HOURS_OPTIONS:
        return int(hours)
    return 24


def _target_label(target_url: str) -> str:
    if not target_url:
        return "未配置"
    parsed = urlparse(target_url)
    return parsed.netloc or target_url


def _classify_failure_reason(message: str) -> str:
    text = (message or "").strip()
    lowered = text.lower()

    if not text:
        return "未知错误"
    if "未配置" in text:
        return "配置缺失"
    if "无法提取 token" in lowered or "no token" in lowered:
        return "Token 提取失败"
    if "登录" in text and ("过期" in text or "失败" in text):
        return "登录状态失效"
    if "http 401" in lowered or "http 403" in lowered:
        return "鉴权失败"
    if "http" in lowered:
        return "上游接口错误"
    if "timeout" in lowered or "超时" in text:
        return "请求超时"
    if "代理" in text or "proxy" in lowered:
        return "代理异常"
    if len(text) > 20:
        return text[:20] + "..."
    return text

def _bucket_hours_for_range(hours: int) -> int:
    if hours <= 24:
        return 1
    if hours <= 72:
        return 3
    return 6


def _is_success_event(event: Dict[str, Any]) -> bool:
    return event.get("status") == "success"


def _is_error_event(event: Dict[str, Any]) -> bool:
    return event.get("status") == "error"


def _build_activity_chart(events: List[Dict[str, Any]], hours: int = 24) -> Dict[str, Any]:
    bucket_hours = _bucket_hours_for_range(hours)
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    now = now - timedelta(hours=now.hour % bucket_hours)

    bucket_count = max(1, hours // bucket_hours)
    buckets = []
    bucket_map: Dict[str, Dict[str, Any]] = {}

    for offset in range(bucket_count - 1, -1, -1):
        bucket_time = now - timedelta(hours=offset * bucket_hours)
        bucket_key = bucket_time.isoformat()
        label = bucket_time.strftime("%H:%M")
        if hours > 24:
            label = bucket_time.strftime("%m-%d %H:%M")
        bucket = {
            "bucket": bucket_key,
            "label": label,
            "success": 0,
            "error": 0,
        }
        buckets.append(bucket)
        bucket_map[bucket_key] = bucket

    for event in events:
        created_at = event.get("created_at")
        if not created_at:
            continue
        try:
            event_time = datetime.fromisoformat(created_at)
        except ValueError:
            continue

        event_time = event_time.replace(minute=0, second=0, microsecond=0)
        event_time = event_time - timedelta(hours=event_time.hour % bucket_hours)
        bucket = bucket_map.get(event_time.isoformat())
        if not bucket:
            continue
        if _is_success_event(event):
            bucket["success"] += 1
        elif _is_error_event(event):
            bucket["error"] += 1

    return {
        "bucket_hours": bucket_hours,
        "points": buckets,
    }


def _build_failure_breakdown(events: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    counts: Dict[str, Dict[str, Any]] = {}
    for event in events:
        if not _is_error_event(event):
            continue
        label = _classify_failure_reason(event.get("message") or event.get("action") or "")
        entry = counts.setdefault(
            label,
            {
                "label": label,
                "count": 0,
                "sample": event.get("message") or event.get("action") or label,
            },
        )
        entry["count"] += 1

    return sorted(counts.values(), key=lambda item: (-item["count"], item["label"]))[:limit]


def _build_target_distribution(
    profiles: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}

    for profile in profiles:
        target_url = profile.get("effective_flow2api_url") or ""
        entry = grouped.setdefault(
            target_url,
            {
                "target_url": target_url,
                "target_label": _target_label(target_url),
                "profile_count": 0,
                "logged_in": 0,
                "custom_count": 0,
                "success": 0,
                "error": 0,
                "last_event_at": None,
            },
        )
        entry["profile_count"] += 1
        entry["logged_in"] += 1 if profile.get("is_logged_in") else 0
        entry["custom_count"] += 1 if profile.get("flow2api_url") else 0

    for event in events:
        target_url = (event.get("target_url") or "").rstrip("/")
        entry = grouped.setdefault(
            target_url,
            {
                "target_url": target_url,
                "target_label": _target_label(target_url),
                "profile_count": 0,
                "logged_in": 0,
                "custom_count": 0,
                "success": 0,
                "error": 0,
                "last_event_at": None,
            },
        )
        if _is_success_event(event):
            entry["success"] += 1
        elif _is_error_event(event):
            entry["error"] += 1
        if event.get("created_at") and (entry["last_event_at"] is None or event["created_at"] > entry["last_event_at"]):
            entry["last_event_at"] = event["created_at"]

    return sorted(
        grouped.values(),
        key=lambda item: (
            -(item["profile_count"] + item["success"] + item["error"]),
            item["target_label"],
        ),
    )


def _serialize_profile(
    profile: Dict[str, Any],
    active_id: Optional[int],
    *,
    include_secret: bool = False,
) -> Dict[str, Any]:
    data = dict(profile)
    data["has_google_cookies"] = bool(data.pop("google_cookies", None))
    data["is_browser_active"] = data["id"] == active_id
    data["effective_flow2api_url"] = (data.get("flow2api_url") or config.flow2api_url or "").rstrip("/")
    data["uses_default_target"] = not bool(data.get("flow2api_url"))
    data["has_connection_token_override"] = bool(data.get("connection_token_override"))
    data["connection_token_override_preview"] = _mask_secret(data.get("connection_token_override") or "")
    data["login_account"] = data.get("login_account") or ""
    data["has_login_password"] = bool(data.get("login_password"))
    data["has_login_credentials"] = bool(data["login_account"] and data.get("login_password"))
    data["login_password_preview"] = _mask_secret(data.get("login_password") or "")
    data["target_label"] = _target_label(data["effective_flow2api_url"])

    if data.get("proxy_url"):
        valid, msg = validate_proxy_format(data["proxy_url"])
        data["proxy_status"] = msg
        data["proxy_valid"] = bool(valid)

    if include_secret:
        data["connection_token_override"] = data.get("connection_token_override") or ""
        data["login_password"] = data.get("login_password") or ""
    else:
        data.pop("connection_token_override", None)
        data.pop("login_password", None)

    return data


def _public_config() -> Dict[str, Any]:
    return {
        "flow2api_url": config.flow2api_url,
        "refresh_interval": config.refresh_interval,
        "has_connection_token": bool(config.connection_token),
        "connection_token_preview": _mask_secret(config.connection_token),
        "has_api_key": bool(config.api_key),
        "enable_vnc": bool(config.enable_vnc),
    }


async def _build_dashboard_payload(hours: int = 24) -> Dict[str, Any]:
    selected_hours = _normalize_dashboard_hours(hours)
    raw_profiles = await profile_db.get_all_profiles()
    active_id = browser_manager.get_active_profile_id()
    profiles = [_serialize_profile(profile, active_id) for profile in raw_profiles]
    recent_events = await profile_db.get_recent_sync_events(RECENT_ACTIVITY_LIMIT)
    activity_events = await profile_db.get_sync_events_since(selected_hours)

    top_profiles = sorted(
        profiles,
        key=lambda item: (item.get("sync_count", 0) + item.get("error_count", 0), item["id"]),
        reverse=True,
    )[:6]

    window_success = sum(1 for event in activity_events if _is_success_event(event))
    window_error = sum(1 for event in activity_events if _is_error_event(event))

    return {
        "browser": browser_manager.get_status(),
        "execution": execution_gate.get_status(),
        "syncer": token_syncer.get_status(),
        "config": _public_config(),
        "profiles": profiles,
        "summary": {
            "total": len(profiles),
            "logged_in": sum(1 for profile in profiles if profile.get("is_logged_in")),
            "active": sum(1 for profile in profiles if profile.get("is_active")),
            "custom_targets": sum(1 for profile in profiles if profile.get("flow2api_url")),
            "token_overrides": sum(1 for profile in profiles if profile.get("has_connection_token_override")),
            "proxy_enabled": sum(1 for profile in profiles if profile.get("proxy_url")),
            "window_success": window_success,
            "window_error": window_error,
        },
        "charts": {
            "sync_activity": _build_activity_chart(activity_events, hours=selected_hours),
            "top_profiles": [
                {
                    "id": profile["id"],
                    "name": profile["name"],
                    "sync_count": profile.get("sync_count", 0),
                    "error_count": profile.get("error_count", 0),
                    "is_logged_in": bool(profile.get("is_logged_in")),
                }
                for profile in top_profiles
            ],
            "status_breakdown": {
                "active": sum(1 for profile in profiles if profile.get("is_active")),
                "inactive": sum(1 for profile in profiles if not profile.get("is_active")),
                "logged_in": sum(1 for profile in profiles if profile.get("is_logged_in")),
                "not_logged_in": sum(1 for profile in profiles if not profile.get("is_logged_in")),
            },
            "failure_reasons": _build_failure_breakdown(activity_events),
            "target_distribution": _build_target_distribution(profiles, activity_events),
        },
        "recent_activity": list(reversed(recent_events)),
        "filters": {
            "hours": selected_hours,
            "hour_options": list(DASHBOARD_HOURS_OPTIONS),
        },
        "realtime": {
            "sse_supported": True,
        },
        "server_time": datetime.now().isoformat(),
        "version": APP_VERSION,
    }


class LoginRequest(BaseModel):
    password: str


class CreateProfileRequest(BaseModel):
    captcha_proxy_url: Optional[str] = ""
    name: str
    remark: Optional[str] = ""
    login_account: Optional[str] = ""
    login_password: Optional[str] = ""
    proxy_url: Optional[str] = ""
    flow2api_url: Optional[str] = ""
    connection_token_override: Optional[str] = ""


class UpdateProfileRequest(BaseModel):
    captcha_proxy_url: Optional[str] = None
    name: Optional[str] = None
    remark: Optional[str] = None
    is_active: Optional[bool] = None
    login_account: Optional[str] = None
    login_password: Optional[str] = None
    clear_login_credentials: Optional[bool] = None
    proxy_url: Optional[str] = None
    proxy_enabled: Optional[bool] = None
    flow2api_url: Optional[str] = None
    connection_token_override: Optional[str] = None


class UpdateConfigRequest(BaseModel):
    flow2api_url: Optional[str] = None
    connection_token: Optional[str] = None
    refresh_interval: Optional[int] = None


class ImportCookiesRequest(BaseModel):
    cookies_json: str


class ProtocolLoginRequest(BaseModel):
    google_cookies: str


class ImportAccountsRequest(BaseModel):
    content: str
    update_existing: bool = True


def _normalize_cookie_export_kind(kind: str | None) -> str:
    normalized = str(kind or "google").strip().lower()
    if normalized in {"session", "labs"}:
        return "session"
    if normalized in {"google", "protocol"}:
        return "google"
    raise HTTPException(400, "Cookie 导出类型仅支持 session / google")


def _build_cookie_export_filename(profile_id: int, kind: str) -> str:
    return f"profile-{profile_id}-{kind}-cookies.json"


def _parse_google_cookie_export(raw: str) -> List[Dict[str, Any]]:
    import json as _json

    text = (raw or "").strip()
    if not text:
        return []

    try:
        data = _json.loads(text)
    except (_json.JSONDecodeError, ValueError):
        data = None

    cookies: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("name") and item.get("value") is not None:
                cookies.append(dict(item))
        return cookies

    if isinstance(data, dict):
        if data.get("name") and data.get("value") is not None:
            return [dict(data)]

        cookie_list = data.get("cookies")
        if isinstance(cookie_list, list):
            for item in cookie_list:
                if isinstance(item, dict) and item.get("name") and item.get("value") is not None:
                    cookies.append(dict(item))
            return cookies

        for name, value in data.items():
            if isinstance(value, str) and value:
                cookies.append({"name": str(name), "value": value})
        return cookies

    from .protocol_login import _parse_google_cookies

    parsed = _parse_google_cookies(text)
    return [{"name": name, "value": value} for name, value in parsed.items()]


def _build_google_cookie_export(profile: Dict[str, Any]) -> Dict[str, Any]:
    import json as _json

    raw = (profile.get("google_cookies") or "").strip()
    if not raw:
        raise HTTPException(404, "当前账号没有可导出的 Google Cookies")

    cookies = _parse_google_cookie_export(raw)
    if not cookies:
        raise HTTPException(400, "当前账号保存的 Google Cookies 无法解析")

    return {
        "success": True,
        "profile_id": profile["id"],
        "profile_name": profile.get("name") or "",
        "kind": "google",
        "source": "database",
        "cookie_count": len(cookies),
        "cookies": cookies,
        "cookies_json": _json.dumps(cookies, ensure_ascii=False, indent=2),
        "filename": _build_cookie_export_filename(profile["id"], "google"),
    }


def _google_browser_seed(raw: str) -> List[Dict[str, Any]]:
    cookies = []
    for item in _parse_google_cookie_export(raw):
        cookie = dict(item)
        domain = str(cookie.get("domain") or "")
        if not domain:
            # Legacy header inputs contain Google login cookies, but OSID is
            # host-specific and cannot safely be assigned a guessed domain.
            if cookie.get("name") in {"OSID", "__Secure-OSID"}:
                continue
            domain = ".google.com"
        if domain.lstrip(".") not in {"google.com", "accounts.google.com", "www.google.com", "flow.google.com"} or cookie.get("partitionKey"):
            continue
        cookie.update(domain=domain, path=cookie.get("path") or "/")
        cookie.pop("url", None)
        cookies.append(cookie)
    return cookies


async def verify_session(authorization: str = Header(None)):
    if not config.admin_password:
        return "anonymous"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    return _validate_session_token(authorization[7:])


async def verify_api_key(x_api_key: str = Header(None)):
    if not config.api_key:
        raise HTTPException(500, "未配置 API_KEY")
    if not x_api_key or not secrets.compare_digest(x_api_key, config.api_key):
        raise HTTPException(401, "Invalid API Key")
    return x_api_key


@app.post("/api/login")
async def login(request: LoginRequest):
    if not config.admin_password:
        raise HTTPException(500, "未设置 ADMIN_PASSWORD")
    if not secrets.compare_digest(request.password, config.admin_password):
        raise HTTPException(401, "密码错误")
    session_token = secrets.token_urlsafe(32)
    ttl = _session_ttl_seconds()
    active_sessions[session_token] = time.time() + ttl if ttl else 0
    return {"success": True, "token": session_token}


@app.post("/api/logout")
async def logout(token: str = Depends(verify_session)):
    active_sessions.pop(token, None)
    return {"success": True}


@app.get("/api/auth/check")
async def check_auth():
    return {"need_password": bool(config.admin_password)}


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
async def get_status(token: str = Depends(verify_session)):
    profiles = await profile_db.get_all_profiles()
    return {
        "browser": browser_manager.get_status(),
        "execution": execution_gate.get_status(),
        "syncer": token_syncer.get_status(),
        "profiles": {
            "total": len(profiles),
            "logged_in": sum(1 for profile in profiles if profile.get("is_logged_in")),
            "active": sum(1 for profile in profiles if profile.get("is_active")),
        },
        "config": _public_config(),
        "version": APP_VERSION,
    }


@app.get("/api/dashboard")
async def get_dashboard(
    hours: int = Query(24, description="Chart range in hours"),
    token: str = Depends(verify_session),
):
    return await _build_dashboard_payload(hours)


@app.get("/api/dashboard/stream")
async def stream_dashboard(session_token: str = Query(..., alias="session_token")):
    _validate_session_token(session_token)
    return StreamingResponse(
        dashboard_events.stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/profiles")
async def get_profiles(token: str = Depends(verify_session)):
    profiles = await profile_db.get_all_profiles()
    active_id = browser_manager.get_active_profile_id()
    return [_serialize_profile(profile, active_id) for profile in profiles]


@app.post("/api/profiles")
async def create_profile(request: CreateProfileRequest, token: str = Depends(verify_session)):
    name = _validate_name(request.name)
    remark = _validate_remark(request.remark or "")
    login_account, login_password = _normalize_login_credentials(
        request.login_account or "",
        request.login_password or "",
    )
    proxy_url = _validate_proxy(request.proxy_url or "")
    flow2api_url = _validate_flow2api_url(request.flow2api_url or "")
    connection_token_override = _validate_connection_token(request.connection_token_override or "")

    if await profile_db.get_profile_by_name(name):
        raise HTTPException(400, "名称已存在")

    profile_id = await profile_db.add_profile(
        name=name,
        remark=remark,
        login_account=login_account,
        login_password=login_password,
        proxy_url=proxy_url,
        captcha_proxy_url=_validate_proxy(request.captcha_proxy_url or ""),
        flow2api_url=flow2api_url,
        connection_token_override=connection_token_override,
    )
    await dashboard_events.publish("profile_created", {"profile_id": profile_id})
    return {"success": True, "profile_id": profile_id}


@app.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    return _serialize_profile(
        profile,
        browser_manager.get_active_profile_id(),
        include_secret=True,
    )


@app.put("/api/profiles/{profile_id}")
async def update_profile(profile_id: int, request: UpdateProfileRequest, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")

    update_data: Dict[str, Any] = {}
    if request.captcha_proxy_url is not None:
        update_data["captcha_proxy_url"] = _validate_proxy(request.captcha_proxy_url)
    if request.name is not None:
        new_name = _validate_name(request.name)
        existing = await profile_db.get_profile_by_name(new_name)
        if existing and existing.get("id") != profile_id:
            raise HTTPException(400, "名称已存在")
        update_data["name"] = new_name
    if request.remark is not None:
        update_data["remark"] = _validate_remark(request.remark)
    if request.is_active is not None:
        update_data["is_active"] = int(request.is_active)
    if (
        request.clear_login_credentials
        or request.login_account is not None
        or request.login_password is not None
    ):
        login_account, login_password = _resolve_login_credentials(
            profile.get("login_account") or "",
            profile.get("login_password") or "",
            request.login_account,
            request.login_password,
            clear=bool(request.clear_login_credentials),
        )
        update_data["login_account"] = login_account
        update_data["login_password"] = login_password
    if request.proxy_url is not None:
        proxy_url = _validate_proxy(request.proxy_url)
        update_data["proxy_url"] = proxy_url
        update_data["proxy_enabled"] = int(bool(proxy_url))
    if request.proxy_enabled is not None and request.proxy_url is None:
        update_data["proxy_enabled"] = int(request.proxy_enabled)
    if request.flow2api_url is not None:
        update_data["flow2api_url"] = _validate_flow2api_url(request.flow2api_url)
    if request.connection_token_override is not None:
        update_data["connection_token_override"] = _validate_connection_token(
            request.connection_token_override
        )

    if update_data:
        await profile_db.update_profile(profile_id, **update_data)
        await dashboard_events.publish("profile_updated", {"profile_id": profile_id})
    return {"success": True}


@app.post("/api/profiles/import-accounts")
async def import_accounts(request: ImportAccountsRequest, token: str = Depends(verify_session)):
    items = _parse_account_import_content(request.content)
    created = 0
    updated = 0
    skipped = 0

    for item in items:
        existing = await profile_db.get_profile_by_name(item["name"])
        if existing:
            if not request.update_existing:
                skipped += 1
                continue
            await profile_db.update_profile(
                existing["id"],
                login_account=item["login_account"],
                login_password=item["login_password"],
            )
            updated += 1
            continue

        await profile_db.add_profile(
            name=item["name"],
            login_account=item["login_account"],
            login_password=item["login_password"],
        )
        created += 1

    if created or updated:
        await dashboard_events.publish(
            "profiles_imported",
            {
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "total": len(items),
            },
        )
    return {
        "success": True,
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "total": len(items),
    }


@app.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "delete_profile",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        await browser_manager.close_browser(profile_id)
        await browser_manager.delete_profile_data(profile_id)
        await profile_db.delete_profile(profile_id)
    await dashboard_events.publish("profile_deleted", {"profile_id": profile_id})
    return {"success": True}


@app.post("/api/profiles/{profile_id}/launch")
async def launch_browser(profile_id: int, token: str = Depends(verify_session)):
    if not config.enable_vnc:
        raise HTTPException(400, "已禁用 VNC 登录（设置 ENABLE_VNC=1 可启用）")
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "launch_browser",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        success = await browser_manager.launch_for_login(profile_id)
    if not success:
        raise HTTPException(500, "启动失败")
    await dashboard_events.publish("browser_launch", {"profile_id": profile_id})
    return {"success": True, "message": "请通过 VNC 登录"}


@app.post("/api/profiles/{profile_id}/close")
async def close_browser(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "close_browser",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        result = await browser_manager.close_browser(profile_id)
    await dashboard_events.publish("browser_close", {"profile_id": profile_id})
    return result


@app.post("/api/profiles/{profile_id}/check-login")
async def check_login(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "check_login",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        result = await browser_manager.check_login_status(profile_id)
    await dashboard_events.publish("login_checked", {"profile_id": profile_id})
    return result


@app.post("/api/profiles/{profile_id}/import-cookies")
async def import_cookies(profile_id: int, request: ImportCookiesRequest, token: str = Depends(verify_session)):
    cookies_json = (request.cookies_json or "").strip()
    if not cookies_json:
        raise HTTPException(400, "Cookie 内容不能为空")
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "import_cookies",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        result = await browser_manager.import_cookies(profile_id, cookies_json)
    if not result.get("success"):
        raise HTTPException(400, result.get("error") or "导入失败")
    await dashboard_events.publish("cookies_imported", {"profile_id": profile_id})
    return result


@app.get("/api/profiles/{profile_id}/export-cookies")
async def export_cookies(
    profile_id: int,
    kind: str = Query("google", description="session|google，默认 google"),
    token: str = Depends(verify_session),
):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")

    export_kind = _normalize_cookie_export_kind(kind)
    if export_kind == "google":
        return _build_google_cookie_export(profile)

    async with execution_gate.hold(
        "export_cookies",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        result = await browser_manager.export_cookies(profile_id)
    if not result.get("success"):
        error = result.get("error") or "导出失败"
        status_code = 404 if any(marker in error for marker in ("没有", "无持久化数据", "不存在", "未找到")) else 400
        raise HTTPException(status_code, error)
    result["filename"] = _build_cookie_export_filename(profile_id, "session")
    return result


@app.post("/api/profiles/{profile_id}/protocol-login")
async def protocol_login(profile_id: int, request: ProtocolLoginRequest, token: str = Depends(verify_session)):
    from .protocol_login import protocol_loginer

    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")

    google_cookies = (request.google_cookies or "").strip()
    if not google_cookies:
        raise HTTPException(400, "Google Cookies 不能为空")

    async with execution_gate.hold(
        "protocol_login",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        proxy_url = profile.get("proxy_url") if profile.get("proxy_enabled") else None
        if profile.get("proxy_enabled") and not proxy_url:
            raise HTTPException(400, "源 Profile 已启用代理但未填写地址，已停止请求以避免使用默认出口")
        result = await protocol_loginer.login(google_cookies, proxy=proxy_url, email=profile.get("email"))

        if result.get("success") and result.get("session_token"):
            # Keep the browser hydration inside the operation gate, including
            # Google's scoped cookies and any chunked legacy session cookie.
            import json as _json
            seed_cookies = _google_browser_seed(_json.dumps(result["google_cookies"]) if "google_cookies" in result else google_cookies)
            session = result["session_token"]
            chunks = [session[i:i + 3800] for i in range(0, len(session), 3800)]
            for i, chunk in enumerate(chunks):
                seed_cookies.append({
                    "name": config.session_cookie_name + (f".{i}" if len(chunks) > 1 else ""),
                    "value": chunk,
                    "domain": "labs.google",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                })
            imported = await browser_manager.import_cookies(profile_id, _json.dumps(seed_cookies))
            if not imported.get("success") or not imported.get("has_token"):
                result = {"success": False, "error": "Google session refreshed, but Flow browser login is incomplete; open Flow and log in"}
            else:
                await profile_db.update_profile(profile_id, login_method="protocol", is_logged_in=1)

    await dashboard_events.publish(
        "protocol_login",
        {"profile_id": profile_id, "success": bool(result.get("success"))},
    )
    if not result.get("success"):
        raise HTTPException(400, result.get("error") or "协议登录失败")
    return result


@app.post("/api/profiles/{profile_id}/auto-login")
async def auto_login_profile(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "auto_login",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        result = await browser_manager.auto_login(profile_id)
    await dashboard_events.publish(
        "profile_auto_login",
        {"profile_id": profile_id, "success": bool(result.get("success"))},
    )
    if not result.get("success"):
        raise HTTPException(400, result.get("error") or "自动登录失败")
    return result


@app.post("/api/profiles/{profile_id}/extract")
async def extract_token(profile_id: int, token: str = Depends(verify_session)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "不存在")
    async with execution_gate.hold(
        "extract_token",
        profile_id=profile_id,
        profile_name=profile.get("name", ""),
    ):
        extracted = await browser_manager.extract_token(profile_id)
    if extracted:
        return {"success": True, "token_length": len(extracted)}
    return {"success": False, "message": "未找到 Token，请先登录"}


@app.post("/api/profiles/{profile_id}/sync")
async def sync_profile(profile_id: int, token: str = Depends(verify_session)):
    result = await token_syncer.sync_profile(profile_id, source="manual")
    await dashboard_events.publish(
        "manual_sync",
        {"profile_id": profile_id, "success": bool(result.get("success"))},
    )
    return result


@app.post("/api/sync-all")
async def sync_all(token: str = Depends(verify_session)):
    result = await token_syncer.sync_all_profiles(source="manual")
    await dashboard_events.publish(
        "manual_sync_all",
        {
            "success": bool(result.get("success")),
            "success_count": result.get("success_count", 0),
            "error_count": result.get("error_count", 0),
            "skipped": result.get("skipped", 0),
        },
    )
    return result


@app.get("/api/config")
async def get_config(token: str = Depends(verify_session)):
    return _public_config()


@app.post("/api/config")
async def update_config(request: UpdateConfigRequest, api_request: Request, token: str = Depends(verify_session)):
    old_interval = config.refresh_interval

    if request.flow2api_url is not None:
        config.flow2api_url = _validate_flow2api_url(request.flow2api_url, required=True)
    if request.connection_token is not None:
        config.connection_token = _validate_connection_token(request.connection_token)
    if request.refresh_interval is not None:
        if request.refresh_interval < 1 or request.refresh_interval > 1440:
            raise HTTPException(400, "刷新间隔需在 1-1440 分钟之间")
        config.refresh_interval = request.refresh_interval
    config.save()

    if request.refresh_interval is not None and config.refresh_interval != old_interval:
        scheduler = getattr(api_request.app.state, "scheduler", None)
        job_id = getattr(api_request.app.state, "sync_job_id", "token_sync")
        if scheduler:
            try:
                scheduler.reschedule_job(
                    job_id,
                    trigger=IntervalTrigger(minutes=config.refresh_interval),
                )
            except Exception as exc:
                logger.warning(f"更新定时任务失败: {exc}")

    await dashboard_events.publish("config_updated", {"refresh_interval": config.refresh_interval})
    return {"success": True}


@app.get("/v1/profiles")
async def ext_list_profiles(api_key: str = Depends(verify_api_key)):
    profiles = await profile_db.get_all_profiles()
    return {
        "profiles": [
            {
                "id": profile["id"],
                "name": profile["name"],
                "email": profile.get("email"),
                "is_logged_in": bool(profile.get("is_logged_in")),
                "is_active": bool(profile.get("is_active")),
            }
            for profile in profiles
        ]
    }


@app.get("/v1/profiles/{profile_id}/token")
async def ext_get_token(profile_id: int, api_key: str = Depends(verify_api_key)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    if not profile.get("is_active"):
        raise HTTPException(400, "Profile is disabled")
    token_value = await browser_manager.extract_token(profile_id)
    if not token_value:
        raise HTTPException(400, "Failed to extract token")
    return {
        "success": True,
        "profile_id": profile_id,
        "profile_name": profile["name"],
        "email": profile.get("email"),
        "session_token": token_value,
    }


@app.post("/v1/profiles/{profile_id}/sync")
async def ext_sync_profile(profile_id: int, api_key: str = Depends(verify_api_key)):
    profile = await profile_db.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    return await token_syncer.sync_profile(profile_id)


@app.get("/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}
