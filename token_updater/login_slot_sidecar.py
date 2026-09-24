"""A single, login-only sidecar for the third sgp011 owner slot.

This process deliberately has no Updater database, scheduler, or application
network access.  It assigns one already-prepared Profile to worker slot 3,
keeps the owner session in memory, and exposes only the isolated desktop
through the existing HTTPS/Basic-Auth vhost.  A restart never reconstructs a
session: a non-empty worker Profile makes the slot quarantine instead.
"""

import asyncio
import json
import os
import secrets
import stat
import time
from pathlib import Path

import httpx
import uvicorn
import websockets
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from .login_worker_protocol import sign_headers


SLOT = 3
PROFILE_ID = int(os.getenv("LOGIN_SLOT3_PROFILE_ID", "9"))
WORKER_SOCKET = os.getenv("LOGIN_SLOT3_WORKER_SOCKET", "/run/login-slot3/worker.sock")
SIDEcar_SOCKET = os.getenv("LOGIN_SLOT3_SIDECAR_SOCKET", "/run/login-slot3/sidecar.sock")
PRIVATE_KEY = os.getenv("LOGIN_SLOT3_SIGNING_PRIVATE_KEY", "")
PROFILE_DIR = Path(os.getenv("LOGIN_SLOT3_PROFILE_DIR", "/slot/profile"))
INVITE_TTL = 4 * 60 * 60
COOKIE_NAME = "flow_login_slot3"
BASE = "/login-slot3"
NOVNC_ROOT = Path("/usr/share/novnc").resolve()
ADMIN_TOKEN = os.getenv("LOGIN_SLOT3_ADMIN_TOKEN", "")
RECOVER_EXISTING = os.getenv("LOGIN_SLOT3_RECOVER_EXISTING", "").strip().lower() in {
    "1", "true", "yes", "on",
}


HTML = """<!doctype html>
<html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>Flow 登录槽位 3</title>
<style>body{font:16px system-ui;margin:0;background:#101827;color:#fff}header{padding:12px 18px;line-height:1.5}iframe{border:0;width:100vw;height:calc(100vh - 100px)}.hidden{display:none}</style></head>
<body><header><strong id=\"title\">正在准备专属浏览器…</strong><span id=\"instructions\" class=\"hidden\">只在下方浏览器完成 Google、Flow 和 Labs 授权；不要导出 Cookie。完成后保持页面打开，管理员会直接检查，无需点击确认。</span><span id=\"status\"></span></header>
<iframe id=\"vnc\" class=\"hidden\" title=\"专属 VNC\"></iframe><script src=\"/login-slot3/client.js\"></script></body></html>"""

JS = """const title=document.getElementById('title'),instructions=document.getElementById('instructions'),status=document.getElementById('status'),frame=document.getElementById('vnc');
async function json(path,opt={}){const r=await fetch(path,{...opt,headers:{'Content-Type':'application/json',...(opt.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'登录槽位不可用');return d}
async function init(){let s;const capability=decodeURIComponent(location.hash.slice(1));if(capability){history.replaceState(null,'','/login-slot3/');s=await json('/login-slot3/claim',{method:'POST',body:JSON.stringify({capability})})}else{s=await json('/login-slot3/session')}title.textContent='独立登录槽位 3';instructions.classList.remove('hidden');frame.src='/login-slot3/vnc/vnc.html?autoconnect=1&resize=scale&path='+encodeURIComponent('login-slot3/vnc/websockify');frame.classList.remove('hidden')}
setInterval(async()=>{try{const s=await json('/login-slot3/session');status.textContent=s.state==='checking'?' 管理员正在执行无成本检查，请暂时不要操作。':' 完成可见授权后保持本页打开；管理员会直接检查。'}catch(_){frame.remove();status.textContent=' 登录桌面已由管理员关闭；请等待后续验收。'}},5000);init().catch(e=>{title.textContent=e.message;status.textContent=' 请联系管理员。'});"""


class Sidecar:
    def __init__(self) -> None:
        if not PRIVATE_KEY or not ADMIN_TOKEN:
            raise RuntimeError("slot3 signing and admin secrets are required")
        self.lock = asyncio.Lock()
        self.input_gate = asyncio.Lock()
        self.generation = secrets.token_urlsafe(24)
        self.capability = secrets.token_urlsafe(32)
        self.expires_at = time.time() + INVITE_TTL
        self.session = ""
        self.state = "starting"
        self.last_error = ""
        self.identity = ""
        self.project_id = ""
        self.existing_project_present = False
        self.expiry_task: asyncio.Task | None = None

    def _headers(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        return sign_headers(PRIVATE_KEY, slot=SLOT, generation=self.generation,
                            profile_id=PROFILE_ID, method=method, path=path, body=body)

    async def worker_call(self, method: str, payload: dict | None = None,
                          timeout: float = 100) -> dict:
        body = json.dumps(payload or {}, sort_keys=True, separators=(",", ":")).encode()
        headers = self._headers("POST", f"/{method}", body)
        headers["Content-Type"] = "application/json"
        transport = httpx.AsyncHTTPTransport(uds=WORKER_SOCKET)
        async with httpx.AsyncClient(transport=transport, base_url="http://slot3-worker", timeout=timeout) as client:
            response = await client.post(f"/{method}", content=body, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"worker {method} HTTP {response.status_code}")
        data = response.json()
        if (data.get("slot") != SLOT or data.get("profile_id") != PROFILE_ID
                or data.get("generation") != self.generation):
            raise RuntimeError("worker response scope mismatch")
        return data

    async def bootstrap(self) -> None:
        # The worker, not this process, is the owner of the 0700 Profile.  Its
        # signed assign call performs the authoritative empty-profile check.
        try:
            for _ in range(60):
                if Path(WORKER_SOCKET).exists():
                    break
                await asyncio.sleep(0.5)
            if not Path(WORKER_SOCKET).exists():
                raise RuntimeError("worker socket unavailable")
            operation = "recover" if RECOVER_EXISTING else "assign"
            result = await self.worker_call(operation, {"proxy_url": "http://127.0.0.1:18088"}, timeout=120)
            if result.get("state") != "ready" or not result.get("browser_running"):
                raise RuntimeError("worker did not confirm browser readiness")
            self.state = "ready"
        except Exception as exc:
            self.state = "quarantined"
            self.last_error = type(exc).__name__

    async def expire(self) -> None:
        await asyncio.sleep(max(0, self.expires_at - time.time()))
        async with self.lock:
            if self.state in {"ready", "awaiting_check"}:
                try:
                    await self.worker_call("abort", timeout=30)
                except Exception:
                    self.state = "quarantined"
                    self.last_error = "expiry_abort_failed"
                else:
                    self.state = "expired"

    def schedule_expiry(self) -> None:
        previous = self.expiry_task
        if previous and previous is not asyncio.current_task():
            previous.cancel()
        self.expiry_task = asyncio.create_task(self.expire())

    def public(self) -> dict:
        return {"slot": SLOT, "profile_id": PROFILE_ID, "state": self.state,
                "expires_at": self.expires_at}

    def _session_ok(self, request: Request | WebSocket) -> bool:
        if time.time() >= self.expires_at or not self.session:
            return False
        return secrets.compare_digest(request.cookies.get(COOKIE_NAME, ""), self.session)

    async def claim(self, capability: str) -> JSONResponse:
        async with self.lock:
            if time.time() >= self.expires_at:
                raise HTTPException(410, "邀请已过期")
            if self.state != "ready":
                raise HTTPException(409, "登录桌面暂不可用")
            if self.session:
                raise HTTPException(409, "邀请已经被领取")
            if not capability or not secrets.compare_digest(capability, self.capability):
                raise HTTPException(404, "邀请不存在")
            self.session = secrets.token_urlsafe(32)
            response = JSONResponse(self.public())
            response.set_cookie(COOKIE_NAME, self.session,
                                max_age=max(1, int(self.expires_at - time.time())),
                                httponly=True, secure=True, samesite="strict", path=BASE)
            return response

    async def rotate_invite(self) -> dict:
        async with self.lock:
            if self.state != "ready" or self.identity or self.project_id:
                raise HTTPException(409, "slot cannot rotate an invitation in this state")
            self.capability = secrets.token_urlsafe(32)
            self.session = ""
            self.expires_at = time.time() + INVITE_TTL
            result = {"path": BASE + "/#" + self.capability, "expires_at": self.expires_at}
        self.schedule_expiry()
        return result

    async def require_owner(self, request: Request) -> None:
        if not self._session_ok(request):
            raise HTTPException(401, "登录会话不存在或已过期")

    async def validate(self, expected_existing_project_id: str = "") -> dict:
        # Serialize the whole same-context check against every inbound RFB
        # input frame.  The worker also stops x11vnc before reading Cookies and
        # provider responses, but this gate prevents a queued owner action
        # from racing the transition into that state.
        async with self.input_gate:
            async with self.lock:
                if self.state not in {"ready", "awaiting_check"}:
                    raise HTTPException(409, "登录槽位当前不能执行管理员检查")
                self.state = "checking"
            try:
                payload = {}
                if expected_existing_project_id:
                    payload["expected_existing_project_id"] = expected_existing_project_id
                result = await self.worker_call("validate", payload, timeout=180)
                accepted = bool(result.get("success") and result.get("is_logged_in")
                                and result.get("has_flow_project") and result.get("state") == "validated")
                async with self.lock:
                    self.state = "validated" if accepted else "ready"
                    self.last_error = "" if accepted else str(result.get("error_code") or "validation_failed")[:64]
                    if accepted:
                        self.identity = str(result.get("identity") or "").strip().lower()
                        self.project_id = str(result.get("project_id") or "").strip()
                        if not self.identity or "@" not in self.identity or not self.project_id:
                            self.state = "quarantined"
                            self.last_error = "incomplete_handoff_evidence"
                            self.identity = ""
                            self.project_id = ""
                            accepted = False
                response = {
                    "success": accepted,
                    "state": self.state,
                    "has_identity": bool(self.identity),
                    "has_project": bool(self.project_id),
                    "error_code": self.last_error or None,
                }
                if not accepted:
                    # Expose only bounded classifier telemetry needed to
                    # distinguish an absent provider response from a changed
                    # response shape.  Never pass through payloads, URLs,
                    # identity, project identifiers, or browser state.
                    allowed_counts = {
                        "flow_rpc_post", "rpc_ids_known", "rpc_ids_other",
                        "known_status_200", "known_content_type",
                        "known_success_envelope", "scoped_candidate_match",
                        "user_list_candidate_match",
                    }
                    raw_counts = result.get("probe_counts")
                    if isinstance(raw_counts, dict):
                        safe_counts = {}
                        for key in allowed_counts:
                            value = raw_counts.get(key)
                            if isinstance(value, int) and not isinstance(value, bool):
                                safe_counts[key] = max(0, min(999, value))
                        if safe_counts:
                            response["probe_counts"] = safe_counts
                    candidate_count = result.get("candidate_count")
                    if isinstance(candidate_count, int) and not isinstance(candidate_count, bool):
                        response["candidate_count"] = max(0, min(99, candidate_count))
                    if isinstance(result.get("candidate_visible"), bool):
                        response["candidate_visible"] = result["candidate_visible"]
                return response
            except Exception as exc:
                async with self.lock:
                    self.state = "quarantined"
                    self.last_error = type(exc).__name__
                return {"success": False, "state": self.state, "error_code": self.last_error}

    async def abort(self) -> dict:
        async with self.lock:
            if self.state in {"stopped", "expired"}:
                return self.public()
        try:
            result = await self.worker_call("abort", timeout=30)
        except Exception as exc:
            async with self.lock:
                self.state = "quarantined"
                self.last_error = type(exc).__name__
            return {**self.public(), "error_code": self.last_error}
        async with self.lock:
            self.state = "stopped" if result.get("state") == "idle" else "quarantined"
        return self.public()

    async def handoff(self) -> dict:
        async with self.lock:
            if self.state != "validated" or not self.identity or not self.project_id:
                raise HTTPException(409, "validated handoff evidence is unavailable")
            return {"identity": self.identity, "project_id": self.project_id,
                    "profile_id": PROFILE_ID, "generation": self.generation}

    async def account_handoff(self) -> dict:
        """Return only the account identity for existing-token recovery.

        The account-project validation branch proves that the authenticated
        account owns projects, but deliberately does not select or export one
        of their identifiers.  The caller keeps the existing token's database-
        bound project and needs only the validated identity plus slot scope to
        prevent a cross-profile handoff.
        """
        async with self.lock:
            if not RECOVER_EXISTING:
                raise HTTPException(409, "account handoff is recovery-only")
            if (self.state != "validated" or not self.identity
                    or not self.existing_project_present):
                raise HTTPException(409, "validated account handoff evidence is unavailable")
            return {
                "identity": self.identity,
                "profile_id": PROFILE_ID,
                "generation": self.generation,
            }

    async def cleanup(self) -> dict:
        if RECOVER_EXISTING:
            raise HTTPException(409, "existing Profile cleanup is forbidden")
        async with self.lock:
            if self.state != "validated":
                raise HTTPException(409, "slot is not ready for post-handoff cleanup")
        try:
            result = await self.worker_call("cleanup", timeout=60)
        except Exception as exc:
            async with self.lock:
                self.state = "quarantined"
                self.last_error = type(exc).__name__
            return {**self.public(), "error_code": self.last_error}
        async with self.lock:
            self.state = "stopped" if result.get("state") == "idle" else "quarantined"
            if self.state == "stopped":
                self.identity = ""
                self.project_id = ""
        return self.public()

    async def validate_account_projects(self, expected_existing_project_id: str) -> dict:
        async with self.input_gate:
            async with self.lock:
                if self.state not in {"ready", "awaiting_check"}:
                    raise HTTPException(409, "登录槽位当前不能执行管理员检查")
                self.state = "checking"
            try:
                result = await self.worker_call(
                    "validate-account-projects",
                    {"expected_existing_project_id": expected_existing_project_id},
                    timeout=180,
                )
                accepted = bool(
                    result.get("success")
                    and result.get("is_logged_in")
                    and result.get("has_account_projects")
                    and result.get("state") == "validated"
                )
                async with self.lock:
                    self.state = "validated" if accepted else "ready"
                    self.last_error = "" if accepted else str(
                        result.get("error_code") or "validation_failed"
                    )[:64]
                    self.identity = str(result.get("identity") or "").strip().lower() if accepted else ""
                    self.project_id = ""
                    self.existing_project_present = bool(
                        accepted and result.get("existing_project_present")
                    )
                    if accepted and (not self.identity or "@" not in self.identity):
                        self.state = "quarantined"
                        self.last_error = "incomplete_handoff_evidence"
                        self.identity = ""
                        accepted = False
                return {
                    "success": accepted,
                    "state": self.state,
                    "has_identity": bool(self.identity),
                    "has_account_projects": bool(result.get("has_account_projects")),
                    "existing_project_present": bool(result.get("existing_project_present")),
                    "error_code": self.last_error or None,
                }
            except Exception as exc:
                async with self.lock:
                    self.state = "quarantined"
                    self.last_error = type(exc).__name__
                return {"success": False, "state": self.state, "error_code": self.last_error}


sidecar = Sidecar()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _admin(request: Request) -> None:
    if not secrets.compare_digest(request.headers.get("X-Slot3-Admin", ""), ADMIN_TOKEN):
        raise HTTPException(404, "not found")


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin", "")
    host = request.headers.get("host", "")
    from urllib.parse import urlparse
    parsed = urlparse(origin)
    if not origin or parsed.scheme != "https" or parsed.netloc != host:
        raise HTTPException(403, "same-origin HTTPS required")


@app.on_event("startup")
async def startup() -> None:
    # Uvicorn creates the UDS immediately before lifespan startup.  Set its
    # mode before the first Nginx accept so www-data can use the sidecar while
    # the socket remains unreachable to unrelated users.
    if Path(SIDEcar_SOCKET).exists():
        os.chmod(SIDEcar_SOCKET, 0o660)
    await sidecar.bootstrap()
    sidecar.schedule_expiry()


@app.get(BASE)
async def base_redirect():
    return RedirectResponse(BASE + "/", status_code=307)


@app.get(BASE + "/")
async def page():
    return HTMLResponse(HTML, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.get(BASE + "/client.js")
async def client_js():
    return HTMLResponse(JS, media_type="application/javascript",
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.post(BASE + "/claim")
async def claim(request: Request):
    _same_origin(request)
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(400, "邀请格式无效") from exc
    return await sidecar.claim(str(payload.get("capability") or ""))


@app.get(BASE + "/session")
async def session(request: Request):
    await sidecar.require_owner(request)
    return sidecar.public()


@app.post(BASE + "/complete")
async def complete(request: Request):
    _same_origin(request)
    await sidecar.require_owner(request)
    async with sidecar.lock:
        if sidecar.state != "ready":
            raise HTTPException(409, "登录槽位状态不允许提交")
        sidecar.state = "awaiting_check"
    return {"success": True, "state": "awaiting_check"}


@app.get(BASE + "/vnc/{asset:path}")
async def asset(request: Request, asset: str):
    await sidecar.require_owner(request)
    parts = Path(asset).parts
    if not parts or parts[0] not in {"app", "core", "vendor", "vnc.html", "favicon.ico"}:
        raise HTTPException(404, "file not found")
    path = (NOVNC_ROOT / asset).resolve()
    if not path.is_relative_to(NOVNC_ROOT) or not path.is_file():
        raise HTTPException(404, "file not found")
    return FileResponse(path, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.websocket(BASE + "/vnc/websockify")
async def websockify(websocket: WebSocket):
    if not sidecar._session_ok(websocket):
        await websocket.close(code=1008)
        return
    async with sidecar.lock:
        if sidecar.state not in {"ready", "awaiting_check"}:
            await websocket.close(code=1008)
            return
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    from urllib.parse import urlparse
    parsed = urlparse(origin)
    if not origin or parsed.scheme != "https" or parsed.netloc != host:
        await websocket.close(code=1008)
        return
    try:
        async with websockets.unix_connect(
            WORKER_SOCKET, uri="ws://slot3-worker/websockify",
            additional_headers=sidecar._headers("GET", "/websockify"),
            max_size=8 * 1024 * 1024, subprotocols=["binary"],
        ) as backend:
            await websocket.accept(subprotocol="binary" if "binary" in websocket.headers.get("sec-websocket-protocol", "") else None)
            async def to_backend():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    async with sidecar.input_gate:
                        async with sidecar.lock:
                            accepts_input = sidecar.state in {"ready", "awaiting_check"}
                        if accepts_input:
                            if message.get("bytes") is not None:
                                await backend.send(message["bytes"])
                            elif message.get("text") is not None:
                                await backend.send(message["text"])
            async def to_client():
                async for message in backend:
                    if isinstance(message, bytes):
                        await websocket.send_bytes(message)
                    else:
                        await websocket.send_text(message)
            tasks = [asyncio.create_task(to_backend()), asyncio.create_task(to_client())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    except (OSError, WebSocketDisconnect, websockets.exceptions.ConnectionClosed):
        pass
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass


@app.get("/__slot3_admin/status")
async def admin_status(request: Request):
    _admin(request)
    return {**sidecar.public(), "last_error": sidecar.last_error or None,
            "session_claimed": bool(sidecar.session)}


@app.get("/__slot3_admin/invite")
async def admin_invite(request: Request):
    _admin(request)
    if sidecar.session:
        raise HTTPException(409, "invite already claimed")
    if sidecar.state != "ready" or time.time() >= sidecar.expires_at:
        raise HTTPException(409, "invite unavailable")
    return {"path": BASE + "/#" + sidecar.capability, "expires_at": sidecar.expires_at}


@app.post("/__slot3_admin/rotate-invite")
async def admin_rotate_invite(request: Request):
    _admin(request)
    return await sidecar.rotate_invite()


@app.post("/__slot3_admin/validate")
async def admin_validate(request: Request):
    _admin(request)
    return await sidecar.validate()


@app.post("/__slot3_admin/validate-existing")
async def admin_validate_existing(request: Request):
    _admin(request)
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(400, "invalid request") from exc
    expected = str(payload.get("expected_existing_project_id") or "").strip()
    if not expected:
        raise HTTPException(400, "existing project is required")
    return await sidecar.validate(expected)


@app.post("/__slot3_admin/validate-account-projects")
async def admin_validate_account_projects(request: Request):
    _admin(request)
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(400, "invalid request") from exc
    expected = str(payload.get("expected_existing_project_id") or "").strip()
    if not expected:
        raise HTTPException(400, "existing project is required")
    return await sidecar.validate_account_projects(expected)


@app.post("/__slot3_admin/abort")
async def admin_abort(request: Request):
    _admin(request)
    return await sidecar.abort()


@app.get("/__slot3_admin/handoff")
async def admin_handoff(request: Request):
    _admin(request)
    return await sidecar.handoff()


@app.get("/__slot3_admin/account-handoff")
async def admin_account_handoff(request: Request):
    _admin(request)
    return await sidecar.account_handoff()


@app.post("/__slot3_admin/cleanup")
async def admin_cleanup(request: Request):
    _admin(request)
    return await sidecar.cleanup()


@app.middleware("http")
async def socket_mode(request: Request, call_next):
    if Path(SIDEcar_SOCKET).exists() and stat.S_IMODE(Path(SIDEcar_SOCKET).stat().st_mode) != 0o660:
        os.chmod(SIDEcar_SOCKET, 0o660)
    return await call_next(request)


def main() -> None:
    uvicorn.run(app, uds=SIDEcar_SOCKET, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
