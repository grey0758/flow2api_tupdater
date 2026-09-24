"""Temporary, login-only VNC invitation for an already running slot worker.

This process owns no Updater database, browser profile, signing key, receiver
secret, or provider credential.  It shares only the selected worker's network
namespace and relays an authenticated noVNC WebSocket to that namespace's
loopback-only x11vnc listener.

The invitation capability is created in memory and handed to the operator once
through a mode-0600 file on a tmpfs-backed host runtime directory.  The public
URL carries it in the fragment, which browsers do not send to Nginx or this
application.  A successful claim replaces it with an HttpOnly owner session.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from uvicorn.config import Config
from uvicorn.server import Server
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse


BASE = "/login-slot1-reissue"
COOKIE_NAME = "flow_login_slot1_reissue"
INVITE_TTL = 4 * 60 * 60
RFB_HOST = "127.0.0.1"
RFB_PORT = 5900
RUNTIME_DIR = Path(os.getenv("LOGIN_REISSUE_RUNTIME_DIR", "/gateway"))
SOCKET_PATH = RUNTIME_DIR / "sidecar.sock"
HANDOFF_PATH = RUNTIME_DIR / "invite"
NOVNC_ROOT = Path("/usr/share/novnc").resolve()


HTML = """<!doctype html>
<html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>Flow 登录槽位 1</title>
<style>body{font:16px system-ui;margin:0;background:#101827;color:#fff}header{padding:12px 18px;line-height:1.5}iframe{border:0;width:100vw;height:calc(100vh - 100px)}.hidden{display:none}</style></head>
<body><header><strong id=\"title\">正在验证专属邀请…</strong><span id=\"instructions\" class=\"hidden\">请在下方已经打开的原 ID10 项目中完成 Sign in with Google；不要创建新项目、切换身份或导出 Cookie。完成后保持项目页面打开，无需点击确认。</span><span id=\"status\"></span></header>
<iframe id=\"vnc\" class=\"hidden\" title=\"专属 VNC\"></iframe><script src=\"/login-slot1-reissue/client.js\"></script></body></html>"""

JS = """const title=document.getElementById('title'),instructions=document.getElementById('instructions'),status=document.getElementById('status'),frame=document.getElementById('vnc');
async function json(path,opt={}){const r=await fetch(path,{...opt,headers:{'Content-Type':'application/json',...(opt.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.detail||'登录槽位不可用');return d}
async function init(){const capability=decodeURIComponent(location.hash.slice(1));if(capability){history.replaceState(null,'','/login-slot1-reissue/');await json('/login-slot1-reissue/claim',{method:'POST',body:JSON.stringify({capability})})}else{await json('/login-slot1-reissue/session')}title.textContent='独立登录槽位 1 / Profile14';instructions.classList.remove('hidden');frame.src='/login-slot1-reissue/vnc/vnc.html?autoconnect=1&resize=scale&path='+encodeURIComponent('login-slot1-reissue/vnc/websockify');frame.classList.remove('hidden')}
setInterval(async()=>{try{await json('/login-slot1-reissue/session');status.textContent=' 完成可见授权后保持原项目打开；管理员稍后执行一次无成本检查。'}catch(_){frame.remove();status.textContent=' 登录邀请已过期；请联系管理员。'}},5000);init().catch(e=>{title.textContent=e.message;status.textContent=' 请联系管理员。'});"""


class Invitation:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.capability = secrets.token_urlsafe(32)
        self.session = ""
        self.expires_at = time.time() + INVITE_TTL

    def session_ok(self, request: Request | WebSocket) -> bool:
        supplied = request.cookies.get(COOKIE_NAME, "")
        return bool(
            self.session
            and time.time() < self.expires_at
            and supplied
            and secrets.compare_digest(supplied, self.session)
        )

    async def claim(self, capability: str) -> JSONResponse:
        async with self.lock:
            if time.time() >= self.expires_at:
                raise HTTPException(410, "邀请已过期")
            if self.session:
                raise HTTPException(409, "邀请已经被领取")
            if not capability or not secrets.compare_digest(capability, self.capability):
                raise HTTPException(404, "邀请不存在")
            self.session = secrets.token_urlsafe(32)
            self.capability = ""
            response = JSONResponse({"slot": 1, "profile_id": 14, "state": "ready"})
            response.set_cookie(
                COOKIE_NAME,
                self.session,
                max_age=max(1, int(self.expires_at - time.time())),
                httponly=True,
                secure=True,
                samesite="strict",
                path=BASE,
            )
            return response


invitation = Invitation()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _same_origin(headers) -> bool:
    origin = headers.get("origin", "")
    host = headers.get("host", "")
    parsed = urlparse(origin)
    return bool(origin and parsed.scheme == "https" and parsed.netloc == host)


def _write_handoff_once() -> None:
    RUNTIME_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    payload = json.dumps(
        {"path": f"{BASE}/#{invitation.capability}", "expires_at": invitation.expires_at},
        separators=(",", ":"),
    ).encode()
    fd = os.open(HANDOFF_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


@app.on_event("startup")
async def startup() -> None:
    if SOCKET_PATH.exists():
        os.chmod(SOCKET_PATH, 0o660)
    _write_handoff_once()


@app.get(BASE)
async def base_redirect():
    return RedirectResponse(BASE + "/", status_code=307)


@app.get(BASE + "/")
async def page():
    return HTMLResponse(
        HTML,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.get(BASE + "/client.js")
async def client_js():
    return HTMLResponse(
        JS,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.post(BASE + "/claim")
async def claim(request: Request):
    if not _same_origin(request.headers):
        raise HTTPException(403, "same-origin HTTPS required")
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(400, "邀请格式无效") from exc
    return await invitation.claim(str(payload.get("capability") or ""))


@app.get(BASE + "/session")
async def session(request: Request):
    if not invitation.session_ok(request):
        raise HTTPException(401, "登录会话不存在或已过期")
    return {"slot": 1, "profile_id": 14, "state": "ready"}


@app.get(BASE + "/vnc/{asset:path}")
async def asset(request: Request, asset: str):
    if not invitation.session_ok(request):
        raise HTTPException(401, "登录会话不存在或已过期")
    parts = Path(asset).parts
    if not parts or parts[0] not in {"app", "core", "vendor", "vnc.html", "favicon.ico"}:
        raise HTTPException(404, "file not found")
    path = (NOVNC_ROOT / asset).resolve()
    if not path.is_relative_to(NOVNC_ROOT) or not path.is_file():
        raise HTTPException(404, "file not found")
    return FileResponse(
        path,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


async def _client_to_rfb(websocket: WebSocket, writer: asyncio.StreamWriter) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        data = message.get("bytes")
        if data is None:
            raise WebSocketDisconnect(code=1003)
        writer.write(data)
        await writer.drain()


async def _rfb_to_client(reader: asyncio.StreamReader, websocket: WebSocket) -> None:
    while data := await reader.read(65536):
        await websocket.send_bytes(data)


async def _expiry_guard() -> None:
    await asyncio.sleep(max(0, invitation.expires_at - time.time()))


@app.websocket(BASE + "/vnc/websockify")
async def websockify(websocket: WebSocket):
    if not invitation.session_ok(websocket) or not _same_origin(websocket.headers):
        await websocket.close(code=1008)
        return
    reader = None
    writer = None
    try:
        reader, writer = await asyncio.open_connection(RFB_HOST, RFB_PORT)
        offered = websocket.headers.get("sec-websocket-protocol", "")
        await websocket.accept(subprotocol="binary" if "binary" in offered else None)
        tasks = [
            asyncio.create_task(_client_to_rfb(websocket, writer)),
            asyncio.create_task(_rfb_to_client(reader, websocket)),
            asyncio.create_task(_expiry_guard()),
        ]
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except (ConnectionError, OSError, WebSocketDisconnect):
        pass
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        try:
            await websocket.close()
        except RuntimeError:
            pass


def main() -> None:
    # Uvicorn deliberately chmods a UDS to 0666 after bind.  Keep the parent
    # private and tighten the live socket immediately after bind, before the
    # server begins accepting requests.
    class RestrictedUdsServer(Server):
        async def startup(self, sockets=None) -> None:
            await super().startup(sockets=sockets)
            os.chmod(SOCKET_PATH, 0o660)

    RestrictedUdsServer(
        Config(app, uds=str(SOCKET_PATH), access_log=False, log_level="warning")
    ).run()


if __name__ == "__main__":
    main()
