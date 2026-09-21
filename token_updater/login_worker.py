"""Unprivileged, single-Profile desktop worker for one owner login slot.

The worker has no TCP network other than loopback.  Chromium reaches the
approved source proxy through one Unix-socket relay supplied by a separate
egress container.  Control and RFB traffic use a different Unix socket and
every request is short-lived, Ed25519-signed, generation-bound, and replay
protected.  The worker never mounts Updater data, logs, secrets, or another
browser Profile.
"""

import asyncio
import json
import os
import re
import secrets
import shutil
import signal
import stat
import struct
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket
from playwright.async_api import BrowserContext, Response, async_playwright

from .browser_profile import configure_web_only_profile
from .login_worker_protocol import ReplayGuard
from .proxy_utils import format_proxy_for_playwright, parse_proxy
from .session_validation import (
    CREDITS_URL,
    LABS_SESSION_URL,
    failure,
    scoped_google_cookies,
    validate_credits,
    validate_google_cookies,
    validate_labs_session,
)


PROFILE_DIR = Path(os.getenv("LOGIN_PROFILE_DIR", "/slot/profile"))
CONTROL_SOCKET = Path(os.getenv("LOGIN_WORKER_SOCKET", "/control/worker.sock"))
EGRESS_SOCKET = Path(os.getenv("LOGIN_EGRESS_SOCKET", "/egress/proxy.sock"))
ALLOW_DIRECT_TEST_EGRESS = os.getenv("LOGIN_WORKER_ALLOW_DIRECT_TEST_EGRESS") == "1"
PUBLIC_KEY = os.getenv("LOGIN_SLOT_SIGNING_PUBLIC_KEY", "")
SLOT_NUMBER = int(os.getenv("LOGIN_SLOT_NUMBER", "0"))
DISPLAY = os.getenv("DISPLAY", ":99")
RESOLUTION = os.getenv("RESOLUTION", "1365x768x24")
FLOW_URL = os.getenv(
    "FLOW_URL",
    os.getenv("LABS_URL", "https://labs.google/fx/tools/flow"),
)
LABS_AUTH_URL = os.getenv(
    "LABS_AUTH_URL",
    "https://labs.google/fx/api/auth/signin?callbackUrl=https%3A%2F%2Flabs.google%2Ffx",
)
RUNTIME_DIR = Path(os.getenv("LOGIN_WORKER_RUNTIME_DIR", "/run/flow-login-worker"))
XAUTHORITY = RUNTIME_DIR / ".Xauthority"
HOME_DIR = Path(os.getenv("HOME", "/tmp/login-worker-home"))

LOGIN_BROWSER_ARGS = [
    "--disable-extensions",
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
]

PROJECT_API_PATH = re.compile(r"^/fx/api/trpc/project\.[A-Za-z0-9_.-]+$")


def _project_id_from_url(value: Any) -> str | None:
    try:
        parsed = urlparse(str(value or ""))
    except Exception:
        return None
    if str(parsed.hostname or "").lower() not in {"flow.google.com", "labs.google"}:
        return None
    candidates: list[str] = []
    match = re.search(r"(?:^|/)(?:project|projects)/([^/?#]+)", parsed.path, re.I)
    if match:
        candidates.append(match.group(1))
    query = parse_qs(parsed.query)
    for key in ("projectId", "project_id"):
        candidates.extend(query.get(key, []))
    for candidate in candidates:
        try:
            return str(UUID(str(candidate).strip()))
        except (ValueError, TypeError, AttributeError):
            continue
    return None


def _uuid_values(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            found.update(_uuid_values(item))
    elif isinstance(value, list):
        for item in value[:1000]:
            found.update(_uuid_values(item))
    elif isinstance(value, str):
        try:
            found.add(str(UUID(value.strip())))
        except (ValueError, TypeError, AttributeError):
            pass
    return found


class LoginWorker:
    def __init__(self) -> None:
        if not PUBLIC_KEY or SLOT_NUMBER not in {1, 2}:
            raise RuntimeError("worker public key and slot number are required")
        self.guard = ReplayGuard(PUBLIC_KEY, SLOT_NUMBER)
        self.lock = asyncio.Lock()
        self.playwright = None
        self.context: BrowserContext | None = None
        self.desktop: dict[str, subprocess.Popen] = {}
        self.proxy_server = None
        self.state = "starting"
        self.generation = ""
        self.profile_id = 0
        self.proxy_url = ""
        self.provider_project_ids: set[str] = set()

    @staticmethod
    def _safe_profile_dir() -> Path:
        raw = PROFILE_DIR.absolute()
        if raw.is_symlink() or raw.parent.is_symlink():
            raise RuntimeError("Profile mount contains a symlink")
        resolved = raw.resolve()
        if resolved != raw or resolved.parent != raw.parent.resolve():
            raise RuntimeError("Profile mount escaped its direct parent")
        return resolved

    @staticmethod
    def _spawn(command: list[str], *, env: dict[str, str]) -> subprocess.Popen:
        return subprocess.Popen(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            start_new_session=True,
        )

    def _desktop_env(self) -> dict[str, str]:
        # Deliberately construct an allowlist; never pass worker/control env to
        # Chromium or the desktop processes.
        return {
            "DISPLAY": DISPLAY,
            "XAUTHORITY": str(XAUTHORITY),
            "HOME": str(HOME_DIR),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
        }

    async def start(self) -> None:
        if os.geteuid() == 0:
            raise RuntimeError("login worker refuses to run as root")
        profile_dir = self._safe_profile_dir()
        if profile_dir.stat().st_uid != os.geteuid():
            raise RuntimeError("Profile mount is not owned by the worker uid")
        HOME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        CONTROL_SOCKET.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
        CONTROL_SOCKET.unlink(missing_ok=True)
        cookie = secrets.token_hex(16)
        # Xauthority binary records are length-prefixed in network byte order.
        # FamilyWild avoids embedding a container hostname while the private
        # cookie still gates every connection to this worker's X server.
        name = b"MIT-MAGIC-COOKIE-1"
        display_number = DISPLAY.lstrip(":").split(".", 1)[0].encode("ascii")
        cookie_bytes = bytes.fromhex(cookie)
        record = b"".join([
            struct.pack("!H", 0xFFFF), struct.pack("!H", 0),
            struct.pack("!H", len(display_number)), display_number,
            struct.pack("!H", len(name)), name,
            struct.pack("!H", len(cookie_bytes)), cookie_bytes,
        ])
        XAUTHORITY.write_bytes(record)
        os.chmod(XAUTHORITY, 0o600)
        env = self._desktop_env()
        self.desktop["xvfb"] = self._spawn(
            ["Xvfb", DISPLAY, "-screen", "0", RESOLUTION, "-nolisten", "tcp",
             "-auth", str(XAUTHORITY)],
            env=env,
        )
        await asyncio.sleep(0.5)
        if self.desktop["xvfb"].poll() is not None:
            raise RuntimeError("Xvfb failed to start")
        self.desktop["fluxbox"] = self._spawn(["fluxbox"], env=env)
        if not ALLOW_DIRECT_TEST_EGRESS:
            for _ in range(120):
                if EGRESS_SOCKET.exists():
                    break
                await asyncio.sleep(0.25)
            if not EGRESS_SOCKET.exists():
                raise RuntimeError("approved egress relay socket is unavailable")
            self.proxy_server = await asyncio.start_server(
                self._relay_proxy_connection, "127.0.0.1", 18088
            )
        await self._start_vnc()
        self.playwright = await async_playwright().start()
        self.state = "quarantined" if any(profile_dir.iterdir()) else "idle"

    @staticmethod
    async def _copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            try:
                writer.write_eof()
            except (OSError, RuntimeError):
                pass

    async def _relay_proxy_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_unix_connection(EGRESS_SOCKET)
            tasks = [
                asyncio.create_task(self._copy_stream(reader, upstream_writer)),
                asyncio.create_task(self._copy_stream(upstream_reader, writer)),
            ]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            upstream_writer.close()
            await upstream_writer.wait_closed()
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _start_vnc(self) -> None:
        process = self.desktop.get("x11vnc")
        if process and process.poll() is None:
            return
        self.desktop["x11vnc"] = self._spawn([
            "x11vnc", "-display", DISPLAY, "-auth", str(XAUTHORITY),
            "-forever", "-shared", "-localhost", "-rfbport", "5900",
            "-nopw", "-noxdamage",
        ], env=self._desktop_env())
        await asyncio.sleep(0.25)
        if self.desktop["x11vnc"].poll() is not None:
            raise RuntimeError("x11vnc failed to start")

    async def _stop_vnc(self) -> None:
        process = self.desktop.get("x11vnc")
        if not process or process.poll() is not None:
            return
        os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
        except asyncio.TimeoutError:
            os.killpg(process.pid, signal.SIGKILL)
            await asyncio.to_thread(process.wait)

    async def _record_provider_project_response(self, response: Response) -> None:
        try:
            parsed = urlparse(response.url)
            content_type = (await response.header_value("content-type") or "").lower()
            if (
                response.request.method != "GET"
                or parsed.scheme != "https"
                or parsed.hostname != "labs.google"
                or not PROJECT_API_PATH.fullmatch(parsed.path)
                or response.status != 200
                or "json" not in content_type
            ):
                return
            payload = await response.json()
            self.provider_project_ids.update(_uuid_values(payload))
        except Exception:
            return

    @staticmethod
    def _normalize_email(value: Any) -> str:
        email = str(value or "").strip().lower()
        return email if email and "@" in email else ""

    @staticmethod
    async def _session_cookie(context: BrowserContext) -> str | None:
        cookies = await context.cookies("https://labs.google")
        candidates = [
            cookie for cookie in cookies
            if cookie.get("name") == "__Secure-next-auth.session-token"
            or str(cookie.get("name") or "").startswith("__Secure-next-auth.session-token.")
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda cookie: str(cookie.get("name") or ""))
        value = "".join(str(cookie.get("value") or "") for cookie in candidates)
        return value or None

    async def _validate_context_session(self, expected_email: str = "") -> dict:
        responses = []
        try:
            response = await self.context.request.get(
                LABS_SESSION_URL, timeout=20000, max_redirects=0,
                headers={"Accept": "application/json"},
            )
            responses.append(response)
            if response.status == 401:
                return failure("auth_required", "Labs 授权已失效，请重新授权")
            if response.status != 200:
                return failure("verification_unavailable", "Labs 会话校验暂不可用")
            validated = validate_labs_session(await response.json(), expected_email)
            if not validated.get("success"):
                return validated
            response = await self.context.request.get(
                CREDITS_URL, timeout=20000, max_redirects=0,
                headers={"Authorization": "Bearer " + validated["access_token"]},
            )
            responses.append(response)
            credits = validate_credits(
                response.status, await response.json() if response.status == 200 else None
            )
            if not credits.get("success"):
                return credits
            if not await self._session_cookie(self.context):
                return failure("auth_required", "Labs 会话 Cookie 缺失")
            return {"success": True, "email": validated["email"]}
        except Exception:
            return failure("verification_unavailable", "源账号鉴权请求失败")
        finally:
            for response in responses:
                try:
                    await response.dispose()
                except Exception:
                    pass

    async def _open_browser(self) -> None:
        if self.context is not None:
            return
        if not self.playwright:
            raise RuntimeError("worker is not initialized")
        profile_dir = self._safe_profile_dir()
        configure_web_only_profile(profile_dir)
        proxy = None
        if self.proxy_url != "direct://":
            parsed = parse_proxy(self.proxy_url)
            if not parsed:
                raise RuntimeError("assigned source proxy is invalid")
            proxy = format_proxy_for_playwright(parsed)
        self.context = await self.playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=False,
            env=self._desktop_env(),
            viewport={"width": 1365, "height": 768},
            locale="en-US",
            timezone_id="America/New_York",
            proxy=proxy,
            args=LOGIN_BROWSER_ARGS,
            ignore_default_args=[
                "--enable-automation", "--no-sandbox", "--disable-dev-shm-usage",
            ],
        )
        self.context.on("response", self._record_provider_project_response)
        flow_page = self.context.pages[0] if self.context.pages else await self.context.new_page()
        await flow_page.goto(FLOW_URL, wait_until="domcontentloaded", timeout=90000)
        labs_page = await self.context.new_page()
        await labs_page.goto(LABS_AUTH_URL, wait_until="domcontentloaded", timeout=90000)

    def _scope(self, generation: str, profile_id: int) -> None:
        if generation != self.generation or profile_id != self.profile_id:
            raise HTTPException(409, "worker assignment does not match")

    async def assign(self, generation: str, profile_id: int, proxy_url: str) -> dict:
        async with self.lock:
            if self.state != "idle" or self.context is not None:
                raise HTTPException(409, "worker is not empty and idle")
            if any(self._safe_profile_dir().iterdir()):
                self.state = "quarantined"
                raise HTTPException(409, "worker Profile contains retained data")
            if proxy_url != "http://127.0.0.1:18088" and not (
                proxy_url == "direct://" and ALLOW_DIRECT_TEST_EGRESS
            ):
                raise HTTPException(400, "worker accepts only its assigned source-proxy route")
            self.generation = generation
            self.profile_id = profile_id
            self.proxy_url = proxy_url
            self.provider_project_ids.clear()
            self.state = "starting_browser"
            try:
                await self._open_browser()
            except Exception:
                self.state = "quarantined"
                raise
            self.state = "ready"
            return self.public()

    async def validate(self, generation: str, profile_id: int) -> dict:
        async with self.lock:
            self._scope(generation, profile_id)
            if self.state != "ready" or self.context is None:
                raise HTTPException(409, "browser is not ready for validation")
            self.state = "checking"
            await self._stop_vnc()
            result: dict[str, Any]
            try:
                initial = await self._validate_context_session("")
                checked = validate_google_cookies(
                    scoped_google_cookies(await self.context.cookies())
                ) if initial.get("success") else initial
                identity = self._normalize_email(initial.get("email") or "")
                candidates = {
                    item for page in list(self.context.pages or [])
                    if (item := _project_id_from_url(getattr(page, "url", "")))
                }
                await asyncio.sleep(0.25)
                final = await self._validate_context_session(identity)
                final_checked = validate_google_cookies(
                    scoped_google_cookies(await self.context.cookies())
                ) if final.get("success") else final
                final_identity = self._normalize_email(final.get("email") or "")
                project_ids = candidates & self.provider_project_ids
                if not initial.get("success") or not checked.get("success"):
                    result = initial if not initial.get("success") else checked
                elif not final.get("success") or not final_checked.get("success") or final_identity != identity:
                    result = {"success": False, "error_code": "context_changed",
                              "error": "验证期间身份或 Cookie 发生变化"}
                elif len(project_ids) != 1:
                    result = {"success": False, "error_code": "project_ownership_unverified",
                              "error": "未从同一身份的只读 provider 响应确认唯一 Flow 项目"}
                else:
                    project_id = next(iter(project_ids))
                    await self.context.close()
                    self.context = None
                    if await self._profile_browser_processes():
                        raise RuntimeError("browser still owns the Profile after close")
                    self.state = "validated"
                    return {
                        **self.public(),
                        "success": True,
                        "is_logged_in": True,
                        "has_flow_project": True,
                        "identity": final_identity,
                        "project_id": project_id,
                    }
            except Exception:
                result = {"success": False, "error_code": "verification_unavailable",
                          "error": "worker 无法完成无成本检查；Profile 已保留"}
            self.state = "ready"
            await self._start_vnc()
            return {**self.public(), **result, "is_logged_in": False, "has_flow_project": False}

    async def _profile_browser_processes(self) -> list[int]:
        needle = str(self._safe_profile_dir()).encode()
        found: list[int] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                if needle in (entry / "cmdline").read_bytes():
                    found.append(int(entry.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
        return found

    async def cleanup(self, generation: str, profile_id: int) -> dict:
        async with self.lock:
            self._scope(generation, profile_id)
            if self.state != "validated" or self.context is not None:
                raise HTTPException(409, "worker has not released a validated Profile")
            if await self._profile_browser_processes():
                self.state = "quarantined"
                raise HTTPException(409, "browser still owns the Profile")
            root = self._safe_profile_dir()
            for child in list(root.iterdir()):
                if child.is_symlink() or child.is_file():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
                else:
                    raise HTTPException(409, "unsupported Profile entry")
            result = {**self.public(), "state": "idle", "browser_running": False}
            self.generation = ""
            self.profile_id = 0
            self.proxy_url = ""
            self.provider_project_ids.clear()
            self.state = "idle"
            return result

    async def abort(self, generation: str, profile_id: int) -> dict:
        async with self.lock:
            self._scope(generation, profile_id)
            await self._stop_vnc()
            if self.context:
                await self.context.close()
                self.context = None
            self.state = "quarantined" if any(self._safe_profile_dir().iterdir()) else "idle"
            result = self.public()
            if self.state == "idle":
                self.generation = ""
                self.profile_id = 0
                self.proxy_url = ""
                self.provider_project_ids.clear()
            return result

    def public(self) -> dict:
        desktop_ready = all(
            self.desktop.get(name) and self.desktop[name].poll() is None
            for name in ("xvfb", "fluxbox")
        ) and (
            ALLOW_DIRECT_TEST_EGRESS
            or (self.proxy_server is not None and self.proxy_server.is_serving())
        )
        return {
            "state": self.state,
            "desktop_ready": bool(desktop_ready),
            "browser_running": self.context is not None,
            "uid": os.geteuid(),
            "slot": SLOT_NUMBER,
            "generation": self.generation,
            "profile_id": self.profile_id,
        }

    async def relay_rfb(self, websocket: WebSocket, generation: str, profile_id: int) -> None:
        async with self.lock:
            self._scope(generation, profile_id)
            if self.state not in {"ready", "checking"} or self.context is None:
                await websocket.close(code=1008)
                return
        reader, writer = await asyncio.open_connection("127.0.0.1", 5900)
        await websocket.accept(subprotocol="binary" if "binary" in websocket.headers.get("sec-websocket-protocol", "") else None)

        async def to_rfb() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                data = message.get("bytes")
                if data is None and message.get("text") is not None:
                    data = message["text"].encode()
                if data:
                    writer.write(data)
                    await writer.drain()

        async def to_client() -> None:
            while data := await reader.read(65536):
                await websocket.send_bytes(data)

        tasks = [asyncio.create_task(to_rfb()), asyncio.create_task(to_client())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        await writer.wait_closed()

    async def stop(self) -> None:
        async with self.lock:
            if self.context:
                try:
                    await self.context.close()
                except Exception:
                    pass
                self.context = None
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
            if self.proxy_server:
                self.proxy_server.close()
                await self.proxy_server.wait_closed()
                self.proxy_server = None
            for process in reversed(list(self.desktop.values())):
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            for process in reversed(list(self.desktop.values())):
                if process.poll() is None:
                    try:
                        await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
                    except asyncio.TimeoutError:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await asyncio.to_thread(process.wait)
            self.desktop.clear()
            self.state = "stopped"


worker = LoginWorker()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _authorized(request: Request, path: str) -> tuple[str, int, dict]:
    body = await request.body()
    try:
        generation, profile_id = worker.guard.verify(
            request.headers, method=request.method, path=path, body=body
        )
        payload = json.loads(body) if body else {}
        if not isinstance(payload, dict):
            raise ValueError("request body must be an object")
        return generation, profile_id, payload
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(401, "invalid signed worker request") from exc


@app.on_event("startup")
async def _startup() -> None:
    await worker.start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await worker.stop()


@app.post("/assign")
async def assign(request: Request) -> dict:
    generation, profile_id, payload = await _authorized(request, "/assign")
    proxy_url = str(payload.get("proxy_url") or "")
    return await worker.assign(generation, profile_id, proxy_url)


@app.post("/validate")
async def validate(request: Request) -> dict:
    generation, profile_id, _ = await _authorized(request, "/validate")
    return await worker.validate(generation, profile_id)


@app.post("/cleanup")
async def cleanup(request: Request) -> dict:
    generation, profile_id, _ = await _authorized(request, "/cleanup")
    return await worker.cleanup(generation, profile_id)


@app.post("/abort")
async def abort(request: Request) -> dict:
    generation, profile_id, _ = await _authorized(request, "/abort")
    return await worker.abort(generation, profile_id)


@app.post("/status")
async def status(request: Request) -> dict:
    generation, profile_id, _ = await _authorized(request, "/status")
    worker._scope(generation, profile_id)
    return worker.public()


@app.middleware("http")
async def _fix_control_socket_mode(request: Request, call_next):
    if CONTROL_SOCKET.exists() and stat.S_IMODE(CONTROL_SOCKET.stat().st_mode) != 0o660:
        os.chmod(CONTROL_SOCKET, 0o660)
    return await call_next(request)


@app.websocket("/websockify")
async def websockify(websocket: WebSocket) -> None:
    try:
        generation, profile_id = worker.guard.verify(
            websocket.headers, method="GET", path="/websockify", body=b""
        )
    except ValueError:
        await websocket.close(code=1008)
        return
    try:
        await worker.relay_rfb(websocket, generation, profile_id)
    except Exception:
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass


def main() -> None:
    uvicorn.run(app, uds=str(CONTROL_SOCKET), log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
