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
from urllib.parse import parse_qs, unquote_plus, urlparse
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
PROJECT_DOCUMENT_PATH = re.compile(
    r"^/(?:project|projects)/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/?$"
)
MODERN_FLOW_HOME_URL = "https://flow.google.com/"
MODERN_USER_PROJECT_RPC_IDS = frozenset({
    # Current Angular homepage project query paths. SearchUserProjects is the
    # active semantic path; GetProjects is its feature-flagged legacy path.
    "OylIJd",  # /AiSandbox.SearchUserProjects
    "UpteDb",  # /FlowService.GetProjects
})
MODERN_PROJECT_SCOPED_RPC_IDS = frozenset({
    "rEhmZd",  # /FlowService.ListCollections
    "Zzl0ze",  # /FlowService.GetProjectContents
    "bOKtO",  # /FlowService.ListMedia
    "ncZTKe",  # /FlowService.ListSceneWorkflows
    "Xffewf",  # /FlowService.ListScenes
    "kGwJ9b",  # /FlowService.ListWorkflows
    "GI4k8",  # /AiSandbox.SearchProjectScenes
    "SIzNd",  # /AiSandbox.SearchProjectWorkflows
    "ngNC2",  # /AiSandbox.GetProject
})
UUID_TEXT_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![0-9A-Fa-f])"
)
PROJECT_DENIAL_MARKERS = (
    "access denied",
    "request access",
    "you don't have access",
    "you do not have access",
    "project not found",
    "doesn't exist",
    "try signing in with a different account",
    "unsupported country",
    "country/region is not supported",
    "country or region is not supported",
    "sign in with google",
    "无权访问",
    "请求访问权限",
    "项目不存在",
    "换一个账号",
    "所在国家/地区暂不支持",
)
PROJECT_EDITOR_MARKERS = (
    "create with flow",
    "scenebuilder",
    "frames to video",
    "ingredients to video",
    "text to video",
    "start creating or drop media",
)
PROJECT_MEDIA_WORKSPACE_MARKERS = (
    "all media",
    "characters",
    "scenes",
    "uploads",
)
PROJECT_MEDIA_WORKSPACE_PROMPTS = (
    "what would you like to create?",
    "what do you want to create?",
)


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
        if not PUBLIC_KEY or SLOT_NUMBER not in {1, 2, 3}:
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
        self.accessible_document_ids: set[str] = set()
        self.validation_candidate_ids: set[str] = set()
        self.project_probe_counts: dict[str, int] = {}
        self.project_probe_rpc_ids: set[str] = set()

    def _probe_count(self, key: str) -> None:
        if key in {
            "flow_rpc_post", "rpc_ids_known", "rpc_ids_other",
            "known_status_200", "known_content_type", "known_success_envelope",
            "scoped_candidate_match", "user_list_candidate_match",
        }:
            self.project_probe_counts[key] = min(999, self.project_probe_counts.get(key, 0) + 1)

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
            rpc_ids = {
                rpc_id
                for value in parse_qs(parsed.query).get("rpcids", [])
                for rpc_id in value.split(",")
                if rpc_id
            }
            if (
                parsed.scheme == "https"
                and parsed.hostname == "flow.google.com"
                and parsed.path.endswith("/data/batchexecute")
                and response.request.method == "POST"
            ):
                self._probe_count("flow_rpc_post")
                self.project_probe_rpc_ids.update(
                    item for item in rpc_ids
                    if len(item) <= 12 and re.fullmatch(r"[A-Za-z0-9_-]+", item)
                )
                if rpc_ids & (MODERN_USER_PROJECT_RPC_IDS | MODERN_PROJECT_SCOPED_RPC_IDS):
                    self._probe_count("rpc_ids_known")
                    if response.status == 200:
                        self._probe_count("known_status_200")
                        if "json" in content_type or "text/plain" in content_type:
                            self._probe_count("known_content_type")
                else:
                    self._probe_count("rpc_ids_other")
            is_legacy_api = (
                response.request.method == "GET"
                and parsed.scheme == "https"
                and parsed.hostname == "labs.google"
                and PROJECT_API_PATH.fullmatch(parsed.path) is not None
                and response.status == 200
                and "json" in content_type
            )
            is_modern_document = (
                response.request.method == "GET"
                and response.request.resource_type == "document"
                and parsed.scheme == "https"
                and parsed.hostname == "flow.google.com"
                and PROJECT_DOCUMENT_PATH.fullmatch(parsed.path) is not None
                and response.status == 200
                and "text/html" in content_type
            )
            is_modern_user_project_list = (
                response.request.method == "POST"
                and parsed.scheme == "https"
                and parsed.hostname == "flow.google.com"
                and parsed.path.endswith("/data/batchexecute")
                and bool(rpc_ids & MODERN_USER_PROJECT_RPC_IDS)
                and response.status == 200
                and ("json" in content_type or "text/plain" in content_type)
            )
            is_modern_project_scoped_read = (
                response.request.method == "POST"
                and parsed.scheme == "https"
                and parsed.hostname == "flow.google.com"
                and parsed.path.endswith("/data/batchexecute")
                and bool(rpc_ids & MODERN_PROJECT_SCOPED_RPC_IDS)
                and response.status == 200
                and ("json" in content_type or "text/plain" in content_type)
            )
            if not any((
                is_legacy_api,
                is_modern_document,
                is_modern_user_project_list,
                is_modern_project_scoped_read,
            )):
                return
            if is_legacy_api:
                payload = await response.json()
                self.provider_project_ids.update(_uuid_values(payload))
                return
            if is_modern_user_project_list or is_modern_project_scoped_read:
                document = await response.text()
                permitted_ids = (
                    MODERN_USER_PROJECT_RPC_IDS
                    if is_modern_user_project_list
                    else MODERN_PROJECT_SCOPED_RPC_IDS
                )
                successful_rpc_ids = {
                    rpc_id for rpc_id in rpc_ids & permitted_ids
                    if re.search(
                        rf'\[\s*"wrb\.fr"\s*,\s*"{re.escape(rpc_id)}"',
                        document,
                    )
                }
                if not successful_rpc_ids:
                    return
                self._probe_count("known_success_envelope")
                if is_modern_user_project_list:
                    matched_ids = {
                        str(UUID(match.group(0)))
                        for match in UUID_TEXT_PATTERN.finditer(document)
                    }
                    if matched_ids & self.validation_candidate_ids:
                        self._probe_count("user_list_candidate_match")
                    self.provider_project_ids.update(matched_ids)
                else:
                    request_body = unquote_plus(
                        str(getattr(response.request, "post_data", "") or "")
                    )
                    request_ids = {
                        str(UUID(match.group(0)))
                        for match in UUID_TEXT_PATTERN.finditer(request_body)
                    }
                    matched_ids = request_ids & self.validation_candidate_ids
                    if matched_ids:
                        self._probe_count("scoped_candidate_match")
                    self.provider_project_ids.update(matched_ids)
                return
            project_id = _project_id_from_url(response.url)
            if not project_id:
                return
            document = (await response.text()).lower()
            if any(marker in document for marker in PROJECT_DENIAL_MARKERS):
                return
            # A modern SPA document can be a generic HTTP 200 shell.  It
            # establishes a candidate for the visible-access check below,
            # but is not an account-bound provider ownership assertion.
            self.accessible_document_ids.add(project_id)
        except Exception:
            return

    async def _project_page_is_accessible(self, project_id: str) -> bool:
        """Require the same context to render the exact project without denial UI."""
        if self.context is None:
            return False
        for page in list(self.context.pages or []):
            if _project_id_from_url(getattr(page, "url", "")) != project_id:
                continue
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                for _ in range(40):
                    if _project_id_from_url(getattr(page, "url", "")) != project_id:
                        break
                    body = (
                        await page.locator("body").inner_text(timeout=10000)
                    ).strip().lower()
                    normalized_body = " ".join(body.split())
                    if any(marker in body for marker in PROJECT_DENIAL_MARKERS):
                        break
                    has_editor = any(
                        marker in body for marker in PROJECT_EDITOR_MARKERS
                    )
                    has_media_workspace = all(
                        marker in normalized_body
                        for marker in PROJECT_MEDIA_WORKSPACE_MARKERS
                    ) and any(
                        prompt in normalized_body
                        for prompt in PROJECT_MEDIA_WORKSPACE_PROMPTS
                    )
                    if has_editor or has_media_workspace:
                        return True
                    await asyncio.sleep(0.5)
            except Exception:
                continue
        return False

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
        pages = list(self.context.pages)
        # A recovered browser may already be inside its own Flow project.
        # Preserve that tab; its current authenticated document is reloaded
        # during validation to prove ownership against the current identity.
        if not any(_project_id_from_url(getattr(page, "url", "")) for page in pages):
            flow_page = pages[0] if pages else await self.context.new_page()
            await flow_page.goto(FLOW_URL, wait_until="domcontentloaded", timeout=90000)
        if not any(
            urlparse(getattr(page, "url", "")).hostname == "labs.google"
            for page in self.context.pages
        ):
            labs_page = await self.context.new_page()
            await labs_page.goto(LABS_AUTH_URL, wait_until="domcontentloaded", timeout=90000)

    async def _refresh_project_documents(self) -> set[str]:
        """Re-read only visible project tabs from this exact browser context."""
        candidates: set[str] = set()
        self.provider_project_ids.clear()
        self.accessible_document_ids.clear()
        for page in list(self.context.pages or []):
            project_id = _project_id_from_url(getattr(page, "url", ""))
            if not project_id:
                continue
            candidates.add(project_id)
        self.validation_candidate_ids = set(candidates)
        for page in list(self.context.pages or []):
            project_id = _project_id_from_url(getattr(page, "url", ""))
            if not project_id:
                continue
            try:
                response = await page.reload(wait_until="domcontentloaded", timeout=90000)
                if response is not None:
                    await self._record_provider_project_response(response)
            except Exception:
                continue
        return candidates

    async def _refresh_current_user_project_membership(self, candidates: set[str]) -> None:
        """Trigger only the modern read-only current-user project listing.

        The provider response listener records UUIDs only from a successful
        SearchUserProjects/GetProjects RPC. Opening the homepage in a
        disposable tab avoids treating the generic project SPA document as
        ownership evidence and preserves the owner's exact project tab.
        """
        if self.context is None or not candidates:
            return
        page = None
        try:
            page = await self.context.new_page()
            await page.goto(
                MODERN_FLOW_HOME_URL,
                wait_until="domcontentloaded",
                timeout=90000,
            )
            for _ in range(40):
                if candidates & self.provider_project_ids:
                    return
                await asyncio.sleep(0.25)
        except Exception:
            return
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass

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
            self.accessible_document_ids.clear()
            self.validation_candidate_ids.clear()
            self.state = "starting_browser"
            try:
                await self._open_browser()
            except Exception:
                self.state = "quarantined"
                raise
            self.state = "ready"
            return self.public()

    async def recover(self, generation: str, profile_id: int, proxy_url: str) -> dict:
        """Reopen only this worker's retained, unowned Profile after expiry.

        The signed control plane must bind the original claimed Profile to
        this exact slot; this worker has no Updater database or other mount.
        No old generation or invitation is reused.
        """
        async with self.lock:
            profile_dir = self._safe_profile_dir()
            if (
                self.state != "quarantined" or self.context is not None
                or self.generation or self.profile_id or not any(profile_dir.iterdir())
                or profile_dir.stat().st_uid != os.geteuid()
            ):
                raise HTTPException(409, "worker is not an unowned retained Profile")
            if await self._profile_browser_processes():
                raise HTTPException(409, "a browser still owns the retained Profile")
            self._remove_stale_browser_locks()
            if proxy_url != "http://127.0.0.1:18088" and not (
                proxy_url == "direct://" and ALLOW_DIRECT_TEST_EGRESS
            ):
                raise HTTPException(400, "worker accepts only its assigned source-proxy route")
            self.generation = generation
            self.profile_id = profile_id
            self.proxy_url = proxy_url
            self.provider_project_ids.clear()
            self.accessible_document_ids.clear()
            self.validation_candidate_ids.clear()
            self.state = "starting_browser"
            try:
                await self._open_browser()
            except Exception:
                self.state = "quarantined"
                raise
            self.state = "ready"
            return self.public()

    async def validate(
        self,
        generation: str,
        profile_id: int,
        expected_existing_project_id: str = "",
    ) -> dict:
        async with self.lock:
            self._scope(generation, profile_id)
            if self.state != "ready" or self.context is None:
                raise HTTPException(409, "browser is not ready for validation")
            self.state = "checking"
            self.project_probe_counts.clear()
            self.project_probe_rpc_ids.clear()
            await self._stop_vnc()
            result: dict[str, Any]
            try:
                expected_project_id = ""
                if expected_existing_project_id:
                    try:
                        expected_project_id = str(UUID(expected_existing_project_id.strip()))
                    except (ValueError, TypeError, AttributeError):
                        result = {
                            "success": False,
                            "error_code": "existing_project_invalid",
                            "error": "既有项目校验目标格式无效",
                        }
                        self.state = "ready"
                        await self._start_vnc()
                        return {
                            **self.public(), **result,
                            "is_logged_in": False, "has_flow_project": False,
                        }
                initial = await self._validate_context_session("")
                checked = validate_google_cookies(
                    scoped_google_cookies(await self.context.cookies())
                ) if initial.get("success") else initial
                identity = self._normalize_email(initial.get("email") or "")
                if checked.get("success") and expected_project_id:
                    existing_page = await self.context.new_page()
                    try:
                        await existing_page.goto(
                            f"https://flow.google.com/project/{expected_project_id}",
                            wait_until="domcontentloaded",
                            timeout=90000,
                        )
                    except Exception:
                        pass
                candidates = await self._refresh_project_documents() if checked.get("success") else set()
                if expected_project_id:
                    candidates &= {expected_project_id}
                    self.validation_candidate_ids = set(candidates)
                if checked.get("success"):
                    await self._refresh_current_user_project_membership(candidates)
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
                              "error": "项目页面可访问，但缺少绑定当前身份的只读 provider 项目归属响应",
                              "probe_counts": dict(self.project_probe_counts),
                              "probe_rpc_ids": sorted(self.project_probe_rpc_ids)[:12],
                              "candidate_count": len(candidates),
                              "candidate_visible": bool(
                                  len(candidates) == 1
                                  and await self._project_page_is_accessible(next(iter(candidates)))
                              )}
                else:
                    project_id = next(iter(project_ids))
                    if not await self._project_page_is_accessible(project_id):
                        result = {
                            "success": False,
                            "error_code": "project_ownership_unverified",
                            "error": "同一浏览器中的 Flow 项目页面未通过可见访问检查",
                        }
                    else:
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

    async def validate_account_projects(
        self,
        generation: str,
        profile_id: int,
        expected_existing_project_id: str = "",
    ) -> dict:
        """Validate current identity and read-only account project membership.

        This is the existing-token recovery branch.  It never accepts a UUID
        supplied by an operator as proof, never creates or mutates a project,
        and returns no identity, UUID, payload or URL.  The expected UUID is
        used only for a boolean local comparison against the provider's
        authenticated SearchUserProjects/GetProjects response.
        """
        async with self.lock:
            self._scope(generation, profile_id)
            if self.state != "ready" or self.context is None:
                raise HTTPException(409, "browser is not ready for validation")
            self.state = "checking"
            self.project_probe_counts.clear()
            self.project_probe_rpc_ids.clear()
            await self._stop_vnc()
            result: dict[str, Any]
            try:
                expected = ""
                if expected_existing_project_id:
                    try:
                        expected = str(UUID(expected_existing_project_id.strip()))
                    except (ValueError, TypeError, AttributeError):
                        result = failure("existing_project_invalid", "既有项目校验目标格式无效")
                    else:
                        result = {}
                else:
                    result = {}
                initial = await self._validate_context_session("") if not result else result
                checked = validate_google_cookies(
                    scoped_google_cookies(await self.context.cookies())
                ) if initial.get("success") else initial
                identity = self._normalize_email(initial.get("email") or "")
                self.provider_project_ids.clear()
                self.validation_candidate_ids.clear()
                if checked.get("success"):
                    page = None
                    try:
                        page = await self.context.new_page()
                        await page.goto(
                            MODERN_FLOW_HOME_URL,
                            wait_until="domcontentloaded",
                            timeout=90000,
                        )
                        for _ in range(40):
                            if self.provider_project_ids:
                                break
                            await asyncio.sleep(0.25)
                    except Exception:
                        pass
                    finally:
                        if page is not None:
                            try:
                                await page.close()
                            except Exception:
                                pass
                final = await self._validate_context_session(identity)
                final_checked = validate_google_cookies(
                    scoped_google_cookies(await self.context.cookies())
                ) if final.get("success") else final
                final_identity = self._normalize_email(final.get("email") or "")
                if not initial.get("success") or not checked.get("success"):
                    result = initial if not initial.get("success") else checked
                elif not final.get("success") or not final_checked.get("success") or final_identity != identity:
                    result = failure("context_changed", "验证期间身份或 Cookie 发生变化")
                elif not self.provider_project_ids:
                    result = failure(
                        "project_membership_unverified",
                        "未获得当前身份的只读项目列表响应",
                    )
                else:
                    await self.context.close()
                    self.context = None
                    if await self._profile_browser_processes():
                        raise RuntimeError("browser still owns the Profile after close")
                    self.state = "validated"
                    return {
                        **self.public(),
                        "success": True,
                        "is_logged_in": True,
                        "has_account_projects": True,
                        "existing_project_present": bool(expected and expected in self.provider_project_ids),
                        "identity": final_identity,
                    }
            except Exception:
                result = failure("verification_unavailable", "worker 无法完成无成本检查；Profile 已保留")
            self.state = "ready"
            await self._start_vnc()
            return {
                **self.public(), **result,
                "is_logged_in": False,
                "has_account_projects": False,
                "existing_project_present": False,
            }

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

    def _remove_stale_browser_locks(self) -> None:
        """Remove only Chromium singleton artifacts after owner-process proof.

        A retained Profile records the prior worker container hostname in
        these top-level entries. Container recreation makes those artifacts
        stale even though no process owns the mounted Profile. Never recurse
        or accept a directory at one of the three exact lock names.
        """
        root = self._safe_profile_dir()
        for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
            path = root / name
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                continue
            if not (
                stat.S_ISLNK(mode)
                or stat.S_ISREG(mode)
                or stat.S_ISSOCK(mode)
            ):
                raise RuntimeError("unexpected Chromium singleton artifact")
            path.unlink()

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
            self.accessible_document_ids.clear()
            self.validation_candidate_ids.clear()
            self.state = "idle"
            return result

    async def abort(self, generation: str, profile_id: int) -> dict:
        async with self.lock:
            # After a worker-container restart, retained Profile data is
            # quarantined while the in-memory assignment is intentionally
            # empty.  Accept the control plane's persisted, signed old
            # generation only for this already-stopped state.  A live or
            # differently assigned context still requires an exact match.
            unowned_retained = bool(
                self.state == "quarantined"
                and self.context is None
                and not self.generation
                and not self.profile_id
                and any(self._safe_profile_dir().iterdir())
            )
            if not unowned_retained:
                self._scope(generation, profile_id)
            await self._stop_vnc()
            if self.context:
                await self.context.close()
                self.context = None
            self.state = "quarantined" if any(self._safe_profile_dir().iterdir()) else "idle"
            self.generation = ""
            self.profile_id = 0
            self.proxy_url = ""
            self.provider_project_ids.clear()
            self.accessible_document_ids.clear()
            self.validation_candidate_ids.clear()
            result = self.public()
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


@app.post("/recover")
async def recover(request: Request) -> dict:
    generation, profile_id, payload = await _authorized(request, "/recover")
    proxy_url = str(payload.get("proxy_url") or "")
    return await worker.recover(generation, profile_id, proxy_url)


@app.post("/validate")
async def validate(request: Request) -> dict:
    generation, profile_id, payload = await _authorized(request, "/validate")
    return await worker.validate(
        generation,
        profile_id,
        str(payload.get("expected_existing_project_id") or ""),
    )


@app.post("/validate-account-projects")
async def validate_account_projects(request: Request) -> dict:
    generation, profile_id, payload = await _authorized(request, "/validate-account-projects")
    return await worker.validate_account_projects(
        generation,
        profile_id,
        str(payload.get("expected_existing_project_id") or ""),
    )


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
