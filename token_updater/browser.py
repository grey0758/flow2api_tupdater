"""浏览器管理 v3.1 - 持久化上下文 + VNC登录 + Headless刷新"""
import asyncio
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import parse_qs, urlparse
from uuid import UUID
from playwright.async_api import async_playwright, BrowserContext, Playwright
from .config import config
from .database import profile_db
from .proxy_utils import parse_proxy, format_proxy_for_playwright
from .logger import logger
from .browser_profile import configure_web_only_profile
from .session_validation import (
    LABS_SESSION_URL, LABS_CSRF_URL, LABS_SIGNIN_URL, CREDITS_URL,
    cookie_is_live, failure, scoped_google_cookies, validate_google_cookies,
    validate_labs_session, validate_credits,
)

try:
    import pyautogui
    import pygetwindow as pygetwindow
    import win32con
    import win32gui

    pyautogui.FAILSAFE = False
    DESKTOP_AUTOMATION_AVAILABLE = True
except Exception:
    pyautogui = None
    pygetwindow = None
    win32con = None
    win32gui = None
    DESKTOP_AUTOMATION_AVAILABLE = False


# 内存优化参数
BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--disable-features=TranslateUI",
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
    "--single-process",  # 单进程模式，省内存
    "--max_old_space_size=128",  # 限制 V8 内存
    "--js-flags=--max-old-space-size=128",
]

LOGIN_BROWSER_ARGS = BROWSER_ARGS[:6] + ["--disable-blink-features=AutomationControlled"]

BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
BUTTON_CANDIDATE_SELECTORS = "button, [role='button'], input[type='submit'], input[type='button'], a[role='button'], cr-button"
ACCOUNT_INPUT_SELECTORS = [
    "#identifierId",
    "input[name='identifier']",
    "input[autocomplete='username']",
    "input[autocomplete='email']",
    "input[type='email']",
    "input[type='tel']",
]
PASSWORD_INPUT_SELECTORS = [
    "input[name='Passwd']",
    "input[autocomplete='current-password']",
    "input[autocomplete='password']",
    "input[type='password']",
]
ACCOUNT_SUBMIT_SELECTORS = [
    "#identifierNext",
    "#identifierNext button",
    "[id='identifierNext'] button",
]
PASSWORD_SUBMIT_SELECTORS = [
    "#passwordNext",
    "#passwordNext button",
    "[id='passwordNext'] button",
]

SUPERVISOR_CONF = "/etc/supervisor/conf.d/supervisord.conf"
VNC_START_ORDER = ("xvfb", "fluxbox", "x11vnc", "novnc")
VNC_STOP_ORDER = ("novnc", "x11vnc", "fluxbox", "xvfb")


class BrowserManager:
    """浏览器管理器 - 持久化上下文"""

    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._active_context: Optional[BrowserContext] = None
        self._active_profile_id: Optional[int] = None
        self._lock = asyncio.Lock()
        self._session_errors: Dict[int, Dict[str, Any]] = {}
        self._flow_project_ids: Dict[int, str] = {}

    def get_session_error(self, profile_id: int) -> Dict[str, Any]:
        return self._session_errors.get(profile_id, failure("auth_required", "无法取得完整有效会话，请在源 Profile 完成 Labs 和 Flow 登录"))

    @staticmethod
    def _normalize_flow_project_id(value: Any) -> Optional[str]:
        raw = str(value or "").strip()
        try:
            return str(UUID(raw))
        except (TypeError, ValueError, AttributeError):
            return None

    @classmethod
    def _flow_project_id_from_url(cls, value: Any) -> Optional[str]:
        try:
            parsed = urlparse(str(value or ""))
        except Exception:
            return None
        host = str(parsed.hostname or "").lower()
        if host not in {"flow.google.com", "labs.google"}:
            return None

        candidates: List[str] = []
        match = re.search(r"(?:^|/)(?:project|projects)/([^/?#]+)", parsed.path, re.IGNORECASE)
        if match:
            candidates.append(match.group(1))
        query = parse_qs(parsed.query)
        for key in ("projectId", "project_id"):
            candidates.extend(query.get(key, []))
        for candidate in candidates:
            normalized = cls._normalize_flow_project_id(candidate)
            if normalized:
                return normalized
        return None

    def _remember_flow_project_id(
        self,
        profile_id: int,
        context: Optional[BrowserContext],
        preferred_page: Optional[Any] = None,
    ) -> Optional[str]:
        pages = []
        if preferred_page is not None:
            pages.append(preferred_page)
        if context is not None:
            pages.extend(
                page for page in list(context.pages or [])
                if page is not preferred_page
            )
        for page in pages:
            project_id = self._flow_project_id_from_url(getattr(page, "url", ""))
            if project_id:
                self._flow_project_ids[int(profile_id)] = project_id
                return project_id
        self._flow_project_ids.pop(int(profile_id), None)
        return None

    async def _discover_flow_project_id(
        self,
        profile_id: int,
        context: Optional[BrowserContext],
    ) -> Optional[str]:
        remembered = self._remember_flow_project_id(profile_id, context)
        if remembered:
            return remembered
        if context is None:
            return None
        for page in list(context.pages or []):
            try:
                host = str(urlparse(str(page.url or "")).hostname or "").lower()
                if host not in {"flow.google.com", "labs.google"}:
                    continue
                hrefs = await page.locator("a[href]").evaluate_all(
                    "elements => elements.slice(0, 200).map(element => element.href)"
                )
            except Exception:
                continue
            for href in hrefs if isinstance(hrefs, list) else []:
                project_id = self._flow_project_id_from_url(href)
                if project_id:
                    self._flow_project_ids[int(profile_id)] = project_id
                    return project_id
        return None

    async def get_flow_project_id(self, profile_id: int) -> Optional[str]:
        """Return a UUID observed in this profile's own Flow browser only."""
        async with self._lock:
            if self._active_profile_id == profile_id and self._active_context:
                return await self._discover_flow_project_id(
                    profile_id, self._active_context
                )
            remembered = self._flow_project_ids.get(int(profile_id))
            if remembered:
                return remembered
            profile = await profile_db.get_profile(profile_id)
            if not profile or not profile.get("observed_flow_project_verified"):
                return None
            project_identity = self._normalize_email(
                profile.get("observed_flow_project_identity") or ""
            )
            profile_identity = self._normalize_email(profile.get("email") or "")
            if not project_identity or project_identity != profile_identity:
                return None
            return self._normalize_flow_project_id(
                profile.get("observed_flow_project_id")
            )

    async def check_login_slot_status(
        self, profile_id: int, context: BrowserContext
    ) -> Dict[str, Any]:
        """Validate Labs/credits/Cookies, then bind a project in that exact context."""
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile or context is None:
                return {"success": False, "error": "登录槽位浏览器不存在"}
            result = await self._validate_context_session(
                context, self._resolve_known_email(profile) or ""
            )
            if result.get("success"):
                try:
                    checked = validate_google_cookies(
                        scoped_google_cookies(await context.cookies())
                    )
                except Exception:
                    checked = failure(
                        "verification_unavailable", "暂无法读取源浏览器 Cookie，请稍后重试"
                    )
                if not checked.get("success"):
                    result = checked
            if not result.get("success"):
                self._session_errors[profile_id] = result
                await self._persist_login_state(profile_id, None)
                return {
                    "success": True,
                    "is_logged_in": False,
                    "has_flow_project": False,
                    "profile_name": profile["name"],
                    "error_code": result.get("error_code", "auth_required"),
                    "error": result.get("error", "请继续完成 Google、Flow 与 Labs 授权"),
                }

            identity = self._normalize_email(result.get("email") or "")
            project_id = await self._discover_flow_project_id(profile_id, context)
            await self._persist_login_state(
                profile_id, result["session_token"], email=identity
            )
            if project_id and identity:
                await profile_db.update_profile(
                    profile_id,
                    observed_flow_project_id=project_id,
                    observed_flow_project_verified=1,
                    observed_flow_project_identity=identity,
                )
            self._session_errors.pop(profile_id, None)
            return {
                "success": True,
                "is_logged_in": True,
                "has_flow_project": bool(project_id and identity),
                "profile_name": profile["name"],
                **(
                    {}
                    if project_id and identity
                    else {
                        "error_code": "project_required",
                        "error": "Labs 已验证，但尚未在同一登录 Profile 中观察到 Flow 项目",
                    }
                ),
            }

    async def _launch_persistent_context(self, **kwargs):
        configure_web_only_profile(kwargs["user_data_dir"])
        return await self._playwright.chromium.launch_persistent_context(**kwargs)

    async def start(self):
        """启动 Playwright"""
        if self._playwright:
            return
        logger.info("启动 Playwright...")
        self._playwright = await async_playwright().start()
        os.makedirs(config.profiles_dir, exist_ok=True)
        logger.info("Playwright 已启动")

    async def stop(self):
        """停止"""
        await self._close_active()
        await self._stop_vnc_stack()
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    def _supervisorctl(self, *args: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        exe = shutil.which("supervisorctl")
        if not exe:
            raise RuntimeError("supervisorctl not found")
        cmd = [exe, "-c", SUPERVISOR_CONF, *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)

    def _get_supervisor_status(self) -> Dict[str, str]:
        try:
            cp = self._supervisorctl("status", timeout=8.0)
        except Exception:
            return {}

        status: Dict[str, str] = {}
        for line in (cp.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                status[parts[0]] = parts[1]
        return status

    async def _ensure_vnc_stack(self) -> bool:
        if not config.enable_vnc:
            return False

        status = self._get_supervisor_status()
        for prog in VNC_START_ORDER:
            if status.get(prog) == "RUNNING":
                continue
            try:
                cp = self._supervisorctl("start", prog, timeout=20.0)
                if cp.returncode != 0:
                    logger.warning(f"启动 {prog} 失败: {(cp.stdout or '').strip()} {(cp.stderr or '').strip()}")
                    return False
            except Exception as e:
                logger.warning(f"启动 {prog} 异常: {e}")
                return False

            if prog == "xvfb":
                await asyncio.sleep(0.4)

        return True

    async def _stop_vnc_stack(self) -> None:
        if not config.enable_vnc:
            return

        for prog in VNC_STOP_ORDER:
            try:
                self._supervisorctl("stop", prog, timeout=10.0)
            except Exception:
                pass

    async def _close_active(self):
        """关闭当前浏览器"""
        if self._active_context:
            try:
                await self._active_context.close()
            except Exception:
                pass
            self._active_context = None
            self._active_profile_id = None
            logger.info("浏览器已关闭")

    def _get_profile_dir(self, profile_id: int) -> str:
        """获取 Profile 持久化目录"""
        return os.path.join(os.path.abspath(config.profiles_dir), f"profile_{profile_id}")

    def _clean_locks(self, profile_dir: str):
        """清理 Chromium 锁文件"""
        lock_files = ["SingletonLock", "SingletonCookie", "SingletonSocket"]
        for lock in lock_files:
            lock_path = os.path.join(profile_dir, lock)
            if os.path.exists(lock_path):
                try:
                    os.remove(lock_path)
                    logger.info(f"已清理锁文件: {lock}")
                except Exception:
                    pass

    def _mask_token(self, token: str) -> str:
        if not token or len(token) <= 8:
            return token or ""
        return f"{token[:4]}...{token[-4:]}"

    def _normalize_email(self, value: str) -> str:
        return str(value or "").strip().lower()

    def _extract_email_from_text(self, text: str) -> Optional[str]:
        content = str(text or "")
        for match in EMAIL_PATTERN.findall(content):
            normalized = self._normalize_email(match)
            if normalized:
                return normalized
        return None

    def _resolve_known_email(self, profile: Dict[str, Any], body_text: str = "") -> Optional[str]:
        stored_email = self._normalize_email(str(profile.get("email") or ""))
        if stored_email:
            return stored_email

        page_email = self._extract_email_from_text(body_text)
        if page_email:
            return page_email

        login_account = self._normalize_email(str(profile.get("login_account") or ""))
        if login_account and EMAIL_PATTERN.fullmatch(login_account):
            return login_account

        return None

    async def _get_proxy(self, profile: Dict[str, Any]) -> Optional[Dict]:
        """获取代理配置"""
        if profile.get("proxy_enabled"):
            proxy_config = parse_proxy(profile.get("proxy_url") or "")
            if proxy_config:
                proxy = format_proxy_for_playwright(proxy_config)
                logger.info(f"[{profile['name']}] 使用代理: {proxy['server']}")
                return proxy
            raise ValueError("源 Profile 已启用代理但地址无效，已停止操作以避免使用错误出口")
        return None

    async def _safe_page_text(self, page) -> str:
        try:
            body = page.locator("body").first
            if await body.count() <= 0:
                return ""
            return str(await body.inner_text(timeout=2000) or "")
        except Exception:
            return ""

    def _text_contains_any(self, text: str, patterns: List[str]) -> bool:
        lowered = str(text or "").lower()
        if not lowered:
            return False
        return any(str(pattern or "").strip().lower() in lowered for pattern in patterns if str(pattern or "").strip())

    async def _get_locator_search_text(self, locator) -> str:
        parts: List[str] = []

        try:
            parts.append(str(await locator.inner_text(timeout=1000) or ""))
        except Exception:
            pass

        try:
            parts.append(str(await locator.text_content(timeout=1000) or ""))
        except Exception:
            pass

        for attr in ("value", "aria-label", "title", "name", "data-identifier", "data-email"):
            try:
                parts.append(str(await locator.get_attribute(attr) or ""))
            except Exception:
                pass

        return " ".join(part.strip() for part in parts if str(part or "").strip())

    async def _click_first_visible(self, page, selectors: List[str]) -> bool:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() <= 0 or not await locator.is_visible():
                    continue
                await locator.click(timeout=5000)
                await asyncio.sleep(1)
                return True
            except Exception:
                continue
        return False

    async def _has_visible_selector(self, page, selectors: List[str]) -> bool:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() > 0 and await locator.is_visible():
                    return True
            except Exception:
                continue
        return False

    async def _wait_for_page_progress(
        self,
        page,
        previous_url: str,
        current_selectors: List[str],
        success_selectors: Optional[List[str]] = None,
        attempts: int = 5,
    ) -> bool:
        success_selectors = success_selectors or []
        for _ in range(max(1, attempts)):
            if str(page.url or "") != previous_url:
                return True
            if success_selectors and await self._has_visible_selector(page, success_selectors):
                return True
            if current_selectors and not await self._has_visible_selector(page, current_selectors):
                return True
            await asyncio.sleep(0.4)
        return False

    async def _click_button_by_text(self, page, patterns: List[str]) -> bool:
        escaped = [re.escape(str(pattern or "").strip()) for pattern in patterns if str(pattern or "").strip()]
        if not escaped:
            return False

        regex = re.compile("|".join(escaped), re.IGNORECASE)
        try:
            candidates = page.locator(BUTTON_CANDIDATE_SELECTORS)
            count = min(await candidates.count(), 100)
        except Exception:
            return False

        for index in range(count):
            try:
                locator = candidates.nth(index)
                if not await locator.is_visible():
                    continue
                label = str(await self._get_locator_search_text(locator) or "").strip()
                if not label or not regex.search(label):
                    continue
                await locator.click(timeout=5000)
                await asyncio.sleep(1)
                return True
            except Exception:
                continue
        return False

    async def _click_text_if_visible(self, page, patterns: List[str]) -> bool:
        for pattern in patterns:
            text = str(pattern or "").strip()
            if not text:
                continue
            try:
                candidate_buttons = page.locator(BUTTON_CANDIDATE_SELECTORS)
                count = min(await candidate_buttons.count(), 40)
                for index in range(count):
                    locator = candidate_buttons.nth(index)
                    if not await locator.is_visible():
                        continue
                    label = str(await self._get_locator_search_text(locator) or "").strip()
                    if text.lower() not in label.lower():
                        continue
                    await locator.click(timeout=5000)
                    await asyncio.sleep(1)
                    return True
                locator = page.get_by_text(text, exact=False).first
                if await locator.count() <= 0:
                    continue
                if not await locator.is_visible():
                    continue
                await locator.click(timeout=5000)
                await asyncio.sleep(1)
                return True
            except Exception:
                continue
        return False

    async def _fill_and_submit_first_visible(
        self,
        page,
        selectors: List[str],
        value: str,
        *,
        submit_selectors: Optional[List[str]] = None,
        submit_patterns: Optional[List[str]] = None,
        success_selectors: Optional[List[str]] = None,
    ) -> bool:
        if not str(value or "").strip():
            return False

        submit_selectors = submit_selectors or []
        submit_patterns = submit_patterns or []
        success_selectors = success_selectors or []

        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() <= 0 or not await locator.is_visible():
                    continue
                previous_url = str(page.url or "")
                await locator.click(timeout=5000)
                await locator.fill("", timeout=5000)
                await locator.fill(value, timeout=5000)
                await asyncio.sleep(0.4)

                try:
                    await locator.press("Enter", timeout=3000)
                    if await self._wait_for_page_progress(page, previous_url, selectors, success_selectors):
                        return True
                except Exception:
                    pass

                if submit_selectors and await self._click_first_visible(page, submit_selectors):
                    if await self._wait_for_page_progress(page, previous_url, selectors, success_selectors):
                        return True

                if submit_patterns and await self._click_button_by_text(page, submit_patterns):
                    if await self._wait_for_page_progress(page, previous_url, selectors, success_selectors):
                        return True
            except Exception:
                continue
        return False

    def _detect_login_blocker(self, body_text: str) -> Optional[str]:
        text = str(body_text or "")
        lowered = text.lower()
        if not lowered:
            return None

        blocked_markers = [
            (
                [
                    "wrong password",
                    "密码错误",
                    "密码不正确",
                ],
                "登录密码错误，请检查后重试",
            ),
            (
                [
                    "couldn’t find your google account",
                    "couldn't find your google account",
                    "找不到您的 google 账号",
                    "输入有效的电子邮件地址或电话号码",
                ],
                "登录账号不存在或无法识别",
            ),
            (
                [
                    "2-step verification",
                    "verify it’s you",
                    "verify it's you",
                    "check your phone",
                    "验证您本人身份",
                    "两步验证",
                    "两步驟驗證",
                ],
                "该账号需要人工完成二次验证，请改用手动登录",
            ),
            (
                [
                    "too many failed attempts",
                    "尝试次数过多",
                    "稍后再试",
                    "try again later",
                ],
                "登录尝试过多，请稍后再试",
            ),
            (
                [
                    "enter the characters",
                    "不是您的计算机？请使用访客模式登录",
                    "confirm you’re not a robot",
                    "确认您不是机器人",
                ],
                "登录过程中需要额外人工验证，请改用手动登录",
            ),
        ]

        for markers, message in blocked_markers:
            if any(marker.lower() in lowered for marker in markers):
                return message
        return None

    async def _click_account_choice(self, page, login_account: str) -> bool:
        normalized_account = self._normalize_email(login_account or "")
        if not normalized_account:
            return False

        attr_selectors = [
            f'[data-identifier="{normalized_account}"]',
            f'[data-email="{normalized_account}"]',
        ]
        if await self._click_first_visible(page, attr_selectors):
            return True

        try:
            candidates = page.locator("button, [role='button'], li, div[data-identifier], div[data-email]")
            count = min(await candidates.count(), 80)
        except Exception:
            count = 0

        for index in range(count):
            try:
                locator = candidates.nth(index)
                if not await locator.is_visible():
                    continue
                label = self._normalize_email(await self._get_locator_search_text(locator))
                if normalized_account not in label:
                    continue
                await locator.click(timeout=5000)
                await asyncio.sleep(1)
                return True
            except Exception:
                continue

        return await self._click_text_if_visible(page, [login_account])

    async def _handle_chromium_signin_prompt(self, page, body_text: str) -> bool:
        text = str(body_text or "")
        markers = [
            "Sign in to Chromium",
            "登录 Chromium",
            "Set up a work profile",
            "设置工作资料",
            "Use Chromium without an account",
            "Continue as",
        ]
        if not self._text_contains_any(text, markers):
            return False

        if await self._click_button_by_text(page, ["Continue as", "继续作为", "以此身份继续", "Continue", "続行", "계속", "Continuar"]):
            return True
        if await self._click_button_by_text(
            page,
            ["Use Chromium without an account", "不使用账号", "不使用帳號", "暂不登录", "以后再说", "Not now", "アカウントなし", "계정 없이", "Sin cuenta", "Plus tard"],
        ):
            return True
        return False

    async def _handle_managed_profile_prompt(self, page, body_text: str) -> bool:
        text = str(body_text or "")
        markers = [
            "Continue to work in this profile",
            "This profile will be managed",
            "Your organization manages this profile",
            "Create a work profile",
            "Separate browsing for work",
            "You're signing in with a managed account",
            "Set up your new profile",
            "此资料将受到管理",
            "该资料将受到管理",
        ]
        if not self._text_contains_any(text, markers):
            return False

        return await self._click_button_by_text(
            page,
            [
                "Continue to work in this profile",
                "Continue",
                "继续",
                "I understand",
                "我了解",
                "我瞭解",
                "Confirm",
                "确认",
                "Create profile",
                "创建资料",
            ],
        )

    async def _handle_profile_data_choice_prompt(self, page, body_text: str) -> bool:
        text = str(body_text or "")
        markers = [
            "How do you want to handle your existing browsing data",
            "Keep existing browsing data separate",
            "Continue using this profile",
            "Use existing data",
            "Create new profile",
            "您想如何处理现有的资料数据",
        ]
        if not self._text_contains_any(text, markers):
            return False

        if await self._click_text_if_visible(
            page,
            [
                "Continue using this profile",
                "Use existing data",
                "Keep existing browsing data separate",
                "继续使用此资料",
                "继续使用这个资料",
            ],
        ):
            return True

        return await self._click_button_by_text(
            page,
            ["Continue", "继续", "Confirm", "确认", "Create new profile", "创建新资料"],
        )

    async def _handle_browser_settings_prompts(self, page, body_text: str) -> bool:
        text = str(body_text or "")

        positive_markers = [
            "Turn on sync",
            "Sync and personalize",
            "Save and continue",
            "Sync your stuff",
            "Save time by syncing",
            "开启同步",
            "同步和个性化",
            "保存并继续",
        ]
        dismiss_markers = [
            "Make Chrome your default browser",
            "Make Chromium your default browser",
            "Help improve Chrome",
            "Help improve Chromium",
            "Import bookmarks and settings",
            "Set as default",
            "默认浏览器",
            "导入书签",
            "帮助改进",
        ]

        if self._text_contains_any(text, positive_markers):
            return await self._click_button_by_text(
                page,
                [
                    "Save and continue",
                    "Yes, I'm in",
                    "Turn on sync",
                    "Continue",
                    "继续",
                    "保存并继续",
                    "开启同步",
                    "保存して続行",
                    "동기화 켜기",
                    "Guardar y continuar",
                ],
            )

        if self._text_contains_any(text, dismiss_markers):
            return await self._click_button_by_text(
                page,
                ["Not now", "No thanks", "Skip", "以后再说", "暂不", "跳过", "後で", "나중에", "Ahora no", "Non merci"],
            )

        return False

    async def _advance_google_login(self, page, login_account: str, login_password: str) -> bool:
        if await self._click_button_by_text(page, ["Use another account", "使用其他账号", "使用其他帳戶", "別のアカウントを使用", "다른 계정 사용", "Usar otra cuenta", "Utiliser un autre compte"]):
            return True
        if await self._click_account_choice(page, login_account):
            return True
        if await self._fill_and_submit_first_visible(
            page,
            ACCOUNT_INPUT_SELECTORS,
            login_account,
            submit_selectors=ACCOUNT_SUBMIT_SELECTORS,
            submit_patterns=["下一步", "Next", "继续", "Continue", "次へ", "다음", "Siguiente", "Suivant", "Weiter", "Avançar"],
            success_selectors=PASSWORD_INPUT_SELECTORS,
        ):
            return True
        if await self._fill_and_submit_first_visible(
            page,
            PASSWORD_INPUT_SELECTORS,
            login_password,
            submit_selectors=PASSWORD_SUBMIT_SELECTORS,
            submit_patterns=["下一步", "Next", "继续", "Continue", "登录", "Sign in", "次へ", "続行", "로그인", "Iniciar sesión", "Connexion", "Anmelden", "Fazer login", "Войти"],
            success_selectors=["[href*='labs.google']", "[href*='flow.google.com']", "[data-test-id='profile-menu-button']"],
        ):
            return True
        return False

    async def _install_page_route(self, page) -> None:
        async def _route(route, request):
            try:
                if request.resource_type in BLOCKED_RESOURCE_TYPES:
                    await route.abort()
                else:
                    await route.continue_()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        try:
            await page.route("**/*", _route)
        except Exception:
            pass

    async def _focus_browser_window_for_native_prompt(self) -> bool:
        if os.name != "nt" or not DESKTOP_AUTOMATION_AVAILABLE or pygetwindow is None:
            return False

        title_keywords = [
            "Flow - Chromium",
            "Chromium",
            "Google Chrome",
        ]
        for keyword in title_keywords:
            try:
                windows = [window for window in pygetwindow.getWindowsWithTitle(keyword) if getattr(window, "title", "")]
            except Exception:
                continue
            if not windows:
                continue

            window = windows[0]
            hwnd = getattr(window, "_hWnd", None)
            try:
                window.restore()
            except Exception:
                pass
            try:
                window.activate()
            except Exception:
                if hwnd and win32gui is not None and win32con is not None:
                    try:
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                        win32gui.SetForegroundWindow(hwnd)
                    except Exception:
                        pass
            await asyncio.sleep(0.8)
            return True
        return False

    async def _handle_native_chrome_profile_prompts(self) -> bool:
        if os.name != "nt" or not DESKTOP_AUTOMATION_AVAILABLE or pyautogui is None:
            return False
        if not await self._focus_browser_window_for_native_prompt():
            return False

        acted = False
        sequences = [
            ("enter",),
            ("tab", "enter"),
            ("shift+tab", "enter"),
            ("esc",),
        ]
        for sequence in sequences:
            try:
                for key in sequence:
                    if key == "shift+tab":
                        pyautogui.hotkey("shift", "tab")
                    else:
                        pyautogui.press(key)
                    await asyncio.sleep(0.8)
                acted = True
            except Exception:
                return acted
        return acted

    async def _handle_managed_account_prompts(self, page, body_text: str) -> bool:
        if await self._click_button_by_text(page, ["Sign in with Google"]):
            return True

        if await self._handle_chromium_signin_prompt(page, body_text):
            return True
        if await self._handle_managed_profile_prompt(page, body_text):
            return True
        if await self._handle_profile_data_choice_prompt(page, body_text):
            return True
        if await self._handle_browser_settings_prompts(page, body_text):
            return True

        if await self._click_button_by_text(
            page,
            [
                "Continue to work in this profile",
                "Continue as",
                "Save and continue",
                "我瞭解",
                "我了解",
                "I understand",
                "确认",
                "Confirm",
                "继续",
                "Continue",
                "続行",
                "계속",
                "Continuar",
                "Bestätigen",
            ],
        ):
            return True

        return False

    async def _handle_labs_onboarding(self, page, body_text: str) -> bool:
        text = str(body_text or "")
        if await page.locator("#marketing-emails").count() > 0 or await page.locator("#research-emails").count() > 0:
            for selector in ("#marketing-emails", "#research-emails"):
                try:
                    checkbox = page.locator(selector).first
                    if await checkbox.count() <= 0 or not await checkbox.is_visible():
                        continue
                    checked = str(await checkbox.get_attribute("aria-checked") or "").strip().lower() == "true"
                    if not checked:
                        await checkbox.click(timeout=5000)
                        await asyncio.sleep(0.3)
                except Exception:
                    continue
            if await self._click_button_by_text(page, ["下一步", "Next", "继续", "Continue", "次へ", "다음", "Siguiente", "Suivant"]):
                return True

        onboarding_markers = [
            "体验 AI 工具的创造力",
            "Experience the creativity",
            "查看我们的《隐私权政策》",
            "隐私权政策",
            "Privacy Policy",
            "Your data and labs.google/fx",
            "Welcome to",
            "Get started",
            "Start using",
            "Introducing",
        ]
        if any(marker.lower() in text.lower() for marker in onboarding_markers):
            try:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            except Exception:
                pass
            await asyncio.sleep(0.5)
            if await self._click_button_by_text(
                page,
                ["继续", "Continue", "同意", "Agree", "下一步", "Next", "Got it", "Done", "Skip", "Accept", "Start", "OK", "次へ", "同意する", "다음", "동의", "Aceptar", "Accepter", "Akzeptieren", "Начать"],
            ):
                return True

        return False

    async def _is_labs_session_ready(self, page, body_text: str) -> bool:
        """Page readiness only. Never use this as proof of OAuth validity."""
        url = str(page.url or "").lower()
        if urlparse(url).hostname not in {"labs.google", "flow.google.com"}:
            return False
        if "accounts.google.com" in url:
            return False

        text = str(body_text or "")
        blocked_markers = [
            "体验 AI 工具的创造力",
            "Experience the creativity",
            "查看我们的《隐私权政策》",
            "Privacy Policy",
            "登录 Chrome",
            "Sign in to Chromium",
            "Set up a work profile",
            "Use Chromium without an account",
            "Continue to work in this profile",
            "How do you want to handle your existing browsing data",
            "Turn on sync",
            "Save and continue",
            "Sign in with Google",
            "Too many failed attempts",
        ]
        if any(marker.lower() in text.lower() for marker in blocked_markers):
            return False

        try:
            if await page.locator(", ".join(ACCOUNT_INPUT_SELECTORS + PASSWORD_INPUT_SELECTORS)).count() > 0:
                return False
        except Exception:
            return False

        return True

    async def _settle_labs_session(self, profile: Dict[str, Any], context: BrowserContext, page) -> Optional[str]:
        native_prompt_attempts = 0
        for _ in range(40):
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass

            body_text = await self._safe_page_text(page)

            blocker = self._detect_login_blocker(body_text)
            if blocker:
                self._session_errors[profile["id"]] = failure("manual_action_required", blocker)
                return None
            if urlparse(str(page.url)).hostname == "accounts.google.com":
                account = self._resolve_known_email(profile) or ""
                if account and await self._click_account_choice(page, account):
                    continue
                if profile.get("login_account") and profile.get("login_password"):
                    if await self._advance_google_login(page, profile["login_account"], profile["login_password"]):
                        continue

            if native_prompt_attempts < 3 and not str(body_text or "").strip() and await self._handle_native_chrome_profile_prompts():
                native_prompt_attempts += 1
                logger.info(f"[{profile['name']}] 已处理 Chromium 原生资料提示")
                continue

            if await self._handle_managed_account_prompts(page, body_text):
                logger.info(f"[{profile['name']}] 已处理 Google / 资料确认提示")
                continue

            if await self._handle_labs_onboarding(page, body_text):
                logger.info(f"[{profile['name']}] 已处理 labs 首次引导")
                continue

            if await self._is_labs_session_ready(page, body_text):
                logger.info(f"[{profile['name']}] labs 会话页面已就绪")
                break

            await asyncio.sleep(1.0)

        token = await self._get_session_cookie(context)
        deadline = asyncio.get_running_loop().time() + 12.0
        while asyncio.get_running_loop().time() < deadline:
            token = await self._get_session_cookie(context)
            if token:
                break
            await asyncio.sleep(0.5)

        if not token:
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            token = await self._get_session_cookie(context)

        if token:
            for _ in range(4):
                body_text = await self._safe_page_text(page)
                if await self._handle_managed_account_prompts(page, body_text):
                    continue
                if await self._handle_labs_onboarding(page, body_text):
                    continue
                break
        return token

    async def _validate_context_session(self, context: BrowserContext, expected_email: str = "") -> Dict[str, Any]:
        """Share the source context's cookie jar AND proxy, never a default HTTP route."""
        responses = []
        try:
            response = await context.request.get(LABS_SESSION_URL, timeout=20000, max_redirects=0,
                                                 headers={"Accept": "application/json"})
            responses.append(response)
            if response.status == 401:
                return failure("auth_required", "Labs 授权已失效，请在源 Profile 重新授权")
            if response.status != 200:
                return failure("verification_unavailable", "Labs 会话校验暂不可用，请检查源代理或稍后重试")
            validated = validate_labs_session(await response.json(), expected_email)
            if not validated["success"]:
                return validated
            response = await context.request.get(CREDITS_URL, timeout=20000, max_redirects=0,
                                                 headers={"Authorization": "Bearer " + validated["access_token"]})
            responses.append(response)
            data = await response.json() if response.status == 200 else None
            checked = validate_credits(response.status, data)
            if not checked["success"]:
                return checked
            # /auth/session may rotate/chunk the ST. Read AFTER validation.
            token = await self._get_session_cookie(context)
            if not token:
                return failure("auth_required", "Labs 会话 Cookie 缺失，请重新完成 Labs 授权")
            return {"success": True, "session_token": token, "email": validated["email"]}
        except Exception as exc:
            logger.warning(f"Source session validation failed ({type(exc).__name__}); credentials retained")
            return failure("verification_unavailable", "源账号鉴权请求失败，请检查代理连接或稍后重试；未清除 Cookie")
        finally:
            for response in responses:
                try:
                    await response.dispose()
                except Exception:
                    pass

    async def _start_labs_authorization(self, context: BrowserContext, page) -> bool:
        """One normal NextAuth sign-in, without clearing either site's cookies."""
        responses = []
        try:
            response = await context.request.get(LABS_CSRF_URL, timeout=20000, max_redirects=0)
            responses.append(response)
            if response.status != 200:
                return False
            csrf = (await response.json()).get("csrfToken")
            if not isinstance(csrf, str) or not csrf:
                return False
            response = await context.request.post(
                LABS_SIGNIN_URL, form={"csrfToken": csrf, "callbackUrl": "https://labs.google/fx", "json": "true"},
                headers={"Origin": "https://labs.google", "Referer": "https://labs.google/fx"},
                timeout=20000, max_redirects=0,
            )
            responses.append(response)
            if response.status != 200:
                return False
            data = await response.json()
            target = data.get("url") or data.get("redirect")
            parsed = urlparse(target) if isinstance(target, str) else None
            if not parsed or parsed.scheme != "https" or parsed.hostname != "accounts.google.com" or parsed.username or parsed.port not in (None, 443):
                return False
            await page.goto(target, wait_until="domcontentloaded", timeout=60000)
            return True
        except Exception as exc:
            logger.warning(f"Labs authorization could not start ({type(exc).__name__})")
            return False
        finally:
            for response in responses:
                try:
                    await response.dispose()
                except Exception:
                    pass

    async def _ensure_labs_authorization(self, profile, context, page) -> Dict[str, Any]:
        expected_email = self._resolve_known_email(profile) or ""
        result = await self._validate_context_session(context, expected_email)
        if result.get("error_code") == "auth_required":
            logger.info(f"[{profile['name']}] Labs OAuth needs renewal; starting one source-profile sign-in")
            if await self._start_labs_authorization(context, page):
                await self._settle_labs_session(profile, context, page)
                if self._session_errors.get(profile["id"], {}).get("error_code") == "manual_action_required":
                    return self._session_errors[profile["id"]]
                result = await self._validate_context_session(context, expected_email)
        if not result["success"]:
            self._session_errors[profile["id"]] = result
        return result

    async def _complete_flow_session(self, profile, context, page) -> Optional[str]:
        result = await self._ensure_labs_authorization(profile, context, page)
        if result["success"]:
            if urlparse(str(page.url)).hostname != "flow.google.com":
                await page.goto(config.flow_url, wait_until="domcontentloaded", timeout=60000)
            await self._wait_for_flow_cookies(context)
            location = urlparse(str(page.url))
            if location.hostname != "flow.google.com" or location.path.rstrip("/") == "/about":
                result = failure("cookies_incomplete", "源浏览器仍停留在 Flow 未登录页面，请完成 Flow 登录后同步")
            elif not await self._save_google_cookies_from_context(profile["id"], context):
                result = failure("cookies_incomplete", "Flow/Google 登录 Cookie 不完整，请在源 Profile 完成 Flow 登录")
            else:
                await self._discover_flow_project_id(profile["id"], context)
        if not result["success"]:
            self._session_errors[profile["id"]] = result
            await self._persist_login_state(profile["id"], None)
            return None
        # Flow navigation can rotate cookies too; don't return an earlier ST snapshot.
        token = await self._get_session_cookie(context)
        if token != result.get("session_token"):
            checked = await self._validate_context_session(context, result["email"])
            if not checked["success"]:
                self._session_errors[profile["id"]] = checked
                await self._persist_login_state(profile["id"], None)
                return None
            token = checked["session_token"]
        project_id = self._flow_project_ids.get(int(profile["id"]))
        identity = self._normalize_email(result.get("email") or "")
        if project_id and identity:
            await profile_db.update_profile(
                profile["id"],
                observed_flow_project_id=project_id,
                observed_flow_project_verified=1,
                observed_flow_project_identity=identity,
            )
        await self._persist_login_state(profile["id"], token, email=result["email"])
        self._session_errors.pop(profile["id"], None)
        return token

    async def _persist_login_state(
        self,
        profile_id: int,
        token: Optional[str],
        email: Optional[str] = None,
        is_logged_in: Optional[bool] = None,
    ) -> None:
        logged_in = bool(token) if is_logged_in is None else bool(is_logged_in)
        if not logged_in:
            self._flow_project_ids.pop(int(profile_id), None)
        update_data: Dict[str, Any] = {"is_logged_in": 1 if logged_in else 0}
        if not logged_in:
            update_data.update(
                observed_flow_project_id=None,
                observed_flow_project_verified=0,
                observed_flow_project_identity=None,
            )
        if token:
            update_data["last_token"] = self._mask_token(token)
            update_data["last_token_time"] = datetime.now().isoformat()
            update_data["login_method"] = "browser"
        normalized_email = self._normalize_email(email or "")
        if normalized_email:
            update_data["email"] = normalized_email
        await profile_db.update_profile(profile_id, **update_data)

    async def _save_google_cookies_from_context(
        self,
        profile_id: int,
        context: BrowserContext,
    ) -> bool:
        """从浏览器上下文提取 Google cookies 并存储，用于后续协议刷新"""
        try:
            all_google_cookies = []
            for domain in ["google.com", "www.google.com", "accounts.google.com", "flow.google.com"]:
                try:
                    cookies = await context.cookies(f"https://{domain}")
                    all_google_cookies.extend(cookies)
                except Exception:
                    pass

            all_google_cookies = scoped_google_cookies(all_google_cookies)
            checked = validate_google_cookies(all_google_cookies)
            if not checked["success"]:
                logger.warning(f"[Profile {profile_id}] {checked['error']}; previous snapshot retained")
                return False
            google_cookies_json = json.dumps(all_google_cookies)
            await profile_db.update_profile(profile_id, google_cookies=google_cookies_json)
            logger.info(f"[Profile {profile_id}] 已从浏览器提取 {len(all_google_cookies)} 个 Google cookies 用于协议刷新")
            return True
        except Exception as e:
            logger.warning(f"[Profile {profile_id}] 提取 Google cookies 失败 ({type(e).__name__})")
            return False

    def _parse_cookies_payload(self, cookies_json: str) -> List[Dict[str, Any]]:
        data = json.loads(cookies_json)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            cookies = data.get("cookies")
            if isinstance(cookies, list):
                return cookies
        return []

    def _to_playwright_cookies(self, cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for c in cookies:
            if not isinstance(c, dict):
                continue

            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue

            domain = c.get("domain") or c.get("host")
            url = c.get("url")
            path = c.get("path") or "/"

            if isinstance(domain, str) and "://" in domain:
                domain = None

            cookie: Dict[str, Any] = {"name": str(name), "value": str(value)}

            if c.get("httpOnly") is not None:
                cookie["httpOnly"] = bool(c.get("httpOnly"))
            if c.get("secure") is not None:
                cookie["secure"] = bool(c.get("secure"))

            expires = c.get("expires")
            if expires is None:
                expires = c.get("expirationDate") or c.get("expiry")
            if expires is not None:
                try:
                    cookie["expires"] = float(expires)
                except (TypeError, ValueError):
                    pass

            same_site = c.get("sameSite")
            if isinstance(same_site, str):
                m = same_site.strip().lower()
                if m in {"lax"}:
                    cookie["sameSite"] = "Lax"
                elif m in {"strict"}:
                    cookie["sameSite"] = "Strict"
                elif m in {"none", "no_restriction"}:
                    cookie["sameSite"] = "None"

            if isinstance(url, str) and url.startswith("http"):
                cookie["url"] = url
            elif isinstance(domain, str) and domain:
                cookie["domain"] = domain
                cookie["path"] = str(path)
            else:
                continue

            out.append(cookie)
        return out

    async def _wait_for_flow_cookies(self, context: BrowserContext) -> None:
        for _ in range(10):
            cookies = await context.cookies(config.flow_url)
            if any(c.get("domain", "").lstrip(".") == "flow.google.com" and c.get("name") in {"OSID", "__Secure-OSID"} for c in cookies):
                return
            await asyncio.sleep(0.5)

    async def _get_session_cookie(self, context: BrowserContext) -> Optional[str]:
        try:
            cookies = await context.cookies(LABS_SESSION_URL)
        except Exception:
            cookies = await context.cookies()

        scoped = [c for c in cookies if c.get("domain", "").lstrip(".") == "labs.google" and cookie_is_live(c)]
        for cookie in scoped:
            if cookie.get("name") == config.session_cookie_name:
                return cookie.get("value")
        prefix = config.session_cookie_name + "."
        chunks = sorted((c for c in scoped if c.get("name", "").startswith(prefix) and c["name"][len(prefix):].isdigit()), key=lambda c: int(c["name"][len(prefix):]))
        if chunks and all(c["name"] == prefix + str(i) for i, c in enumerate(chunks)):
            return "".join(c["value"] for c in chunks)
        return None

    async def import_cookies(self, profile_id: int, cookies_json: str) -> Dict[str, Any]:
        """导入 Cookie（JSON），写入到持久化 profile 中"""
        if len(cookies_json) > 300_000:
            return {"success": False, "error": "Cookie 内容过大（建议只导出 labs.google 域名的 Cookie）"}

        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return {"success": False, "error": "Profile 不存在"}

            try:
                raw = self._parse_cookies_payload(cookies_json)
            except Exception as e:
                return {"success": False, "error": f"Cookie JSON 解析失败: {e}"}

            if not raw:
                return {"success": False, "error": "未识别到 Cookie 列表（请粘贴 JSON 数组或包含 cookies 字段的对象）"}

            cookies = self._to_playwright_cookies(raw)
            if not cookies:
                return {"success": False, "error": "Cookie 列表为空或格式不支持（至少需要 name/value/domain+path 或 url）"}

            context = None
            try:
                if not self._playwright:
                    await self.start()

                profile_dir = self._get_profile_dir(profile_id)
                os.makedirs(profile_dir, exist_ok=True)
                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)

                context = await self._launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,
                    viewport={"width": 1024, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    proxy=proxy,
                    args=BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )

                await context.add_cookies(cookies)

                # 导入后访问 labs 页面刷新 session
                token = await self._extract_from_context(profile, context)

                return {
                    "success": True,
                    "imported": len(cookies),
                    "raw_count": len(raw),
                    "has_token": bool(token),
                }

            except Exception as e:
                logger.error(f"[{profile['name']}] Cookie 导入失败: {e}")
                return {"success": False, "error": str(e)}
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def export_cookies(self, profile_id: int) -> Dict[str, Any]:
        """导出 labs.google 域名 Cookie，格式与导入接口兼容。"""
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return {"success": False, "error": "Profile 不存在"}

            context = None
            try:
                if self._active_profile_id == profile_id and self._active_context:
                    cookies = await self._active_context.cookies("https://labs.google")
                else:
                    profile_dir = self._get_profile_dir(profile_id)
                    if not os.path.exists(profile_dir):
                        return {"success": False, "error": "无持久化数据，请先登录或导入会话数据"}

                    if not self._playwright:
                        await self.start()

                    self._clean_locks(profile_dir)
                    proxy = await self._get_proxy(profile)
                    context = await self._launch_persistent_context(
                        user_data_dir=profile_dir,
                        headless=True,
                        viewport={"width": 1024, "height": 768},
                        locale="en-US",
                        timezone_id="America/New_York",
                        proxy=proxy,
                        args=BROWSER_ARGS,
                        ignore_default_args=["--enable-automation"],
                    )
                    cookies = await context.cookies("https://labs.google")

                if not cookies:
                    return {"success": False, "error": "当前账号暂无可导出的 Cookie"}

                return {
                    "success": True,
                    "kind": "session",
                    "source": "active_context" if self._active_profile_id == profile_id and self._active_context else "browser_profile",
                    "profile_id": profile_id,
                    "profile_name": profile.get("name") or "",
                    "cookies": cookies,
                    "cookie_count": len(cookies),
                    "count": len(cookies),
                    "cookies_json": json.dumps(cookies, ensure_ascii=False, indent=2),
                    "has_token": any(c.get("name") == config.session_cookie_name for c in cookies),
                }

            except Exception as e:
                logger.error(f"[{profile['name']}] Cookie 导出失败: {e}")
                return {"success": False, "error": str(e)}
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def launch_for_login(self, profile_id: int) -> bool:
        """启动浏览器用于 VNC 登录（非 headless）"""
        if not config.enable_vnc:
            logger.warning("已禁用 VNC 登录（设置 ENABLE_VNC=1 可启用）")
            return False
        async with self._lock:
            self._flow_project_ids.pop(int(profile_id), None)
            await self._close_active()

            profile = await profile_db.get_profile(profile_id)
            if not profile:
                logger.error(f"Profile {profile_id} 不存在")
                return False

            try:
                if not self._playwright:
                    await self.start()

                ok = await self._ensure_vnc_stack()
                if not ok:
                    logger.error(f"[{profile['name']}] VNC 服务启动失败")
                    return False

                profile_dir = self._get_profile_dir(profile_id)
                os.makedirs(profile_dir, exist_ok=True)
                self._clean_locks(profile_dir)  # 清理锁文件
                proxy = await self._get_proxy(profile)

                # 非 headless，用于 VNC 登录
                self._active_context = await self._launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=False,  # VNC 可见
                    viewport={"width": 1024, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    proxy=proxy,
                    args=LOGIN_BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                self._active_profile_id = profile_id

                page = self._active_context.pages[0] if self._active_context.pages else await self._active_context.new_page()
                await page.goto(config.labs_url, wait_until="domcontentloaded", timeout=90000)

                logger.info(f"[{profile['name']}] 浏览器已启动，请通过 VNC 登录")
                return True

            except Exception as e:
                logger.error(f"[{profile['name']}] 启动失败: {e}")
                return False

    async def close_browser(self, profile_id: int) -> Dict[str, Any]:
        """关闭浏览器并保存状态"""
        async with self._lock:
            if self._active_profile_id != profile_id:
                return {"success": False, "error": "该 Profile 浏览器未运行"}

            if self._active_context:
                profile = await profile_db.get_profile(profile_id)
                token = await self._extract_from_context(profile, self._active_context) if profile else None
                is_logged_in = bool(token)
                await self._close_active()
                await self._stop_vnc_stack()

                status = "已登录" if is_logged_in else "未登录"
                logger.info(f"Profile {profile_id} 浏览器已关闭，状态: {status}")
                return {"success": True, "is_logged_in": is_logged_in,
                        **({"error": self.get_session_error(profile_id)["error"]} if not is_logged_in else {})}

            return {"success": True}

    async def abort_active_browser(self, profile_id: Optional[int] = None) -> bool:
        """Force close the active browser without persisting login state."""
        async with self._lock:
            if self._active_context is None:
                return False
            if profile_id is not None and self._active_profile_id != profile_id:
                return False
            try:
                await self._close_active()
            finally:
                await self._stop_vnc_stack()
            return True

    async def extract_token(self, profile_id: int) -> Optional[str]:
        """提取 Token（Headless 模式，使用持久化上下文）"""
        self._session_errors.pop(profile_id, None)
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return None

            profile_dir = self._get_profile_dir(profile_id)

            # 检查是否有持久化数据
            if not os.path.exists(profile_dir) and not profile.get("google_cookies"):
                logger.warning(f"[{profile['name']}] 无持久化数据，请先登录")
                return None

            # 如果当前 profile 浏览器正在运行（VNC 登录中），直接提取
            if self._active_profile_id == profile_id and self._active_context:
                return await self._extract_from_context(profile, self._active_context)

            # 否则用 headless 模式启动
            context = None
            try:
                if not self._playwright:
                    await self.start()

                profile_dir = self._get_profile_dir(profile_id)
                self._clean_locks(profile_dir)  # 清理锁文件
                proxy = await self._get_proxy(profile)

                logger.info(f"[{profile['name']}] Headless 模式提取 Token...")
                seed_cookies = not os.path.exists(profile_dir)
                os.makedirs(profile_dir, exist_ok=True)

                # Headless + 持久化上下文
                context = await self._launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,  # Headless 省资源
                    viewport={"width": 1024, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    proxy=proxy,
                    args=BROWSER_ARGS,  # 完整内存优化参数
                    ignore_default_args=["--enable-automation"],
                )

                if seed_cookies:
                    try:
                        raw = self._parse_cookies_payload(profile.get("google_cookies") or "[]")
                        scoped = [c for c in raw if c.get("domain", "").lstrip(".") in {"google.com", "accounts.google.com", "flow.google.com", "www.google.com"} and not c.get("partitionKey")]
                        await context.add_cookies(self._to_playwright_cookies(scoped))
                    except (ValueError, TypeError):
                        logger.warning("Stored cookies lack domain metadata; browser login is required")
                token = await self._extract_from_context(profile, context)
                return token

            except Exception as e:
                self._session_errors[profile_id] = failure("extraction_failed", "源浏览器启动或代理连接失败，请检查 Profile 配置")
                logger.error(f"[{profile['name']}] 提取失败 ({type(e).__name__})")
                return None
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                    logger.info(f"[{profile['name']}] Headless 浏览器已关闭")

    async def _extract_from_context(self, profile: Dict[str, Any], context: BrowserContext) -> Optional[str]:
        """从上下文提取 Token（通过 signin 页面刷新 session）"""
        page = None
        self._session_errors.pop(profile["id"], None)
        try:
            page = await context.new_page()
            await self._install_page_route(page)

            # 访问 labs 页面，必要时自动推进 Google / 托管资料 / labs 首次引导。
            logger.info(f"[{profile['name']}] 访问 {config.labs_url} 刷新 session...")
            await page.goto(config.labs_url, wait_until="domcontentloaded", timeout=60000)

            await self._settle_labs_session(profile, context, page)
            if self._session_errors.get(profile["id"], {}).get("error_code") == "manual_action_required":
                await self._persist_login_state(profile["id"], None)
                return None
            return await self._complete_flow_session(profile, context, page)

        except Exception as e:
            self._session_errors[profile["id"]] = failure("extraction_failed", "源浏览器会话提取失败，请检查代理连接并完成 Labs/Flow 登录")
            await self._persist_login_state(profile["id"], None)
            logger.error(f"[{profile['name']}] 提取异常 ({type(e).__name__})")
            return None
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass

    async def auto_login(self, profile_id: int) -> Dict[str, Any]:
        self._session_errors.pop(profile_id, None)
        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}

        login_account = str(profile.get("login_account") or "").strip()
        login_password = str(profile.get("login_password") or "").strip()
        if not login_account or not login_password:
            return {"success": False, "error": "请先为该账号配置登录账号和登录密码"}

        async with self._lock:
            await self._close_active()

            context = None
            page = None
            use_vnc = False
            try:
                if not self._playwright:
                    await self.start()

                profile_dir = self._get_profile_dir(profile_id)
                os.makedirs(profile_dir, exist_ok=True)
                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)

                if config.enable_vnc:
                    use_vnc = await self._ensure_vnc_stack()

                context = await self._launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=not use_vnc,
                    viewport={"width": 1280, "height": 900},
                    locale="en-US",
                    timezone_id="America/New_York",
                    proxy=proxy,
                    args=LOGIN_BROWSER_ARGS if use_vnc else BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )

                page = context.pages[0] if context.pages else await context.new_page()
                await self._install_page_route(page)
                await page.goto(config.login_url, wait_until="domcontentloaded", timeout=60000)

                for _ in range(45):
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=3000)
                    except Exception:
                        pass

                    body_text = await self._safe_page_text(page)
                    blocker = self._detect_login_blocker(body_text)
                    if blocker:
                        await self._persist_login_state(
                            profile_id,
                            None,
                            email=self._resolve_known_email(profile, body_text),
                        )
                        return {"success": False, "error": blocker, "requires_manual_action": True}

                    if use_vnc and not str(body_text or "").strip() and await self._handle_native_chrome_profile_prompts():
                        continue

                    if await self._handle_managed_account_prompts(page, body_text):
                        continue

                    if await self._advance_google_login(page, login_account, login_password):
                        continue

                    if await self._handle_labs_onboarding(page, body_text):
                        continue

                    if await self._is_labs_session_ready(page, body_text):
                        break

                    await asyncio.sleep(1.0)

                token = await self._complete_flow_session(profile, context, page)
                if not token:
                    return self.get_session_error(profile_id)

                return {
                    "success": True,
                    "is_logged_in": True,
                    "has_token": True,
                    "profile_name": profile["name"],
                }

            except Exception as e:
                await self._persist_login_state(profile_id, None)
                logger.error(f"[{profile['name']}] 自动登录失败 ({type(e).__name__})")
                return failure("extraction_failed", "源浏览器自动登录失败，请检查代理或通过手动登录完成授权")
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                if use_vnc:
                    await self._stop_vnc_stack()

    async def check_login_status(self, profile_id: int) -> Dict[str, Any]:
        """检查登录状态"""
        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}

        token = await self.peek_token(profile_id)
        project_id = await self.get_flow_project_id(profile_id)
        await self._persist_login_state(
            profile_id,
            token,
            email=self._resolve_known_email(profile),
        )
        return {
            "success": True,
            "is_logged_in": token is not None,
            "has_flow_project": bool(project_id),
            "profile_name": profile["name"],
            **({"error": self.get_session_error(profile_id)["error"]} if not token else {}),
        }

    async def _peek_context_session(self, profile, context) -> Optional[str]:
        result = await self._validate_context_session(context, self._resolve_known_email(profile) or "")
        if result["success"]:
            try:
                cookies = scoped_google_cookies(await context.cookies())
                checked = validate_google_cookies(cookies)
            except Exception:
                checked = failure("verification_unavailable", "暂无法读取源浏览器 Cookie，请稍后重试")
            if not checked["success"]:
                result = checked
        if not result["success"]:
            self._session_errors[profile["id"]] = result
            return None
        self._session_errors.pop(profile["id"], None)
        return result["session_token"]

    async def peek_token(self, profile_id: int) -> Optional[str]:
        """Verify existing OAuth without triggering a sign-in or changing browser pages."""
        async with self._lock:
            profile = await profile_db.get_profile(profile_id)
            if not profile:
                return None

            profile_dir = self._get_profile_dir(profile_id)
            if not os.path.exists(profile_dir):
                return None

            if self._active_profile_id == profile_id and self._active_context:
                return await self._peek_context_session(profile, self._active_context)

            context = None
            try:
                if not self._playwright:
                    await self.start()

                self._clean_locks(profile_dir)
                proxy = await self._get_proxy(profile)
                context = await self._launch_persistent_context(
                    user_data_dir=profile_dir,
                    headless=True,
                    viewport={"width": 1024, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    proxy=proxy,
                    args=BROWSER_ARGS,
                    ignore_default_args=["--enable-automation"],
                )
                return await self._peek_context_session(profile, context)
            except Exception:
                return None
            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def delete_profile_data(self, profile_id: int):
        """删除 profile 数据"""
        profile_dir = self._get_profile_dir(profile_id)
        if os.path.exists(profile_dir):
            shutil.rmtree(profile_dir)
            logger.info(f"已删除: {profile_dir}")

    def get_active_profile_id(self) -> Optional[int]:
        return self._active_profile_id

    def get_status(self) -> Dict[str, Any]:
        status = self._get_supervisor_status()
        vnc_stack_running = all(status.get(p) == "RUNNING" for p in ("xvfb", "x11vnc", "novnc")) if status else False
        return {
            "is_running": self._playwright is not None,
            "active_profile_id": self._active_profile_id,
            "has_active_browser": self._active_context is not None,
            "profiles_dir": config.profiles_dir,
            "enable_vnc": bool(config.enable_vnc),
            "vnc_stack_running": bool(vnc_stack_running),
        }


browser_manager = BrowserManager()
