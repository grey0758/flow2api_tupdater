"""Two isolated, owner-operated login desktops. No token extraction or sync."""
import asyncio
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import async_playwright

from .browser_profile import configure_web_only_profile
from .config import config
from .logger import logger
from .proxy_utils import format_proxy_for_playwright, parse_proxy


MAX_LOGIN_SLOTS = 2
INVITE_TTL_SECONDS = 4 * 60 * 60
SUPERVISOR_CONF = "/etc/supervisor/conf.d/supervisord.conf"


@dataclass
class LoginSlot:
    number: int
    profile_id: int
    capability: str
    expires_at: float
    session_capability: str = ""
    context: Any = None
    state: str = "starting"
    lifecycle: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    closed: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    cleanup_task: Any = field(default=None, repr=False)

    @property
    def display(self) -> str:
        return f":{100 + self.number}"

    @property
    def novnc_port(self) -> int:
        return 6080 + self.number

    def public(self) -> dict:
        return {"slot": self.number, "profile_id": self.profile_id, "state": self.state}


class LoginSlotError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


class LoginSlots:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._slots: dict[int, LoginSlot] = {}
        self._expiry_tasks: dict[int, asyncio.Task] = {}
        self._playwright = None
        self._launch_lock = asyncio.Lock()

    def owns(self, profile_id: int) -> bool:
        return any(slot.profile_id == profile_id for slot in self._slots.values())

    def any_active(self) -> bool:
        return bool(self._slots)

    def has_slot(self, number: int) -> bool:
        return number in self._slots

    def status(self) -> list[dict]:
        return [
            self._slots[number].public() if number in self._slots
            else {"slot": number, "state": "free"}
            for number in range(1, MAX_LOGIN_SLOTS + 1)
        ]

    def authorize(self, capability: str) -> LoginSlot:
        for slot in self._slots.values():
            if slot.session_capability and secrets.compare_digest(slot.session_capability, capability):
                if time.time() >= slot.expires_at:
                    raise LoginSlotError(410, "邀请已过期，请联系管理员")
                if slot.state not in {"ready", "awaiting_check", "checking"}:
                    raise LoginSlotError(409, "登录桌面暂不可用")
                return slot
        raise LoginSlotError(404, "邀请不存在")

    async def get_slot(self, number: int) -> LoginSlot | None:
        async with self._lock:
            return self._slots.get(number)

    async def get_profile_slot(self, profile_id: int) -> LoginSlot | None:
        async with self._lock:
            return next(
                (slot for slot in self._slots.values() if slot.profile_id == profile_id),
                None,
            )

    async def claim(self, capability: str) -> tuple[LoginSlot, str]:
        async with self._lock:
            for slot in self._slots.values():
                if secrets.compare_digest(slot.capability, capability):
                    if time.time() >= slot.expires_at:
                        raise LoginSlotError(410, "邀请已过期，请联系管理员")
                    if slot.state != "ready":
                        raise LoginSlotError(409, "登录桌面暂不可用")
                    if slot.session_capability:
                        raise LoginSlotError(409, "邀请已经被领取")
                    slot.session_capability = secrets.token_urlsafe(32)
                    return slot, slot.session_capability
        raise LoginSlotError(404, "邀请不存在")

    @staticmethod
    def _supervisorctl(action: str, name: str):
        import subprocess

        result = subprocess.run(
            ["supervisorctl", "-c", SUPERVISOR_CONF, action, name],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"Supervisor could not {action} {name}")

    async def _stack(self, number: int, action: str):
        order = ("xvfb", "fluxbox", "x11vnc", "novnc")
        stopped = True
        for service in (order if action == "start" else reversed(order)):
            try:
                await asyncio.to_thread(self._supervisorctl, action, f"slot{number}-{service}")
                if action == "start" and service == "xvfb":
                    await asyncio.sleep(0.4)
            except Exception:
                if action == "start":
                    raise
                stopped = False
                logger.warning("登录槽位桌面停止失败: slot%s-%s", number, service)
        return stopped

    async def launch(self, profile: dict) -> LoginSlot:
        if not config.enable_vnc:
            raise LoginSlotError(400, "VNC 未启用")
        profile_id = int(profile["id"])
        from .execution import execution_gate
        async with execution_gate.hold("reserve_login_slot", profile_id=profile_id):
            async with self._lock:
                if self.owns(profile_id):
                    raise LoginSlotError(409, "该 Profile 已占用一个槽位")
                from .browser import browser_manager
                from .updater import token_syncer
                if token_syncer.is_syncing():
                    raise LoginSlotError(409, "正在同步；稍后再申请槽位")
                if browser_manager.get_active_profile_id() is not None:
                    raise LoginSlotError(409, "旧版登录桌面仍在运行；固定并发槽位不可超过两个")
                number = next((i for i in range(1, MAX_LOGIN_SLOTS + 1) if i not in self._slots), None)
                if number is None:
                    raise LoginSlotError(409, "两个登录槽位已满")
                slot = LoginSlot(number, profile_id, secrets.token_urlsafe(32), time.time() + INVITE_TTL_SECONDS)
                self._slots[number] = slot
                self._expiry_tasks[number] = asyncio.create_task(self._expire(slot))

        async with slot.lifecycle:
            try:
                await self._stack(number, "start")
                async with self._launch_lock:
                    if self._playwright is None:
                        self._playwright = await async_playwright().start()
                    playwright = self._playwright
                profile_dir = os.path.join(os.path.abspath(config.profiles_dir), f"profile_{profile_id}")
                os.makedirs(profile_dir, mode=0o700, exist_ok=True)
                configure_web_only_profile(profile_dir)
                proxy = None
                if profile.get("proxy_enabled"):
                    parsed = parse_proxy(profile.get("proxy_url") or "")
                    if not parsed:
                        raise LoginSlotError(400, "源代理无效；不允许直连回退")
                    proxy = format_proxy_for_playwright(parsed)
                context = await playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir, headless=False,
                    env={**os.environ, "DISPLAY": slot.display},
                    viewport={"width": 1024, "height": 768},
                    locale="en-US", timezone_id="America/New_York",
                    proxy=proxy,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-extensions",
                          "--disable-blink-features=AutomationControlled"],
                    ignore_default_args=["--enable-automation"],
                )
                slot.context = context
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto(config.labs_url, wait_until="domcontentloaded", timeout=90000)
                async with self._lock:
                    if self._slots.get(number) is not slot:
                        raise LoginSlotError(409, "登录槽位已经取消")
                    slot.state = "ready"
                return slot
            except BaseException:
                await asyncio.shield(self._close_slot(slot))
                raise

    async def _expire(self, slot: LoginSlot) -> None:
        await asyncio.sleep(max(0, slot.expires_at - time.time()))
        async with self._lock:
            should_release = self._slots.get(slot.number) is slot
        if should_release:
            await self.release(slot.number, expected=slot)

    async def _cleanup_slot(self, slot: LoginSlot) -> None:
        slot.state = "closing"
        slot.closed.set()
        context_closed = True
        try:
            if slot.context:
                await slot.context.close()
                slot.context = None
        except Exception:
            context_closed = False
            logger.warning("登录槽位浏览器关闭失败；隔离槽位 %s", slot.number)
        finally:
            stopped = await self._stack(slot.number, "stop")
            async with self._lock:
                if stopped is False or not context_closed:
                    slot.state = "quarantined"
                elif self._slots.get(slot.number) is slot:
                    del self._slots[slot.number]
                task = self._expiry_tasks.get(slot.number)
                if task and task is not asyncio.current_task():
                    task.cancel()
                if self._expiry_tasks.get(slot.number) is task:
                    self._expiry_tasks.pop(slot.number, None)

    async def _close_slot(self, slot: LoginSlot) -> None:
        if slot.cleanup_task is None or (
            slot.cleanup_task.done() and slot.state == "quarantined"
        ):
            slot.cleanup_task = asyncio.create_task(self._cleanup_slot(slot))
        await asyncio.shield(slot.cleanup_task)

    async def release(self, number: int, *, expected: LoginSlot | None = None) -> None:
        async with self._lock:
            slot = self._slots.get(number)
            if not slot or (expected is not None and slot is not expected):
                return
        async with slot.lifecycle:
            async with self._lock:
                if self._slots.get(number) is not slot:
                    return
            await self._close_slot(slot)

    async def finish_owner_login(self, expected: LoginSlot) -> int:
        """Pause at the owner handoff; operator validation decides whether to close."""
        slot = expected
        async with slot.lifecycle:
            async with self._lock:
                if self._slots.get(slot.number) is not slot or slot.state != "ready":
                    raise LoginSlotError(409, "登录槽位已经结束")
                slot.state = "awaiting_check"
        return slot.profile_id

    async def check_owner_login(self, expected: LoginSlot) -> dict:
        """Validate the exact context; close only after all no-cost gates pass."""
        slot = expected
        async with slot.lifecycle:
            async with self._lock:
                if self._slots.get(slot.number) is not slot or slot.state != "awaiting_check":
                    raise LoginSlotError(409, "请先等待 owner 在该槽位报告登录完成")
                slot.state = "checking"
            from .browser import browser_manager
            try:
                result = await browser_manager.check_login_slot_status(
                    slot.profile_id, slot.context
                )
                accepted = bool(
                    result.get("success")
                    and result.get("is_logged_in")
                    and result.get("has_flow_project")
                )
            except BaseException:
                async with self._lock:
                    if self._slots.get(slot.number) is slot:
                        slot.state = "ready"
                raise
            if not accepted:
                async with self._lock:
                    if self._slots.get(slot.number) is slot:
                        slot.state = "ready"
                return result
            await self._close_slot(slot)
            if slot.state == "quarantined":
                return {
                    **result,
                    "success": False,
                    "error_code": "slot_quarantined",
                    "error": "登录已验证，但桌面未完全停止；该槽位已隔离，暂不可继续 extract",
                }
            return result

    async def stop(self) -> None:
        for slot in tuple(self._slots.values()):
            await self.release(slot.number, expected=slot)
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


login_slots = LoginSlots()
