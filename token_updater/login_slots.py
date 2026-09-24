"""Coordinate two isolated, non-root owner-login worker containers."""

import asyncio
import hashlib
import json
import os
import secrets
import shutil
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .config import config
from .logger import logger
from .login_worker_protocol import sign_headers


MAX_LOGIN_SLOTS = 2
INVITE_TTL_SECONDS = 4 * 60 * 60


@dataclass
class LoginSlot:
    number: int
    profile_id: int
    capability: str
    expires_at: float
    worker_socket: str = ""
    staging_dir: str = ""
    worker_uid: int = 0
    worker_proxy_url: str = ""
    generation: str = ""
    session_capability: str = ""
    state: str = "starting"
    lifecycle: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    input_gate: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    closed: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

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
        self._blocked_profiles: set[int] = set()
        self._quarantined_numbers: set[int] = set()
        self._reconciled = False

    async def reconcile(self) -> None:
        """Revoke lost invitations and stop unfinished worker contexts.

        Owner capabilities remain memory-only and are never reconstructed.
        The non-secret persisted generation is used exactly once to sign an
        ``abort`` for a pre-restart worker context.  A later administrator
        recovery rotates to a new generation and a new invitation.
        """
        from .database import profile_db
        profiles = await profile_db.get_all_profiles()
        unfinished = [
            profile for profile in profiles
            if profile.get("login_slot_claimed") and not profile.get("login_slot_handoff_complete")
        ]
        blocked = {int(profile["id"]) for profile in unfinished}
        claimed_by_number: dict[int, dict] = {}
        for profile in unfinished:
            number = int(profile.get("login_slot_number") or 0)
            generation = str(profile.get("login_slot_generation") or "")
            if number not in {1, 2} or not generation or len(generation) > 128:
                continue
            if number in claimed_by_number:
                raise RuntimeError(f"multiple unfinished Profiles claim login slot {number}")
            claimed_by_number[number] = profile

        quarantined = set()
        for number, uid in enumerate(config.login_slot_worker_ids, 1):
            stage, _ = self._slot_paths(number, 0)
            if not stage.is_dir() or stage.is_symlink() or stage.stat().st_uid != uid:
                raise RuntimeError(f"login worker {number} Profile mount is not ready")
            if any(stage.iterdir()):
                quarantined.add(number)
                profile = claimed_by_number.get(number)
                if profile:
                    stale = LoginSlot(
                        number=number,
                        profile_id=int(profile["id"]),
                        capability="",
                        expires_at=0,
                        worker_socket=config.login_slot_worker_sockets[number - 1],
                        staging_dir=str(stage),
                        worker_uid=uid,
                        worker_proxy_url=config.login_slot_worker_proxy_urls[number - 1],
                        generation=str(profile["login_slot_generation"]),
                        state="quarantined",
                    )
                    stale.closed.set()
                    try:
                        result = await self._worker(stale, "abort", timeout=30)
                    except Exception as exc:
                        raise RuntimeError(
                            f"login worker {number} old generation could not be revoked"
                        ) from exc
                    if result.get("state") != "quarantined" or result.get("browser_running"):
                        raise RuntimeError(
                            f"login worker {number} did not release its old browser context"
                        )
        async with self._lock:
            if self._slots:
                raise RuntimeError("cannot reconcile live login invitations")
            self._blocked_profiles = blocked
            self._quarantined_numbers = quarantined
            self._reconciled = True

    def owns(self, profile_id: int) -> bool:
        return profile_id in self._blocked_profiles or any(
            slot.profile_id == profile_id for slot in self._slots.values()
        )

    def any_active(self) -> bool:
        return bool(self._slots or self._blocked_profiles or self._quarantined_numbers)

    def has_slot(self, number: int) -> bool:
        return number in self._slots

    def status(self) -> list[dict]:
        active_profiles = {slot.profile_id for slot in self._slots.values()}
        orphaned = bool(self._blocked_profiles - active_profiles)
        return [
            self._slots[number].public() if number in self._slots
            else {"slot": number, "state": "quarantined" if orphaned or number in self._quarantined_numbers else "free"}
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

    async def is_current(self, expected: LoginSlot) -> bool:
        async with self._lock:
            return (
                self._slots.get(expected.number) is expected
                and not expected.closed.is_set()
                and expected.state in {"ready", "awaiting_check", "checking"}
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
    def _signed_headers(slot: LoginSlot, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        if not config.login_slot_signing_private_key:
            raise RuntimeError("login worker signing key is not configured")
        return sign_headers(
            config.login_slot_signing_private_key,
            slot=slot.number,
            generation=slot.generation,
            profile_id=slot.profile_id,
            method=method,
            path=path,
            body=body,
        )

    @classmethod
    async def _worker(
        cls, slot: LoginSlot, method: str, *, payload: dict | None = None,
        timeout: float = 100,
    ) -> dict:
        path = f"/{method}"
        body = json.dumps(payload or {}, sort_keys=True, separators=(",", ":")).encode()
        headers = cls._signed_headers(slot, "POST", path, body)
        headers["Content-Type"] = "application/json"
        try:
            transport = httpx.AsyncHTTPTransport(uds=slot.worker_socket)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://login-worker", timeout=timeout
            ) as client:
                response = await client.post(path, content=body, headers=headers)
            if response.status_code != 200:
                raise RuntimeError(f"worker {method} returned HTTP {response.status_code}")
            data = response.json()
            if not isinstance(data, dict):
                raise RuntimeError(f"worker {method} returned an invalid response")
            exact_scope = bool(
                data.get("slot") == slot.number
                and data.get("generation") == slot.generation
                and data.get("profile_id") == slot.profile_id
            )
            # A successful abort deliberately clears the worker assignment
            # before returning its public state.  Accept only that exact
            # terminal shape on the signed, slot-specific UDS request; every
            # other worker method must still echo the original scope.
            cleared_abort_scope = bool(
                method == "abort"
                and data.get("slot") == slot.number
                and data.get("generation") == ""
                and data.get("profile_id") == 0
                and data.get("state") in {"idle", "quarantined"}
                and data.get("browser_running") is False
            )
            if not (exact_scope or cleared_abort_scope):
                raise RuntimeError("worker response scope does not match")
            return data
        except Exception as exc:
            raise RuntimeError(f"login worker {slot.number} {method} failed") from exc

    @classmethod
    def websocket_headers(cls, slot: LoginSlot) -> dict[str, str]:
        return cls._signed_headers(slot, "GET", "/websockify")

    @staticmethod
    def _raw_not_symlink(path: Path) -> None:
        current = path.absolute()
        while current != current.parent:
            if current.exists() and stat.S_ISLNK(os.lstat(current).st_mode):
                raise LoginSlotError(503, "登录槽位路径包含符号链接")
            current = current.parent

    @classmethod
    def _slot_paths(cls, number: int, profile_id: int) -> tuple[Path, Path]:
        raw_root = Path(config.login_slot_root).absolute()
        raw_profiles = Path(config.profiles_dir).absolute()
        cls._raw_not_symlink(raw_root)
        cls._raw_not_symlink(raw_profiles)
        root = raw_root.resolve()
        profiles = raw_profiles.resolve()
        if root != profiles / ".login-slots":
            raise LoginSlotError(503, "登录槽位目录不在受控 Profile 根目录")
        stage = root / f"slot{number}" / "profile"
        target = profiles / f"profile_{profile_id}"
        if stage.parent.parent != root or target.parent != profiles:
            raise LoginSlotError(503, "登录槽位路径越界")
        return stage, target

    @staticmethod
    def _assert_empty_profile(path: Path, uid: int) -> None:
        if not path.is_dir() or path.is_symlink():
            raise LoginSlotError(503, "槽位 Profile 挂载未预创建")
        details = path.stat()
        if details.st_uid != uid:
            raise LoginSlotError(503, "槽位 Profile 所有者与 worker 不一致")
        if any(path.iterdir()):
            raise LoginSlotError(409, "槽位仍含上一次登录数据，已隔离等待管理员处理")

    @staticmethod
    def _profile_manifest(root: Path) -> tuple[int, int, str]:
        digest = hashlib.sha256()
        files = 0
        size = 0
        for current, directories, names in os.walk(root, topdown=True, followlinks=False):
            directories.sort()
            names.sort()
            current_path = Path(current)
            for name in list(directories):
                path = current_path / name
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise LoginSlotError(409, "Profile 含不支持的目录项")
                relative = path.relative_to(root).as_posix().encode()
                digest.update(b"D" + len(relative).to_bytes(4, "big") + relative)
            for name in names:
                path = current_path / name
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    raise LoginSlotError(409, "Profile 含不支持的文件项")
                relative = path.relative_to(root).as_posix().encode()
                digest.update(b"F" + len(relative).to_bytes(4, "big") + relative)
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                files += 1
        return files, size, digest.hexdigest()

    @classmethod
    def _promote_profile_snapshot(cls, slot: LoginSlot) -> None:
        stage, target = cls._slot_paths(slot.number, slot.profile_id)
        if Path(slot.staging_dir).resolve() != stage or not any(stage.iterdir()):
            raise LoginSlotError(409, "已验证 Profile 数据不存在")
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise LoginSlotError(409, "正式 Profile 目录发生冲突，槽位已隔离")
        if target.exists():
            target.rmdir()
        temporary = target.parent / f".{target.name}.import-{slot.generation}"
        if temporary.exists():
            raise LoginSlotError(409, "Profile 导入暂存目录已存在")
        before = cls._profile_manifest(stage)
        try:
            shutil.copytree(stage, temporary, symlinks=False)
            after = cls._profile_manifest(stage)
            copied = cls._profile_manifest(temporary)
            if before != after or before != copied:
                raise LoginSlotError(409, "Profile 在快照期间发生变化")
            os.chmod(temporary, 0o700)
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    async def launch(self, profile: dict) -> LoginSlot:
        if not self._reconciled:
            raise LoginSlotError(503, "登录槽位尚未完成启动对账")
        if not config.enable_vnc:
            raise LoginSlotError(400, "VNC 未启用")
        profile_id = int(profile["id"])
        if (profile.get("proxy_url") or "") != config.login_slot_expected_source_proxy:
            raise LoginSlotError(400, "源代理与隔离 worker 的固定出口不一致")
        from .execution import execution_gate
        async with execution_gate.hold("reserve_login_slot", profile_id=profile_id):
            async with self._lock:
                if any(slot.profile_id == profile_id for slot in self._slots.values()):
                    raise LoginSlotError(409, "该 Profile 已占用一个槽位")
                if profile_id in self._blocked_profiles:
                    raise LoginSlotError(409, "该 Profile 的旧邀请仍在隔离等待管理员处理")
                active_profiles = {slot.profile_id for slot in self._slots.values()}
                if self._blocked_profiles - active_profiles:
                    raise LoginSlotError(503, "存在重启后未完成的 Profile 交接，暂停新邀请")
                from .browser import browser_manager
                from .updater import token_syncer
                if token_syncer.is_syncing():
                    raise LoginSlotError(409, "正在同步；稍后再申请槽位")
                if browser_manager.get_active_profile_id() is not None:
                    raise LoginSlotError(409, "旧版登录桌面仍在运行；请先完成其安全交接")
                number = next((
                    i for i in range(1, MAX_LOGIN_SLOTS + 1)
                    if i not in self._slots and i not in self._quarantined_numbers
                ), None)
                if number is None:
                    raise LoginSlotError(409, "两个登录槽位已满")
                stage, target = self._slot_paths(number, profile_id)
                if target.exists() and (not target.is_dir() or any(target.iterdir())):
                    raise LoginSlotError(409, "正式 Profile 目录已有数据；不可交给新邀请")
                self._assert_empty_profile(stage, config.login_slot_worker_ids[number - 1])
                generation = secrets.token_urlsafe(24)
                from .database import profile_db
                if not await profile_db.claim_login_slot(profile_id, number, generation):
                    raise LoginSlotError(409, "Profile 不再符合首次邀请条件")
                self._blocked_profiles.add(profile_id)
                slot = LoginSlot(
                    number=number,
                    profile_id=profile_id,
                    capability=secrets.token_urlsafe(32),
                    expires_at=time.time() + INVITE_TTL_SECONDS,
                    worker_socket=config.login_slot_worker_sockets[number - 1],
                    staging_dir=str(stage),
                    worker_uid=config.login_slot_worker_ids[number - 1],
                    worker_proxy_url=config.login_slot_worker_proxy_urls[number - 1],
                    generation=generation,
                )
                self._slots[number] = slot
                self._expiry_tasks[number] = asyncio.create_task(self._expire(slot))

        async with slot.lifecycle:
            try:
                launched = await self._worker(
                    slot, "assign", payload={"proxy_url": slot.worker_proxy_url}
                )
                if launched.get("state") != "ready" or not launched.get("browser_running"):
                    raise RuntimeError("login worker did not confirm browser readiness")
                async with self._lock:
                    if self._slots.get(number) is not slot:
                        raise LoginSlotError(409, "登录槽位已经取消")
                    slot.state = "ready"
                return slot
            except BaseException:
                try:
                    await asyncio.shield(self._worker(slot, "abort", timeout=30))
                except Exception:
                    pass
                async with self._lock:
                    if self._slots.get(number) is slot:
                        slot.state = "quarantined"
                        slot.closed.set()
                raise

    async def recover(self, profile: dict, number: int) -> LoginSlot:
        """Issue a new invitation for an expired, exact-slot retained Profile.

        Never reconstruct an old capability/generation or reset the claimed
        database row.  A different slot or a live browser is a hard stop.
        """
        if not self._reconciled or number not in {1, 2}:
            raise LoginSlotError(503, "登录槽位尚未完成安全对账")
        profile_id = int(profile["id"])
        if not (
            profile.get("login_slot_claimed")
            and not profile.get("login_slot_handoff_complete")
            and not profile.get("is_active")
            and not profile.get("is_logged_in")
            and int(profile.get("sync_count") or 0) == 0
            and int(profile.get("login_slot_number") or 0) == number
            and (profile.get("proxy_url") or "") == config.login_slot_expected_source_proxy
        ):
            raise LoginSlotError(409, "该 Profile 不属于未交接的隔离登录槽位")

        from .execution import execution_gate
        async with execution_gate.hold("recover_login_slot", profile_id=profile_id):
            async with self._lock:
                previous = self._slots.get(number)
                if previous and not (
                    previous.profile_id == profile_id
                    and previous.state == "quarantined"
                    and previous.closed.is_set()
                    and time.time() >= previous.expires_at
                ):
                    raise LoginSlotError(409, "该槽位仍在使用或不属于指定 Profile")
                if any(
                    slot.profile_id == profile_id and slot.number != number
                    for slot in self._slots.values()
                ):
                    raise LoginSlotError(409, "该 Profile 已绑定其他槽位")
                if profile_id not in self._blocked_profiles:
                    raise LoginSlotError(409, "未找到该 Profile 的隔离交接记录")
                stage, target = self._slot_paths(number, profile_id)
                if (
                    not stage.is_dir() or stage.is_symlink()
                    or stage.stat().st_uid != config.login_slot_worker_ids[number - 1]
                    or not any(stage.iterdir())
                    or (target.exists() and (not target.is_dir() or any(target.iterdir())))
                ):
                    raise LoginSlotError(409, "原槽位数据与正式 Profile 边界不符")
                from .browser import browser_manager
                from .updater import token_syncer
                if browser_manager.get_active_profile_id() is not None or token_syncer.is_syncing():
                    raise LoginSlotError(409, "存在运行中的浏览器或同步")
                previous_generation = str(profile.get("login_slot_generation") or "")
                next_generation = secrets.token_urlsafe(24)
                if not previous_generation:
                    raise LoginSlotError(409, "该 Profile 缺少可撤销的槽位代际记录")
                from .database import profile_db
                if not await profile_db.rotate_login_slot_generation(
                    profile_id,
                    number,
                    previous_generation,
                    next_generation,
                ):
                    raise LoginSlotError(409, "该 Profile 的槽位代际已变化，请刷新后重试")
                slot = LoginSlot(
                    number=number,
                    profile_id=profile_id,
                    capability=secrets.token_urlsafe(32),
                    expires_at=time.time() + INVITE_TTL_SECONDS,
                    worker_socket=config.login_slot_worker_sockets[number - 1],
                    staging_dir=str(stage),
                    worker_uid=config.login_slot_worker_ids[number - 1],
                    worker_proxy_url=config.login_slot_worker_proxy_urls[number - 1],
                    generation=next_generation,
                )
                # Install the new scope before the signed worker request so a
                # concurrent recovery cannot rebind the same volume.
                self._slots[number] = slot
                self._quarantined_numbers.add(number)
            async with slot.lifecycle:
                try:
                    result = await self._worker(
                        slot, "recover", payload={"proxy_url": slot.worker_proxy_url}, timeout=120,
                    )
                    if result.get("state") != "ready" or not result.get("browser_running"):
                        raise RuntimeError("worker did not reopen the retained Profile")
                    async with self._lock:
                        if self._slots.get(number) is not slot:
                            raise RuntimeError("recovery scope was replaced")
                        slot.state = "ready"
                        self._quarantined_numbers.discard(number)
                        self._expiry_tasks[number] = asyncio.create_task(self._expire(slot))
                    return slot
                except BaseException:
                    async with self._lock:
                        if self._slots.get(number) is slot:
                            slot.state = "quarantined"
                            # No invitation was returned to an owner. Permit a
                            # reviewed retry after the worker fault is fixed
                            # without waiting for a phantom invitation TTL.
                            slot.expires_at = 0
                            slot.closed.set()
                    raise

    async def _expire(self, slot: LoginSlot) -> None:
        await asyncio.sleep(max(0, slot.expires_at - time.time()))
        async with self._lock:
            should_release = self._slots.get(slot.number) is slot
        if should_release:
            await self.release(slot.number, expected=slot)

    async def _remove_slot(self, slot: LoginSlot) -> None:
        slot.closed.set()
        async with self._lock:
            if self._slots.get(slot.number) is slot:
                del self._slots[slot.number]
            task = self._expiry_tasks.get(slot.number)
            if task and task is not asyncio.current_task():
                task.cancel()
            if self._expiry_tasks.get(slot.number) is task:
                self._expiry_tasks.pop(slot.number, None)

    async def release(self, number: int, *, expected: LoginSlot | None = None) -> None:
        async with self._lock:
            slot = self._slots.get(number)
            if not slot or (expected is not None and slot is not expected):
                return
        async with slot.lifecycle:
            async with self._lock:
                if self._slots.get(number) is not slot:
                    return
                slot.state = "closing"
            try:
                result = await self._worker(slot, "abort", timeout=30)
            except Exception:
                logger.warning("登录 worker %s 无法确认停止；槽位已隔离", slot.number)
                slot.state = "quarantined"
                slot.closed.set()
                return
            if result.get("state") == "idle" and not any(Path(slot.staging_dir).iterdir()):
                await self._remove_slot(slot)
            else:
                slot.state = "quarantined"
                slot.closed.set()

    async def finish_owner_login(self, expected: LoginSlot) -> int:
        slot = expected
        async with slot.lifecycle:
            async with self._lock:
                if self._slots.get(slot.number) is not slot or slot.state != "ready":
                    raise LoginSlotError(409, "登录槽位已经结束")
                slot.state = "awaiting_check"
        return slot.profile_id

    async def check_owner_login(self, expected: LoginSlot) -> dict:
        slot = expected
        async with slot.lifecycle:
            async with slot.input_gate:
                async with self._lock:
                    if (
                        self._slots.get(slot.number) is not slot
                        or slot.state not in {"ready", "awaiting_check"}
                    ):
                        raise LoginSlotError(409, "登录槽位当前不能执行管理员检查")
                    slot.state = "checking"
                try:
                    result = await self._worker(slot, "validate", timeout=90)
                except Exception:
                    async with self._lock:
                        if self._slots.get(slot.number) is slot:
                            slot.state = "quarantined"
                            slot.closed.set()
                    raise LoginSlotError(503, "worker 无法完成同上下文检查；槽位已隔离")
                accepted = bool(
                    result.get("success")
                    and result.get("is_logged_in")
                    and result.get("has_flow_project")
                    and result.get("state") == "validated"
                )
                if not accepted:
                    async with self._lock:
                        if self._slots.get(slot.number) is slot:
                            slot.state = "ready" if result.get("state") == "ready" else "quarantined"
                    return {
                        key: value for key, value in result.items()
                        if key not in {"identity", "project_id", "generation", "profile_id", "uid", "slot"}
                    }

                identity = str(result.get("identity") or "").strip().lower()
                project_id = str(result.get("project_id") or "").strip()
                if not identity or "@" not in identity or not project_id:
                    slot.state = "quarantined"
                    slot.closed.set()
                    raise LoginSlotError(503, "worker 返回的验证证据不完整")
                try:
                    await asyncio.to_thread(self._promote_profile_snapshot, slot)
                    from .database import profile_db
                    await profile_db.update_profile(
                        slot.profile_id,
                        email=identity,
                        is_logged_in=1,
                        observed_flow_project_id=project_id,
                        observed_flow_project_verified=1,
                        observed_flow_project_identity=identity,
                    )
                    cleaned = await self._worker(slot, "cleanup", timeout=60)
                    if cleaned.get("state") != "idle" or any(Path(slot.staging_dir).iterdir()):
                        raise RuntimeError("worker cleanup did not empty the staging Profile")
                    await profile_db.update_profile(
                        slot.profile_id,
                        login_slot_handoff_complete=1,
                        login_slot_generation=None,
                    )
                except Exception as exc:
                    slot.state = "quarantined"
                    slot.closed.set()
                    raise LoginSlotError(503, "Profile 已验证但安全交接未完成；槽位保持隔离") from exc
                self._blocked_profiles.discard(slot.profile_id)
                await self._remove_slot(slot)
                return {
                    "success": True,
                    "is_logged_in": True,
                    "has_flow_project": True,
                    "profile_name": "",
                }

    async def stop(self) -> None:
        for slot in tuple(self._slots.values()):
            await self.release(slot.number, expected=slot)


login_slots = LoginSlots()
