"""Token sync service."""
import asyncio
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import httpx

from .browser import browser_manager
from .config import config
from .database import profile_db
from .events import dashboard_events
from .execution import execution_gate
from .gemini_bridge import gemini_cookie_bridge
from .logger import logger
from .session_validation import failure, scoped_google_cookies, validate_google_cookies
from .sync_errors import destination_error


class TokenSyncer:
    """Token 同步器。"""

    BROWSER_EXTRACT_TIMEOUT_SECONDS = 300

    def __init__(self):
        self._total_sync_count = 0
        self._total_error_count = 0
        self._last_batch_time: Optional[datetime] = None
        self._sync_lock = asyncio.Lock()

    def _normalize_email(self, email: Optional[str]) -> str:
        return (email or "").strip().lower()

    @staticmethod
    def _normalize_project_id(value: Any) -> Optional[str]:
        raw = str(value or "").strip()
        try:
            return str(UUID(raw))
        except (TypeError, ValueError, AttributeError):
            return None

    def is_syncing(self) -> bool:
        return self._sync_lock.locked()

    def _parse_time(self, value: Any) -> Optional[datetime]:
        if not value or not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo is not None else parsed
        except ValueError:
            return None

    async def _extract_token_with_timeout(self, profile: Dict[str, Any]) -> Optional[str]:
        profile_id = int(profile["id"])
        profile_name = str(profile.get("name") or profile_id)
        try:
            return await asyncio.wait_for(
                browser_manager.extract_token(profile_id),
                timeout=self.BROWSER_EXTRACT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.error(
                f"[{profile_name}] Browser token extraction timed out after {self.BROWSER_EXTRACT_TIMEOUT_SECONDS} seconds"
            )
            await browser_manager.abort_active_browser(profile_id)
            return None

    async def _build_gemini_token_with_timeout(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        profile_id = int(profile["id"])
        profile_name = str(profile.get("name") or profile_id)
        try:
            return await asyncio.wait_for(
                gemini_cookie_bridge.build_plugin_session_token(profile),
                timeout=self.BROWSER_EXTRACT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.error(
                f"[{profile_name}] Browser Gemini extraction timed out after {self.BROWSER_EXTRACT_TIMEOUT_SECONDS} seconds"
            )
            await browser_manager.abort_active_browser(profile_id)
            return {
                "success": False,
                "error": f"browser extraction timeout after {self.BROWSER_EXTRACT_TIMEOUT_SECONDS} seconds",
            }

    def _is_sync_overdue(self, profile: Dict[str, Any], now: Optional[datetime] = None) -> bool:
        """超过刷新间隔或从未同步过的 Profile，仍然需要兜底同步。"""
        last_sync_time = self._parse_time(profile.get("last_sync_time"))
        if not last_sync_time:
            return True

        current_time = now or datetime.now()
        if current_time.tzinfo is not None:
            current_time = current_time.astimezone().replace(tzinfo=None)
        interval_minutes = max(1, int(config.refresh_interval or 60))
        return current_time - last_sync_time >= timedelta(minutes=interval_minutes)

    def _should_sync_profile(
        self,
        profile: Dict[str, Any],
        token_lookup: Dict[str, Dict[str, Any]],
        now: Optional[datetime] = None,
    ) -> Tuple[bool, str]:
        email = self._normalize_email(profile.get("email"))
        if not email:
            return True, "未识别邮箱，无法精确检查上游状态"

        token_info = token_lookup.get(email)
        if not token_info:
            return True, "目标端不存在该 Token 记录"

        if token_info.get("sync_allowed") is False:
            return False, "目标不允许外部会话同步（如服务器独立登录），请在目标管理登录态"

        if not token_info.get("is_active", True):
            return True, "目标端 Token 已失活"

        if token_info.get("needs_refresh"):
            return True, "目标端判定需要刷新"

        if self._is_sync_overdue(profile, now=now):
            return True, f"距离上次同步已超过 {config.refresh_interval} 分钟"

        return False, "目标端 Token 状态正常"

    def _resolve_target(self, profile: Dict[str, Any]) -> Tuple[str, str]:
        """优先使用 Profile 级配置，没有则回退到全局默认值。"""
        flow2api_url = (profile.get("flow2api_url") or config.flow2api_url or "").strip().rstrip("/")
        connection_token = (
            profile.get("connection_token_override") or config.connection_token or ""
        ).strip()
        return flow2api_url, connection_token

    def _resolve_extract_mode(self, profile: Dict[str, Any]) -> str:
        remark = str(profile.get("remark") or "").strip().lower()
        if remark:
            if any(
                token in remark
                for token in (
                    "gemini2api",
                    "extract=gemini_cookies",
                    "mode=gemini_cookies",
                    "gemini-fastapi",
                    "gemini_fastapi",
                    "[gemini]",
                )
            ):
                return "gemini_cookies"
            if any(
                token in remark
                for token in (
                    "extract=session",
                    "mode=session",
                    "flow2api",
                    "[flow2api]",
                )
            ):
                return "session"
        fallback = str(config.token_extract_mode or "").strip().lower()
        if fallback in {"session", "gemini_cookies"}:
            return fallback
        return "session"

    async def _record_sync_result(
        self,
        profile: Dict[str, Any],
        target_url: str,
        success: Optional[bool] = None,
        action: str = "",
        message: str = "",
        email: Optional[str] = None,
        status: Optional[str] = None,
    ) -> None:
        event_status = status or ("success" if success else "error")
        await profile_db.record_sync_event(
            profile_id=profile["id"],
            profile_name=profile["name"],
            email=email or profile.get("email"),
            target_url=target_url,
            status=event_status,
            action=action,
            message=message,
        )
        await dashboard_events.publish(
            "sync_result",
            {
                "profile_id": profile["id"],
                "profile_name": profile["name"],
                "status": event_status,
                "target_url": target_url,
                "action": action,
                "message": message,
                "email": email or profile.get("email"),
            },
        )

    async def _update_profile_check_result(
        self,
        profile_id: int,
        result: str,
        checked_at: Optional[str] = None,
        **extra_fields: Any,
    ) -> str:
        timestamp = checked_at or datetime.now().isoformat()
        await profile_db.update_profile(
            profile_id,
            last_check_time=timestamp,
            last_check_result=result,
            **extra_fields,
        )
        return timestamp

    async def _check_tokens_status(
        self,
        flow2api_url: str,
        connection_token: str,
        emails: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """从指定 Flow2API 查询 Token 状态。"""
        if not connection_token:
            return {"success": False, "error": "未配置 CONNECTION_TOKEN"}
        if not flow2api_url:
            return {"success": False, "error": "未配置 Flow2API 地址"}

        url = f"{flow2api_url}/api/plugin/check-tokens"

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                payload = {}
                if emails:
                    payload["emails"] = emails

                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {connection_token}",
                    },
                )

                if response.status_code != 200:
                    return destination_error(response, endpoint="check-tokens")

                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
                    return failure("destination_response", "目标返回的账号状态格式无效")
                tokens = data["tokens"]
                return {
                    "success": True,
                    "tokens": tokens,
                }
        except Exception:
            return failure("destination_unavailable", "目标状态查询失败，请检查服务地址、网络连接或稍后重试")

    async def sync_profile(self, profile_id: int, *, source: str = "manual") -> Dict[str, Any]:
        from .login_slots import login_slots
        if login_slots.owns(profile_id):
            return {"success": False, "error": "Profile 正在独立登录槽位中，禁止同步"}
        profile = await profile_db.get_profile(profile_id)
        profile_name = profile.get("name", "") if profile else ""
        async with self._sync_lock:
            async with execution_gate.hold(
                "sync_profile",
                profile_id=profile_id,
                profile_name=profile_name,
                source=source,
            ):
                return await self._sync_profile(profile_id)

    async def _sync_profile(self, profile_id: int) -> Dict[str, Any]:
        """同步单个 Profile。"""
        from .login_slots import login_slots
        if login_slots.owns(profile_id):
            return {"success": False, "error": "Profile 正在独立登录槽位中，禁止同步"}
        profile = await profile_db.get_profile(profile_id)
        if not profile:
            return {"success": False, "error": "Profile 不存在"}

        flow2api_url, connection_token = self._resolve_target(profile)
        if not flow2api_url or not connection_token:
            error = "未配置完整的 Flow2API 地址或连接 Token"
            await self._update_profile_check_result(
                profile_id,
                f"failed: {error}",
                last_sync_time=datetime.now().isoformat(),
                last_sync_result=f"failed: {error}",
                error_count=profile.get("error_count", 0) + 1,
            )
            self._total_error_count += 1
            await self._record_sync_result(profile, flow2api_url, False, message=error)
            return {"success": False, "error": error, "target_url": flow2api_url}

        logger.info(f"[{profile['name']}] 开始同步 -> {flow2api_url}")
        extract_mode = self._resolve_extract_mode(profile)
        token_to_push = ""
        token_source = ""

        if extract_mode == "gemini_cookies":
            gemini_result = await self._build_gemini_token_with_timeout(profile)
            token_source = "browser"
            if not gemini_result["success"]:
                error = str(gemini_result.get("error") or "Unable to extract Gemini cookies")
                await self._update_profile_check_result(
                    profile_id,
                    last_sync_time=datetime.now().isoformat(),
                    result="failed: no gemini cookies",
                    last_sync_result=f"failed: {error}",
                    error_count=profile.get("error_count", 0) + 1,
                )
                self._total_error_count += 1
                await self._record_sync_result(profile, flow2api_url, False, message=error)
                return {"success": False, "error": error, "target_url": flow2api_url}

            token_to_push = str(gemini_result["session_token"])
            logger.info(
                f"[{profile['name']}] Gemini cookies extracted and encoded as gcu payload (client_id={gemini_result.get('client_id')})"
            )
        else:
            token: Optional[str] = None
            google_cookies = profile.get("google_cookies")
            if (config.protocol_refresh_enabled and validate_google_cookies(scoped_google_cookies(google_cookies))["success"]
                    and (not profile.get("proxy_enabled") or profile.get("proxy_url"))):
                from .protocol_login import protocol_loginer

                proxy_url = profile.get("proxy_url") if profile.get("proxy_enabled") else None
                logger.info(f"[{profile['name']}] Trying protocol refresh with Google cookies...")
                login_result = await protocol_loginer.login(
                    google_cookies,
                    proxy=proxy_url,
                    email=profile.get("email"),
                )
                if login_result.get("success"):
                    token = str(login_result["session_token"])
                    token_source = "protocol"
                    logger.info(f"[{profile['name']}] Protocol refresh succeeded")
                    refreshed = scoped_google_cookies(login_result.get("google_cookies"))
                    if validate_google_cookies(refreshed)["success"]:
                        await profile_db.update_profile(profile_id, google_cookies=json.dumps(refreshed))
                    elif "google_cookies" in login_result:
                        # A rotation/deletion made the new snapshot incomplete.
                        # Never pair the refreshed ST with the cached old jar.
                        token = None
                else:
                    logger.warning(
                        f"[{profile['name']}] Protocol refresh failed: {login_result.get('error')}; falling back to browser extraction"
                    )

            if not token:
                token = await self._extract_token_with_timeout(profile)
                token_source = "browser"
                if not token:
                    extraction_error = browser_manager.get_session_error(profile_id)
                    error = extraction_error["error"]
                    await self._update_profile_check_result(
                        profile_id,
                        last_sync_time=datetime.now().isoformat(),
                        result="failed: no token",
                        last_sync_result=f"failed: {error}",
                        error_count=profile.get("error_count", 0) + 1,
                    )
                    self._total_error_count += 1
                    await self._record_sync_result(profile, flow2api_url, False, message=error)
                    return {**extraction_error, "target_url": flow2api_url}

            logger.info(f"[{profile['name']}] Extracted session via {token_source}")
            token_to_push = token

        async def push_current_session():
            if extract_mode == "gemini_cookies":
                return await self._push_to_flow2api(token_to_push, flow2api_url, connection_token)
            # Browser extraction persists rotating cookies. Reload after extraction,
            # otherwise the stale pre-login snapshot is sent to the other server.
            fresh_profile = await profile_db.get_profile(profile_id) or {}
            options = {}
            cookies = scoped_google_cookies(fresh_profile.get("google_cookies"))
            checked = validate_google_cookies(cookies)
            if not checked["success"]:
                return checked
            options["google_cookies"] = cookies
            project_identity = browser_manager._normalize_email(
                fresh_profile.get("observed_flow_project_identity") or ""
            )
            current_identity = browser_manager._normalize_email(
                fresh_profile.get("email") or ""
            )
            stored_project = None
            if (
                fresh_profile.get("observed_flow_project_verified")
                and project_identity
                and project_identity == current_identity
            ):
                stored_project = browser_manager._normalize_flow_project_id(
                    fresh_profile.get("observed_flow_project_id")
                )
            project_id = stored_project or await browser_manager.get_flow_project_id(profile_id)
            if project_id:
                options["project_id"] = project_id
            # Source localhost and destination localhost can be different machines.
            # Only an explicit destination binding may overwrite server configuration.
            target_proxy = str(fresh_profile.get("captcha_proxy_url") or "").strip()
            if target_proxy:
                options["captcha_proxy_url"] = target_proxy
            return await self._push_to_flow2api(token_to_push, flow2api_url, connection_token, **options)

        result = await push_current_session()

        if (not result["success"] and extract_mode != "gemini_cookies" and token_source == "protocol"
                and result.get("error_code") in {"auth_required", "cookies_incomplete"}):
            logger.warning(
                f"[{profile['name']}] Protocol-derived session push failed: {result.get('error')}; retrying with browser extraction"
            )
            browser_token = await self._extract_token_with_timeout(profile)
            if browser_token:
                token_to_push = browser_token
                token_source = "browser"
                result = await push_current_session()
            else:
                result = browser_manager.get_session_error(profile_id)

        if result["success"]:
            success_result = f"success: {result.get('action', 'synced')}"
            await self._update_profile_check_result(
                profile_id,
                success_result,
                email=result.get("email", profile.get("email")),
                last_sync_time=datetime.now().isoformat(),
                last_sync_result=success_result,
                sync_count=profile.get("sync_count", 0) + 1,
            )
            self._total_sync_count += 1
            logger.info(f"[{profile['name']}] 同步成功")
            await self._record_sync_result(
                profile,
                flow2api_url,
                True,
                action=result.get("action", "synced"),
                message=result.get("message", ""),
                email=result.get("email"),
            )
        else:
            error_result = f"failed: {result.get('error', 'unknown')}"
            await self._update_profile_check_result(
                profile_id,
                error_result,
                last_sync_time=datetime.now().isoformat(),
                last_sync_result=error_result,
                error_count=profile.get("error_count", 0) + 1,
            )
            self._total_error_count += 1
            logger.error(f"[{profile['name']}] 同步失败: {result.get('error')}")
            await self._record_sync_result(
                profile,
                flow2api_url,
                False,
                message=result.get("error", "unknown"),
            )

        return {**result, "target_url": flow2api_url}

    async def sync_all_profiles(self, *, source: str = "manual") -> Dict[str, Any]:
        """同步所有活跃 Profile（智能模式：按目标地址分组刷新）。"""
        if source == "scheduled" and (self.is_syncing() or execution_gate.is_busy()):
            current = execution_gate.get_status().get("current") or {}
            reason = "another sync is still running" if self.is_syncing() else (
                f"execution gate is busy with {current.get('action') or 'another operation'}"
            )
            logger.warning(f"Scheduled sync skipped before enqueue: {reason}")
            result = {
                "success": True,
                "total": 0,
                "synced": 0,
                "success_count": 0,
                "error_count": 0,
                "skipped": 0,
                "results": [],
                "skipped_reason": reason,
            }
            await dashboard_events.publish("sync_batch", result)
            return result
        async with self._sync_lock:
            async with execution_gate.hold("sync_all", source=source):
                logger.info("=" * 40)
                logger.info("开始智能同步...")

                self._last_batch_time = datetime.now()
                profiles = await profile_db.get_active_profiles()
                from .login_slots import login_slots
                profiles = [
                    profile for profile in profiles
                    if not login_slots.owns(profile["id"])
                    and not (profile.get("login_slot_claimed") and not profile.get("sync_count"))
                ]

                if not profiles:
                    result = {"success": True, "total": 0, "synced": 0, "skipped": 0, "results": []}
                    await dashboard_events.publish("sync_batch", result)
                    return result

                grouped_profiles: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
                invalid_profiles: List[Dict[str, Any]] = []

                for profile in profiles:
                    flow2api_url, connection_token = self._resolve_target(profile)
                    if not flow2api_url or not connection_token:
                        invalid_profiles.append(profile)
                        continue
                    grouped_profiles[(flow2api_url, connection_token)].append(profile)

                results: List[Dict[str, Any]] = []
                success_count = 0
                error_count = 0
                skipped_count = 0
                now = datetime.now()

                for profile in invalid_profiles:
                    flow2api_url, _ = self._resolve_target(profile)
                    error = "未配置完整的 Flow2API 地址或连接 Token"
                    await self._update_profile_check_result(
                        profile["id"],
                        f"failed: {error}",
                        last_sync_time=datetime.now().isoformat(),
                        last_sync_result=f"failed: {error}",
                        error_count=profile.get("error_count", 0) + 1,
                    )
                    self._total_error_count += 1
                    await self._record_sync_result(profile, flow2api_url, False, message=error)
                    results.append(
                        {
                            "profile_id": profile["id"],
                            "profile_name": profile["name"],
                            "success": False,
                            "error": error,
                            "target_url": flow2api_url,
                        }
                    )
                    error_count += 1

                for (flow2api_url, connection_token), target_profiles in grouped_profiles.items():
                    profile_emails = [profile["email"] for profile in target_profiles if profile.get("email")]
                    check_result = await self._check_tokens_status(
                        flow2api_url,
                        connection_token,
                        profile_emails or None,
                    )

                    if not check_result["success"]:
                        # A failed destination check is not evidence that every
                        # Google session expired. Avoid a full-account login storm.
                        for profile in target_profiles:
                            message = check_result.get("error") or "目标状态暂无法确认"
                            await self._update_profile_check_result(profile["id"], f"failed: {message}")
                            await self._record_sync_result(profile, flow2api_url, False, message=message)
                            results.append({"profile_id": profile["id"], "profile_name": profile["name"],
                                            **check_result, "target_url": flow2api_url})
                            error_count += 1
                            self._total_error_count += 1
                        continue

                    token_lookup = {
                        self._normalize_email(token.get("email")): token
                        for token in check_result.get("tokens", [])
                        if self._normalize_email(token.get("email"))
                    }

                    for profile in target_profiles:
                        should_sync, reason = self._should_sync_profile(profile, token_lookup, now=now)
                        if should_sync:
                            logger.info(f"[{profile['name']}] 满足同步条件: {reason}")
                            result = await self._sync_profile(profile["id"])
                            results.append(
                                {
                                    "profile_id": profile["id"],
                                    "profile_name": profile["name"],
                                    **result,
                                }
                            )
                            if result["success"]:
                                success_count += 1
                            else:
                                error_count += 1
                        else:
                            skipped_count += 1
                            logger.info(f"[{profile['name']}] {reason}，跳过")
                            await self._update_profile_check_result(
                                profile["id"],
                                f"skipped: {reason}",
                                checked_at=now.isoformat(),
                            )
                            await self._record_sync_result(
                                profile,
                                flow2api_url,
                                action="skipped",
                                message=reason,
                                status="skipped",
                            )

                logger.info(
                    f"智能同步完成: 成功 {success_count}, 失败 {error_count}, 跳过 {skipped_count}"
                )

                result = {
                    "success": True,
                    "total": len(profiles),
                    "synced": success_count + error_count,
                    "success_count": success_count,
                    "error_count": error_count,
                    "skipped": skipped_count,
                    "results": results,
                }
                await dashboard_events.publish("sync_batch", result)
                return result

    async def _sync_profiles_force(self, profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """强制同步指定 Profile 列表。"""
        results = []
        success_count = 0
        error_count = 0

        for profile in profiles:
            result = await self._sync_profile(profile["id"])
            results.append(
                {
                    "profile_id": profile["id"],
                    "profile_name": profile["name"],
                    **result,
                }
            )
            if result["success"]:
                success_count += 1
            else:
                error_count += 1

        return {
            "results": results,
            "success_count": success_count,
            "error_count": error_count,
        }

    async def _sync_all_profiles_force(self) -> Dict[str, Any]:
        """强制同步所有 Profile（不检查过期状态）。"""
        profiles = await profile_db.get_active_profiles()
        from .login_slots import login_slots
        profiles = [
            profile for profile in profiles
            if not login_slots.owns(profile["id"])
            and not (profile.get("login_slot_claimed") and not profile.get("sync_count"))
        ]
        group_result = await self._sync_profiles_force(profiles)

        logger.info(
            f"强制同步完成: 成功 {group_result['success_count']}, 失败 {group_result['error_count']}"
        )

        return {
            "success": True,
            "total": len(profiles),
            "success_count": group_result["success_count"],
            "error_count": group_result["error_count"],
            "results": group_result["results"],
        }

    async def _push_to_flow2api(
        self,
        session_token: str,
        flow2api_url: str,
        connection_token: str,
        *,
        google_cookies: Optional[List[Dict[str, Any]]] = None,
        captcha_proxy_url: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """推送到指定 Flow2API。"""
        if not connection_token:
            return {"success": False, "error": "未配置 CONNECTION_TOKEN"}
        if not flow2api_url:
            return {"success": False, "error": "未配置 Flow2API 地址"}

        url = f"{flow2api_url}/api/plugin/update-token"
        payload = {"session_token": session_token}
        if google_cookies is not None:
            google_cookies = scoped_google_cookies(google_cookies)
            checked = validate_google_cookies(google_cookies)
            if not checked["success"]:
                return checked
            payload["google_cookies"] = google_cookies
        if captcha_proxy_url:
            payload["captcha_proxy_url"] = captcha_proxy_url
        normalized_project_id = self._normalize_project_id(project_id)
        if project_id and not normalized_project_id:
            return failure("project_context_invalid", "源浏览器 Flow 项目标识无效；未向目标发送")
        if normalized_project_id:
            payload["project_id"] = normalized_project_id

        try:
            # Server verifies OAuth on the account proxy before acknowledging the write.
            async with httpx.AsyncClient(timeout=90) as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {connection_token}",
                    },
                )

                if response.status_code != 200:
                    return destination_error(response, endpoint="update-token")

                data = response.json()
                if not isinstance(data, dict) or data.get("success") is not True:
                    return {"success": False, "error": "Flow2API did not acknowledge the session update"}
                if google_cookies is not None and (data.get("cookies_updated") is not True or data.get("flow_cookies_configured") is not True or data.get("google_session_cookies_configured") is not True):
                    return {"success": False, "error": "Flow cookie synchronization was not confirmed; upgrade Flow2API and refresh the source profile"}
                if google_cookies is not None and data.get("proxy_configured") is not True:
                    return {"success": False, "error": "目标账号未绑定代理，请配置目标 Flow2API 可访问的同出口代理地址"}
                if captcha_proxy_url and (data.get("proxy_updated") is not True or data.get("proxy_configured") is not True):
                    return {"success": False, "error": "Flow2API did not acknowledge the destination proxy binding"}
                if normalized_project_id and data.get("project_context_accepted") is not True:
                    return failure("project_context_unconfirmed", "目标未确认复用源浏览器 Flow 项目；请升级目标服务")
                if google_cookies is not None:
                    if data.get("oauth_verified") is not True:
                        return failure("oauth_unconfirmed", "目标未确认 Labs 实际鉴权，请先升级 Flow2API；不能将已接收视为已恢复")
                    if data.get("native_session_verified") is False:
                        return {**failure("native_session_unverified", "会话已保存且 OAuth 有效，但目标 Flow 项目登录预检失败；不要以生成任务反复验证登录态"),
                                "synced": True, "oauth_verified": True, "native_session_verified": False}
                    pending_enable = (
                        data.get("pending_enable") is True
                        and data.get("account_active") is False
                        and data.get("action") == "added_pending_enable"
                    )
                    if data.get("account_active") is False and not pending_enable:
                        return {**failure("account_disabled", "会话已保存并通过鉴权，但目标账号仍禁用；请检查目标手动禁用状态或自动启用设置"),
                                "synced": True, "account_active": data.get("account_active"), "oauth_verified": True}
                    if data.get("account_active") is not True and not pending_enable:
                        return failure("activation_unconfirmed", "目标未确认账号启用状态，请升级目标服务并检查账号状态")
                message = data.get("message", "")
                email = None
                if " for " in message:
                    email = message.split(" for ")[-1]

                return {
                    "success": True,
                    "action": data.get("action"),
                    "message": message,
                    "email": email,
                    **({
                        "oauth_verified": True,
                        "account_active": data.get("account_active"),
                        "pending_enable": data.get("pending_enable") is True,
                        "project_context_accepted": data.get("project_context_accepted") is True,
                        "project_reused": data.get("project_reused") is True,
                    } if google_cookies is not None else {}),
                }
        except Exception:
            return failure("destination_unavailable", "同步响应未确认，请检查目标账号状态后再重试；未清除源 Cookie")

    def get_status(self) -> Dict[str, Any]:
        return {
            "total_sync_count": self._total_sync_count,
            "total_error_count": self._total_error_count,
            "last_batch_time": self._last_batch_time.isoformat() if self._last_batch_time else None,
            "flow2api_url": config.flow2api_url,
            "has_connection_token": bool(config.connection_token),
            "refresh_interval_minutes": config.refresh_interval,
        }


token_syncer = TokenSyncer()
