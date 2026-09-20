"""单浏览器执行闸门。"""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Optional


_ACTION_LABELS = {
    "auto_login": "自动登录",
    "launch_browser": "启动浏览器登录",
    "close_browser": "关闭浏览器",
    "check_login": "检测登录状态",
    "import_cookies": "导入会话数据",
    "export_cookies": "导出 Cookie",
    "extract_token": "提取会话令牌",
    "sync_profile": "同步账号",
    "sync_all": "同步全部账号",
    "delete_profile": "删除账号",
}


class ExecutionGate:
    """统一串行化需要独占浏览器的操作。"""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._current: Optional[Dict[str, Any]] = None

    @asynccontextmanager
    async def hold(
        self,
        action: str,
        *,
        profile_id: Optional[int] = None,
        profile_name: str = "",
        source: str = "manual",
    ) -> AsyncIterator[Dict[str, Any]]:
        await self._lock.acquire()
        self._current = {
            "action": action,
            "label": _ACTION_LABELS.get(action, action),
            "profile_id": profile_id,
            "profile_name": profile_name or "",
            "source": source,
            "started_at": datetime.now().isoformat(),
        }
        try:
            yield self._current
        finally:
            self._current = None
            self._lock.release()

    def get_status(self) -> Dict[str, Any]:
        current = dict(self._current) if self._current else None
        return {
            "busy": current is not None,
            "current": current,
        }

    def is_busy(self) -> bool:
        return self._lock.locked()


execution_gate = ExecutionGate()
