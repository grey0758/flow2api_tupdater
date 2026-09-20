"""Profile 数据库管理"""
import aiosqlite
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from .config import config


class ProfileDB:
    """Profile 数据库"""
    
    def __init__(self):
        self.db_path = config.db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    async def init(self):
        """初始化数据库"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    email TEXT,
                    is_logged_in INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    last_token TEXT,
                    last_token_time TEXT,
                    last_check_time TEXT,
                    last_check_result TEXT,
                    last_sync_time TEXT,
                    last_sync_result TEXT,
                    sync_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    remark TEXT,
                    login_account TEXT,
                    login_password TEXT,
                    proxy_url TEXT,
                    proxy_enabled INTEGER DEFAULT 0,
                    flow2api_url TEXT,
                    connection_token_override TEXT
                )
            """)
            
            # 检查并添加新列
            cursor = await db.execute("PRAGMA table_info(profiles)")
            columns = [row[1] for row in await cursor.fetchall()]
            
            if 'proxy_url' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN proxy_url TEXT")
            if 'login_account' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN login_account TEXT")
            if 'login_password' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN login_password TEXT")
            if 'proxy_enabled' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN proxy_enabled INTEGER DEFAULT 0")
            if 'flow2api_url' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN flow2api_url TEXT")
            if 'connection_token_override' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN connection_token_override TEXT")
            if 'google_cookies' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN google_cookies TEXT")
            if 'captcha_proxy_url' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN captcha_proxy_url TEXT")
            if 'last_check_time' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN last_check_time TEXT")
            if 'last_check_result' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN last_check_result TEXT")
            if 'login_method' not in columns:
                await db.execute("ALTER TABLE profiles ADD COLUMN login_method TEXT")

            await db.execute("""
                CREATE TABLE IF NOT EXISTS sync_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id INTEGER NOT NULL,
                    profile_name TEXT NOT NULL,
                    email TEXT,
                    target_url TEXT,
                    status TEXT NOT NULL,
                    action TEXT,
                    message TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_sync_history_created_at ON sync_history(created_at)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_sync_history_profile_id ON sync_history(profile_id)"
            )
            
            await db.commit()
    
    async def add_profile(
        self,
        name: str,
        remark: str = "",
        login_account: str = "",
        login_password: str = "",
        proxy_url: str = "",
        flow2api_url: str = "",
        connection_token_override: str = "",
        captcha_proxy_url: str = "",
    ) -> int:
        """添加 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO profiles (
                    name,
                    remark,
                    login_account,
                    login_password,
                    proxy_url,
                    proxy_enabled,
                    flow2api_url,
                    connection_token_override,
                    created_at, captcha_proxy_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    remark,
                    login_account,
                    login_password,
                    proxy_url,
                    1 if proxy_url else 0,
                    flow2api_url,
                    connection_token_override,
                    datetime.now().isoformat(),
                    captcha_proxy_url,
                )
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_all_profiles(self) -> List[Dict[str, Any]]:
        """获取所有 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles ORDER BY id")
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_profile(self, profile_id: int) -> Optional[Dict[str, Any]]:
        """获取单个 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_profile_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """通过名称获取 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM profiles WHERE name = ?", (name,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def update_profile(self, profile_id: int, **kwargs):
        """更新 profile"""
        if not kwargs:
            return
        
        fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [profile_id]
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"UPDATE profiles SET {fields} WHERE id = ?", values)
            await db.commit()
    
    async def delete_profile(self, profile_id: int):
        """删除 profile"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
            await db.execute("DELETE FROM sync_history WHERE profile_id = ?", (profile_id,))
            await db.commit()
    
    async def get_active_profiles(self) -> List[Dict[str, Any]]:
        """获取所有启用的 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM profiles WHERE is_active = 1 ORDER BY id"
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_logged_in_profiles(self) -> List[Dict[str, Any]]:
        """获取所有已登录的 profiles"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM profiles WHERE is_logged_in = 1 AND is_active = 1 ORDER BY id"
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def record_sync_event(
        self,
        profile_id: int,
        profile_name: str,
        email: Optional[str],
        target_url: str,
        status: str,
        action: str = "",
        message: str = "",
    ) -> None:
        """记录同步历史，用于仪表盘图表与近期动态。"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO sync_history (
                    profile_id,
                    profile_name,
                    email,
                    target_url,
                    status,
                    action,
                    message,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_id,
                    profile_name,
                    email,
                    target_url,
                    status,
                    action,
                    message,
                    datetime.now().isoformat(),
                ),
            )
            await db.commit()

    async def get_recent_sync_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取近期同步事件。"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM sync_history ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_sync_events_since(self, hours: int = 24) -> List[Dict[str, Any]]:
        """获取一段时间内的同步事件。"""
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM sync_history WHERE created_at >= ? ORDER BY created_at ASC",
                (since,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


# 全局实例
profile_db = ProfileDB()
