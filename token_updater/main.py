"""Token Updater entrypoint v3.3 (lightweight)."""

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .api import app
from .browser import browser_manager
from .config import config
from .database import profile_db
from .execution import execution_gate
from .logger import logger
from .updater import token_syncer


scheduler = AsyncIOScheduler()
SYNC_JOB_ID = "token_sync"


async def scheduled_sync():
    """定时同步任务"""
    logger.info("=== 定时同步任务触发 ===")

    if token_syncer.is_syncing():
        logger.warning("Scheduled sync skipped: previous sync batch is still running")
        return

    if execution_gate.is_busy():
        current = execution_gate.get_status().get("current") or {}
        logger.warning(
            f"Scheduled sync skipped: execution gate busy with {current.get('action') or 'another operation'}"
        )
        return

    profiles = await profile_db.get_active_profiles()
    if not profiles:
        logger.warning("没有启用中的 Profile，跳过本次同步")
        return

    await token_syncer.sync_all_profiles(source="scheduled")


async def startup():
    """启动时初始化"""
    logger.info("=" * 60)
    logger.info("Flow2API Token Updater v3.2 - 轻量版")
    logger.info("Cookie 导入模式")
    logger.info("=" * 60)

    await profile_db.init()
    logger.info("数据库初始化完成")

    scheduler.add_job(
        scheduled_sync,
        trigger=IntervalTrigger(minutes=config.refresh_interval),
        id=SYNC_JOB_ID,
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()

    app.state.scheduler = scheduler
    app.state.sync_job_id = SYNC_JOB_ID

    logger.info(f"定时任务已启动: 每 {config.refresh_interval} 分钟执行一次")
    logger.info(f"Flow2API URL: {config.flow2api_url}")
    logger.info(f"API 端口: {config.api_port}")
    logger.info("")
    logger.info("管理界面: http://localhost:8002")
    logger.info("")


async def shutdown():
    """关闭时清理"""
    logger.info("正在关闭...")
    if scheduler.running:
        scheduler.shutdown()
    await browser_manager.stop()


@app.on_event("startup")
async def on_startup():
    await startup()


@app.on_event("shutdown")
async def on_shutdown():
    await shutdown()


def main():
    """主函数"""
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config.api_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
