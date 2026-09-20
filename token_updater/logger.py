"""日志模块"""
import logging
import sys
import os
from logging.handlers import RotatingFileHandler

# 确保日志目录存在
log_dir = os.getenv("LOG_DIR", "/app/logs")
os.makedirs(log_dir, exist_ok=True)

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log_max_bytes = int(os.getenv("LOG_MAX_BYTES", "5242880"))
log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "3"))

# 配置日志
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("token_updater")

# 添加文件 handler
try:
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "token_updater.log"),
        maxBytes=log_max_bytes,
        backupCount=log_backup_count
    )
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)
except Exception:
    pass  # 忽略文件日志错误
