"""Token Updater 配置 v3.1"""
import json
import os
from pydantic import BaseModel


PERSIST_KEYS = ("flow2api_url", "connection_token", "refresh_interval")


def _get_env(name: str) -> str | None:
    value = os.getenv(name)
    return value if value else None


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_persisted(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_persisted(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


class Config(BaseModel):
    admin_password: str
    api_key: str
    flow2api_url: str
    connection_token: str
    refresh_interval: int
    enable_vnc: bool
    profiles_dir: str = "/app/profiles"
    labs_url: str = "https://labs.google/fx/tools/flow"
    flow_url: str = "https://flow.google.com/"
    protocol_refresh_enabled: bool = False
    login_url: str = "https://labs.google/fx/api/auth/signin/google"
    session_cookie_name: str = "__Secure-next-auth.session-token"
    token_extract_mode: str = "session"
    api_port: int
    db_path: str = "/app/data/profiles.db"
    session_ttl_minutes: int
    config_file: str

    def save(self) -> None:
        data = {key: getattr(self, key) for key in PERSIST_KEYS}
        _save_persisted(self.config_file, data)


def _build_config() -> Config:
    config_file = _get_env("CONFIG_FILE") or "/app/data/config.json"
    persisted = _load_persisted(config_file)

    flow2api_url = _get_env("FLOW2API_URL") or persisted.get("flow2api_url") or "http://host.docker.internal:4020"
    connection_token = _get_env("CONNECTION_TOKEN") or persisted.get("connection_token", "")
    refresh_interval = _parse_int(_get_env("REFRESH_INTERVAL") or str(persisted.get("refresh_interval", 60)), 60)
    enable_vnc = _parse_bool(_get_env("ENABLE_VNC"), default=True)

    return Config(
        admin_password=_get_env("ADMIN_PASSWORD") or "",
        api_key=_get_env("API_KEY") or "",
        flow2api_url=flow2api_url,
        connection_token=connection_token,
        refresh_interval=refresh_interval,
        enable_vnc=enable_vnc,
        profiles_dir=_get_env("PROFILES_DIR") or "/app/profiles",
        db_path=_get_env("DB_PATH") or "/app/data/profiles.db",
        token_extract_mode="session",
        protocol_refresh_enabled=_parse_bool(_get_env("FLOW_PROTOCOL_REFRESH_ENABLED"), default=False),
        api_port=_parse_int(_get_env("API_PORT"), 8002),
        session_ttl_minutes=_parse_int(_get_env("SESSION_TTL_MINUTES"), 1440),
        config_file=config_file,
    )


config = _build_config()
