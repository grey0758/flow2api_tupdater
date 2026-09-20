"""Classify destination failures without storing response bodies/secrets in logs."""
from .session_validation import failure


def destination_error(response, *, endpoint: str = "") -> dict:
    status = response.status_code
    # Endpoint is a call-site constant, never an arbitrary server URL or response body.
    route = f"/api/plugin/{endpoint}" if endpoint in {"check-tokens", "update-token"} else "插件接口"
    try:
        data = response.json()
        detail = str(data.get("detail") or data.get("error") or "").lower() if isinstance(data, dict) else ""
    except (ValueError, TypeError):
        detail = ""
    if status in (401, 403):
        result = failure("destination_auth", "目标拒绝同步连接，请检查 CONNECTION_TOKEN 和插件接口是否启用；无需重新登录源账号")
    elif status in (404, 405):
        result = failure("destination_endpoint", f"目标接口 {route} 不存在或不支持 POST，请核对服务基础地址（不要填写完整插件接口路径）并升级目标服务；无需重新登录源账号")
    elif 300 <= status < 400:
        result = failure("destination_redirect", f"目标接口 {route} 返回跳转，请配置最终服务基础地址；未跟随跳转或转发连接 Token")
    elif status == 409:
        result = failure("independent_login", "目标账号采用服务器独立登录，不能由同步器覆盖；请在目标 Native Profile 更新会话")
    elif status == 400 and "captcha_proxy_url" in detail:
        result = failure("destination_proxy", "请配置目标 Flow2API 可访问、与源 Profile 同出口的 captcha_proxy_url；首次同步或 ST 变化时必须提供")
    elif status == 400 and "proxy" in detail:
        result = failure("verification_unavailable", "目标无法确认会话或账号代理，请先检查两端代理出口和 Labs 授权；未触发重复登录")
    elif status == 400 and any(word in detail for word in ("expired labs", "invalid session token", "labs access token", "missing labs", "renew labs")):
        result = failure("auth_required", "目标拒绝过期或失效的 Labs 授权，请在源 Profile 重新授权后同步")
    elif status == 400 and any(word in detail for word in ("cookie", "google session")):
        result = failure("cookies_incomplete", "目标拒绝不完整的 Google/Flow Cookie，请在源 Profile 完成登录后重新同步")
    elif status == 429 or status >= 500:
        result = failure("destination_unavailable", "目标服务或账号校验暂不可用，请稍后重试；源 Cookie 保留，不重复登录")
    else:
        result = failure("destination_rejected", "目标拒绝同步请求，请核对接口地址、配置及服务端版本")
    return {**result, "error": f"{result['error']}（HTTP {status}）", "status_code": status}
