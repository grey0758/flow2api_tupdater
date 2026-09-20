"""curl_cffi 指纹请求协议登录 labs.google — 走 NextAuth + Google OAuth 流程"""
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urljoin

from curl_cffi.requests import AsyncSession

from .config import config
from .logger import logger
from .proxy_utils import parse_proxy
from .session_validation import (
    LABS_SESSION_URL, CREDITS_URL, failure, scoped_google_cookies,
    validate_labs_session, validate_credits,
)

# Google OAuth 所需的 cookie 名称
_GOOGLE_COOKIE_NAMES = ("SID", "__Secure-1PSID", "__Secure-3PSID")


def _parse_google_cookies(raw: str) -> Dict[str, str]:
    """解析 Google cookies 输入，支持 JSON 和纯文本格式"""
    text = (raw or "").strip()
    if not text:
        return {}

    # 尝试 JSON
    try:
        data = json.loads(text)
        if isinstance(data, list):
            result = {}
            for item in data:
                if isinstance(item, dict) and item.get("domain", ".google.com").lstrip(".") in {"google.com", "accounts.google.com"}:
                    name = item.get("name", "")
                    value = item.get("value", "")
                    if name and value:
                        result[name] = value
            return result
        if isinstance(data, dict):
            cookies_list = data.get("cookies")
            if isinstance(cookies_list, list):
                result = {}
                for item in cookies_list:
                    if isinstance(item, dict) and item.get("domain", ".google.com").lstrip(".") in {"google.com", "accounts.google.com"}:
                        name = item.get("name", "")
                        value = item.get("value", "")
                        if name and value:
                            result[name] = value
                return result
            return {k: v for k, v in data.items() if isinstance(v, str) and v}
    except (json.JSONDecodeError, ValueError):
        pass

    # 纯文本格式：name=value; name2=value2
    result = {}
    for part in text.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            name = name.strip()
            value = value.strip()
            if name and value:
                result[name] = value
    return result


def _build_cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def _get_set_cookies(headers) -> List[str]:
    """安全获取所有 Set-Cookie 头值"""
    # curl_cffi Headers 支持 getlist()
    if hasattr(headers, "getlist"):
        return headers.getlist("set-cookie") or []
    if hasattr(headers, "get_list"):
        return headers.get_list("set-cookie") or []
    val = headers.get("set-cookie")
    return [val] if val else []


def _merge_cookies(cookies: Dict[str, str], headers) -> None:
    """从响应 Set-Cookie 头合并 cookies"""
    for val in _get_set_cookies(headers):
        parts = val.split(";")[0]
        if "=" in parts:
            name, _, value = parts.partition("=")
            cookies[name.strip()] = value.strip()


def _extract_session_token(headers) -> Optional[str]:
    """从 Set-Cookie 提取 session token"""
    cookie_name = config.session_cookie_name
    values = {}
    _merge_cookies(values, headers)
    return _session_token_from_values(values, cookie_name)


def _session_token_from_values(values, cookie_name=None) -> Optional[str]:
    cookie_name = cookie_name or config.session_cookie_name
    if values.get(cookie_name):
        return values[cookie_name]
    prefix = cookie_name + "."
    chunks = sorted((name for name in values if name.startswith(prefix) and name[len(prefix):].isdigit()),
                    key=lambda name: int(name[len(prefix):]))
    if chunks and all(name == prefix + str(i) and values[name] for i, name in enumerate(chunks)):
        return "".join(values[name] for name in chunks)
    return None


def _session_from_jar(session) -> Optional[str]:
    return _session_token_from_values({c.name: c.value for c in session.cookies.jar
                                      if c.domain.lstrip(".") == "labs.google" and not c.is_expired()})


def _extract_redirect_from_html(text: str) -> Optional[str]:
    """从 HTML 响应中提取跳转 URL（meta refresh / JS location / form action）"""
    # <meta http-equiv="refresh" content="0;url=...">
    m = re.search(r'content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'>\s]+)', text, re.IGNORECASE)
    if m:
        return m.group(1)
    # window.location = "..." / location.href = "..." / location.replace("...")
    m = re.search(r'location\.(?:href|replace)\s*\(\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'location\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
    if m:
        return m.group(1)
    # <form action="..."> 自动提交
    m = re.search(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
    if m:
        return m.group(1)
    # accounts.google.com 页面中的 URL 参数
    m = re.search(r'(https://labs\.google/fx/api/auth/callback/google[^"\'<>\s]*)', text)
    if m:
        return m.group(1)
    # continue 参数
    m = re.search(r'[&?]continue=([^"\'<>\s&]+)', text)
    if m:
        from urllib.parse import unquote
        return unquote(m.group(1))
    return None


class ProtocolLogin:
    """curl_cffi 指纹请求协议登录 labs.google"""

    LABS_BASE = "https://labs.google/fx"
    IMPERSONATE = "chrome124"

    def _get_proxy_url(self, proxy_str: Optional[str]) -> Optional[str]:
        if not proxy_str:
            return None
        proxy_config = parse_proxy(proxy_str)
        if not proxy_config:
            return None
        server = proxy_config.get("server", "")
        username = proxy_config.get("username", "")
        password = proxy_config.get("password", "")
        if not server:
            return None
        if username and password:
            # 注入认证信息到 URL
            scheme, _, rest = server.partition("://")
            return f"{scheme}://{username}:{password}@{rest}"
        return server

    async def login(
        self,
        google_cookies_raw: str,
        proxy: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        协议登录。

        输入：Google cookies（JSON 或纯文本，需要 SID/HSID/SSID/APISID/SAPISID）
        输出：{"success": bool, "session_token": str, "error": str}
        """
        google_cookies = _parse_google_cookies(google_cookies_raw)
        try:
            parsed_cookies = json.loads(google_cookies_raw)
        except (ValueError, TypeError):
            parsed_cookies = None
        structured = isinstance(parsed_cookies, list) or (isinstance(parsed_cookies, dict) and isinstance(parsed_cookies.get("cookies"), list))
        seed = scoped_google_cookies(google_cookies_raw)
        if structured and not any(c["domain"] == ".google.com" and c["name"] in _GOOGLE_COOKIE_NAMES for c in seed):
            return failure("auth_required", "结构化 Cookie 中缺少有效 Google 主域登录态，请重新导出完整 Cookie")
        has_required = any(name in google_cookies for name in _GOOGLE_COOKIE_NAMES)
        if not has_required:
            return failure("auth_required", "未找到有效的 Google 登录 Cookie（需要 SID 或 Secure PSID）")

        proxy_url = self._get_proxy_url(proxy)
        if proxy and not proxy_url:
            return failure("source_proxy", "源代理地址无效，已停止协议请求以避免走默认出口")
        session_kwargs = {"impersonate": self.IMPERSONATE, "timeout": 30, "trust_env": False}
        if proxy_url:
            session_kwargs["proxy"] = proxy_url

        async with AsyncSession(**session_kwargs) as s:
            try:
                # Let the scoped jar apply Set-Cookie rotations/deletions. Never
                # flatten Flow OSID or account-host cookies into a root Cookie header.
                if not seed:
                    seed = [{"name": name, "value": value, "domain": ".google.com", "path": "/"}
                            for name, value in google_cookies.items()]
                for cookie in seed:
                    s.cookies.set(cookie["name"], cookie["value"], domain=cookie["domain"],
                                  path=cookie.get("path", "/"), secure=bool(cookie.get("secure", True)))
                for cookie in s.cookies.jar:
                    original = next((c for c in seed if (c["name"], c["domain"], c.get("path", "/")) ==
                                     (cookie.name, cookie.domain, cookie.path)), {})
                    expires = original.get("expires", original.get("expirationDate", original.get("expiry")))
                    if expires is not None and float(expires) > 0:
                        cookie.expires = int(float(expires))
                    if original.get("httpOnly"):
                        cookie.set_nonstandard_attr("HttpOnly", None)
                    if original.get("sameSite"):
                        cookie.set_nonstandard_attr("SameSite", original["sameSite"])
                # 步骤1：获取 CSRF token
                logger.info("[协议登录] 获取 CSRF token...")
                resp = await s.get(f"{self.LABS_BASE}/api/auth/csrf", allow_redirects=False)
                if resp.status_code != 200:
                    return {"success": False, "error": f"CSRF 失败: HTTP {resp.status_code}"}

                csrf_token = resp.json().get("csrfToken")
                if not csrf_token:
                    return {"success": False, "error": "CSRF 响应中无 csrfToken"}

                # 步骤2：POST signin/google → 获取 OAuth 重定向 URL
                logger.info("[协议登录] 请求 Google OAuth URL...")
                resp = await s.post(
                    f"{self.LABS_BASE}/api/auth/signin/google",
                    data={
                        "csrfToken": csrf_token,
                        "callbackUrl": "https://labs.google/fx",
                        "json": "true",
                    },
                    headers={
                        "Referer": self.LABS_BASE,
                        "Origin": "https://labs.google",
                    },
                    allow_redirects=False,
                )
                if resp.status_code != 200:
                    return {"success": False, "error": f"Signin 失败: HTTP {resp.status_code}"}

                signin_data = resp.json()
                redirect_url = signin_data.get("redirect") or signin_data.get("url")
                if not redirect_url:
                    return failure("auth_required", "Labs 登录未返回授权地址，请在源浏览器重新授权")

                # 添加 login_hint 跳过账号选择器
                if email:
                    from urllib.parse import urlencode, urlparse, parse_qs
                    parsed = urlparse(redirect_url)
                    qs = parse_qs(parsed.query)
                    qs["login_hint"] = [email]
                    new_query = urlencode({k: v[0] for k, v in qs.items()}, doseq=True)
                    redirect_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    logger.info(f"[协议登录] 添加 login_hint={email}")

                from urllib.parse import urljoin

                # 步骤3：用 Google cookies 跟随 OAuth 重定向链
                logger.info("[协议登录] 跟随 Google OAuth 重定向...")
                callback_url = None
                current_url = redirect_url

                for i in range(10):
                    if urlsplit(current_url).scheme != "https" or urlsplit(current_url).hostname != "accounts.google.com":
                        return {"success": False, "error": "Unexpected Google OAuth redirect host"}
                    resp = await s.get(
                        current_url,
                        headers={
                            "Referer": "https://labs.google/" if i == 0 else "https://accounts.google.com/",
                        },
                        allow_redirects=False,
                    )
                    location = resp.headers.get("location")

                    # 检查是否有 callback URL
                    check_url = urljoin(current_url, location) if location else ""
                    if urlsplit(check_url).hostname == "labs.google" and urlsplit(check_url).path == "/fx/api/auth/callback/google":
                        callback_url = check_url
                        break

                    if location:
                        logger.info(f"[协议登录] 重定向到: {urlsplit(check_url).hostname}")
                        current_url = check_url
                        continue

                    # 没有 Location 头，尝试从 HTML 提取跳转
                    if resp.status_code == 200:
                        body = resp.text or ""

                        # 检查是否被拒绝
                        if "/v3/signin/rejected" in body or "signin/rejected" in body:
                            return {"success": False, "error": "Google 拒绝登录，Cookies 可能已过期或被风控，请重新导出"}

                        html_redirect = _extract_redirect_from_html(body)
                        if html_redirect:
                            # 相对路径补全为绝对 URL
                            if html_redirect.startswith("/"):
                                html_redirect = urljoin(current_url, html_redirect)
                            logger.info(f"[协议登录] 从 HTML 提取到跳转: {urlsplit(html_redirect).hostname}")
                            if urlsplit(html_redirect).hostname == "labs.google" and urlsplit(html_redirect).path == "/fx/api/auth/callback/google":
                                callback_url = html_redirect
                                break
                            current_url = html_redirect
                            continue

                    return {"success": False, "error": f"Google OAuth 未返回重定向（HTTP {resp.status_code}）"}

                if not callback_url:
                    return {"success": False, "error": "Google OAuth 流程中未获得 callback URL"}

                # 步骤4：访问 callback 换取 session cookie
                logger.info("[协议登录] 交换 auth code 换取 session...")
                if urlsplit(callback_url).scheme != "https" or urlsplit(callback_url).hostname != "labs.google":
                    return {"success": False, "error": "Unexpected OAuth callback host"}
                resp = await s.get(
                    callback_url,
                    headers={
                        "Referer": "https://accounts.google.com/",
                    },
                    allow_redirects=False,
                )

                session_token = _session_from_jar(s)

                # callback 可能多次重定向，跟随直到拿到 session token
                for _ in range(5):
                    if session_token:
                        break
                    location = resp.headers.get("location")
                    if not location or resp.status_code not in (301, 302, 303, 307, 308):
                        break
                    location = urljoin(callback_url, location)
                    if urlsplit(location).scheme != "https" or urlsplit(location).hostname != "labs.google":
                        break
                    resp = await s.get(
                        location,
                        allow_redirects=False,
                    )
                    callback_url = location
                    session_token = _session_from_jar(s)

                if not session_token:
                    return {"success": False, "error": "未获取到 session token，Google session 可能已过期"}

                resp = await s.get(LABS_SESSION_URL, allow_redirects=False)
                if resp.status_code != 200:
                    return failure("verification_unavailable", "Labs 会话校验暂不可用，请检查源代理或通过浏览器授权")
                validated = validate_labs_session(resp.json(), email or "")
                if not validated["success"]:
                    return validated
                resp = await s.get(CREDITS_URL, headers={"Authorization": "Bearer " + validated["access_token"]}, allow_redirects=False)
                checked = validate_credits(resp.status_code, resp.json() if resp.status_code == 200 else None)
                if not checked["success"]:
                    return checked
                session_token = _session_from_jar(s)
                if not session_token:
                    return failure("auth_required", "Labs 会话校验后 Cookie 缺失，请通过源浏览器重新授权")
                refreshed = scoped_google_cookies([
                    {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
                     "secure": c.secure, "httpOnly": c.has_nonstandard_attr("HttpOnly"),
                     **({"sameSite": c.get_nonstandard_attr("SameSite")} if c.has_nonstandard_attr("SameSite") else {}),
                     "expires": c.expires if c.expires is not None else -1}
                    for c in s.cookies.jar if not c.is_expired()
                ])
                logger.info("[协议登录] 登录成功")
                return {"success": True, "session_token": session_token, "email": validated["email"], "google_cookies": refreshed}

            except Exception as e:
                logger.error(f"[协议登录] 异常 ({type(e).__name__})")
                return failure("verification_unavailable", "协议授权请求失败，请检查源代理或通过浏览器重新授权；未清除 Cookie")


protocol_loginer = ProtocolLogin()
