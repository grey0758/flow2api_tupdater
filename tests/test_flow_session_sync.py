import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from token_updater.browser import BrowserManager
from token_updater.config import config
from token_updater.updater import TokenSyncer

JAR = [{"name":"SID", "value":"new-cookie", "domain":".google.com", "path":"/"},
       {"name":"OSID", "value":"new-flow", "domain":"flow.google.com", "path":"/"}]


class FlowSessionSyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_browser_sync_reloads_cookies_and_preserves_destination_proxy(self):
        syncer = TokenSyncer()
        profile = {"id":1, "name":"test", "flow2api_url":"http://server", "connection_token_override":"key",
                   "proxy_enabled":1, "proxy_url":"socks5://127.0.0.1:20001", "google_cookies":"SID=old"}
        fresh = {**profile, "google_cookies":json.dumps(JAR)}
        with patch.object(config, "protocol_refresh_enabled", False), \
             patch("token_updater.updater.profile_db.get_profile", AsyncMock(side_effect=[profile, fresh])), \
             patch("token_updater.updater.profile_db.update_profile", AsyncMock()), \
             patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()), \
             patch("token_updater.updater.dashboard_events.publish", AsyncMock()), \
             patch("token_updater.protocol_login.protocol_loginer.login", AsyncMock()) as protocol, \
             patch.object(syncer, "_extract_token_with_timeout", AsyncMock(return_value="session")), \
             patch.object(syncer, "_push_to_flow2api", AsyncMock(return_value={"success":True, "action":"updated"})) as push:
            result = await syncer._sync_profile(1)
        self.assertTrue(result["success"])
        protocol.assert_not_awaited()
        self.assertEqual(push.await_args.kwargs["google_cookies"], JAR)
        self.assertNotIn("captcha_proxy_url", push.await_args.kwargs)

    async def test_transport_sends_full_jar_and_explicit_target_proxy(self):
        response = SimpleNamespace(status_code=200, json=lambda: {"success":True,"cookies_updated":True,"flow_cookies_configured":True,"google_session_cookies_configured":True,"proxy_updated":True,"proxy_configured":True,"oauth_verified":True,"account_active":True})
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.post.return_value = response
        with patch("token_updater.updater.httpx.AsyncClient", return_value=client):
            result = await TokenSyncer()._push_to_flow2api("session", "http://server", "key", google_cookies=JAR, captcha_proxy_url="socks5://host.docker.internal:20001")
        self.assertTrue(result["success"])
        self.assertEqual(client.post.await_args.kwargs["json"], {"session_token":"session", "google_cookies":JAR, "captcha_proxy_url":"socks5://host.docker.internal:20001"})

    async def test_rejects_old_server_that_silently_ignores_cookie_payload(self):
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.post.return_value = SimpleNamespace(status_code=200, json=lambda: {"success":True})
        with patch("token_updater.updater.httpx.AsyncClient", return_value=client):
            self.assertFalse((await TokenSyncer()._push_to_flow2api("st", "http://server", "key", google_cookies=JAR))["success"])

    async def test_cookie_sync_requires_destination_account_proxy(self):
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.post.return_value = SimpleNamespace(status_code=200, json=lambda: {"success":True, "cookies_updated":True, "flow_cookies_configured":True, "google_session_cookies_configured":True, "proxy_configured":False})
        with patch("token_updater.updater.httpx.AsyncClient", return_value=client):
            result = await TokenSyncer()._push_to_flow2api("st", "http://server", "key", google_cookies=JAR)
        self.assertFalse(result["success"])
        self.assertIn("代理", result["error"])

    async def test_collects_flow_host_cookie_and_deduplicates(self):
        context = SimpleNamespace(cookies=AsyncMock(return_value=JAR))
        with patch("token_updater.browser.profile_db.update_profile", AsyncMock()) as save:
            self.assertTrue(await BrowserManager()._save_google_cookies_from_context(1, context))
        self.assertEqual(len(json.loads(save.await_args.kwargs["google_cookies"])), 2)
        self.assertIn(("https://flow.google.com",), [c.args for c in context.cookies.await_args_list])
        self.assertIn(("https://google.com",), [c.args for c in context.cookies.await_args_list])

    async def test_host_only_osid_is_not_a_complete_session(self):
        context = SimpleNamespace(cookies=AsyncMock(return_value=[JAR[1]]))
        with patch("token_updater.browser.profile_db.update_profile", AsyncMock()) as save:
            self.assertFalse(await BrowserManager()._save_google_cookies_from_context(1, context))
        save.assert_not_awaited()
        with patch("token_updater.updater.httpx.AsyncClient") as client:
            result = await TokenSyncer()._push_to_flow2api("st", "http://server", "key", google_cookies=[JAR[1]])
        self.assertFalse(result["success"])
        client.assert_not_called()

    async def test_chunked_nextauth_and_redirect_readiness(self):
        manager = BrowserManager()
        context = SimpleNamespace(cookies=AsyncMock(return_value=[{"name":config.session_cookie_name + ".1", "value":"tail", "domain":"labs.google"},
            {"name":config.session_cookie_name + ".0", "value":"head", "domain":"labs.google"}]))
        self.assertEqual(await manager._get_session_cookie(context), "headtail")
        page = SimpleNamespace(url="https://flow.google.com/project/p", locator=lambda _: SimpleNamespace(count=AsyncMock(return_value=0)))
        self.assertTrue(await manager._is_labs_session_ready(page, "My projects"))
        page.url = "https://evil.test/?next=https://labs.google"
        self.assertFalse(await manager._is_labs_session_ready(page, "My projects"))
