import json
import unittest
from unittest.mock import AsyncMock, patch

from token_updater.updater import TokenSyncer
from token_updater.config import config

JAR = [{"name": "SID", "value": "root", "domain": ".google.com", "path": "/"},
       {"name": "OSID", "value": "flow", "domain": "flow.google.com", "path": "/"}]


class TokenSyncerMergeTests(unittest.IsolatedAsyncioTestCase):
    async def test_gemini_mode_keeps_gemini_cookie_flow(self):
        syncer = TokenSyncer()
        profile = {
            "id": 1,
            "name": "gemini-profile",
            "remark": "extract=gemini_cookies",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-1",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.updater.gemini_cookie_bridge.build_plugin_session_token",
                AsyncMock(return_value={"success": True, "session_token": "gcu:v1:test", "client_id": "profile-1"}),
            ) as gemini_build,
            patch("token_updater.updater.browser_manager.extract_token", AsyncMock()) as extract_token,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(return_value={"success": True, "action": "updated", "message": ""}),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(1)

        self.assertTrue(result["success"])
        gemini_build.assert_awaited_once_with(profile)
        extract_token.assert_not_awaited()
        push_to_flow2api.assert_awaited_once_with("gcu:v1:test", "http://example.com", "token-1")

    async def test_gemini_mode_ignores_google_cookies_and_uses_browser_only(self):
        syncer = TokenSyncer()
        profile = {
            "id": 11,
            "name": "gemini-browser-profile",
            "remark": "gemini2api",
            "google_cookies": "__Secure-1PSID=aaa; __Secure-1PSIDTS=bbb",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-11",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.updater.gemini_cookie_bridge.build_plugin_session_token",
                AsyncMock(return_value={"success": True, "session_token": "gcu:v1:from-browser", "client_id": "profile-11"}),
            ) as from_browser_profile,
            patch("token_updater.updater.browser_manager.extract_token", AsyncMock()) as extract_token,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(return_value={"success": True, "action": "updated", "message": ""}),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(11)

        self.assertTrue(result["success"])
        from_browser_profile.assert_awaited_once_with(profile)
        extract_token.assert_not_awaited()
        push_to_flow2api.assert_awaited_once_with("gcu:v1:from-browser", "http://example.com", "token-11")

    async def test_gemini_mode_reports_failure_when_browser_extraction_fails(self):
        syncer = TokenSyncer()
        profile = {
            "id": 12,
            "name": "gemini-failed-profile",
            "remark": "extract=gemini_cookies",
            "google_cookies": "SID=aaa; HSID=bbb",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-12",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.updater.gemini_cookie_bridge.build_plugin_session_token",
                AsyncMock(return_value={"success": False, "error": "browser extraction timeout"}),
            ) as from_browser_profile,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(12)

        self.assertFalse(result["success"])
        from_browser_profile.assert_awaited_once_with(profile)
        push_to_flow2api.assert_not_awaited()

    @patch.object(config, "protocol_refresh_enabled", True)
    async def test_protocol_mode_retries_with_browser_when_protocol_payload_push_fails(self):
        syncer = TokenSyncer()
        profile = {
            "id": 13,
            "name": "protocol-retry-profile",
            "email": "user@example.com",
            "google_cookies": json.dumps(JAR),
            "proxy_enabled": 0,
            "proxy_url": "",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-13",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.protocol_login.protocol_loginer.login",
                AsyncMock(return_value={"success": True, "session_token": "session-from-protocol"}),
            ) as protocol_login,
            patch(
                "token_updater.updater.browser_manager.extract_token",
                AsyncMock(return_value="session-from-browser"),
            ) as extract_token,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(side_effect=[
                    {"success": False, "error": "invalid labs session", "error_code": "auth_required"},
                    {"success": True, "action": "updated", "message": ""},
                ]),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()) as update_profile,
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(13)

        self.assertTrue(result["success"])
        protocol_login.assert_awaited_once()
        extract_token.assert_awaited_once_with(13)
        self.assertFalse(any("google_cookies" in call.kwargs for call in update_profile.await_args_list))
        self.assertEqual(push_to_flow2api.await_count, 2)

    @patch.object(config, "protocol_refresh_enabled", True)
    async def test_protocol_refresh_uses_google_cookies_before_browser_fallback(self):
        syncer = TokenSyncer()
        profile = {
            "id": 2,
            "name": "protocol-profile",
            "email": "user@example.com",
            "google_cookies": json.dumps(JAR),
            "proxy_enabled": 1,
            "proxy_url": "http://127.0.0.1:8080",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-2",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.protocol_login.protocol_loginer.login",
                AsyncMock(return_value={"success": True, "session_token": "session-from-protocol"}),
            ) as protocol_login,
            patch("token_updater.updater.browser_manager.extract_token", AsyncMock()) as extract_token,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(return_value={"success": True, "action": "updated", "message": ""}),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(2)

        self.assertTrue(result["success"])
        protocol_login.assert_awaited_once_with(
            json.dumps(JAR),
            proxy="http://127.0.0.1:8080",
            email="user@example.com",
        )
        extract_token.assert_not_awaited()
        push_to_flow2api.assert_awaited_once_with("session-from-protocol", "http://example.com", "token-2", google_cookies=JAR)

    @patch.object(config, "protocol_refresh_enabled", True)
    async def test_protocol_refresh_falls_back_to_browser_without_erasing_google_cookies(self):
        syncer = TokenSyncer()
        profile = {
            "id": 3,
            "name": "fallback-profile",
            "email": "user@example.com",
            "google_cookies": json.dumps(JAR),
            "proxy_enabled": 0,
            "proxy_url": "",
            "flow2api_url": "http://example.com",
            "connection_token_override": "token-3",
            "error_count": 0,
        }

        with (
            patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
            patch(
                "token_updater.protocol_login.protocol_loginer.login",
                AsyncMock(return_value={"success": False, "error": "expired"}),
            ) as protocol_login,
            patch(
                "token_updater.updater.browser_manager.extract_token",
                AsyncMock(return_value="session-from-browser"),
            ) as extract_token,
            patch.object(
                syncer,
                "_push_to_flow2api",
                AsyncMock(return_value={"success": True, "action": "updated", "message": ""}),
            ) as push_to_flow2api,
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()) as update_profile,
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
        ):
            result = await syncer._sync_profile(3)

        self.assertTrue(result["success"])
        protocol_login.assert_awaited_once()
        self.assertFalse(any("google_cookies" in call.kwargs for call in update_profile.await_args_list))
        extract_token.assert_awaited_once_with(3)
        push_to_flow2api.assert_awaited_once_with("session-from-browser", "http://example.com", "token-3", google_cookies=JAR)


if __name__ == "__main__":
    unittest.main()
