import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from token_updater.updater import TokenSyncer


class TokenSyncerBatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_protected_inactive_overdue_profile_is_skipped_before_source_login(self):
        syncer = TokenSyncer()
        profile = {"id":7, "name":"independent", "email":"independent@example.com",
                   "flow2api_url":"http://server", "connection_token_override":"test-key",
                   "last_sync_time":None}
        token = {"email":profile["email"], "is_active":False, "needs_refresh":True,
                 "sync_allowed":False, "sync_block_reason":"independent_login"}
        with (
            patch("token_updater.updater.profile_db.get_active_profiles", AsyncMock(return_value=[profile])),
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
            patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={"success":True, "tokens":[token]})),
            patch.object(syncer, "_sync_profile", AsyncMock()) as sync_profile,
        ):
            result = await syncer.sync_all_profiles()
        sync_profile.assert_not_awaited()
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["error_count"], 0)

    async def test_syncs_when_target_token_missing(self):
        syncer = TokenSyncer()
        now = datetime.now()
        profiles = [
            {
                "id": 1,
                "name": "alpha",
                "email": "alpha@example.com",
                "flow2api_url": "http://example.com",
                "connection_token_override": "token-1",
                "last_sync_time": now.isoformat(),
            }
        ]

        with (
            patch("token_updater.updater.profile_db.get_active_profiles", AsyncMock(return_value=profiles)),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
            patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={"success": True, "tokens": []})),
            patch.object(
                syncer,
                "_sync_profile",
                AsyncMock(return_value={"success": True, "target_url": "http://example.com"}),
            ) as sync_profile,
        ):
            result = await syncer.sync_all_profiles()

        sync_profile.assert_awaited_once_with(1)
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["skipped"], 0)

    async def test_syncs_when_profile_is_overdue_even_if_target_healthy(self):
        syncer = TokenSyncer()
        now = datetime.now()
        profiles = [
            {
                "id": 2,
                "name": "beta",
                "email": "beta@example.com",
                "flow2api_url": "http://example.com",
                "connection_token_override": "token-2",
                "last_sync_time": (now - timedelta(minutes=61)).isoformat(),
            }
        ]
        tokens = [
            {
                "email": "beta@example.com",
                "is_active": True,
                "needs_refresh": False,
            }
        ]

        with (
            patch("token_updater.updater.profile_db.get_active_profiles", AsyncMock(return_value=profiles)),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
            patch("token_updater.updater.config.refresh_interval", 60),
            patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={"success": True, "tokens": tokens})),
            patch.object(
                syncer,
                "_sync_profile",
                AsyncMock(return_value={"success": True, "target_url": "http://example.com"}),
            ) as sync_profile,
        ):
            result = await syncer.sync_all_profiles()

        sync_profile.assert_awaited_once_with(2)
        self.assertEqual(result["success_count"], 1)
        self.assertEqual(result["skipped"], 0)

    async def test_skips_recent_healthy_profile(self):
        syncer = TokenSyncer()
        now = datetime.now()
        profiles = [
            {
                "id": 3,
                "name": "gamma",
                "email": "gamma@example.com",
                "flow2api_url": "http://example.com",
                "connection_token_override": "token-3",
                "last_sync_time": (now - timedelta(minutes=5)).isoformat(),
            }
        ]
        tokens = [
            {
                "email": "gamma@example.com",
                "is_active": True,
                "needs_refresh": False,
            }
        ]

        with (
            patch("token_updater.updater.profile_db.get_active_profiles", AsyncMock(return_value=profiles)),
            patch("token_updater.updater.profile_db.update_profile", AsyncMock()),
            patch("token_updater.updater.profile_db.record_sync_event", AsyncMock()),
            patch("token_updater.updater.dashboard_events.publish", AsyncMock()),
            patch("token_updater.updater.config.refresh_interval", 60),
            patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={"success": True, "tokens": tokens})),
            patch.object(syncer, "_sync_profile", AsyncMock()) as sync_profile,
        ):
            result = await syncer.sync_all_profiles()

        sync_profile.assert_not_awaited()
        self.assertEqual(result["success_count"], 0)
        self.assertEqual(result["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
