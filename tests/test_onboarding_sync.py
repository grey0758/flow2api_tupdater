from unittest.mock import AsyncMock, patch

import pytest

from token_updater.updater import TokenSyncer


PROJECT = "0f6ddfcf-11ce-4a79-9792-b23cc4d189aa"
COOKIES = (
    '[{"name":"SID","value":"root","domain":".google.com","path":"/"},'
    '{"name":"OSID","value":"flow","domain":"flow.google.com","path":"/"}]'
)


def candidate(**changes):
    profile = {
        "id": 19,
        "name": "fresh",
        "email": "fresh@example.com",
        "is_active": 0,
        "is_logged_in": 1,
        "sync_count": 0,
        "error_count": 0,
        "login_slot_claimed": 1,
        "login_slot_handoff_complete": 1,
        "observed_flow_project_verified": 1,
        "observed_flow_project_identity": "fresh@example.com",
        "observed_flow_project_id": PROJECT,
        "last_token": "present",
        "google_cookies": COOKIES,
        "flow2api_url": "http://server",
        "connection_token_override": "connection",
    }
    profile.update(changes)
    return profile


ACK = {
    "success": True,
    "action": "added_pending_enable",
    "oauth_verified": True,
    "project_context_accepted": True,
    "project_reused": True,
    "project_owned": True,
    "pending_enable": True,
    "account_active": False,
    "needs_refresh": False,
    "token_id": 19,
}


@pytest.mark.asyncio
async def test_new_onboarding_requires_backup_before_any_lookup_or_write():
    syncer = TokenSyncer()
    with patch("token_updater.updater.profile_db.get_profile", AsyncMock()) as get_profile:
        result = await syncer.onboard_new_profile_once(19, backup_confirmed=False)
    assert result["error_code"] == "onboarding_backup_unconfirmed"
    get_profile.assert_not_awaited()


@pytest.mark.asyncio
async def test_new_onboarding_stops_on_destination_identity_duplicate():
    syncer = TokenSyncer()
    profile = candidate()
    with (
        patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
        patch("token_updater.updater.profile_db.update_profile", AsyncMock()) as update,
        patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={
            "success": True,
            "tokens": [{"email": profile["email"]}],
        })),
        patch.object(syncer, "_sync_profile", AsyncMock()) as sync,
    ):
        result = await syncer.onboard_new_profile_once(19, backup_confirmed=True)
    assert result["error_code"] == "onboarding_identity_duplicate"
    update.assert_not_awaited()
    sync.assert_not_awaited()


@pytest.mark.asyncio
async def test_new_onboarding_activates_and_syncs_once_then_pauses_pending_profile():
    syncer = TokenSyncer()
    profile = candidate()
    updates = AsyncMock()
    with (
        patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
        patch("token_updater.updater.profile_db.update_profile", updates),
        patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={
            "success": True,
            "tokens": [],
        })),
        patch.object(syncer, "_sync_profile", AsyncMock(return_value=ACK)) as sync,
    ):
        result = await syncer.onboard_new_profile_once(19, backup_confirmed=True)
    assert result["success"] is True
    assert result["pending_image_acceptance"] is True
    sync.assert_awaited_once_with(19)
    assert updates.await_args_list[0].kwargs == {
        "is_active": 1,
        "login_slot_prepared": 0,
    }
    assert updates.await_args_list[-1].kwargs == {"is_active": 0}


@pytest.mark.asyncio
async def test_new_onboarding_partial_write_is_paused_and_never_retried():
    syncer = TokenSyncer()
    profile = candidate()
    updates = AsyncMock()
    with (
        patch("token_updater.updater.profile_db.get_profile", AsyncMock(return_value=profile)),
        patch("token_updater.updater.profile_db.update_profile", updates),
        patch.object(syncer, "_check_tokens_status", AsyncMock(return_value={
            "success": True,
            "tokens": [],
        })),
        patch.object(syncer, "_sync_profile", AsyncMock(return_value={
            **ACK,
            "success": False,
            "synced": True,
        })) as sync,
    ):
        result = await syncer.onboard_new_profile_once(19, backup_confirmed=True)
    assert result["error_code"] == "onboarding_sync_contract_failed"
    assert result["synced"] is True
    sync.assert_awaited_once_with(19)
    assert updates.await_args_list[-1].kwargs == {"is_active": 0}
