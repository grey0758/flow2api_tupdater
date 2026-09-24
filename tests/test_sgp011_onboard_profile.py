import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "sgp011_onboard_profile.py"
SPEC = importlib.util.spec_from_file_location("sgp011_onboard_profile", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(module)


def state(**changes):
    result = {
        "profile_id": 19,
        "identity": "fresh@example.com",
        "project_identity": "fresh@example.com",
        "project_id": "0f6ddfcf-11ce-4a79-9792-b23cc4d189aa",
        "active": False,
        "logged_in": True,
        "sync_count": 0,
        "error_count": 0,
        "last_sync_result": "",
        "slot_claimed": True,
        "handoff_complete": True,
        "project_verified": True,
        "token_present": True,
        "cookies_present": True,
    }
    result.update(changes)
    return result


def test_candidate_rejects_any_previous_sync_or_error():
    for changed in (state(sync_count=1), state(error_count=1), state(active=True)):
        with pytest.raises(module.OperatorError, match="重放"):
            module.require_fresh_candidate(changed, extracted=True)


def test_candidate_requires_stable_identity_project_and_extraction():
    for changed in (
        state(logged_in=False),
        state(project_identity="other@example.com"),
        state(project_verified=False),
        state(token_present=False),
        state(cookies_present=False),
    ):
        with pytest.raises(module.OperatorError, match="会话提取"):
            module.require_fresh_candidate(changed, extracted=True)


def test_run_stops_duplicate_before_backup_or_sync():
    with (
        patch.object(module, "profile_state", return_value=state()),
        patch.object(module, "dedupe_state", return_value={
            "identity_matches": 1,
            "token_project_matches": 1,
            "project_rows": 1,
        }),
        patch.object(module, "online_backup") as backup,
        patch.object(module, "updater_call") as api,
    ):
        with pytest.raises(module.OperatorError, match="既有账号"):
            module.run(19)
    backup.assert_not_called()
    api.assert_not_called()


def test_run_orders_backup_before_single_onboard_and_stops_pending(tmp_path):
    events = []
    before = state()
    pending = {
        "profile_id": 19,
        "token_id": 20,
        "profile_active": False,
        "token_active": False,
        "pending_image_acceptance": True,
        "newapi_unchanged": True,
        "flow_tasks": 0,
    }

    def backup(*_):
        events.append("backup")
        return tmp_path, {"max_log": 1, "tasks": 0}

    def api(mode, _):
        events.append(mode)
        assert mode == "onboard"
        return {
            "success": True,
            "action": "added_pending_enable",
            "pending_image_acceptance": True,
            "token_id": 20,
        }

    def verify(*_):
        events.append("verify")
        return dict(pending)

    with (
        patch.object(module, "profile_state", return_value=before),
        patch.object(module, "dedupe_state", return_value={
            "identity_matches": 0,
            "token_project_matches": 0,
            "project_rows": 0,
        }),
        patch.object(module, "online_backup", side_effect=backup),
        patch.object(module, "updater_call", side_effect=api),
        patch.object(module, "verify_pending", side_effect=verify),
    ):
        result = module.run(19)
    assert events == ["backup", "onboard", "verify"]
    assert result["pending_image_acceptance"] is True
    assert (tmp_path / "PENDING_IMAGE_ACCEPTANCE").is_file()
