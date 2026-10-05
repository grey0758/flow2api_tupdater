import importlib.util
import json
import subprocess
import sys
import threading
import time
from argparse import Namespace
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest


SCRIPT = Path(__file__).with_name("sgp011_flow_account_pipeline.py")
SPEC = importlib.util.spec_from_loader(
    "sgp011_flow_account_pipeline",
    SourceFileLoader("sgp011_flow_account_pipeline", str(SCRIPT)),
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_record_id_is_narrow():
    assert MODULE.validate_record_id("account-001") == "account-001"
    for value in ("account-1", "../account-001", "account-001/secret", "index"):
        with pytest.raises(MODULE.PipelineError):
            MODULE.validate_record_id(value)


def test_parse_last_json_ignores_non_json_lines():
    assert MODULE.parse_last_json('progress\n{"success":true}\n') == {"success": True}


def test_safe_record_excludes_provider_credentials():
    safe = MODULE.safe_record(
        "account-001",
        {
            "STATUS": "pending",
            "PROFILE_ID": "18",
            "LOGIN_SLOT": "1",
            "FLOW_TOKEN_ID": "21",
            "EMAIL": "secret@example.invalid",
            "PASSWORD": "private",
            "TOTP_SECRET": "PRIVATE",
        },
        2,
    )
    assert safe == {
        "record_id": "account-001",
        "version": 2,
        "status": "pending",
        "profile_id": 18,
        "slot": 1,
        "flow_token_id": 21,
    }


def test_record_binding_requires_exact_stage_profile_and_token():
    record = {
        "RECORD_ID": "account-001",
        "STATUS": "pending_image_acceptance",
        "PROFILE_ID": "18",
        "FLOW_TOKEN_ID": "21",
        "EMAIL": "owner@example.invalid",
    }
    assert MODULE.require_record_binding(
        "account-001",
        record,
        status="pending_image_acceptance",
        profile_id=18,
        token_id=21,
    ) == "owner@example.invalid"
    for field, value, code in (
        ("STATUS", "login_invited", "record_stage_mismatch"),
        ("PROFILE_ID", "19", "record_profile_mismatch"),
        ("FLOW_TOKEN_ID", "22", "record_token_mismatch"),
    ):
        changed = dict(record, **{field: value})
        with pytest.raises(MODULE.PipelineError) as raised:
            MODULE.require_record_binding(
                "account-001",
                changed,
                status="pending_image_acceptance",
                profile_id=18,
                token_id=21,
            )
        assert raised.value.code == code


def test_cli_has_no_plaintext_password_argument():
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"--basic-password-stdin"' not in source
    assert '"--password"' not in source
    assert "pyotp" not in source
    assert "xdotool" not in source
    assert "playwright" not in source
    assert '"--expected-identity-stdin"' in source


def test_invitation_requires_exact_256_bit_urlsafe_capability():
    assert MODULE.CAPABILITY_RE.fullmatch("A" * 43)
    assert not MODULE.CAPABILITY_RE.fullmatch("A" * 42)
    assert not MODULE.CAPABILITY_RE.fullmatch("A" * 44)


def test_embedded_remote_helpers_are_valid_python():
    compile(MODULE.PREPARE_HELPER, "<prepare-helper>", "exec")
    compile(MODULE.ENABLE_HELPER, "<enable-helper>", "exec")
    compile(MODULE.ACCEPTANCE_EVIDENCE_HELPER, "<acceptance-evidence-helper>", "exec")
    compile(MODULE.SLOT_CAPACITY_HELPER, "<capacity-helper>", "exec")


def test_auto_login_secret_uses_stdin_only(monkeypatch):
    captured = {}
    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["stdin"] = kwargs["input_text"]
        return subprocess.CompletedProcess(command, 0, '{"success":true,"profile_id":61}', "")
    monkeypatch.setattr(MODULE, "run", fake_run)
    reply = MODULE.auto_login_remote(61, {
        "EMAIL": "owner@example.invalid", "PASSWORD": "private-password",
        "TOTP_SECRET": "PRIVATESEED",
    })
    assert reply["success"] is True
    assert "private-password" not in " ".join(captured["command"])
    assert "PRIVATESEED" not in " ".join(captured["command"])
    assert json.loads(captured["stdin"])["password"] == "private-password"


def test_batch_caps_active_profiles_at_five(monkeypatch):
    counts = {"active": 0, "peak": 0}
    guard = threading.Lock()
    def fake_record(record_id, admission_lock):
        with guard:
            counts["active"] += 1
            counts["peak"] = max(counts["peak"], counts["active"])
        time.sleep(0.02)
        with guard:
            counts["active"] -= 1
        return {"record_id": record_id, "status": "imported"}
    monkeypatch.setattr(MODULE, "slot_capacity_remote", lambda: {"free": 5, "total": 5})
    monkeypatch.setattr(MODULE, "_batch_record", fake_record)
    report = MODULE.command_batch(Namespace(
        parallel=5, record_ids=[f"account-{number:03d}" for number in range(50, 57)],
    ))
    assert report["success"] is True
    assert report["active_parallel"] == 5
    assert counts["peak"] == 5


def test_batch_stops_before_paid_admission(monkeypatch):
    class FakeBao:
        def get(self, record_id):
            return ({"RECORD_ID": record_id, "STATUS": "pending",
                     "EMAIL": "owner@example.invalid", "PASSWORD": "private",
                     "TOTP_SECRET": "PRIVATESEED"}, 1)
        def transition(self, record_id, expected, fields):
            transitions.append((expected, fields["STATUS"]))
            return len(transitions) + 1
    transitions = []
    monkeypatch.setattr(MODULE, "OpenBao", FakeBao)
    monkeypatch.setattr(MODULE, "prepare_remote", lambda name: {
        "profile_id": 61, "slot": 1, "invite_url": "https://example.invalid/login-slots#private"})
    monkeypatch.setattr(MODULE, "auto_login_remote", lambda profile, data: {"success": True})
    monkeypatch.setattr(MODULE, "command_onboard", lambda args: pytest.fail("sync attempted"))
    monkeypatch.setattr(MODULE, "command_accept", lambda args: pytest.fail("paid image attempted"))
    result = MODULE._batch_record("account-041", threading.Lock())
    assert result["status"] == "ready_for_pro_redemption"
    assert transitions == [("pending", "preparing"), ("preparing", "login_invited"),
                           ("login_invited", "ready_for_pro_redemption")]


def test_onboard_requires_pro_verification_before_remote_side_effect(monkeypatch):
    class FakeBao:
        def get(self, record_id):
            return ({"RECORD_ID": record_id, "STATUS": "ready_for_pro_redemption",
                     "PROFILE_ID": "61", "EMAIL": "owner@example.invalid"}, 1)
    monkeypatch.setattr(MODULE, "OpenBao", FakeBao)
    monkeypatch.setattr(MODULE, "run", lambda *args, **kwargs: pytest.fail("remote sync attempted"))
    with pytest.raises(MODULE.PipelineError, match="record_stage_mismatch"):
        MODULE.command_onboard(Namespace(record_id="account-041", profile_id=61))


def test_stage_transition_refuses_a_changed_record_before_side_effect(monkeypatch):
    bao = object.__new__(MODULE.OpenBao)
    bao.token = "test-token"
    monkeypatch.setattr(bao, "get", lambda _: ({"STATUS": "image_acceptance_running"}, 4))
    called = []
    monkeypatch.setattr(bao, "_request", lambda *args, **kwargs: called.append(args))
    with pytest.raises(MODULE.PipelineError, match="record_stage_mismatch"):
        bao.transition("account-001", "pending_image_acceptance", {"STATUS": "image_acceptance_running"})
    assert called == []


def test_completed_image_report_is_reconciled_without_a_second_request(tmp_path):
    folder = tmp_path / "sgp011-flow-account-health-test"
    folder.mkdir()
    (folder / "COMPLETE").touch()
    report = {
        "success": True,
        "mode": "pending_image_acceptance",
        "results": [{
            "success": True, "stage": "complete", "profile_id": 54,
            "flow_token_id": 43, "newapi_http": 200, "media_http": 200,
            "image_format": "JPEG", "width": 1376, "height": 768,
            "bytes": 405251, "flow_log_id": 24635, "newapi_log_id": 52900,
            "newapi_log_rows": 14,
        }],
    }
    (folder / "result.json").write_text(json.dumps(report))
    helper = MODULE.ACCEPTANCE_EVIDENCE_HELPER.replace(
        "/home/grey/backups/sgp011-flow-account-health-*", str(tmp_path / "sgp011-flow-account-health-*")
    )
    completed = subprocess.run(
        [sys.executable, "-", "54", "43"], input=helper, text=True,
        capture_output=True, check=False,
    )
    assert completed.returncode == 0
    evidence = json.loads(completed.stdout)
    assert evidence["evidence"] == folder.name
    assert evidence["results"][0]["flow_log_id"] == 24635

    report["results"][0]["media_http"] = 500
    (folder / "result.json").write_text(json.dumps(report))
    rejected = subprocess.run(
        [sys.executable, "-", "54", "43"], input=helper, text=True,
        capture_output=True, check=False,
    )
    assert rejected.returncode == 1
