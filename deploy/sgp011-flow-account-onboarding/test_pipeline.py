import importlib.util
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


def test_cli_has_no_plaintext_password_argument():
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"--basic-password-stdin"' in source
    assert '"--password"' not in source
    assert "pyotp" not in source
    assert "xdotool" not in source
    assert "playwright" not in source


def test_invitation_requires_exact_256_bit_urlsafe_capability():
    assert MODULE.CAPABILITY_RE.fullmatch("A" * 43)
    assert not MODULE.CAPABILITY_RE.fullmatch("A" * 42)
    assert not MODULE.CAPABILITY_RE.fullmatch("A" * 44)


def test_embedded_remote_helpers_are_valid_python():
    compile(MODULE.PREPARE_HELPER, "<prepare-helper>", "exec")
    compile(MODULE.ENABLE_HELPER, "<enable-helper>", "exec")
