"""Synthetic raw native bytes only; no authentication, Windows or network calls."""

import json
from copy import deepcopy

import pytest

from bluefire.ad_smb_contract import AdSmbError, AdSmbReadTarget, AdSmbScope
from bluefire.ad_smb_native_results import project_native_read
from tests_platform.test_ad_smb_contract import pin, scope_row


def fixture():
    scope = AdSmbScope.from_mapping(scope_row())
    target = AdSmbReadTarget.from_scope(scope, reader="probe", purpose="primary").to_dict()
    request = {
        "request_id": "1" * 32,
        "scope": scope.to_dict(),
        "scope_digest": scope.digest,
        "target": target,
        "phase": "baseline",
        "step": "read_probe_primary",
    }
    row = {
        "schema_version": "bluefire.ad-smb-fresh-read.v1",
        "request_id": request["request_id"],
        "reader": "probe",
        "purpose": "primary",
        "scope_digest": scope.digest,
        "client_identity_digest": pin("2"),
        "credential_binding_digest": pin("3"),
        "hardened_unc_receipt_digest": target["hardened_unc_receipt_digest"],
        "expected_remote_sid": target["expected_remote_sid"],
        "state": "bytes_matched",
        "local_logon": {
            "authentication_id": 2**64 - 2,
            "local_token_user_sid": "S-1-5-21-7-8-9-1100",
        },
        "file_open_attempted": True,
        "protocol": {"version": 2, "size": 116, "protocol": 0x20000, "major": 3, "flags": 0x28},
        "bytes_read": target["file"]["size_bytes"],
        "expected_volume_serial": int(target["file"]["volume_serial"], 16),
        "observed_volume_serial": int(target["file"]["volume_serial"], 16),
        "observed_file_id": target["file"]["file_id"],
        "observed_sha256": target["file"]["sha256"],
        "failed_stage": None,
        "win32_error": None,
        "issue": None,
        "cleanup": {
            "file_closed": True,
            "exact_unc_cancel_status": 0,
            "impersonation_reverted": True,
            "token_closed": True,
            "observation_tokens_closed": None,
            "owned_process_exit_required": False,
            "server_session_closed": None,
        },
        "authenticated_remote_reader": False,
        "fresh_server_logon": False,
        "independent_observation": False,
        "effective_access_claim": False,
    }
    return request, row


def project(request, row, **kwargs):
    return project_native_read(
        request,
        json.dumps(row).encode(),
        client_identity_digest=pin("2"),
        credential_binding_digest=pin("3"),
        owned_process_exit_verified=kwargs.get("exit", True),
    )


def test_matched_raw_read_preserves_u64_without_asserting_remote_identity():
    request, row = fixture()
    original = deepcopy(row)
    result = project(request, row)
    assert row == original
    assert result["state"] == "bytes_matched"
    assert result["volume_serial"] == "f123456789abcdef"
    assert result["local_authentication_id"] == "fffffffffffffffe"
    assert result["file_id"] == row["observed_file_id"]
    assert result["local_user_sid"] != result["expected_remote_sid"]
    assert result["server_session_closed"] is None
    for key in (
        "authenticated_remote_reader",
        "fresh_server_logon",
        "independent_observation",
        "effective_access_claim",
    ):
        assert result[key] is False
    assert "credential_binding_digest" not in result and "protocol" not in result


def test_separate_process_exit_is_required_even_for_a_complete_native_read():
    request, row = fixture()
    result = project(request, row, exit=False)
    assert result["state"] == "unknown" and result["local_cleanup"] == "unknown"
    assert result["bytes_read"] == row["bytes_read"] and result["sha256"] == row["observed_sha256"]


def denied(row):
    row.update(
        state="open_access_denied",
        protocol=None,
        bytes_read=0,
        observed_volume_serial=None,
        observed_file_id=None,
        observed_sha256=None,
        failed_stage="open",
        win32_error=5,
        issue="win32_failure",
    )
    row["cleanup"]["file_closed"] = None


def test_exact_open_denial_is_not_a_failed_authentication_or_read_error():
    request, row = fixture()
    denied(row)
    assert project(request, row)["state"] == "open_access_denied"
    for field, value in (
        ("failed_stage", "logon"),
        ("win32_error", 1326),
        ("observed_file_id", "1" * 32),
        ("bytes_read", 1),
    ):
        changed = deepcopy(row)
        changed[field] = value
        with pytest.raises(AdSmbError):
            project(request, changed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "0" * 32),
        ("scope_digest", pin("0")),
        ("client_identity_digest", pin("0")),
        ("credential_binding_digest", pin("0")),
        ("hardened_unc_receipt_digest", pin("0")),
        ("expected_remote_sid", "S-1-5-21-7-8-9-1100"),
        ("reader", "legitimate"),
        ("purpose", "health"),
        ("authenticated_remote_reader", True),
        ("fresh_server_logon", True),
        ("independent_observation", True),
        ("effective_access_claim", True),
        ("expected_volume_serial", 2**64),
        ("expected_volume_serial", True),
        ("observed_volume_serial", 1),
        ("observed_volume_serial", float(2**63)),
        ("observed_file_id", "0" * 32),
        ("observed_file_id", None),
        ("observed_sha256", pin("0")),
        ("bytes_read", True),
        ("bytes_read", 0),
        ("file_open_attempted", False),
        ("state", []),
        ("failed_stage", {}),
        ("issue", "private value with spaces"),
        ("extra", "secret"),
    ],
)
def test_changed_or_malformed_native_fields_refused(field, value):
    request, row = fixture()
    row[field] = value
    with pytest.raises(AdSmbError, match="invalid or differs"):
        project(request, row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("flags", 0x20),
        ("flags", 0x29),
        ("flags", 0x68),
        ("major", 2),
        ("size", 180),
        ("version", 1),
        ("protocol", 0),
        ("version", True),
    ],
)
def test_smb_protection_cannot_be_asserted_from_an_incompatible_protocol(field, value):
    request, row = fixture()
    row["protocol"][field] = value
    with pytest.raises(AdSmbError):
        project(request, row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("authentication_id", 0),
        ("authentication_id", 2**64),
        ("authentication_id", True),
        ("local_token_user_sid", "BA"),
        ("extra", "secret"),
    ],
)
def test_invalid_native_local_logon_refused(field, value):
    request, row = fixture()
    row["local_logon"][field] = value
    with pytest.raises(AdSmbError):
        project(request, row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("file_closed", None),
        ("token_closed", False),
        ("impersonation_reverted", None),
        ("server_session_closed", True),
        ("exact_unc_cancel_status", -1),
        ("observation_tokens_closed", 1),
    ],
)
def test_malformed_or_incomplete_success_cleanup_refused(field, value):
    request, row = fixture()
    row["cleanup"][field] = value
    with pytest.raises(AdSmbError):
        project(request, row)


def test_unknown_native_object_drift_is_retained_without_target_substitution():
    request, row = fixture()
    row.update(
        state="unknown",
        observed_file_id="0" * 32,
        bytes_read=0,
        observed_sha256=None,
        failed_stage="metadata",
        issue="file_identity_mismatch",
    )
    result = project(request, row)
    assert result["state"] == "unknown" and result["file_id"] == "0" * 32
    assert result["file_id"] != request["target"]["file"]["file_id"]


def test_not_started_cannot_hide_any_observed_work():
    request, row = fixture()
    row.update(state="not_started")
    with pytest.raises(AdSmbError):
        project(request, row)
    row.update(
        local_logon=None,
        file_open_attempted=False,
        protocol=None,
        bytes_read=0,
        observed_volume_serial=None,
        observed_file_id=None,
        observed_sha256=None,
        issue="credential_upn_binding_mismatch",
    )
    row["cleanup"] = {
        key: False if key == "owned_process_exit_required" else None for key in row["cleanup"]
    }
    assert project(request, row)["state"] == "not_started"


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b'{"state":1,"state":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"[]",
        b"{" + b" " * 16384 + b"}",
        b"\xff",
    ],
)
def test_raw_wire_is_strict_and_bounded(raw):
    request, _row = fixture()
    with pytest.raises(AdSmbError):
        project_native_read(
            request,
            raw,
            client_identity_digest=pin("2"),
            credential_binding_digest=pin("3"),
            owned_process_exit_verified=True,
        )
