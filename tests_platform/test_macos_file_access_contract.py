"""Pure documents cannot recreate a live creator or prove process custody."""

from copy import deepcopy

import pytest

from bluefire.macos_file_access_contract import (
    BINDING_SCHEMA,
    MONOTONIC_CLOCK,
    OBSERVATION_SCHEMA,
    REQUEST_SCHEMA,
    MacOSFileAccessContractError,
    OwnedMacOSAuthority,
    decode_request,
    validate_binding,
    validate_credentials,
    validate_observation,
    validate_request,
)
from bluefire.util import canonical_json_bytes, content_hash


def credentials(uid):
    return dict(
        real_uid=uid,
        effective_uid=uid,
        saved_uid=uid,
        real_gid=501,
        effective_gid=501,
        saved_gid=501,
        groups=[501],
    )


def binding():
    return dict(
        schema_version=BINDING_SCHEMA,
        enrollment_id="file-enrollment-" + "1" * 32,
        generation="file-generation-" + "2" * 32,
        custody_digest="sha256:" + "3" * 64,
        issued_at_ms=1000,
        expires_at_ms=901000,
        original_deadline_ns=900000001000,
        owner=credentials(501),
        reader=credentials(502),
        directory=dict(device=1, inode=10, owner_uid=0, group_gid=501, mode="0550"),
        resource=dict(
            device=1,
            inode=11,
            owner_uid=501,
            group_gid=501,
            size_bytes=24,
            record_count=8,
            sha256="sha256:" + "4" * 64,
        ),
        control_revision=1,
        mode="0640",
    )


def request(operation="read_reader"):
    setup = binding()
    return dict(
        schema_version=REQUEST_SCHEMA,
        binding=setup,
        binding_digest=content_hash(setup),
        request_id="5" * 64,
        sequence=1,
        operation=operation,
        issued_at_ms=1000,
        expires_at_ms=6000,
        issued_monotonic_ns=1000,
        deadline_ns=5000001000,
    )


def observation(original, outcome="allowed"):
    setup = original["binding"]
    resource = setup["resource"]
    return dict(
        schema_version=OBSERVATION_SCHEMA,
        **{
            field: original[field]
            for field in ("binding_digest", "request_id", "sequence", "operation")
        },
        outcome=outcome,
        principal=setup["reader"],
        fresh_read={
            **{
                field: resource[field]
                for field in ("device", "inode", "size_bytes", "record_count", "sha256")
            },
            "mode": "0640",
        },
        held_control=None,
        request_handle_cleanup="closed",
        held_handle_cleanup="retained",
        custody="requires_original_creator_evidence",
        prevention_proven=False,
    )


def test_roundtrip_documents_are_inactive_and_clock_is_explicit():
    original = request()
    assert decode_request(canonical_json_bytes(original), now_ms=1000, now_ns=1000) == original
    assert MONOTONIC_CLOCK == "darwin-mach-absolute-ns"
    assert validate_observation(observation(original), original)["prevention_proven"] is False
    with pytest.raises(TypeError, match="creator"):
        OwnedMacOSAuthority(original["binding"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("sequence", True),
        ("sequence", 0),
        ("sequence", 65),
        ("deadline_ns", 1000),
        ("deadline_ns", 5000001001),
        ("expires_at_ms", 6001),
        ("binding_digest", "sha256:" + "0" * 64),
        ("operation", "chmod"),
        ("request_id", "5" * 63),
        ("schema_version", "other"),
    ],
)
def test_request_rejects_unbounded_or_substituted_fields(field, value):
    row = request()
    row[field] = value
    with pytest.raises(MacOSFileAccessContractError):
        validate_request(row)


@pytest.mark.parametrize(
    "clock", [dict(now_ms=6000), dict(now_ns=5000001000), dict(now_ms=999), dict(now_ns=999)]
)
def test_expiry_equality_and_clock_rollback_refuse(clock):
    with pytest.raises(MacOSFileAccessContractError):
        validate_request(request(), **clock)


@pytest.mark.parametrize(
    "raw", [b"{}", b'{"sequence":1,"sequence":2}', b"NaN", b"Infinity", b"\xff", b" " * 16385]
)
def test_decode_rejects_duplicate_nonfinite_invalid_and_oversize_json(raw):
    with pytest.raises(MacOSFileAccessContractError):
        decode_request(raw)


def test_extra_fields_and_credential_changes_refuse():
    row = binding()
    row["path"] = "/private/not-an-input"
    with pytest.raises(MacOSFileAccessContractError):
        validate_binding(row)
    for field, value in [("saved_uid", 503), ("groups", [501, 501]), ("effective_gid", True)]:
        row = credentials(501)
        row[field] = value
        with pytest.raises(MacOSFileAccessContractError):
            validate_credentials(row)


def test_owner_result_cannot_claim_reader_credentials_or_held_read():
    original = request("read_owner")
    row = observation(original)
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)
    row["principal"] = original["binding"]["owner"]
    assert validate_observation(row, original)["outcome"] == "allowed"
    row["held_control"] = deepcopy(row["fresh_read"])
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_handle_cleanup", "unknown"),
        ("held_handle_cleanup", "closed"),
        ("prevention_proven", True),
        ("sequence", True),
    ],
)
def test_primitive_success_needs_exact_join_and_positive_local_closure(field, value):
    original = request()
    row = observation(original)
    row[field] = value
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)


def test_denial_has_no_inode_or_whole_custody_proof():
    original = request()
    row = observation(original, "denied")
    row.update(fresh_read=None, request_handle_cleanup="not_opened")
    assert validate_observation(row, original)["custody"] == "requires_original_creator_evidence"
    row["fresh_read"] = {"inode": 11}
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)


def test_mode_change_is_held_preservation_not_fresh_owner_read():
    original = request("harden")
    row = observation(original, "mode_changed")
    row.update(
        principal=original["binding"]["owner"],
        fresh_read=None,
        request_handle_cleanup="not_opened",
        held_control={
            **{
                field: original["binding"]["resource"][field]
                for field in ("device", "inode", "size_bytes", "record_count", "sha256")
            },
            "before_mode": "0640",
            "after_mode": "0600",
        },
    )
    assert validate_observation(row, original)["fresh_read"] is None
    row["held_control"]["after_mode"] = "0640"
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)


def test_cleanup_unknown_cannot_be_promoted_to_closed():
    original = request("close")
    row = observation(original, "unknown")
    row.update(
        principal=None,
        fresh_read=None,
        held_handle_cleanup="unknown",
        request_handle_cleanup="not_opened",
    )
    assert validate_observation(row, original)["outcome"] == "unknown"
    row["outcome"] = "closed"
    with pytest.raises(MacOSFileAccessContractError):
        validate_observation(row, original)
