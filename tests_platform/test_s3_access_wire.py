"""Worker framing tests, not native containment or live credential tests."""

from datetime import datetime, timedelta, timezone

import pytest

from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_policy import plan_hardening
from bluefire.s3_access_wire import (
    S3Credentials,
    S3WorkerHandshake,
    S3WorkerRequest,
    decode_frame,
    encode_frame,
    permit_request,
    validate_permit,
)
from tests_platform.test_s3_access_policy import fixture

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


def request_row(operation="inspect_policy"):
    scope, policy = fixture()
    mutation = operation in {"apply_policy", "rollback_policy"}
    return {
        "schema_version": "bluefire.s3-worker-request.v1",
        "launch_id": "a" * 64,
        "request_id": "b" * 64,
        "worker_generation": "sha256:" + "c" * 64,
        "runtime_digest": "sha256:" + "d" * 64,
        "scope": scope.to_dict(),
        "scope_digest": scope.digest,
        "operation": operation,
        "policy_change": plan_hardening(scope, policy).to_dict()
        if mutation or operation == "reconcile_policy" else None,
        "deadline": (NOW + timedelta(seconds=30)).isoformat(),
        "max_sends": {
            "inspect_policy": 2,
            "reconcile_policy": 2,
            "apply_policy": 4,
            "rollback_policy": 4,
            "probe_read": 4,
            "legitimate_read": 5,
        }[operation],
        "exclusive_writer_digest": "sha256:" + "e" * 64 if mutation else None,
    }


def credential_row():
    return {
        "access_key": "ASIA" + "F" * 16,
        "secret_key": "S" * 40,
        "token": "T" * 64,
        "expires_at": (NOW + timedelta(seconds=900)).isoformat(),
    }


def credentials():
    return S3Credentials.from_mapping(
        credential_row(), clock=lambda: NOW, deadline=NOW + timedelta(seconds=30)
    )


def acknowledge(send):
    return {
        "kind": "permit",
        **{key: send[key] for key in ("request_digest", "sequence", "send_digest")},
    }


@pytest.mark.parametrize(
    "operation",
    ["inspect_policy", "reconcile_policy", "apply_policy", "rollback_policy", "probe_read", "legitimate_read"],
)
def test_request_roundtrip_is_exact_and_revalidated(operation):
    row = request_row(operation)
    request = S3WorkerRequest.from_mapping(row)
    request.assert_current(lambda: NOW)
    assert (
        S3WorkerRequest.from_mapping(decode_frame(encode_frame(request.to_dict()))).digest
        == request.digest
    )
    row["scope"]["roles"]["controller"] = "bad"
    assert request.to_dict()["scope"]["roles"]["controller"] != "bad"


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_digest", ""),
        ("worker_generation", "bad"),
        ("launch_id", "A" * 64),
        ("request_id", "b"),
        ("scope_digest", "sha256:" + "0" * 64),
        ("max_sends", True),
        ("max_sends", 0),
        ("max_sends", 3),
        ("operation", "arbitrary"),
        ("deadline", "2026-10-09T00:00:30"),
        ("exclusive_writer_digest", "sha256:" + "a" * 64),
        ("policy_change", {}),
    ],
)
def test_request_rejects_invalid_or_widened_fields(field, value):
    row = request_row()
    row[field] = value
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(row)


def test_request_rejects_raw_dataclass_bypass_and_scope_drift():
    row = request_row()
    row["scope"]["bucket"] = "other-bucket"
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(row)
    forged = S3WorkerRequest(encode_frame(row))
    with pytest.raises(S3AccessError):
        forged.assert_current(lambda: NOW)
    assert S3AccessScope.from_mapping(request_row()["scope"])


@pytest.mark.parametrize("offset", [-1, 30, 31])
def test_request_deadline_is_checked_with_injected_clock(offset):
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(request_row()).assert_current(
            lambda: NOW + timedelta(seconds=offset)
        )


@pytest.mark.parametrize(
    "payload",
    [b"{}", b"{}\n{}\n", b'{"a":1,"a":2}\n', b"[]\n", b"{}\n\n", b"x" * 81921 + b"\n"],
    ids=["missing-newline", "two-frames", "duplicate-key", "array", "blank-line", "oversized"],
)
def test_frames_are_bounded_one_line_strict_json(payload):
    with pytest.raises(S3AccessError):
        decode_frame(payload)


def handshake():
    return S3WorkerHandshake(
        S3WorkerRequest.from_mapping(request_row()),
        process_id=123,
        creation_identity="456",
        nonce="f" * 64,
    )


def private_frame(hand):
    return encode_frame(
        {
            "kind": "credentials",
            "request_digest": hand.ready()["request_digest"],
            "nonce": hand.ready()["nonce"],
            "credentials": credential_row(),
        }
    )


def test_credential_frame_requires_matching_single_use_containment_ack():
    hand = handshake()
    with pytest.raises(S3AccessError):
        hand.accept_credentials(private_frame(hand), clock=lambda: NOW)
    hand.accept_containment_ack({**hand.ready(), "kind": "contained"})
    secret = hand.accept_credentials(private_frame(hand), clock=lambda: NOW)
    assert secret.access_key == credential_row()["access_key"]
    assert secret.secret_key not in repr(secret)
    with pytest.raises(S3AccessError):
        hand.accept_credentials(private_frame(hand), clock=lambda: NOW)


@pytest.mark.parametrize(
    "field,value",
    [
        ("process_id", 124),
        ("creation_identity", "457"),
        ("nonce", "0" * 64),
        ("request_digest", "sha256:" + "0" * 64),
    ],
)
def test_wrong_containment_ack_closes_protocol(field, value):
    hand = handshake()
    row = {**hand.ready(), "kind": "contained", field: value}
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack(row)
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack({**hand.ready(), "kind": "contained"})


@pytest.mark.parametrize("malformed", [b'{"x":1,"x":2}', b"invalid", [], None])
def test_malformed_containment_ack_terminally_closes_protocol(malformed):
    hand = handshake()
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack(malformed)
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack({**hand.ready(), "kind": "contained"})


def test_containment_ack_does_not_accept_float_process_identity():
    hand = handshake()
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack({**hand.ready(), "kind": "contained", "process_id": 123.0})
    with pytest.raises(S3AccessError):
        hand.accept_containment_ack({**hand.ready(), "kind": "contained"})


@pytest.mark.parametrize(
    "field,value",
    [
        ("access_key", "short"),
        ("secret_key", "secret with spaces"),
        ("token", "T" * 12289),
        ("expires_at", "2026-10-09T00:00:29Z"),
        ("expires_at", "2026-10-09T00:15:01Z"),
    ],
)
def test_credential_shape_and_lifetime_are_bounded(field, value):
    row = credential_row()
    row[field] = value
    with pytest.raises(S3AccessError):
        S3Credentials.from_mapping(row, clock=lambda: NOW, deadline=NOW + timedelta(seconds=30))


def test_wrong_private_nonce_consumes_handshake_without_echoing_secret():
    hand = handshake()
    hand.accept_containment_ack({**hand.ready(), "kind": "contained"})
    row = decode_frame(private_frame(hand))
    row["nonce"] = "0" * 64
    with pytest.raises(S3AccessError) as caught:
        hand.accept_credentials(encode_frame(row), clock=lambda: NOW)
    assert credential_row()["secret_key"] not in str(caught.value)
    with pytest.raises(S3AccessError):
        hand.accept_credentials(private_frame(hand), clock=lambda: NOW)


def test_permit_is_exact_sequence_and_send_digest():
    request = S3WorkerRequest.from_mapping(request_row())
    send = permit_request(request, 1, {"operation": "GetCallerIdentity"})
    validate_permit(acknowledge(send), send)
    for field in ("request_digest", "sequence", "send_digest"):
        invalid = acknowledge(send)
        invalid[field] = None
        with pytest.raises(S3AccessError):
            validate_permit(invalid, send)
    with pytest.raises(S3AccessError):
        permit_request(request, 3, {})


@pytest.mark.parametrize("sequence", [True, 1.0, "1"])
def test_permit_sequence_requires_integer_type(sequence):
    send = permit_request(S3WorkerRequest.from_mapping(request_row()), 1, {})
    with pytest.raises(S3AccessError):
        validate_permit({**acknowledge(send), "sequence": sequence}, send)
