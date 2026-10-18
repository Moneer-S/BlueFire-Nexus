"""Synthetic shared collector vectors. No worker, credentials, SDK or native effects."""

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bluefire import s3_audit_collection_contract as audit
from bluefire import s3_audit_wire as wire
from bluefire.s3_access_audit import correlate_read_pair
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_wire import (
    S3WorkerHandshake,
    S3WorkerRequest,
    encode_frame,
    validate_result,
)
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_wire import credential_row
from tests_platform.test_s3_audit_collection_contract import collection_row, listing_rows

VECTORS = json.loads(
    (Path(__file__).parents[1] / "runner/tests/fixtures/s3_audit_wire_v3.json").read_text(
        encoding="utf-8"
    )
)


def request_row(phase="baseline"):
    collection = collection_row(phase=phase)
    scope = collection["original_pair"]["reads"][0]["request"]["scope"]
    return {
        "schema_version": wire.REQUEST_SCHEMA,
        "launch_id": collection["launch_id"],
        "request_id": collection["request_id"],
        "worker_generation": collection["source"]["worker_generation"],
        "runtime_digest": collection["source"]["protected_runtime_digest"],
        "scope": scope,
        "scope_digest": S3AccessScope.from_mapping(scope).digest,
        "operation": "collect_audit",
        "policy_change": None,
        "deadline": collection["deadline"],
        "max_sends": 9,
        "exclusive_writer_digest": None,
        "audit": collection,
        "audit_authority_digest": content_hash(collection["source"]),
    }


def observation(case=None):
    case = case or VECTORS["cases"][0]
    raw = request_row(case["phase"])
    scope = S3AccessScope.from_mapping(raw["scope"])
    found = audit.discovery(
        scope,
        raw["audit"],
        request_digest=content_hash(raw),
        reservation_digest=VECTORS["reservation_digest"],
        listings=listing_rows(
            scope, raw["audit"], count=case["candidate_count"], size=case["size_bytes"]
        ),
    )
    delivery = "truncated" if found["durable"]["truncated"] else "incomplete"
    originals = raw["audit"]["original_pair"]["reads"]
    correlation = correlate_read_pair(
        S3WorkerRequest.from_mapping(originals[0]["request"]),
        originals[0]["result"],
        S3WorkerRequest.from_mapping(originals[1]["request"]),
        originals[1]["result"],
        [],
        delivery_state=delivery,
    )
    objects = [
        {
            "selected_index": index,
            "compressed_sha256": "sha256:" + "1" * 64,
            "expanded_sha256": "sha256:" + "2" * 64,
            "expanded_bytes": 14,
            "event_count": 0,
        }
        for index in range(case["selected_count"])
    ]
    plan = wire.operation_plan(raw, selected_count=len(objects))
    calls = [
        {
            "operation": operation,
            "role": role,
            "request_id": f"audit-request-{index}",
            "http_status": 200,
        }
        for index, (_, operation, role) in enumerate(plan)
    ]
    calls[3]["request_id"] = "list-request-0"
    result = {
        "schema_version": wire.RESULT_SCHEMA,
        "request_digest": content_hash(raw),
        "outcome": "observed",
        "problem": None,
        "send_permits_consumed": len(plan),
        "calls": calls,
        "runtime_isolation_proven": False,
        "data": {
            "schema_version": wire.OBSERVATION_SCHEMA,
            "collection_digest": content_hash(raw["audit"]),
            "pair_digest": content_hash(raw["audit"]["original_pair"]),
            "audit_source_digest": raw["audit_authority_digest"],
            "reservation_digest": VECTORS["reservation_digest"],
            "discovery": found["durable"],
            "objects": objects,
            "usage": {
                "sdk_body_bytes": 1000 + len(objects) * case["size_bytes"],
                "compressed_bytes": len(objects) * case["size_bytes"],
                "expanded_bytes": 14 * len(objects),
                "files": len(objects),
                "events": 0,
            },
            "normalized_digest": content_hash(correlation["audit"]),
            "correlations": correlation["correlations"],
            "delivery_state": delivery,
            "effective_access_claim": False,
            "log_integrity_proven": False,
        },
    }
    return raw, found, result


@pytest.mark.parametrize("case_index", [0, 1, 2])
def test_shared_collector_vectors_keep_exact_requests_discovery_send_and_result(case_index):
    case = VECTORS["cases"][case_index]
    raw, found, result = observation(case)
    request = S3WorkerRequest.from_mapping(raw)
    assert request.to_dict() == raw
    assert raw["schema_version"] == VECTORS["request_schema"]
    assert result["schema_version"] == VECTORS["result_schema"]
    assert found["frame"]["prefixes"] == [[VECTORS["prefix"], VECTORS["start_after"]]]
    assert found["durable"]["truncated"] is case["truncated"]
    assert len(found["durable"]["selected"]) == case["selected_count"]
    assert (
        wire.discovery(raw, found["frame"], reservation_digest=VECTORS["reservation_digest"])
        == found["durable"]
    )
    assert validate_result(request, result) == result
    for sequence in range(1, case["actual_sends"] + 1):
        send = wire.planned_send(raw, sequence, committed_discovery=found["durable"])
        if sequence >= 4:
            assert send["host"] == VECTORS["sdk_s3_host"]
        frame = {
            "kind": "send",
            "request_digest": request.digest,
            "sequence": sequence,
            "send": send,
        }
        frame["send_digest"] = content_hash(frame)
        assert (
            wire.validate_send(raw, frame, sequence=sequence, committed_discovery=found["durable"])
            == frame
        )
        assert len(canonical_json_bytes(frame)) + 1 <= VECTORS["send_bytes"]
    assert len(canonical_json_bytes(raw)) + 1 <= VECTORS["request_bytes"]
    assert len(audit.result_frame(result)) <= VECTORS["line_bytes"]
    assert len(canonical_json_bytes(found["durable"])) <= VECTORS["durable_bytes"]
    assert (
        9 * VECTORS["send_bytes"] + 2 * VECTORS["line_bytes"] + 2048 < VECTORS["conversation_bytes"]
    )


@pytest.mark.parametrize("vector_index", [0, 1, 2, 3, 4, 5, 6, 7])
def test_shared_collector_request_refusal_vectors(vector_index):
    raw = request_row()
    vector = VECTORS["request_refusals"][vector_index]
    parts = vector["pointer"].split("/")[1:]
    target = raw
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    target[parts[-1]] = vector["value"]
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(raw)


@pytest.mark.parametrize(
    "change",
    ["unknown", "duplicate", "get_before_discovery", "different_key", "selection", "float_count"],
)
def test_discovery_and_send_refuse_wrong_original_identity_sequence_or_selection(change):
    raw, found, _result = observation()
    if change == "get_before_discovery":
        with pytest.raises(S3AccessError, match="Discovery"):
            wire.planned_send(raw, 5)
        return
    frame = found["frame"]
    if change == "unknown":
        frame["reservation_digest"] = "sha256:" + "f" * 64
    elif change == "duplicate":
        frame["candidates"].append(deepcopy(frame["candidates"][0]))
    elif change == "different_key":
        frame["candidates"][0][1] = "outside.json.gz"
    elif change == "selection":
        frame["selected"] = []
    else:
        frame["completed_list_count"] = 1.0
    with pytest.raises(S3AccessError):
        wire.discovery(raw, frame, reservation_digest=VECTORS["reservation_digest"])


@pytest.mark.parametrize(
    "change",
    ["index", "wire", "expansion", "events", "original", "access", "coverage", "result_size"],
)
def test_observation_refuses_overbudget_rebinding_or_coverage_claims(change):
    raw, _found, result = observation()
    data = result["data"]
    if change == "index":
        data["objects"][0]["selected_index"] = True
    elif change in {"wire", "expansion", "events"}:
        data["usage"][
            {"wire": "sdk_body_bytes", "expansion": "expanded_bytes", "events": "events"}[change]
        ] = (10**9)
    elif change == "original":
        data["correlations"]["probe"]["worker_result_digest"] = "sha256:" + "e" * 64
    elif change == "access":
        data["effective_access_claim"] = True
    elif change == "coverage":
        data["delivery_state"] = "complete"
    else:
        data["normalized_digest"] = "x" * 16384
    with pytest.raises(S3AccessError):
        validate_result(S3WorkerRequest.from_mapping(raw), result)


def test_collector_failed_result_is_not_reconciliation_and_does_not_claim_observations():
    raw, _found, result = observation()
    result.update(
        outcome="failed",
        data=None,
        problem="scoped_operation_failed",
        calls=[],
        send_permits_consumed=0,
    )
    assert validate_result(S3WorkerRequest.from_mapping(raw), result) == result
    result.update(outcome="reconcile_required", problem="write_outcome_unsettled")
    with pytest.raises(S3AccessError):
        validate_result(S3WorkerRequest.from_mapping(raw), result)


@pytest.mark.parametrize("later", ["none", "call", "permit"])
def test_service_failure_ends_the_consumed_send_sequence(later):
    raw, _found, result = observation()
    result.update(outcome="failed", data=None, problem="scoped_operation_failed")
    result["calls"] = result["calls"][:4]
    result["calls"][-1].update(error_code="AccessDenied", http_status=403)
    result["send_permits_consumed"] = 4
    if later == "call":
        result["calls"].append(
            {
                "operation": "GetObject",
                "role": "audit",
                "request_id": "unexpected-later-request",
                "http_status": 200,
            }
        )
        result["send_permits_consumed"] = 5
    elif later == "permit":
        result["send_permits_consumed"] = 5
    request = S3WorkerRequest.from_mapping(raw)
    if later == "none":
        assert validate_result(request, result) == result
    else:
        with pytest.raises(S3AccessError, match="service failure must end"):
            validate_result(request, result)


def test_discovery_ack_is_exact_original_no_bool_alias_or_duplicate_frame():
    raw, found, _result = observation()
    durable = found["durable"]
    ack = {
        "kind": "discovery_committed",
        "request_digest": content_hash(raw),
        "reservation_digest": durable["reservation_digest"],
        "discovery_digest": content_hash(durable),
        "frame_digest": durable["frame_digest"],
        "next_send_sequence": durable["next_send_sequence"],
    }
    wire.validate_discovery_ack(raw, durable, ack)
    for name in ("request_digest", "reservation_digest", "discovery_digest", "frame_digest"):
        bad = {**ack, name: "sha256:" + "f" * 64}
        with pytest.raises(S3AccessError):
            wire.validate_discovery_ack(raw, durable, bad)
    with pytest.raises(S3AccessError):
        S3WorkerRequest.from_mapping(
            b'{"schema_version":"duplicate",' + canonical_json_bytes(raw)[1:]
        )


@pytest.mark.parametrize("change", ["valid", "missing", "malformed", "other_request"])
def test_v3_private_credentials_require_original_reservation_and_never_retain_failed_frame(change):
    request = S3WorkerRequest.from_mapping(request_row())
    handshake = S3WorkerHandshake(request, process_id=123, creation_identity="456", nonce="7" * 64)
    assert handshake.reservation_digest is None
    handshake.accept_containment_ack({**handshake.ready(), "kind": "contained"})
    frame = {
        "kind": "credentials",
        "request_digest": request.digest,
        "nonce": "7" * 64,
        "credentials": credential_row(),
        "reservation_digest": VECTORS["reservation_digest"],
    }
    if change == "missing":
        del frame["reservation_digest"]
    elif change == "malformed":
        frame["reservation_digest"] = "not-a-digest"
    elif change == "other_request":
        frame["request_digest"] = "sha256:" + "f" * 64

    def clock():
        return datetime(2026, 10, 9, 0, 1, 1, tzinfo=timezone.utc)

    if change == "valid":
        handshake.accept_credentials(encode_frame(frame), clock=clock)
        assert handshake.reservation_digest == VECTORS["reservation_digest"]
    else:
        with pytest.raises(S3AccessError):
            handshake.accept_credentials(encode_frame(frame), clock=clock)
        assert handshake.reservation_digest is None
    with pytest.raises(S3AccessError):
        handshake.accept_credentials(encode_frame(frame), clock=clock)


def test_legacy_golden_requests_keep_exact_canonical_bytes_and_digests():
    corpus = json.loads(
        (Path(__file__).parents[1] / "runner/tests/fixtures/s3_access_binding_v1.json").read_text(
            encoding="utf-8"
        )
    )
    for case in corpus["cases"]:
        request = S3WorkerRequest.from_mapping(case["request"])
        assert request.to_dict() == case["request"]
        assert request.digest == case["request_digest"]
        assert canonical_json_bytes(request.to_dict()) == canonical_json_bytes(case["request"])


def test_failed_collector_accepts_configured_smaller_file_ceiling_without_fake_gets():
    raw = request_row()
    raw["audit"]["source"]["audit_limits"]["files"] = 1
    raw["audit_authority_digest"] = content_hash(raw["audit"]["source"])
    request = S3WorkerRequest.from_mapping(raw)
    failed = {
        "schema_version": wire.RESULT_SCHEMA,
        "request_digest": request.digest,
        "outcome": "failed",
        "problem": "scoped_operation_failed",
        "data": None,
        "send_permits_consumed": 0,
        "calls": [],
        "runtime_isolation_proven": False,
    }
    assert validate_result(request, failed) == failed


@pytest.mark.parametrize(
    "instant,accepted",
    [
        ("2026-10-09T00:00:59.500000+00:00", False),
        ("2026-10-09T00:01:00+00:00", True),
        ("2026-10-09T00:01:01+00:00", True),
        ("2026-10-09T00:01:02+00:00", False),
    ],
)
def test_collector_current_check_keeps_narrow_original_issued_and_expiry_bounds(instant, accepted):
    raw = request_row()
    raw["audit"]["source"]["audit_limits"]["seconds"] = 5
    raw["audit"]["deadline"] = raw["deadline"] = "2026-10-09T00:01:02Z"
    raw["audit_authority_digest"] = content_hash(raw["audit"]["source"])
    request = S3WorkerRequest.from_mapping(raw)

    def clock():
        return datetime.fromisoformat(instant)

    if accepted:
        request.assert_current(clock)
    else:
        with pytest.raises(S3AccessError):
            request.assert_current(clock)
