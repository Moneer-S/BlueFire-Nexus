"""Public runtime failure classifications stay typed, bounded, and conservative."""

from __future__ import annotations

import pytest

from bluefire.adaptive_observations import project_runtime_observations
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.util import canonical_json_bytes


def _record(provenance: EvidenceProvenance) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id="run-adaptive-classification",
        step_id="step-1",
        behavior_id="behavior-1",
        provenance=provenance,
        producer="classification-test",
        target_scope_ref="sandbox.workspace",
        content={},
    )


def _project(
    row: dict[str, object], records: list[EvidenceRecord] | None = None
) -> dict[str, object]:
    return project_runtime_observations(
        steps=[row],
        records=records or [],
        alternatives=[],
        artifacts={},
        platform="linux",
        remaining_steps=3,
        remaining_seconds=12.0,
        retries_remaining=1,
    )


@pytest.mark.parametrize(
    "code,expected",
    [
        ("atomic_gzip_timeout", "execution_timeout"),
        ("atomic_gzip_failed", "execution_failure"),
        ("atomic_gzip_write_failed", "execution_failure"),
    ],
)
def test_known_gzip_failures_keep_their_classification_with_unknown_evidence(code, expected):
    record = _record(EvidenceProvenance.UNKNOWN)
    failure = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "error": {"code": code},
            "evidence_ids": [record.evidence_id],
        },
        [record],
    )["attempts"][0]["failure"]
    assert failure["classification"] == expected
    assert failure["telemetry_gap"] is True


@pytest.mark.parametrize("evidence_state", ["observed", "unknown", "missing"])
@pytest.mark.parametrize("code", ["collection_timeout", "private-collection-error"])
def test_collection_timeout_and_telemetry_gap_remain_independent(evidence_state, code):
    record = _record(
        EvidenceProvenance.UNKNOWN if evidence_state == "unknown" else EvidenceProvenance.OBSERVED
    )
    projection = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "error": {"code": code, "message": "private collection output"},
            "evidence_ids": [record.evidence_id],
        },
        [] if evidence_state == "missing" else [record],
    )
    attempt = projection["attempts"][0]
    gap = evidence_state != "observed"
    known_timeout = code == "collection_timeout"
    assert attempt["failure"] == {
        "classification": (
            "execution_timeout"
            if known_timeout
            else "missing_telemetry" if gap else "execution_failure"
        ),
        "code": code if known_timeout else None,
        "unrecognized_code_present": not known_timeout,
        "target_prevention": "not_established",
        "telemetry_gap": gap,
    }
    assert attempt["missing_evidence_count"] == int(evidence_state == "missing")
    encoded = canonical_json_bytes(projection)
    assert b"private-collection-error" not in encoded
    assert b"private collection output" not in encoded


def test_unresolved_evidence_is_missing_telemetry_even_for_success():
    projection = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "success",
            "evidence_ids": ["never-recorded"],
        }
    )
    attempt = projection["attempts"][0]
    assert attempt["failure"]["classification"] == "missing_telemetry"
    assert attempt["failure"]["telemetry_gap"] is True
    assert attempt["missing_evidence_count"] == 1


@pytest.mark.parametrize(
    "code,expected,gap",
    [
        ("transport_error", "runner_transport_failure", True),
        ("runner_transport_failed", "runner_transport_failure", True),
        ("execution_failed", "execution_failure", False),
    ],
)
def test_transport_failure_is_distinct_from_actual_execution_failure(code, expected, gap):
    failure = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "error": {"code": code},
        }
    )["attempts"][0]["failure"]
    assert failure["classification"] == expected
    assert failure["telemetry_gap"] is gap


def test_unrecognized_error_is_sanitized_without_raw_message_or_code_leakage():
    projection = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "error": {"code": "private-provider-code", "message": "secret raw provider output"},
        }
    )
    failure = projection["attempts"][0]["failure"]
    assert failure["classification"] == "execution_failure"
    assert failure["code"] is None
    assert failure["unrecognized_code_present"] is True
    encoded = canonical_json_bytes(projection)
    assert b"private-provider-code" not in encoded
    assert b"secret raw provider output" not in encoded


@pytest.mark.parametrize(
    "code,policy_status,expected",
    [
        ("platform_blocked", "refused", "platform_mismatch"),
        ("target_scope_refused", "allowed", "bluefire_authorization_refusal"),
        ("approval_required", "refused", "bluefire_authorization_refusal"),
        ("action_control_blocked", "control_blocked", "bluefire_control_refusal"),
        ("policy_refused", "refused", "bluefire_authorization_refusal"),
    ],
)
def test_platform_and_authorization_refusals_have_explicit_priority(code, policy_status, expected):
    failure = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "error": {"code": code},
            "policy": {"status": policy_status},
        }
    )["attempts"][0]["failure"]
    assert failure["classification"] == expected
    assert failure["target_prevention"] == "not_established"


def test_observed_record_without_gap_stays_execution_failure_and_success_stays_none():
    observed = _record(EvidenceProvenance.OBSERVED)
    failed = _project(
        {
            "step_id": "step-1",
            "behavior_id": "behavior-1",
            "status": "failed",
            "evidence_ids": [observed.evidence_id],
        },
        [observed],
    )["attempts"][0]["failure"]
    clean = _project({"step_id": "step-1", "behavior_id": "behavior-1", "status": "success"})[
        "attempts"
    ][0]["failure"]
    assert failed["classification"] == "execution_failure"
    assert failed["telemetry_gap"] is False
    assert clean["classification"] == "none"
    assert clean["telemetry_gap"] is False
