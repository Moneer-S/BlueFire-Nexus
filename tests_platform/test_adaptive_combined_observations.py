"""Combined adaptive regression cases using authored software evidence only.

These envelopes and the deterministic provider do not establish host permission
observations, executed gzip operations, or live-provider/experiment evidence.
"""

import pytest

from bluefire.adaptive_record_validation import validate_v4_attempt_record
from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.file_permissions import PERMISSION_FIELDS, PERMISSION_LIMITATION
from bluefire.util import canonical_json_bytes
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_adaptive_runtime import runtime as runtime


def _permissions(*, group_writable=False):
    return {
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": "0660" if group_writable else "0640",
        "group_write_bit": group_writable,
        "other_write_bit": False,
        "non_owner_write_bit": group_writable,
    }


def _record(kwargs, content, provenance=EvidenceProvenance.OBSERVED):
    step = kwargs["current_step"]
    return EvidenceRecord.create(
        run_id=kwargs["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action_id=step.action_id,
        provenance=provenance,
        producer="authored-combined-fixture",
        target_scope_ref="fixture-scope",
        timestamp="2026-09-20T00:00:00Z",
        limitations=("Authored fixture; no host observation or executed operation.",),
        content=content,
    )


def _propose(runtime, records, *, missing=False, error=None):
    kwargs, config = runtime
    references = [record.evidence_id for record in records]
    if missing:
        references.append("unresolved-authored-evidence")
    row = {
        **kwargs["steps"][0],
        "evidence_ids": references,
        "error": error if error is not None else {"code": "atomic_gzip_timeout"},
    }
    provider = Provider(config)
    result = propose_reviewed_method(
        **{**kwargs, "steps": [row], "evidence": records}, provider=provider
    )
    assert result.record["application_status"] == "applied_reviewed_method"
    assert len(provider.requests) == 1
    projection = provider.requests[0].context["observations"]
    assert result.record["planner_state"]["observations"] == projection
    validate_v4_attempt_record(result.record)
    return projection


@pytest.mark.parametrize(
    "gap_source,code,classification",
    [
        ("unknown", "atomic_gzip_timeout", "execution_timeout"),
        ("unresolved", "atomic_gzip_write_failed", "execution_failure"),
    ],
)
def test_permission_evidence_and_known_gzip_failure_survive_telemetry_gap(
    runtime, gap_source, code, classification
):
    kwargs, _ = runtime
    permissions = _permissions(group_writable=True)
    observed = _record(kwargs, {"artifact_type": "file_observation", **permissions})
    records = [observed]
    if gap_source == "unknown":
        records.append(
            _record(kwargs, {"artifact_type": "evidence_gap"}, EvidenceProvenance.UNKNOWN)
        )
    projection = _propose(
        runtime, records, missing=gap_source == "unresolved", error={"code": code}
    )
    attempt = projection["attempts"][0]
    failure = attempt["failure"]
    assert failure["classification"] == classification
    assert failure["code"] == code
    assert failure["telemetry_gap"] is True
    assert failure["target_prevention"] == "not_established"
    assert attempt["missing_evidence_count"] == int(gap_source == "unresolved")
    by_id = {item["evidence_id"]: item for item in attempt["evidence"]}
    assert set(by_id) == {record.evidence_id for record in records}
    for record in records:
        assert by_id[record.evidence_id]["record_hash"] == record.record_hash
        assert by_id[record.evidence_id]["provenance"] == record.provenance.value
    facts = by_id[observed.evidence_id]["facts"]
    assert {key: facts[key] for key in PERMISSION_FIELDS} == permissions
    assert PERMISSION_LIMITATION in projection["unknowns"]


def test_mixed_provenance_cannot_promote_bogus_permissions_to_observations(runtime):
    kwargs, _ = runtime
    permissions = _permissions()
    observed = _record(kwargs, {"artifact_type": "file_observation", **permissions})
    bogus = {**_permissions(group_writable=True), "effective_access": "allowed"}
    reported = [
        _record(
            kwargs,
            {
                "artifact_type": "file_observation",
                **bogus,
                "observed_fields": bogus,
                "output": {**bogus, "size": 120},
            },
            provenance,
        )
        for provenance in (EvidenceProvenance.EXECUTED, EvidenceProvenance.SYNTHETIC)
    ]
    projection = _propose(runtime, [observed, *reported], missing=True)
    attempt = projection["attempts"][0]
    by_id = {item["evidence_id"]: item for item in attempt["evidence"]}
    facts = by_id[observed.evidence_id]["facts"]
    assert {key: facts[key] for key in PERMISSION_FIELDS} == permissions
    for record in reported:
        item = by_id[record.evidence_id]
        assert item["provenance"] == record.provenance.value
        assert item["record_hash"] == record.record_hash
        assert not set(PERMISSION_FIELDS) & item["facts"].keys()
    assert by_id[reported[0].evidence_id]["facts"]["reported_size_bytes"] == 120
    assert "reported_size_bytes" not in by_id[reported[1].evidence_id]["facts"]
    assert attempt["failure"]["classification"] == "execution_timeout"
    assert attempt["failure"]["telemetry_gap"] is True


def test_private_fields_and_unknown_failure_code_are_sanitized_together(runtime):
    kwargs, _ = runtime
    permissions = _permissions(group_writable=True)
    observed = _record(
        kwargs,
        {
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            "path": "/authored-private/fixture",
            "owner": "authored-private-owner",
            "observed_fields": {**permissions, "path": "/authored-private/nested"},
            "output": {"stdout": "authored-private-output"},
        },
    )
    projection = _propose(
        runtime,
        [observed],
        missing=True,
        error={"code": "authored-private-unknown-code", "message": "authored-private-message"},
    )
    attempt = projection["attempts"][0]
    failure = attempt["failure"]
    assert failure["code"] is None
    assert failure["unrecognized_code_present"] is True
    assert failure["classification"] == "missing_telemetry"
    assert failure["telemetry_gap"] is True
    assert failure["target_prevention"] == "not_established"
    assert attempt["evidence"][0]["facts"]["permission_mode_octal"] == "0660"
    encoded = canonical_json_bytes(projection)
    for excluded in (b"authored-private", b'"path"', b'"owner"', b'"stdout"', b'"message"'):
        assert excluded not in encoded


def test_combined_projection_digest_tracks_permission_and_gap_changes(runtime):
    kwargs, _ = runtime

    def project(*, group_writable=False, missing=False):
        observed = _record(
            kwargs,
            {"artifact_type": "file_observation", **_permissions(group_writable=group_writable)},
        )
        return _propose(runtime, [observed], missing=missing)

    baseline = project()
    repeated = project()
    permission_changed = project(group_writable=True)
    gap_changed = project(missing=True)
    assert canonical_json_bytes(baseline) == canonical_json_bytes(repeated)
    assert (
        len(
            {
                projection["projection_digest"]
                for projection in (baseline, permission_changed, gap_changed)
            }
        )
        == 3
    )
    assert baseline["attempts"][0]["evidence"] == gap_changed["attempts"][0]["evidence"]
    for projection, expected_gap in (
        (baseline, False),
        (permission_changed, False),
        (gap_changed, True),
    ):
        failure = projection["attempts"][0]["failure"]
        assert failure["classification"] == "execution_timeout"
        assert failure["telemetry_gap"] is expected_gap
