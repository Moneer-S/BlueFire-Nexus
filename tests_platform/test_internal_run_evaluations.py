"""Real collector/software tests; no claim of installed or live-method proof."""

import threading
from dataclasses import replace

import pytest

from bluefire import detection_internal_evaluation as engine
from bluefire.application_errors import APIError
from bluefire.detections import DetectionCandidate, DetectionError, DetectionState
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.service import BlueFireService
from tests_platform.test_detection_evaluations import ROOT, evaluate, observed_run
from tests_platform.test_detection_evaluations import service as service


def internal_candidate(service, selection=None):
    result = service.upsert_detection_hypothesis(
        {
            "behavior_id": "sandbox.collection.stage.v1",
            "title": "Structured staging rule",
            "target_language": "internal",
            "logsource": {"category": "file_event", "product": "generic"},
            "selection": selection
            or {"artifact_type": "collector_observation", "path|contains": "staged/"},
            "provenance": {"source": "internal-evaluation-software-test"},
        }
    )
    identity = result["candidate"]["id"]
    service.parse_detection_candidate(identity, {})
    return identity


def candidate_document(service, identity):
    return DetectionCandidate.from_mapping(
        service.detection_candidate(identity)["candidate"]["document"]
    )


def record(content, index=0):
    return EvidenceRecord.create(
        run_id="run-20260906T120000Z-0123456789abcdef",
        step_id=f"step-{index}",
        behavior_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="authored-test-observation",
        content=content,
        target_scope_ref="software-test",
    )


def test_same_internal_revision_records_multiple_runs_without_lifecycle_rewrite(service, tmp_path):
    identity = internal_candidate(service)
    first_run, records = observed_run(service, tmp_path)
    service.exercise_detection_observed(identity, {"run_id": first_run})
    before = service.detection_candidate(identity)
    assert before["candidate"]["document"]["state"] == "observed_exercised"
    old_run = service.store.get_run(first_run)
    first = evaluate(service, identity, first_run)
    second_run, _ = observed_run(service, tmp_path, path="safe/variation.txt")
    second = evaluate(service, identity, second_run, "benign")
    again = evaluate(service, identity, first_run)
    assert first["result"]["matched_evidence_ids"] == [records[0].evidence_id]
    assert first["result"]["matched_evidence_hashes"] == {
        records[0].evidence_id: records[0].record_hash
    }
    assert second["result"]["state"] == "not_matched"
    assert second["result"]["match_count"] == 0
    assert again["evaluation_id"] != first["evaluation_id"]
    assert first["candidate"]["query_sha256"] is None
    assert first["candidate"]["source_sha256"] is None
    assert (
        first["candidate"]["definition_digest"]
        == before["candidate"]["document"]["definition_digest"]
    )
    assert first["backend"]["semantics"] == "typed-json-conjunction.v1"
    assert first["backend"]["name"] == "bluefire-structured-matcher"
    assert service.detection_candidate(identity) == before
    assert service.store.get_run(first_run) == old_run
    assert len(service.detection_run_evaluations(identity)["evaluations"]) == 3
    reopened = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        assert reopened.detection_run_evaluations(identity) == service.detection_run_evaluations(
            identity
        )
    finally:
        reopened.close()
    # The old lifecycle transition is still single-use, not an evaluation shortcut.
    with pytest.raises(APIError):
        service.exercise_detection_observed(identity, {"run_id": second_run})


def test_real_tune_changes_same_observations_and_retains_prior_miss(service, tmp_path):
    identity = internal_candidate(service, {"path": "staged/discovery.tar"})
    run_id, _ = observed_run(service, tmp_path)
    missed = evaluate(service, identity, run_id)
    child = service.tune_detection_candidate(
        identity,
        {
            "reason": "Record staging uses a different suffix.",
            "selection": {"path|contains": "staged/"},
        },
    )["candidate"]["id"]
    service.parse_detection_candidate(child, {})
    hit = evaluate(service, child, run_id)
    variation, _ = observed_run(service, tmp_path, path="staged/variation.json")
    assert evaluate(service, child, variation)["result"]["state"] == "matched"
    assert missed["result"]["state"] == "not_matched"
    assert hit["result"]["state"] == "matched"
    assert missed["source"] == hit["source"]
    assert missed["candidate"]["definition_digest"] != hit["candidate"]["definition_digest"]
    assert service.detection_run_evaluations(identity)["evaluations"] == [missed]


@pytest.mark.parametrize(
    "options", [{"missing": True}, {"synthetic_only": True}, {"unobserved_postcondition": True}]
)
def test_missing_unknown_and_unobserved_sources_never_become_zero_matches(
    service, tmp_path, options
):
    identity = internal_candidate(
        service, {"path|contains": "staged/", "path|endswith": ".jsonl", "nested.value": 1}
    )
    run_id, _ = observed_run(service, tmp_path, **options)
    result = evaluate(service, identity, run_id)
    assert result["result"]["state"] == "insufficient_evidence"
    assert result["result"]["match_count"] is None
    assert result["backend"]["executed"] is False
    assert result["result"]["mapped_fields"] == ["nested.value", "path"]
    assert service.detection_run_evaluations(identity)["evaluations"] == [result]


def test_missing_fields_only_exclude_decidably_unrelated_records(service):
    identity = internal_candidate(
        service, {"artifact_type": "collector_observation", "nested.flag": True}
    )
    candidate = candidate_document(service, identity)
    rows = [
        record({"artifact_type": "file_observation"}),
        record({"artifact_type": "collector_observation", "nested": {"flag": True}}, 1),
    ]
    result = engine.execute_internal(candidate, rows)
    assert result["matched_evidence_ids"] == [rows[1].evidence_id]
    assert result["missing_fields"] == []
    rows.append(record({"artifact_type": "collector_observation"}, 2))
    result = engine.execute_internal(candidate, rows)
    assert result["missing_fields"] == ["nested.flag"]
    assert result["matched_evidence_ids"] == []


@pytest.mark.parametrize("record_kind", ["artifact_type", "observation_kind"])
def test_record_kind_boolean_mismatch_uses_strict_field_validation(service, record_kind):
    candidate = candidate_document(service, internal_candidate(service, {record_kind: True}))
    with pytest.raises(DetectionError, match="boolean field"):
        engine.execute_internal(candidate, [record({record_kind: 1})])


@pytest.mark.parametrize("record_kind", ["artifact_type", "observation_kind"])
def test_record_kind_values_obey_comparison_byte_limit(service, record_kind):
    candidate = candidate_document(service, internal_candidate(service, {record_kind: "expected"}))
    oversized = "x" * (engine.INTERNAL_LIMITS["value_bytes"] + 1)
    with pytest.raises(DetectionError, match="comparison byte limit"):
        engine.execute_internal(candidate, [record({record_kind: oversized})])


@pytest.mark.parametrize("record_kind", ["artifact_type", "observation_kind"])
def test_valid_record_kind_nonmatch_remains_a_negative_result(service, record_kind):
    candidate = candidate_document(service, internal_candidate(service, {record_kind: "expected"}))
    result = engine.execute_internal(candidate, [record({record_kind: "other"})])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == []


def test_record_kind_mismatch_still_excludes_permission_gaps(service):
    candidate = candidate_document(
        service,
        internal_candidate(
            service, {"artifact_type": "collector_observation", "other_write_bit": True}
        ),
    )
    unrelated = record({"artifact_type": "file_observation"})
    observed = record({"artifact_type": "collector_observation", **permission_content("0666")}, 1)
    result = engine.execute_internal(candidate, [unrelated, observed])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == [observed.evidence_id]


def test_record_kind_mismatches_across_rows_obey_aggregate_comparison_budget(service, monkeypatch):
    expected = "x" * 60_000
    candidate = candidate_document(
        service, internal_candidate(service, {"artifact_type": expected})
    )
    per_comparison = len(engine.canonical_json_bytes("other")) + len(
        engine.canonical_json_bytes(expected)
    )
    assert per_comparison < engine.INTERNAL_LIMITS["value_bytes"]
    monkeypatch.setitem(engine.INTERNAL_LIMITS, "comparison_bytes", 4 * per_comparison)
    record_count = engine.INTERNAL_LIMITS["comparison_bytes"] // per_comparison + 1
    rows = [record({"artifact_type": "other"}, index) for index in range(record_count)]
    encoded_record_bytes = sum(len(engine.canonical_json_bytes(dict(row.content))) for row in rows)
    assert encoded_record_bytes < engine.INTERNAL_LIMITS["record_bytes"]
    with pytest.raises(DetectionError, match="comparison byte limit"):
        engine.execute_internal(candidate, rows)


@pytest.mark.parametrize(
    "selector,target,other",
    [
        ("path", {"path": "target"}, {"path": "different"}),
        ("path|contains", {"path": "staged/target"}, {"path": "safe/different"}),
        ("nested.name", {"nested": {"name": "target"}}, {"nested": {"name": "different"}}),
    ],
)
def test_known_nonpermission_mismatch_excludes_irrelevant_permission_gaps(
    service, selector, target, other
):
    candidate = candidate_document(
        service, internal_candidate(service, {selector: "target", "other_write_bit": True})
    )
    matched = record({**target, **permission_content("0666")})
    unrelated = record(other, 1)
    result = engine.execute_internal(candidate, [matched, unrelated])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == [matched.evidence_id]
    assert result["evaluated_evidence_ids"] == [matched.evidence_id, unrelated.evidence_id]
    # A potentially matching row still makes the entire result undecidable.
    relevant_gap = record(target, 2)
    result = engine.execute_internal(candidate, [matched, unrelated, relevant_gap])
    assert result["missing_fields"] == ["other_write_bit"]
    assert result["matched_evidence_ids"] == []
    undecidable = engine.execute_internal(candidate, [matched, record({}, 3)])
    assert undecidable["missing_fields"] == sorted([selector.partition("|")[0], "other_write_bit"])
    assert undecidable["matched_evidence_ids"] == []


@pytest.mark.parametrize(
    "permission_facts",
    [
        {},
        {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"},
        {"permission_status": "available", "effective_access": "not_evaluated"},
        {"permission_status": "invalid_metadata", "effective_access": "not_evaluated"},
    ],
)
def test_nonpermission_mismatch_excludes_unrelated_unusable_permission_facts(
    service, permission_facts
):
    candidate = candidate_document(
        service, internal_candidate(service, {"path": "target", "permission_status": "available"})
    )
    result = engine.execute_internal(candidate, [record({"path": "different", **permission_facts})])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == []


@pytest.mark.parametrize("value", [0, 1, "false", "true", None])
def test_non_boolean_values_refuse_whole_dataset(service, value):
    identity = internal_candidate(service, {"flag": True})
    with pytest.raises(DetectionError, match="boolean"):
        engine.execute_internal(
            candidate_document(service, identity),
            [record({"flag": True}), record({"flag": value}, 1)],
        )


@pytest.mark.parametrize("status_selector", ["permission_status", "permission_status|contains"])
@pytest.mark.parametrize("access_selector", ["effective_access", "effective_access|contains"])
def test_known_access_mismatch_excludes_unavailable_permission_gap(
    service, status_selector, access_selector
):
    candidate = candidate_document(
        service,
        internal_candidate(service, {status_selector: "available", access_selector: "allowed"}),
    )
    unavailable = record(
        {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"}
    )
    for rows in ([unavailable], [record(permission_content("0666"), 1), unavailable]):
        result = engine.execute_internal(candidate, rows)
        assert result["missing_fields"] == []
        assert result["matched_evidence_ids"] == []
    # A mismatching field never legitimizes an invalid permission group.
    with pytest.raises(DetectionError, match="permission facts"):
        engine.execute_internal(
            candidate,
            [record({"permission_status": "invalid", "effective_access": "not_evaluated"})],
        )


def test_known_permission_mismatch_preserves_other_match_and_relevant_unknown(service):
    candidate = candidate_document(
        service, internal_candidate(service, {"path": "target", "other_write_bit": True})
    )
    matched = record({"path": "target", **permission_content("0666")})
    unrelated = record(permission_content("0640"), 1)
    result = engine.execute_internal(candidate, [matched, unrelated])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == [matched.evidence_id]
    relevant = record(permission_content("0666"), 2)
    result = engine.execute_internal(candidate, [matched, unrelated, relevant])
    assert result["missing_fields"] == ["path"]
    assert result["matched_evidence_ids"] == []


def test_permission_unavailable_is_insufficient_even_when_status_disagrees(service):
    identity = internal_candidate(
        service,
        {
            "artifact_type": "collector_observation",
            "permission_status": "available",
            "other_write_bit": True,
        },
    )
    result = engine.execute_internal(
        candidate_document(service, identity),
        [
            record(
                {
                    "artifact_type": "collector_observation",
                    "permission_status": "unavailable_windows",
                    "effective_access": "not_evaluated",
                }
            )
        ],
    )
    assert result["missing_fields"] == ["other_write_bit", "permission_status"]
    assert result["matched_evidence_ids"] == []


@pytest.mark.parametrize(
    "selector,expected,requires_available,unavailable_matches",
    [
        ("permission_status", "available", True, False),
        ("permission_status|contains", "available", True, False),
        ("permission_status|startswith", "available", True, False),
        ("permission_status|endswith", "available", True, False),
        ("permission_status|contains", "avail", True, False),
        ("permission_status", "unavailable_windows", False, True),
        ("permission_status|contains", "unavailable", False, True),
        ("permission_status|startswith", "unavailable", False, True),
        ("permission_status|endswith", "windows", False, True),
        ("permission_status", ["available"], False, False),
        ("permission_status|contains", ["available"], False, False),
        ("permission_status|endswith", ["available", "unavailable_windows"], False, False),
    ],
)
def test_permission_status_selectors_preserve_availability_and_inspection_semantics(
    service, selector, expected, requires_available, unavailable_matches
):
    candidate = candidate_document(service, internal_candidate(service, {selector: expected}))
    available = record(permission_content("0666"))
    unavailable = record(
        {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"}, 1
    )
    known = engine.execute_internal(candidate, [available])
    assert known["missing_fields"] == []
    assert known["matched_evidence_ids"] == ([available.evidence_id] if requires_available else [])
    result = engine.execute_internal(candidate, [available, unavailable])
    assert result["missing_fields"] == (["permission_status"] if requires_available else [])
    assert result["matched_evidence_ids"] == (
        [unavailable.evidence_id] if unavailable_matches else []
    )
    # Lists retain existing JSON/string operator semantics, not invented OR alternatives.
    assert result["mapped_fields"] == ["permission_status"]


def test_status_operator_unknown_is_persisted_without_partial_matches(service):
    identity = internal_candidate(service, {"permission_status|contains": "available"})
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.unit"},
    )
    rows = [
        EvidenceRecord.create(
            run_id=handle.run_id,
            step_id=f"step-{index}",
            behavior_id="sandbox.collection.stage.v1",
            provenance=EvidenceProvenance.OBSERVED,
            producer="authored-test-observation",
            content=content,
            target_scope_ref="software-test",
        )
        for index, content in enumerate(
            [
                permission_content("0666"),
                {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"},
            ]
        )
    ]
    service.store.finalize(
        handle.run_id,
        result={"status": "completed", "mode": "execute", "steps": []},
        evidence=[row.to_dict() for row in rows],
        detections=[],
    )
    before = service.detection_candidate(identity)
    report = evaluate(service, identity, handle.run_id)
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["match_count"] is None
    assert report["result"]["matched_evidence_ids"] == []
    assert report["result"]["matched_evidence_hashes"] == {}
    assert report["result"]["missing_fields"] == ["permission_status"]
    assert report["result"]["evaluated_evidence_ids"] == [row.evidence_id for row in rows]
    assert service.detection_run_evaluations(identity)["evaluations"] == [report]
    assert service.detection_candidate(identity) == before


@pytest.mark.parametrize(
    "limit,value",
    [
        ("records", 0),
        ("record_bytes", 1),
        ("field_comparisons", 0),
        ("comparison_bytes", 1),
        ("value_bytes", 1),
        ("json_nodes", 1),
        ("json_depth", 0),
        ("deadline_ms", 0),
    ],
)
def test_resource_refusal_has_no_partial_result(service, monkeypatch, limit, value):
    identity = internal_candidate(service, {"flag": True})
    monkeypatch.setitem(engine.INTERNAL_LIMITS, limit, value)
    with pytest.raises(DetectionError):
        engine.execute_internal(candidate_document(service, identity), [record({"flag": True})])


def test_cancellation_parser_binding_and_invalid_json_are_refused(service):
    identity = internal_candidate(service, {"flag": True})
    candidate = candidate_document(service, identity)
    event = threading.Event()
    event.set()
    with pytest.raises(DetectionError, match="cancelled"):
        engine.execute_internal(candidate, [record({"flag": True})], cancel_event=event)
    with pytest.raises(DetectionError, match="parser"):
        engine.execute_internal(replace(candidate, parser_backend={"name": "pretend"}), [])
    with pytest.raises(DetectionError, match="value"):
        engine.execute_internal(
            candidate, [replace(record({"flag": True}), content={"flag": object()})]
        )


def test_cancellation_after_a_match_discards_all_partial_work(service, monkeypatch):
    candidate = candidate_document(service, internal_candidate(service, {"flag": True}))
    event = threading.Event()
    original = engine.matches_value

    def cancel_after_match(*args, **kwargs):
        result = original(*args, **kwargs)
        event.set()
        return result

    monkeypatch.setattr(engine, "matches_value", cancel_after_match)
    with pytest.raises(DetectionError, match="cancelled"):
        engine.execute_internal(
            candidate, [record({"flag": True}), record({"flag": True}, 1)], cancel_event=event
        )


def test_false_boolean_is_a_measured_nonmatch_and_excess_depth_is_refused(service):
    candidate = candidate_document(service, internal_candidate(service, {"flag": True}))
    result = engine.execute_internal(candidate, [record({"flag": False})])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == []
    nested = {"flag": True}
    for _ in range(18):
        nested = {"nested": nested}
    with pytest.raises(DetectionError, match="JSON work"):
        engine.execute_internal(candidate, [record(nested)])


def test_engine_refusal_is_retained_without_partial_matches(service, tmp_path, monkeypatch):
    identity = internal_candidate(service)
    run_id, _ = observed_run(service, tmp_path)
    monkeypatch.setitem(engine.INTERNAL_LIMITS, "record_bytes", 1)
    report = evaluate(service, identity, run_id)
    assert report["result"]["state"] == "backend_error"
    assert report["result"]["match_count"] is None
    assert report["result"]["matched_evidence_ids"] == []
    assert report["result"]["evaluated_evidence_ids"] == []
    assert report["backend"]["executed"] is False
    assert report["result"]["mapped_fields"] == ["artifact_type", "path"]
    assert service.detection_run_evaluations(identity)["evaluations"] == [report]
    assert (
        service.detection_candidate(identity)["candidate"]["status"] == DetectionState.PARSED.value
    )


def permission_content(mode):
    bits = int(mode, 8)
    return {
        "artifact_type": "collector_observation",
        "observation_kind": "filesystem",
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": mode,
        "group_write_bit": bool(bits & 0o020),
        "other_write_bit": bool(bits & 0o002),
        "non_owner_write_bit": bool(bits & 0o022),
    }


@pytest.mark.parametrize("mode,matched", [("0640", False), ("0666", True), ("0660", True)])
def test_coherent_permission_groups_retain_mode_and_strict_bits(service, mode, matched):
    identity = internal_candidate(
        service,
        {
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            "permission_status": "available",
            "non_owner_write_bit": True,
        },
    )
    row = record(permission_content(mode))
    result = engine.execute_internal(candidate_document(service, identity), [row])
    assert result["missing_fields"] == []
    assert result["matched_evidence_ids"] == ([row.evidence_id] if matched else [])


def test_contradictory_permission_group_refuses_and_incomplete_group_is_unknown(service):
    identity = internal_candidate(
        service, {"permission_status": "available", "other_write_bit": True}
    )
    candidate = candidate_document(service, identity)
    contradictory = {**permission_content("0640"), "other_write_bit": True}
    with pytest.raises(DetectionError, match="permission facts"):
        engine.execute_internal(
            candidate, [record(permission_content("0666")), record(contradictory, 1)]
        )
    incomplete = permission_content("0666")
    incomplete.pop("group_write_bit")
    result = engine.execute_internal(candidate, [record(incomplete)])
    assert result["missing_fields"] == ["group_write_bit"]
    assert result["matched_evidence_ids"] == []


@pytest.mark.parametrize("confidence", [0.0, 0.5])
def test_inconclusive_observed_confidence_cannot_create_match_or_negative(service, confidence):
    identity = internal_candidate(service, {"flag": True})
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.unit"},
    )
    rows = [
        EvidenceRecord.create(
            run_id=handle.run_id,
            step_id=f"step-{index}",
            behavior_id="sandbox.collection.stage.v1",
            provenance=EvidenceProvenance.OBSERVED,
            producer="authored-confidence-case",
            content={"flag": flag},
            confidence=quality,
            target_scope_ref="software-test",
        )
        for index, (flag, quality) in enumerate([(True, 1.0), (False, confidence)])
    ]
    service.store.finalize(
        handle.run_id,
        result={"status": "completed", "mode": "execute", "steps": []},
        evidence=[row.to_dict() for row in rows],
        detections=[],
    )
    report = evaluate(service, identity, handle.run_id)
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["match_count"] is None
    assert report["result"]["gap_evidence_ids"] == [rows[1].evidence_id]
    assert report["result"]["matched_evidence_ids"] == []
    assert report["backend"]["executed"] is False
    assert report["result"]["mapped_fields"] == ["flag"]
    assert service.detection_run_evaluations(identity)["evaluations"] == [report]
    assert "source_contains_uncertain_observations" in report["result"]["diagnostic_codes"]
