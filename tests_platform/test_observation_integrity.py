from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.observation_integrity import evaluate_observation_integrity

PATH = "staged/bundle.jsonl"
DIGEST = "a" * 64


def _execution(*, declared: bool = True, path: str = PATH) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id="run-test",
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="sandbox-execute.v1",
        target_scope_ref="runner-profile:sandbox-execute.v1",
        timestamp="2026-09-06T12:00:00Z",
        content={
            "runner_status": "success",
            "expected_observable_paths": [path] if declared else [],
            "output": {"artifact": path, "sha256": DIGEST, "size": 32},
        },
    )


def _observation(**fields: object) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id="run-test",
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="collector.filesystem.sandbox.v1",
        runner_profile_id="sandbox-execute.v1",
        target_scope_ref="runner-profile:sandbox-execute.v1",
        timestamp="2026-09-06T12:00:01Z",
        content={
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            "observed_fields": {"path": PATH, "sha256": DIGEST, "size_bytes": 32, **fields},
        },
    )


def test_success_receipt_without_independent_observation_cannot_complete() -> None:
    report = evaluate_observation_integrity([_execution()])
    assert report["satisfied"] is False
    assert report["file_postconditions"][0]["state"] == "observation_unavailable"


def test_read_only_action_does_not_claim_a_verified_file_effect() -> None:
    report = evaluate_observation_integrity([_execution(declared=False)])
    assert report["satisfied"] is True
    assert report["state"] == "not_required"
    assert report["verified_file_count"] == 0


def test_real_observation_must_bind_the_expected_file_identity() -> None:
    execution, observation = _execution(), _observation()
    report = evaluate_observation_integrity([execution, observation])
    assert report["satisfied"] is True
    assert report["required_file_count"] == report["verified_file_count"] == 1
    assert report["file_postconditions"][0]["observed_evidence_ids"] == [observation.evidence_id]


@pytest.mark.parametrize("fields", [{"sha256": "b" * 64}, {"size_bytes": 33}])
def test_changed_file_does_not_hide_behind_a_successful_runner(fields: dict) -> None:
    report = evaluate_observation_integrity([_execution(), _observation(**fields)])
    assert report["satisfied"] is False
    assert report["file_postconditions"][0]["state"] == "conflicting_observation"


@pytest.mark.parametrize(
    "change",
    [
        {"provenance": EvidenceProvenance.SYNTHETIC},
        {"producer": "bluefire-rust-runner"},
        {"run_id": "run-other"},
        {"runner_profile_id": "profile-other"},
        {"target_scope_ref": "scope-other"},
        {"timestamp": "2026-09-06T11:59:59Z"},
    ],
)
def test_synthetic_unrelated_or_stale_records_are_not_postconditions(change: dict) -> None:
    report = evaluate_observation_integrity([_execution(), replace(_observation(), **change)])
    assert report["satisfied"] is False
    assert report["verified_file_count"] == 0


def test_conflicting_observation_is_not_masked_by_another_matching_record() -> None:
    report = evaluate_observation_integrity(
        [_execution(), _observation(), _observation(sha256="b" * 64)]
    )
    assert report["satisfied"] is False


def test_managed_schedule_requires_only_the_configured_file_postconditions() -> None:
    report = evaluate_observation_integrity(
        [
            _execution(declared=False, path="fixtures/input.jsonl"),
            _execution(declared=False),
            replace(_observation(), step_id="later_collection_step"),
        ],
        configured_file_paths=[PATH],
    )
    assert report["satisfied"] is True
    assert report["required_file_count"] == 1


def test_managed_file_without_executed_producer_fails_visibly() -> None:
    report = evaluate_observation_integrity([_observation()], configured_file_paths=[PATH])
    assert report["satisfied"] is False
    assert report["file_postconditions"][0]["state"] == "producer_identity_unavailable"


def test_telemetry_gap_remains_failure_even_when_file_was_observed() -> None:
    gap = replace(
        _observation(),
        evidence_id="evidence-missing-process",
        provenance=EvidenceProvenance.UNKNOWN,
        content={"artifact_type": "evidence_gap", "requested_artifact": "process/native-child"},
    )
    report = evaluate_observation_integrity([_execution(), _observation(), gap])
    assert report["satisfied"] is False
    assert report["gap_evidence_ids"] == [gap.evidence_id]
    assert report["verified_file_count"] == 1


def test_missing_observation_keeps_product_run_incomplete_after_cleanup(tmp_path: Path) -> None:
    # Exercise the actual orchestration/finalization path with an existing bounded
    # transport double. It returns success receipts but creates no public files.
    from tests_platform.test_orchestrator import (
        FULL_TARGET_SCOPE,
        SCENARIO_PATH,
        StructuredFakeRunner,
        _approval_kwargs,
        _execute_profile,
        _orchestrator,
    )

    orchestrator = _orchestrator(tmp_path, StructuredFakeRunner())
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=tmp_path / "sandbox",
        target_scope=FULL_TARGET_SCOPE,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
        ),
    )
    assert result["status"] == "incomplete"
    assert result["objective_reached"] is False
    assert result["cleanup"]["success"] is True
    assert result["cleanup"]["outstanding_receipt_count"] == 0
    report = result["objective_evaluation"]["observation_integrity"]
    assert report["satisfied"] is False
    assert report["gap_evidence_ids"]
    assert report["required_file_count"] > 0
    assert report["verified_file_count"] == 0
