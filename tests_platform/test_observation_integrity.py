from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.evidence import EvidenceProvenance, EvidenceRecord, SandboxObserver
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


def test_independently_observed_file_incarnations_do_not_conflict_across_writes() -> None:
    first = _execution()
    second = replace(
        first,
        evidence_id="evidence-second-write",
        timestamp="2026-09-06T12:00:02Z",
        content={**first.content, "output": {"artifact": PATH, "sha256": "b" * 64, "size": 32}},
    )
    second_observation = replace(_observation(sha256="b" * 64), timestamp="2026-09-06T12:00:03Z")
    report = evaluate_observation_integrity([first, _observation(), second, second_observation])
    assert report["satisfied"] is True
    assert report["required_file_count"] == report["verified_file_count"] == 2
    missing_first = evaluate_observation_integrity([first, second, second_observation])
    assert missing_first["satisfied"] is False
    assert missing_first["file_postconditions"][0]["state"] == "observation_unavailable"


def test_managed_schedule_requires_only_the_configured_file_postconditions() -> None:
    report = evaluate_observation_integrity(
        [
            _execution(path="fixtures/input.jsonl"),
            _execution(),
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


def test_managed_postcondition_uses_producer_not_later_transport_output() -> None:
    producer = _execution()
    transport = replace(
        producer,
        evidence_id="evidence-transport",
        action_id="sandbox.network.loopback.v1",
        timestamp="2026-09-06T12:00:00.500Z",
        content={
            "runner_status": "success",
            "expected_observable_paths": [],
            "output": {"artifact": PATH, "sha256": DIGEST, "bytes_sent": 32},
        },
    )
    report = evaluate_observation_integrity(
        [producer, transport, _observation()], configured_file_paths=[PATH]
    )
    assert report["satisfied"] is True
    assert report["file_postconditions"][0]["execution_evidence_id"] == producer.evidence_id


@pytest.mark.parametrize("tampered", [False, True])
@pytest.mark.parametrize("action", ["seed", "marker"])
def test_production_wire_identities_bind_actual_independent_file_reads(
    tmp_path: Path, action: str, tampered: bool
) -> None:
    if action == "seed":
        path = "identity-material/public-canary.json"
        payload = (
            b'{"canary_id":"bluefire-public-identity-canary-v1","classification":"public",'
            b'"material":"synthetic-public-identity-canary","schema_version":'
            b'"bluefire.identity-material.v1","synthetic":true}\n'
        )
        assert len(payload) == 189
        output = {
            "artifact": path,
            "byte_count": 189,
            "classification": "public",
            # Pinned digest of the public fixture above, not authentication material.
            "sha256": "4af6ae2cf13d13d9d325632af3f90d1730faae52424f176b2cc34a0eef0db6ca",  # pragma: allowlist secret
            "synthetic": True,
        }
        action_id = "sandbox.identity-material.seed.v1"
        dimensions = ["path", "sha256", "size_bytes"]
    else:
        path = "restricted/persistence-marker.json"
        payload = (
            b'{"executable":false,"kind":"non_executable_marker",'
            b'"label":"persistence_detection_canary",'
            b'"schema_version":"bluefire.persistence-detection-canary/v1"}\n'
        )
        output = {
            "artifact": path,
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "label": "persistence_detection_canary",
            "executable": False,
        }
        action_id = "sandbox.restricted.persistence-marker.v1"
        dimensions = ["path", "sha256"]
    producer = replace(
        _execution(path=path),
        action_id=action_id,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        content={
            "runner_status": "success",
            "expected_observable_paths": [path],
            "output": output,
        },
    )
    effect = tmp_path / path
    effect.parent.mkdir()
    # Keep the tampered file the same size: only a real digest comparison can fail it.
    effect.write_bytes(
        payload.replace(b"public", b"PUBLIC", 1)
        if tampered and action == "seed"
        else payload.replace(b"marker", b"MARKER", 1) if tampered else payload
    )
    observed = SandboxObserver(tmp_path).observe_file(
        relative_path=path,
        run_id=producer.run_id,
        step_id=producer.step_id,
        behavior_id=producer.behavior_id,
        action_id=action_id,
        runner_profile_id=producer.runner_profile_id,
        parent_evidence_ids=(producer.evidence_id,),
    )
    report = evaluate_observation_integrity([producer, observed])
    assert report["satisfied"] is (not tampered)
    row = report["file_postconditions"][0]
    assert row["state"] == ("conflicting_observation" if tampered else "verified")
    assert row["verified_dimensions"] == ([] if tampered else dimensions)


def test_disabling_filesystem_does_not_establish_final_file_effect() -> None:
    report = evaluate_observation_integrity([_execution()], configured_file_paths=[])
    assert report["satisfied"] is False
    assert report["final_file_effect_paths"] == [PATH]
    assert report["required_file_count"] == 1


def test_observing_only_earlier_fixture_does_not_establish_final_staging() -> None:
    fixture_path = "fixtures/input.jsonl"
    report = evaluate_observation_integrity(
        [_execution(path=fixture_path), _execution(), _observation(path=fixture_path)],
        configured_file_paths=[fixture_path],
    )
    assert report["satisfied"] is False
    assert report["verified_file_count"] == 1
    assert report["required_file_count"] == 2


def test_later_local_export_requires_its_own_observation() -> None:
    export_path = "exports/ephemeral/bundle.bin"
    exported = replace(_execution(path=export_path), action_id="sandbox.export.local.v1")
    records = [_execution(), exported, _observation()]
    report = evaluate_observation_integrity(records, configured_file_paths=[PATH])
    assert report["satisfied"] is False
    assert report["final_file_effect_paths"] == [export_path]
    completed = evaluate_observation_integrity(
        [*records, _observation(path=export_path)], configured_file_paths=[PATH, export_path]
    )
    assert completed["satisfied"] is True


@pytest.mark.parametrize(
    "action_id, output",
    [
        ("sandbox.identity-material.seed.v1", {"byte_count": True, "sha256": DIGEST}),
        ("sandbox.restricted.persistence-marker.v1", {"sha256": "sha256:sha256:" + DIGEST}),
    ],
)
def test_malformed_reviewed_size_or_digest_is_not_a_file_identity(
    action_id: str, output: dict
) -> None:
    execution = replace(
        _execution(),
        action_id=action_id,
        content={
            "runner_status": "success",
            "expected_observable_paths": [PATH],
            "output": {"artifact": PATH, **output},
        },
    )
    report = evaluate_observation_integrity([execution, _observation()])
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
