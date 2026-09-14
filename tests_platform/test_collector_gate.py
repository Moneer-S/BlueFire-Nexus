from __future__ import annotations

import copy
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.collector_gate as collector_gate
import bluefire.collector_gate_validation as collector_gate_validation
import bluefire.product_gates as product_gates
from bluefire.collector_gate_validation import (
    CollectorGateValidationError,
    validate_persisted_collectors,
)
from bluefire.collector_journey import (
    COMPARISON_REPORT,
    JOURNEY_REPORT,
    produce_collector_evidence,
)
from bluefire.collectors import CollectionSession, FilesystemCollector, NativeProcessCollector
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.run_store import RunStore
from bluefire.util import canonical_json_bytes, content_hash, file_hash

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Gate 05 executes the packaged Windows runner artifact",
)


@pytest.fixture(scope="module")
def collector_evidence_template(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Mapping[str, object]]:
    evidence = tmp_path_factory.mktemp("gate05-template") / "evidence"
    evidence.mkdir()
    summary = produce_collector_evidence(Path.cwd(), evidence)
    return evidence, summary


@pytest.fixture
def collector_evidence(
    collector_evidence_template: tuple[Path, Mapping[str, object]],
    tmp_path: Path,
) -> tuple[Path, Mapping[str, object]]:
    template, summary = collector_evidence_template
    evidence = tmp_path / "evidence"
    shutil.copytree(template, evidence)
    return evidence, summary


def _append_bundle_evidence(
    evidence_dir: Path,
    run_id: str,
    record: EvidenceRecord,
) -> None:
    bundle = evidence_dir / "runs" / run_id
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["records"].append(record.to_dict())
    evidence_path.write_bytes(canonical_json_bytes(evidence) + b"\n")

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["evidence.json"] = {
        "hash": file_hash(evidence_path),
        "size_bytes": evidence_path.stat().st_size,
    }
    manifest["bundle_hash"] = content_hash(manifest["files"])
    manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")


def _write_bundle_json(
    evidence_dir: Path,
    run_id: str,
    name: str,
    value: Mapping[str, Any],
) -> None:
    bundle = evidence_dir / "runs" / run_id
    target = bundle / name
    target.write_bytes(canonical_json_bytes(value) + b"\n")
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][name] = {
        "hash": file_hash(target),
        "size_bytes": target.stat().st_size,
    }
    manifest["bundle_hash"] = content_hash(manifest["files"])
    manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")


def _write_journey(evidence_dir: Path, journey: Mapping[str, Any]) -> None:
    (evidence_dir / JOURNEY_REPORT).write_text(
        json.dumps(journey, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _replay_context(
    evidence_dir: Path,
) -> tuple[
    dict[str, Any],
    Mapping[str, Any],
    tuple[EvidenceRecord, ...],
    CollectionSession,
]:
    journey = json.loads((evidence_dir / JOURNEY_REPORT).read_text(encoding="utf-8"))
    run_id = journey["run_ids"][1]
    run = RunStore(evidence_dir / "runs").get_run(run_id)
    rows = run["evidence"]["records"]
    records = tuple(EvidenceRecord.from_mapping(row) for row in rows)
    session = CollectionSession.from_mapping(journey["replay_session"])
    return journey, run, records, session


def test_collector_journey_produces_real_verified_runs_and_all_checks(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, summary = collector_evidence
    checks, bundles = validate_persisted_collectors(Path.cwd(), evidence)

    assert summary["status"] == "passed"
    assert summary["run_count"] == 2
    assert len(bundles) == 2
    assert all(checks.values())


def test_collector_gate_workflow_is_registered() -> None:
    assert product_gates._WORKFLOWS["GATE-05"] is product_gates._gate_05_workflow


def test_collector_helper_preserves_exact_windows_architecture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    captured: dict[str, str] = {}

    def bounded_helper(
        _command: list[str],
        *,
        repository: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> tuple[int, bytes]:
        assert repository == Path.cwd()
        assert timeout_seconds == 180
        captured.update(environment)
        return 0, json.dumps(
            {
                "schema_version": "bluefire.gate-05-helper.v1",
                "status": "passed",
                "reports": [
                    "gate05-collector-journey.json",
                    "gate05-platform-readiness.json",
                    "gate05-collector-comparison.json",
                    "gate05-corruption-refusal.json",
                ],
                "run_count": 2,
            }
        ).encode("utf-8")

    monkeypatch.setattr(collector_gate, "_run_bounded_helper_process", bounded_helper)
    outcome = collector_gate._run_helper(Path.cwd(), evidence)

    assert outcome["passed"] is True
    assert captured["PROCESSOR_ARCHITECTURE"] in {"AMD64", "ARM64"}


def test_collector_validation_refuses_rewritten_comparison(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    comparison_path = evidence / COMPARISON_REPORT
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    comparison["deltas"][0]["collector_session_delta"]["observation_delta"] = 99
    comparison_path.write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CollectorGateValidationError, match="does not match"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_evidence_from_another_run(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    run_id = journey["run_ids"][0]
    _append_bundle_evidence(
        evidence,
        run_id,
        EvidenceRecord.create(
            run_id="run-not-the-containing-bundle",
            step_id="audit",
            behavior_id="collection.independent-observation.v1",
            provenance=EvidenceProvenance.UNKNOWN,
            producer="bluefire.gate05-audit.v1",
            content={"artifact_type": "audit-probe"},
            target_scope_ref="runner-profile:collector-gate.v1",
        ),
    )

    with pytest.raises(CollectorGateValidationError, match="belongs to a different run"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_untracked_collector_evidence(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    run_id = journey["run_ids"][0]
    _append_bundle_evidence(
        evidence,
        run_id,
        EvidenceRecord.create(
            run_id=run_id,
            step_id="observe_effects",
            behavior_id="collection.independent-observation.v1",
            action_id="sandbox.collection.stage.v1",
            provenance=EvidenceProvenance.OBSERVED,
            producer=FilesystemCollector.descriptor.id,
            runner_profile_id="collector-gate.v1",
            content={
                "artifact_type": "collector_observation",
                "observation_key": "filesystem/untracked.txt",
                "observation_kind": "filesystem",
                "observed_fields": {"path": "untracked.txt"},
            },
            target_scope_ref="runner-profile:collector-gate.v1",
        ),
    )

    with pytest.raises(CollectorGateValidationError, match="does not match persisted"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_rewritten_builtin_descriptor(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, _run, _records, _session = _replay_context(evidence)
    replay_session = journey["replay_session"]
    result = replay_session["results"][FilesystemCollector.descriptor.id]
    result["descriptor"]["name"] = "Untrusted filesystem observer"
    session_body = dict(replay_session)
    session_body.pop("session_hash")
    replay_session["session_hash"] = content_hash(session_body)
    _write_journey(evidence, journey)

    with pytest.raises(CollectorGateValidationError, match="exact built-in collector descriptor"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_filesystem_not_bound_to_stage_bundle(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, run, records, session = _replay_context(evidence)
    rewritten_run = copy.deepcopy(run)
    stage = next(step for step in rewritten_run["steps"] if step["step_id"] == "stage_evidence")
    original_digest = stage["artifacts"]["bundle"]["sha256"]
    stage["artifacts"]["bundle"]["sha256"] = "0" * 64 if original_digest != "0" * 64 else "1" * 64

    with pytest.raises(CollectorGateValidationError, match="filesystem observation"):
        collector_gate_validation._validate_filesystem_binding(
            rewritten_run,
            records,
            session,
            journey["predicted_fields"],
        )


def test_collector_validation_refuses_rewritten_process_prediction(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, _run, _records, _session = _replay_context(evidence)
    journey["predicted_fields"]["process/native-child"]["process_id"] += 1
    _write_journey(evidence, journey)

    with pytest.raises(CollectorGateValidationError, match="process prediction"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_invalid_native_process_identity(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, run, records, session = _replay_context(evidence)
    source_result = session.results[NativeProcessCollector.descriptor.id]
    source = source_result.records[0]
    rewritten_fields = dict(source.content["observed_fields"])
    rewritten_fields["creation_identity"] = "not-decimal"
    rewritten = EvidenceRecord.create(
        run_id=source.run_id,
        step_id=source.step_id,
        behavior_id=source.behavior_id,
        action_id=source.action_id,
        provenance=source.provenance,
        producer=source.producer,
        runner_profile_id=source.runner_profile_id,
        environment=source.environment,
        timestamp=source.timestamp,
        parent_evidence_ids=source.parent_evidence_ids,
        content={**source.content, "observed_fields": rewritten_fields},
        confidence=source.confidence,
        limitations=source.limitations,
        target_scope_ref=source.target_scope_ref,
    )
    rewritten_results = dict(session.results)
    rewritten_results[NativeProcessCollector.descriptor.id] = replace(
        source_result,
        records=(rewritten,),
    )
    rewritten_session = CollectionSession(
        settings=session.settings,
        results=rewritten_results,
    )
    rewritten_records = tuple(
        rewritten if record.evidence_id == source.evidence_id else record for record in records
    )
    rewritten_run = copy.deepcopy(run)
    step = next(row for row in rewritten_run["steps"] if row["step_id"] == source.step_id)
    step["evidence_ids"] = [
        rewritten.evidence_id if evidence_id == source.evidence_id else evidence_id
        for evidence_id in step["evidence_ids"]
    ]

    with pytest.raises(CollectorGateValidationError, match="creation identity"):
        collector_gate_validation._validate_process_binding(
            rewritten_run,
            rewritten_records,
            rewritten_session,
            journey["predicted_fields"],
            journey["execution"]["runner_platform"],
        )


def test_collector_validation_refuses_receiver_process_identity_mismatch(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, run, records, session = _replay_context(evidence)
    predicted_fields = copy.deepcopy(journey["predicted_fields"])
    predicted_fields["process/native-child"]["parent_process_id"] += 1

    with pytest.raises(CollectorGateValidationError, match="receiver process identity"):
        collector_gate_validation._validate_receiver_bindings(
            run,
            records,
            session,
            journey["receiver"],
            predicted_fields,
        )


def test_collector_validation_refuses_rewritten_receiver_summary(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, _run, _records, _session = _replay_context(evidence)
    journey["receiver"]["summary"]["requests_accepted"] = 0
    _write_journey(evidence, journey)

    with pytest.raises(CollectorGateValidationError, match="receiver report"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_rewritten_receiver_binding(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey, _run, _records, _session = _replay_context(evidence)
    journey["receiver"]["accepted_artifact_bindings"][0]["bytes_received"] += 1
    _write_journey(evidence, journey)

    with pytest.raises(CollectorGateValidationError, match="receiver report"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_semantically_rehashed_policy_authority(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    replay_run_id = journey["run_ids"][1]
    policy_path = evidence / "runs" / replay_run_id / "policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    authority = policy["approval_context"]["collector_registry_authority"]
    authority["backends"][0]["implementation_id"] = "untrusted.collectors.Filesystem"
    authority_body = dict(authority)
    authority_body.pop("authority_hash")
    authority["authority_hash"] = content_hash(authority_body)
    _write_bundle_json(evidence, replay_run_id, "policy.json", policy)

    with pytest.raises(CollectorGateValidationError, match="backend is not canonical"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_binds_receiver_authority_to_authenticated_session(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    replay_run_id = journey["run_ids"][1]
    result_path = evidence / "runs" / replay_run_id / "result.json"
    policy_path = evidence / "runs" / replay_run_id / "policy.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    authority = policy["approval_context"]["collector_registry_authority"]
    receiver = next(
        backend
        for backend in authority["backends"]
        if backend["collector_id"] == "collector.network.loopback-receiver.v1"
    )
    receiver["source_authority"]["session_id"] = "8" * 64
    receiver["source_authority_hash"] = content_hash(receiver["source_authority"])
    authority_body = dict(authority)
    authority_body.pop("authority_hash")
    authority["authority_hash"] = content_hash(authority_body)
    policy["approval_context"]["replay"]["collector_authority_to"] = copy.deepcopy(authority)
    result["replay"]["collector_authority_to"] = copy.deepcopy(authority)
    _write_bundle_json(evidence, replay_run_id, "result.json", result)
    _write_bundle_json(evidence, replay_run_id, "policy.json", policy)

    with pytest.raises(CollectorGateValidationError, match="source authority"):
        validate_persisted_collectors(Path.cwd(), evidence)


@pytest.mark.parametrize("field", ["source_run_id", "collector_settings_from"])
def test_collector_validation_refuses_rehashed_replay_source_lineage(
    collector_evidence: tuple[Path, Mapping[str, object]],
    field: str,
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    replay_run_id = journey["run_ids"][1]
    result_path = evidence / "runs" / replay_run_id / "result.json"
    policy_path = evidence / "runs" / replay_run_id / "policy.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    replacement = replay_run_id if field == "source_run_id" else "sha256:" + "0" * 64
    result["replay"][field] = replacement
    policy["approval_context"]["replay"][field] = replacement
    _write_bundle_json(evidence, replay_run_id, "result.json", result)
    _write_bundle_json(evidence, replay_run_id, "policy.json", policy)

    with pytest.raises(CollectorGateValidationError, match="exact source and collector settings"):
        validate_persisted_collectors(Path.cwd(), evidence)


def test_collector_validation_refuses_truncated_replay_lineage(
    collector_evidence: tuple[Path, Mapping[str, object]],
) -> None:
    evidence, _summary = collector_evidence
    journey = json.loads((evidence / JOURNEY_REPORT).read_text(encoding="utf-8"))
    replay_run_id = journey["run_ids"][1]
    result_path = evidence / "runs" / replay_run_id / "result.json"
    policy_path = evidence / "runs" / replay_run_id / "policy.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    result["replay"].pop("defense_change")
    policy["approval_context"]["replay"].pop("defense_change")
    _write_bundle_json(evidence, replay_run_id, "result.json", result)
    _write_bundle_json(evidence, replay_run_id, "policy.json", policy)

    with pytest.raises(CollectorGateValidationError, match="exact source and collector settings"):
        validate_persisted_collectors(Path.cwd(), evidence)
