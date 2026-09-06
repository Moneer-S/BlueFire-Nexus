from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.collector_gate_validation import (
    CollectorGateValidationError,
    _validate_filesystem_binding,
)
from bluefire.collector_journey import _runtime_settings
from bluefire.collectors import (
    CollectionRequest,
    CollectionSession,
    CollectorRuntimeSettings,
    FilesystemCollector,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.observation_integrity import evaluate_observation_integrity

STAGE = "staged/bundle.jsonl"
EXPORT = "exports/ephemeral/bundle.bin"


def test_frontier_collector_observes_the_later_export_without_widening_replay(
    tmp_path: Path,
) -> None:
    baseline = _runtime_settings(
        process_id=10, parent_process_id=9, network_enabled=False, observe_export=True
    )
    replay = _runtime_settings(process_id=10, parent_process_id=9, network_enabled=True)
    collector_id = FilesystemCollector.descriptor.id
    row = baseline.to_dict()["collectors"][collector_id]
    assert row["settings"]["collect_after_step"] == "preserve_approved_copy"
    assert tuple(row["settings"]["paths"]) == (STAGE, EXPORT)
    assert tuple(replay.collectors[collector_id]["settings"]["paths"]) == (STAGE,)
    assert (
        replay.collectors[collector_id]["settings"]["collect_after_step"]
        == "try_internal_transport"
    )
    assert baseline.settings_hash != replay.settings_hash
    payload = b"public collector regression bytes\n"
    digest = hashlib.sha256(payload).hexdigest()
    for path in (STAGE, EXPORT):
        target = tmp_path / path
        target.parent.mkdir(parents=True)
        target.write_bytes(payload)

    def execution(step: str, action: str, path: str) -> EvidenceRecord:
        return EvidenceRecord.create(
            run_id="run-unit",
            step_id=step,
            behavior_id=action,
            action_id=action,
            provenance=EvidenceProvenance.EXECUTED,
            producer="bluefire-rust-runner",
            runner_profile_id="sandbox-execute.v1",
            target_scope_ref="runner-profile:sandbox-execute.v1",
            timestamp="2026-01-01T00:00:00Z",
            content={
                "runner_status": "success",
                "expected_observable_paths": [path],
                "output": {
                    "artifact": path,
                    "source": STAGE,
                    "sha256": digest,
                    "size": len(payload),
                },
            },
        )

    staged = execution("stage_evidence", "sandbox.collection.stage.v1", STAGE)
    exported = execution("preserve_approved_copy", "sandbox.export.local.v1", EXPORT)
    collected = FilesystemCollector(tmp_path).collect(
        CollectionRequest(
            run_id=exported.run_id,
            step_id=exported.step_id,
            behavior_id=exported.behavior_id,
            action_id=exported.action_id,
            runner_profile_id=exported.runner_profile_id,
            target_scope_ref=exported.target_scope_ref,
            parent_evidence_ids=(exported.evidence_id,),
            settings=row["settings"],
        )
    )
    session = CollectionSession(
        CollectorRuntimeSettings(collectors={collector_id: row}), {collector_id: collected}
    )
    records = (staged, exported, *collected.records)
    run = {
        "steps": [
            {
                "step_id": staged.step_id,
                "behavior_id": staged.behavior_id,
                "action_id": staged.action_id,
                "status": "success",
                "runner_status": "success",
                "evidence_ids": [staged.evidence_id],
                "artifacts": {
                    "bundle": {
                        "type": "artifact.sandbox.bundle.v1",
                        "format": "jsonl",
                        "path": STAGE,
                        "size": len(payload),
                        "sha256": digest,
                    }
                },
            },
            {
                "step_id": exported.step_id,
                "behavior_id": exported.behavior_id,
                "action_id": exported.action_id,
                "status": "success",
                "runner_status": "success",
                "evidence_ids": [
                    exported.evidence_id,
                    *(item.evidence_id for item in collected.records),
                ],
            },
        ]
    }
    _validate_filesystem_binding(run, records, session)
    assert (
        evaluate_observation_integrity(records, configured_file_paths=(STAGE, EXPORT))["satisfied"]
        is True
    )
    assert (
        evaluate_observation_integrity(
            (staged, exported, collected.records[0]), configured_file_paths=(STAGE,)
        )["satisfied"]
        is False
    )
    incomplete = CollectionSession(
        session.settings, {collector_id: replace(collected, records=collected.records[:1])}
    )
    with pytest.raises(CollectorGateValidationError, match="exact staged and final"):
        _validate_filesystem_binding(run, records, incomplete)
