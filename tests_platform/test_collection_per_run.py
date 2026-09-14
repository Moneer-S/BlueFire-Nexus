from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.collectors import CollectionSemanticsCollector, CollectorRegistry, FilesystemCollector
from bluefire.config import load_config
from bluefire.contracts import ExecutionMode
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.observation_integrity import evaluate_observation_integrity
from bluefire.orchestrator import Orchestrator
from bluefire.registry import load_builtin_registry
from bluefire.run_store import RunStore
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS
from bluefire.service import BlueFireService
from tests_platform.test_collection_methods import _plan
from tests_platform.test_service import ReadyInventoryRunner

ROOT = Path(__file__).resolve().parents[1]
SEMANTIC = CollectionSemanticsCollector.descriptor.id
FILESYSTEM = FilesystemCollector.descriptor.id


def test_real_service_binds_explicit_semantic_selection_into_preflight(tmp_path: Path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner(actions=set(BUILTIN_RUNNER_ACTION_VERSIONS))
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    try:
        request = {
            "scenario_id": "scenario.endpoint.lab-collection-methods.v1",
            "mode": "execute",
            "runner_profile_id": "sandbox-execute.v1",
            "autonomy": "off",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
            "collectors": [FILESYSTEM, SEMANTIC],
        }
        report = service.preflight(request)
        assert report["status"] == "approval_required", report.get("problems")
        assert report["collectors"] == [FILESYSTEM, SEMANTIC]
        assert report["collector_binding"]["collectors"] == [FILESYSTEM, SEMANTIC]
        filesystem_only = service.preflight({**request, "collectors": [FILESYSTEM]})
        assert (
            report["approval_binding"]["state_digest"]
            != filesystem_only["approval_binding"]["state_digest"]
        )
        assert runner.execute_calls == 0
        assert service._source_collector_configuration(
            {"policy": {"approval_context": {"collector_binding": report["collector_binding"]}}},
            mode=ExecutionMode.EXECUTE,
        )[0] == (FILESYSTEM, SEMANTIC)
    finally:
        service.close()


@pytest.mark.parametrize("variant", ("primary", "heldout"))
@pytest.mark.parametrize("redacted", (False, True))
def test_per_run_semantics_read_exact_declared_episode_and_cannot_be_replaced_by_hashes(
    tmp_path: Path, variant: str, redacted: bool
):
    _, plan = _plan()
    step = next(row for row in plan.steps if row.step_id == "stage_collection")
    step = replace(step, parameters={"stage_variant": variant})
    path = f"staged/{'collection' if variant == 'primary' else 'variation'}/bundle.jsonl"
    payload = (
        json.dumps(
            {
                "record_id": "synthetic-001",
                "synthetic": True,
                "template": "telemetry-seed",
                "value": "synthetic-redacted" if redacted else "telemetry-value-001",
            }
        )
        + "\n"
    ).encode()
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_bytes(payload)
    profile = next(
        row
        for row in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if row.id == "sandbox-execute.v1"
    )
    # Production-shaped execution evidence is only an assertion to reconcile;
    # the actual collector independently opens the test artifact below.
    execution = EvidenceRecord.create(
        run_id="run-per-run",
        step_id=step.step_id,
        action_id=step.action_id,
        behavior_id=step.behavior_id,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id=profile.id,
        target_scope_ref=f"runner-profile:{profile.id}",
        content={
            "runner_status": "success",
            "expected_observable_paths": [path],
            "output": {
                "artifact": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            },
        },
    )
    orchestrator = Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        collector_registry=CollectorRegistry(
            (FilesystemCollector(tmp_path), CollectionSemanticsCollector(tmp_path))
        ),
    )
    records = orchestrator._collect_observable_paths(
        run_id=execution.run_id,
        step=step,
        profile=profile,
        paths=(path,),
        parent_evidence_id=execution.evidence_id,
        collector_ids=(FILESYSTEM, SEMANTIC),
    )
    filesystem, semantic = records
    assert semantic.producer == SEMANTIC
    assert semantic.parent_evidence_ids == (execution.evidence_id,)
    assert semantic.content["path"] == path
    assert semantic.content["retained_record_count"] == (0 if redacted else 1)
    assert semantic.content["redacted_record_count"] == (1 if redacted else 0)
    assert evaluate_observation_integrity([execution, *records])["satisfied"] is True
    assert evaluate_observation_integrity([execution, filesystem])["satisfied"] is False
    assert (
        evaluate_observation_integrity([execution, filesystem], configured_file_paths=[])[
            "satisfied"
        ]
        is False
    )
    changed = replace(
        semantic,
        content={
            **semantic.content,
            "observed_fields": {
                **semantic.content["observed_fields"],
                "retained_record_count": True,
            },
        },
    )
    assert evaluate_observation_integrity([execution, filesystem, changed])["satisfied"] is False
    alias_step = replace(
        step,
        action_id="package.reviewed-collection.v1",
        execution_binding={
            "runner_opcode": step.action_id,
            "logical_behavior_id": step.behavior_id,
            "logical_action_id": "package.reviewed-collection.v1",
        },
    )
    alias_execution = replace(
        execution,
        action_id=alias_step.action_id,
        content={**execution.content, "collection_method": step.action_id},
    )
    alias_records = orchestrator._collect_observable_paths(
        run_id=execution.run_id,
        step=alias_step,
        profile=profile,
        paths=(path,),
        parent_evidence_id=alias_execution.evidence_id,
        collector_ids=(SEMANTIC,),
    )
    assert len(alias_records) == 1
    assert alias_records[0].action_id == alias_step.action_id
    assert evaluate_observation_integrity([alias_execution, *alias_records])["satisfied"] is True
    assert evaluate_observation_integrity([alias_execution, filesystem])["satisfied"] is False
    unrelated = replace(
        step, action_id="sandbox.fixture.create.v1", behavior_id="sandbox.fixture.create.v1"
    )
    assert (
        orchestrator._collect_observable_paths(
            run_id=execution.run_id,
            step=unrelated,
            profile=profile,
            paths=(path,),
            parent_evidence_id=execution.evidence_id,
            collector_ids=(SEMANTIC,),
        )
        == ()
    )
