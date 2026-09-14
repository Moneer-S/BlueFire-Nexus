"""Real temporary-file reads under a fake transport; no native runner is started."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bluefire.application_errors import APIError
from bluefire.collector_comparison import summarize_collector_session
from bluefire.collector_schedule import (
    FILESYSTEM_ID,
    collect_produced_files,
    produced_paths,
    producer_settings,
    scheduled_settings,
)
from bluefire.collectors import (
    CollectionSession,
    CollectorError,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    NativeProcessCollector,
)
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.observation_integrity import evaluate_observation_integrity
from bluefire.orchestrator import OrchestrationError, Orchestrator
from bluefire.product_store import ProductStore
from bluefire.registry import load_builtin_registry
from bluefire.replay import ReplayError
from bluefire.run_store import RunStore
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS
from bluefire.service import BlueFireService
from tests_platform.test_orchestrator import (
    FULL_TARGET_SCOPE,
    SCENARIO_PATH,
    StructuredFakeRunner,
    _approval_kwargs,
    _execute_profile,
)
from tests_platform.test_service import ReadyInventoryRunner

STAGE = "staged/bundle.jsonl"
EXPORT = "exports/ephemeral/bundle.bin"
PATHS = ("fixtures/input.jsonl", "fixtures/transformed.jsonl", STAGE, EXPORT)


def _runtime(paths=PATHS):
    return CollectorRuntimeSettings(
        collectors={
            FILESYSTEM_ID: {
                "enabled": True,
                "settings": {"schedule": "after_each_producer", "paths": list(paths)},
            }
        }
    )


class FileWritingContractFake(StructuredFakeRunner):
    def __init__(self, *, missing_export=False, network_status="success"):
        super().__init__(network_status=network_status)
        self.missing_export = missing_export

    def execute(self, manifest, profile):
        result = dict(super().execute(manifest, profile))
        output = dict(result["output"])
        payload = b"public storage contract regression\n"
        if manifest["action_id"] == "sandbox.network.loopback.v1":
            output = {
                "destination": dict(manifest["params"]["destination"]),
                "artifact": STAGE,
                "bytes_sent": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "http_status": 200,
                "receiver_acknowledged": True,
                "receiver_stored": False,
            }
        path = output.get("artifact")
        if path is not None and manifest["action_id"] != "sandbox.network.loopback.v1":
            assert path in PATHS
            output.update(sha256=hashlib.sha256(payload).hexdigest(), size=len(payload))
            if not (self.missing_export and path == EXPORT):
                target = Path(profile["sandbox_root"]) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
        result["output"] = output
        return result


def _run(
    tmp_path, *, missing_export=False, network_status="success", paths=PATHS, with_process=False
):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = FileWritingContractFake(missing_export=missing_export, network_status=network_status)
    collectors = [FilesystemCollector(sandbox)]
    if with_process:
        collectors.append(NativeProcessCollector({10: 9}))
    orchestrator = Orchestrator(
        load_builtin_registry(),
        RunStore(tmp_path / "runs"),
        runner=runner,
        approval_store=ProductStore(tmp_path / "product.sqlite3"),
        collector_registry=CollectorRegistry(collectors),
    )
    runtime = _runtime(paths)
    if with_process:
        payload = runtime.to_dict()
        payload["collectors"][NativeProcessCollector.descriptor.id] = {
            "enabled": True,
            "settings": {
                "collect_after_step": "try_loopback",
                "process_id": 10,
                "expected_parent_process_id": 9,
            },
        }
        runtime = CollectorRuntimeSettings.from_mapping(payload)
    scenario = load_scenario(SCENARIO_PATH)
    profile = _execute_profile()
    authority = orchestrator.collector_registry.authority_snapshot(
        runtime, expected_sandbox=sandbox
    )
    result = orchestrator.run(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        sandbox_root=sandbox,
        target_scope=FULL_TARGET_SCOPE,
        collector_runtime_settings=runtime,
        collector_registry_authority=authority,
        **_approval_kwargs(
            orchestrator,
            scenario=scenario,
            profile=profile,
            target_scope=FULL_TARGET_SCOPE,
            context={
                "collector_binding": orchestrator._collector_binding((), runtime),
                "collector_registry_authority": authority,
            },
        ),
    )
    return result, runtime, runner


@pytest.mark.parametrize(
    "network_status,missing_export,expected",
    [("success", False, True), ("failed", False, True), ("failed", True, False)],
)
def test_conditional_file_effects_require_actual_matching_observations(
    tmp_path, network_status, missing_export, expected
):
    result, runtime, _ = _run(
        tmp_path, network_status=network_status, missing_export=missing_export
    )
    session = CollectionSession.from_mapping(result["collector_session"])
    assert session.settings == runtime
    summary = summarize_collector_session(
        result["collector_session"],
        result["evidence"]["records"],
        result["run_id"],
        result["steps"],
    )
    assert summary["state"] == "verified"
    assert BlueFireService._source_collector_runtime(result) == runtime
    records = session.results[FILESYSTEM_ID].records
    observed = [row for row in records if row.provenance.value == "observed"]
    assert {row.content["path"] for row in observed} == set(
        PATHS if network_status == "failed" and not missing_export else PATHS[:-1]
    )
    evidence = {row["evidence_id"]: row for row in result["evidence"]["records"]}
    for observation in observed:
        parent = evidence[observation.parent_evidence_ids[0]]
        assert parent["step_id"] == observation.step_id
        assert observation.content["path"] in parent["content"]["expected_observable_paths"]
        assert parent["content"]["output"]["sha256"] == observation.content["sha256"]
    integrity = result["objective_evaluation"]["observation_integrity"]
    assert integrity["satisfied"] is expected
    assert result["objective_reached"] is expected
    if missing_export:
        assert integrity["gap_evidence_ids"]
        assert any(
            row["path"] == EXPORT and row["state"] != "verified"
            for row in integrity["file_postconditions"]
        )
    elif network_status == "success":
        assert all(row["path"] != EXPORT for row in integrity["file_postconditions"])


def test_paths_are_an_allowlist_and_unobserved_final_effect_stays_incomplete(tmp_path):
    result, _, _ = _run(tmp_path, network_status="failed", paths=(STAGE,))
    session = CollectionSession.from_mapping(result["collector_session"])
    assert [row.content["path"] for row in session.results[FILESYSTEM_ID].records] == [STAGE]
    assert result["objective_reached"] is False


@pytest.mark.parametrize(
    "change", [{"collect_after_step": "stage_records"}, {"schedule": "always"}, {"schedule": True}]
)
def test_service_refuses_ambiguous_or_unknown_producer_schedule(change):
    payload = _runtime().to_dict()
    payload["collectors"][FILESYSTEM_ID]["settings"].update(change)
    with pytest.raises(APIError):
        BlueFireService._validate_managed_collector_settings(
            CollectorRuntimeSettings.from_mapping(payload)
        )


def test_per_producer_selection_does_not_weaken_other_collector_schedule(tmp_path):
    runtime = _runtime()
    BlueFireService._validate_managed_collector_settings(runtime)
    assert producer_settings(runtime) == runtime
    assert scheduled_settings(runtime).collectors[FILESYSTEM_ID]["enabled"] is False
    scenario = load_scenario(SCENARIO_PATH)
    orchestrator = Orchestrator(load_builtin_registry(), RunStore(tmp_path / "runs"))
    plan = orchestrator.planner.compile(scenario)
    assert orchestrator._collector_schedule(plan, runtime, start_step_id=scenario.start) is None
    payload = runtime.to_dict()
    payload["collectors"]["collector.process.native.v1"] = {
        "enabled": True,
        "settings": {
            "collect_after_step": "export_locally",
            "process_id": 10,
            "expected_parent_process_id": 9,
        },
    }
    with pytest.raises(OrchestrationError, match="bypassed"):
        orchestrator._collector_schedule(
            plan, CollectorRuntimeSettings.from_mapping(payload), start_step_id=scenario.start
        )


def test_producer_paths_never_come_from_runner_output_alone(tmp_path):
    result, runtime, _ = _run(tmp_path)
    source = next(row for row in result["evidence"]["records"] if row["provenance"] == "executed")
    execution = EvidenceRecord.from_mapping(source)
    altered = EvidenceRecord.create(
        run_id=execution.run_id,
        step_id=execution.step_id,
        behavior_id=execution.behavior_id,
        action_id=execution.action_id,
        provenance=execution.provenance,
        producer=execution.producer,
        runner_profile_id=execution.runner_profile_id,
        target_scope_ref=execution.target_scope_ref,
        content={"runner_status": "success", "output": {"artifact": STAGE}},
    )
    assert produced_paths(runtime, altered) == ()


def test_real_service_preflight_and_exact_replay_bind_producer_schedule(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner(actions=set(BUILTIN_RUNNER_ACTION_VERSIONS))
    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
        collector_registry_factory=lambda root: CollectorRegistry((FilesystemCollector(root),)),
    )
    try:
        runtime = _runtime()
        request = {
            "scenario": load_scenario(SCENARIO_PATH).to_dict(),
            "mode": "execute",
            "runner_profile_id": "sandbox-execute.v1",
            "autonomy": "off",
            "target_scope": FULL_TARGET_SCOPE,
            "collector_runtime": runtime.to_dict(),
        }
        report = service.preflight(request)
        assert report["status"] == "approval_required", report.get("problems")
        assert report["collector_binding"]["settings_hash"] == runtime.settings_hash
        changed_runtime = _runtime((STAGE,))
        changed = service.preflight({**request, "collector_runtime": changed_runtime.to_dict()})
        assert (
            report["approval_binding"]["state_digest"]
            != changed["approval_binding"]["state_digest"]
        )
        source = {
            "policy": {
                "approval_context": {
                    "collector_binding": report["collector_binding"],
                    "collector_registry_authority": report["collector_registry_authority"],
                }
            }
        }
        assert service._replay_collector_configuration(
            {}, source=source, mode=ExecutionMode.EXECUTE, exact=True
        ) == ((), runtime)
        with pytest.raises(ReplayError):
            service._replay_collector_configuration(
                {"collector_runtime": changed_runtime.to_dict()},
                source=source,
                mode=ExecutionMode.EXECUTE,
                exact=True,
            )
        assert runner.execute_calls == 0
    finally:
        service.close()


def test_unreached_allowlist_is_not_an_observed_objective_and_replay_preserves_it(tmp_path):
    result, runtime, _ = _run(tmp_path, paths=(EXPORT,))
    session = CollectionSession.from_mapping(result["collector_session"])
    assert not session.results[FILESYSTEM_ID].records
    summary = summarize_collector_session(
        result["collector_session"],
        result["evidence"]["records"],
        result["run_id"],
        result["steps"],
    )
    assert summary["state"] == "not_triggered"
    assert summary["observation_count"] == 0
    assert result["objective_reached"] is False
    assert BlueFireService._source_collector_runtime(result) == runtime
    # A rehashed empty session cannot conceal a reached producer.
    changed = CollectionSession(_runtime((STAGE,)), session.results)
    with pytest.raises(CollectorError, match="no attributable"):
        summarize_collector_session(
            changed.to_dict(), result["evidence"]["records"], result["run_id"], result["steps"]
        )


def test_repeated_path_episodes_need_each_actual_independent_read(tmp_path):
    runtime = _runtime((STAGE,))
    registry = CollectorRegistry((FilesystemCollector(tmp_path),))
    authority = registry.authority_snapshot(runtime, expected_sandbox=tmp_path)
    target = tmp_path / STAGE
    target.parent.mkdir()
    records = []
    for index, payload in enumerate((b"first public bytes\n", b"replacement public bytes\n")):
        target.write_bytes(payload)
        execution = EvidenceRecord.create(
            run_id="unit-file-episodes",
            step_id=f"stage_{index}",
            behavior_id="sandbox.collection.stage.v1",
            action_id="sandbox.collection.stage.v1",
            provenance=EvidenceProvenance.EXECUTED,
            producer="bluefire-rust-runner",
            runner_profile_id="sandbox-execute.v1",
            target_scope_ref="runner-profile:sandbox-execute.v1",
            content={
                "runner_status": "success",
                "expected_observable_paths": [STAGE],
                "output": {
                    "artifact": STAGE,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                },
            },
        )
        session = collect_produced_files(
            registry, runtime, execution, sandbox=tmp_path, authority=authority, timeout_seconds=2.0
        )
        assert session is not None
        records.extend((execution, *session.results[FILESYSTEM_ID].records))
        target.unlink()
    result = evaluate_observation_integrity(
        records, configured_file_paths=(), producer_file_paths=(STAGE,)
    )
    assert result["satisfied"] is True
    assert len(result["file_postconditions"]) == 2
    missing_first = evaluate_observation_integrity(
        (records[0], *records[2:]), configured_file_paths=(), producer_file_paths=(STAGE,)
    )
    assert missing_first["satisfied"] is False


def test_paused_run_retains_untriggered_process_authority_without_claiming_observation(
    tmp_path, monkeypatch
):
    # Replace only OS identity reads and the proposal decision. The actual
    # orchestrator, approval, filesystem collector, session and replay validators run.
    monkeypatch.setattr(
        "bluefire.collectors.observe_native_process",
        lambda *args, **kwargs: {"creation_identity": "123"},
    )
    monkeypatch.setattr("bluefire.collectors.native_process_readiness", lambda: {"ready": True})
    monkeypatch.setattr(
        Orchestrator,
        "_propose_next_step",
        lambda *args, **kwargs: (
            {"application_status": "awaiting_operator_approval"},
            None,
            None,
            False,
        ),
    )
    result, runtime, _ = _run(tmp_path, with_process=True)
    assert result["status"] == "awaiting_approval"
    assert [step["action_id"] for step in result["steps"]] == [
        "sandbox.fixture.create.v1",
        "sandbox.cleanup.v1",
    ]
    session = CollectionSession.from_mapping(result["collector_session"])
    process = session.results[NativeProcessCollector.descriptor.id]
    assert process.records == ()
    assert process.health.details["schedule_state"] == "not_triggered"
    assert BlueFireService._source_collector_runtime(result) == runtime
    with pytest.raises(ReplayError, match="approval-paused"):
        BlueFireService._source_collector_runtime({**result, "status": "completed"})
    summary = summarize_collector_session(
        result["collector_session"],
        result["evidence"]["records"],
        result["run_id"],
        result["steps"],
    )
    assert summary["observation_count"] == 1
    # Existing fixed-only sessions cannot acquire the new empty-phase exception.
    fixed = runtime.to_dict()
    fixed["collectors"][FILESYSTEM_ID]["enabled"] = False
    forged = CollectionSession(
        CollectorRuntimeSettings.from_mapping(fixed),
        {NativeProcessCollector.descriptor.id: process},
    )
    with pytest.raises(CollectorError):
        summarize_collector_session(forged.to_dict(), [], result["run_id"], [])


def test_gate05_managed_paths_keep_anchored_phase_on_every_graph_path(tmp_path):
    from bluefire.collector_journey import _runtime_settings

    scenario = load_scenario(
        Path(__file__).resolve().parents[1] / "scenarios" / "ai_adaptive_safe_chain.yaml"
    )
    orchestrator = Orchestrator(load_builtin_registry(), RunStore(tmp_path / "runs"))
    plan = orchestrator.planner.compile(scenario)
    for enabled in (False, True):
        runtime = _runtime_settings(process_id=10, parent_process_id=9, network_enabled=enabled)
        BlueFireService._validate_managed_collector_settings(runtime)
        assert (
            orchestrator._collector_schedule(plan, runtime, start_step_id=scenario.start)
            == "try_internal_transport"
        )


def test_mixed_phase_session_keeps_producer_reads_and_exact_process_anchor(tmp_path, monkeypatch):
    # A bounded mocked OS API exercises the real anchored collector without
    # enumerating or executing native processes on the operator machine.
    monkeypatch.setattr(
        "bluefire.collectors.observe_native_process",
        lambda *args, **kwargs: {
            "creation_identity": "123",
            "process_id": 10,
            "parent_process_id": 9,
            "platform": "windows",
            "native_api": "unit-identity-read",
            "executable_name": "unit-child",
        },
    )
    monkeypatch.setattr("bluefire.collectors.native_process_readiness", lambda: {"ready": True})
    result, runtime, _ = _run(tmp_path, with_process=True)
    session = CollectionSession.from_mapping(result["collector_session"])
    process = session.results[NativeProcessCollector.descriptor.id]
    assert len(process.records) == 1
    assert process.records[0].step_id == "try_loopback"
    assert len(session.results[FILESYSTEM_ID].records) == 3
    assert BlueFireService._source_collector_runtime(result) == runtime
    summary = summarize_collector_session(
        result["collector_session"],
        result["evidence"]["records"],
        result["run_id"],
        result["steps"],
    )
    assert summary["observation_count"] == 4


def test_service_refuses_checkpoint_producer_replay_before_preparation(tmp_path):
    result, _, runner = _run(tmp_path)
    source_calls = list(runner.calls)

    def refuse_runner(_profile):
        pytest.fail("partial producer replay must not prepare a runner")

    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        runner_factory=refuse_runner,
    )
    try:
        before_jobs = service.product_store.list_jobs()
        before_runs = service.store.list_runs()
        with pytest.raises(APIError) as failure:
            service.replay(result["run_id"], {"from_step_id": "stage_records", "exact": False})
        assert "checkpoint-prefix" in str(failure.value.details)
        assert service.product_store.list_jobs() == before_jobs
        assert service.store.list_runs() == before_runs
        assert runner.calls == source_calls
    finally:
        service.close()
