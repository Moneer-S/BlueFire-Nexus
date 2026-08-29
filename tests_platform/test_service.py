from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.ai import UrllibAIJSONTransport
from bluefire.api import APIError
from bluefire.approvals import execution_approval_binding, public_approval_record
from bluefire.collectors import (
    CollectionRequest,
    CollectorError,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
)
from bluefire.config import load_config
from bluefire.contracts import ContractError, ExecutionMode
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.job_runtime import JobCancelled, JobState
from bluefire.orchestrator import Orchestrator
from bluefire.replay import ReplayError
from bluefire.runner_bootstrap import RUNNER_ID
from bluefire.runner_client import RunnerTaskCancelled, RunnerTransportError
from bluefire.runner_contracts import current_platform
from bluefire.runner_inventory import (
    BUILTIN_RUNNER_ACTION_VERSIONS,
    RUNNER_ACTION_SDK_SCHEMA_VERSION,
)
from bluefire.runner_lifecycle import RunnerLifecycleError
from bluefire.service import BlueFireService
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
EXECUTE_PROFILE_ACTIONS = {
    "endpoint.discovery.processes.v1",
    "endpoint.discovery.system.v1",
    "sandbox.archive.tar.v1",
    "sandbox.cleanup.v1",
    "sandbox.collection.stage.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.execution.native-canary.v1",
    "sandbox.export.local.v1",
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.network.loopback.v1",
    "sandbox.observability.variant.v1",
    "sandbox.peer.handoff.v1",
}


def _rehash_collector_authority(authority: dict[str, Any]) -> None:
    for backend in authority.get("backends", []):
        if not isinstance(backend, dict):
            continue
        descriptor = backend.get("descriptor")
        source_authority = backend.get("source_authority")
        if isinstance(descriptor, dict):
            backend["descriptor_hash"] = content_hash(descriptor)
        if isinstance(source_authority, dict):
            backend["source_authority_hash"] = content_hash(source_authority)
    authority["authority_hash"] = content_hash(
        {key: value for key, value in authority.items() if key != "authority_hash"}
    )


def _collector_authority_fixture(
    runtime: CollectorRuntimeSettings,
    source_authorities: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    canonical_types = {
        FilesystemCollector.descriptor.id: FilesystemCollector,
        NativeProcessCollector.descriptor.id: NativeProcessCollector,
        LoopbackReceiverCollector.descriptor.id: LoopbackReceiverCollector,
    }
    backends: list[dict[str, Any]] = []
    for collector_id, row in runtime.collectors.items():
        if row["enabled"] is not True:
            continue
        canonical_type = canonical_types[collector_id]
        descriptor = canonical_type.descriptor.to_dict()
        source_authority = dict(source_authorities[collector_id])
        backends.append(
            {
                "collector_id": collector_id,
                "descriptor": descriptor,
                "descriptor_hash": content_hash(descriptor),
                "implementation_id": (f"{canonical_type.__module__}.{canonical_type.__qualname__}"),
                "source_authority": source_authority,
                "source_authority_hash": content_hash(source_authority),
            }
        )
    authority = {
        "schema_version": "bluefire.collector-registry-authority.v1",
        "settings_hash": runtime.settings_hash,
        "backends": backends,
    }
    return {**authority, "authority_hash": content_hash(authority)}


def _canonical_collector_authority_source() -> tuple[CollectorRuntimeSettings, dict[str, Any]]:
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            },
            NativeProcessCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "observe_child",
                    "process_id": 321,
                    "expected_parent_process_id": 123,
                },
            },
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "try_internal_transport",
                    "task_ids": ["execute-" + "a" * 64],
                },
            },
        }
    )
    authority = _collector_authority_fixture(
        runtime,
        {
            FilesystemCollector.descriptor.id: {
                "schema_version": "bluefire.filesystem-source-authority.v1",
                "sandbox_binding": "exact-factory-argument",
                "max_file_bytes": 64 * 1024 * 1024,
                "read_timeout_seconds": 5.0,
                "path_policy": "handle-pinned-contained-no-follow",
            },
            NativeProcessCollector.descriptor.id: {
                "schema_version": "bluefire.process-source-authority.v1",
                "authorized_processes": [
                    {
                        "process_id": 321,
                        "parent_process_id": 123,
                        "creation_identity": "987654321",
                    }
                ],
            },
            LoopbackReceiverCollector.descriptor.id: {
                "schema_version": "bluefire.receiver-source-authority.v1",
                "host": "127.0.0.1",
                "port": 43123,
                "process_id": 777,
                "session_id": "b" * 64,
            },
        },
    )
    source = {
        "policy": {
            "approval_context": {
                "collector_binding": BlueFireService._collector_binding((), runtime),
                "collector_registry_authority": authority,
            }
        }
    }
    return runtime, source


def _ready_inventory(
    *,
    actions: set[str] | None = None,
    runner_version: str = "test-1.0.0",
) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.runner-inventory.v1",
        "runner_id": "bluefire-test-runner.v1",
        "runner_version": runner_version,
        "action_sdk_version": "bluefire.runner-action-sdk.v1",
        "receipt_protocol": "bluefire.runner-receipt-wal.v2",
        "platform": current_platform(),
        "actions": [
            {
                "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                "action_id": action_id,
                "action_version": BUILTIN_RUNNER_ACTION_VERSIONS[action_id],
                "readiness": "ready",
            }
            for action_id in sorted(actions or EXECUTE_PROFILE_ACTIONS)
        ],
    }


class ReadyInventoryRunner:
    def __init__(self, *, actions: set[str] | None = None) -> None:
        self.actions = set(actions or EXECUTE_PROFILE_ACTIONS)
        self.inventory_calls = 0
        self.execute_calls = 0

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        return _ready_inventory(actions=self.actions)

    def execute(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.execute_calls += 1
        raise RunnerTransportError("deliberate test runner has no action implementation")


class PostApprovalReadinessRunner(ReadyInventoryRunner):
    def __init__(self, failure: str) -> None:
        super().__init__()
        self.failure = failure

    def inventory(self) -> Mapping[str, Any]:
        self.inventory_calls += 1
        if self.inventory_calls < 3:
            return _ready_inventory(actions=self.actions)
        if self.failure == "disconnect":
            raise RunnerTransportError("connection failed at C:/sensitive/local/runner.sock")
        return _ready_inventory(
            actions=self.actions - {"sandbox.fixture.create.v1"},
        )


class CancellableTaskRunner(ReadyInventoryRunner):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.task_id: str | None = None
        self.durable_result_path: Path | None = None

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        self.execute_calls += 1
        expected_hash = content_hash(
            {
                "manifest": dict(manifest),
                "profile": dict(profile),
                "execution_attempt": 1,
            }
        ).removeprefix("sha256:")
        assert task_id == f"execute-{expected_hash}"
        self.task_id = task_id
        self.durable_result_path = Path(durable_result_path)
        self.started.set()
        if not cancel_event.wait(3):
            raise RunnerTransportError("test cancellation signal was not delivered")
        raise RunnerTaskCancelled("test runner confirmed its task tree stopped")


class RecordingRunnerLifecycle:
    def __init__(self, runner: ReadyInventoryRunner, sandbox: Path) -> None:
        self.runner = runner
        self.sandbox = sandbox
        self.calls: list[tuple[str, object]] = []
        self.client_available = True

    def status(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        self.calls.append(("status", profile_id))
        return {
            "schema_version": "bluefire.runner-lifecycle-status.v1",
            "state": "ready",
            "profile_id": profile_id,
        }

    def bootstrap(
        self,
        *,
        allowed_profile_ids: tuple[str, ...],
        allow_upgrade: bool,
    ) -> Mapping[str, Any]:
        self.calls.append(("bootstrap", (allowed_profile_ids, allow_upgrade)))
        return self.status(profile_id=allowed_profile_ids[0])

    def start(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        self.calls.append(("start", profile_id))
        return self.status(profile_id=profile_id)

    def stop(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        self.calls.append(("stop", profile_id))
        return self.status(profile_id=profile_id)

    def revoke(self) -> Mapping[str, Any]:
        self.calls.append(("revoke", None))
        return self.status()

    def remove(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        self.calls.append(("remove", confirm_runner_id))
        return {
            "schema_version": "bluefire.runner-lifecycle-status.v1",
            "state": "unbootstrapped",
        }

    def client_for_profile(self, profile_id: str) -> tuple[ReadyInventoryRunner, Path]:
        self.calls.append(("client_for_profile", profile_id))
        if not self.client_available:
            raise RunnerLifecycleError("managed runner is stopped")
        return self.runner, self.sandbox


class CleanupOnlyRecoveryRunner:
    def __init__(self) -> None:
        self.calls: list[Mapping[str, Any]] = []

    def inventory(self) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.runner-inventory.v1",
            "action_sdk_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
            "receipt_protocol": "bluefire.runner-receipt-wal.v2",
            "actions": [
                {
                    "schema_version": RUNNER_ACTION_SDK_SCHEMA_VERSION,
                    "action_id": "sandbox.cleanup.v1",
                    "action_version": BUILTIN_RUNNER_ACTION_VERSIONS["sandbox.cleanup.v1"],
                    "readiness": "ready",
                }
            ],
        }

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        assert manifest["action_id"] == "sandbox.cleanup.v1"
        self.calls.append(dict(manifest))
        root = Path(str(profile["sandbox_root"]))
        receipt_ids = list(manifest["params"]["receipt_ids"])
        removed_paths: list[str] = []
        for receipt_id in receipt_ids:
            receipt_path = root / ".bluefire" / "receipts" / f"{receipt_id}.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            for owned in reversed(receipt["paths"]):
                owned_path = root / str(owned["relative_path"])
                if owned_path.is_file():
                    owned_path.unlink()
                    removed_paths.append(str(owned["relative_path"]))
                elif owned_path.is_dir():
                    owned_path.rmdir()
                    removed_paths.append(str(owned["relative_path"]))
            receipt_path.unlink()
        cleanup_report = {
            "requested_receipts": len(receipt_ids),
            "removed_paths": removed_paths,
            "already_absent_receipts": [],
            "retained_paths": [],
            "errors": [],
            "verification_performed": True,
            "verified_removed_paths": len(removed_paths),
            "verified_absent_paths": 0,
            "verified_receipts": len(receipt_ids),
        }
        return {
            "schema_version": "bluefire.runner-result.v1",
            "request_id": manifest["request_id"],
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": manifest["action_id"],
            "runner_id": manifest["runner_id"],
            "runner_profile_id": manifest["runner_profile_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
            "platform": profile["platform"],
            "status": "success",
            "output": cleanup_report,
            "stdout": {"bytes": 0, "truncated": False},
            "stderr": {"bytes": 0, "truncated": False},
            "evidence": [{"kind": "restart-cleanup", "status": "success"}],
            "receipt_ids": [],
            "cleanup": cleanup_report,
            "error": None,
            "limitations": [],
        }


def _persist_interrupted_scenario_job(
    service: BlueFireService,
    request: Mapping[str, Any],
) -> Mapping[str, Any]:
    job = service.product_store.create_job("scenario.run", request)
    job_id = str(job["job_id"])
    service.product_store.transition_job(job_id, "planning")
    service.product_store.transition_job(job_id, "running")
    return service.product_store.transition_job(job_id, "interrupted")


def _pending_execute_approval(
    service: BlueFireService,
    request: Mapping[str, Any],
) -> Mapping[str, Any]:
    preflight = service.preflight(request)
    binding = preflight["approval_binding"]
    assert isinstance(binding, Mapping)
    digest = content_hash(binding)
    return service.product_store.create_approval_request(
        run_id="intent-" + digest[7:39],
        state_digest=str(binding["state_digest"]),
        plan_digest=str(binding["plan_digest"]),
        profile_id=str(binding["profile_id"]),
        target_scope_digest=str(binding["target_scope_digest"]),
        maximum_tier=str(binding["maximum_tier"]),
        expires_at=service._approval_review_expires_at(),
    )


def test_default_run_store_uses_callers_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    service = BlueFireService(project_root=ROOT)

    assert service.store.root == (tmp_path / ".bluefire-runs").resolve()


def test_service_seeds_durable_product_state_and_indexes_completed_runs(
    tmp_path: Path,
) -> None:
    runs_dir = tmp_path / "runs"
    database = tmp_path / "state" / "bluefire.sqlite3"
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
    )

    assert service.product_store.path == database.resolve()
    assert service.seed_counts["scenario"] == 8
    assert service.seed_counts["action"] == 18
    assert len(service.product_store.list_resources("collector")) == 10

    result = service.run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": "off",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
    )

    indexed = service.product_store.list_runs()
    assert [item["run_id"] for item in indexed] == [result["run_id"]]
    assert indexed[0]["bundle_digest"] == result["manifest"]["bundle_hash"]
    assert indexed[0]["objective_reached"] is True
    first_page = service.events(result["run_id"], limit=2)
    second_page = service.events(
        result["run_id"],
        after_sequence=first_page["next_sequence"],
        limit=2,
    )
    assert first_page["items"]
    assert not {item["sequence"] for item in first_page["items"]} & {
        item["sequence"] for item in second_page["items"]
    }

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
    )
    assert restarted.recovered_runs == 0
    assert restarted.recovered_jobs == 0
    assert all(item["version"] == 1 for item in restarted.product_store.list_scenarios())
    assert restarted.product_store.list_runs()[0]["run_id"] == result["run_id"]


def test_service_recovers_inflight_product_jobs_after_restart(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    database = tmp_path / "bluefire.sqlite3"
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
    )
    job = service.product_store.create_job("run", {"scenario_id": "scenario.test.v1"})
    service.product_store.transition_job(job["job_id"], "planning")
    service.product_store.transition_job(job["job_id"], "running")

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
    )

    assert restarted.recovered_jobs == 1
    assert restarted.product_store.get_job(job["job_id"])["state"] == "interrupted"


def test_restart_cleanup_uses_exact_bound_workspace_and_audits_run_bundle(
    request: pytest.FixtureRequest,
) -> None:
    short_root = Path(tempfile.mkdtemp(prefix="bf-recovery-"))
    request.addfinalizer(lambda: shutil.rmtree(short_root, ignore_errors=True))
    runs_dir = short_root / "r"
    database = short_root / "s.db"
    original_root = short_root / "o"
    changed_root = short_root / "n"
    original_root.mkdir()
    changed_root.mkdir()
    runner = CleanupOnlyRecoveryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
        runner_factory=lambda _profile: (runner, original_root),
    )
    scenario = next(item for item in service._scenarios if item.id.endswith("research.chain.v1"))
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    autonomy, provider = service._ai_context({"autonomy": "off"})
    target_scope = {"scope_refs": list(profile.scope)}
    orchestrator = Orchestrator(
        service.registry,
        service.store,
        runner=runner,
        approval_store=service.product_store,
    )
    consumed = service._bind_and_consume_approval(
        scenario=scenario,
        profile=profile,
        target_scope=target_scope,
        autonomy=autonomy,
        ai_provider=provider,
        approved_by="restart-test-operator",
        orchestrator=orchestrator,
    )
    plan = orchestrator.planner.compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
        autonomy=autonomy,
        ai_provider=provider,
    )
    approval_binding = execution_approval_binding(
        registry=service.registry,
        scenario=scenario,
        plan=plan.to_dict(),
        profile=profile,
        target_scope=target_scope,
        autonomy=autonomy,
        ai_provider=provider,
    )
    claimed = service.product_store.claim_consumed_approval(
        str(consumed["approval_id"]),
        nonce=str(consumed["nonce"]),
        approved_by="restart-test-operator",
        expected_state_digest=str(approval_binding["state_digest"]),
        expected_plan_digest=str(approval_binding["plan_digest"]),
        expected_target_scope_digest=str(approval_binding["target_scope_digest"]),
        expected_profile_id=profile.id,
        expected_maximum_tier=str(approval_binding["maximum_tier"]),
    )
    workspace = service._isolated_execution_sandbox(original_root, claimed)
    service._bind_execution_workspace(
        approval_record=claimed,
        workspace=workspace,
        runner=runner,
        scenario=scenario,
        profile=profile,
        target_scope=target_scope,
        autonomy=autonomy,
        ai_provider=provider,
    )
    handle = service.store.create_run(
        scenario=scenario.to_dict(),
        plan=plan.to_dict(),
        policy={
            "schema_version": "bluefire.run-policy.v1",
            "authorized_target_scope": target_scope,
            "autonomy": autonomy.value,
            "ai_provider": dict(provider),
            "approval": public_approval_record(claimed),
        },
        profile=profile.to_dict(),
    )
    service.product_store.transition_execution_workspace(
        str(claimed["approval_id"]),
        "active",
        run_id=handle.run_id,
    )
    job = service.product_store.create_job(
        "scenario.run",
        {
            "scenario_id": scenario.id,
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": autonomy.value,
            "target_scope": target_scope,
            "approval_request_id": claimed["approval_id"],
        },
    )
    service.product_store.transition_job(str(job["job_id"]), "planning")
    service.product_store.transition_job(
        str(job["job_id"]),
        "running",
        progress={"run_id": handle.run_id, "phase": "running"},
    )

    artifact = workspace / "fixtures" / "interrupted.txt"
    artifact.parent.mkdir()
    artifact.write_text("bounded test artifact", encoding="utf-8")
    receipt_root = workspace / ".bluefire" / "receipts"
    receipt_root.mkdir(parents=True)
    identity = {
        "schema_version": "bluefire.receipt/v1",
        "request_hash": "sha256:" + "1" * 64,
        "action_id": "sandbox.fixture.create.v1",
        "runner_profile_id": profile.id,
        "workspace_id": hashlib.sha256(
            str(workspace.resolve(strict=True)).replace("\\", "/").encode("utf-8")
        ).hexdigest(),
        "created_at": "2026-08-24T00:00:00Z",
        "paths": [
            {
                "relative_path": "fixtures/interrupted.txt",
                "kind": "file",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "size": artifact.stat().st_size,
            }
        ],
    }
    receipt_id = content_hash(identity).removeprefix("sha256:")
    (receipt_root / f"{receipt_id}.json").write_text(
        json.dumps({"receipt_id": receipt_id, **identity}),
        encoding="utf-8",
    )
    service.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=database,
        runner_factory=lambda _profile: (runner, changed_root),
    )

    assert restarted.cleanup_recovery["completed"] == 1
    assert runner.calls and [call["action_id"] for call in runner.calls] == ["sandbox.cleanup.v1"]
    assert not artifact.exists()
    assert not (receipt_root / f"{receipt_id}.json").exists()
    durable = restarted.product_store.get_execution_workspace(str(claimed["approval_id"]))
    assert durable["state"] == "recovered"
    recovered_job = restarted.product_store.get_job(str(job["job_id"]))
    assert recovered_job["state"] == "interrupted"
    assert recovered_job["progress"]["cleanup_recovery"]["status"] == "completed"
    detail = restarted.detail(handle.run_id)
    assert detail["status"] == "interrupted"
    assert detail["cleanup_recovery"]["status"] == "completed"
    assert detail["cleanup"]["outstanding_receipts"] == 0
    assert restarted.store.validate_bundle(handle.run_id)["valid"] is True
    restarted.close()


def test_simulate_submission_runs_as_a_durable_background_job(tmp_path: Path) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": "off",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
    )
    job_id = str(submission["job"]["job_id"])

    completed = service.job_controller.wait(job_id, timeout=5)

    assert completed["state"] == "completed"
    assert str(completed["result_ref"]).startswith("run-")
    assert service.detail(str(completed["result_ref"]))["status"] == "completed"
    service.close()


def test_interrupted_simulate_retry_clones_request_and_records_lineage(tmp_path: Path) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "simulate",
        "autonomy": "off",
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }
    interrupted = _persist_interrupted_scenario_job(service, request)

    retry = service.retry_job(str(interrupted["job_id"]))
    retry_job_id = str(retry["job"]["job_id"])
    completed = service.job_controller.wait(retry_job_id, timeout=5)

    assert retry["schema_version"] == "bluefire.job-retry.v1"
    assert retry["retry_of_job_id"] == interrupted["job_id"]
    assert completed["state"] == "completed"
    assert completed["request"] == request
    source = service.job(str(interrupted["job_id"]))
    assert source["progress"]["retry_lineage"][-1]["retry_job_id"] == retry_job_id
    assert source["progress"]["retry_lineage"][-1]["mode"] == "simulate"
    service.close()


def test_interrupted_execute_retry_requires_a_fresh_exact_approval(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    base_request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
    }
    old_approval = _pending_execute_approval(service, base_request)
    interrupted = _persist_interrupted_scenario_job(
        service,
        {**base_request, "approval_request_id": old_approval["approval_id"]},
    )

    retry = service.retry_job(str(interrupted["job_id"]))
    retry_job_id = str(retry["job"]["job_id"])
    awaiting = service.job_controller.wait_for_state(
        retry_job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=3,
    )

    fresh_approval = retry["approval_request"]
    assert fresh_approval["status"] == "pending"
    assert fresh_approval["approval_id"] != old_approval["approval_id"]
    assert awaiting["request"]["approval_request_id"] == fresh_approval["approval_id"]
    assert old_approval["approval_id"] not in str(awaiting["request"])
    assert retry["source_job"]["progress"]["retry_lineage"][-1]["mode"] == "execute"
    service.close()


def test_interrupted_execute_retry_refuses_an_unsettled_workspace(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
    }
    pending = _pending_execute_approval(service, request)
    approved = service.product_store.approve(
        str(pending["approval_id"]),
        approved_by="retry-safety-test",
        expected_state_digest=str(pending["state_digest"]),
        expected_plan_digest=str(pending["plan_digest"]),
        expected_target_scope_digest=str(pending["target_scope_digest"]),
        expires_at=service._approval_execution_expires_at(profile),
    )
    consumed = service.product_store.consume_approval(
        str(pending["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest=str(pending["state_digest"]),
        expected_plan_digest=str(pending["plan_digest"]),
        expected_target_scope_digest=str(pending["target_scope_digest"]),
    )
    claimed = service.product_store.claim_consumed_approval(
        str(pending["approval_id"]),
        nonce=str(consumed["nonce"]),
        approved_by="retry-safety-test",
        expected_state_digest=str(pending["state_digest"]),
        expected_plan_digest=str(pending["plan_digest"]),
        expected_target_scope_digest=str(pending["target_scope_digest"]),
        expected_profile_id=profile.id,
        expected_maximum_tier=str(pending["maximum_tier"]),
    )
    workspace = service._isolated_execution_sandbox(sandbox, claimed)
    service.product_store.bind_execution_workspace(
        str(claimed["approval_id"]),
        profile_id=profile.id,
        workspace_path=workspace,
        runner_identity={"receipt_protocol": "bluefire.runner-receipt-wal.v2"},
        recovery_context={"test": "active-unsettled"},
    )
    interrupted = _persist_interrupted_scenario_job(
        service,
        {**request, "approval_request_id": claimed["approval_id"]},
    )

    with pytest.raises(APIError) as refused:
        service.retry_job(str(interrupted["job_id"]))

    assert refused.value.status == 409
    assert refused.value.code == "job_retry_refused"
    assert service.product_store.list_jobs() == [interrupted]
    service.close()


def test_execute_job_requires_separate_exact_approval_before_callback(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    runner = ReadyInventoryRunner()

    def unavailable_after_gate(_profile: object) -> tuple[ReadyInventoryRunner, Path]:
        # Readiness is exact before review. The deliberately non-executing fake
        # then proves the callback was released only after approval was claimed.
        return runner, sandbox

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=unavailable_after_gate,
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "approval": {"confirmed": True, "approved_by": "must-not-auto-apply"},
        }
    )
    job_id = str(submission["job"]["job_id"])
    awaiting = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=3,
    )

    assert awaiting["state"] == "awaiting_approval"
    assert submission["approval_request"]["status"] == "pending"
    assert submission["approval_request"]["approved_by"] is None
    assert "nonce" not in submission["approval_request"]
    reloaded = service.job(job_id)
    assert reloaded["approval_request"] == submission["approval_request"]
    assert "nonce" not in reloaded["approval_request"]

    approved = service.approve_job(job_id, {"approved_by": "local-reviewer"})
    assert approved["job"]["state"] == "running"
    assert approved["approval_request"]["status"] == "consumed"
    assert "nonce" not in approved["approval_request"]

    settled = service.job_controller.wait(job_id, timeout=3)
    assert settled["state"] == "completed"
    assert runner.execute_calls > 0
    approval_id = str(submission["approval_request"]["approval_id"])
    assert service.product_store.get_approval_request(approval_id)["status"] == "claimed"
    service.close()


def test_managed_runner_lifecycle_is_inert_and_actions_are_explicit(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    lifecycle = RecordingRunnerLifecycle(ReadyInventoryRunner(), sandbox)
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_lifecycle=lifecycle,  # type: ignore[arg-type]
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )

    assert lifecycle.calls == []
    assert service.runner_status(profile_id=profile.id)["state"] == "ready"
    service.bootstrap_runner(profile_id=profile.id, allow_upgrade=True)
    service.start_runner(profile_id=profile.id)
    service.stop_runner(profile_id=profile.id)
    service.revoke_runner()
    service.remove_runner(confirm_runner_id=RUNNER_ID)

    bootstrap_call = next(value for action, value in lifecycle.calls if action == "bootstrap")
    allowed_profiles, allow_upgrade = bootstrap_call
    assert allow_upgrade is True
    assert set(allowed_profiles) == {
        item.id for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    }
    assert ("start", profile.id) in lifecycle.calls
    assert ("stop", profile.id) in lifecycle.calls
    assert ("remove", RUNNER_ID) in lifecycle.calls
    service.close()


def test_default_runner_binding_never_bootstraps_or_starts_implicitly(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    lifecycle = RecordingRunnerLifecycle(ReadyInventoryRunner(), sandbox)
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_lifecycle=lifecycle,  # type: ignore[arg-type]
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
    }

    report = service.preflight(request)

    assert report["runner_readiness"]["profile_id"] == profile.id
    assert lifecycle.calls == [("client_for_profile", profile.id)]
    service.close()


def test_execute_preflight_binds_declared_per_run_collectors(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
        "collectors": ["collector.filesystem.sandbox.v1"],
    }

    report = service.preflight(request)

    assert report["collectors"] == ["collector.filesystem.sandbox.v1"]
    assert report["collector_binding"] == {
        "schema_version": "bluefire.collector-binding.v1",
        "collectors": ["collector.filesystem.sandbox.v1"],
        "authority": "declared-per-run-observable-artifacts",
    }
    assert isinstance(report["approval_binding"], Mapping)
    service.close()


def test_execute_preflight_binds_versioned_runtime_collector_settings(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            }
        }
    )
    request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "execute",
        "runner_profile_id": profile.id,
        "autonomy": "off",
        "target_scope": {"scope_refs": list(profile.scope)},
        "collector_runtime": runtime.to_dict(),
    }

    report = service.preflight(request)

    assert report["collectors"] == [FilesystemCollector.descriptor.id]
    assert report["collector_runtime"] == runtime.to_dict()
    assert report["collector_binding"] == {
        "schema_version": "bluefire.collector-binding.v2",
        "settings": runtime.to_dict(),
        "settings_hash": runtime.settings_hash,
        "enabled_collectors": [FilesystemCollector.descriptor.id],
        "disabled_collectors": [],
        "authority": "versioned-runtime-settings-and-independent-observation",
    }
    assert isinstance(report["approval_binding"], Mapping)
    service.close()


def test_disabled_runtime_backend_needs_no_live_source_or_operational_settings(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
        collector_registry_factory=lambda root: CollectorRegistry((FilesystemCollector(root),)),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            },
            "collector.process.native.v1": {"enabled": False, "settings": {}},
            "collector.network.loopback-receiver.v1": {
                "enabled": False,
                "settings": {},
            },
        }
    )

    report = service.preflight(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
            "collector_runtime": runtime.to_dict(),
        }
    )

    assert report["collectors"] == [FilesystemCollector.descriptor.id]
    assert set(report["collector_binding"]["disabled_collectors"]) == {
        "collector.process.native.v1",
        "collector.network.loopback-receiver.v1",
    }
    service.close()


def test_managed_collector_authority_cannot_change_between_readiness_and_dispatch(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    maximums = iter((1024, 2048))

    def changing_factory(root: Path) -> CollectorRegistry:
        return CollectorRegistry((FilesystemCollector(root, max_file_bytes=next(maximums)),))

    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        collector_registry_factory=changing_factory,
    )
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["staged/bundle.jsonl"],
                },
            }
        }
    )
    _registry, authority = service._managed_collector_registry(sandbox, runtime)

    with pytest.raises(CollectorError, match="authority changed"):
        service._managed_collector_registry(
            sandbox,
            runtime,
            expected_authority=authority,
        )
    service.close()


def test_execute_preflight_rejects_unavailable_collector_selection(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    with pytest.raises(APIError, match="collector_unavailable"):
        service.preflight(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
                "collectors": ["collector.sysmon-eventlog.v1"],
            }
        )
    with pytest.raises(APIError, match="collectors_invalid"):
        service.preflight(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "simulate",
                "autonomy": "off",
                "collectors": ["collector.filesystem.sandbox.v1"],
            }
        )
    service.close()


def test_source_collector_session_requires_run_evidence_and_approved_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "observed.txt").write_text("observed", encoding="utf-8")
    runtime = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": "stage_records",
                    "paths": ["observed.txt"],
                },
            }
        }
    )
    parent = EvidenceRecord.create(
        run_id="run-source",
        step_id="stage_records",
        behavior_id="collection.independent-observation.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.EXECUTED,
        producer="rust-runner.test.v1",
        runner_profile_id="profile.test.v1",
        target_scope_ref="runner-profile:profile.test.v1",
        content={"artifact_type": "runner_receipt", "status": "succeeded"},
    )
    registry = CollectorRegistry((FilesystemCollector(tmp_path),))
    session = registry.collect_configured(
        runtime,
        CollectionRequest(
            run_id="run-source",
            step_id="stage_records",
            behavior_id="collection.independent-observation.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test.v1",
            target_scope_ref="runner-profile:profile.test.v1",
            parent_evidence_ids=(parent.evidence_id,),
        ),
    )
    records = [
        parent.to_dict(),
        *[record.to_dict() for result in session.results.values() for record in result.records],
    ]
    source = {
        "run_id": "run-source",
        "evidence": {"records": records},
        "steps": [
            {
                "step_id": "stage_records",
                "behavior_id": "collection.independent-observation.v1",
                "action_id": "sandbox.collection.stage.v1",
                "policy": {
                    "step_id": "stage_records",
                    "behavior_id": "collection.independent-observation.v1",
                    "action_id": "sandbox.collection.stage.v1",
                    "runner_profile_id": "profile.test.v1",
                },
                "evidence_ids": [
                    parent.evidence_id,
                    *[
                        record.evidence_id
                        for result in session.results.values()
                        for record in result.records
                    ],
                ],
            }
        ],
        "collector_session": session.to_dict(),
        "policy": {
            "approval_context": {
                "collector_binding": BlueFireService._collector_binding((), runtime),
                "collector_registry_authority": registry.authority_snapshot(
                    runtime,
                    expected_sandbox=tmp_path,
                ),
            }
        },
    }

    assert BlueFireService._source_collector_runtime(source) == runtime

    detached = copy.deepcopy(source)
    detached["run_id"] = "run-detached"
    with pytest.raises(ReplayError, match="failed integrity validation"):
        BlueFireService._source_collector_runtime(detached)

    rebound = copy.deepcopy(source)
    rebound["policy"]["approval_context"]["collector_binding"]["settings_hash"] = (
        "sha256:" + "0" * 64
    )
    with pytest.raises(ReplayError, match="not bound to its approved runtime settings"):
        BlueFireService._source_collector_runtime(rebound)

    counterfeit_session = copy.deepcopy(source)
    stored_session = counterfeit_session["collector_session"]
    stored_session["results"][FilesystemCollector.descriptor.id]["descriptor"][
        "name"
    ] = "Counterfeit filesystem observer"
    stored_session["session_hash"] = content_hash(
        {key: value for key, value in stored_session.items() if key != "session_hash"}
    )
    with pytest.raises(ReplayError, match="collection session"):
        BlueFireService._source_collector_runtime(counterfeit_session)

    additional = CollectorRegistry((FilesystemCollector(tmp_path),)).collect_configured(
        runtime,
        CollectionRequest(
            run_id="run-source",
            step_id="stage_records-retry",
            behavior_id="collection.independent-observation.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test.v1",
            target_scope_ref="runner-profile:profile.test.v1",
        ),
    )
    omitted = copy.deepcopy(source)
    omitted["evidence"]["records"].extend(
        record.to_dict() for result in additional.results.values() for record in result.records
    )
    with pytest.raises(ReplayError, match="failed integrity validation"):
        BlueFireService._source_collector_runtime(omitted)


def test_source_collector_authority_requires_backend_bijection_and_canonical_identity() -> None:
    runtime, source = _canonical_collector_authority_source()

    assert BlueFireService._source_collector_runtime(source) == runtime

    authority_mutations: list[dict[str, Any]] = []
    unexpected_top_field = copy.deepcopy(source)
    unexpected_top_field["policy"]["approval_context"]["collector_registry_authority"][
        "unapproved"
    ] = True
    authority_mutations.append(unexpected_top_field)

    wrong_settings = copy.deepcopy(source)
    wrong_settings["policy"]["approval_context"]["collector_registry_authority"][
        "settings_hash"
    ] = ("sha256:" + "0" * 64)
    authority_mutations.append(wrong_settings)

    missing_backend = copy.deepcopy(source)
    missing_backend["policy"]["approval_context"]["collector_registry_authority"]["backends"].pop()
    authority_mutations.append(missing_backend)

    duplicate_backend = copy.deepcopy(source)
    duplicate_rows = duplicate_backend["policy"]["approval_context"][
        "collector_registry_authority"
    ]["backends"]
    duplicate_rows[1] = copy.deepcopy(duplicate_rows[0])
    authority_mutations.append(duplicate_backend)

    changed_descriptor = copy.deepcopy(source)
    changed_descriptor["policy"]["approval_context"]["collector_registry_authority"]["backends"][0][
        "descriptor"
    ]["name"] = "Unapproved descriptor"
    authority_mutations.append(changed_descriptor)

    changed_implementation = copy.deepcopy(source)
    changed_implementation["policy"]["approval_context"]["collector_registry_authority"][
        "backends"
    ][0]["implementation_id"] = "bluefire.collectors.SubstituteCollector"
    authority_mutations.append(changed_implementation)

    unexpected_backend_field = copy.deepcopy(source)
    unexpected_backend_field["policy"]["approval_context"]["collector_registry_authority"][
        "backends"
    ][0]["adapter"] = "unapproved"
    authority_mutations.append(unexpected_backend_field)

    for mutated in authority_mutations:
        _rehash_collector_authority(
            mutated["policy"]["approval_context"]["collector_registry_authority"]
        )
        with pytest.raises(ReplayError, match="collector registry authority"):
            BlueFireService._source_collector_runtime(mutated)


def test_source_collector_authority_rejects_rehashed_source_schema_mutations() -> None:
    runtime, source = _canonical_collector_authority_source()

    assert BlueFireService._source_collector_runtime(source) == runtime

    source_mutations: list[dict[str, Any]] = []

    filesystem_extra = copy.deepcopy(source)
    filesystem_extra["policy"]["approval_context"]["collector_registry_authority"]["backends"][0][
        "source_authority"
    ]["sandbox_path"] = "C:/unapproved"
    source_mutations.append(filesystem_extra)

    filesystem_boolean_limit = copy.deepcopy(source)
    filesystem_boolean_limit["policy"]["approval_context"]["collector_registry_authority"][
        "backends"
    ][0]["source_authority"]["max_file_bytes"] = True
    source_mutations.append(filesystem_boolean_limit)

    filesystem_timeout = copy.deepcopy(source)
    filesystem_timeout["policy"]["approval_context"]["collector_registry_authority"]["backends"][0][
        "source_authority"
    ]["read_timeout_seconds"] = 4.0
    source_mutations.append(filesystem_timeout)

    receiver_remote_host = copy.deepcopy(source)
    receiver_remote_host["policy"]["approval_context"]["collector_registry_authority"]["backends"][
        1
    ]["source_authority"]["host"] = "192.0.2.10"
    source_mutations.append(receiver_remote_host)

    receiver_boolean_port = copy.deepcopy(source)
    receiver_boolean_port["policy"]["approval_context"]["collector_registry_authority"]["backends"][
        1
    ]["source_authority"]["port"] = True
    source_mutations.append(receiver_boolean_port)

    receiver_session = copy.deepcopy(source)
    receiver_session["policy"]["approval_context"]["collector_registry_authority"]["backends"][1][
        "source_authority"
    ]["session_id"] = ("B" * 64)
    source_mutations.append(receiver_session)

    process_identity = copy.deepcopy(source)
    process_identity["policy"]["approval_context"]["collector_registry_authority"]["backends"][2][
        "source_authority"
    ]["authorized_processes"][0]["creation_identity"] = "pid"
    source_mutations.append(process_identity)

    process_not_authorized = copy.deepcopy(source)
    process_not_authorized["policy"]["approval_context"]["collector_registry_authority"][
        "backends"
    ][2]["source_authority"]["authorized_processes"][0]["process_id"] = 322
    source_mutations.append(process_not_authorized)

    duplicate_process = copy.deepcopy(source)
    process_rows = duplicate_process["policy"]["approval_context"]["collector_registry_authority"][
        "backends"
    ][2]["source_authority"]["authorized_processes"]
    process_rows.append(copy.deepcopy(process_rows[0]))
    source_mutations.append(duplicate_process)

    for mutated in source_mutations:
        _rehash_collector_authority(
            mutated["policy"]["approval_context"]["collector_registry_authority"]
        )
        with pytest.raises(ReplayError, match="backend is not canonical"):
            BlueFireService._source_collector_runtime(mutated)


def test_source_collector_runtime_requires_persisted_registry_authority() -> None:
    _runtime, source = _canonical_collector_authority_source()
    del source["policy"]["approval_context"]["collector_registry_authority"]

    with pytest.raises(ReplayError, match="no approved registry authority"):
        BlueFireService._source_collector_runtime(source)


def test_exact_replay_inherits_and_cannot_replace_legacy_collector_binding(
    tmp_path: Path,
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    source = {
        "policy": {
            "approval_context": {
                "collector_binding": BlueFireService._collector_binding(
                    [FilesystemCollector.descriptor.id]
                )
            }
        }
    }

    inherited, runtime = service._replay_collector_configuration(
        {},
        source=source,
        mode=ExecutionMode.EXECUTE,
        exact=True,
    )
    assert inherited == (FilesystemCollector.descriptor.id,)
    assert runtime is None

    with pytest.raises(APIError, match="collectors_invalid"):
        service._replay_collector_configuration(
            {"collectors": []},
            source=source,
            mode=ExecutionMode.EXECUTE,
            exact=True,
        )
    service.close()


def test_execute_job_cancel_reaches_exact_task_aware_runner(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = CancellableTaskRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
    )
    job_id = str(submission["job"]["job_id"])
    service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=3,
    )
    service.approve_job(job_id, {"approved_by": "cancellation-reviewer"})
    assert runner.started.wait(3)

    cancelling = service.cancel_job(job_id)
    cancelled = service.job_controller.wait(job_id, timeout=5)

    assert cancelling["state"] == JobState.CANCELLING.value
    assert cancelled["state"] == JobState.CANCELLED.value
    assert runner.execute_calls == 1
    assert runner.task_id is not None
    assert runner.durable_result_path is not None
    assert runner.durable_result_path.parent.name == ".bluefire-runner-results"
    service.close()


def test_execute_job_translates_runner_cancel_during_proposal_continuation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
    )
    cancellation_event = threading.Event()
    cancellation_event.set()

    class ContinuationContext:
        job_id = "job-" + "0" * 32

        @staticmethod
        def progress_snapshot() -> Mapping[str, Any]:
            return {"proposal_record_id": "proposal-review-" + "0" * 32}

        @staticmethod
        def checkpoint(_progress: Mapping[str, Any]) -> None:
            return None

    context = ContinuationContext()
    context.cancellation_event = cancellation_event  # type: ignore[attr-defined]
    monkeypatch.setattr(
        service.product_store,
        "get_ai_proposal_review",
        lambda _proposal_record_id: {"job_id": context.job_id, "status": "accepted"},
    )

    def cancel_continuation(*_args: object, **_kwargs: object) -> Mapping[str, Any]:
        raise RunnerTaskCancelled("runner confirmed cancellation")

    monkeypatch.setattr(service, "_run_ai_proposal_continuation", cancel_continuation)

    with pytest.raises(JobCancelled, match="cancellation was confirmed"):
        service._execute_job(context, {})  # type: ignore[arg-type]

    service.close()


def test_cleanup_pending_callback_cannot_override_cancellation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    callback_started = threading.Event()
    release_callback = threading.Event()
    run_id = "run-20260826T000000Z-" + "c" * 16

    def cleanup_pending_run(
        _request: Mapping[str, Any],
        **_kwargs: object,
    ) -> Mapping[str, Any]:
        callback_started.set()
        if not release_callback.wait(timeout=3):
            raise AssertionError("test callback was not released")
        return {
            "schema_version": "bluefire.run-result.v1",
            "run_id": run_id,
            "status": "incomplete",
            "mode": ExecutionMode.EXECUTE.value,
            "steps": [],
            "cleanup": {
                "attempted": True,
                "success": False,
                "outstanding_receipt_count": 1,
            },
        }

    monkeypatch.setattr(service, "run", cleanup_pending_run)
    queued = service.job_controller.submit("scenario.run", {"mode": "execute"})
    job_id = str(queued["job_id"])
    try:
        service.job_controller.wait_for_state(job_id, {JobState.RUNNING}, timeout=3)
        assert callback_started.wait(timeout=3)
        cancelling = service.cancel_job(job_id)
        assert cancelling["state"] == JobState.CANCELLING.value
        release_callback.set()
        settled = service.job_controller.wait(job_id, timeout=3)
        assert settled["state"] == JobState.CANCELLED.value
        assert settled["result_ref"] is None
        assert settled.get("completion_confirmed") is not True
    finally:
        release_callback.set()
        service.close()


def test_execute_preflight_refuses_missing_enabled_action_without_side_effects(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner(actions=EXECUTE_PROFILE_ACTIONS - {"sandbox.fixture.create.v1"})
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )

    with pytest.raises(APIError) as refused:
        service.submit_run(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
            }
        )

    assert refused.value.code == "preflight_refused"
    assert refused.value.details == [
        "Runner inventory is missing enabled action(s): sandbox.fixture.create.v1"
    ]
    assert not (sandbox / ".bluefire-executions").exists()
    assert runner.execute_calls == 0
    service.close()


@pytest.mark.parametrize("sandbox_kind", ["missing", "file"])
def test_execute_preflight_refuses_missing_or_unusable_sandbox_without_creating_it(
    tmp_path: Path,
    sandbox_kind: str,
) -> None:
    sandbox = tmp_path / "configured-sandbox"
    if sandbox_kind == "file":
        sandbox.write_text("not a directory", encoding="utf-8")
    runner = ReadyInventoryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )

    with pytest.raises(APIError) as refused:
        service.submit_run(
            {
                "scenario_id": "scenario.sandbox.research.chain.v1",
                "mode": "execute",
                "runner_profile_id": profile.id,
                "autonomy": "off",
                "target_scope": {"scope_refs": list(profile.scope)},
            }
        )

    assert refused.value.code == "preflight_refused"
    assert "sandbox" in " ".join(refused.value.details or []).casefold()
    assert str(sandbox) not in " ".join(refused.value.details or [])
    assert not sandbox.exists() if sandbox_kind == "missing" else sandbox.is_file()
    assert runner.inventory_calls == 0
    assert runner.execute_calls == 0
    service.close()


@pytest.mark.parametrize("failure", ["mutation", "disconnect"])
def test_execute_fails_closed_on_post_approval_runner_change(
    tmp_path: Path,
    failure: str,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = PostApprovalReadinessRunner(failure)
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda _profile: (runner, sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "autonomy": "off",
            "target_scope": {"scope_refs": list(profile.scope)},
        }
    )
    readiness = submission["preflight"]["runner_readiness"]
    assert readiness["runner_identity_digest"].startswith("sha256:")
    assert readiness["inventory_digest"].startswith("sha256:")
    assert readiness["freshness"]["max_age_seconds"] == 15 * 60
    job_id = str(submission["job"]["job_id"])
    service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=3,
    )

    service.approve_job(job_id, {"approved_by": "readiness-reviewer"})
    failed = service.job_controller.wait(job_id, timeout=3)

    assert failed["state"] == "failed"
    assert failed["error"] == {
        "code": "execution_callback_failed",
        "message": "execution callback failed",
        "exception_type": "APIError",
    }
    assert "sensitive/local" not in str(failed)
    assert runner.inventory_calls == 3
    assert runner.execute_calls == 0
    approval_id = str(submission["approval_request"]["approval_id"])
    assert service.product_store.get_approval_request(approval_id)["status"] == "claimed"
    assert service.product_store.get_execution_workspace(approval_id)["state"] == "not_required"
    service.close()


def test_action_implementation_payload_is_strict_and_persisted_in_execute_job(
    tmp_path: Path,
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    simulate_request = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "simulate",
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
        "action_implementations": {},
    }
    with pytest.raises(APIError) as simulate_refused:
        service.preflight(simulate_request)
    assert simulate_refused.value.status == 400
    assert simulate_refused.value.code == "action_implementations_invalid"

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    service.close()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "execute-runs",
        runner_factory=lambda _profile: (ReadyInventoryRunner(), sandbox),
    )
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    selections = {"create_fixture": "sandbox.fixture.create.v1"}
    submission = service.submit_run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "execute",
            "runner_profile_id": profile.id,
            "target_scope": {"scope_refs": list(profile.scope)},
            "action_implementations": selections,
        }
    )
    job_id = str(submission["job"]["job_id"])
    awaiting = service.job_controller.wait_for_state(
        job_id,
        {JobState.AWAITING_APPROVAL},
        timeout=3,
    )

    assert awaiting["request"]["action_implementations"] == selections
    assert submission["preflight"]["action_implementations"]["create_fixture"] == (
        "sandbox.fixture.create.v1"
    )
    assert (
        submission["approval_request"]["plan_digest"]
        == submission["preflight"]["approval_binding"]["plan_digest"]
    )
    service.close()


def test_execute_approval_ids_create_distinct_contained_workspaces(tmp_path: Path) -> None:
    configured = tmp_path / "configured-sandbox"
    configured.mkdir()

    first = BlueFireService._isolated_execution_sandbox(
        configured,
        {"approval_id": "approval-" + "a" * 32},
    )
    second = BlueFireService._isolated_execution_sandbox(
        configured,
        {"approval_id": "approval-" + "b" * 32},
    )

    assert first != second
    assert first.parent == second.parent == configured / ".bluefire-executions"
    assert first.is_dir() and second.is_dir()


def test_execute_confirmation_becomes_a_consumed_exact_envelope_approval(
    tmp_path: Path,
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    scenario = next(item for item in service._scenarios if item.id.endswith("research.chain.v1"))
    profile = next(
        item for item in service.config.runner_profiles if item.mode is ExecutionMode.EXECUTE
    )
    autonomy, provider = service._ai_context({"autonomy": "off"})
    orchestrator = Orchestrator(
        service.registry,
        service.store,
        runner=object(),  # type: ignore[arg-type]
    )

    record = service._bind_and_consume_approval(
        scenario=scenario,
        profile=profile,
        target_scope={"scope_refs": list(profile.scope)},
        autonomy=autonomy,
        ai_provider=provider,
        approved_by="local-test-operator",
        orchestrator=orchestrator,
    )

    assert record["status"] == "consumed"
    assert record["approved_by"] == "local-test-operator"
    assert record["profile_id"] == profile.id
    assert record["nonce"]
    persisted = service.product_store.get_approval_request(str(record["approval_id"]))
    assert persisted["status"] == "consumed"
    assert persisted["state_digest"].startswith("sha256:")
    assert persisted["plan_digest"].startswith("sha256:")
    assert persisted["target_scope_digest"].startswith("sha256:")
    requested_at = datetime.fromisoformat(str(persisted["requested_at"]).replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(str(persisted["expires_at"]).replace("Z", "+00:00"))
    assert (expires_at - requested_at).total_seconds() >= max(
        15 * 60,
        profile.budgets.max_seconds + 60,
    )


def test_catalog_reports_provider_health_without_resolving_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "catalog-test-key-value")  # pragma: allowlist secret
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")

    catalog = service.catalog()

    assert catalog["ai"]["autonomy_levels"] == ["off", "assist", "auto"]
    remote = next(
        provider
        for provider in catalog["ai"]["providers"]
        if provider["provider_id"] == "openai-responses.v1"
    )
    assert remote["health"]["credential_available"] is True
    assert "catalog-test-key-value" not in json.dumps(  # pragma: allowlist secret
        catalog, sort_keys=True
    )


def test_service_enumerates_all_checkout_and_packaged_scenarios_in_stable_order(
    tmp_path: Path,
) -> None:
    expected = [
        "scenario.ai-adaptive.safe-chain.v1",
        "scenario.detection.regression.v1",
        "scenario.endpoint.deep-behavior-lab.v1",
        "scenario.linux-container.validation.v1",
        "scenario.operator.representative-validation.v1",
        "scenario.restricted.persistence-canary.v1",
        "scenario.sandbox.research.chain.v1",
        "scenario.windows.endpoint.validation.v1",
    ]
    checkout = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "checkout-runs")
    packaged = BlueFireService(
        project_root=tmp_path / "no-checkout",
        config=load_config(ROOT / "config" / "bluefire.example.yaml"),
        runs_dir=tmp_path / "packaged-runs",
    )

    assert [item["id"] for item in checkout.scenarios()["scenarios"]] == expected
    assert [item["id"] for item in packaged.scenarios()["scenarios"]] == expected


def test_service_rejects_duplicate_scenario_ids(tmp_path: Path) -> None:
    scenario_root = tmp_path / "project" / "scenarios"
    scenario_root.mkdir(parents=True)
    source = ROOT / "scenarios" / "sandbox_research_chain.yaml"
    shutil.copyfile(source, scenario_root / "first.yaml")
    shutil.copyfile(source, scenario_root / "second.yaml")

    with pytest.raises(ContractError, match="duplicate scenario ID"):
        BlueFireService(
            project_root=tmp_path / "project",
            config=load_config(ROOT / "config" / "bluefire.example.yaml"),
            runs_dir=tmp_path / "runs",
        )


@pytest.mark.parametrize("autonomy", ["off", "assist", "auto"])
def test_preflight_records_strict_autonomy_and_provider_metadata(
    tmp_path: Path, autonomy: str
) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")

    report = service.preflight(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": autonomy,
            "ai_provider_id": "deterministic-offline.v1",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
    )

    assert report["autonomy"] == autonomy
    assert report["ai_enabled"] is (autonomy != "off")
    assert report["ai_provider"]["provider_id"] == "deterministic-offline.v1"
    assert report["ai_provider"]["trust_boundary"] == ("proposal_schema_then_deterministic_policy")
    assert report["plan"]["autonomy"] == autonomy
    assert report["plan"]["ai_provider"]["provider_id"] == "deterministic-offline.v1"


def test_legacy_ai_flag_maps_to_assist_and_conflicts_are_rejected(tmp_path: Path) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    base = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "simulate",
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }

    report = service.preflight({**base, "ai_enabled": True})
    assert report["autonomy"] == "assist"

    with pytest.raises(APIError) as exc_info:
        service.preflight({**base, "autonomy": "auto", "ai_enabled": True})
    assert exc_info.value.code == "autonomy_conflict"


def test_simulate_run_and_replay_persist_autonomy_provider_and_lineage(tmp_path: Path) -> None:
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")
    base = {
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": "simulate",
        "ai_provider_id": "deterministic-offline.v1",
        "target_scope": {"scope_refs": ["sandbox.workspace"]},
    }

    original = service.run({**base, "autonomy": "auto"})
    replay = service.replay(
        original["run_id"],
        {
            "autonomy": "assist",
            "ai_provider_id": "deterministic-offline.v1",
        },
    )
    parameter_replay = service.replay(
        original["run_id"],
        {"parameter_overrides": {"create_fixture": {"record_count": 3}}},
    )

    persisted = service.detail(original["run_id"])
    assert original["autonomy"] == "auto"
    assert original["ai_provider"]["provider_id"] == "deterministic-offline.v1"
    assert persisted["plan"]["autonomy"] == "auto"
    assert persisted["plan"]["ai_provider"]["provider_id"] == "deterministic-offline.v1"
    assert replay["autonomy"] == "assist"
    assert replay["replay"]["autonomy_from"] == "auto"
    assert replay["replay"]["autonomy_to"] == "assist"
    assert replay["replay"]["ai_provider_to"] == "deterministic-offline.v1"
    create_step = next(
        step for step in parameter_replay["scenario"]["steps"] if step["id"] == "create_fixture"
    )
    assert create_step["parameters"]["record_count"] == 3
    assert parameter_replay["replay"]["parameter_overrides"] == {
        "create_fixture": {"record_count": 3}
    }
    original_create = next(
        step for step in persisted["scenario"]["steps"] if step["id"] == "create_fixture"
    )
    assert original_create["parameters"]["record_count"] == 8


def test_remote_provider_selection_persists_only_the_credential_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_value = "service-test-key-value"  # pragma: allowlist secret
    monkeypatch.setenv("OPENAI_API_KEY", secret_value)

    def refuse_network(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("service metadata recording must not invoke the model provider")

    monkeypatch.setattr(UrllibAIJSONTransport, "post", refuse_network)
    service = BlueFireService(project_root=ROOT, runs_dir=tmp_path / "runs")

    result = service.run(
        {
            "scenario_id": "scenario.sandbox.research.chain.v1",
            "mode": "simulate",
            "autonomy": "off",
            "ai_provider_id": "openai-responses.v1",
            "target_scope": {"scope_refs": ["sandbox.workspace"]},
        }
    )

    persisted = service.detail(result["run_id"])
    serialized = json.dumps(persisted, sort_keys=True)
    assert secret_value not in serialized
    assert persisted["ai_provider"]["credential_reference"] == "OPENAI_API_KEY"
    assert persisted["ai_provider"]["health"]["credential_available"] is True
    assert persisted["ai_proposals"] == []
