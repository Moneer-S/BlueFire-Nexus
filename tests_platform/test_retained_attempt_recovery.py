"""Durable retained attempt closure without business dispatch."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import product_store_retained_recovery as recovery
from bluefire import retained_artifacts as retained
from bluefire import retained_attempt_recovery as runtime
from bluefire.adaptive_dispatch import reviewed_operation
from bluefire.composition_authority import native_envelope
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.execution_contracts import execution_task_identity
from bluefire.planner import DeterministicPlanner
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.retained_receiver_closure import close_exact_receiver
from bluefire.run_store import RunStore, RunStoreError
from bluefire.runner_contracts import (
    _verified_grant_attempt,
    _verified_grant_cleanup,
    build_execution_manifest,
    build_runner_profile,
)
from bluefire.runner_linux_containment import LinuxPrivateProcessContainment
from bluefire.runner_management_service import RunnerManagementServiceMixin
from bluefire.runner_private_files import _windows_extended_path
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_capability_composition import state as state
from tests_platform.test_composition_runtime import profile as execution_profile
from tests_platform.test_orchestrator import StructuredFakeRunner, _write_bound_receipt
from tests_platform.test_product_store_capability_grants import (
    claim,
    reserve,
)
from tests_platform.test_product_store_capability_grants import saved as _saved_fixture
from tests_platform.test_retained_artifact_execution import generated_bytes, v2_state

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def saved(state, tmp_path):
    return _saved_fixture.__wrapped__(v2_state(state), tmp_path)


def _bound(saved, tmp_path):
    store, state, _, _ = saved
    lease = reserve(saved)
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"], now_ms=4500, current_environment=state["current_environment"]
    )
    store.bind_capability_receiver(
        lease["attempt_id"],
        session_generation="generation-" + lease["attempt_id"],
        review_digest=content_hash("session-review"),
        process_id=424242,
        creation_identity="123456789",
    )
    root = tmp_path / "sandbox" / ".bluefire-executions" / lease["attempt_id"]
    (_windows_extended_path(root) if os.name == "nt" else root).mkdir(parents=True)
    profile = {
        "sandbox_root": str(root.resolve()),
        "policy_digest": content_hash("sealed-profile"),
        "profile_id": "fixture-profile",
    }
    store.bind_capability_workspace(
        lease["attempt_id"],
        runner_policy_digest=profile["policy_digest"],
        workspace_path_digest=content_hash({"sandbox_root": profile["sandbox_root"]}),
        workspace_path=profile["sandbox_root"],
        runner_profile=profile,
        runner_readiness={"schema_version": "fixture-readiness"},
        now_ms=4500,
        current_environment=state["current_environment"],
    )
    return store, lease, root


def _effect_bound(saved, tmp_path, *, register=True):
    store, state, compiled, _ = saved
    selected = execution_profile()
    scenario = ScenarioDefinition.from_mapping(compiled["scenario"])
    plan = DeterministicPlanner(state["registry"]).compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=selected,
        autonomy="off",
        ai_enabled=False,
        action_implementations=compiled["action_implementations"],
    )
    envelope = native_envelope(plan, compiled)
    submission = uuid.uuid4()
    token = submission.hex
    run_id = "run-20261104T000000Z-" + token[:16]
    marker = {
        "parent_job_id": state["parent_job_id"],
        "grant_id": state["grant"]["grant_id"],
        "grant_digest": state["grant"]["grant_digest"],
        "attempt_id": "attempt-" + token,
        "compiled_digest": compiled["compiled_digest"],
        "run_id": run_id,
    }
    request = {"composition_attempt": marker}
    store.create_idempotent_job(
        "composition.attempt",
        request,
        submission_id=str(submission),
        intent_digest=content_hash(request),
    )
    arguments = {
        "expected_compiled_digest": compiled["compiled_digest"],
        "attempt_id": marker["attempt_id"],
        "job_id": "job-" + token,
        "run_id": run_id,
        "plan_digest": content_hash(plan.to_dict()),
        "native_envelope_digest": content_hash(envelope),
        "current_environment": state["current_environment"],
        "now_ms": 3000,
    }
    lease = store.reserve_capability_attempt(
        state["grant"]["grant_id"],
        compiled,
        **arguments,
    )
    RunStore(tmp_path / "runs").create_run(
        scenario=compiled["scenario"],
        plan=plan.to_dict(),
        policy={},
        profile={},
        _reserved_run_id=run_id,
    )
    attempt_id = lease["attempt_id"]
    claimed = claim(saved, lease)
    store.start_capability_preparation(
        attempt_id,
        now_ms=4500,
        current_environment=state["current_environment"],
    )
    store.bind_capability_receiver(
        attempt_id,
        session_generation="generation-" + attempt_id,
        review_digest=content_hash("session-review"),
        process_id=424242,
        creation_identity="123456789",
    )
    root = tmp_path / "sandbox" / ".bluefire-executions" / attempt_id
    (_windows_extended_path(root) if os.name == "nt" else root).mkdir(parents=True)
    profile = build_runner_profile(
        selected,
        sandbox_root=root,
        reviewed_execution=envelope,
    )
    store.bind_capability_workspace(
        attempt_id,
        runner_policy_digest=profile["policy_digest"],
        workspace_path_digest=content_hash({"sandbox_root": profile["sandbox_root"]}),
        workspace_path=profile["sandbox_root"],
        runner_profile=profile,
        runner_readiness={"schema_version": "fixture-readiness"},
        now_ms=4500,
        current_environment=state["current_environment"],
    )
    step = next(row for row in plan.steps if row.action_id == "sandbox.fixture.create.v1")
    manifest = build_execution_manifest(
        run_id=lease["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action=state["registry"].get_action(step.action_id),
        runner_profile=profile,
        params={"path": "fixtures/input.jsonl", **step.parameters},
        filesystem_scope=(),
        network_destinations=(),
        evidence_refs=(),
        approval_record=None,
        grant_attempt=_verified_grant_attempt(
            claimed["document"],
            expected_document_digest=claimed["document_digest"],
        ),
        reviewed_operation=reviewed_operation(step, profile),
        now=datetime.fromtimestamp(5, timezone.utc),
    )
    task_id, transport_hash = execution_task_identity(manifest, profile)
    if register:
        store.register_capability_task(
            attempt_id,
            task_id=task_id,
            step_id=step.step_id,
            request_hash=manifest["request_hash"],
            now_ms=5000,
            current_environment=state["current_environment"],
            manifest=manifest,
            runner_profile=profile,
        )
    return store, lease, root, selected, profile, manifest, task_id, transport_hash, plan


class _RecoveryWal:
    def __init__(self):
        self.fake = StructuredFakeRunner()
        self.results = {}
        self.execute_actions = []

    def remember(self, manifest, profile, task_id, transport_hash):
        result = self.fake.execute(manifest, profile)
        self.results[(task_id, transport_hash)] = result
        return result

    def recover(self, task_id, request_hash):
        result = self.results.get((task_id, request_hash))
        if result is None:
            return {"state": "unknown"}
        return {
            "state": "completed",
            "original_task_id": task_id,
            "original_request_hash": request_hash,
            "result": result,
        }

    def execute_task(self, manifest, runner_profile, *, task_id, **_kwargs):
        self.execute_actions.append(manifest["action_id"])
        _, request_hash = execution_task_identity(manifest, runner_profile)
        return self.remember(manifest, runner_profile, task_id, request_hash)


class _PartialRecoveryWal(_RecoveryWal):
    def __init__(self, original_manifest, original_profile, *, exact_ids=True):
        super().__init__()
        self.original_manifest = original_manifest
        self.original_profile = original_profile
        self.exact_ids = exact_ids

    def execute_task(self, manifest, runner_profile, *, task_id, **_kwargs):
        result = dict(super().execute_task(manifest, runner_profile, task_id=task_id, **_kwargs))
        if self.execute_actions.count("sandbox.cleanup.v1") != 1:
            return result
        survivor = manifest["params"]["receipt_ids"][-1]
        assert (
            _write_bound_receipt(
                self.original_manifest,
                self.original_profile,
                created_at="2026-08-24T00:00:02Z",
            )
            == survivor
        )
        report = dict(result["cleanup"])
        report.update(
            {
                "removed_paths": ["fixtures/input.jsonl"],
                "retained_paths": ["fixtures/input.jsonl"],
                "errors": ["survivor retained"],
                "verified_removed_paths": 1,
                "verified_receipts": 1,
                "verified_receipt_ids": [manifest["params"]["receipt_ids"][0]],
            }
        )
        if not self.exact_ids:
            report.pop("verified_receipt_ids")
        result.update(
            {
                "status": "partial",
                "output": report,
                "cleanup": report,
                "error": {"code": "cleanup_incomplete", "message": "survivor retained"},
            }
        )
        _, request_hash = execution_task_identity(manifest, runner_profile)
        self.results[(task_id, request_hash)] = result
        return result


def _recovery_jobs(store, runs_path, registry, selected):
    run_store = RunStore(runs_path)
    service = SimpleNamespace(
        store=run_store,
        registry=registry,
        detection_lab=SimpleNamespace(run_store=run_store),
    )
    return SimpleNamespace(
        store=store,
        service=service,
        clock=lambda: int(datetime.now(timezone.utc).timestamp() * 1000),
        _orchestrator=lambda _current: SimpleNamespace(planner=DeterministicPlanner(registry)),
    )


def _capture_prepared(lease, receipt_id):
    payload = generated_bytes()
    run_id = lease["run_id"]
    action_id = retained.POLICY["producer"]
    producer = EvidenceRecord.create(
        run_id=run_id,
        step_id="stage",
        behavior_id=action_id,
        action_id=action_id,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id="fixture-profile",
        target_scope_ref="runner-profile:fixture-profile",
        content={"runner_status": "success", "request_hash": content_hash("stage")},
    )
    observation = EvidenceRecord.create(
        run_id=run_id,
        step_id="stage",
        behavior_id=action_id,
        action_id=action_id,
        provenance=EvidenceProvenance.OBSERVED,
        producer="sandbox-observer.v1",
        runner_profile_id="fixture-profile",
        target_scope_ref="runner-profile:fixture-profile",
        parent_evidence_ids=(producer.evidence_id,),
        content={
            "path": "staged/bundle.jsonl",
            "sha256": sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        },
    )
    prepared = retained._capture_documents(
        run_id=run_id,
        attempt_id=lease["attempt_id"],
        lineage_id=lease["lineage_id"],
        job_id=lease["job_id"],
        step=SimpleNamespace(step_id="stage", action_id=action_id),
        artifact={
            "type": "artifact.sandbox.bundle.v1",
            "format": "jsonl",
            "path": "staged/bundle.jsonl",
            "sha256": sha256(payload).hexdigest(),
            "size": len(payload),
            "receipt_ids": [receipt_id],
        },
        payload=payload,
        producer_record=producer.to_dict(),
        observation_record=observation.to_dict(),
    )
    return payload, prepared


def _crash_boundary(
    stage,
    product_path,
    runs_path,
    attempt_id,
    task_id,
    request_hash,
    terminal_digest,
    payload_path,
    prepared_path,
):
    """Child-only irreversible test boundary; exit without Python cleanup."""
    import json

    store = ProductStore(product_path)
    if stage == "task_terminal_before_intent":
        store.record_capability_task_terminal(
            task_id,
            request_hash=request_hash,
            terminal_digest=terminal_digest,
        )
    elif stage == "receiver_close_before_settlement":
        recovery.record_receiver_closure(
            store,
            attempt_id,
            {
                "schema_version": "bluefire.receiver-closure-proof.v1",
                "process_id": 424242,
                "creation_identity": "123456789",
                "session_member_count": 0,
                "verified_closed": True,
            },
        )
    else:
        run_store = RunStore(runs_path)
        prepared = json.loads(Path(prepared_path).read_text(encoding="utf-8"))
        run_id = prepared["publication"]["run_id"]
        run_store.publish_retained_capture(
            run_id,
            payload=Path(payload_path).read_bytes(),
            capture=prepared["publication"],
            artifacts=prepared["artifacts"],
            event=prepared["event"],
        )
        if stage in {"partial_finalize", "finalized_before_receiver_close"}:
            if stage == "partial_finalize":
                original = run_store.write_json

                def crash_at_manifest(run, name, value):
                    if name == "manifest.json":
                        os._exit(73)
                    return original(run, name, value)

                run_store.write_json = crash_at_manifest
            run_store.finalize(
                run_id,
                result={
                    "status": "failed",
                    "mode": "execute",
                    "steps": [],
                    "cleanup": {"success": True, "outstanding_receipt_count": 0},
                },
                evidence=list(prepared["publication"]["evidence"].values()),
                detections=[],
            )
    os._exit(73)


def _closure(store, lease):
    receiver = recovery.record_receiver_closure(
        store,
        lease["attempt_id"],
        {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": 424242,
            "creation_identity": "123456789",
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    generation = recovery.begin_generation(store, lease["attempt_id"], 5000)
    native = recovery.record_cleanup_closure(
        store,
        lease["attempt_id"],
        generation=generation,
        inspection_digest=content_hash("empty-pinned-receipts"),
    )
    settlement = {
        "schema_version": "bluefire.capability-attempt-settlement.v2",
        "attempt_id": lease["attempt_id"],
        "lease_digest": lease["lease_digest"],
        "generation": generation,
        "disposition": "interrupted_unusable",
        "native": {"state": "verified_clean", "closure_digest": content_hash(native)},
        "receiver": {"state": "verified_closed", "closure_digest": content_hash(receiver)},
    }
    return settlement


def test_exact_v2_closure_is_append_only_and_reopens(saved, tmp_path):
    store, lease, _ = _bound(saved, tmp_path)
    settlement = _closure(store, lease)
    store.settle_capability_attempt(lease["attempt_id"], settlement)
    reopened = ProductStore(store.path)
    assert reopened.get_capability_attempt(lease["attempt_id"])["settlement"] == settlement
    reopened.settle_capability_attempt(lease["attempt_id"], settlement)
    recovery.repair_progress(reopened, lease["attempt_id"], settlement)
    recovery.repair_progress(ProductStore(store.path), lease["attempt_id"], settlement)
    assert (
        ProductStore(store.path).get_job(lease["job_id"])["progress"]["settlement"]
        == "interrupted_unusable"
    )
    with reopened._connection() as connection:
        for table in (
            "capability_recovery_generations",
            "capability_recovery_closures",
            "capability_receiver_closure_proofs",
            "capability_attempt_settlements",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1


def test_startup_recovers_no_effect_attempt_twice_without_business_replay(
    saved, tmp_path, monkeypatch
):
    store, lease, _ = _bound(saved, tmp_path)
    runner_calls = []
    monkeypatch.setattr(
        runtime,
        "_runner",
        lambda *_args, **_kwargs: (runner_calls.append("read") or None, None, None),
    )
    closure_calls = []

    def close(process_id, creation_identity):
        closure_calls.append((process_id, creation_identity))
        return {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        }

    monkeypatch.setattr(runtime, "close_exact_receiver", close)
    service = SimpleNamespace(store=RunStore(tmp_path / "runs"))
    jobs = SimpleNamespace(store=store, service=service, clock=lambda: 5000)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert closure_calls == [(424242, "123456789")]
    assert runner_calls == ["read"]
    assert (
        store.get_capability_attempt(lease["attempt_id"])["settlement"]["disposition"]
        == "interrupted_unusable"
    )


@pytest.mark.parametrize("has_stop_event", [False, True])
def test_runner_start_retries_pending_retained_recovery(has_stop_event):
    calls = []
    service = SimpleNamespace(
        _runner_lifecycle_profile=lambda _profile_id: SimpleNamespace(id="profile"),
        _managed_host_profile_budget=lambda: 42,
        runner_lifecycle=SimpleNamespace(
            start=lambda **kwargs: (calls.append(("start", kwargs)) or {"status": "running"})
        ),
        composition=SimpleNamespace(
            recover_retained_attempts=lambda **kwargs: (
                calls.append(("recover", kwargs)) or {"pending": 0, "settled": 1}
            )
        ),
    )
    if has_stop_event:
        service._retained_recovery_stop = threading.Event()
    assert RunnerManagementServiceMixin.start_runner(service, profile_id="profile") == {
        "status": "running"
    }
    assert calls == [
        ("start", {"profile_id": "profile", "profile_budget_seconds": 42}),
        ("recover", {"stop_event": service._retained_recovery_stop} if has_stop_event else {}),
    ]
    assert service.retained_attempt_recovery == {"pending": 0, "settled": 1}


def test_background_retries_running_wal_until_terminal_without_runner_start():
    scans = []
    pending = {"examined": 1, "pending": 1, "settled": 0}
    settled = {"examined": 1, "pending": 0, "settled": 1}
    service = BlueFireService.__new__(BlueFireService)
    service._retained_recovery_stop = threading.Event()
    service.composition = SimpleNamespace(
        recover_retained_attempts=lambda **_kwargs: (
            scans.append("reconcile") or (pending if len(scans) == 1 else settled)
        )
    )
    service.retained_attempt_recovery = pending
    service._retry_retained_attempts(interval_seconds=0.001, max_interval_seconds=0.002)
    assert scans == ["reconcile", "reconcile"]
    assert service.retained_attempt_recovery == settled


def test_background_retries_page_error_without_dropping_pending_attempt():
    scans = []
    service = BlueFireService.__new__(BlueFireService)
    service._retained_recovery_stop = threading.Event()

    def reconcile(**_kwargs):
        scans.append("reconcile")
        if len(scans) == 1:
            raise OSError("temporary product database lock")
        return {"examined": 1, "pending": 0, "settled": 1}

    service.composition = SimpleNamespace(recover_retained_attempts=reconcile)
    service.retained_attempt_recovery = {"examined": 1, "pending": 1, "settled": 0}
    service._retry_retained_attempts(interval_seconds=0.001, max_interval_seconds=0.002)
    assert scans == ["reconcile", "reconcile"]
    assert service.retained_attempt_recovery_error == "OSError"
    assert service.retained_attempt_recovery["pending"] == 0


def test_close_waits_for_committed_partial_cleanup_then_reopens_without_redispatch(
    saved,
    tmp_path,
    monkeypatch,
):
    from tests_platform.test_windows_file_access_service_shutdown import bare_service

    store, lease, root, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    first = original["receipt_ids"][0]
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    original["receipt_ids"].append(survivor)
    started, release = threading.Event(), threading.Event()
    private_events, executed_task_ids = [], []

    def execute_in_two_stages(
        cleanup_manifest, cleanup_profile, *, task_id, cancel_event, **_kwargs
    ):
        wal.execute_actions.append(cleanup_manifest["action_id"])
        executed_task_ids.append(task_id)
        private_events.append(cancel_event)
        assert 0 < cleanup_manifest["limits"]["timeout_ms"] <= 120000
        result = wal.fake.execute(cleanup_manifest, cleanup_profile)
        # Model the single native task between two verified receipt removals.
        # Its completed WAL/normal result is withheld until the last removal.
        assert (
            _write_bound_receipt(
                manifest,
                profile,
                created_at="2026-08-24T00:00:02Z",
            )
            == survivor
        )
        started.set()
        assert release.wait(5), "test did not release the finite committed cleanup"
        assert not cancel_event.is_set(), "shutdown cancelled a partially applied cleanup"
        wal.fake.execute(
            {**cleanup_manifest, "params": {"receipt_ids": [survivor]}},
            cleanup_profile,
        )
        _, request_hash = execution_task_identity(cleanup_manifest, cleanup_profile)
        wal.results[(task_id, request_hash)] = result
        return result

    wal.execute_task = execute_in_two_stages
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    service, _ = bare_service()
    service.composition.recover_retained_attempts = lambda **kwargs: runtime.recover_all(
        jobs, **kwargs
    )
    service.retained_attempt_recovery = {"examined": 1, "pending": 1, "settled": 0}
    worker = threading.Thread(
        target=service._retry_retained_attempts,
        kwargs={"interval_seconds": 0.001, "max_interval_seconds": 0.002},
        daemon=True,
    )
    service._retained_recovery_thread = worker
    close_errors = []

    def close():
        try:
            service.close()
        except BaseException as error:
            close_errors.append(error)

    closer = threading.Thread(target=close, daemon=True)
    worker.start()
    try:
        assert started.wait(3)
        first_path = root / ".bluefire" / "receipts" / f"{first}.json"
        survivor_path = root / ".bluefire" / "receipts" / f"{survivor}.json"
        assert not (_windows_extended_path(first_path) if os.name == "nt" else first_path).exists()
        assert (
            _windows_extended_path(survivor_path) if os.name == "nt" else survivor_path
        ).exists()
        closer.start()
        assert service._retained_recovery_stop.wait(2)
        closer.join(timeout=0.05)
        assert closer.is_alive(), "close abandoned an already registered cleanup"
        assert private_events[0] is not service._retained_recovery_stop
        assert not private_events[0].is_set()
        snapshot = recovery.snapshot(store, lease["attempt_id"])
        assert snapshot["recovery_task"] is not None
        assert snapshot["recovery_terminal"] is None and snapshot["settlement"] is None
        before = time.monotonic()
        release.set()
        closer.join(timeout=2)
        assert not closer.is_alive() and not worker.is_alive()
        assert time.monotonic() - before < 2 and not close_errors
    finally:
        service._retained_recovery_stop.set()
        release.set()
        worker.join(timeout=3)
        if closer.ident is not None:
            closer.join(timeout=3)
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_terminal"]["result"]["status"] == "success"
    assert snapshot["recovery_terminal"]["remaining_receipts"] == []
    assert snapshot["settlement"] is None
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert len(snapshot["recovery_history"]) == 1
    assert len(executed_task_ids) == 1 and wal.execute_actions == ["sandbox.cleanup.v1"]


def test_stop_after_cleanup_claim_keeps_task_unregistered_and_can_resume(
    saved,
    tmp_path,
    monkeypatch,
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    wal.remember(manifest, profile, task_id, transport_hash)
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    stop = threading.Event()
    original_claim = recovery.claim_cleanup

    def claim_and_stop(*args, **kwargs):
        claimed = original_claim(*args, **kwargs)
        stop.set()
        return claimed

    monkeypatch.setattr(recovery, "claim_cleanup", claim_and_stop)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    assert runtime.recover_one(jobs, lease["attempt_id"], stop_event=stop) == "pending"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_claim"] is not None and snapshot["recovery_task"] is None
    assert wal.execute_actions == []
    monkeypatch.setattr(recovery, "claim_cleanup", original_claim)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1"]


@pytest.mark.parametrize("next_boundary", ["next_task", "original_cleanup"])
def test_stop_after_first_original_wal_read_starts_no_second_remote_read(
    saved,
    tmp_path,
    monkeypatch,
    next_boundary,
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    wal.remember(manifest, profile, task_id, transport_hash)
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    first = snapshot["tasks"][0]
    second = {
        **first,
        "task_id": "execute-later",
        "payload": {
            **first["payload"],
            "runner_wal": {
                **first["payload"]["runner_wal"],
                "task_id": "execute-later",
            },
        },
    }
    snapshot["tasks"] = [first, second] if next_boundary == "next_task" else [first]
    if next_boundary == "original_cleanup":
        snapshot["original_cleanup_task"] = {"task_id": "cleanup-later", "terminal": None}
    snapshot["receiver_closure"] = {"verified_closed": True}
    stop, calls = threading.Event(), []
    original_recover = wal.recover

    def recover_and_stop(received_id, received_hash):
        calls.append(received_id)
        if next_boundary == "next_task":
            stop.set()
        return original_recover(received_id, received_hash)

    wal.recover = recover_and_stop
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    jobs.store = SimpleNamespace(
        get_capability_task_payload=lambda *_args: None,
        record_capability_task_terminal=lambda *_args, **_kwargs: stop.set(),
    )
    monkeypatch.setattr(recovery, "snapshot", lambda *_args: snapshot)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    assert runtime.recover_one(jobs, lease["attempt_id"], stop_event=stop) == "pending"
    assert calls == [task_id]


def test_startup_scan_reaches_retained_attempt_after_256_rows(saved, tmp_path, monkeypatch):
    store, lease, _ = _bound(saved, tmp_path)
    attempts = [lease["attempt_id"]]
    with store._connection(write=True) as connection:
        original = dict(
            connection.execute(
                "SELECT * FROM capability_attempts WHERE attempt_id=?", (lease["attempt_id"],)
            ).fetchone()
        )
        columns = list(original)
        statement = "INSERT INTO capability_attempts VALUES(" + ",".join("?" for _ in columns) + ")"
        for index in range(256):
            attempt_id = f"attempt-scan-{index:032x}"
            row = dict(original)
            row.update(
                {
                    "attempt_id": attempt_id,
                    "job_id": f"job-scan-{index:032x}",
                    "run_id": f"run-scan-{index:032x}",
                }
            )
            connection.execute(statement, [row[column] for column in columns])
            attempts.append(attempt_id)
    visited = []
    monkeypatch.setattr(
        store,
        "get_capability_attempt",
        lambda _attempt: {
            "lease": {"grant_id": lease["grant_id"]},
        },
    )
    monkeypatch.setattr(
        store,
        "get_capability_grant",
        lambda *_args, **_kwargs: {
            "document": {},
        },
    )
    monkeypatch.setattr(runtime, "grant_pack", lambda _grant: runtime.RECEIVER_RETAINED_PACK)
    monkeypatch.setattr(
        runtime,
        "recover_one",
        lambda _jobs, attempt_id, **_kwargs: (visited.append(attempt_id) or "pending"),
    )
    jobs = SimpleNamespace(store=store, clock=lambda: 5000)
    summary = runtime.recover_all(jobs)
    assert summary == {"examined": 257, "settled": 0, "pending": 257}
    assert visited == attempts


def test_missing_terminal_recovers_original_wal_then_runs_only_new_cleanup(
    saved, tmp_path, monkeypatch
):
    (
        store,
        lease,
        root,
        selected,
        profile,
        manifest,
        task_id,
        transport_hash,
        _plan,
    ) = _effect_bound(saved, tmp_path)
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    receipt_id = original["receipt_ids"][0]
    receipt_path = root / ".bluefire" / "receipts" / f"{receipt_id}.json"
    assert (_windows_extended_path(receipt_path) if os.name == "nt" else receipt_path).is_file()
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    service = SimpleNamespace(store=RunStore(tmp_path / "runs"), registry=saved[1]["registry"])
    jobs = SimpleNamespace(
        store=store,
        service=service,
        clock=lambda: int(datetime.now(timezone.utc).timestamp() * 1000),
        _orchestrator=lambda _current: SimpleNamespace(
            planner=DeterministicPlanner(saved[1]["registry"])
        ),
    )
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1"]
    assert not (_windows_extended_path(receipt_path) if os.name == "nt" else receipt_path).exists()
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["tasks"][0]["terminal"] is not None
    assert snapshot["recovery_task"]["task_id"] != task_id
    assert snapshot["recovery_terminal"] is not None
    assert snapshot["recovery_closure"]["outstanding_receipt_count"] == 0
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


def test_partial_recovery_cleanup_reissues_only_verified_survivor(saved, tmp_path, monkeypatch):
    store, lease, root, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _PartialRecoveryWal(manifest, profile)
    original = wal.remember(manifest, profile, task_id, transport_hash)
    first = original["receipt_ids"][0]
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    assert first != survivor
    original["receipt_ids"].append(survivor)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1", "sandbox.cleanup.v1"]
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert len(snapshot["recovery_history"]) == 2
    first_cleanup, second_cleanup = snapshot["recovery_history"]
    assert first_cleanup["terminal"]["result"]["status"] == "partial"
    assert [row["receipt_id"] for row in first_cleanup["terminal"]["remaining_receipts"]] == [
        survivor
    ]
    assert second_cleanup["task"]["manifest"]["params"] == {"receipt_ids": [survivor]}
    assert second_cleanup["terminal"]["result"]["status"] == "success"
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"
    for receipt_id in (first, survivor):
        path = root / ".bluefire" / "receipts" / f"{receipt_id}.json"
        assert not (_windows_extended_path(path) if os.name == "nt" else path).exists()


def test_partial_cleanup_without_exact_verified_ids_stays_pending(saved, tmp_path, monkeypatch):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _PartialRecoveryWal(manifest, profile, exact_ids=False)
    original = wal.remember(manifest, profile, task_id, transport_hash)
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    original["receipt_ids"].append(survivor)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_all(jobs)["pending"] >= 1
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["settlement"] is None
    assert len(snapshot["recovery_history"]) == 1
    assert snapshot["recovery_history"][0]["terminal"] is None
    assert wal.execute_actions == ["sandbox.cleanup.v1"]


def test_partial_cleanup_lost_ack_recovers_same_task_then_one_survivor(
    saved, tmp_path, monkeypatch
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _PartialRecoveryWal(manifest, profile)
    original = wal.remember(manifest, profile, task_id, transport_hash)
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    original["receipt_ids"].append(survivor)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    original_record = recovery.record_cleanup_terminal
    lost = False

    def lose_ack(*args, **kwargs):
        nonlocal lost
        if not lost:
            lost = True
            raise OSError("simulated lost terminal acknowledgment")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(recovery, "record_cleanup_terminal", lose_ack)
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    with pytest.raises(OSError, match="lost terminal"):
        runtime.recover_one(jobs, lease["attempt_id"])
    assert len(wal.execute_actions) == 1
    assert recovery.snapshot(store, lease["attempt_id"])["recovery_terminal"] is None
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1", "sandbox.cleanup.v1"]
    history = recovery.snapshot(store, lease["attempt_id"])["recovery_history"]
    assert len(history) == 2
    assert history[0]["terminal"]["result"]["status"] == "partial"
    assert history[1]["task"]["manifest"]["params"] == {"receipt_ids": [survivor]}


def test_real_exit_after_partial_cleanup_terminal_reopens_survivor_only(
    saved, tmp_path, monkeypatch
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _PartialRecoveryWal(manifest, profile)
    original = wal.remember(manifest, profile, task_id, transport_hash)
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    original["receipt_ids"].append(survivor)
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    payload_path = tmp_path / "partial-terminal.json"

    def durable_terminal_then_exit(store_arg, attempt_id, **kwargs):
        payload_path.write_text(canonical_json(kwargs), encoding="utf-8")
        program = (
            "import json,os,sys; from pathlib import Path; "
            "from bluefire.product_store import ProductStore; "
            "from bluefire import product_store_retained_recovery as recovery; "
            "recovery.record_cleanup_terminal(ProductStore(sys.argv[1]),sys.argv[2],"
            "**json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))); os._exit(73)"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
        child = subprocess.run(
            [sys.executable, "-c", program, str(store_arg.path), attempt_id, str(payload_path)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=90,
            check=False,
        )
        assert child.returncode == 73, child.stderr.decode(errors="replace")
        raise SystemExit("partial terminal persisted before parent acknowledgment")

    monkeypatch.setattr(recovery, "record_cleanup_terminal", durable_terminal_then_exit)
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    with pytest.raises(SystemExit, match="terminal persisted"):
        runtime.recover_one(jobs, lease["attempt_id"])
    monkeypatch.undo()
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert len(snapshot["recovery_history"]) == 2
    assert snapshot["recovery_history"][0]["terminal"]["result"]["status"] == "partial"
    assert snapshot["recovery_history"][1]["task"]["manifest"]["params"] == {
        "receipt_ids": [survivor],
    }
    assert wal.execute_actions == ["sandbox.cleanup.v1", "sandbox.cleanup.v1"]
    assert len(wal.fake.calls) == 3  # original business effect and two cleanup tasks


def test_original_partial_cleanup_credits_only_verified_removed_receipt(
    saved, tmp_path, monkeypatch
):
    store, lease, root, selected, profile, manifest, task_id, transport_hash, plan = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    first = original["receipt_ids"][0]
    survivor = _write_bound_receipt(
        manifest,
        profile,
        created_at="2026-08-24T00:00:02Z",
    )
    original["receipt_ids"].append(survivor)
    store.record_capability_task_terminal(
        task_id,
        request_hash=manifest["request_hash"],
        terminal_digest=content_hash(original),
    )
    workspace_id = sha256(str(root.resolve(strict=True)).replace("\\", "/").encode()).hexdigest()
    store.record_capability_cleanup_obligation(
        lease["attempt_id"],
        workspace_id=workspace_id,
        receipts=[
            {
                "receipt_id": receipt_id,
                "source_request_hash": manifest["request_hash"],
                "source_task_id": task_id,
            }
            for receipt_id in (first, survivor)
        ],
    )
    authority = store.claim_capability_cleanup(
        lease["attempt_id"],
        now_ms=6000,
        timeout_ms=1000,
    )
    step = next(row for row in plan.steps if row.action_id == "sandbox.cleanup.v1")
    cleanup_manifest = build_execution_manifest(
        run_id=lease["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action=saved[1]["registry"].get_action("sandbox.cleanup.v1"),
        runner_profile=profile,
        params={"receipt_ids": [first, survivor]},
        filesystem_scope=(),
        network_destinations=(),
        evidence_refs=(),
        approval_record=None,
        grant_cleanup=_verified_grant_cleanup(
            authority["document"],
            expected_document_digest=authority["document_digest"],
        ),
        reviewed_operation=reviewed_operation(step, profile),
        now=datetime.fromtimestamp(6, timezone.utc),
    )
    cleanup_id, cleanup_transport = execution_task_identity(cleanup_manifest, profile)
    store.register_capability_cleanup_task(
        lease["attempt_id"],
        task_id=cleanup_id,
        request_hash=cleanup_manifest["request_hash"],
        expected_document_digest=authority["document_digest"],
        now_ms=6000,
        step_id=step.step_id,
        manifest=cleanup_manifest,
        runner_profile=profile,
    )
    result = dict(wal.fake.execute(cleanup_manifest, profile))
    assert (
        _write_bound_receipt(
            manifest,
            profile,
            created_at="2026-08-24T00:00:02Z",
        )
        == survivor
    )
    report = dict(result["cleanup"])
    report.update(
        {
            "removed_paths": ["fixtures/input.jsonl"],
            "retained_paths": ["fixtures/input.jsonl"],
            "errors": ["survivor retained"],
            "verified_removed_paths": 1,
            "verified_receipts": 1,
            "verified_receipt_ids": [first],
        }
    )
    result.update(
        {
            "status": "partial",
            "output": report,
            "cleanup": report,
            "error": {"code": "cleanup_incomplete", "message": "survivor retained"},
        }
    )
    wal.results[(cleanup_id, cleanup_transport)] = result
    store.record_capability_cleanup_terminal(
        cleanup_id,
        request_hash=cleanup_manifest["request_hash"],
        terminal_digest=content_hash(result),
    )
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1"]
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_task"]["manifest"]["params"] == {"receipt_ids": [survivor]}
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


def test_sealed_original_cleanup_and_exact_receiver_reuse_v1_settlement(
    saved, tmp_path, monkeypatch
):
    store, lease, root, selected, profile, manifest, task_id, transport_hash, plan = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    receipt_id = original["receipt_ids"][0]
    store.record_capability_task_terminal(
        task_id,
        request_hash=manifest["request_hash"],
        terminal_digest=content_hash(original),
    )
    workspace_id = sha256(str(root.resolve(strict=True)).replace("\\", "/").encode()).hexdigest()
    store.record_capability_cleanup_obligation(
        lease["attempt_id"],
        workspace_id=workspace_id,
        receipts=[
            {
                "receipt_id": receipt_id,
                "source_request_hash": manifest["request_hash"],
                "source_task_id": task_id,
            }
        ],
    )
    authority = store.claim_capability_cleanup(
        lease["attempt_id"],
        now_ms=6000,
        timeout_ms=1000,
    )
    step = next(row for row in plan.steps if row.action_id == "sandbox.cleanup.v1")
    cleanup_manifest = build_execution_manifest(
        run_id=lease["run_id"],
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action=saved[1]["registry"].get_action("sandbox.cleanup.v1"),
        runner_profile=profile,
        params={"receipt_ids": [receipt_id]},
        filesystem_scope=(),
        network_destinations=(),
        evidence_refs=(),
        approval_record=None,
        grant_cleanup=_verified_grant_cleanup(
            authority["document"],
            expected_document_digest=authority["document_digest"],
        ),
        reviewed_operation=reviewed_operation(step, profile),
        now=datetime.fromtimestamp(6, timezone.utc),
    )
    cleanup_id, cleanup_transport = execution_task_identity(cleanup_manifest, profile)
    store.register_capability_cleanup_task(
        lease["attempt_id"],
        task_id=cleanup_id,
        request_hash=cleanup_manifest["request_hash"],
        expected_document_digest=authority["document_digest"],
        now_ms=6000,
        step_id=step.step_id,
        manifest=cleanup_manifest,
        runner_profile=profile,
    )
    cleanup_result = wal.remember(cleanup_manifest, profile, cleanup_id, cleanup_transport)
    store.record_capability_cleanup_terminal(
        cleanup_id,
        request_hash=cleanup_manifest["request_hash"],
        terminal_digest=content_hash(cleanup_result),
    )
    RunStore(tmp_path / "runs").finalize(
        lease["run_id"],
        result={
            "status": "failed",
            "mode": "execute",
            "steps": [],
            "cleanup": {"success": True, "outstanding_receipt_count": 0},
        },
        evidence=[],
        detections=[],
    )
    job = store.get_job(lease["job_id"])
    receipt = {
        "verified_closed": True,
        "process_id": 424242,
        "creation_identity": "123456789",
    }
    store.transition_job(
        lease["job_id"],
        job["state"],
        progress={
            **job["progress"],
            "receiver_closed": True,
            "receiver_observation": {"state": "verified"},
            "receiver_cleanup_receipt": receipt,
            "session": {
                "receiver_session_id": "generation-" + lease["attempt_id"],
                "receiver_process_id": 424242,
                "creation_identity": "123456789",
            },
        },
    )
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_history"] == []
    assert snapshot["settlement"]["schema_version"] == "bluefire.capability-attempt-settlement.v1"
    assert snapshot["settlement"]["native"]["cleanup_digest"] == content_hash(cleanup_result)
    assert wal.execute_actions == []


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path receipt inspection")
def test_recovery_inspects_long_receipt_directory_with_supported_path(saved, tmp_path, monkeypatch):
    suffix_length = len(str(Path("sandbox") / ".bluefire-executions" / ("attempt-" + "x" * 32)))
    padding = 242 - len(str(tmp_path)) - suffix_length - 2
    assert padding > 0
    long_base = tmp_path / ("x" * padding)
    long_base.mkdir()
    store, lease, root, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, long_base
    )
    receipt_root = root / ".bluefire" / "receipts"
    assert len(str(receipt_root)) > 260
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    receipt_path = receipt_root / f"{original['receipt_ids'][0]}.json"
    assert _windows_extended_path(receipt_path).is_file()
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, long_base / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert not _windows_extended_path(receipt_path).exists()
    assert wal.execute_actions == ["sandbox.cleanup.v1"]


def test_expired_unregistered_recovery_claim_appends_fresh_generation(saved, tmp_path):
    store, lease, _ = _bound(saved, tmp_path)
    source_hash = content_hash("business-request")
    store.register_capability_task(
        lease["attempt_id"],
        task_id="execute-original",
        step_id="seed",
        request_hash=source_hash,
        now_ms=5000,
        current_environment=saved[1]["current_environment"],
    )
    store.record_capability_task_terminal(
        "execute-original",
        request_hash=source_hash,
        terminal_digest=content_hash("original-result"),
    )
    receipt = [
        {
            "receipt_id": "a" * 64,
            "source_request_hash": source_hash,
            "source_task_id": "execute-original",
        }
    ]
    first = recovery.begin_generation(store, lease["attempt_id"], 5500)
    recovery.claim_cleanup(
        store,
        lease["attempt_id"],
        generation=first,
        workspace_id="b" * 64,
        receipts=receipt,
        now_ms=6000,
        timeout_ms=1000,
    )
    assert recovery.begin_generation(store, lease["attempt_id"], 6999) == first
    second = recovery.begin_generation(store, lease["attempt_id"], 7000)
    assert second != first
    recovery.claim_cleanup(
        store,
        lease["attempt_id"],
        generation=second,
        workspace_id="b" * 64,
        receipts=receipt,
        now_ms=7000,
        timeout_ms=1000,
    )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT count(*) FROM capability_recovery_generations").fetchone()[0]
            == 2
        )
        assert (
            connection.execute("SELECT count(*) FROM capability_recovery_claims").fetchone()[0] == 2
        )
        assert (
            connection.execute("SELECT count(*) FROM capability_recovery_task_claims").fetchone()[0]
            == 0
        )


def test_original_runner_not_found_stays_pending_without_no_send_proof(
    saved, tmp_path, monkeypatch
):
    store, lease, _, selected, _, _, task_id, transport_hash, _ = _effect_bound(saved, tmp_path)
    task = recovery.snapshot(store, lease["attempt_id"])["tasks"][0]
    store.mark_capability_task_dispatch(
        lease["attempt_id"],
        task_id=task_id,
        request_hash=task["request_hash"],
        transport_request_hash=transport_hash,
    )
    wal = _RecoveryWal()
    wal.recover = lambda received_id, received_hash: {
        "state": "not_found",
        "original_task_id": received_id,
        "original_request_hash": received_hash,
        "result": None,
        "cleanup_required": False,
        "receipt_ids": [],
    }
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "pending"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "pending"
    assert wal.execute_actions == []
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["tasks"][0]["task_id"] == task_id
    assert snapshot["tasks"][0]["payload"]["transport_request_hash"] == transport_hash
    assert snapshot["tasks"][0]["terminal"] is None
    assert snapshot["settlement"] is None


def test_durable_pre_dispatch_no_send_terminal_closes_without_replay(saved, tmp_path, monkeypatch):
    store, lease, _, selected, _, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    store.record_capability_task_no_send(
        lease["attempt_id"],
        task_id=task_id,
        request_hash=manifest["request_hash"],
        transport_request_hash=transport_hash,
    )
    wal = _RecoveryWal()
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == []
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["tasks"][0]["payload"]["transport_request_hash"] == transport_hash
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


def test_real_exit_after_registration_closes_unsent_and_bars_late_dispatch(
    saved,
    tmp_path,
    monkeypatch,
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path, register=False
    )
    arguments = {
        "task_id": task_id,
        "step_id": manifest["step_id"],
        "request_hash": manifest["request_hash"],
        "now_ms": 5000,
        "current_environment": saved[1]["current_environment"],
        "manifest": manifest,
        "runner_profile": profile,
    }
    arguments_path = tmp_path / "registration.json"
    arguments_path.write_text(canonical_json(arguments), encoding="utf-8")
    program = (
        "import json,os,sys; from pathlib import Path; "
        "from bluefire.product_store import ProductStore; "
        "ProductStore(sys.argv[1]).register_capability_task(sys.argv[2], "
        "**json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))); os._exit(73)"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    child = subprocess.run(
        [sys.executable, "-c", program, str(store.path), lease["attempt_id"], str(arguments_path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert child.returncode == 73, child.stderr.decode(errors="replace")
    wal = _RecoveryWal()
    wal.recover = lambda received_id, received_hash: {
        "state": "not_found",
        "original_task_id": received_id,
        "original_request_hash": received_hash,
        "result": None,
        "cleanup_required": False,
        "receipt_ids": [],
    }
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
        with pytest.raises(ProductStoreError, match="terminal before dispatch"):
            reopened.mark_capability_task_dispatch(
                lease["attempt_id"],
                task_id=task_id,
                request_hash=manifest["request_hash"],
                transport_request_hash=transport_hash,
            )
    assert wal.execute_actions == []
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_history"] == []
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


def test_dispatch_and_no_send_race_has_one_durable_winner(saved, tmp_path):
    store, lease, _, _, _, manifest, task_id, transport_hash, _ = _effect_bound(saved, tmp_path)
    barrier = threading.Barrier(2)

    def compete(method):
        reopened = ProductStore(store.path)
        barrier.wait(timeout=10)
        try:
            getattr(reopened, method)(
                lease["attempt_id"],
                task_id=task_id,
                request_hash=manifest["request_hash"],
                transport_request_hash=transport_hash,
            )
            return method
        except ProductStoreError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                compete,
                [
                    "mark_capability_task_dispatch",
                    "record_capability_task_no_send",
                ],
            )
        )
    assert sum(result is not None for result in results) == 1
    reopened = ProductStore(store.path)
    with pytest.raises(ProductStoreError):
        reopened.mark_capability_task_dispatch(
            lease["attempt_id"],
            task_id=task_id,
            request_hash=manifest["request_hash"],
            transport_request_hash=transport_hash,
        )
    snapshot = recovery.snapshot(reopened, lease["attempt_id"])
    assert (snapshot["tasks"][0]["terminal"] is not None) == (results[1] is not None)


def test_send_intent_cannot_be_changed_to_no_send_terminal(saved, tmp_path):
    store, lease, _, _, _, manifest, task_id, transport_hash, _ = _effect_bound(saved, tmp_path)
    arguments = {
        "task_id": task_id,
        "request_hash": manifest["request_hash"],
        "transport_request_hash": transport_hash,
    }
    store.mark_capability_task_dispatch(lease["attempt_id"], **arguments)
    reopened = ProductStore(store.path)
    with pytest.raises(ProductStoreError, match="may already have been sent"):
        reopened.record_capability_task_no_send(lease["attempt_id"], **arguments)
    with pytest.raises(ProductStoreError, match="may already have been sent"):
        reopened.record_capability_task_terminal(
            task_id,
            request_hash=manifest["request_hash"],
            terminal_digest=content_hash(
                {
                    "schema_version": "bluefire.task-not-sent.v1",
                    "task_id": task_id,
                    "request_hash": manifest["request_hash"],
                }
            ),
        )
    assert recovery.snapshot(reopened, lease["attempt_id"])["tasks"][0]["terminal"] is None


def test_receiver_recovery_closure_bars_original_dispatch(saved, tmp_path):
    store, lease, _, _, _, manifest, task_id, transport_hash, _ = _effect_bound(saved, tmp_path)
    recovery.record_receiver_closure(
        store,
        lease["attempt_id"],
        {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": 424242,
            "creation_identity": "123456789",
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    with pytest.raises(ProductStoreError, match="entered recovery closure"):
        store.mark_capability_task_dispatch(
            lease["attempt_id"],
            task_id=task_id,
            request_hash=manifest["request_hash"],
            transport_request_hash=transport_hash,
        )


def test_legacy_payload_not_found_cannot_infer_no_send(saved, tmp_path, monkeypatch):
    from bluefire import product_store_capability_transport as transport

    original = transport.payload_document

    def legacy_payload(**kwargs):
        payload = original(**kwargs)
        payload.pop("dispatch_protocol", None)
        return payload

    monkeypatch.setattr(transport, "payload_document", legacy_payload)
    store, lease, _, selected, _, _, _, _, _ = _effect_bound(saved, tmp_path)
    monkeypatch.setattr(transport, "payload_document", original)
    wal = _RecoveryWal()
    wal.recover = lambda received_id, received_hash: {
        "state": "not_found",
        "original_task_id": received_id,
        "original_request_hash": received_hash,
        "result": None,
        "cleanup_required": False,
        "receipt_ids": [],
    }
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "pending"
    assert recovery.snapshot(store, lease["attempt_id"])["tasks"][0]["terminal"] is None
    assert wal.execute_actions == []


def test_registered_cleanup_not_found_stays_pending_without_second_claim(
    saved, tmp_path, monkeypatch
):
    store, lease, _, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    wal.remember(manifest, profile, task_id, transport_hash)
    original_recover = wal.recover

    def recover(received_id, received_hash):
        if (received_id, received_hash) not in wal.results:
            return {
                "state": "not_found",
                "original_task_id": received_id,
                "original_request_hash": received_hash,
                "result": None,
                "cleanup_required": False,
                "receipt_ids": [],
            }
        return original_recover(received_id, received_hash)

    wal.recover = recover
    original_execute = wal.execute_task
    attempted = False

    def interrupted_before_send(*args, **kwargs):
        nonlocal attempted
        if not attempted:
            attempted = True
            raise SystemExit("registered before runner send")
        return original_execute(*args, **kwargs)

    wal.execute_task = interrupted_before_send
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    with pytest.raises(SystemExit, match="before runner send"):
        runtime.recover_one(jobs, lease["attempt_id"])
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["recovery_task"] is not None
    assert snapshot["recovery_terminal"] is None
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "pending"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert len(snapshot["recovery_history"]) == 1
    assert snapshot["recovery_history"][0]["terminal"] is None
    assert snapshot["settlement"] is None
    assert wal.execute_actions == []


def test_runner_recovery_required_cleans_authenticated_receipt_without_replay(
    saved, tmp_path, monkeypatch
):
    store, lease, root, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    receipt_id = _write_bound_receipt(manifest, profile)
    wal = _RecoveryWal()
    original_recover = wal.recover

    def recover(received_id, received_hash):
        if (received_id, received_hash) == (task_id, transport_hash):
            return {
                "state": "recovery_required",
                "original_task_id": received_id,
                "original_request_hash": received_hash,
                "result": None,
                "cleanup_required": True,
                "error_code": "recovery_required",
                "receipt_ids": [receipt_id],
            }
        return original_recover(received_id, received_hash)

    wal.recover = recover
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    jobs = _recovery_jobs(store, tmp_path / "runs", saved[1]["registry"], selected)
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    assert wal.execute_actions == ["sandbox.cleanup.v1"]
    receipt_path = root / ".bluefire" / "receipts" / f"{receipt_id}.json"
    assert not (_windows_extended_path(receipt_path) if os.name == "nt" else receipt_path).exists()
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["tasks"][0]["terminal"] is not None
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


def test_crash_after_receiver_binding_before_workspace_closes_no_dispatch(
    saved, tmp_path, monkeypatch
):
    store, state, _, _ = saved
    lease = reserve(saved)
    claim(saved, lease)
    store.start_capability_preparation(
        lease["attempt_id"],
        now_ms=4500,
        current_environment=state["current_environment"],
    )
    program = (
        "import os,sys; from bluefire.product_store import ProductStore; "
        "from bluefire.util import content_hash; "
        "ProductStore(sys.argv[1]).bind_capability_receiver("
        "sys.argv[2], session_generation='generation-'+sys.argv[2], "
        "review_digest=content_hash('session-review'), process_id=424242, "
        "creation_identity='123456789'); os._exit(73)"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    child = subprocess.run(
        [sys.executable, "-c", program, str(store.path), lease["attempt_id"]],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert child.returncode == 73, child.stderr.decode(errors="replace")
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: pytest.fail("no dispatch"))
    monkeypatch.setattr(
        runtime,
        "close_exact_receiver",
        lambda process_id, creation_identity: {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        },
    )
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", state["registry"], None)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
    snapshot = recovery.snapshot(store, lease["attempt_id"])
    assert snapshot["workspace"] is None
    assert snapshot["tasks"] == []
    assert snapshot["recovery_history"] == []
    assert snapshot["settlement"]["disposition"] == "interrupted_unusable"


@pytest.mark.parametrize(
    "boundary",
    [
        "task_terminal_before_intent",
        "journal_before_manifest",
        "partial_finalize",
        "finalized_before_receiver_close",
        "receiver_close_before_settlement",
    ],
)
def test_real_exit_reopens_exact_attempt_without_business_replay(
    saved,
    tmp_path,
    monkeypatch,
    boundary,
):
    store, lease, root, selected, profile, manifest, task_id, transport_hash, _ = _effect_bound(
        saved, tmp_path
    )
    wal = _RecoveryWal()
    original = wal.remember(manifest, profile, task_id, transport_hash)
    receipt_id = original["receipt_ids"][0]
    payload, prepared = _capture_prepared(lease, receipt_id)
    payload_path = tmp_path / "capture-payload.jsonl"
    prepared_path = tmp_path / "capture-prepared.json"
    payload_path.write_bytes(payload)
    prepared_path.write_text(canonical_json(prepared), encoding="utf-8")
    program = (
        "import sys; from tests_platform.test_retained_attempt_recovery "
        "import _crash_boundary; _crash_boundary(*sys.argv[1:])"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            boundary,
            str(store.path),
            str(tmp_path / "runs"),
            lease["attempt_id"],
            task_id,
            manifest["request_hash"],
            content_hash(original),
            str(payload_path),
            str(prepared_path),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert child.returncode == 73, child.stderr.decode(errors="replace")
    run_store = RunStore(tmp_path / "runs")
    if boundary in {"journal_before_manifest", "partial_finalize"}:
        assert run_store.retained_capture(lease["run_id"]) == prepared["publication"]
        with pytest.raises(RunStoreError):
            run_store.get_run(lease["run_id"], require_finalized=True)
    if boundary == "finalized_before_receiver_close":
        assert (
            run_store.get_run(lease["run_id"], require_finalized=True)["manifest"]["run_id"]
            == lease["run_id"]
        )
    monkeypatch.setattr(runtime, "_runner", lambda *_args, **_kwargs: (wal, wal, selected))
    close_calls = []

    def close(process_id, creation_identity):
        close_calls.append((process_id, creation_identity))
        return {
            "schema_version": "bluefire.receiver-closure-proof.v1",
            "process_id": process_id,
            "creation_identity": creation_identity,
            "session_member_count": 0,
            "verified_closed": True,
        }

    monkeypatch.setattr(runtime, "close_exact_receiver", close)
    for _ in range(2):
        reopened = ProductStore(store.path)
        jobs = _recovery_jobs(reopened, tmp_path / "runs", saved[1]["registry"], selected)
        assert runtime.recover_one(jobs, lease["attempt_id"]) == "settled"
        assert (
            retained.available_sources(
                jobs,
                saved[1]["grant"],
                owner_id=saved[1]["parent_job_id"],
            )
            == []
        )
    assert close_calls == (
        [] if boundary == "receiver_close_before_settlement" else [(424242, "123456789")]
    )
    assert wal.execute_actions == ["sandbox.cleanup.v1"]
    assert len(wal.fake.calls) == 2  # original business task, one recovery cleanup
    receipt_path = root / ".bluefire" / "receipts" / f"{receipt_id}.json"
    assert not (_windows_extended_path(receipt_path) if os.name == "nt" else receipt_path).exists()
    with ProductStore(store.path)._connection() as connection:
        for table in (
            "capability_recovery_claims",
            "capability_recovery_task_claims",
            "capability_recovery_terminals",
            "capability_recovery_closures",
            "capability_receiver_closure_proofs",
            "capability_attempt_settlements",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1
        assert (
            connection.execute("SELECT count(*) FROM capability_cleanup_claims").fetchone()[0] == 0
        )


def test_concurrent_recovery_claim_is_one_finite_cleanup_only_authority(saved, tmp_path):
    store, lease, _ = _bound(saved, tmp_path)
    source_hash = content_hash("original-business-request")
    store.register_capability_task(
        lease["attempt_id"],
        task_id="execute-original",
        step_id="seed",
        request_hash=source_hash,
        now_ms=5000,
        current_environment=saved[1]["current_environment"],
    )
    store.record_capability_task_terminal(
        "execute-original",
        request_hash=source_hash,
        terminal_digest=content_hash("original-result"),
    )
    generation = recovery.begin_generation(store, lease["attempt_id"], 5500)
    receipts = [
        {
            "receipt_id": "a" * 64,
            "source_request_hash": source_hash,
            "source_task_id": "execute-original",
        }
    ]

    def claim_once(_index):
        reopened = ProductStore(store.path)
        return recovery.claim_cleanup(
            reopened,
            lease["attempt_id"],
            generation=generation,
            workspace_id="b" * 64,
            receipts=receipts,
            now_ms=6000,
            timeout_ms=5000,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(claim_once, range(2)))
    assert first == second
    assert first["document"]["timeout_ms"] == 5000
    assert first["document"]["receipts"] == receipts
    with store._connection() as connection:
        assert (
            connection.execute("SELECT count(*) FROM capability_recovery_claims").fetchone()[0] == 1
        )
        assert (
            connection.execute("SELECT count(*) FROM capability_cleanup_claims").fetchone()[0] == 0
        )
    with pytest.raises(ProductStoreError, match="immutable"):
        recovery.claim_cleanup(
            store,
            lease["attempt_id"],
            generation=generation,
            workspace_id="b" * 64,
            receipts=[{**receipts[0], "receipt_id": "c" * 64}],
            now_ms=6000,
            timeout_ms=5000,
        )


@pytest.mark.parametrize("changed", ["process_id", "creation_identity", "verified_closed"])
def test_receiver_closure_refuses_wrong_generation(saved, tmp_path, changed):
    store, lease, _ = _bound(saved, tmp_path)
    proof = {
        "schema_version": "bluefire.receiver-closure-proof.v1",
        "process_id": 424242,
        "creation_identity": "123456789",
        "session_member_count": 0,
        "verified_closed": True,
    }
    proof[changed] = {
        "process_id": 424243,
        "creation_identity": "123456788",
        "verified_closed": False,
    }[changed]
    with pytest.raises(ProductStoreError):
        recovery.record_receiver_closure(store, lease["attempt_id"], proof)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux pidfd session proof")
def test_exact_receiver_close_signals_only_owned_child_generation():
    if not LinuxPrivateProcessContainment.available():
        pytest.skip("pidfd closure unavailable")
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
    )
    try:
        identity = LinuxPrivateProcessContainment.process_identity(child.pid)
        assert identity[2:] == (child.pid, child.pid)
        with pytest.raises(OSError, match="receiver process identity changed"):
            close_exact_receiver(child.pid, str(identity[1] + 1))
        assert child.poll() is None
        reaper = threading.Thread(target=child.wait, daemon=True)
        reaper.start()
        proof = close_exact_receiver(child.pid, str(identity[1]))
        reaper.join(timeout=5)
        assert not reaper.is_alive()
        assert proof["session_member_count"] == 0
        assert proof["verified_closed"] is True
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)


def test_settlement_before_progress_crash_repairs_on_two_reopens(saved, tmp_path):
    store, lease, _ = _bound(saved, tmp_path)
    settlement = _closure(store, lease)
    program = (
        "import json,os,sys; "
        "from bluefire.product_store import ProductStore; "
        "ProductStore(sys.argv[1]).settle_capability_attempt(sys.argv[2], json.loads(sys.argv[3])); "
        "os._exit(73)"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(store.path),
            lease["attempt_id"],
            canonical_json(settlement),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert child.returncode == 73, child.stderr.decode(errors="replace")
    for _ in range(2):
        reopened = ProductStore(store.path)
        assert reopened.get_capability_attempt(lease["attempt_id"])["settlement"] == settlement
        assert (
            runtime.recover_one(SimpleNamespace(store=reopened), lease["attempt_id"]) == "settled"
        )
    assert (
        ProductStore(store.path).get_job(lease["job_id"])["progress"]["settlement"]
        == "interrupted_unusable"
    )
