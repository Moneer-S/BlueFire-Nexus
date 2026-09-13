"""Replay cancellation finalizes file-only run fixtures; no native effects run."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.local_lock import owner_private_database_lock
from bluefire.orchestrator import Orchestrator
from bluefire.product_store import ProductStoreError
from bluefire.runner_transport_errors import RunnerTaskCancelled
from bluefire.util import content_hash
from tests_platform.test_replay_jobs import awaiting, submission
from tests_platform.test_replay_preparation import service as service
from tests_platform.test_replay_preparation import source_run
from tests_platform.test_service import CleanupOnlyRecoveryRunner


@pytest.fixture
def tmp_path():
    # Keep the owned workspace plus canonical 64-character receipt filename
    # below the Windows path limit without changing product path validation.
    with TemporaryDirectory(prefix="bf-replay-cancel-") as owned:
        yield Path(owned)


@pytest.mark.parametrize("cancellation", ["runner", "provider", "checkpoint", "result_link"])
def test_execute_replay_cancellation_finalizes_and_links_its_run_before_terminal_state(
    service, monkeypatch, cancellation
):
    source = source_run(service, execute=True)
    entered = threading.Event()
    seen = {}
    if cancellation == "result_link":
        transition = service.product_store.transition_job

        def refuse_result_link(*args, **kwargs):
            if kwargs.get("result_ref") is not None:
                raise ProductStoreError("bounded result publication refusal")
            return transition(*args, **kwargs)

        monkeypatch.setattr(service.product_store, "transition_job", refuse_result_link)

    def interrupted(_self, **kwargs):
        seen["run_id"] = kwargs["handle"].run_id
        entered.set()
        assert kwargs["cancel_event"].wait(10)
        if cancellation == "checkpoint":
            kwargs["checkpoint"]({"run_id": seen["run_id"], "completed_steps": 0})
            pytest.fail("cancelled checkpoint returned")
        if cancellation == "provider":
            raise AIProviderCancelled()
        raise RunnerTaskCancelled("fixture task stopped")

    monkeypatch.setattr(Orchestrator, "_run_prepared", interrupted)
    created = service.submit_replay(source["run_id"], submission(service, source))
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    assert not entered.is_set()
    service.approve_job(job_id, {"approved_by": "cancellation-reviewer"})
    assert entered.wait(10)
    service.cancel_job(job_id)
    job = service.job_controller.wait(job_id, timeout=10)
    if cancellation == "result_link":
        assert job["state"] == "failed", job
        assert job["result_ref"] is None
        assert service.store.validate_bundle(seen["run_id"])["valid"]
        return
    assert job["state"] == "cancelled", job
    assert job["result_ref"] == seen["run_id"]
    workspace = service.product_store.get_execution_workspace(
        created["approval_request"]["approval_id"]
    )
    assert workspace["state"] == "recovered"
    assert workspace["run_id"] == job["result_ref"]
    result = service.detail(job["result_ref"])
    assert result["status"] == "cancelled"
    assert result["finalized_at"]
    assert result["objective_reached"] is False
    assert result["cleanup"]["success"] is True
    assert result["cleanup"]["outstanding_receipt_count"] == 0
    assert result["cleanup"]["recovered_after_restart"] is False
    assert result["replay"]["source_run_id"] == source["run_id"]
    assert service.store.validate_bundle(job["result_ref"])["valid"]
    assert job["progress"]["cleanup_recovery"]["status"] == "reconciled_no_outstanding"
    assert service.product_store.list_runs()[0]["run_id"] == job["result_ref"]


@pytest.mark.parametrize("cleanup_available", [True, False])
def test_cancelled_replay_reconciles_only_its_exact_receipts_or_reports_deferred_failure(
    service, monkeypatch, cleanup_available
):
    source = source_run(service, execute=True)
    entered = threading.Event()
    seen = {}
    cleanup = CleanupOnlyRecoveryRunner()
    runner, _root = service.runner_factory(None)
    if cleanup_available:
        monkeypatch.setattr(runner, "execute", cleanup.execute)

    def interrupted(_self, **kwargs):
        workspace = kwargs["collector_sandbox_root"]
        artifact = workspace / "fixture.txt"
        artifact.write_text("owned cancellation fixture", encoding="utf-8")
        receipt_root = workspace / ".bluefire" / "receipts"
        receipt_root.mkdir(parents=True)
        identity = {
            "schema_version": "bluefire.receipt/v1",
            "request_hash": "sha256:" + "1" * 64,
            "action_id": "sandbox.fixture.create.v1",
            "runner_profile_id": kwargs["profile"].id,
            "workspace_id": hashlib.sha256(
                str(workspace.resolve()).replace("\\", "/").encode()
            ).hexdigest(),
            "created_at": "2026-09-06T00:00:00Z",
            "paths": [
                {
                    "relative_path": artifact.name,
                    "kind": "file",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "size": artifact.stat().st_size,
                }
            ],
        }
        receipt_id = content_hash(identity).removeprefix("sha256:")
        receipt = receipt_root / f"{receipt_id}.json"
        receipt.write_text(json.dumps({"receipt_id": receipt_id, **identity}), encoding="utf-8")
        seen.update(artifact=artifact, receipt=receipt, run_id=kwargs["handle"].run_id)
        entered.set()
        assert kwargs["cancel_event"].wait(10)
        raise RunnerTaskCancelled("fixture task stopped with an owned receipt")

    monkeypatch.setattr(Orchestrator, "_run_prepared", interrupted)
    # An unrelated unresolved binding must never be selected by this cancellation.
    original_list = service.product_store.list_execution_workspaces
    unrelated = {"approval_id": "approval-unrelated", "state": "active"}
    monkeypatch.setattr(
        service.product_store,
        "list_execution_workspaces",
        lambda **kwargs: [unrelated, *original_list(**kwargs)],
    )
    created = service.submit_replay(source["run_id"], submission(service, source))
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    service.approve_job(job_id, {"approved_by": "cancellation-reviewer"})
    assert entered.wait(10)
    service.cancel_job(job_id)
    job = service.job_controller.wait(job_id, timeout=10)
    workspace = service.product_store.get_execution_workspace(
        created["approval_request"]["approval_id"]
    )
    if cleanup_available:
        assert job["state"] == "cancelled", job
        assert workspace["state"] == "recovered"
        assert len(cleanup.calls) == 1
        assert not seen["artifact"].exists() and not seen["receipt"].exists()
        assert job["result_ref"] == seen["run_id"]
        assert service.store.validate_bundle(job["result_ref"])["valid"]
        assert job["progress"]["cleanup_recovery"]["status"] == "completed"
    else:
        assert job["state"] == "failed", job
        assert workspace["state"] == "deferred"
        assert seen["artifact"].exists() and seen["receipt"].exists()
        assert job["progress"]["cleanup_recovery"]["status"] == "deferred"
        assert job["result_ref"] is None


def _hold_catalog_lock(path, identity, held, release):
    with owner_private_database_lock(path, expected=identity):
        held.set()
        assert release.wait(15)


def test_recovered_result_link_retries_state_race_without_reversing_cancellation(
    service, monkeypatch
):
    source = source_run(service)
    approval_id = "approval-" + "a" * 32
    job = service.product_store.create_job("scenario.replay", {"approval_request_id": approval_id})
    job_id = job["job_id"]
    service.product_store.transition_job(job_id, "planning")
    service.product_store.transition_job(job_id, "running")
    transition = service.product_store.transition_job
    attempted_states = []

    def race(identifier, state, **kwargs):
        attempted_states.append(state)
        if len(attempted_states) == 1:
            transition(identifier, "cancelling")
        return transition(identifier, state, **kwargs)

    monkeypatch.setattr(service.product_store, "transition_job", race)
    outcome = {"status": "completed", "remaining_receipt_count": 0}
    service._update_interrupted_job_cleanup(approval_id, outcome, result_ref=source["run_id"])
    linked = service.product_store.get_job(job_id)
    assert attempted_states == ["running", "cancelling"]
    assert linked["state"] == "cancelling"
    assert linked["result_ref"] == source["run_id"]
    assert linked["progress"]["cleanup_recovery"] == outcome


def test_replay_admission_expires_while_another_process_still_owns_catalog(service, monkeypatch):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    context = multiprocessing.get_context("spawn")
    held, release = context.Event(), context.Event()
    owner = context.Process(
        target=_hold_catalog_lock,
        args=(service.product_store.path, service.product_store._database_identity, held, release),
    )
    monkeypatch.setattr("bluefire.service._REPLAY_ADMISSION_SECONDS", 0.15)
    try:
        owner.start()
        assert held.wait(10)
        started = time.monotonic()
        with pytest.raises(APIError) as failure:
            service.submit_replay(source["run_id"], payload)
        assert failure.value.code == "replay_job_refused"
        assert time.monotonic() - started < 2
        assert owner.is_alive()
        assert service.product_store.list_jobs() == []
        assert service._action_catalog_lock.acquire(blocking=False)
        service._action_catalog_lock.release()
    finally:
        release.set()
        if owner.pid is not None:
            owner.join(10)
    assert owner.exitcode == 0
