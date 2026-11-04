from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.engine_attempt_contract import AttemptCompleteness, AttemptRole, AttemptState
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import CleanupState, EngineExperiment
from bluefire.engine_experiment_jobs import EngineExperimentJobs
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import (
    BASELINE_ATTEMPT,
    BASELINE_RUN,
    ENVIRONMENT_REF,
    EXPERIMENT_ID,
    INITIAL_SNAPSHOT,
    OBJECTIVE_REF,
    SCOPE_REF,
    _binding,
    _digest,
    _new_experiment,
)

SUBMISSION_ID = "22222222-2222-4222-8222-222222222222"
JOB_ID = "job-" + SUBMISSION_ID.replace("-", "")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validator(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return EngineExperiment._from_controller_mapping(value).to_dict()


def _authority():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    delegation_created = _iso(now - timedelta(minutes=2))
    binding_created = _iso(now - timedelta(minutes=1))
    expires = _iso(now + timedelta(minutes=10))
    binding = _binding(
        AttemptRole.BASELINE,
        attempt_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        target_snapshot_ref=INITIAL_SNAPSHOT,
        created_at=binding_created,
        parent_attempt_id=None,
    )
    delegation = EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "2" * 32,
        experiment_id=EXPERIMENT_ID,
        attempt_id=BASELINE_ATTEMPT,
        role=AttemptRole.BASELINE,
        parent_attempt_id=None,
        objective_ref=OBJECTIVE_REF,
        environment_ref=ENVIRONMENT_REF,
        target_snapshot_ref=INITIAL_SNAPSHOT,
        scope_ref=SCOPE_REF,
        scope_version=binding.scope_version,
        engine_id=binding.engine_id,
        engine_version=binding.engine_version,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        policy_overlay_digest=binding.policy_overlay_digest,
        model_authorization_ref=binding.model_authorization_ref,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_data_destination=binding.model_data_destination,
        network_policy_digest=_digest("d"),
        custody_plan_digest=_digest("e"),
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
        created_at=delegation_created,
        expires_at=expires,
    )
    return binding, delegation, delegation.approval_binding(binding), _iso(now)


def _prepared_store(path: Path):
    store = ProductStore(path)
    experiment = _new_experiment()
    created = store.create_engine_experiment(
        EXPERIMENT_ID, experiment.to_dict(), validator=_validator
    )
    binding, delegation, approval, reserved_at = _authority()
    request = store.create_approval_request(**approval.request_binding())
    approved = store.approve(
        str(request["approval_id"]),
        approved_by="operator",
        expected_state_digest=approval.state_digest,
        expected_plan_digest=approval.plan_digest,
        expected_target_scope_digest=approval.target_scope_digest,
    )
    consumed = store.consume_approval(
        str(request["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest=approval.state_digest,
        expected_plan_digest=approval.plan_digest,
        expected_target_scope_digest=approval.target_scope_digest,
    )
    job_request = EngineExperimentJobs._request(
        experiment=experiment,
        binding=binding,
        delegation=delegation,
        approval=approval,
        approval_id=str(request["approval_id"]),
    )
    values = {
        "experiment_id": EXPERIMENT_ID,
        "binding": binding.to_dict(),
        "delegation": delegation.to_dict(),
        "approval_binding": approval.to_dict(),
        "approval_id": str(request["approval_id"]),
        "approval_nonce": str(approved["nonce"]),
        "approved_by": "operator",
        "job_kind": "engine-attempt",
        "job_request": job_request,
        "submission_id": SUBMISSION_ID,
        "intent_digest": content_hash(job_request),
        "expected_revision": int(created["revision"]),
        "expected_experiment_digest": str(created["digest"]),
        "reserved_at": reserved_at,
    }
    assert consumed["status"] == "consumed"
    return store, values, binding, delegation, approval


def test_atomic_reservation_claims_exact_approval_and_reopens_context(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store, values, binding, delegation, approval = _prepared_store(path)

    job, created = store.reserve_engine_attempt_submission(**values)
    replay, replay_created = store.reserve_engine_attempt_submission(**values)

    assert created is True
    assert replay_created is False
    assert replay == job
    assert job["job_id"] == JOB_ID
    assert job["request"]["_submission"]["submission_id"] == SUBMISSION_ID
    assert store.get_approval_request(values["approval_id"])["status"] == "claimed"
    assert len(store.list_engine_experiment_versions(EXPERIMENT_ID)) == 2

    context = job["progress"]["_engine_execution"]
    assert "nonce" not in json.dumps(context).lower()
    assert "approved_by" not in json.dumps(context)
    assert context["delegation_digest"] == delegation.delegation_digest
    assert context["execution_approval_digest"] == content_hash(approval.to_dict())

    reopened = ProductStore(path)
    loaded = reopened.load_engine_attempt_execution(EXPERIMENT_ID, binding.attempt_id)
    assert loaded == {
        "experiment": reopened.get_engine_experiment_document(EXPERIMENT_ID),
        "delegation": delegation.to_dict(),
        "approval_binding": approval.to_dict(),
        "approval_record": reopened.get_approval_request(values["approval_id"]),
    }


def test_failed_reservation_rolls_back_approval_job_and_experiment(tmp_path: Path) -> None:
    store, values, _binding_value, _delegation, _approval = _prepared_store(
        tmp_path / "bluefire.db"
    )
    values["expected_experiment_digest"] = _digest("f")

    with pytest.raises(ResourceConflictError, match="expected revision"):
        store.reserve_engine_attempt_submission(**values)

    assert store.get_approval_request(values["approval_id"])["status"] == "consumed"
    assert store.get_job_submission(
        "engine-attempt",
        submission_id=SUBMISSION_ID,
        intent_digest=values["intent_digest"],
    ) is None
    assert store.get_engine_experiment_document(EXPERIMENT_ID)["attempts"] == []


def test_lifecycle_settlement_cleanup_and_stale_cas_are_durable(tmp_path: Path) -> None:
    store, values, binding, _delegation, _approval = _prepared_store(tmp_path / "bluefire.db")
    store.reserve_engine_attempt_submission(**values)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    queued = experiment.attempts[0].record
    preflight = queued.transition(AttemptState.PREFLIGHT)
    preflight_document = store.compare_and_swap_engine_attempt_record(
        experiment_id=EXPERIMENT_ID,
        record=preflight.to_dict(),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
        timestamp=values["reserved_at"],
    )
    with pytest.raises(ResourceConflictError, match="expected revision"):
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=preflight.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=values["reserved_at"],
        )

    current = EngineExperiment._from_controller_mapping(preflight_document)
    running_at = _iso(datetime.now(timezone.utc))
    running = current.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-product-store",
        timestamp=running_at,
    )
    current = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=current.revision,
            expected_experiment_digest=current.digest,
            timestamp=running_at,
        )
    )
    ended_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=1))
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp=ended_at,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    settled = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=completed.to_dict(),
            engine_evidence=(),
            artifact_manifest_ref=_digest("a"),
            cleanup_state=CleanupState.UNKNOWN.value,
            cleanup_evidence_ref=_digest("b"),
            settled_at=ended_at,
            expected_revision=current.revision,
            expected_experiment_digest=current.digest,
        )
    )
    reconciled = EngineExperiment._from_controller_mapping(
        store.reconcile_engine_attempt_cleanup(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            cleanup_state=CleanupState.VERIFIED_ABSENT.value,
            cleanup_evidence_ref=_digest("c"),
            timestamp=_iso(datetime.now(timezone.utc) + timedelta(seconds=2)),
            expected_revision=settled.revision,
            expected_experiment_digest=settled.digest,
        )
    )
    assert reconciled.attempts[0].record.state is AttemptState.COMPLETED
    assert reconciled.attempts[0].cleanup_state is CleanupState.VERIFIED_ABSENT


def test_cancel_and_callback_cas_have_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store, values, binding, _delegation, _approval = _prepared_store(path)
    store.reserve_engine_attempt_submission(**values)
    store.transition_job(JOB_ID, "cancelled")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    queued = experiment.attempts[0].record
    preflight = queued.transition(AttemptState.PREFLIGHT)
    cancelled = queued.transition(
        AttemptState.CANCELLED,
        timestamp=values["reserved_at"],
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_dispatch",
        limitations=("External-engine dispatch did not begin.",),
    )
    barrier = threading.Barrier(2)
    winners: list[str] = []
    errors: list[Exception] = []

    def callback_cas() -> None:
        candidate = ProductStore(path)
        barrier.wait(timeout=5)
        try:
            candidate.compare_and_swap_engine_attempt_record(
                experiment_id=EXPERIMENT_ID,
                record=preflight.to_dict(),
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                timestamp=values["reserved_at"],
            )
            winners.append("callback")
        except Exception as exc:  # pragma: no branch - asserted below
            errors.append(exc)

    def cancellation_cas() -> None:
        candidate = ProductStore(path)
        barrier.wait(timeout=5)
        try:
            candidate.settle_undispatched_engine_attempt_cancellation(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                job_id=JOB_ID,
                record=cancelled.to_dict(),
                cleanup_evidence_ref=_digest("f"),
                settled_at=values["reserved_at"],
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
            )
            winners.append("cancel")
        except Exception as exc:  # pragma: no branch - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=callback_cas), threading.Thread(target=cancellation_cas)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(winners) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ResourceConflictError)
    saved = EngineExperiment._from_controller_mapping(
        ProductStore(path).get_engine_experiment_document(EXPERIMENT_ID)
    ).attempts[0]
    if winners == ["cancel"]:
        assert saved.record.state is AttemptState.CANCELLED
        assert saved.record.upstream_session_id is None
        assert saved.cleanup_state is CleanupState.VERIFIED_ABSENT
    else:
        assert saved.record.state is AttemptState.PREFLIGHT
        assert saved.cleanup_state is CleanupState.PENDING


def test_undispatched_settlement_requires_durable_cancelled_job(tmp_path: Path) -> None:
    store, values, binding, _delegation, _approval = _prepared_store(tmp_path / "bluefire.db")
    store.reserve_engine_attempt_submission(**values)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    cancelled = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=values["reserved_at"],
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_dispatch",
        limitations=("External-engine dispatch did not begin.",),
    )

    with pytest.raises(ResourceConflictError, match="durably cancelled"):
        store.settle_undispatched_engine_attempt_cancellation(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=JOB_ID,
            record=cancelled.to_dict(),
            cleanup_evidence_ref=_digest("f"),
            settled_at=values["reserved_at"],
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )

    current = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    assert current.attempts[0].record.state is AttemptState.QUEUED


def test_undispatched_settlement_rejects_a_failed_terminal_record(tmp_path: Path) -> None:
    store, values, binding, _delegation, _approval = _prepared_store(tmp_path / "bluefire.db")
    store.reserve_engine_attempt_submission(**values)
    store.transition_job(JOB_ID, "cancelled")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    failed = experiment.attempts[0].record.transition(
        AttemptState.FAILED,
        timestamp=values["reserved_at"],
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="job_cancelled_but_attempt_marked_failed",
    )

    with pytest.raises(ProductStoreError, match="exact no-custody outcome"):
        store.settle_undispatched_engine_attempt_cancellation(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=JOB_ID,
            record=failed.to_dict(),
            cleanup_evidence_ref=_digest("f"),
            settled_at=values["reserved_at"],
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )

    current = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    assert current.attempts[0].record.state is AttemptState.QUEUED


def test_load_rejects_authority_context_tampering(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store, values, binding, _delegation, _approval = _prepared_store(path)
    job, _created = store.reserve_engine_attempt_submission(**values)
    progress = dict(job["progress"])
    context = dict(progress["_engine_execution"])
    context["delegation_digest"] = _digest("f")
    progress["_engine_execution"] = context
    with store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET progress_json = ? WHERE job_id = ?",
            (json.dumps(progress, sort_keys=True, separators=(",", ":")), JOB_ID),
        )

    with pytest.raises(ProductStoreError, match="authority digest changed"):
        store.load_engine_attempt_execution(EXPERIMENT_ID, binding.attempt_id)
