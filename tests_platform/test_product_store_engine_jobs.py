from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.engine_attempt_contract import AttemptCompleteness, AttemptRole, AttemptState
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_experiment_jobs import EngineExperimentJobs
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.util import content_hash
from tests_platform.test_engine_controller_jobs import (
    _CheckExecutor,
    _defense,
)
from tests_platform.test_engine_experiment import (
    AFTER_SNAPSHOT,
    BASELINE_ATTEMPT,
    BASELINE_RUN,
    ENVIRONMENT_REF,
    EXPERIMENT_ID,
    INITIAL_SNAPSHOT,
    MECHANISM_REF,
    OBJECTIVE_REF,
    REPRODUCER_CHECK,
    REPRODUCER_RUN,
    SCOPE_REF,
    _binding,
    _digest,
    _new_experiment,
    _reserve_baseline,
    _tenant_observation,
)

SUBMISSION_ID = "22222222-2222-4222-8222-222222222222"
JOB_ID = "job-" + SUBMISSION_ID.replace("-", "")
DEFENSE_SUBMISSION_ID = "33333333-3333-4333-8333-333333333333"
DEFENSE_JOB_ID = "job-" + DEFENSE_SUBMISSION_ID.replace("-", "")
CHECK_SUBMISSION_ID = "44444444-4444-4444-8444-444444444444"
CHECK_JOB_ID = "job-" + CHECK_SUBMISSION_ID.replace("-", "")


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


def _reviewed_versions() -> list[EngineExperiment]:
    versions = [_new_experiment()]
    experiment = _reserve_baseline(versions[-1])
    versions.append(experiment)
    current = experiment.attempts[-1].record
    experiment = experiment.update_attempt_record(
        current.transition(AttemptState.PREFLIGHT), timestamp="2026-11-04T12:02:00Z"
    )
    versions.append(experiment)
    running = experiment.attempts[-1].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-aaaaaaaa",
        timestamp="2026-11-04T12:02:00Z",
    )
    experiment = experiment.update_attempt_record(running, timestamp="2026-11-04T12:02:00Z")
    versions.append(experiment)
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:04:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    experiment = experiment.settle_attempt(
        completed,
        engine_evidence=(),
        artifact_manifest_ref=_digest("c"),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("d"),
        settled_at="2026-11-04T12:04:00Z",
    )
    versions.append(experiment)
    observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:03:00Z",
            hardened=False,
        ),
    )
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    )
    versions.append(experiment)
    experiment = experiment.review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")
    versions.append(experiment)
    return versions


def _applied_versions() -> list[EngineExperiment]:
    versions = _reviewed_versions()
    experiment = versions[-1].begin_defense_application(
        _defense().change_id,
        operation_receipt_digest=_digest("1"),
        started_at="2026-11-04T12:06:30Z",
    )
    versions.append(experiment)
    experiment = experiment.reconcile_defense_applied(
        _defense().change_id,
        applied_configuration_digest=_digest("f"),
        reconciliation_receipt_digest=_digest("2"),
        observed_target_snapshot_ref=AFTER_SNAPSHOT,
        reconciled_at="2026-11-04T12:07:00Z",
    )
    versions.append(experiment)
    return versions


def _experiment_store(path: Path, versions: list[EngineExperiment]) -> ProductStore:
    store = ProductStore(path)
    saved = store.create_engine_experiment(
        EXPERIMENT_ID, versions[0].to_dict(), validator=_validator
    )
    for experiment in versions[1:]:
        saved = store.save_engine_experiment(
            EXPERIMENT_ID,
            experiment.to_dict(),
            expected_revision=int(saved["revision"]),
            expected_digest=str(saved["digest"]),
            validator=_validator,
        )
    return store


def _defense_request(
    experiment: EngineExperiment,
    operation: str,
    *,
    origin_job_id: str | None = None,
) -> dict[str, Any]:
    change = experiment.defense_change
    assert change is not None
    origin_receipt = None
    if operation == "reconcile_application":
        origin_receipt = change.application_receipt_digest
    elif operation == "reconcile_rollback":
        origin_receipt = change.rollback_operation_digest
    return {
        "schema_version": "bluefire.engine-defense-operation-job.v1",
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "change_id": change.change_id,
        "change_digest": content_hash(change.to_dict()),
        "operation": operation,
        "originating_job_id": origin_job_id,
        "originating_operation_receipt_digest": origin_receipt,
    }


def _check_job_request(experiment: EngineExperiment) -> dict[str, Any]:
    preview = ControllerCheckRecord.reserve(
        check_id=REPRODUCER_CHECK,
        experiment_id=EXPERIMENT_ID,
        job_id="job-" + "0" * 32,
        run_id=REPRODUCER_RUN,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("3"),
        created_at="2026-11-04T12:08:00Z",
    )
    return {
        "schema_version": "bluefire.engine-controller-check-job.v1",
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "check_id": preview.check_id,
        "run_id": preview.run_id,
        "role": preview.role.value,
        "performer": preview.performer.value,
        "mechanism_ref": preview.mechanism_ref,
        "target_snapshot_ref": preview.target_snapshot_ref,
        "input_digest": preview.input_digest,
        "reserved_at": preview.created_at,
    }


def _reserve_check(store: ProductStore) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    request = _check_job_request(experiment)
    job, created = store.reserve_engine_controller_check_submission(
        experiment_id=EXPERIMENT_ID,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
        role=ControllerCheckRole.RETAINED_REPRODUCER.value,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("3"),
        reserved_at="2026-11-04T12:08:00Z",
        job_kind="engine-controller-check",
        job_request=request,
        submission_id=CHECK_SUBMISSION_ID,
        intent_digest=content_hash(request),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
    )
    assert created is True
    return job, request


def _cancelled_check(check: ControllerCheckRecord) -> ControllerCheckRecord:
    recorded_at = "2026-11-04T12:09:00Z"
    result_digest = content_hash(
        {
            "schema_version": "bluefire.engine-controller-check-unknown.v1",
            "check_id": check.check_id,
            "dispatched": False,
            "recorded_at": recorded_at,
        }
    )
    cleanup_receipt = content_hash(
        {
            "schema_version": "bluefire.engine-controller-check-uncertain.v1",
            "experiment_id": EXPERIMENT_ID,
            "check_id": check.check_id,
            "job_id": CHECK_JOB_ID,
            "run_id": check.run_id,
            "dispatched": False,
            "cleanup_state": CleanupState.VERIFIED_ABSENT.value,
            "recorded_at": recorded_at,
        }
    )
    return check.settle(
        state=ControllerCheckState.UNKNOWN,
        result_digest=result_digest,
        independent_evidence_refs=(),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=cleanup_receipt,
        settled_at=recorded_at,
    )


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
    assert (
        store.get_job_submission(
            "engine-attempt",
            submission_id=SUBMISSION_ID,
            intent_digest=values["intent_digest"],
        )
        is None
    )
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


def test_controller_observation_admission_is_atomic_idempotent_and_restart_safe(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bluefire.db"
    store, values, binding, _delegation, _approval = _prepared_store(path)
    store.reserve_engine_attempt_submission(**values)
    store.transition_job(JOB_ID, "planning")
    store.transition_job(JOB_ID, "running")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    preflight = experiment.attempts[0].record.transition(AttemptState.PREFLIGHT)
    experiment = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=preflight.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=values["reserved_at"],
        )
    )
    observed_at = _iso(datetime.now(timezone.utc))
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-observation",
        timestamp=observed_at,
    )
    experiment = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=observed_at,
        )
    )
    observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=binding.attempt_id,
        evidence=_tenant_observation(
            owner_id=binding.attempt_id,
            run_id=binding.run_id,
            timestamp=observed_at,
            hardened=False,
        ),
    )
    with pytest.raises(ProductStoreError, match="settled attempt binding"):
        store.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=observation.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=observed_at,
        )
    settled_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=2))
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp=settled_at,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    experiment = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=completed.to_dict(),
            engine_evidence=(),
            artifact_manifest_ref=_digest("7"),
            cleanup_state=CleanupState.VERIFIED_ABSENT.value,
            cleanup_evidence_ref=_digest("8"),
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    with pytest.raises(ProductStoreError, match="terminal bound job"):
        store.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=observation.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=settled_at,
        )
    store.transition_job(JOB_ID, "completed")
    saved = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=observation.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=settled_at,
        )
    )
    assert saved.independent_observations == (observation,)

    reopened = ProductStore(path)
    identical = EngineExperiment._from_controller_mapping(
        reopened.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=observation.to_dict(),
            expected_revision=saved.revision,
            expected_experiment_digest=saved.digest,
            timestamp=settled_at,
        )
    )
    assert identical.revision == saved.revision
    assert identical.digest == saved.digest

    conflicting = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=_digest("9"),
        attempt_id=binding.attempt_id,
        evidence=observation.evidence,
    )
    with pytest.raises(ProductStoreError, match="different evidence"):
        reopened.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=conflicting.to_dict(),
            expected_revision=saved.revision,
            expected_experiment_digest=saved.digest,
            timestamp=settled_at,
        )

    wrong_target = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=binding.attempt_id,
        evidence=_tenant_observation(
            owner_id=binding.attempt_id,
            run_id=binding.run_id,
            timestamp=observed_at,
            hardened=True,
        ),
    )
    with pytest.raises(ProductStoreError, match="settled attempt binding"):
        reopened.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=wrong_target.to_dict(),
            expected_revision=saved.revision,
            expected_experiment_digest=saved.digest,
            timestamp=settled_at,
        )

    with reopened._connection(write=True) as connection:
        row = connection.execute(
            "SELECT request_json FROM jobs WHERE job_id = ?", (JOB_ID,)
        ).fetchone()
        tampered_request = json.loads(str(row["request_json"]))
        tampered_request["delegation_digest"] = _digest("e")
        connection.execute(
            "UPDATE jobs SET request_json = ? WHERE job_id = ?",
            (json.dumps(tampered_request, sort_keys=True, separators=(",", ":")), JOB_ID),
        )
    with pytest.raises(ProductStoreError, match="submission changed"):
        reopened.compare_and_swap_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            observation=observation.to_dict(),
            expected_revision=saved.revision,
            expected_experiment_digest=saved.digest,
            timestamp=settled_at,
        )


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


def test_defense_begin_and_reconciliation_bind_the_terminal_origin_job(tmp_path: Path) -> None:
    store = _experiment_store(tmp_path / "bluefire.db", _reviewed_versions())
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    request = _defense_request(experiment, "apply")
    job, created = store.reserve_engine_defense_operation_submission(
        experiment_id=EXPERIMENT_ID,
        change_id=_defense().change_id,
        operation="apply",
        job_kind="engine-controller-operation",
        job_request=request,
        submission_id=DEFENSE_SUBMISSION_ID,
        intent_digest=content_hash(request),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
        originating_job_id=None,
        originating_operation_receipt_digest=None,
    )
    assert created is True
    assert job["job_id"] == DEFENSE_JOB_ID
    store.transition_job(DEFENSE_JOB_ID, "planning")
    store.transition_job(DEFENSE_JOB_ID, "running")
    operation_receipt = content_hash(
        {
            "schema_version": "bluefire.engine-defense-operation-receipt.v1",
            "job_id": DEFENSE_JOB_ID,
            "request_digest": content_hash(request),
            "operation": "apply",
        }
    )
    unknown = EngineExperiment._from_controller_mapping(
        store.begin_engine_defense_operation(
            experiment_id=EXPERIMENT_ID,
            change_id=_defense().change_id,
            operation="apply",
            operation_receipt_digest=operation_receipt,
            job_id=DEFENSE_JOB_ID,
            request_digest=content_hash(request),
            started_at="2026-11-04T12:06:30Z",
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    assert unknown.defense_change is not None
    assert unknown.defense_change.state.value == "unknown"
    reconciliation = _defense_request(
        unknown, "reconcile_application", origin_job_id=DEFENSE_JOB_ID
    )
    reconciliation_values = {
        "experiment_id": EXPERIMENT_ID,
        "change_id": _defense().change_id,
        "operation": "reconcile_application",
        "job_kind": "engine-controller-operation",
        "job_request": reconciliation,
        "submission_id": "55555555-5555-4555-8555-555555555555",
        "intent_digest": content_hash(reconciliation),
        "expected_revision": unknown.revision,
        "expected_experiment_digest": unknown.digest,
        "originating_job_id": DEFENSE_JOB_ID,
        "originating_operation_receipt_digest": operation_receipt,
    }

    with pytest.raises(ProductStoreError, match="terminal origin job"):
        store.reserve_engine_defense_operation_submission(**reconciliation_values)
    assert (
        store.get_job_submission(
            "engine-controller-operation",
            submission_id=reconciliation_values["submission_id"],
            intent_digest=reconciliation_values["intent_digest"],
        )
        is None
    )

    store.transition_job(DEFENSE_JOB_ID, "failed")
    recovery_job, recovery_created = store.reserve_engine_defense_operation_submission(
        **reconciliation_values
    )
    assert recovery_created is True
    assert recovery_job["request"]["originating_job_id"] == DEFENSE_JOB_ID
    applied = EngineExperiment._from_controller_mapping(
        store.settle_engine_defense_operation(
            experiment_id=EXPERIMENT_ID,
            change_id=_defense().change_id,
            operation="reconcile_application",
            target_snapshot_ref=AFTER_SNAPSHOT,
            configuration_digest=_digest("f"),
            receipt_digest=_digest("7"),
            settled_at="2026-11-04T12:10:00Z",
            expected_revision=unknown.revision,
            expected_experiment_digest=unknown.digest,
        )
    )
    assert applied.defense_change is not None
    assert applied.defense_change.state.value == "applied"


def test_controller_check_recovery_and_atomic_observation_settlement(tmp_path: Path) -> None:
    store = _experiment_store(tmp_path / "bluefire.db", _applied_versions())
    job, _request = _reserve_check(store)
    assert job["job_id"] == CHECK_JOB_ID
    store.transition_job(CHECK_JOB_ID, "planning")
    store.transition_job(CHECK_JOB_ID, "running")
    store.transition_job(CHECK_JOB_ID, "failed")

    snapshot = store.load_engine_controller_check_recovery(EXPERIMENT_ID, REPRODUCER_CHECK)
    assert snapshot["job"]["state"] == "failed"
    experiment = EngineExperiment._from_controller_mapping(snapshot["experiment"])
    check = experiment.checks[0]
    settlement = _CheckExecutor()._settlement(check)
    observations = tuple(
        _controller_observation_record(
            target_snapshot_ref=check.target_snapshot_ref,
            mechanism_ref=check.mechanism_ref,
            check_id=check.check_id,
            check_input_digest=check.input_digest,
            evidence=evidence,
        )
        for evidence in settlement.observations
    )
    terminal = check.settle(
        state=settlement.state,
        result_digest=settlement.result_digest,
        independent_evidence_refs=(item.evidence_id for item in observations),
        cleanup_state=settlement.cleanup_state,
        cleanup_evidence_ref=settlement.cleanup_evidence_ref,
        settled_at=settlement.settled_at,
    )
    unknown = check.settle(
        state=ControllerCheckState.UNKNOWN,
        result_digest=_digest("4"),
        independent_evidence_refs=(),
        cleanup_state=CleanupState.UNKNOWN,
        cleanup_evidence_ref=_digest("5"),
        settled_at=settlement.settled_at,
    )
    with pytest.raises(ProductStoreError, match="terminal evidence references"):
        store.compare_and_swap_engine_controller_check_settlement(
            experiment_id=EXPERIMENT_ID,
            check=unknown.to_dict(),
            independent_observations=(item.to_dict() for item in observations),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    settled = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_controller_check_settlement(
            experiment_id=EXPERIMENT_ID,
            check=terminal.to_dict(),
            independent_observations=(item.to_dict() for item in observations),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    assert settled.checks[0].state is ControllerCheckState.COMPLETED
    assert settled.checks[0].cleanup_state is CleanupState.VERIFIED_ABSENT
    assert settled.checks[0].independent_evidence_refs == (observations[0].evidence_id,)
    assert settled.independent_observations[-1].check_id == REPRODUCER_CHECK


def test_controller_check_undispatched_cancel_requires_cancelled_job(tmp_path: Path) -> None:
    store = _experiment_store(tmp_path / "bluefire.db", _applied_versions())
    _job, _request = _reserve_check(store)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    check = experiment.checks[0]
    terminal = _cancelled_check(check)
    values = {
        "experiment_id": EXPERIMENT_ID,
        "check_id": check.check_id,
        "job_id": CHECK_JOB_ID,
        "check": terminal.to_dict(),
        "expected_revision": experiment.revision,
        "expected_experiment_digest": experiment.digest,
    }

    with pytest.raises(ResourceConflictError, match="dispatch or custody"):
        store.settle_undispatched_engine_controller_check_cancellation(**values)
    store.transition_job(CHECK_JOB_ID, "cancelled")
    settled = EngineExperiment._from_controller_mapping(
        store.settle_undispatched_engine_controller_check_cancellation(**values)
    )
    assert settled.checks[0].state is ControllerCheckState.UNKNOWN
    assert settled.checks[0].cleanup_state is CleanupState.VERIFIED_ABSENT


def test_controller_check_cancel_refuses_a_job_that_reached_running(tmp_path: Path) -> None:
    store = _experiment_store(tmp_path / "bluefire.db", _applied_versions())
    _job, _request = _reserve_check(store)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    terminal = _cancelled_check(experiment.checks[0])
    store.transition_job(CHECK_JOB_ID, "planning")
    store.transition_job(CHECK_JOB_ID, "running", progress={"phase": "replaced"})
    store.transition_job(CHECK_JOB_ID, "cancelling", progress={})
    cancelled = store.transition_job(CHECK_JOB_ID, "cancelled", progress={})
    assert cancelled["progress"]["_engine_controller_dispatch"]["begun"] is True

    with pytest.raises(ResourceConflictError, match="dispatch may have begun"):
        store.settle_undispatched_engine_controller_check_cancellation(
            experiment_id=EXPERIMENT_ID,
            check_id=REPRODUCER_CHECK,
            job_id=CHECK_JOB_ID,
            check=terminal.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    saved = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    assert saved.checks[0].state is ControllerCheckState.RESERVED
    assert saved.checks[0].cleanup_state is CleanupState.PENDING
