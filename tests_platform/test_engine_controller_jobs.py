from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Mapping

import pytest

from bluefire.domain_errors import JobCancelled
from bluefire.engine_controller_jobs import (
    ControllerCheckRecovery,
    ControllerCheckSettlement,
    DefenseOperation,
    DefenseOperationSettlement,
    EngineControllerJobError,
    EngineControllerJobs,
)
from bluefire.engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    DefenseState,
    EngineExperiment,
    IndependentObservationRecord,
    _controller_observation_record,
)
from bluefire.evidence import EvidenceRecord
from bluefire.job_runtime import JobResult
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import (
    AFTER_SNAPSHOT,
    BASELINE_ATTEMPT,
    BASELINE_RUN,
    EXPERIMENT_ID,
    INITIAL_SNAPSHOT,
    MECHANISM_REF,
    REPRODUCER_CHECK,
    REPRODUCER_RUN,
    _defense,
    _new_experiment,
    _reserve_baseline,
    _settle_latest_attempt,
    _tenant_observation,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _reviewed_experiment() -> EngineExperiment:
    experiment = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
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
    return experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    ).review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")


def _applied_experiment() -> EngineExperiment:
    change_id = _defense().change_id
    return (
        _reviewed_experiment()
        .begin_defense_application(
            change_id,
            operation_receipt_digest=_digest("1"),
            started_at="2026-11-04T12:06:30Z",
        )
        .reconcile_defense_applied(
            change_id,
            applied_configuration_digest=_digest("f"),
            reconciliation_receipt_digest=_digest("2"),
            observed_target_snapshot_ref=AFTER_SNAPSHOT,
            reconciled_at="2026-11-04T12:07:00Z",
        )
    )


class _Context:
    def __init__(self, *, cancel_at: int | None = None) -> None:
        self.calls = 0
        self.cancel_at = cancel_at
        self.job_id = "job-" + "0" * 32

    def checkpoint(self, _progress: Mapping[str, Any]) -> None:
        self.calls += 1
        if self.calls == self.cancel_at:
            raise JobCancelled


class _Repository:
    def __init__(self, experiment: EngineExperiment) -> None:
        self.experiment = experiment
        self.jobs: dict[tuple[str, str, str], dict[str, Any]] = {}

    def get_engine_experiment_document(self, experiment_id: str) -> Mapping[str, Any]:
        if experiment_id != self.experiment.experiment_id:
            raise KeyError(experiment_id)
        return self.experiment.to_dict()

    def get_job_submission(
        self, kind: str, *, submission_id: str, intent_digest: str
    ) -> Mapping[str, Any] | None:
        return self.jobs.get((kind, submission_id, intent_digest))

    def _assert_head(self, revision: int, digest: str) -> None:
        assert self.experiment.revision == revision
        assert self.experiment.digest == digest

    @staticmethod
    def _job_id(submission_id: str) -> str:
        return "job-" + uuid.UUID(submission_id).hex

    def _create_job(
        self,
        *,
        kind: str,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
    ) -> tuple[Mapping[str, Any], bool]:
        key = (kind, submission_id, intent_digest)
        existing = self.jobs.get(key)
        if existing is not None:
            return existing, False
        value = {
            "schema_version": "bluefire.job.v1",
            "job_id": self._job_id(submission_id),
            "kind": kind,
            "state": "queued",
            "request": dict(request),
        }
        self.jobs[key] = value
        return value, True

    def reserve_engine_defense_operation_submission(self, **kwargs: Any):
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        origin_id = kwargs["originating_job_id"]
        origin_receipt = kwargs["originating_operation_receipt_digest"]
        if origin_id is not None:
            origin = next(job for job in self.jobs.values() if job["job_id"] == origin_id)
            assert origin["state"] in {"cancelled", "failed", "interrupted", "completed"}
            assert origin_receipt == content_hash(
                {
                    "schema_version": "bluefire.engine-defense-operation-receipt.v1",
                    "job_id": origin_id,
                    "request_digest": content_hash(origin["request"]),
                    "operation": origin["request"]["operation"],
                }
            )
        return self._create_job(
            kind=kwargs["job_kind"],
            request=kwargs["job_request"],
            submission_id=kwargs["submission_id"],
            intent_digest=kwargs["intent_digest"],
        )

    def begin_engine_defense_operation(self, **kwargs: Any) -> Mapping[str, Any]:
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        job = next(job for job in self.jobs.values() if job["job_id"] == kwargs["job_id"])
        assert job["state"] == "running"
        assert kwargs["request_digest"] == content_hash(job["request"])
        assert kwargs["operation_receipt_digest"] == content_hash(
            {
                "schema_version": "bluefire.engine-defense-operation-receipt.v1",
                "job_id": kwargs["job_id"],
                "request_digest": kwargs["request_digest"],
                "operation": kwargs["operation"],
            }
        )
        operation = DefenseOperation(kwargs["operation"])
        if operation is DefenseOperation.APPLY:
            self.experiment = self.experiment.begin_defense_application(
                kwargs["change_id"],
                operation_receipt_digest=kwargs["operation_receipt_digest"],
                started_at=kwargs["started_at"],
            )
        elif operation is DefenseOperation.ROLLBACK:
            self.experiment = self.experiment.begin_defense_rollback(
                kwargs["change_id"],
                rollback_operation_digest=kwargs["operation_receipt_digest"],
                rollback_started_at=kwargs["started_at"],
            )
        else:  # pragma: no cover - coordinator does not call begin for reconciliation
            raise AssertionError(operation)
        return self.experiment.to_dict()

    def settle_engine_defense_operation(self, **kwargs: Any) -> Mapping[str, Any]:
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        operation = DefenseOperation(kwargs["operation"])
        if operation in {DefenseOperation.APPLY, DefenseOperation.RECONCILE_APPLICATION}:
            self.experiment = self.experiment.reconcile_defense_applied(
                kwargs["change_id"],
                applied_configuration_digest=kwargs["configuration_digest"],
                reconciliation_receipt_digest=kwargs["receipt_digest"],
                observed_target_snapshot_ref=kwargs["target_snapshot_ref"],
                reconciled_at=kwargs["settled_at"],
            )
        else:
            self.experiment = self.experiment.reconcile_defense_rolled_back(
                kwargs["change_id"],
                rollback_receipt_digest=kwargs["receipt_digest"],
                observed_target_snapshot_ref=kwargs["target_snapshot_ref"],
                rolled_back_at=kwargs["settled_at"],
            )
        return self.experiment.to_dict()

    def reserve_engine_controller_check_submission(self, **kwargs: Any):
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        job, created = self._create_job(
            kind=kwargs["job_kind"],
            request=kwargs["job_request"],
            submission_id=kwargs["submission_id"],
            intent_digest=kwargs["intent_digest"],
        )
        if created:
            check = ControllerCheckRecord.reserve(
                check_id=kwargs["check_id"],
                experiment_id=kwargs["experiment_id"],
                job_id=job["job_id"],
                run_id=kwargs["run_id"],
                role=ControllerCheckRole(kwargs["role"]),
                mechanism_ref=kwargs["mechanism_ref"],
                target_snapshot_ref=kwargs["target_snapshot_ref"],
                input_digest=kwargs["input_digest"],
                created_at=kwargs["reserved_at"],
            )
            self.experiment = self.experiment.reserve_controller_check(
                check, timestamp=kwargs["reserved_at"]
            )
        return job, created

    def _observation(self, value: Mapping[str, Any]) -> IndependentObservationRecord:
        return _controller_observation_record(
            target_snapshot_ref=value["target_snapshot_ref"],
            mechanism_ref=value["mechanism_ref"],
            check_id=value["check_id"],
            check_input_digest=value["check_input_digest"],
            evidence=EvidenceRecord.from_mapping(value["evidence"]),
        )

    def compare_and_swap_engine_controller_check_settlement(
        self, **kwargs: Any
    ) -> Mapping[str, Any]:
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        check = ControllerCheckRecord.from_mapping(kwargs["check"])
        observations = [self._observation(value) for value in kwargs["independent_observations"]]
        for observation in observations:
            self.experiment = self.experiment.record_independent_observation(
                observation, timestamp=check.settled_at or observation.evidence.timestamp
            )
        self.experiment = self.experiment.settle_controller_check(
            check, timestamp=check.settled_at or check.created_at
        )
        return self.experiment.to_dict()

    def reconcile_engine_controller_check_cleanup(self, **kwargs: Any) -> Mapping[str, Any]:
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        self.experiment = self.experiment.reconcile_check_cleanup(
            kwargs["check_id"],
            cleanup_state=CleanupState(kwargs["cleanup_state"]),
            cleanup_evidence_ref=kwargs["cleanup_evidence_ref"],
            timestamp=kwargs["timestamp"],
        )
        return self.experiment.to_dict()

    def settle_undispatched_engine_controller_check_cancellation(
        self, **kwargs: Any
    ) -> Mapping[str, Any]:
        self._assert_head(kwargs["expected_revision"], kwargs["expected_experiment_digest"])
        assert any(
            job["job_id"] == kwargs["job_id"] and job["state"] == "cancelled"
            for job in self.jobs.values()
        )
        terminal = ControllerCheckRecord.from_mapping(kwargs["check"])
        self.experiment = self.experiment.settle_controller_check(
            terminal, timestamp=terminal.settled_at or terminal.created_at
        )
        return self.experiment.to_dict()

    def load_engine_controller_check_recovery(
        self, experiment_id: str, check_id: str
    ) -> Mapping[str, Any]:
        assert experiment_id == self.experiment.experiment_id
        check = next(row for row in self.experiment.checks if row.check_id == check_id)
        job = next(value for value in self.jobs.values() if value["job_id"] == check.job_id)
        return {"experiment": self.experiment.to_dict(), "job": dict(job)}


class _Controller:
    def __init__(self, *, context: _Context | None = None, autorun: bool = True) -> None:
        self.context = context or _Context()
        self.autorun = autorun
        self.results: list[JobResult | str | None] = []

    def submit(self, _kind: str, _request: Mapping[str, Any], **kwargs: Any):
        job, created = kwargs["submission_factory"]()
        if created and self.autorun:
            self.context.job_id = job["job_id"]
            job["state"] = "running"
            try:
                self.results.append(kwargs["callback"](self.context, _request))
            except JobCancelled:
                job["state"] = "cancelled"
                raise
            except Exception:
                job["state"] = "failed"
                raise
            else:
                job["state"] = "completed"
        return job


@dataclass
class _DefenseExecutor:
    calls: int = 0
    fail: bool = False
    returned_operation: DefenseOperation | None = None

    def execute(
        self, _context: _Context, experiment: EngineExperiment, operation: DefenseOperation
    ) -> DefenseOperationSettlement:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic trusted-controller failure")
        change = experiment.defense_change
        assert change is not None
        application = operation in {
            DefenseOperation.APPLY,
            DefenseOperation.RECONCILE_APPLICATION,
        }
        return DefenseOperationSettlement(
            operation=self.returned_operation or operation,
            change_id=change.change_id,
            target_snapshot_ref=(
                change.after_target_snapshot_ref
                if application
                else experiment.initial_target_snapshot_ref
            ),
            configuration_digest=(change.approved_configuration_digest if application else None),
            receipt_digest=_digest("7"),
            settled_at="2026-11-04T12:10:00Z",
        )


@dataclass
class _CheckExecutor:
    calls: int = 0
    fail: bool = False

    def _settlement(self, check: ControllerCheckRecord) -> ControllerCheckSettlement:
        evidence = _tenant_observation(
            owner_id=check.check_id,
            run_id=check.run_id,
            timestamp="2026-11-04T12:09:00Z",
            hardened=True,
            legitimate=check.role is ControllerCheckRole.LEGITIMATE_USE,
        )
        return ControllerCheckSettlement(
            state=ControllerCheckState.COMPLETED,
            result_digest=_digest("8"),
            observations=(evidence,),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("9"),
            settled_at="2026-11-04T12:10:00Z",
        )

    def execute(
        self, _context: _Context, check: ControllerCheckRecord
    ) -> ControllerCheckSettlement:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic trusted-check failure")
        return self._settlement(check)

    def reconcile(self, check: ControllerCheckRecord) -> ControllerCheckRecovery:
        settlement = (
            self._settlement(check) if check.state is ControllerCheckState.RESERVED else None
        )
        return ControllerCheckRecovery(
            settlement=settlement,
            cleanup_state=(
                settlement.cleanup_state if settlement is not None else CleanupState.VERIFIED_ABSENT
            ),
            cleanup_evidence_ref=(
                settlement.cleanup_evidence_ref if settlement is not None else _digest("a")
            ),
            reconciled_at=(
                settlement.settled_at if settlement is not None else "2026-11-04T12:11:00Z"
            ),
        )


def _jobs(
    repository: _Repository,
    *,
    controller: _Controller | None = None,
    defense: _DefenseExecutor | None = None,
    check: _CheckExecutor | None = None,
) -> EngineControllerJobs:
    return EngineControllerJobs(
        controller=controller or _Controller(),
        repository=repository,
        defense_executor=defense,
        check_executor=check,
        clock=lambda: "2026-11-04T12:09:30Z",
    )


def _submit_defense(
    jobs: EngineControllerJobs,
    operation: DefenseOperation,
    *,
    suffix: str = "1",
    originating_job_id: str | None = None,
):
    request = jobs.prepare_defense_operation(
        experiment_id=EXPERIMENT_ID,
        change_id=_defense().change_id,
        operation=operation,
        originating_job_id=originating_job_id,
    )
    return jobs.submit_defense_operation(
        request=request,
        submission_id=f"00000000-0000-4000-8000-00000000000{suffix}",
        intent_digest=content_hash(request),
    )


def _check_request(jobs: EngineControllerJobs) -> dict[str, Any]:
    return jobs.prepare_controller_check(
        experiment_id=EXPERIMENT_ID,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("3"),
        reserved_at="2026-11-04T12:08:00Z",
    )


def _submit_check(jobs: EngineControllerJobs, request: Mapping[str, Any]):
    return jobs.submit_controller_check(
        request=request,
        submission_id="00000000-0000-4000-8000-000000000002",
        intent_digest=content_hash(request),
    )


def test_defense_operation_is_idempotent_and_reconciles_exact_readback() -> None:
    repository = _Repository(_reviewed_experiment())
    executor = _DefenseExecutor()
    jobs = _jobs(repository, defense=executor)

    first = _submit_defense(jobs, DefenseOperation.APPLY)
    assert repository.experiment.defense_change is not None
    assert repository.experiment.defense_change.state is DefenseState.APPLIED
    assert repository.experiment.current_target_snapshot_ref == AFTER_SNAPSHOT
    assert executor.calls == 1

    request = next(iter(repository.jobs.values()))["request"]
    replay = jobs.submit_defense_operation(
        request=request,
        submission_id="00000000-0000-4000-8000-000000000001",
        intent_digest=content_hash(request),
    )
    assert replay == first
    assert executor.calls == 1


def test_defense_cancellation_before_begin_keeps_reviewed_state() -> None:
    repository = _Repository(_reviewed_experiment())
    controller = _Controller(context=_Context(cancel_at=1))
    jobs = _jobs(repository, controller=controller, defense=_DefenseExecutor())

    with pytest.raises(JobCancelled):
        _submit_defense(jobs, DefenseOperation.APPLY)

    assert repository.experiment.defense_change is not None
    assert repository.experiment.defense_change.state is DefenseState.REVIEWED
    assert repository.experiment.current_target_snapshot_ref == INITIAL_SNAPSHOT


def test_interrupted_defense_stays_unknown_then_uses_explicit_reconciliation_job() -> None:
    repository = _Repository(_reviewed_experiment())
    failing = _jobs(repository, defense=_DefenseExecutor(fail=True))
    with pytest.raises(RuntimeError, match="synthetic"):
        _submit_defense(failing, DefenseOperation.APPLY)

    assert repository.experiment.defense_change is not None
    assert repository.experiment.defense_change.state is DefenseState.UNKNOWN
    assert repository.experiment.current_target_snapshot_ref is None

    recovering = _jobs(repository, defense=_DefenseExecutor())
    origin_job_id = next(iter(repository.jobs.values()))["job_id"]
    _submit_defense(
        recovering,
        DefenseOperation.RECONCILE_APPLICATION,
        suffix="3",
        originating_job_id=origin_job_id,
    )
    assert repository.experiment.defense_change.state is DefenseState.APPLIED
    assert repository.experiment.current_target_snapshot_ref == AFTER_SNAPSHOT


def test_controller_check_attests_observation_without_engine_identity() -> None:
    repository = _Repository(_applied_experiment())
    executor = _CheckExecutor()
    jobs = _jobs(repository, check=executor)

    _submit_check(jobs, _check_request(jobs))

    check = repository.experiment.checks[0]
    assert check.state is ControllerCheckState.COMPLETED
    assert check.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert len(repository.experiment.independent_observations) == 2
    observation = repository.experiment.independent_observations[-1]
    assert observation.check_id == check.check_id
    assert observation.attempt_id is None
    assert observation.check_input_digest == check.input_digest
    assert not hasattr(check, "engine_id")
    assert executor.calls == 1


@pytest.mark.parametrize(
    ("cancel_at", "failure", "expected_state", "expected_cleanup"),
    [
        (1, False, ControllerCheckState.UNKNOWN, CleanupState.VERIFIED_ABSENT),
        (None, True, ControllerCheckState.RESERVED, CleanupState.PENDING),
    ],
)
def test_controller_check_failure_preserves_unknown_without_replay(
    cancel_at: int | None,
    failure: bool,
    expected_state: ControllerCheckState,
    expected_cleanup: CleanupState,
) -> None:
    repository = _Repository(_applied_experiment())
    controller = _Controller(context=_Context(cancel_at=cancel_at))
    executor = _CheckExecutor(fail=failure)
    jobs = _jobs(repository, controller=controller, check=executor)

    error = JobCancelled if cancel_at is not None else RuntimeError
    with pytest.raises(error):
        _submit_check(jobs, _check_request(jobs))

    check = repository.experiment.checks[0]
    assert check.state is expected_state
    assert check.cleanup_state is expected_cleanup
    assert not check.independent_evidence_refs
    assert executor.calls == (0 if cancel_at is not None else 1)


def test_reserved_check_recovery_settles_without_execute_or_new_identity() -> None:
    repository = _Repository(_applied_experiment())
    controller = _Controller(autorun=False)
    executor = _CheckExecutor()
    jobs = _jobs(repository, controller=controller, check=executor)
    request = _check_request(jobs)
    _submit_check(jobs, request)
    original_job = repository.experiment.checks[0].job_id
    next(iter(repository.jobs.values()))["state"] = "interrupted"

    recovered = jobs.reconcile_interrupted_check(
        experiment_id=EXPERIMENT_ID, check_id=REPRODUCER_CHECK
    )

    assert recovered["checks"][0]["job_id"] == original_job
    assert recovered["checks"][0]["state"] == "completed"
    assert executor.calls == 0


def test_post_dispatch_failure_recovers_evidence_without_replaying_execute() -> None:
    repository = _Repository(_applied_experiment())
    failing_executor = _CheckExecutor(fail=True)
    jobs = _jobs(repository, check=failing_executor)
    with pytest.raises(RuntimeError, match="synthetic"):
        _submit_check(jobs, _check_request(jobs))

    assert repository.experiment.checks[0].state is ControllerCheckState.RESERVED
    assert next(iter(repository.jobs.values()))["state"] == "failed"

    recovery_executor = _CheckExecutor()
    recovered = _jobs(repository, check=recovery_executor).reconcile_interrupted_check(
        experiment_id=EXPERIMENT_ID,
        check_id=REPRODUCER_CHECK,
    )
    assert recovered["checks"][0]["state"] == "completed"
    assert len(recovered["checks"][0]["independent_evidence_refs"]) == 1
    assert failing_executor.calls == 1
    assert recovery_executor.calls == 0


def test_controller_check_recovery_refuses_an_active_job() -> None:
    repository = _Repository(_applied_experiment())
    jobs = _jobs(repository, controller=_Controller(autorun=False), check=_CheckExecutor())
    _submit_check(jobs, _check_request(jobs))

    with pytest.raises(EngineControllerJobError, match="terminal bound job"):
        jobs.reconcile_interrupted_check(
            experiment_id=EXPERIMENT_ID,
            check_id=REPRODUCER_CHECK,
        )


def test_controller_check_recovery_revalidates_the_terminal_job_intent() -> None:
    repository = _Repository(_applied_experiment())
    jobs = _jobs(repository, controller=_Controller(autorun=False), check=_CheckExecutor())
    _submit_check(jobs, _check_request(jobs))
    job = next(iter(repository.jobs.values()))
    job["state"] = "interrupted"
    job["request"] = {**job["request"], "mechanism_ref": _digest("0")}

    with pytest.raises(EngineControllerJobError, match="intent changed"):
        jobs.reconcile_interrupted_check(
            experiment_id=EXPERIMENT_ID,
            check_id=REPRODUCER_CHECK,
        )


def test_undispatched_cancellation_requires_cancelled_job_and_settles_absent() -> None:
    repository = _Repository(_applied_experiment())
    jobs = _jobs(repository, controller=_Controller(autorun=False), check=_CheckExecutor())
    request = _check_request(jobs)
    job = _submit_check(jobs, request)

    with pytest.raises(AssertionError):
        jobs.settle_undispatched_check_cancellation(
            experiment_id=EXPERIMENT_ID,
            check_id=REPRODUCER_CHECK,
            job_id=job["job_id"],
        )

    job["state"] = "cancelled"
    settled = jobs.settle_undispatched_check_cancellation(
        experiment_id=EXPERIMENT_ID,
        check_id=REPRODUCER_CHECK,
        job_id=job["job_id"],
    )
    assert settled["checks"][0]["state"] == "unknown"
    assert settled["checks"][0]["cleanup_state"] == "verified_absent"


def test_requests_reject_tampering_and_unavailable_callbacks() -> None:
    repository = _Repository(_reviewed_experiment())
    jobs = _jobs(repository)
    request = jobs.prepare_defense_operation(
        experiment_id=EXPERIMENT_ID,
        change_id=_defense().change_id,
        operation=DefenseOperation.APPLY,
    )
    tampered = dict(request)
    tampered["change_digest"] = _digest("0")

    with pytest.raises(EngineControllerJobError, match="change state changed"):
        jobs.submit_defense_operation(
            request=tampered,
            submission_id="00000000-0000-4000-8000-000000000004",
            intent_digest=content_hash(tampered),
        )
    with pytest.raises(EngineControllerJobError, match="unavailable"):
        jobs.submit_defense_operation(
            request=request,
            submission_id="00000000-0000-4000-8000-000000000005",
            intent_digest=content_hash(request),
        )


def test_product_store_submission_metadata_is_strictly_normalized() -> None:
    defense_repository = _Repository(_reviewed_experiment())
    defense_jobs = _jobs(defense_repository)
    defense = defense_jobs.prepare_defense_operation(
        experiment_id=EXPERIMENT_ID,
        change_id=_defense().change_id,
        operation=DefenseOperation.APPLY,
    )
    check_repository = _Repository(_applied_experiment())
    check_jobs = _jobs(check_repository)
    check = _check_request(check_jobs)

    for request, parser in (
        (defense, defense_jobs._exact_defense_request),
        (check, check_jobs._exact_check_request),
    ):
        stored = {
            **request,
            "_submission": {
                "schema_version": "bluefire.job-submission.v1",
                "submission_id": "66666666-6666-4666-8666-666666666666",
                "intent_digest": content_hash(request),
            },
        }
        parsed = parser(stored)
        assert (parsed[0] if isinstance(parsed, tuple) else parsed) == request
        stored["_submission"]["intent_digest"] = _digest("0")
        with pytest.raises(EngineControllerJobError, match="submission binding changed"):
            parser(stored)


def test_defense_executor_cannot_change_the_saved_operation() -> None:
    repository = _Repository(_reviewed_experiment())
    jobs = _jobs(
        repository,
        defense=_DefenseExecutor(returned_operation=DefenseOperation.ROLLBACK),
    )

    with pytest.raises(EngineControllerJobError, match="operation changed"):
        _submit_defense(jobs, DefenseOperation.APPLY)

    assert repository.experiment.defense_change is not None
    assert repository.experiment.defense_change.state is DefenseState.UNKNOWN
    assert repository.experiment.current_target_snapshot_ref is None
