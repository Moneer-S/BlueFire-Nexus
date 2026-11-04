from __future__ import annotations

from typing import Any, Mapping

import pytest

from bluefire.domain_errors import JobCancelled
from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptRecord,
    EngineEvidenceItem,
)
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import CleanupState, EngineExperiment
from bluefire.engine_experiment_jobs import (
    EngineExperimentJobError,
    EngineExperimentJobs,
    EngineRuntimeSettlement,
)
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

SUBMISSION_ID = "11111111-1111-4111-8111-111111111111"
JOB_ID = "job-" + SUBMISSION_ID.replace("-", "")


class _Context:
    def __init__(self, *, cancel_at: int | None = None) -> None:
        self.progress: list[Mapping[str, Any]] = []
        self.cancel_at = cancel_at
        self.checkpoint_calls = 0

    def checkpoint(self, progress=None, *, replace_progress: bool = False) -> None:
        del replace_progress
        self.checkpoint_calls += 1
        if self.cancel_at == self.checkpoint_calls:
            raise JobCancelled("cancelled at controller checkpoint")
        if progress is not None:
            self.progress.append(progress)


class _Controller:
    def __init__(self, *, context: _Context | None = None, run_callback: bool = True) -> None:
        self.jobs: dict[tuple[str, str], dict[str, Any]] = {}
        self.callback_calls = 0
        self.context = _Context() if context is None else context
        self.run_callback = run_callback

    def submit(
        self,
        kind,
        request,
        *,
        requires_approval=False,
        callback=None,
        submission_id=None,
        intent_digest=None,
        submission_factory=None,
    ):
        del requires_approval, intent_digest
        key = (kind, submission_id)
        if key in self.jobs:
            return self.jobs[key]
        assert callback is not None and submission_factory is not None
        job, created = submission_factory()
        saved = dict(job)
        self.jobs[key] = saved
        if created and self.run_callback:
            self.callback_calls += 1
            result = callback(self.context, request)
            saved["state"] = "completed"
            saved["result_ref"] = result.result_ref
            saved["progress"] = dict(result.progress or {})
        return saved


class _Repository:
    def __init__(self, experiment: EngineExperiment) -> None:
        self.experiment = experiment
        self.delegation: EngineCapabilityDelegation | None = None
        self.approval_binding = None
        self.approval_record: Mapping[str, Any] | None = None
        self.reserve_calls = 0
        self.existing_submission: Mapping[str, Any] | None = None
        self.cancelled_job_ids: set[str] = set()
        self.cancel_settle_calls = 0

    def get_engine_experiment_document(self, experiment_id: str):
        assert experiment_id == self.experiment.experiment_id
        return self.experiment.to_dict()

    def get_job_submission(self, kind, *, submission_id, intent_digest):
        del kind, submission_id, intent_digest
        return self.existing_submission

    def reserve_engine_attempt_submission(self, **values):
        self.reserve_calls += 1
        self._cas(values)
        self.delegation = EngineCapabilityDelegation.from_mapping(values["delegation"])
        self.approval_binding = self.delegation.validate_approval_binding(
            values["approval_binding"], values["binding"]
        )
        self.approval_record = {
            "schema_version": "bluefire.approval-request.v1",
            **self.approval_binding.request_binding(),
            "approval_id": values["approval_id"],
            "status": "claimed",
            "requested_at": "2026-11-04T12:00:00Z",
            "approved_at": "2026-11-04T12:00:20Z",
            "nonce": values["approval_nonce"],
            "approved_by": values["approved_by"],
            "consumed_at": "2026-11-04T12:00:30Z",
            "claimed_at": "2026-11-04T12:01:00Z",
        }
        self.experiment = self.experiment.reserve_attempt(
            self.delegation.validate_attempt_binding(values["binding"]),
            job_id=JOB_ID,
            delegation_digest=self.delegation.delegation_digest,
            execution_approval_digest=content_hash(self.approval_binding.to_dict()),
            execution_approval_id=values["approval_id"],
            timestamp=values["reserved_at"],
        )
        return (
            {
                "job_id": JOB_ID,
                "kind": values["job_kind"],
                "request": dict(values["job_request"]),
                "state": "queued",
            },
            True,
        )

    def load_engine_attempt_execution(self, experiment_id: str, attempt_id: str):
        assert experiment_id == self.experiment.experiment_id
        assert attempt_id == BASELINE_ATTEMPT
        assert self.delegation is not None
        assert self.approval_binding is not None
        assert self.approval_record is not None
        return {
            "experiment": self.experiment.to_dict(),
            "delegation": self.delegation.to_dict(),
            "approval_binding": self.approval_binding.to_dict(),
            "approval_record": dict(self.approval_record),
        }

    def compare_and_swap_engine_attempt_record(self, **values):
        self._cas(values)
        self.experiment = self.experiment.update_attempt_record(
            EngineAttemptRecord.from_mapping(values["record"]),
            timestamp=values["timestamp"],
        )
        return self.experiment.to_dict()

    def compare_and_swap_engine_attempt_settlement(self, **values):
        self._cas(values)
        self.experiment = self.experiment.settle_attempt(
            EngineAttemptRecord.from_mapping(values["record"]),
            engine_evidence=tuple(
                EngineEvidenceItem.from_mapping(item) for item in values["engine_evidence"]
            ),
            artifact_manifest_ref=values["artifact_manifest_ref"],
            cleanup_state=CleanupState(values["cleanup_state"]),
            cleanup_evidence_ref=values["cleanup_evidence_ref"],
            settled_at=values["settled_at"],
        )
        return self.experiment.to_dict()

    def reconcile_engine_attempt_cleanup(self, **values):
        self._cas(values)
        self.experiment = self.experiment.reconcile_attempt_cleanup(
            values["attempt_id"],
            cleanup_state=CleanupState(values["cleanup_state"]),
            cleanup_evidence_ref=values["cleanup_evidence_ref"],
            timestamp=values["timestamp"],
        )
        return self.experiment.to_dict()

    def settle_undispatched_engine_attempt_cancellation(self, **values):
        self.cancel_settle_calls += 1
        self._cas(values)
        assert values["job_id"] in self.cancelled_job_ids
        _index, current = self.experiment._attempt(values["attempt_id"])
        assert current.job_id == values["job_id"]
        assert current.record.state is AttemptState.QUEUED
        assert current.record.upstream_session_id is None
        self.experiment = self.experiment.settle_attempt(
            EngineAttemptRecord.from_mapping(values["record"]),
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=values["cleanup_evidence_ref"],
            settled_at=values["settled_at"],
        )
        return self.experiment.to_dict()

    def _cas(self, values) -> None:
        assert values["expected_revision"] == self.experiment.revision
        assert values["expected_experiment_digest"] == self.experiment.digest


class _Runtime:
    def __init__(self, *, fail: bool = False, cancel: bool = False) -> None:
        self.execute_calls = 0
        self.reconcile_calls = 0
        self.fail = fail
        self.cancel = cancel

    def execute(self, context, binding, delegation, transition):
        del context
        self.execute_calls += 1
        assert delegation.validate_attempt_binding(binding) == binding
        preflight = EngineAttemptRecord.create(binding).transition(AttemptState.PREFLIGHT)
        running = preflight.transition(
            AttemptState.RUNNING,
            upstream_session_id="strix-session-1",
            timestamp="2026-11-04T12:03:00Z",
        )
        transition(running, "2026-11-04T12:03:00Z")
        if self.cancel:
            raise JobCancelled("cancelled")
        if self.fail:
            raise RuntimeError("synthetic runtime failure")
        completed = running.transition(
            AttemptState.COMPLETED,
            timestamp="2026-11-04T12:04:00Z",
            exit_code=0,
            completeness=AttemptCompleteness.COMPLETE,
            exit_reason="completed",
        )
        return EngineRuntimeSettlement(
            record=completed,
            engine_evidence=(),
            artifact_manifest_ref=_digest("a"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("b"),
            settled_at="2026-11-04T12:04:00Z",
        )

    def reconcile(self, binding, delegation, saved_record):
        self.reconcile_calls += 1
        assert delegation.validate_attempt_binding(binding) == binding
        return EngineRuntimeSettlement(
            record=saved_record,
            engine_evidence=(),
            artifact_manifest_ref=_digest("a"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("c"),
            settled_at="2026-11-04T12:05:00Z",
        )


class _Clock:
    def __init__(self, values: tuple[str, ...] | None = None) -> None:
        self.values = iter(
            values
            or (
                "2026-11-04T12:01:30Z",
                "2026-11-04T12:02:00Z",
                "2026-11-04T12:02:30Z",
                "2026-11-04T12:04:30Z",
            )
        )

    def __call__(self) -> str:
        return next(self.values)


def _authority():
    binding = _binding(
        AttemptRole.BASELINE,
        attempt_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        target_snapshot_ref=INITIAL_SNAPSHOT,
        created_at="2026-11-04T12:01:00Z",
        parent_attempt_id=None,
    )
    delegation = EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "1" * 32,
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
        created_at="2026-11-04T12:00:30Z",
        expires_at="2026-11-04T12:06:00Z",
    )
    return binding, delegation, delegation.approval_binding(binding)


def _jobs(runtime=None, *, controller=None, clock=None):
    selected_controller = _Controller() if controller is None else controller
    repository = _Repository(_new_experiment())
    selected_runtime = _Runtime() if runtime is None else runtime
    jobs = EngineExperimentJobs(
        controller=selected_controller,
        repository=repository,
        runtime=selected_runtime,
        clock=_Clock() if clock is None else clock,
    )
    return jobs, selected_controller, repository, selected_runtime


def _submit(jobs, binding, delegation, approval):
    experiment = _new_experiment()
    request = jobs._request(
        experiment=experiment,
        binding=binding,
        delegation=delegation,
        approval=approval,
        approval_id="approval-" + "1" * 32,
    )
    return jobs.submit(
        experiment_id=EXPERIMENT_ID,
        binding=binding,
        delegation=delegation,
        approval_binding=approval,
        approval_id="approval-" + "1" * 32,
        approval_nonce="nonce-1",
        approved_by="operator",
        submission_id=SUBMISSION_ID,
        intent_digest=content_hash(request),
    )


def test_idempotent_submission_executes_once_and_persists_cas_state() -> None:
    jobs, controller, repository, runtime = _jobs()
    binding, delegation, approval = _authority()

    first = _submit(jobs, binding, delegation, approval)
    second = _submit(jobs, binding, delegation, approval)

    assert second == first
    assert controller.callback_calls == 1
    assert repository.reserve_calls == 1
    assert runtime.execute_calls == 1
    entry = repository.experiment.attempts[0]
    assert entry.record.state is AttemptState.COMPLETED
    assert entry.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert entry.delegation_digest == delegation.delegation_digest
    assert entry.execution_approval_digest == content_hash(approval.to_dict())
    assert entry.execution_approval_id == "approval-" + "1" * 32


def test_runtime_unavailable_fails_before_approval_or_job_reservation() -> None:
    controller = _Controller()
    repository = _Repository(_new_experiment())
    jobs = EngineExperimentJobs(
        controller=controller,
        repository=repository,
        runtime=None,
        clock=_Clock(),
    )
    binding, delegation, approval = _authority()

    with pytest.raises(EngineExperimentJobError, match="runtime is unavailable"):
        _submit(jobs, binding, delegation, approval)

    assert repository.reserve_calls == 0
    assert repository.experiment.attempts == ()


def test_runtime_unavailable_can_reopen_existing_submission_without_resubmit() -> None:
    controller = _Controller()
    repository = _Repository(_new_experiment())
    repository.existing_submission = {
        "job_id": JOB_ID,
        "state": "completed",
    }
    jobs = EngineExperimentJobs(
        controller=controller,
        repository=repository,
        runtime=None,
        clock=_Clock(),
    )
    binding, delegation, approval = _authority()

    reopened = _submit(jobs, binding, delegation, approval)

    assert reopened == repository.existing_submission
    assert repository.reserve_calls == 0
    assert controller.callback_calls == 0


def test_runtime_failure_settles_unknown_cleanup_without_claiming_prevention() -> None:
    runtime = _Runtime(fail=True)
    jobs, _controller, repository, _runtime = _jobs(runtime)
    binding, delegation, approval = _authority()

    with pytest.raises(RuntimeError, match="synthetic runtime failure"):
        _submit(jobs, binding, delegation, approval)

    entry = repository.experiment.attempts[0]
    assert entry.record.state is AttemptState.FAILED
    assert entry.record.completeness is AttemptCompleteness.UNKNOWN
    assert entry.cleanup_state is CleanupState.UNKNOWN
    assert entry.record.exit_reason == "engine_runtime_failed"


def test_cancellation_remains_distinct_and_requires_cleanup_reconciliation() -> None:
    runtime = _Runtime(cancel=True)
    jobs, _controller, repository, _runtime = _jobs(runtime)
    binding, delegation, approval = _authority()

    with pytest.raises(JobCancelled):
        _submit(jobs, binding, delegation, approval)

    entry = repository.experiment.attempts[0]
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.record.exit_reason == "controller_cancelled"
    assert entry.cleanup_state is CleanupState.UNKNOWN


def test_restart_reconciliation_never_reexecutes_or_rewrites_outcome() -> None:
    jobs, _controller, repository, runtime = _jobs()
    binding, delegation, approval = _authority()
    _submit(jobs, binding, delegation, approval)
    execute_calls = runtime.execute_calls

    reopened = jobs.reconcile_interrupted_attempt(
        experiment_id=EXPERIMENT_ID,
        attempt_id=BASELINE_ATTEMPT,
    )

    assert reopened["attempts"][0]["record"]["state"] == "completed"
    assert runtime.execute_calls == execute_calls
    assert runtime.reconcile_calls == 1
    assert repository.reserve_calls == 1


def test_submission_rejects_mismatched_intent_before_reservation() -> None:
    jobs, _controller, repository, _runtime = _jobs()
    binding, delegation, approval = _authority()

    with pytest.raises(EngineExperimentJobError, match="intent digest changed"):
        jobs.submit(
            experiment_id=EXPERIMENT_ID,
            binding=binding,
            delegation=delegation,
            approval_binding=approval,
            approval_id="approval-" + "1" * 32,
            approval_nonce="nonce-1",
            approved_by="operator",
            submission_id=SUBMISSION_ID,
            intent_digest=_digest("f"),
        )

    assert repository.reserve_calls == 0


def test_initial_checkpoint_cancellation_settles_without_engine_custody() -> None:
    controller = _Controller(context=_Context(cancel_at=1))
    runtime = _Runtime()
    jobs, _controller, repository, _runtime = _jobs(runtime, controller=controller)
    binding, delegation, approval = _authority()

    with pytest.raises(JobCancelled, match="controller checkpoint"):
        _submit(jobs, binding, delegation, approval)

    entry = repository.experiment.attempts[0]
    assert runtime.execute_calls == 0
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.record.upstream_session_id is None
    assert entry.record.exit_reason == "controller_cancelled_before_dispatch"
    assert entry.cleanup_state is CleanupState.VERIFIED_ABSENT


def test_checkpoint_cancellation_after_session_persists_session_before_settlement() -> None:
    controller = _Controller(context=_Context(cancel_at=2))
    runtime = _Runtime()
    jobs, _controller, repository, _runtime = _jobs(runtime, controller=controller)
    binding, delegation, approval = _authority()

    with pytest.raises(JobCancelled, match="controller checkpoint"):
        _submit(jobs, binding, delegation, approval)

    entry = repository.experiment.attempts[0]
    assert runtime.execute_calls == 1
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.record.upstream_session_id == "strix-session-1"
    assert entry.cleanup_state is CleanupState.UNKNOWN


def test_expired_authority_is_settled_before_runtime_dispatch() -> None:
    clock = _Clock(
        (
            "2026-11-04T12:01:30Z",
            "2026-11-04T12:02:00Z",
            "2026-11-04T12:06:00Z",
        )
    )
    runtime = _Runtime()
    jobs, _controller, repository, _runtime = _jobs(runtime, clock=clock)
    binding, delegation, approval = _authority()

    with pytest.raises(EngineExperimentJobError, match="expired before dispatch"):
        _submit(jobs, binding, delegation, approval)

    entry = repository.experiment.attempts[0]
    assert runtime.execute_calls == 0
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.record.exit_reason == "authority_expired_before_dispatch"
    assert entry.cleanup_state is CleanupState.VERIFIED_ABSENT


def test_saved_attempt_binds_exact_one_time_approval_identity() -> None:
    jobs, _controller, repository, runtime = _jobs()
    binding, delegation, approval = _authority()
    _submit(jobs, binding, delegation, approval)
    assert repository.approval_record is not None
    repository.approval_record = {
        **repository.approval_record,
        "approval_id": "approval-" + "2" * 32,
    }

    with pytest.raises(EngineExperimentJobError, match="approval identity changed"):
        jobs.reconcile_interrupted_attempt(
            experiment_id=EXPERIMENT_ID,
            attempt_id=BASELINE_ATTEMPT,
        )

    assert runtime.reconcile_calls == 0


@pytest.mark.parametrize(
    "mutation",
    [
        {"nonce": None},
        {"approved_at": None},
        {"claimed_at": "2026-11-04T12:00:25Z"},
    ],
)
def test_saved_attempt_requires_canonical_claimed_approval_proof(mutation) -> None:
    jobs, _controller, repository, runtime = _jobs()
    binding, delegation, approval = _authority()
    _submit(jobs, binding, delegation, approval)
    assert repository.approval_record is not None
    repository.approval_record = {**repository.approval_record, **mutation}

    with pytest.raises(EngineExperimentJobError, match="approval"):
        jobs.reconcile_interrupted_attempt(
            experiment_id=EXPERIMENT_ID,
            attempt_id=BASELINE_ATTEMPT,
        )

    assert runtime.reconcile_calls == 0


def test_product_store_submission_metadata_is_exactly_admitted() -> None:
    jobs, _controller, repository, _runtime = _jobs()
    binding, delegation, approval = _authority()
    _submit(jobs, binding, delegation, approval)
    request = jobs._request(
        experiment=_new_experiment(),
        binding=binding,
        delegation=delegation,
        approval=approval,
        approval_id="approval-" + "1" * 32,
    )
    stored = {
        **request,
        "_submission": {
            "schema_version": "bluefire.job-submission.v1",
            "submission_id": SUBMISSION_ID,
            "intent_digest": content_hash(request),
        },
    }

    loaded = jobs._load_execution(stored)

    assert loaded[0].experiment_id == EXPERIMENT_ID
    assert loaded[4] == "approval-" + "1" * 32


def test_submission_identity_must_match_product_store_canonical_uuid() -> None:
    jobs, _controller, repository, _runtime = _jobs()
    binding, delegation, approval = _authority()
    request = jobs._request(
        experiment=_new_experiment(),
        binding=binding,
        delegation=delegation,
        approval=approval,
        approval_id="approval-" + "1" * 32,
    )

    with pytest.raises(EngineExperimentJobError, match="canonical UUID"):
        jobs.submit(
            experiment_id=EXPERIMENT_ID,
            binding=binding,
            delegation=delegation,
            approval_binding=approval,
            approval_id="approval-" + "1" * 32,
            approval_nonce="nonce-1",
            approved_by="operator",
            submission_id="submission-engine-1",
            intent_digest=content_hash(request),
        )

    assert repository.reserve_calls == 0


def test_precallback_cancel_settles_queued_attempt_once_with_no_custody() -> None:
    controller = _Controller(run_callback=False)
    runtime = _Runtime()
    jobs, _controller, repository, _runtime = _jobs(runtime, controller=controller)
    binding, delegation, approval = _authority()
    submitted = _submit(jobs, binding, delegation, approval)
    job_id = str(submitted["job_id"])
    repository.cancelled_job_ids.add(job_id)

    first = jobs.settle_undispatched_cancellation(
        experiment_id=EXPERIMENT_ID,
        attempt_id=BASELINE_ATTEMPT,
        job_id=job_id,
    )
    second = jobs.settle_undispatched_cancellation(
        experiment_id=EXPERIMENT_ID,
        attempt_id=BASELINE_ATTEMPT,
        job_id=job_id,
    )

    assert second == first
    entry = repository.experiment.attempts[0]
    assert runtime.execute_calls == 0
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.record.upstream_session_id is None
    assert entry.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert repository.cancel_settle_calls == 1


def test_precallback_cancel_loses_race_after_callback_state_advance() -> None:
    controller = _Controller(run_callback=False)
    jobs, _controller, repository, _runtime = _jobs(controller=controller)
    binding, delegation, approval = _authority()
    submitted = _submit(jobs, binding, delegation, approval)
    job_id = str(submitted["job_id"])
    repository.cancelled_job_ids.add(job_id)
    queued = repository.experiment.attempts[0].record
    repository.experiment = repository.experiment.update_attempt_record(
        queued.transition(AttemptState.PREFLIGHT),
        timestamp="2026-11-04T12:02:00Z",
    )

    with pytest.raises(EngineExperimentJobError, match="dispatch already began"):
        jobs.settle_undispatched_cancellation(
            experiment_id=EXPERIMENT_ID,
            attempt_id=BASELINE_ATTEMPT,
            job_id=job_id,
        )

    assert repository.experiment.attempts[0].record.state is AttemptState.PREFLIGHT
    assert repository.cancel_settle_calls == 0
