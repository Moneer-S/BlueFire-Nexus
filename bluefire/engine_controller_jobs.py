"""Durable controller-owned jobs for external-engine defense experiments.

This module owns no target, runner, network, or model implementation.  It binds
trusted controller callbacks to the existing product-job lifecycle and the
canonical :mod:`bluefire.engine_experiment` state machine.  Engine workers can
never invoke these callbacks or mint independent observations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol

from .domain_errors import JobCancelled
from .engine_controller_job_contract import (
    DefenseOperation,
    EngineControllerJobError,
    _digest,
    _submission,
    _timestamp,
    exact_check_request,
    exact_defense_request,
    require_defense_operation,
)
from .engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    EngineDefenseChange,
    EngineExperiment,
    EngineExperimentError,
    _controller_observation_record,
)
from .evidence import EvidenceProvenance, EvidenceRecord
from .job_runtime import JobContext, JobResult
from .util import content_hash, parse_iso8601_datetime

_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")


_APPLICATION_OPERATIONS = frozenset(
    {DefenseOperation.APPLY, DefenseOperation.RECONCILE_APPLICATION}
)
_ROLLBACK_OPERATIONS = frozenset({DefenseOperation.ROLLBACK, DefenseOperation.RECONCILE_ROLLBACK})


@dataclass(frozen=True, slots=True)
class DefenseOperationSettlement:
    """Trusted readback after a controller-owned defense operation."""

    operation: DefenseOperation
    change_id: str
    target_snapshot_ref: str
    configuration_digest: str | None
    receipt_digest: str
    settled_at: str

    def validate(
        self, experiment: EngineExperiment, *, expected_operation: DefenseOperation
    ) -> None:
        if self.operation is not expected_operation:
            raise EngineControllerJobError("defense settlement operation changed")
        change = experiment.defense_change
        if change is None or change.change_id != self.change_id:
            raise EngineControllerJobError("defense settlement belongs to another change")
        _digest(self.target_snapshot_ref, "defense settlement target")
        _digest(self.receipt_digest, "defense settlement receipt")
        when = parse_iso8601_datetime(_timestamp(self.settled_at, "defense settlement time"))
        if when < parse_iso8601_datetime(experiment.updated_at):
            raise EngineControllerJobError("defense settlement predates its durable operation")
        if self.operation in _APPLICATION_OPERATIONS:
            if (
                _digest(self.configuration_digest, "applied configuration")
                != change.approved_configuration_digest
                or self.target_snapshot_ref != change.after_target_snapshot_ref
            ):
                raise EngineControllerJobError("defense application readback changed")
        elif self.operation in _ROLLBACK_OPERATIONS:
            if (
                self.configuration_digest is not None
                or self.target_snapshot_ref != experiment.initial_target_snapshot_ref
            ):
                raise EngineControllerJobError("defense rollback readback changed")
        else:  # pragma: no cover - enum exhaustiveness
            raise EngineControllerJobError("defense operation is unsupported")


@dataclass(frozen=True, slots=True)
class ControllerCheckSettlement:
    """Trusted check outcome before controller attestation and atomic persistence."""

    state: ControllerCheckState
    result_digest: str
    observations: tuple[EvidenceRecord, ...]
    cleanup_state: CleanupState
    cleanup_evidence_ref: str
    settled_at: str

    def validate(self, check: ControllerCheckRecord) -> None:
        if self.state not in {
            ControllerCheckState.COMPLETED,
            ControllerCheckState.FAILED,
            ControllerCheckState.UNKNOWN,
        }:
            raise EngineControllerJobError("controller check did not settle")
        _digest(self.result_digest, "controller check result")
        _digest(self.cleanup_evidence_ref, "controller check cleanup receipt")
        when = parse_iso8601_datetime(_timestamp(self.settled_at, "check settlement time"))
        if when < parse_iso8601_datetime(check.created_at):
            raise EngineControllerJobError("controller check settlement predates reservation")
        if self.cleanup_state is CleanupState.PENDING:
            raise EngineControllerJobError("controller check cleanup is still pending")
        if self.state in {ControllerCheckState.COMPLETED, ControllerCheckState.FAILED} and not (
            self.observations
        ):
            raise EngineControllerJobError("controller check outcome lacks independent evidence")
        identities: set[str] = set()
        for observation in self.observations:
            checked = EvidenceRecord.from_mapping(observation.to_dict())
            if (
                checked.provenance is not EvidenceProvenance.OBSERVED
                or checked.run_id != check.run_id
                or checked.evidence_id in identities
            ):
                raise EngineControllerJobError("controller check observation is invalid")
            identities.add(checked.evidence_id)


@dataclass(frozen=True, slots=True)
class ControllerCheckRecovery:
    """Restart result: either settle a reserved check or reconcile terminal cleanup."""

    settlement: ControllerCheckSettlement | None
    cleanup_state: CleanupState
    cleanup_evidence_ref: str
    reconciled_at: str

    def validate(self, check: ControllerCheckRecord) -> None:
        _digest(self.cleanup_evidence_ref, "controller recovery cleanup receipt")
        when = parse_iso8601_datetime(_timestamp(self.reconciled_at, "recovery time"))
        if when < parse_iso8601_datetime(check.created_at):
            raise EngineControllerJobError("controller recovery predates reservation")
        if self.cleanup_state is CleanupState.PENDING:
            raise EngineControllerJobError("controller recovery cleanup is still pending")
        if check.state is ControllerCheckState.RESERVED:
            if self.settlement is None:
                raise EngineControllerJobError("reserved controller check lacks recovered outcome")
            self.settlement.validate(check)
            if (
                self.settlement.cleanup_state is not self.cleanup_state
                or self.settlement.cleanup_evidence_ref != self.cleanup_evidence_ref
                or self.settlement.settled_at != self.reconciled_at
            ):
                raise EngineControllerJobError("controller recovery settlement changed")
        elif self.settlement is not None:
            raise EngineControllerJobError("terminal controller check outcome cannot be rewritten")


class EngineControllerJobController(Protocol):
    def submit(
        self,
        kind: str,
        request: Mapping[str, Any],
        *,
        requires_approval: bool = False,
        callback: Callable[[JobContext, Mapping[str, Any]], JobResult | str | None] | None = None,
        submission_id: str | None = None,
        intent_digest: str | None = None,
        submission_factory: Callable[[], tuple[Mapping[str, Any], bool]] | None = None,
    ) -> Mapping[str, Any]: ...


class EngineControllerRepository(Protocol):
    """Atomic ProductStore operations required by trusted controller jobs."""

    def get_engine_experiment_document(self, experiment_id: str) -> Mapping[str, Any]: ...

    def get_job_submission(
        self, kind: str, *, submission_id: str, intent_digest: str
    ) -> Mapping[str, Any] | None: ...

    def reserve_engine_defense_operation_submission(
        self,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
        originating_job_id: str | None,
        originating_operation_receipt_digest: str | None,
    ) -> tuple[Mapping[str, Any], bool]: ...

    # For reconciliation, the transaction must additionally prove the cited
    # originating job is failed, cancelled, or interrupted (never running or
    # merely queued) and that its request produces the cited operation receipt.

    def begin_engine_defense_operation(
        self,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        operation_receipt_digest: str,
        job_id: str,
        request_digest: str,
        started_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]: ...

    def settle_engine_defense_operation(
        self,
        *,
        experiment_id: str,
        change_id: str,
        operation: str,
        target_snapshot_ref: str,
        configuration_digest: str | None,
        receipt_digest: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]: ...

    def reserve_engine_controller_check_submission(
        self,
        *,
        experiment_id: str,
        check_id: str,
        run_id: str,
        role: str,
        mechanism_ref: str,
        target_snapshot_ref: str,
        input_digest: str,
        reserved_at: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> tuple[Mapping[str, Any], bool]: ...

    def compare_and_swap_engine_controller_check_settlement(
        self,
        *,
        experiment_id: str,
        check: Mapping[str, Any],
        independent_observations: Iterable[Mapping[str, Any]],
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Atomically persist preverified evidence identities, attest, and settle.

        The trusted controller executor/service must verify the finalized
        filesystem RunStore bundle before this call.  ProductStore then binds
        the canonical controller attestations and exact terminal evidence IDs
        in its own SQLite transaction; it does not claim a cross-filesystem
        transaction with RunStore.
        """

        ...

    def reconcile_engine_controller_check_cleanup(
        self,
        *,
        experiment_id: str,
        check_id: str,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]: ...

    def settle_undispatched_engine_controller_check_cancellation(
        self,
        *,
        experiment_id: str,
        check_id: str,
        job_id: str,
        check: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]: ...

    def load_engine_controller_check_recovery(
        self, experiment_id: str, check_id: str
    ) -> Mapping[str, Any]:
        """Atomically return the experiment and bound terminal job snapshot."""

        ...


class DefenseOperationExecutor(Protocol):
    def execute(
        self,
        context: JobContext,
        experiment: EngineExperiment,
        operation: DefenseOperation,
    ) -> DefenseOperationSettlement: ...


class ControllerCheckExecutor(Protocol):
    def execute(
        self, context: JobContext, check: ControllerCheckRecord
    ) -> ControllerCheckSettlement: ...

    def reconcile(self, check: ControllerCheckRecord) -> ControllerCheckRecovery: ...


class EngineControllerJobs:
    """Submit controller-owned mutations and checks without engine provenance."""

    DEFENSE_JOB_KIND = "engine-controller-operation"
    CHECK_JOB_KIND = "engine-controller-check"

    def __init__(
        self,
        *,
        controller: EngineControllerJobController,
        repository: EngineControllerRepository,
        defense_executor: DefenseOperationExecutor | None,
        check_executor: ControllerCheckExecutor | None,
        clock: Callable[[], str],
    ) -> None:
        self._controller = controller
        self._repository = repository
        self._defense_executor = defense_executor
        self._check_executor = check_executor
        self._clock = clock

    def submit_prepared(
        self,
        *,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        submission_factory: Callable[[], tuple[Mapping[str, Any], bool]],
    ) -> Mapping[str, Any]:
        """Enqueue an exact retained controller request through its job gate."""

        submission_id = _submission(submission_id)
        if not isinstance(request, Mapping):
            raise EngineControllerJobError("prepared controller request fields changed")
        if request.get("schema_version") == "bluefire.engine-defense-operation-job.v1":
            parsed, operation = self._exact_defense_request(request)
            if operation not in {DefenseOperation.APPLY, DefenseOperation.ROLLBACK}:
                raise EngineControllerJobError("prepared defense reconciliation is unavailable")
            if (
                parsed["originating_job_id"] is not None
                or parsed["originating_operation_receipt_digest"] is not None
            ):
                raise EngineControllerJobError("prepared defense operation gained an origin")
            if self._defense_executor is None:
                raise EngineControllerJobError("defense controller is unavailable")
            kind = self.DEFENSE_JOB_KIND
            callback = self._execute_defense
        elif request.get("schema_version") == "bluefire.engine-controller-check-job.v1":
            parsed = self._exact_check_request(request)
            if self._check_executor is None:
                raise EngineControllerJobError("controller check runtime is unavailable")
            kind = self.CHECK_JOB_KIND
            callback = self._execute_check
        else:
            raise EngineControllerJobError("prepared controller request version changed")
        if parsed != dict(request):
            raise EngineControllerJobError("prepared controller request fields changed")
        if intent_digest != content_hash(parsed):
            raise EngineControllerJobError("prepared controller intent digest changed")
        if not callable(submission_factory):
            raise EngineControllerJobError("prepared controller submission factory is unavailable")
        return self._controller.submit(
            kind,
            parsed,
            callback=callback,
            submission_id=submission_id,
            intent_digest=intent_digest,
            submission_factory=submission_factory,
        )

    def prepare_defense_operation(
        self,
        *,
        experiment_id: str,
        change_id: str,
        operation: DefenseOperation,
        originating_job_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(operation, DefenseOperation):
            raise EngineControllerJobError("defense operation is invalid")
        experiment = self._experiment(experiment_id)
        change = self._change(experiment, change_id)
        self._require_defense_operation(change, operation)
        origin_receipt: str | None = None
        if operation is DefenseOperation.RECONCILE_APPLICATION:
            origin_receipt = change.application_receipt_digest
        elif operation is DefenseOperation.RECONCILE_ROLLBACK:
            origin_receipt = change.rollback_operation_digest
        if operation in {
            DefenseOperation.RECONCILE_APPLICATION,
            DefenseOperation.RECONCILE_ROLLBACK,
        }:
            if (
                not isinstance(originating_job_id, str)
                or _JOB_ID.fullmatch(originating_job_id) is None
                or origin_receipt is None
            ):
                raise EngineControllerJobError(
                    "defense reconciliation requires its originating job"
                )
        elif originating_job_id is not None:
            raise EngineControllerJobError("new defense operation cannot cite an origin job")
        return {
            "schema_version": "bluefire.engine-defense-operation-job.v1",
            "experiment_id": experiment.experiment_id,
            "experiment_revision": experiment.revision,
            "experiment_digest": experiment.digest,
            "change_id": change.change_id,
            "change_digest": content_hash(change.to_dict()),
            "operation": operation.value,
            "originating_job_id": originating_job_id,
            "originating_operation_receipt_digest": origin_receipt,
        }

    def submit_defense_operation(
        self,
        *,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        submission_id = _submission(submission_id)
        parsed, operation = self._exact_defense_request(request)
        if intent_digest != content_hash(parsed):
            raise EngineControllerJobError("defense operation intent digest changed")
        existing = self._repository.get_job_submission(
            self.DEFENSE_JOB_KIND,
            submission_id=submission_id,
            intent_digest=intent_digest,
        )
        if existing is not None:
            return existing
        parsed, experiment, operation = self._parse_defense_request(parsed)
        if self._defense_executor is None:
            raise EngineControllerJobError("defense controller is unavailable")

        def reserve() -> tuple[Mapping[str, Any], bool]:
            return self._repository.reserve_engine_defense_operation_submission(
                experiment_id=experiment.experiment_id,
                change_id=parsed["change_id"],
                operation=operation.value,
                job_kind=self.DEFENSE_JOB_KIND,
                job_request=parsed,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                originating_job_id=parsed["originating_job_id"],
                originating_operation_receipt_digest=parsed["originating_operation_receipt_digest"],
            )

        return self._controller.submit(
            self.DEFENSE_JOB_KIND,
            parsed,
            callback=self._execute_defense,
            submission_id=submission_id,
            intent_digest=intent_digest,
            submission_factory=reserve,
        )

    def prepare_controller_check(
        self,
        *,
        experiment_id: str,
        check_id: str,
        run_id: str,
        role: ControllerCheckRole,
        mechanism_ref: str,
        target_snapshot_ref: str,
        input_digest: str,
        reserved_at: str,
    ) -> dict[str, Any]:
        if not isinstance(role, ControllerCheckRole):
            raise EngineControllerJobError("controller check role is invalid")
        experiment = self._experiment(experiment_id)
        checked_at = _timestamp(reserved_at, "controller check reservation time")
        if parse_iso8601_datetime(checked_at) > parse_iso8601_datetime(self._now()):
            raise EngineControllerJobError("controller check reservation is in the future")
        preview = ControllerCheckRecord.reserve(
            check_id=check_id,
            experiment_id=experiment.experiment_id,
            job_id="job-" + "0" * 32,
            run_id=run_id,
            role=role,
            mechanism_ref=mechanism_ref,
            target_snapshot_ref=target_snapshot_ref,
            input_digest=input_digest,
            created_at=checked_at,
        )
        experiment.reserve_controller_check(preview, timestamp=checked_at)
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

    def submit_controller_check(
        self,
        *,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        submission_id = _submission(submission_id)
        parsed = self._exact_check_request(request)
        if intent_digest != content_hash(parsed):
            raise EngineControllerJobError("controller check intent digest changed")
        existing = self._repository.get_job_submission(
            self.CHECK_JOB_KIND,
            submission_id=submission_id,
            intent_digest=intent_digest,
        )
        if existing is not None:
            return existing
        parsed, experiment, role = self._parse_check_request(parsed)
        if self._check_executor is None:
            raise EngineControllerJobError("controller check runtime is unavailable")

        def reserve() -> tuple[Mapping[str, Any], bool]:
            return self._repository.reserve_engine_controller_check_submission(
                experiment_id=experiment.experiment_id,
                check_id=parsed["check_id"],
                run_id=parsed["run_id"],
                role=role.value,
                mechanism_ref=parsed["mechanism_ref"],
                target_snapshot_ref=parsed["target_snapshot_ref"],
                input_digest=parsed["input_digest"],
                reserved_at=parsed["reserved_at"],
                job_kind=self.CHECK_JOB_KIND,
                job_request=parsed,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
            )

        return self._controller.submit(
            self.CHECK_JOB_KIND,
            parsed,
            callback=self._execute_check,
            submission_id=submission_id,
            intent_digest=intent_digest,
            submission_factory=reserve,
        )

    def reconcile_interrupted_check(
        self, *, experiment_id: str, check_id: str
    ) -> Mapping[str, Any]:
        executor = self._check_executor
        if executor is None:
            raise EngineControllerJobError("controller check runtime is unavailable")
        snapshot = self._repository.load_engine_controller_check_recovery(experiment_id, check_id)
        if not isinstance(snapshot, Mapping) or set(snapshot) != {"experiment", "job"}:
            raise EngineControllerJobError("controller recovery snapshot fields changed")
        try:
            experiment = EngineExperiment._from_controller_mapping(snapshot["experiment"])
        except (EngineExperimentError, TypeError, ValueError) as exc:
            raise EngineControllerJobError("controller recovery experiment is invalid") from exc
        _index, check = experiment._check(check_id)
        job = snapshot["job"]
        if (
            not isinstance(job, Mapping)
            or job.get("schema_version") != "bluefire.job.v1"
            or job.get("job_id") != check.job_id
            or job.get("kind") != self.CHECK_JOB_KIND
            or job.get("state") not in {"cancelled", "failed", "interrupted", "completed"}
        ):
            raise EngineControllerJobError(
                "controller check recovery requires its terminal bound job"
            )
        if check.state is ControllerCheckState.RESERVED and job.get("state") == "completed":
            raise EngineControllerJobError("completed job lacks its controller check outcome")
        request = job.get("request")
        if not isinstance(request, Mapping):
            raise EngineControllerJobError("controller recovery job request is invalid")
        parsed = self._exact_check_request(request)
        expected = {
            "experiment_id": experiment.experiment_id,
            "check_id": check.check_id,
            "run_id": check.run_id,
            "role": check.role.value,
            "performer": check.performer.value,
            "mechanism_ref": check.mechanism_ref,
            "target_snapshot_ref": check.target_snapshot_ref,
            "input_digest": check.input_digest,
            "reserved_at": check.created_at,
        }
        if any(parsed[field] != value for field, value in expected.items()):
            raise EngineControllerJobError("controller recovery job intent changed")
        recovery = executor.reconcile(check)
        recovery.validate(check)
        if check.state is ControllerCheckState.RESERVED:
            assert recovery.settlement is not None
            return self._persist_check_settlement(experiment, check, recovery.settlement).to_dict()
        value = self._repository.reconcile_engine_controller_check_cleanup(
            experiment_id=experiment.experiment_id,
            check_id=check.check_id,
            cleanup_state=recovery.cleanup_state.value,
            cleanup_evidence_ref=recovery.cleanup_evidence_ref,
            timestamp=recovery.reconciled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
        return EngineExperiment._from_controller_mapping(value).to_dict()

    def settle_undispatched_check_cancellation(
        self, *, experiment_id: str, check_id: str, job_id: str
    ) -> Mapping[str, Any]:
        experiment = self._experiment(experiment_id)
        _index, check = experiment._check(check_id)
        if check.job_id != job_id:
            raise EngineControllerJobError("cancelled job belongs to another controller check")
        if check.state is not ControllerCheckState.RESERVED:
            if (
                check.state is ControllerCheckState.UNKNOWN
                and check.cleanup_state is CleanupState.VERIFIED_ABSENT
            ):
                return experiment.to_dict()
            raise EngineControllerJobError("controller check dispatch already settled")
        settlement = self._unknown_check_settlement(check, dispatched=False)
        terminal = check.settle(
            state=settlement.state,
            result_digest=settlement.result_digest,
            independent_evidence_refs=(),
            cleanup_state=settlement.cleanup_state,
            cleanup_evidence_ref=settlement.cleanup_evidence_ref,
            settled_at=settlement.settled_at,
        )
        value = self._repository.settle_undispatched_engine_controller_check_cancellation(
            experiment_id=experiment.experiment_id,
            check_id=check.check_id,
            job_id=job_id,
            check=terminal.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
        return EngineExperiment._from_controller_mapping(value).to_dict()

    def _execute_defense(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        executor = self._defense_executor
        if executor is None:
            raise EngineControllerJobError("defense controller is unavailable")
        parsed, experiment, operation = self._parse_defense_request(request)
        context.checkpoint(
            {
                "phase": "defense_ready",
                "experiment_id": experiment.experiment_id,
                "change_id": parsed["change_id"],
                "operation": operation.value,
            }
        )
        if operation in {DefenseOperation.APPLY, DefenseOperation.ROLLBACK}:
            started_at = self._now()
            value = self._repository.begin_engine_defense_operation(
                experiment_id=experiment.experiment_id,
                change_id=parsed["change_id"],
                operation=operation.value,
                operation_receipt_digest=content_hash(
                    {
                        "schema_version": "bluefire.engine-defense-operation-receipt.v1",
                        "job_id": context.job_id,
                        "request_digest": content_hash(parsed),
                        "operation": operation.value,
                    }
                ),
                job_id=context.job_id,
                request_digest=content_hash(parsed),
                started_at=started_at,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
            )
            experiment = EngineExperiment._from_controller_mapping(value)
            context.checkpoint(
                {
                    "phase": "defense_state_unknown",
                    "experiment_id": experiment.experiment_id,
                    "change_id": parsed["change_id"],
                    "operation": operation.value,
                }
            )
        settlement = executor.execute(context, experiment, operation)
        settlement.validate(experiment, expected_operation=operation)
        value = self._repository.settle_engine_defense_operation(
            experiment_id=experiment.experiment_id,
            change_id=settlement.change_id,
            operation=operation.value,
            target_snapshot_ref=settlement.target_snapshot_ref,
            configuration_digest=settlement.configuration_digest,
            receipt_digest=settlement.receipt_digest,
            settled_at=settlement.settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
        settled = EngineExperiment._from_controller_mapping(value)
        return JobResult(
            result_ref=f"engine-experiment:{settled.experiment_id}",
            progress={
                "phase": "defense_settled",
                "experiment_id": settled.experiment_id,
                "change_id": settlement.change_id,
                "operation": operation.value,
                "experiment_revision": settled.revision,
                "experiment_digest": settled.digest,
            },
            completion_confirmed=True,
        )

    def _execute_check(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        executor = self._check_executor
        if executor is None:
            raise EngineControllerJobError("controller check runtime is unavailable")
        experiment, check = self._load_reserved_check(request)
        dispatched = False
        try:
            context.checkpoint(
                {
                    "phase": "controller_check_ready",
                    "experiment_id": experiment.experiment_id,
                    "check_id": check.check_id,
                    "role": check.role.value,
                }
            )
            dispatched = True
            settlement = executor.execute(context, check)
            settlement.validate(check)
        except JobCancelled:
            if not dispatched:
                self._persist_check_settlement(
                    experiment,
                    check,
                    self._unknown_check_settlement(check, dispatched=False),
                )
            raise
        except Exception:
            # Once the trusted callback was entered, a process interruption may
            # leave both an effect and finalized evidence.  Keep the check
            # reserved and cleanup pending so terminal-job recovery can inspect
            # custody and attach that outcome exactly once without replay.
            raise
        settled = self._persist_check_settlement(experiment, check, settlement)
        return JobResult(
            result_ref=f"engine-experiment:{settled.experiment_id}",
            progress={
                "phase": "controller_check_settled",
                "experiment_id": settled.experiment_id,
                "check_id": check.check_id,
                "role": check.role.value,
                "experiment_revision": settled.revision,
                "experiment_digest": settled.digest,
                "cleanup_state": settlement.cleanup_state.value,
            },
            completion_confirmed=(settlement.cleanup_state is CleanupState.VERIFIED_ABSENT),
        )

    def _persist_check_settlement(
        self,
        experiment: EngineExperiment,
        check: ControllerCheckRecord,
        settlement: ControllerCheckSettlement,
    ) -> EngineExperiment:
        settlement.validate(check)
        observations = tuple(
            _controller_observation_record(
                target_snapshot_ref=check.target_snapshot_ref,
                mechanism_ref=check.mechanism_ref,
                check_id=check.check_id,
                check_input_digest=check.input_digest,
                evidence=record,
            )
            for record in settlement.observations
        )
        terminal = check.settle(
            state=settlement.state,
            result_digest=settlement.result_digest,
            independent_evidence_refs=(item.evidence_id for item in observations),
            cleanup_state=settlement.cleanup_state,
            cleanup_evidence_ref=settlement.cleanup_evidence_ref,
            settled_at=settlement.settled_at,
        )
        value = self._repository.compare_and_swap_engine_controller_check_settlement(
            experiment_id=experiment.experiment_id,
            check=terminal.to_dict(),
            independent_observations=(item.to_dict() for item in observations),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
        return EngineExperiment._from_controller_mapping(value)

    def _load_reserved_check(
        self, request: Mapping[str, Any]
    ) -> tuple[EngineExperiment, ControllerCheckRecord]:
        parsed = self._exact_check_request(request)
        experiment = self._experiment(parsed["experiment_id"])
        _index, check = experiment._check(parsed["check_id"])
        expected = {
            "check_id": check.check_id,
            "run_id": check.run_id,
            "role": check.role.value,
            "performer": check.performer.value,
            "mechanism_ref": check.mechanism_ref,
            "target_snapshot_ref": check.target_snapshot_ref,
            "input_digest": check.input_digest,
            "reserved_at": check.created_at,
        }
        if any(parsed[field] != value for field, value in expected.items()):
            raise EngineControllerJobError("controller check intent changed after reservation")
        if check.state is not ControllerCheckState.RESERVED:
            raise EngineControllerJobError("controller check is already settled")
        return experiment, check

    def _parse_defense_request(
        self, request: Mapping[str, Any]
    ) -> tuple[dict[str, Any], EngineExperiment, DefenseOperation]:
        parsed, operation = self._exact_defense_request(request)
        experiment = self._experiment(parsed["experiment_id"])
        if (
            experiment.revision != parsed["experiment_revision"]
            or experiment.digest != parsed["experiment_digest"]
        ):
            raise EngineControllerJobError("defense experiment state changed")
        change = self._change(experiment, parsed["change_id"])
        if content_hash(change.to_dict()) != parsed["change_digest"]:
            raise EngineControllerJobError("defense change state changed")
        self._require_defense_operation(change, operation)
        expected_origin = None
        if operation is DefenseOperation.RECONCILE_APPLICATION:
            expected_origin = change.application_receipt_digest
        elif operation is DefenseOperation.RECONCILE_ROLLBACK:
            expected_origin = change.rollback_operation_digest
        if operation in {
            DefenseOperation.RECONCILE_APPLICATION,
            DefenseOperation.RECONCILE_ROLLBACK,
        }:
            if (
                parsed["originating_job_id"] is None
                or parsed["originating_operation_receipt_digest"] != expected_origin
            ):
                raise EngineControllerJobError("defense reconciliation origin changed")
        elif (
            parsed["originating_job_id"] is not None
            or parsed["originating_operation_receipt_digest"] is not None
        ):
            raise EngineControllerJobError("new defense operation has an invalid origin")
        return parsed, experiment, operation

    _exact_defense_request = staticmethod(exact_defense_request)

    def _parse_check_request(
        self, request: Mapping[str, Any]
    ) -> tuple[dict[str, Any], EngineExperiment, ControllerCheckRole]:
        parsed = self._exact_check_request(request)
        experiment = self._experiment(parsed["experiment_id"])
        if (
            experiment.revision != parsed["experiment_revision"]
            or experiment.digest != parsed["experiment_digest"]
        ):
            raise EngineControllerJobError("controller check experiment state changed")
        try:
            role = ControllerCheckRole(parsed["role"])
        except (TypeError, ValueError) as exc:
            raise EngineControllerJobError("controller check role is invalid") from exc
        preview = ControllerCheckRecord.reserve(
            check_id=parsed["check_id"],
            experiment_id=experiment.experiment_id,
            job_id="job-" + "0" * 32,
            run_id=parsed["run_id"],
            role=role,
            mechanism_ref=parsed["mechanism_ref"],
            target_snapshot_ref=parsed["target_snapshot_ref"],
            input_digest=parsed["input_digest"],
            created_at=parsed["reserved_at"],
        )
        if preview.performer.value != parsed["performer"]:
            raise EngineControllerJobError("controller check performer changed")
        experiment.reserve_controller_check(preview, timestamp=parsed["reserved_at"])
        return parsed, experiment, role

    _exact_check_request = staticmethod(exact_check_request)

    _require_defense_operation = staticmethod(require_defense_operation)

    @staticmethod
    def _change(experiment: EngineExperiment, change_id: str) -> EngineDefenseChange:
        change = experiment.defense_change
        if change is None or change.change_id != change_id:
            raise EngineControllerJobError("defense change is unavailable")
        return change

    def _experiment(self, experiment_id: str) -> EngineExperiment:
        try:
            return EngineExperiment._from_controller_mapping(
                self._repository.get_engine_experiment_document(experiment_id)
            )
        except (EngineExperimentError, KeyError, TypeError, ValueError) as exc:
            raise EngineControllerJobError("engine experiment is unavailable") from exc

    def _unknown_check_settlement(
        self, check: ControllerCheckRecord, *, dispatched: bool
    ) -> ControllerCheckSettlement:
        settled_at = self._now()
        cleanup_state = CleanupState.UNKNOWN if dispatched else CleanupState.VERIFIED_ABSENT
        receipt = content_hash(
            {
                "schema_version": "bluefire.engine-controller-check-uncertain.v1",
                "experiment_id": check.experiment_id,
                "check_id": check.check_id,
                "job_id": check.job_id,
                "run_id": check.run_id,
                "dispatched": dispatched,
                "cleanup_state": cleanup_state.value,
                "recorded_at": settled_at,
            }
        )
        return ControllerCheckSettlement(
            state=ControllerCheckState.UNKNOWN,
            result_digest=content_hash(
                {
                    "schema_version": "bluefire.engine-controller-check-unknown.v1",
                    "check_id": check.check_id,
                    "dispatched": dispatched,
                    "recorded_at": settled_at,
                }
            ),
            observations=(),
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=receipt,
            settled_at=settled_at,
        )

    def _now(self) -> str:
        return _timestamp(self._clock(), "controller clock")


__all__ = [
    "ControllerCheckExecutor",
    "ControllerCheckRecovery",
    "ControllerCheckSettlement",
    "DefenseOperation",
    "DefenseOperationExecutor",
    "DefenseOperationSettlement",
    "EngineControllerJobError",
    "EngineControllerJobs",
    "EngineControllerRepository",
]
