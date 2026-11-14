"""Concrete controller jobs for the generated tenant-record defense journey.

The external engine never receives these objects.  They reopen only an
accepted, append-only prepared action through its durable job identity, invoke
the narrow tenant controller, and publish controller-check evidence through
the existing tamper-evident RunStore.  Recovery reopens a finalized run or
settles unknown; it never repeats a target request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, cast

from .engine_action_contract import EngineWorkspaceAction
from .engine_controller_job_contract import DefenseOperation, EngineControllerJobError
from .engine_controller_jobs import (
    ControllerCheckRecovery,
    ControllerCheckSettlement,
    DefenseOperationSettlement,
)
from .engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    EngineExperiment,
)
from .evidence import EvidenceRecord
from .job_runtime import JobContext
from .product_store_engine_actions import (
    _safe_protected,
    _tenant_check_authority,
    _tenant_mechanism,
    _tenant_plan,
)
from .run_store import RunStore, RunStoreError
from .tenant_record_controller_contract import (
    ControllerCheckRole as TenantCheckRole,
)
from .tenant_record_controller_contract import (
    MutationState,
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRecordControllerError,
    TenantTargetOperationUnknown,
    _digest,
    tenant_target_snapshot_ref,
)
from .tenant_record_experiment_controller import (
    TenantControllerCheck,
    TenantRecordExperimentController,
)
from .tenant_record_observer import checked_observation_content
from .util import content_hash, parse_iso8601_datetime


class TenantRecordJobExecutorError(EngineControllerJobError):
    """Accepted tenant controller work lost an exact authority or result binding."""


class AcceptedControllerActionStore(Protocol):
    def get_protected_engine_controller_action_for_job(self, job_id: str) -> Mapping[str, Any]: ...


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise TenantRecordJobExecutorError(f"{label} is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError as exc:
        raise TenantRecordJobExecutorError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise TenantRecordJobExecutorError(f"{label} is not canonical")
    return value


def _protected(record: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    protected = _safe_protected(record.get("protected_request"))
    for field in (
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "workspace_digest",
        "action_kind",
        "preparation_kind",
        "approval_request_id",
        "submission_id",
    ):
        if protected.get(field) != record.get(field):
            raise TenantRecordJobExecutorError("accepted controller request binding changed")
    authority = protected.get("authority")
    request = protected.get("job_request")
    if not isinstance(authority, Mapping) or not isinstance(request, Mapping):
        raise TenantRecordJobExecutorError("accepted controller authority is unavailable")
    return request, authority


@dataclass(frozen=True, slots=True)
class AcceptedDefenseAuthority:
    action: EngineWorkspaceAction
    plan: TenantDefensePlan


@dataclass(frozen=True, slots=True)
class AcceptedCheckAuthority:
    action: EngineWorkspaceAction
    mechanism: TenantFailureMechanism
    scope_ref: str


class ProductStoreTenantRecordAuthoritySource:
    """Resolve protected plan/mechanism material from one accepted job only."""

    def __init__(self, store: AcceptedControllerActionStore) -> None:
        self._store = store

    def defense(
        self,
        *,
        job_id: str,
        experiment: EngineExperiment,
        operation: DefenseOperation,
    ) -> AcceptedDefenseAuthority:
        try:
            record = self._store.get_protected_engine_controller_action_for_job(job_id)
            action = EngineWorkspaceAction(record["action_kind"])
            request, authority = _protected(record)
            expected_action = {
                DefenseOperation.APPLY: EngineWorkspaceAction.APPLY_DEFENSE,
                DefenseOperation.ROLLBACK: EngineWorkspaceAction.ROLLBACK_DEFENSE,
            }.get(operation)
            if expected_action is None or action is not expected_action:
                raise TenantRecordJobExecutorError("accepted defense operation is unavailable")
            if authority.get("kind") != "tenant_defense_plan" or authority.get(
                "document_digest"
            ) != content_hash(authority.get("document")):
                raise TenantRecordJobExecutorError("accepted defense plan changed")
            plan = _tenant_plan(authority["document"])
            change = experiment.defense_change
            if (
                record.get("experiment_id") != experiment.experiment_id
                or request.get("experiment_id") != experiment.experiment_id
                or request.get("operation") != operation.value
                or change is None
                or request.get("change_id") != change.change_id
                or plan.before.digest != change.preimage_digest
                or plan.after.digest != change.approved_configuration_digest
                or tenant_target_snapshot_ref(
                    fixture_digest=plan.before.fixture_digest,
                    target_snapshot_id=plan.before.target_snapshot_id,
                    service_generation=plan.before.service_generation,
                )
                != change.before_target_snapshot_ref
                or tenant_target_snapshot_ref(
                    fixture_digest=plan.after.fixture_digest,
                    target_snapshot_id=plan.after.target_snapshot_id,
                    service_generation=plan.after.service_generation,
                )
                != change.after_target_snapshot_ref
            ):
                raise TenantRecordJobExecutorError(
                    "accepted defense plan differs from current custody"
                )
            return AcceptedDefenseAuthority(action, plan)
        except TenantRecordJobExecutorError:
            raise
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            raise TenantRecordJobExecutorError(
                "accepted defense authority could not be reopened"
            ) from exc

    def check(self, *, job_id: str, check: ControllerCheckRecord) -> AcceptedCheckAuthority:
        try:
            record = self._store.get_protected_engine_controller_action_for_job(job_id)
            action = EngineWorkspaceAction(record["action_kind"])
            expected_action = {
                ControllerCheckRole.RETAINED_REPRODUCER: EngineWorkspaceAction.REPEAT_MECHANISM,
                ControllerCheckRole.LEGITIMATE_USE: EngineWorkspaceAction.RUN_LEGITIMATE_USE,
            }[check.role]
            request, authority = _protected(record)
            experiment_document = record.get("experiment_document")
            if not isinstance(experiment_document, Mapping):
                raise TenantRecordJobExecutorError("accepted controller experiment is unavailable")
            scope_ref = _digest(experiment_document.get("scope_ref"), "accepted experiment scope")
            if action is not expected_action or authority.get("kind") != "tenant_controller_check":
                raise TenantRecordJobExecutorError("accepted controller check is unavailable")
            mechanism, document = _tenant_check_authority(authority.get("document"))
            if authority.get("document_digest") != content_hash(document):
                raise TenantRecordJobExecutorError("accepted controller check changed")
            if (
                record.get("experiment_id") != check.experiment_id
                or experiment_document.get("experiment_id") != check.experiment_id
                or content_hash(experiment_document) != record.get("experiment_digest")
                or request.get("check_id") != check.check_id
                or request.get("run_id") != check.run_id
                or request.get("role") != check.role.value
                or request.get("performer") != check.performer.value
                or request.get("mechanism_ref") != check.mechanism_ref
                or request.get("target_snapshot_ref") != check.target_snapshot_ref
                or request.get("input_digest") != check.input_digest
                or request.get("reserved_at") != check.created_at
                or document.get("check_id") != check.check_id
                or document.get("run_id") != check.run_id
                or document.get("role") != check.role.value
                or document.get("input_digest") != check.input_digest
                or document.get("reserved_at") != check.created_at
                or content_hash(mechanism.to_dict()) != check.mechanism_ref
            ):
                raise TenantRecordJobExecutorError(
                    "accepted controller check differs from current custody"
                )
            return AcceptedCheckAuthority(action, mechanism, scope_ref)
        except TenantRecordJobExecutorError:
            raise
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            raise TenantRecordJobExecutorError(
                "accepted controller-check authority could not be reopened"
            ) from exc


class TenantRecordDefenseExecutor:
    """Apply or roll back the exact accepted tenant defense plan."""

    def __init__(
        self,
        *,
        controller: TenantRecordExperimentController,
        authority: ProductStoreTenantRecordAuthoritySource,
        clock: Callable[[], str],
    ) -> None:
        self._controller = controller
        self._authority = authority
        self._clock = clock

    def execute(
        self,
        context: JobContext,
        experiment: EngineExperiment,
        operation: DefenseOperation,
    ) -> DefenseOperationSettlement:
        change = experiment.defense_change
        if change is None:
            raise TenantRecordJobExecutorError("tenant defense change is unavailable")
        accepted = self._authority.defense(
            job_id=context.job_id, experiment=experiment, operation=operation
        )
        context.checkpoint(
            {
                "phase": "tenant_defense_dispatch",
                "experiment_id": experiment.experiment_id,
                "operation": operation.value,
            }
        )
        # Reopen immediately after the cooperative cancellation point.  No
        # target operation occurs if accepted authority changed while waiting.
        if (
            self._authority.defense(
                job_id=context.job_id, experiment=experiment, operation=operation
            )
            != accepted
        ):
            raise TenantRecordJobExecutorError("accepted defense authority changed")
        settled_at = _timestamp(self._clock(), "tenant defense settlement time")
        try:
            if operation is DefenseOperation.APPLY:
                result = self._controller.apply_defense(accepted.plan, settled_at=settled_at)
                expected_state = MutationState.APPLIED
                configuration_digest: str | None = accepted.plan.after.digest
            elif operation is DefenseOperation.ROLLBACK:
                result = self._controller.rollback_defense(
                    accepted.plan,
                    operation_id="tenant-rollback-" + context.job_id.removeprefix("job-"),
                    settled_at=settled_at,
                )
                expected_state = MutationState.ROLLED_BACK
                configuration_digest = None
            else:
                raise TenantRecordJobExecutorError("prepared defense reconciliation is unavailable")
        except TenantRecordControllerError as exc:
            raise TenantRecordJobExecutorError("tenant defense operation failed") from exc
        if result.state is not expected_state or result.observed_config_digest is None:
            # NOT_APPLIED and UNKNOWN are materially different target results,
            # but neither can be coerced into a successful generic settlement.
            # The outer job has already made the saved target state unknown and
            # retains this failure for explicit reconciliation.
            raise TenantRecordJobExecutorError(
                f"tenant defense target settled as {result.state.value}"
            )
        target_config = (
            accepted.plan.after if operation is DefenseOperation.APPLY else accepted.plan.before
        )
        return DefenseOperationSettlement(
            operation=operation,
            change_id=change.change_id,
            target_snapshot_ref=tenant_target_snapshot_ref(
                fixture_digest=target_config.fixture_digest,
                target_snapshot_id=target_config.target_snapshot_id,
                service_generation=target_config.service_generation,
            ),
            configuration_digest=configuration_digest,
            receipt_digest=result.target_receipt_digest,
            settled_at=result.settled_at,
        )


_RUN_RESULT_SCHEMA = "bluefire.tenant-controller-check-run.v1"


class TenantControllerCheckRunPublisher:
    """Publish and reopen one exact controller-check RunStore bundle."""

    def __init__(self, runs: RunStore, *, clock: Callable[[], str]) -> None:
        self._runs = runs
        self._clock = clock

    @staticmethod
    def _cleanup_ref(check: ControllerCheckRecord, outcome: TenantControllerCheck) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.tenant-controller-check-cleanup.v1",
                "check_id": check.check_id,
                "run_id": check.run_id,
                "result_digest": outcome.digest,
                "owned_resources": "none_after_bounded_read",
            }
        )

    @staticmethod
    def _unknown_cleanup_ref(check: ControllerCheckRecord, receipt_digest: str) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.tenant-controller-check-cleanup.v1",
                "check_id": check.check_id,
                "run_id": check.run_id,
                "target_operation_receipt_digest": receipt_digest,
                "cleanup_state": CleanupState.UNKNOWN.value,
                "replayed": False,
            }
        )

    @staticmethod
    def _bundle_documents(
        check: ControllerCheckRecord,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        return (
            {
                "schema_version": "bluefire.tenant-controller-check-scenario.v1",
                "experiment_id": check.experiment_id,
                "check_id": check.check_id,
                "role": check.role.value,
            },
            {
                "schema_version": "bluefire.tenant-controller-check-plan.v1",
                "check_id": check.check_id,
                "mechanism_ref": check.mechanism_ref,
                "failure_mechanism": mechanism.to_dict(),
            },
            {
                "schema_version": "bluefire.tenant-controller-check-policy.v1",
                "performer": "controller",
                "operation": check.role.value,
                "effect": "bounded_read",
            },
            {
                "schema_version": "bluefire.tenant-controller-check-profile.v1",
                "scope_ref": scope_ref,
                "target_snapshot_ref": check.target_snapshot_ref,
                "input_digest": check.input_digest,
            },
        )

    @staticmethod
    def _validate_outcome(
        check: ControllerCheckRecord,
        outcome: TenantControllerCheck,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
    ) -> None:
        content = checked_observation_content(outcome.evidence)
        environment = outcome.evidence.environment
        if not isinstance(environment, Mapping):
            raise TenantRecordJobExecutorError("tenant check environment is invalid")
        target_ref = tenant_target_snapshot_ref(
            fixture_digest=cast(str, environment["fixture_digest"]),
            target_snapshot_id=outcome.target_snapshot_id,
            service_generation=cast(str, content["service_generation"]),
        )
        expected_role = (
            TenantCheckRole.RETAINED_REPRODUCER
            if check.role is ControllerCheckRole.RETAINED_REPRODUCER
            else TenantCheckRole.LEGITIMATE_USE
        )
        if (
            outcome.role is not expected_role
            or outcome.check_id != check.check_id
            or outcome.run_id != check.run_id
            or outcome.evidence.run_id != check.run_id
            or content_hash(mechanism.to_dict()) != check.mechanism_ref
            or outcome.mechanism_digest != mechanism.request_digest
            or outcome.evidence.target_scope_ref != scope_ref
            or target_ref != check.target_snapshot_ref
        ):
            raise TenantRecordJobExecutorError("tenant controller check result changed")

    def publish(
        self,
        check: ControllerCheckRecord,
        outcome: TenantControllerCheck,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
    ) -> ControllerCheckSettlement:
        scope_ref = _digest(scope_ref, "tenant check experiment scope")
        self._validate_outcome(check, outcome, mechanism, scope_ref)
        cleanup_ref = self._cleanup_ref(check, outcome)
        scenario, plan, policy, profile = self._bundle_documents(check, mechanism, scope_ref)
        result = {
            "schema_version": _RUN_RESULT_SCHEMA,
            "status": "completed",
            "experiment_id": check.experiment_id,
            "check_id": check.check_id,
            "role": check.role.value,
            "mechanism_ref": check.mechanism_ref,
            "target_snapshot_ref": check.target_snapshot_ref,
            "input_digest": check.input_digest,
            "failure_mechanism": mechanism.to_dict(),
            "controller_check": outcome.to_dict(),
            "result_digest": outcome.digest,
            "cleanup_state": CleanupState.VERIFIED_ABSENT.value,
            "cleanup_evidence_ref": cleanup_ref,
        }
        try:
            self._runs.publish_finalized_run(
                check.run_id,
                created_at=check.created_at,
                finalized_at=outcome.performed_at,
                scenario=scenario,
                plan=plan,
                policy=policy,
                profile=profile,
                result=result,
                evidence=(outcome.evidence.to_dict(),),
                detections=(),
            )
        except (RunStoreError, OSError) as exc:
            raise TenantRecordJobExecutorError(
                "tenant controller check evidence could not be published exactly"
            ) from exc
        settlement = self._settlement(check, mechanism, scope_ref)
        if settlement is None:
            raise TenantRecordJobExecutorError(
                "tenant controller check run was not finalized exactly"
            )
        return settlement

    def publish_unknown(
        self,
        check: ControllerCheckRecord,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
        *,
        target_operation_receipt_digest: str,
        settled_at: str,
    ) -> ControllerCheckSettlement:
        scope_ref = _digest(scope_ref, "tenant check experiment scope")
        receipt = _digest(target_operation_receipt_digest, "unknown target operation receipt")
        settled_at = _timestamp(settled_at, "tenant check unknown settlement time")
        if content_hash(mechanism.to_dict()) != check.mechanism_ref:
            raise TenantRecordJobExecutorError("unknown tenant check mechanism changed")
        cleanup_ref = self._unknown_cleanup_ref(check, receipt)
        ControllerCheckSettlement(
            state=ControllerCheckState.UNKNOWN,
            result_digest=receipt,
            observations=(),
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref=cleanup_ref,
            settled_at=settled_at,
        ).validate(check)
        scenario, plan, policy, profile = self._bundle_documents(check, mechanism, scope_ref)
        result = {
            "schema_version": _RUN_RESULT_SCHEMA,
            "status": "unknown",
            "experiment_id": check.experiment_id,
            "check_id": check.check_id,
            "role": check.role.value,
            "mechanism_ref": check.mechanism_ref,
            "target_snapshot_ref": check.target_snapshot_ref,
            "input_digest": check.input_digest,
            "failure_mechanism": mechanism.to_dict(),
            "target_operation_receipt_digest": receipt,
            "result_digest": receipt,
            "cleanup_state": CleanupState.UNKNOWN.value,
            "cleanup_evidence_ref": cleanup_ref,
        }
        try:
            self._runs.publish_finalized_run(
                check.run_id,
                created_at=check.created_at,
                finalized_at=settled_at,
                scenario=scenario,
                plan=plan,
                policy=policy,
                profile=profile,
                result=result,
                evidence=(),
                detections=(),
            )
        except (RunStoreError, OSError) as exc:
            raise TenantRecordJobExecutorError(
                "unknown tenant controller check could not be published exactly"
            ) from exc
        settlement = self._settlement(check, mechanism, scope_ref)
        if settlement is None:
            raise TenantRecordJobExecutorError(
                "unknown tenant controller check run was not finalized exactly"
            )
        return settlement

    def _settlement(
        self,
        check: ControllerCheckRecord,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
    ) -> ControllerCheckSettlement | None:
        try:
            scope_ref = _digest(scope_ref, "tenant check experiment scope")
            run = self._runs.get_run(check.run_id, require_finalized=True)
            evidence_document = run.get("evidence")
            rows = (
                evidence_document.get("records") if isinstance(evidence_document, Mapping) else None
            )
            retained_mechanism = _tenant_mechanism(run.get("failure_mechanism"))
            profile_document = run.get("profile")
            if not isinstance(rows, list) or not isinstance(profile_document, Mapping):
                return None
            retained_scope_ref = _digest(profile_document.get("scope_ref"), "tenant check scope")
            if (
                retained_scope_ref != scope_ref
                or retained_mechanism.to_dict() != mechanism.to_dict()
                or content_hash(mechanism.to_dict()) != check.mechanism_ref
            ):
                return None
            scenario, plan, policy, profile = self._bundle_documents(check, mechanism, scope_ref)
            if (
                run.get("created_at") != check.created_at
                or run.get("scenario") != scenario
                or run.get("plan") != plan
                or run.get("policy") != policy
                or run.get("profile") != profile
            ):
                return None
            if run.get("status") == "completed":
                controller_check = run.get("controller_check")
                if len(rows) != 1 or not isinstance(controller_check, Mapping):
                    return None
                evidence = EvidenceRecord.from_mapping(rows[0])
                outcome = TenantControllerCheck(
                    role=TenantCheckRole(controller_check["role"]),
                    check_id=controller_check["check_id"],
                    run_id=controller_check["run_id"],
                    mechanism_digest=controller_check["mechanism_digest"],
                    evidence=evidence,
                    assessment=controller_check["assessment"],
                    passed=controller_check["passed"],
                    target_snapshot_id=controller_check["target_snapshot_id"],
                    performed_at=controller_check["performed_at"],
                )
                self._validate_outcome(check, outcome, mechanism, scope_ref)
                cleanup_ref = self._cleanup_ref(check, outcome)
                expected = {
                    "schema_version": _RUN_RESULT_SCHEMA,
                    "status": "completed",
                    "experiment_id": check.experiment_id,
                    "check_id": check.check_id,
                    "role": check.role.value,
                    "mechanism_ref": check.mechanism_ref,
                    "target_snapshot_ref": check.target_snapshot_ref,
                    "input_digest": check.input_digest,
                    "failure_mechanism": mechanism.to_dict(),
                    "controller_check": outcome.to_dict(),
                    "result_digest": outcome.digest,
                    "cleanup_state": CleanupState.VERIFIED_ABSENT.value,
                    "cleanup_evidence_ref": cleanup_ref,
                }
                if (
                    any(run.get(key) != value for key, value in expected.items())
                    or run.get("finalized_at") != outcome.performed_at
                ):
                    return None
                return ControllerCheckSettlement(
                    state=ControllerCheckState.COMPLETED,
                    result_digest=outcome.digest,
                    observations=(evidence,),
                    cleanup_state=CleanupState.VERIFIED_ABSENT,
                    cleanup_evidence_ref=cleanup_ref,
                    settled_at=outcome.performed_at,
                )
            if run.get("status") == "unknown":
                receipt = _digest(
                    run.get("target_operation_receipt_digest"),
                    "unknown target operation receipt",
                )
                finalized_at = _timestamp(
                    run.get("finalized_at"), "tenant check unknown settlement time"
                )
                cleanup_ref = self._unknown_cleanup_ref(check, receipt)
                expected = {
                    "schema_version": _RUN_RESULT_SCHEMA,
                    "status": "unknown",
                    "experiment_id": check.experiment_id,
                    "check_id": check.check_id,
                    "role": check.role.value,
                    "mechanism_ref": check.mechanism_ref,
                    "target_snapshot_ref": check.target_snapshot_ref,
                    "input_digest": check.input_digest,
                    "failure_mechanism": mechanism.to_dict(),
                    "target_operation_receipt_digest": receipt,
                    "result_digest": receipt,
                    "cleanup_state": CleanupState.UNKNOWN.value,
                    "cleanup_evidence_ref": cleanup_ref,
                }
                if (
                    rows
                    or run.get("controller_check") is not None
                    or any(run.get(key) != value for key, value in expected.items())
                ):
                    return None
                return ControllerCheckSettlement(
                    state=ControllerCheckState.UNKNOWN,
                    result_digest=receipt,
                    observations=(),
                    cleanup_state=CleanupState.UNKNOWN,
                    cleanup_evidence_ref=cleanup_ref,
                    settled_at=finalized_at,
                )
            return None
        except (
            KeyError,
            OSError,
            RunStoreError,
            TenantRecordJobExecutorError,
            TypeError,
            ValueError,
        ):
            return None

    def recover(
        self,
        check: ControllerCheckRecord,
        mechanism: TenantFailureMechanism,
        scope_ref: str,
    ) -> ControllerCheckRecovery:
        settlement = self._settlement(check, mechanism, scope_ref)
        if settlement is not None:
            return ControllerCheckRecovery(
                settlement=(settlement if check.state is ControllerCheckState.RESERVED else None),
                cleanup_state=settlement.cleanup_state,
                cleanup_evidence_ref=settlement.cleanup_evidence_ref,
                reconciled_at=settlement.settled_at,
            )
        now = _timestamp(self._clock(), "tenant check recovery time")
        unknown_ref = content_hash(
            {
                "schema_version": "bluefire.tenant-controller-check-recovery.v1",
                "check_id": check.check_id,
                "run_id": check.run_id,
                "state": "unknown",
                "replayed": False,
            }
        )
        unknown = ControllerCheckSettlement(
            state=ControllerCheckState.UNKNOWN,
            result_digest=unknown_ref,
            observations=(),
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref=unknown_ref,
            settled_at=now,
        )
        return ControllerCheckRecovery(
            settlement=unknown if check.state is ControllerCheckState.RESERVED else None,
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref=unknown_ref,
            reconciled_at=now,
        )


class TenantRecordControllerCheckExecutor:
    """Run exact controller-owned checks and never replay them during recovery."""

    def __init__(
        self,
        *,
        controller: TenantRecordExperimentController,
        authority: ProductStoreTenantRecordAuthoritySource,
        publisher: TenantControllerCheckRunPublisher,
        clock: Callable[[], str],
        legitimate_session_lifetime_seconds: int = 60,
    ) -> None:
        if (
            isinstance(legitimate_session_lifetime_seconds, bool)
            or not 1 <= legitimate_session_lifetime_seconds <= 300
        ):
            raise ValueError("legitimate session lifetime must be between 1 and 300 seconds")
        self._controller = controller
        self._authority = authority
        self._publisher = publisher
        self._clock = clock
        self._legitimate_lifetime = legitimate_session_lifetime_seconds

    def execute(
        self, context: JobContext, check: ControllerCheckRecord
    ) -> ControllerCheckSettlement:
        accepted = self._authority.check(job_id=context.job_id, check=check)
        current_target = self._controller.current_target_snapshot_ref()
        if current_target != check.target_snapshot_ref:
            raise TenantRecordJobExecutorError("tenant check target snapshot changed")
        context.checkpoint(
            {
                "phase": "tenant_controller_check_dispatch",
                "experiment_id": check.experiment_id,
                "check_id": check.check_id,
                "role": check.role.value,
            }
        )
        if self._authority.check(job_id=context.job_id, check=check) != accepted:
            raise TenantRecordJobExecutorError("accepted controller check authority changed")
        if self._controller.current_target_snapshot_ref() != check.target_snapshot_ref:
            raise TenantRecordJobExecutorError("tenant check target snapshot changed")
        requested_at = _timestamp(self._clock(), "tenant controller check time")
        try:
            if check.role is ControllerCheckRole.RETAINED_REPRODUCER:
                outcome = self._controller.run_exact_reproducer(
                    accepted.mechanism,
                    check_id=check.check_id,
                    run_id=check.run_id,
                    target_scope_ref=accepted.scope_ref,
                    expected_target_snapshot_ref=check.target_snapshot_ref,
                    performed_at=None,
                )
            else:
                issued_at = parse_iso8601_datetime(requested_at)
                if not isinstance(issued_at, datetime):  # pragma: no cover - typing guard
                    raise TenantRecordJobExecutorError("legitimate-use time is invalid")
                outcome = self._controller.run_legitimate_use(
                    accepted.mechanism,
                    check_id=check.check_id,
                    run_id=check.run_id,
                    target_scope_ref=accepted.scope_ref,
                    expected_target_snapshot_ref=check.target_snapshot_ref,
                    performed_at=None,
                    issued_at=issued_at,
                    lifetime_seconds=self._legitimate_lifetime,
                )
        except TenantTargetOperationUnknown as exc:
            return self._publisher.publish_unknown(
                check,
                accepted.mechanism,
                accepted.scope_ref,
                target_operation_receipt_digest=exc.receipt_digest,
                settled_at=_timestamp(self._clock(), "tenant controller unknown settlement time"),
            )
        except TenantRecordControllerError as exc:
            raise TenantRecordJobExecutorError("tenant controller check failed") from exc
        return self._publisher.publish(check, outcome, accepted.mechanism, accepted.scope_ref)

    def reconcile(self, check: ControllerCheckRecord) -> ControllerCheckRecovery:
        # Recovery reopens the accepted historical authority read-only but does
        # not call the target.  This prevents adoption of a self-consistent
        # bundle for another evidence scope.  Only already finalized evidence
        # can settle a known result; otherwise the exact operation remains
        # unknown without replay.
        accepted = self._authority.check(job_id=check.job_id, check=check)
        return self._publisher.recover(check, accepted.mechanism, accepted.scope_ref)


__all__ = [
    "ProductStoreTenantRecordAuthoritySource",
    "TenantControllerCheckRunPublisher",
    "TenantRecordControllerCheckExecutor",
    "TenantRecordDefenseExecutor",
    "TenantRecordJobExecutorError",
]
