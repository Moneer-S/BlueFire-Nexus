"""Durable RunJobController wiring for admitted external-engine attempts.

The repository protocol is intentionally narrow and must be backed by the
existing ProductStore/RunStore transaction boundary.  It atomically claims the
one-time approval, compares the saved experiment revision and digest, appends
the attempt reservation, and creates the idempotent product job.  This module
adds no scheduler, database, subprocess, model client, or target access.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol

from .domain_errors import EnginePreDispatchCancelled, JobCancelled
from .engine_attempt_contract import (
    AttemptCompleteness,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
    EngineEvidenceItem,
    EvidenceCategory,
)
from .engine_delegation import (
    EngineCapabilityDelegation,
    EngineDelegationError,
    EngineExecutionApprovalBinding,
)
from .engine_experiment import (
    CleanupState,
    EngineExperiment,
    EngineExperimentError,
    IndependentObservationRecord,
)
from .engine_reconciliation import (
    ClaimedEngineReconciliation,
    EngineReconciliationCoordinator,
    EngineReconciliationError,
    SettledClaimedEngineAttempt,
    SettledNoDispatchEngineAttempt,
    UnclaimedEngineReconciliation,
)
from .evidence import EvidenceProvenance
from .job_runtime import JobContext, JobResult
from .util import content_hash, parse_iso8601_datetime


class EngineExperimentJobError(RuntimeError):
    """Raised when an engine job cannot retain its exact authority or state."""


_CLAIMED_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "approval_id",
        "run_id",
        "state_digest",
        "plan_digest",
        "profile_id",
        "target_scope_digest",
        "maximum_tier",
        "status",
        "requested_at",
        "expires_at",
        "approved_at",
        "approved_by",
        "nonce",
        "consumed_at",
        "claimed_at",
    }
)
_EXECUTION_CLAIM_POLICY = {
    "schema_version": "bluefire.engine-execution-claim-policy.v1",
    "claim_protocol": "bluefire.engine-attempt-execution-claim.v1",
    "accepted_jobs_adapter": "bluefire.product-store-accepted-engine-jobs.v1",
}
_JOB_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "attempt_id",
        "binding_digest",
        "delegation_digest",
        "execution_approval_digest",
        "execution_approval_id",
    }
)


def installed_execution_claim_policy() -> dict[str, str]:
    """Return the one exact immutable policy accepted by installed composition."""

    return dict(_EXECUTION_CLAIM_POLICY)


def _claim_policy(value: Any, *, allow_none: bool = True) -> dict[str, str] | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, Mapping) or dict(value) != _EXECUTION_CLAIM_POLICY:
        raise EngineExperimentJobError("engine execution claim policy changed")
    return dict(_EXECUTION_CLAIM_POLICY)


def _runtime_claim_policy(runtime: EngineAttemptRuntime | None) -> dict[str, str] | None:
    if runtime is None:
        return None
    return _claim_policy(getattr(runtime, "execution_claim_policy", None))


def _job_request(
    value: Mapping[str, Any], *, expected_policy: Mapping[str, Any] | None
) -> dict[str, Any]:
    parsed = dict(value)
    version = parsed.get("schema_version")
    fields = set(parsed)
    if version == "bluefire.engine-attempt-job.v1":
        if fields != _JOB_REQUEST_FIELDS or expected_policy is not None:
            raise EngineExperimentJobError("prepared engine request policy changed")
    elif version == "bluefire.engine-attempt-job.v2":
        if fields != _JOB_REQUEST_FIELDS | {"execution_claim_policy"}:
            raise EngineExperimentJobError("prepared engine request fields changed")
        policy = _claim_policy(parsed.get("execution_claim_policy"), allow_none=False)
        if expected_policy is None or policy != dict(expected_policy):
            raise EngineExperimentJobError("prepared engine request policy changed")
        parsed["execution_claim_policy"] = policy
    else:
        raise EngineExperimentJobError("prepared engine request version changed")
    for field, pattern in (
        ("experiment_id", r"experiment-[0-9a-f]{32}"),
        ("attempt_id", r"engine-attempt-[0-9a-f]{32}"),
        ("execution_approval_id", r"approval-[0-9a-f]{32}"),
        ("binding_digest", r"sha256:[0-9a-f]{64}"),
        ("delegation_digest", r"sha256:[0-9a-f]{64}"),
        ("execution_approval_digest", r"sha256:[0-9a-f]{64}"),
    ):
        if not isinstance(parsed[field], str) or re.fullmatch(pattern, parsed[field]) is None:
            raise EngineExperimentJobError("prepared engine request identity changed")
    return parsed


class EngineJobController(Protocol):
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


class EngineExperimentRepository(Protocol):
    """Existing-store operations required by the engine job coordinator."""

    def get_engine_experiment_document(self, experiment_id: str) -> Mapping[str, Any]: ...

    def get_job_submission(
        self, kind: str, *, submission_id: str, intent_digest: str
    ) -> Mapping[str, Any] | None: ...

    def reserve_engine_attempt_submission(
        self,
        *,
        experiment_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        approval_binding: Mapping[str, Any],
        approval_id: str,
        approval_nonce: str,
        approved_by: str,
        job_kind: str,
        job_request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_experiment_digest: str,
        reserved_at: str,
    ) -> tuple[Mapping[str, Any], bool]: ...

    def load_engine_attempt_execution(
        self, experiment_id: str, attempt_id: str
    ) -> Mapping[str, Any]: ...

    def compare_and_swap_engine_attempt_record(
        self,
        *,
        experiment_id: str,
        record: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
        timestamp: str,
    ) -> Mapping[str, Any]: ...

    def compare_and_swap_engine_attempt_settlement(
        self,
        *,
        experiment_id: str,
        record: Mapping[str, Any],
        engine_evidence: Iterable[Mapping[str, Any]],
        independent_observations: Iterable[Mapping[str, Any]] = (),
        artifact_manifest_ref: str | None,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
        recovery: bool = False,
        reconciliation_ref: str | None = None,
        reconciliation_capability: object | None = None,
        reconciled_at: str | None = None,
    ) -> Mapping[str, Any]: ...

    def reconcile_engine_attempt_cleanup(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        cleanup_state: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
        reconciliation_ref: str | None = None,
        reconciliation_capability: object | None = None,
    ) -> Mapping[str, Any]: ...

    def settle_unclaimed_engine_attempt_recovery(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        job_state: str,
        binding_digest: str,
        delegation_digest: str,
        cleanup_evidence_ref: str,
        timestamp: str,
        expected_revision: int,
        expected_experiment_digest: str,
        reconciliation_capability: object,
    ) -> Mapping[str, Any]:
        """Atomically recheck no claim and settle ambiguous custody UNKNOWN."""

        ...

    def settle_undispatched_engine_attempt_cancellation(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        record: Mapping[str, Any],
        cleanup_evidence_ref: str,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]:
        """Atomically prove cancelled job/no custody and settle the queued attempt."""

        ...

    def settle_engine_attempt_pre_dispatch(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
        binding: Mapping[str, Any],
        delegation: Mapping[str, Any],
        record: Mapping[str, Any],
        exit_reason: str,
        adapter_pre_dispatch_ref: str | None,
        settled_at: str,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> Mapping[str, Any]: ...


TransitionSink = Callable[[EngineAttemptRecord, str], None]


class EngineAttemptRuntime(Protocol):
    """Injected trusted adapter/runtime; it has no defensive-change method."""

    def execute(
        self,
        context: JobContext,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        transition: TransitionSink,
    ) -> "EngineRuntimeSettlement": ...

    def reconcile(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> "EngineRuntimeSettlement": ...


class ClaimedEngineAttemptRuntime(Protocol):
    """Installed v2 recovery bound to one immutable idempotency reference."""

    def reconcile_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        *,
        reconciliation_ref: str,
    ) -> "EngineRuntimeSettlement":
        """Reopen custody only; never launch, allocate, or reissue execution.

        A crash may cause another process to invoke this method again with the
        same reference. Every effectful adapter below this boundary must use
        that reference as an idempotency/fencing identity or fail closed.
        """

        ...


@dataclass(frozen=True, slots=True)
class EngineRuntimeSettlement:
    """One terminal runtime result ready for an atomic ProductStore append.

    ``independent_observations`` are controller-attested references to evidence
    the caller already reopened and verified byte-for-byte in a finalized
    RunStore bundle.  This value carries that verified result across the
    ProductStore transaction boundary; it does not publish or verify RunStore
    evidence itself.
    """

    record: EngineAttemptRecord
    engine_evidence: tuple[EngineEvidenceItem, ...]
    artifact_manifest_ref: str | None
    cleanup_state: CleanupState
    cleanup_evidence_ref: str
    settled_at: str
    independent_observations: tuple[IndependentObservationRecord, ...] = ()
    reconciliation_ref: str | None = None

    def validate(self, binding: EngineAttemptBinding) -> None:
        if self.reconciliation_ref is not None and (
            not isinstance(self.reconciliation_ref, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.reconciliation_ref) is None
        ):
            raise EngineExperimentJobError("runtime settlement reconciliation changed")
        if (
            self.record.binding_digest != binding.binding_digest
            or self.record.binding.attempt_id != binding.attempt_id
            or self.record.state
            not in {
                AttemptState.COMPLETED,
                AttemptState.PARTIAL,
                AttemptState.FAILED,
                AttemptState.CANCELLED,
                AttemptState.BUDGET_EXHAUSTED,
                AttemptState.UNKNOWN,
            }
        ):
            raise EngineExperimentJobError("runtime settlement has the wrong attempt or state")
        if any(
            item.attempt_id != binding.attempt_id
            or item.run_id != binding.run_id
            or item.category
            not in {EvidenceCategory.ENGINE_ASSERTION, EvidenceCategory.TOOL_RESULT}
            for item in self.engine_evidence
        ):
            raise EngineExperimentJobError("runtime returned invalid engine evidence")
        observations = self.independent_observations
        if not isinstance(observations, tuple) or len(observations) > 256:
            raise EngineExperimentJobError("runtime returned too many independent observations")
        observation_ids: set[str] = set()
        for observation in observations:
            try:
                observation.validate()
            except (AttributeError, EngineExperimentError, TypeError, ValueError) as exc:
                raise EngineExperimentJobError(
                    "runtime returned an invalid independent observation"
                ) from exc
            evidence = observation.evidence
            if (
                observation.attempt_id != binding.attempt_id
                or observation.check_id is not None
                or observation.check_input_digest is not None
                or observation.target_snapshot_ref != binding.target_snapshot_ref
                or evidence.run_id != binding.run_id
                or evidence.target_scope_ref != binding.scope_ref
                or evidence.provenance is not EvidenceProvenance.OBSERVED
                or evidence.content.get("independent_observation") is not True
                or evidence.content.get("engine_assertion") is not False
            ):
                raise EngineExperimentJobError(
                    "runtime observation differs from its attempt binding"
                )
            if evidence.evidence_id in observation_ids:
                raise EngineExperimentJobError("runtime reused an independent observation")
            observation_ids.add(evidence.evidence_id)
        if observations:
            if self.record.started_at is None or self.record.ended_at is None:
                raise EngineExperimentJobError(
                    "runtime observations require a bounded attempt lifecycle"
                )
            try:
                binding_created = parse_iso8601_datetime(binding.created_at)
                started = parse_iso8601_datetime(self.record.started_at)
                ended = parse_iso8601_datetime(self.record.ended_at)
                settled = parse_iso8601_datetime(self.settled_at)
                observed = tuple(
                    parse_iso8601_datetime(item.evidence.timestamp) for item in observations
                )
            except ValueError as exc:
                raise EngineExperimentJobError("runtime observation time is invalid") from exc
            if not binding_created <= started <= ended <= settled or any(
                timestamp < started or timestamp > ended for timestamp in observed
            ):
                raise EngineExperimentJobError(
                    "runtime observation falls outside its attempt lifecycle"
                )
        if self.cleanup_state is CleanupState.PENDING:
            raise EngineExperimentJobError("runtime settlement left cleanup pending")
        if not isinstance(
            self.cleanup_evidence_ref, str
        ) or not self.cleanup_evidence_ref.startswith("sha256:"):
            raise EngineExperimentJobError("runtime settlement lacks a cleanup receipt")
        try:
            ended = parse_iso8601_datetime(str(self.record.ended_at))
            settled = parse_iso8601_datetime(self.settled_at)
        except ValueError as exc:
            raise EngineExperimentJobError("runtime settlement time is invalid") from exc
        if settled < ended:
            raise EngineExperimentJobError("runtime settlement predates its terminal record")


class EngineExperimentJobs:
    """Admit, execute, and reconcile exact engine attempts without replay."""

    JOB_KIND = "engine-attempt"

    def __init__(
        self,
        *,
        controller: EngineJobController,
        repository: EngineExperimentRepository,
        runtime: EngineAttemptRuntime | None,
        clock: Callable[[], str],
        reconciliation: EngineReconciliationCoordinator | None = None,
    ) -> None:
        self._controller = controller
        self._repository = repository
        self._runtime = runtime
        self._execution_claim_policy = _runtime_claim_policy(runtime)
        if (reconciliation is None) != (self._execution_claim_policy is None):
            raise EngineExperimentJobError(
                "engine reconciliation coordinator and installed claim policy must agree"
            )
        self._reconciliation = reconciliation
        self._clock = clock

    def submit_prepared(
        self,
        *,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        submission_factory: Callable[[], tuple[Mapping[str, Any], bool]],
    ) -> Mapping[str, Any]:
        """Enqueue one retained request through the existing admission gate.

        The trusted factory owns atomic preparation, approval, reservation,
        and acceptance validation. This adapter never reconstructs authority
        from a caller-selected experiment head.
        """

        if not isinstance(request, Mapping):
            raise EngineExperimentJobError("prepared engine request fields changed")
        parsed = _job_request(request, expected_policy=self._execution_claim_policy)
        try:
            canonical_submission = str(uuid.UUID(submission_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise EngineExperimentJobError("submission identity must be a canonical UUID") from exc
        if canonical_submission != submission_id:
            raise EngineExperimentJobError("submission identity must be a canonical UUID")
        if intent_digest != content_hash(parsed):
            raise EngineExperimentJobError("prepared engine intent digest changed")
        if not callable(submission_factory):
            raise EngineExperimentJobError("prepared engine submission factory is unavailable")
        if self._runtime is None:
            raise EngineExperimentJobError("external engine runtime is unavailable")
        return self._controller.submit(
            self.JOB_KIND,
            parsed,
            requires_approval=False,
            callback=self._execute,
            submission_id=submission_id,
            intent_digest=intent_digest,
            submission_factory=submission_factory,
        )

    def submit(
        self,
        *,
        experiment_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        approval_binding: EngineExecutionApprovalBinding,
        approval_id: str,
        approval_nonce: str,
        approved_by: str,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        try:
            checked_binding = delegation.validate_attempt_binding(binding)
            checked_approval = delegation.validate_approval_binding(
                approval_binding, checked_binding
            )
        except EngineDelegationError as exc:
            raise EngineExperimentJobError("engine delegation or approval is invalid") from exc
        for value, label in (
            (approval_id, "approval identity"),
            (approval_nonce, "approval nonce"),
            (approved_by, "approval reviewer"),
            (submission_id, "submission identity"),
        ):
            if not isinstance(value, str) or not value or len(value) > 200:
                raise EngineExperimentJobError(f"{label} is invalid")
        try:
            submission_uuid = uuid.UUID(submission_id)
        except ValueError as exc:
            raise EngineExperimentJobError("submission identity must be a canonical UUID") from exc
        if str(submission_uuid) != submission_id:
            raise EngineExperimentJobError("submission identity must be a canonical UUID")
        experiment = EngineExperiment._from_controller_mapping(
            self._repository.get_engine_experiment_document(experiment_id)
        )
        request = self._request(
            experiment=experiment,
            binding=checked_binding,
            delegation=delegation,
            approval=checked_approval,
            approval_id=approval_id,
            execution_claim_policy=self._execution_claim_policy,
        )
        if intent_digest != content_hash(request):
            raise EngineExperimentJobError("engine submission intent digest changed")
        existing = self._repository.get_job_submission(
            self.JOB_KIND,
            submission_id=submission_id,
            intent_digest=intent_digest,
        )
        if existing is not None:
            return existing
        if self._runtime is None:
            raise EngineExperimentJobError("external engine runtime is unavailable")
        reserved_at = self._now()

        def reserve() -> tuple[Mapping[str, Any], bool]:
            return self._repository.reserve_engine_attempt_submission(
                experiment_id=experiment.experiment_id,
                binding=checked_binding.to_dict(),
                delegation=delegation.to_dict(),
                approval_binding=checked_approval.to_dict(),
                approval_id=approval_id,
                approval_nonce=approval_nonce,
                approved_by=approved_by,
                job_kind=self.JOB_KIND,
                job_request=request,
                submission_id=submission_id,
                intent_digest=intent_digest,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                reserved_at=reserved_at,
            )

        return self._controller.submit(
            self.JOB_KIND,
            request,
            requires_approval=False,
            callback=self._execute,
            submission_id=submission_id,
            intent_digest=intent_digest,
            submission_factory=reserve,
        )

    def _execute(self, context: JobContext, request: Mapping[str, Any]) -> JobResult:
        runtime = self._runtime
        if runtime is None:
            raise EngineExperimentJobError("external engine runtime is unavailable")
        experiment, binding, delegation, approval, _approval_id, claimed_at = self._load_execution(
            request
        )
        try:
            context.checkpoint(
                {
                    "phase": "engine_preflight",
                    "experiment_id": experiment.experiment_id,
                    "attempt_id": binding.attempt_id,
                }
            )
        except JobCancelled:
            self._settle_without_dispatch(
                experiment,
                binding,
                delegation,
                state=AttemptState.CANCELLED,
                exit_reason="controller_cancelled_before_dispatch",
            )
            raise
        _index, entry = experiment._attempt(binding.attempt_id)
        preflight_at = self._now()
        preflight = entry.record.transition(AttemptState.PREFLIGHT)
        experiment = self._cas_record(experiment, preflight, timestamp=preflight_at)

        dispatch_at = self._now()
        try:
            self._require_current_authority(
                delegation,
                approval,
                dispatch_at=dispatch_at,
                claimed_at=claimed_at,
            )
        except EngineExperimentJobError:
            self._settle_without_dispatch(
                experiment,
                binding,
                delegation,
                state=AttemptState.CANCELLED,
                exit_reason="authority_expired_before_dispatch",
                settled_at=dispatch_at,
            )
            raise

        def transition(record: EngineAttemptRecord, timestamp: str) -> None:
            nonlocal experiment
            # Persist the upstream session/state before honoring a cancellation
            # checkpoint.  Otherwise a worker that already allocated custody
            # could disappear while the canonical attempt still says preflight.
            experiment = self._cas_record(experiment, record, timestamp=timestamp)
            context.checkpoint(
                {
                    "phase": f"engine_{record.state.value}",
                    "attempt_id": binding.attempt_id,
                }
            )

        try:
            settlement = runtime.execute(
                context,
                binding,
                delegation,
                transition,
            )
            settlement.validate(binding)
        except EnginePreDispatchCancelled as exc:
            proof_ref = exc.pre_dispatch_ref
            if (
                self._execution_claim_policy is None
                or not isinstance(proof_ref, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", proof_ref) is None
            ):
                self._settle_runtime_error(
                    experiment,
                    binding,
                    delegation,
                    state=AttemptState.CANCELLED,
                    exit_reason="controller_cancelled",
                )
            else:
                self._settle_without_dispatch(
                    experiment,
                    binding,
                    delegation,
                    state=AttemptState.CANCELLED,
                    exit_reason="controller_cancelled_before_execution_claim",
                    pre_dispatch_ref=proof_ref,
                )
            raise
        except JobCancelled:
            experiment = self._settle_runtime_error(
                experiment,
                binding,
                delegation,
                state=AttemptState.CANCELLED,
                exit_reason="controller_cancelled",
            )
            raise
        except Exception:
            # A runtime failure cannot be treated as target prevention or clean
            # shutdown.  Persist an unknown-custody terminal record, then let
            # RunJobController retain the job failure for operator recovery.
            experiment = self._settle_runtime_error(
                experiment,
                binding,
                delegation,
                state=AttemptState.FAILED,
                exit_reason="engine_runtime_failed",
            )
            raise
        experiment = self._cas_settlement(experiment, settlement)
        return JobResult(
            result_ref=f"engine-experiment:{experiment.experiment_id}",
            progress={
                "phase": "engine_settled",
                "experiment_id": experiment.experiment_id,
                "attempt_id": binding.attempt_id,
                "experiment_revision": experiment.revision,
                "experiment_digest": experiment.digest,
                "cleanup_state": settlement.cleanup_state.value,
            },
            completion_confirmed=(settlement.cleanup_state is CleanupState.VERIFIED_ABSENT),
        )

    def _settle_runtime_error(
        self,
        experiment: EngineExperiment,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        state: AttemptState,
        exit_reason: str,
    ) -> EngineExperiment:
        _index, current = experiment._attempt(binding.attempt_id)
        ended_at = self._now()
        terminal = current.record
        if terminal.state not in {
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.CANCELLED,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }:
            terminal = terminal.transition(
                state,
                timestamp=ended_at,
                completeness=AttemptCompleteness.UNKNOWN,
                exit_reason=exit_reason,
                limitations=(
                    "Runtime ended before a complete settlement; custody requires reconciliation.",
                ),
            )
        cleanup_receipt = content_hash(
            {
                "schema_version": "bluefire.engine-runtime-failure-receipt.v1",
                "attempt_id": binding.attempt_id,
                "binding_digest": binding.binding_digest,
                "attempt_state": terminal.state.value,
                "cleanup_state": "unknown",
                "recorded_at": ended_at,
            }
        )
        return self._cas_settlement(
            experiment,
            EngineRuntimeSettlement(
                record=terminal,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.UNKNOWN,
                cleanup_evidence_ref=cleanup_receipt,
                settled_at=ended_at,
            ),
        )

    def _settle_without_dispatch(
        self,
        experiment: EngineExperiment,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        state: AttemptState,
        exit_reason: str,
        settled_at: str | None = None,
        pre_dispatch_ref: str | None = None,
    ) -> EngineExperiment:
        """Settle a controller stop before any engine custody was allocated."""

        _index, current = experiment._attempt(binding.attempt_id)
        when = self._now() if settled_at is None else settled_at
        terminal = current.record.transition(
            state,
            timestamp=when,
            completeness=AttemptCompleteness.UNKNOWN,
            exit_reason=exit_reason,
            limitations=("External-engine dispatch did not begin.",),
        )
        receipt = {
            "schema_version": "bluefire.engine-prelaunch-settlement-receipt.v1",
            "attempt_id": binding.attempt_id,
            "binding_digest": binding.binding_digest,
            "attempt_state": state.value,
            "cleanup_state": CleanupState.VERIFIED_ABSENT.value,
            "recorded_at": when,
        }
        if pre_dispatch_ref is not None:
            if re.fullmatch(r"sha256:[0-9a-f]{64}", pre_dispatch_ref) is None:
                raise EngineExperimentJobError("pre-dispatch proof reference is invalid")
            receipt["pre_dispatch_ref"] = pre_dispatch_ref
        cleanup_receipt = (
            pre_dispatch_ref if pre_dispatch_ref is not None else content_hash(receipt)
        )
        if self._execution_claim_policy is not None:
            value = self._repository.settle_engine_attempt_pre_dispatch(
                experiment_id=experiment.experiment_id,
                attempt_id=binding.attempt_id,
                job_id=current.job_id,
                binding=binding.to_dict(),
                delegation=delegation.to_dict(),
                record=terminal.to_dict(),
                exit_reason=exit_reason,
                adapter_pre_dispatch_ref=pre_dispatch_ref,
                settled_at=when,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
            )
            return EngineExperiment._from_controller_mapping(value)
        return self._cas_settlement(
            experiment,
            EngineRuntimeSettlement(
                record=terminal,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.VERIFIED_ABSENT,
                cleanup_evidence_ref=cleanup_receipt,
                settled_at=when,
            ),
        )

    def reconcile_interrupted_attempt(
        self, *, experiment_id: str, attempt_id: str
    ) -> Mapping[str, Any]:
        """Inspect saved custody after restart without launching or resubmitting."""

        runtime = self._runtime
        if runtime is None:
            raise EngineExperimentJobError("external engine runtime is unavailable")
        if self._execution_claim_policy is not None:
            coordinator = self._reconciliation
            if coordinator is None:
                raise EngineExperimentJobError(
                    "installed engine reconciliation coordinator is unavailable"
                )
            try:
                with coordinator.session(
                    experiment_id=experiment_id,
                    attempt_id=attempt_id,
                ) as session:
                    reconciliation_capability = session.reconciliation_capability
                    # The fixed-purpose OS lock is already held here. This must
                    # be a fresh snapshot, not a value loaded before admission.
                    snapshot = self._repository.load_engine_attempt_execution(
                        experiment_id,
                        attempt_id,
                    )
                    experiment, binding, delegation, _approval, _approval_id, _claimed_at = (
                        self._parse_execution_snapshot(snapshot)
                    )
                    _index, entry = experiment._attempt(attempt_id)
                    plan = session.begin_or_reopen(
                        binding=binding,
                        delegation=delegation,
                        saved_record=entry.record,
                        expected_revision=experiment.revision,
                        expected_experiment_digest=experiment.digest,
                    )
                    if (
                        not isinstance(
                            plan,
                            (
                                ClaimedEngineReconciliation,
                                SettledClaimedEngineAttempt,
                                SettledNoDispatchEngineAttempt,
                                UnclaimedEngineReconciliation,
                            ),
                        )
                        or plan.job_id != entry.job_id
                    ):
                        raise EngineReconciliationError(
                            "engine reconciliation job identity changed"
                        )
                    if isinstance(plan, SettledNoDispatchEngineAttempt):
                        plan.validate(binding, delegation, entry.record)
                        if (
                            entry.record.state is not AttemptState.CANCELLED
                            or entry.record.upstream_session_id is not None
                            or entry.record.started_at is not None
                            or entry.record.exit_reason != plan.exit_reason
                            or entry.cleanup_state is not CleanupState.VERIFIED_ABSENT
                            or entry.cleanup_evidence_ref != plan.cleanup_evidence_ref
                            or entry.settled_at is None
                        ):
                            raise EngineReconciliationError(
                                "saved pre-dispatch cancellation proof changed"
                            )
                        return experiment.to_dict()
                    if isinstance(plan, SettledClaimedEngineAttempt):
                        plan.validate(binding, delegation, entry.record)
                        if (
                            entry.record.state
                            not in {
                                AttemptState.COMPLETED,
                                AttemptState.PARTIAL,
                                AttemptState.FAILED,
                                AttemptState.CANCELLED,
                                AttemptState.BUDGET_EXHAUSTED,
                                AttemptState.UNKNOWN,
                            }
                            or entry.settled_at is None
                            or entry.cleanup_state is not CleanupState.VERIFIED_ABSENT
                            or entry.cleanup_evidence_ref != plan.cleanup_evidence_ref
                        ):
                            raise EngineReconciliationError(
                                "saved claimed engine cleanup outcome changed"
                            )
                        return experiment.to_dict()
                    if isinstance(plan, UnclaimedEngineReconciliation):
                        plan.validate(binding, delegation, entry.record)
                        recorded_at = self._now()
                        receipt = content_hash(
                            {
                                "schema_version": "bluefire.engine-unclaimed-recovery.v1",
                                "attempt_id": binding.attempt_id,
                                "binding_digest": binding.binding_digest,
                                "delegation_digest": delegation.delegation_digest,
                                "job_id": plan.job_id,
                                "job_state": plan.job_state,
                                "recorded_at": recorded_at,
                            }
                        )
                        # ProductStore rechecks claim absence and the terminal
                        # bound job in this same atomic UNKNOWN settlement.
                        return self._repository.settle_unclaimed_engine_attempt_recovery(
                            experiment_id=experiment.experiment_id,
                            attempt_id=attempt_id,
                            job_id=plan.job_id,
                            job_state=plan.job_state,
                            binding_digest=binding.binding_digest,
                            delegation_digest=delegation.delegation_digest,
                            cleanup_evidence_ref=receipt,
                            timestamp=recorded_at,
                            expected_revision=experiment.revision,
                            expected_experiment_digest=experiment.digest,
                            reconciliation_capability=reconciliation_capability,
                        )
                    if not isinstance(plan, ClaimedEngineReconciliation):
                        raise EngineReconciliationError("engine reconciliation plan is invalid")
                    plan.validate(binding, delegation, entry.record)
                    terminal_states = {
                        AttemptState.COMPLETED,
                        AttemptState.PARTIAL,
                        AttemptState.FAILED,
                        AttemptState.CANCELLED,
                        AttemptState.BUDGET_EXHAUSTED,
                        AttemptState.UNKNOWN,
                    }
                    if plan.job_state == "completed" and entry.record.state not in terminal_states:
                        raise EngineReconciliationError(
                            "completed engine job has no terminal attempt outcome"
                        )
                    if (
                        entry.record.state in terminal_states
                        and entry.settled_at is not None
                        and entry.cleanup_state is CleanupState.VERIFIED_ABSENT
                        and entry.cleanup_evidence_ref is not None
                    ):
                        # Lost acknowledgements after a successful recovery are
                        # reads, not another external cleanup or experiment
                        # revision. The exact claim/intent plan above has already
                        # been reopened and validated under the purpose lock.
                        return experiment.to_dict()
                    try:
                        reconcile_claimed = getattr(runtime, "reconcile_claimed", None)
                        if not callable(reconcile_claimed):
                            raise TypeError("installed engine runtime lacks claimed recovery")
                        settlement = reconcile_claimed(
                            binding,
                            delegation,
                            entry.record,
                            reconciliation_ref=plan.reconciliation_ref,
                        )
                    except Exception:
                        raise EngineReconciliationError(
                            "installed engine reconciliation failed"
                        ) from None
                    if not isinstance(settlement, EngineRuntimeSettlement):
                        raise EngineReconciliationError(
                            "installed engine runtime returned an invalid settlement"
                        )
                    settlement.validate(binding)
                    if settlement.reconciliation_ref != plan.reconciliation_ref:
                        raise EngineReconciliationError(
                            "runtime settlement reconciliation reference changed"
                        )
                    if entry.record.state in terminal_states:
                        if settlement.record.to_dict() != entry.record.to_dict():
                            raise EngineExperimentJobError(
                                "recovery attempted to rewrite a settled engine outcome"
                            )
                        saved_observations = {
                            item.evidence_id: item
                            for item in experiment.independent_observations
                            if item.attempt_id == attempt_id
                        }
                        if any(
                            (saved := saved_observations.get(item.evidence_id)) is None
                            or saved.to_dict() != item.to_dict()
                            for item in settlement.independent_observations
                        ):
                            raise EngineExperimentJobError(
                                "settled recovery observations require separate "
                                "verified publication"
                            )
                        return self._repository.reconcile_engine_attempt_cleanup(
                            experiment_id=experiment.experiment_id,
                            attempt_id=attempt_id,
                            cleanup_state=settlement.cleanup_state.value,
                            cleanup_evidence_ref=settlement.cleanup_evidence_ref,
                            timestamp=self._now(),
                            expected_revision=experiment.revision,
                            expected_experiment_digest=experiment.digest,
                            reconciliation_ref=plan.reconciliation_ref,
                            reconciliation_capability=reconciliation_capability,
                        )
                    return self._cas_settlement(
                        experiment,
                        settlement,
                        recovery=True,
                        reconciliation_ref=plan.reconciliation_ref,
                        reconciliation_capability=reconciliation_capability,
                    ).to_dict()
            except EngineReconciliationError as exc:
                raise EngineExperimentJobError(
                    "installed engine reconciliation is unavailable"
                ) from exc
        snapshot = self._repository.load_engine_attempt_execution(experiment_id, attempt_id)
        experiment, binding, delegation, _approval, _approval_id, _claimed_at = (
            self._parse_execution_snapshot(snapshot)
        )
        _index, entry = experiment._attempt(attempt_id)
        settlement = runtime.reconcile(binding, delegation, entry.record)
        settlement.validate(binding)
        if settlement.reconciliation_ref is not None:
            raise EngineExperimentJobError(
                "generic runtime returned installed reconciliation metadata"
            )
        if entry.record.state in {
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.CANCELLED,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }:
            if settlement.record.to_dict() != entry.record.to_dict():
                raise EngineExperimentJobError(
                    "recovery attempted to rewrite a settled engine outcome"
                )
            saved_observations = {
                item.evidence_id: item
                for item in experiment.independent_observations
                if item.attempt_id == attempt_id
            }
            if any(
                (saved := saved_observations.get(item.evidence_id)) is None
                or saved.to_dict() != item.to_dict()
                for item in settlement.independent_observations
            ):
                raise EngineExperimentJobError(
                    "settled recovery observations require separate verified publication"
                )
            return self._repository.reconcile_engine_attempt_cleanup(
                experiment_id=experiment.experiment_id,
                attempt_id=attempt_id,
                cleanup_state=settlement.cleanup_state.value,
                cleanup_evidence_ref=settlement.cleanup_evidence_ref,
                timestamp=self._now(),
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
            )
        return self._cas_settlement(experiment, settlement, recovery=True).to_dict()

    def settle_undispatched_cancellation(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
    ) -> Mapping[str, Any]:
        """Settle a generic-job cancellation that won before callback dispatch.

        The repository is the authority that verifies the durable job is
        cancelled and that no session/custody was allocated. A competing
        callback start changes the experiment revision, so this CAS loses and
        normal callback cancellation/reconciliation owns the outcome.
        """

        experiment = EngineExperiment._from_controller_mapping(
            self._repository.get_engine_experiment_document(experiment_id)
        )
        _index, entry = experiment._attempt(attempt_id)
        if entry.job_id != job_id:
            raise EngineExperimentJobError("cancelled job belongs to another engine attempt")
        if (
            entry.record.state is AttemptState.CANCELLED
            and entry.record.upstream_session_id is None
            and entry.record.exit_reason == "controller_cancelled_before_dispatch"
            and entry.cleanup_state is CleanupState.VERIFIED_ABSENT
        ):
            return experiment.to_dict()
        if (
            entry.record.state is not AttemptState.QUEUED
            or entry.record.upstream_session_id is not None
            or entry.settled_at is not None
        ):
            raise EngineExperimentJobError(
                "engine attempt dispatch already began; callback reconciliation is required"
            )
        settled_at = self._now()
        terminal = entry.record.transition(
            AttemptState.CANCELLED,
            timestamp=settled_at,
            completeness=AttemptCompleteness.UNKNOWN,
            exit_reason="controller_cancelled_before_dispatch",
            limitations=("External-engine dispatch did not begin.",),
        )
        cleanup_receipt = content_hash(
            {
                "schema_version": "bluefire.engine-undispatched-cancellation-receipt.v1",
                "experiment_id": experiment.experiment_id,
                "attempt_id": attempt_id,
                "job_id": job_id,
                "binding_digest": terminal.binding_digest,
                "job_state": "cancelled",
                "custody_state": "never_dispatched",
                "recorded_at": settled_at,
            }
        )
        value = self._repository.settle_undispatched_engine_attempt_cancellation(
            experiment_id=experiment.experiment_id,
            attempt_id=attempt_id,
            job_id=job_id,
            record=terminal.to_dict(),
            cleanup_evidence_ref=cleanup_receipt,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
        return EngineExperiment._from_controller_mapping(value).to_dict()

    def _load_execution(
        self, request: Mapping[str, Any]
    ) -> tuple[
        EngineExperiment,
        EngineAttemptBinding,
        EngineCapabilityDelegation,
        EngineExecutionApprovalBinding,
        str,
        str,
    ]:
        request_document = dict(request)
        submission = request_document.pop("_submission", None)
        request_document = _job_request(
            request_document,
            expected_policy=self._execution_claim_policy,
        )
        if submission is not None:
            if (
                not isinstance(submission, Mapping)
                or set(submission) != {"schema_version", "submission_id", "intent_digest"}
                or submission.get("schema_version") != "bluefire.job-submission.v1"
                or submission.get("intent_digest") != content_hash(request_document)
            ):
                raise EngineExperimentJobError("engine job submission binding changed")
            submission_id = submission.get("submission_id")
            try:
                parsed_submission = uuid.UUID(str(submission_id))
            except ValueError as exc:
                raise EngineExperimentJobError("engine job submission identity is invalid") from exc
            if not isinstance(submission_id, str) or str(parsed_submission) != submission_id:
                raise EngineExperimentJobError("engine job submission identity is invalid")
        snapshot = self._repository.load_engine_attempt_execution(
            str(request_document["experiment_id"]), str(request_document["attempt_id"])
        )
        parsed = self._parse_execution_snapshot(snapshot)
        experiment, binding, delegation, approval, approval_id, _claimed_at = parsed
        if request_document != self._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval,
            approval_id=approval_id,
            execution_claim_policy=self._execution_claim_policy,
        ):
            raise EngineExperimentJobError("saved engine job authority changed")
        return parsed

    @staticmethod
    def _parse_execution_snapshot(
        snapshot: Mapping[str, Any],
    ) -> tuple[
        EngineExperiment,
        EngineAttemptBinding,
        EngineCapabilityDelegation,
        EngineExecutionApprovalBinding,
        str,
        str,
    ]:
        if set(snapshot) != {
            "experiment",
            "delegation",
            "approval_binding",
            "approval_record",
        }:
            raise EngineExperimentJobError("engine execution snapshot fields changed")
        try:
            experiment = EngineExperiment._from_controller_mapping(snapshot["experiment"])
            delegation = EngineCapabilityDelegation.from_mapping(snapshot["delegation"])
            approval = EngineExecutionApprovalBinding.from_mapping(snapshot["approval_binding"])
            _index, entry = experiment._attempt(delegation.attempt_id)
            binding = delegation.validate_attempt_binding(entry.record.binding)
            delegation.validate_approval_binding(approval, binding)
            approval_record = snapshot["approval_record"]
            if not isinstance(approval_record, Mapping):
                raise EngineExperimentJobError("engine approval record is invalid")
            if (
                set(approval_record) != _CLAIMED_APPROVAL_FIELDS
                or approval_record.get("schema_version") != "bluefire.approval-request.v1"
            ):
                raise EngineExperimentJobError("engine approval record fields changed")
            approval.validate_approval_record(approval_record)
            if approval_record.get("status") != "claimed":
                raise EngineExperimentJobError("engine approval is not claimed")
            approval_id = approval_record.get("approval_id")
            if not isinstance(approval_id, str) or approval_id != entry.execution_approval_id:
                raise EngineExperimentJobError("engine approval identity changed")
            if entry.delegation_digest != delegation.delegation_digest or (
                entry.execution_approval_digest != content_hash(approval.to_dict())
            ):
                raise EngineExperimentJobError("engine attempt authority changed")
            for field in ("nonce", "approved_by"):
                value = approval_record.get(field)
                if not isinstance(value, str) or not value.strip() or len(value) > 200:
                    raise EngineExperimentJobError("engine approval claim proof is incomplete")
            for field in (
                "requested_at",
                "approved_at",
                "consumed_at",
                "claimed_at",
                "expires_at",
            ):
                value = approval_record.get(field)
                if not isinstance(value, str) or not value:
                    raise EngineExperimentJobError("engine approval claim proof is incomplete")
            requested_at = parse_iso8601_datetime(approval_record["requested_at"])
            approved_at = parse_iso8601_datetime(approval_record["approved_at"])
            consumed_at = parse_iso8601_datetime(approval_record["consumed_at"])
            claimed_at_value = approval_record["claimed_at"]
            claimed_at_time = parse_iso8601_datetime(claimed_at_value)
            expires_at = parse_iso8601_datetime(approval_record["expires_at"])
            if not (requested_at <= approved_at <= consumed_at <= claimed_at_time < expires_at):
                raise EngineExperimentJobError("engine approval claim chronology is invalid")
        except (EngineDelegationError, EngineExperimentError, TypeError, ValueError) as exc:
            if isinstance(exc, EngineExperimentJobError):
                raise
            raise EngineExperimentJobError("engine execution snapshot is invalid") from exc
        return experiment, binding, delegation, approval, approval_id, claimed_at_value

    def _cas_record(
        self,
        experiment: EngineExperiment,
        record: EngineAttemptRecord,
        *,
        timestamp: str,
    ) -> EngineExperiment:
        value = self._repository.compare_and_swap_engine_attempt_record(
            experiment_id=experiment.experiment_id,
            record=record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=timestamp,
        )
        return EngineExperiment._from_controller_mapping(value)

    def _cas_settlement(
        self,
        experiment: EngineExperiment,
        settlement: EngineRuntimeSettlement,
        *,
        recovery: bool = False,
        reconciliation_ref: str | None = None,
        reconciliation_capability: object | None = None,
    ) -> EngineExperiment:
        settlement.validate(settlement.record.binding)
        if settlement.reconciliation_ref != reconciliation_ref:
            raise EngineExperimentJobError("runtime settlement reconciliation reference changed")
        values: dict[str, Any] = {
            "experiment_id": experiment.experiment_id,
            "record": settlement.record.to_dict(),
            "engine_evidence": (item.to_dict() for item in settlement.engine_evidence),
            "independent_observations": (
                item.to_dict() for item in settlement.independent_observations
            ),
            "artifact_manifest_ref": settlement.artifact_manifest_ref,
            "cleanup_state": settlement.cleanup_state.value,
            "cleanup_evidence_ref": settlement.cleanup_evidence_ref,
            "settled_at": settlement.settled_at,
            "expected_revision": experiment.revision,
            "expected_experiment_digest": experiment.digest,
            "recovery": recovery,
        }
        if recovery:
            values["reconciled_at"] = self._now()
        if reconciliation_ref is not None:
            values["reconciliation_ref"] = reconciliation_ref
        if reconciliation_capability is not None:
            values["reconciliation_capability"] = reconciliation_capability
        value = self._repository.compare_and_swap_engine_attempt_settlement(**values)
        return EngineExperiment._from_controller_mapping(value)

    @staticmethod
    def _request(
        *,
        experiment: EngineExperiment,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        approval: EngineExecutionApprovalBinding,
        approval_id: str,
        execution_claim_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if binding.experiment_id != experiment.experiment_id:
            raise EngineExperimentJobError("engine binding belongs to another experiment")
        policy = _claim_policy(execution_claim_policy)
        request: dict[str, Any] = {
            "schema_version": (
                "bluefire.engine-attempt-job.v2"
                if policy is not None
                else "bluefire.engine-attempt-job.v1"
            ),
            "experiment_id": experiment.experiment_id,
            "attempt_id": binding.attempt_id,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "execution_approval_digest": content_hash(approval.to_dict()),
            "execution_approval_id": approval_id,
        }
        if policy is not None:
            request["execution_claim_policy"] = policy
        return request

    @staticmethod
    def _require_current_authority(
        delegation: EngineCapabilityDelegation,
        approval: EngineExecutionApprovalBinding,
        *,
        dispatch_at: str,
        claimed_at: str,
    ) -> None:
        now = parse_iso8601_datetime(dispatch_at)
        if (
            parse_iso8601_datetime(claimed_at) > now
            or now >= parse_iso8601_datetime(delegation.expires_at)
            or now >= parse_iso8601_datetime(approval.expires_at)
        ):
            raise EngineExperimentJobError("engine authority expired before dispatch")

    def _now(self) -> str:
        value = self._clock()
        try:
            parse_iso8601_datetime(value)
        except (TypeError, ValueError) as exc:
            raise EngineExperimentJobError("engine job clock returned an invalid time") from exc
        return value
