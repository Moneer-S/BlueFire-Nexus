"""Application-owned one-shot bridge from accepted jobs to installed runtime."""

from __future__ import annotations

import re
import threading
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Mapping, Protocol

from .domain_errors import EnginePreDispatchCancelled
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_delegation import EngineCapabilityDelegation, EngineDelegationError
from .engine_reconciliation import (
    ClaimedEngineReconciliation,
    EngineReconciliationError,
    EngineReconciliationPlan,
    SettledClaimedEngineAttempt,
    SettledNoDispatchEngineAttempt,
    UnclaimedEngineReconciliation,
)
from .product_store_engine_execution_claims import (
    EngineExecutionClaimRecovery,
    EngineExecutionClaimResult,
    EngineExecutionReconciliationResult,
)
from .product_store_errors import ProductStoreError
from .strix_runtime_admission_resolver import (
    ControllerQualifiedStrixAdmissionResolver,
    StrixRuntimeAdmissionResolverError,
)

_JOB = re.compile(r"^job-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AcceptedEngineExecutionStore(Protocol):
    def engine_attempt_reconciliation_session(
        self,
        *,
        cancel_event: threading.Event | None = None,
        deadline: float | None = None,
    ) -> AbstractContextManager[object]: ...

    def begin_or_reopen_engine_attempt_reconciliation(
        self,
        *,
        binding: Mapping[str, object],
        delegation: Mapping[str, object],
        reviewer: str,
        created_at: str,
        saved_record: Mapping[str, object],
        expected_revision: int,
        expected_experiment_digest: str,
        reconciliation_capability: object,
    ) -> EngineExecutionReconciliationResult: ...

    def inspect_accepted_engine_attempt_pre_dispatch_cancellation(
        self,
        *,
        job_id: str,
        binding: Mapping[str, object],
        delegation: Mapping[str, object],
        reviewer: str,
        checked_at: str,
    ) -> EngineExecutionClaimResult | None: ...

    def claim_accepted_engine_attempt_execution(
        self,
        *,
        job_id: str,
        binding: Mapping[str, object],
        delegation: Mapping[str, object],
        runtime_resolution_ref: str,
        reviewer: str,
        claimed_at: str,
    ) -> EngineExecutionClaimResult: ...

    def get_accepted_engine_attempt_execution(
        self,
        *,
        binding: Mapping[str, object],
        delegation: Mapping[str, object],
        reviewer: str,
    ) -> EngineExecutionClaimRecovery: ...


class AcceptedEngineJobError(RuntimeError):
    """The durable accepted job could not issue installed runtime authority."""


AcceptedEnginePreDispatchCancelled = EnginePreDispatchCancelled


@dataclass(frozen=True, slots=True)
class AcceptedPreparedEngineAttempt:
    job_id: str
    preparation_ref: str
    binding_digest: str
    delegation_digest: str
    claim_ref: str
    runtime_resolution_ref: str

    def validate(
        self, job_id: str, binding: EngineAttemptBinding, delegation: EngineCapabilityDelegation
    ) -> None:
        if (
            not isinstance(self.job_id, str)
            or _JOB.fullmatch(self.job_id) is None
            or self.job_id != job_id
            or not isinstance(self.preparation_ref, str)
            or _DIGEST.fullmatch(self.preparation_ref) is None
            or self.binding_digest != binding.binding_digest
            or self.delegation_digest != delegation.delegation_digest
            or not isinstance(self.claim_ref, str)
            or _DIGEST.fullmatch(self.claim_ref) is None
            or not isinstance(self.runtime_resolution_ref, str)
            or _DIGEST.fullmatch(self.runtime_resolution_ref) is None
        ):
            raise AcceptedEngineJobError("accepted prepared job binding changed")


@dataclass(frozen=True, slots=True)
class AbsentPreparedEngineAttempt:
    """Pinned terminal job with no claim; absence never proves no prior effect."""

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str

    def validate(
        self, binding: EngineAttemptBinding, delegation: EngineCapabilityDelegation
    ) -> None:
        if (
            _JOB.fullmatch(self.job_id) is None
            or self.job_state not in {"cancelled", "failed", "interrupted"}
            or self.binding_digest != binding.binding_digest
            or self.delegation_digest != delegation.delegation_digest
        ):
            raise AcceptedEngineJobError("absent prepared job binding changed")


@dataclass(frozen=True, slots=True)
class PreDispatchCancelledEngineAttempt:
    """Atomic current-callback proof that cancellation preceded claim/factory."""

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str
    pre_dispatch_ref: str

    def validate(
        self,
        job_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        if (
            self.job_id != job_id
            or _JOB.fullmatch(self.job_id) is None
            or self.job_state != "cancelling"
            or self.binding_digest != binding.binding_digest
            or self.delegation_digest != delegation.delegation_digest
            or _DIGEST.fullmatch(self.pre_dispatch_ref) is None
        ):
            raise AcceptedEngineJobError("pre-dispatch cancellation binding changed")


@dataclass(frozen=True, slots=True)
class SettledPreDispatchEngineAttempt:
    """Exact terminal no-custody receipt reopened after a job interruption."""

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str
    settlement_ref: str
    exit_reason: str
    settled_at: str

    def validate(
        self, binding: EngineAttemptBinding, delegation: EngineCapabilityDelegation
    ) -> None:
        if (
            _JOB.fullmatch(self.job_id) is None
            or self.job_state not in {"cancelled", "failed", "interrupted"}
            or self.binding_digest != binding.binding_digest
            or self.delegation_digest != delegation.delegation_digest
            or _DIGEST.fullmatch(self.settlement_ref) is None
            or self.exit_reason
            not in {
                "controller_cancelled_before_dispatch",
                "controller_cancelled_before_execution_claim",
                "authority_expired_before_dispatch",
            }
            or not isinstance(self.settled_at, str)
            or not self.settled_at
        ):
            raise AcceptedEngineJobError("settled pre-dispatch binding changed")


class AcceptedPreparedEngineJobs(Protocol):
    def claim_for_execution(
        self,
        *,
        job_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> AcceptedPreparedEngineAttempt | PreDispatchCancelledEngineAttempt | None: ...

    def reopen_for_reconciliation(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> (
        AcceptedPreparedEngineAttempt
        | AbsentPreparedEngineAttempt
        | SettledPreDispatchEngineAttempt
    ): ...

    def require_current(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None: ...


class ProductStoreAcceptedEngineJobs:
    """Issue authority exactly once after durable acceptance and preflight."""

    def __init__(
        self,
        *,
        store: AcceptedEngineExecutionStore,
        resolver: ControllerQualifiedStrixAdmissionResolver,
        reviewer: str,
        clock: Callable[[], str],
    ) -> None:
        if (
            store is None
            or not isinstance(resolver, ControllerQualifiedStrixAdmissionResolver)
            or not isinstance(reviewer, str)
            or not reviewer
            or reviewer != reviewer.strip()
            or not callable(clock)
        ):
            raise AcceptedEngineJobError("accepted engine job dependencies are invalid")
        self._store = store
        self._resolver = resolver
        self._reviewer = reviewer
        self._clock = clock

    @staticmethod
    def _accepted(document: Mapping[str, object]) -> AcceptedPreparedEngineAttempt:
        try:

            def required(field: str) -> str:
                value = document[field]
                if not isinstance(value, str):
                    raise TypeError("accepted engine execution identities are invalid")
                return value

            accepted = AcceptedPreparedEngineAttempt(
                job_id=required("job_id"),
                preparation_ref=required("preparation_ref"),
                binding_digest=required("binding_digest"),
                delegation_digest=required("delegation_digest"),
                claim_ref=required("claim_ref"),
                runtime_resolution_ref=required("runtime_resolution_ref"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AcceptedEngineJobError("saved accepted engine job is invalid") from exc
        return accepted

    @staticmethod
    def _cancelled(
        result: EngineExecutionClaimResult,
        *,
        job_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> PreDispatchCancelledEngineAttempt:
        if result.document is not None or result.pre_dispatch_ref is None:
            raise AcceptedEngineJobError("accepted engine execution returned no durable decision")
        cancelled = PreDispatchCancelledEngineAttempt(
            job_id=job_id,
            job_state=result.job_state,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
            pre_dispatch_ref=result.pre_dispatch_ref,
        )
        cancelled.validate(job_id, binding, delegation)
        return cancelled

    def claim_for_execution(
        self,
        *,
        job_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> AcceptedPreparedEngineAttempt | PreDispatchCancelledEngineAttempt | None:
        try:
            checked_binding = delegation.validate_attempt_binding(binding)
            cancelled = self._store.inspect_accepted_engine_attempt_pre_dispatch_cancellation(
                job_id=job_id,
                binding=checked_binding.to_dict(),
                delegation=delegation.to_dict(),
                reviewer=self._reviewer,
                checked_at=self._clock(),
            )
            if cancelled is not None:
                return self._cancelled(
                    cancelled,
                    job_id=job_id,
                    binding=checked_binding,
                    delegation=delegation,
                )
            try:
                resolution = self._resolver.resolve_for_launch(checked_binding, delegation)
            except StrixRuntimeAdmissionResolverError:
                cancelled = self._store.inspect_accepted_engine_attempt_pre_dispatch_cancellation(
                    job_id=job_id,
                    binding=checked_binding.to_dict(),
                    delegation=delegation.to_dict(),
                    reviewer=self._reviewer,
                    checked_at=self._clock(),
                )
                if cancelled is not None:
                    return self._cancelled(
                        cancelled,
                        job_id=job_id,
                        binding=checked_binding,
                        delegation=delegation,
                    )
                raise
            result = self._store.claim_accepted_engine_attempt_execution(
                job_id=job_id,
                binding=checked_binding.to_dict(),
                delegation=delegation.to_dict(),
                runtime_resolution_ref=resolution.resolution_ref,
                reviewer=self._reviewer,
                claimed_at=self._clock(),
            )
            if result.document is None:
                return self._cancelled(
                    result,
                    job_id=job_id,
                    binding=checked_binding,
                    delegation=delegation,
                )
            if not result.created:
                return None
            self._resolver.require_current(
                checked_binding,
                delegation,
                expected_resolution_ref=resolution.resolution_ref,
            )
            accepted = self._accepted(result.document)
            accepted.validate(job_id, checked_binding, delegation)
            return accepted
        except (
            EngineDelegationError,
            ProductStoreError,
            StrixRuntimeAdmissionResolverError,
            ValueError,
            TypeError,
        ) as exc:
            raise AcceptedEngineJobError("accepted engine execution could not be issued") from exc

    def reopen_for_reconciliation(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> (
        AcceptedPreparedEngineAttempt
        | AbsentPreparedEngineAttempt
        | SettledPreDispatchEngineAttempt
    ):
        try:
            checked_binding = delegation.validate_attempt_binding(binding)
            recovery = self._store.get_accepted_engine_attempt_execution(
                binding=checked_binding.to_dict(),
                delegation=delegation.to_dict(),
                reviewer=self._reviewer,
            )
            if recovery.pre_dispatch_document is not None:
                document = recovery.pre_dispatch_document
                settlement_ref = document.get("settlement_ref")
                exit_reason = document.get("exit_reason")
                settled_at = document.get("settled_at")
                if (
                    not isinstance(settlement_ref, str)
                    or not isinstance(exit_reason, str)
                    or not isinstance(settled_at, str)
                ):
                    raise AcceptedEngineJobError("saved pre-dispatch settlement is invalid")
                settled = SettledPreDispatchEngineAttempt(
                    job_id=recovery.job_id,
                    job_state=recovery.job_state,
                    binding_digest=checked_binding.binding_digest,
                    delegation_digest=delegation.delegation_digest,
                    settlement_ref=settlement_ref,
                    exit_reason=exit_reason,
                    settled_at=settled_at,
                )
                settled.validate(checked_binding, delegation)
                return settled
            if recovery.document is None:
                absent = AbsentPreparedEngineAttempt(
                    job_id=recovery.job_id,
                    job_state=recovery.job_state,
                    binding_digest=checked_binding.binding_digest,
                    delegation_digest=delegation.delegation_digest,
                )
                absent.validate(checked_binding, delegation)
                return absent
            accepted = self._accepted(recovery.document)
            accepted.validate(recovery.job_id, checked_binding, delegation)
            return accepted
        except (EngineDelegationError, ProductStoreError, ValueError, TypeError) as exc:
            raise AcceptedEngineJobError("accepted engine execution could not be reopened") from exc

    def require_current(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        try:
            checked_binding = delegation.validate_attempt_binding(binding)
            accepted.validate(accepted.job_id, checked_binding, delegation)
            self._resolver.require_current(
                checked_binding,
                delegation,
                expected_resolution_ref=accepted.runtime_resolution_ref,
            )
        except (
            EngineDelegationError,
            StrixRuntimeAdmissionResolverError,
            ValueError,
            TypeError,
        ) as exc:
            raise AcceptedEngineJobError(
                "accepted engine execution admission is no longer current"
            ) from exc


class _ProductStoreReconciliationSession:
    def __init__(
        self,
        *,
        owner: ProductStoreEngineReconciliationCoordinator,
        experiment_id: str,
        attempt_id: str,
        reconciliation_capability: object,
    ) -> None:
        self._owner = owner
        self._experiment_id = experiment_id
        self._attempt_id = attempt_id
        self._reconciliation_capability = reconciliation_capability
        self._used = False
        self._plan: EngineReconciliationPlan | None = None

    @property
    def plan(self) -> EngineReconciliationPlan | None:
        return self._plan

    @property
    def reconciliation_capability(self) -> object:
        return self._reconciliation_capability

    def begin_or_reopen(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> EngineReconciliationPlan:
        if (
            self._used
            or not isinstance(saved_record, EngineAttemptRecord)
            or binding.experiment_id != self._experiment_id
            or binding.attempt_id != self._attempt_id
            or saved_record.binding != binding
        ):
            raise EngineReconciliationError("engine reconciliation session binding changed")
        self._used = True
        try:
            decision = self._owner._store.begin_or_reopen_engine_attempt_reconciliation(
                binding=binding.to_dict(),
                delegation=delegation.to_dict(),
                reviewer=self._owner._reviewer,
                created_at=self._owner._clock(),
                saved_record=saved_record.to_dict(),
                expected_revision=expected_revision,
                expected_experiment_digest=expected_experiment_digest,
                reconciliation_capability=self._reconciliation_capability,
            )
            if (
                decision.settled_reconciliation_ref is not None
                and decision.settled_cleanup_evidence_ref is None
            ) or (
                decision.settled_cleanup_evidence_ref is not None
                and decision.claim_document is None
            ):
                raise EngineReconciliationError(
                    "settled claimed reconciliation decision is inconsistent"
                )
            if (
                decision.claim_document is not None
                and decision.settled_cleanup_evidence_ref is not None
            ):
                claim = decision.claim_document
                intent = decision.reconciliation_document
                if decision.pre_dispatch_document is not None:
                    raise EngineReconciliationError(
                        "settled claimed recovery conflicts with pre-dispatch history"
                    )
                if (intent is None) != (decision.settled_reconciliation_ref is None) or (
                    intent is not None
                    and intent.get("reconciliation_ref") != decision.settled_reconciliation_ref
                ):
                    raise EngineReconciliationError("settled claimed recovery intent changed")
                plan: EngineReconciliationPlan = SettledClaimedEngineAttempt(
                    job_id=decision.job_id,
                    job_state=decision.job_state,
                    binding_digest=str(claim["binding_digest"]),
                    delegation_digest=str(claim["delegation_digest"]),
                    claim_ref=str(claim["claim_ref"]),
                    runtime_resolution_ref=str(claim["runtime_resolution_ref"]),
                    cleanup_evidence_ref=decision.settled_cleanup_evidence_ref,
                    reconciliation_ref=decision.settled_reconciliation_ref,
                )
            elif decision.claim_document is not None:
                claim = decision.claim_document
                intent = decision.reconciliation_document
                if decision.pre_dispatch_document is not None or intent is None:
                    raise EngineReconciliationError("claimed reconciliation intent is incomplete")
                plan = ClaimedEngineReconciliation(
                    job_id=decision.job_id,
                    job_state=decision.job_state,
                    binding_digest=str(claim["binding_digest"]),
                    delegation_digest=str(claim["delegation_digest"]),
                    claim_ref=str(claim["claim_ref"]),
                    runtime_resolution_ref=str(claim["runtime_resolution_ref"]),
                    reconciliation_ref=str(intent["reconciliation_ref"]),
                )
            elif decision.pre_dispatch_document is not None:
                receipt = decision.pre_dispatch_document
                if decision.reconciliation_document is not None:
                    raise EngineReconciliationError(
                        "pre-dispatch recovery gained a reconciliation intent"
                    )
                plan = SettledNoDispatchEngineAttempt(
                    job_id=decision.job_id,
                    job_state=decision.job_state,
                    binding_digest=str(receipt["binding_digest"]),
                    delegation_digest=str(receipt["delegation_digest"]),
                    exit_reason=str(receipt["exit_reason"]),
                    cleanup_evidence_ref=str(receipt["settlement_ref"]),
                )
            else:
                if decision.reconciliation_document is not None:
                    raise EngineReconciliationError(
                        "unclaimed recovery gained a reconciliation intent"
                    )
                plan = UnclaimedEngineReconciliation(
                    job_id=decision.job_id,
                    job_state=decision.job_state,
                    binding_digest=binding.binding_digest,
                    delegation_digest=delegation.delegation_digest,
                )
            plan.validate(binding, delegation, saved_record)
        except (
            EngineDelegationError,
            ProductStoreError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise EngineReconciliationError(
                "engine reconciliation decision is unavailable"
            ) from exc
        self._plan = plan
        return plan


class ProductStoreEngineReconciliationCoordinator:
    """Purpose-locked ProductStore coordinator for installed v2 recovery."""

    _WAIT_SECONDS = 5.0

    def __init__(
        self,
        *,
        store: AcceptedEngineExecutionStore,
        reviewer: str,
        clock: Callable[[], str],
    ) -> None:
        if store is None or not reviewer or reviewer != reviewer.strip() or not callable(clock):
            raise AcceptedEngineJobError("engine reconciliation dependencies are invalid")
        self._store = store
        self._reviewer = reviewer
        self._clock = clock
        self._active = threading.local()

    @contextmanager
    def session(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
    ) -> Iterator[_ProductStoreReconciliationSession]:
        if getattr(self._active, "session", None) is not None:
            raise EngineReconciliationError("engine reconciliation session is already active")
        guard = self._store.engine_attempt_reconciliation_session(
            deadline=time.monotonic() + self._WAIT_SECONDS
        )
        try:
            reconciliation_capability = guard.__enter__()
        except (ProductStoreError, TypeError, ValueError) as exc:
            raise EngineReconciliationError(
                "engine reconciliation purpose lock is unavailable"
            ) from exc
        session = _ProductStoreReconciliationSession(
            owner=self,
            experiment_id=experiment_id,
            attempt_id=attempt_id,
            reconciliation_capability=reconciliation_capability,
        )
        self._active.session = session
        try:
            yield session
        except BaseException as exc:
            self._active.session = None
            if not guard.__exit__(type(exc), exc, exc.__traceback__):
                raise
        else:
            self._active.session = None
            guard.__exit__(None, None, None)

    def require_active_claimed(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        reconciliation_ref: str,
    ) -> ClaimedEngineReconciliation:
        session = getattr(self._active, "session", None)
        plan = session.plan if isinstance(session, _ProductStoreReconciliationSession) else None
        try:
            checked_binding = delegation.validate_attempt_binding(binding)
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise EngineReconciliationError("claimed reconciliation authority is invalid") from exc
        if (
            not isinstance(plan, ClaimedEngineReconciliation)
            or checked_binding != binding
            or plan.binding_digest != binding.binding_digest
            or plan.delegation_digest != delegation.delegation_digest
        ):
            raise EngineReconciliationError("claimed reconciliation session is not active")
        if plan.reconciliation_ref != reconciliation_ref:
            raise EngineReconciliationError("engine reconciliation reference changed")
        return plan


__all__ = [
    "AcceptedEngineJobError",
    "AcceptedEnginePreDispatchCancelled",
    "AcceptedPreparedEngineAttempt",
    "AcceptedPreparedEngineJobs",
    "AbsentPreparedEngineAttempt",
    "PreDispatchCancelledEngineAttempt",
    "ProductStoreAcceptedEngineJobs",
    "ProductStoreEngineReconciliationCoordinator",
    "SettledPreDispatchEngineAttempt",
]
