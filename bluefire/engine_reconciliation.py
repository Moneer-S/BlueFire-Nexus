"""Neutral contracts for fenced installed-engine recovery.

The coordinator owns a crash-released, purpose-scoped lock outside SQLite.  A
session starts before the fresh ProductStore snapshot and remains open through
the final settlement transaction.  The immutable reconciliation reference is
not execution authority: it only identifies one no-launch, repeat-idempotent
cleanup of custody established by an earlier durable execution claim.

Generic v1 runtimes do not implement or use these contracts.  Missing claims
also never create an intent or call a runtime; ProductStore must atomically
settle that ambiguous history as UNKNOWN.
"""

from __future__ import annotations

import re
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol, TypeAlias

from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_delegation import EngineCapabilityDelegation, EngineDelegationError

_JOB = re.compile(r"^job-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLAIMED_JOB_STATES = frozenset({"cancelled", "completed", "failed", "interrupted"})
_UNCLAIMED_JOB_STATES = frozenset({"cancelled", "failed", "interrupted"})


class EngineReconciliationError(RuntimeError):
    """A recovery fence, intent, or exact saved identity is unavailable."""


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineReconciliationError(f"{context} is invalid")
    return value


def _job(value: object) -> str:
    if not isinstance(value, str) or _JOB.fullmatch(value) is None:
        raise EngineReconciliationError("engine reconciliation job identity is invalid")
    return value


def _validate_authority(
    *,
    binding_digest: str,
    delegation_digest: str,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    saved_record: EngineAttemptRecord,
) -> None:
    try:
        checked_binding = delegation.validate_attempt_binding(binding)
    except (EngineDelegationError, TypeError, ValueError) as exc:
        raise EngineReconciliationError("engine reconciliation authority is invalid") from exc
    if (
        checked_binding != binding
        or saved_record.binding != binding
        or saved_record.binding_digest != binding.binding_digest
        or binding_digest != binding.binding_digest
        or delegation_digest != delegation.delegation_digest
    ):
        raise EngineReconciliationError("engine reconciliation authority changed")


@dataclass(frozen=True, slots=True)
class ClaimedEngineReconciliation:
    """One immutable, non-authorizing recovery intent for claimed custody.

    Reopening after a crash must return the same ``reconciliation_ref``.  Every
    external reconciliation adapter must use that value as its idempotency or
    fencing identity and must never allocate, launch, or reissue execution.
    """

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str
    claim_ref: str
    runtime_resolution_ref: str
    reconciliation_ref: str

    def validate(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> None:
        _job(self.job_id)
        if self.job_state not in _CLAIMED_JOB_STATES:
            raise EngineReconciliationError("engine reconciliation job is not terminal")
        _digest(self.binding_digest, "engine reconciliation binding digest")
        _digest(self.delegation_digest, "engine reconciliation delegation digest")
        _digest(self.claim_ref, "engine execution claim reference")
        _digest(self.runtime_resolution_ref, "engine runtime resolution reference")
        _digest(self.reconciliation_ref, "engine reconciliation reference")
        _validate_authority(
            binding_digest=self.binding_digest,
            delegation_digest=self.delegation_digest,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
        )


@dataclass(frozen=True, slots=True)
class SettledClaimedEngineAttempt:
    """A claimed attempt whose durable cleanup is already verified absent.

    Recovery may return the saved experiment without reopening external
    custody.  ``reconciliation_ref`` is present when the saved outcome was
    produced by an earlier recovery intent; live settlements legitimately
    have no recovery intent.
    """

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str
    claim_ref: str
    runtime_resolution_ref: str
    cleanup_evidence_ref: str
    reconciliation_ref: str | None

    def validate(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> None:
        _job(self.job_id)
        if self.job_state not in _CLAIMED_JOB_STATES:
            raise EngineReconciliationError("settled engine job is not terminal")
        for value, label in (
            (self.binding_digest, "engine reconciliation binding digest"),
            (self.delegation_digest, "engine reconciliation delegation digest"),
            (self.claim_ref, "engine execution claim reference"),
            (self.runtime_resolution_ref, "engine runtime resolution reference"),
            (self.cleanup_evidence_ref, "engine cleanup evidence reference"),
        ):
            _digest(value, label)
        if self.reconciliation_ref is not None:
            _digest(self.reconciliation_ref, "engine reconciliation reference")
        _validate_authority(
            binding_digest=self.binding_digest,
            delegation_digest=self.delegation_digest,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
        )


@dataclass(frozen=True, slots=True)
class UnclaimedEngineReconciliation:
    """Pinned terminal history with no claim and therefore unknown custody.

    This value is deliberately not absence proof.  It creates no reconciliation
    intent and cannot authorize an attempt factory or runtime call.
    """

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str

    def validate(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> None:
        _job(self.job_id)
        if self.job_state not in _UNCLAIMED_JOB_STATES:
            raise EngineReconciliationError("unclaimed engine job is not recoverable")
        _digest(self.binding_digest, "engine reconciliation binding digest")
        _digest(self.delegation_digest, "engine reconciliation delegation digest")
        _validate_authority(
            binding_digest=self.binding_digest,
            delegation_digest=self.delegation_digest,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
        )


@dataclass(frozen=True, slots=True)
class SettledNoDispatchEngineAttempt:
    """Durable proof that the callback settled before claim or custody.

    The attempt is already CANCELLED with VERIFIED_ABSENT cleanup and retains
    an exact cleanup evidence reference. Recovery returns that saved experiment
    idempotently; it must not create an intent, call a runtime, or rewrite
    cleanup. Only the three controller-owned pre-effect outcomes are admitted.
    """

    job_id: str
    job_state: str
    binding_digest: str
    delegation_digest: str
    exit_reason: str
    cleanup_evidence_ref: str

    def validate(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> None:
        _job(self.job_id)
        if self.job_state not in _UNCLAIMED_JOB_STATES:
            raise EngineReconciliationError("pre-dispatch cancellation job is not recoverable")
        _digest(self.binding_digest, "engine reconciliation binding digest")
        _digest(self.delegation_digest, "engine reconciliation delegation digest")
        if self.exit_reason not in {
            "authority_expired_before_dispatch",
            "controller_cancelled_before_dispatch",
            "controller_cancelled_before_execution_claim",
        }:
            raise EngineReconciliationError("settled no-dispatch engine outcome is invalid")
        _digest(self.cleanup_evidence_ref, "engine no-dispatch cleanup reference")
        _validate_authority(
            binding_digest=self.binding_digest,
            delegation_digest=self.delegation_digest,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
        )


EngineReconciliationPlan: TypeAlias = (
    ClaimedEngineReconciliation
    | SettledClaimedEngineAttempt
    | SettledNoDispatchEngineAttempt
    | UnclaimedEngineReconciliation
)


class EngineReconciliationSession(Protocol):
    """A purpose lock held from fresh snapshot through the final store CAS."""

    @property
    def reconciliation_capability(self) -> object:
        """Return the nonserializable ProductStore-issued active-session proof."""

        ...

    def begin_or_reopen(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        expected_revision: int,
        expected_experiment_digest: str,
    ) -> EngineReconciliationPlan:
        """Recheck the fresh snapshot and create/reopen its exact recovery intent."""

        ...


class EngineReconciliationCoordinator(Protocol):
    """Open one fixed-purpose recovery session over the pinned ProductStore."""

    def session(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
    ) -> AbstractContextManager[EngineReconciliationSession]: ...


__all__ = [
    "ClaimedEngineReconciliation",
    "EngineReconciliationCoordinator",
    "EngineReconciliationError",
    "EngineReconciliationPlan",
    "EngineReconciliationSession",
    "SettledClaimedEngineAttempt",
    "SettledNoDispatchEngineAttempt",
    "UnclaimedEngineReconciliation",
]
