"""Trusted bridge from an admitted engine attempt to the pinned Strix worker.

This module deliberately owns no provider, Docker, network, or target
implementation.  It accepts controller-owned collaborators only after their
exact receipts revalidate against the delegation.  Strix output remains an
engine assertion; independent target evidence and defensive changes are never
created here.

The bridge never retries a launch identity.  Recovery reads the durable worker
reservation/outcome and reconciles custody without calling ``run``.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .domain_errors import JobCancelled
from .engine_artifact_store import (
    MAX_SOURCE_TREE_ENTRIES,
    PUBLICATION_REF_SCHEMA,
    V2_MANIFEST_SCHEMA,
    EngineArtifactPublicationBinding,
    EngineArtifactPublicationUnknown,
    EngineArtifactStore,
    EngineArtifactStoreError,
    ReopenedEngineArtifactAttempt,
    SourceCollectionSeal,
    _is_reparse,
    _safe_name,
)
from .engine_attempt_contract import (
    AttemptCompleteness,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
    EngineEvidenceItem,
    EvidenceCategory,
)
from .engine_container_custody import ContainerCustodyPlan
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment import CleanupState
from .engine_experiment_jobs import EngineRuntimeSettlement, TransitionSink
from .engine_network_policy import (
    EffectiveNetworkSnapshot,
    EngineNetworkPlan,
    EngineNetworkVerification,
    VerificationState,
)
from .engine_worker_runtime import (
    EngineCleanupState,
    EngineExecutionState,
    EngineLaunchPlan,
    EngineResourceCustody,
    EngineWorkerOutcome,
    EngineWorkerRuntime,
    ResourceCustodySnapshot,
    ResourceCustodyState,
    read_launch_reservation,
    read_worker_outcome,
)
from .job_runtime import JobContext
from .strix_adapter import (
    StrixAttemptWorkspace,
    StrixBudgets,
    StrixBuildIdentity,
    StrixLaunchPlan,
    StrixModelGateway,
    StrixRuntimeLimits,
    StrixScope,
    build_launch_plan,
)
from .strix_run_bytes import StrixRunByteSnapshot, parse_strix_run_bytes
from .util import content_hash, parse_iso8601_datetime


class StrixEngineRuntimeError(RuntimeError):
    """The trusted runtime boundary could not prove an exact safe settlement."""


_OPTIONAL_STRIX_RUN_FILES = (
    "vulnerabilities.json",
    "vulnerabilities.csv",
    "penetration_test_report.md",
    "findings.sarif",
)


class ModelGatewayLease(Protocol):
    """Attempt-scoped credential held only in the trusted controller process.

    Revocation returns the stable receipt for this exact attempt, including
    when claimed recovery finishes the same revocation after an acknowledgement
    is lost.
    """

    @property
    def authorization_ref(self) -> str: ...

    def secret_value(self) -> str: ...

    def revoke(self) -> str: ...


class ModelGatewayCredentialProvider(Protocol):
    def acquire(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> ModelGatewayLease: ...

    def reconcile_revocation(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> str | None: ...

    def reconcile_revocation_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        reconciliation_ref: str,
        timeout_seconds: float,
    ) -> str | None:
        """Finish ref-fenced revocation without acquiring a lease.

        Return the same receipt as live ``ModelGatewayLease.revoke`` and every
        retry for the exact attempt, so cleanup evidence keeps one identity.
        """

        ...


class SourceCollectionController(Protocol):
    """Issue a seal only after process/container stop and write revocation."""

    def seal(
        self,
        *,
        attempt_id: str,
        source_run_dir: Path,
        worker_outcome: EngineWorkerOutcome,
    ) -> SourceCollectionSeal: ...

    def reconcile_seal(
        self,
        *,
        reconciliation_ref: str,
        attempt_id: str,
        source_run_dir: Path,
        worker_outcome: EngineWorkerOutcome | None,
        timeout_seconds: float,
    ) -> SourceCollectionSeal:
        """Ref-fenced process stop and source-write revocation, even without an outcome."""

        ...


class StrixRuntimeAdmissionResolver(Protocol):
    def resolve(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> "StrixRuntimeAdmission":
        """Read an accepted admission without launch or new resource allocation."""

        ...

    def resolve_for_launch(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> "StrixRuntimeAdmissionResolution": ...

    def require_current(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        expected_resolution_ref: str,
    ) -> "StrixRuntimeAdmissionResolution": ...


@dataclass(frozen=True, slots=True)
class ProcessContainmentReceipt:
    """Controller assertion that the outer worker boundary is effective.

    The receipt is not model-writable and is bound to the exact attempt,
    executable, network policy, container plan, and disposable boundary.
    """

    schema_version: str
    attempt_id: str
    binding_digest: str
    executable_sha256: str
    network_policy_digest: str
    custody_plan_digest: str
    protected_roots_digest: str
    disposable_boundary_ref: str
    supervisor_ref: str
    checked_at: str
    effective: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProcessContainmentReceipt":
        fields = frozenset(cls.__dataclass_fields__)
        if not isinstance(value, Mapping) or set(value) != fields:
            raise StrixEngineRuntimeError("process containment receipt fields changed")
        receipt = cls(**{field: value[field] for field in cls.__dataclass_fields__})
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-process-containment.v1":
            raise StrixEngineRuntimeError("process containment receipt version is unsupported")
        _adapter_attempt_id(self.attempt_id)
        for value, label in (
            (self.binding_digest, "binding"),
            (self.executable_sha256, "executable"),
            (self.network_policy_digest, "network policy"),
            (self.custody_plan_digest, "custody plan"),
            (self.protected_roots_digest, "protected roots"),
            (self.disposable_boundary_ref, "disposable boundary"),
            (self.supervisor_ref, "supervisor"),
        ):
            _require_digest(value, f"process containment {label}")
        _require_timestamp(self.checked_at, "process containment check time")
        if self.effective is not True:
            raise StrixEngineRuntimeError("process containment is not effective")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProtectedRuntimeRootsReceipt:
    """External verifier assertion for roots the engine must not control."""

    schema_version: str
    attempt_id: str
    workspace_root_digest: str
    control_root_digest: str
    artifact_root_digest: str
    verifier_ref: str
    checked_at: str
    control_root_protected: bool
    artifact_root_protected: bool
    engine_control_write_denied: bool
    engine_artifact_write_denied: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProtectedRuntimeRootsReceipt":
        fields = frozenset(cls.__dataclass_fields__)
        if not isinstance(value, Mapping) or set(value) != fields:
            raise StrixEngineRuntimeError("protected runtime root receipt fields changed")
        receipt = cls(**{field: value[field] for field in cls.__dataclass_fields__})
        receipt.validate()
        return receipt

    def validate(self) -> None:
        if self.schema_version != "bluefire.engine-protected-runtime-roots.v1":
            raise StrixEngineRuntimeError("protected runtime root receipt version is unsupported")
        _adapter_attempt_id(self.attempt_id)
        for value, label in (
            (self.workspace_root_digest, "workspace root"),
            (self.control_root_digest, "control root"),
            (self.artifact_root_digest, "artifact root"),
            (self.verifier_ref, "root verifier"),
        ):
            _require_digest(value, label)
        _require_timestamp(self.checked_at, "protected root check time")
        if (
            self.control_root_protected is not True
            or self.artifact_root_protected is not True
            or self.engine_control_write_denied is not True
            or self.engine_artifact_write_denied is not True
        ):
            raise StrixEngineRuntimeError("controller roots are not externally protected")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class StrixRuntimeAdmission:
    """Controller-resolved inputs for one exact already-authorized attempt."""

    objective_ref: str
    environment_ref: str
    runtime_qualification_ref: str
    runtime_qualified: bool
    build: StrixBuildIdentity
    scope: StrixScope
    gateway: StrixModelGateway
    budgets: StrixBudgets
    limits: StrixRuntimeLimits
    workspace: StrixAttemptWorkspace
    executable: Path
    path_environment: str
    control_root: Path
    network_plan: EngineNetworkPlan
    network_snapshot: EffectiveNetworkSnapshot
    network_verification: EngineNetworkVerification
    custody_plan: ContainerCustodyPlan
    protected_roots: ProtectedRuntimeRootsReceipt
    containment: ProcessContainmentReceipt
    custody: EngineResourceCustody


@dataclass(frozen=True, slots=True)
class StrixRuntimeAdmissionResolution:
    """One opaque, controller-bound view of an already persisted admission."""

    admission: StrixRuntimeAdmission
    resolution_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.admission, StrixRuntimeAdmission):
            raise StrixEngineRuntimeError("Strix runtime resolution admission is invalid")
        _require_digest(self.resolution_ref, "Strix runtime resolution")


@dataclass(frozen=True, slots=True)
class _PreparedAdmission:
    admission: StrixRuntimeAdmission
    strix_plan: StrixLaunchPlan
    network_plan: EngineNetworkPlan
    network_verification: EngineNetworkVerification
    custody_plan: ContainerCustodyPlan
    containment: ProcessContainmentReceipt
    launch_plan_digest: str
    resolution_ref: str


@dataclass(frozen=True, slots=True)
class _ArtifactResult:
    manifest_ref: str | None
    evidence: tuple[EngineEvidenceItem, ...]
    seal_ref: str | None
    limitation: str | None


_RECOVERY_BUDGET_SECONDS = 15.0


class StrixEngineRuntime:
    """Implement ``EngineAttemptRuntime`` without adding execution authority."""

    def __init__(
        self,
        *,
        resolver: StrixRuntimeAdmissionResolver,
        worker: EngineWorkerRuntime,
        artifact_store: EngineArtifactStore,
        credential_provider: ModelGatewayCredentialProvider,
        source_controller: SourceCollectionController,
        clock: Callable[[], str],
        expected_claim_ref: str,
        expected_resolution_ref: str,
        expected_launch_digest: str | None = None,
    ) -> None:
        _require_digest(expected_claim_ref, "expected execution claim")
        _require_digest(expected_resolution_ref, "expected Strix runtime resolution")
        if expected_launch_digest is not None:
            _require_digest(expected_launch_digest, "expected claim-bound launch")
        self._resolver = resolver
        self._worker = worker
        self._artifact_store = artifact_store
        self._credentials = credential_provider
        self._source_controller = source_controller
        self._clock = clock
        self._expected_resolution_ref = expected_resolution_ref
        self._expected_claim_ref = expected_claim_ref
        self._expected_launch_digest = expected_launch_digest

    def execute(
        self,
        context: JobContext,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        transition: TransitionSink,
    ) -> EngineRuntimeSettlement:
        checked_binding, checked_delegation, prepared = self._prepare(binding, delegation)
        preflight = EngineAttemptRecord.create(checked_binding).transition(AttemptState.PREFLIGHT)
        session_started_at = _require_timestamp(self._clock(), "Strix session start time")
        running = preflight.transition(
            AttemptState.RUNNING,
            upstream_session_id=_adapter_attempt_id(checked_binding.attempt_id),
            timestamp=session_started_at,
        )
        try:
            transition(running, session_started_at)
        except JobCancelled:
            ended_at = _require_timestamp(self._clock(), "Strix cancellation time")
            terminal = running.transition(
                AttemptState.CANCELLED,
                timestamp=ended_at,
                completeness=AttemptCompleteness.UNKNOWN,
                exit_reason="controller_cancelled_before_launch",
                limitations=("External-engine process launch did not begin.",),
            )
            return EngineRuntimeSettlement(
                record=terminal,
                engine_evidence=(),
                artifact_manifest_ref=None,
                cleanup_state=CleanupState.VERIFIED_ABSENT,
                cleanup_evidence_ref=content_hash(
                    {
                        "schema_version": "bluefire.strix-prelaunch-cancellation.v1",
                        "binding_digest": checked_binding.binding_digest,
                        "launch_plan_digest": prepared.launch_plan_digest,
                        "recorded_at": ended_at,
                    }
                ),
                settled_at=ended_at,
            )

        if not self._launch_resolution_is_current(
            checked_binding,
            checked_delegation,
            expected_resolution_ref=prepared.resolution_ref,
        ):
            return self._prelaunch_authority_failure(
                checked_binding,
                prepared,
                running,
                credential_lease_acquired=False,
                revocation_ref=None,
            )
        lease = self._credentials.acquire(checked_binding, checked_delegation)
        revocation_ref: str | None = None
        launch: EngineLaunchPlan | None = None
        outcome: EngineWorkerOutcome | None = None
        authority_changed = False
        try:
            # This closes the credential-acquisition window with a fresh
            # fail-closed reread.  It is not an atomic claim over OS launch.
            if not self._launch_resolution_is_current(
                checked_binding,
                checked_delegation,
                expected_resolution_ref=prepared.resolution_ref,
            ):
                authority_changed = True
            else:
                secret = _gateway_secret(lease, checked_binding.model_authorization_ref)
                launch = self._worker_plan(prepared, checked_binding, secret)
                outcome = self._worker.run(
                    launch,
                    cancellation=context.cancellation_event,
                    custody=prepared.admission.custody,
                )
        finally:
            try:
                revocation_ref = _require_digest(lease.revoke(), "model gateway revocation receipt")
            except (OSError, RuntimeError, TypeError, ValueError):
                revocation_ref = None
        if authority_changed:
            return self._prelaunch_authority_failure(
                checked_binding,
                prepared,
                running,
                credential_lease_acquired=True,
                revocation_ref=revocation_ref,
            )
        if launch is None or outcome is None:
            raise StrixEngineRuntimeError("Strix launch outcome is unavailable")
        retained_reservation = read_launch_reservation(
            prepared.admission.control_root, checked_binding.attempt_id
        )
        retained_outcome = read_worker_outcome(
            prepared.admission.control_root, checked_binding.attempt_id
        )
        if not _reservation_matches(
            retained_reservation,
            launch.public_launch_receipt(),
            not_before=running.started_at,
            not_after=outcome.completed_at,
        ) or (retained_outcome is None or retained_outcome.to_dict() != outcome.to_dict()):
            return self._persistence_unknown(
                checked_binding,
                prepared,
                running,
                outcome,
                revocation_ref=revocation_ref,
            )
        return self._settlement(
            checked_binding,
            checked_delegation,
            prepared,
            running,
            outcome,
            revocation_ref=revocation_ref,
        )

    def _launch_resolution_is_current(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        *,
        expected_resolution_ref: str,
    ) -> bool:
        try:
            current = self._resolver.require_current(
                binding,
                delegation,
                expected_resolution_ref=expected_resolution_ref,
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return False
        return (
            isinstance(current, StrixRuntimeAdmissionResolution)
            and current.resolution_ref == expected_resolution_ref
            and current.admission.runtime_qualified is True
        )

    def _prelaunch_authority_failure(
        self,
        binding: EngineAttemptBinding,
        prepared: _PreparedAdmission,
        running: EngineAttemptRecord,
        *,
        credential_lease_acquired: bool,
        revocation_ref: str | None,
    ) -> EngineRuntimeSettlement:
        ended_at = _require_timestamp(self._clock(), "Strix authority refusal time")
        limitations = [
            "Runtime authority or the exact saved admission changed before launch; "
            "external-engine process launch did not begin."
        ]
        if credential_lease_acquired and revocation_ref is None:
            limitations.append("Model gateway credential revocation is unverified.")
        terminal = running.transition(
            AttemptState.FAILED,
            timestamp=ended_at,
            completeness=AttemptCompleteness.UNKNOWN,
            exit_reason="runtime_authority_changed_before_launch",
            limitations=tuple(limitations),
        )
        return EngineRuntimeSettlement(
            record=terminal,
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=content_hash(
                {
                    "schema_version": "bluefire.strix-prelaunch-authority-refusal.v1",
                    "binding_digest": binding.binding_digest,
                    "launch_plan_digest": prepared.launch_plan_digest,
                    "resolution_ref": prepared.resolution_ref,
                    "credential_lease_acquired": credential_lease_acquired,
                    "gateway_revocation_ref": revocation_ref,
                    "recorded_at": ended_at,
                }
            ),
            settled_at=ended_at,
        )

    def _persistence_unknown(
        self,
        binding: EngineAttemptBinding,
        prepared: _PreparedAdmission,
        running: EngineAttemptRecord,
        outcome: EngineWorkerOutcome,
        *,
        revocation_ref: str | None,
    ) -> EngineRuntimeSettlement:
        self._stop_external_custody(prepared)
        settled_at = _require_timestamp(outcome.completed_at, "Strix worker completion time")
        record = running.transition(
            AttemptState.UNKNOWN,
            timestamp=settled_at,
            completeness=AttemptCompleteness.UNKNOWN,
            exit_reason="worker_settlement_not_durable",
            limitations=(
                "The exact launch reservation and worker outcome were not retained; "
                "launch was not replayed and engine output was not imported.",
            ),
        )
        cleanup_ref = content_hash(
            {
                "schema_version": "bluefire.strix-worker-persistence-unknown.v1",
                "attempt_id": binding.attempt_id,
                "binding_digest": binding.binding_digest,
                "launch_plan_digest": prepared.launch_plan_digest,
                "returned_outcome_digest": content_hash(outcome.to_dict()),
                "gateway_revocation_ref": revocation_ref,
                "recorded_at": settled_at,
            }
        )
        return EngineRuntimeSettlement(
            record=record,
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref=cleanup_ref,
            settled_at=settled_at,
        )

    def reconcile(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> EngineRuntimeSettlement:
        """Historical v1 entry point cannot settle an installed claimed attempt."""

        del binding, delegation, saved_record
        raise StrixEngineRuntimeError(
            "Strix recovery requires an exact claimed reconciliation reference"
        )

    def reconcile_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        *,
        reconciliation_ref: str,
    ) -> EngineRuntimeSettlement:
        """Reopen exact v2 bytes and ref-fenced custody without launch authority."""

        _require_digest(reconciliation_ref, "claimed reconciliation")
        checked_delegation = EngineCapabilityDelegation.from_mapping(delegation.to_dict())
        checked_binding = checked_delegation.validate_attempt_binding(binding)
        saved = EngineAttemptRecord.from_mapping(saved_record.to_dict())
        if (
            saved.binding != checked_binding
            or saved.binding_digest != checked_binding.binding_digest
        ):
            raise StrixEngineRuntimeError("saved Strix attempt binding changed")

        # A final publication is inspected before any saved source admission.
        # A partial publication remains untouched through every retry.
        publication_issue: str | None = None
        try:
            reopened = self._artifact_store.reopen_attempt(checked_binding.attempt_id)
        except EngineArtifactPublicationUnknown:
            reopened = None
            publication_issue = "artifact_publication_pending"
        except EngineArtifactStoreError as exc:
            reopened = None
            publication_issue = (
                "artifact_publication_missing"
                if str(exc) == "artifact publication is unavailable"
                else "artifact_publication_invalid"
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            reopened = None
            publication_issue = "artifact_publication_invalid"
        if reopened is None and publication_issue is None:
            publication_issue = "artifact_publication_invalid"
        if reopened is not None and (
            not isinstance(reopened, ReopenedEngineArtifactAttempt)
            or not reopened.recovery_eligible
            or reopened.schema_version != V2_MANIFEST_SCHEMA
        ):
            reopened = None
            publication_issue = "artifact_publication_legacy_or_invalid"

        deadline = time.monotonic() + _RECOVERY_BUDGET_SECONDS
        revoke = getattr(self._credentials, "reconcile_revocation_claimed", None)
        revocation_ref: str | None = None
        effect_issue: str | None = None
        if callable(revoke):
            try:
                revocation_ref = _require_digest(
                    revoke(
                        checked_binding,
                        checked_delegation,
                        reconciliation_ref=reconciliation_ref,
                        timeout_seconds=_remaining_recovery_budget(deadline),
                    ),
                    "claimed model gateway revocation receipt",
                )
                _remaining_recovery_budget(deadline)
            except (OSError, RuntimeError, TypeError, ValueError):
                effect_issue = "ref_fenced_revocation_unavailable"
        else:
            effect_issue = "missing_ref_fenced_revocation_adapter"

        # resolve() only reopens the saved admission. It does not issue launch
        # authority or allocate a worker, credential, or listener.
        try:
            admission = self._resolver.resolve(checked_binding, checked_delegation)
            if not isinstance(admission, StrixRuntimeAdmission):
                raise StrixEngineRuntimeError("claimed recovery admission is invalid")
            custody_plan = ContainerCustodyPlan.from_mapping(admission.custody_plan.to_dict())
            if (
                admission.objective_ref != checked_binding.objective_ref
                or admission.environment_ref != checked_binding.environment_ref
                or admission.workspace.attempt_id != _adapter_attempt_id(checked_binding.attempt_id)
                or admission.scope.target_snapshot_digest != checked_binding.target_snapshot_ref
                or admission.scope.scope_digest != checked_binding.scope_ref
                or custody_plan.attempt_id != checked_binding.attempt_id
                or custody_plan.plan_digest != checked_delegation.custody_plan_digest
                or custody_plan.network_policy_digest != checked_delegation.network_policy_digest
            ):
                raise StrixEngineRuntimeError("claimed recovery admission changed")
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "recovery_admission_unavailable",
            )

        # Receipt damage must not bypass stop and source-write revocation.
        reservation: Mapping[str, Any] | None = None
        outcome: EngineWorkerOutcome | None = None
        receipt_issue: str | None = None
        try:
            reservation = read_launch_reservation(
                admission.control_root, checked_binding.attempt_id
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            receipt_issue = "launch_reservation_unavailable"
        try:
            outcome = read_worker_outcome(admission.control_root, checked_binding.attempt_id)
        except (OSError, RuntimeError, TypeError, ValueError):
            receipt_issue = receipt_issue or "worker_outcome_unavailable"

        stop = getattr(admission.custody, "reconcile_stop_owned", None)
        source_revoke = getattr(self._source_controller, "reconcile_seal", None)
        custody: ResourceCustodySnapshot | None = None
        seal: SourceCollectionSeal | None = None
        if callable(stop):
            try:
                custody = stop(
                    checked_binding.attempt_id,
                    reconciliation_ref=reconciliation_ref,
                    custody_identity_digest=custody_plan.plan_digest,
                    network_policy_digest=checked_delegation.network_policy_digest,
                    timeout_seconds=_remaining_recovery_budget(deadline),
                )
                _remaining_recovery_budget(deadline)
            except (OSError, RuntimeError, TypeError, ValueError):
                effect_issue = effect_issue or "ref_fenced_custody_stop_unavailable"
        else:
            effect_issue = effect_issue or "missing_ref_fenced_custody_adapter"
        if reopened is None:
            if callable(source_revoke):
                try:
                    seal = source_revoke(
                        reconciliation_ref=reconciliation_ref,
                        attempt_id=checked_binding.attempt_id,
                        source_run_dir=admission.workspace.cwd,
                        worker_outcome=outcome,
                        timeout_seconds=_remaining_recovery_budget(deadline),
                    )
                    seal.to_dict()
                    _remaining_recovery_budget(deadline)
                    if (
                        seal.attempt_id != checked_binding.attempt_id
                        or seal.worker_state != "stopped"
                        or seal.write_access_revoked is not True
                    ):
                        raise StrixEngineRuntimeError("claimed source revocation is unverified")
                except (
                    AttributeError,
                    EngineArtifactStoreError,
                    OSError,
                    RuntimeError,
                    TypeError,
                    ValueError,
                ):
                    effect_issue = effect_issue or "ref_fenced_source_revocation_unavailable"
                    seal = None
            else:
                effect_issue = effect_issue or "missing_ref_fenced_source_revocation_adapter"

        if receipt_issue is not None:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                receipt_issue,
                outcome=outcome,
            )
        if publication_issue is not None and publication_issue != "artifact_publication_missing":
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                publication_issue,
                outcome=outcome,
            )
        if outcome is None or outcome.attempt_id != checked_binding.attempt_id:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                effect_issue or "worker_outcome_unavailable",
                outcome=outcome,
            )
        if (
            effect_issue is not None
            or revocation_ref is None
            or not isinstance(custody, ResourceCustodySnapshot)
            or custody.state is not ResourceCustodyState.VERIFIED_ABSENT
            or _cleanup_state(outcome, revocation_ref) is not CleanupState.VERIFIED_ABSENT
        ):
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                effect_issue or "process_or_external_custody_unverified",
                outcome=outcome,
            )
        launch_digest = _retained_launch_digest(
            reservation,
            binding=checked_binding,
            delegation=checked_delegation,
            not_before=saved.started_at or checked_delegation.created_at,
            not_after=outcome.completed_at,
        )
        if launch_digest is None:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "launch_identity_unavailable",
                outcome=outcome,
            )
        if (
            self._expected_launch_digest is not None
            and launch_digest != self._expected_launch_digest
        ):
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "claim_bound_launch_identity_changed",
                outcome=outcome,
            )
        if reopened is None and self._expected_launch_digest is None:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "missing_claim_bound_launch_receipt_for_new_publication",
                outcome=outcome,
            )
        expected_publication_binding = EngineArtifactPublicationBinding(
            attempt_id=checked_binding.attempt_id,
            binding_digest=checked_binding.binding_digest,
            delegation_digest=checked_delegation.delegation_digest,
            launch_digest=launch_digest,
            runtime_resolution_ref=self._expected_resolution_ref,
            execution_claim_ref=self._expected_claim_ref,
            worker_outcome_digest=content_hash(outcome.to_dict()),
        )
        if reopened is not None and reopened.publication_binding != expected_publication_binding:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "artifact_publication_binding_changed",
                outcome=outcome,
            )
        if reopened is None:
            if seal is None:
                return self._claimed_unknown(
                    checked_binding,
                    checked_delegation,
                    saved,
                    reconciliation_ref,
                    "ref_fenced_source_revocation_unavailable",
                    outcome=outcome,
                )
            try:
                names = _source_artifact_selection(
                    admission.workspace.cwd,
                    max_files=self._artifact_store.max_files,
                    max_file_bytes=self._artifact_store.max_file_bytes,
                )
                reopened = self._artifact_store.import_or_reopen(
                    attempt_id=checked_binding.attempt_id,
                    source_run_dir=admission.workspace.cwd,
                    source_seal=seal,
                    allowed_names=names,
                    publication_binding=expected_publication_binding,
                )
                _remaining_recovery_budget(deadline)
            except (EngineArtifactStoreError, OSError, RuntimeError, TypeError, ValueError):
                return self._claimed_unknown(
                    checked_binding,
                    checked_delegation,
                    saved,
                    reconciliation_ref,
                    "artifact_recovery_unavailable",
                    outcome=outcome,
                )
        try:
            snapshot, artifacts = _reopened_artifact_result(
                reopened,
                expected_binding=expected_publication_binding,
                expected_target=admission.scope.target,
                expected_instruction_sha256=admission.workspace.objective_sha256,
                outcome=outcome,
                run_id=checked_binding.run_id,
                max_file_bytes=self._artifact_store.max_file_bytes,
                max_total_bytes=self._artifact_store.max_total_bytes,
                max_files=self._artifact_store.max_files,
            )
        except (EngineArtifactStoreError, OSError, RuntimeError, TypeError, ValueError):
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "retained_strix_bytes_invalid",
                outcome=outcome,
            )
        if saved.state in _TERMINAL_STATES:
            projected_state, projected_completeness, projected_reason = _terminal_projection(
                outcome, snapshot
            )
            if (
                not _terminal_outcome_matches(saved, outcome)
                or saved.state is not projected_state
                or saved.completeness is not projected_completeness
                or saved.exit_reason != projected_reason
            ):
                return self._claimed_unknown(
                    checked_binding,
                    checked_delegation,
                    saved,
                    reconciliation_ref,
                    "saved_terminal_outcome_changed",
                    outcome=outcome,
                )
            return EngineRuntimeSettlement(
                record=saved,
                engine_evidence=artifacts.evidence,
                artifact_manifest_ref=artifacts.manifest_ref,
                cleanup_state=CleanupState.VERIFIED_ABSENT,
                cleanup_evidence_ref=_v2_cleanup_receipt(
                    checked_binding,
                    checked_delegation,
                    launch_digest,
                    self._expected_resolution_ref,
                    self._expected_claim_ref,
                    outcome,
                    revocation_ref,
                    artifacts.seal_ref,
                    artifacts.manifest_ref,
                    CleanupState.VERIFIED_ABSENT,
                ),
                settled_at=outcome.completed_at,
                reconciliation_ref=reconciliation_ref,
            )
        if saved.state not in {AttemptState.RUNNING, AttemptState.STOPPING}:
            return self._claimed_unknown(
                checked_binding,
                checked_delegation,
                saved,
                reconciliation_ref,
                "recovery_session_not_durable",
                outcome=outcome,
            )
        return self._build_v2_settlement(
            checked_binding,
            checked_delegation,
            saved,
            outcome,
            snapshot=snapshot,
            artifact_result=artifacts,
            snapshot_limitation=None,
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            revocation_ref=revocation_ref,
            launch_digest=launch_digest,
            resolution_ref=self._expected_resolution_ref,
            reconciliation_ref=reconciliation_ref,
        )

    def _claimed_unknown(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved: EngineAttemptRecord,
        reconciliation_ref: str,
        issue: str,
        *,
        outcome: EngineWorkerOutcome | None = None,
    ) -> EngineRuntimeSettlement:
        settled_at = saved.ended_at or (
            outcome.completed_at
            if outcome is not None
            else saved.started_at or delegation.created_at
        )
        limitation = {
            "artifact_publication_pending": (
                "A partial artifact publication remains untouched; claimed cleanup is unverified."
            ),
            "missing_ref_fenced_revocation_or_custody_adapter": (
                "Claimed recovery requires reconcile_revocation_claimed and "
                "reconcile_stop_owned adapters fenced by the reconciliation reference."
            ),
            "missing_ref_fenced_source_revocation_adapter": (
                "Claimed recovery requires a reconcile_seal adapter that proves process stop "
                "and source write revocation."
            ),
            "missing_claim_bound_launch_receipt_for_new_publication": (
                "New recovery publication requires an exact claim-bound launch digest."
            ),
        }.get(issue, "Claimed Strix recovery could not verify stopped custody or exact bytes.")
        if saved.state in _TERMINAL_STATES:
            record = saved
        else:
            state = (
                AttemptState.UNKNOWN
                if saved.state in {AttemptState.RUNNING, AttemptState.STOPPING}
                else AttemptState.FAILED
            )
            record = saved.transition(
                state,
                timestamp=settled_at,
                completeness=AttemptCompleteness.UNKNOWN,
                exit_reason="claimed_recovery_unverified",
                limitations=(limitation,),
            )
        return EngineRuntimeSettlement(
            record=record,
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref=content_hash(
                {
                    "schema_version": "bluefire.strix-claimed-recovery-unknown.v1",
                    "binding_digest": binding.binding_digest,
                    "delegation_digest": delegation.delegation_digest,
                    "execution_claim_ref": self._expected_claim_ref,
                    "runtime_resolution_ref": self._expected_resolution_ref,
                    "reconciliation_ref": reconciliation_ref,
                    "worker_outcome_digest": None
                    if outcome is None
                    else content_hash(outcome.to_dict()),
                    "issue": issue,
                }
            ),
            settled_at=settled_at,
            reconciliation_ref=reconciliation_ref,
        )

    def _prepare(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> tuple[EngineAttemptBinding, EngineCapabilityDelegation, _PreparedAdmission]:
        if (
            not callable(getattr(self._source_controller, "seal", None))
            or not callable(getattr(self._source_controller, "reconcile_seal", None))
            or not callable(getattr(self._credentials, "reconcile_revocation_claimed", None))
            or not callable(getattr(self._artifact_store, "import_or_reopen", None))
            or not callable(getattr(self._artifact_store, "reopen_attempt", None))
        ):
            raise StrixEngineRuntimeError(
                "claimed Strix execution requires v2 artifact intake, source revocation, "
                "and ref-fenced credential recovery adapters"
            )
        checked_delegation = EngineCapabilityDelegation.from_mapping(delegation.to_dict())
        checked_binding = checked_delegation.validate_attempt_binding(binding)
        resolution = self._resolver.resolve_for_launch(checked_binding, checked_delegation)
        if not isinstance(resolution, StrixRuntimeAdmissionResolution):
            raise StrixEngineRuntimeError("Strix runtime resolution is invalid")
        if (
            self._expected_resolution_ref is not None
            and resolution.resolution_ref != self._expected_resolution_ref
        ):
            raise StrixEngineRuntimeError(
                "Strix runtime resolution differs from the accepted execution claim"
            )
        admission = resolution.admission
        if not isinstance(admission, StrixRuntimeAdmission):
            raise StrixEngineRuntimeError("Strix runtime admission is invalid")
        if not callable(getattr(admission.custody, "reconcile_stop_owned", None)):
            raise StrixEngineRuntimeError(
                "claimed Strix execution requires ref-fenced external custody recovery"
            )
        if (
            admission.objective_ref != checked_binding.objective_ref
            or admission.environment_ref != checked_binding.environment_ref
        ):
            raise StrixEngineRuntimeError("Strix runtime admission belongs to another objective")
        _require_digest(admission.runtime_qualification_ref, "runtime qualification")
        if admission.runtime_qualified is not True:
            raise StrixEngineRuntimeError("exact Strix runtime candidate is not qualified")
        if not isinstance(admission.executable, Path) or not isinstance(
            admission.control_root, Path
        ):
            raise StrixEngineRuntimeError("Strix runtime paths are invalid")
        build = StrixBuildIdentity(
            **{
                field: getattr(admission.build, field)
                for field in admission.build.__dataclass_fields__
            }
        )
        scope = StrixScope(
            target=admission.scope.target,
            resolved_addresses=admission.scope.resolved_addresses,
            target_snapshot_digest=admission.scope.target_snapshot_digest,
            scope_digest=admission.scope.scope_digest,
            network_policy_digest=admission.scope.network_policy_digest,
            network_name=admission.scope.network_name,
        )
        gateway = StrixModelGateway(
            model=admission.gateway.model,
            base_url=admission.gateway.base_url,
            authorization_digest=admission.gateway.authorization_digest,
        )
        budgets = StrixBudgets(
            wall_seconds=admission.budgets.wall_seconds,
            max_turns_per_agent=admission.budgets.max_turns_per_agent,
            max_model_cost_usd=admission.budgets.max_model_cost_usd,
        )
        limits = StrixRuntimeLimits(
            memory=admission.limits.memory,
            cpus=admission.limits.cpus,
            pids=admission.limits.pids,
            log_size=admission.limits.log_size,
            log_files=admission.limits.log_files,
        )
        if (
            checked_binding.engine_id != "strix"
            or checked_binding.engine_version != build.package_version
            or checked_binding.engine_revision != build.source_revision
            or checked_binding.engine_package_digest != build.package_sha256
            or checked_binding.policy_overlay_digest != build.prompt_overlay_sha256
        ):
            raise StrixEngineRuntimeError("Strix build identity differs from the delegation")
        if (
            gateway.model != checked_binding.model_id
            or gateway.base_url != checked_binding.model_data_destination
            or gateway.authorization_digest != checked_binding.model_authorization_ref
        ):
            raise StrixEngineRuntimeError("Strix model gateway differs from the delegation")
        if (
            scope.target_snapshot_digest != checked_binding.target_snapshot_ref
            or scope.scope_digest != checked_binding.scope_ref
            or scope.network_policy_digest != checked_delegation.network_policy_digest
        ):
            raise StrixEngineRuntimeError("Strix target scope differs from the delegation")
        if budgets.wall_seconds != checked_binding.wall_clock_seconds:
            raise StrixEngineRuntimeError("Strix wall-clock budget differs from the delegation")
        if budgets.max_turns_per_agent != checked_binding.action_limit:
            raise StrixEngineRuntimeError("Strix action budget differs from the delegation")
        try:
            exact_cost_microunits = Decimal(budgets.max_model_cost_usd) * Decimal(1_000_000)
        except (InvalidOperation, ValueError) as exc:
            raise StrixEngineRuntimeError("Strix cost budget is invalid") from exc
        cost_microunits = int(exact_cost_microunits)
        if exact_cost_microunits != Decimal(cost_microunits):
            raise StrixEngineRuntimeError("Strix cost budget exceeds microunit precision")
        if cost_microunits != checked_binding.cost_limit_microunits:
            raise StrixEngineRuntimeError("Strix cost budget differs from the delegation")
        if (
            self._artifact_store.max_total_bytes > checked_binding.artifact_byte_limit
            or self._artifact_store.max_file_bytes > checked_binding.artifact_byte_limit
        ):
            raise StrixEngineRuntimeError("artifact intake exceeds the delegated byte limit")
        if admission.workspace.attempt_id != _adapter_attempt_id(checked_binding.attempt_id):
            raise StrixEngineRuntimeError("Strix workspace belongs to another attempt")

        network_plan = EngineNetworkPlan.from_mapping(admission.network_plan.to_dict())
        network_snapshot = EffectiveNetworkSnapshot.from_mapping(
            admission.network_snapshot.to_dict()
        )
        network_verification = EngineNetworkVerification.from_mapping(
            admission.network_verification.to_dict(),
            plan=network_plan,
            snapshot=network_snapshot,
        )
        if (
            network_plan.attempt_id != checked_binding.attempt_id
            or network_plan.policy_digest != checked_delegation.network_policy_digest
            or network_verification.state is not VerificationState.VERIFIED
            or scope.network_name != network_plan.network_name
            or scope.origin != network_plan.target.origin
            or scope.resolved_addresses != (network_plan.target.address,)
            or gateway.base_url != network_plan.model_gateway.origin + "/v1"
        ):
            raise StrixEngineRuntimeError("effective Strix network is outside the delegation")
        checked_at = parse_iso8601_datetime(network_verification.checked_at)
        plan_created_at = parse_iso8601_datetime(network_plan.created_at)
        snapshot_captured_at = parse_iso8601_datetime(network_snapshot.captured_at)
        delegation_created_at = parse_iso8601_datetime(checked_delegation.created_at)
        delegation_expires_at = parse_iso8601_datetime(checked_delegation.expires_at)
        if not (
            plan_created_at <= snapshot_captured_at
            and delegation_created_at <= snapshot_captured_at <= checked_at < delegation_expires_at
        ):
            raise StrixEngineRuntimeError("Strix network proof is stale for this delegation")

        custody_plan = ContainerCustodyPlan.from_mapping(admission.custody_plan.to_dict())
        if (
            custody_plan.attempt_id != checked_binding.attempt_id
            or custody_plan.plan_digest != checked_delegation.custody_plan_digest
            or custody_plan.network_policy_digest != checked_delegation.network_policy_digest
        ):
            raise StrixEngineRuntimeError("Strix container custody differs from the delegation")
        if (
            _image_reference_digest(build.image_reference) != custody_plan.sandbox_image_digest
            or _docker_memory_bytes(limits.memory) != custody_plan.memory_bytes
            or _docker_nano_cpus(limits.cpus) != custody_plan.nano_cpus
            or limits.pids != custody_plan.pids_limit
        ):
            raise StrixEngineRuntimeError("Strix sandbox resources differ from container custody")

        protected_roots = ProtectedRuntimeRootsReceipt.from_mapping(
            admission.protected_roots.to_dict()
        )
        workspace_root = _resolved_root(admission.workspace.cwd, "Strix workspace root")
        control_root = _resolved_root(admission.control_root, "Strix controller root")
        artifact_root = _resolved_root(self._artifact_store.root, "Strix artifact root")
        roots = (workspace_root, control_root, artifact_root)
        if any(
            left == right or left.is_relative_to(right) or right.is_relative_to(left)
            for index, left in enumerate(roots)
            for right in roots[index + 1 :]
        ):
            raise StrixEngineRuntimeError("Strix runtime roots are not isolated")
        if (
            protected_roots.attempt_id != checked_binding.attempt_id
            or protected_roots.workspace_root_digest != _root_digest(workspace_root)
            or protected_roots.control_root_digest != _root_digest(control_root)
            or protected_roots.artifact_root_digest != _root_digest(artifact_root)
        ):
            raise StrixEngineRuntimeError("Strix protected roots differ from the admission")
        roots_checked_at = parse_iso8601_datetime(protected_roots.checked_at)
        if not delegation_created_at <= roots_checked_at < delegation_expires_at:
            raise StrixEngineRuntimeError("Strix protected root proof is stale")

        containment = ProcessContainmentReceipt.from_mapping(admission.containment.to_dict())
        if (
            containment.attempt_id != checked_binding.attempt_id
            or containment.binding_digest != checked_binding.binding_digest
            or containment.executable_sha256 != build.executable_sha256
            or containment.network_policy_digest != checked_delegation.network_policy_digest
            or containment.custody_plan_digest != custody_plan.plan_digest
            or containment.protected_roots_digest != protected_roots.receipt_digest
            or containment.disposable_boundary_ref != custody_plan.disposable_boundary_ref
        ):
            raise StrixEngineRuntimeError("Strix process containment differs from the delegation")
        containment_checked = parse_iso8601_datetime(containment.checked_at)
        if not (
            parse_iso8601_datetime(checked_delegation.created_at)
            <= containment_checked
            < parse_iso8601_datetime(checked_delegation.expires_at)
        ):
            raise StrixEngineRuntimeError("Strix process containment proof is stale")

        strix_plan = build_launch_plan(
            build=build,
            scope=scope,
            gateway=gateway,
            budgets=budgets,
            limits=limits,
            workspace=admission.workspace,
            executable=admission.executable,
            path_environment=admission.path_environment,
        )
        launch_plan_digest = content_hash(
            {
                "schema_version": "bluefire.strix-worker-launch.v1",
                "binding_digest": checked_binding.binding_digest,
                "delegation_digest": checked_delegation.delegation_digest,
                "strix_intent_digest": strix_plan.intent_digest,
                "runtime_qualification_ref": admission.runtime_qualification_ref,
                "network_verification": content_hash(network_verification.to_dict()),
                "custody_plan": custody_plan.plan_digest,
                "protected_roots": protected_roots.receipt_digest,
                "process_containment": containment.receipt_digest,
            }
        )
        if (
            self._expected_launch_digest is not None
            and launch_plan_digest != self._expected_launch_digest
        ):
            raise StrixEngineRuntimeError("Strix launch differs from the accepted claim")
        return (
            checked_binding,
            checked_delegation,
            _PreparedAdmission(
                admission=admission,
                strix_plan=strix_plan,
                network_plan=network_plan,
                network_verification=network_verification,
                custody_plan=custody_plan,
                containment=containment,
                launch_plan_digest=launch_plan_digest,
                resolution_ref=resolution.resolution_ref,
            ),
        )

    def _worker_plan(
        self,
        prepared: _PreparedAdmission,
        binding: EngineAttemptBinding,
        gateway_secret: str,
    ) -> EngineLaunchPlan:
        environment = dict(prepared.strix_plan.environment)
        if "LLM_API_KEY" in environment:
            raise StrixEngineRuntimeError("Strix launch plan unexpectedly contains a secret")
        environment["LLM_API_KEY"] = gateway_secret
        return EngineLaunchPlan(
            attempt_id=binding.attempt_id,
            plan_digest=prepared.launch_plan_digest,
            argv=prepared.strix_plan.argv,
            environment=tuple(sorted(environment.items())),
            sensitive_environment_names=("LLM_API_KEY",),
            working_directory=prepared.admission.workspace.cwd,
            attempt_root=prepared.admission.workspace.cwd,
            control_root=prepared.admission.control_root,
            wall_time_seconds=prepared.strix_plan.wall_seconds,
            output_limit_bytes=max(
                1024,
                min(4 * 1024 * 1024, binding.artifact_byte_limit),
            ),
            requires_resource_custody=True,
            custody_identity_digest=prepared.custody_plan.plan_digest,
            network_policy_digest=prepared.network_plan.policy_digest,
        )

    def _settlement(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        prepared: _PreparedAdmission,
        base_record: EngineAttemptRecord,
        outcome: EngineWorkerOutcome,
        *,
        revocation_ref: str | None,
    ) -> EngineRuntimeSettlement:
        if outcome.attempt_id != binding.attempt_id:
            raise StrixEngineRuntimeError("worker outcome belongs to another attempt")
        cleanup_state = _cleanup_state(outcome, revocation_ref)
        if cleanup_state is CleanupState.VERIFIED_ABSENT and not self._custody_absent(
            prepared.admission.custody,
            attempt_id=binding.attempt_id,
            custody_plan_digest=prepared.custody_plan.plan_digest,
            network_policy_digest=prepared.network_plan.policy_digest,
        ):
            cleanup_state = CleanupState.UNKNOWN
        snapshot: StrixRunByteSnapshot | None = None
        snapshot_limitation: str | None = None
        artifact_result = _ArtifactResult(None, (), None, None)
        if (
            outcome.started
            and cleanup_state is CleanupState.VERIFIED_ABSENT
            and revocation_ref is not None
        ):
            snapshot, artifact_result = self._collect_artifacts(
                binding, delegation, prepared, outcome
            )
        if artifact_result.limitation is not None:
            snapshot_limitation = artifact_result.limitation

        return self._build_v2_settlement(
            binding,
            delegation,
            base_record,
            outcome,
            snapshot=snapshot,
            artifact_result=artifact_result,
            snapshot_limitation=snapshot_limitation,
            cleanup_state=cleanup_state,
            revocation_ref=revocation_ref,
            launch_digest=prepared.launch_plan_digest,
            resolution_ref=prepared.resolution_ref,
        )

    def _build_v2_settlement(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        base_record: EngineAttemptRecord,
        outcome: EngineWorkerOutcome,
        *,
        snapshot: StrixRunByteSnapshot | None,
        artifact_result: _ArtifactResult,
        snapshot_limitation: str | None,
        cleanup_state: CleanupState,
        revocation_ref: str | None,
        launch_digest: str,
        resolution_ref: str,
        reconciliation_ref: str | None = None,
    ) -> EngineRuntimeSettlement:

        terminal_state, completeness, exit_reason = _terminal_projection(outcome, snapshot)
        limitations = list(outcome.issues)
        if snapshot is not None:
            limitations.extend(snapshot.caveats)
        if snapshot_limitation is not None:
            limitations.append(snapshot_limitation)
            if outcome.started:
                terminal_state = AttemptState.UNKNOWN
                completeness = AttemptCompleteness.UNKNOWN
                exit_reason = "engine_artifacts_unavailable"
        if revocation_ref is None:
            limitations.append("Model gateway credential revocation is unverified.")
        limitations = list(dict.fromkeys(limitations))[:32]
        ended_at = _require_timestamp(outcome.completed_at, "Strix worker completion time")
        record = base_record.transition(
            terminal_state,
            timestamp=ended_at,
            exit_code=(outcome.exit_code if _portable_exit_code(outcome.exit_code) else None),
            completeness=completeness,
            exit_reason=exit_reason,
            limitations=tuple(limitations),
        )
        cleanup_ref = _v2_cleanup_receipt(
            binding,
            delegation,
            launch_digest,
            resolution_ref,
            self._expected_claim_ref,
            outcome,
            revocation_ref,
            artifact_result.seal_ref,
            artifact_result.manifest_ref,
            cleanup_state,
        )
        return EngineRuntimeSettlement(
            record=record,
            engine_evidence=artifact_result.evidence,
            artifact_manifest_ref=artifact_result.manifest_ref,
            cleanup_state=cleanup_state,
            cleanup_evidence_ref=cleanup_ref,
            settled_at=ended_at,
            reconciliation_ref=reconciliation_ref,
        )

    def _collect_artifacts(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        prepared: _PreparedAdmission,
        outcome: EngineWorkerOutcome,
    ) -> tuple[StrixRunByteSnapshot | None, _ArtifactResult]:
        try:
            # The trusted worker retained its process-stop outcome and external
            # custody was independently re-inspected before source sealing.
            seal = self._source_controller.seal(
                attempt_id=binding.attempt_id,
                source_run_dir=prepared.admission.workspace.cwd,
                worker_outcome=outcome,
            )
            seal.to_dict()
            if (
                seal.attempt_id != binding.attempt_id
                or seal.worker_state != "stopped"
                or seal.write_access_revoked is not True
            ):
                raise StrixEngineRuntimeError("artifact source is not stopped and write-revoked")
            names = _source_artifact_selection(
                prepared.admission.workspace.cwd,
                max_files=self._artifact_store.max_files,
                max_file_bytes=self._artifact_store.max_file_bytes,
            )
            publication_binding = EngineArtifactPublicationBinding(
                attempt_id=binding.attempt_id,
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                launch_digest=prepared.launch_plan_digest,
                runtime_resolution_ref=prepared.resolution_ref,
                execution_claim_ref=self._expected_claim_ref,
                worker_outcome_digest=content_hash(outcome.to_dict()),
            )
            reopened = self._artifact_store.import_or_reopen(
                attempt_id=binding.attempt_id,
                source_run_dir=prepared.admission.workspace.cwd,
                source_seal=seal,
                allowed_names=names,
                publication_binding=publication_binding,
            )
            return _reopened_artifact_result(
                reopened,
                expected_binding=publication_binding,
                expected_target=prepared.strix_plan.target,
                expected_instruction_sha256=prepared.admission.workspace.objective_sha256,
                outcome=outcome,
                run_id=binding.run_id,
                max_file_bytes=self._artifact_store.max_file_bytes,
                max_total_bytes=self._artifact_store.max_total_bytes,
                max_files=self._artifact_store.max_files,
            )
        except (EngineArtifactStoreError, OSError, RuntimeError, TypeError, ValueError):
            return None, _ArtifactResult(
                None, (), None, "Stopped Strix artifacts could not be retained safely."
            )

    @staticmethod
    def _custody_absent(
        custody: EngineResourceCustody,
        *,
        attempt_id: str,
        custody_plan_digest: str,
        network_policy_digest: str,
    ) -> bool:
        try:
            snapshot = custody.inspect(
                attempt_id,
                custody_identity_digest=custody_plan_digest,
                network_policy_digest=network_policy_digest,
                timeout_seconds=5.0,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return False
        return (
            isinstance(snapshot, ResourceCustodySnapshot)
            and snapshot.state is ResourceCustodyState.VERIFIED_ABSENT
        )

    @staticmethod
    def _stop_external_custody(prepared: _PreparedAdmission) -> None:
        try:
            prepared.admission.custody.stop_owned(
                prepared.admission.network_plan.attempt_id,
                custody_identity_digest=prepared.custody_plan.plan_digest,
                network_policy_digest=prepared.network_plan.policy_digest,
                timeout_seconds=5.0,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return

    @staticmethod
    def _stop_recovery_custody(
        admission: StrixRuntimeAdmission,
        custody_plan: ContainerCustodyPlan,
        network_policy_digest: str,
    ) -> None:
        try:
            admission.custody.stop_owned(
                custody_plan.attempt_id,
                custody_identity_digest=custody_plan.plan_digest,
                network_policy_digest=network_policy_digest,
                timeout_seconds=5.0,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return


_TERMINAL_STATES = frozenset(
    {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
)


def _adapter_attempt_id(attempt_id: str) -> str:
    prefix = "engine-attempt-"
    if not isinstance(attempt_id, str) or not attempt_id.startswith(prefix):
        raise StrixEngineRuntimeError("engine attempt identity is invalid")
    suffix = attempt_id[len(prefix) :]
    if len(suffix) != 32 or any(character not in "0123456789abcdef" for character in suffix):
        raise StrixEngineRuntimeError("engine attempt identity is invalid")
    return "attempt-" + suffix


def _image_reference_digest(reference: str) -> str:
    if not isinstance(reference, str):
        raise StrixEngineRuntimeError("Strix sandbox image reference is invalid")
    _name, separator, digest = reference.rpartition("@")
    if not separator:
        raise StrixEngineRuntimeError("Strix sandbox image reference is invalid")
    return _require_digest(digest, "Strix sandbox image")


def _docker_memory_bytes(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise StrixEngineRuntimeError("Strix sandbox memory limit is invalid")
    suffix = value[-1].lower()
    factors = {"k": 1024, "m": 1024**2, "g": 1024**3}
    if suffix in factors:
        number = value[:-1]
        factor = factors[suffix]
    else:
        number = value
        factor = 1
    if not number.isdigit() or number.startswith("0"):
        raise StrixEngineRuntimeError("Strix sandbox memory limit is invalid")
    return int(number) * factor


def _docker_nano_cpus(value: str) -> int:
    try:
        cpus = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise StrixEngineRuntimeError("Strix sandbox CPU limit is invalid") from exc
    nano_cpus = cpus * Decimal(1_000_000_000)
    if not nano_cpus.is_finite() or nano_cpus <= 0 or nano_cpus != nano_cpus.to_integral():
        raise StrixEngineRuntimeError("Strix sandbox CPU limit is invalid")
    return int(nano_cpus)


def _resolved_root(path: Any, label: str) -> Path:
    if not isinstance(path, Path) or path.is_symlink():
        raise StrixEngineRuntimeError(f"{label} is not an ordinary directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise StrixEngineRuntimeError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise StrixEngineRuntimeError(f"{label} is not an ordinary directory")
    return resolved


def _root_digest(path: Path) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.engine-runtime-root-identity.v1",
            "resolved_path": str(path),
        }
    )


def _ordinary_artifact_directory(path: Path) -> None:
    details = path.lstat()
    if path.is_symlink() or _is_reparse(details) or not stat.S_ISDIR(details.st_mode):
        raise StrixEngineRuntimeError("Strix artifact directory is unsafe")


def _ordinary_optional_artifact(entry: os.DirEntry[str], *, max_file_bytes: int) -> None:
    details = Path(entry.path).lstat()
    if (
        entry.is_symlink()
        or _is_reparse(details)
        or not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or not 1 <= details.st_size <= max_file_bytes
    ):
        raise StrixEngineRuntimeError("optional Strix artifact is unsafe or outside its byte bound")


def _optional_strix_artifact_names(
    run_directory: Path,
    *,
    prefix: str,
    max_files: int,
    max_file_bytes: int,
    required_count: int,
) -> tuple[str, ...]:
    """Select reviewed public outputs only; missing optional outputs stay missing."""

    _ordinary_artifact_directory(run_directory.parent)
    _ordinary_artifact_directory(run_directory)
    if required_count > max_files:
        raise StrixEngineRuntimeError("Strix artifact selection exceeds its file bound")
    selected: list[str] = []
    scanned = 0
    report_directory: Path | None = None
    allowed_root = frozenset((*_OPTIONAL_STRIX_RUN_FILES, "vulnerabilities"))
    with os.scandir(run_directory) as entries:
        for entry in entries:
            scanned += 1
            if scanned > MAX_SOURCE_TREE_ENTRIES:
                raise StrixEngineRuntimeError("Strix artifact directory exceeds its entry bound")
            name = entry.name
            if name not in allowed_root:
                if name.casefold() in allowed_root:
                    raise StrixEngineRuntimeError("optional Strix artifact has a portable alias")
                continue
            if name == "vulnerabilities":
                report_directory = run_directory / name
                _ordinary_artifact_directory(report_directory)
                continue
            _safe_name(f"{prefix}/{name}")
            _ordinary_optional_artifact(entry, max_file_bytes=max_file_bytes)
            selected.append(f"{prefix}/{name}")
            if required_count + len(selected) > max_files:
                raise StrixEngineRuntimeError("Strix artifact selection exceeds its file bound")
    if report_directory is not None:
        with os.scandir(report_directory) as entries:
            for entry in entries:
                scanned += 1
                if scanned > MAX_SOURCE_TREE_ENTRIES:
                    raise StrixEngineRuntimeError(
                        "Strix artifact directory exceeds its entry bound"
                    )
                name = entry.name
                if not name.casefold().endswith(".md"):
                    continue
                if not name.endswith(".md"):
                    raise StrixEngineRuntimeError("optional Strix artifact has a portable alias")
                artifact_name = f"{prefix}/vulnerabilities/{name}"
                _safe_name(artifact_name)
                _ordinary_optional_artifact(entry, max_file_bytes=max_file_bytes)
                selected.append(artifact_name)
                if required_count + len(selected) > max_files:
                    raise StrixEngineRuntimeError("Strix artifact selection exceeds its file bound")
    return tuple(sorted(selected))


def _source_artifact_selection(
    source_run_dir: Path,
    *,
    max_files: int,
    max_file_bytes: int,
) -> tuple[str, ...]:
    """Select names only after the controller has stopped and sealed the source."""

    runs_root = source_run_dir / "strix_runs"
    _ordinary_artifact_directory(runs_root)
    with os.scandir(runs_root) as entries:
        run_entries: list[os.DirEntry[str]] = []
        for entry in entries:
            if len(run_entries) >= 2:
                raise StrixEngineRuntimeError("Strix attempt has more than one upstream run")
            run_entries.append(entry)
    if len(run_entries) != 1:
        raise StrixEngineRuntimeError("Strix attempt has no unique upstream run")
    upstream = run_entries[0].name
    _safe_name(f"strix_runs/{upstream}/run.json")
    run_directory = Path(run_entries[0].path)
    _ordinary_artifact_directory(run_directory)
    prefix = f"strix_runs/{upstream}"
    run_record = run_directory / "run.json"
    if not run_record.exists():
        raise StrixEngineRuntimeError("Strix run artifact is unavailable")
    names = [f"{prefix}/run.json"]
    if (run_directory / "coverage.json").exists():
        names.append(f"{prefix}/coverage.json")
    names.extend(
        _optional_strix_artifact_names(
            run_directory,
            prefix=prefix,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            required_count=len(names),
        )
    )
    return tuple(sorted(names))


def _reopened_artifact_result(
    reopened: ReopenedEngineArtifactAttempt,
    *,
    expected_binding: EngineArtifactPublicationBinding,
    expected_target: str,
    expected_instruction_sha256: str,
    outcome: EngineWorkerOutcome,
    run_id: str,
    max_file_bytes: int,
    max_total_bytes: int,
    max_files: int,
) -> tuple[StrixRunByteSnapshot, _ArtifactResult]:
    if (
        not isinstance(reopened, ReopenedEngineArtifactAttempt)
        or not reopened.recovery_eligible
        or reopened.schema_version != V2_MANIFEST_SCHEMA
        or reopened.attempt_id != expected_binding.attempt_id
        or reopened.publication_binding != expected_binding
        or reopened.source_collection_seal is None
        or reopened.source_collection_seal.worker_state != "stopped"
        or reopened.source_collection_seal.write_access_revoked is not True
        or reopened.source_collection_receipt
        != reopened.source_collection_seal.controller_receipt_digest
        or reopened.source_tree_digest != reopened.source_collection_seal.source_tree_digest
        or reopened.source_collection_seal_ref
        != content_hash(reopened.source_collection_seal.to_dict())
        or reopened.manifest_ref != content_hash(reopened.to_manifest())
    ):
        raise StrixEngineRuntimeError("reopened Strix publication is not an exact v2 attempt")
    if not reopened.artifacts:
        raise StrixEngineRuntimeError("reopened Strix publication has no run")
    names = tuple(artifact.name for artifact in reopened.artifacts)
    if names != tuple(sorted(set(names))) or len(names) > max_files:
        raise StrixEngineRuntimeError("reopened Strix publication names are not canonical")
    total_bytes = 0
    for artifact in reopened.artifacts:
        _safe_name(artifact.name)
        if (
            not isinstance(artifact.payload, bytes)
            or not 1 <= artifact.size_bytes <= max_file_bytes
            or len(artifact.payload) != artifact.size_bytes
            or artifact.sha256 != "sha256:" + hashlib.sha256(artifact.payload).hexdigest()
        ):
            raise StrixEngineRuntimeError("reopened Strix artifact bytes are unverified")
        total_bytes += artifact.size_bytes
    if total_bytes != reopened.total_bytes or total_bytes > max_total_bytes:
        raise StrixEngineRuntimeError("reopened Strix artifact total changed")
    publication_identity = {
        "schema_version": PUBLICATION_REF_SCHEMA,
        "attempt_id": reopened.attempt_id,
        "source_collection_receipt": reopened.source_collection_receipt,
        "source_tree_digest": reopened.source_tree_digest,
        "source_collection_seal_ref": reopened.source_collection_seal_ref,
        "source_collection_seal": reopened.source_collection_seal.to_dict(),
        "publication_binding": expected_binding.to_dict(),
        "artifact_count": len(reopened.artifacts),
        "total_bytes": reopened.total_bytes,
        "artifacts": [artifact.to_manifest_row() for artifact in reopened.artifacts],
    }
    if reopened.artifact_publication_ref != content_hash(publication_identity):
        raise StrixEngineRuntimeError("reopened Strix publication identity changed")
    parsed_names = [name.split("/") for name in names]
    if any(len(parts) < 3 or parts[0] != "strix_runs" for parts in parsed_names):
        raise StrixEngineRuntimeError("reopened Strix publication has an unrelated artifact")
    upstream_ids = {parts[1] for parts in parsed_names}
    if len(upstream_ids) != 1:
        raise StrixEngineRuntimeError("reopened Strix publication has multiple runs")
    upstream = next(iter(upstream_ids))
    prefix = f"strix_runs/{upstream}/"
    accepted_root = frozenset((*_OPTIONAL_STRIX_RUN_FILES, "run.json", "coverage.json"))
    for parts in parsed_names:
        if len(parts) == 3 and parts[2] in accepted_root:
            continue
        if len(parts) == 4 and parts[2] == "vulnerabilities" and parts[3].endswith(".md"):
            continue
        raise StrixEngineRuntimeError("reopened Strix publication has an unreviewed artifact")
    by_name = {artifact.name: artifact for artifact in reopened.artifacts}
    run_artifact = by_name.get(prefix + "run.json")
    if run_artifact is None:
        raise StrixEngineRuntimeError("reopened Strix publication has no run record")
    coverage_artifact = by_name.get(prefix + "coverage.json")
    snapshot = parse_strix_run_bytes(
        run_artifact.payload,
        None if coverage_artifact is None else coverage_artifact.payload,
        upstream_run_id=upstream,
        expected_target=expected_target,
        expected_instruction_sha256=expected_instruction_sha256,
        process_exit_code=outcome.exit_code,
        cancellation_requested=outcome.execution_state is EngineExecutionState.CANCELLED,
        cessation_verified=True,
    )
    evidence = EngineEvidenceItem.create(
        attempt_id=expected_binding.attempt_id,
        run_id=run_id,
        category=EvidenceCategory.ENGINE_ASSERTION,
        producer="strix",
        observed_at=outcome.completed_at,
        content=snapshot.to_dict(),
        source_artifact_digest=run_artifact.sha256,
        limitations=("Engine-reported result; independent target observation is required.",),
    )
    return snapshot, _ArtifactResult(
        manifest_ref=reopened.manifest_ref,
        evidence=(evidence,),
        seal_ref=content_hash(reopened.publication_seal()),
        limitation=None,
    )


def _validate_artifact_manifest(
    manifest: Any,
    *,
    attempt_id: str,
    source_receipt: str,
    selected_names: tuple[str, ...],
    expected_digests: Mapping[str, str],
    max_file_bytes: int,
    max_total_bytes: int,
    max_files: int,
) -> None:
    fields = {
        "schema_version",
        "attempt_id",
        "storage_boundary",
        "source_collection_receipt",
        "artifact_count",
        "total_bytes",
        "artifacts",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != fields:
        raise StrixEngineRuntimeError("retained Strix artifact manifest fields changed")
    artifacts = manifest.get("artifacts")
    if (
        manifest.get("schema_version") != "bluefire.engine-artifacts.v1"
        or manifest.get("attempt_id") != attempt_id
        or manifest.get("storage_boundary") != "contained_exclusive_protected_root"
        or manifest.get("source_collection_receipt") != source_receipt
        or not isinstance(artifacts, list)
        or manifest.get("artifact_count") != len(selected_names)
        or len(artifacts) != len(selected_names)
        or len(set(selected_names)) != len(selected_names)
        or len(selected_names) > max_files
    ):
        raise StrixEngineRuntimeError("retained Strix artifact manifest identity changed")
    total = 0
    retained: dict[str, str] = {}
    for row in artifacts:
        if not isinstance(row, Mapping) or set(row) != {"name", "size_bytes", "sha256"}:
            raise StrixEngineRuntimeError("retained Strix artifact row changed")
        name = row.get("name")
        size = row.get("size_bytes")
        digest = row.get("sha256")
        if (
            not isinstance(name, str)
            or name in retained
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= max_file_bytes
        ):
            raise StrixEngineRuntimeError("retained Strix artifact row is invalid")
        retained[name] = _require_digest(digest, "retained Strix artifact")
        total += size
    if (
        set(retained) != set(selected_names)
        or any(retained.get(name) != digest for name, digest in expected_digests.items())
        or manifest.get("total_bytes") != total
        or total > max_total_bytes
    ):
        raise StrixEngineRuntimeError("retained Strix artifact bytes differ from discovery")


def _reservation_matches(
    reservation: Mapping[str, Any] | None,
    expected: Mapping[str, Any],
    *,
    not_before: str | None,
    not_after: str | None,
) -> bool:
    if (
        reservation is None
        or set(reservation) != {*expected, "reserved_at"}
        or not_before is None
        or not_after is None
    ):
        return False
    try:
        reserved_at = parse_iso8601_datetime(reservation["reserved_at"])
        lower = parse_iso8601_datetime(not_before)
        upper = parse_iso8601_datetime(not_after)
    except (KeyError, TypeError, ValueError):
        return False
    return lower <= reserved_at <= upper and all(
        reservation.get(name) == value for name, value in expected.items()
    )


def _retained_launch_digest(
    reservation: Mapping[str, Any] | None,
    *,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    not_before: str,
    not_after: str,
) -> str | None:
    """Read a protected reservation identity without reconstructing launch inputs."""

    fields = {
        "schema_version",
        "attempt_id",
        "plan_digest",
        "argv_sha256",
        "environment_names",
        "sensitive_environment_names",
        "requires_resource_custody",
        "custody_identity_digest",
        "network_policy_digest",
        "wall_time_seconds",
        "reserved_at",
    }
    if not isinstance(reservation, Mapping) or set(reservation) != fields:
        return None
    try:
        if (
            reservation["schema_version"] != "bluefire.engine-launch-reservation.v1"
            or reservation["attempt_id"] != binding.attempt_id
            or reservation["requires_resource_custody"] is not True
            or reservation["custody_identity_digest"] != delegation.custody_plan_digest
            or reservation["network_policy_digest"] != delegation.network_policy_digest
            or reservation["wall_time_seconds"] != binding.wall_clock_seconds
            or reservation["sensitive_environment_names"] != ["LLM_API_KEY"]
            or not isinstance(reservation["environment_names"], list)
            or "LLM_API_KEY" not in reservation["environment_names"]
            or _require_digest(reservation["argv_sha256"], "retained launch arguments")
            != reservation["argv_sha256"]
            or not parse_iso8601_datetime(not_before)
            <= parse_iso8601_datetime(reservation["reserved_at"])
            <= parse_iso8601_datetime(not_after)
        ):
            return None
        return _require_digest(reservation["plan_digest"], "retained launch plan")
    except (KeyError, RuntimeError, TypeError, ValueError):
        return None


def _remaining_recovery_budget(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise StrixEngineRuntimeError("claimed recovery deadline expired")
    return remaining


def _terminal_outcome_matches(
    record: EngineAttemptRecord,
    outcome: EngineWorkerOutcome,
) -> bool:
    if (
        record.upstream_session_id != _adapter_attempt_id(record.binding.attempt_id)
        or record.started_at is None
        or record.ended_at != outcome.completed_at
        or record.exit_code
        != (outcome.exit_code if _portable_exit_code(outcome.exit_code) else None)
    ):
        return False
    required_state = {
        EngineExecutionState.CANCELLED: AttemptState.CANCELLED,
        EngineExecutionState.TIMED_OUT: AttemptState.BUDGET_EXHAUSTED,
        EngineExecutionState.STARTUP_FAILED: AttemptState.FAILED,
        EngineExecutionState.RESERVED: AttemptState.UNKNOWN,
        EngineExecutionState.INTERRUPTED: AttemptState.UNKNOWN,
    }.get(outcome.execution_state)
    if required_state is not None and record.state is not required_state:
        return False
    if (
        outcome.execution_state is EngineExecutionState.EXITED
        and record.state is AttemptState.CANCELLED
    ):
        return False
    if outcome.started:
        return outcome.started_at is not None and parse_iso8601_datetime(
            record.started_at
        ) <= parse_iso8601_datetime(outcome.started_at)
    return outcome.started_at is None


def _require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise StrixEngineRuntimeError(f"{label} must be a sha256 digest")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise StrixEngineRuntimeError(f"{label} is invalid")
    try:
        parse_iso8601_datetime(value)
    except ValueError as exc:
        raise StrixEngineRuntimeError(f"{label} is invalid") from exc
    return value


def _gateway_secret(lease: ModelGatewayLease, expected_ref: str) -> str:
    if lease.authorization_ref != expected_ref:
        raise StrixEngineRuntimeError("model gateway lease belongs to another authorization")
    value = lease.secret_value()
    if (
        not isinstance(value, str)
        or not 8 <= len(value.encode("utf-8")) <= 4096
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise StrixEngineRuntimeError("model gateway lease secret is invalid")
    return value


def _cleanup_state(outcome: EngineWorkerOutcome, revocation_ref: str | None) -> CleanupState:
    if (
        outcome.cleanup_state is EngineCleanupState.VERIFIED
        and outcome.custody_after.state is ResourceCustodyState.VERIFIED_ABSENT
        and revocation_ref is not None
    ):
        return CleanupState.VERIFIED_ABSENT
    if outcome.custody_after.state is ResourceCustodyState.PRESENT:
        return CleanupState.RESIDUE
    return CleanupState.UNKNOWN


def _portable_exit_code(value: int | None) -> bool:
    return value is not None and not isinstance(value, bool) and -255 <= value <= 255


def _terminal_projection(
    outcome: EngineWorkerOutcome,
    snapshot: StrixRunByteSnapshot | None,
) -> tuple[AttemptState, AttemptCompleteness, str]:
    if outcome.execution_state is EngineExecutionState.CANCELLED:
        return AttemptState.CANCELLED, AttemptCompleteness.PARTIAL, "controller_cancelled"
    if outcome.execution_state is EngineExecutionState.TIMED_OUT:
        return (
            AttemptState.BUDGET_EXHAUSTED,
            AttemptCompleteness.PARTIAL,
            "wall_clock_budget_exhausted",
        )
    if outcome.execution_state is EngineExecutionState.STARTUP_FAILED:
        return AttemptState.FAILED, AttemptCompleteness.UNKNOWN, "engine_start_failed"
    if outcome.execution_state is EngineExecutionState.RESERVED:
        return AttemptState.UNKNOWN, AttemptCompleteness.UNKNOWN, "launch_identity_unknown"
    if outcome.execution_state is EngineExecutionState.INTERRUPTED:
        return AttemptState.UNKNOWN, AttemptCompleteness.UNKNOWN, "engine_interrupted"
    if snapshot is None:
        return AttemptState.UNKNOWN, AttemptCompleteness.UNKNOWN, "engine_result_unavailable"
    states = {
        "completed": AttemptState.COMPLETED,
        "partial": AttemptState.PARTIAL,
        "failed": AttemptState.FAILED,
        "cancelled": AttemptState.CANCELLED,
        "budget_exhausted": AttemptState.BUDGET_EXHAUSTED,
        "unknown": AttemptState.UNKNOWN,
        "running": AttemptState.UNKNOWN,
    }
    completeness = {
        "complete": AttemptCompleteness.COMPLETE,
        "partial": AttemptCompleteness.PARTIAL,
        "unknown": AttemptCompleteness.UNKNOWN,
    }[snapshot.completeness]
    return states[snapshot.attempt_state], completeness, "strix_" + snapshot.attempt_state


def _v2_cleanup_receipt(
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    launch_digest: str,
    resolution_ref: str,
    claim_ref: str,
    outcome: EngineWorkerOutcome,
    revocation_ref: str | None,
    publication_seal_ref: str | None,
    manifest_ref: str | None,
    cleanup_state: CleanupState,
) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.strix-runtime-settlement.v2",
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "launch_digest": launch_digest,
            "runtime_resolution_ref": resolution_ref,
            "execution_claim_ref": claim_ref,
            "worker_outcome_digest": content_hash(outcome.to_dict()),
            "gateway_revocation_ref": revocation_ref,
            "artifact_publication_seal_ref": publication_seal_ref,
            "artifact_manifest_ref": manifest_ref,
            "cleanup_state": cleanup_state.value,
        }
    )


def _cleanup_receipt(
    binding: EngineAttemptBinding,
    prepared: _PreparedAdmission,
    outcome: EngineWorkerOutcome,
    revocation_ref: str | None,
    seal_ref: str | None,
    manifest_ref: str | None,
    cleanup_state: CleanupState,
    settled_at: str,
) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.strix-runtime-settlement.v1",
            "attempt_id": binding.attempt_id,
            "binding_digest": binding.binding_digest,
            "launch_plan_digest": prepared.launch_plan_digest,
            "worker_outcome": outcome.to_dict(),
            "network_verification_ref": content_hash(prepared.network_verification.to_dict()),
            "custody_plan_ref": prepared.custody_plan.plan_digest,
            "containment_ref": prepared.containment.receipt_digest,
            "gateway_revocation_ref": revocation_ref,
            "source_seal_ref": seal_ref,
            "artifact_manifest_ref": manifest_ref,
            "cleanup_state": cleanup_state.value,
            "settled_at": settled_at,
        }
    )
