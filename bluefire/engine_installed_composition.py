"""Inert assembly boundary for an explicitly configured installed engine.

This is not a default production backend. Admission persistence, the product
controller/executors and the protected attempt factory require explicit wiring.
The attempt factory owns per-attempt target/provider forwarders, their protected
transports, listeners and credentials. This assembly does not establish their
custody. No such dependency comes from an HTTP request or a workspace read.

Tenant preparation currently requires an already checked running generation.
An idle lab therefore remains unavailable: this module cannot invent the
missing reviewed bootstrap contract or start a lab while preparing a request.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Callable, Protocol

from .engine_action_preparation import EngineActionPreparationCoordinator
from .engine_action_submission import EngineActionSubmissionCoordinator
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_controller_jobs import (
    ControllerCheckExecutor,
    DefenseOperationExecutor,
    EngineControllerJobs,
)
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment_jobs import (
    EngineAttemptRuntime,
    EngineExperimentJobs,
    EngineRuntimeSettlement,
    TransitionSink,
)
from .engine_experiment_service import EngineExperimentService, TrustedEngineController
from .job_runtime import JobContext
from .strix_admission_issuer import (
    ControllerPrivateStrixAdmissionIssuer,
    IndependentStrixIssuanceVerifier,
    ProtectedStrixIssuanceRegistry,
    StrixIssuanceIdentitySource,
    StrixIssuancePersistence,
)
from .strix_runtime_admission_resolver import (
    AppendOnlyStrixRuntimeAuthoritySource,
    ControllerQualifiedStrixAdmissionResolver,
    PersistedStrixRuntimeAdmissionSource,
    StrixQualificationManifestSource,
)
from .tenant_action_material_source import (
    ProductStoreTenantActionMaterialSource,
    TenantGenerationJournalReader,
    TenantRuntimeAdmissionIdentitySource,
)
from .tenant_engine_action_preparer import (
    ActiveTenantGenerationSource,
    ControllerOwnedTenantActionPreparer,
    RetainedTenantActionMaterialSource,
)

if TYPE_CHECKING:
    from .job_runtime import RunJobController
    from .product_store import ProductStore
    from .run_store import RunStore


class InstalledEngineCompositionError(RuntimeError):
    """A required protected dependency or lifecycle binding is unavailable."""


class InstalledEngineResource(Protocol):
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class AcceptedPreparedEngineAttempt:
    """Identity reopened and atomically consumed by the protected job owner.

    This value is not authority by itself. Only ``accepted_jobs`` may supply it
    after checking durable preparation, reviewer acceptance, job claim and the
    exact still-active admission. The owner must refuse a second execution,
    including after process restart or a lost acknowledgement.
    """

    job_id: str
    preparation_ref: str
    binding_digest: str
    delegation_digest: str

    def validate(
        self, job_id: str, binding: EngineAttemptBinding, delegation: EngineCapabilityDelegation
    ) -> None:
        if (
            not isinstance(self.job_id, str)
            or re.fullmatch(r"job-[0-9a-f]{32}", self.job_id) is None
            or self.job_id != job_id
            or not isinstance(self.preparation_ref, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.preparation_ref) is None
            or self.binding_digest != binding.binding_digest
            or self.delegation_digest != delegation.delegation_digest
        ):
            raise InstalledEngineCompositionError("accepted prepared job binding changed")


class AcceptedPreparedEngineJobs(Protocol):
    def claim_for_execution(
        self,
        *,
        job_id: str,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> AcceptedPreparedEngineAttempt | None:
        """Durably consume exact accepted work before any runtime/lab effect."""
        ...


@dataclass(frozen=True, slots=True)
class InstalledEngineSources:
    authority: AppendOnlyStrixRuntimeAuthoritySource
    manifests: StrixQualificationManifestSource
    admissions: PersistedStrixRuntimeAdmissionSource
    issuance_identities: StrixIssuanceIdentitySource
    issuance_persistence: StrixIssuancePersistence
    issuance_registry: ProtectedStrixIssuanceRegistry
    issuance_verifier: IndependentStrixIssuanceVerifier
    generations: ActiveTenantGenerationSource
    generation_journal: TenantGenerationJournalReader
    material_candidates: RetainedTenantActionMaterialSource
    admission_identities: TenantRuntimeAdmissionIdentitySource
    accepted_jobs: AcceptedPreparedEngineJobs


@dataclass(frozen=True, slots=True)
class InstalledAttemptComponents:
    """Exact attempt runtime and owned relay/listener/controller handles.

    The execution factory must build StrixEngineRuntime with the shared resolver,
    protected worker/artifact/credential/source adapters and exact reviewed
    target/provider forwarders. A Test provider remains a Test provider; this
    assembly never claims live-provider proof from fixture output.
    """

    runtime: EngineAttemptRuntime
    resources: tuple[InstalledEngineResource, ...] = ()


class InstalledAttemptFactory(Protocol):
    """Protected owner of exact reviewed target/provider/runtime components.

    Implementations must retain and verify their own target/provider transports,
    construct the attempt-bound forwarders and relays from reviewed authority,
    and return their lifecycle handles in ``InstalledAttemptComponents``.
    Dependency presence in this assembly is not transport custody verification.
    """

    def for_execution(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        composition: InstalledEngineComposition,
    ) -> InstalledAttemptComponents: ...

    def for_reconciliation(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        composition: InstalledEngineComposition,
    ) -> InstalledAttemptComponents:
        """Reopen existing custody only; never allocate, start or reissue."""
        ...


@dataclass(frozen=True, slots=True)
class InstalledEngineAdapters:
    controller: TrustedEngineController
    defense_executor: DefenseOperationExecutor
    check_executor: ControllerCheckExecutor
    attempts: InstalledAttemptFactory
    resources: tuple[InstalledEngineResource, ...] = ()


@dataclass(frozen=True, slots=True)
class InstalledEngineBinding:
    preparation: EngineActionPreparationCoordinator
    submission: EngineActionSubmissionCoordinator
    material_source: ProductStoreTenantActionMaterialSource
    preparer: ControllerOwnedTenantActionPreparer


class _InstalledRuntime:
    def __init__(self, owner: InstalledEngineComposition) -> None:
        self._owner = owner

    def execute(
        self,
        context: JobContext,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        transition: TransitionSink,
    ) -> EngineRuntimeSettlement:
        owner = self._owner
        delegation.validate_attempt_binding(binding)
        with owner._lock:
            owner._require_bound()
            if binding.attempt_id in owner._dispatched:
                raise InstalledEngineCompositionError("attempt execution was already consumed")
            # Consume locally before any protected call; errors never retry effects.
            owner._dispatched.add(binding.attempt_id)
        accepted = owner.sources.accepted_jobs.claim_for_execution(
            job_id=context.job_id, binding=binding, delegation=delegation
        )
        if not isinstance(accepted, AcceptedPreparedEngineAttempt):
            raise InstalledEngineCompositionError("accepted prepared job is unavailable")
        accepted.validate(context.job_id, binding, delegation)
        components = owner.adapters.attempts.for_execution(
            accepted=accepted, binding=binding, delegation=delegation, composition=owner
        )
        owner._retain(components)
        return components.runtime.execute(context, binding, delegation, transition)

    def reconcile(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> EngineRuntimeSettlement:
        owner = self._owner
        delegation.validate_attempt_binding(binding)
        if saved_record.binding != binding:
            raise InstalledEngineCompositionError("saved attempt binding changed")
        with owner._lock:
            owner._require_bound()
        components = owner.adapters.attempts.for_reconciliation(
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
            composition=owner,
        )
        owner._retain(components)
        return components.runtime.reconcile(binding, delegation, saved_record)


class InstalledEngineComposition:
    """One service's shared owners, with an effect-free second binding phase.

    Pass ``runtime``, ``controller``, and the three factory methods to the
    existing service constructor. The controller-job factory runs first; the
    preparation/submission factories bind after EngineExperimentService and
    EngineExperimentJobs exist. Construction never reads a source or invokes a
    factory. The injected dependencies must already exist; none are synthesized.
    """

    def __init__(
        self,
        *,
        sources: InstalledEngineSources,
        adapters: InstalledEngineAdapters,
        installed_bluefire_revision: str,
        reviewer: str,
        clock: Callable[[], str],
    ) -> None:
        if not isinstance(sources, InstalledEngineSources) or not isinstance(
            adapters, InstalledEngineAdapters
        ):
            raise InstalledEngineCompositionError(
                "explicit protected sources and adapters required"
            )
        for group in (sources, adapters):
            for field in fields(group):
                if getattr(group, field.name) is None:
                    raise InstalledEngineCompositionError(
                        f"required dependency absent: {field.name}"
                    )
        if (
            not callable(clock)
            or not isinstance(reviewer, str)
            or not 1 <= len(reviewer) <= 200
            or reviewer != reviewer.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in reviewer)
        ):
            raise InstalledEngineCompositionError("trusted clock and stable reviewer required")
        self.sources, self.adapters = sources, adapters
        self.controller = adapters.controller
        self.resolver = ControllerQualifiedStrixAdmissionResolver(
            authority_source=sources.authority,
            protected_manifest_source=sources.manifests,
            persisted_admission_source=sources.admissions,
            installed_bluefire_revision=installed_bluefire_revision,
        )
        self.issuer = ControllerPrivateStrixAdmissionIssuer(
            identities=sources.issuance_identities,
            persistence=sources.issuance_persistence,
            registry=sources.issuance_registry,
            verifier=sources.issuance_verifier,
        )
        self.runtime = _InstalledRuntime(self)
        self._reviewer, self._clock = reviewer, clock
        self._lock = threading.RLock()
        self._shutdown_lock = threading.Lock()
        self._controller_jobs: EngineControllerJobs | None = None
        self._store: ProductStore | None = None
        self._run_store: RunStore | None = None
        self._job_controller: RunJobController | None = None
        self._workspace: EngineExperimentService | None = None
        self._binding: InstalledEngineBinding | None = None
        self._dispatched: set[str] = set()
        self._resources = list(adapters.resources)
        self._stopping = self._jobs_stopped = self._closed = False

    @property
    def live_provider_proof(self) -> bool:
        """Assembly and fake-provider output cannot establish live proof."""
        return False

    def _require_open(self) -> None:
        if self._closed or self._stopping:
            raise InstalledEngineCompositionError("installed engine composition is stopping")

    def _require_bound(self) -> None:
        self._require_open()
        if self._binding is None:
            raise InstalledEngineCompositionError("installed engine composition is not bound")

    def controller_jobs_factory(
        self, store: ProductStore, run_store: RunStore, jobs: RunJobController
    ) -> EngineControllerJobs:
        with self._lock:
            self._require_open()
            if store is None or run_store is None or jobs is None:
                raise InstalledEngineCompositionError("shared service owners are required")
            if self._controller_jobs is None:
                self._store, self._run_store, self._job_controller = store, run_store, jobs
                self._controller_jobs = EngineControllerJobs(
                    controller=jobs,
                    repository=store,
                    defense_executor=self.adapters.defense_executor,
                    check_executor=self.adapters.check_executor,
                    clock=self._clock,
                )
            elif (
                store is not self._store
                or run_store is not self._run_store
                or jobs is not self._job_controller
            ):
                raise InstalledEngineCompositionError("composition belongs to another service")
            return self._controller_jobs

    def bind(
        self, store: ProductStore, workspace: EngineExperimentService
    ) -> InstalledEngineBinding:
        with self._lock:
            self._require_open()
            # Existing concrete service APIs carry no public binding descriptor.
            # Validate identities without invoking workspace/read/target methods.
            if (
                not isinstance(workspace, EngineExperimentService)
                or store is not self._store
                or workspace._history is not store
                or workspace._run_source is not self._run_store
                or not isinstance(workspace._jobs, EngineExperimentJobs)
                or workspace._jobs._runtime is not self.runtime
                or workspace._jobs._repository is not store
                or workspace._jobs._controller is not self._job_controller
                or workspace._controller is not self.controller
                or workspace._controller_jobs is not self._controller_jobs
                or workspace._job_lifecycle is not self._job_controller
                or self._controller_jobs is None
                or (self._workspace is not None and self._workspace is not workspace)
            ):
                raise InstalledEngineCompositionError("installed service binding changed")
            if self._binding is None:
                materials = ProductStoreTenantActionMaterialSource(
                    store=store,
                    generation_journal=self.sources.generation_journal,
                    generation_source=self.sources.generations,
                    runtime_authority_source=self.sources.authority,
                    runtime_resolver=self.resolver,
                    clock=self._clock,
                    candidate_source=self.sources.material_candidates,
                    admission_identity_source=self.sources.admission_identities,
                )
                preparer = ControllerOwnedTenantActionPreparer(
                    material_source=materials,
                    generation_source=self.sources.generations,
                    runtime_resolver=self.resolver,
                    controller_jobs=self._controller_jobs,
                    material_issuer=materials,
                )
                self._binding = InstalledEngineBinding(
                    preparation=EngineActionPreparationCoordinator(
                        history=store,
                        workspace_source=workspace,
                        preparer=preparer,
                        clock=self._clock,
                    ),
                    submission=EngineActionSubmissionCoordinator(
                        history=store,
                        workspace_source=workspace,
                        jobs=workspace._jobs,
                        controller_jobs=self._controller_jobs,
                        reviewer=self._reviewer,
                    ),
                    material_source=materials,
                    preparer=preparer,
                )
                self._workspace = workspace
            return self._binding

    def action_preparation_factory(
        self, store: ProductStore, workspace: EngineExperimentService
    ) -> EngineActionPreparationCoordinator:
        return self.bind(store, workspace).preparation

    def action_submission_factory(
        self,
        store: ProductStore,
        workspace: EngineExperimentService,
        jobs: EngineExperimentJobs,
        controller_jobs: EngineControllerJobs | None,
    ) -> EngineActionSubmissionCoordinator:
        if jobs is not workspace._jobs or controller_jobs is not self._controller_jobs:
            raise InstalledEngineCompositionError("prepared submission jobs binding changed")
        return self.bind(store, workspace).submission

    def _retain(self, components: InstalledAttemptComponents) -> None:
        if (
            not isinstance(components, InstalledAttemptComponents)
            or components.runtime is self.runtime
        ):
            raise InstalledEngineCompositionError("exact attempt components are unavailable")
        with self._lock:
            self._resources.extend(components.resources)

    def shutdown_jobs(self) -> None:
        """Join the owning job controller before any relay/owner is closed."""
        with self._shutdown_lock:
            with self._lock:
                if self._jobs_stopped or self._closed:
                    return
                self._stopping = True
                jobs = self._job_controller
            if jobs is not None:
                jobs.shutdown(cancel_active=True)
            with self._lock:
                self._jobs_stopped = True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._job_controller is not None and not self._jobs_stopped:
                raise InstalledEngineCompositionError("shutdown_jobs must finish before close")
            self._closed = True
            resources = tuple(reversed(self._resources))
        seen: set[int] = set()
        failed = False
        for resource in resources:
            if id(resource) in seen:
                continue
            seen.add(id(resource))
            try:
                resource.close()
            except Exception:
                failed = True
        if failed:
            raise InstalledEngineCompositionError(
                "installed engine resource close failed"
            ) from None
