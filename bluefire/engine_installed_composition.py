"""Inert assembly boundary for an explicitly configured installed engine.

This is not a default production backend. Admission persistence, the product
controller and protected attempt factory require explicit wiring. Controller
jobs use either direct executors or one late-bound installed adapter factory.
The attempt factory owns per-attempt target/provider forwarders, their protected
transports, listeners and credentials. This assembly does not establish their
custody. No such dependency comes from an HTTP request or a workspace read.

Tenant preparation currently requires an already checked running generation.
An idle lab therefore remains unavailable: this module cannot invent the
missing reviewed bootstrap contract or start a lab while preparing a request.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any, Callable, Iterator, Mapping, Protocol

from .accepted_engine_jobs import (
    AcceptedEngineJobError,
    AcceptedEnginePreDispatchCancelled,
    AcceptedPreparedEngineAttempt,
    PreDispatchCancelledEngineAttempt,
    ProductStoreAcceptedEngineJobs,
    ProductStoreEngineReconciliationCoordinator,
)
from .engine_action_preparation import EngineActionPreparationCoordinator
from .engine_action_submission import EngineActionSubmissionCoordinator
from .engine_artifact_store import EngineArtifactStore
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_controller_jobs import (
    ControllerCheckExecutor,
    DefenseOperationExecutor,
    EngineControllerJobError,
    EngineControllerJobs,
)
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment_jobs import (
    EngineAttemptRuntime,
    EngineExperimentJobs,
    EngineRuntimeSettlement,
    TransitionSink,
    installed_execution_claim_policy,
)
from .engine_experiment_service import (
    EngineControllerJobAction,
    EngineExperimentService,
    TrustedEngineController,
)
from .engine_installed_cleanup import (
    InstalledEngineBundleCleanupOwner,
    InstalledEngineBundleCleanupReceipt,
    InstalledEngineCleanupError,
    InstalledEngineCleanupResourceBinding,
    cleanup_request_ref,
    cleanup_status_document,
    validate_cleanup_owner,
    validate_cleanup_receipt,
)
from .engine_reconciliation import EngineReconciliationError
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
    from .engine_experiment import EngineExperiment
    from .engine_experiment_service import EngineControllerJobs as LegacyControllerJobs
    from .job_runtime import RunJobController
    from .product_store import ProductStore
    from .run_store import RunStore


_RECONCILIATION_POLICY = {
    "schema_version": "bluefire.installed-attempt-reconciliation.v1",
    "effects": "exact-reference-idempotent-no-launch",
}


class InstalledEngineCompositionError(RuntimeError):
    """A required protected dependency or lifecycle binding is unavailable."""


class InstalledEngineCleanupUnresolved(InstalledEngineCompositionError):
    """Retained cleanup is unresolved; only effect-specific recovery may advance it."""


class InstalledEngineResource(Protocol):
    def close(self) -> None: ...


class _LegacyControllerJobs:
    """Keep unprepared generic work closed while preserving check cancellation."""

    def __init__(self, prepared_jobs: EngineControllerJobs) -> None:
        self._prepared_jobs = prepared_jobs

    def submit(
        self,
        *,
        action: EngineControllerJobAction,
        experiment: EngineExperiment,
        request_ref: str,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        raise EngineControllerJobError("a protected prepared controller request is required")

    def settle_undispatched_check_cancellation(
        self, *, experiment_id: str, check_id: str, job_id: str
    ) -> Mapping[str, Any]:
        return self._prepared_jobs.settle_undispatched_check_cancellation(
            experiment_id=experiment_id, check_id=check_id, job_id=job_id
        )


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
    runtime_resolution_ref: str | None = None
    cleanup_owner: InstalledEngineBundleCleanupOwner | None = None
    resource_set_ref: str | None = None
    attempt_ref: str | None = None
    activation_ref: str | None = None


class InstalledAttemptFactory(Protocol):
    """Protected owner of exact reviewed target/provider/runtime components.

    Implementations must retain and verify their own target/provider transports,
    construct the attempt-bound forwarders and relays from reviewed authority,
    and return their lifecycle handles in ``InstalledAttemptComponents``.
    Dependency presence in this assembly is not transport custody verification.
    """

    @property
    def reconciliation_policy(self) -> Mapping[str, str]:
        """Declare no-launch, exact-reference idempotent recovery support."""
        ...

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
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
        composition: InstalledEngineComposition,
    ) -> InstalledAttemptComponents:
        """Reopen existing custody only; never allocate, start or reissue.

        Every returned resource and its ``close`` path must use the exact
        reconciliation reference idempotently. A crash may repeat the call
        with that same reference after an external effect but before the
        ProductStore settlement becomes visible.
        """
        ...


@dataclass(frozen=True, slots=True)
class InstalledEngineAdapters:
    controller: TrustedEngineController
    defense_executor: DefenseOperationExecutor | None
    check_executor: ControllerCheckExecutor | None
    attempts: InstalledAttemptFactory
    resources: tuple[InstalledEngineResource, ...] = ()
    controller_job_adapter_factory: InstalledControllerJobAdapterFactory | None = None
    artifact_store: EngineArtifactStore | None = None


@dataclass(frozen=True, slots=True)
class InstalledControllerJobAdapters:
    """Concrete controller-job executors bound to one service's exact stores."""

    defense_executor: DefenseOperationExecutor
    check_executor: ControllerCheckExecutor

    def __post_init__(self) -> None:
        if self.defense_executor is None or self.check_executor is None:
            raise InstalledEngineCompositionError(
                "installed controller-job adapter binding is incomplete"
            )


class InstalledControllerJobAdapterFactory(Protocol):
    """Late-bind controller-job adapters to exact service-owned stores."""

    def bind(
        self, *, store: ProductStore, run_store: RunStore, jobs: RunJobController
    ) -> InstalledControllerJobAdapters: ...


@dataclass(frozen=True, slots=True)
class InstalledEngineBinding:
    preparation: EngineActionPreparationCoordinator
    submission: EngineActionSubmissionCoordinator
    material_source: ProductStoreTenantActionMaterialSource
    preparer: ControllerOwnedTenantActionPreparer


@dataclass(slots=True)
class _BundleCleanup:
    owner: InstalledEngineBundleCleanupOwner
    cleanup_ref: str
    attempt_ref: str
    activation_ref: str
    owner_ref: str
    runtime_resolution_ref: str
    resource_set_ref: str
    resource_manifest: tuple[InstalledEngineCleanupResourceBinding, ...]
    resource_ids: frozenset[int]
    receipt: InstalledEngineBundleCleanupReceipt | None = None
    settle_attempted: bool = False


class _InstalledReconciliationCoordinator:
    """Keep composition lifecycle ownership around the ProductStore OS session."""

    def __init__(self, owner: InstalledEngineComposition) -> None:
        self._owner = owner

    @contextmanager
    def session(self, *, experiment_id: str, attempt_id: str) -> Iterator[Any]:
        owner = self._owner
        # Enter lifecycle tracking before waiting on the purpose lock. Shutdown
        # therefore refuses new work and joins a waiter as well as an active
        # reconciliation through its final ProductStore CAS.
        try:
            with owner._reconciliation_lease(attempt_id):
                with owner._lock:
                    raw = owner._product_store_reconciliation
                    owner._require_bound()
                if raw is None:
                    raise InstalledEngineCompositionError(
                        "engine reconciliation coordinator is unavailable"
                    )
                with raw.session(
                    experiment_id=experiment_id,
                    attempt_id=attempt_id,
                ) as session:
                    yield session
        except EngineReconciliationError:
            raise
        except InstalledEngineCompositionError as exc:
            raise EngineReconciliationError(
                "installed engine reconciliation lifecycle is unavailable"
            ) from exc


class _InstalledRuntime:
    def __init__(self, owner: InstalledEngineComposition) -> None:
        self._owner = owner

    @property
    def execution_claim_policy(self) -> Mapping[str, str]:
        return installed_execution_claim_policy()

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
            accepted_jobs = owner._accepted_jobs
            if binding.attempt_id in owner._dispatched:
                raise InstalledEngineCompositionError("attempt execution was already consumed")
            # Consume locally before any protected call; errors never retry effects.
            owner._dispatched.add(binding.attempt_id)
        if accepted_jobs is None:
            raise InstalledEngineCompositionError("accepted prepared jobs are unavailable")
        try:
            accepted = accepted_jobs.claim_for_execution(
                job_id=context.job_id, binding=binding, delegation=delegation
            )
        except AcceptedEngineJobError as exc:
            raise InstalledEngineCompositionError("accepted prepared job is unavailable") from exc
        if isinstance(accepted, PreDispatchCancelledEngineAttempt):
            accepted.validate(context.job_id, binding, delegation)
            raise AcceptedEnginePreDispatchCancelled(accepted.pre_dispatch_ref)
        if not isinstance(accepted, AcceptedPreparedEngineAttempt):
            raise InstalledEngineCompositionError("accepted prepared job is unavailable")
        try:
            accepted.validate(context.job_id, binding, delegation)
        except AcceptedEngineJobError as exc:
            raise InstalledEngineCompositionError("accepted prepared job binding changed") from exc
        context.checkpoint(
            {
                "phase": "engine_execution_claimed",
                "attempt_id": binding.attempt_id,
                "execution_claim_ref": accepted.claim_ref,
            }
        )
        # A checkpoint may pause long enough for admission to expire or be
        # revoked. Reassert the exact claim-bound resolution immediately before
        # the protected factory can allocate anything.
        try:
            accepted_jobs.require_current(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
            )
        except AcceptedEngineJobError as exc:
            raise InstalledEngineCompositionError(
                "accepted engine admission is no longer current"
            ) from exc
        components = owner.adapters.attempts.for_execution(
            accepted=accepted, binding=binding, delegation=delegation, composition=owner
        )
        owner._retain(
            components,
            expected_resolution_ref=accepted.runtime_resolution_ref,
            expected_attempt_ref=binding.binding_digest,
            expected_activation_ref=accepted.claim_ref,
        )
        return components.runtime.execute(context, binding, delegation, transition)

    def reconcile(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> EngineRuntimeSettlement:
        del binding, delegation, saved_record
        raise InstalledEngineCompositionError(
            "installed engine reconciliation requires its active claimed session"
        )

    def reconcile_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        *,
        reconciliation_ref: str,
    ) -> EngineRuntimeSettlement:
        owner = self._owner
        delegation.validate_attempt_binding(binding)
        if saved_record.binding != binding:
            raise InstalledEngineCompositionError("saved attempt binding changed")
        with owner._lock:
            owner._require_bound()
            accepted_jobs = owner._accepted_jobs
            coordinator = owner._product_store_reconciliation
        if accepted_jobs is None or coordinator is None:
            raise InstalledEngineCompositionError(
                "installed reconciliation dependencies are unavailable"
            )
        try:
            plan = coordinator.require_active_claimed(
                binding=binding,
                delegation=delegation,
                reconciliation_ref=reconciliation_ref,
            )
            accepted = accepted_jobs.reopen_for_reconciliation(
                binding=binding, delegation=delegation
            )
        except (AcceptedEngineJobError, EngineReconciliationError) as exc:
            raise InstalledEngineCompositionError(
                "accepted reconciliation intent is unavailable"
            ) from exc
        if not isinstance(accepted, AcceptedPreparedEngineAttempt):
            raise InstalledEngineCompositionError("claimed reconciliation lost its execution claim")
        try:
            accepted.validate(accepted.job_id, binding, delegation)
        except AcceptedEngineJobError as exc:
            raise InstalledEngineCompositionError(
                "accepted reconciliation binding changed"
            ) from exc
        if (
            accepted.job_id != plan.job_id
            or accepted.claim_ref != plan.claim_ref
            or accepted.binding_digest != plan.binding_digest
            or accepted.delegation_digest != plan.delegation_digest
            or accepted.runtime_resolution_ref != plan.runtime_resolution_ref
        ):
            raise InstalledEngineCompositionError("accepted reconciliation intent binding changed")
        owner._require_reconciliation_policy()
        try:
            components = owner.adapters.attempts.for_reconciliation(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                saved_record=saved_record,
                reconciliation_ref=reconciliation_ref,
                composition=owner,
            )
        except Exception as exc:
            raise InstalledEngineCompositionError(
                "installed attempt reconciliation factory failed"
            ) from exc
        reconcile = getattr(components.runtime, "reconcile_claimed", None)
        if not callable(reconcile):
            owner._discard_components(components)
            raise InstalledEngineCompositionError(
                "installed attempt runtime cannot reconcile claimed custody"
            )
        owner._retain(
            components,
            expected_resolution_ref=accepted.runtime_resolution_ref,
            expected_attempt_ref=binding.binding_digest,
            expected_activation_ref=accepted.claim_ref,
        )
        try:
            settlement = reconcile(
                binding,
                delegation,
                saved_record,
                reconciliation_ref=reconciliation_ref,
            )
        except Exception as exc:
            raise InstalledEngineCompositionError(
                "installed attempt reconciliation failed"
            ) from exc
        if (
            not isinstance(settlement, EngineRuntimeSettlement)
            or settlement.reconciliation_ref != reconciliation_ref
        ):
            raise InstalledEngineCompositionError(
                "installed reconciliation settlement binding changed"
            )
        return settlement


class InstalledEngineComposition:
    """One service's shared owners, with an effect-free second binding phase.

    Pass this owner as ``BlueFireService(engine_workflow_composition=...)`` or
    construct it through ``engine_workflow_composition_factory`` when protected
    sources must use the exact service-owned ProductStore. That inert factory
    closes its partial allocations on failure; after its returned owner is
    successfully claimed, the service owns construction rollback and shutdown.
    Explicit ``runtime``, ``controller``, and factory injection remains available
    for callers that manage their own lifecycle. The controller-job factory runs
    first; the preparation/submission factories bind after EngineExperimentService and
    EngineExperimentJobs exist. Construction never reads a source or invokes a
    factory. Protected sources and the target controller must already exist;
    the installed controller-job factory constructs executors only at binding.
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
        if adapters.artifact_store is not None and type(adapters.artifact_store) is not EngineArtifactStore:
            raise InstalledEngineCompositionError("artifact review requires a protected store")
        for field in fields(sources):
            if getattr(sources, field.name) is None:
                raise InstalledEngineCompositionError(f"required dependency absent: {field.name}")
        for name in ("controller", "attempts", "resources"):
            if getattr(adapters, name) is None:
                raise InstalledEngineCompositionError(f"required dependency absent: {name}")
        factory_mode = adapters.controller_job_adapter_factory is not None
        direct_pair = (
            adapters.defense_executor is not None,
            adapters.check_executor is not None,
        )
        if (factory_mode and any(direct_pair)) or (
            not factory_mode and direct_pair != (True, True)
        ):
            raise InstalledEngineCompositionError(
                "select either controller_job_adapter_factory or both "
                "defense_executor and check_executor"
            )
        if factory_mode and not callable(
            getattr(adapters.controller_job_adapter_factory, "bind", None)
        ):
            raise InstalledEngineCompositionError(
                "installed controller-job factory bind is unavailable"
            )
        self.sources, self.adapters = sources, adapters
        self._require_reconciliation_policy()
        if (
            not callable(clock)
            or not isinstance(reviewer, str)
            or not 1 <= len(reviewer) <= 200
            or reviewer != reviewer.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in reviewer)
        ):
            raise InstalledEngineCompositionError("trusted clock and stable reviewer required")
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
        self._operation_condition = threading.Condition(self._lock)
        self._shutdown_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._controller_jobs: EngineControllerJobs | None = None
        self._legacy_controller_jobs: _LegacyControllerJobs | None = None
        self._accepted_jobs: ProductStoreAcceptedEngineJobs | None = None
        self._product_store_reconciliation: ProductStoreEngineReconciliationCoordinator | None = (
            None
        )
        self._reconciliation_coordinator = _InstalledReconciliationCoordinator(self)
        self._service_claimed = False
        self._controller_job_owners: tuple[ProductStore, RunStore, RunJobController] | None = None
        self._store: ProductStore | None = None
        self._run_store: RunStore | None = None
        self._job_controller: RunJobController | None = None
        self._workspace: EngineExperimentService | None = None
        self._binding: InstalledEngineBinding | None = None
        self._dispatched: set[str] = set()
        self._resources = list(adapters.resources)
        self._bundle_cleanups: dict[str, _BundleCleanup] = {}
        self._cleanup_receipts: dict[str, InstalledEngineBundleCleanupReceipt] = {}
        self._managed_resources: dict[int, InstalledEngineResource] = {}
        self._legacy_closed_resource_ids: set[int] = set()
        self._legacy_unknown_resources: dict[int, InstalledEngineResource] = {}
        self._cleanup_collisions: list[InstalledAttemptComponents] = []
        self._active_reconciliations: set[str] = set()
        self._stopping = self._jobs_stopped = self._closed = False

    @property
    def live_provider_proof(self) -> bool:
        """Assembly and fake-provider output cannot establish live proof."""
        return False

    @property
    def cleanup_status(self) -> Mapping[str, object]:
        """Expose only receipt identities and unresolved counts."""

        with self._lock:
            return cleanup_status_document(
                self._cleanup_receipts,
                pending_bundle_count=len(self._bundle_cleanups),
                legacy_unknown_count=len(self._legacy_unknown_resources),
                collision_count=len(self._cleanup_collisions),
                closed=self._closed,
                stopping=self._stopping,
            )

    @property
    def reconciliation_coordinator(self) -> _InstalledReconciliationCoordinator:
        """Return the exact lifecycle wrapper after ProductStore binding."""

        with self._lock:
            self._require_open()
            if self._product_store_reconciliation is None:
                raise InstalledEngineCompositionError(
                    "engine reconciliation coordinator is not bound"
                )
            return self._reconciliation_coordinator

    def _require_open(self) -> None:
        if self._closed or self._stopping:
            raise InstalledEngineCompositionError("installed engine composition is stopping")

    def _require_reconciliation_policy(self) -> None:
        try:
            policy = getattr(self.adapters.attempts, "reconciliation_policy", None)
            valid = isinstance(policy, Mapping) and dict(policy) == _RECONCILIATION_POLICY
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise InstalledEngineCompositionError(
                "attempt factory reconciliation policy is unavailable"
            )

    def claim_service(self) -> None:
        """Atomically transfer this unused owner before binding service resources."""
        with self._lock:
            self._require_open()
            if (
                self._service_claimed
                or self._controller_job_owners is not None
                or self._binding is not None
            ):
                raise InstalledEngineCompositionError("composition belongs to another service")
            self._service_claimed = True

    def _require_bound(self) -> None:
        self._require_open()
        if self._binding is None:
            raise InstalledEngineCompositionError("installed engine composition is not bound")

    def require_product_store(self, store: ProductStore) -> None:
        """Reassert the exact service-owned store without reading product data."""

        with self._lock:
            self._require_bound()
            if store is not self._store:
                raise InstalledEngineCompositionError(
                    "installed engine composition belongs to another service"
                )

    def controller_jobs_factory(
        self, store: ProductStore, run_store: RunStore, jobs: RunJobController
    ) -> _LegacyControllerJobs:
        with self._lock:
            self._require_open()
            if store is None or run_store is None or jobs is None:
                raise InstalledEngineCompositionError("shared service owners are required")
            owners = self._controller_job_owners
            if owners is None:
                # Reserve identity before calling an injected factory. A failed
                # bind may retry, but cannot substitute a different service.
                self._controller_job_owners = (store, run_store, jobs)
            elif store is not owners[0] or run_store is not owners[1] or jobs is not owners[2]:
                raise InstalledEngineCompositionError("composition belongs to another service")
            if self._controller_jobs is None:
                # The attempt factory is constructed before the service owns its
                # RunStore. Bind that exact store once, before any attempt can be
                # dispatched, so the installed runtime can finalize observations
                # in the same run history the service presents.
                bind_run_store = getattr(self.adapters.attempts, "bind_run_store", None)
                if callable(bind_run_store):
                    bind_run_store(run_store)
                factory = self.adapters.controller_job_adapter_factory
                if factory is None:
                    defense_executor = self.adapters.defense_executor
                    check_executor = self.adapters.check_executor
                else:
                    bound = factory.bind(store=store, run_store=run_store, jobs=jobs)
                    if not isinstance(bound, InstalledControllerJobAdapters):
                        raise InstalledEngineCompositionError(
                            "installed controller-job factory returned an invalid binding"
                        )
                    defense_executor = bound.defense_executor
                    check_executor = bound.check_executor
                controller_jobs = EngineControllerJobs(
                    controller=jobs,
                    repository=store,
                    defense_executor=defense_executor,
                    check_executor=check_executor,
                    clock=self._clock,
                )
                legacy_controller_jobs = _LegacyControllerJobs(controller_jobs)
                accepted_jobs = ProductStoreAcceptedEngineJobs(
                    store=store,
                    resolver=self.resolver,
                    reviewer=self._reviewer,
                    clock=self._clock,
                )
                reconciliation = ProductStoreEngineReconciliationCoordinator(
                    store=store,
                    reviewer=self._reviewer,
                    clock=self._clock,
                )
                self._store, self._run_store, self._job_controller = store, run_store, jobs
                self._controller_jobs = controller_jobs
                self._legacy_controller_jobs = legacy_controller_jobs
                self._accepted_jobs = accepted_jobs
                self._product_store_reconciliation = reconciliation
            elif (
                store is not self._store
                or run_store is not self._run_store
                or jobs is not self._job_controller
            ):
                raise InstalledEngineCompositionError("composition belongs to another service")
            if self._legacy_controller_jobs is None:
                raise InstalledEngineCompositionError("installed controller jobs are unavailable")
            return self._legacy_controller_jobs

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
                or workspace._jobs._reconciliation is not self._reconciliation_coordinator
                or workspace._controller is not self.controller
                or workspace._controller_jobs is not self._legacy_controller_jobs
                or workspace._job_lifecycle is not self._job_controller
                or self._controller_jobs is None
                or self._accepted_jobs is None
                or self._product_store_reconciliation is None
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
                    execution_claim_policy=self.runtime.execution_claim_policy,
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
        controller_jobs: LegacyControllerJobs | None,
    ) -> EngineActionSubmissionCoordinator:
        if jobs is not workspace._jobs or controller_jobs is not self._legacy_controller_jobs:
            raise InstalledEngineCompositionError("prepared submission jobs binding changed")
        return self.bind(store, workspace).submission

    @contextmanager
    def _reconciliation_lease(self, attempt_id: str) -> Iterator[None]:
        with self._operation_condition:
            self._require_bound()
            if attempt_id in self._active_reconciliations:
                raise InstalledEngineCompositionError(
                    "engine attempt reconciliation is already active"
                )
            self._active_reconciliations.add(attempt_id)
        try:
            yield
        finally:
            with self._operation_condition:
                self._active_reconciliations.discard(attempt_id)
                self._operation_condition.notify_all()

    def _retain(
        self,
        components: InstalledAttemptComponents,
        *,
        expected_resolution_ref: str,
        expected_attempt_ref: str,
        expected_activation_ref: str,
    ) -> None:
        valid = isinstance(components, InstalledAttemptComponents) and (
            components.runtime is not self.runtime
            and components.runtime_resolution_ref == expected_resolution_ref
            and components.attempt_ref == expected_attempt_ref
            and components.activation_ref == expected_activation_ref
        )
        cleanup: _BundleCleanup | None = None
        if valid:
            try:
                cleanup = self._bundle_cleanup(components)
            except Exception:
                valid = False
        if not valid:
            self._discard_components(components)
            raise InstalledEngineCompositionError("exact attempt components are unavailable")
        if cleanup is None:
            raise InstalledEngineCompositionError("exact attempt cleanup owner is unavailable")
        with self._lock:
            unavailable = self._stopping or self._closed
            if not unavailable:
                if cleanup.cleanup_ref in self._bundle_cleanups:
                    self._cleanup_collisions.append(components)
                    raise InstalledEngineCompositionError(
                        "installed cleanup identity collision remains unresolved"
                    )
                else:
                    self._bundle_cleanups[cleanup.cleanup_ref] = cleanup
                    self._managed_resources.update(
                        {id(resource): resource for resource in components.resources}
                    )
                if not unavailable:
                    self._resources.extend(components.resources)
        if unavailable:
            self._discard_components(components)
            raise InstalledEngineCompositionError("installed engine composition is stopping")

    def _bundle_cleanup(self, components: InstalledAttemptComponents) -> _BundleCleanup:
        owner, resource_set_ref = components.cleanup_owner, components.resource_set_ref
        if (
            owner is None
            or not isinstance(resource_set_ref, str)
            or not isinstance(components.attempt_ref, str)
            or not isinstance(components.activation_ref, str)
            or not isinstance(components.runtime_resolution_ref, str)
        ):
            raise InstalledEngineCleanupError("attempt cleanup owner is incomplete")
        validate_cleanup_owner(
            owner,
            attempt_ref=components.attempt_ref,
            activation_ref=components.activation_ref,
            runtime_resolution_ref=components.runtime_resolution_ref,
            resource_set_ref=resource_set_ref,
        )
        cleanup_ref = cleanup_request_ref(
            components.attempt_ref,
            components.activation_ref,
            owner.owner_ref,
            components.runtime_resolution_ref,
            resource_set_ref,
        )
        return _BundleCleanup(
            owner=owner,
            cleanup_ref=cleanup_ref,
            attempt_ref=components.attempt_ref,
            activation_ref=components.activation_ref,
            owner_ref=owner.owner_ref,
            runtime_resolution_ref=components.runtime_resolution_ref,
            resource_set_ref=resource_set_ref,
            resource_manifest=owner.resource_manifest,
            resource_ids=frozenset(id(resource) for resource in components.resources),
        )

    def _settle_bundle(self, cleanup: _BundleCleanup) -> bool:
        try:
            validate_cleanup_owner(
                cleanup.owner,
                attempt_ref=cleanup.attempt_ref,
                activation_ref=cleanup.activation_ref,
                owner_ref=cleanup.owner_ref,
                runtime_resolution_ref=cleanup.runtime_resolution_ref,
                resource_set_ref=cleanup.resource_set_ref,
            )
            if cleanup.receipt is None:
                if cleanup.settle_attempted:
                    # The first call might have applied an effect before it
                    # failed. Only an exact durable owner may resolve that
                    # uncertainty; never repeat the initial settlement.
                    return False
                cleanup.settle_attempted = True
                receipt = cleanup.owner.settle(cleanup_ref=cleanup.cleanup_ref)
            else:
                receipt = cleanup.owner.reconcile(receipt=cleanup.receipt)
            cleanup.receipt = validate_cleanup_receipt(
                receipt,
                cleanup_ref=cleanup.cleanup_ref,
                attempt_ref=cleanup.attempt_ref,
                activation_ref=cleanup.activation_ref,
                owner_ref=cleanup.owner_ref,
                runtime_resolution_ref=cleanup.runtime_resolution_ref,
                resource_set_ref=cleanup.resource_set_ref,
                resource_manifest=cleanup.resource_manifest,
                predecessor=cleanup.receipt,
            )
            with self._lock:
                self._cleanup_receipts[cleanup.cleanup_ref] = cleanup.receipt
        except Exception:
            return False
        return cleanup.receipt.state == "verified_absent"

    def _close_legacy_resources(self, resources: tuple[InstalledEngineResource, ...]) -> bool:
        failed = False
        seen: set[int] = set()
        for resource in resources:
            identity = id(resource)
            if identity in seen or identity in self._managed_resources:
                continue
            seen.add(identity)
            with self._lock:
                if identity in self._legacy_closed_resource_ids:
                    continue
                if identity in self._legacy_unknown_resources:
                    failed = True
                    continue
            try:
                resource.close()
            except Exception:
                # close(2) may release a descriptor even when it reports an
                # error. Retain the object and uncertainty, but never retry the
                # same generic numeric handle. An effect-specific cleanup owner
                # is required for safe reconciliation.
                with self._lock:
                    self._legacy_unknown_resources[identity] = resource
                failed = True
            else:
                with self._lock:
                    self._legacy_closed_resource_ids.add(identity)
        return not failed

    def _discard_components(self, components: object) -> bool:
        if not isinstance(components, InstalledAttemptComponents):
            return False
        # Serialize with close() so the same effect owner is never settled
        # concurrently by a discard and service shutdown.
        with self._close_lock:
            try:
                cleanup = self._bundle_cleanup(components)
            except Exception:
                with self._lock:
                    self._cleanup_collisions.append(components)
                    self._closed = False
                return False
            with self._lock:
                existing = self._bundle_cleanups.get(cleanup.cleanup_ref)
                if existing is not None:
                    self._cleanup_collisions.append(components)
                    self._closed = False
                    return False
                self._bundle_cleanups[cleanup.cleanup_ref] = cleanup
                self._managed_resources.update(
                    {id(resource): resource for resource in components.resources}
                )
                self._closed = False
            if self._settle_bundle(cleanup):
                with self._lock:
                    self._bundle_cleanups.pop(cleanup.cleanup_ref, None)
                    retained = {id(resource) for resource in self._resources}
                    for identity in cleanup.resource_ids:
                        if identity not in retained:
                            self._managed_resources.pop(identity, None)
                return True
            return False

    def shutdown_jobs(self, jobs: RunJobController | None = None) -> None:
        """Join the exact service controller, including before factory binding."""
        with self._shutdown_lock:
            with self._lock:
                expected_jobs = (
                    self._controller_job_owners[2]
                    if self._controller_job_owners is not None
                    else self._job_controller
                )
                if jobs is not None and expected_jobs is not None and jobs is not expected_jobs:
                    raise InstalledEngineCompositionError("composition belongs to another service")
                if self._jobs_stopped or self._closed:
                    return
                self._stopping = True
                # A service may fail before its first factory binds us. Its
                # explicit controller still needs cancellation and joining.
                jobs = expected_jobs if jobs is None else jobs
                self._job_controller = jobs
            if jobs is not None:
                jobs.shutdown(cancel_active=True)
            with self._operation_condition:
                while self._active_reconciliations:
                    self._operation_condition.wait()
                self._jobs_stopped = True

    def close(self) -> None:
        with self._close_lock:
            with self._lock:
                if self._closed:
                    return
                if (
                    self._job_controller is not None or self._controller_job_owners is not None
                ) and not self._jobs_stopped:
                    raise InstalledEngineCompositionError("shutdown_jobs must finish before close")
                if self._active_reconciliations:
                    raise InstalledEngineCompositionError(
                        "engine reconciliation must finish before close"
                    )
                resources = tuple(reversed(self._resources))
                cleanups = tuple(reversed(tuple(self._bundle_cleanups.values())))
            failed = False
            for cleanup in cleanups:
                if self._settle_bundle(cleanup):
                    with self._lock:
                        self._bundle_cleanups.pop(cleanup.cleanup_ref, None)
                else:
                    failed = True
            if not self._close_legacy_resources(resources):
                failed = True
            with self._lock:
                failed = (
                    failed
                    or bool(self._bundle_cleanups)
                    or bool(self._legacy_unknown_resources)
                    or bool(self._cleanup_collisions)
                )
                if not failed:
                    self._closed = True
            if failed:
                raise InstalledEngineCleanupUnresolved(
                    "installed engine resource close failed; cleanup remains unresolved"
                ) from None
