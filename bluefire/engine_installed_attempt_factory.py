"""Concrete, store-bound assembly gate for one installed Strix attempt.

This module replaces the unconstrained installed-attempt protocol injection
with a maintained composition gate. It deliberately does *not* wrap the legacy
``StrixEngineRuntime``: that runtime still builds the stock Docker launch plan.
Only a runtime that exposes the exact claim-derived ``bluefire-controlled``
identity accepted here can reach the installed composition.

Platform owners implement the Docker, worker, Caido, target, model, artifact,
and source-settlement details behind the two narrow opener interfaces below.
Execution may allocate only after the durable accepted claim is consumed.
Reconciliation may reopen exact custody only; it cannot allocate, start, or
reissue work. Resource role labels make lifecycle ownership complete and
reviewable, but are not themselves proof that containment is effective.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Protocol, cast

from .accepted_engine_jobs import AcceptedPreparedEngineAttempt
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment_jobs import EngineAttemptRuntime
from .engine_installed_cleanup import (
    InstalledEngineBundleCleanupOwner,
    InstalledEngineCleanupError,
    InstalledEngineCleanupResourceBinding,
    resource_set_ref_for_owner,
    validate_cleanup_owner,
)
from .engine_installed_composition import (
    InstalledAttemptComponents,
    InstalledEngineComposition,
    InstalledEngineResource,
)
from .strix_engine_runtime import StrixEngineRuntime
from .util import content_hash

if TYPE_CHECKING:
    from .product_store import ProductStore
    from .run_store import RunStore


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_JOB = re.compile(r"^job-[0-9a-f]{32}$")
_RECONCILIATION_POLICY = {
    "schema_version": "bluefire.installed-attempt-reconciliation.v1",
    "effects": "exact-reference-idempotent-no-launch",
}
INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA = "bluefire.installed-controlled-strix-runtime.v2"
INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA = "bluefire.installed-controlled-strix-launch.v2"
INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES = (
    "caido_channel",
    "docker_control",
    "model_gateway",
    "source_collection",
    "target_relay",
    "worker_controller",
)
INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES = (
    "docker_custody",
    "operation_custody",
    "source_settlement",
    "target_observation",
    "worker_containment",
)
INSTALLED_STRIX_RESOURCE_ROLES = INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
_RESOURCE_ROLES = frozenset(
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES + INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
)


class InstalledAttemptFactoryError(RuntimeError):
    """A protected attempt bundle or its exact composition is unavailable."""


class InstalledAttemptCleanupUncertain(InstalledAttemptFactoryError):
    """A failed bundle could not prove that every returned owner closed."""

    def __init__(
        self,
        message: str,
        *,
        original_error: BaseException,
        cleanup_errors: tuple[BaseException, ...],
    ) -> None:
        super().__init__(message)
        self.original_error = original_error
        self.cleanup_errors = cleanup_errors


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InstalledAttemptFactoryError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class InstalledStrixOwnedResource:
    """One final-shutdown owner and its attempt-bound protected role."""

    role: str
    binding_ref: str
    owner: InstalledEngineResource

    def __post_init__(self) -> None:
        if self.role not in _RESOURCE_ROLES:
            raise InstalledAttemptFactoryError("installed attempt resource role is invalid")
        _digest(self.binding_ref, "installed attempt resource binding")
        if not callable(getattr(self.owner, "close", None)):
            raise InstalledAttemptFactoryError("installed attempt resource owner is invalid")


def installed_strix_resource_set_digest(
    resources: tuple[InstalledStrixOwnedResource, ...],
    *,
    expected_roles: tuple[str, ...] = INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
) -> str:
    if not isinstance(resources, tuple):
        raise InstalledAttemptFactoryError("installed attempt resources are invalid")
    if any(not isinstance(resource, InstalledStrixOwnedResource) for resource in resources):
        raise InstalledAttemptFactoryError("installed attempt resource row is invalid")
    roles = tuple(resource.role for resource in resources)
    if roles != expected_roles:
        raise InstalledAttemptFactoryError(
            "installed attempt resource ownership is incomplete or noncanonical"
        )
    return cast(
        str,
        content_hash(
            {
                "schema_version": "bluefire.installed-strix-resource-set.v1",
                "resources": [
                    {"role": resource.role, "binding_ref": resource.binding_ref}
                    for resource in resources
                ],
            }
        ),
    )


_resource_set_digest = installed_strix_resource_set_digest


@dataclass(frozen=True, slots=True)
class InstalledControlledStrixRuntimeIdentity:
    """Claim-derived identity required from the controlled installed runtime."""

    schema_version: str
    backend: str
    job_id: str
    preparation_ref: str
    binding_digest: str
    delegation_digest: str
    claim_ref: str
    runtime_resolution_ref: str
    controlled_profile_ref: str
    runtime_admission_ref: str
    runtime_activation_ref: str
    controlled_launch_digest: str
    startup_overlay_ref: str
    runtime_closure_plan_ref: str
    fixed_exec_receipt_ref: str
    target_scope_admission_ref: str
    installed_projection_ref: str
    sealed_inputs_ref: str
    runtime_image_contract_ref: str
    runtime_image_qualification_ref: str
    runtime_image_closure_ref: str
    worker_identity_ref: str
    exec_broker_binding_digest: str
    worker_launch_digest: str
    worker_controller_server_ref: str
    worker_custody_ready_receipt_ref: str
    resource_set_digest: str
    launch_digest: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA
            or self.backend != "bluefire-controlled"
            or not isinstance(self.job_id, str)
            or _JOB.fullmatch(self.job_id) is None
        ):
            raise InstalledAttemptFactoryError(
                "installed controlled runtime identity is unsupported"
            )
        for name in (
            "preparation_ref",
            "binding_digest",
            "delegation_digest",
            "claim_ref",
            "runtime_resolution_ref",
            "controlled_profile_ref",
            "runtime_admission_ref",
            "runtime_activation_ref",
            "controlled_launch_digest",
            "startup_overlay_ref",
            "runtime_closure_plan_ref",
            "fixed_exec_receipt_ref",
            "target_scope_admission_ref",
            "installed_projection_ref",
            "sealed_inputs_ref",
            "runtime_image_contract_ref",
            "runtime_image_qualification_ref",
            "runtime_image_closure_ref",
            "worker_identity_ref",
            "exec_broker_binding_digest",
            "worker_launch_digest",
            "worker_controller_server_ref",
            "worker_custody_ready_receipt_ref",
            "resource_set_digest",
            "launch_digest",
        ):
            _digest(getattr(self, name), f"installed controlled runtime {name}")
        if self.launch_digest != self.expected_launch_digest():
            raise InstalledAttemptFactoryError(
                "installed controlled runtime launch identity changed"
            )

    def expected_launch_digest(self) -> str:
        return cast(
            str,
            content_hash(
                {
                    "schema_version": INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
                    "backend": self.backend,
                    "job_id": self.job_id,
                    "preparation_ref": self.preparation_ref,
                    "binding_digest": self.binding_digest,
                    "delegation_digest": self.delegation_digest,
                    "claim_ref": self.claim_ref,
                    "runtime_resolution_ref": self.runtime_resolution_ref,
                    "controlled_profile_ref": self.controlled_profile_ref,
                    "runtime_admission_ref": self.runtime_admission_ref,
                    "runtime_activation_ref": self.runtime_activation_ref,
                    "controlled_launch_digest": self.controlled_launch_digest,
                    "startup_overlay_ref": self.startup_overlay_ref,
                    "runtime_closure_plan_ref": self.runtime_closure_plan_ref,
                    "fixed_exec_receipt_ref": self.fixed_exec_receipt_ref,
                    "target_scope_admission_ref": self.target_scope_admission_ref,
                    "installed_projection_ref": self.installed_projection_ref,
                    "sealed_inputs_ref": self.sealed_inputs_ref,
                    "runtime_image_contract_ref": self.runtime_image_contract_ref,
                    "runtime_image_qualification_ref": self.runtime_image_qualification_ref,
                    "runtime_image_closure_ref": self.runtime_image_closure_ref,
                    "worker_identity_ref": self.worker_identity_ref,
                    "exec_broker_binding_digest": self.exec_broker_binding_digest,
                    "worker_launch_digest": self.worker_launch_digest,
                    "worker_controller_server_ref": self.worker_controller_server_ref,
                    "worker_custody_ready_receipt_ref": self.worker_custody_ready_receipt_ref,
                    "resource_set_digest": self.resource_set_digest,
                }
            ),
        )


class InstalledControlledStrixRuntime(EngineAttemptRuntime, Protocol):
    """Runtime assembled from the reviewed controlled backend components."""

    @property
    def installed_runtime_identity(self) -> InstalledControlledStrixRuntimeIdentity: ...

    def reconcile_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        *,
        reconciliation_ref: str,
    ) -> Any: ...


class InstalledControlledStrixReconciliationRuntime(Protocol):
    """Historical cleanup runtime that cannot dispatch or reconnect work."""

    @property
    def installed_runtime_identity(self) -> InstalledControlledStrixRuntimeIdentity: ...

    @property
    def installed_execution_disabled(self) -> bool: ...

    def reconcile(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
    ) -> Any: ...

    def reconcile_claimed(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        *,
        reconciliation_ref: str,
    ) -> Any: ...


class InstalledStrixRuntimeResolution(Protocol):
    """Opaque current resolution returned by the composition's trusted resolver."""

    @property
    def resolution_ref(self) -> str: ...


@dataclass(frozen=True, slots=True)
class InstalledStrixExecutionBundle:
    """Complete controlled runtime and final-shutdown owners for execution."""

    runtime: InstalledControlledStrixRuntime
    identity: InstalledControlledStrixRuntimeIdentity
    resources: tuple[InstalledStrixOwnedResource, ...]
    cleanup_owner: InstalledEngineBundleCleanupOwner | None = None

    def validate(self) -> None:
        _validate_bundle(self.runtime, self.identity, self.resources)
        _validate_bundle_cleanup(self.cleanup_owner, self.identity, self.resources)


@dataclass(frozen=True, slots=True)
class InstalledStrixReconciliationBundle:
    """Exact no-launch reopen of a previously claimed controlled runtime."""

    runtime: InstalledControlledStrixReconciliationRuntime
    identity: InstalledControlledStrixRuntimeIdentity
    resources: tuple[InstalledStrixOwnedResource, ...]
    reconciliation_ref: str
    cleanup_owner: InstalledEngineBundleCleanupOwner | None = None

    def validate(self) -> None:
        _digest(self.reconciliation_ref, "installed attempt reconciliation")
        _validate_reconciliation_bundle(self.runtime, self.identity, self.resources)
        _validate_bundle_cleanup(self.cleanup_owner, self.identity, self.resources)


def _validate_bundle_cleanup(
    owner: InstalledEngineBundleCleanupOwner | None,
    identity: InstalledControlledStrixRuntimeIdentity,
    resources: tuple[InstalledStrixOwnedResource, ...],
) -> None:
    if owner is None:
        raise InstalledAttemptFactoryError("installed attempt cleanup owner is unavailable")
    if any(not callable(getattr(owner, method, None)) for method in ("settle", "reconcile")):
        raise InstalledAttemptFactoryError("installed attempt cleanup owner is incomplete")
    expected_manifest = tuple(
        InstalledEngineCleanupResourceBinding(resource.role, resource.binding_ref)
        for resource in resources
    )
    try:
        resource_set_ref = resource_set_ref_for_owner(owner)
        validate_cleanup_owner(
            owner,
            attempt_ref=identity.binding_digest,
            activation_ref=identity.claim_ref,
            runtime_resolution_ref=identity.runtime_resolution_ref,
            resource_set_ref=resource_set_ref,
        )
    except (AttributeError, InstalledEngineCleanupError) as exc:
        raise InstalledAttemptFactoryError("installed attempt cleanup owner changed") from exc
    if getattr(owner, "runtime_activation_ref", None) != identity.runtime_activation_ref:
        raise InstalledAttemptFactoryError("installed attempt cleanup activation changed")
    if owner.resource_manifest != expected_manifest:
        raise InstalledAttemptFactoryError("installed attempt cleanup resource set changed")


def _validate_bundle(
    runtime: object,
    identity: InstalledControlledStrixRuntimeIdentity,
    resources: tuple[InstalledStrixOwnedResource, ...],
) -> None:
    if not isinstance(identity, InstalledControlledStrixRuntimeIdentity):
        raise InstalledAttemptFactoryError("installed controlled runtime identity is invalid")
    # The V1 runtime always calls strix_adapter.build_launch_plan, whose
    # controller-owned backend value remains the stock Docker backend. Its
    # mutable Python object must not be relabeled as the controlled runtime.
    if isinstance(runtime, StrixEngineRuntime):
        raise InstalledAttemptFactoryError("legacy stock-Docker runtime is refused")
    resource_digest = _resource_set_digest(resources)
    if identity.resource_set_digest != resource_digest:
        raise InstalledAttemptFactoryError("installed controlled resource set changed")
    required = ("execute", "reconcile", "reconcile_claimed")
    if any(not callable(getattr(runtime, name, None)) for name in required):
        raise InstalledAttemptFactoryError("installed controlled runtime is incomplete")
    try:
        observed = cast(InstalledControlledStrixRuntime, runtime).installed_runtime_identity
    except Exception as exc:
        raise InstalledAttemptFactoryError(
            "installed controlled runtime identity is unavailable"
        ) from exc
    if observed != identity:
        raise InstalledAttemptFactoryError("installed controlled runtime identity changed")


def _validate_reconciliation_bundle(
    runtime: object,
    identity: InstalledControlledStrixRuntimeIdentity,
    resources: tuple[InstalledStrixOwnedResource, ...],
) -> None:
    if not isinstance(identity, InstalledControlledStrixRuntimeIdentity):
        raise InstalledAttemptFactoryError("installed historical runtime identity is invalid")
    if isinstance(runtime, StrixEngineRuntime):
        raise InstalledAttemptFactoryError("legacy stock-Docker runtime is refused")
    installed_strix_resource_set_digest(
        resources,
        expected_roles=INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    )
    required = ("reconcile", "reconcile_claimed")
    if (
        any(not callable(getattr(runtime, name, None)) for name in required)
        or getattr(runtime, "installed_execution_disabled", None) is not True
        or any(
            callable(getattr(runtime, name, None))
            for name in (
                "allocate",
                "claim",
                "connect",
                "dispatch",
                "execute",
                "launch",
                "reconnect",
                "send",
                "spawn",
                "start",
            )
        )
    ):
        raise InstalledAttemptFactoryError(
            "installed reconciliation runtime is not structurally no-launch"
        )
    try:
        observed = cast(
            InstalledControlledStrixReconciliationRuntime,
            runtime,
        ).installed_runtime_identity
    except Exception as exc:
        raise InstalledAttemptFactoryError(
            "installed historical runtime identity is unavailable"
        ) from exc
    if observed != identity:
        raise InstalledAttemptFactoryError("installed historical runtime identity changed")


class InstalledStrixAttemptOpener(Protocol):
    """Allocate a complete bundle only after the durable claim is consumed.

    The opener retains responsibility for any partial allocation until it has
    returned a complete ``InstalledStrixExecutionBundle``.
    """

    def open_execution(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        runtime_resolution: InstalledStrixRuntimeResolution,
    ) -> InstalledStrixExecutionBundle: ...


class InstalledStrixReconciliationOpener(Protocol):
    """Reopen exact custody only; never allocate, start, or reissue work.

    The opener retains responsibility for partial handles until it returns a
    complete reconciliation bundle.
    """

    def reopen_reconciliation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> InstalledStrixReconciliationBundle: ...


class ControllerOwnedInstalledStrixAttemptFactory:
    """Maintained concrete ``InstalledAttemptFactory`` for installed Strix.

    The exact service ProductStore is pinned at construction and reasserted
    after the composition's two-phase service binding. The durable accepted
    execution claim, not an in-memory set, is the one-shot authority fence.
    """

    def __init__(
        self,
        *,
        product_store: ProductStore,
        execution_opener: InstalledStrixAttemptOpener,
        reconciliation_opener: InstalledStrixReconciliationOpener,
    ) -> None:
        if product_store is None:
            raise InstalledAttemptFactoryError("installed attempt store is required")
        if not callable(getattr(execution_opener, "open_execution", None)):
            raise InstalledAttemptFactoryError("installed execution opener is incomplete")
        if not callable(getattr(reconciliation_opener, "reopen_reconciliation", None)):
            raise InstalledAttemptFactoryError("installed reconciliation opener is incomplete")
        self._store = product_store
        self._execution_opener = execution_opener
        self._reconciliation_opener = reconciliation_opener
        self._run_store: RunStore | None = None
        self._run_store_lock = threading.Lock()

    def bind_run_store(self, run_store: RunStore) -> None:
        """Bind the sole service run history before installed dispatch."""
        if run_store is None:
            raise InstalledAttemptFactoryError("installed run store is required")
        with self._run_store_lock:
            if self._run_store is not None:
                if self._run_store is not run_store:
                    raise InstalledAttemptFactoryError("installed run store belongs to another service")
                return
            seen: set[int] = set()
            for opener in (self._execution_opener, self._reconciliation_opener):
                if id(opener) in seen:
                    continue
                seen.add(id(opener))
                bind = getattr(opener, "bind_run_store", None)
                if callable(bind):
                    bind(run_store)
            self._run_store = run_store

    @property
    def reconciliation_policy(self) -> Mapping[str, str]:
        return dict(_RECONCILIATION_POLICY)

    def for_execution(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        composition: InstalledEngineComposition,
    ) -> InstalledAttemptComponents:
        self._require_owner(composition)
        self._require_accepted(accepted, binding, delegation)
        resolution = self._require_current(composition, accepted, binding, delegation)
        bundle = self._execution_opener.open_execution(
            product_store=self._store,
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            runtime_resolution=resolution,
        )
        if not isinstance(bundle, InstalledStrixExecutionBundle):
            raise InstalledAttemptFactoryError(
                "protected execution opener returned an invalid bundle"
            )
        try:
            bundle.validate()
            # Close the allocation window with another protected authority read.
            self._require_current(composition, accepted, binding, delegation)
            self._require_identity(bundle.identity, accepted, binding, delegation)
            return _components(
                bundle.runtime,
                bundle.resources,
                bundle.cleanup_owner,
                bundle.identity,
            )
        except Exception as exc:
            self._discard_rejected_bundle(
                bundle,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=composition,
                original_error=exc,
            )
            raise

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
        self._require_owner(composition)
        self._require_accepted(accepted, binding, delegation)
        _digest(reconciliation_ref, "installed attempt reconciliation")
        if not isinstance(saved_record, EngineAttemptRecord) or saved_record.binding != binding:
            raise InstalledAttemptFactoryError("saved installed attempt binding changed")
        bundle = self._reconciliation_opener.reopen_reconciliation(
            product_store=self._store,
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
            reconciliation_ref=reconciliation_ref,
        )
        if not isinstance(bundle, InstalledStrixReconciliationBundle):
            raise InstalledAttemptFactoryError(
                "protected reconciliation opener returned an invalid bundle"
            )
        try:
            bundle.validate()
            if bundle.reconciliation_ref != reconciliation_ref:
                raise InstalledAttemptFactoryError("protected reconciliation identity changed")
            self._require_identity(bundle.identity, accepted, binding, delegation)
            return _components(
                bundle.runtime,
                bundle.resources,
                bundle.cleanup_owner,
                bundle.identity,
            )
        except Exception as exc:
            self._discard_rejected_bundle(
                bundle,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=composition,
                original_error=exc,
            )
            raise

    def _discard_rejected_bundle(
        self,
        bundle: InstalledStrixExecutionBundle | InstalledStrixReconciliationBundle,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        composition: InstalledEngineComposition,
        original_error: BaseException,
    ) -> None:
        try:
            self._require_identity(bundle.identity, accepted, binding, delegation)
            _validate_bundle_cleanup(bundle.cleanup_owner, bundle.identity, bundle.resources)
            components = _components(
                bundle.runtime,
                bundle.resources,
                bundle.cleanup_owner,
                bundle.identity,
            )
        except Exception as binding_error:
            # The returned owner cannot be trusted for this claim. Close known
            # handles as best effort, but never claim their absence from close().
            _close_resources(bundle.resources, original_error=original_error)
            raise InstalledAttemptCleanupUncertain(
                "installed attempt cleanup owner is unverified",
                original_error=original_error,
                cleanup_errors=(binding_error,),
            ) from original_error
        try:
            verified_absent = composition._discard_components(components)
        except Exception as cleanup_error:
            raise InstalledAttemptCleanupUncertain(
                "installed attempt cleanup remains unresolved",
                original_error=original_error,
                cleanup_errors=(cleanup_error,),
            ) from original_error
        if not verified_absent:
            raise InstalledAttemptCleanupUncertain(
                "installed attempt cleanup remains unresolved",
                original_error=original_error,
                cleanup_errors=(),
            ) from original_error

    def _require_owner(self, composition: InstalledEngineComposition) -> None:
        if not isinstance(composition, InstalledEngineComposition):
            raise InstalledAttemptFactoryError("installed engine composition is invalid")
        try:
            composition.require_product_store(self._store)
        except Exception as exc:
            raise InstalledAttemptFactoryError(
                "installed attempt factory belongs to another service"
            ) from exc

    @staticmethod
    def _require_accepted(
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        if not isinstance(accepted, AcceptedPreparedEngineAttempt):
            raise InstalledAttemptFactoryError("accepted installed execution claim is unavailable")
        try:
            accepted.validate(accepted.job_id, binding, delegation)
            delegation.validate_attempt_binding(binding)
        except Exception as exc:
            raise InstalledAttemptFactoryError(
                "accepted installed execution claim changed"
            ) from exc

    @staticmethod
    def _require_current(
        composition: InstalledEngineComposition,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> InstalledStrixRuntimeResolution:
        try:
            resolution = composition.resolver.require_current(
                binding,
                delegation,
                expected_resolution_ref=accepted.runtime_resolution_ref,
            )
        except Exception as exc:
            raise InstalledAttemptFactoryError(
                "installed runtime resolution is no longer current"
            ) from exc
        try:
            resolution_ref = resolution.resolution_ref
        except Exception as exc:
            raise InstalledAttemptFactoryError("installed runtime resolution changed") from exc
        if resolution_ref != accepted.runtime_resolution_ref:
            raise InstalledAttemptFactoryError("installed runtime resolution changed")
        return cast(InstalledStrixRuntimeResolution, resolution)

    @staticmethod
    def _require_identity(
        identity: InstalledControlledStrixRuntimeIdentity,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        if (
            identity.backend != "bluefire-controlled"
            or identity.job_id != accepted.job_id
            or identity.preparation_ref != accepted.preparation_ref
            or identity.binding_digest != binding.binding_digest
            or identity.delegation_digest != delegation.delegation_digest
            or identity.claim_ref != accepted.claim_ref
            or identity.runtime_resolution_ref != accepted.runtime_resolution_ref
        ):
            raise InstalledAttemptFactoryError("protected controlled runtime identity changed")


def _components(
    runtime: InstalledControlledStrixRuntime | InstalledControlledStrixReconciliationRuntime,
    resources: tuple[InstalledStrixOwnedResource, ...],
    cleanup_owner: InstalledEngineBundleCleanupOwner | None,
    identity: InstalledControlledStrixRuntimeIdentity,
) -> InstalledAttemptComponents:
    _validate_bundle_cleanup(cleanup_owner, identity, resources)
    assert cleanup_owner is not None
    owners: list[InstalledEngineResource] = []
    seen: set[int] = set()
    for resource in resources:
        owner_id = id(resource.owner)
        if owner_id not in seen:
            seen.add(owner_id)
            owners.append(resource.owner)
    return InstalledAttemptComponents(
        runtime=cast(EngineAttemptRuntime, runtime),
        resources=tuple(owners),
        runtime_resolution_ref=identity.runtime_resolution_ref,
        cleanup_owner=cleanup_owner,
        resource_set_ref=resource_set_ref_for_owner(cleanup_owner),
        attempt_ref=identity.binding_digest,
        activation_ref=identity.claim_ref,
    )


def _close_resources(
    resources: tuple[object, ...],
    *,
    original_error: BaseException,
) -> None:
    seen: set[int] = set()
    cleanup_errors: list[BaseException] = []
    for resource in reversed(resources):
        try:
            owner = resource.owner  # type: ignore[attr-defined]
        except Exception:
            continue
        close = getattr(owner, "close", None)
        if not callable(close):
            continue
        identity = id(owner)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            close()
        except Exception as exc:
            cleanup_errors.append(exc)
    if cleanup_errors:
        raise InstalledAttemptCleanupUncertain(
            "installed attempt cleanup is uncertain",
            original_error=original_error,
            cleanup_errors=tuple(cleanup_errors),
        ) from original_error


__all__ = [
    "ControllerOwnedInstalledStrixAttemptFactory",
    "INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES",
    "INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA",
    "INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES",
    "INSTALLED_STRIX_RESOURCE_ROLES",
    "INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA",
    "InstalledAttemptCleanupUncertain",
    "InstalledAttemptFactoryError",
    "InstalledControlledStrixRuntime",
    "InstalledControlledStrixReconciliationRuntime",
    "InstalledControlledStrixRuntimeIdentity",
    "InstalledStrixAttemptOpener",
    "InstalledStrixExecutionBundle",
    "InstalledStrixOwnedResource",
    "InstalledStrixReconciliationBundle",
    "InstalledStrixReconciliationOpener",
    "InstalledStrixRuntimeResolution",
    "installed_strix_resource_set_digest",
]
