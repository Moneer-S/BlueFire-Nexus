"""Protected V2 openers for the installed Strix attempt factory.

This application-layer join reopens exact durable authority, composes only
activation-bound owners, and keeps reconciliation structurally no-launch.
Effects remain behind reviewed platform providers; absent providers keep the
installed path closed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from .accepted_engine_jobs import AcceptedPreparedEngineAttempt
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_delegation import EngineCapabilityDelegation
from .engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
    INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
    InstalledControlledStrixRuntimeIdentity,
    InstalledStrixExecutionBundle,
    InstalledStrixReconciliationBundle,
    InstalledStrixRuntimeResolution,
)
from .engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthorityGuard,
    InstalledStrixV2AuthoritySnapshot,
    InstalledStrixV2AuthoritySource,
    InstalledStrixV2CompositionError,
    InstalledStrixV2HistoricalSnapshot,
    InstalledStrixV2PrelaunchSnapshot,
    _binding_set_digest,
    _digest,
)
from .engine_installed_v2_resources import (
    InstalledStrixV2CaidoProvider,
    InstalledStrixV2CleanupReceipt,
    InstalledStrixV2ExecAttachment,
    InstalledStrixV2ExecutionAllocation,
    InstalledStrixV2ExecutionResourceFactory,
    InstalledStrixV2ExecutionResources,
    InstalledStrixV2ModelGatewayLease,
    InstalledStrixV2ReconciliationReopen,
    InstalledStrixV2ReconciliationResourceFactory,
    InstalledStrixV2ReopenedResources,
    InstalledStrixV2ResourceReceipt,
    InstalledStrixV2RuntimeBuilder,
    InstalledStrixV2SourceCollection,
    InstalledStrixV2TargetRelay,
    InstalledStrixV2WorkerController,
)
from .strix_controlled_runtime_admission import StrixControlledLaunchPlanV2
from .util import content_hash

if TYPE_CHECKING:
    from .product_store import ProductStore
    from .run_store import RunStore


class InstalledStrixV2CleanupUncertain(InstalledStrixV2CompositionError):
    """An abort retained both its triggering and cleanup failures."""

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


class ControllerOwnedInstalledStrixV2Openers:
    """Concrete execution/reconciliation opener pair with closed dependencies."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        authority_source: InstalledStrixV2AuthoritySource,
        execution_resources: InstalledStrixV2ExecutionResourceFactory,
        reconciliation_resources: InstalledStrixV2ReconciliationResourceFactory,
        runtime_builder: InstalledStrixV2RuntimeBuilder,
    ) -> None:
        if product_store is None:
            raise InstalledStrixV2CompositionError("V2 product store is required")
        for value, method, label in (
            (authority_source, "require_prelaunch_current", "prelaunch authority source"),
            (authority_source, "retain_activation", "activation retention source"),
            (authority_source, "require_current", "activation authority source"),
            (authority_source, "reopen_reconciliation", "reconciliation authority source"),
            (execution_resources, "begin_execution", "execution resource factory"),
            (
                reconciliation_resources,
                "begin_reconciliation",
                "reconciliation resource factory",
            ),
            (runtime_builder, "build_execution", "execution runtime builder"),
            (runtime_builder, "build_reconciliation", "reconciliation runtime builder"),
        ):
            if not callable(getattr(value, method, None)):
                raise InstalledStrixV2CompositionError(f"V2 {label} is incomplete")
        self._store = product_store
        self._authority = authority_source
        self._execution_resources = execution_resources
        self._reconciliation_resources = reconciliation_resources
        self._runtime_builder = runtime_builder
        self._run_store: RunStore | None = None

    def bind_run_store(self, run_store: RunStore) -> None:
        """Give the runtime builder only the run history owned by this service."""
        if run_store is None:
            raise InstalledStrixV2CompositionError("V2 run store is required")
        if self._run_store is not None:
            if self._run_store is not run_store:
                raise InstalledStrixV2CompositionError("V2 run store belongs to another service")
            return
        bind = getattr(self._runtime_builder, "bind_run_store", None)
        if not callable(bind):
            raise InstalledStrixV2CompositionError("V2 runtime cannot retain the service run store")
        bind(run_store)
        self._run_store = run_store

    def open_execution(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        runtime_resolution: InstalledStrixRuntimeResolution,
    ) -> InstalledStrixExecutionBundle:
        self._require_inputs(product_store, accepted, binding, delegation, runtime_resolution)
        guard = InstalledStrixV2AuthorityGuard(
            product_store=self._store,
            source=self._authority,
            accepted=accepted,
            binding=binding,
            delegation=delegation,
        )
        prelaunch = guard.require_prelaunch_current()
        launch_plan = prelaunch.validate(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
        )
        allocation = self._execution_resources.begin_execution(
            product_store=self._store,
            snapshot=prelaunch,
            launch_plan=launch_plan,
            authority_guard=guard,
        )
        transaction_ref: str | None = None
        activated: InstalledStrixV2AuthoritySnapshot | None = None
        committed = False
        try:
            transaction_ref = _digest(
                getattr(allocation, "transaction_ref", None),
                "V2 execution transaction",
            )
            _require_transaction_methods(
                allocation,
                methods=("allocate", "commit", "close"),
                label="execution allocation",
            )
            if getattr(allocation, "effects_started", None) is not False:
                raise InstalledStrixV2CompositionError("V2 execution begin was not effect-free")
            # Begin is contractually inert. Reopen after it and immediately before
            # the first allocation; the exec authority's own fence is still the
            # atomic before-send owner retained below.
            if guard.require_prelaunch_current().prelaunch_ref != prelaunch.prelaunch_ref:
                raise InstalledStrixV2CompositionError("V2 authority changed before allocation")
            resources = allocation.allocate()
            if not isinstance(resources, InstalledStrixV2ExecutionResources):
                raise InstalledStrixV2CompositionError("V2 execution resources are invalid")
            # Allocation may start fixed, owned resources. It must durably
            # publish their observed activation before this read succeeds.
            activated = guard.require_current()
            if activated.prelaunch_ref != prelaunch.prelaunch_ref:
                raise InstalledStrixV2CompositionError("V2 activation changed prelaunch authority")
            if resources.authority_guard is not guard:
                raise InstalledStrixV2CompositionError("V2 execution authority owner changed")
            resources.validate(activated.activation)
            identity = _runtime_identity(accepted, binding, delegation, activated, launch_plan)
            runtime = self._runtime_builder.build_execution(
                identity=identity,
                authority_guard=guard,
                snapshot=activated,
                launch_plan=launch_plan,
                resources=resources,
            )
            _validate_execution_runtime(
                runtime, identity, authority_guard=guard, resources=resources
            )
            if guard.require_current().snapshot_ref != activated.snapshot_ref:
                raise InstalledStrixV2CompositionError("V2 authority changed after construction")
            bundle = InstalledStrixExecutionBundle(
                runtime, identity, resources.resources, resources.cleanup_owner
            )
            bundle.validate()
            allocation.commit()
            committed = True
            return bundle
        except Exception as exc:
            if not committed:
                _abort_transaction(
                    allocation,
                    exc,
                    message="V2 execution allocation cleanup is uncertain",
                    action="execution_abort",
                    transaction_ref=transaction_ref,
                    authority_ref=guard.authority_ref,
                    activation_receipt_ref=(
                        None if activated is None else activated.activation.receipt_ref
                    ),
                    reconciliation_ref=None,
                )
            raise

    def reopen_reconciliation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> InstalledStrixReconciliationBundle:
        self._require_base(product_store, accepted, binding, delegation)
        _digest(reconciliation_ref, "V2 reconciliation reference")
        if not isinstance(saved_record, EngineAttemptRecord) or saved_record.binding != binding:
            raise InstalledStrixV2CompositionError("V2 saved attempt binding changed")
        try:
            snapshot = self._authority.reopen_reconciliation(
                product_store=self._store,
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                saved_record=saved_record,
                reconciliation_ref=reconciliation_ref,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError(
                "V2 reconciliation authority is unavailable"
            ) from exc
        if not isinstance(snapshot, InstalledStrixV2HistoricalSnapshot):
            raise InstalledStrixV2CompositionError("V2 reconciliation authority is invalid")
        snapshot.validate(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            saved_record=saved_record,
            reconciliation_ref=reconciliation_ref,
        )
        reopening = self._reconciliation_resources.begin_reconciliation(
            product_store=self._store,
            snapshot=snapshot,
            saved_record=saved_record,
            reconciliation_ref=reconciliation_ref,
        )
        transaction_ref: str | None = None
        committed = False
        try:
            transaction_ref = _digest(
                getattr(reopening, "transaction_ref", None),
                "V2 reconciliation transaction",
            )
            _require_transaction_methods(
                reopening,
                methods=("reopen", "commit", "close"),
                label="reconciliation reopen",
            )
            if getattr(reopening, "effects_started", None) is not False:
                raise InstalledStrixV2CompositionError(
                    "V2 reconciliation begin was not effect-free"
                )
            resources = reopening.reopen()
            if not isinstance(resources, InstalledStrixV2ReopenedResources):
                raise InstalledStrixV2CompositionError("V2 reopened resources are invalid")
            resources.validate(
                activation=snapshot.activation,
                authority_ref=snapshot.authority_ref,
                reconciliation_ref=reconciliation_ref,
            )
            identity = snapshot.identity
            runtime = self._runtime_builder.build_reconciliation(
                identity=identity,
                snapshot=snapshot,
                resources=resources,
                reconciliation_ref=reconciliation_ref,
            )
            _validate_reconciliation_runtime(
                runtime,
                identity,
                resources=resources,
                reconciliation_ref=reconciliation_ref,
            )
            bundle = InstalledStrixReconciliationBundle(
                runtime,
                identity,
                resources.resources,
                reconciliation_ref,
                resources.cleanup_owner,
            )
            bundle.validate()
            reopening.commit()
            committed = True
            return bundle
        except Exception as exc:
            if not committed:
                _abort_transaction(
                    reopening,
                    exc,
                    message="V2 reconciliation cleanup is uncertain",
                    action="reconciliation_abort",
                    transaction_ref=transaction_ref,
                    authority_ref=snapshot.authority_ref,
                    activation_receipt_ref=snapshot.activation.receipt_ref,
                    reconciliation_ref=reconciliation_ref,
                )
            raise

    def _require_inputs(
        self,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        runtime_resolution: InstalledStrixRuntimeResolution,
    ) -> None:
        self._require_base(product_store, accepted, binding, delegation)
        try:
            resolution_ref = runtime_resolution.resolution_ref
        except Exception as exc:
            raise InstalledStrixV2CompositionError("V2 current resolution is invalid") from exc
        if resolution_ref != accepted.runtime_resolution_ref:
            raise InstalledStrixV2CompositionError("V2 current resolution changed")

    def _require_base(
        self,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        if product_store is not self._store:
            raise InstalledStrixV2CompositionError("V2 opener belongs to another service")
        try:
            accepted.validate(accepted.job_id, binding, delegation)
            delegation.validate_attempt_binding(binding)
        except Exception as exc:
            raise InstalledStrixV2CompositionError("V2 accepted authority changed") from exc


def _runtime_identity(
    accepted: AcceptedPreparedEngineAttempt,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    snapshot: InstalledStrixV2AuthoritySnapshot,
    launch_plan: StrixControlledLaunchPlanV2,
) -> InstalledControlledStrixRuntimeIdentity:
    row = snapshot.admission.to_dict()
    activation = snapshot.activation
    values: dict[str, Any] = {
        "schema_version": INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
        "backend": "bluefire-controlled",
        "job_id": accepted.job_id,
        "preparation_ref": accepted.preparation_ref,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "claim_ref": accepted.claim_ref,
        "runtime_resolution_ref": accepted.runtime_resolution_ref,
        "controlled_profile_ref": row["execution_identity"]["controlled_runtime_profile"][
            "profile_digest"
        ],
        "runtime_admission_ref": snapshot.admission.admission_ref,
        "runtime_activation_ref": activation.receipt_ref,
        "controlled_launch_digest": launch_plan.launch_digest,
        "startup_overlay_ref": activation.startup_overlay_ref,
        "runtime_closure_plan_ref": activation.runtime_closure_plan_ref,
        "fixed_exec_receipt_ref": activation.fixed_exec_receipt_ref,
        "target_scope_admission_ref": activation.target_scope_admission_ref,
        "installed_projection_ref": activation.installed_projection_ref,
        "sealed_inputs_ref": activation.sealed_inputs_ref,
        "runtime_image_contract_ref": activation.runtime_image_contract_ref,
        "runtime_image_qualification_ref": activation.runtime_image_qualification_ref,
        "runtime_image_closure_ref": activation.runtime_image_closure_ref,
        "worker_identity_ref": activation.worker_identity_ref,
        "exec_broker_binding_digest": launch_plan.exec_broker_binding_digest,
        "worker_launch_digest": activation.worker_launch_digest,
        "worker_controller_server_ref": activation.worker_controller_server_ref,
        "worker_custody_ready_receipt_ref": (activation.worker_custody_ready_receipt_ref),
        "resource_set_digest": _binding_set_digest(
            activation.role_bindings,
            expected_roles=INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
        ),
    }
    values["launch_digest"] = content_hash(
        {
            "schema_version": INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
            **{name: values[name] for name in values if name != "schema_version"},
        }
    )
    return InstalledControlledStrixRuntimeIdentity(**values)


def _validate_execution_runtime(
    runtime: object,
    identity: InstalledControlledStrixRuntimeIdentity,
    *,
    authority_guard: InstalledStrixV2AuthorityGuard,
    resources: InstalledStrixV2ExecutionResources,
) -> None:
    if getattr(runtime, "installed_runtime_identity", None) != identity:
        raise InstalledStrixV2CompositionError("V2 runtime identity changed")
    if getattr(runtime, "installed_authority_guard", None) is not authority_guard:
        raise InstalledStrixV2CompositionError("V2 runtime authority owner changed")
    expected_owners = (
        ("installed_caido_provider", resources.caido_provider),
        ("installed_exec_attachment", resources.exec_attachment),
        (
            "installed_exec_dispatch_authority",
            resources.exec_attachment.dispatch_authority,
        ),
        (
            "installed_exec_dispatch_runtime",
            resources.exec_attachment.dispatch_runtime,
        ),
        ("installed_docker_transport", resources.exec_attachment.docker_transport),
        (
            "installed_operation_watchdog",
            resources.exec_attachment.operation_watchdog,
        ),
        (
            "installed_exec_cancellation_authority",
            resources.exec_attachment.cancellation_authority,
        ),
        (
            "installed_worker_containment_verifier",
            resources.worker_controller.containment_verifier,
        ),
        ("installed_worker_controller", resources.worker_controller),
        (
            "installed_worker_controller_server",
            resources.worker_controller.controller_server,
        ),
        ("installed_model_gateway_lease", resources.model_gateway_lease),
        (
            "installed_source_collection",
            resources.source_collection,
        ),
        ("installed_target_relay", resources.target_relay),
    )
    if any(getattr(runtime, name, None) is not owner for name, owner in expected_owners):
        raise InstalledStrixV2CompositionError("V2 runtime protected owner changed")
    if getattr(runtime, "installed_execution_enabled", None) is not True:
        raise InstalledStrixV2CompositionError("V2 runtime execution is not enabled")


def _validate_reconciliation_runtime(
    runtime: object,
    identity: InstalledControlledStrixRuntimeIdentity,
    *,
    resources: InstalledStrixV2ReopenedResources,
    reconciliation_ref: str,
) -> None:
    if getattr(runtime, "installed_runtime_identity", None) != identity:
        raise InstalledStrixV2CompositionError("V2 historical runtime identity changed")
    if getattr(runtime, "installed_reconciliation_ref", None) != reconciliation_ref:
        raise InstalledStrixV2CompositionError("V2 reconciliation runtime changed")
    if getattr(runtime, "installed_execution_disabled", None) is not True or any(
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
    ):
        raise InstalledStrixV2CompositionError("V2 reconciliation runtime can execute")
    expected_owners = tuple((f"installed_{row.role}", row.owner) for row in resources.resources)
    if any(getattr(runtime, name, None) is not owner for name, owner in expected_owners):
        raise InstalledStrixV2CompositionError("V2 reconciliation runtime ignored a cleanup owner")


def _abort_transaction(
    owner: object,
    original: Exception,
    *,
    message: str,
    action: str,
    transaction_ref: str | None,
    authority_ref: str,
    activation_receipt_ref: str | None,
    reconciliation_ref: str | None,
) -> None:
    if not callable(getattr(owner, "close", None)):
        issue = InstalledStrixV2CompositionError("V2 transaction close is unavailable")
        raise InstalledStrixV2CleanupUncertain(
            message,
            original_error=original,
            cleanup_errors=(issue,),
        ) from original
    try:
        receipt = cast(Any, owner).close()
    except Exception as cleanup_error:
        raise InstalledStrixV2CleanupUncertain(
            message,
            original_error=original,
            cleanup_errors=(cleanup_error,),
        ) from original
    if (
        transaction_ref is None
        or not isinstance(receipt, InstalledStrixV2CleanupReceipt)
        or receipt.action != action
        or receipt.transaction_ref != transaction_ref
        or receipt.authority_ref != authority_ref
        or (
            activation_receipt_ref is not None
            and receipt.activation_receipt_ref != activation_receipt_ref
        )
        or receipt.reconciliation_ref != reconciliation_ref
        or receipt.absence_verified is not True
        or receipt.cleanup_uncertain is not False
    ):
        issue = InstalledStrixV2CompositionError("V2 cleanup receipt changed")
        raise InstalledStrixV2CleanupUncertain(
            message,
            original_error=original,
            cleanup_errors=(issue,),
        ) from original
    raise original


def _require_transaction_methods(
    owner: object,
    *,
    methods: tuple[str, ...],
    label: str,
) -> None:
    if any(not callable(getattr(owner, name, None)) for name in methods):
        raise InstalledStrixV2CompositionError(f"V2 {label} is incomplete")


__all__ = [
    "ControllerOwnedInstalledStrixV2Openers",
    "InstalledStrixV2ActivationReceipt",
    "InstalledStrixV2AuthorityGuard",
    "InstalledStrixV2AuthoritySnapshot",
    "InstalledStrixV2AuthoritySource",
    "InstalledStrixV2CaidoProvider",
    "InstalledStrixV2CleanupReceipt",
    "InstalledStrixV2CleanupUncertain",
    "InstalledStrixV2CompositionError",
    "InstalledStrixV2ExecAttachment",
    "InstalledStrixV2ExecutionAllocation",
    "InstalledStrixV2ExecutionResourceFactory",
    "InstalledStrixV2ExecutionResources",
    "InstalledStrixV2HistoricalSnapshot",
    "InstalledStrixV2PrelaunchSnapshot",
    "InstalledStrixV2ModelGatewayLease",
    "InstalledStrixV2ReconciliationReopen",
    "InstalledStrixV2ReconciliationResourceFactory",
    "InstalledStrixV2ReopenedResources",
    "InstalledStrixV2ResourceReceipt",
    "InstalledStrixV2RuntimeBuilder",
    "InstalledStrixV2SourceCollection",
    "InstalledStrixV2TargetRelay",
    "InstalledStrixV2WorkerController",
]
