"""Protected resource and transaction contracts for installed Strix V2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Protocol

from .engine_attempt_contract import EngineAttemptRecord
from .engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    InstalledControlledStrixReconciliationRuntime,
    InstalledControlledStrixRuntime,
    InstalledControlledStrixRuntimeIdentity,
    InstalledStrixOwnedResource,
    installed_strix_resource_set_digest,
)
from .engine_installed_cleanup import InstalledEngineBundleCleanupOwner
from .engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthorityGuard,
    InstalledStrixV2AuthoritySnapshot,
    InstalledStrixV2CompositionError,
    InstalledStrixV2HistoricalSnapshot,
    InstalledStrixV2PrelaunchSnapshot,
    _digest,
    _role_bindings,
)
from .strix_controlled_runtime_admission import StrixControlledLaunchPlanV2
from .util import content_hash

if TYPE_CHECKING:
    from .product_store import ProductStore


_RESOURCE_RECEIPT_SCHEMA = "bluefire.installed-strix-v2-resource-receipt.v1"
_CLEANUP_RECEIPT_SCHEMA = "bluefire.installed-strix-v2-cleanup-receipt.v1"


@dataclass(frozen=True, slots=True)
class InstalledStrixV2ResourceReceipt:
    action: str
    authority_ref: str
    activation_receipt_ref: str
    role_bindings: tuple[tuple[str, str], ...]
    reconciliation_ref: str | None
    receipt_ref: str

    def __post_init__(self) -> None:
        if self.action not in {"allocated", "reopened"}:
            raise InstalledStrixV2CompositionError("V2 resource receipt action is invalid")
        for value, label in (
            (self.authority_ref, "V2 resource authority"),
            (self.activation_receipt_ref, "V2 resource activation"),
            (self.receipt_ref, "V2 resource receipt"),
        ):
            _digest(value, label)
        expected_roles = (
            INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
            if self.action == "allocated"
            else INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
        )
        bindings = _role_bindings(self.role_bindings, expected_roles=expected_roles)
        if bindings != self.role_bindings:
            raise InstalledStrixV2CompositionError("V2 resource receipt bindings changed")
        if (self.action == "reopened") != (self.reconciliation_ref is not None):
            raise InstalledStrixV2CompositionError("V2 resource reconciliation receipt changed")
        if self.reconciliation_ref is not None:
            _digest(self.reconciliation_ref, "V2 resource reconciliation")
        if self.receipt_ref != content_hash(self.document(include_receipt=False)):
            raise InstalledStrixV2CompositionError("V2 resource receipt changed")

    @classmethod
    def create(
        cls,
        *,
        action: str,
        authority_ref: str,
        activation_receipt_ref: str,
        role_bindings: tuple[tuple[str, str], ...],
        reconciliation_ref: str | None = None,
    ) -> InstalledStrixV2ResourceReceipt:
        values: dict[str, Any] = {
            "action": action,
            "authority_ref": authority_ref,
            "activation_receipt_ref": activation_receipt_ref,
            "role_bindings": role_bindings,
            "reconciliation_ref": reconciliation_ref,
        }
        document = _resource_receipt_document(values)
        return cls(**values, receipt_ref=content_hash(document))

    def document(self, *, include_receipt: bool = True) -> dict[str, Any]:
        result = _resource_receipt_document(
            {
                "action": self.action,
                "authority_ref": self.authority_ref,
                "activation_receipt_ref": self.activation_receipt_ref,
                "role_bindings": self.role_bindings,
                "reconciliation_ref": self.reconciliation_ref,
            }
        )
        if include_receipt:
            result["receipt_ref"] = self.receipt_ref
        return result


@dataclass(frozen=True, slots=True)
class InstalledStrixV2CleanupReceipt:
    """Typed proof that an uncommitted transaction retained no live effects."""

    schema_version: str
    action: str
    transaction_ref: str
    authority_ref: str
    activation_receipt_ref: str | None
    reconciliation_ref: str | None
    absence_verified: bool
    cleanup_uncertain: bool
    receipt_ref: str

    def __post_init__(self) -> None:
        if self.schema_version != _CLEANUP_RECEIPT_SCHEMA:
            raise InstalledStrixV2CompositionError("V2 cleanup receipt schema is unsupported")
        if self.action not in {"execution_abort", "reconciliation_abort"}:
            raise InstalledStrixV2CompositionError("V2 cleanup receipt action is invalid")
        for value, label in (
            (self.transaction_ref, "V2 cleanup transaction"),
            (self.authority_ref, "V2 cleanup authority"),
            (self.receipt_ref, "V2 cleanup receipt"),
        ):
            _digest(value, label)
        if self.activation_receipt_ref is not None:
            _digest(self.activation_receipt_ref, "V2 cleanup activation")
        if (self.action == "reconciliation_abort") != (self.reconciliation_ref is not None):
            raise InstalledStrixV2CompositionError("V2 cleanup reconciliation changed")
        if self.reconciliation_ref is not None:
            _digest(self.reconciliation_ref, "V2 cleanup reconciliation")
        if self.absence_verified is not True or self.cleanup_uncertain is not False:
            raise InstalledStrixV2CompositionError("V2 cleanup absence is unverified")
        if self.receipt_ref != content_hash(self.document(include_receipt=False)):
            raise InstalledStrixV2CompositionError("V2 cleanup receipt changed")

    @classmethod
    def create(
        cls,
        *,
        action: str,
        transaction_ref: str,
        authority_ref: str,
        activation_receipt_ref: str | None,
        reconciliation_ref: str | None = None,
    ) -> InstalledStrixV2CleanupReceipt:
        values: dict[str, Any] = {
            "schema_version": _CLEANUP_RECEIPT_SCHEMA,
            "action": action,
            "transaction_ref": transaction_ref,
            "authority_ref": authority_ref,
            "activation_receipt_ref": activation_receipt_ref,
            "reconciliation_ref": reconciliation_ref,
            "absence_verified": True,
            "cleanup_uncertain": False,
        }
        return cls(
            schema_version=_CLEANUP_RECEIPT_SCHEMA,
            action=action,
            transaction_ref=transaction_ref,
            authority_ref=authority_ref,
            activation_receipt_ref=activation_receipt_ref,
            reconciliation_ref=reconciliation_ref,
            absence_verified=True,
            cleanup_uncertain=False,
            receipt_ref=content_hash(values),
        )

    def document(self, *, include_receipt: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "action": self.action,
            "transaction_ref": self.transaction_ref,
            "authority_ref": self.authority_ref,
            "activation_receipt_ref": self.activation_receipt_ref,
            "reconciliation_ref": self.reconciliation_ref,
            "absence_verified": self.absence_verified,
            "cleanup_uncertain": self.cleanup_uncertain,
        }
        if include_receipt:
            result["receipt_ref"] = self.receipt_ref
        return result


def _resource_receipt_document(values: Mapping[str, Any]) -> dict[str, Any]:
    expected_roles = (
        INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
        if values["action"] == "allocated"
        else INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
    )
    return {
        "schema_version": _RESOURCE_RECEIPT_SCHEMA,
        "action": values["action"],
        "authority_ref": values["authority_ref"],
        "activation_receipt_ref": values["activation_receipt_ref"],
        "role_bindings": [
            {"role": role, "binding_ref": binding_ref}
            for role, binding_ref in _role_bindings(
                values["role_bindings"], expected_roles=expected_roles
            )
        ],
        "reconciliation_ref": values["reconciliation_ref"],
    }


class InstalledStrixV2ExecAttachment(Protocol):
    @property
    def exec_broker_binding_digest(self) -> str: ...

    @property
    def dispatch_authority_ref(self) -> str: ...

    @property
    def dispatch_authority(self) -> object: ...

    @property
    def dispatch_runtime(self) -> object: ...

    @property
    def docker_transport(self) -> object: ...

    @property
    def cancellation_ref(self) -> str: ...

    @property
    def cancellation_authority(self) -> object: ...

    @property
    def operation_watchdog_ref(self) -> str: ...

    @property
    def operation_watchdog(self) -> object: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def close(self) -> None: ...


class InstalledStrixV2CaidoProvider(Protocol):
    """Exact provider owner; mode flags come from this retained object."""

    @property
    def provider_identity_ref(self) -> str: ...

    @property
    def mode(self) -> str: ...

    @property
    def test_provider(self) -> bool: ...

    @property
    def live_caido_proof(self) -> bool: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def close(self) -> None: ...


class InstalledStrixV2ModelGatewayLease(Protocol):
    """Custody-bound adapter; never a generic secret-value lease."""

    @property
    def lease_binding_ref(self) -> str: ...

    @property
    def custody_identity_ref(self) -> str: ...

    @property
    def provider_kind(self) -> str: ...

    @property
    def live_model_proof(self) -> bool: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def claim(self, binding: object, custody_identity: object) -> str: ...

    def revoke(self) -> None: ...

    def close(self) -> None: ...


class InstalledStrixV2SourceCollection(Protocol):
    @property
    def binding_ref(self) -> str: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def close(self) -> None: ...


class InstalledStrixV2TargetRelay(Protocol):
    @property
    def binding_ref(self) -> str: ...

    @property
    def target_scope_admission_ref(self) -> str: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def close(self) -> None: ...


class InstalledStrixV2WorkerController(Protocol):
    @property
    def startup_overlay_ref(self) -> str: ...

    @property
    def runtime_closure_plan_ref(self) -> str: ...

    @property
    def fixed_exec_receipt_ref(self) -> str: ...

    @property
    def installed_projection_ref(self) -> str: ...

    @property
    def sealed_inputs_ref(self) -> str: ...

    @property
    def runtime_image_contract_ref(self) -> str: ...

    @property
    def runtime_image_qualification_ref(self) -> str: ...

    @property
    def runtime_image_closure_ref(self) -> str: ...

    @property
    def worker_identity_ref(self) -> str: ...

    @property
    def custody_ready_receipt_ref(self) -> str: ...

    @property
    def worker_launch_digest(self) -> str: ...

    @property
    def worker_containment_ref(self) -> str: ...

    @property
    def custody_identity_ref(self) -> str: ...

    @property
    def controller_server(self) -> object: ...

    @property
    def containment_verifier(self) -> object: ...

    @property
    def model_gateway_lease(self) -> InstalledStrixV2ModelGatewayLease: ...

    @property
    def cleanup_uncertain(self) -> bool: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class InstalledStrixV2ExecutionResources:
    authority_guard: InstalledStrixV2AuthorityGuard
    resources: tuple[InstalledStrixOwnedResource, ...]
    caido_provider: InstalledStrixV2CaidoProvider
    exec_attachment: InstalledStrixV2ExecAttachment
    model_gateway_lease: InstalledStrixV2ModelGatewayLease
    source_collection: InstalledStrixV2SourceCollection
    target_relay: InstalledStrixV2TargetRelay
    worker_controller: InstalledStrixV2WorkerController
    receipt: InstalledStrixV2ResourceReceipt
    cleanup_owner: InstalledEngineBundleCleanupOwner | None = None

    def validate(self, activation: InstalledStrixV2ActivationReceipt) -> None:
        _validate_resources(self.resources, activation)
        if not isinstance(self.authority_guard, InstalledStrixV2AuthorityGuard):
            raise InstalledStrixV2CompositionError("V2 execution authority guard changed")
        by_role = {resource.role: resource.owner for resource in self.resources}
        if (
            by_role["caido_channel"] is not self.caido_provider
            or by_role["docker_control"] is not self.exec_attachment
            or by_role["model_gateway"] is not self.model_gateway_lease
            or by_role["source_collection"] is not self.source_collection
            or by_role["target_relay"] is not self.target_relay
            or by_role["worker_controller"] is not self.worker_controller
            or self.worker_controller.model_gateway_lease is not self.model_gateway_lease
        ):
            raise InstalledStrixV2CompositionError("V2 execution handle ownership changed")
        if (
            _digest(
                getattr(self.caido_provider, "provider_identity_ref", None),
                "V2 Caido provider identity",
            )
            != activation.caido_provider_identity_ref
            or getattr(self.caido_provider, "mode", None) != activation.caido_mode
            or getattr(self.caido_provider, "test_provider", None)
            is not activation.caido_test_provider
            or getattr(self.caido_provider, "live_caido_proof", None)
            is not activation.caido_live_proof
            or not callable(getattr(self.caido_provider, "close", None))
            or type(getattr(self.caido_provider, "cleanup_uncertain", None)) is not bool
            or self.caido_provider.cleanup_uncertain
        ):
            raise InstalledStrixV2CompositionError("V2 Caido provider owner changed")
        if (
            _digest(
                getattr(self.exec_attachment, "exec_broker_binding_digest", None),
                "V2 exec attachment",
            )
            != activation.exec_broker_binding_digest
            or _digest(
                getattr(self.exec_attachment, "dispatch_authority_ref", None),
                "V2 exec dispatch authority",
            )
            != activation.exec_dispatch_authority_ref
            or _digest(
                getattr(self.exec_attachment, "cancellation_ref", None),
                "V2 exec cancellation",
            )
            != activation.exec_cancellation_ref
            or not callable(getattr(self.exec_attachment, "close", None))
            or getattr(self.exec_attachment, "dispatch_authority", None) is None
            or getattr(self.exec_attachment, "dispatch_runtime", None) is None
            or getattr(self.exec_attachment, "docker_transport", None) is None
            or not callable(getattr(self.exec_attachment.docker_transport, "exchange", None))
            or getattr(self.exec_attachment, "cancellation_authority", None) is None
            or _digest(
                getattr(self.exec_attachment, "operation_watchdog_ref", None),
                "V2 operation watchdog",
            )
            != activation.operation_watchdog_ref
            or getattr(self.exec_attachment, "operation_watchdog", None) is None
            or type(getattr(self.exec_attachment, "cleanup_uncertain", None)) is not bool
            or self.exec_attachment.cleanup_uncertain
        ):
            raise InstalledStrixV2CompositionError("V2 exec attachment is incomplete")
        dispatch_runtime = self.exec_attachment.dispatch_runtime
        if (
            getattr(dispatch_runtime, "authority", None)
            is not self.exec_attachment.dispatch_authority
            or getattr(dispatch_runtime, "continuous_custody", None)
            is not self.exec_attachment.operation_watchdog
            or not callable(getattr(dispatch_runtime, "gate", None))
            or not callable(getattr(self.exec_attachment.operation_watchdog, "require_live", None))
        ):
            raise InstalledStrixV2CompositionError(
                "V2 exec dispatch runtime or continuous custody changed"
            )
        if (
            _digest(
                getattr(self.model_gateway_lease, "lease_binding_ref", None),
                "V2 model gateway lease",
            )
            != activation.model_gateway_lease_ref
            or _digest(
                getattr(self.model_gateway_lease, "custody_identity_ref", None),
                "V2 worker custody identity",
            )
            != activation.worker_custody_identity_ref
            or getattr(self.model_gateway_lease, "provider_kind", None)
            != activation.model_provider_kind
            or getattr(self.model_gateway_lease, "live_model_proof", None)
            is not activation.model_live_proof
            or any(
                not callable(getattr(self.model_gateway_lease, name, None))
                for name in ("claim", "revoke", "close")
            )
            or type(getattr(self.model_gateway_lease, "cleanup_uncertain", None)) is not bool
            or self.model_gateway_lease.cleanup_uncertain
        ):
            raise InstalledStrixV2CompositionError("V2 model gateway lease is incomplete")
        bindings = dict(activation.role_bindings)
        if (
            _digest(
                getattr(self.source_collection, "binding_ref", None),
                "V2 source collection binding",
            )
            != bindings["source_collection"]
            or not callable(getattr(self.source_collection, "close", None))
            or getattr(self.source_collection, "cleanup_uncertain", None) is not False
        ):
            raise InstalledStrixV2CompositionError("V2 source collection is incomplete")
        if (
            _digest(
                getattr(self.target_relay, "binding_ref", None),
                "V2 target relay binding",
            )
            != bindings["target_relay"]
            or _digest(
                getattr(self.target_relay, "target_scope_admission_ref", None),
                "V2 target scope admission",
            )
            != activation.target_scope_admission_ref
            or not callable(getattr(self.target_relay, "close", None))
            or getattr(self.target_relay, "cleanup_uncertain", None) is not False
        ):
            raise InstalledStrixV2CompositionError("V2 target relay is incomplete")
        if (
            _digest(
                getattr(self.worker_controller, "startup_overlay_ref", None),
                "V2 startup overlay",
            )
            != activation.startup_overlay_ref
            or _digest(
                getattr(self.worker_controller, "runtime_closure_plan_ref", None),
                "V2 runtime closure plan",
            )
            != activation.runtime_closure_plan_ref
            or _digest(
                getattr(self.worker_controller, "fixed_exec_receipt_ref", None),
                "V2 fixed exec receipt",
            )
            != activation.fixed_exec_receipt_ref
            or _digest(
                getattr(self.worker_controller, "installed_projection_ref", None),
                "V2 installed projection",
            )
            != activation.installed_projection_ref
            or _digest(
                getattr(self.worker_controller, "sealed_inputs_ref", None),
                "V2 sealed inputs",
            )
            != activation.sealed_inputs_ref
            or _digest(
                getattr(self.worker_controller, "runtime_image_contract_ref", None),
                "V2 runtime image contract",
            )
            != activation.runtime_image_contract_ref
            or _digest(
                getattr(self.worker_controller, "runtime_image_qualification_ref", None),
                "V2 runtime image qualification",
            )
            != activation.runtime_image_qualification_ref
            or _digest(
                getattr(self.worker_controller, "runtime_image_closure_ref", None),
                "V2 runtime image closure",
            )
            != activation.runtime_image_closure_ref
            or _digest(
                getattr(self.worker_controller, "worker_identity_ref", None),
                "V2 worker package identity",
            )
            != activation.worker_identity_ref
            or _digest(
                getattr(self.worker_controller, "custody_ready_receipt_ref", None),
                "V2 worker custody readiness",
            )
            != activation.worker_custody_ready_receipt_ref
            or _digest(
                getattr(self.worker_controller, "worker_launch_digest", None),
                "V2 worker launch",
            )
            != activation.worker_launch_digest
            or _digest(
                getattr(self.worker_controller, "worker_containment_ref", None),
                "V2 worker containment",
            )
            != activation.worker_containment_ref
            or _digest(
                getattr(self.worker_controller, "custody_identity_ref", None),
                "V2 worker custody identity",
            )
            != activation.worker_custody_identity_ref
            or getattr(self.worker_controller, "controller_server", None) is None
            or getattr(self.worker_controller, "containment_verifier", None) is None
            or not callable(getattr(self.worker_controller, "close", None))
            or type(getattr(self.worker_controller, "cleanup_uncertain", None)) is not bool
            or self.worker_controller.cleanup_uncertain
        ):
            raise InstalledStrixV2CompositionError("V2 worker controller is incomplete")
        server = self.worker_controller.controller_server
        if (
            getattr(server, "server_identity_ref", None) != activation.worker_controller_server_ref
            or getattr(server, "retained_model_gateway_lease", None) is not self.model_gateway_lease
            or getattr(server, "retained_containment_verifier", None)
            is not self.worker_controller.containment_verifier
            or getattr(server, "retained_containment_ref", None)
            != activation.worker_containment_ref
            or getattr(server, "custody_active", None) is not True
            or getattr(server, "retained_custody_identity", None) is None
            or not callable(getattr(server, "close", None))
            or not callable(getattr(server, "wait_until_custody_ready", None))
            or not callable(getattr(self.worker_controller.containment_verifier, "verify", None))
        ):
            raise InstalledStrixV2CompositionError(
                "V2 worker controller has no consumed live containment verifier"
            )
        cancellation = self.exec_attachment.cancellation_authority
        if not callable(getattr(cancellation, "require_binding", None)):
            raise InstalledStrixV2CompositionError(
                "V2 cancellation binding verifier is unavailable"
            )
        authority = self.exec_attachment.dispatch_authority
        if (
            getattr(authority, "authority_ref", None) != activation.exec_dispatch_authority_ref
            or getattr(authority, "claim_ref", None) != activation.claim_ref
            or getattr(authority, "controller_fence", None) != activation.controller_fence
        ):
            raise InstalledStrixV2CompositionError("V2 dispatch authority binding changed")
        try:
            cancellation.require_binding(
                authority=authority,
                custody_plan_digest=activation.custody_plan_digest,
                network_policy_digest=activation.network_policy_digest,
                authority_ref=activation.exec_dispatch_authority_ref,
                claim_ref=activation.claim_ref,
                controller_fence=activation.controller_fence,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError(
                "V2 cancellation and dispatch authority owners differ"
            ) from exc
        _validate_resource_receipt(
            self.receipt,
            action="allocated",
            authority_ref=self.authority_guard.authority_ref,
            activation_receipt_ref=activation.receipt_ref,
            role_bindings=activation.role_bindings,
            reconciliation_ref=None,
        )


@dataclass(frozen=True, slots=True)
class InstalledStrixV2ReopenedResources:
    resources: tuple[InstalledStrixOwnedResource, ...]
    receipt: InstalledStrixV2ResourceReceipt
    cleanup_owner: InstalledEngineBundleCleanupOwner | None = None

    def validate(
        self,
        *,
        activation: InstalledStrixV2ActivationReceipt,
        authority_ref: str,
        reconciliation_ref: str,
    ) -> None:
        installed_strix_resource_set_digest(
            self.resources,
            expected_roles=INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
        )
        role_bindings = tuple((resource.role, resource.binding_ref) for resource in self.resources)
        for resource in self.resources:
            _require_cleanup_only_owner(resource.owner, role=resource.role)
        _validate_resource_receipt(
            self.receipt,
            action="reopened",
            authority_ref=authority_ref,
            activation_receipt_ref=activation.receipt_ref,
            role_bindings=role_bindings,
            reconciliation_ref=reconciliation_ref,
        )


def _require_cleanup_only_owner(owner: object, *, role: str) -> None:
    forbidden = (
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
    if any(callable(getattr(owner, name, None)) for name in forbidden):
        raise InstalledStrixV2CompositionError(f"V2 {role} reconciliation owner can launch work")


def _validate_resources(
    resources: tuple[InstalledStrixOwnedResource, ...],
    activation: InstalledStrixV2ActivationReceipt,
) -> None:
    installed_strix_resource_set_digest(resources)
    observed = tuple((resource.role, resource.binding_ref) for resource in resources)
    if observed != activation.role_bindings:
        raise InstalledStrixV2CompositionError("V2 protected resource set changed")


def _validate_resource_receipt(
    receipt: InstalledStrixV2ResourceReceipt,
    *,
    action: str,
    authority_ref: str,
    activation_receipt_ref: str,
    role_bindings: tuple[tuple[str, str], ...],
    reconciliation_ref: str | None,
) -> None:
    if (
        not isinstance(receipt, InstalledStrixV2ResourceReceipt)
        or receipt.action != action
        or receipt.authority_ref != authority_ref
        or receipt.activation_receipt_ref != activation_receipt_ref
        or receipt.role_bindings != role_bindings
        or receipt.reconciliation_ref != reconciliation_ref
    ):
        raise InstalledStrixV2CompositionError("V2 protected resource receipt changed")


class InstalledStrixV2ExecutionAllocation(Protocol):
    @property
    def transaction_ref(self) -> str: ...

    @property
    def effects_started(self) -> bool: ...

    def allocate(self) -> InstalledStrixV2ExecutionResources: ...

    def commit(self) -> None: ...

    def close(self) -> InstalledStrixV2CleanupReceipt: ...


class InstalledStrixV2ReconciliationReopen(Protocol):
    @property
    def transaction_ref(self) -> str: ...

    @property
    def effects_started(self) -> bool: ...

    def reopen(self) -> InstalledStrixV2ReopenedResources: ...

    def commit(self) -> None: ...

    def close(self) -> InstalledStrixV2CleanupReceipt: ...


class InstalledStrixV2ExecutionResourceFactory(Protocol):
    """Begin an effect-free transaction; allocate owns every partial effect."""

    def begin_execution(
        self,
        *,
        product_store: ProductStore,
        snapshot: InstalledStrixV2PrelaunchSnapshot,
        launch_plan: StrixControlledLaunchPlanV2,
        authority_guard: InstalledStrixV2AuthorityGuard,
        resource_transaction_ref: str,
        resource_owner_bindings: tuple[tuple[str, str, str], ...],
    ) -> InstalledStrixV2ExecutionAllocation: ...


class InstalledStrixV2ReconciliationResourceFactory(Protocol):
    """Begin an effect-free no-launch reopen transaction."""

    def begin_reconciliation(
        self,
        *,
        product_store: ProductStore,
        snapshot: InstalledStrixV2HistoricalSnapshot,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
        resource_transaction_ref: str,
        resource_owner_bindings: tuple[tuple[str, str, str], ...],
    ) -> InstalledStrixV2ReconciliationReopen: ...


class InstalledStrixV2RuntimeBuilder(Protocol):
    def build_execution(
        self,
        *,
        identity: InstalledControlledStrixRuntimeIdentity,
        authority_guard: InstalledStrixV2AuthorityGuard,
        snapshot: InstalledStrixV2AuthoritySnapshot,
        launch_plan: StrixControlledLaunchPlanV2,
        resources: InstalledStrixV2ExecutionResources,
    ) -> InstalledControlledStrixRuntime: ...

    def build_reconciliation(
        self,
        *,
        identity: InstalledControlledStrixRuntimeIdentity,
        snapshot: InstalledStrixV2HistoricalSnapshot,
        resources: InstalledStrixV2ReopenedResources,
        reconciliation_ref: str,
    ) -> InstalledControlledStrixReconciliationRuntime: ...


__all__ = [
    "InstalledStrixV2CaidoProvider",
    "InstalledStrixV2CleanupReceipt",
    "InstalledStrixV2ExecAttachment",
    "InstalledStrixV2ExecutionAllocation",
    "InstalledStrixV2ExecutionResourceFactory",
    "InstalledStrixV2ExecutionResources",
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
