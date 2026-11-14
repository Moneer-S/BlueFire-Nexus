"""Durable authority contracts for installed Strix V2 composition."""

from __future__ import annotations

import re
import threading
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Mapping, Protocol, cast

from .accepted_engine_jobs import AcceptedPreparedEngineAttempt
from .engine_attempt_contract import EngineAttemptBinding, EngineAttemptRecord
from .engine_container_custody import ContainerCustodyPlanV2
from .engine_delegation import EngineCapabilityDelegation
from .engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    InstalledControlledStrixRuntimeIdentity,
)
from .engine_network_policy import EngineNetworkPlanV2, HistoricalEngineNetworkPlanV2
from .strix_controlled_runtime_admission import (
    StrixControlledLaunchPlanV2,
    StrixControlledRuntimeAdmissionV2,
    build_controlled_launch_plan,
)
from .util import content_hash

if TYPE_CHECKING:
    from .product_store import ProductStore


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTIVATION_SCHEMA = "bluefire.installed-strix-v2-activation.v1"


class InstalledStrixV2CompositionError(RuntimeError):
    """Protected V2 authority, resources, or runtime composition changed."""


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InstalledStrixV2CompositionError(f"{label} is invalid")
    return value


def _role_bindings(
    value: object,
    *,
    expected_roles: tuple[str, ...] = INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, tuple) or any(
        not isinstance(item, tuple) or len(item) != 2 for item in value
    ):
        raise InstalledStrixV2CompositionError("V2 activation resource bindings are invalid")
    result = tuple(
        (str(role), _digest(binding_ref, "V2 resource binding")) for role, binding_ref in value
    )
    if tuple(role for role, _ in result) != expected_roles:
        raise InstalledStrixV2CompositionError(
            "V2 activation resource bindings are incomplete or noncanonical"
        )
    return result


def _binding_set_digest(
    bindings: tuple[tuple[str, str], ...],
    *,
    expected_roles: tuple[str, ...],
) -> str:
    checked = _role_bindings(bindings, expected_roles=expected_roles)
    return cast(
        str,
        content_hash(
            {
                "schema_version": "bluefire.installed-strix-resource-set.v1",
                "resources": [
                    {"role": role, "binding_ref": binding_ref} for role, binding_ref in checked
                ],
            }
        ),
    )


@dataclass(frozen=True, slots=True)
class InstalledStrixV2ActivationReceipt:
    """Durable qualification of the exact component set, not a caller flag."""

    schema_version: str
    runtime_resolution_ref: str
    admission_ref: str
    claim_ref: str
    controlled_profile_ref: str
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
    caido_mode: str
    caido_test_provider: bool
    caido_provider_identity_ref: str
    caido_terms_acceptance_ref: str | None
    caido_entitlement_ref: str | None
    caido_live_proof: bool
    model_provider_kind: str
    model_live_proof: bool
    model_gateway_lease_ref: str
    worker_custody_identity_ref: str
    network_policy_digest: str
    custody_plan_digest: str
    exec_broker_binding_digest: str
    exec_dispatch_authority_ref: str
    controller_fence: str
    exec_cancellation_ref: str
    worker_launch_digest: str
    worker_controller_server_ref: str
    worker_custody_ready_receipt_ref: str
    operation_watchdog_ref: str
    worker_containment_ref: str
    candidate_qualification_ref: str
    role_bindings: tuple[tuple[str, str], ...]
    receipt_ref: str

    def __post_init__(self) -> None:
        if self.schema_version != _ACTIVATION_SCHEMA:
            raise InstalledStrixV2CompositionError("V2 activation schema is unsupported")
        for name in (
            "runtime_resolution_ref",
            "admission_ref",
            "claim_ref",
            "controlled_profile_ref",
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
            "caido_provider_identity_ref",
            "model_gateway_lease_ref",
            "worker_custody_identity_ref",
            "network_policy_digest",
            "custody_plan_digest",
            "exec_broker_binding_digest",
            "exec_dispatch_authority_ref",
            "controller_fence",
            "exec_cancellation_ref",
            "worker_launch_digest",
            "worker_controller_server_ref",
            "worker_custody_ready_receipt_ref",
            "operation_watchdog_ref",
            "worker_containment_ref",
            "candidate_qualification_ref",
            "receipt_ref",
        ):
            _digest(getattr(self, name), f"V2 activation {name}")
        if self.caido_mode == "real_sidecar":
            _digest(self.caido_terms_acceptance_ref, "V2 Caido terms acceptance")
            _digest(self.caido_entitlement_ref, "V2 Caido entitlement")
            if self.caido_test_provider is not False or type(self.caido_live_proof) is not bool:
                raise InstalledStrixV2CompositionError("V2 Caido live proof is invalid")
        elif self.caido_mode == "test_protocol_provider":
            if (
                self.caido_test_provider is not True
                or self.caido_terms_acceptance_ref is not None
                or self.caido_entitlement_ref is not None
                or self.caido_live_proof is not False
            ):
                raise InstalledStrixV2CompositionError(
                    "V2 test Caido provider cannot satisfy live proof"
                )
        else:
            raise InstalledStrixV2CompositionError("V2 Caido provider kind is invalid")
        if self.model_provider_kind == "test":
            if self.model_live_proof is not False:
                raise InstalledStrixV2CompositionError(
                    "V2 Test provider cannot satisfy live model proof"
                )
        elif self.model_provider_kind == "live":
            if type(self.model_live_proof) is not bool:
                raise InstalledStrixV2CompositionError("V2 live model proof is invalid")
        else:
            raise InstalledStrixV2CompositionError("V2 model provider kind is invalid")
        bindings = _role_bindings(
            self.role_bindings,
            expected_roles=INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
        )
        if bindings != self.role_bindings:
            raise InstalledStrixV2CompositionError(
                "V2 activation resource bindings are not canonical"
            )
        by_role = dict(bindings)
        if (
            by_role["caido_channel"] != self.caido_provider_identity_ref
            or by_role["docker_control"] != self.exec_broker_binding_digest
            or by_role["model_gateway"] != self.model_gateway_lease_ref
            or by_role["worker_controller"] != self.worker_launch_digest
        ):
            raise InstalledStrixV2CompositionError(
                "V2 activation execution component bindings changed"
            )
        if self.receipt_ref != content_hash(self.document(include_receipt=False)):
            raise InstalledStrixV2CompositionError("V2 activation receipt changed")

    @classmethod
    def create(
        cls,
        *,
        runtime_resolution_ref: str,
        admission_ref: str,
        claim_ref: str,
        controlled_profile_ref: str,
        controlled_launch_digest: str,
        startup_overlay_ref: str,
        runtime_closure_plan_ref: str,
        fixed_exec_receipt_ref: str,
        target_scope_admission_ref: str,
        installed_projection_ref: str,
        sealed_inputs_ref: str,
        runtime_image_contract_ref: str,
        runtime_image_qualification_ref: str,
        runtime_image_closure_ref: str,
        worker_identity_ref: str,
        caido_mode: str,
        caido_test_provider: bool,
        caido_provider_identity_ref: str,
        caido_terms_acceptance_ref: str | None,
        caido_entitlement_ref: str | None,
        caido_live_proof: bool,
        model_provider_kind: str,
        model_live_proof: bool,
        model_gateway_lease_ref: str,
        worker_custody_identity_ref: str,
        network_policy_digest: str,
        custody_plan_digest: str,
        exec_broker_binding_digest: str,
        exec_dispatch_authority_ref: str,
        controller_fence: str,
        exec_cancellation_ref: str,
        worker_launch_digest: str,
        worker_controller_server_ref: str,
        worker_custody_ready_receipt_ref: str,
        operation_watchdog_ref: str,
        worker_containment_ref: str,
        candidate_qualification_ref: str,
        role_bindings: tuple[tuple[str, str], ...],
    ) -> InstalledStrixV2ActivationReceipt:
        values: dict[str, Any] = {
            "schema_version": _ACTIVATION_SCHEMA,
            "runtime_resolution_ref": runtime_resolution_ref,
            "admission_ref": admission_ref,
            "claim_ref": claim_ref,
            "controlled_profile_ref": controlled_profile_ref,
            "controlled_launch_digest": controlled_launch_digest,
            "startup_overlay_ref": startup_overlay_ref,
            "runtime_closure_plan_ref": runtime_closure_plan_ref,
            "fixed_exec_receipt_ref": fixed_exec_receipt_ref,
            "target_scope_admission_ref": target_scope_admission_ref,
            "installed_projection_ref": installed_projection_ref,
            "sealed_inputs_ref": sealed_inputs_ref,
            "runtime_image_contract_ref": runtime_image_contract_ref,
            "runtime_image_qualification_ref": runtime_image_qualification_ref,
            "runtime_image_closure_ref": runtime_image_closure_ref,
            "worker_identity_ref": worker_identity_ref,
            "caido_mode": caido_mode,
            "caido_test_provider": caido_test_provider,
            "caido_provider_identity_ref": caido_provider_identity_ref,
            "caido_terms_acceptance_ref": caido_terms_acceptance_ref,
            "caido_entitlement_ref": caido_entitlement_ref,
            "caido_live_proof": caido_live_proof,
            "model_provider_kind": model_provider_kind,
            "model_live_proof": model_live_proof,
            "model_gateway_lease_ref": model_gateway_lease_ref,
            "worker_custody_identity_ref": worker_custody_identity_ref,
            "network_policy_digest": network_policy_digest,
            "custody_plan_digest": custody_plan_digest,
            "exec_broker_binding_digest": exec_broker_binding_digest,
            "exec_dispatch_authority_ref": exec_dispatch_authority_ref,
            "controller_fence": controller_fence,
            "exec_cancellation_ref": exec_cancellation_ref,
            "worker_launch_digest": worker_launch_digest,
            "worker_controller_server_ref": worker_controller_server_ref,
            "worker_custody_ready_receipt_ref": worker_custody_ready_receipt_ref,
            "operation_watchdog_ref": operation_watchdog_ref,
            "worker_containment_ref": worker_containment_ref,
            "candidate_qualification_ref": candidate_qualification_ref,
            "role_bindings": role_bindings,
        }
        return cls(**values, receipt_ref=content_hash(_activation_document(values)))

    def document(self, *, include_receipt: bool = True) -> dict[str, Any]:
        values: dict[str, Any] = {
            "schema_version": self.schema_version,
            "runtime_resolution_ref": self.runtime_resolution_ref,
            "admission_ref": self.admission_ref,
            "claim_ref": self.claim_ref,
            "controlled_profile_ref": self.controlled_profile_ref,
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
            "caido_mode": self.caido_mode,
            "caido_test_provider": self.caido_test_provider,
            "caido_provider_identity_ref": self.caido_provider_identity_ref,
            "caido_terms_acceptance_ref": self.caido_terms_acceptance_ref,
            "caido_entitlement_ref": self.caido_entitlement_ref,
            "caido_live_proof": self.caido_live_proof,
            "model_provider_kind": self.model_provider_kind,
            "model_live_proof": self.model_live_proof,
            "model_gateway_lease_ref": self.model_gateway_lease_ref,
            "worker_custody_identity_ref": self.worker_custody_identity_ref,
            "network_policy_digest": self.network_policy_digest,
            "custody_plan_digest": self.custody_plan_digest,
            "exec_broker_binding_digest": self.exec_broker_binding_digest,
            "exec_dispatch_authority_ref": self.exec_dispatch_authority_ref,
            "controller_fence": self.controller_fence,
            "exec_cancellation_ref": self.exec_cancellation_ref,
            "worker_launch_digest": self.worker_launch_digest,
            "worker_controller_server_ref": self.worker_controller_server_ref,
            "worker_custody_ready_receipt_ref": self.worker_custody_ready_receipt_ref,
            "operation_watchdog_ref": self.operation_watchdog_ref,
            "worker_containment_ref": self.worker_containment_ref,
            "candidate_qualification_ref": self.candidate_qualification_ref,
            "role_bindings": self.role_bindings,
        }
        result = _activation_document(values)
        if include_receipt:
            result["receipt_ref"] = self.receipt_ref
        return result


def _activation_document(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **{name: values[name] for name in values if name != "role_bindings"},
        "role_bindings": [
            {"role": role, "binding_ref": binding_ref}
            for role, binding_ref in _role_bindings(values["role_bindings"])
        ],
    }


@dataclass(frozen=True, slots=True)
class InstalledStrixV2PrelaunchSnapshot:
    """Durable, effect-free admission before observed worker activation exists."""

    resolution_ref: str
    admission: StrixControlledRuntimeAdmissionV2

    @property
    def prelaunch_ref(self) -> str:
        return cast(
            str,
            content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-prelaunch-snapshot.v1",
                    "resolution_ref": self.resolution_ref,
                    "admission_ref": self.admission.admission_ref,
                }
            ),
        )

    def validate(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> StrixControlledLaunchPlanV2:
        _digest(self.resolution_ref, "V2 authority resolution")
        if self.resolution_ref != accepted.runtime_resolution_ref:
            raise InstalledStrixV2CompositionError("V2 authority resolution changed")
        if not isinstance(self.admission, StrixControlledRuntimeAdmissionV2):
            raise InstalledStrixV2CompositionError("V2 canonical admission is unavailable")
        row = self.admission.to_dict()
        claim = row["accepted_execution_claim"]
        expected = {
            "job_id": accepted.job_id,
            "preparation_ref": accepted.preparation_ref,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "claim_ref": accepted.claim_ref,
            "runtime_resolution_ref": accepted.runtime_resolution_ref,
            "attempt_id": binding.attempt_id,
        }
        if any(claim.get(name) != value for name, value in expected.items()) or any(
            row.get(name) != value
            for name, value in (
                ("attempt_id", binding.attempt_id),
                ("binding_digest", binding.binding_digest),
                ("delegation_digest", delegation.delegation_digest),
                ("objective_ref", binding.objective_ref),
                ("environment_ref", binding.environment_ref),
            )
        ):
            raise InstalledStrixV2CompositionError("V2 admission claim binding changed")
        _validate_admission_semantics(row, binding=binding, delegation=delegation)
        plan = build_controlled_launch_plan(
            self.admission,
            expected_admission_ref=self.admission.admission_ref,
            expected_execution_claim_ref=accepted.claim_ref,
        )
        return plan


@dataclass(frozen=True, slots=True)
class InstalledStrixV2AuthoritySnapshot(InstalledStrixV2PrelaunchSnapshot):
    """Prelaunch authority joined to an observed, durable activation receipt."""

    activation: InstalledStrixV2ActivationReceipt

    @property
    def snapshot_ref(self) -> str:
        return cast(
            str,
            content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-authority-snapshot.v1",
                    "prelaunch_ref": self.prelaunch_ref,
                    "activation_receipt_ref": self.activation.receipt_ref,
                }
            ),
        )

    def validate(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> StrixControlledLaunchPlanV2:
        plan = InstalledStrixV2PrelaunchSnapshot.validate(
            self, accepted=accepted, binding=binding, delegation=delegation
        )
        if not isinstance(self.activation, InstalledStrixV2ActivationReceipt):
            raise InstalledStrixV2CompositionError("V2 durable activation is unavailable")
        row = self.admission.to_dict()
        profile_ref = cast(
            str,
            row["execution_identity"]["controlled_runtime_profile"]["profile_digest"],
        )
        activation = self.activation
        network = EngineNetworkPlanV2.from_mapping(row["network_plan"])
        custody = ContainerCustodyPlanV2.from_mapping(row["custody_plan"])
        if (
            activation.runtime_resolution_ref != accepted.runtime_resolution_ref
            or activation.admission_ref != self.admission.admission_ref
            or activation.claim_ref != accepted.claim_ref
            or activation.controlled_profile_ref != profile_ref
            or activation.controlled_launch_digest != plan.launch_digest
            or activation.network_policy_digest != network.policy_digest
            or activation.custody_plan_digest != custody.plan_digest
            or activation.exec_broker_binding_digest != plan.exec_broker_binding_digest
        ):
            raise InstalledStrixV2CompositionError("V2 activation binding changed")
        return plan


def _validate_admission_semantics(
    row: Mapping[str, Any],
    *,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    historical_legacy: bool = False,
) -> None:
    """Bind declared authority to admission meaning, not only opaque digests."""

    try:
        network = (
            HistoricalEngineNetworkPlanV2.from_mapping(row["network_plan"])
            if historical_legacy
            else EngineNetworkPlanV2.from_mapping(row["network_plan"])
        )
        custody = ContainerCustodyPlanV2.from_mapping(row["custody_plan"])
        build = row["execution_identity"]["startup_build_identity"]
        scope = row["scope"]
        gateway = row["gateway"]
        budgets = row["budgets"]
        exact_cost_microunits = Decimal(str(budgets["max_model_cost_usd"])) * 1_000_000
        if exact_cost_microunits != exact_cost_microunits.to_integral_value():
            raise ValueError("sub-microunit cost")
        cost_microunits = int(exact_cost_microunits)
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise InstalledStrixV2CompositionError("V2 admission semantics are invalid") from exc
    expected = (
        (network.policy_digest, delegation.network_policy_digest),
        (custody.plan_digest, delegation.custody_plan_digest),
        (scope.get("target_snapshot_digest"), binding.target_snapshot_ref),
        (scope.get("scope_digest"), binding.scope_ref),
        (build.get("package_version"), binding.engine_version),
        (build.get("source_revision"), binding.engine_revision),
        (build.get("package_sha256"), binding.engine_package_digest),
        (build.get("prompt_overlay_sha256"), binding.policy_overlay_digest),
        (gateway.get("authorization_digest"), binding.model_authorization_ref),
        (gateway.get("model"), binding.model_id),
        (gateway.get("base_url"), binding.model_data_destination),
    )
    if any(observed != authorized for observed, authorized in expected):
        raise InstalledStrixV2CompositionError("V2 admission exceeds or differs from authority")
    bounded = (
        (budgets.get("wall_seconds"), binding.wall_clock_seconds),
        (budgets.get("max_turns_per_agent"), binding.action_limit),
        (cost_microunits, binding.cost_limit_microunits),
    )
    if any(
        type(observed) is not int or observed < 0 or observed > authorized
        for observed, authorized in bounded
    ):
        raise InstalledStrixV2CompositionError("V2 admission budget exceeds authority")


@dataclass(frozen=True, slots=True)
class InstalledStrixV2HistoricalSnapshot:
    """Persisted execution identity for cleanup-only recovery after upgrades."""

    resolution_ref: str
    authority_ref: str
    saved_record_ref: str
    reconciliation_ref: str
    identity: InstalledControlledStrixRuntimeIdentity
    activation: InstalledStrixV2ActivationReceipt

    @classmethod
    def create(
        cls,
        *,
        resolution_ref: str,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
        identity: InstalledControlledStrixRuntimeIdentity,
        activation: InstalledStrixV2ActivationReceipt,
    ) -> InstalledStrixV2HistoricalSnapshot:
        saved_record_ref = content_hash(saved_record.to_dict())
        document = {
            "schema_version": "bluefire.installed-strix-v2-historical-authority.v1",
            "resolution_ref": resolution_ref,
            "saved_record_ref": saved_record_ref,
            "reconciliation_ref": reconciliation_ref,
            "identity": asdict(identity),
            "activation_receipt_ref": activation.receipt_ref,
        }
        return cls(
            resolution_ref=resolution_ref,
            authority_ref=content_hash(document),
            saved_record_ref=saved_record_ref,
            reconciliation_ref=reconciliation_ref,
            identity=identity,
            activation=activation,
        )

    def validate(
        self,
        *,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> None:
        _digest(self.resolution_ref, "V2 historical resolution")
        _digest(self.authority_ref, "V2 historical authority")
        _digest(self.saved_record_ref, "V2 historical saved record")
        _digest(self.reconciliation_ref, "V2 historical reconciliation")
        identity = self.identity
        activation = self.activation
        if not isinstance(identity, InstalledControlledStrixRuntimeIdentity):
            raise InstalledStrixV2CompositionError("V2 historical runtime identity is invalid")
        if not isinstance(activation, InstalledStrixV2ActivationReceipt):
            raise InstalledStrixV2CompositionError("V2 historical activation is invalid")
        expected_authority_ref = content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-historical-authority.v1",
                "resolution_ref": self.resolution_ref,
                "saved_record_ref": self.saved_record_ref,
                "reconciliation_ref": self.reconciliation_ref,
                "identity": asdict(identity),
                "activation_receipt_ref": activation.receipt_ref,
            }
        )
        if self.authority_ref != expected_authority_ref:
            raise InstalledStrixV2CompositionError("V2 historical authority changed")
        if (
            not isinstance(saved_record, EngineAttemptRecord)
            or self.saved_record_ref != content_hash(saved_record.to_dict())
            or self.reconciliation_ref != reconciliation_ref
        ):
            raise InstalledStrixV2CompositionError(
                "V2 historical saved record or reconciliation changed"
            )
        expected = (
            (self.resolution_ref, accepted.runtime_resolution_ref),
            (identity.job_id, accepted.job_id),
            (identity.preparation_ref, accepted.preparation_ref),
            (identity.binding_digest, binding.binding_digest),
            (identity.delegation_digest, delegation.delegation_digest),
            (identity.claim_ref, accepted.claim_ref),
            (identity.runtime_resolution_ref, accepted.runtime_resolution_ref),
            (identity.controlled_profile_ref, activation.controlled_profile_ref),
            (identity.runtime_admission_ref, activation.admission_ref),
            (identity.runtime_activation_ref, activation.receipt_ref),
            (identity.controlled_launch_digest, activation.controlled_launch_digest),
            (identity.startup_overlay_ref, activation.startup_overlay_ref),
            (identity.runtime_closure_plan_ref, activation.runtime_closure_plan_ref),
            (identity.fixed_exec_receipt_ref, activation.fixed_exec_receipt_ref),
            (identity.target_scope_admission_ref, activation.target_scope_admission_ref),
            (identity.installed_projection_ref, activation.installed_projection_ref),
            (identity.sealed_inputs_ref, activation.sealed_inputs_ref),
            (identity.runtime_image_contract_ref, activation.runtime_image_contract_ref),
            (
                identity.runtime_image_qualification_ref,
                activation.runtime_image_qualification_ref,
            ),
            (identity.runtime_image_closure_ref, activation.runtime_image_closure_ref),
            (identity.worker_identity_ref, activation.worker_identity_ref),
            (identity.exec_broker_binding_digest, activation.exec_broker_binding_digest),
            (identity.worker_launch_digest, activation.worker_launch_digest),
            (identity.worker_controller_server_ref, activation.worker_controller_server_ref),
            (
                identity.worker_custody_ready_receipt_ref,
                activation.worker_custody_ready_receipt_ref,
            ),
            (activation.runtime_resolution_ref, accepted.runtime_resolution_ref),
            (activation.claim_ref, accepted.claim_ref),
            (activation.network_policy_digest, delegation.network_policy_digest),
            (activation.custody_plan_digest, delegation.custody_plan_digest),
            (
                identity.resource_set_digest,
                _binding_set_digest(
                    activation.role_bindings,
                    expected_roles=INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
                ),
            ),
        )
        if any(observed != retained for observed, retained in expected):
            raise InstalledStrixV2CompositionError("V2 historical runtime binding changed")


class InstalledStrixV2AuthoritySource(Protocol):
    """Protected source; no in-memory or caller-authored implementation is supplied."""

    def require_prelaunch_current(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2PrelaunchSnapshot: ...

    def retain_activation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        prelaunch_ref: str,
        admission_ref: str,
        activation_ref: str,
        resource_transaction_ref: str,
        observed_identity_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot: ...

    def require_current(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot: ...

    def require_active(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        expected_resolution_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot: ...

    def reopen_reconciliation(
        self,
        *,
        product_store: ProductStore,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        saved_record: EngineAttemptRecord,
        reconciliation_ref: str,
    ) -> InstalledStrixV2HistoricalSnapshot: ...


class InstalledStrixV2AuthorityGuard:
    """Retained durable-currentness reader, distinct from the atomic send fence."""

    def __init__(
        self,
        *,
        product_store: ProductStore,
        source: InstalledStrixV2AuthoritySource,
        accepted: AcceptedPreparedEngineAttempt,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None:
        self._store = product_store
        self._source = source
        self._accepted = accepted
        self._binding = binding
        self._delegation = delegation
        self._prelaunch_ref: str | None = None
        self._admission_ref: str | None = None
        self._snapshot_ref: str | None = None
        self._lock = threading.Lock()

    def require_product_store(self, product_store: ProductStore) -> None:
        if product_store is not self._store:
            raise InstalledStrixV2CompositionError(
                "V2 authority guard belongs to a different ProductStore"
            )

    @property
    def authority_ref(self) -> str:
        with self._lock:
            if self._prelaunch_ref is None:
                raise InstalledStrixV2CompositionError("V2 authority guard is not opened")
            return self._prelaunch_ref

    def require_prelaunch_current(self) -> InstalledStrixV2PrelaunchSnapshot:
        try:
            snapshot = self._source.require_prelaunch_current(
                product_store=self._store,
                accepted=self._accepted,
                binding=self._binding,
                delegation=self._delegation,
                expected_resolution_ref=self._accepted.runtime_resolution_ref,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError(
                "V2 prelaunch authority is no longer current"
            ) from exc
        if type(snapshot) is not InstalledStrixV2PrelaunchSnapshot:
            raise InstalledStrixV2CompositionError("V2 prelaunch source returned an invalid value")
        snapshot.validate(
            accepted=self._accepted,
            binding=self._binding,
            delegation=self._delegation,
        )
        with self._lock:
            if self._prelaunch_ref is None:
                self._prelaunch_ref = snapshot.prelaunch_ref
                self._admission_ref = snapshot.admission.admission_ref
            elif self._prelaunch_ref != snapshot.prelaunch_ref:
                raise InstalledStrixV2CompositionError("V2 prelaunch authority changed")
        return snapshot

    def retain_activation(
        self,
        *,
        admission_ref: str,
        activation_ref: str,
        resource_transaction_ref: str,
        observed_identity_ref: str,
    ) -> InstalledStrixV2AuthoritySnapshot:
        _digest(admission_ref, "V2 activation admission")
        _digest(activation_ref, "V2 activation receipt")
        _digest(resource_transaction_ref, "V2 activation resource transaction")
        _digest(observed_identity_ref, "V2 activation observed identity")
        with self._lock:
            prelaunch_ref = self._prelaunch_ref
            if prelaunch_ref is None or self._admission_ref != admission_ref:
                raise InstalledStrixV2CompositionError("V2 activation lacks prelaunch authority")
        try:
            self._source.retain_activation(
                product_store=self._store,
                accepted=self._accepted,
                binding=self._binding,
                delegation=self._delegation,
                prelaunch_ref=prelaunch_ref,
                admission_ref=admission_ref,
                activation_ref=activation_ref,
                resource_transaction_ref=resource_transaction_ref,
                observed_identity_ref=observed_identity_ref,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError(
                "V2 observed activation was not retained"
            ) from exc
        snapshot = self.require_current()
        if snapshot.activation.receipt_ref != activation_ref:
            raise InstalledStrixV2CompositionError("V2 retained activation changed")
        return snapshot

    def require_current(self) -> InstalledStrixV2AuthoritySnapshot:
        try:
            snapshot = self._source.require_current(
                product_store=self._store,
                accepted=self._accepted,
                binding=self._binding,
                delegation=self._delegation,
                expected_resolution_ref=self._accepted.runtime_resolution_ref,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError("V2 authority is no longer current") from exc
        if not isinstance(snapshot, InstalledStrixV2AuthoritySnapshot):
            raise InstalledStrixV2CompositionError("V2 authority source returned an invalid value")
        snapshot.validate(
            accepted=self._accepted,
            binding=self._binding,
            delegation=self._delegation,
        )
        with self._lock:
            if self._prelaunch_ref is None or self._prelaunch_ref != snapshot.prelaunch_ref:
                raise InstalledStrixV2CompositionError("V2 activation changed prelaunch authority")
            if self._snapshot_ref is None:
                self._snapshot_ref = snapshot.snapshot_ref
            elif self._snapshot_ref != snapshot.snapshot_ref:
                raise InstalledStrixV2CompositionError("V2 authority changed after allocation")
        return snapshot

    def require_active(self) -> InstalledStrixV2AuthoritySnapshot:
        try:
            snapshot = self._source.require_active(
                product_store=self._store,
                accepted=self._accepted,
                binding=self._binding,
                delegation=self._delegation,
                expected_resolution_ref=self._accepted.runtime_resolution_ref,
            )
        except Exception as exc:
            raise InstalledStrixV2CompositionError(
                "V2 execution resources are not durably active"
            ) from exc
        if not isinstance(snapshot, InstalledStrixV2AuthoritySnapshot):
            raise InstalledStrixV2CompositionError(
                "V2 active authority source returned invalid value"
            )
        snapshot.validate(
            accepted=self._accepted, binding=self._binding, delegation=self._delegation
        )
        with self._lock:
            if (
                self._prelaunch_ref != snapshot.prelaunch_ref
                or self._snapshot_ref != snapshot.snapshot_ref
            ):
                raise InstalledStrixV2CompositionError("V2 active authority changed")
        return snapshot


__all__ = [
    "InstalledStrixV2ActivationReceipt",
    "InstalledStrixV2AuthorityGuard",
    "InstalledStrixV2AuthoritySnapshot",
    "InstalledStrixV2AuthoritySource",
    "InstalledStrixV2CompositionError",
    "InstalledStrixV2HistoricalSnapshot",
    "InstalledStrixV2PrelaunchSnapshot",
]
