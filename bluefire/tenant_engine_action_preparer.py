"""Inert preparation of the fixed, controller-owned tenant-record journey.

The two sources below can only reopen retained controller material and inspect
an already running generation.  They must never allocate an admission, start a
lab, acquire a credential, or execute a request.  Missing material is a refusal;
preparation is deliberately not a provisioning or recovery interface.

The private issuer can retain a candidate slot atomically with its preparation.
The first store materialization must use that material's creation time;
subsequent requests reuse its exact identities, expiry and approval binding.
The existing store assigns and retains the submission identity atomically,
then passes it to the pure protected factory. Reconciliation is unavailable.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Mapping, Protocol

from .engine_action_preparation import (
    EngineActionPreparationError,
    EngineActionPreparationPlan,
    EngineWorkspaceAction,
    PreparedEngineActionLimits,
)
from .engine_attempt_contract import AttemptRole, EngineAttemptBinding
from .engine_container_custody import ContainerCustodyPlan
from .engine_controller_jobs import DefenseOperation, EngineControllerJobs
from .engine_delegation import EngineCapabilityDelegation
from .engine_experiment import ControllerCheckRole, EngineDefenseChange, EngineExperiment
from .engine_experiment_jobs import EngineExperimentJobs, installed_execution_claim_policy
from .engine_network_policy import (
    EffectiveNetworkSnapshot,
    EngineNetworkPlan,
    EngineNetworkVerification,
    VerificationState,
)
from .strix_adapter import (
    StrixBudgets,
    StrixBuildIdentity,
    StrixModelGateway,
    StrixRuntimeLimits,
    StrixScope,
)
from .strix_engine_runtime import (
    ProcessContainmentReceipt,
    ProtectedRuntimeRootsReceipt,
    StrixRuntimeAdmission,
    StrixRuntimeAdmissionResolver,
    _docker_memory_bytes,
    _docker_nano_cpus,
    _image_reference_digest,
)
from .tenant_record_experiment_controller import (
    TenantDefensePlan,
    TenantFailureMechanism,
    tenant_target_snapshot_ref,
)
from .tenant_record_lab import baseline_defense_config
from .tenant_record_target_adapter import TenantGenerationExpectation, TenantRunningGeneration
from .util import content_hash, json_clone, parse_iso8601_datetime

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENGINE_ACTIONS = frozenset(
    {EngineWorkspaceAction.START_BASELINE, EngineWorkspaceAction.START_ADAPTIVE_SEARCH}
)
_CHECK_ACTIONS = frozenset(
    {EngineWorkspaceAction.REPEAT_MECHANISM, EngineWorkspaceAction.RUN_LEGITIMATE_USE}
)
_UNAVAILABLE = frozenset(
    {EngineWorkspaceAction.RECONCILE_DEFENSE, EngineWorkspaceAction.RECONCILE_ROLLBACK}
)
_EMPTY_LIMITS = PreparedEngineActionLimits(None, None, None, None, None, None)


@dataclass(frozen=True, slots=True)
class TenantEnginePreparationPolicy:
    """Fixed protected policy; never populated from browser or model content."""

    build: StrixBuildIdentity
    model_provider: str
    model_id: str
    model_data_destination: str
    model_authorization_ref: str
    network_policy_digest: str
    custody_plan_digest: str
    wall_clock_seconds: int
    action_limit: int
    cost_limit_microunits: int
    artifact_byte_limit: int


@dataclass(frozen=True, slots=True)
class TenantEngineAttemptIdentity:
    attempt_id: str
    run_id: str
    delegation_id: str


@dataclass(frozen=True, slots=True)
class TenantControllerCheckIdentity:
    check_id: str
    run_id: str


@dataclass(frozen=True, slots=True)
class TenantActionPreparationMaterial:
    """One already-retained immutable slot, bound to an exact experiment head."""

    experiment_id: str
    experiment_revision: int
    experiment_digest: str
    action: EngineWorkspaceAction
    prepared_at: str
    expires_at: str
    target: TenantGenerationExpectation
    engine_identity: TenantEngineAttemptIdentity | None = None
    engine_policy: TenantEnginePreparationPolicy | None = None
    check_identity: TenantControllerCheckIdentity | None = None
    defense_plan: TenantDefensePlan | None = None
    mechanism: TenantFailureMechanism | None = None
    change_id: str | None = None


class RetainedTenantActionMaterialSource(Protocol):
    """Reopen exact protected material.  Never create or refresh a slot."""

    def reopen_exact(
        self,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        action: EngineWorkspaceAction,
    ) -> TenantActionPreparationMaterial | None: ...


class ActiveTenantGenerationSource(Protocol):
    """Read-only subset of the existing launcher-owned generation source."""

    def checked_running(
        self, expected: TenantGenerationExpectation | None
    ) -> TenantRunningGeneration: ...


class TenantActionMaterialIssuer(Protocol):
    """Private atomic retention callback; browser requests supply no material."""

    def retainer(
        self,
        *,
        material: TenantActionPreparationMaterial,
        experiment: EngineExperiment,
        workspace_digest: str,
    ) -> Callable[..., Mapping[str, Any]]: ...


def _timestamp(value: str) -> str:
    parsed = parse_iso8601_datetime(value)
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise EngineActionPreparationError("tenant preparation time is not canonical")
    return value


def _snapshot(config: Any) -> str:
    return tenant_target_snapshot_ref(
        fixture_digest=config.fixture_digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )


def _authority(kind: str, document: Mapping[str, Any]) -> dict[str, Any]:
    document = dict(json_clone(document))
    return {
        "schema_version": "bluefire.engine-action-authority.v1",
        "kind": kind,
        "document": document,
        "document_digest": content_hash(document),
    }


class ControllerOwnedTenantActionPreparer:
    """Prepare exact tenant actions using only pre-existing trusted authority."""

    def __init__(
        self,
        *,
        material_source: RetainedTenantActionMaterialSource,
        generation_source: ActiveTenantGenerationSource,
        runtime_resolver: StrixRuntimeAdmissionResolver,
        controller_jobs: EngineControllerJobs,
        material_issuer: TenantActionMaterialIssuer | None = None,
        execution_claim_policy: Mapping[str, Any] | None = None,
    ) -> None:
        self._materials = material_source
        self._generations = generation_source
        self._resolver = runtime_resolver
        self._jobs = controller_jobs
        self._issuer = material_issuer
        expected_policy = installed_execution_claim_policy()
        if execution_claim_policy is not None and dict(execution_claim_policy) != expected_policy:
            raise EngineActionPreparationError("engine execution claim policy changed")
        self._execution_claim_policy = (
            expected_policy if execution_claim_policy is not None else None
        )

    def prepare(
        self,
        *,
        experiment: EngineExperiment,
        workspace: Mapping[str, Any],
        action: EngineWorkspaceAction,
        prepared_at: str,
    ) -> EngineActionPreparationPlan:
        try:
            return self._prepare(experiment, workspace, action, prepared_at)
        except EngineActionPreparationError:
            raise
        except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise EngineActionPreparationError("trusted tenant preparation is unavailable") from exc

    def _prepare(
        self,
        experiment: EngineExperiment,
        workspace: Mapping[str, Any],
        action: EngineWorkspaceAction,
        prepared_at: str,
    ) -> EngineActionPreparationPlan:
        if not isinstance(experiment, EngineExperiment) or not isinstance(
            action, EngineWorkspaceAction
        ):
            raise EngineActionPreparationError("tenant action or experiment is invalid")
        experiment = EngineExperiment._from_controller_mapping(experiment.to_dict())
        prepared_at = _timestamp(prepared_at)
        if action in _UNAVAILABLE:
            raise EngineActionPreparationError("tenant reconciliation preparation is unavailable")
        if (
            workspace.get("schema_version") != "bluefire.engine-experiment-workspace.v1"
            or workspace.get("experiment_id") != experiment.experiment_id
            or workspace.get("revision") != experiment.revision
            or workspace.get("experiment_digest") != experiment.digest
            or not isinstance(workspace.get("workspace_digest"), str)
            or _DIGEST.fullmatch(workspace["workspace_digest"]) is None
        ):
            raise EngineActionPreparationError("tenant workspace binding changed")
        rows = workspace.get("actions")
        if (
            not isinstance(rows, list)
            or len(rows) != 1
            or not isinstance(rows[0], Mapping)
            or rows[0].get("kind") != action.value
            or rows[0].get("enabled") is not True
        ):
            raise EngineActionPreparationError("tenant workspace action changed")
        material = self._read_material(experiment, action)
        if (
            not (
                parse_iso8601_datetime(experiment.updated_at)
                <= parse_iso8601_datetime(_timestamp(material.prepared_at))
                <= parse_iso8601_datetime(prepared_at)
                < parse_iso8601_datetime(_timestamp(material.expires_at))
            )
            or not 0
            < (
                parse_iso8601_datetime(material.expires_at)
                - parse_iso8601_datetime(material.prepared_at)
            ).total_seconds()
            <= 7_800
        ):
            raise EngineActionPreparationError("tenant preparation slot is stale")
        self._check_material_shape(material)
        generation = self._check_target(experiment, material, prepared_at)
        binding: EngineAttemptBinding | None = None
        delegation: EngineCapabilityDelegation | None = None
        approval_request: Mapping[str, Any] | None = None
        limits = _EMPTY_LIMITS
        if action in _ENGINE_ACTIONS:
            binding, delegation = self._engine_authority(experiment, material)
            self._check_runtime(binding, delegation, generation, material.prepared_at)
            approval = delegation.approval_binding(binding)
            approval_request = approval.request_binding()
            limits = PreparedEngineActionLimits(
                binding.wall_clock_seconds,
                binding.action_limit,
                binding.artifact_byte_limit,
                binding.cost_limit_microunits,
                approval.target_scope_digest,
                approval.maximum_tier,
            )
            experiment.reserve_attempt(
                binding,
                job_id="job-" + "0" * 32,
                delegation_digest=delegation.delegation_digest,
                execution_approval_digest=content_hash(approval.to_dict()),
                execution_approval_id="approval-" + "0" * 32,
                timestamp=material.prepared_at,
            )
            request = None
            authority = None
        else:
            request, authority = self._controller_authority(experiment, material, generation)

        def protected_factory(
            approval_record: Mapping[str, Any] | None,
            submission_id: str | None,
        ) -> tuple[Mapping[str, Any] | None, Mapping[str, Any]]:
            try:
                # The store calls this only when creating a new preparation.
                # A retry reuses the existing protected row before this point.
                if prepared_at != material.prepared_at:
                    raise EngineActionPreparationError("new preparation requires its retained time")
                if self._read_material(experiment, action) != material:
                    raise EngineActionPreparationError("retained preparation material changed")
                current = self._check_target(experiment, material, prepared_at)
                is_transition = action in {
                    EngineWorkspaceAction.REVIEW_DEFENSE,
                    EngineWorkspaceAction.RETAIN_DEFENSE,
                }
                if is_transition:
                    if submission_id is not None:
                        raise EngineActionPreparationError(
                            "controller transition gained submission"
                        )
                elif (
                    not isinstance(submission_id, str)
                    or str(uuid.UUID(submission_id)) != submission_id
                ):
                    raise EngineActionPreparationError("controller submission identity is invalid")
                if binding is not None and delegation is not None:
                    self._check_runtime(binding, delegation, current, material.prepared_at)
                    if approval_record is None:
                        raise EngineActionPreparationError("engine approval is unavailable")
                    exact_approval = delegation.approval_binding(binding)
                    exact_approval.validate_approval_record(approval_record)
                    approval_id = approval_record.get("approval_id")
                    if not isinstance(approval_id, str) or not approval_id:
                        raise EngineActionPreparationError("engine approval identity is invalid")
                    return EngineExperimentJobs._request(
                        experiment=experiment,
                        binding=binding,
                        delegation=delegation,
                        approval=exact_approval,
                        approval_id=approval_id,
                        execution_claim_policy=self._execution_claim_policy,
                    ), _authority(
                        "engine_attempt",
                        {
                            "binding": binding.to_dict(),
                            "delegation": delegation.to_dict(),
                            "approval_binding": exact_approval.to_dict(),
                        },
                    )
                if approval_record is not None:
                    raise EngineActionPreparationError("controller action gained engine approval")
                fresh_request, fresh_authority = self._controller_authority(
                    experiment, material, current
                )
                if fresh_request != request or fresh_authority != authority:
                    raise EngineActionPreparationError("controller preparation changed")
                return fresh_request, fresh_authority
            except EngineActionPreparationError:
                raise
            except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
                raise EngineActionPreparationError(
                    "trusted tenant materialization refused"
                ) from exc

        return EngineActionPreparationPlan(
            action,
            limits,
            material.expires_at,
            protected_factory,
            approval_request,
            (
                None
                if self._issuer is None
                else self._issuer.retainer(
                    material=material,
                    experiment=experiment,
                    workspace_digest=workspace["workspace_digest"],
                )
            ),
        )

    def _read_material(
        self, experiment: EngineExperiment, action: EngineWorkspaceAction
    ) -> TenantActionPreparationMaterial:
        value = self._materials.reopen_exact(
            experiment_id=experiment.experiment_id,
            experiment_revision=experiment.revision,
            experiment_digest=experiment.digest,
            action=action,
        )
        if not isinstance(value, TenantActionPreparationMaterial) or (
            value.experiment_id != experiment.experiment_id
            or type(value.experiment_revision) is not int
            or value.experiment_revision != experiment.revision
            or value.experiment_digest != experiment.digest
            or value.action is not action
            or not isinstance(value.target, TenantGenerationExpectation)
        ):
            raise EngineActionPreparationError("exact retained tenant material is unavailable")
        return value

    @staticmethod
    def _check_material_shape(material: TenantActionPreparationMaterial) -> None:
        engine = material.action in _ENGINE_ACTIONS
        check = material.action in _CHECK_ACTIONS
        review = material.action is EngineWorkspaceAction.REVIEW_DEFENSE
        if (
            (material.engine_identity is not None) != engine
            or (material.engine_policy is not None) != engine
            or (material.check_identity is not None) != check
            or (material.defense_plan is not None) != (not engine)
            or (material.mechanism is not None) != (check or review)
            or (material.change_id is not None) != review
        ):
            raise EngineActionPreparationError("tenant material gained unrelated authority")

    def _check_target(
        self,
        experiment: EngineExperiment,
        material: TenantActionPreparationMaterial,
        prepared_at: str,
    ) -> TenantRunningGeneration:
        generation = self._generations.checked_running(material.target)
        if not isinstance(generation, TenantRunningGeneration):
            raise EngineActionPreparationError("active tenant generation is unavailable")
        # Re-run immutable generation validation, including active lifecycle,
        # packet/config/fixture bindings and complete controller admissions.
        generation = TenantRunningGeneration(
            **{name: getattr(generation, name) for name in generation.__dataclass_fields__}
        )
        expected = material.target
        baseline = baseline_defense_config(generation.fixture)
        if material.action is EngineWorkspaceAction.START_BASELINE:
            if generation.config != baseline:
                raise EngineActionPreparationError("baseline target configuration changed")
        elif material.action is EngineWorkspaceAction.START_ADAPTIVE_SEARCH:
            change = experiment.defense_change
            if change is None or generation.config.digest != change.approved_configuration_digest:
                raise EngineActionPreparationError("adaptive target configuration changed")
        if (
            generation.lifecycle.plan.digest != expected.plan_digest
            or generation.lifecycle.digest != expected.lifecycle_digest
            or generation.config.target_snapshot_id != expected.target_snapshot_id
            or generation.config.service_generation != expected.service_generation
            or _snapshot(generation.config) != experiment.current_target_snapshot_ref
            or not (
                parse_iso8601_datetime(generation.packet.created_at)
                <= parse_iso8601_datetime(prepared_at)
                < parse_iso8601_datetime(material.expires_at)
                <= parse_iso8601_datetime(generation.packet.expires_at)
            )
            or not (
                parse_iso8601_datetime(material.prepared_at)
                <= parse_iso8601_datetime(generation.packet.verified_at)
                < parse_iso8601_datetime(generation.packet.expires_at)
            )
        ):
            raise EngineActionPreparationError("tenant target generation or lifetime changed")
        return generation

    @staticmethod
    def _engine_authority(
        experiment: EngineExperiment, material: TenantActionPreparationMaterial
    ) -> tuple[EngineAttemptBinding, EngineCapabilityDelegation]:
        identity, policy = material.engine_identity, material.engine_policy
        if not isinstance(identity, TenantEngineAttemptIdentity) or not isinstance(
            policy, TenantEnginePreparationPolicy
        ):
            raise EngineActionPreparationError("retained engine policy is unavailable")
        role = (
            AttemptRole.BASELINE
            if material.action is EngineWorkspaceAction.START_BASELINE
            else AttemptRole.ADAPTIVE_SEARCH
        )
        if (role is AttemptRole.BASELINE and experiment.attempts) or (
            role is AttemptRole.ADAPTIVE_SEARCH and len(experiment.attempts) != 1
        ):
            raise EngineActionPreparationError("engine action lineage changed")
        build = StrixBuildIdentity(
            **{name: getattr(policy.build, name) for name in policy.build.__dataclass_fields__}
        )
        shared: dict[str, Any] = {
            "experiment_id": experiment.experiment_id,
            "attempt_id": identity.attempt_id,
            "role": role,
            "parent_attempt_id": (
                None
                if role is AttemptRole.BASELINE
                else experiment.attempts[0].record.binding.attempt_id
            ),
            "objective_ref": experiment.objective_ref,
            "environment_ref": experiment.environment_ref,
            "target_snapshot_ref": experiment.current_target_snapshot_ref,
            "scope_ref": experiment.scope_ref,
            "scope_version": experiment.scope_version,
            "engine_id": "strix",
            "engine_version": build.package_version,
            "engine_revision": build.source_revision,
            "engine_package_digest": build.package_sha256,
            "policy_overlay_digest": build.prompt_overlay_sha256,
            "model_provider": policy.model_provider,
            "model_id": policy.model_id,
            "model_data_destination": policy.model_data_destination,
            "model_authorization_ref": policy.model_authorization_ref,
            "wall_clock_seconds": policy.wall_clock_seconds,
            "action_limit": policy.action_limit,
            "cost_limit_microunits": policy.cost_limit_microunits,
            "artifact_byte_limit": policy.artifact_byte_limit,
            "created_at": material.prepared_at,
        }
        binding = EngineAttemptBinding(
            schema_version="bluefire.engine-attempt-binding.v1", run_id=identity.run_id, **shared
        )
        delegation = EngineCapabilityDelegation.create(
            delegation_id=identity.delegation_id,
            expires_at=material.expires_at,
            network_policy_digest=policy.network_policy_digest,
            custody_plan_digest=policy.custody_plan_digest,
            **shared,
        )
        delegation.validate_attempt_binding(binding)
        return binding, delegation

    def _check_runtime(
        self,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        generation: TenantRunningGeneration,
        prepared_at: str,
    ) -> None:
        saved = self._resolver.resolve(binding, delegation)
        if not isinstance(saved, StrixRuntimeAdmission) or saved.runtime_qualified is not True:
            raise EngineActionPreparationError("active persisted runtime admission is unavailable")
        build = StrixBuildIdentity(
            **{name: getattr(saved.build, name) for name in StrixBuildIdentity.__dataclass_fields__}
        )
        scope = StrixScope(
            **{name: getattr(saved.scope, name) for name in StrixScope.__dataclass_fields__}
        )
        gateway = StrixModelGateway(
            **{
                name: getattr(saved.gateway, name)
                for name in StrixModelGateway.__dataclass_fields__
            }
        )
        budgets = StrixBudgets(
            **{name: getattr(saved.budgets, name) for name in StrixBudgets.__dataclass_fields__}
        )
        runtime_limits = StrixRuntimeLimits(
            **{
                name: getattr(saved.limits, name)
                for name in StrixRuntimeLimits.__dataclass_fields__
            }
        )
        network = EngineNetworkPlan.from_mapping(saved.network_plan.to_dict())
        snapshot = EffectiveNetworkSnapshot.from_mapping(saved.network_snapshot.to_dict())
        verification = EngineNetworkVerification.from_mapping(
            saved.network_verification.to_dict(), plan=network, snapshot=snapshot
        )
        custody = ContainerCustodyPlan.from_mapping(saved.custody_plan.to_dict())
        roots = ProtectedRuntimeRootsReceipt.from_mapping(saved.protected_roots.to_dict())
        containment = ProcessContainmentReceipt.from_mapping(saved.containment.to_dict())
        if (
            saved.objective_ref != binding.objective_ref
            or saved.environment_ref != binding.environment_ref
            or build.package_version != binding.engine_version
            or build.source_revision != binding.engine_revision
            or build.package_sha256 != binding.engine_package_digest
            or build.prompt_overlay_sha256 != binding.policy_overlay_digest
            or saved.workspace.attempt_id
            != "attempt-" + binding.attempt_id.removeprefix("engine-attempt-")
            or _DIGEST.fullmatch(saved.runtime_qualification_ref) is None
            or scope.target_snapshot_digest != binding.target_snapshot_ref
            or scope.scope_digest != binding.scope_ref
            or scope.network_policy_digest != delegation.network_policy_digest
            or gateway.model != binding.model_id
            or gateway.base_url != binding.model_data_destination
            or gateway.authorization_digest != binding.model_authorization_ref
            or budgets.wall_seconds != binding.wall_clock_seconds
            or budgets.max_turns_per_agent != binding.action_limit
            or Decimal(budgets.max_model_cost_usd) * Decimal(1_000_000)
            != binding.cost_limit_microunits
            or network.attempt_id != binding.attempt_id
            or network.policy_digest != delegation.network_policy_digest
            or verification.state is not VerificationState.VERIFIED
            or scope.network_name != network.network_name
            or scope.origin != network.target.origin
            or scope.resolved_addresses != (network.target.address,)
            or gateway.base_url != network.model_gateway.origin + "/v1"
            or custody.attempt_id != binding.attempt_id
            or custody.plan_digest != delegation.custody_plan_digest
            or custody.network_policy_digest != delegation.network_policy_digest
            or custody.sandbox_image_digest != _image_reference_digest(build.image_reference)
            or custody.memory_bytes != _docker_memory_bytes(runtime_limits.memory)
            or custody.nano_cpus != _docker_nano_cpus(runtime_limits.cpus)
            or custody.pids_limit != runtime_limits.pids
            or roots.attempt_id != binding.attempt_id
            or containment.attempt_id != binding.attempt_id
            or containment.binding_digest != binding.binding_digest
            or containment.executable_sha256 != build.executable_sha256
            or containment.network_policy_digest != delegation.network_policy_digest
            or containment.custody_plan_digest != custody.plan_digest
            or containment.protected_roots_digest != roots.receipt_digest
            or containment.disposable_boundary_ref != custody.disposable_boundary_ref
            or binding.wall_clock_seconds > generation.packet.max_runtime_seconds
            or binding.wall_clock_seconds > generation.packet.remaining_seconds
            or binding.action_limit > generation.packet.max_requests
        ):
            raise EngineActionPreparationError(
                "persisted runtime authority differs from tenant action"
            )
        for timestamp in (
            snapshot.captured_at,
            verification.checked_at,
            roots.checked_at,
            containment.checked_at,
        ):
            if not (
                parse_iso8601_datetime(prepared_at)
                <= parse_iso8601_datetime(timestamp)
                < parse_iso8601_datetime(delegation.expires_at)
            ):
                raise EngineActionPreparationError("persisted runtime proof is stale")
        if not (
            parse_iso8601_datetime(network.created_at)
            <= parse_iso8601_datetime(snapshot.captured_at)
            <= parse_iso8601_datetime(verification.checked_at)
        ):
            raise EngineActionPreparationError("persisted network proof chronology changed")

    def _controller_authority(
        self,
        experiment: EngineExperiment,
        material: TenantActionPreparationMaterial,
        generation: TenantRunningGeneration,
    ) -> tuple[Mapping[str, Any] | None, Mapping[str, Any]]:
        plan = material.defense_plan
        if not isinstance(plan, TenantDefensePlan):
            raise EngineActionPreparationError("retained reviewed defense plan is unavailable")
        plan = TenantDefensePlan(
            **{name: getattr(plan, name) for name in plan.__dataclass_fields__}
        )
        if plan.before != baseline_defense_config(generation.fixture):
            raise EngineActionPreparationError("defense plan belongs to another tenant fixture")
        expected_config = (
            plan.before
            if material.action
            in {EngineWorkspaceAction.REVIEW_DEFENSE, EngineWorkspaceAction.APPLY_DEFENSE}
            else plan.after
        )
        if generation.config != expected_config:
            raise EngineActionPreparationError("retained defense target configuration changed")
        before, after = _snapshot(plan.before), _snapshot(plan.after)
        change = experiment.defense_change
        if material.action is EngineWorkspaceAction.REVIEW_DEFENSE:
            mechanism = self._mechanism(material, generation)
            if plan.planned_at != material.prepared_at or material.change_id is None:
                raise EngineActionPreparationError("defense review time changed")
            proposed = EngineDefenseChange.reviewed(
                change_id=material.change_id,
                experiment_id=experiment.experiment_id,
                mechanism_ref=content_hash(mechanism.to_dict()),
                preimage_digest=plan.before.digest,
                approved_configuration_digest=plan.after.digest,
                before_target_snapshot_ref=before,
                after_target_snapshot_ref=after,
                rollback_digest=plan.before.digest,
                reviewed_by="bluefire.controller",
                reviewed_at=plan.planned_at,
            )
            experiment.review_defense(proposed, timestamp=plan.planned_at)
            return None, _authority(
                "tenant_defense_review",
                {
                    "schema_version": "bluefire.tenant-defense-review-authority.v1",
                    "plan": plan.to_dict(),
                    "proposed_change": proposed.to_dict(),
                },
            )
        if change is None or (
            change.preimage_digest != plan.before.digest
            or change.approved_configuration_digest != plan.after.digest
            or change.rollback_digest != plan.before.digest
            or change.before_target_snapshot_ref != before
            or change.after_target_snapshot_ref != after
            or change.reviewed_at != plan.planned_at
        ):
            raise EngineActionPreparationError("retained defense plan differs from saved change")
        if material.action is EngineWorkspaceAction.RETAIN_DEFENSE:
            experiment.retain_defense(change.change_id, retained_at=material.prepared_at)
            return None, _authority("tenant_defense_plan", plan.to_dict())
        if material.action in {
            EngineWorkspaceAction.APPLY_DEFENSE,
            EngineWorkspaceAction.ROLLBACK_DEFENSE,
        }:
            operation = (
                DefenseOperation.APPLY
                if material.action is EngineWorkspaceAction.APPLY_DEFENSE
                else DefenseOperation.ROLLBACK
            )
            request = self._jobs.prepare_defense_operation(
                experiment_id=experiment.experiment_id,
                change_id=change.change_id,
                operation=operation,
            )
            if (
                request.get("experiment_revision") != experiment.revision
                or request.get("experiment_digest") != experiment.digest
            ):
                raise EngineActionPreparationError(
                    "defense builder observed another experiment head"
                )
            preview_receipt = content_hash(
                {
                    "schema_version": "bluefire.engine-defense-preparation-preview.v1",
                    "experiment_id": experiment.experiment_id,
                    "change_id": change.change_id,
                    "operation": operation.value,
                    "request_digest": content_hash(request),
                }
            )
            if operation is DefenseOperation.APPLY:
                experiment.begin_defense_application(
                    change.change_id,
                    operation_receipt_digest=preview_receipt,
                    started_at=material.prepared_at,
                )
            else:
                experiment.begin_defense_rollback(
                    change.change_id,
                    rollback_operation_digest=preview_receipt,
                    rollback_started_at=material.prepared_at,
                )
            return request, _authority("tenant_defense_plan", plan.to_dict())
        mechanism = self._mechanism(material, generation)
        if change.mechanism_ref != content_hash(mechanism.to_dict()):
            raise EngineActionPreparationError("retained failure mechanism lineage changed")
        identity = material.check_identity
        if not isinstance(identity, TenantControllerCheckIdentity):
            raise EngineActionPreparationError("retained controller check identity is unavailable")
        if experiment.current_target_snapshot_ref is None:
            raise EngineActionPreparationError("current tenant snapshot is unknown")
        role = (
            ControllerCheckRole.RETAINED_REPRODUCER
            if material.action is EngineWorkspaceAction.REPEAT_MECHANISM
            else ControllerCheckRole.LEGITIMATE_USE
        )
        input_digest = content_hash(
            {
                "schema_version": "bluefire.tenant-controller-check-input.v1",
                "mechanism": mechanism.to_dict(),
                "role": role.value,
                "target_snapshot_ref": experiment.current_target_snapshot_ref,
                "configuration_digest": generation.config.digest,
            }
        )
        request = self._jobs.prepare_controller_check(
            experiment_id=experiment.experiment_id,
            check_id=identity.check_id,
            run_id=identity.run_id,
            role=role,
            mechanism_ref=change.mechanism_ref,
            target_snapshot_ref=experiment.current_target_snapshot_ref,
            input_digest=input_digest,
            reserved_at=material.prepared_at,
        )
        if (
            request.get("experiment_revision") != experiment.revision
            or request.get("experiment_digest") != experiment.digest
        ):
            raise EngineActionPreparationError("check builder observed another experiment head")
        return request, _authority(
            "tenant_controller_check",
            {
                "schema_version": "bluefire.tenant-controller-check-authority.v1",
                "mechanism": mechanism.to_dict(),
                "check_id": identity.check_id,
                "run_id": identity.run_id,
                "role": role.value,
                "input_digest": input_digest,
                "reserved_at": material.prepared_at,
            },
        )

    @staticmethod
    def _mechanism(
        material: TenantActionPreparationMaterial, generation: TenantRunningGeneration
    ) -> TenantFailureMechanism:
        mechanism = material.mechanism
        if not isinstance(mechanism, TenantFailureMechanism):
            raise EngineActionPreparationError("retained failure mechanism is unavailable")
        mechanism = TenantFailureMechanism(
            **{name: getattr(mechanism, name) for name in mechanism.__dataclass_fields__}
        )
        if (
            mechanism.fixture_digest != generation.fixture.digest
            or mechanism.original_target_snapshot_id
            != baseline_defense_config(generation.fixture).target_snapshot_id
            or mechanism.protected_tenant_id != generation.fixture.protected_tenant_id
            or (
                mechanism.record_id is not None
                and mechanism.record_id
                not in {
                    record.record_id
                    for record in generation.fixture.records_for(
                        generation.fixture.protected_tenant_id
                    )
                }
            )
        ):
            raise EngineActionPreparationError(
                "retained mechanism belongs to another target lineage"
            )
        return mechanism


__all__ = [
    "ActiveTenantGenerationSource",
    "ControllerOwnedTenantActionPreparer",
    "RetainedTenantActionMaterialSource",
    "TenantActionPreparationMaterial",
    "TenantControllerCheckIdentity",
    "TenantEngineAttemptIdentity",
    "TenantEnginePreparationPolicy",
]
