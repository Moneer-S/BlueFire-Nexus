from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.engine_experiment as experiment_module
import bluefire.tenant_record_experiment_controller as tenant_controller_module
import bluefire.tenant_record_observer as tenant_observer_module
import tests_platform.test_strix_engine_runtime as runtime_fakes
from bluefire.engine_action_preparation import (
    EngineActionPreparationError,
    EngineActionPreparationPlan,
    EngineWorkspaceAction,
)
from bluefire.engine_attempt_contract import AttemptRole, EngineAttemptBinding
from bluefire.engine_controller_jobs import EngineControllerJobs
from bluefire.engine_experiment import (
    ControllerCheckRecord,
    ControllerCheckRole,
    DefenseState,
    EngineDefenseChange,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_experiment_jobs import installed_execution_claim_policy
from bluefire.product_store_engine_actions import _protected_authority, _tenant_plan
from bluefire.strix_engine_runtime import StrixEngineRuntime, StrixRuntimeAdmission
from bluefire.tenant_engine_action_preparer import (
    ControllerOwnedTenantActionPreparer,
    TenantActionPreparationMaterial,
    TenantControllerCheckIdentity,
    TenantEngineAttemptIdentity,
    TenantEnginePreparationPolicy,
)
from bluefire.tenant_record_experiment_controller import (
    TenantFailureMechanism,
    TenantRecordExperimentController,
)
from bluefire.tenant_record_lab import TenantDefenseConfig
from bluefire.tenant_record_lab_launcher import TenantRecordLabLauncher
from bluefire.tenant_record_target_adapter import TenantRunningGeneration
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import build_completed_experiment
from tests_platform.test_product_store_engine_actions import (
    _FIXTURE,
    _defense_plan,
    _failure_mechanism,
)
from tests_platform.test_tenant_record_target_adapter import _expectation, _generation

_SUBMISSION = "00000000-0000-4000-8000-000000000001"
_ACTION_TIMES = {
    EngineWorkspaceAction.START_BASELINE: "2026-11-04T12:00:00Z",
    EngineWorkspaceAction.REVIEW_DEFENSE: "2026-11-04T12:06:00Z",
    EngineWorkspaceAction.APPLY_DEFENSE: "2026-11-04T12:06:10Z",
    EngineWorkspaceAction.REPEAT_MECHANISM: "2026-11-04T12:08:00Z",
    EngineWorkspaceAction.START_ADAPTIVE_SEARCH: "2026-11-04T12:11:00Z",
    EngineWorkspaceAction.RUN_LEGITIMATE_USE: "2026-11-04T12:16:00Z",
    EngineWorkspaceAction.RETAIN_DEFENSE: "2026-11-04T12:19:00Z",
    EngineWorkspaceAction.ROLLBACK_DEFENSE: "2026-11-04T12:20:00Z",
}
_ENGINE_ACTIONS = {
    EngineWorkspaceAction.START_BASELINE,
    EngineWorkspaceAction.START_ADAPTIVE_SEARCH,
}
_CHECK_ACTIONS = {
    EngineWorkspaceAction.REPEAT_MECHANISM,
    EngineWorkspaceAction.RUN_LEGITIMATE_USE,
}
_TRANSITIONS = {EngineWorkspaceAction.REVIEW_DEFENSE, EngineWorkspaceAction.RETAIN_DEFENSE}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _shift(value: str, seconds: int) -> str:
    return _iso(datetime.fromisoformat(value.replace("Z", "+00:00")) + timedelta(seconds=seconds))


def _snapshot(config: TenantDefenseConfig) -> str:
    from bluefire.tenant_record_experiment_controller import tenant_target_snapshot_ref

    return tenant_target_snapshot_ref(
        fixture_digest=config.fixture_digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )


def _stage(action: EngineWorkspaceAction):
    """Rebind established fake workflow data to one real fixed tenant plan."""
    plan = _tenant_plan(_defense_plan("2026-11-04T12:06:00Z"))
    mechanism = _failure_mechanism()
    before, after = _snapshot(plan.before), _snapshot(plan.after)
    mechanism_ref = content_hash(mechanism.to_dict())
    completed = build_completed_experiment()
    assert completed.defense_change is not None
    change: EngineDefenseChange | None = replace(
        completed.defense_change,
        mechanism_ref=mechanism_ref,
        preimage_digest=plan.before.digest,
        approved_configuration_digest=plan.after.digest,
        applied_configuration_digest=plan.after.digest,
        rollback_digest=plan.before.digest,
        before_target_snapshot_ref=before,
        after_target_snapshot_ref=after,
    )
    attempts = []
    for entry in completed.attempts:
        binding = replace(
            entry.record.binding,
            target_snapshot_ref=(
                before if entry.record.binding.role is AttemptRole.BASELINE else after
            ),
        )
        attempts.append(
            replace(
                entry,
                record=replace(
                    entry.record, binding=binding, binding_digest=binding.binding_digest
                ),
            )
        )
    checks = tuple(
        replace(check, target_snapshot_ref=after, mechanism_ref=mechanism_ref)
        for check in completed.checks
    )
    observations = tuple(
        _controller_observation_record(
            target_snapshot_ref=(
                before if observation.attempt_id == attempts[0].record.binding.attempt_id else after
            ),
            mechanism_ref=mechanism_ref,
            attempt_id=observation.attempt_id,
            check_id=observation.check_id,
            check_input_digest=observation.check_input_digest,
            evidence=observation.evidence,
        )
        for observation in completed.independent_observations
    )
    experiment = replace(
        completed,
        revision=1,
        previous_revision_digest=None,
        initial_target_snapshot_ref=before,
        current_target_snapshot_ref=after,
        attempts=tuple(attempts),
        checks=checks,
        independent_observations=observations,
        defense_change=change,
    )
    if action is EngineWorkspaceAction.START_BASELINE:
        return (
            EngineExperiment.create(
                experiment_id=experiment.experiment_id,
                objective_ref=experiment.objective_ref,
                environment_ref=experiment.environment_ref,
                scope_ref=experiment.scope_ref,
                scope_version=experiment.scope_version,
                target_snapshot_ref=before,
                created_at=_ACTION_TIMES[action],
            ),
            plan,
            mechanism,
        )
    if action in {
        EngineWorkspaceAction.REVIEW_DEFENSE,
        EngineWorkspaceAction.APPLY_DEFENSE,
        EngineWorkspaceAction.REPEAT_MECHANISM,
    }:
        experiment = replace(
            experiment,
            attempts=experiment.attempts[:1],
            checks=(),
            independent_observations=experiment.independent_observations[:1],
        )
    elif action is EngineWorkspaceAction.START_ADAPTIVE_SEARCH:
        experiment = replace(
            experiment,
            attempts=experiment.attempts[:1],
            checks=experiment.checks[:1],
            independent_observations=experiment.independent_observations[:2],
        )
    elif action is EngineWorkspaceAction.RUN_LEGITIMATE_USE:
        experiment = replace(
            experiment,
            checks=experiment.checks[:1],
            independent_observations=experiment.independent_observations[:3],
        )
    assert change is not None
    if action is not EngineWorkspaceAction.ROLLBACK_DEFENSE:
        change = replace(change, state=DefenseState.APPLIED, retained_at=None)
    if action is EngineWorkspaceAction.REVIEW_DEFENSE:
        change = None
    elif action is EngineWorkspaceAction.APPLY_DEFENSE:
        assert change is not None
        change = replace(
            change,
            state=DefenseState.REVIEWED,
            applied_configuration_digest=None,
            application_receipt_digest=None,
            reconciliation_receipt_digest=None,
            applied_at=None,
            reconciled_at=None,
        )
    before_change = action in {
        EngineWorkspaceAction.REVIEW_DEFENSE,
        EngineWorkspaceAction.APPLY_DEFENSE,
    }
    experiment = replace(
        experiment,
        defense_change=change,
        current_target_snapshot_ref=before if before_change else after,
        updated_at=_shift(_ACTION_TIMES[action], -1),
    )
    experiment.validate()
    return experiment, plan, mechanism


class _NoEffects:
    def __getattr__(self, name: str):
        raise AssertionError(f"preparation attempted forbidden effect: {name}")


class _Repository(_NoEffects):
    def __init__(self, experiment: EngineExperiment) -> None:
        self.experiment = experiment
        self.reads = 0

    def get_engine_experiment_document(self, experiment_id: str):
        assert experiment_id == self.experiment.experiment_id
        self.reads += 1
        return self.experiment.to_dict()


class _Materials(_NoEffects):
    def __init__(self, material: TenantActionPreparationMaterial) -> None:
        self.material: TenantActionPreparationMaterial | None = material
        self.calls: list[dict[str, Any]] = []

    def reopen_exact(self, **values: Any):
        self.calls.append(values)
        return self.material


class _Generations(_NoEffects):
    def __init__(self, generation: TenantRunningGeneration) -> None:
        self.generation: TenantRunningGeneration | None = generation
        self.calls = 0

    def checked_running(self, expected):
        self.calls += 1
        return self.generation


class _Resolver(_NoEffects):
    def __init__(self, admission: StrixRuntimeAdmission | None) -> None:
        self.admission = admission
        self.calls: list[tuple[Any, Any]] = []

    def resolve(self, binding, delegation):
        self.calls.append((binding, delegation))
        return self.admission


@dataclass
class _Case:
    preparer: ControllerOwnedTenantActionPreparer
    experiment: EngineExperiment
    workspace: dict[str, Any]
    materials: _Materials
    generations: _Generations
    resolver: _Resolver
    repository: _Repository

    @property
    def material(self) -> TenantActionPreparationMaterial:
        assert self.materials.material is not None
        return self.materials.material

    @material.setter
    def material(self, value: TenantActionPreparationMaterial | None) -> None:
        self.materials.material = value

    @property
    def generation(self) -> TenantRunningGeneration:
        assert self.generations.generation is not None
        return self.generations.generation

    @generation.setter
    def generation(self, value: TenantRunningGeneration | None) -> None:
        self.generations.generation = value

    @property
    def admission(self) -> StrixRuntimeAdmission:
        assert self.resolver.admission is not None
        return self.resolver.admission

    @admission.setter
    def admission(self, value: StrixRuntimeAdmission | None) -> None:
        self.resolver.admission = value

    def prepare(self, *, prepared_at: str | None = None) -> EngineActionPreparationPlan:
        material = self.materials.material
        assert material is not None
        return self.preparer.prepare(
            experiment=self.experiment,
            workspace=self.workspace,
            action=material.action,
            prepared_at=prepared_at or material.prepared_at,
        )


def _case(
    tmp_path: Path,
    action: EngineWorkspaceAction,
    monkeypatch,
    *,
    execution_claim_policy: Mapping[str, Any] | None = None,
) -> _Case:
    experiment, plan, mechanism = _stage(action)
    prepared_at = _ACTION_TIMES[action]
    config = (
        plan.before
        if experiment.current_target_snapshot_ref == _snapshot(plan.before)
        else plan.after
    )
    target_root = tmp_path / "target"
    target_root.mkdir()
    generation = _generation(target_root, fixture=_FIXTURE, config=config, marker="a")
    expected = _expectation(generation, target_root)
    generation = replace(
        generation,
        packet=replace(
            generation.packet,
            created_at=_shift(prepared_at, -1),
            expires_at=_shift(prepared_at, 599),
            verified_at=prepared_at,
        ),
    )
    engine_identity = None
    policy = None
    admission = None
    if action in _ENGINE_ACTIONS:
        suffix = "a" if action is EngineWorkspaceAction.START_BASELINE else "b"
        engine_identity = TenantEngineAttemptIdentity(
            "engine-attempt-" + suffix * 32,
            "run-20261104T120100Z-" + suffix * 16,
            "engine-delegation-" + suffix * 32,
        )
        runtime_root = tmp_path / "runtime"
        runtime_root.mkdir()
        with monkeypatch.context() as context:
            context.setattr(runtime_fakes, "ENGINE_ATTEMPT", engine_identity.attempt_id)
            context.setattr(runtime_fakes, "ADAPTER_ATTEMPT", "attempt-" + suffix * 32)
            _, _, admission = runtime_fakes._fixture(
                runtime_root,
                network_created_at=prepared_at,
                network_captured_at=prepared_at,
                network_checked_at=prepared_at,
            )
        policy = TenantEnginePreparationPolicy(
            build=admission.build,
            model_provider="provider.test",
            model_id=admission.gateway.model,
            model_data_destination=admission.gateway.base_url,
            model_authorization_ref=admission.gateway.authorization_digest,
            network_policy_digest=admission.network_plan.policy_digest,
            custody_plan_digest=admission.custody_plan.plan_digest,
            wall_clock_seconds=300,
            action_limit=20,
            cost_limit_microunits=1_000_000,
            artifact_byte_limit=4 * 1024 * 1024,
        )
    material = TenantActionPreparationMaterial(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        action=action,
        prepared_at=prepared_at,
        expires_at=_shift(prepared_at, 300),
        target=expected,
        engine_identity=engine_identity,
        engine_policy=policy,
        check_identity=(
            TenantControllerCheckIdentity(
                "controller-check-" + "f" * 32, "run-20261104T120100Z-" + "f" * 16
            )
            if action in _CHECK_ACTIONS
            else None
        ),
        defense_plan=None if action in _ENGINE_ACTIONS else plan,
        mechanism=(
            mechanism
            if action in _CHECK_ACTIONS or action is EngineWorkspaceAction.REVIEW_DEFENSE
            else None
        ),
        change_id=(
            "defense-change-" + "e" * 32 if action is EngineWorkspaceAction.REVIEW_DEFENSE else None
        ),
    )
    if admission is not None:
        binding, _ = ControllerOwnedTenantActionPreparer._engine_authority(experiment, material)
        roots = replace(admission.protected_roots, checked_at=prepared_at)
        admission = replace(
            admission,
            objective_ref=experiment.objective_ref,
            environment_ref=experiment.environment_ref,
            scope=replace(
                admission.scope,
                target_snapshot_digest=experiment.current_target_snapshot_ref,
                scope_digest=experiment.scope_ref,
            ),
            protected_roots=roots,
            containment=replace(
                admission.containment,
                binding_digest=binding.binding_digest,
                protected_roots_digest=roots.receipt_digest,
                checked_at=prepared_at,
            ),
        )
    materials, generations, resolver = (
        _Materials(material),
        _Generations(generation),
        _Resolver(admission),
    )
    repository = _Repository(experiment)
    jobs = EngineControllerJobs(
        controller=_NoEffects(),
        repository=repository,
        defense_executor=None,
        check_executor=None,
        clock=lambda: prepared_at,
    )
    preparer = ControllerOwnedTenantActionPreparer(
        material_source=materials,
        generation_source=generations,
        runtime_resolver=resolver,
        controller_jobs=jobs,
        execution_claim_policy=execution_claim_policy,
    )
    workspace = {
        "schema_version": "bluefire.engine-experiment-workspace.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "workspace_digest": content_hash({"workspace": action.value}),
        "actions": [{"kind": action.value, "enabled": True}],
    }
    return _Case(preparer, experiment, workspace, materials, generations, resolver, repository)


def _materialize(plan: EngineActionPreparationPlan):
    approval = (
        None
        if plan.approval_request is None
        else {**plan.approval_request, "approval_id": "approval-" + "e" * 32}
    )
    return plan.protected_factory(approval, None if plan.action in _TRANSITIONS else _SUBMISSION)


def _forbid_effects(monkeypatch) -> None:
    def forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("preparation performed an external effect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(experiment_module, "_controller_observation_record", forbidden)
    monkeypatch.setattr(tenant_controller_module, "_controller_observation_record", forbidden)
    monkeypatch.setattr(tenant_controller_module, "observe_tenant_response", forbidden)
    monkeypatch.setattr(tenant_observer_module, "observe_tenant_response", forbidden)
    for cls, names in (
        (StrixEngineRuntime, ("execute", "reconcile", "_prepare")),
        (runtime_fakes.Credentials, ("acquire", "reconcile_revocation")),
        (
            TenantRecordExperimentController,
            (
                "prepare_defense",
                "apply_defense",
                "rollback_defense",
                "run_exact_reproducer",
                "run_legitimate_use",
                "observe_engine_response",
                "retain_hardening",
                "cleanup_lab",
            ),
        ),
        (TenantRecordLabLauncher, ("prepare", "start", "stop", "cleanup", "reconcile")),
    ):
        for name in names:
            monkeypatch.setattr(cls, name, forbidden)


@pytest.mark.parametrize("action", list(_ACTION_TIMES))
def test_all_supported_actions_are_exact_inert_and_stable(
    tmp_path: Path, monkeypatch, action
) -> None:
    case = _case(tmp_path, action, monkeypatch)
    before = case.experiment.to_dict()
    _forbid_effects(monkeypatch)

    first, second = case.prepare(), case.prepare()
    first_result, second_result = _materialize(first), _materialize(second)

    assert first.action is action
    assert first.limits == second.limits
    assert first.expires_at == second.expires_at
    assert first.approval_request == second.approval_request
    assert first_result == second_result
    assert case.experiment.to_dict() == before
    assert case.generations.calls == 4
    request, authority = first_result
    assert authority["document_digest"] == content_hash(authority["document"])
    approval = (
        None
        if first.approval_request is None
        else {**first.approval_request, "approval_id": "approval-" + "e" * 32}
    )
    checked = _protected_authority(
        authority,
        action=action,
        experiment=case.experiment,
        prepared_at=case.material.prepared_at,
        reviewed_plan=(
            None if action is EngineWorkspaceAction.REVIEW_DEFENSE else case.material.defense_plan
        ),
        approval_id=None if approval is None else approval["approval_id"],
        approval_record=approval,
        limits=first.limits,
        job_request=request,
    )
    assert checked == authority
    if action in _ENGINE_ACTIONS:
        binding = EngineAttemptBinding.from_mapping(authority["document"]["binding"])
        assert binding.role is (
            AttemptRole.BASELINE
            if action is EngineWorkspaceAction.START_BASELINE
            else AttemptRole.ADAPTIVE_SEARCH
        )
        assert binding.parent_attempt_id == (
            None
            if action is EngineWorkspaceAction.START_BASELINE
            else case.experiment.attempts[0].record.binding.attempt_id
        )
        assert binding.target_snapshot_ref == case.experiment.current_target_snapshot_ref
        assert binding.created_at == case.material.prepared_at
        assert binding.wall_clock_seconds == 300 and binding.action_limit == 20
        assert len(case.resolver.calls) == 4
        assert request["schema_version"] == "bluefire.engine-attempt-job.v1"
    else:
        assert all(value is None for value in first.limits.to_dict().values())
        assert first.approval_request is None and case.resolver.calls == []
        if action in _TRANSITIONS:
            assert request is None
        else:
            assert request["experiment_digest"] == case.experiment.digest
            assert request["experiment_revision"] == case.experiment.revision
            assert case.repository.reads == 4


def test_installed_preparer_binds_exact_execution_claim_policy(tmp_path: Path, monkeypatch) -> None:
    policy = installed_execution_claim_policy()
    case = _case(
        tmp_path,
        EngineWorkspaceAction.START_BASELINE,
        monkeypatch,
        execution_claim_policy=policy,
    )

    request, authority = _materialize(case.prepare())

    assert request["schema_version"] == "bluefire.engine-attempt-job.v2"
    assert request["execution_claim_policy"] == policy
    assert authority["document_digest"] == content_hash(authority["document"])


def test_installed_preparer_rejects_changed_execution_claim_policy(
    tmp_path: Path, monkeypatch
) -> None:
    policy = {**installed_execution_claim_policy(), "accepted_jobs_adapter": "changed"}

    with pytest.raises(EngineActionPreparationError, match="claim policy changed"):
        _case(
            tmp_path,
            EngineWorkspaceAction.START_BASELINE,
            monkeypatch,
            execution_claim_policy=policy,
        )


@pytest.mark.parametrize(
    "action", [EngineWorkspaceAction.RECONCILE_DEFENSE, EngineWorkspaceAction.RECONCILE_ROLLBACK]
)
def test_reconciliation_has_no_preparation_authority(tmp_path: Path, monkeypatch, action) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError, match="reconciliation"):
        case.preparer.prepare(
            experiment=case.experiment,
            workspace=case.workspace,
            action=action,
            prepared_at=_ACTION_TIMES[EngineWorkspaceAction.START_BASELINE],
        )
    assert case.materials.calls == [] and case.generations.calls == 0 and case.resolver.calls == []


def test_advancing_clock_reuses_exact_review_material_but_cannot_create_new_slot(
    tmp_path: Path, monkeypatch
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    first = case.prepare()
    later = case.prepare(prepared_at=_shift(case.material.prepared_at, 1))
    assert first.approval_request == later.approval_request
    assert first.expires_at == later.expires_at and first.limits == later.limits
    with pytest.raises(EngineActionPreparationError, match="retained time"):
        _materialize(later)


@pytest.mark.parametrize(
    "change", ["missing", "different_snapshot", "different_generation", "expired", "lifecycle"]
)
def test_target_must_be_active_exact_and_unexpired(tmp_path: Path, monkeypatch, change) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    generation = case.generation
    if change == "missing":
        case.generation = None
    elif change == "different_snapshot":
        case.material = replace(
            case.material,
            target=replace(case.material.target, target_snapshot_id="other-snapshot"),
        )
    elif change == "different_generation":
        case.material = replace(
            case.material,
            target=replace(case.material.target, service_generation="other-generation"),
        )
    elif change == "expired":
        case.material = replace(case.material, expires_at=generation.packet.expires_at)
        generation = replace(
            generation,
            packet=replace(
                generation.packet,
                expires_at=_shift(generation.packet.expires_at, -1),
                max_runtime_seconds=599,
            ),
        )
        case.generation = generation
    else:
        case.material = replace(
            case.material,
            target=replace(case.material.target, lifecycle_digest="sha256:" + "9" * 64),
        )
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError):
        case.prepare()
    assert case.resolver.calls == []


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "revoked",
        "scope",
        "model",
        "budget",
        "custody",
        "containment",
        "proof_time",
        "sandbox",
    ],
)
def test_engine_preparation_rejects_missing_revoked_or_inexact_runtime(
    tmp_path: Path, monkeypatch, change
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    if change == "missing":
        case.admission = None
        _forbid_effects(monkeypatch)
        with pytest.raises(EngineActionPreparationError):
            case.prepare()
        return
    admission = case.admission
    if change == "revoked":
        admission = replace(admission, runtime_qualified=False)
    elif change == "scope":
        admission = replace(
            admission, scope=replace(admission.scope, scope_digest="sha256:" + "9" * 64)
        )
    elif change == "model":
        admission = replace(
            admission, gateway=replace(admission.gateway, authorization_digest="sha256:" + "9" * 64)
        )
    elif change == "budget":
        admission = replace(admission, budgets=replace(admission.budgets, max_turns_per_agent=21))
    elif change == "custody":
        admission = replace(
            admission,
            custody_plan=replace(
                admission.custody_plan, network_policy_digest="sha256:" + "9" * 64
            ),
        )
    elif change == "containment":
        admission = replace(
            admission,
            containment=replace(admission.containment, binding_digest="sha256:" + "9" * 64),
        )
    elif change == "sandbox":
        admission = replace(admission, limits=replace(admission.limits, memory="1g"))
    else:
        admission = replace(
            admission,
            protected_roots=replace(admission.protected_roots, checked_at="2026-11-03T12:00:00Z"),
        )
    case.admission = admission
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError):
        case.prepare()


@pytest.mark.parametrize("drift", ["target", "runtime", "material"])
def test_protected_factory_rereads_authority_and_refuses_drift(
    tmp_path: Path, monkeypatch, drift
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    plan = case.prepare()
    if drift == "target":
        case.generation = None
    elif drift == "runtime":
        case.admission = replace(case.admission, runtime_qualified=False)
    else:
        case.material = replace(case.material, expires_at=_shift(case.material.expires_at, 1))
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError):
        _materialize(plan)


@pytest.mark.parametrize(
    "field,value",
    [
        ("experiment_revision", 2),
        ("experiment_digest", "sha256:" + "9" * 64),
        ("experiment_id", "experiment-" + "9" * 32),
        ("action", EngineWorkspaceAction.START_ADAPTIVE_SEARCH),
    ],
)
def test_wrong_retained_material_lineage_is_refused(
    tmp_path: Path, monkeypatch, field, value
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    case.material = replace(case.material, **{field: value})
    with pytest.raises(EngineActionPreparationError):
        case.preparer.prepare(
            experiment=case.experiment,
            workspace=case.workspace,
            action=EngineWorkspaceAction.START_BASELINE,
            prepared_at=_ACTION_TIMES[EngineWorkspaceAction.START_BASELINE],
        )
    assert case.generations.calls == 0 and case.resolver.calls == []


def test_wrong_failure_mechanism_lineage_is_refused(tmp_path: Path, monkeypatch) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.REPEAT_MECHANISM, monkeypatch)
    mechanism = case.material.mechanism
    assert mechanism is not None
    fixture_digest = "sha256:" + "9" * 64
    wrong = replace(
        mechanism,
        fixture_digest=fixture_digest,
        request_digest=content_hash(
            TenantFailureMechanism._request_binding(
                fixture_digest,
                mechanism.original_target_snapshot_id,
                mechanism.route,
                mechanism.protected_tenant_id,
                mechanism.record_id,
            )
        ),
    )
    case.material = replace(case.material, mechanism=wrong)
    with pytest.raises(EngineActionPreparationError):
        case.prepare()
    assert case.repository.reads == 0


@pytest.mark.parametrize(
    "action",
    [EngineWorkspaceAction.START_ADAPTIVE_SEARCH, EngineWorkspaceAction.REPEAT_MECHANISM],
)
def test_same_snapshot_ids_cannot_hide_a_different_full_configuration(
    tmp_path: Path, monkeypatch, action
) -> None:
    case = _case(tmp_path, action, monkeypatch)
    generation = case.generation
    wrong = replace(generation.config, session_key_digest="sha256:" + "9" * 64)
    assert _snapshot(wrong) == case.experiment.current_target_snapshot_ref
    case.generation = replace(
        generation, config=wrong, packet=replace(generation.packet, config_digest=wrong.digest)
    )
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError):
        case.prepare()
    assert case.resolver.calls == [] and case.repository.reads == 0


def test_rollback_cannot_be_prepared_while_controller_work_is_active(
    tmp_path: Path, monkeypatch
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.ROLLBACK_DEFENSE, monkeypatch)
    experiment, _, _ = _stage(EngineWorkspaceAction.REPEAT_MECHANISM)
    check = ControllerCheckRecord.reserve(
        check_id="controller-check-" + "f" * 32,
        experiment_id=experiment.experiment_id,
        job_id="job-" + "f" * 32,
        run_id="run-20261104T120800Z-" + "f" * 16,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=experiment.defense_change.mechanism_ref,
        target_snapshot_ref=experiment.current_target_snapshot_ref,
        input_digest="sha256:" + "9" * 64,
        created_at="2026-11-04T12:08:00Z",
    )
    case.experiment = experiment.reserve_controller_check(check, timestamp="2026-11-04T12:08:00Z")
    case.repository.experiment = case.experiment
    case.material = replace(
        case.material,
        experiment_revision=case.experiment.revision,
        experiment_digest=case.experiment.digest,
    )
    case.workspace.update(
        revision=case.experiment.revision, experiment_digest=case.experiment.digest
    )
    _forbid_effects(monkeypatch)
    with pytest.raises(EngineActionPreparationError):
        case.prepare()


@pytest.mark.parametrize("field,value", [("enabled", False), ("kind", "start_adaptive_search")])
def test_workspace_cannot_supply_another_action(tmp_path: Path, monkeypatch, field, value) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    case.workspace["actions"][0][field] = value
    with pytest.raises(EngineActionPreparationError):
        case.prepare()
    assert case.materials.calls == []


def test_engine_factory_requires_the_exact_store_approval_and_submission(
    tmp_path: Path, monkeypatch
) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    plan = case.prepare()
    assert plan.approval_request is not None
    for approval, submission in [
        (None, _SUBMISSION),
        ({**plan.approval_request, "scope_ref": "bad"}, "not-a-uuid"),
    ]:
        with pytest.raises(EngineActionPreparationError):
            plan.protected_factory(approval, submission)
    wrong_approval = {
        **plan.approval_request,
        "approval_id": "approval-" + "e" * 32,
        "target_scope_digest": "sha256:" + "9" * 64,
    }
    with pytest.raises(EngineActionPreparationError):
        plan.protected_factory(wrong_approval, _SUBMISSION)


def test_preparation_never_reads_browser_authority_fields(tmp_path: Path, monkeypatch) -> None:
    case = _case(tmp_path, EngineWorkspaceAction.START_BASELINE, monkeypatch)
    case.workspace.update(
        {
            "binding": {"role": "adaptive_search"},
            "model_id": "attacker-model",
            "command": "untrusted",
            "parent_attempt_id": "engine-attempt-" + "9" * 32,
        }
    )
    plan = case.prepare()
    _, authority = _materialize(plan)
    binding = authority["document"]["binding"]
    assert binding["role"] == "baseline" and binding["parent_attempt_id"] is None
    assert binding["model_id"] == "controlled-test-provider"
    assert "command" not in str(authority)
