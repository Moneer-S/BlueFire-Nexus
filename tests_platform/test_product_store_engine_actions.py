from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

import bluefire.product_store_engine_actions as action_store
from bluefire.engine_action_preparation import (
    EnginePreparedActionKind,
    EnginePreparedApprovalState,
    EngineWorkspaceAction,
    PreparedEngineAction,
    PreparedEngineActionLimits,
    engine_action_contract,
)
from bluefire.engine_attempt_contract import AttemptRole, EngineAttemptBinding
from bluefire.engine_controller_jobs import DefenseOperation, EngineControllerJobs
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    ControllerCheckRole,
    EngineDefenseChange,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_experiment_jobs import EngineExperimentJobs
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.tenant_record_experiment_controller import (
    TenantFailureMechanism,
    TenantRecordExperimentController,
    TenantRoute,
    tenant_target_snapshot_ref,
)
from bluefire.tenant_record_lab import (
    TenantDefenseConfig,
    baseline_defense_config,
    generate_tenant_record_fixture,
)
from bluefire.util import content_hash
from tests_platform.test_engine_controller_jobs import (
    _applied_experiment,
    _reviewed_experiment,
)
from tests_platform.test_engine_controller_jobs import (
    _Controller as _ControllerJobController,
)
from tests_platform.test_engine_controller_jobs import (
    _jobs as _controller_jobs,
)
from tests_platform.test_engine_controller_jobs import (
    _Repository as _ControllerRepository,
)

EXPERIMENT_ID = "experiment-" + "1" * 32
OBJECTIVE_REF = "sha256:" + "1" * 64
ENVIRONMENT_REF = "sha256:" + "2" * 64
SCOPE_REF = "sha256:" + "3" * 64
_FIXTURE = generate_tenant_record_fixture(seed=b"prepared-action-tests-000000000000")
_BASE_CONFIG = baseline_defense_config(_FIXTURE)
TARGET_REF = tenant_target_snapshot_ref(
    fixture_digest=_BASE_CONFIG.fixture_digest,
    target_snapshot_id=_BASE_CONFIG.target_snapshot_id,
    service_generation=_BASE_CONFIG.service_generation,
)
WORKSPACE_REF = "sha256:" + "6" * 64


class _ActionStore(ProductStore):
    pass


class _PlanTarget:
    def current_config(self) -> TenantDefenseConfig:
        return _BASE_CONFIG


def _defense_plan(
    planned_at: str,
    *,
    operation_id: str = "tenant-defense-" + "d" * 32,
) -> Mapping[str, Any]:
    controller = TenantRecordExperimentController(
        fixture=_FIXTURE,
        target=_PlanTarget(),  # type: ignore[arg-type]
        signing_key=b"prepared-action-signing-key-0001",
    )
    return controller.prepare_defense(
        operation_id=operation_id,
        key_id="session-key-0001",
        application_nonce="application-nonce-0001",
        responsible_actor="bluefire-controller",
        planned_at=planned_at,
    ).to_dict()


def _material_authority(kind: str, document: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.engine-action-authority.v1",
        "kind": kind,
        "document": dict(document),
        "document_digest": content_hash(document),
    }


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validator(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return EngineExperiment._from_controller_mapping(value).to_dict()


def _store(tmp_path: Path) -> _ActionStore:
    store = _ActionStore(tmp_path / "state" / "bluefire.sqlite3")
    experiment = EngineExperiment.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref=OBJECTIVE_REF,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=TARGET_REF,
        created_at="2026-11-04T12:00:00Z",
    )
    store.create_engine_experiment(
        EXPERIMENT_ID,
        experiment.to_dict(),
        validator=_validator,
    )
    return store


def _store_experiment(tmp_path: Path, experiment: EngineExperiment) -> _ActionStore:
    store = _ActionStore(tmp_path / "state" / "bluefire.sqlite3")
    store.create_engine_experiment(
        experiment.experiment_id,
        experiment.to_dict(),
        validator=_validator,
    )
    return store


def _failure_mechanism() -> TenantFailureMechanism:
    record = _FIXTURE.records_for(_FIXTURE.protected_tenant_id)[0]
    request = TenantFailureMechanism._request_binding(
        _FIXTURE.digest,
        _BASE_CONFIG.target_snapshot_id,
        TenantRoute.RECORD_LOOKUP,
        _FIXTURE.protected_tenant_id,
        record.record_id,
    )
    return TenantFailureMechanism(
        fixture_digest=_FIXTURE.digest,
        original_target_snapshot_id=_BASE_CONFIG.target_snapshot_id,
        route=TenantRoute.RECORD_LOOKUP,
        protected_tenant_id=_FIXTURE.protected_tenant_id,
        record_id=record.record_id,
        request_digest=content_hash(request),
    )


def _applied_tenant_mechanism_experiment() -> tuple[EngineExperiment, TenantFailureMechanism]:
    experiment = _applied_experiment()
    mechanism = _failure_mechanism()
    mechanism_ref = content_hash(mechanism.to_dict())
    assert experiment.defense_change is not None
    experiment = replace(
        experiment,
        revision=1,
        previous_revision_digest=None,
        defense_change=replace(experiment.defense_change, mechanism_ref=mechanism_ref),
        independent_observations=tuple(
            _controller_observation_record(
                target_snapshot_ref=observation.target_snapshot_ref,
                mechanism_ref=mechanism_ref,
                evidence=observation.evidence,
                attempt_id=observation.attempt_id,
                check_id=observation.check_id,
                check_input_digest=observation.check_input_digest,
            )
            for observation in experiment.independent_observations
        ),
    )
    experiment.validate()
    return experiment, mechanism


def _tenant_defense_states(
    plan: Mapping[str, Any],
) -> tuple[EngineExperiment, EngineExperiment, EngineExperiment, EngineExperiment]:
    """Build the exact no-defense, reviewed, unknown, and applied tenant states."""

    experiment = _reviewed_experiment()
    before = plan["before"]
    after = plan["after"]
    before_ref = tenant_target_snapshot_ref(
        fixture_digest=before["fixture_digest"],
        target_snapshot_id=before["target_snapshot_id"],
        service_generation=before["service_generation"],
    )
    after_ref = tenant_target_snapshot_ref(
        fixture_digest=after["fixture_digest"],
        target_snapshot_id=after["target_snapshot_id"],
        service_generation=after["service_generation"],
    )
    entry = experiment.attempts[0]
    binding = replace(entry.record.binding, target_snapshot_ref=before_ref)
    record = replace(
        entry.record,
        binding=binding,
        binding_digest=binding.binding_digest,
    )
    observation = experiment.independent_observations[0]
    rebound_observation = _controller_observation_record(
        target_snapshot_ref=before_ref,
        mechanism_ref=observation.mechanism_ref,
        attempt_id=observation.attempt_id,
        evidence=observation.evidence,
    )
    prior_change = experiment.defense_change
    assert prior_change is not None
    proposed = EngineDefenseChange.reviewed(
        change_id=prior_change.change_id,
        experiment_id=experiment.experiment_id,
        mechanism_ref=prior_change.mechanism_ref,
        preimage_digest=content_hash(before),
        approved_configuration_digest=content_hash(after),
        before_target_snapshot_ref=before_ref,
        after_target_snapshot_ref=after_ref,
        rollback_digest=content_hash(before),
        reviewed_by=prior_change.reviewed_by,
        reviewed_at=plan["planned_at"],
    )
    prereview = replace(
        experiment,
        revision=1,
        previous_revision_digest=None,
        initial_target_snapshot_ref=before_ref,
        current_target_snapshot_ref=before_ref,
        attempts=(replace(entry, record=record),),
        independent_observations=(rebound_observation,),
        defense_change=None,
    )
    prereview.validate()
    reviewed = prereview.review_defense(proposed, timestamp=proposed.reviewed_at)
    planned_time = datetime.fromisoformat(str(plan["planned_at"]).replace("Z", "+00:00"))
    unknown = reviewed.begin_defense_application(
        proposed.change_id,
        operation_receipt_digest="sha256:" + "1" * 64,
        started_at=_iso(planned_time + timedelta(seconds=1)),
    )
    applied = unknown.reconcile_defense_applied(
        proposed.change_id,
        applied_configuration_digest=content_hash(after),
        reconciliation_receipt_digest="sha256:" + "2" * 64,
        observed_target_snapshot_ref=after_ref,
        reconciled_at=_iso(planned_time + timedelta(seconds=2)),
    )
    return prereview, reviewed, unknown, applied


def _tenant_defense_experiment(plan: Mapping[str, Any], *, applied: bool) -> EngineExperiment:
    states = _tenant_defense_states(plan)
    return states[3] if applied else states[1]


def _times(*, offset: int = 0) -> tuple[str, str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset)
    return _iso(now), _iso(now + timedelta(minutes=5)), _iso(now + timedelta(seconds=1))


def _limits() -> PreparedEngineActionLimits:
    return PreparedEngineActionLimits(
        wall_clock_seconds=300,
        action_limit=20,
        artifact_byte_limit=4 * 1024 * 1024,
        cost_limit_microunits=1_000_000,
        target_scope_digest=SCOPE_REF,
        maximum_tier="controlled",
    )


def _controller_limits() -> PreparedEngineActionLimits:
    return PreparedEngineActionLimits(
        wall_clock_seconds=None,
        action_limit=None,
        artifact_byte_limit=None,
        cost_limit_microunits=None,
        target_scope_digest=None,
        maximum_tier=None,
    )


def _store_tenant_defense_history(
    tmp_path: Path,
    *,
    plan: Mapping[str, Any],
    expires_at: str,
    applied: bool,
) -> tuple[_ActionStore, EngineExperiment]:
    prereview, reviewed, unknown, applied_state = _tenant_defense_states(plan)
    proposed = reviewed.defense_change
    assert proposed is not None
    store = _store_experiment(tmp_path, prereview)
    authority = _material_authority(
        "tenant_defense_review",
        {
            "schema_version": "bluefire.tenant-defense-review-authority.v1",
            "plan": plan,
            "proposed_change": proposed.to_dict(),
        },
    )
    store.create_engine_action_preparation(
        experiment_id=prereview.experiment_id,
        experiment_revision=prereview.revision,
        experiment_digest=prereview.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REVIEW_DEFENSE,
        limits=_controller_limits(),
        prepared_at=plan["planned_at"],
        expires_at=expires_at,
        protected_factory=lambda approval, submission: (None, authority),
    )
    store.save_engine_experiment(
        prereview.experiment_id,
        reviewed.to_dict(),
        expected_revision=prereview.revision,
        expected_digest=prereview.digest,
        validator=_validator,
    )
    if not applied:
        return store, reviewed
    store.save_engine_experiment(
        prereview.experiment_id,
        unknown.to_dict(),
        expected_revision=reviewed.revision,
        expected_digest=reviewed.digest,
        validator=_validator,
    )
    store.save_engine_experiment(
        prereview.experiment_id,
        applied_state.to_dict(),
        expected_revision=unknown.revision,
        expected_digest=unknown.digest,
        validator=_validator,
    )
    return store, applied_state


def _attempt_authority(
    prepared_at: str, expires_at: str
) -> tuple[EngineAttemptBinding, EngineCapabilityDelegation, Any]:
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": "engine-attempt-" + "a" * 32,
            "run_id": "run-20261104T120000Z-" + "8" * 16,
            "role": "baseline",
            "objective_ref": OBJECTIVE_REF,
            "environment_ref": ENVIRONMENT_REF,
            "target_snapshot_ref": TARGET_REF,
            "scope_ref": SCOPE_REF,
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "engine_id": "strix",
            "engine_version": "1.7.0",
            "engine_revision": "7" * 40,
            "engine_package_digest": "sha256:" + "7" * 64,
            "policy_overlay_digest": "sha256:" + "8" * 64,
            "model_provider": "provider.test",
            "model_id": "controlled-provider",
            "model_data_destination": "https://model.test/v1",
            "model_authorization_ref": "sha256:" + "9" * 64,
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": prepared_at,
            "parent_attempt_id": None,
        }
    )
    delegation = EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "a" * 32,
        experiment_id=EXPERIMENT_ID,
        attempt_id=binding.attempt_id,
        role=AttemptRole.BASELINE,
        parent_attempt_id=None,
        objective_ref=OBJECTIVE_REF,
        environment_ref=ENVIRONMENT_REF,
        target_snapshot_ref=TARGET_REF,
        scope_ref=SCOPE_REF,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        engine_id=binding.engine_id,
        engine_version=binding.engine_version,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        policy_overlay_digest=binding.policy_overlay_digest,
        model_authorization_ref=binding.model_authorization_ref,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_data_destination=binding.model_data_destination,
        network_policy_digest="sha256:" + "b" * 64,
        custody_plan_digest="sha256:" + "c" * 64,
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
        created_at=prepared_at,
        expires_at=expires_at,
    )
    return binding, delegation, delegation.approval_binding(binding)


def _attempt_factory(
    store: _ActionStore,
    prepared_at: str,
    expires_at: str,
    calls: list[tuple[str, str]],
) -> tuple[action_store.ProtectedActionFactory, Mapping[str, Any]]:
    binding, delegation, approval_binding = _attempt_authority(prepared_at, expires_at)

    def factory(
        approval: Mapping[str, Any] | None,
        submission_id: str | None,
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        assert approval is not None
        assert submission_id is not None
        approval_id = str(approval["approval_id"])
        calls.append((approval_id, submission_id))
        experiment = EngineExperiment._from_controller_mapping(
            store.get_engine_experiment(EXPERIMENT_ID)["document"]
        )
        request = EngineExperimentJobs._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval_binding,
            approval_id=approval_id,
        )
        document = {
            "binding": binding.to_dict(),
            "delegation": delegation.to_dict(),
            "approval_binding": approval_binding.to_dict(),
        }
        authority = {
            "schema_version": "bluefire.engine-action-authority.v1",
            "kind": "engine_attempt",
            "document": document,
            "document_digest": content_hash(document),
        }
        return request, authority

    return factory, approval_binding.request_binding()


def _create_attempt(
    store: _ActionStore,
    *,
    prepared_at: str,
    expires_at: str,
    calls: list[tuple[str, str]] | None = None,
) -> Mapping[str, Any]:
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval = _attempt_factory(
        store,
        prepared_at,
        expires_at,
        calls if calls is not None else [],
    )
    return store.create_engine_action_preparation(
        experiment_id=EXPERIMENT_ID,
        experiment_revision=history["revision"],
        experiment_digest=history["digest"],
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.START_BASELINE,
        limits=_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=factory,
        approval_request=approval,
    )


def _advance_experiment(store: _ActionStore) -> Mapping[str, Any]:
    current = store.get_engine_experiment(EXPERIMENT_ID)
    experiment = EngineExperiment._from_controller_mapping(current["document"])
    advanced = replace(
        experiment,
        revision=experiment.revision + 1,
        previous_revision_digest=experiment.digest,
        updated_at="2026-11-04T12:00:01Z",
    )
    advanced.validate()
    return store.save_engine_experiment(
        EXPERIMENT_ID,
        advanced.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validator,
    )


def test_schema_initialization_requires_the_caller_transaction() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ProductStoreError, match="requires one transaction"):
            action_store.initialize_schema(connection)
    finally:
        connection.close()


def test_v15_upgrade_preserves_experiment_and_enables_action_preparation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    path = store.path
    before = store.get_engine_experiment(EXPERIMENT_ID)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE engine_action_preparations")
        connection.execute("DELETE FROM schema_migrations")
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (15, ?)",
            ("2026-11-03T00:00:00Z",),
        )

    upgraded = _ActionStore(path)
    assert upgraded.schema_version == 17
    assert upgraded.get_engine_experiment(EXPERIMENT_ID) == before
    prepared_at, expires_at, _ = _times()
    protected = _create_attempt(
        upgraded,
        prepared_at=prepared_at,
        expires_at=expires_at,
    )
    assert (
        upgraded.prepared_engine_action(protected["request_ref"])["action_kind"] == "start_baseline"
    )


def test_v15_applied_state_keeps_safe_continuation_without_fabricated_plan(
    tmp_path: Path,
) -> None:
    experiment, mechanism = _applied_tenant_mechanism_experiment()
    store = _store_experiment(tmp_path, experiment)
    path = store.path
    before = store.get_engine_experiment(experiment.experiment_id)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE engine_action_preparations")
        connection.execute("DELETE FROM schema_migrations")
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (15, ?)",
            ("2026-11-03T00:00:00Z",),
        )

    upgraded = _ActionStore(path)
    assert upgraded.get_engine_experiment(experiment.experiment_id) == before
    prepared_at, expires_at, _ = _times()
    check_request, check_authority = _prepared_controller_check_material(
        experiment,
        mechanism,
        reserved_at=prepared_at,
    )
    check = upgraded.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REPEAT_MECHANISM,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda approval, submission: (
            check_request,
            check_authority,
        ),
    )
    assert (
        upgraded.prepared_engine_action(check["request_ref"])["action_kind"] == "repeat_mechanism"
    )

    assert experiment.defense_change is not None
    jobs: EngineControllerJobs = _controller_jobs(_ControllerRepository(experiment))
    rollback_request = jobs.prepare_defense_operation(
        experiment_id=experiment.experiment_id,
        change_id=experiment.defense_change.change_id,
        operation=DefenseOperation.ROLLBACK,
    )
    with pytest.raises(ProductStoreError, match="exact retained review plan"):
        upgraded.create_engine_action_preparation(
            experiment_id=experiment.experiment_id,
            experiment_revision=experiment.revision,
            experiment_digest=experiment.digest,
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.ROLLBACK_DEFENSE,
            limits=_controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=lambda approval, submission: (
                rollback_request,
                _material_authority("tenant_defense_plan", _defense_plan(prepared_at)),
            ),
        )
    with upgraded._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_action_preparations "
                "WHERE action_kind = 'rollback_defense'"
            ).fetchone()[0]
            == 0
        )


def test_preparation_is_exact_private_and_public_review_omits_authority(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    calls: list[tuple[str, str]] = []

    protected = _create_attempt(
        store,
        prepared_at=prepared_at,
        expires_at=expires_at,
        calls=calls,
    )
    public = store.prepared_engine_action(protected["request_ref"])

    assert len(calls) == 1
    assert protected["protected_request"]["authority"]["document"]["binding"]["schema_version"]
    assert protected["approval_request_id"].startswith("approval-")
    assert protected["submission_id"] == calls[0][1]
    assert protected["intent_digest"] == content_hash(protected["protected_request"]["job_request"])
    assert public["schema_version"] == "bluefire.engine-prepared-action.v1"
    assert public["protected_request_ref"] == protected["request_ref"]
    assert public["approval"] == {
        "required": True,
        "state": "pending",
        "review_binding_digest": protected["approval_review_binding_digest"],
        "expires_at": expires_at,
    }
    assert public["effects_started_at_preparation"] is False
    assert PreparedEngineAction.from_mapping(public).to_dict() == public
    flattened = repr(public).lower()
    for forbidden in (
        "approval_request_id",
        "approval_id",
        "nonce",
        "authority",
        "job_request",
        "command",
        "artifact_body",
        "evidence",
    ):
        assert forbidden not in flattened


def test_exact_unexpired_retry_reuses_one_row_approval_and_submission(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    calls: list[tuple[str, str]] = []

    first = _create_attempt(
        store,
        prepared_at=prepared_at,
        expires_at=expires_at,
        calls=calls,
    )
    second = _create_attempt(
        store,
        prepared_at=prepared_at,
        expires_at=expires_at,
        calls=calls,
    )

    assert second == first
    assert calls == [calls[0]]
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wall_clock_seconds", 299),
        ("action_limit", 19),
        ("artifact_byte_limit", 4 * 1024 * 1024 - 1),
        ("cost_limit_microunits", 999_999),
        ("target_scope_digest", "sha256:" + "7" * 64),
        ("maximum_tier", "safe"),
    ],
)
def test_public_limits_must_exactly_match_protected_attempt_authority(
    field: str,
    value: Any,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])

    with pytest.raises(ProductStoreError, match="limits differ"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=replace(_limits(), **{field: value}),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=factory,
            approval_request=approval_request,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_created_approval_must_match_protected_typed_approval(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])
    mismatched = {
        **approval_request,
        "run_id": "run-20261104T120001Z-" + "9" * 16,
    }

    with pytest.raises(ProductStoreError, match="authority is invalid"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=factory,
            approval_request=mismatched,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_attempt_authority_creation_time_is_bound_to_trusted_preparation_time(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, different_time = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval = _attempt_factory(store, different_time, expires_at, [])

    with pytest.raises(ProductStoreError, match="differs from the current experiment"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=factory,
            approval_request=approval,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_unexpired_retry_refuses_different_review_inputs(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    _create_attempt(store, prepared_at=prepared_at, expires_at=expires_at)
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])

    with pytest.raises(ResourceConflictError, match="different review inputs"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=replace(_limits(), action_limit=19),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=factory,
            approval_request=approval_request,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1


def test_concurrent_retry_creates_one_preparation_and_one_approval(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    barrier = threading.Barrier(2)
    calls: list[tuple[str, str]] = []
    results: list[Mapping[str, Any]] = []
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=5)
            results.append(
                _create_attempt(
                    store,
                    prepared_at=prepared_at,
                    expires_at=expires_at,
                    calls=calls,
                )
            )
        except BaseException as exc:  # pragma: no cover - assertion reports thread failure
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert failures == []
    assert len(results) == 2
    assert results[0] == results[1]
    assert len(calls) == 1
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1


def test_factory_failure_rolls_back_its_pending_approval(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    _unused_factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])

    def fail(_approval: Mapping[str, Any] | None, _submission: str | None):
        raise RuntimeError("pure factory failed")

    with pytest.raises(RuntimeError, match="pure factory failed"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=fail,
            approval_request=approval_request,
        )

    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_stale_experiment_head_refuses_without_orphaned_approval(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    old = store.get_engine_experiment(EXPERIMENT_ID)
    attempt_factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])
    _advance_experiment(store)

    with pytest.raises(ResourceConflictError, match="head changed"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=old["revision"],
            experiment_digest=old["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=attempt_factory,
            approval_request=approval_request,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_unexpired_retry_rechecks_head_before_returning_saved_authority(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    old = store.get_engine_experiment(EXPERIMENT_ID)
    retry_factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])
    first = _create_attempt(store, prepared_at=prepared_at, expires_at=expires_at)
    _advance_experiment(store)

    with pytest.raises(ResourceConflictError, match="head changed"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=old["revision"],
            experiment_digest=old["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=retry_factory,
            approval_request=approval_request,
        )

    assert store.get_protected_engine_action_preparation(first["request_ref"]) == first
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 1


def test_preparation_identity_is_stable_as_approval_status_advances(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    record = _create_attempt(store, prepared_at=prepared_at, expires_at=expires_at)
    pending = store.prepared_engine_action(record["request_ref"])
    authority = record["protected_request"]["authority"]["document"]
    approval_binding = authority["approval_binding"]

    approved = store.approve(
        record["approval_request_id"],
        approved_by="prepared-action-reviewer",
        expected_state_digest=approval_binding["state_digest"],
        expected_plan_digest=approval_binding["plan_digest"],
        expected_target_scope_digest=approval_binding["target_scope_digest"],
    )
    approved_review = store.prepared_engine_action(record["request_ref"])
    store.consume_approval(
        record["approval_request_id"],
        nonce=approved["nonce"],
        expected_state_digest=approval_binding["state_digest"],
        expected_plan_digest=approval_binding["plan_digest"],
        expected_target_scope_digest=approval_binding["target_scope_digest"],
    )
    consumed_review = store.prepared_engine_action(record["request_ref"])

    assert pending["approval"]["state"] == "pending"
    assert approved_review["approval"]["state"] == "approved"
    assert consumed_review["approval"]["state"] == "consumed"
    assert {
        pending["preparation_id"],
        approved_review["preparation_id"],
        consumed_review["preparation_id"],
    } == {pending["preparation_id"]}


def test_untyped_or_command_bearing_attempt_authority_is_rejected_atomically(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    valid_factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])

    def malicious(approval: Mapping[str, Any] | None, submission: str | None):
        request, authority = valid_factory(approval, submission)
        changed = dict(authority)
        changed_document = dict(changed["document"])
        changed_document["command"] = "powershell -enc not-allowed"
        changed["document"] = changed_document
        changed["document_digest"] = content_hash(changed_document)
        return request, changed

    with pytest.raises(ProductStoreError, match="authority fields changed"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=malicious,
            approval_request=approval_request,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_preparation_refuses_future_server_time_without_writes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times(offset=10)
    history = store.get_engine_experiment(EXPERIMENT_ID)
    factory, approval_request = _attempt_factory(store, prepared_at, expires_at, [])

    with pytest.raises(ProductStoreError, match="time is not current"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.START_BASELINE,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=factory,
            approval_request=approval_request,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_expired_generation_is_replaced_without_reusing_submission_or_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    base = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(action_store, "utc_now", lambda: _iso(base))
    calls: list[tuple[str, str]] = []
    first = _create_attempt(
        store,
        prepared_at=_iso(base),
        expires_at=_iso(base + timedelta(minutes=1)),
        calls=calls,
    )
    monkeypatch.setattr(action_store, "utc_now", lambda: _iso(base + timedelta(minutes=2)))
    second = _create_attempt(
        store,
        prepared_at=_iso(base + timedelta(minutes=2)),
        expires_at=_iso(base + timedelta(minutes=7)),
        calls=calls,
    )

    assert second["generation"] == 2
    assert second["request_ref"] != first["request_ref"]
    assert second["approval_request_id"] != first["approval_request_id"]
    assert second["submission_id"] != first["submission_id"]
    assert len(calls) == 2


def test_registry_is_immutable_after_valid_attempt_preparation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    protected = _create_attempt(
        store,
        prepared_at=prepared_at,
        expires_at=expires_at,
    )

    public = store.prepared_engine_action(protected["request_ref"])
    assert public["approval"]["state"] == "pending"
    assert public["submission"] is not None
    with store._connection(write=True) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE engine_action_preparations SET generation = 2 WHERE request_ref = ?",
                (protected["request_ref"],),
            )
    with store._connection(write=True) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM engine_action_preparations WHERE request_ref = ?",
                (protected["request_ref"],),
            )
    with store._connection(write=True) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only history"):
            connection.execute(
                "INSERT OR REPLACE INTO engine_action_preparations "
                "SELECT * FROM engine_action_preparations WHERE request_ref = ?",
                (protected["request_ref"],),
            )


def test_defense_review_requires_settled_independent_baseline_proof(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    plan = _defense_plan(prepared_at)
    proposed = EngineDefenseChange.reviewed(
        change_id="defense-change-" + "d" * 32,
        experiment_id=EXPERIMENT_ID,
        mechanism_ref="sha256:" + "e" * 64,
        preimage_digest=content_hash(plan["before"]),
        approved_configuration_digest=content_hash(plan["after"]),
        before_target_snapshot_ref=TARGET_REF,
        after_target_snapshot_ref=tenant_target_snapshot_ref(
            fixture_digest=plan["after"]["fixture_digest"],
            target_snapshot_id=plan["after"]["target_snapshot_id"],
            service_generation=plan["after"]["service_generation"],
        ),
        rollback_digest=content_hash(plan["before"]),
        reviewed_by="Test operator",
        reviewed_at=prepared_at,
    )
    authority = {
        "schema_version": "bluefire.tenant-defense-review-authority.v1",
        "plan": plan,
        "proposed_change": proposed.to_dict(),
    }

    with pytest.raises(ProductStoreError, match="not currently valid"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.REVIEW_DEFENSE,
            limits=_controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=lambda approval, submission: (
                None,
                _material_authority("tenant_defense_review", authority),
            ),
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )


@pytest.mark.parametrize("timing", ["exact", "proposal_mismatch", "future_pair"])
def test_defense_review_binds_the_exact_tenant_plan_and_review_event(
    timing: str,
    tmp_path: Path,
) -> None:
    prepared_at, expires_at, alternate_time = _times()
    plan = _defense_plan(alternate_time if timing == "future_pair" else prepared_at)
    experiment, reviewed, _unknown, _applied = _tenant_defense_states(plan)
    prior_change = reviewed.defense_change
    assert prior_change is not None
    proposed = EngineDefenseChange.reviewed(
        change_id="defense-change-" + "f" * 32,
        experiment_id=experiment.experiment_id,
        mechanism_ref=prior_change.mechanism_ref,
        preimage_digest=content_hash(plan["before"]),
        approved_configuration_digest=content_hash(plan["after"]),
        before_target_snapshot_ref=experiment.initial_target_snapshot_ref,
        after_target_snapshot_ref=tenant_target_snapshot_ref(
            fixture_digest=plan["after"]["fixture_digest"],
            target_snapshot_id=plan["after"]["target_snapshot_id"],
            service_generation=plan["after"]["service_generation"],
        ),
        rollback_digest=content_hash(plan["before"]),
        reviewed_by="Test operator",
        reviewed_at=(prepared_at if timing == "exact" else alternate_time),
    )
    authority = _material_authority(
        "tenant_defense_review",
        {
            "schema_version": "bluefire.tenant-defense-review-authority.v1",
            "plan": plan,
            "proposed_change": proposed.to_dict(),
        },
    )
    store = _store_experiment(tmp_path, experiment)
    before = store.get_engine_experiment(experiment.experiment_id)

    if timing != "exact":
        with pytest.raises(ProductStoreError, match="differs from its plan"):
            store.create_engine_action_preparation(
                experiment_id=experiment.experiment_id,
                experiment_revision=experiment.revision,
                experiment_digest=experiment.digest,
                workspace_digest=WORKSPACE_REF,
                action=EngineWorkspaceAction.REVIEW_DEFENSE,
                limits=_controller_limits(),
                prepared_at=prepared_at,
                expires_at=expires_at,
                protected_factory=lambda approval, submission: (None, authority),
            )
        with store._connection() as connection:
            assert (
                connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0]
                == 0
            )
        return

    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REVIEW_DEFENSE,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda approval, submission: (None, authority),
    )
    assert protected["protected_request"]["authority"] == authority
    assert store.get_engine_experiment(experiment.experiment_id) == before
    assert (
        store.prepared_engine_action(protected["request_ref"])["effects_started_at_preparation"]
        is False
    )


@pytest.mark.parametrize(
    ("action", "operation", "applied"),
    [
        (EngineWorkspaceAction.APPLY_DEFENSE, DefenseOperation.APPLY, False),
        (EngineWorkspaceAction.ROLLBACK_DEFENSE, DefenseOperation.ROLLBACK, True),
    ],
)
def test_defense_job_preparation_accepts_exact_trusted_builder_without_effects(
    action: EngineWorkspaceAction,
    operation: DefenseOperation,
    applied: bool,
    tmp_path: Path,
) -> None:
    prepared_at, expires_at, _ = _times()
    reviewed_at, review_expires_at, _ = _times(offset=-10)
    plan = _defense_plan(reviewed_at)
    store, experiment = _store_tenant_defense_history(
        tmp_path,
        plan=plan,
        expires_at=review_expires_at,
        applied=applied,
    )
    jobs: EngineControllerJobs = _controller_jobs(_ControllerRepository(experiment))
    assert experiment.defense_change is not None
    request = jobs.prepare_defense_operation(
        experiment_id=experiment.experiment_id,
        change_id=experiment.defense_change.change_id,
        operation=operation,
    )
    authority = _material_authority("tenant_defense_plan", plan)
    before = store.get_engine_experiment(experiment.experiment_id)

    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=action,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda approval, submission: (request, authority),
    )

    assert protected["protected_request"]["job_request"] == request
    assert protected["intent_digest"] == content_hash(request)
    assert store.get_engine_experiment(experiment.experiment_id) == before
    public = store.prepared_engine_action(protected["request_ref"])
    assert public["action_kind"] == action.value
    assert public["effects_started_at_preparation"] is False
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def test_defense_job_rejects_a_new_plan_with_the_same_configuration(
    tmp_path: Path,
) -> None:
    prepared_at, expires_at, _ = _times()
    reviewed_at, review_expires_at, _ = _times(offset=-10)
    reviewed_plan = _defense_plan(reviewed_at)
    store, experiment = _store_tenant_defense_history(
        tmp_path,
        plan=reviewed_plan,
        expires_at=review_expires_at,
        applied=False,
    )
    alternate_plan = _defense_plan(
        reviewed_at,
        operation_id="tenant-defense-" + "e" * 32,
    )
    assert alternate_plan["before"] == reviewed_plan["before"]
    assert alternate_plan["after"] == reviewed_plan["after"]
    assert alternate_plan != reviewed_plan
    assert experiment.defense_change is not None
    jobs: EngineControllerJobs = _controller_jobs(_ControllerRepository(experiment))
    request = jobs.prepare_defense_operation(
        experiment_id=experiment.experiment_id,
        change_id=experiment.defense_change.change_id,
        operation=DefenseOperation.APPLY,
    )

    with pytest.raises(ProductStoreError, match="retained review plan"):
        store.create_engine_action_preparation(
            experiment_id=experiment.experiment_id,
            experiment_revision=experiment.revision,
            experiment_digest=experiment.digest,
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.APPLY_DEFENSE,
            limits=_controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=lambda approval, submission: (
                request,
                _material_authority("tenant_defense_plan", alternate_plan),
            ),
        )
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_action_preparations "
                "WHERE action_kind != 'review_defense'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    ("action", "operation", "applied"),
    [
        (
            EngineWorkspaceAction.RECONCILE_DEFENSE,
            DefenseOperation.RECONCILE_APPLICATION,
            False,
        ),
        (
            EngineWorkspaceAction.RECONCILE_ROLLBACK,
            DefenseOperation.RECONCILE_ROLLBACK,
            True,
        ),
    ],
)
def test_reconciliation_preparation_fails_closed_without_terminal_origin_proof(
    action: EngineWorkspaceAction,
    operation: DefenseOperation,
    applied: bool,
    tmp_path: Path,
) -> None:
    prepared_at, expires_at, _ = _times()
    reviewed_at, review_expires_at, _ = _times(offset=-10)
    plan = _defense_plan(reviewed_at)
    store, experiment = _store_tenant_defense_history(
        tmp_path,
        plan=plan,
        expires_at=review_expires_at,
        applied=applied,
    )
    assert experiment.defense_change is not None
    change_id = experiment.defense_change.change_id
    if operation is DefenseOperation.RECONCILE_APPLICATION:
        experiment = experiment.begin_defense_application(
            change_id,
            operation_receipt_digest="sha256:" + "1" * 64,
            started_at=prepared_at,
        )
    else:
        experiment = experiment.begin_defense_rollback(
            change_id,
            rollback_operation_digest="sha256:" + "2" * 64,
            rollback_started_at=prepared_at,
        )
    previous = store.get_engine_experiment(experiment.experiment_id)
    store.save_engine_experiment(
        experiment.experiment_id,
        experiment.to_dict(),
        expected_revision=previous["revision"],
        expected_digest=previous["digest"],
        validator=_validator,
    )
    jobs: EngineControllerJobs = _controller_jobs(_ControllerRepository(experiment))
    request = jobs.prepare_defense_operation(
        experiment_id=experiment.experiment_id,
        change_id=change_id,
        operation=operation,
        originating_job_id="job-" + "9" * 32,
    )
    authority = _material_authority("tenant_defense_plan", plan)
    before = store.get_engine_experiment(experiment.experiment_id)

    with pytest.raises(ProductStoreError, match="requires its terminal origin job"):
        store.create_engine_action_preparation(
            experiment_id=experiment.experiment_id,
            experiment_revision=experiment.revision,
            experiment_digest=experiment.digest,
            workspace_digest=WORKSPACE_REF,
            action=action,
            limits=_controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=lambda approval, submission: (request, authority),
        )

    assert store.get_engine_experiment(experiment.experiment_id) == before
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_action_preparations "
                "WHERE action_kind != 'review_defense'"
            ).fetchone()[0]
            == 0
        )
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0] == 0


def _prepared_controller_check_material(
    experiment: EngineExperiment,
    mechanism: TenantFailureMechanism,
    *,
    reserved_at: str,
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    jobs = EngineControllerJobs(
        controller=cast(Any, _ControllerJobController()),
        repository=_ControllerRepository(experiment),
        defense_executor=None,
        check_executor=None,
        clock=lambda: reserved_at,
    )
    target_snapshot_ref = experiment.current_target_snapshot_ref
    assert target_snapshot_ref is not None
    request = jobs.prepare_controller_check(
        experiment_id=experiment.experiment_id,
        check_id="controller-check-" + "c" * 32,
        run_id="run-20261104T120800Z-" + "b" * 16,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=content_hash(mechanism.to_dict()),
        target_snapshot_ref=target_snapshot_ref,
        input_digest="sha256:" + "8" * 64,
        reserved_at=reserved_at,
    )
    authority = {
        "schema_version": "bluefire.tenant-controller-check-authority.v1",
        "mechanism": mechanism.to_dict(),
        "check_id": request["check_id"],
        "run_id": request["run_id"],
        "role": request["role"],
        "input_digest": request["input_digest"],
        "reserved_at": request["reserved_at"],
    }
    return request, _material_authority("tenant_controller_check", authority)


def test_controller_check_preparation_accepts_exact_trusted_builder_output(
    tmp_path: Path,
) -> None:
    experiment, mechanism = _applied_tenant_mechanism_experiment()
    store = _store_experiment(tmp_path, experiment)
    prepared_at, expires_at, _ = _times()
    request, authority = _prepared_controller_check_material(
        experiment, mechanism, reserved_at=prepared_at
    )

    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REPEAT_MECHANISM,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda approval, submission: (request, authority),
    )

    assert protected["approval_request_id"] is None
    assert protected["protected_request"]["job_request"] == request
    assert protected["intent_digest"] == content_hash(request)
    public = store.prepared_engine_action(protected["request_ref"])
    assert public["action_kind"] == "repeat_mechanism"
    assert public["effects_started_at_preparation"] is False


@pytest.mark.parametrize("tamper", ["performer", "protected_input", "reservation_time"])
def test_controller_check_preparation_rejects_builder_or_typed_input_tampering(
    tamper: str,
    tmp_path: Path,
) -> None:
    experiment, mechanism = _applied_tenant_mechanism_experiment()
    store = _store_experiment(tmp_path, experiment)
    prepared_at, expires_at, _ = _times()
    request, authority = _prepared_controller_check_material(
        experiment, mechanism, reserved_at=prepared_at
    )
    request = dict(request)
    authority = dict(authority)
    if tamper == "performer":
        request["performer"] = "trusted_client"
    elif tamper == "protected_input":
        document = dict(authority["document"])
        document["input_digest"] = "sha256:" + "9" * 64
        authority["document"] = document
        authority["document_digest"] = content_hash(document)
    else:
        request["reserved_at"] = expires_at
        document = dict(authority["document"])
        document["reserved_at"] = expires_at
        authority["document"] = document
        authority["document_digest"] = content_hash(document)

    with pytest.raises(ProductStoreError):
        store.create_engine_action_preparation(
            experiment_id=experiment.experiment_id,
            experiment_revision=experiment.revision,
            experiment_digest=experiment.digest,
            workspace_digest=WORKSPACE_REF,
            action=EngineWorkspaceAction.REPEAT_MECHANISM,
            limits=_controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=lambda approval, submission: (request, authority),
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_action_preparations").fetchone()[0] == 0
        )


@pytest.mark.parametrize(
    ("action", "approval"),
    [
        (EngineWorkspaceAction.START_BASELINE, None),
        (EngineWorkspaceAction.REVIEW_DEFENSE, "unexpected"),
    ],
)
def test_action_kind_rejects_wrong_approval_contract(
    action: EngineWorkspaceAction,
    approval: str | None,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    history = store.get_engine_experiment(EXPERIMENT_ID)
    attempt_factory, valid_approval = _attempt_factory(store, prepared_at, expires_at, [])
    approval_request = None if approval is None else valid_approval

    with pytest.raises(ProductStoreError, match="approval requirement changed"):
        store.create_engine_action_preparation(
            experiment_id=EXPERIMENT_ID,
            experiment_revision=history["revision"],
            experiment_digest=history["digest"],
            workspace_digest=WORKSPACE_REF,
            action=action,
            limits=_limits()
            if action is EngineWorkspaceAction.START_BASELINE
            else _controller_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
            protected_factory=attempt_factory,
            approval_request=approval_request,
        )


def test_public_contract_rejects_incomplete_attempt_limits() -> None:
    prepared_at, expires_at, _ = _times()
    with pytest.raises(ValueError, match="attempt is incomplete"):
        PreparedEngineAction.create(
            protected_request_ref="sha256:" + "1" * 64,
            experiment_id=EXPERIMENT_ID,
            revision=1,
            experiment_digest="sha256:" + "2" * 64,
            workspace_digest=WORKSPACE_REF,
            action_kind=EngineWorkspaceAction.START_BASELINE,
            preparation_kind=EnginePreparedActionKind.ENGINE_ATTEMPT,
            effect_kind=engine_action_contract(EngineWorkspaceAction.START_BASELINE)[1],
            effect_summary=engine_action_contract(EngineWorkspaceAction.START_BASELINE)[2],
            changes_target=False,
            uses_external_engine=True,
            requires_approval=True,
            approval_state=EnginePreparedApprovalState.PENDING,
            approval_review_binding_digest="sha256:" + "3" * 64,
            approval_expires_at=expires_at,
            submission_id="11111111-1111-4111-8111-111111111111",
            intent_digest="sha256:" + "4" * 64,
            limits=PreparedEngineActionLimits(
                wall_clock_seconds=300,
                action_limit=20,
                artifact_byte_limit=4 * 1024 * 1024,
                cost_limit_microunits=1_000_000,
                target_scope_digest=None,
                maximum_tier=None,
            ),
            prepared_at=prepared_at,
            expires_at=expires_at,
        )


def test_public_contract_rejects_controller_engine_limits_and_mismatched_approval_expiry() -> None:
    prepared_at, expires_at, _ = _times()
    with pytest.raises(ValueError, match="controller action claimed engine authority"):
        PreparedEngineAction.create(
            protected_request_ref="sha256:" + "1" * 64,
            experiment_id=EXPERIMENT_ID,
            revision=1,
            experiment_digest="sha256:" + "2" * 64,
            workspace_digest=WORKSPACE_REF,
            action_kind=EngineWorkspaceAction.REVIEW_DEFENSE,
            preparation_kind=EnginePreparedActionKind.CONTROLLER_TRANSITION,
            effect_kind=engine_action_contract(EngineWorkspaceAction.REVIEW_DEFENSE)[1],
            effect_summary=engine_action_contract(EngineWorkspaceAction.REVIEW_DEFENSE)[2],
            changes_target=False,
            uses_external_engine=False,
            requires_approval=False,
            approval_state=EnginePreparedApprovalState.NOT_REQUIRED,
            approval_review_binding_digest=None,
            approval_expires_at=None,
            submission_id=None,
            intent_digest=None,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
        )
    with pytest.raises(ValueError, match="approval expiry changed"):
        PreparedEngineAction.create(
            protected_request_ref="sha256:" + "1" * 64,
            experiment_id=EXPERIMENT_ID,
            revision=1,
            experiment_digest="sha256:" + "2" * 64,
            workspace_digest=WORKSPACE_REF,
            action_kind=EngineWorkspaceAction.START_BASELINE,
            preparation_kind=EnginePreparedActionKind.ENGINE_ATTEMPT,
            effect_kind=engine_action_contract(EngineWorkspaceAction.START_BASELINE)[1],
            effect_summary=engine_action_contract(EngineWorkspaceAction.START_BASELINE)[2],
            changes_target=False,
            uses_external_engine=True,
            requires_approval=True,
            approval_state=EnginePreparedApprovalState.PENDING,
            approval_review_binding_digest="sha256:" + "3" * 64,
            approval_expires_at=prepared_at,
            submission_id="11111111-1111-4111-8111-111111111111",
            intent_digest="sha256:" + "4" * 64,
            limits=_limits(),
            prepared_at=prepared_at,
            expires_at=expires_at,
        )
