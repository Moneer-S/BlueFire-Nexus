from __future__ import annotations

import json
from dataclasses import asdict, fields, replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire.accepted_engine_jobs import AcceptedPreparedEngineAttempt
from bluefire.engine_attempt_contract import AttemptState, EngineAttemptRecord
from bluefire.engine_container_custody import ContainerCustodyPlanV2
from bluefire.engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
    INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
    InstalledControlledStrixRuntimeIdentity,
)
from bluefire.engine_installed_cleanup import (
    InstalledEngineBundleCleanupReceipt,
    InstalledEngineResourceCleanupOutcome,
)
from bluefire.engine_installed_v2_authority import (
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthorityGuard,
)
from bluefire.engine_installed_v2_product_store import (
    ProductStoreInstalledStrixV2ResourceFactory,
    installed_strix_v2_prelaunch_binding_ref,
)
from bluefire.engine_installed_v2_resources import InstalledStrixV2ResourceReceipt
from bluefire.engine_network_policy import EngineNetworkPlanV2
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.product_store_strix_v2_authority import (
    ProductStoreInstalledStrixV2AuthoritySource,
    QualifiedInstalledStrixV2Activation,
)
from bluefire.product_store_strix_v2_resources import (
    ProductStoreInstalledStrixV2TransactionRepository,
)
from bluefire.strix_controlled_runtime_admission import (
    StrixControlledRuntimeAdmissionV2,
    build_controlled_launch_plan,
)
from bluefire.strix_v2_role_terminal_observer import (
    InstalledStrixV2ProtectedRoleTerminalObserver,
    StrixV2ProtectedRoleEvidence,
)
from bluefire.util import content_hash, parse_iso8601_datetime
from tests_platform import test_product_store_engine_execution_claims as execution
from tests_platform import test_product_store_strix_runtime as old_runtime
from tests_platform.test_strix_controlled_runtime_admission import admission_document


def _time(timestamp, seconds):
    return (
        (parse_iso8601_datetime(timestamp) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


class _ProtectedActivationOwner:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = []

    def reopen_qualified_activation(self, **references):
        self.calls.append(references)
        assert references == {
            "admission_ref": self.evidence.admission.admission_ref,
            "activation_ref": self.evidence.activation.receipt_ref,
        }
        return self.evidence

    def reopen_qualified_prelaunch(self, **references):
        self.calls.append(references)
        assert references == {"admission_ref": self.evidence.admission.admission_ref}
        return self.evidence.admission


def _qualified(admission, accepted):
    plan = build_controlled_launch_plan(
        admission,
        expected_admission_ref=admission.admission_ref,
        expected_execution_claim_ref=accepted.claim_ref,
    )
    raw = admission.to_dict()
    values = {
        field.name: content_hash(field.name)
        for field in fields(InstalledStrixV2ActivationReceipt)
        if field.name not in {"schema_version", "receipt_ref"}
    }
    values.update(
        runtime_resolution_ref=accepted.runtime_resolution_ref,
        admission_ref=admission.admission_ref,
        claim_ref=accepted.claim_ref,
        controlled_profile_ref=raw["execution_identity"]["controlled_runtime_profile"][
            "profile_digest"
        ],
        controlled_launch_digest=plan.launch_digest,
        network_policy_digest=EngineNetworkPlanV2.from_mapping(raw["network_plan"]).policy_digest,
        custody_plan_digest=ContainerCustodyPlanV2.from_mapping(raw["custody_plan"]).plan_digest,
        exec_broker_binding_digest=plan.exec_broker_binding_digest,
        caido_mode="test_protocol_provider",
        caido_test_provider=True,
        caido_terms_acceptance_ref=None,
        caido_entitlement_ref=None,
        caido_live_proof=False,
        model_provider_kind="test",
        model_live_proof=False,
    )
    special_roles = {
        "caido_channel": values["caido_provider_identity_ref"],
        "docker_control": values["exec_broker_binding_digest"],
        "model_gateway": values["model_gateway_lease_ref"],
        "worker_controller": values["worker_launch_digest"],
    }
    values["role_bindings"] = tuple(
        (role, special_roles.get(role, content_hash(role)))
        for role in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
    )
    activation = InstalledStrixV2ActivationReceipt.create(**values)
    identity_values = {
        field.name: getattr(activation, field.name)
        for field in fields(InstalledControlledStrixRuntimeIdentity)
        if hasattr(activation, field.name)
    }
    identity_values.update(
        schema_version=INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
        backend="bluefire-controlled",
        job_id=accepted.job_id,
        preparation_ref=accepted.preparation_ref,
        binding_digest=accepted.binding_digest,
        delegation_digest=accepted.delegation_digest,
        runtime_admission_ref=admission.admission_ref,
        runtime_activation_ref=activation.receipt_ref,
        resource_set_digest=content_hash(
            {
                "schema_version": "bluefire.installed-strix-resource-set.v1",
                "resources": [
                    {"role": role, "binding_ref": reference}
                    for role, reference in values["role_bindings"]
                ],
            }
        ),
    )
    identity_values["launch_digest"] = content_hash(
        {
            **identity_values,
            "schema_version": INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
        }
    )
    return QualifiedInstalledStrixV2Activation(
        admission,
        activation,
        InstalledControlledStrixRuntimeIdentity(**identity_values),
    )


@pytest.fixture
def f(tmp_path, monkeypatch):
    raw = admission_document()
    network = EngineNetworkPlanV2.from_mapping(raw["network_plan"])
    custody = ContainerCustodyPlanV2.from_mapping(raw["custody_plan"])
    original = execution._attempt_authority

    def authority(prepared_at, expires_at):
        binding, delegation, _approval = original(prepared_at, expires_at)
        build = raw["execution_identity"]["startup_build_identity"]
        aligned = {
            "engine_version": build["package_version"],
            "engine_revision": build["source_revision"],
            "engine_package_digest": build["package_sha256"],
            "policy_overlay_digest": build["prompt_overlay_sha256"],
            "model_data_destination": raw["gateway"]["base_url"],
        }
        binding = replace(binding, **aligned)
        delegation = replace(
            delegation,
            **aligned,
            network_policy_digest=network.policy_digest,
            custody_plan_digest=custody.plan_digest,
        )
        return binding, delegation, delegation.approval_binding(binding)

    monkeypatch.setattr(execution, "_attempt_authority", authority)
    store, _protected, _values, binding, delegation, job_id, claimed_at = execution._ready(tmp_path)
    claim = execution._claim(
        store, job_id=job_id, binding=binding, delegation=delegation, claimed_at=claimed_at
    ).document
    accepted = AcceptedPreparedEngineAttempt(
        **{
            name: claim[name]
            for name in (
                "job_id",
                "preparation_ref",
                "binding_digest",
                "delegation_digest",
                "claim_ref",
                "runtime_resolution_ref",
            )
        }
    )
    authority_record = old_runtime.append_authority(store)
    reserve = old_runtime.reservation(store, authority_record, attempt_id=binding.attempt_id)
    reserve.update(
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        target_snapshot_digest=binding.target_snapshot_ref,
        created_at=claimed_at,
        expires_at=delegation.expires_at,
    )
    store._reserve_strix_runtime_admission(reserve)
    envelope = store._read_strix_runtime_admission_envelope(binding.attempt_id)
    preparing = store._append_strix_runtime_admission_event(
        attempt_id=binding.attempt_id,
        state="preparing",
        lifecycle_basis_ref=content_hash("preparing"),
        recorded_at=_time(claimed_at, 1),
        expected_head_digest=envelope["lifecycle_head_digest"],
    )
    legacy = old_runtime.admission(store, authority_record, attempt_id=binding.attempt_id)
    legacy.update(
        {
            name: value
            for name, value in reserve.items()
            if name in legacy and name != "schema_version"
        }
    )
    store._retain_verified_strix_runtime_admission(
        document=legacy,
        lifecycle_basis_ref=content_hash("verified"),
        recorded_at=_time(claimed_at, 2),
        expected_head_digest=preparing["event_digest"],
    )
    raw.update(
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        accepted_execution_claim=dict(claim),
        accepted_execution_claim_ref=accepted.claim_ref,
    )
    raw["scope"].update(
        target_snapshot_digest=binding.target_snapshot_ref, scope_digest=binding.scope_ref
    )
    raw["gateway"].update(
        model=binding.model_id, authorization_digest=binding.model_authorization_ref
    )
    evidence = _qualified(StrixControlledRuntimeAdmissionV2.from_mapping(raw), accepted)
    owner = _ProtectedActivationOwner(evidence)
    now = [_time(claimed_at, 3)]
    source = ProductStoreInstalledStrixV2AuthoritySource(
        product_store=store, activations=owner, clock=lambda: now[0]
    )
    return SimpleNamespace(
        store=store,
        binding=binding,
        delegation=delegation,
        accepted=accepted,
        source=source,
        owner=owner,
        evidence=evidence,
        now=now,
    )


def _retain(f):
    prelaunch = _prelaunch(f)
    _prepare_resource_intent(f, prelaunch)
    return f.source.retain_activation(
        product_store=f.store,
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
        prelaunch_ref=prelaunch.prelaunch_ref,
        admission_ref=f.evidence.admission.admission_ref,
        activation_ref=f.evidence.activation.receipt_ref,
        resource_transaction_ref=f.transaction_ref,
        observed_identity_ref=content_hash(asdict(f.evidence.identity)),
    )


def _prepare_resource_intent(f, prelaunch):
    if not hasattr(f, "transaction_ref"):
        repository = ProductStoreInstalledStrixV2TransactionRepository(product_store=f.store)
        guard = InstalledStrixV2AuthorityGuard(
            product_store=f.store,
            source=f.source,
            accepted=f.accepted,
            binding=f.binding,
            delegation=f.delegation,
        )
        assert guard.require_prelaunch_current() == prelaunch
        no_platform = SimpleNamespace(
            begin_execution=lambda **_kwargs: None,
            begin_reconciliation=lambda **_kwargs: None,
        )
        factory = ProductStoreInstalledStrixV2ResourceFactory(
            product_store=f.store,
            repository=repository,
            execution_resources=no_platform,
            reconciliation_resources=no_platform,
        )
        transaction = factory.begin_execution(
            product_store=f.store,
            snapshot=prelaunch,
            launch_plan=prelaunch.validate(
                accepted=f.accepted,
                binding=f.binding,
                delegation=f.delegation,
            ),
            authority_guard=guard,
        )
        f.transaction_ref = transaction.transaction_ref
        repository.append_event(
            transaction_ref=f.transaction_ref,
            expected_generation=1,
            event_type="allocation_started",
            state="allocating",
            document={},
        )


def _prelaunch(f):
    return f.source.retain_prelaunch(
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
        admission_ref=f.evidence.admission.admission_ref,
    )


def _current(f, **changes):
    values = dict(
        product_store=f.store,
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
        expected_resolution_ref=f.accepted.runtime_resolution_ref,
    )
    values.update(changes)
    return f.source.require_current(**values)


def test_retain_current_restart_and_test_identity(f):
    snapshot = _retain(f)
    assert _retain(f) == snapshot
    assert _current(f) == snapshot
    reopened = ProductStore(f.store.path)
    source = ProductStoreInstalledStrixV2AuthoritySource(
        product_store=reopened, activations=f.owner, clock=lambda: f.now[0]
    )
    assert (
        source.require_current(
            product_store=reopened,
            accepted=f.accepted,
            binding=f.binding,
            delegation=f.delegation,
            expected_resolution_ref=f.accepted.runtime_resolution_ref,
        )
        == snapshot
    )
    assert snapshot.activation.caido_test_provider is True
    assert snapshot.activation.caido_live_proof is False
    assert snapshot.activation.model_live_proof is False
    assert not any(
        hasattr(source, method) for method in ("launch", "allocate", "execute", "reissue")
    )


def test_prelaunch_can_reopen_without_synthesizing_activation(f):
    prelaunch = _prelaunch(f)
    assert _prelaunch(f) == prelaunch
    assert (
        f.source.require_prelaunch_current(
            product_store=f.store,
            accepted=f.accepted,
            binding=f.binding,
            delegation=f.delegation,
            expected_resolution_ref=f.accepted.runtime_resolution_ref,
        )
        == prelaunch
    )
    with f.store._connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM strix_composition_authority_records"
            ).fetchone()[0]
            == 0
        )


def test_resource_journal_refuses_caller_authored_absence(f):
    _retain(f)
    repository = ProductStoreInstalledStrixV2TransactionRepository(product_store=f.store)
    head = repository.load_transaction(f.transaction_ref)
    assert head.state == "allocating"
    with pytest.raises(ProductStoreError, match="protected observation owner"):
        repository.append_event(
            transaction_ref=f.transaction_ref,
            expected_generation=head.generation,
            event_type="absence_observed",
            state="stopping",
            document={"state": "absent", "observation_ref": content_hash("fabricated")},
            receipt_ref=content_hash("fabricated"),
        )
    with pytest.raises(ResourceConflictError, match="unavailable"):
        repository.record_absence(
            transaction_ref=f.transaction_ref,
            expected_generation=head.generation,
            document={"observation_ref": content_hash("fabricated")},
        )
    assert repository.load_transaction(f.transaction_ref) == head


def test_activated_authority_does_not_imply_committed_resources(f):
    _retain(f)
    assert _current(f).activation.receipt_ref == f.evidence.activation.receipt_ref
    with pytest.raises(ResourceConflictError, match="durably active"):
        f.source.require_active(
            product_store=f.store,
            accepted=f.accepted,
            binding=f.binding,
            delegation=f.delegation,
            expected_resolution_ref=f.accepted.runtime_resolution_ref,
        )


@pytest.mark.parametrize("field", ["claim_ref", "runtime_resolution_ref", "preparation_ref"])
def test_swapped_accepted_claim_refuses(f, field):
    _retain(f)
    with pytest.raises((ProductStoreError, ValueError, RuntimeError)):
        _current(f, accepted=replace(f.accepted, **{field: content_hash("swapped")}))


@pytest.mark.parametrize(
    "field", ["scope_ref", "target_snapshot_ref", "objective_ref", "environment_ref"]
)
def test_swapped_scope_target_and_objective_refuse(f, field):
    _retain(f)
    with pytest.raises((ProductStoreError, ValueError, RuntimeError)):
        _current(f, binding=replace(f.binding, **{field: content_hash("swapped")}))


def test_missing_activation_and_other_store_refuse_before_import(f):
    with pytest.raises(ProductStoreError):
        _current(f)
    with pytest.raises(ProductStoreError):
        _current(f, product_store=ProductStore(f.store.path))
    assert not f.owner.calls


@pytest.mark.parametrize("mutation", ["expired", "cancelled", "lifecycle", "revoked"])
def test_currentness_changes_fail_closed(f, mutation):
    _retain(f)
    if mutation == "expired":
        f.now[0] = f.delegation.expires_at
    elif mutation == "cancelled":
        f.store.transition_job(f.accepted.job_id, "cancelling")
    elif mutation == "lifecycle":
        envelope = f.store._read_strix_runtime_admission_envelope(f.binding.attempt_id)
        f.store._append_strix_runtime_admission_event(
            attempt_id=f.binding.attempt_id,
            state="unknown",
            lifecycle_basis_ref=content_hash("unknown"),
            recorded_at=f.now[0],
            expected_head_digest=envelope["lifecycle_head_digest"],
        )
    else:
        head = f.store._read_current_strix_runtime_authority(old_runtime.AUTHORITY_REF)
        f.store._append_strix_runtime_authority(
            authority_ref=old_runtime.AUTHORITY_REF,
            authority=old_runtime.authority(2, state="revoked", recorded_at=f.now[0]),
            authority_basis_ref=content_hash("revoke"),
            expected_previous_event_digest=head["event_digest"],
        )
    with pytest.raises(ProductStoreError):
        _current(f)


@pytest.mark.parametrize("mutation", ["extra", "missing", "future", "activation", "admission"])
def test_damaged_or_future_durable_codecs_refuse_even_with_recomputed_hash(f, mutation):
    _retain(f)
    with f.store._connection(write=True) as connection:
        row = connection.execute("SELECT * FROM strix_composition_authority_records").fetchone()
        document = json.loads(row["document_json"])
        if mutation == "extra":
            document["future"] = True
        elif mutation == "missing":
            document.pop("anchors")
        elif mutation == "future":
            document["schema_version"] += ".future"
        elif mutation == "activation":
            document["activation"]["claim_ref"] = content_hash("swapped")
        else:
            document["admission"]["accepted_execution_claim_ref"] = content_hash("swapped")
        connection.execute("DROP TRIGGER strix_composition_authority_records_no_update")
        connection.execute(
            "UPDATE strix_composition_authority_records SET document_json=?,document_digest=?",
            (canonical_json(document), content_hash(document)),
        )
    with pytest.raises((ProductStoreError, RuntimeError, ValueError)):
        _current(f)


def _terminal_intent(f):
    f.store.transition_job(f.accepted.job_id, "failed")
    active = f.store.get_engine_experiment(f.binding.experiment_id)
    record = EngineAttemptRecord.from_mapping(active["document"]["attempts"][0]["record"])
    with f.store.engine_attempt_reconciliation_session() as capability:
        recovery = f.store.begin_or_reopen_engine_attempt_reconciliation(
            binding=f.binding.to_dict(),
            delegation=f.delegation.to_dict(),
            reviewer=execution.REVIEWER,
            created_at=_time(f.now[0], 2),
            saved_record=record.to_dict(),
            expected_revision=active["revision"],
            expected_experiment_digest=active["digest"],
            reconciliation_capability=capability,
        )
    return record, recovery.reconciliation_document["reconciliation_ref"]


def test_preactivation_recovery_reopens_only_owned_cleanup_locators(f):
    prelaunch = _prelaunch(f)
    _prepare_resource_intent(f, prelaunch)
    record, reconciliation_ref = _terminal_intent(f)
    recovered = f.source.reopen_preactivation_recovery(
        product_store=f.store,
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
        saved_record=record,
        reconciliation_ref=reconciliation_ref,
        transaction_ref=f.transaction_ref,
    )
    assert recovered.prelaunch_ref == prelaunch.prelaunch_ref
    assert recovered.transaction_ref == f.transaction_ref
    assert recovered.state == "allocating"
    assert recovered.observed_activation_ref is None
    assert len(recovered.role_owner_bindings) == 6
    assert not any(
        hasattr(recovered, name) for name in ("launch_plan", "credentials", "allocate", "execute")
    )


def test_historical_reopen_requires_retention_and_exact_saved_record_and_intent(f):
    _retain(f)
    record, reconciliation_ref = _terminal_intent(f)
    values = dict(
        product_store=f.store,
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
        saved_record=record,
        reconciliation_ref=reconciliation_ref,
    )
    with pytest.raises(ProductStoreError):
        f.source.reopen_reconciliation(**values)
    historical = f.source.ensure_historical(**values)
    assert f.source.ensure_historical(**values) == historical
    assert f.source.reopen_reconciliation(**values) == historical
    f.now[0] = f.delegation.expires_at
    assert f.source.reopen_reconciliation(**values) == historical
    for changes in (
        {"reconciliation_ref": content_hash("different-reconciliation")},
        {
            "saved_record": record.transition(
                AttemptState.CANCELLED, timestamp=f.now[0], exit_reason="cancelled"
            )
        },
    ):
        with pytest.raises((ProductStoreError, ValueError, RuntimeError)):
            f.source.reopen_reconciliation(**{**values, **changes})


def _commit_active_bundle(f):
    activated = _retain(f)
    repository = ProductStoreInstalledStrixV2TransactionRepository(product_store=f.store)
    receipt = InstalledStrixV2ResourceReceipt.create(
        action="allocated",
        authority_ref=activated.prelaunch_ref,
        activation_receipt_ref=activated.activation.receipt_ref,
        role_bindings=activated.activation.role_bindings,
        reconciliation_ref=None,
    )
    head = repository.load_transaction(f.transaction_ref)
    head = repository.append_event(
        transaction_ref=f.transaction_ref,
        expected_generation=head.generation,
        event_type="activation_recorded",
        state="allocating",
        document={
            "activation_ref": activated.activation.receipt_ref,
            "identity_ref": content_hash(asdict(f.evidence.identity)),
            "resource_receipt_ref": receipt.receipt_ref,
        },
        receipt_ref=activated.activation.receipt_ref,
    )
    for role, actual_ref in activated.activation.role_bindings:
        binding_ref = installed_strix_v2_prelaunch_binding_ref(
            prelaunch_ref=activated.prelaunch_ref, role=role
        )
        owner = {
            "role": role,
            "binding_ref": binding_ref,
            "owner_ref": content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
                    "transaction_ref": f.transaction_ref,
                    "role": role,
                    "binding_ref": binding_ref,
                }
            ),
        }
        head = repository.append_event(
            transaction_ref=f.transaction_ref,
            expected_generation=head.generation,
            event_type="role_allocated",
            state="allocating",
            document={
                "resource_receipt_ref": receipt.receipt_ref,
                "actual_binding_ref": actual_ref,
            },
            role=role,
            owner_ref=owner["owner_ref"],
            binding_ref=binding_ref,
            receipt_ref=content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-role-allocation.v1",
                    "transaction_ref": f.transaction_ref,
                    **owner,
                    "resource_receipt_ref": receipt.receipt_ref,
                    "actual_binding_ref": actual_ref,
                }
            ),
        )
    head = repository.append_event(
        transaction_ref=f.transaction_ref,
        expected_generation=head.generation,
        event_type="allocated",
        state="allocated",
        document=receipt.document(),
        receipt_ref=receipt.receipt_ref,
    )
    for event_type, state in (("commit_started", "committing"), ("committed", "active")):
        head = repository.append_event(
            transaction_ref=f.transaction_ref,
            expected_generation=head.generation,
            event_type=event_type,
            state=state,
            document={},
        )
    assert head.state == "active"
    with f.store._connection() as connection:
        latest = connection.execute(
            "SELECT updated_at FROM strix_composition_resource_transactions WHERE transaction_ref=?",
            (f.transaction_ref,),
        ).fetchone()["updated_at"]
    f.now[0] = _time(latest, 1)
    return repository.load_settlement(f.transaction_ref)


class _RoleTerminalObserver:
    def __init__(self):
        self.rows = {}

    def role_identity_ref(self, role):
        return content_hash(("role-terminal-owner", role))

    def reopen_role_terminal(self, *, role, source_receipt_ref):
        return self.rows[(role, source_receipt_ref)]


class _WholeAbsenceObserver:
    observer_identity_ref = content_hash("whole-set-observer")
    observer_generation = 1

    def __init__(self):
        self.rows = {}

    def reopen_absence(self, *, observation_ref):
        return self.rows[observation_ref]


def _settlement_repository(f):
    roles = _RoleTerminalObserver()
    absence = _WholeAbsenceObserver()
    return (
        ProductStoreInstalledStrixV2TransactionRepository(
            product_store=f.store,
            clock=lambda: f.now[0],
            role_terminal_observer=roles,
            absence_observer=absence,
        ),
        roles,
        absence,
    )


def _role_terminal(f, repository, observer, snapshot, role):
    repository.claim_role_stop(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        role=role,
    )
    snapshot = repository.load_settlement(snapshot.transaction_ref)
    owner = next(row for row in snapshot.role_owner_bindings if row[0] == role)
    actual_ref = dict(snapshot.actual_role_bindings)[role]
    source_ref = content_hash(("source-receipt", role))
    document = {
        "schema_version": "bluefire.installed-strix-v2-role-terminal-observation.v1",
        "transaction_ref": snapshot.transaction_ref,
        "attempt_id": snapshot.attempt_id,
        "authority_ref": snapshot.authority_ref,
        "claim_ref": snapshot.claim_ref,
        "runtime_activation_ref": snapshot.runtime_activation_ref,
        "role": role,
        "prelaunch_binding_ref": owner[1],
        "resource_ref": actual_ref,
        "owner_ref": owner[2],
        "state": "verified_absent",
        "evidence_ref": content_hash(("independent-absence", role)),
        "source_receipt_ref": source_ref,
        "source_identity_ref": observer.role_identity_ref(role),
        "observed_at": f.now[0],
    }
    document["observation_ref"] = content_hash(document)
    observer.rows[(role, source_ref)] = document
    repository.record_role_terminal(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        role=role,
        receipt=SimpleNamespace(receipt_ref=source_ref),
    )
    return repository.load_settlement(snapshot.transaction_ref)


def _whole_absence(f, repository, observer, snapshot):
    document = {
        "schema_version": "bluefire.installed-strix-v2-bundle-absence.v1",
        "transaction_ref": snapshot.transaction_ref,
        "attempt_id": snapshot.attempt_id,
        "authority_ref": snapshot.authority_ref,
        "claim_ref": snapshot.claim_ref,
        "runtime_activation_ref": snapshot.runtime_activation_ref,
        "resource_set_ref": snapshot.resource_set_ref,
        "owner_ref": snapshot.owner_ref,
        "role_bindings": [
            {
                "role": role,
                "binding_ref": prelaunch_ref,
                "owner_ref": owner_ref,
                "resource_ref": dict(snapshot.actual_role_bindings)[role],
            }
            for role, prelaunch_ref, owner_ref in snapshot.role_owner_bindings
        ],
        "state": "absent",
        "observer_identity_ref": observer.observer_identity_ref,
        "observer_generation": observer.observer_generation,
        "observed_at": f.now[0],
    }
    document["observation_ref"] = content_hash(document)
    observer.rows[document["observation_ref"]] = document
    repository.record_absence(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        document=document,
    )
    return repository.load_settlement(snapshot.transaction_ref)


def _bundle_receipt(f, snapshot, *, state, generation=1, predecessor=None):
    outcomes = tuple(
        outcome
        if outcome is not None
        else InstalledEngineResourceCleanupOutcome(
            role=role,
            resource_ref=resource_ref,
            state="unknown",
            evidence_ref=None,
        )
        for (role, resource_ref), outcome in zip(
            reversed(snapshot.actual_role_bindings), reversed(snapshot.role_outcomes), strict=True
        )
    )
    return InstalledEngineBundleCleanupReceipt.create(
        cleanup_ref=snapshot.cleanup_ref,
        attempt_ref=snapshot.attempt_ref,
        activation_ref=snapshot.claim_ref,
        owner_ref=snapshot.owner_ref,
        runtime_resolution_ref=snapshot.runtime_resolution_ref,
        resource_set_ref=snapshot.resource_set_ref,
        generation=generation,
        predecessor_receipt_ref=predecessor,
        state=state,
        outcomes=outcomes,
        settled_at=f.now[0],
    )


def test_postcommit_settlement_needs_protected_roles_and_whole_absence(f):
    active = _commit_active_bundle(f)
    assert active.claim_ref == f.accepted.claim_ref
    assert active.runtime_activation_ref == f.evidence.activation.receipt_ref
    assert active.claim_ref != active.runtime_activation_ref
    lineage = f.source.reopen_execution_lineage(
        product_store=f.store,
        attempt_id=f.binding.attempt_id,
        resource_transaction_ref=active.transaction_ref,
    )
    assert lineage.claim_ref == active.claim_ref
    assert lineage.runtime_activation_ref == active.runtime_activation_ref
    assert lineage.engine_revision == f.binding.engine_revision
    assert lineage.actual_role_bindings == active.actual_role_bindings
    repository, roles, absence = _settlement_repository(f)
    guard = InstalledStrixV2AuthorityGuard(
        product_store=f.store,
        source=f.source,
        accepted=f.accepted,
        binding=f.binding,
        delegation=f.delegation,
    )
    guard.require_prelaunch_current()
    guard.require_current()
    with repository.hold_active_execution(
        transaction_ref=active.transaction_ref,
        claim_ref=active.claim_ref,
        controller_fence=f.evidence.activation.controller_fence,
        authority_guard=guard,
    ) as activation:
        assert activation.receipt_ref == active.runtime_activation_ref
        with repository.hold_active_execution(
            transaction_ref=active.transaction_ref,
            claim_ref=active.claim_ref,
            controller_fence=f.evidence.activation.controller_fence,
            authority_guard=guard,
        ):
            assert repository.load_settlement(active.transaction_ref).state == "active"
    with pytest.raises(ResourceConflictError):
        repository.retain_bundle_receipt(
            transaction_ref=active.transaction_ref,
            expected_generation=active.generation,
            receipt=_bundle_receipt(f, active, state="unknown"),
        )
    head = repository.begin_settlement(
        transaction_ref=active.transaction_ref,
        expected_generation=active.generation,
        cleanup_ref=active.cleanup_ref,
    )
    assert head.state == "stopping"
    previous_time = f.now[0]
    f.now[0] = _time(previous_time, -2)
    backdated = _bundle_receipt(
        f, repository.load_settlement(active.transaction_ref), state="unknown"
    )
    f.now[0] = previous_time
    with pytest.raises(ProductStoreError, match="chronology"):
        repository.retain_bundle_receipt(
            transaction_ref=active.transaction_ref,
            expected_generation=head.generation,
            receipt=backdated,
        )
    with pytest.raises(ResourceConflictError):
        with repository.hold_active_execution(
            transaction_ref=active.transaction_ref,
            claim_ref=active.claim_ref,
            controller_fence=f.evidence.activation.controller_fence,
            authority_guard=guard,
        ):
            pass
    with pytest.raises(ResourceConflictError):
        repository.begin_settlement(
            transaction_ref=active.transaction_ref,
            expected_generation=active.generation,
            cleanup_ref=active.cleanup_ref,
        )
    snapshot = repository.load_settlement(active.transaction_ref)
    for role, _actual_ref in reversed(snapshot.actual_role_bindings):
        snapshot = _role_terminal(f, repository, roles, snapshot, role)
    assert all(outcome is not None for outcome in snapshot.role_outcomes)
    with pytest.raises(ResourceConflictError):
        repository.retain_bundle_receipt(
            transaction_ref=snapshot.transaction_ref,
            expected_generation=snapshot.generation,
            receipt=_bundle_receipt(f, snapshot, state="verified_absent"),
        )
    snapshot = _whole_absence(f, repository, absence, snapshot)
    receipt = _bundle_receipt(f, snapshot, state="verified_absent")
    repository.retain_bundle_receipt(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        receipt=receipt,
    )
    closed = repository.load_settlement(snapshot.transaction_ref)
    assert closed.state == "closed"
    assert closed.whole_absence_ref is not None
    assert closed.retained_receipt == receipt
    assert (
        f.source.reopen_execution_lineage(
            product_store=f.store,
            attempt_id=f.binding.attempt_id,
            resource_transaction_ref=active.transaction_ref,
        ).resource_state
        == "closed"
    )
    role = closed.role_owner_bindings[0][0]
    source_ref = content_hash(("source-receipt", role))
    saved = roles.rows[(role, source_ref)]
    roles.rows[(role, source_ref)] = {**saved, "evidence_ref": content_hash("changed")}
    with pytest.raises(ResourceConflictError, match="source changed"):
        repository.load_settlement(closed.transaction_ref)
    roles.rows[(role, source_ref)] = saved
    absence.rows.clear()
    with pytest.raises(ResourceConflictError, match="cannot be reopened"):
        repository.load_settlement(closed.transaction_ref)


def test_postcommit_unknown_receipt_reopens_and_requires_linked_successor(f):
    active = _commit_active_bundle(f)
    repository, roles, absence = _settlement_repository(f)
    repository.begin_settlement(
        transaction_ref=active.transaction_ref,
        expected_generation=active.generation,
        cleanup_ref=active.cleanup_ref,
    )
    snapshot = repository.load_settlement(active.transaction_ref)
    first = _bundle_receipt(f, snapshot, state="unknown")
    repository.retain_bundle_receipt(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        receipt=first,
    )
    restarted = ProductStoreInstalledStrixV2TransactionRepository(
        product_store=f.store,
        clock=lambda: f.now[0],
        role_terminal_observer=roles,
        absence_observer=absence,
    )
    snapshot = restarted.load_settlement(active.transaction_ref)
    assert snapshot.state == "cleanup_unknown"
    assert snapshot.retained_receipt == first
    for role, _actual_ref in reversed(snapshot.actual_role_bindings):
        snapshot = _role_terminal(f, restarted, roles, snapshot, role)
    all_roles_known = _bundle_receipt(
        f,
        snapshot,
        state="unknown",
        generation=2,
        predecessor=first.receipt_ref,
    )
    restarted.retain_bundle_receipt(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        receipt=all_roles_known,
    )
    snapshot = restarted.load_settlement(active.transaction_ref)
    assert snapshot.retained_receipt == all_roles_known
    assert snapshot.whole_absence_ref is None
    snapshot = _whole_absence(f, restarted, absence, snapshot)
    successor = _bundle_receipt(
        f,
        snapshot,
        state="verified_absent",
        generation=3,
        predecessor=all_roles_known.receipt_ref,
    )
    restarted.retain_bundle_receipt(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        receipt=successor,
    )
    assert restarted.load_settlement(active.transaction_ref).retained_receipt == successor


def test_postcommit_role_source_swap_and_caller_events_refuse(f):
    active = _commit_active_bundle(f)
    repository, roles, _absence = _settlement_repository(f)
    repository.begin_settlement(
        transaction_ref=active.transaction_ref,
        expected_generation=active.generation,
        cleanup_ref=active.cleanup_ref,
    )
    snapshot = repository.load_settlement(active.transaction_ref)
    role = snapshot.actual_role_bindings[-1][0]
    repository.claim_role_stop(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        role=role,
    )
    claimed = repository.load_settlement(snapshot.transaction_ref)
    assert claimed.stop_claimed_roles == (role,)
    with pytest.raises(ResourceConflictError):
        repository.claim_role_stop(
            transaction_ref=claimed.transaction_ref,
            expected_generation=claimed.generation,
            role=role,
        )
    snapshot = claimed
    wrong = next(other for other, _ref in snapshot.actual_role_bindings if other != role)
    with pytest.raises(KeyError):
        repository.record_role_terminal(
            transaction_ref=active.transaction_ref,
            expected_generation=snapshot.generation,
            role=role,
            receipt=SimpleNamespace(receipt_ref=content_hash(("source-receipt", wrong))),
        )
    for event_type in (
        "role_terminal",
        "role_stop_claimed",
        "bundle_absence_observed",
        "bundle_receipt_recorded",
    ):
        with pytest.raises(ProductStoreError):
            repository.append_event(
                transaction_ref=active.transaction_ref,
                expected_generation=snapshot.generation,
                event_type=event_type,
                state="stopping",
                document={},
            )
    assert repository.load_settlement(active.transaction_ref).generation == snapshot.generation


def test_composed_role_observer_joins_exact_saved_owner_and_refuses_missing_source(f):
    active = _commit_active_bundle(f)
    role, actual_ref = active.actual_role_bindings[-1]
    source_ref = content_hash("protected-worker-terminal")
    evidence_ref = content_hash("protected-worker-absence")

    class ProtectedFixtureSource:
        source_identity_ref = content_hash("protected-worker-source")

        def __init__(self):
            self.evidence_ref = evidence_ref
            self.state = "verified_revoked"

        def reopen_source(self, receipt_ref, expected):
            assert receipt_ref == source_ref
            assert expected.attempt_id == active.attempt_id
            assert expected.claim_ref == active.claim_ref
            assert expected.runtime_activation_ref == active.runtime_activation_ref
            assert expected.resource_ref == actual_ref
            assert expected.role == role
            return StrixV2ProtectedRoleEvidence(
                source_receipt_ref=receipt_ref,
                evidence_ref=self.evidence_ref,
                state=self.state,
                source_observed_at=None,
            )

    source = ProtectedFixtureSource()
    observer = InstalledStrixV2ProtectedRoleTerminalObserver(
        product_store=f.store,
        transaction_ref=active.transaction_ref,
        sources={role: source},
    )
    repository = ProductStoreInstalledStrixV2TransactionRepository(
        product_store=f.store,
        clock=lambda: f.now[0],
        role_terminal_observer=observer,
    )
    repository.begin_settlement(
        transaction_ref=active.transaction_ref,
        expected_generation=active.generation,
        cleanup_ref=active.cleanup_ref,
    )
    snapshot = repository.load_settlement(active.transaction_ref)
    with pytest.raises(ResourceConflictError, match="source is unavailable"):
        observer.role_identity_ref(active.actual_role_bindings[0][0])
    repository.claim_role_stop(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        role=role,
    )
    snapshot = repository.load_settlement(active.transaction_ref)
    with pytest.raises(ResourceConflictError, match="identity changed"):
        observer.reopen_role_terminal(role=role, source_receipt_ref=source_ref)
    source.state = "verified_absent"
    repository.record_role_terminal(
        transaction_ref=snapshot.transaction_ref,
        expected_generation=snapshot.generation,
        role=role,
        receipt=SimpleNamespace(receipt_ref=source_ref),
    )
    settled = repository.load_settlement(active.transaction_ref)
    assert settled.role_outcomes[-1].evidence_ref == evidence_ref
    source.evidence_ref = content_hash("changed-worker-absence")
    with pytest.raises(ResourceConflictError, match="source changed"):
        repository.load_settlement(active.transaction_ref)
