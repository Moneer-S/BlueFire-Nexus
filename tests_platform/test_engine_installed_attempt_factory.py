"""Concrete installed Strix factory remains closed to legacy runtime wiring."""

from __future__ import annotations

from dataclasses import replace

import pytest

from bluefire.accepted_engine_jobs import AcceptedPreparedEngineAttempt
from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_installed_attempt_factory import (
    INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
    ControllerOwnedInstalledStrixAttemptFactory,
    InstalledAttemptCleanupUncertain,
    InstalledAttemptFactoryError,
    InstalledControlledStrixRuntimeIdentity,
    InstalledStrixExecutionBundle,
    InstalledStrixOwnedResource,
    InstalledStrixReconciliationBundle,
    _resource_set_digest,
)
from bluefire.engine_installed_cleanup import (
    InstalledEngineBundleCleanupReceipt,
    InstalledEngineCleanupResourceBinding,
    InstalledEngineResourceCleanupOutcome,
    resource_set_ref,
)
from bluefire.strix_engine_runtime import StrixEngineRuntime
from bluefire.util import content_hash
from tests_platform.test_engine_experiment_jobs import _authority
from tests_platform.test_engine_installed_composition import (
    CLAIM,
    JOB,
    PREPARATION,
    RESOLUTION,
    _bind,
    _configured,
)


def _sha(character: str) -> str:
    return "sha256:" + character * 64


class _Resource:
    def __init__(self, events: list[tuple[str, str]], name: str) -> None:
        self.events = events
        self.name = name

    def close(self) -> None:
        self.events.append(("close", self.name))


class _FailCloseResource(_Resource):
    def close(self) -> None:
        super().close()
        raise RuntimeError("close failed")


class _CleanupOwner:
    def __init__(self, identity, resources, *, initial_unknown=False):
        self.attempt_ref = identity.binding_digest
        self.activation_ref = identity.claim_ref
        self.runtime_activation_ref = identity.runtime_activation_ref
        self.owner_ref = _sha("e")
        self.runtime_resolution_ref = identity.runtime_resolution_ref
        self.resource_manifest = tuple(
            InstalledEngineCleanupResourceBinding(row.role, row.binding_ref) for row in resources
        )
        self.resource_set_ref = resource_set_ref(self.resource_manifest)
        self.settle_calls = []
        self.reconcile_calls = []
        self.initial_unknown = initial_unknown

    def _receipt(self, *, cleanup_ref, generation, predecessor, unknown):
        return InstalledEngineBundleCleanupReceipt.create(
            cleanup_ref=cleanup_ref,
            attempt_ref=self.attempt_ref,
            activation_ref=self.activation_ref,
            owner_ref=self.owner_ref,
            runtime_resolution_ref=self.runtime_resolution_ref,
            resource_set_ref=self.resource_set_ref,
            generation=generation,
            predecessor_receipt_ref=predecessor,
            state="unknown" if unknown else "verified_absent",
            outcomes=tuple(
                InstalledEngineResourceCleanupOutcome(
                    role=row.role,
                    resource_ref=row.resource_ref,
                    state="unknown" if unknown else "verified_absent",
                    evidence_ref=None if unknown else _sha("a"),
                )
                for row in reversed(self.resource_manifest)
            ),
            settled_at="2026-11-13T00:00:00Z",
        )

    def settle(self, *, cleanup_ref):
        self.settle_calls.append(cleanup_ref)
        return self._receipt(
            cleanup_ref=cleanup_ref,
            generation=1,
            predecessor=None,
            unknown=self.initial_unknown,
        )

    def reconcile(self, *, receipt):
        self.reconcile_calls.append(receipt.receipt_ref)
        return self._receipt(
            cleanup_ref=receipt.cleanup_ref,
            generation=receipt.generation + 1,
            predecessor=receipt.receipt_ref,
            unknown=False,
        )


class _Runtime:
    def __init__(self, identity: InstalledControlledStrixRuntimeIdentity | None) -> None:
        self.installed_runtime_identity = identity

    def execute(self, *_args, **_values):
        raise AssertionError("factory construction must not execute")

    def reconcile(self, *_args, **_values):
        raise AssertionError("factory construction must not reconcile")

    def reconcile_claimed(self, *_args, **_values):
        raise AssertionError("factory construction must not reconcile")


class _ReconciliationRuntime:
    installed_execution_disabled = True

    def __init__(self, identity: InstalledControlledStrixRuntimeIdentity | None) -> None:
        self.installed_runtime_identity = identity

    def reconcile(self, *_args, **_values):
        raise AssertionError("factory construction must not reconcile")

    def reconcile_claimed(self, *_args, **_values):
        raise AssertionError("factory construction must not reconcile")


class _Resolver:
    def __init__(self, *, fail_after: int | None = None) -> None:
        self.calls = 0
        self.fail_after = fail_after
        self.resolution = type("Resolution", (), {"resolution_ref": RESOLUTION})()

    def require_current(self, *_args, **values):
        self.calls += 1
        assert values["expected_resolution_ref"] == RESOLUTION
        if self.fail_after is not None and self.calls > self.fail_after:
            raise RuntimeError("authority changed")
        return self.resolution


class _Openers:
    def __init__(self) -> None:
        self.execution = None
        self.reconciliation = None
        self.execution_calls = []
        self.reconciliation_calls = []

    def open_execution(self, **values):
        self.execution_calls.append(values)
        return self.execution

    def reopen_reconciliation(self, **values):
        self.reconciliation_calls.append(values)
        return self.reconciliation


def _resources(events: list[tuple[str, str]], *, shared: bool = False):
    common = _Resource(events, "shared") if shared else None
    result = []
    for index, role in enumerate(
        (
            "caido_channel",
            "docker_control",
            "model_gateway",
            "source_collection",
            "target_relay",
            "worker_controller",
        )
    ):
        owner = common if common is not None else _Resource(events, role)
        result.append(InstalledStrixOwnedResource(role, _sha(str(index + 1)), owner))
    return tuple(result)


def _reconciliation_resources(events: list[tuple[str, str]]):
    return tuple(
        InstalledStrixOwnedResource(role, _sha(str(index + 1)), _Resource(events, role))
        for index, role in enumerate(INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES)
    )


def _identity(binding, delegation, resources, **changes):
    values = {
        "schema_version": INSTALLED_STRIX_RUNTIME_IDENTITY_SCHEMA,
        "backend": "bluefire-controlled",
        "job_id": JOB,
        "preparation_ref": PREPARATION,
        "binding_digest": binding.binding_digest,
        "delegation_digest": delegation.delegation_digest,
        "claim_ref": CLAIM,
        "runtime_resolution_ref": RESOLUTION,
        "controlled_profile_ref": _sha("a"),
        "runtime_admission_ref": _sha("b"),
        "runtime_activation_ref": _sha("6"),
        "controlled_launch_digest": _sha("7"),
        "startup_overlay_ref": _sha("8"),
        "runtime_closure_plan_ref": _sha("9"),
        "fixed_exec_receipt_ref": _sha("0"),
        "target_scope_admission_ref": _sha("f"),
        "installed_projection_ref": _sha("1"),
        "sealed_inputs_ref": _sha("2"),
        "runtime_image_contract_ref": _sha("3"),
        "runtime_image_qualification_ref": _sha("4"),
        "runtime_image_closure_ref": _sha("5"),
        "worker_identity_ref": _sha("6"),
        "exec_broker_binding_digest": _sha("c"),
        "worker_launch_digest": _sha("d"),
        "worker_controller_server_ref": _sha("7"),
        "worker_custody_ready_receipt_ref": _sha("8"),
        "resource_set_digest": _resource_set_digest(resources),
    }
    values.update(changes)
    values["launch_digest"] = content_hash(
        {
            "schema_version": INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
            "backend": values["backend"],
            "job_id": values["job_id"],
            "preparation_ref": values["preparation_ref"],
            "binding_digest": values["binding_digest"],
            "delegation_digest": values["delegation_digest"],
            "claim_ref": values["claim_ref"],
            "runtime_resolution_ref": values["runtime_resolution_ref"],
            "controlled_profile_ref": values["controlled_profile_ref"],
            "runtime_admission_ref": values["runtime_admission_ref"],
            "runtime_activation_ref": values["runtime_activation_ref"],
            "controlled_launch_digest": values["controlled_launch_digest"],
            "startup_overlay_ref": values["startup_overlay_ref"],
            "runtime_closure_plan_ref": values["runtime_closure_plan_ref"],
            "fixed_exec_receipt_ref": values["fixed_exec_receipt_ref"],
            "target_scope_admission_ref": values["target_scope_admission_ref"],
            "installed_projection_ref": values["installed_projection_ref"],
            "sealed_inputs_ref": values["sealed_inputs_ref"],
            "runtime_image_contract_ref": values["runtime_image_contract_ref"],
            "runtime_image_qualification_ref": values["runtime_image_qualification_ref"],
            "runtime_image_closure_ref": values["runtime_image_closure_ref"],
            "worker_identity_ref": values["worker_identity_ref"],
            "exec_broker_binding_digest": values["exec_broker_binding_digest"],
            "worker_launch_digest": values["worker_launch_digest"],
            "worker_controller_server_ref": values["worker_controller_server_ref"],
            "worker_custody_ready_receipt_ref": values["worker_custody_ready_receipt_ref"],
            "resource_set_digest": values["resource_set_digest"],
        }
    )
    return InstalledControlledStrixRuntimeIdentity(**values)


def _accepted(binding, delegation):
    return AcceptedPreparedEngineAttempt(
        job_id=JOB,
        preparation_ref=PREPARATION,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM,
        runtime_resolution_ref=RESOLUTION,
    )


def _case():
    config = _configured()
    workspace, _, _ = _bind(config)
    config.composition.bind(config.store, workspace)
    config.composition.resolver = _Resolver()
    binding, delegation, _ = _authority()
    accepted = _accepted(binding, delegation)
    events: list[tuple[str, str]] = []
    resources = _resources(events)
    identity = _identity(binding, delegation, resources)
    runtime = _Runtime(identity)
    openers = _Openers()
    openers.execution = InstalledStrixExecutionBundle(
        runtime, identity, resources, _CleanupOwner(identity, resources)
    )
    reference = _sha("9")
    reconciliation_resources = _reconciliation_resources(events)
    openers.reconciliation = InstalledStrixReconciliationBundle(
        _ReconciliationRuntime(identity),
        identity,
        reconciliation_resources,
        reference,
        _CleanupOwner(identity, reconciliation_resources),
    )
    factory = ControllerOwnedInstalledStrixAttemptFactory(
        product_store=config.store,
        execution_opener=openers,
        reconciliation_opener=openers,
    )
    return config, binding, delegation, accepted, events, resources, openers, factory, reference


def _close_case(config) -> None:
    config.composition.shutdown_jobs()
    config.composition.close()


def test_construction_is_inert_and_declares_exact_recovery_policy():
    config, *_rest, openers, factory, _reference = _case()
    try:
        assert openers.execution_calls == openers.reconciliation_calls == []
        assert factory.reconciliation_policy == {
            "schema_version": "bluefire.installed-attempt-reconciliation.v1",
            "effects": "exact-reference-idempotent-no-launch",
        }
    finally:
        _close_case(config)


def test_execution_binds_store_claim_controlled_identity_and_two_fresh_reads():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    try:
        components = factory.for_execution(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            composition=config.composition,
        )
        assert components.runtime is openers.execution.runtime
        assert components.resources == tuple(resource.owner for resource in resources)
        assert components.runtime_resolution_ref == RESOLUTION
        assert components.cleanup_owner is openers.execution.cleanup_owner
        assert components.resource_set_ref == openers.execution.cleanup_owner.resource_set_ref
        assert components.attempt_ref == binding.binding_digest
        assert components.activation_ref == CLAIM
        assert config.composition.resolver.calls == 2
        assert len(openers.execution_calls) == 1
        call = openers.execution_calls[0]
        assert call["product_store"] is config.store
        assert call["accepted"] is accepted
        assert call["binding"] is binding
        assert call["delegation"] is delegation
        assert call["runtime_resolution"] is config.composition.resolver.resolution
        assert events == []
    finally:
        _close_case(config)


def test_resolution_drift_before_open_never_allocates():
    config, binding, delegation, accepted, events, _resources_rows, openers, factory, _ = _case()
    config.composition.resolver.fail_after = 0
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="no longer current"):
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert openers.execution_calls == []
        assert events == []
    finally:
        _close_case(config)


def test_resolution_drift_after_open_settles_through_exact_cleanup_owner():
    config, binding, delegation, accepted, events, _resources, openers, factory, _ = _case()
    config.composition.resolver.fail_after = 1
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="no longer current"):
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert events == []
        assert len(openers.execution.cleanup_owner.settle_calls) == 1
    finally:
        _close_case(config)


def test_resolution_drift_surfaces_cleanup_uncertainty_without_hiding_original():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    identity = _identity(binding, delegation, resources)
    owner = _CleanupOwner(identity, resources, initial_unknown=True)
    openers.execution = InstalledStrixExecutionBundle(
        _Runtime(identity), identity, resources, owner
    )
    config.composition.resolver.fail_after = 1
    try:
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "no longer current" in str(captured.value.original_error)
        assert captured.value.cleanup_errors == ()
        assert len(owner.settle_calls) == 1
        assert events == []
    finally:
        _close_case(config)
    assert len(owner.reconcile_calls) == 1


def test_other_service_store_is_refused_before_open():
    config, binding, delegation, accepted, events, _resources_rows, openers, _factory, _ = _case()
    factory = ControllerOwnedInstalledStrixAttemptFactory(
        product_store=object(),
        execution_opener=openers,
        reconciliation_opener=openers,
    )
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="another service"):
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert openers.execution_calls == []
        assert events == []
    finally:
        _close_case(config)


def test_claim_identity_mismatch_closes_bundle_and_legacy_runtime_shape_is_rejected():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    changed = _identity(binding, delegation, resources, claim_ref=_sha("e"))
    openers.execution = InstalledStrixExecutionBundle(
        _Runtime(changed), changed, resources, _CleanupOwner(changed, resources)
    )
    try:
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "identity changed" in str(captured.value.original_error)
        assert len(events) == 6
        events.clear()
        identity = _identity(binding, delegation, resources)
        openers.execution = InstalledStrixExecutionBundle(
            object(),  # type: ignore[arg-type]
            identity,
            resources,
            _CleanupOwner(identity, resources),
        )
        with pytest.raises(InstalledAttemptFactoryError, match="runtime is incomplete"):
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert events == []
        assert len(openers.execution.cleanup_owner.settle_calls) == 1
    finally:
        _close_case(config)


def test_actual_legacy_runtime_cannot_be_relabelled_as_controlled():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    identity = _identity(binding, delegation, resources)
    legacy = object.__new__(StrixEngineRuntime)
    legacy.installed_runtime_identity = identity
    openers.execution = InstalledStrixExecutionBundle(  # type: ignore[arg-type]
        legacy,
        identity,
        resources,
        _CleanupOwner(identity, resources),
    )
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="stock-Docker"):
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert events == []
        assert len(openers.execution.cleanup_owner.settle_calls) == 1
    finally:
        _close_case(config)


def test_malformed_resource_row_does_not_mask_cleanup_of_valid_owners():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    malformed = resources[:3] + (object(),) + resources[4:]
    identity = _identity(binding, delegation, resources)
    openers.execution = InstalledStrixExecutionBundle(  # type: ignore[arg-type]
        _Runtime(identity),
        identity,
        malformed,
        _CleanupOwner(identity, resources),
    )
    try:
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "resource row" in str(captured.value.original_error)
        assert events == [
            ("close", "worker_controller"),
            ("close", "target_relay"),
            ("close", "model_gateway"),
            ("close", "docker_control"),
            ("close", "caido_channel"),
        ]
    finally:
        _close_case(config)


def test_reconciliation_uses_only_no_launch_opener_and_exact_reference():
    config, binding, delegation, accepted, events, resources, openers, factory, reference = _case()
    saved = EngineAttemptRecord.create(binding)
    try:
        components = factory.for_reconciliation(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            saved_record=saved,
            reconciliation_ref=reference,
            composition=config.composition,
        )
        assert components.runtime is openers.reconciliation.runtime
        assert components.resources == tuple(
            resource.owner for resource in openers.reconciliation.resources
        )
        assert components.cleanup_owner is openers.reconciliation.cleanup_owner
        assert components.resource_set_ref == openers.reconciliation.cleanup_owner.resource_set_ref
        assert components.attempt_ref == binding.binding_digest
        assert components.activation_ref == CLAIM
        assert openers.execution_calls == []
        assert len(openers.reconciliation_calls) == 1
        call = openers.reconciliation_calls[0]
        assert call["product_store"] is config.store
        assert call["saved_record"] is saved
        assert call["reconciliation_ref"] == reference
        # Recovery may run after authority revocation; it does not call the
        # execution-only current-resolution guard.
        assert config.composition.resolver.calls == 0
        assert events == []
    finally:
        _close_case(config)


def test_factory_components_are_accepted_by_composition_cleanup():
    config, binding, delegation, accepted, events, _resources_rows, openers, factory, _ = _case()
    try:
        components = factory.for_execution(
            accepted=accepted,
            binding=binding,
            delegation=delegation,
            composition=config.composition,
        )
        config.composition._retain(
            components,
            expected_resolution_ref=RESOLUTION,
            expected_attempt_ref=binding.binding_digest,
            expected_activation_ref=CLAIM,
        )
        assert events == []
    finally:
        _close_case(config)
    assert len(openers.execution.cleanup_owner.settle_calls) == 1


def test_missing_or_mismatched_cleanup_owner_is_refused_before_component_handoff():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    identity = _identity(binding, delegation, resources)
    try:
        openers.execution = InstalledStrixExecutionBundle(
            _Runtime(identity), identity, resources, None
        )
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "cleanup owner is unavailable" in str(captured.value.original_error)
        assert len(events) == len(resources)
        events.clear()

        wrong = _CleanupOwner(identity, resources)
        wrong.resource_manifest = tuple(reversed(wrong.resource_manifest))
        wrong.resource_set_ref = resource_set_ref(wrong.resource_manifest)
        openers.execution = InstalledStrixExecutionBundle(
            _Runtime(identity), identity, resources, wrong
        )
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "cleanup resource set changed" in str(captured.value.original_error)
        assert len(events) == len(resources)
        events.clear()

        wrong_activation = _CleanupOwner(identity, resources)
        wrong_activation.runtime_activation_ref = _sha("f")
        openers.execution = InstalledStrixExecutionBundle(
            _Runtime(identity), identity, resources, wrong_activation
        )
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "cleanup activation changed" in str(captured.value.original_error)
        assert len(events) == len(resources)
    finally:
        _close_case(config)


def test_missing_owner_preserves_raw_close_failure_as_cleanup_uncertainty():
    config, binding, delegation, accepted, events, resources, openers, factory, _ = _case()
    changed = list(resources)
    changed[2] = InstalledStrixOwnedResource(
        changed[2].role,
        changed[2].binding_ref,
        _FailCloseResource(events, changed[2].role),
    )
    rows = tuple(changed)
    identity = _identity(binding, delegation, rows)
    openers.execution = InstalledStrixExecutionBundle(_Runtime(identity), identity, rows, None)
    try:
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "cleanup owner is unavailable" in str(captured.value.original_error)
        assert len(captured.value.cleanup_errors) == 1
        assert "close failed" in str(captured.value.cleanup_errors[0])
        assert len(events) == len(rows)
    finally:
        _close_case(config)


def test_invalid_reconciliation_reference_never_reopens():
    config, binding, delegation, accepted, events, _resources_rows, openers, factory, _ = _case()
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="reconciliation"):
            factory.for_reconciliation(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                saved_record=EngineAttemptRecord.create(binding),
                reconciliation_ref="invalid",
                composition=config.composition,
            )
        assert openers.reconciliation_calls == []
        assert events == []
    finally:
        _close_case(config)


def test_duplicate_resource_owner_is_retained_and_closed_once_on_failure():
    config, binding, delegation, accepted, events, _rows, openers, factory, _ = _case()
    resources = _resources(events, shared=True)
    identity = _identity(binding, delegation, resources, claim_ref=_sha("f"))
    openers.execution = InstalledStrixExecutionBundle(
        _Runtime(identity), identity, resources, _CleanupOwner(identity, resources)
    )
    try:
        with pytest.raises(InstalledAttemptCleanupUncertain) as captured:
            factory.for_execution(
                accepted=accepted,
                binding=binding,
                delegation=delegation,
                composition=config.composition,
            )
        assert "identity changed" in str(captured.value.original_error)
        assert events == [("close", "shared")]
    finally:
        _close_case(config)


def test_constructor_requires_separate_execution_and_reconciliation_openers():
    with pytest.raises(InstalledAttemptFactoryError, match="execution opener"):
        ControllerOwnedInstalledStrixAttemptFactory(
            product_store=object(),
            execution_opener=object(),  # type: ignore[arg-type]
            reconciliation_opener=_Openers(),
        )
    with pytest.raises(InstalledAttemptFactoryError, match="reconciliation opener"):
        ControllerOwnedInstalledStrixAttemptFactory(
            product_store=object(),
            execution_opener=_Openers(),
            reconciliation_opener=object(),  # type: ignore[arg-type]
        )


def test_resource_rows_are_canonical_and_launch_digest_is_recomputed():
    config, binding, delegation, _accepted_row, events, resources, _openers, _factory, _ = _case()
    try:
        with pytest.raises(InstalledAttemptFactoryError, match="noncanonical"):
            _resource_set_digest(tuple(reversed(resources)))
        identity = _identity(binding, delegation, resources)
        with pytest.raises(InstalledAttemptFactoryError, match="launch identity"):
            replace(identity, launch_digest=_sha("0"))
        assert events == []
    finally:
        _close_case(config)


def test_v1_runtime_identity_schema_is_not_silently_redefined():
    config, binding, delegation, _accepted_row, _events, resources, _openers, _factory, _ = _case()
    try:
        identity = _identity(binding, delegation, resources)
        with pytest.raises(InstalledAttemptFactoryError, match="unsupported"):
            replace(
                identity,
                schema_version="bluefire.installed-controlled-strix-runtime.v1",
            )
    finally:
        _close_case(config)
