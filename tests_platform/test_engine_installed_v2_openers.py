"""Fail-closed composition for the protected installed Strix V2 seams."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from typing import Any

import pytest

from bluefire.accepted_engine_jobs import AcceptedPreparedEngineAttempt
from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_container_custody import ContainerCustodyPlanV2
from bluefire.engine_installed_attempt_factory import (
    INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES,
    INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
    INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES,
    InstalledAttemptFactoryError,
    InstalledControlledStrixRuntimeIdentity,
    InstalledStrixOwnedResource,
)
from bluefire.engine_installed_cleanup import (
    InstalledEngineCleanupResourceBinding,
    resource_set_ref,
)
from bluefire.engine_installed_v2_authority import _validate_admission_semantics
from bluefire.engine_installed_v2_openers import (
    ControllerOwnedInstalledStrixV2Openers,
    InstalledStrixV2ActivationReceipt,
    InstalledStrixV2AuthorityGuard,
    InstalledStrixV2AuthoritySnapshot,
    InstalledStrixV2CleanupReceipt,
    InstalledStrixV2CompositionError,
    InstalledStrixV2ExecutionResources,
    InstalledStrixV2HistoricalSnapshot,
    InstalledStrixV2PrelaunchSnapshot,
    InstalledStrixV2ReopenedResources,
    InstalledStrixV2ResourceReceipt,
    _runtime_identity,
)
from bluefire.engine_network_policy import EngineNetworkPlanV2
from bluefire.product_store_engine_execution_claims import _claim_reference
from bluefire.strix_controlled_runtime_admission import (
    StrixControlledRuntimeAdmissionV2,
    build_controlled_launch_plan,
)
from bluefire.util import content_hash
from tests_platform.test_engine_experiment_jobs import _authority
from tests_platform.test_strix_controlled_runtime_admission import admission_document


def _digest(label: str) -> str:
    return content_hash(label)


def _replace_identity(identity, **changes):
    values = {
        name: getattr(identity, name)
        for name in identity.__dataclass_fields__
        if name != "launch_digest"
    }
    values.update(changes)
    values["launch_digest"] = content_hash(
        {
            "schema_version": INSTALLED_STRIX_LAUNCH_IDENTITY_SCHEMA,
            **{name: value for name, value in values.items() if name != "schema_version"},
        }
    )
    return InstalledControlledStrixRuntimeIdentity(**values)


class _Owner:
    def __init__(self, events: list[str], label: str, *, close_error: bool = False) -> None:
        self.events = events
        self.label = label
        self.close_error = close_error

    def close(self) -> None:
        self.events.append("close:" + self.label)
        if self.close_error:
            raise RuntimeError("close failed")


class _TestCleanupOwner:
    def __init__(
        self,
        *,
        attempt_ref,
        activation_ref,
        runtime_activation_ref,
        runtime_resolution_ref,
        resources,
    ):
        self.attempt_ref = attempt_ref
        self.activation_ref = activation_ref
        self.runtime_activation_ref = runtime_activation_ref
        self.owner_ref = _digest("cleanup-owner")
        self.runtime_resolution_ref = runtime_resolution_ref
        self.resource_manifest = tuple(
            InstalledEngineCleanupResourceBinding(row.role, row.binding_ref) for row in resources
        )
        self.resource_set_ref = resource_set_ref(self.resource_manifest)

    def settle(self, *, cleanup_ref):
        raise AssertionError(f"opener construction must not settle {cleanup_ref}")

    def reconcile(self, *, receipt):
        raise AssertionError("opener construction must not reconcile cleanup")


class _LaunchCapableOwner(_Owner):
    def launch(self):
        raise AssertionError("must not launch during reconciliation")


class _PendingMaintainedLease:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def revoke_and_reconcile(self) -> None:
        self.events.append("revoke-reconcile:maintained-model-lease")


class _DispatchAuthority:
    def __init__(self, activation: InstalledStrixV2ActivationReceipt) -> None:
        self.authority_ref = activation.exec_dispatch_authority_ref
        self.claim_ref = activation.claim_ref
        self.controller_fence = activation.controller_fence


class _OperationWatchdog:
    def require_live(self, *_args, **_values):
        return object()


class _DispatchRuntime:
    def __init__(self, authority: object, continuous_custody: object) -> None:
        self.authority = authority
        self.continuous_custody = continuous_custody

    def gate(self, *_args, **_values):
        return object()


class _DockerTransport:
    def exchange(self, *_args, **_values):
        return object()


class _CancellationAuthority:
    def __init__(
        self,
        dispatch_authority: _DispatchAuthority,
        activation: InstalledStrixV2ActivationReceipt,
    ) -> None:
        self.dispatch_authority = dispatch_authority
        self.activation = activation

    def require_binding(self, **values):
        expected = {
            "authority": self.dispatch_authority,
            "custody_plan_digest": self.activation.custody_plan_digest,
            "network_policy_digest": self.activation.network_policy_digest,
            "authority_ref": self.activation.exec_dispatch_authority_ref,
            "claim_ref": self.activation.claim_ref,
            "controller_fence": self.activation.controller_fence,
        }
        if values != expected:
            raise ValueError("cancellation binding changed")


class _ExecAttachment(_Owner):
    def __init__(self, events: list[str], activation: InstalledStrixV2ActivationReceipt) -> None:
        super().__init__(events, "docker_control")
        self.exec_broker_binding_digest = activation.exec_broker_binding_digest
        self.dispatch_authority_ref = activation.exec_dispatch_authority_ref
        self.dispatch_authority = _DispatchAuthority(activation)
        self.operation_watchdog_ref = activation.operation_watchdog_ref
        self.operation_watchdog = _OperationWatchdog()
        self.dispatch_runtime = _DispatchRuntime(
            self.dispatch_authority,
            self.operation_watchdog,
        )
        self.docker_transport = _DockerTransport()
        self.cancellation_ref = activation.exec_cancellation_ref
        self.cancellation_authority = _CancellationAuthority(
            self.dispatch_authority,
            activation,
        )
        self.cleanup_uncertain = False


class _CaidoProvider(_Owner):
    def __init__(self, events: list[str], activation: InstalledStrixV2ActivationReceipt) -> None:
        super().__init__(events, "caido_channel")
        self.provider_identity_ref = activation.caido_provider_identity_ref
        self.mode = activation.caido_mode
        self.test_provider = activation.caido_test_provider
        self.live_caido_proof = activation.caido_live_proof
        self.cleanup_uncertain = False


class _ModelGatewayLease(_Owner):
    def __init__(self, events: list[str], activation: InstalledStrixV2ActivationReceipt) -> None:
        super().__init__(events, "model_gateway")
        self.lease_binding_ref = activation.model_gateway_lease_ref
        self.custody_identity_ref = activation.worker_custody_identity_ref
        self.provider_kind = activation.model_provider_kind
        self.live_model_proof = activation.model_live_proof
        self.cleanup_uncertain = False

    def claim(self, _binding, _custody_identity):
        return "ephemeral-test-bearer"

    def revoke(self):
        self.events.append("revoke:model_gateway")
        return None

    def close(self) -> None:
        self.revoke()
        super().close()


class _ContainmentVerifier:
    def verify(self) -> None:
        return None


class _ControllerServer:
    def __init__(self, activation, verifier, model_gateway_lease) -> None:
        self.server_identity_ref = activation.worker_controller_server_ref
        self.retained_containment_verifier = verifier
        self.retained_custody_identity = object()
        self.retained_containment_ref = activation.worker_containment_ref
        self.retained_model_gateway_lease = model_gateway_lease
        self.custody_active = True

    def wait_until_custody_ready(self, _timeout):
        return type("Ready", (), {"receipt_ref": _digest("worker-custody-ready")})()

    def close(self) -> None:
        self.custody_active = False


class _SourceCollection(_Owner):
    def __init__(self, events, activation) -> None:
        super().__init__(events, "source_collection")
        self.binding_ref = dict(activation.role_bindings)["source_collection"]
        self.cleanup_uncertain = False


class _TargetRelay(_Owner):
    def __init__(self, events, activation) -> None:
        super().__init__(events, "target_relay")
        self.binding_ref = dict(activation.role_bindings)["target_relay"]
        self.target_scope_admission_ref = activation.target_scope_admission_ref
        self.cleanup_uncertain = False


class _WorkerController(_Owner):
    def __init__(
        self,
        events: list[str],
        activation: InstalledStrixV2ActivationReceipt,
        model_gateway_lease: _ModelGatewayLease,
    ) -> None:
        super().__init__(events, "worker_controller")
        self.startup_overlay_ref = activation.startup_overlay_ref
        self.runtime_closure_plan_ref = activation.runtime_closure_plan_ref
        self.fixed_exec_receipt_ref = activation.fixed_exec_receipt_ref
        self.installed_projection_ref = activation.installed_projection_ref
        self.sealed_inputs_ref = activation.sealed_inputs_ref
        self.runtime_image_contract_ref = activation.runtime_image_contract_ref
        self.runtime_image_qualification_ref = activation.runtime_image_qualification_ref
        self.runtime_image_closure_ref = activation.runtime_image_closure_ref
        self.worker_identity_ref = activation.worker_identity_ref
        self.custody_ready_receipt_ref = activation.worker_custody_ready_receipt_ref
        self.worker_launch_digest = activation.worker_launch_digest
        self.worker_containment_ref = activation.worker_containment_ref
        self.custody_identity_ref = activation.worker_custody_identity_ref
        self.containment_verifier = _ContainmentVerifier()
        self.controller_server = _ControllerServer(
            activation,
            self.containment_verifier,
            model_gateway_lease,
        )
        self.model_gateway_lease = model_gateway_lease
        self.cleanup_uncertain = False


class _ExecutionRuntime:
    installed_execution_enabled = True

    def __init__(self, identity, guard, resources) -> None:
        self.installed_runtime_identity = identity
        self.installed_authority_guard = guard
        self.installed_caido_provider = resources.caido_provider
        self.installed_exec_attachment = resources.exec_attachment
        self.installed_exec_dispatch_authority = resources.exec_attachment.dispatch_authority
        self.installed_exec_dispatch_runtime = resources.exec_attachment.dispatch_runtime
        self.installed_docker_transport = resources.exec_attachment.docker_transport
        self.installed_operation_watchdog = resources.exec_attachment.operation_watchdog
        self.installed_exec_cancellation_authority = (
            resources.exec_attachment.cancellation_authority
        )
        self.installed_worker_containment_verifier = (
            resources.worker_controller.containment_verifier
        )
        self.installed_worker_controller = resources.worker_controller
        self.installed_worker_controller_server = resources.worker_controller.controller_server
        self.installed_model_gateway_lease = resources.model_gateway_lease
        owners = {row.role: row.owner for row in resources.resources}
        self.installed_source_collection = owners["source_collection"]
        self.installed_target_relay = owners["target_relay"]

    def execute(self, *_args, **_values):
        raise AssertionError("composition must not execute")

    def reconcile(self, *_args, **_values):
        raise AssertionError("composition must not reconcile")

    def reconcile_claimed(self, *_args, **_values):
        raise AssertionError("composition must not reconcile")


class _ReconciliationRuntime:
    installed_execution_disabled = True

    def __init__(self, identity, reconciliation_ref, resources) -> None:
        self.installed_runtime_identity = identity
        self.installed_reconciliation_ref = reconciliation_ref
        for row in resources.resources:
            setattr(self, f"installed_{row.role}", row.owner)

    def reconcile(self, *_args, **_values):
        raise AssertionError("composition must not reconcile")

    def reconcile_claimed(self, *_args, **_values):
        raise AssertionError("composition must not reconcile")


class _AuthoritySource:
    def __init__(self, snapshots, events=None) -> None:
        self.snapshots = list(snapshots)
        self.current_calls = 0
        self.reconciliation = None
        self.events: list[str] = [] if events is None else events

    def require_current(self, **_values):
        self.events.append("current")
        index = min(self.current_calls, len(self.snapshots) - 1)
        self.current_calls += 1
        return self.snapshots[index]

    def require_prelaunch_current(self, **_values):
        self.events.append("prelaunch")
        index = min(self.current_calls, len(self.snapshots) - 1)
        self.current_calls += 1
        snapshot = self.snapshots[index]
        return InstalledStrixV2PrelaunchSnapshot(snapshot.resolution_ref, snapshot.admission)

    def retain_activation(self, **_values):
        self.events.append("retain-activation")

    def reopen_reconciliation(self, **_values):
        self.events.append("reopen-authority")
        return self.reconciliation


class _ExecutionTransaction:
    def __init__(
        self,
        *,
        snapshot,
        activation,
        guard,
        events,
        fail_allocate=False,
        invalid_cleanup=False,
        effects_started=False,
        fail_model_adapter=False,
        transaction_ref=None,
    ) -> None:
        self.snapshot = snapshot
        self.activation = activation
        self.guard = guard
        self.events = events
        self.fail_allocate = fail_allocate
        self.invalid_cleanup = invalid_cleanup
        self.effects_started = effects_started
        self.fail_model_adapter = fail_model_adapter
        self.transaction_ref = transaction_ref or _digest("execution-transaction")
        self.resources = None
        self.pending_lease = None

    def allocate(self):
        self.events.append("allocate")
        self.pending_lease = _PendingMaintainedLease(self.events)
        if self.fail_allocate:
            raise RuntimeError("partial allocation failed")
        if self.fail_model_adapter:
            raise RuntimeError("model gateway adapter construction failed")
        activation = self.activation
        caido_provider = _CaidoProvider(self.events, activation)
        attachment = _ExecAttachment(self.events, activation)
        model_gateway = _ModelGatewayLease(self.events, activation)
        self.pending_lease = None
        source_collection = _SourceCollection(self.events, activation)
        target_relay = _TargetRelay(self.events, activation)
        worker = _WorkerController(self.events, activation, model_gateway)
        owners = {
            "caido_channel": caido_provider,
            "docker_control": attachment,
            "model_gateway": model_gateway,
            "source_collection": source_collection,
            "target_relay": target_relay,
            "worker_controller": worker,
        }
        rows = tuple(
            InstalledStrixOwnedResource(
                role,
                binding_ref,
                owners.get(role, _Owner(self.events, role)),
            )
            for role, binding_ref in activation.role_bindings
        )
        receipt = InstalledStrixV2ResourceReceipt.create(
            action="allocated",
            authority_ref=self.guard.authority_ref,
            activation_receipt_ref=activation.receipt_ref,
            role_bindings=activation.role_bindings,
        )
        self.resources = InstalledStrixV2ExecutionResources(
            self.guard,
            rows,
            caido_provider,
            attachment,
            model_gateway,
            source_collection,
            target_relay,
            worker,
            receipt,
            _TestCleanupOwner(
                attempt_ref=self.snapshot.admission.to_dict()["binding_digest"],
                activation_ref=activation.claim_ref,
                runtime_activation_ref=activation.receipt_ref,
                runtime_resolution_ref=activation.runtime_resolution_ref,
                resources=rows,
            ),
        )
        if self.observed_identity is not None:
            return self.resources, activation, self.observed_identity
        return self.resources

    def commit(self) -> None:
        self.pending_lease = None
        self.events.append("commit")

    def close(self):
        if self.resources is not None:
            seen: set[int] = set()
            for row in reversed(self.resources.resources):
                if id(row.owner) in seen:
                    continue
                seen.add(id(row.owner))
                row.owner.close()
        if self.pending_lease is not None:
            self.pending_lease.revoke_and_reconcile()
            self.pending_lease = None
        self.events.append("abort")
        receipt = InstalledStrixV2CleanupReceipt.create(
            action="execution_abort",
            transaction_ref=(
                _digest("wrong-execution-transaction")
                if self.invalid_cleanup
                else self.transaction_ref
            ),
            authority_ref=self.guard.authority_ref,
            activation_receipt_ref=(
                self.activation.receipt_ref if self.resources is not None else None
            ),
        )
        return receipt


class _ExecutionFactory:
    def __init__(self, events: list[str], **changes: Any) -> None:
        self.events = events
        self.changes = changes
        self.transaction = None
        self.activation = None
        self.observed_identity = None

    def begin_execution(self, **values):
        self.events.append("begin")
        self.transaction = _ExecutionTransaction(
            snapshot=values["snapshot"],
            activation=self.activation,
            guard=values["authority_guard"],
            events=self.events,
            transaction_ref=values.get("resource_transaction_ref"),
            **self.changes,
        )
        self.transaction.observed_identity = self.observed_identity
        return self.transaction


class _ReconciliationTransaction:
    effects_started = False

    def __init__(self, *, snapshot, reconciliation_ref, events, transaction_ref=None) -> None:
        self.snapshot = snapshot
        self.reconciliation_ref = reconciliation_ref
        self.events = events
        self.transaction_ref = transaction_ref or _digest("reconciliation-transaction")

    def reopen(self):
        self.events.append("reopen-resources")
        rows = tuple(
            InstalledStrixOwnedResource(role, _digest(role), _Owner(self.events, role))
            for role in INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
        )
        role_bindings = tuple((row.role, row.binding_ref) for row in rows)
        receipt = InstalledStrixV2ResourceReceipt.create(
            action="reopened",
            authority_ref=self.snapshot.authority_ref,
            activation_receipt_ref=self.snapshot.activation.receipt_ref,
            role_bindings=role_bindings,
            reconciliation_ref=self.reconciliation_ref,
        )
        return InstalledStrixV2ReopenedResources(
            rows,
            receipt,
            _TestCleanupOwner(
                attempt_ref=self.snapshot.identity.binding_digest,
                activation_ref=self.snapshot.identity.claim_ref,
                runtime_activation_ref=self.snapshot.identity.runtime_activation_ref,
                runtime_resolution_ref=self.snapshot.identity.runtime_resolution_ref,
                resources=rows,
            ),
        )

    def commit(self) -> None:
        self.events.append("reconciliation-commit")

    def close(self):
        self.events.append("reconciliation-abort")
        return InstalledStrixV2CleanupReceipt.create(
            action="reconciliation_abort",
            transaction_ref=self.transaction_ref,
            authority_ref=self.snapshot.authority_ref,
            activation_receipt_ref=self.snapshot.activation.receipt_ref,
            reconciliation_ref=self.reconciliation_ref,
        )


class _ReconciliationFactory:
    def __init__(self, events) -> None:
        self.events = events
        self.calls = []

    def begin_reconciliation(self, **values):
        self.events.append("begin-reconciliation")
        self.calls.append(values)
        return _ReconciliationTransaction(
            snapshot=values["snapshot"],
            reconciliation_ref=values["reconciliation_ref"],
            events=self.events,
            transaction_ref=values.get("resource_transaction_ref"),
        )


class _RuntimeBuilder:
    def __init__(self, events) -> None:
        self.events = events
        self.execution_calls = []
        self.reconciliation_calls = []

    def build_execution(self, **values):
        self.events.append("build")
        self.execution_calls.append(values)
        return _ExecutionRuntime(
            values["identity"],
            values["authority_guard"],
            values["resources"],
        )

    def build_reconciliation(self, **values):
        self.events.append("build-reconciliation")
        self.reconciliation_calls.append(values)
        return _ReconciliationRuntime(
            values["identity"],
            values["reconciliation_ref"],
            values["resources"],
        )


def _case():
    raw = admission_document()
    base_binding, base_delegation, _approval = _authority()
    claim = raw["accepted_execution_claim"]
    scope = raw["scope"]
    gateway = raw["gateway"]
    budgets = raw["budgets"]
    build = raw["execution_identity"]["startup_build_identity"]
    network = EngineNetworkPlanV2.from_mapping(raw["network_plan"])
    custody = ContainerCustodyPlanV2.from_mapping(raw["custody_plan"])
    binding = replace(
        base_binding,
        experiment_id=claim["experiment_id"],
        attempt_id=raw["attempt_id"],
        objective_ref=raw["objective_ref"],
        environment_ref=raw["environment_ref"],
        target_snapshot_ref=scope["target_snapshot_digest"],
        scope_ref=scope["scope_digest"],
        engine_version=build["package_version"],
        engine_revision=build["source_revision"],
        engine_package_digest=build["package_sha256"],
        policy_overlay_digest=build["prompt_overlay_sha256"],
        model_id=gateway["model"],
        model_data_destination=gateway["base_url"],
        model_authorization_ref=gateway["authorization_digest"],
        wall_clock_seconds=budgets["wall_seconds"],
        action_limit=budgets["max_turns_per_agent"],
        cost_limit_microunits=int(Decimal(budgets["max_model_cost_usd"]) * 1_000_000),
    )
    delegation = replace(
        base_delegation,
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        target_snapshot_ref=binding.target_snapshot_ref,
        scope_ref=binding.scope_ref,
        scope_version=binding.scope_version,
        engine_id=binding.engine_id,
        engine_version=binding.engine_version,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        policy_overlay_digest=binding.policy_overlay_digest,
        model_authorization_ref=binding.model_authorization_ref,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_data_destination=binding.model_data_destination,
        network_policy_digest=network.policy_digest,
        custody_plan_digest=custody.plan_digest,
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
    )
    raw.update(
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
    )
    claim.update(
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
    )
    claim["claim_ref"] = _claim_reference(claim)
    raw["accepted_execution_claim_ref"] = claim["claim_ref"]
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(raw)
    accepted = AcceptedPreparedEngineAttempt(
        job_id=claim["job_id"],
        preparation_ref=claim["preparation_ref"],
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=claim["claim_ref"],
        runtime_resolution_ref=claim["runtime_resolution_ref"],
    )
    plan = build_controlled_launch_plan(
        admission,
        expected_admission_ref=admission.admission_ref,
        expected_execution_claim_ref=accepted.claim_ref,
    )
    worker_launch = _digest("worker-launch")
    caido_sidecar = _digest("caido-sidecar")
    model_gateway_lease = _digest("model-gateway-lease")
    role_bindings = tuple(
        (
            role,
            plan.exec_broker_binding_digest
            if role == "docker_control"
            else caido_sidecar
            if role == "caido_channel"
            else model_gateway_lease
            if role == "model_gateway"
            else worker_launch
            if role == "worker_controller"
            else _digest(role),
        )
        for role in INSTALLED_STRIX_EXECUTION_RESOURCE_ROLES
    )
    profile_ref = raw["execution_identity"]["controlled_runtime_profile"]["profile_digest"]
    activation = InstalledStrixV2ActivationReceipt.create(
        runtime_resolution_ref=accepted.runtime_resolution_ref,
        admission_ref=admission.admission_ref,
        claim_ref=accepted.claim_ref,
        controlled_profile_ref=profile_ref,
        controlled_launch_digest=plan.launch_digest,
        startup_overlay_ref=_digest("startup-overlay-receipt"),
        runtime_closure_plan_ref=_digest("runtime-closure-plan"),
        fixed_exec_receipt_ref=_digest("fixed-exec-receipt"),
        target_scope_admission_ref=_digest("target-scope-admission"),
        installed_projection_ref=_digest("installed-projection"),
        sealed_inputs_ref=_digest("sealed-inputs"),
        runtime_image_contract_ref=_digest("runtime-image-contract"),
        runtime_image_qualification_ref=_digest("runtime-image-qualification"),
        runtime_image_closure_ref=_digest("runtime-image-closure"),
        worker_identity_ref=_digest("minimal-worker-identity"),
        caido_mode="real_sidecar",
        caido_test_provider=False,
        caido_provider_identity_ref=caido_sidecar,
        caido_terms_acceptance_ref=_digest("caido-terms-acceptance"),
        caido_entitlement_ref=_digest("caido-entitlement"),
        caido_live_proof=False,
        model_provider_kind="test",
        model_live_proof=False,
        model_gateway_lease_ref=model_gateway_lease,
        worker_custody_identity_ref=_digest("worker-custody-identity"),
        network_policy_digest=network.policy_digest,
        custody_plan_digest=custody.plan_digest,
        exec_broker_binding_digest=plan.exec_broker_binding_digest,
        exec_dispatch_authority_ref=_digest("exec-dispatch-authority"),
        controller_fence=_digest("controller-fence"),
        exec_cancellation_ref=_digest("exec-cancellation"),
        worker_launch_digest=worker_launch,
        worker_controller_server_ref=_digest("worker-controller-server"),
        worker_custody_ready_receipt_ref=_digest("worker-custody-ready"),
        operation_watchdog_ref=_digest("operation-watchdog"),
        worker_containment_ref=_digest("worker-containment"),
        candidate_qualification_ref=_digest("candidate-qualification"),
        role_bindings=role_bindings,
    )
    snapshot = InstalledStrixV2AuthoritySnapshot(
        accepted.runtime_resolution_ref,
        admission,
        activation,
    )
    return binding, delegation, accepted, plan, snapshot


def _openers(*, source=None, execution_factory=None):
    binding, delegation, accepted, plan, snapshot = _case()
    events: list[str] = []
    if source is None:
        source = _AuthoritySource([snapshot], events)
    else:
        source.events = events
    execution_factory = (
        _ExecutionFactory(events) if execution_factory is None else execution_factory
    )
    execution_factory.activation = snapshot.activation
    reconciliation_factory = _ReconciliationFactory(events)
    builder = _RuntimeBuilder(events)
    store = object()
    openers = ControllerOwnedInstalledStrixV2Openers(
        product_store=store,
        authority_source=source,
        execution_resources=execution_factory,
        reconciliation_resources=reconciliation_factory,
        runtime_builder=builder,
    )
    resolution = type("Resolution", (), {"resolution_ref": accepted.runtime_resolution_ref})()
    return {
        "binding": binding,
        "delegation": delegation,
        "accepted": accepted,
        "plan": plan,
        "snapshot": snapshot,
        "events": events,
        "source": source,
        "execution_factory": execution_factory,
        "reconciliation_factory": reconciliation_factory,
        "builder": builder,
        "store": store,
        "openers": openers,
        "resolution": resolution,
    }


def _execute(case):
    return case["openers"].open_execution(
        product_store=case["store"],
        accepted=case["accepted"],
        binding=case["binding"],
        delegation=case["delegation"],
        runtime_resolution=case["resolution"],
    )


def _prepare_reconciliation(case):
    saved_record = EngineAttemptRecord.create(case["binding"])
    reconciliation_ref = _digest("reconciliation")
    identity = _runtime_identity(
        case["accepted"],
        case["binding"],
        case["delegation"],
        case["snapshot"],
        case["plan"],
    )
    case["source"].reconciliation = InstalledStrixV2HistoricalSnapshot.create(
        resolution_ref=case["accepted"].runtime_resolution_ref,
        saved_record=saved_record,
        reconciliation_ref=reconciliation_ref,
        identity=identity,
        activation=case["snapshot"].activation,
    )
    return saved_record, reconciliation_ref, identity


def _reconcile(case, saved_record, reconciliation_ref):
    return case["openers"].reopen_reconciliation(
        product_store=case["store"],
        accepted=case["accepted"],
        binding=case["binding"],
        delegation=case["delegation"],
        saved_record=saved_record,
        reconciliation_ref=reconciliation_ref,
    )


def test_execution_reopens_currentness_around_allocation_and_binds_exact_owners():
    case = _openers()
    bundle = _execute(case)
    assert case["source"].current_calls == 4
    assert case["events"] == [
        "prelaunch",
        "begin",
        "prelaunch",
        "allocate",
        "current",
        "build",
        "current",
        "commit",
    ]
    call = case["builder"].execution_calls[0]
    resources = call["resources"]
    runtime = bundle.runtime
    assert resources.authority_guard is call["authority_guard"]
    assert runtime.installed_exec_dispatch_authority is resources.exec_attachment.dispatch_authority
    assert runtime.installed_operation_watchdog is resources.exec_attachment.operation_watchdog
    assert (
        runtime.installed_worker_containment_verifier
        is resources.worker_controller.containment_verifier
    )
    assert bundle.identity.controlled_launch_digest == case["plan"].launch_digest
    assert bundle.identity.runtime_activation_ref == case["snapshot"].activation.receipt_ref


def test_execution_without_postcommit_cleanup_owner_aborts_before_commit():
    case = _openers()
    begin_execution = case["execution_factory"].begin_execution

    def begin_without_owner(**values):
        transaction = begin_execution(**values)
        allocate = transaction.allocate

        def allocate_without_owner():
            return replace(allocate(), cleanup_owner=None)

        transaction.allocate = allocate_without_owner
        return transaction

    case["execution_factory"].begin_execution = begin_without_owner
    with pytest.raises(InstalledAttemptFactoryError, match="cleanup owner is unavailable"):
        _execute(case)
    assert "commit" not in case["events"]
    assert case["events"][-1] == "abort"


def test_prelaunch_authority_precedes_observed_activation():
    case = _openers()
    guard = InstalledStrixV2AuthorityGuard(
        product_store=case["store"],
        source=case["source"],
        accepted=case["accepted"],
        binding=case["binding"],
        delegation=case["delegation"],
    )
    prelaunch = guard.require_prelaunch_current()
    assert guard.authority_ref == prelaunch.prelaunch_ref
    assert "retain-activation" not in case["events"]
    activated = guard.retain_activation(
        admission_ref=prelaunch.admission.admission_ref,
        activation_ref=case["snapshot"].activation.receipt_ref,
        resource_transaction_ref=_digest("execution-transaction"),
        observed_identity_ref=_digest("observed-identity"),
    )
    assert activated.activation == case["snapshot"].activation
    assert case["events"] == ["prelaunch", "retain-activation", "current"]


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("engine_version", "different-version"),
        ("engine_revision", "0" * 40),
        ("engine_package_digest", _digest("different-package")),
        ("policy_overlay_digest", _digest("different-overlay")),
        ("model_data_destination", "https://different.example/v1"),
    ],
)
def test_prelaunch_refuses_changed_engine_or_model_destination(field, changed):
    binding, delegation, _accepted, _plan, snapshot = _case()
    with pytest.raises(InstalledStrixV2CompositionError, match="authority"):
        _validate_admission_semantics(
            snapshot.admission.to_dict(),
            binding=replace(binding, **{field: changed}),
            delegation=delegation,
        )


def test_prelaunch_refuses_sub_microunit_cost_even_with_zero_limit():
    binding, delegation, _accepted, _plan, snapshot = _case()
    row = snapshot.admission.to_dict()
    row["budgets"]["max_model_cost_usd"] = "0.0000001"
    with pytest.raises(InstalledStrixV2CompositionError, match="semantics"):
        _validate_admission_semantics(
            row,
            binding=replace(binding, cost_limit_microunits=0),
            delegation=delegation,
        )


def test_authority_drift_before_allocation_closes_typed_transaction_without_dispatch():
    binding, delegation, accepted, _plan, snapshot = _case()
    changed = replace(snapshot, resolution_ref=_digest("changed-resolution"))
    source = _AuthoritySource([snapshot, changed])
    case = _openers(source=source)
    with pytest.raises(InstalledStrixV2CompositionError, match="no longer current|changed"):
        _execute(case)
    assert case["events"] == ["prelaunch", "begin", "prelaunch", "abort"]
    assert case["builder"].execution_calls == []
    assert binding == case["binding"] and delegation == case["delegation"]
    assert accepted == case["accepted"]


def test_invalid_execution_transaction_shape_is_closed_exactly_once():
    case = _openers()
    original_begin = case["execution_factory"].begin_execution

    def begin(**values):
        transaction = original_begin(**values)
        transaction.allocate = None
        return transaction

    case["execution_factory"].begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="incomplete"):
        _execute(case)
    assert case["events"].count("abort") == 1
    assert "allocate" not in case["events"]


def test_unbound_execution_transaction_is_closed_but_cleanup_remains_uncertain():
    case = _openers()
    original_begin = case["execution_factory"].begin_execution

    def begin(**values):
        transaction = original_begin(**values)
        transaction.transaction_ref = None
        return transaction

    case["execution_factory"].begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="cleanup is uncertain"):
        _execute(case)
    assert case["events"].count("abort") == 1
    assert "allocate" not in case["events"]


@pytest.mark.parametrize("changed_call", [3, 4])
def test_authority_drift_after_allocation_or_construction_closes_transaction(changed_call):
    _binding, _delegation, _accepted, _plan, snapshot = _case()
    activation = InstalledStrixV2ActivationReceipt.create(
        **{
            name: (
                _digest(f"changed-qualification-{changed_call}")
                if name == "candidate_qualification_ref"
                else getattr(snapshot.activation, name)
            )
            for name in snapshot.activation.__dataclass_fields__
            if name not in {"schema_version", "receipt_ref"}
        }
    )
    source = _AuthoritySource(
        [snapshot] * (changed_call - 1) + [replace(snapshot, activation=activation)]
    )
    case = _openers(source=source)
    with pytest.raises(InstalledStrixV2CompositionError, match="changed|uncertain") as caught:
        _execute(case)
    assert case["events"].count("abort") == 1
    assert "commit" not in case["events"]
    if changed_call == 3:
        assert "build" not in case["events"]
        assert "resource receipt changed" in str(caught.value.original_error)
    else:
        assert case["events"].count("build") == 1


@pytest.mark.parametrize("stage", ["build", "commit"])
def test_builder_and_commit_failures_close_uncommitted_transaction(stage):
    case = _openers()
    if stage == "build":

        def fail_build(**_values):
            case["events"].append("build")
            raise RuntimeError("builder failed")

        case["builder"].build_execution = fail_build
    else:
        original_begin = case["execution_factory"].begin_execution

        def begin(**values):
            transaction = original_begin(**values)

            def fail_commit():
                case["events"].append("commit")
                raise RuntimeError("commit failed")

            transaction.commit = fail_commit
            return transaction

        case["execution_factory"].begin_execution = begin
    with pytest.raises(RuntimeError, match=f"{stage}(er)? failed"):
        _execute(case)
    assert case["events"].count("abort") == 1


def test_partial_allocation_failure_requires_verified_cleanup_receipt():
    case = _openers()
    case["execution_factory"].changes["fail_allocate"] = True
    with pytest.raises(RuntimeError, match="partial allocation"):
        _execute(case)
    assert case["events"] == [
        "prelaunch",
        "begin",
        "prelaunch",
        "allocate",
        "revoke-reconcile:maintained-model-lease",
        "abort",
    ]

    case = _openers()
    case["execution_factory"].changes.update(
        fail_allocate=True,
        invalid_cleanup=True,
    )
    with pytest.raises(InstalledStrixV2CompositionError, match="cleanup is uncertain") as caught:
        _execute(case)
    assert isinstance(caught.value.original_error, RuntimeError)
    assert len(caught.value.cleanup_errors) == 1


def test_model_gateway_adapter_constructor_failure_revokes_acquired_lease():
    case = _openers()
    case["execution_factory"].changes["fail_model_adapter"] = True
    with pytest.raises(RuntimeError, match="adapter construction failed"):
        _execute(case)
    assert case["events"][-2:] == [
        "revoke-reconcile:maintained-model-lease",
        "abort",
    ]


def test_abort_close_failure_retains_original_and_cleanup_errors():
    case = _openers()
    original_begin = case["execution_factory"].begin_execution

    def begin(**values):
        transaction = original_begin(**values)
        transaction.fail_allocate = True

        def fail_close():
            raise RuntimeError("cleanup close failed")

        transaction.close = fail_close
        return transaction

    case["execution_factory"].begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="cleanup is uncertain") as caught:
        _execute(case)
    assert str(caught.value.original_error) == "partial allocation failed"
    assert tuple(str(error) for error in caught.value.cleanup_errors) == ("cleanup close failed",)


@pytest.mark.parametrize("owner", ["caido", "exec", "model", "worker"])
def test_changed_live_owner_identity_is_refused_and_transaction_is_closed(owner):
    case = _openers()
    transaction = case["execution_factory"]
    original_begin = transaction.begin_execution

    def begin(**values):
        result = original_begin(**values)
        original_allocate = result.allocate

        def allocate():
            resources = original_allocate()
            if owner == "caido":
                resources.caido_provider.cleanup_uncertain = True
            elif owner == "exec":
                resources.exec_attachment.cleanup_uncertain = True
            elif owner == "model":
                resources.model_gateway_lease.cleanup_uncertain = True
            else:
                resources.worker_controller.cleanup_uncertain = True
            return resources

        result.allocate = allocate
        return result

    transaction.begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError):
        _execute(case)
    assert case["events"][-1] == "abort"


@pytest.mark.parametrize(
    "attribute",
    [
        "installed_exec_dispatch_runtime",
        "installed_docker_transport",
        "installed_operation_watchdog",
        "installed_model_gateway_lease",
        "installed_worker_controller_server",
        "installed_source_collection",
        "installed_target_relay",
    ],
)
def test_runtime_cannot_substitute_equal_ref_protected_owner(attribute):
    case = _openers()
    original_build = case["builder"].build_execution

    def build(**values):
        runtime = original_build(**values)
        setattr(runtime, attribute, object())
        return runtime

    case["builder"].build_execution = build
    with pytest.raises(InstalledStrixV2CompositionError, match="owner changed"):
        _execute(case)
    assert case["events"][-1] == "abort"


def test_cancellation_bound_to_different_dispatch_authority_is_refused():
    case = _openers()
    original_begin = case["execution_factory"].begin_execution

    def begin(**values):
        transaction = original_begin(**values)
        original_allocate = transaction.allocate

        def allocate():
            resources = original_allocate()
            resources.exec_attachment.cancellation_authority = _CancellationAuthority(
                _DispatchAuthority(case["snapshot"].activation),
                case["snapshot"].activation,
            )
            return resources

        transaction.allocate = allocate
        return transaction

    case["execution_factory"].begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="owners differ"):
        _execute(case)


def test_test_model_lease_cannot_be_relabelled_live():
    case = _openers()
    original_begin = case["execution_factory"].begin_execution

    def begin(**values):
        transaction = original_begin(**values)
        original_allocate = transaction.allocate

        def allocate():
            resources = original_allocate()
            resources.model_gateway_lease.provider_kind = "live"
            resources.model_gateway_lease.live_model_proof = True
            return resources

        transaction.allocate = allocate
        return transaction

    case["execution_factory"].begin_execution = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="lease is incomplete"):
        _execute(case)


def test_semantically_different_network_authority_is_refused_despite_matching_digest_field():
    case = _openers()
    changed = replace(case["delegation"], network_policy_digest=_digest("other-network"))
    raw = case["snapshot"].admission.to_dict()
    raw["delegation_digest"] = changed.delegation_digest
    raw["accepted_execution_claim"]["delegation_digest"] = changed.delegation_digest
    raw["accepted_execution_claim"]["claim_ref"] = _claim_reference(raw["accepted_execution_claim"])
    raw["accepted_execution_claim_ref"] = raw["accepted_execution_claim"]["claim_ref"]
    admission = StrixControlledRuntimeAdmissionV2.from_mapping(raw)
    accepted = replace(
        case["accepted"],
        delegation_digest=changed.delegation_digest,
        claim_ref=raw["accepted_execution_claim_ref"],
    )
    snapshot = replace(case["snapshot"], admission=admission)
    with pytest.raises(InstalledStrixV2CompositionError, match="differs from authority"):
        snapshot.validate(accepted=accepted, binding=case["binding"], delegation=changed)


def test_reconciliation_uses_historical_identity_and_never_receives_launch_material(
    monkeypatch,
):
    case = _openers()
    saved_record = EngineAttemptRecord.create(case["binding"])
    reference = _digest("reconciliation")
    identity = _runtime_identity(
        case["accepted"],
        case["binding"],
        case["delegation"],
        case["snapshot"],
        case["plan"],
    )
    historical = InstalledStrixV2HistoricalSnapshot.create(
        resolution_ref=case["accepted"].runtime_resolution_ref,
        saved_record=saved_record,
        reconciliation_ref=reference,
        identity=identity,
        activation=case["snapshot"].activation,
    )
    case["source"].reconciliation = historical
    monkeypatch.setattr(
        "bluefire.engine_installed_v2_authority.build_controlled_launch_plan",
        lambda *_args, **_values: (_ for _ in ()).throw(
            AssertionError("historical recovery must not derive a current launch")
        ),
    )
    bundle = case["openers"].reopen_reconciliation(
        product_store=case["store"],
        accepted=case["accepted"],
        binding=case["binding"],
        delegation=case["delegation"],
        saved_record=saved_record,
        reconciliation_ref=reference,
    )
    assert case["source"].current_calls == 0
    assert bundle.identity is identity
    factory_call = case["reconciliation_factory"].calls[0]
    builder_call = case["builder"].reconciliation_calls[0]
    assert "launch_plan" not in factory_call
    assert "launch_plan" not in builder_call
    assert "authority_guard" not in builder_call
    assert not callable(getattr(bundle.runtime, "execute", None))
    assert tuple(row.role for row in bundle.resources) == (
        INSTALLED_STRIX_RECONCILIATION_RESOURCE_ROLES
    )


@pytest.mark.parametrize(
    ("activation_field", "identity_field"),
    [
        ("runtime_resolution_ref", "runtime_resolution_ref"),
        ("claim_ref", "claim_ref"),
        ("network_policy_digest", None),
        ("custody_plan_digest", None),
    ],
)
def test_reconciliation_refuses_cross_claim_historical_activation(
    activation_field,
    identity_field,
):
    case = _openers()
    saved_record, reconciliation_ref, identity = _prepare_reconciliation(case)
    activation = case["snapshot"].activation
    values = {
        name: getattr(activation, name)
        for name in activation.__dataclass_fields__
        if name not in {"schema_version", "receipt_ref"}
    }
    changed_ref = _digest("cross-claim-" + activation_field)
    values[activation_field] = changed_ref
    changed_activation = InstalledStrixV2ActivationReceipt.create(**values)
    identity_changes = {"runtime_activation_ref": changed_activation.receipt_ref}
    if identity_field is not None:
        identity_changes[identity_field] = changed_ref
    changed_identity = _replace_identity(identity, **identity_changes)
    case["source"].reconciliation = InstalledStrixV2HistoricalSnapshot.create(
        resolution_ref=case["accepted"].runtime_resolution_ref,
        saved_record=saved_record,
        reconciliation_ref=reconciliation_ref,
        identity=changed_identity,
        activation=changed_activation,
    )
    with pytest.raises(InstalledStrixV2CompositionError, match="historical runtime binding"):
        _reconcile(case, saved_record, reconciliation_ref)


def test_reconciliation_runtime_cannot_replace_cleanup_owner():
    case = _openers()
    saved_record, reconciliation_ref, _identity = _prepare_reconciliation(case)
    original_build = case["builder"].build_reconciliation

    def build(**values):
        runtime = original_build(**values)
        runtime.installed_target_observation = object()
        return runtime

    case["builder"].build_reconciliation = build
    with pytest.raises(InstalledStrixV2CompositionError, match="ignored a cleanup owner"):
        _reconcile(case, saved_record, reconciliation_ref)
    assert case["events"][-1] == "reconciliation-abort"


def test_reconciliation_refuses_launch_capable_owner_and_runtime():
    case = _openers()
    saved_record, reconciliation_ref, _identity = _prepare_reconciliation(case)
    original_begin = case["reconciliation_factory"].begin_reconciliation

    def begin(**values):
        transaction = original_begin(**values)
        original_reopen = transaction.reopen

        def reopen():
            resources = original_reopen()
            rows = list(resources.resources)
            row = rows[0]
            rows[0] = InstalledStrixOwnedResource(
                row.role,
                row.binding_ref,
                _LaunchCapableOwner(case["events"], row.role),
            )
            receipt = InstalledStrixV2ResourceReceipt.create(
                action="reopened",
                authority_ref=case["source"].reconciliation.authority_ref,
                activation_receipt_ref=case["snapshot"].activation.receipt_ref,
                role_bindings=tuple((item.role, item.binding_ref) for item in rows),
                reconciliation_ref=reconciliation_ref,
            )
            return InstalledStrixV2ReopenedResources(tuple(rows), receipt)

        transaction.reopen = reopen
        return transaction

    case["reconciliation_factory"].begin_reconciliation = begin
    with pytest.raises(InstalledStrixV2CompositionError, match="can launch work"):
        _reconcile(case, saved_record, reconciliation_ref)

    case = _openers()
    saved_record, reconciliation_ref, _identity = _prepare_reconciliation(case)
    original_build = case["builder"].build_reconciliation

    def build(**values):
        runtime = original_build(**values)
        runtime.launch = lambda: None
        return runtime

    case["builder"].build_reconciliation = build
    with pytest.raises(InstalledStrixV2CompositionError, match="can execute"):
        _reconcile(case, saved_record, reconciliation_ref)


def test_other_store_or_resolution_refuses_before_any_protected_source_read():
    case = _openers()
    with pytest.raises(InstalledStrixV2CompositionError, match="another service"):
        case["openers"].open_execution(
            product_store=object(),
            accepted=case["accepted"],
            binding=case["binding"],
            delegation=case["delegation"],
            runtime_resolution=case["resolution"],
        )
    assert case["source"].current_calls == 0


def test_test_caido_provider_is_distinct_and_can_never_satisfy_live_proof():
    _binding, _delegation, _accepted, _plan, snapshot = _case()
    activation = snapshot.activation
    test_identity = _digest("caido-test-wire-provider")
    values = {
        name: getattr(activation, name)
        for name in activation.__dataclass_fields__
        if name not in {"schema_version", "receipt_ref"}
    }
    values.update(
        caido_mode="test_protocol_provider",
        caido_test_provider=True,
        caido_provider_identity_ref=test_identity,
        caido_terms_acceptance_ref=None,
        caido_entitlement_ref=None,
        caido_live_proof=False,
        role_bindings=tuple(
            (role, test_identity if role == "caido_channel" else binding_ref)
            for role, binding_ref in activation.role_bindings
        ),
    )
    test_activation = InstalledStrixV2ActivationReceipt.create(**values)
    assert test_activation.caido_mode == "test_protocol_provider"
    assert test_activation.caido_test_provider is True
    assert test_activation.caido_live_proof is False
    with pytest.raises(InstalledStrixV2CompositionError, match="cannot satisfy live proof"):
        replace(test_activation, caido_live_proof=True)

    real_values = dict(values)
    real_values.update(
        caido_mode="real_sidecar",
        caido_test_provider=False,
        caido_terms_acceptance_ref=None,
        caido_entitlement_ref=None,
    )
    with pytest.raises(InstalledStrixV2CompositionError, match="terms acceptance"):
        InstalledStrixV2ActivationReceipt.create(**real_values)
    with pytest.raises(InstalledStrixV2CompositionError, match="live model proof"):
        replace(test_activation, model_live_proof=True)
