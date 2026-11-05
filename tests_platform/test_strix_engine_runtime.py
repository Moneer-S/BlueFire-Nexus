from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, cast

import pytest

from bluefire.engine_artifact_store import (
    _CONTROLLER_SOURCE_AUTHORITY,
    MAX_SOURCE_TREE_ENTRIES,
    EngineArtifactPublicationUnknown,
    EngineArtifactStore,
    EngineArtifactStoreError,
    ReopenedEngineArtifact,
    ReopenedEngineArtifactAttempt,
    SourceCollectionSeal,
    source_collection_tree_digest,
)
from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
    EvidenceCategory,
)
from bluefire.engine_container_custody import ContainerCustodyPlan
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION, CleanupState
from bluefire.engine_network_policy import (
    EffectiveNetworkSnapshot,
    EndpointRole,
    EngineNetworkPlan,
    NetworkFlow,
    NetworkProbeResult,
    ResolutionBinding,
    required_probe_matrix,
    verify_effective_network,
)
from bluefire.engine_worker_runtime import (
    EngineCleanupState,
    EngineExecutionState,
    EngineLogReceipt,
    EngineWorkerOutcome,
    ResourceCustodySnapshot,
    ResourceCustodyState,
)
from bluefire.strix_adapter import (
    StrixBudgets,
    StrixBuildIdentity,
    StrixModelGateway,
    StrixRuntimeLimits,
    StrixScope,
    prepare_attempt_workspace,
)
from bluefire.strix_engine_runtime import (
    ProcessContainmentReceipt,
    ProtectedRuntimeRootsReceipt,
    StrixEngineRuntime,
    StrixEngineRuntimeError,
    StrixRuntimeAdmission,
    StrixRuntimeAdmissionResolution,
    _optional_strix_artifact_names,
)
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import content_hash, file_hash

ENGINE_ATTEMPT = "engine-attempt-" + "a" * 32
ADAPTER_ATTEMPT = "attempt-" + "a" * 32
EXPERIMENT = "experiment-" + "1" * 32
RUN = "run-20261104T120100Z-" + "a" * 16
OBJECTIVE = "Assess the admitted generated tenant-record lab only."
NOW = "2026-11-04T12:00:00Z"
STARTED = "2026-11-04T12:01:00Z"
COMPLETED = "2026-11-04T12:02:00Z"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def root_digest(path: Path) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.engine-runtime-root-identity.v1",
            "resolved_path": str(path.resolve(strict=True)),
        }
    )


class Context:
    def __init__(self) -> None:
        self.cancellation_event = threading.Event()


class Custody:
    def __init__(self) -> None:
        self.stop_calls = 0

    def inspect(self, attempt_id: str, **values: Any) -> ResourceCustodySnapshot:
        del attempt_id, values
        return ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)

    def stop_owned(self, attempt_id: str, **values: Any) -> ResourceCustodySnapshot:
        del attempt_id, values
        self.stop_calls += 1
        return ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)

    def reconcile_stop_owned(self, attempt_id: str, **values: Any) -> ResourceCustodySnapshot:
        assert values["reconciliation_ref"] == digest("b")
        return self.stop_owned(attempt_id, **values)


class Lease:
    def __init__(
        self,
        authorization_ref: str,
        events: list[str],
        *,
        fail_revoke: bool = False,
    ) -> None:
        self._authorization_ref = authorization_ref
        self.events = events
        self.fail_revoke = fail_revoke

    @property
    def authorization_ref(self) -> str:
        return self._authorization_ref

    def secret_value(self) -> str:
        self.events.append("secret")
        return "attempt-scoped-controlled-provider-token"

    def revoke(self) -> str:
        self.events.append("revoked")
        if self.fail_revoke:
            raise RuntimeError("credential revocation unavailable")
        return digest("e")


class Credentials:
    def __init__(self, authorization_ref: str, events: list[str]) -> None:
        self.authorization_ref = authorization_ref
        self.events = events
        self.reconcile_calls = 0
        self.fail_revoke = False

    def acquire(self, binding, delegation):
        del binding, delegation
        self.events.append("lease")
        return Lease(
            self.authorization_ref,
            self.events,
            fail_revoke=self.fail_revoke,
        )

    def reconcile_revocation(self, binding, delegation):
        del binding, delegation
        self.reconcile_calls += 1
        self.events.append("reconciled-revocation")
        return digest("e")

    def reconcile_revocation_claimed(self, binding, delegation, **values: Any) -> str:
        assert values["reconciliation_ref"] == digest("b")
        return self.reconcile_revocation(binding, delegation)


class FakeArtifactStore:
    max_file_bytes = 1024 * 1024
    max_total_bytes = 4 * 1024 * 1024
    max_files = 64

    def __init__(self, events: list[str], root: Path, *, drift_digest: bool = False) -> None:
        self.events = events
        self.root = root
        self.drift_digest = drift_digest
        self.names: tuple[str, ...] = ()
        self.reopened: ReopenedEngineArtifactAttempt | None = None

    def import_or_reopen(self, **values: Any) -> ReopenedEngineArtifactAttempt:
        assert self.events[-1] == "sealed"
        self.events.append("imported")
        self.names = tuple(values["allowed_names"])
        seal = cast(SourceCollectionSeal, values["source_seal"])
        source = cast(Path, values["source_run_dir"])
        artifacts = tuple(
            ReopenedEngineArtifact(
                name=name,
                size_bytes=len(payload),
                sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
                payload=payload,
            )
            for name in self.names
            for payload in ((source / name).read_bytes(),)
        )
        if self.drift_digest:
            artifacts = (replace(artifacts[0], sha256=digest("f")), *artifacts[1:])
        publication_binding = values["publication_binding"]
        seal_document = seal.to_dict()
        seal_ref = content_hash(seal_document)
        total_bytes = sum(item.size_bytes for item in artifacts)
        identity = {
            "schema_version": "bluefire.engine-artifact-publication-ref.v1",
            "attempt_id": values["attempt_id"],
            "source_collection_receipt": seal.controller_receipt_digest,
            "source_tree_digest": seal.source_tree_digest,
            "source_collection_seal_ref": seal_ref,
            "source_collection_seal": seal_document,
            "publication_binding": publication_binding.to_dict(),
            "artifact_count": len(artifacts),
            "total_bytes": total_bytes,
            "artifacts": [item.to_manifest_row() for item in artifacts],
        }
        reopened = ReopenedEngineArtifactAttempt(
            schema_version="bluefire.engine-artifacts.v2",
            attempt_id=values["attempt_id"],
            storage_boundary="contained_exclusive_protected_root",
            source_collection_receipt=seal.controller_receipt_digest,
            source_tree_digest=seal.source_tree_digest,
            source_collection_seal_ref=seal_ref,
            source_collection_seal=seal,
            artifact_publication_ref=content_hash(identity),
            publication_binding=publication_binding,
            artifacts=artifacts,
            total_bytes=total_bytes,
            manifest_ref=digest("0"),
            recovery_eligible=True,
        )
        self.reopened = replace(reopened, manifest_ref=content_hash(reopened.to_manifest()))
        return self.reopened

    def reopen_attempt(self, attempt_id: str) -> ReopenedEngineArtifactAttempt:
        if self.reopened is None:
            raise EngineArtifactStoreError("artifact publication is unavailable")
        assert self.reopened.attempt_id == attempt_id
        return self.reopened


class SourceController:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reconcile_calls = 0

    def seal(self, *, attempt_id: str, source_run_dir: Path, worker_outcome):
        if worker_outcome is not None:
            assert worker_outcome.cleanup_state is EngineCleanupState.VERIFIED
            assert worker_outcome.custody_after.state is ResourceCustodyState.VERIFIED_ABSENT
        assert self.events[-1] in {"revoked", "reconciled-revocation"}
        details = source_run_dir.lstat()
        document = {
            "schema_version": "bluefire.engine-source-collection-seal.v1",
            "attempt_id": attempt_id,
            "source_root_device": details.st_dev,
            "source_root_inode": details.st_ino,
            "source_root_mtime_ns": details.st_mtime_ns,
            "source_tree_digest": source_collection_tree_digest(source_run_dir),
            "worker_state": "stopped",
            "write_access_revoked": True,
            "controller_receipt_digest": digest("d"),
        }
        self.events.append("sealed")
        return SourceCollectionSeal.from_mapping(
            document,
            _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
        )

    def reconcile_seal(self, *, reconciliation_ref: str, timeout_seconds: float, **values: Any):
        assert reconciliation_ref == digest("b")
        assert timeout_seconds > 0
        self.reconcile_calls += 1
        return self.seal(**values)


class Worker:
    def __init__(self, events: list[str], *, retain_outcome: bool = True) -> None:
        self.events = events
        self.run_calls = 0
        self.retain_outcome = retain_outcome

    def run(self, plan, *, cancellation, custody):
        assert not cancellation.is_set()
        assert custody is not None
        self.run_calls += 1
        self.events.append("worker")
        environment = plan.exact_environment
        assert environment["LLM_API_KEY"] == "attempt-scoped-controlled-provider-token"
        assert "attempt-scoped-controlled-provider-token" not in json.dumps(
            plan.public_launch_receipt()
        )
        run_dir = plan.working_directory / "strix_runs" / "upstream-run-1"
        run_dir.mkdir(parents=True)
        instruction = (plan.working_directory / "objective.txt").read_text(encoding="utf-8").strip()
        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "run_id": "upstream-run-1",
                    "run_name": "upstream-run-1",
                    "status": "completed",
                    "non_interactive": True,
                    "scan_mode": "quick",
                    "scope_mode": "full",
                    "targets_info": [
                        {
                            "type": "web_application",
                            "details": {"target_url": plan.exact_environment["BF_TEST_TARGET"]}
                            if "BF_TEST_TARGET" in plan.exact_environment
                            else {"target_url": plan.argv[plan.argv.index("--target") + 1]},
                            "original": plan.argv[plan.argv.index("--target") + 1],
                        }
                    ],
                    "instruction": instruction,
                }
            ),
            encoding="utf-8",
        )
        (run_dir / "coverage.json").write_text(
            json.dumps(
                {
                    "run_id": "upstream-run-1",
                    "run_name": "upstream-run-1",
                    "completeness": {
                        "complete": True,
                        "scan_status": "completed",
                        "exit_reason": "completed",
                        "caveats": [],
                    },
                }
            ),
            encoding="utf-8",
        )
        absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
        outcome = EngineWorkerOutcome(
            attempt_id=plan.attempt_id,
            execution_state=EngineExecutionState.EXITED,
            cleanup_state=EngineCleanupState.VERIFIED,
            started=True,
            exit_code=0,
            started_at=STARTED,
            completed_at=COMPLETED,
            stdout=EngineLogReceipt("worker.stdout.bin", 0, digest("1"), False),
            stderr=EngineLogReceipt("worker.stderr.bin", 0, digest("2"), False),
            custody_before=absent,
            custody_after=absent,
            issues=(),
        )
        if self.retain_outcome:
            control = plan.control_root / plan.attempt_id
            control.mkdir()
            reservation = plan.public_launch_receipt()
            reservation["reserved_at"] = STARTED
            (control / "launch.json").write_text(json.dumps(reservation), encoding="utf-8")
            (control / "outcome.json").write_text(json.dumps(outcome.to_dict()), encoding="utf-8")
        return outcome


class OutputWorker(Worker):
    def __init__(
        self,
        events: list[str],
        *,
        outputs: dict[str, bytes],
        execution_state: EngineExecutionState = EngineExecutionState.EXITED,
        cleanup_state: EngineCleanupState = EngineCleanupState.VERIFIED,
        post_run: Callable[[Path], None] | None = None,
    ) -> None:
        super().__init__(events)
        self.outputs = outputs
        self.execution_state = execution_state
        self.cleanup_state = cleanup_state
        self.post_run = post_run

    def run(self, plan, *, cancellation, custody):
        outcome = super().run(plan, cancellation=cancellation, custody=custody)
        run_directory = plan.working_directory / "strix_runs" / "upstream-run-1"
        for name, payload in self.outputs.items():
            target = run_directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        if self.post_run is not None:
            self.post_run(run_directory)
        if (
            self.execution_state is not EngineExecutionState.EXITED
            or self.cleanup_state is not EngineCleanupState.VERIFIED
        ):
            outcome = replace(
                outcome,
                execution_state=self.execution_state,
                cleanup_state=self.cleanup_state,
            )
            control = plan.control_root / plan.attempt_id
            (control / "outcome.json").write_text(json.dumps(outcome.to_dict()), encoding="utf-8")
        return outcome


class Resolver:
    def __init__(
        self,
        admission: StrixRuntimeAdmission,
        *,
        on_require_current: Callable[[int], None] | None = None,
    ) -> None:
        self.admission = admission
        self.resolution_ref = digest("e")
        self.require_current_calls = 0
        self.on_require_current = on_require_current

    def resolve(self, binding, delegation):
        del binding, delegation
        return self.admission

    def resolve_for_launch(self, binding, delegation):
        del binding, delegation
        return StrixRuntimeAdmissionResolution(self.admission, self.resolution_ref)

    def require_current(self, binding, delegation, *, expected_resolution_ref):
        del binding, delegation
        self.require_current_calls += 1
        if self.on_require_current is not None:
            self.on_require_current(self.require_current_calls)
        if expected_resolution_ref != self.resolution_ref:
            raise RuntimeError("runtime admission changed")
        return StrixRuntimeAdmissionResolution(self.admission, self.resolution_ref)


def _build(executable: Path) -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256=digest("1"),
        package_sha256=digest("2"),
        executable_sha256=file_hash(executable),
        image_reference="ghcr.io/usestrix/sandbox@sha256:" + "3" * 64,
        image_inventory_sha256=digest("4"),
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )


def _network(
    *,
    created_at: str = NOW,
    captured_at: str = NOW,
    checked_at: str = NOW,
):
    plan = EngineNetworkPlan.create(
        attempt_id=ENGINE_ATTEMPT,
        network_identity_ref=digest("5"),
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=created_at,
    )
    snapshot = EffectiveNetworkSnapshot(
        schema_version="bluefire.engine-network-snapshot.v1",
        attempt_id=plan.attempt_id,
        policy_digest=plan.policy_digest,
        network_identity_ref=plan.network_identity_ref,
        network_name=plan.network_name,
        subnet=plan.subnet,
        controller_address=plan.controller_address,
        daemon_address=plan.daemon_address,
        enforcer_ref=digest("6"),
        captured_at=captured_at,
        attached_network_identity_refs=(plan.network_identity_ref,),
        allowed_flows=(
            NetworkFlow(EndpointRole.TARGET, plan.target.address, plan.target.port),
            NetworkFlow(
                EndpointRole.MODEL_GATEWAY,
                plan.model_gateway.address,
                plan.model_gateway.port,
            ),
        ),
        resolution_bindings=(
            ResolutionBinding(
                EndpointRole.TARGET, plan.target.service_name, (plan.target.address,)
            ),
            ResolutionBinding(
                EndpointRole.MODEL_GATEWAY,
                plan.model_gateway.service_name,
                (plan.model_gateway.address,),
            ),
        ),
        blocked_classes=(
            "controller",
            "daemon",
            "host_gateway",
            "link_local",
            "metadata",
            "other_egress",
            "public_dns",
        ),
        default_egress_deny=True,
        public_dns_blocked=True,
        metadata_blocked=True,
        host_gateway_blocked=True,
        controller_blocked=True,
        daemon_tcp_disabled=True,
        management_socket_exposed=False,
        redirects_revalidated=True,
        single_network_attachment=True,
        host_network_disabled=True,
        overlapping_host_routes_absent=True,
        host_loopback_unreachable=True,
    )
    probes = tuple(
        NetworkProbeResult(name, address, port, expected)
        for name, address, port, expected in required_probe_matrix(plan)
    )
    verification = verify_effective_network(plan, snapshot, probes, checked_at=checked_at)
    return plan, snapshot, verification


def _custody(network_policy_digest: str) -> ContainerCustodyPlan:
    return ContainerCustodyPlan.from_mapping(
        {
            "schema_version": "bluefire.engine-container-custody.v1",
            "attempt_id": ENGINE_ATTEMPT,
            "daemon_instance_digest": digest("7"),
            "disposable_boundary_ref": digest("8"),
            "baseline_inventory_digest": digest("9"),
            "required_labels": {"bluefire.engine.attempt": ENGINE_ATTEMPT},
            "sandbox_image_digest": digest("3"),
            "network_id": "1" * 64,
            "network_policy_digest": network_policy_digest,
            "expected_mounts": [
                {
                    "mount_type": "tmpfs",
                    "source": "",
                    "destination": "/workspace",
                    "read_only": False,
                    "options_digest": digest("a"),
                }
            ],
            "expected_capabilities": ["NET_ADMIN", "NET_RAW"],
            "expected_user": "1000:1000",
            "memory_bytes": 2 * 1024**3,
            "nano_cpus": 2_000_000_000,
            "pids_limit": 512,
            "expected_container_count": 1,
        }
    )


def _fixture(
    tmp_path: Path,
    *,
    network_created_at: str = NOW,
    network_captured_at: str = NOW,
    network_checked_at: str = NOW,
):
    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed Strix executable")
    build = _build(executable)
    network, snapshot, verification = _network(
        created_at=network_created_at,
        captured_at=network_captured_at,
        checked_at=network_checked_at,
    )
    custody_plan = _custody(network.policy_digest)
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": EXPERIMENT,
            "attempt_id": ENGINE_ATTEMPT,
            "run_id": RUN,
            "role": AttemptRole.BASELINE.value,
            "objective_ref": digest("b"),
            "environment_ref": digest("c"),
            "target_snapshot_ref": digest("d"),
            "scope_ref": digest("e"),
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "engine_id": "strix",
            "engine_version": build.package_version,
            "engine_revision": build.source_revision,
            "engine_package_digest": build.package_sha256,
            "policy_overlay_digest": build.prompt_overlay_sha256,
            "model_provider": "provider.test",
            "model_id": "controlled-test-provider",
            "model_data_destination": network.model_gateway.origin + "/v1",
            "model_authorization_ref": digest("f"),
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": STARTED,
            "parent_attempt_id": None,
        }
    )
    delegation = EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "1" * 32,
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
        role=binding.role,
        parent_attempt_id=binding.parent_attempt_id,
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
        custody_plan_digest=custody_plan.plan_digest,
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
        created_at=NOW,
        expires_at="2026-11-04T12:05:00Z",
    )
    attempts = tmp_path / "attempts"
    attempts.mkdir()
    workspace = prepare_attempt_workspace(attempts, attempt_id=ADAPTER_ATTEMPT, objective=OBJECTIVE)
    control = tmp_path / "controller"
    control.mkdir()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    protected_roots = ProtectedRuntimeRootsReceipt(
        schema_version="bluefire.engine-protected-runtime-roots.v1",
        attempt_id=binding.attempt_id,
        workspace_root_digest=root_digest(workspace.cwd),
        control_root_digest=root_digest(control),
        artifact_root_digest=root_digest(artifact_root),
        verifier_ref=digest("0"),
        checked_at=NOW,
        control_root_protected=True,
        artifact_root_protected=True,
        engine_control_write_denied=True,
        engine_artifact_write_denied=True,
    )
    admission = StrixRuntimeAdmission(
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        runtime_qualification_ref=digest("1"),
        runtime_qualified=True,
        build=build,
        scope=StrixScope(
            target=network.target.origin + "/",
            resolved_addresses=(network.target.address,),
            target_snapshot_digest=binding.target_snapshot_ref,
            scope_digest=binding.scope_ref,
            network_policy_digest=network.policy_digest,
            network_name=network.network_name,
        ),
        gateway=StrixModelGateway(
            model=binding.model_id,
            base_url=binding.model_data_destination,
            authorization_digest=binding.model_authorization_ref,
        ),
        budgets=StrixBudgets(300, 20, "1"),
        limits=StrixRuntimeLimits(),
        workspace=workspace,
        executable=executable.resolve(),
        path_environment="/reviewed/bin",
        control_root=control,
        network_plan=network,
        network_snapshot=snapshot,
        network_verification=verification,
        custody_plan=custody_plan,
        protected_roots=protected_roots,
        containment=ProcessContainmentReceipt(
            schema_version="bluefire.engine-process-containment.v1",
            attempt_id=binding.attempt_id,
            binding_digest=binding.binding_digest,
            executable_sha256=build.executable_sha256,
            network_policy_digest=network.policy_digest,
            custody_plan_digest=custody_plan.plan_digest,
            protected_roots_digest=protected_roots.receipt_digest,
            disposable_boundary_ref=custody_plan.disposable_boundary_ref,
            supervisor_ref=digest("2"),
            checked_at=NOW,
            effective=True,
        ),
        custody=Custody(),
    )
    return binding, delegation, admission


def _runtime(tmp_path: Path):
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events)
    artifacts = FakeArtifactStore(events, tmp_path / "artifacts")
    credentials = Credentials(binding.model_authorization_ref, events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, artifacts),
        credential_provider=credentials,
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )
    return runtime, binding, delegation, admission, worker, artifacts, credentials, events


def _output_runtime(
    tmp_path: Path,
    *,
    outputs: dict[str, bytes],
    execution_state: EngineExecutionState = EngineExecutionState.EXITED,
    cleanup_state: EngineCleanupState = EngineCleanupState.VERIFIED,
    post_run: Callable[[Path], None] | None = None,
    artifact_store_factory: Callable[[list[str], Path], Any] | None = None,
    source_controller_factory: Callable[[list[str]], Any] | None = None,
):
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = OutputWorker(
        events,
        outputs=outputs,
        execution_state=execution_state,
        cleanup_state=cleanup_state,
        post_run=post_run,
    )
    artifacts = (
        artifact_store_factory(events, tmp_path / "artifacts")
        if artifact_store_factory is not None
        else FakeArtifactStore(events, tmp_path / "artifacts")
    )
    if isinstance(artifacts, EngineArtifactStore):
        protected_roots = replace(
            admission.protected_roots,
            artifact_root_digest=root_digest(artifacts.root),
        )
        admission = replace(
            admission,
            protected_roots=protected_roots,
            containment=replace(
                admission.containment,
                protected_roots_digest=protected_roots.receipt_digest,
            ),
        )
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, artifacts),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=(
            source_controller_factory(events)
            if source_controller_factory is not None
            else SourceController(events)
        ),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )
    return runtime, binding, delegation, admission, worker, artifacts, events


def test_execute_binds_exact_plan_revokes_before_intake_and_retains_only_engine_claims(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, _admission, worker, artifacts, _credentials, events = _runtime(
        tmp_path
    )
    transitions = []

    settlement = runtime.execute(
        cast(Any, Context()),
        binding,
        delegation,
        lambda record, timestamp: transitions.append((record, timestamp)),
    )

    assert worker.run_calls == 1
    assert cast(Resolver, runtime._resolver).require_current_calls == 2
    assert events == ["lease", "secret", "worker", "revoked", "sealed", "imported"]
    assert [record.state for record, _timestamp in transitions] == [AttemptState.RUNNING]
    assert settlement.record.state is AttemptState.COMPLETED
    assert settlement.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert settlement.artifact_manifest_ref is not None
    assert len(settlement.engine_evidence) == 1
    assert settlement.engine_evidence[0].category is EvidenceCategory.ENGINE_ASSERTION
    assert settlement.engine_evidence[0].content["security_outcome"] == (
        "not_independently_established"
    )
    assert artifacts.names == (
        "strix_runs/upstream-run-1/coverage.json",
        "strix_runs/upstream-run-1/run.json",
    )


def test_retains_present_findings_and_reports_without_private_state(tmp_path: Path) -> None:
    outputs = {
        "vulnerabilities.json": b'[{"id":"finding-one"}]',
        "vulnerabilities.csv": b"id,title\nfinding-one,Example\n",
        "vulnerabilities/finding-one.md": b"# Engine finding\n",
        "penetration_test_report.md": b"# Engine report\n",
        "findings.sarif": b'{"version":"2.1.0"}',
        "strix.log": b"private log content",
        ".state/agents.db": b"private runtime database",
    }
    runtime, binding, delegation, _admission, _worker, store, _events = _output_runtime(
        tmp_path,
        outputs=outputs,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.COMPLETED
    assert settlement.artifact_manifest_ref is not None
    assert settlement.engine_evidence[0].category is EvidenceCategory.ENGINE_ASSERTION
    prefix = "strix_runs/upstream-run-1/"
    assert set(store.names) == {
        prefix + "run.json",
        prefix + "coverage.json",
        *(prefix + name for name in outputs if not name.startswith((".state/", "strix.log"))),
    }


def test_real_store_preserves_optional_raw_bytes_and_excludes_private_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        # The ephemeral test root has an AppContainer ACL. The store still
        # exercises its real publication, inventory, hash and reopen logic.
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_protected_root",
            staticmethod(lambda _path: None),
        )
        monkeypatch.setattr(
            "bluefire.engine_artifact_store.verify_owner_private_acl",
            lambda _descriptor, *, directory: None,
        )
    outputs = {
        "vulnerabilities.json": b'[{"id":"finding-one"}]',
        "vulnerabilities/finding-one.md": b"# Engine finding\n",
        "penetration_test_report.md": b"# Engine report\n",
        "strix.log": b"private log content",
        ".state/agents.db": b"private runtime database",
    }

    def store_factory(_events: list[str], root: Path) -> EngineArtifactStore:
        root.chmod(0o700)
        return EngineArtifactStore(
            root, max_file_bytes=1024 * 1024, max_total_bytes=4 * 1024 * 1024
        )

    runtime, binding, delegation, admission, _worker, store, _events = _output_runtime(
        tmp_path, outputs=outputs, artifact_store_factory=store_factory
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.COMPLETED
    assert settlement.artifact_manifest_ref is not None
    raw_root = store.root / ENGINE_ATTEMPT / "raw" / "strix_runs" / "upstream-run-1"
    for name, payload in outputs.items():
        retained = raw_root / name
        if name.startswith((".state/", "strix.log")):
            assert not retained.exists()
        else:
            assert retained.read_bytes() == payload

    class RecoveryOnlyResolver(Resolver):
        def resolve_for_launch(self, binding, delegation):
            pytest.fail("claimed recovery called the launch resolver")

        def require_current(self, binding, delegation, *, expected_resolution_ref):
            pytest.fail("claimed recovery rechecked launch authority")

    shutil.rmtree(admission.workspace.cwd)
    recovery_worker = Worker([])
    restarted_store = EngineArtifactStore(
        store.root,
        max_file_bytes=store.max_file_bytes,
        max_total_bytes=store.max_total_bytes,
        max_files=store.max_files,
    )
    recovered_runtime = StrixEngineRuntime(
        resolver=RecoveryOnlyResolver(admission),
        worker=cast(Any, recovery_worker),
        artifact_store=restarted_store,
        credential_provider=Credentials(binding.model_authorization_ref, []),
        source_controller=SourceController([]),
        clock=lambda: "2026-11-05T00:00:00Z",
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )
    recovered = recovered_runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )
    repeated = recovered_runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )
    assert recovery_worker.run_calls == 0
    assert recovered.cleanup_evidence_ref == settlement.cleanup_evidence_ref
    assert repeated.cleanup_evidence_ref == settlement.cleanup_evidence_ref
    assert recovered.artifact_manifest_ref == settlement.artifact_manifest_ref
    assert repeated.artifact_manifest_ref == settlement.artifact_manifest_ref
    assert [item.to_dict() for item in recovered.engine_evidence] == [
        item.to_dict() for item in settlement.engine_evidence
    ]


def test_optional_selector_bounds_ignored_entries_before_store_intake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_directory = tmp_path / "strix_runs" / "upstream-run-1"
    run_directory.mkdir(parents=True)

    class ManyEntries:
        def __enter__(self):
            return (
                SimpleNamespace(name=f"ignored-{index}")
                for index in range(MAX_SOURCE_TREE_ENTRIES + 1)
            )

        def __exit__(self, _type, _value, _traceback):
            return None

    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", lambda _path: ManyEntries())
        with pytest.raises(StrixEngineRuntimeError, match="entry bound"):
            _optional_strix_artifact_names(
                run_directory,
                prefix="strix_runs/upstream-run-1",
                max_files=64,
                max_file_bytes=1024,
                required_count=1,
            )


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("vulnerabilities/bad name.md", b"invalid portable filename"),
        ("penetration_test_report.md", b""),
        ("findings.sarif", b"x" * (1024 * 1024 + 1)),
    ],
    ids=("unsafe-name", "empty-report", "oversized-sarif"),
)
def test_present_unsafe_optional_output_fails_closed(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    runtime, binding, delegation, _admission, _worker, artifacts, _events = _output_runtime(
        tmp_path, outputs={name: payload}
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.UNKNOWN
    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert settlement.engine_evidence == ()
    assert artifacts.names == ()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink", "directory_symlink"])
def test_optional_output_link_is_not_imported(tmp_path: Path, link_kind: str) -> None:
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside content")

    def make_link(run_directory: Path) -> None:
        try:
            if link_kind == "directory_symlink":
                (run_directory / "vulnerabilities").symlink_to(tmp_path, target_is_directory=True)
            elif link_kind == "symlink":
                (run_directory / "penetration_test_report.md").symlink_to(outside)
            else:
                os.link(outside, run_directory / "penetration_test_report.md")
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"{link_kind} unavailable: {exc}")

    runtime, binding, delegation, _admission, _worker, artifacts, _events = _output_runtime(
        tmp_path, outputs={}, post_run=make_link
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.UNKNOWN
    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert artifacts.names == ()


def test_optional_output_count_over_store_bound_fails_closed(tmp_path: Path) -> None:
    outputs = {f"vulnerabilities/finding-{index}.md": b"finding" for index in range(3)}

    def store_factory(events: list[str], root: Path) -> FakeArtifactStore:
        store = FakeArtifactStore(events, root)
        store.max_files = 4
        return store

    runtime, binding, delegation, _admission, _worker, artifacts, _events = _output_runtime(
        tmp_path, outputs=outputs, artifact_store_factory=store_factory
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert artifacts.names == ()


def test_claimed_resolution_drift_refuses_before_allocation_or_launch(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events)
    resolver = Resolver(admission)
    claimed_resolution_ref = digest("d")
    assert resolver.resolution_ref != claimed_resolution_ref
    runtime = StrixEngineRuntime(
        resolver=resolver,
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=claimed_resolution_ref,
    )

    with pytest.raises(
        StrixEngineRuntimeError,
        match="differs from the accepted execution claim",
    ):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)

    assert events == []
    assert worker.run_calls == 0
    assert resolver.require_current_calls == 0
    assert list(admission.control_root.iterdir()) == []


@pytest.mark.parametrize("reason", ["expired", "revoked"])
def test_unavailable_claimed_resolution_refuses_before_allocation_or_launch(
    tmp_path: Path,
    reason: str,
) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events)

    class UnavailableResolver(Resolver):
        def resolve_for_launch(self, binding, delegation):
            del binding, delegation
            raise RuntimeError(f"runtime admission {reason}")

    resolver = UnavailableResolver(admission)
    runtime = StrixEngineRuntime(
        resolver=resolver,
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=resolver.resolution_ref,
    )

    with pytest.raises(RuntimeError, match=f"runtime admission {reason}"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)

    assert events == []
    assert worker.run_calls == 0
    assert resolver.require_current_calls == 0
    assert list(admission.control_root.iterdir()) == []


def test_claimed_resolution_is_rechecked_unchanged_at_launch_boundaries(
    tmp_path: Path,
) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events)
    resolver = Resolver(admission)
    runtime = StrixEngineRuntime(
        resolver=resolver,
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=resolver.resolution_ref,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert resolver.require_current_calls == 2
    assert worker.run_calls == 1
    assert settlement.record.state is AttemptState.COMPLETED


@pytest.mark.parametrize(
    ("drift_on_check", "expected_events"),
    [
        (1, []),
        (2, ["lease", "revoked"]),
    ],
)
def test_runtime_authority_drift_before_launch_fails_without_worker_or_secret(
    tmp_path: Path,
    drift_on_check: int,
    expected_events: list[str],
) -> None:
    runtime, binding, delegation, _admission, worker, _artifacts, _credentials, events = _runtime(
        tmp_path
    )
    resolver = cast(Resolver, runtime._resolver)

    def drift(check_number: int) -> None:
        if check_number == drift_on_check:
            resolver.resolution_ref = digest("f")

    resolver.on_require_current = drift

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert resolver.require_current_calls == drift_on_check
    assert events == expected_events
    assert worker.run_calls == 0
    assert settlement.record.state is AttemptState.FAILED
    assert settlement.record.completeness is AttemptCompleteness.UNKNOWN
    assert settlement.record.exit_reason == "runtime_authority_changed_before_launch"
    assert settlement.engine_evidence == ()
    assert settlement.artifact_manifest_ref is None
    assert settlement.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert settlement.cleanup_evidence_ref is not None


@pytest.mark.parametrize(
    ("malformed_on_check", "expected_events"),
    [
        (1, []),
        (2, ["lease", "revoked"]),
    ],
)
def test_malformed_reread_settles_as_prelaunch_authority_failure(
    tmp_path: Path,
    malformed_on_check: int,
    expected_events: list[str],
) -> None:
    runtime, binding, delegation, _admission, worker, _artifacts, _credentials, events = _runtime(
        tmp_path
    )
    resolver = cast(Resolver, runtime._resolver)

    def malformed(check_number: int) -> None:
        if check_number == malformed_on_check:
            raise AttributeError("malformed nested admission")

    resolver.on_require_current = malformed

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert events == expected_events
    assert worker.run_calls == 0
    assert settlement.record.state is AttemptState.FAILED
    assert settlement.record.exit_reason == "runtime_authority_changed_before_launch"
    assert settlement.cleanup_state is CleanupState.VERIFIED_ABSENT


def test_second_reread_failure_records_unverified_credential_revocation(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, _admission, worker, _artifacts, credentials, events = _runtime(
        tmp_path
    )
    resolver = cast(Resolver, runtime._resolver)
    credentials.fail_revoke = True

    def drift(check_number: int) -> None:
        if check_number == 2:
            resolver.resolution_ref = digest("f")

    resolver.on_require_current = drift

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert events == ["lease", "revoked"]
    assert worker.run_calls == 0
    assert settlement.record.exit_reason == "runtime_authority_changed_before_launch"
    assert "Model gateway credential revocation is unverified." in settlement.record.limitations
    assert settlement.cleanup_state is CleanupState.VERIFIED_ABSENT


def test_execute_requires_exact_durable_reservation_and_outcome(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events, retain_outcome=False)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert worker.run_calls == 1
    assert events == ["lease", "secret", "worker", "revoked"]
    assert settlement.record.state is AttemptState.UNKNOWN
    assert settlement.record.exit_reason == "worker_settlement_not_durable"
    assert settlement.engine_evidence == ()
    assert settlement.artifact_manifest_ref is None
    assert settlement.cleanup_state is CleanupState.UNKNOWN
    assert cast(Custody, admission.custody).stop_calls == 1


def test_imported_artifact_digest_drift_cannot_become_engine_evidence(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, Worker(events)),
        artifact_store=cast(
            Any,
            FakeArtifactStore(events, tmp_path / "artifacts", drift_digest=True),
        ),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.UNKNOWN
    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.engine_evidence == ()
    assert settlement.artifact_manifest_ref is None


def test_run_record_changed_after_discovery_cannot_become_engine_evidence(tmp_path: Path) -> None:
    class ChangingRunController(SourceController):
        def seal(self, *, attempt_id: str, source_run_dir: Path, worker_outcome):
            sealed = super().seal(
                attempt_id=attempt_id,
                source_run_dir=source_run_dir,
                worker_outcome=worker_outcome,
            )
            run_record = source_run_dir / "strix_runs" / "upstream-run-1" / "run.json"
            run_record.write_bytes(
                run_record.read_bytes().replace(b"upstream-run-1", b"upstream-run-2")
            )
            return sealed

    runtime, binding, delegation, _admission, _worker, _artifacts, _events = _output_runtime(
        tmp_path,
        outputs={"vulnerabilities.json": b"[]"},
        source_controller_factory=ChangingRunController,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert settlement.engine_evidence == ()


def test_extra_output_added_after_seal_is_rejected_by_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        monkeypatch.setattr(
            EngineArtifactStore,
            "_verify_protected_root",
            staticmethod(lambda _path: None),
        )

    class ChangingTreeController(SourceController):
        def seal(self, *, attempt_id: str, source_run_dir: Path, worker_outcome):
            sealed = super().seal(
                attempt_id=attempt_id,
                source_run_dir=source_run_dir,
                worker_outcome=worker_outcome,
            )
            run_directory = source_run_dir / "strix_runs" / "upstream-run-1"
            (run_directory / "vulnerabilities.csv").write_bytes(b"new source entry")
            current = source_run_dir.lstat()
            os.utime(source_run_dir, ns=(current.st_atime_ns, sealed.source_root_mtime_ns))
            return sealed

    runtime, binding, delegation, _admission, _worker, store, _events = _output_runtime(
        tmp_path,
        outputs={"vulnerabilities.json": b"[]"},
        artifact_store_factory=lambda _events, root: EngineArtifactStore(
            root, max_file_bytes=1024 * 1024, max_total_bytes=4 * 1024 * 1024
        ),
        source_controller_factory=ChangingTreeController,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert settlement.engine_evidence == ()
    assert not (store.root / ENGINE_ATTEMPT).exists()


def test_forged_optional_manifest_row_cannot_become_engine_evidence(tmp_path: Path) -> None:
    class ForgedArtifactStore(FakeArtifactStore):
        def import_or_reopen(self, **values: Any) -> ReopenedEngineArtifactAttempt:
            reopened = super().import_or_reopen(**values)
            forged = replace(
                reopened.artifacts[-1],
                name="strix_runs/upstream-run-1/.state/agents.db",
            )
            return replace(reopened, artifacts=(*reopened.artifacts[:-1], forged))

    runtime, binding, delegation, _admission, _worker, _artifacts, _events = _output_runtime(
        tmp_path,
        outputs={"vulnerabilities.json": b"[]"},
        artifact_store_factory=ForgedArtifactStore,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert settlement.engine_evidence == ()


def test_forged_optional_manifest_size_cannot_become_engine_evidence(tmp_path: Path) -> None:
    class ForgedArtifactStore(FakeArtifactStore):
        def import_or_reopen(self, **values: Any) -> ReopenedEngineArtifactAttempt:
            reopened = super().import_or_reopen(**values)
            forged = replace(reopened.artifacts[-1], size_bytes=self.max_file_bytes + 1)
            return replace(reopened, artifacts=(*reopened.artifacts[:-1], forged))

    runtime, binding, delegation, _admission, _worker, _artifacts, _events = _output_runtime(
        tmp_path,
        outputs={"vulnerabilities.json": b"[]"},
        artifact_store_factory=ForgedArtifactStore,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.exit_reason == "engine_artifacts_unavailable"
    assert settlement.artifact_manifest_ref is None
    assert settlement.engine_evidence == ()


@pytest.mark.parametrize(
    ("cleanup_state", "expected_manifest"),
    [
        (EngineCleanupState.VERIFIED, True),
        (EngineCleanupState.UNKNOWN, False),
    ],
)
def test_cancelled_attempt_retains_outputs_only_after_verified_cessation(
    tmp_path: Path, cleanup_state: EngineCleanupState, expected_manifest: bool
) -> None:
    runtime, binding, delegation, _admission, _worker, artifacts, events = _output_runtime(
        tmp_path,
        outputs={"vulnerabilities.json": b"[]"},
        execution_state=EngineExecutionState.CANCELLED,
        cleanup_state=cleanup_state,
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert settlement.record.state is AttemptState.CANCELLED
    assert (settlement.artifact_manifest_ref is not None) is expected_manifest
    assert ("sealed" in events) is expected_manifest
    assert ("imported" in events) is expected_manifest
    if expected_manifest:
        assert "strix_runs/upstream-run-1/vulnerabilities.json" in artifacts.names
        assert settlement.engine_evidence[0].category is EvidenceCategory.ENGINE_ASSERTION
    else:
        assert artifacts.names == ()
        assert settlement.engine_evidence == ()


def _durable_running(binding: EngineAttemptBinding) -> EngineAttemptRecord:
    return (
        EngineAttemptRecord.create(binding)
        .transition(AttemptState.PREFLIGHT)
        .transition(
            AttemptState.RUNNING,
            upstream_session_id=ADAPTER_ATTEMPT,
            timestamp=STARTED,
        )
    )


def test_legacy_reconcile_cannot_settle_claimed_execution(tmp_path: Path) -> None:
    runtime, binding, delegation, _admission, worker, _store, credentials, _events = _runtime(
        tmp_path
    )
    with pytest.raises(StrixEngineRuntimeError, match="claimed reconciliation"):
        runtime.reconcile(binding, delegation, _durable_running(binding))
    assert worker.run_calls == 0
    assert credentials.reconcile_calls == 0


def test_claimed_recovery_reopens_final_after_source_removal_with_stable_refs(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, admission, worker, store, events = _output_runtime(
        tmp_path, outputs={"vulnerabilities.json": b"[]"}
    )
    first = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )
    assert first.record.state is AttemptState.COMPLETED
    resolver = cast(Resolver, runtime._resolver)
    current_checks = resolver.require_current_calls
    shutil.rmtree(admission.workspace.cwd)
    before = tuple(events)

    recovered = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )
    again = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert worker.run_calls == 1
    assert resolver.require_current_calls == current_checks
    assert events.count("lease") == 1
    assert events.count("secret") == 1
    assert events.count("sealed") == 1
    assert events.count("imported") == 1
    assert tuple(events[: len(before)]) == before
    assert recovered.record.to_dict() == first.record.to_dict()
    assert recovered.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert (
        recovered.artifact_manifest_ref
        == first.artifact_manifest_ref
        == again.artifact_manifest_ref
    )
    assert (
        recovered.cleanup_evidence_ref == first.cleanup_evidence_ref == again.cleanup_evidence_ref
    )
    assert [item.to_dict() for item in recovered.engine_evidence] == [
        item.to_dict() for item in first.engine_evidence
    ]
    assert [item.to_dict() for item in again.engine_evidence] == [
        item.to_dict() for item in first.engine_evidence
    ]
    assert recovered.independent_observations == ()
    assert store.reopened is not None


def test_claimed_recovery_rejects_publication_claim_drift(tmp_path: Path) -> None:
    runtime, binding, delegation, _admission, worker, store, _events = _output_runtime(
        tmp_path, outputs={"vulnerabilities.json": b"[]"}
    )
    runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert store.reopened is not None
    assert store.reopened.publication_binding is not None
    store.reopened = replace(
        store.reopened,
        publication_binding=replace(
            store.reopened.publication_binding,
            execution_claim_ref=digest("d"),
        ),
    )

    recovered = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert worker.run_calls == 1
    assert recovered.record.state is AttemptState.UNKNOWN
    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.engine_evidence == ()
    assert recovered.artifact_manifest_ref is None


def test_claimed_recovery_rejects_saved_terminal_state_changed_from_verified_bytes(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, _admission, worker, _store, _events = _output_runtime(
        tmp_path, outputs={"vulnerabilities.json": b"[]"}
    )
    runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    drifted = _durable_running(binding).transition(
        AttemptState.FAILED,
        timestamp=COMPLETED,
        exit_code=0,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="strix_failed",
    )

    recovered = runtime.reconcile_claimed(
        binding, delegation, drifted, reconciliation_ref=digest("b")
    )

    assert worker.run_calls == 1
    assert recovered.record.to_dict() == drifted.to_dict()
    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.engine_evidence == ()
    assert recovered.artifact_manifest_ref is None


@pytest.mark.parametrize(
    "publication_error",
    [
        EngineArtifactPublicationUnknown("artifact publication is incomplete"),
        EngineArtifactStoreError("artifact publication is invalid"),
        OSError("artifact publication cannot be read"),
    ],
    ids=("pending", "invalid", "read-error"),
)
def test_claimed_recovery_unavailable_publication_runs_cleanup_without_import(
    tmp_path: Path, publication_error: Exception
) -> None:
    runtime, binding, delegation, admission, worker, store, credentials, events = _runtime(tmp_path)

    def unavailable(_attempt_id: str) -> ReopenedEngineArtifactAttempt:
        raise publication_error

    store.reopen_attempt = unavailable  # type: ignore[method-assign]
    resolver = cast(Resolver, runtime._resolver)

    first = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )
    second = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert first.record.state is AttemptState.UNKNOWN
    assert first.cleanup_state is CleanupState.UNKNOWN
    assert first.cleanup_evidence_ref == second.cleanup_evidence_ref
    assert first.engine_evidence == ()
    assert first.artifact_manifest_ref is None
    assert worker.run_calls == 0
    assert credentials.reconcile_calls == 2
    assert resolver.require_current_calls == 0
    assert cast(Custody, cast(Resolver, runtime._resolver).admission.custody).stop_calls == 2
    assert cast(SourceController, runtime._source_controller).reconcile_calls == 2
    assert store.reopened is None
    assert store.names == ()
    assert events == [
        "reconciled-revocation",
        "sealed",
        "reconciled-revocation",
        "sealed",
    ]


@pytest.mark.parametrize("receipt_reader", ["read_launch_reservation", "read_worker_outcome"])
def test_claimed_recovery_receipt_read_error_still_revokes_owned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, receipt_reader: str
) -> None:
    runtime, binding, delegation, admission, worker, store, credentials, events = _runtime(tmp_path)

    def unreadable(*_args: Any) -> None:
        raise OSError("retained receipt is unreadable")

    monkeypatch.setattr("bluefire.strix_engine_runtime." + receipt_reader, unreadable)
    recovered = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert recovered.record.state is AttemptState.UNKNOWN
    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.engine_evidence == ()
    assert recovered.artifact_manifest_ref is None
    assert worker.run_calls == 0
    assert credentials.reconcile_calls == 1
    assert cast(Custody, admission.custody).stop_calls == 1
    assert cast(SourceController, runtime._source_controller).reconcile_calls == 1
    assert store.names == ()
    assert events == ["reconciled-revocation", "sealed"]


def test_claimed_recovery_missing_final_cannot_publish_without_claim_bound_launch(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, admission, worker, store, credentials, events = _runtime(tmp_path)
    runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    store.reopened = None
    before = tuple(events)

    recovered = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert recovered.record.state is AttemptState.UNKNOWN
    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.artifact_manifest_ref is None
    assert recovered.engine_evidence == ()
    assert worker.run_calls == 1
    assert credentials.reconcile_calls == 1
    assert cast(Custody, admission.custody).stop_calls == 1
    assert cast(SourceController, runtime._source_controller).reconcile_calls == 1
    assert tuple(events[: len(before)]) == before
    assert events.count("imported") == 1


def test_claimed_recovery_imports_only_with_exact_claim_bound_launch_digest(
    tmp_path: Path,
) -> None:
    runtime, binding, delegation, admission, worker, store, _credentials, events = _runtime(
        tmp_path
    )
    first = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )
    reservation = json.loads(
        (admission.control_root / binding.attempt_id / "launch.json").read_text(encoding="utf-8")
    )
    store.reopened = None
    recovery_worker = Worker(events)
    recovered_runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, recovery_worker),
        artifact_store=cast(Any, store),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: "2026-11-05T00:00:00Z",
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
        expected_launch_digest=reservation["plan_digest"],
    )

    recovered = recovered_runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert worker.run_calls == 1
    assert recovery_worker.run_calls == 0
    assert recovered.record.to_dict() == first.record.to_dict()
    assert recovered.artifact_manifest_ref == first.artifact_manifest_ref
    assert recovered.cleanup_evidence_ref == first.cleanup_evidence_ref
    assert [item.to_dict() for item in recovered.engine_evidence] == [
        item.to_dict() for item in first.engine_evidence
    ]


def test_claimed_recovery_without_ref_fenced_adapter_fails_closed(tmp_path: Path) -> None:
    runtime, binding, delegation, admission, worker, _store, credentials, _events = _runtime(
        tmp_path
    )
    runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    cast(Any, admission.custody).reconcile_stop_owned = None

    recovered = runtime.reconcile_claimed(
        binding, delegation, _durable_running(binding), reconciliation_ref=digest("b")
    )

    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.engine_evidence == ()
    assert recovered.artifact_manifest_ref is None
    assert worker.run_calls == 1
    assert credentials.reconcile_calls == 1


def test_live_execution_refuses_missing_recovery_custody_before_lease(tmp_path: Path) -> None:
    runtime, binding, delegation, admission, worker, _store, credentials, events = _runtime(
        tmp_path
    )
    cast(Any, admission.custody).reconcile_stop_owned = None

    with pytest.raises(StrixEngineRuntimeError, match="ref-fenced external custody"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)

    assert worker.run_calls == 0
    assert events == []
    assert credentials.reconcile_calls == 0


@pytest.mark.parametrize("missing_adapter", ["credential", "source"])
def test_live_execution_refuses_missing_claimed_cleanup_adapter_before_lease(
    tmp_path: Path, missing_adapter: str
) -> None:
    runtime, binding, delegation, _admission, worker, _store, credentials, events = _runtime(
        tmp_path
    )
    if missing_adapter == "credential":
        cast(Any, credentials).reconcile_revocation_claimed = None
    else:
        cast(Any, runtime._source_controller).reconcile_seal = None

    with pytest.raises(StrixEngineRuntimeError, match="claimed Strix execution requires"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)

    assert worker.run_calls == 0
    assert events == []


def test_unverified_or_drifted_outer_boundary_refuses_before_lease_or_worker(
    tmp_path: Path,
) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    admission = StrixRuntimeAdmission(
        **{
            **{name: getattr(admission, name) for name in admission.__dataclass_fields__},
            "runtime_qualified": False,
        }
    )
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    with pytest.raises(StrixEngineRuntimeError, match="not qualified"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert events == []
    assert worker.run_calls == 0


def test_drifted_sandbox_limits_refuse_before_lease_or_worker(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    admission = StrixRuntimeAdmission(
        **{
            **{name: getattr(admission, name) for name in admission.__dataclass_fields__},
            "limits": StrixRuntimeLimits(memory="3g"),
        }
    )
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    with pytest.raises(StrixEngineRuntimeError, match="sandbox resources"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert events == []
    assert worker.run_calls == 0


def test_unprotected_controller_root_refuses_before_lease_or_worker(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    unprotected = ProtectedRuntimeRootsReceipt(
        **{
            **{
                name: getattr(admission.protected_roots, name)
                for name in admission.protected_roots.__dataclass_fields__
            },
            "engine_control_write_denied": False,
        }
    )
    admission = StrixRuntimeAdmission(
        **{
            **{name: getattr(admission, name) for name in admission.__dataclass_fields__},
            "protected_roots": unprotected,
        }
    )
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    with pytest.raises(StrixEngineRuntimeError, match="not externally protected"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert events == []
    assert worker.run_calls == 0


def test_predelegation_network_snapshot_refuses_before_lease_or_worker(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(
        tmp_path,
        network_created_at="2026-11-04T11:00:00Z",
        network_captured_at="2026-11-04T11:01:00Z",
        network_checked_at=NOW,
    )
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    with pytest.raises(StrixEngineRuntimeError, match="network proof is stale"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert events == []
    assert worker.run_calls == 0


def test_precreated_plan_accepts_fresh_postdelegation_snapshot(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(
        tmp_path,
        network_created_at="2026-11-04T11:00:00Z",
        network_captured_at=NOW,
        network_checked_at=NOW,
    )
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    settlement = runtime.execute(
        cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None
    )

    assert worker.run_calls == 1
    assert settlement.record.state is AttemptState.COMPLETED


def test_gateway_authorization_mismatch_never_starts_worker(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    events: list[str] = []
    worker = Worker(events)
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, worker),
        artifact_store=cast(Any, FakeArtifactStore(events, tmp_path / "artifacts")),
        credential_provider=Credentials(digest("0"), events),
        source_controller=SourceController(events),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )

    with pytest.raises(StrixEngineRuntimeError, match="another authorization"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
    assert worker.run_calls == 0
    assert events == ["lease", "revoked"]


def test_objective_hash_remains_bound_to_exact_workspace_bytes(tmp_path: Path) -> None:
    binding, delegation, admission = _fixture(tmp_path)
    expected = "sha256:" + hashlib.sha256((OBJECTIVE + "\n").encode()).hexdigest()
    assert admission.workspace.objective_sha256 == expected
    admission.workspace.objective_file.write_text("changed\n", encoding="utf-8")
    runtime = StrixEngineRuntime(
        resolver=Resolver(admission),
        worker=cast(Any, Worker([])),
        artifact_store=cast(Any, FakeArtifactStore([], tmp_path / "artifacts")),
        credential_provider=Credentials(binding.model_authorization_ref, []),
        source_controller=SourceController([]),
        clock=lambda: STARTED,
        expected_claim_ref=digest("c"),
        expected_resolution_ref=digest("e"),
    )
    with pytest.raises(ValueError, match="objective changed"):
        runtime.execute(cast(Any, Context()), binding, delegation, lambda _record, _timestamp: None)
