from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.tenant_record_lab_launcher import (
    CleanupReceipt,
    ControllerOwnedFixedProcessBackend,
    FixedChildSpec,
    LifecycleCommit,
    LifecycleState,
    LogSummary,
    LoopbackEndpoint,
    OwnedChild,
    Presence,
    ProcessSettlement,
    ReadinessReceipt,
    RuntimeBinding,
    SealedFile,
    ServiceRole,
    TenantLabLaunchError,
    TenantLabLifecycleRecord,
    TenantLabPackets,
    TenantLabStartFailure,
    TenantRecordLabLauncher,
    _BoundedDrain,
    _NativeLaunch,
    _SystemNativeSupervisor,
)
from bluefire.tenant_record_target_child import TargetReadyReceipt
from bluefire.util import content_hash

RUN_ID = "engine-lab-" + "1" * 32
ATTEMPT_ID = "engine-attempt-" + "2" * 32
RUN_ID_TWO = "engine-lab-" + "3" * 32
ATTEMPT_ID_TWO = "engine-attempt-" + "4" * 32
EMPTY_DIGEST = content_hash("")


def _sealed(path: Path) -> SealedFile:
    candidate = path.resolve(strict=True)
    details = candidate.stat()
    return SealedFile(
        path=candidate,
        path_digest="sha256:" + hashlib.sha256(os.fsencode(candidate)).hexdigest(),
        sha256="sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest(),
        device=details.st_dev,
        inode=details.st_ino,
        size=details.st_size,
        mtime_ns=details.st_mtime_ns,
    )


class Clock:
    def __init__(self) -> None:
        self.minute = 0

    def __call__(self) -> str:
        value = f"2026-11-04T12:{self.minute:02d}:00Z"
        self.minute += 1
        return value


class RecordingSink:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.events: list[tuple[str, LifecycleState]] = []

    def __call__(
        self,
        record: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        self.events.append((phase, record.state))
        committed_at = self.clock()
        fields = {
            "plan_digest": record.plan.digest,
            "prior_record_digest": prior_record_digest,
            "record_digest": record.digest,
            "phase": phase,
            "committed_at": committed_at,
        }
        return LifecycleCommit(**fields, receipt_digest=content_hash(fields))


class FakeBackend:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.events: list[str] = []
        self.specs: list[FixedChildSpec] = []
        self.fail_ready: ServiceRole | None = None
        self.stop_presence: dict[ServiceRole, Presence] = {}
        self.reconcile_presence: dict[ServiceRole, Presence] = {}
        self.cleanup_presence = Presence.ABSENT
        self.all_running = True

    def launch(self, spec: FixedChildSpec) -> OwnedChild:
        self.events.append(f"launch:{spec.role.value}")
        self.specs.append(spec)
        process_identity = content_hash({"process": spec.role.value})
        custody_snapshot = content_hash(
            {
                "session": spec.role.value,
                "pid": 5001 if spec.role is ServiceRole.TARGET else 5002,
            }
        )
        custody_fields = {
            "role": spec.role.value,
            "process_identity_digest": process_identity,
            "plan_digest": spec.plan_digest,
            "spec_digest": spec.digest,
            "custody_mode": spec.custody_mode,
            "custody_snapshot_digest": custody_snapshot,
        }
        return OwnedChild(
            role=spec.role,
            pid=5001 if spec.role is ServiceRole.TARGET else 5002,
            process_identity_digest=process_identity,
            plan_digest=spec.plan_digest,
            custody_mode=spec.custody_mode,
            custody_snapshot_digest=custody_snapshot,
            custody_receipt_digest=content_hash(custody_fields),
            spec_digest=spec.digest,
            endpoint=spec.endpoint,
            started_at=self.clock(),
        )

    def verify_ready(self, spec: FixedChildSpec, child: OwnedChild) -> ReadinessReceipt:
        self.events.append(f"ready:{spec.role.value}")
        if self.fail_ready is spec.role:
            raise RuntimeError("fixture readiness failed")
        observed_at = self.clock()
        endpoint = LoopbackEndpoint(
            child.endpoint.host, 41001 if spec.role is ServiceRole.TARGET else 41002
        )
        binding = content_hash(
            {
                "role": spec.role.value,
                "process": child.process_identity_digest,
                "endpoint": endpoint.to_dict(),
                "packet": spec.packet_digest,
                "plan": spec.plan_digest,
            }
        )
        return ReadinessReceipt(
            role=spec.role,
            process_identity_digest=child.process_identity_digest,
            spec_digest=spec.digest,
            endpoint=endpoint,
            binding_digest=binding,
            observed_at=observed_at,
            receipt_digest=content_hash({"binding_digest": binding, "observed_at": observed_at}),
        )

    def verify_all_running(
        self,
        _plan,
        children: tuple[OwnedChild, ...],  # type: ignore[no-untyped-def]
    ) -> bool:
        self.events.append("verify_all_running")
        return self.all_running and {child.role for child in children} == set(ServiceRole)

    def stop(
        self,
        plan,  # type: ignore[no-untyped-def]
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        self.events.append(f"stop:{role.value}")
        return self._settlement(plan, role, child, self.stop_presence.get(role, Presence.ABSENT))

    def reconcile(
        self,
        plan,  # type: ignore[no-untyped-def]
        role: ServiceRole,
        child: OwnedChild | None,
    ) -> ProcessSettlement:
        self.events.append(f"reconcile:{role.value}")
        return self._settlement(
            plan,
            role,
            child,
            self.reconcile_presence.get(role, Presence.ABSENT),
        )

    def _settlement(
        self,
        plan,  # type: ignore[no-untyped-def]
        role: ServiceRole,
        child: OwnedChild | None,
        presence: Presence,
    ) -> ProcessSettlement:
        observed_at = self.clock()
        empty = LogSummary(0, EMPTY_DIGEST, False)
        process_identity = None if child is None else child.process_identity_digest
        custody_snapshot = (
            content_hash({"role": role.value, "discovery": "empty"})
            if child is None
            else child.custody_snapshot_digest
        )
        fields = {
            "role": role.value,
            "process_identity_digest": process_identity,
            "plan_digest": plan.digest,
            "custody_mode": plan.custody_mode,
            "custody_snapshot_digest": custody_snapshot,
            "presence": presence.value,
            "observed_at": observed_at,
            "stdout": {"byte_count": 0, "sha256": empty.sha256, "truncated": False},
            "stderr": {"byte_count": 0, "sha256": empty.sha256, "truncated": False},
        }
        return ProcessSettlement(
            role=role,
            process_identity_digest=process_identity,
            plan_digest=plan.digest,
            custody_mode=plan.custody_mode,
            custody_snapshot_digest=custody_snapshot,
            presence=presence,
            observed_at=observed_at,
            custody_receipt_digest=content_hash(fields),
            stdout=empty,
            stderr=empty,
        )

    def cleanup(self, plan, layout) -> CleanupReceipt:  # type: ignore[no-untyped-def]
        self.events.append("cleanup")
        if self.cleanup_presence is Presence.ABSENT:
            shutil.rmtree(layout.run_root)
        observed_at = self.clock()
        details = layout.root.stat()
        root_identity = content_hash(
            {
                "resolved_path_digest": "sha256:"
                + hashlib.sha256(os.fsencode(layout.root)).hexdigest(),
                "device": details.st_dev,
                "inode": details.st_ino,
            }
        )
        workspace_digest = content_hash(
            {
                "root_identity_digest": root_identity,
                "plan_digest": plan.digest,
                "run_id": plan.run_id,
                "relative_entries": [
                    "target/packet.json",
                    "target/audit.jsonl",
                    "target/ready.json",
                    "provider/manifest.json",
                    "provider/token.txt",
                    "provider/audit.jsonl",
                    "provider/ready.json",
                ],
                "run_root_name": layout.run_root.name,
            }
        )
        fields = {
            "state": self.cleanup_presence.value,
            "plan_digest": plan.digest,
            "workspace_digest": workspace_digest,
            "observed_at": observed_at,
        }
        return CleanupReceipt(
            state=self.cleanup_presence,
            plan_digest=plan.digest,
            workspace_digest=workspace_digest,
            observed_at=observed_at,
            receipt_digest=content_hash(fields),
        )


class FakeProcess:
    def __init__(self, pid: int = 6101, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.pid = pid
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = 1

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeNativeSupervisor:
    def __init__(
        self, *, wrong_target_pid: bool = False, wrong_manifest_digest: bool = False
    ) -> None:
        self.wrong_target_pid = wrong_target_pid
        self.wrong_manifest_digest = wrong_manifest_digest
        self.specs: list[FixedChildSpec] = []
        self.launches: list[_NativeLaunch] = []
        self.stops = 0

    def launch(self, spec: FixedChildSpec) -> _NativeLaunch:
        process = FakeProcess(6101 + len(self.launches))
        native = _NativeLaunch(
            process=process,
            custody=object(),
            custody_handle=None,
            process_identity_digest=content_hash({"native": spec.role.value, "pid": process.pid}),
            custody_snapshot_digest=content_hash({"custody": spec.role.value, "pid": process.pid}),
            activated=False,
        )
        self.specs.append(spec)
        self.launches.append(native)
        return native

    def activate(self, launch: _NativeLaunch) -> None:
        index = self.launches.index(launch)
        spec = self.specs[index]
        launch.activated = True
        ready_path = Path(spec.argv[11] if spec.role is ServiceRole.TARGET else spec.argv[12])
        if spec.role is ServiceRole.TARGET:
            receipt = TargetReadyReceipt(
                pid=launch.process.pid + (1 if self.wrong_target_pid else 0),
                host=spec.endpoint.host,
                port=42101,
                packet_digest=spec.packet_digest,
                fixture_digest=content_hash("fixture"),
                config_digest=content_hash("config"),
                target_snapshot_id="target-snapshot-0001",
                service_generation="service-generation-0001",
                admission_digests={
                    name: content_hash(name)
                    for name in ("engine_worker", "ordinary_user", "controller_probe")
                },
                max_audit_events=32,
                max_audit_bytes=4096,
                max_requests=16,
                max_runtime_seconds=min(60, spec.max_runtime_seconds),
                started_at="2026-11-04T12:00:00Z",
            )
            ready_path.write_bytes(receipt.to_bytes())
        else:
            manifest_value = json.loads(spec.packet_source.path.read_text("utf-8"))
            manifest_canonical = json.dumps(
                manifest_value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
            value = {
                "schema_version": "bluefire.controlled-provider-ready.v1",
                "provider_id": "controlled-strix-mechanics.v1",
                "provider_label": "Test provider",
                "attempt_id": spec.attempt_id,
                "model_id": "bluefire-controlled-strix-mechanics-v1",
                "host": spec.endpoint.host,
                "port": 42102,
                "manifest_digest": (
                    "sha256:" + "0" * 64
                    if self.wrong_manifest_digest
                    else "sha256:" + hashlib.sha256(manifest_canonical).hexdigest()
                ),
                "live_model_proof": False,
            }
            ready_path.write_bytes(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            )

    @staticmethod
    def running(launch: _NativeLaunch) -> Presence:
        return Presence.RUNNING if launch.process.returncode is None else Presence.ABSENT

    @staticmethod
    def bind_ready_pid(launch: _NativeLaunch, process_id: int) -> bool:
        return process_id == launch.process.pid

    def stop(self, launch: _NativeLaunch) -> Presence:
        self.stops += 1
        launch.process.returncode = 0
        return Presence.ABSENT


class FakeWindowsCustody:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def create_job(self) -> int:
        self.events.append("create_job")
        return 91

    @staticmethod
    def system_directory() -> Path:
        return Path("C:/Windows/System32")

    def assign(self, _job: int, _process: FakeProcess) -> None:
        self.events.append("assign")

    def resume_suspended(self, _process: FakeProcess) -> None:
        self.events.append("resume")

    def finish(self, process: FakeProcess) -> bool:
        self.events.append("finish")
        process.returncode = 0
        return True

    @staticmethod
    def close_handle(_job: int) -> bool:
        return True


class FailingWindowsCustody:
    def __init__(
        self,
        events: list[str],
        *,
        fail_create: bool = False,
        fail_assign: bool = False,
    ) -> None:
        self.events = events
        self.fail_create = fail_create
        self.fail_assign = fail_assign
        self.releases = 0

    def create_job(self) -> int:
        self.events.append("create_job")
        if self.fail_create:
            raise RuntimeError("create failed")
        return 91

    @staticmethod
    def system_directory() -> Path:
        return Path("C:/Windows/System32")

    def assign(self, _job: int, _process: FakeProcess) -> None:
        self.events.append("assign")
        if self.fail_assign:
            raise RuntimeError("assign failed")

    def terminate(self, process: FakeProcess) -> bool:
        self.events.append("terminate_and_close")
        self.releases += 1
        process.returncode = 0
        return True

    def close_handle(self, job: int) -> bool:
        self.events.append(f"close:{job}")
        self.releases += 1
        return True


class FakeLinuxCustody:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def register(self, _process: FakeProcess) -> None:
        self.events.append("register")

    @staticmethod
    def process_identity(pid: int) -> tuple[int, int, int, int]:
        return (pid, 1001, pid, pid)

    def exited_without_reap(self, process: FakeProcess) -> bool:
        return process.returncode is not None

    def release(self, process: FakeProcess, *, terminate: bool) -> bool:
        assert terminate is True
        self.events.append("release")
        process.returncode = 0
        return True


def _packets() -> TenantLabPackets:
    return TenantLabPackets(
        target_packet=b'{"schema_version":"bluefire.tenant-record-target-packet.v1"}\n',
        provider_manifest=b'{"schema_version":"bluefire.controlled-strix-mechanics.v1"}\n',
        provider_token=b"t" * 48,
    )


def _launcher(tmp_path: Path) -> tuple[TenantRecordLabLauncher, FakeBackend, Clock]:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    provider = tmp_path / "controlled_strix_provider.py"
    target = tmp_path / "tenant_record_target_child.py"
    provider.write_text("# fixed test provider\n", encoding="utf-8")
    target.write_text("# fixed test target\n", encoding="utf-8")
    runtime = RuntimeBinding.inspect_for_test(
        python_path=Path(sys.executable),
        target_path=target,
        provider_path=provider,
    )
    clock = Clock()
    backend = FakeBackend(clock)
    return (
        TenantRecordLabLauncher(
            scratch_root=scratch,
            runtime=runtime,
            backend=backend,
            root_is_protected=lambda candidate: candidate == scratch.resolve(),
            clock=clock,
        ),
        backend,
        clock,
    )


def _prepared(
    tmp_path: Path,
):
    launcher, backend, clock = _launcher(tmp_path)
    packets = _packets()
    plan = launcher.plan(run_id=RUN_ID, attempt_id=ATTEMPT_ID, packets=packets)
    sink = RecordingSink(clock)
    record = launcher.prepare(plan, packets, sink)
    return launcher, backend, record, sink


def test_fixed_launch_stop_cleanup_and_round_trip(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)

    running = launcher.start(prepared, lifecycle)

    assert running.state is LifecycleState.RUNNING
    assert {child.role for child in running.children} == set(ServiceRole)
    assert lifecycle.events[1] == ("launch_reserved", LifecycleState.LAUNCH_RESERVED)
    assert backend.events[:4] == [
        "launch:target",
        "ready:target",
        "launch:test_provider",
        "ready:test_provider",
    ]
    target, provider = backend.specs
    assert target.argv[1:7] == (
        "-I",
        "-B",
        "-m",
        "bluefire.tenant_record_target_child",
        "--fixed-target",
        "--packet",
    )
    assert provider.argv[1:6] == (
        "-I",
        "-B",
        "-m",
        "bluefire.controlled_strix_provider",
        "--manifest",
    )
    assert all("http://" not in argument and "https://" not in argument for argument in target.argv)
    assert all(
        Path(provider.argv[index]).is_relative_to(tmp_path / "scratch" / RUN_ID)
        for index in (6, 8, 10, 12)
    )

    stopped = launcher.stop(running, lifecycle)
    assert stopped.state is LifecycleState.STOPPED
    assert [item.role for item in stopped.settlements] == [
        ServiceRole.TARGET,
        ServiceRole.TEST_PROVIDER,
    ]
    assert backend.events[-2:] == ["stop:test_provider", "stop:target"]
    assert TenantLabLifecycleRecord.from_mapping(stopped.to_dict()) == stopped

    cleaned = launcher.cleanup(stopped, lifecycle)
    assert cleaned.state is LifecycleState.CLEANED
    assert not (tmp_path / "scratch" / RUN_ID).exists()
    assert TenantLabLifecycleRecord.from_mapping(cleaned.to_dict()) == cleaned


def test_launch_is_reserved_before_effect_and_never_replayed(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    ordered: list[str] = []

    def sink(
        value: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        ordered.append(phase)
        return lifecycle(value, phase, prior_record_digest)

    original_launch = backend.launch

    def launch(spec: FixedChildSpec) -> OwnedChild:
        ordered.append(f"effect:{spec.role.value}")
        return original_launch(spec)

    backend.launch = launch  # type: ignore[method-assign]
    running = launcher.start(prepared, sink)

    assert ordered.index("launch_reserved") < ordered.index("effect:target")
    with pytest.raises(TenantLabLaunchError, match="only once"):
        launcher.start(running, sink)
    assert backend.events.count("launch:target") == 1


def test_joint_running_observation_blocks_a_stale_running_commit(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    backend.all_running = False

    with pytest.raises(TenantLabStartFailure) as captured:
        launcher.start(prepared, lifecycle)

    assert captured.value.record.state is LifecycleState.STOPPED
    assert "verify_all_running" in backend.events
    assert ("running", LifecycleState.RUNNING) not in lifecycle.events


def test_readiness_failure_settles_both_roles_without_starting_provider(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    backend.fail_ready = ServiceRole.TARGET

    with pytest.raises(TenantLabStartFailure) as captured:
        launcher.start(prepared, lifecycle)

    assert captured.value.record.state is LifecycleState.STOPPED
    assert "launch:test_provider" not in backend.events
    assert backend.events[-2:] == ["reconcile:test_provider", "reconcile:target"]
    assert {item.role for item in captured.value.record.settlements} == set(ServiceRole)


def test_failure_and_cleanup_uncertainty_remain_unknown(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    backend.fail_ready = ServiceRole.TARGET
    backend.reconcile_presence[ServiceRole.TARGET] = Presence.UNKNOWN

    with pytest.raises(TenantLabStartFailure) as captured:
        launcher.start(prepared, lifecycle)
    unknown = captured.value.record
    assert unknown.state is LifecycleState.UNKNOWN
    with pytest.raises(TenantLabLaunchError, match="verified process absence"):
        launcher.cleanup(unknown, lifecycle)


def test_reconcile_never_launches_a_reserved_identity(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    reserved = replace(
        prepared,
        revision=prepared.revision + 1,
        state=LifecycleState.LAUNCH_RESERVED,
        reserved_at="2026-11-04T12:02:00Z",
    )

    recovered = launcher.reconcile(reserved, lifecycle)

    assert recovered.state is LifecycleState.STOPPED
    assert not any(event.startswith("launch:") for event in backend.events)
    assert backend.events == ["reconcile:test_provider", "reconcile:target"]


def test_reconcile_reservation_rejection_precedes_every_backend_effect(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, _lifecycle = _prepared(tmp_path)
    reserved = replace(
        prepared,
        revision=prepared.revision + 1,
        state=LifecycleState.LAUNCH_RESERVED,
        reserved_at="2026-11-04T12:02:00Z",
    )

    def reject(
        _record: TenantLabLifecycleRecord,
        phase: str,
        _prior_record_digest: str | None,
    ) -> LifecycleCommit:
        assert phase == "reconcile_reserved"
        raise RuntimeError("stale prior record")

    with pytest.raises(RuntimeError, match="stale prior"):
        launcher.reconcile(reserved, reject)

    assert backend.events == []


def test_reconcile_persists_each_role_before_the_next_effect(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    reserved = replace(
        prepared,
        revision=prepared.revision + 1,
        state=LifecycleState.LAUNCH_RESERVED,
        reserved_at="2026-11-04T12:02:00Z",
    )
    ordered: list[str] = []
    original = backend.reconcile

    def reconcile(plan, role, child):  # type: ignore[no-untyped-def]
        ordered.append(f"effect:{role.value}")
        return original(plan, role, child)

    backend.reconcile = reconcile  # type: ignore[method-assign]

    def crash_after_first(
        record: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        ordered.append(f"commit:{phase}")
        if phase == "test_provider_reconciled":
            raise RuntimeError("controller crash")
        return lifecycle(record, phase, prior_record_digest)

    with pytest.raises(RuntimeError, match="controller crash"):
        launcher.reconcile(reserved, crash_after_first)

    assert ordered == [
        "commit:reconcile_reserved",
        "effect:test_provider",
        "commit:test_provider_reconciled",
    ]
    assert backend.events == ["reconcile:test_provider"]


def test_changed_packet_or_workspace_link_is_rejected_before_launch(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    target_packet = tmp_path / "scratch" / RUN_ID / "target" / "packet.json"
    target_packet.write_bytes(b"changed")

    with pytest.raises(TenantLabLaunchError, match="packet changed"):
        launcher.start(prepared, lifecycle)
    assert backend.events == []


def test_preparation_sink_failure_removes_secret_scratch(tmp_path: Path) -> None:
    launcher, _backend, _clock = _launcher(tmp_path)
    packets = _packets()
    plan = launcher.plan(run_id=RUN_ID, attempt_id=ATTEMPT_ID, packets=packets)

    def fail(
        _record: TenantLabLifecycleRecord,
        _phase: str,
        _prior_record_digest: str | None,
    ) -> LifecycleCommit:
        raise RuntimeError("persistence unavailable")

    with pytest.raises(RuntimeError, match="persistence unavailable"):
        launcher.prepare(plan, packets, fail)
    assert not (tmp_path / "scratch" / RUN_ID).exists()


def test_stop_and_scratch_cleanup_preserve_uncertainty(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    backend.stop_presence[ServiceRole.TEST_PROVIDER] = Presence.UNKNOWN
    unknown = launcher.stop(running, lifecycle)
    assert unknown.state is LifecycleState.UNKNOWN

    backend.reconcile_presence = {
        ServiceRole.TEST_PROVIDER: Presence.ABSENT,
        ServiceRole.TARGET: Presence.ABSENT,
    }
    stopped = launcher.reconcile(unknown, lifecycle)
    backend.cleanup_presence = Presence.UNKNOWN
    cleanup_unknown = launcher.cleanup(stopped, lifecycle)
    assert cleanup_unknown.state is LifecycleState.UNKNOWN
    assert cleanup_unknown.cleanup_receipt is not None
    assert cleanup_unknown.cleanup_receipt.state is Presence.UNKNOWN


def test_public_contracts_reject_nonloopback_commands_and_extra_fields(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, _lifecycle = _prepared(tmp_path)
    with pytest.raises(TenantLabLaunchError, match="numeric loopback"):
        LoopbackEndpoint("example.test", 443)
    python_source = _sealed(Path(sys.executable))
    module_source = _sealed(tmp_path / "controlled_strix_provider.py")
    packet_source = _sealed(tmp_path / "scratch" / RUN_ID / "provider" / "manifest.json")
    secret_source = _sealed(tmp_path / "scratch" / RUN_ID / "provider" / "token.txt")
    with pytest.raises(TenantLabLaunchError, match="package grammar"):
        FixedChildSpec(
            role=ServiceRole.TEST_PROVIDER,
            argv=(
                os.fspath(Path(sys.executable).resolve()),
                "-c",
                "print('arbitrary')",
            ),
            environment=(
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("PYTHONHASHSEED", "0"),
                ("PYTHONNOUSERSITE", "1"),
            ),
            endpoint=LoopbackEndpoint("127.0.0.1", 0),
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            plan_digest=prepared.plan.digest,
            packet_digest=prepared.plan.provider_manifest_digest,
            runtime_digest=prepared.plan.runtime_digest,
            python_digest=python_source.sha256,
            module_digest=module_source.sha256,
            secondary_secret_digest=prepared.plan.provider_token_digest,
            python_source=python_source,
            module_source=module_source,
            packet_source=packet_source,
            secondary_secret_source=secret_source,
            custody_mode=prepared.plan.custody_mode,
            max_runtime_seconds=1,
            max_log_bytes=1,
        )
    document = prepared.to_dict()
    document["unexpected"] = True
    with pytest.raises(TenantLabLaunchError, match="fields are invalid"):
        TenantLabLifecycleRecord.from_mapping(document)
    assert backend.events == []


def test_lifecycle_state_matrix_rejects_contradictory_rehydration(
    tmp_path: Path,
) -> None:
    launcher, _backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    stopped = launcher.stop(running, lifecycle)

    running_with_settlements = running.to_dict()
    running_with_settlements["settlements"] = stopped.to_dict()["settlements"]
    with pytest.raises(TenantLabLaunchError, match="running lab is incomplete"):
        TenantLabLifecycleRecord.from_mapping(running_with_settlements)

    with pytest.raises(TenantLabLaunchError, match="launch-reserved"):
        replace(running, state=LifecycleState.LAUNCH_RESERVED)
    with pytest.raises(TenantLabLaunchError, match="stopping lab"):
        replace(stopped, state=LifecycleState.STOPPING)


def test_settlement_log_bound_is_fail_closed(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    original = backend.stop

    def oversized(plan, role, child):  # type: ignore[no-untyped-def]
        value = original(plan, role, child)
        if role is ServiceRole.TEST_PROVIDER:
            return replace(
                value,
                stdout=LogSummary(plan.max_log_bytes + 1, EMPTY_DIGEST, True),
            )
        return value

    backend.stop = oversized  # type: ignore[method-assign]
    result = launcher.stop(running, lifecycle)
    assert result.state is LifecycleState.UNKNOWN


def test_runtime_and_root_protection_are_rechecked(tmp_path: Path) -> None:
    launcher, _backend, prepared, lifecycle = _prepared(tmp_path)
    provider_path = tmp_path / "controlled_strix_provider.py"
    provider_path.write_text("# changed\n", encoding="utf-8")

    with pytest.raises(TenantLabLaunchError, match="runtime changed"):
        launcher.start(prepared, lifecycle)

    # The launch plan keeps the original immutable runtime identity. Rebuilding
    # the configured binding against changed bytes produces a different digest.
    changed = RuntimeBinding.inspect_for_test(
        python_path=Path(sys.executable),
        target_path=tmp_path / "tenant_record_target_child.py",
        provider_path=provider_path,
    )
    assert changed.digest != prepared.plan.runtime_digest
    with pytest.raises(TenantLabLaunchError, match="configured runtime"):
        TenantRecordLabLauncher(
            scratch_root=tmp_path / "scratch",
            runtime=changed,
            backend=FakeBackend(Clock()),
            root_is_protected=lambda _path: True,
            clock=Clock(),
        ).start(prepared, lifecycle)


def test_cleanup_uncertainty_can_be_reconciled_without_process_replay(
    tmp_path: Path,
) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    stopped = launcher.stop(running, lifecycle)
    backend.cleanup_presence = Presence.UNKNOWN
    unknown = launcher.cleanup(stopped, lifecycle)
    backend.cleanup_presence = Presence.ABSENT

    cleaned = launcher.cleanup(unknown, lifecycle)

    assert cleaned.state is LifecycleState.CLEANED
    assert backend.events.count("cleanup") == 2
    assert not any(event.startswith("launch:") for event in backend.events[6:])


def _concrete_prepared(
    tmp_path: Path,
    *,
    wrong_target_pid: bool = False,
    wrong_manifest_digest: bool = False,
):
    scratch = tmp_path / "concrete-scratch"
    scratch.mkdir()
    provider = tmp_path / "concrete-controlled-provider.py"
    target = tmp_path / "concrete-target-child.py"
    provider.write_text("# fixed provider\n", encoding="utf-8")
    target.write_text("# fixed target\n", encoding="utf-8")
    runtime = RuntimeBinding.inspect_for_test(
        python_path=Path(sys.executable),
        target_path=target,
        provider_path=provider,
    )
    clock = Clock()
    native = FakeNativeSupervisor(
        wrong_target_pid=wrong_target_pid,
        wrong_manifest_digest=wrong_manifest_digest,
    )
    probes: list[LoopbackEndpoint] = []
    backend = ControllerOwnedFixedProcessBackend(
        scratch_root=scratch,
        runtime=runtime,
        native=native,
        clock=clock,
        socket_probe=lambda endpoint, _timeout: probes.append(endpoint),
    )
    launcher = TenantRecordLabLauncher(
        scratch_root=scratch,
        runtime=runtime,
        backend=backend,
        root_is_protected=lambda candidate: candidate == scratch.resolve(),
        clock=clock,
    )
    packets = _packets()
    plan = launcher.plan(run_id=RUN_ID, attempt_id=ATTEMPT_ID, packets=packets)
    lifecycle = RecordingSink(clock)
    prepared = launcher.prepare(plan, packets, lifecycle)
    return launcher, backend, native, prepared, lifecycle, probes, runtime, clock


def test_concrete_backend_resolves_readiness_and_settles_owned_children(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, probes, _runtime, _clock = _concrete_prepared(
        tmp_path
    )
    running = launcher.start(prepared, lifecycle)

    assert running.state is LifecycleState.RUNNING
    assert [item.endpoint.port for item in running.children] == [0, 0]
    assert [item.endpoint.port for item in running.readiness] == [42101, 42102]
    assert [item.port for item in probes] == [42101, 42102]
    assert native.specs[0].argv[4] == "bluefire.tenant_record_target_child"
    assert native.specs[1].argv[4] == "bluefire.controlled_strix_provider"

    stopped = launcher.stop(running, lifecycle)
    assert stopped.state is LifecycleState.STOPPED
    assert native.stops == 2
    assert launcher.cleanup(stopped, lifecycle).state is LifecycleState.CLEANED


def test_concrete_backend_reaps_each_cleaned_run_without_enabling_relaunch(
    tmp_path: Path,
) -> None:
    launcher, backend, native, prepared, lifecycle, _probes, _runtime, _clock = _concrete_prepared(
        tmp_path
    )
    first_running = launcher.start(prepared, lifecycle)
    first_stopped = launcher.stop(first_running, lifecycle)
    first_cleaned = launcher.cleanup(first_stopped, lifecycle)

    packets = _packets()
    second_plan = launcher.plan(
        run_id=RUN_ID_TWO,
        attempt_id=ATTEMPT_ID_TWO,
        packets=packets,
    )
    second_prepared = launcher.prepare(second_plan, packets, lifecycle)
    second_running = launcher.start(second_prepared, lifecycle)
    second_stopped = launcher.stop(second_running, lifecycle)
    second_cleaned = launcher.cleanup(second_stopped, lifecycle)

    assert first_cleaned.state is LifecycleState.CLEANED
    assert second_cleaned.state is LifecycleState.CLEANED
    assert backend._live == {}
    assert len(backend._attempted) == 4
    assert set(backend._settled.values()) == {Presence.ABSENT}
    assert len(native.specs) == 4
    with pytest.raises(TenantLabLaunchError, match="only once"):
        launcher.start(first_cleaned, lifecycle)
    assert len(native.specs) == 4


def test_concrete_backend_fresh_controller_reconcile_is_unknown_and_never_replays(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, _probes, runtime, clock = _concrete_prepared(
        tmp_path
    )
    running = launcher.start(prepared, lifecycle)
    fresh_native = FakeNativeSupervisor()
    scratch = tmp_path / "concrete-scratch"
    fresh = TenantRecordLabLauncher(
        scratch_root=scratch,
        runtime=runtime,
        backend=ControllerOwnedFixedProcessBackend(
            scratch_root=scratch,
            runtime=runtime,
            native=fresh_native,
            clock=clock,
            socket_probe=lambda _endpoint, _timeout: None,
        ),
        root_is_protected=lambda candidate: candidate == scratch.resolve(),
        clock=clock,
    )

    recovered = fresh.reconcile(running, RecordingSink(clock))

    assert recovered.state is LifecycleState.UNKNOWN
    assert fresh_native.specs == []
    assert fresh_native.stops == 0
    stopped = launcher.stop(running, lifecycle)
    assert stopped.state is LifecycleState.STOPPED
    launcher.cleanup(stopped, lifecycle)
    assert native.stops == 2


def test_concrete_backend_rejects_mismatched_target_ready_and_stops_custody(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, _probes, _runtime, _clock = _concrete_prepared(
        tmp_path, wrong_target_pid=True
    )
    with pytest.raises(TenantLabStartFailure) as captured:
        launcher.start(prepared, lifecycle)

    assert captured.value.record.state is LifecycleState.STOPPED
    assert len(native.specs) == 1
    assert native.stops == 1


def test_concrete_backend_rejects_mismatched_provider_manifest_receipt(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, _probes, _runtime, _clock = _concrete_prepared(
        tmp_path, wrong_manifest_digest=True
    )

    with pytest.raises(TenantLabStartFailure) as captured:
        launcher.start(prepared, lifecycle)

    assert captured.value.record.state is LifecycleState.STOPPED
    assert len(native.specs) == 2
    assert native.stops == 2


@pytest.mark.parametrize("platform_name", ["win32", "linux"])
def test_system_supervisor_uses_platform_custody_before_fixed_child_runs(
    tmp_path: Path, platform_name: str
) -> None:
    launcher, fake_backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    spec = fake_backend.specs[0]
    if platform_name == "linux":
        spec = replace(spec, custody_mode="posix_session")
    events: list[str] = []
    options: dict[str, object] = {}

    def popen(argv, **kwargs):  # type: ignore[no-untyped-def]
        assert tuple(argv) == spec.argv
        events.append("popen")
        options.update(kwargs)
        return FakeProcess()

    if platform_name == "win32":
        custody = FakeWindowsCustody(events)
        supervisor = _SystemNativeSupervisor(
            popen_factory=popen,
            platform_name="win32",
            windows_factory=lambda: custody,
            windows_identity=lambda pid: {"process_id": pid, "created": 777},
        )
    else:
        custody = FakeLinuxCustody(events)
        supervisor = _SystemNativeSupervisor(
            popen_factory=popen,
            platform_name="linux",
            linux_factory=lambda: custody,
        )

    native = supervisor.launch(spec)
    supervisor.activate(native)

    assert options["shell"] is False
    assert options["close_fds"] is True
    if platform_name == "win32":
        assert events[:3] == ["create_job", "popen", "assign"]
        assert events[3] == "resume"
        assert int(options["creationflags"]) & 0x0000_0004
    else:
        assert events[:2] == ["popen", "register"]
        assert options["start_new_session"] is True
        assert options["umask"] == 0o077
    assert supervisor.stop(native) is Presence.ABSENT

    stopped = launcher.stop(running, lifecycle)
    launcher.cleanup(stopped, lifecycle)


@pytest.mark.parametrize("stage", ["create", "popen", "assign", "identity"])
def test_windows_launch_failure_releases_each_created_job_exactly_once(
    tmp_path: Path, stage: str
) -> None:
    launcher, fake_backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    spec = fake_backend.specs[0]
    events: list[str] = []
    custody = FailingWindowsCustody(
        events,
        fail_create=stage == "create",
        fail_assign=stage == "assign",
    )
    process = FakeProcess()

    def popen(_argv, **_kwargs):  # type: ignore[no-untyped-def]
        events.append("popen")
        if stage == "popen":
            raise RuntimeError("popen failed")
        return process

    def identity(pid: int) -> dict[str, int]:
        events.append("identity")
        if stage == "identity":
            raise RuntimeError("identity failed")
        return {"process_id": pid, "created": 777}

    supervisor = _SystemNativeSupervisor(
        popen_factory=popen,
        platform_name="win32",
        windows_factory=lambda: custody,
        windows_identity=identity,
    )

    with pytest.raises(RuntimeError, match=f"{stage} failed"):
        supervisor.launch(spec)

    assert custody.releases == (0 if stage == "create" else 1)
    if stage == "identity":
        assert events[-1] == "terminate_and_close"
        assert not any(event.startswith("close:") for event in events)
    elif stage != "create":
        assert events[-1] == "close:91"

    stopped = launcher.stop(running, lifecycle)
    launcher.cleanup(stopped, lifecycle)


def test_concrete_backend_rechecks_sealed_packet_before_native_launch(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, _probes, _runtime, _clock = _concrete_prepared(
        tmp_path
    )
    packet = tmp_path / "concrete-scratch" / RUN_ID / "target" / "packet.json"
    packet.write_bytes(b"changed")

    with pytest.raises(TenantLabLaunchError, match="packet changed"):
        launcher.start(prepared, lifecycle)
    assert native.specs == []


def test_concrete_backend_rejects_a_fixed_spec_from_another_scratch_root(
    tmp_path: Path,
) -> None:
    launcher, _backend, native, prepared, lifecycle, _probes, runtime, clock = _concrete_prepared(
        tmp_path
    )
    running = launcher.start(prepared, lifecycle)
    foreign_root = tmp_path / "foreign-scratch"
    foreign_root.mkdir()
    foreign_native = FakeNativeSupervisor()
    foreign = ControllerOwnedFixedProcessBackend(
        scratch_root=foreign_root,
        runtime=runtime,
        native=foreign_native,
        clock=clock,
        socket_probe=lambda _endpoint, _timeout: None,
    )

    with pytest.raises(TenantLabLaunchError, match="does not belong"):
        foreign.launch(native.specs[0])
    assert foreign_native.specs == []

    stopped = launcher.stop(running, lifecycle)
    launcher.cleanup(stopped, lifecycle)


def test_launch_effect_waits_for_exact_durable_acknowledgement(tmp_path: Path) -> None:
    launcher, backend, clock = _launcher(tmp_path)
    packets = _packets()
    plan = launcher.plan(run_id=RUN_ID, attempt_id=ATTEMPT_ID, packets=packets)
    persisted = launcher.prepare(plan, packets, RecordingSink(clock))

    def wrong_ack(
        record: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        committed_at = clock()
        fields = {
            "plan_digest": record.plan.digest,
            "prior_record_digest": prior_record_digest,
            "record_digest": content_hash("another-record"),
            "phase": phase,
            "committed_at": committed_at,
        }
        return LifecycleCommit(**fields, receipt_digest=content_hash(fields))

    with pytest.raises(TenantLabLaunchError, match="different transition"):
        launcher.start(persisted, wrong_ack)
    assert backend.events == []


def test_lifecycle_commit_cannot_predate_the_transition(tmp_path: Path) -> None:
    launcher, backend, prepared, lifecycle = _prepared(tmp_path)

    def stale_ack(
        record: TenantLabLifecycleRecord,
        phase: str,
        prior_record_digest: str | None,
    ) -> LifecycleCommit:
        fields = {
            "plan_digest": record.plan.digest,
            "prior_record_digest": prior_record_digest,
            "record_digest": record.digest,
            "phase": phase,
            "committed_at": record.plan.created_at,
        }
        return LifecycleCommit(**fields, receipt_digest=content_hash(fields))

    with pytest.raises(TenantLabLaunchError, match="out of order"):
        launcher.start(prepared, stale_ack)
    assert backend.events == []
    assert lifecycle.events == [("prepared", LifecycleState.PREPARED)]


def test_rehydration_rejects_cross_process_readiness_replay(tmp_path: Path) -> None:
    launcher, _backend, prepared, lifecycle = _prepared(tmp_path)
    running = launcher.start(prepared, lifecycle)
    document = running.to_dict()
    readiness = document["readiness"]
    assert isinstance(readiness, list) and isinstance(readiness[0], dict)
    readiness[0]["process_identity_digest"] = content_hash("foreign-process")

    with pytest.raises(TenantLabLaunchError, match="does not match its owned child"):
        TenantLabLifecycleRecord.from_mapping(document)

    stopped = launcher.stop(running, lifecycle)
    launcher.cleanup(stopped, lifecycle)


def test_root_protection_drift_blocks_cleanup_without_deleting_scratch(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "protected-scratch"
    scratch.mkdir()
    provider = tmp_path / "protected-provider.py"
    target = tmp_path / "protected-target.py"
    provider.write_text("# provider\n", encoding="utf-8")
    target.write_text("# target\n", encoding="utf-8")
    runtime = RuntimeBinding.inspect_for_test(
        python_path=Path(sys.executable),
        target_path=target,
        provider_path=provider,
    )
    protected = [True]
    clock = Clock()
    backend = FakeBackend(clock)
    launcher = TenantRecordLabLauncher(
        scratch_root=scratch,
        runtime=runtime,
        backend=backend,
        root_is_protected=lambda _candidate: protected[0],
        clock=clock,
    )
    packets = _packets()
    plan = launcher.plan(run_id=RUN_ID, attempt_id=ATTEMPT_ID, packets=packets)
    lifecycle = RecordingSink(clock)
    running = launcher.start(launcher.prepare(plan, packets, lifecycle), lifecycle)
    stopped = launcher.stop(running, lifecycle)
    protected[0] = False

    with pytest.raises(TenantLabLaunchError, match="protection changed"):
        launcher.cleanup(stopped, lifecycle)
    assert (scratch / RUN_ID).is_dir()


def test_bounded_log_drain_never_retains_bytes_beyond_its_limit() -> None:
    overflow = threading.Event()
    drain = _BoundedDrain(io.BytesIO(b"abcdefghijk"), 4, overflow)

    drain.start()
    summary = drain.finish(1.0)

    assert summary == LogSummary(
        byte_count=4,
        sha256="sha256:" + hashlib.sha256(b"abcd").hexdigest(),
        truncated=True,
    )
    assert overflow.is_set()
