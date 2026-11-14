from __future__ import annotations

import io
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from bluefire import engine_worker_runtime as runtime
from bluefire.engine_worker_runtime import (
    EngineCleanupState,
    EngineExecutionState,
    EngineLaunchPlan,
    EngineWorkerError,
    EngineWorkerRuntime,
    ResourceCustodySnapshot,
    ResourceCustodyState,
    read_launch_reservation,
)


class Signal:
    def __init__(self, *states: bool) -> None:
        self.states = list(states) or [False]
        self.index = 0

    def is_set(self) -> bool:
        value = self.states[min(self.index, len(self.states) - 1)]
        self.index += 1
        return value


class FakeProcess:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", exit_code: int | None = 0) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.pid = 4242
        self.returncode = exit_code
        self.signals: list[int] = []

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            raise runtime.subprocess.TimeoutExpired(["engine"], 1)
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def send_signal(self, value: int) -> None:
        self.signals.append(value)


class Custody:
    def __init__(self, *inspections: ResourceCustodySnapshot) -> None:
        self.inspections = list(inspections)
        self.calls: list[tuple[str, str]] = []

    def inspect(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        assert timeout_seconds > 0
        assert custody_identity_digest == "sha256:" + "b" * 64
        assert network_policy_digest == "sha256:" + "c" * 64
        self.calls.append(("inspect", attempt_id))
        if len(self.inspections) > 1:
            return self.inspections.pop(0)
        return self.inspections[0]

    def stop_owned(
        self,
        attempt_id: str,
        *,
        custody_identity_digest: str,
        network_policy_digest: str,
        timeout_seconds: float,
    ) -> ResourceCustodySnapshot:
        assert timeout_seconds > 0
        assert custody_identity_digest == "sha256:" + "b" * 64
        assert network_policy_digest == "sha256:" + "c" * 64
        self.calls.append(("stop", attempt_id))
        return self.inspections[0]


class BlockingReadStream(io.BytesIO):
    def __init__(self, value: bytes, released: threading.Event) -> None:
        super().__init__(value)
        self.released = released

    def read(self, size: int | None = -1) -> bytes:
        self.released.wait(timeout=2.0)
        return super().read(size)


def plan(tmp_path: Path, **changes: Any) -> EngineLaunchPlan:
    root = tmp_path / "attempt"
    control_root = tmp_path / "controller-records"
    root.mkdir(exist_ok=True)
    control_root.mkdir(exist_ok=True)
    values: dict[str, Any] = {
        "attempt_id": "attempt-0123456789abcdef",
        "plan_digest": "sha256:" + "a" * 64,
        "argv": (str(Path(sys.executable).resolve()), "-I", "-B", "worker.py"),
        "environment": (
            ("LANG", "C"),
            ("LLM_API_KEY", "secret-that-must-not-be-retained"),
        ),
        "sensitive_environment_names": ("LLM_API_KEY",),
        "working_directory": root,
        "attempt_root": root,
        "control_root": control_root,
        "wall_time_seconds": 1.0,
        "graceful_stop_seconds": 0.1,
        "hard_stop_seconds": 0.1,
        "output_limit_bytes": 1024,
        "requires_resource_custody": True,
        "custody_identity_digest": "sha256:" + "b" * 64,
        "network_policy_digest": "sha256:" + "c" * 64,
    }
    values.update(changes)
    return EngineLaunchPlan(**values)


def test_launch_plan_is_closed_and_public_receipt_omits_values(tmp_path: Path) -> None:
    value = plan(tmp_path)
    receipt = value.public_launch_receipt()
    encoded = json.dumps(receipt)
    assert receipt["environment_names"] == ["LANG", "LLM_API_KEY"]
    assert receipt["sensitive_environment_names"] == ["LLM_API_KEY"]
    assert "secret-that-must-not-be-retained" not in encoded
    assert "worker.py" not in encoded
    assert receipt["argv_sha256"].startswith("sha256:")


def test_launch_plan_rejects_relative_executable_and_mutable_environment_order(
    tmp_path: Path,
) -> None:
    with pytest.raises(EngineWorkerError, match="absolute"):
        plan(tmp_path, argv=("python", "worker.py"))
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(EngineWorkerError, match="outside"):
        plan(tmp_path, working_directory=other)
    nested_control = tmp_path / "attempt" / "controller-records"
    nested_control.mkdir()
    with pytest.raises(EngineWorkerError, match="outside the engine filesystem"):
        plan(tmp_path, control_root=nested_control)
    with pytest.raises(EngineWorkerError, match="sorted and unique"):
        plan(tmp_path, environment=(("Z_VALUE", "1"), ("A_VALUE", "2")))


def test_missing_custody_refuses_launch_and_never_retains_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)

    def forbidden(_plan: EngineLaunchPlan) -> runtime._OwnedProcess:
        raise AssertionError("worker must not start without independent custody")

    monkeypatch.setattr(EngineWorkerRuntime, "_start", staticmethod(forbidden))
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert outcome.execution_state is EngineExecutionState.STARTUP_FAILED
    assert outcome.cleanup_state is EngineCleanupState.UNKNOWN
    assert outcome.started is False
    assert outcome.issues == ("custody_unavailable",)
    control = launch.control_root / launch.attempt_id
    retained = (control / "launch.json").read_text(encoding="utf-8")
    retained += (control / "outcome.json").read_text(encoding="utf-8")
    assert "secret-that-must-not-be-retained" not in retained
    assert (control / "worker.stdout.bin").read_bytes() == b""
    assert (control / "worker.stderr.bin").read_bytes() == b""


def test_duplicate_reservation_never_resubmits_or_touches_custody(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(
        tmp_path,
        requires_resource_custody=False,
        custody_identity_digest=None,
        network_policy_digest=None,
    )
    process = FakeProcess(stdout=b"first", exit_code=0)
    calls = 0

    def start(_plan: EngineLaunchPlan) -> runtime._OwnedProcess:
        nonlocal calls
        calls += 1
        return runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))

    monkeypatch.setattr(EngineWorkerRuntime, "_start", staticmethod(start))
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    first = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    second = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert first.execution_state is EngineExecutionState.EXITED
    assert second == first
    assert calls == 1
    reservation = read_launch_reservation(launch.control_root, launch.attempt_id)
    assert reservation is not None and reservation["attempt_id"] == launch.attempt_id


def test_existing_in_progress_reservation_never_resubmits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(
        tmp_path,
        requires_resource_custody=False,
        custody_identity_digest=None,
        network_policy_digest=None,
    )
    control = launch.control_root / launch.attempt_id
    control.mkdir()
    receipt = launch.public_launch_receipt()
    receipt["reserved_at"] = runtime._utc_now()
    runtime._write_exclusive_json(control / "launch.json", receipt)

    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(lambda _plan: (_ for _ in ()).throw(AssertionError("must not resubmit"))),
    )
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert outcome.execution_state is EngineExecutionState.RESERVED
    assert outcome.cleanup_state is EngineCleanupState.UNKNOWN
    assert outcome.issues == ("launch_already_reserved",)


def test_success_caps_logs_and_verifies_process_and_resource_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(stdout=b"x" * 1500, stderr=b"warning", exit_code=2)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    custody = Custody(absent, absent)
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    outcome = EngineWorkerRuntime().run(
        launch,
        cancellation=Signal(False),
        custody=custody,
    )
    assert outcome.execution_state is EngineExecutionState.EXITED
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED
    assert outcome.exit_code == 2
    assert outcome.stdout.size_bytes == 1024 and outcome.stdout.truncated is True
    assert outcome.stderr.size_bytes == len(b"warning") and outcome.stderr.truncated is False
    assert custody.calls == [
        ("inspect", launch.attempt_id),
        ("stop", launch.attempt_id),
        ("inspect", launch.attempt_id),
    ]
    assert "secret-that-must-not-be-retained" not in json.dumps(outcome.to_dict())


def test_sensitive_environment_output_is_redacted_across_read_boundaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = b"secret-that-must-not-be-retained"
    output = b"x" * (runtime._READ_CHUNK - 3) + secret + b"-tail"
    launch = plan(tmp_path, output_limit_bytes=2 * runtime._READ_CHUNK)
    process = FakeProcess(stdout=output, stderr=output, exit_code=0)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    custody = Custody(absent, absent)
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False), custody=custody)
    control = launch.control_root / launch.attempt_id
    for name in ("worker.stdout.bin", "worker.stderr.bin"):
        retained = (control / name).read_bytes()
        assert secret not in retained
        assert b"[REDACTED]" in retained
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED


def test_streaming_redactor_handles_prefixes_and_large_no_match_input() -> None:
    redactor = runtime._StreamingRedactor((b"abcdefgh", b"abcdefgh-more"))
    assert redactor.feed(b"prefix-abc") == b""
    assert redactor.feed(b"defgh-more-suffix") == b"prefix-[REDACTED]"
    assert redactor.finish() == b"-suffix"

    large = b"x" * (2 * 1024 * 1024)
    no_match = runtime._StreamingRedactor((b"eight-byte-secret",))
    retained = no_match.feed(large) + no_match.finish()
    assert retained == large


@pytest.mark.parametrize("failing_start", [1, 2])
def test_log_drain_start_failure_retains_outcome_and_reconciles_custody(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failing_start: int
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(stdout=b"stdout", stderr=b"stderr", exit_code=0)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    custody = Custody(absent, absent)
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    original_start = runtime._LogDrain.start
    starts = 0

    def fail_selected(drain: runtime._LogDrain) -> None:
        nonlocal starts
        starts += 1
        if starts == failing_start:
            raise RuntimeError("injected thread start failure")
        original_start(drain)

    monkeypatch.setattr(runtime._LogDrain, "start", fail_selected)
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False), custody=custody)
    assert outcome.execution_state is EngineExecutionState.STARTUP_FAILED
    assert outcome.started is True
    assert outcome.cleanup_state is EngineCleanupState.UNKNOWN
    assert "worker_output_start_failed" in outcome.issues
    assert "output_cleanup_unknown" in outcome.issues
    assert custody.calls == [
        ("inspect", launch.attempt_id),
        ("stop", launch.attempt_id),
        ("inspect", launch.attempt_id),
    ]
    assert (launch.control_root / launch.attempt_id / "outcome.json").is_file()


def test_external_custody_stops_before_inherited_pipe_is_finalized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    released = threading.Event()
    process = FakeProcess(exit_code=0)
    process.stdout = BlockingReadStream(b"released-output", released)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)

    class ReleasingCustody(Custody):
        def stop_owned(
            self,
            attempt_id: str,
            *,
            custody_identity_digest: str,
            network_policy_digest: str,
            timeout_seconds: float,
        ) -> ResourceCustodySnapshot:
            released.set()
            return super().stop_owned(
                attempt_id,
                custody_identity_digest=custody_identity_digest,
                network_policy_digest=network_policy_digest,
                timeout_seconds=timeout_seconds,
            )

    custody = ReleasingCustody(absent, absent)
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False), custody=custody)
    retained = (launch.control_root / launch.attempt_id / "worker.stdout.bin").read_bytes()
    assert retained == b"released-output"
    assert outcome.stdout.size_bytes == len(retained)
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED


def test_cancellation_stops_started_worker_but_does_not_claim_engine_completion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(
        tmp_path,
        requires_resource_custody=False,
        custody_identity_digest=None,
        network_policy_digest=None,
    )
    process = FakeProcess(exit_code=None)

    def settle(_owned: runtime._OwnedProcess, _plan: EngineLaunchPlan) -> bool:
        process.returncode = -15
        return True

    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(EngineWorkerRuntime, "_settle_process", staticmethod(settle))
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False, True))
    assert outcome.execution_state is EngineExecutionState.CANCELLED
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED
    assert outcome.exit_code == -15


def test_deadline_is_distinct_from_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(
        tmp_path,
        wall_time_seconds=0.1,
        requires_resource_custody=False,
        custody_identity_digest=None,
        network_policy_digest=None,
    )
    process = FakeProcess(exit_code=None)

    def settle(_owned: runtime._OwnedProcess, _plan: EngineLaunchPlan) -> bool:
        process.returncode = -9
        return True

    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(EngineWorkerRuntime, "_settle_process", staticmethod(settle))
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert outcome.execution_state is EngineExecutionState.TIMED_OUT
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED


def test_external_resource_residue_preserves_cleanup_uncertainty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=0)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    unknown = ResourceCustodySnapshot(
        ResourceCustodyState.UNKNOWN,
        resource_ids=("container-a",),
        issue="inventory_failed",
    )
    custody = Custody(absent, unknown)
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_settle_process",
        staticmethod(lambda _owned, _plan: True),
    )
    outcome = EngineWorkerRuntime().run(
        launch,
        cancellation=Signal(False),
        custody=custody,
    )
    assert outcome.execution_state is EngineExecutionState.EXITED
    assert outcome.cleanup_state is EngineCleanupState.UNKNOWN
    assert outcome.issues == ("inventory_failed",)


def test_startup_failure_is_not_reported_as_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(
        tmp_path,
        requires_resource_custody=False,
        custody_identity_digest=None,
        network_policy_digest=None,
    )
    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(lambda _plan: (_ for _ in ()).throw(OSError("not found"))),
    )
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert outcome.execution_state is EngineExecutionState.STARTUP_FAILED
    assert outcome.started is False and outcome.exit_code is None
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED
    assert "worker_start_failed" in outcome.issues


def test_windows_assignment_failure_closes_unadopted_job_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=None)

    class Containment:
        instance: Containment

        def __init__(self, *, kill_on_close: bool) -> None:
            assert kill_on_close is True
            self.closed: list[int] = []
            self.terminated = 0
            Containment.instance = self

        def create_job(self) -> int:
            return 81

        def assign(self, job: int, child: FakeProcess) -> None:
            assert job == 81 and child is process
            raise runtime.RunnerTransportError("injected assignment failure")

        @staticmethod
        def resume_suspended(child: FakeProcess) -> None:
            raise AssertionError(f"unexpected resume for {child.pid}")

        def terminate(self, child: FakeProcess) -> bool:
            self.terminated += 1
            child.returncode = -1
            return True

        def close_handle(self, handle: int) -> bool:
            self.closed.append(handle)
            return True

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(runtime, "WindowsJobContainment", Containment)
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_options: process)
    with pytest.raises(runtime._EngineStartFailure) as captured:
        EngineWorkerRuntime._start(launch)
    assert captured.value.cleanup_verified is True
    assert process.returncode == -9
    assert Containment.instance.closed == [81]
    assert Containment.instance.terminated == 0


def test_windows_resume_failure_terminates_adopted_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=None)

    class Containment:
        instance: Containment

        def __init__(self, *, kill_on_close: bool) -> None:
            assert kill_on_close is True
            self.closed: list[int] = []
            self.terminated = 0
            Containment.instance = self

        def create_job(self) -> int:
            return 82

        def assign(self, job: int, child: FakeProcess) -> None:
            assert job == 82 and child is process

        @staticmethod
        def resume_suspended(child: FakeProcess) -> None:
            assert child is process
            raise runtime.RunnerTransportError("injected resume failure")

        def terminate(self, child: FakeProcess) -> bool:
            self.terminated += 1
            child.returncode = -1
            return True

        def close_handle(self, handle: int) -> bool:
            self.closed.append(handle)
            return True

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(runtime, "WindowsJobContainment", Containment)
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_options: process)
    with pytest.raises(runtime._EngineStartFailure) as captured:
        EngineWorkerRuntime._start(launch)
    assert captured.value.cleanup_verified is True
    assert Containment.instance.terminated == 1
    assert Containment.instance.closed == []


def test_windows_interrupt_before_start_returns_reconciles_before_reraising(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=None)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    custody = Custody(absent, absent)

    class Containment:
        def __init__(self, *, kill_on_close: bool) -> None:
            assert kill_on_close is True

        def create_job(self) -> int:
            return 83

        def assign(self, job: int, child: FakeProcess) -> None:
            assert job == 83 and child is process

        @staticmethod
        def resume_suspended(child: FakeProcess) -> None:
            assert child is process
            raise KeyboardInterrupt

        def terminate(self, child: FakeProcess) -> bool:
            child.returncode = -1
            return True

        def close_handle(self, _handle: int) -> bool:
            return True

    monkeypatch.setattr(runtime.sys, "platform", "win32")
    monkeypatch.setattr(runtime, "WindowsJobContainment", Containment)
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_options: process)
    with pytest.raises(KeyboardInterrupt):
        EngineWorkerRuntime().run(launch, cancellation=Signal(False), custody=custody)
    retained = runtime.read_worker_outcome(launch.control_root, launch.attempt_id)
    assert retained is not None
    assert retained.execution_state is EngineExecutionState.INTERRUPTED
    assert retained.started is True
    assert custody.calls == [
        ("inspect", launch.attempt_id),
        ("stop", launch.attempt_id),
        ("inspect", launch.attempt_id),
    ]


def test_interrupt_after_start_reconciles_before_reraising(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=None)
    absent = ResourceCustodySnapshot(ResourceCustodyState.VERIFIED_ABSENT)
    custody = Custody(absent, absent)

    class InterruptAfterPrecheck:
        calls = 0

        def is_set(self) -> bool:
            self.calls += 1
            if self.calls > 1:
                raise KeyboardInterrupt
            return False

    def settle(_owned: runtime._OwnedProcess, _plan: EngineLaunchPlan) -> bool:
        process.returncode = -9
        return True

    monkeypatch.setattr(
        EngineWorkerRuntime,
        "_start",
        staticmethod(
            lambda _plan: runtime._OwnedProcess(cast(runtime.subprocess.Popen[bytes], process))
        ),
    )
    monkeypatch.setattr(EngineWorkerRuntime, "_settle_process", staticmethod(settle))
    with pytest.raises(KeyboardInterrupt):
        EngineWorkerRuntime().run(
            launch,
            cancellation=InterruptAfterPrecheck(),
            custody=custody,
        )
    retained = runtime.read_worker_outcome(launch.control_root, launch.attempt_id)
    assert retained is not None
    assert retained.execution_state is EngineExecutionState.INTERRUPTED
    assert retained.cleanup_state is EngineCleanupState.VERIFIED
    assert retained.issues == ("controller_interrupted",)
    assert custody.calls == [
        ("inspect", launch.attempt_id),
        ("stop", launch.attempt_id),
        ("inspect", launch.attempt_id),
    ]


def test_windows_settlement_is_explicit_job_hard_stop(tmp_path: Path) -> None:
    launch = plan(tmp_path)
    process = FakeProcess(exit_code=None)

    class Containment:
        def __init__(self) -> None:
            self.finished = 0

        def finish(self, child: FakeProcess) -> bool:
            assert child is process
            self.finished += 1
            child.returncode = -1
            return True

    containment = Containment()
    owned = runtime._OwnedProcess(
        cast(runtime.subprocess.Popen[bytes], process),
        cast(runtime.WindowsJobContainment, containment),
    )
    assert EngineWorkerRuntime._settle_process(owned, launch) is True
    assert containment.finished == 1
    assert process.signals == []


def test_custody_snapshot_rejects_ambiguous_identity_sets() -> None:
    with pytest.raises(EngineWorkerError, match="sorted and unique"):
        ResourceCustodySnapshot(
            ResourceCustodyState.PRESENT,
            resource_ids=("container-b", "container-a"),
        )
    with pytest.raises(EngineWorkerError, match="require bounded identities"):
        ResourceCustodySnapshot(ResourceCustodyState.PRESENT)


def test_reconnect_rejects_tampered_or_duplicate_launch_receipt(tmp_path: Path) -> None:
    launch = plan(tmp_path)
    control_root = launch.control_root
    control = control_root / launch.attempt_id
    control.mkdir()
    receipt = control / "launch.json"
    receipt.write_text(
        '{"schema_version":"bluefire.engine-launch-reservation.v1"}', encoding="utf-8"
    )
    assert read_launch_reservation(control_root, control.name) is None
    receipt.write_text(
        '{"schema_version":"bluefire.engine-launch-reservation.v1",'
        '"schema_version":"bluefire.engine-launch-reservation.v1"}',
        encoding="utf-8",
    )
    assert read_launch_reservation(control_root, control.name) is None

    valid = launch.public_launch_receipt()
    valid["reserved_at"] = runtime._utc_now()
    receipt.write_text(json.dumps(valid), encoding="utf-8")
    assert read_launch_reservation(control_root, launch.attempt_id) is not None
    copied = control_root / "attempt-copied"
    copied.mkdir()
    copied.joinpath("launch.json").write_text(json.dumps(valid), encoding="utf-8")
    assert read_launch_reservation(control_root, copied.name) is None


def test_linux_proc_inventory_handles_names_with_spaces_and_parentheses(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    for process_id, name, group, session in (
        (1, "init", 1, 1),
        (2, "kthreadd", 0, 0),
        (301, "engine (root)", 301, 301),
        (302, "child worker", 301, 301),
        (401, "unrelated", 401, 401),
    ):
        directory = proc / str(process_id)
        directory.mkdir(parents=True)
        fields = ["S", "1", str(group), str(session), *(["0"] * 15), str(process_id * 10)]
        directory.joinpath("stat").write_text(
            f"{process_id} ({name}) {' '.join(fields)}\n",
            encoding="ascii",
        )
    assert runtime._linux_process_identity(1, proc_root=proc) == (1, 1, "S", 10)
    assert runtime._linux_process_identity(2, proc_root=proc) == (0, 0, "S", 20)
    assert runtime._linux_process_identity(301, proc_root=proc) == (301, 301, "S", 3010)
    assert runtime._linux_private_session_members(301, 301, proc_root=proc) == {301, 302}


@pytest.mark.parametrize(("group", "session"), ((-1, 0), (0, -1), (-1, -1)))
def test_linux_proc_identity_rejects_negative_scope(
    tmp_path: Path, group: int, session: int
) -> None:
    proc = tmp_path / "proc"
    directory = proc / "1"
    directory.mkdir(parents=True)
    fields = ["S", "0", str(group), str(session), *("0" for _ in range(15)), "10"]
    directory.joinpath("stat").write_text(
        f"1 (init) {' '.join(fields)}\n",
        encoding="ascii",
    )
    assert runtime._linux_process_identity(1, proc_root=proc) is None


def test_linux_proc_inventory_fails_closed_for_persistent_unreadable_pid(
    tmp_path: Path,
) -> None:
    proc = tmp_path / "proc"
    (proc / "301").mkdir(parents=True)
    assert runtime._linux_private_session_members(301, 301, proc_root=proc) is None


def test_linux_pidfd_signal_rechecks_captured_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = (301, 301, "S", 100)
    sent: list[tuple[int, int]] = []
    closed: list[int] = []
    monkeypatch.setattr(runtime.os, "pidfd_open", lambda _pid, _flags: 71, raising=False)
    monkeypatch.setattr(
        runtime.signal,
        "pidfd_send_signal",
        lambda descriptor, number, _info, _flags: sent.append((descriptor, number)),
        raising=False,
    )
    monkeypatch.setattr(
        runtime,
        "_linux_process_identity",
        lambda _pid: (301, 301, "S", 101),
    )
    monkeypatch.setattr(runtime.os, "close", lambda descriptor: closed.append(descriptor))
    assert runtime._linux_signal_pidfd(301, captured, 15) is False
    assert sent == []
    assert closed == [71]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process inventory")
@pytest.mark.parametrize("with_descendant", [False, True])
def test_real_linux_natural_exit_reaps_leader_and_owned_group(
    tmp_path: Path, with_descendant: bool
) -> None:
    root = tmp_path / "attempt"
    control_root = tmp_path / "controller-records"
    root.mkdir()
    control_root.mkdir()
    if with_descendant:
        source = (
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(60)']);"
            "print(p.pid,flush=True)"
        )
    else:
        source = "print('done',flush=True)"
    launch = EngineLaunchPlan(
        attempt_id=f"attempt-linux-{int(with_descendant)}",
        plan_digest="sha256:" + "d" * 64,
        argv=(str(Path(sys.executable).resolve()), "-I", "-B", "-c", source),
        environment=(("LANG", "C"), ("PYTHONDONTWRITEBYTECODE", "1")),
        working_directory=root,
        attempt_root=root,
        control_root=control_root,
        wall_time_seconds=5.0,
        graceful_stop_seconds=2.0,
        hard_stop_seconds=2.0,
        output_limit_bytes=4096,
        requires_resource_custody=False,
    )
    outcome = EngineWorkerRuntime().run(launch, cancellation=Signal(False))
    assert outcome.execution_state is EngineExecutionState.EXITED
    assert outcome.cleanup_state is EngineCleanupState.VERIFIED
    assert outcome.exit_code == 0
    if with_descendant:
        child_pid = int(
            (control_root / launch.attempt_id / "worker.stdout.bin")
            .read_text(encoding="ascii")
            .strip()
        )
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
