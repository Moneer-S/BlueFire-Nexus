from __future__ import annotations

import json
import os
import signal
import stat
import subprocess  # nosec B404
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.runner_client import (
    RunnerDurableResultExists,
    RunnerPendingResultExists,
    RunnerTaskCancelled,
    RunnerTransportError,
    SubprocessRustRunner,
    cleanup_runner_watchdog_terminal_state,
    runner_pending_result_path,
    runner_watchdog_control_root,
    runner_watchdog_ready_path,
    runner_watchdog_status_path,
)

_HELPER = r"""
import json
import os
import subprocess
import sys
import time

arguments = sys.argv[1:]
manifest_path = arguments[arguments.index("--manifest") + 1]
with open(manifest_path, "r", encoding="utf-8") as stream:
    manifest = json.load(stream)
profile_path = arguments[arguments.index("--profile") + 1]
with open(profile_path, "r", encoding="utf-8") as stream:
    profile = json.load(stream)
behavior = manifest.get("test_behavior", "success")

if behavior == "sleep":
    time.sleep(60)
elif behavior == "descendant":
    descendant = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(manifest["descendant_pid_path"], "w", encoding="ascii") as stream:
        stream.write(str(descendant.pid))
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(60)
elif behavior == "orphan_after_exit":
    descendant = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(manifest["descendant_pid_path"], "w", encoding="ascii") as stream:
        stream.write(str(descendant.pid))
        stream.flush()
        os.fsync(stream.fileno())
elif behavior == "effect_then_result":
    with open(manifest["effect_marker_path"], "w", encoding="ascii") as stream:
        stream.write("effect-complete")
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(0.75)
elif behavior == "self_pid_sleep":
    with open(manifest["runner_pid_path"], "w", encoding="ascii") as stream:
        stream.write(str(os.getpid()))
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(60)
elif behavior == "oversized":
    sys.stdout.write("x" * (128 * 1024))
    sys.stdout.flush()
    raise SystemExit(0)
elif behavior == "duplicate_json":
    sys.stdout.write(
        '{"schema_version":"bluefire.runner-result.v1",'
        '"schema_version":"bluefire.runner-result.v1",'
        '"run_id":"run-20260825T120000Z-0123456789abcdef",'
        '"step_id":"controlled-helper",'
        '"action_id":"sandbox.fixture.create.v1"}'
    )
    sys.stdout.flush()
    raise SystemExit(0)
elif behavior == "nonfinite_json":
    sys.stdout.write(
        '{"schema_version":"bluefire.runner-result.v1",'
        '"run_id":"run-20260825T120000Z-0123456789abcdef",'
        '"step_id":"controlled-helper",'
        '"action_id":"sandbox.fixture.create.v1",'
        '"unsafe_number":NaN}'
    )
    sys.stdout.flush()
    raise SystemExit(0)
elif behavior == "invalid":
    result = {"schema_version": "unsupported"}
    sys.stdout.write(json.dumps(result, sort_keys=True))
    sys.stdout.flush()
    raise SystemExit(0)

result = {
    "schema_version": "bluefire.runner-result.v1",
    "run_id": manifest["run_id"],
    "step_id": manifest["step_id"],
    "action_id": manifest["action_id"],
    "status": "succeeded",
}
for field in (
    "request_id",
    "behavior_id",
    "runner_id",
    "runner_profile_id",
    "platform",
    "request_hash",
    "policy_digest",
):
    if field in manifest:
        result[field] = manifest[field]
profile_bindings = {
    "runner_id": "runner_id",
    "runner_profile_id": "profile_id",
    "platform": "platform",
    "policy_digest": "policy_digest",
}
for result_field, profile_field in profile_bindings.items():
    if profile_field in profile:
        result[result_field] = profile[profile_field]
result.update(manifest.get("result_override", {}))
sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
sys.stdout.flush()
"""

_PARENT_DRIVER = r"""
import json
import sys
import threading
from pathlib import Path

from bluefire.runner_client import SubprocessRustRunner

runner = SubprocessRustRunner(
    Path(sys.argv[1]).resolve(strict=True),
    Path(sys.argv[2]).resolve(strict=True),
    timeout_seconds=float(sys.argv[5]) if len(sys.argv) > 5 else 10.0,
    output_limit_bytes=64 * 1024,
)
with open(sys.argv[4], "r", encoding="utf-8") as stream:
    manifest = json.load(stream)
runner.execute_task(
    manifest,
    {},
    task_id="task-parent-loss-01",
    cancel_event=threading.Event(),
    durable_result_path=Path(sys.argv[3]).resolve(),
)
"""


def _manifest(behavior: str = "success", **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.runner-manifest.v1",
        "run_id": "run-20260825T120000Z-0123456789abcdef",
        "step_id": "controlled-helper",
        "action_id": "sandbox.fixture.create.v1",
        "test_behavior": behavior,
        **extra,
    }


def _full_manifest(behavior: str = "success", **extra: Any) -> dict[str, Any]:
    platform = "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
    return {
        **_manifest(behavior, **extra),
        "schema_version": "bluefire.runner-task-manifest.v1",
        "request_id": "request-watchdog-01",
        "behavior_id": "sandbox.fixture.create.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_profile_id": "sandbox-execute.v1",
        "platform": platform,
        "request_hash": "sha256:" + "1" * 64,
        "policy_digest": "sha256:" + "2" * 64,
    }


def _full_profile() -> dict[str, Any]:
    platform = "windows" if os.name == "nt" else "macos" if sys.platform == "darwin" else "linux"
    return {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": "sandbox-execute.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "platform": platform,
        "policy_digest": "sha256:" + "2" * 64,
    }


def _runner(
    tmp_path: Path,
    *,
    timeout_seconds: float = 5.0,
) -> SubprocessRustRunner:
    work_root = tmp_path / "runner-work"
    work_root.mkdir()
    (work_root / "execute").write_text(_HELPER, encoding="utf-8")
    return SubprocessRustRunner(
        Path(sys.executable).resolve(strict=True),
        work_root,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=64 * 1024,
    )


def _wait_for_file(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return
        time.sleep(0.025)
    raise AssertionError("helper did not publish its descendant pid")


def _pid_is_running(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
        process_query_limited_information, False, pid
    )
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetExitCodeProcess(  # type: ignore[attr-defined]
            handle, ctypes.byref(exit_code)
        ):
            return False
        return exit_code.value == still_active
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def test_execute_task_promotes_complete_stdout_and_preserves_execute_contract(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)
    manifest = _manifest()
    durable = (tmp_path / "durable" / "task-result.json").resolve()
    result = runner.execute_task(
        manifest,
        {},
        task_id="task-success-01",
        cancel_event=threading.Event(),
        durable_result_path=durable,
    )

    assert result["status"] == "succeeded"
    assert json.loads(durable.read_text(encoding="utf-8")) == result
    if os.name != "nt":
        assert stat.S_IMODE(durable.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(durable.stat().st_mode) == 0o600
    assert not runner_pending_result_path(durable, "task-success-01").exists()
    assert not list(runner.work_root.glob("request-*"))

    legacy = runner.execute(manifest, {})
    assert legacy == result
    assert not list(runner.work_root.glob("request-*"))


def test_execute_task_rejects_invalid_result_without_promoting_it(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "task-result.json").resolve()

    with pytest.raises(RunnerTransportError, match="unsupported result schema"):
        runner.execute_task(
            _manifest("invalid"),
            {},
            task_id="task-invalid-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, "task-invalid-01").exists()
    assert not list(runner.work_root.glob("request-*"))


def test_execute_task_timeout_stops_child_and_cleans_pending_result(tmp_path: Path) -> None:
    runner = _runner(tmp_path, timeout_seconds=0.2)
    durable = (tmp_path / "durable" / "task-result.json").resolve()

    with pytest.raises(RunnerTransportError, match="timed out"):
        runner.execute_task(
            _manifest("sleep"),
            {},
            task_id="task-timeout-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, "task-timeout-01").exists()
    assert not list(runner.work_root.glob("request-*"))


def test_execute_task_enforces_stdout_limit_and_cleans_pending_result(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "task-result.json").resolve()

    with pytest.raises(RunnerTransportError, match="output limit"):
        runner.execute_task(
            _manifest("oversized"),
            {},
            task_id="task-oversized-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, "task-oversized-01").exists()
    assert not list(runner.work_root.glob("request-*"))


@pytest.mark.parametrize("behavior", ["duplicate_json", "nonfinite_json"])
def test_execute_task_rejects_ambiguous_or_nonstandard_json(
    tmp_path: Path,
    behavior: str,
) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "task-result.json").resolve()

    with pytest.raises(RunnerTransportError, match="not valid UTF-8 JSON"):
        runner.execute_task(
            _manifest(behavior),
            {},
            task_id=f"task-{behavior}-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, f"task-{behavior}-01").exists()


def test_execute_task_cancellation_confirms_descendant_process_is_stopped(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path, timeout_seconds=20.0)
    durable = (tmp_path / "durable" / "task-result.json").resolve()
    descendant_pid_path = (tmp_path / "descendant.pid").resolve()
    cancel_event = threading.Event()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runner.execute_task,
            _manifest("descendant", descendant_pid_path=str(descendant_pid_path)),
            {},
            task_id="task-cancel-01",
            cancel_event=cancel_event,
            durable_result_path=durable,
        )
        _wait_for_file(descendant_pid_path)
        descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
        assert _pid_is_running(descendant_pid)
        cancel_event.set()
        with pytest.raises(RunnerTaskCancelled, match="process tree stopped"):
            future.result(timeout=10)

    # Cancellation is not reported merely because a kill was sent. The
    # watchdog confirms its inner Job/process group is empty first.
    assert not _pid_is_running(descendant_pid)
    assert not durable.exists()
    assert not runner_pending_result_path(durable, "task-cancel-01").exists()
    assert not list(runner.work_root.glob("request-*"))


def test_normal_runner_exit_does_not_leave_descendants_running(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "task-result.json").resolve()
    descendant_pid_path = (tmp_path / "orphan.pid").resolve()

    result = runner.execute_task(
        _manifest("orphan_after_exit", descendant_pid_path=str(descendant_pid_path)),
        {},
        task_id="task-orphan-01",
        cancel_event=threading.Event(),
        durable_result_path=durable,
    )

    descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
    assert result["status"] == "succeeded"
    assert not _pid_is_running(descendant_pid)


def test_parent_loss_allows_watchdog_to_publish_recoverable_result(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "task-result.json").resolve()
    durable.parent.mkdir()
    effect_marker = (tmp_path / "effect-complete").resolve()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            _manifest("effect_then_result", effect_marker_path=str(effect_marker)),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    driver_path = tmp_path / "parent_driver.py"
    driver_path.write_text(_PARENT_DRIVER, encoding="utf-8")
    parent = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            str(driver_path),
            sys.executable,
            str(runner.work_root),
            str(durable),
            str(manifest_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        _wait_for_file(effect_marker)
        parent.kill()
        parent.wait(timeout=5)

        pending = runner_pending_result_path(durable, "task-parent-loss-01")
        status_path = runner_watchdog_status_path(durable, "task-parent-loss-01")
        control_root = runner_watchdog_control_root(durable, "task-parent-loss-01")
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            terminal_entries = (
                {entry.name for entry in control_root.iterdir()} if control_root.is_dir() else set()
            )
            if durable.is_file() and status_path.is_file() and terminal_entries == {"status.json"}:
                break
            time.sleep(0.025)
        recovered = json.loads(durable.read_text(encoding="utf-8"))
        assert recovered["schema_version"] == "bluefire.runner-result.v1"
        assert recovered["run_id"] == _manifest()["run_id"]
        assert not pending.exists()
        status = json.loads(status_path.read_text(encoding="utf-8"))
        assert status["state"] == "succeeded"
        assert {entry.name for entry in control_root.iterdir()} == {"status.json"}
        cleanup_runner_watchdog_terminal_state(durable, "task-parent-loss-01")
        assert not control_root.exists()
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)


def test_pending_result_path_is_deterministic_and_task_id_cannot_select_a_path(
    tmp_path: Path,
) -> None:
    durable = (tmp_path / "result.json").resolve()

    first = runner_pending_result_path(durable, "task-01")
    assert first == runner_pending_result_path(durable, "task-01")
    assert first != runner_pending_result_path(durable, "task-02")
    assert first.parent == durable.parent
    assert first.name.startswith(".bluefire-result-")

    with pytest.raises(RunnerTransportError, match="task identity"):
        runner_pending_result_path(durable, "../escape")
    with pytest.raises(RunnerTransportError, match="destination"):
        runner_pending_result_path(Path("relative.json"), "task-01")


def test_existing_pending_result_is_preserved_for_restart_reconciliation(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    pending = runner_pending_result_path(durable, "task-recovery-01")
    recovery_bytes = b'{"schema_version":"bluefire.runner-result.v1"}\n'
    pending.write_bytes(recovery_bytes)

    with pytest.raises(RunnerPendingResultExists, match="requires recovery"):
        runner.execute_task(
            _manifest(),
            {},
            task_id="task-recovery-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert pending.read_bytes() == recovery_bytes


def test_atomic_promotion_refuses_racing_final_and_preserves_both_results(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "result.json").resolve()
    effect_marker = (tmp_path / "effect-for-race").resolve()
    cancel_event = threading.Event()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runner.execute_task,
            _manifest("effect_then_result", effect_marker_path=str(effect_marker)),
            {},
            task_id="task-final-race-01",
            cancel_event=cancel_event,
            durable_result_path=durable,
        )
        _wait_for_file(effect_marker)
        sentinel = b"pre-existing-final"
        durable.write_bytes(sentinel)
        with pytest.raises(RunnerDurableResultExists, match="requires reconciliation"):
            future.result(timeout=10)

    assert durable.read_bytes() == sentinel
    pending = runner_pending_result_path(durable, "task-final-race-01")
    recovered = json.loads(pending.read_text(encoding="utf-8"))
    assert recovered["schema_version"] == "bluefire.runner-result.v1"
    pending.unlink()


def test_durable_result_parent_must_not_be_a_link_or_reparse_point(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    real_parent = tmp_path / "real-results"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-results"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(RunnerTransportError, match="destination is unavailable"):
        runner.execute_task(
            _manifest(),
            {},
            task_id="task-linked-root-01",
            cancel_event=threading.Event(),
            durable_result_path=(linked_parent / "result.json").absolute(),
        )


def test_parent_loss_hung_runner_is_killed_by_watchdog_deadline(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "hung-result.json").resolve()
    durable.parent.mkdir()
    runner_pid_path = (tmp_path / "hung-runner.pid").resolve()
    manifest_path = tmp_path / "hung-manifest.json"
    manifest_path.write_text(
        json.dumps(
            _manifest("self_pid_sleep", runner_pid_path=str(runner_pid_path)),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    driver_path = tmp_path / "hung-parent-driver.py"
    driver_path.write_text(_PARENT_DRIVER, encoding="utf-8")
    parent = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            str(driver_path),
            sys.executable,
            str(runner.work_root),
            str(durable),
            str(manifest_path),
            "0.35",
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    runner_pid: int | None = None
    try:
        _wait_for_file(runner_pid_path)
        runner_pid = int(runner_pid_path.read_text(encoding="ascii"))
        assert _pid_is_running(runner_pid)
        parent.kill()
        parent.wait(timeout=5)

        stopped_deadline = time.monotonic() + 10.0
        while _pid_is_running(runner_pid) and time.monotonic() < stopped_deadline:
            time.sleep(0.025)
        assert not _pid_is_running(runner_pid)

        status_path = runner_watchdog_status_path(durable, "task-parent-loss-01")
        _wait_for_file(status_path, timeout=10)
        status = json.loads(status_path.read_text(encoding="utf-8"))
        assert status["state"] == "failed"
        assert status["error_code"] == "timed_out"
        assert not durable.exists()
        assert not runner_pending_result_path(durable, "task-parent-loss-01").exists()
        cleanup_runner_watchdog_terminal_state(durable, "task-parent-loss-01")
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if runner_pid is not None and _pid_is_running(runner_pid):
            os.kill(runner_pid, signal.SIGTERM)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job assignment gate")
def test_windows_watchdog_gate_blocks_rust_until_outer_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path, timeout_seconds=10.0)
    durable = (tmp_path / "durable" / "gated-result.json").resolve()
    effect_marker = (tmp_path / "gated-effect").resolve()
    assignment_entered = threading.Event()
    release_assignment = threading.Event()
    original_assignment = runner._assign_windows_job

    def delayed_assignment(job: int, process: subprocess.Popen[bytes]) -> None:
        assignment_entered.set()
        if not release_assignment.wait(timeout=10):
            raise RunnerTransportError("synthetic assignment release timed out")
        original_assignment(job, process)

    monkeypatch.setattr(runner, "_assign_windows_job", delayed_assignment)
    cancel_event = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runner.execute_task,
            _manifest("effect_then_result", effect_marker_path=str(effect_marker)),
            {},
            task_id="task-gated-start-01",
            cancel_event=cancel_event,
            durable_result_path=durable,
        )
        try:
            assert assignment_entered.wait(timeout=5)
            ready = runner_watchdog_ready_path(durable, "task-gated-start-01")
            _wait_for_file(ready)
            time.sleep(0.25)
            assert not effect_marker.exists()
        finally:
            release_assignment.set()
        result = future.result(timeout=15)

    assert result["status"] == "succeeded"
    assert effect_marker.read_text(encoding="ascii") == "effect-complete"


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended inner Job start")
def test_windows_inner_rust_is_suspended_until_kill_on_close_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _runner(tmp_path)
    runner = SubprocessRustRunner(
        base.runner_binary,
        base.work_root,
        timeout_seconds=10.0,
        output_limit_bytes=64 * 1024,
        _kill_child_on_job_close=True,
    )
    effect_marker = (tmp_path / "inner-gated-effect").resolve()
    assignment_entered = threading.Event()
    release_assignment = threading.Event()
    original_assignment = runner._assign_windows_job

    def delayed_assignment(job: int, process: subprocess.Popen[bytes]) -> None:
        assignment_entered.set()
        if not release_assignment.wait(timeout=10):
            raise RunnerTransportError("synthetic inner assignment release timed out")
        original_assignment(job, process)

    monkeypatch.setattr(runner, "_assign_windows_job", delayed_assignment)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            runner.execute,
            _manifest("effect_then_result", effect_marker_path=str(effect_marker)),
            {},
        )
        try:
            assert assignment_entered.wait(timeout=5)
            time.sleep(0.25)
            assert not effect_marker.exists()
        finally:
            release_assignment.set()
        result = future.result(timeout=15)

    assert result["status"] == "succeeded"
    assert effect_marker.read_text(encoding="ascii") == "effect-complete"


@pytest.mark.parametrize(
    ("field", "mismatch"),
    [
        ("schema_version", "unsupported"),
        ("request_id", "request-other"),
        ("run_id", "run-other"),
        ("step_id", "step-other"),
        ("behavior_id", "sandbox.other.v1"),
        ("action_id", "sandbox.fixture.transform.v1"),
        ("runner_id", "runner-other.v1"),
        ("runner_profile_id", "profile-other.v1"),
        ("platform", "other"),
        ("request_hash", "sha256:" + "9" * 64),
        ("policy_digest", "sha256:" + "8" * 64),
    ],
)
def test_exact_identity_mismatch_never_publishes_result(
    tmp_path: Path,
    field: str,
    mismatch: str,
) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / f"mismatch-{field}.json").resolve()
    task_id = f"task-mismatch-{field}"
    manifest = _full_manifest(result_override={field: mismatch})

    with pytest.raises(RunnerTransportError):
        runner.execute_task(
            manifest,
            _full_profile(),
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, task_id).exists()
    assert not runner_watchdog_control_root(durable, task_id).exists()


def test_caller_interruption_requests_watchdog_cancel_before_unwinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CallerInterrupted(BaseException):
        pass

    runner = _runner(tmp_path, timeout_seconds=20.0)
    durable = (tmp_path / "durable" / "interrupted.json").resolve()
    runner_pid_path = (tmp_path / "interrupted-runner.pid").resolve()
    task_id = "task-caller-interrupted-01"

    def interrupt_after_dispatch(
        _process: subprocess.Popen[bytes],
        **_kwargs: Any,
    ) -> Mapping[str, Any]:
        _wait_for_file(runner_pid_path)
        raise CallerInterrupted()

    monkeypatch.setattr(runner, "_await_watchdog", interrupt_after_dispatch)
    with pytest.raises(CallerInterrupted):
        runner.execute_task(
            _manifest("self_pid_sleep", runner_pid_path=str(runner_pid_path)),
            {},
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    runner_pid = int(runner_pid_path.read_text(encoding="ascii"))
    assert not _pid_is_running(runner_pid)
    assert not durable.exists()
    assert not runner_pending_result_path(durable, task_id).exists()
    assert not runner_watchdog_control_root(durable, task_id).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows KILL_ON_JOB_CLOSE guarantee")
def test_watchdog_crash_kills_rust_after_request_host_is_gone(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "watchdog-crash.json").resolve()
    durable.parent.mkdir()
    runner_pid_path = (tmp_path / "watchdog-crash-runner.pid").resolve()
    manifest_path = tmp_path / "watchdog-crash-manifest.json"
    manifest_path.write_text(
        json.dumps(
            _manifest("self_pid_sleep", runner_pid_path=str(runner_pid_path)),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    driver_path = tmp_path / "watchdog-crash-parent.py"
    driver_path.write_text(_PARENT_DRIVER, encoding="utf-8")
    parent = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            str(driver_path),
            sys.executable,
            str(runner.work_root),
            str(durable),
            str(manifest_path),
            "20",
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    runner_pid: int | None = None
    watchdog_pid: int | None = None
    try:
        _wait_for_file(runner_pid_path)
        runner_pid = int(runner_pid_path.read_text(encoding="ascii"))
        ready_path = runner_watchdog_ready_path(durable, "task-parent-loss-01")
        _wait_for_file(ready_path)
        watchdog_pid = int(json.loads(ready_path.read_text(encoding="utf-8"))["watchdog_pid"])
        assert _pid_is_running(runner_pid)
        assert _pid_is_running(watchdog_pid)

        # Close the outer request-host Job handle first. The watchdog and Rust
        # continue; only the watchdog-owned inner KILL_ON_JOB_CLOSE Job remains.
        parent.kill()
        parent.wait(timeout=5)
        assert _pid_is_running(runner_pid)
        os.kill(watchdog_pid, signal.SIGTERM)

        stopped_deadline = time.monotonic() + 10.0
        while _pid_is_running(runner_pid) and time.monotonic() < stopped_deadline:
            time.sleep(0.025)
        assert not _pid_is_running(runner_pid)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        for process_id in (watchdog_pid, runner_pid):
            if process_id is not None and _pid_is_running(process_id):
                os.kill(process_id, signal.SIGTERM)
