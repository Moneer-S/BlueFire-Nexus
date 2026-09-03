from __future__ import annotations

import errno
import json
import os
import shutil
import signal
import socket
import stat
import subprocess  # nosec B404
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Mapping, cast

import pytest

import bluefire.runner_client as runner_client_module
import bluefire.runner_darwin_containment as darwin_containment_module
import bluefire.runner_private_files as private_files_module
import bluefire.runner_trust as runner_trust_module
import bluefire.runner_watchdog as runner_watchdog_module
from bluefire.runner_client import (
    RunnerDurableResultExists,
    RunnerPendingResultExists,
    RunnerTaskCancelled,
    RunnerTransportError,
    SubprocessRustRunner,
    cleanup_runner_watchdog_terminal_state,
    request_runner_task_cancel,
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
child_runtime = (
    os.path.realpath("/proc/self/exe") if sys.platform.startswith("linux") else sys.executable
)

if behavior == "sleep":
    time.sleep(60)
elif behavior == "descendant":
    descendant = subprocess.Popen(
        [child_runtime, "-c", "import time; time.sleep(60)"],
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
        [child_runtime, "-c", "import time; time.sleep(60)"],
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
if behavior == "receiver_environment":
    receiver_key = os.environ.get("BLUEFIRE_RECEIVER_TASK_KEY", "")
    result["receiver_environment"] = {
        "names": sorted(
            name for name in os.environ if name.startswith("BLUEFIRE_RECEIVER_")
        ),
        "task_id": os.environ.get("BLUEFIRE_RECEIVER_TASK_ID"),
        "key_is_lower_hex_64": (
            len(receiver_key) == 64
            and all(character in "0123456789abcdef" for character in receiver_key)
        ),
    }
sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
sys.stdout.flush()
"""

_PARENT_DRIVER = r"""
import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from bluefire.runner_client import SubprocessRustRunner

runner = SubprocessRustRunner(
    Path(sys.argv[1]).resolve(strict=True),
    Path(sys.argv[2]).resolve(strict=True),
    timeout_seconds=float(sys.argv[5]) if len(sys.argv) > 5 else 10.0,
    output_limit_bytes=64 * 1024,
    _watchdog_interpreter=(
        Path(sys.executable).resolve(strict=True) if sys.platform == "darwin" else None
    ),
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

# Process publication can follow nested interpreter/watchdog startup under loaded CI.
# This harness allowance does not alter runner or watchdog semantic deadlines.
_NESTED_PROCESS_START_TIMEOUT_SECONDS = 15.0
# Keep the synthetic deadline long enough to observe a live runner before parent loss.
_PARENT_LOSS_TEST_RUNNER_TIMEOUT_SECONDS = 2.0


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
    durable_result_guard: private_files_module._PinnedPrivateDirectory | None = None,
) -> SubprocessRustRunner:
    work_root = tmp_path / "runner-work"
    work_root.mkdir(mode=0o700)
    (work_root / "execute").write_text(_HELPER, encoding="utf-8")
    runner_binary = Path(sys.executable).resolve(strict=True)
    watchdog_interpreter: Path | None = None
    if sys.platform == "darwin":
        copied_binary = work_root / "python-runner"
        shutil.copyfile(runner_binary, copied_binary)
        copied_binary.chmod(0o700)
        runner_binary = copied_binary
        watchdog_interpreter = work_root / "python-watchdog"
        shutil.copyfile(sys.executable, watchdog_interpreter)
        watchdog_interpreter.chmod(0o700)
    return SubprocessRustRunner(
        runner_binary,
        work_root,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=64 * 1024,
        durable_result_guard=durable_result_guard,
        _watchdog_interpreter=watchdog_interpreter,
    )


def _isolated_module(source: ModuleType, **overrides: object) -> ModuleType:
    isolated = ModuleType(source.__name__)
    isolated.__dict__.update(vars(source))
    isolated.__dict__.update(overrides)
    return isolated


@pytest.mark.skipif(os.name != "nt", reason="Windows child environment contract")
def test_windows_spawn_uses_owned_work_root_for_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    assert os.environ.get("TEMP") != str(runner.work_root)
    assert os.environ.get("TMP") != str(runner.work_root)
    monkeypatch.setenv("BLUEFIRE_AMBIENT_MARKER", "must-not-cross-boundary")
    probe = (
        "import json,os,tempfile;"
        "print(json.dumps({'ambient':os.environ.get('BLUEFIRE_AMBIENT_MARKER'),"
        "'cwd':os.getcwd(),'temp':os.environ.get('TEMP'),'tempdir':tempfile.gettempdir(),"
        "'tmp':os.environ.get('TMP')},sort_keys=True))"
    )
    process = runner._spawn(
        [sys.executable, "-I", "-B", "-c", probe],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        process_sink=[],
    )
    try:
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            runner._terminate_windows_process_tree(process)

    assert process.returncode == 0
    assert stderr == b""
    assert runner._finish_windows_job(process) is True
    observed = json.loads(stdout)
    assert observed == {
        "ambient": None,
        "cwd": str(runner.work_root),
        "temp": str(runner.work_root),
        "tempdir": str(runner.work_root),
        "tmp": str(runner.work_root),
    }


@pytest.mark.parametrize("timeout_seconds", (float("nan"), float("inf"), 86_400.1))
def test_runner_rejects_timeouts_outside_the_helper_protocol(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    base = _runner(tmp_path)

    with pytest.raises(RunnerTransportError, match="transport bounds"):
        SubprocessRustRunner(
            base.runner_binary,
            base.work_root,
            timeout_seconds=timeout_seconds,
            _watchdog_interpreter=base._watchdog_interpreter,
        )


def _wait_for_file(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return
        time.sleep(0.025)
    raise AssertionError("helper did not publish its descendant pid")


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin test-runner ownership boundary")
def test_macos_runner_fixture_uses_an_owner_controlled_interpreter_copy(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)

    assert runner.runner_binary.parent == runner.work_root
    assert runner.runner_binary.name == "python-runner"
    assert runner._watchdog_interpreter.parent == runner.work_root
    assert runner._watchdog_interpreter.name == "python-watchdog"
    assert runner._watchdog_interpreter != runner.runner_binary
    assert runner.runner_binary.stat().st_nlink == 1
    assert runner._watchdog_interpreter.stat().st_nlink == 1
    assert stat.S_IMODE(runner.work_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(runner.runner_binary.stat().st_mode) == 0o700
    assert stat.S_IMODE(runner._watchdog_interpreter.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX inherited descriptors")
def test_darwin_descriptor_backed_launch_uses_the_verified_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "verified-script.py"
    script.write_text("print('verified')\n", encoding="utf-8")
    digest = runner_client_module.file_hash(script)
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")

    with runner_client_module._pinned_launch_file(
        script,
        digest,
        darwin_descriptor_backed=True,
    ) as launch:
        descriptor = int(launch[0])
        assert descriptor > 2
        assert launch[1] == (descriptor,)
        assert os.path.samestat(os.fstat(descriptor), script.stat())
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX inherited descriptors")
def test_darwin_descriptor_bootstrap_verifies_digest_and_resets_offset(tmp_path: Path) -> None:
    script = tmp_path / "verified-bootstrap.py"
    script.write_text(
        "import sys\nprint('|'.join(sys.argv))\n",
        encoding="utf-8",
    )
    descriptor = os.open(script, os.O_RDONLY)
    try:
        os.lseek(descriptor, 0, os.SEEK_END)
        arguments = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            darwin_containment_module._DARWIN_DESCRIPTOR_BOOTSTRAP,
            str(descriptor),
            str(script.resolve()),
            runner_client_module.file_hash(script),
            "one",
            "two",
        ]
        completed = subprocess.run(  # nosec B603
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(descriptor,),
            check=False,
            timeout=5,
        )
        assert completed.returncode == 0
        assert completed.stderr == b""
        assert completed.stdout == f"{script.resolve()}|one|two\n".encode()

        arguments[7] = "sha256:" + "0" * 64
        rejected = subprocess.run(  # nosec B603
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(descriptor,),
            check=False,
            timeout=5,
        )
        assert rejected.returncode == 74
        assert rejected.stdout == b""
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin watchdog launch hard link")
def test_macos_verified_watchdog_launch_reaches_readiness_and_executes(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "macos-watchdog-result.json").resolve()

    result = runner.execute_task(
        _manifest(),
        {},
        task_id="task-macos-watchdog-launch-01",
        cancel_event=threading.Event(),
        durable_result_path=durable,
    )

    assert result["status"] == "succeeded"
    assert json.loads(durable.read_text(encoding="utf-8")) == result
    assert runner.watchdog_script.stat().st_nlink == 1
    assert not list(runner.watchdog_script.parent.glob(".bluefire-verified-launch-*"))


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


def test_receiver_task_key_crosses_watchdog_only_through_fixed_scrubbed_environment(
    tmp_path: Path,
) -> None:
    base = _runner(tmp_path)
    derived_for: list[str] = []

    def derive(task_id: str) -> bytes:
        derived_for.append(task_id)
        return b"\xab" * 32

    runner = SubprocessRustRunner(
        base.runner_binary,
        base.work_root,
        timeout_seconds=5,
        output_limit_bytes=64 * 1024,
        receiver_task_key_factory=derive,
        _watchdog_interpreter=base._watchdog_interpreter,
    )
    authenticated_actions = (
        "sandbox.network.loopback.v1",
        "sandbox.peer.handoff.v1",
    )
    authenticated_tasks: list[str] = []
    for index, action_id in enumerate(authenticated_actions, start=1):
        task_id = f"task-receiver-auth-{index:02d}"
        authenticated_tasks.append(task_id)
        durable = (tmp_path / "durable" / f"receiver-result-{index}.json").resolve()
        result = runner.execute_task(
            _manifest(
                "receiver_environment",
                action_id=action_id,
            ),
            {},
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

        assert result["receiver_environment"] == {
            "names": ["BLUEFIRE_RECEIVER_TASK_ID", "BLUEFIRE_RECEIVER_TASK_KEY"],
            "task_id": task_id,
            "key_is_lower_hex_64": True,
        }
        assert (b"ab" * 32) not in durable.read_bytes()
        assert not runner_watchdog_control_root(durable, task_id).exists()

    assert derived_for == authenticated_tasks

    ordinary_task = "task-no-receiver-auth-01"
    ordinary_durable = (tmp_path / "durable" / "ordinary-result.json").resolve()
    ordinary = runner.execute_task(
        _manifest("receiver_environment"),
        {},
        task_id=ordinary_task,
        cancel_event=threading.Event(),
        durable_result_path=ordinary_durable,
    )
    assert derived_for == authenticated_tasks
    assert ordinary["receiver_environment"] == {
        "names": [],
        "task_id": None,
        "key_is_lower_hex_64": False,
    }


def test_receiver_environment_is_consumed_and_invalid_key_factory_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLUEFIRE_RECEIVER_TASK_ID", "task-consume-01")
    monkeypatch.setenv("BLUEFIRE_RECEIVER_TASK_KEY", "a" * 64)
    consumed = runner_client_module._consume_receiver_task_environment(
        expected_task_id="task-consume-01"
    )
    assert consumed == {
        "BLUEFIRE_RECEIVER_TASK_ID": "task-consume-01",
        "BLUEFIRE_RECEIVER_TASK_KEY": "a" * 64,
    }
    assert "BLUEFIRE_RECEIVER_TASK_ID" not in os.environ
    assert "BLUEFIRE_RECEIVER_TASK_KEY" not in os.environ

    invalid_root = tmp_path / "invalid-factory"
    invalid_root.mkdir()
    base = _runner(invalid_root)
    runner = SubprocessRustRunner(
        base.runner_binary,
        base.work_root,
        receiver_task_key_factory=lambda _task_id: b"short",
        _watchdog_interpreter=base._watchdog_interpreter,
    )
    durable = (tmp_path / "invalid-result.json").resolve()
    with pytest.raises(RunnerTransportError, match="authentication is invalid"):
        runner.execute_task(
            _manifest(action_id="sandbox.network.loopback.v1"),
            {},
            task_id="task-invalid-receiver-key-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )
    assert not durable.exists()


@pytest.mark.skipif(
    os.name == "nt" or sys.platform == "darwin",
    reason="non-Darwin POSIX descriptor-backed launch boundary",
)
def test_posix_verified_launch_cannot_be_redirected_before_receiver_key_exposure(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)
    executable = (tmp_path / "verified-echo").resolve()
    parked = (tmp_path / "verified-echo.parked").resolve()
    leaked = Path(str(executable) + ".leaked")
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    expected_digest = runner_client_module.file_hash(executable)
    receiver_environment = {
        "BLUEFIRE_RECEIVER_TASK_ID": "task-posix-launch-01",
        "BLUEFIRE_RECEIVER_TASK_KEY": "a" * 64,
    }

    with runner_client_module._pinned_launch_file(executable, expected_digest) as launch:
        executable.rename(parked)
        executable.write_text(
            '#!/bin/sh\nprintf "%s" "$BLUEFIRE_RECEIVER_TASK_KEY" > "$0.leaked"\n',
            encoding="utf-8",
        )
        executable.chmod(0o700)
        process = runner._spawn(
            [launch[0], "trusted"],
            stdout=subprocess.PIPE,
            receiver_environment=receiver_environment,
            inherited_descriptors=launch[1],
            process_sink=[],
        )

    assert process.stdout is not None
    stdout = process.stdout.read()
    assert runner._finish_posix_process_group(process) is True
    assert process.returncode == 0
    assert stdout == b"trusted\n"
    assert not leaked.exists()


@pytest.mark.skipif(sys.platform == "darwin", reason="Darwin requires proved process ownership")
def test_finished_posix_group_waits_for_the_exact_child_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    waited: list[float] = []

    class Process:
        pid = 501
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, *, timeout: float) -> int:
            waited.append(timeout)
            self.returncode = 0
            return 0

    process = Process()
    monkeypatch.setattr(runner, "_posix_process_group_exists", lambda _group: False)

    assert runner._finish_posix_process_group(process) is True  # type: ignore[arg-type]
    assert process.returncode == 0
    assert waited == [runner_client_module._PROCESS_TERM_GRACE_SECONDS]


def test_finished_darwin_group_inventories_before_reaping_zombie(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    events: list[str] = []

    class Process:
        pid = 502
        returncode: int | None = None

        def poll(self) -> int:
            pytest.fail("Darwin leader was polled before its group was inventoried")

        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
            events.append("wait")
            self.returncode = 0
            return 0

    process = Process()

    class WaitResult:
        si_pid = process.pid

    def observe(id_type: int, process_id: int, flags: int) -> WaitResult:
        assert id_type == 1
        assert process_id == process.pid
        assert flags == runner_client_module._DARWIN_WAITID_OPTIONS
        events.append("observe-without-reap")
        return WaitResult()

    def members(process_group: int, session_id: int) -> set[int]:
        assert (process_group, session_id) == (process.pid, process.pid)
        assert process.returncode is None
        events.append("inventory")
        return set()

    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(runner_client_module, "_WAIT_ID", observe)
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_process_group_members",
        members,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        lambda session_id: members(session_id, session_id),
    )
    monkeypatch.setattr(
        runner,
        "_posix_process_group_exists",
        lambda _group: pytest.fail("an empty Darwin group reached killpg(0)"),
    )
    runner._darwin_no_fork_proven.add(process)  # type: ignore[arg-type]

    assert runner._finish_posix_process_group(process) is True  # type: ignore[arg-type]
    assert events == [
        "observe-without-reap",
        "inventory",
        "inventory",
        "observe-without-reap",
        "inventory",
        "inventory",
        "wait",
    ]


def test_live_darwin_group_is_terminated_while_leader_pins_identifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    events: list[str] = []

    class Process:
        pid = 503
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            pytest.fail(f"live Darwin leader was reaped with timeout {timeout}")

    process = Process()

    class WaitResult:
        si_pid = process.pid

    group_inventories = iter(({process.pid, 504}, set(), set()))
    # The first session snapshot intentionally misses the still-positive group
    # snapshot; the drain must honor either positive inventory.
    session_inventories = iter((set(), set(), set()))

    def observe(id_type: int, process_id: int, flags: int) -> WaitResult:
        assert (id_type, process_id, flags) == (
            1,
            process.pid,
            runner_client_module._DARWIN_WAITID_OPTIONS,
        )
        assert process.returncode is None
        events.append("observe-without-reap")
        return WaitResult()

    def members(process_group: int, session_id: int) -> set[int]:
        assert (process_group, session_id) == (process.pid, process.pid)
        assert process.returncode is None
        events.append("inventory")
        return next(group_inventories)

    def session_members(session_id: int) -> set[int]:
        assert session_id == process.pid
        assert process.returncode is None
        events.append("session-inventory")
        return next(session_inventories)

    def signal_group(process_group: int, signum: int) -> None:
        assert process_group == process.pid
        assert signum == signal.SIGTERM
        assert process.returncode is None
        events.append("signal-with-pinned-leader")

    def wait(*, timeout: float) -> int:
        assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
        events.append("reap-leader")
        process.returncode = 0
        return 0

    process.wait = wait  # type: ignore[method-assign]
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(runner_client_module, "_WAIT_ID", observe)
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_process_group_members",
        members,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        session_members,
    )
    monkeypatch.setattr(runner_client_module, "_KILL_PROCESS_GROUP", signal_group)
    monkeypatch.setattr(runner_client_module.time, "sleep", lambda _seconds: None)
    runner._darwin_no_fork_proven.add(process)  # type: ignore[arg-type]

    assert runner._finish_posix_process_group(process) is True  # type: ignore[arg-type]
    assert events == [
        "observe-without-reap",
        "inventory",
        "session-inventory",
        "signal-with-pinned-leader",
        "observe-without-reap",
        "inventory",
        "session-inventory",
        "observe-without-reap",
        "inventory",
        "session-inventory",
        "reap-leader",
    ]
    assert runner._process_exited_without_reap(process) is True  # type: ignore[arg-type]


def test_darwin_libc_waitid_fallback_observes_without_reaping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_id = 509
    calls: list[tuple[int, int, int]] = []

    def waitid(id_type: int, candidate: int, information: object, options: int) -> int:
        calls.append((id_type, candidate, options))
        cast(Any, information)._obj.si_pid = candidate
        return 0

    monkeypatch.setattr(runner_client_module, "_WAIT_ID", None)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LIBC_WAIT_ID", waitid)

    assert runner_client_module._darwin_child_exited_without_reap(process_id) is True
    assert calls == [
        (
            runner_client_module._DARWIN_P_PID,
            process_id,
            runner_client_module._DARWIN_WAITID_OPTIONS,
        )
    ]


def test_darwin_libc_waitid_retries_interrupted_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_id = 510
    attempts = 0

    def waitid(_id_type: int, candidate: int, information: object, _options: int) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            runner_client_module.ctypes.set_errno(errno.EINTR)
            return -1
        cast(Any, information)._obj.si_pid = candidate
        return 0

    monkeypatch.setattr(runner_client_module, "_WAIT_ID", None)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LIBC_WAIT_ID", waitid)

    assert runner_client_module._darwin_child_exited_without_reap(process_id) is True
    assert attempts == 2


def test_darwin_child_status_ownership_requires_default_sigchld(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_client_module, "_WAIT_ID", lambda *_args: None)
    monkeypatch.setattr(runner_client_module.signal, "SIGCHLD", 17, raising=False)
    monkeypatch.setattr(
        runner_client_module.signal,
        "getsignal",
        lambda _signum: signal.SIG_DFL,
    )

    assert runner_client_module._darwin_child_status_ownership_available() is True

    monkeypatch.setattr(
        runner_client_module.signal,
        "getsignal",
        lambda _signum: signal.SIG_IGN,
    )
    assert runner_client_module._darwin_child_status_ownership_available() is False


def test_darwin_watchdog_proof_accepts_only_the_exact_atomic_record() -> None:
    proof = runner_client_module._DarwinWatchdogProof()
    process_id = 509
    expected = f"no-fork-v1:{proof.nonce}:{process_id}\n".encode("ascii")

    if hasattr(socket, "AF_UNIX"):
        assert proof.reader.type == socket.SOCK_DGRAM
    assert proof.writer.send(expected) == len(expected)
    assert proof.verify(process_id) is True
    assert proof.verified is True


def test_darwin_watchdog_proof_retries_when_no_record_has_arrived() -> None:
    proof = runner_client_module._DarwinWatchdogProof()
    process_id = 509
    child_writer = proof.writer.dup()

    assert proof.verify(process_id) is False
    assert proof.verified is None
    payload = f"no-fork-v1:{proof.nonce}:{process_id}\n".encode("ascii")
    try:
        assert child_writer.send(payload) == len(payload)
        assert proof.verify(process_id) is True
    finally:
        child_writer.close()


@pytest.mark.parametrize("payload_kind", ("truncated", "wrong-pid", "extra"))
def test_darwin_watchdog_proof_rejects_inexact_records(payload_kind: str) -> None:
    proof = runner_client_module._DarwinWatchdogProof()
    process_id = 510
    expected = f"no-fork-v1:{proof.nonce}:{process_id}\n".encode("ascii")
    payload = {
        "truncated": expected[:-1],
        "wrong-pid": f"no-fork-v1:{proof.nonce}:{process_id + 1}\n".encode("ascii"),
        "extra": expected + b"x",
    }[payload_kind]

    assert proof.writer.send(payload) == len(payload)
    assert proof.verify(process_id) is False
    assert proof.verified is False


def test_darwin_watchdog_proof_survives_interrupted_publication(
    tmp_path: Path,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 511
        returncode: int | None = None

    class InterruptingProofSet(set[object]):
        interrupted = False

        def add(self, element: object) -> None:
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            super().add(element)

    process = Process()
    proof = runner_client_module._DarwinWatchdogProof()
    payload = f"no-fork-v1:{proof.nonce}:{process.pid}\n".encode("ascii")
    assert proof.writer.send(payload) == len(payload)
    runner._darwin_watchdog_proofs[process] = proof  # type: ignore[index]
    proven = InterruptingProofSet()
    runner._darwin_no_fork_proven = cast(Any, proven)

    with pytest.raises(KeyboardInterrupt):
        runner._refresh_darwin_no_fork_proof(process)  # type: ignore[arg-type]
    assert proof.verified is True
    assert process in runner._darwin_watchdog_proofs

    assert runner._refresh_darwin_no_fork_proof(process) is True  # type: ignore[arg-type]
    assert process in proven
    assert process not in runner._darwin_watchdog_proofs


@pytest.mark.parametrize("gate", ("cancelled", "timed-out"))
def test_darwin_watchdog_prelaunch_gate_publishes_no_fork_proof(
    gate: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    published: list[tuple[int | None, str | None]] = []
    nonce = "a" * 64
    monkeypatch.setattr(runner_watchdog_module.sys, "platform", "darwin")
    monkeypatch.setattr(runner_watchdog_module, "_wait_for_start", lambda _config: gate)
    monkeypatch.setattr(
        runner_watchdog_module,
        "_publish_darwin_no_fork_proof",
        lambda descriptor, proof_nonce: published.append((descriptor, proof_nonce)),
    )

    result = runner_watchdog_module._run(
        cast(Any, object()),
        receiver_environment={},
        darwin_proof_descriptor=71,
        darwin_proof_nonce=nonce,
    )

    assert result[0] == ("cancelled" if gate == "cancelled" else "failed")
    assert published == [(71, nonce)]


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    (("config", 65), ("receiver", 65), ("readiness", 66)),
)
def test_darwin_watchdog_main_prelaunch_failures_publish_no_fork_proof(
    failure: str,
    expected_status: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = "b" * 64
    config = SimpleNamespace(task_id="task-darwin-proof-01")
    published: list[tuple[int | None, str | None]] = []
    monkeypatch.setattr(runner_watchdog_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_watchdog_module,
        "_publish_darwin_no_fork_proof",
        lambda descriptor, proof_nonce: published.append((descriptor, proof_nonce)),
    )
    monkeypatch.setattr(runner_watchdog_module, "_close_config", lambda _config: None)
    monkeypatch.setattr(
        runner_watchdog_module,
        "_cleanup_private_inputs",
        lambda _config: None,
    )
    if failure == "config":
        monkeypatch.setattr(
            runner_watchdog_module,
            "_load_config",
            lambda _path: (_ for _ in ()).throw(RunnerTransportError("invalid config")),
        )
    else:
        monkeypatch.setattr(runner_watchdog_module, "_load_config", lambda _path: config)
        if failure == "receiver":
            monkeypatch.setattr(
                runner_watchdog_module,
                "_consume_receiver_task_environment",
                lambda **_kwargs: (_ for _ in ()).throw(RunnerTransportError("invalid receiver")),
            )
        else:
            monkeypatch.setattr(
                runner_watchdog_module,
                "_consume_receiver_task_environment",
                lambda **_kwargs: {},
            )
            monkeypatch.setattr(
                runner_watchdog_module,
                "_write_private_json",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RunnerTransportError("readiness unavailable")
                ),
            )

    assert runner_watchdog_module.main(["config.json", "72", nonce]) == expected_status
    assert published == [(72, nonce)]


def test_darwin_watchdog_launch_passes_a_rewritable_proof_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    captured: dict[str, Any] = {}

    class Process:
        pid = 515
        returncode: int | None = None

    class Launch:
        def __init__(self, path: str, descriptors: tuple[int, ...]) -> None:
            self.path = path
            self.descriptors = descriptors

        def __enter__(self) -> tuple[str, tuple[int, ...]]:
            return self.path, self.descriptors

        def __exit__(self, *_args: object) -> None:
            return None

    process = Process()

    def spawn(argv: list[str], **options: Any) -> Any:
        captured["argv"] = list(argv)
        captured["options"] = dict(options)
        options["process_sink"].append(process)
        return process

    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_pinned_launch_file",
        lambda path, _digest, **options: Launch(
            "73" if options.get("darwin_descriptor_backed") else str(path),
            (73,) if options.get("darwin_descriptor_backed") else (),
        ),
    )
    monkeypatch.setattr(runner, "_spawn", spawn)
    monkeypatch.setattr(runner, "_await_watchdog_readiness", lambda *_args: None)

    result = runner._spawn_watchdog(
        tmp_path / "config.json",
        receiver_environment={},
        task_id="task-darwin-proof-02",
        process_sink=[],
    )
    proof = runner._darwin_watchdog_proofs[process]  # type: ignore[index]
    try:
        argv = captured["argv"]
        options = captured["options"]
        script_descriptor = int(argv[7])
        passed_descriptor = int(argv[11])
        assert result is process
        assert script_descriptor == 73
        assert passed_descriptor > 2
        assert proof.write_descriptor == -1
        assert options["inherited_descriptors"] == (script_descriptor, passed_descriptor)
        assert options["darwin_descriptor_argument_indexes"] == (7, 11)
        assert options["darwin_allow_fork"] is True
    finally:
        proof.close_reader()


def test_darwin_spawn_rechecks_child_status_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_status_ownership_available",
        lambda: False,
    )

    with pytest.raises(RunnerTransportError, match="child status ownership"):
        runner._spawn(  # noqa: SLF001
            [str(runner.runner_binary)],
            stdout=subprocess.DEVNULL,
            process_sink=[],
        )


def test_darwin_process_slots_reject_before_exceeding_governor(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    slots: list[object] = []
    try:
        for _index in range(runner_client_module._DARWIN_INDETERMINATE_LIMIT):
            slot = object()
            assert runner._reserve_darwin_process_slot(slot) is True
            slots.append(slot)
        assert runner._reserve_darwin_process_slot(object()) is False
    finally:
        for slot in slots:
            runner._cancel_darwin_process_slot(slot)


def test_darwin_launch_descriptor_argument_is_rewritten_with_its_worker_copy() -> None:
    read_descriptor, write_descriptor = os.pipe()
    resources: Any = None
    try:
        argv = ["runner", *("fixed" for _index in range(9)), str(read_descriptor)]
        resources = runner_client_module._prepare_darwin_launch_resources(
            argv,
            {
                "pass_fds": (read_descriptor,),
                "_bluefire_descriptor_argument_indexes": (10,),
            },
            [],
        )
        copied_descriptor = int(resources.argv[10])
        assert copied_descriptor > 2
        assert copied_descriptor != read_descriptor
        assert resources.options["pass_fds"] == (copied_descriptor,)
        assert "_bluefire_descriptor_argument_indexes" not in resources.options
        assert os.fstat(copied_descriptor).st_ino == os.fstat(read_descriptor).st_ino
    finally:
        if resources is not None:
            resources.close()
        os.close(read_descriptor)
        os.close(write_descriptor)


def test_darwin_launch_prepares_before_publication_and_retires_interrupted_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    prepared = SimpleNamespace(argv=["owned-runner"], options={})
    events: list[str] = []
    retired: list[Any] = []
    cancelled: list[object] = []

    def prepare(argv: list[str], options: Mapping[str, Any], sink: list[Any]) -> Any:
        assert argv == ["borrowed-runner"]
        assert options == {"pass_fds": ()}
        sink.append(prepared)
        events.append("prepared")
        return prepared

    class InterruptingCondition:
        entries = 0

        def __enter__(self) -> InterruptingCondition:
            self.entries += 1
            if self.entries == 1:
                assert events == ["prepared"]
                raise KeyboardInterrupt
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def notify(self) -> None:
            return None

    monkeypatch.setattr(runner_client_module, "_start_darwin_launch_worker", lambda: None)
    monkeypatch.setattr(runner_client_module, "_prepare_darwin_launch_resources", prepare)
    monkeypatch.setattr(
        runner_client_module,
        "_retire_darwin_launch_resources",
        retired.append,
    )
    monkeypatch.setattr(runner, "_cancel_darwin_process_slot", cancelled.append)
    monkeypatch.setattr(
        runner_client_module,
        "_DARWIN_LAUNCH_REQUESTS",
        type(runner_client_module._DARWIN_LAUNCH_REQUESTS)(),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_DARWIN_LAUNCH_CONDITION",
        InterruptingCondition(),
    )
    token = object()

    with pytest.raises(KeyboardInterrupt):
        runner._spawn_registered_darwin_popen(  # noqa: SLF001
            token,
            [],
            ["borrowed-runner"],
            pass_fds=(),
        )

    assert retired == [prepared]
    assert cancelled == [token]
    assert not runner_client_module._DARWIN_LAUNCH_REQUESTS


def test_darwin_launch_worker_captures_queue_domain_before_thread_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    condition = threading.Condition()
    requests = type(runner_client_module._DARWIN_LAUNCH_REQUESTS)()
    cleanups = type(runner_client_module._DARWIN_LAUNCH_CLEANUPS)()
    replacement_condition = threading.Condition()
    replacement_requests = type(requests)()
    replacement_cleanups = type(cleanups)()
    captured: dict[str, Any] = {}

    class CapturingThread:
        def __init__(self, **options: Any) -> None:
            captured.update(options)

        def start(self) -> None:
            # Model a rebind after Thread construction but before its target is
            # scheduled. The worker arguments must retain one coherent domain.
            runner_client_module._DARWIN_LAUNCH_CONDITION = replacement_condition
            runner_client_module._DARWIN_LAUNCH_REQUESTS = replacement_requests
            runner_client_module._DARWIN_LAUNCH_CLEANUPS = replacement_cleanups

    monkeypatch.setattr(
        runner_client_module,
        "threading",
        _isolated_module(threading, Thread=CapturingThread),
    )
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_THREAD", None)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_CONDITION", condition)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_REQUESTS", requests)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_CLEANUPS", cleanups)

    runner_client_module._start_darwin_launch_worker()

    assert captured["target"] is runner_client_module._run_darwin_launch_worker
    worker_args = captured["args"]
    assert worker_args[0] is condition
    assert worker_args[1] is requests
    assert worker_args[2] is cleanups
    assert runner_client_module._DARWIN_LAUNCH_CONDITION is replacement_condition
    assert runner_client_module._DARWIN_LAUNCH_REQUESTS is replacement_requests
    assert runner_client_module._DARWIN_LAUNCH_CLEANUPS is replacement_cleanups


def test_darwin_failed_link_retirement_stays_on_captured_worker_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class RetryResources:
        argv: list[str] = []
        options: dict[str, Any] = {}

        def close_descriptors(self) -> None:
            events.append("descriptors-closed")

        def close_links(self) -> bool:
            events.append("links-retained")
            return False

        def scrub_for_cleanup_retry(self) -> None:
            events.append("resources-scrubbed")

        def abandon_link_retries(self) -> None:
            events.append("retries-abandoned")

    class ForbiddenCondition:
        def __enter__(self) -> None:
            raise AssertionError("global launch condition was used")

        def __exit__(self, *_args: object) -> None:
            return None

    resources = RetryResources()
    request = runner_client_module._DarwinLaunchRequest(
        owner=SimpleNamespace(),
        token=object(),
        process_sink=[],
        resources=cast(Any, resources),
    )
    request.abandoned.set()
    cleanup_condition = threading.Condition()
    cleanup_queue = type(runner_client_module._DARWIN_LAUNCH_CLEANUPS)()
    global_cleanup_queue = type(cleanup_queue)()
    monkeypatch.setattr(
        runner_client_module,
        "_DARWIN_LAUNCH_CONDITION",
        ForbiddenCondition(),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_DARWIN_LAUNCH_CLEANUPS",
        global_cleanup_queue,
    )

    runner_client_module._execute_darwin_launch_request(
        request,
        cleanup_condition=cleanup_condition,
        cleanup_queue=cleanup_queue,
    )

    assert request.done.is_set()
    assert isinstance(request.error, RunnerTransportError)
    assert list(cleanup_queue) == [resources]
    assert not global_cleanup_queue
    assert events == ["descriptors-closed", "links-retained", "resources-scrubbed"]


def test_darwin_launch_worker_abandons_retry_when_cleanup_queue_refills() -> None:
    events: list[str] = []
    requests = type(runner_client_module._DARWIN_LAUNCH_REQUESTS)()
    cleanups = type(runner_client_module._DARWIN_LAUNCH_CLEANUPS)()
    fillers = [
        cast(Any, object()) for _index in range(runner_client_module._DARWIN_INDETERMINATE_LIMIT)
    ]

    class StopWorker(Exception):
        pass

    class BoundedCondition:
        entries = 0
        waits = 0

        def __enter__(self) -> BoundedCondition:
            self.entries += 1
            if self.entries == 3:
                raise StopWorker
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def wait(self, *, timeout: float) -> None:
            del timeout
            self.waits += 1

    class SaturatingCleanup:
        def close_links(self) -> bool:
            events.append("links-retained")
            assert not cleanups
            cleanups.extend(fillers)
            return False

        def abandon_link_retries(self) -> None:
            events.append("retries-abandoned")

    condition = BoundedCondition()
    cleanup = SaturatingCleanup()
    cleanups.append(cast(Any, cleanup))

    with pytest.raises(StopWorker):
        runner_client_module._run_darwin_launch_worker(
            cast(Any, condition),
            requests,
            cleanups,
        )

    assert len(cleanups) == runner_client_module._DARWIN_INDETERMINATE_LIMIT
    assert all(item is not cleanup for item in cleanups)
    assert condition.waits == 0
    assert events == ["links-retained", "retries-abandoned"]


@pytest.mark.parametrize("registration_wins", (False, True))
def test_darwin_launch_accepted_request_finishes_worker_owned_after_abandon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    registration_wins: bool,
) -> None:
    runner = _runner(tmp_path)
    prepared = runner_client_module._DarwinLaunchResources(
        argv=["owned-runner"],
        options={},
        descriptors=[],
        links=[],
    )
    retired: list[Any] = []
    requests = type(runner_client_module._DARWIN_LAUNCH_REQUESTS)()
    cleanups = type(runner_client_module._DARWIN_LAUNCH_CLEANUPS)()
    condition = threading.Condition()
    accepted = threading.Event()
    construction_started = threading.Event()
    release_worker = threading.Event()
    worker_threads: list[threading.Thread] = []
    popen_calls: list[list[str]] = []

    class Process:
        pid = 608
        returncode: int | None = None
        _child_created = False

    process = Process()

    class Popen:
        def __new__(cls) -> object:
            return process

        def __init__(self, argv: list[str], **_options: Any) -> None:
            popen_calls.append(argv)
            self._child_created = True
            construction_started.set()
            assert release_worker.wait(2.0)

    def one_request_worker() -> None:
        with condition:
            assert condition.wait_for(lambda: bool(requests), timeout=2.0)
            request = requests.popleft()
            request.accepted.set()
        accepted.set()
        if not registration_wins:
            assert release_worker.wait(2.0)
        runner_client_module._execute_darwin_launch_request(request)

    def start_worker() -> None:
        worker = threading.Thread(target=one_request_worker, daemon=True)
        worker_threads.append(worker)
        worker.start()

    def worker_is_alive() -> bool:
        boundary = construction_started if registration_wins else accepted
        assert boundary.wait(1.0)
        return bool(worker_threads and worker_threads[0].is_alive())

    def prepare(_argv: list[str], _options: Mapping[str, Any], sink: list[Any]) -> Any:
        sink.append(prepared)
        return prepared

    retire_resources = runner_client_module._retire_darwin_launch_resources

    def retire(resources: Any) -> None:
        retired.append(resources)
        retire_resources(resources)

    active: dict[Any, Any] = {}
    indeterminate: dict[Any, Any] = {}
    pending: set[object] = set()
    token = object()

    # Isolate the process governor and launch queue from the session worker.
    monkeypatch.setattr(runner_client_module, "_DARWIN_ACTIVE_PROCESSES", active)
    monkeypatch.setattr(runner_client_module, "_DARWIN_INDETERMINATE_PROCESSES", indeterminate)
    monkeypatch.setattr(runner_client_module, "_DARWIN_PENDING_PROCESS_SLOTS", pending)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_REQUESTS", requests)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_CLEANUPS", cleanups)
    monkeypatch.setattr(runner_client_module, "_DARWIN_LAUNCH_CONDITION", condition)
    monkeypatch.setattr(runner_client_module, "_WATCHDOG_START_GRACE_SECONDS", 0.05)
    monkeypatch.setattr(runner_client_module, "_PROCESS_POLL_SECONDS", 0.002)
    monkeypatch.setattr(runner_client_module, "_start_darwin_launch_worker", start_worker)
    monkeypatch.setattr(runner_client_module, "_prepare_darwin_launch_resources", prepare)
    monkeypatch.setattr(runner_client_module, "_darwin_launch_worker_is_alive", worker_is_alive)
    monkeypatch.setattr(runner_client_module, "_retire_darwin_launch_resources", retire)
    monkeypatch.setattr(runner_client_module.subprocess, "Popen", Popen)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    assert runner._reserve_darwin_process_slot(token) is True  # noqa: SLF001

    with pytest.raises(RunnerTransportError, match="exceeded its deadline"):
        runner._spawn_registered_darwin_popen(  # noqa: SLF001
            token,
            [],
            ["borrowed-runner"],
        )

    assert accepted.is_set()
    assert token not in pending
    if registration_wins:
        assert construction_started.is_set()
        assert set(active) | set(indeterminate) == {process}
    else:
        assert popen_calls == []
        assert not active
        assert not indeterminate

    release_worker.set()
    worker_threads[0].join(timeout=2.0)
    assert not worker_threads[0].is_alive()
    assert retired == [prepared]
    if registration_wins:
        assert popen_calls == [["owned-runner"]]
        assert set(active) | set(indeterminate) == {process}
        assert indeterminate[process] == (runner, True, False, True)
    else:
        assert popen_calls == []
        assert not active
        assert not indeterminate


def test_darwin_stale_pin_reservation_is_recoverable_and_token_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = (901, 902)
    stale_token = object()
    successor_token = object()
    monkeypatch.setattr(darwin_containment_module, "_MACOS_PIN_LOCK_TIMEOUT_SECONDS", 0.0)
    try:
        with darwin_containment_module._MACOS_PIN_REGISTRY_CONDITION:
            darwin_containment_module._MACOS_PIN_PENDING[identity] = (
                darwin_containment_module._MacOSPinReservation(
                    owner_thread=-1,
                    token=stale_token,
                    created_at=0.0,
                )
            )
        assert (
            darwin_containment_module._reserve_macos_pin_identity(
                identity,
                successor_token,
                allow_same_thread_reuse=False,
            )
            is None
        )
        pending = darwin_containment_module._MACOS_PIN_PENDING[identity]
        assert pending.token is successor_token

        darwin_containment_module._release_macos_pin_reservation(identity, stale_token)
        assert darwin_containment_module._MACOS_PIN_PENDING[identity].token is successor_token
        darwin_containment_module._release_macos_pin_reservation(identity, successor_token)
        assert identity not in darwin_containment_module._MACOS_PIN_PENDING
    finally:
        with darwin_containment_module._MACOS_PIN_REGISTRY_CONDITION:
            darwin_containment_module._MACOS_PIN_REGISTRY.pop(identity, None)
            darwin_containment_module._MACOS_PIN_PENDING.pop(identity, None)
            darwin_containment_module._MACOS_PIN_REGISTRY_CONDITION.notify_all()


def test_darwin_prelaunch_interruption_releases_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 509
        returncode: int | None = None

    class Popen:
        def __new__(cls) -> object:
            return process

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._child_created = True

    class InterruptingSlots(set[object]):
        interrupted = False

        def discard(self, element: object) -> None:
            if (
                not self.interrupted
                and element in self
                and runner_client_module._DARWIN_ACTIVE_PROCESSES.get(process) is runner
            ):
                self.interrupted = True
                raise KeyboardInterrupt
            super().discard(element)

    process = Process()
    slots = InterruptingSlots()

    monkeypatch.setattr(
        runner_client_module,
        "sys",
        _isolated_module(sys, platform="darwin"),
    )
    monkeypatch.setattr(
        runner_client_module,
        "os",
        _isolated_module(os, name="posix"),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_status_ownership_available",
        lambda: True,
    )
    monkeypatch.setattr(runner_client_module.subprocess, "Popen", Popen)
    monkeypatch.setattr(runner_client_module, "_DARWIN_PENDING_PROCESS_SLOTS", slots)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )

    with pytest.raises(KeyboardInterrupt):
        runner._spawn(  # noqa: SLF001
            [str(runner.runner_binary)],
            stdout=subprocess.DEVNULL,
            darwin_allow_fork=True,
            process_sink=[],
        )
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        assert process not in runner_client_module._DARWIN_ACTIVE_PROCESSES
        assert process not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
        assert not runner_client_module._DARWIN_PENDING_PROCESS_SLOTS
    assert slots.interrupted is True


def test_darwin_post_registration_interruption_quarantines_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 510
        returncode: int | None = None

    class Popen:
        def __new__(cls) -> object:
            return process

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._child_created = True

    class InterruptingPlatform(str):
        linux_checks = 0

        def startswith(self, prefix: str, *args: int) -> bool:
            if prefix == "linux":
                self.linux_checks += 1
                if self.linux_checks == 2:
                    raise KeyboardInterrupt
            return super().startswith(prefix, *args)

    process = Process()
    monkeypatch.setattr(
        runner_client_module,
        "sys",
        _isolated_module(sys, platform=InterruptingPlatform("darwin")),
    )
    monkeypatch.setattr(
        runner_client_module,
        "os",
        _isolated_module(os, name="posix"),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_status_ownership_available",
        lambda: True,
    )
    monkeypatch.setattr(runner_client_module.subprocess, "Popen", Popen)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )

    with pytest.raises(KeyboardInterrupt):
        runner._spawn(  # noqa: SLF001
            [str(runner.runner_binary)],
            stdout=subprocess.DEVNULL,
            darwin_allow_fork=True,
            process_sink=[],
        )
    try:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            assert runner_client_module._DARWIN_ACTIVE_PROCESSES.get(process) is runner
            assert runner_client_module._DARWIN_INDETERMINATE_PROCESSES.get(process) == (
                runner,
                True,
                False,
                True,
            )
    finally:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            runner_client_module._DARWIN_INDETERMINATE_PROCESSES.pop(process, None)
            runner_client_module._DARWIN_ACTIVE_PROCESSES.pop(process, None)


def test_darwin_popen_runtime_error_after_child_creation_is_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Popen:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.pid = 511
            self.returncode: int | None = None
            self._child_created = True
            raise RuntimeError("signal handler interrupted launch")

    process_sink: list[Any] = []
    monkeypatch.setattr(
        runner_client_module,
        "sys",
        _isolated_module(sys, platform="darwin"),
    )
    monkeypatch.setattr(
        runner_client_module,
        "os",
        _isolated_module(os, name="posix"),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_status_ownership_available",
        lambda: True,
    )
    monkeypatch.setattr(runner_client_module.subprocess, "Popen", Popen)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: False,
    )

    with pytest.raises(RuntimeError, match="interrupted launch"):
        runner._spawn(  # noqa: SLF001
            [str(runner.runner_binary)],
            stdout=subprocess.DEVNULL,
            darwin_allow_fork=True,
            process_sink=process_sink,
        )
    assert len(process_sink) == 1
    process = process_sink[0]
    try:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            assert runner_client_module._DARWIN_ACTIVE_PROCESSES.get(process) is runner
            assert runner_client_module._DARWIN_INDETERMINATE_PROCESSES.get(process) == (
                runner,
                True,
                False,
                True,
            )
    finally:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            runner_client_module._DARWIN_INDETERMINATE_PROCESSES.pop(process, None)
            runner_client_module._DARWIN_ACTIVE_PROCESSES.pop(process, None)


def test_invoke_recovers_process_from_pre_return_ownership_sink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process = cast(Any, SimpleNamespace(pid=512, returncode=None))
    stopped: list[Any] = []

    def interrupted_spawn(*_args: object, **options: Any) -> None:
        options["process_sink"].append(process)
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "_spawn", interrupted_spawn)
    monkeypatch.setattr(
        runner,
        "_stop_process_tree",
        lambda candidate: stopped.append(candidate) is None,
    )

    with pytest.raises(KeyboardInterrupt):
        runner._invoke([str(runner.runner_binary), "inventory", "--json"])
    assert stopped == [process]


def test_darwin_reconciler_start_failure_clears_retry_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Thread:
        def is_alive(self) -> bool:
            return False

        def start(self) -> None:
            raise RuntimeError("thread unavailable")

    monkeypatch.setattr(runner_client_module.threading, "Thread", lambda **_kwargs: Thread())
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        monkeypatch.setattr(runner_client_module, "_DARWIN_RECONCILER_THREAD", None)

    with pytest.raises(RunnerTransportError, match="reconciliation worker"):
        runner_client_module._start_darwin_indeterminate_reconciler()

    assert runner_client_module._DARWIN_RECONCILER_THREAD is None


def test_darwin_drain_does_not_reap_with_alternate_group_session_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 510
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            pytest.fail(f"Darwin leader was reaped with an alternate member: {timeout}")

    process = Process()
    times = iter((0.0, 8.0))
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _process_id: True,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_process_group_members",
        lambda _group, _session: set(),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        lambda _session: {511},
    )
    monkeypatch.setattr(
        runner_client_module,
        "_KILL_PROCESS_GROUP",
        lambda _group, _signal: pytest.fail("alternate group was signalled by stale PGID"),
    )
    monkeypatch.setattr(runner_client_module.time, "monotonic", lambda: next(times))
    runner._darwin_no_fork_proven.add(process)  # type: ignore[arg-type]

    assert runner._drain_darwin_process_group(process) is False  # type: ignore[arg-type]
    assert process.returncode is None


def test_darwin_drain_requires_proof_and_accepts_the_parent_owned_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 514
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
            self.returncode = 0
            return 0

    unproved = Process()
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner,
        "_process_exited_without_reap",
        lambda _process, **_kwargs: True,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_process_group_members",
        lambda _group, _session: set(),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        lambda _session: set(),
    )
    monkeypatch.setattr(runner_client_module.time, "sleep", lambda _seconds: None)

    assert runner._drain_darwin_process_group(unproved) is False  # type: ignore[arg-type]
    assert unproved.returncode is None

    process = Process()
    proof = runner_client_module._DarwinWatchdogProof()
    payload = f"no-fork-v1:{proof.nonce}:{process.pid}\n".encode("ascii")
    assert proof.writer.send(payload) == len(payload)
    runner._darwin_watchdog_proofs[process] = proof  # type: ignore[index]

    assert runner._drain_darwin_process_group(process) is True  # type: ignore[arg-type]
    assert process.returncode == 0
    assert process in runner._darwin_no_fork_proven
    assert process not in runner._darwin_watchdog_proofs


def test_darwin_release_retains_process_across_transient_drain_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    outcomes = iter((False, True))
    attempts: list[object] = []

    class Process:
        pid = 511
        returncode: int | None = None

    process = Process()

    def drain(candidate: object, *, _reconciling: bool = False) -> bool:
        assert candidate is process
        attempts.append((candidate, _reconciling))
        return next(outcomes)

    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(runner, "_drain_darwin_process_group", drain)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    slot = object()
    assert runner._reserve_darwin_process_slot(slot) is True
    runner._register_darwin_process_slot(slot, process)  # type: ignore[arg-type]

    assert runner._finish_posix_process_group(process) is False  # type: ignore[arg-type]
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        state = runner_client_module._DARWIN_INDETERMINATE_PROCESSES.get(process)
        assert state is not None and state[0] is runner
    assert runner._finish_posix_process_group(process) is False  # type: ignore[arg-type]
    assert (
        runner._reconcile_indeterminate_darwin_process(  # type: ignore[arg-type]
            process,
            terminate=False,
        )
        is True
    )
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        assert process not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
        assert process not in runner_client_module._DARWIN_ACTIVE_PROCESSES
    assert attempts == [(process, False), (process, True)]


def test_darwin_observe_only_reconciliation_never_signals_numeric_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 513
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
            self.returncode = 0
            return 0

    process = Process()
    session_id = process.pid
    slot = object()
    assert runner._reserve_darwin_process_slot(slot) is True
    runner._register_darwin_process_slot(slot, process)  # type: ignore[arg-type]
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: True,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        lambda _session: {session_id},
    )
    monkeypatch.setattr(
        runner_client_module,
        "_KILL_PROCESS_GROUP",
        lambda *_args: pytest.fail("observe-only reconciliation attempted a numeric signal"),
    )
    monkeypatch.setattr(runner_client_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    assert (
        runner._retain_indeterminate_darwin_process(  # type: ignore[arg-type]
            process,
            terminate=True,
            observe_only=True,
        )
        is True
    )

    assert (
        runner._reconcile_indeterminate_darwin_process(  # type: ignore[arg-type]
            process,
            terminate=True,
            observe_only=True,
        )
        is True
    )
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        assert process not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
        assert process not in runner_client_module._DARWIN_ACTIVE_PROCESSES


def test_unproved_generic_darwin_launch_is_reaped_observe_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 516
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
            self.returncode = 74
            return 74

    process = Process()
    slot = object()
    assert runner._reserve_darwin_process_slot(slot) is True
    runner._register_darwin_process_slot(slot, process)  # type: ignore[arg-type]
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: True,
    )
    inventories: list[int] = []

    def session_members(session_id: int) -> set[int]:
        assert session_id == process.pid
        inventories.append(session_id)
        return {session_id}

    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        session_members,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_KILL_PROCESS_GROUP",
        lambda *_args: pytest.fail("observe-only recovery signalled a numeric identity"),
    )
    monkeypatch.setattr(runner_client_module.time, "sleep", lambda _seconds: None)

    runner._quarantine_interrupted_darwin_launch(process)  # type: ignore[arg-type]
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        assert runner_client_module._DARWIN_INDETERMINATE_PROCESSES[process] == (
            runner,
            True,
            False,
            True,
        )

    assert (
        runner._reconcile_indeterminate_darwin_process(  # type: ignore[arg-type]
            process,
            terminate=True,
            observe_only=True,
        )
        is True
    )
    assert process.returncode == 74
    assert inventories == [process.pid, process.pid]
    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        assert process not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
        assert process not in runner_client_module._DARWIN_ACTIVE_PROCESSES


def test_observe_only_darwin_quarantine_upgrades_when_proof_arrives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 517
        returncode: int | None = None

    process = Process()
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_start_darwin_indeterminate_reconciler",
        lambda: None,
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: False,
    )
    drains: list[tuple[Any, bool]] = []

    def drain(candidate: Any, *, _reconciling: bool = False) -> bool:
        drains.append((candidate, _reconciling))
        return True

    monkeypatch.setattr(runner, "_drain_darwin_process_group", drain)

    with runner_client_module._DARWIN_INDETERMINATE_LOCK:
        slot = object()
        assert runner._reserve_darwin_process_slot(slot) is True
        runner._register_darwin_process_slot(slot, process)  # type: ignore[arg-type]
        runner._quarantine_interrupted_darwin_launch(process)  # type: ignore[arg-type]

        proof = runner_client_module._DarwinWatchdogProof()
        payload = f"no-fork-v1:{proof.nonce}:{process.pid}\n".encode("ascii")
        assert proof.writer.send(payload) == len(payload)
        runner._darwin_watchdog_proofs[process] = proof  # type: ignore[index]

        assert (
            runner._reconcile_indeterminate_darwin_process(  # type: ignore[arg-type]
                process,
                terminate=True,
            )
            is True
        )
        assert drains == [(process, True)]
        assert process in runner._darwin_no_fork_proven
        assert process not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
        assert process not in runner_client_module._DARWIN_ACTIVE_PROCESSES


def test_darwin_observation_failure_enters_bounded_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)

    class Process:
        pid = 512
        returncode: int | None = None

    process = Process()
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: (_ for _ in ()).throw(OSError("waitid unavailable")),
    )
    monkeypatch.setattr(runner, "_drain_darwin_process_group", lambda _process: False)
    slot = object()
    assert runner._reserve_darwin_process_slot(slot) is True
    runner._register_darwin_process_slot(slot, process)  # type: ignore[arg-type]

    assert runner._process_exited_without_reap(process) is False  # type: ignore[arg-type]
    assert runner._finish_posix_process_group(process) is False  # type: ignore[arg-type]
    try:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            state = runner_client_module._DARWIN_INDETERMINATE_PROCESSES.get(process)
            assert state is not None and state == (runner, False, True, False)
    finally:
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            runner_client_module._DARWIN_INDETERMINATE_PROCESSES.pop(process, None)
            runner_client_module._DARWIN_ACTIVE_PROCESSES.pop(process, None)


def test_darwin_drain_signals_a_live_sole_group_leader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    events: list[str] = []
    exit_states = iter((False, True, True))

    class Process:
        pid = 512
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            assert timeout == runner_client_module._PROCESS_KILL_GRACE_SECONDS
            events.append("reap")
            self.returncode = 0
            return 0

    process = Process()

    def signal_group(group: int, signum: int) -> None:
        assert (group, signum) == (process.pid, signal.SIGTERM)
        assert process.returncode is None
        events.append("signal")

    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _process_id: next(exit_states),
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_process_group_members",
        lambda _group, _session: {process.pid},
    )
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_private_session_members",
        lambda _session: {process.pid},
    )
    monkeypatch.setattr(runner_client_module, "_KILL_PROCESS_GROUP", signal_group)
    monkeypatch.setattr(runner_client_module.time, "sleep", lambda _seconds: None)
    runner._darwin_no_fork_proven.add(process)  # type: ignore[arg-type]

    assert runner._terminate_posix_process_tree(process) is True  # type: ignore[arg-type]
    assert events == ["signal", "reap"]


@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin hard-link launch boundary")
def test_macos_configured_launch_rejects_canonical_replacement_before_key_exposure(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "runner-work"
    work_root.mkdir(mode=0o700)
    executable = (work_root / "configured-runner").resolve()
    watchdog = (work_root / "python-watchdog").resolve()
    parked = (work_root / "configured-runner.parked").resolve()
    leaked = Path(str(executable) + ".leaked")
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    shutil.copyfile(Path(sys.executable).resolve(), watchdog)
    watchdog.chmod(0o700)
    runner = SubprocessRustRunner(
        executable,
        work_root,
        timeout_seconds=5.0,
        output_limit_bytes=64 * 1024,
        _watchdog_interpreter=watchdog,
    )
    assert runner.runner_binary == executable
    assert runner._watchdog_interpreter == watchdog
    receiver_environment = {
        "BLUEFIRE_RECEIVER_TASK_ID": "task-macos-launch-01",
        "BLUEFIRE_RECEIVER_TASK_KEY": "a" * 64,
    }
    with runner_client_module._pinned_launch_file(
        runner.runner_binary,
        runner.runner_binary_digest,
    ) as launch:
        assert launch[1] == ()
        launch_path = Path(launch[0])
        assert os.path.samestat(launch_path.stat(), executable.stat())
        launch_nonce = launch_path.name.removeprefix(".bluefire-verified-launch-")
        assert len(launch_nonce) == 64
        assert set(launch_nonce) <= set("0123456789abcdef")
        executable.rename(parked)
        executable.write_text(
            '#!/bin/sh\nprintf "%s" "$BLUEFIRE_RECEIVER_TASK_KEY" > "$0.leaked"\n',
            encoding="utf-8",
        )
        executable.chmod(0o700)
        with pytest.raises(RunnerTransportError, match="Darwin no-fork launch failed"):
            runner._spawn(
                [launch[0], "trusted"],
                stdout=subprocess.PIPE,
                receiver_environment=receiver_environment,
                inherited_descriptors=launch[1],
                process_sink=[],
            )

    assert not leaked.exists()
    assert not list(work_root.glob(".bluefire-verified-launch-*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX Darwin hard-link launch boundary")
def test_macos_verified_launch_rejects_a_group_writable_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o770)
    executable = (shared / "verified-echo").resolve()
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    expected_digest = runner_client_module.file_hash(executable)
    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")

    with pytest.raises(RunnerTransportError, match="verified launch input is unavailable"):
        with runner_client_module._pinned_launch_file(executable, expected_digest):
            pytest.fail("an untrusted parent reached the launch boundary")

    assert not list(shared.glob(".bluefire-verified-launch-*"))


@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin hard-link launch boundary")
def test_macos_verified_launch_cleans_a_link_after_post_link_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = (tmp_path / "verified-echo").resolve()
    shutil.copyfile("/bin/echo", executable)
    executable.chmod(0o700)
    expected_digest = runner_client_module.file_hash(executable)
    real_stat = os.stat
    failed = False

    def fail_first_link_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal failed
        if not failed and isinstance(path, str) and path.startswith(".bluefire-verified-launch-"):
            failed = True
            raise OSError("post-link stat failure")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(runner_client_module.sys, "platform", "darwin")
    monkeypatch.setattr(runner_client_module.os, "stat", fail_first_link_stat)

    with pytest.raises(RunnerTransportError, match="verified launch input is unavailable"):
        with runner_client_module._pinned_launch_file(executable, expected_digest):
            pytest.fail("a failed link verification reached the launch boundary")

    assert failed is True
    assert not list(tmp_path.glob(".bluefire-verified-launch-*"))


def test_watchdog_readiness_failure_retains_and_stops_spawned_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    task_id = "task-readiness-failure-01"
    durable = (tmp_path / "durable" / "readiness-failure.json").resolve()
    spawned: list[subprocess.Popen[bytes]] = []

    def fail_readiness(
        process: subprocess.Popen[bytes],
        _control_root: Path,
        _task_id: str,
    ) -> None:
        spawned.append(process)
        raise RunnerTransportError("synthetic watchdog readiness failure")

    monkeypatch.setattr(runner, "_await_watchdog_readiness", fail_readiness)
    expected_error = (
        "Runner watchdog process tree could not be stopped safely"
        if sys.platform == "darwin"
        else "synthetic watchdog readiness failure"
    )
    with pytest.raises(RunnerTransportError, match=expected_error):
        runner.execute_task(
            _manifest(),
            {},
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert len(spawned) == 1
    if sys.platform == "darwin":
        assert spawned[0].returncode is not None
        assert spawned[0] in runner._released_darwin_processes
        with runner_client_module._DARWIN_INDETERMINATE_LOCK:
            assert spawned[0] not in runner_client_module._DARWIN_ACTIVE_PROCESSES
            assert spawned[0] not in runner_client_module._DARWIN_INDETERMINATE_PROCESSES
    else:
        assert spawned[0].poll() is not None
    assert runner._windows_jobs == {}
    assert not runner_watchdog_control_root(durable, task_id).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation retry boundary")
def test_watchdog_readiness_retries_only_transient_windows_sharing_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process = cast(subprocess.Popen[bytes], SimpleNamespace(pid=4242))
    attempts = 0

    class SharingThenReady:
        def __init__(self, _root: Path) -> None:
            pass

        def __enter__(self) -> SharingThenReady:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, _name: str, *, maximum: int) -> bytes:
            nonlocal attempts
            assert maximum == 4096
            attempts += 1
            if attempts <= 2:
                raise OSError(
                    (32, 33)[attempts - 1],
                    "transient Windows sharing denial",
                )
            return json.dumps(
                {
                    "schema_version": "bluefire.runner-watchdog-ready.v1",
                    "task_id": "task-sharing-retry-01",
                    "watchdog_pid": process.pid,
                },
                sort_keys=True,
            ).encode("utf-8")

    monkeypatch.setattr(runner_client_module, "_PinnedPrivateDirectory", SharingThenReady)
    monkeypatch.setattr(runner, "_process_exited_without_reap", lambda _process: False)

    runner._await_watchdog_readiness(
        process,
        tmp_path,
        "task-sharing-retry-01",
    )

    assert attempts == 3


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation retry boundary")
def test_watchdog_readiness_fails_closed_on_other_windows_io_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process = cast(subprocess.Popen[bytes], SimpleNamespace(pid=4242))
    attempts = 0

    class AccessDenied:
        def __init__(self, _root: Path) -> None:
            pass

        def __enter__(self) -> AccessDenied:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, _name: str, *, maximum: int) -> bytes:
            nonlocal attempts
            assert maximum == 4096
            attempts += 1
            raise OSError(5, "non-transient Windows denial")

    monkeypatch.setattr(runner_client_module, "_PinnedPrivateDirectory", AccessDenied)
    monkeypatch.setattr(runner, "_process_exited_without_reap", lambda _process: False)

    with pytest.raises(RunnerTransportError, match="readiness is unavailable"):
        runner._await_watchdog_readiness(
            process,
            tmp_path,
            "task-access-denied-01",
        )

    assert attempts == 1


def test_watchdog_rejects_parent_death_helper_digest_change(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    replacement = tmp_path / "swapped-parent-death.py"
    replacement.write_text("raise SystemExit(0)\n", encoding="utf-8")
    runner.parent_death_script = replacement
    runner.parent_death_script_digest = runner_client_module.file_hash(replacement)
    durable = (tmp_path / "durable" / "parent-death-helper-swap.json").resolve()
    task_id = "task-parent-death-helper-swap-01"

    with pytest.raises(RunnerTransportError):
        runner.execute_task(
            _manifest(),
            {},
            task_id=task_id,
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert not durable.exists()
    assert not runner_pending_result_path(durable, task_id).exists()
    assert not runner_watchdog_control_root(durable, task_id).exists()


def test_linux_identity_change_is_never_signalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = (701, 7001, 701, 701)
    changed = (701, 7002, 701, 701)
    observations = iter((identity, changed))
    descriptor = os.open(os.devnull, os.O_RDONLY)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(
        SubprocessRustRunner,
        "_linux_process_identity",
        staticmethod(lambda _process_id: next(observations)),
    )
    monkeypatch.setattr(runner_client_module, "_PIDFD_OPEN", lambda _pid, _flags: descriptor)
    monkeypatch.setattr(
        runner_client_module,
        "_PIDFD_SEND_SIGNAL",
        lambda pidfd, signum, _info, _flags: signals.append((pidfd, signum)),
    )

    force_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    assert SubprocessRustRunner._signal_linux_process_identity(identity, force_signal) is False
    assert signals == []


def test_linux_process_identity_accepts_zero_scoped_namespace_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_id = 2
    start_time_ticks = 7001
    stat_payload = (
        f"{process_id} (init) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks} 0\n"
    ).encode("ascii")

    def read_bytes(path: Path) -> bytes:
        assert path == Path("/proc") / str(process_id) / "stat"
        return stat_payload

    monkeypatch.setattr(Path, "read_bytes", read_bytes)

    assert SubprocessRustRunner._linux_process_identity(process_id) == (
        process_id,
        start_time_ticks,
        0,
        0,
    )


def test_linux_process_identity_rejects_negative_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_id = 2
    scope = [0, 0]

    def read_bytes(path: Path) -> bytes:
        assert path == Path("/proc") / str(process_id) / "stat"
        process_group, session_id = scope
        return (
            f"{process_id} (init) S 0 {process_group} {session_id} 0 -1 "
            "0 0 0 0 0 0 0 0 0 20 0 1 0 7001 0\n"
        ).encode("ascii")

    monkeypatch.setattr(Path, "read_bytes", read_bytes)

    for invalid_scope in ((-1, 0), (0, -1)):
        scope[:] = invalid_scope
        with pytest.raises(RunnerTransportError, match="identity is invalid"):
            SubprocessRustRunner._linux_process_identity(process_id)


def test_linux_private_session_scan_ignores_zero_scoped_namespace_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    leader = (701, 7001, 701, 701)
    identities = {2: (2, 2001, 0, 0), leader[0]: leader}

    class Entries:
        def __enter__(self) -> object:
            return iter(SimpleNamespace(name=str(process_id)) for process_id in identities)

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(runner_client_module.os, "scandir", lambda _path: Entries())
    monkeypatch.setattr(
        runner,
        "_linux_process_identity",
        lambda process_id: identities[process_id],
    )

    assert runner._linux_private_session_identities((*leader, 91)) == [leader]


def test_linux_private_registration_rejects_zero_scoped_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process_id = 2
    descriptor = os.open(os.devnull, os.O_RDONLY)
    stopped: list[str] = []

    class Process:
        pid = process_id

        def kill(self) -> None:
            stopped.append("kill")

        def wait(self, *, timeout: float) -> int:
            stopped.append(f"wait:{timeout}")
            return 0

    monkeypatch.setattr(
        runner,
        "_linux_process_identity",
        lambda _process_id: (process_id, 7001, 0, 0),
    )
    monkeypatch.setattr(runner_client_module, "_PIDFD_OPEN", lambda _pid, _flags: descriptor)

    with pytest.raises(RunnerTransportError, match="containment is unavailable"):
        runner._register_linux_private_process(Process())  # type: ignore[arg-type]

    assert stopped == ["kill", "wait:5.0"]
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_linux_private_leader_is_reaped_only_after_wnowait_and_empty_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process_id = 801
    identity = (process_id, 8001, process_id, process_id)
    descriptor = os.open(os.devnull, os.O_RDONLY)
    events: list[object] = []
    wait_no_reap = 0x01000000

    class Process:
        pid = process_id
        returncode: int | None = None

        def poll(self) -> int | None:
            raise AssertionError("Popen.poll must not reap a contained Linux leader")

        def wait(self, *, timeout: float) -> int:
            events.append(("reap", timeout))
            self.returncode = 0
            return 0

    def wait_id(_kind: int, pidfd: int, options: int) -> SimpleNamespace:
        events.append(("waitid", pidfd, options))
        return SimpleNamespace(si_pid=process_id)

    monkeypatch.setattr(runner_client_module, "_WAIT_ID", wait_id)
    monkeypatch.setattr(runner_client_module, "_PIDFD_ID_TYPE", 3)
    monkeypatch.setattr(runner_client_module, "_WAIT_EXITED", 4)
    monkeypatch.setattr(runner_client_module, "_WAIT_NO_HANG", 1)
    monkeypatch.setattr(runner_client_module, "_WAIT_NO_REAP", wait_no_reap)

    def empty_session(
        _containment: tuple[int, int, int, int, int],
    ) -> list[tuple[int, int, int, int]]:
        events.append("session-empty")
        return [identity]

    monkeypatch.setattr(runner, "_linux_private_session_identities", empty_session)

    process = Process()
    runner._linux_process_containments[process] = (*identity, descriptor)  # type: ignore[index]
    assert runner._release_linux_private_process(process, terminate=False) is True  # type: ignore[arg-type]
    wait_events = [event for event in events if isinstance(event, tuple) and event[0] == "waitid"]
    assert wait_events
    assert all(int(event[2]) & wait_no_reap for event in wait_events)
    assert events.index("session-empty") < next(
        index
        for index, event in enumerate(events)
        if isinstance(event, tuple) and event[0] == "reap"
    )
    assert process not in runner._linux_process_containments
    assert process in runner._released_linux_processes
    assert runner._process_exited_without_reap(process) is True  # type: ignore[arg-type]
    assert runner._finish_posix_process_group(process) is True  # type: ignore[arg-type]


def test_linux_private_session_cleanup_includes_alternate_process_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    process_id = 901
    leader = (process_id, 9001, process_id, process_id)
    alternate_group_child = (902, 9002, 990, process_id)
    descriptor = os.open(os.devnull, os.O_RDONLY)
    inventories = iter(([leader, alternate_group_child], [leader]))
    signalled: list[tuple[int, int, int, int]] = []

    class Process:
        pid = process_id
        returncode: int | None = None

        def wait(self, *, timeout: float) -> int:
            self.returncode = 0
            return 0

    monkeypatch.setattr(
        runner,
        "_process_exited_without_reap",
        lambda _process: True,
    )
    monkeypatch.setattr(
        runner,
        "_linux_private_session_identities",
        lambda _containment: list(next(inventories)),
    )
    monkeypatch.setattr(
        runner,
        "_signal_linux_process_identity",
        lambda identity, _signum: signalled.append(identity) or True,
    )

    process = Process()
    runner._linux_process_containments[process] = (*leader, descriptor)  # type: ignore[index]
    assert runner._release_linux_private_process(process, terminate=False) is True  # type: ignore[arg-type]
    assert signalled == [alternate_group_child]


def test_private_posix_session_members_are_not_filtered_by_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Entries:
        def __enter__(self) -> object:
            return iter(
                (
                    SimpleNamespace(name="1001"),
                    SimpleNamespace(name="1002"),
                    SimpleNamespace(name="2001"),
                    SimpleNamespace(name="self"),
                )
            )

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(runner_client_module.sys, "platform", "linux")
    monkeypatch.setattr(runner_client_module.os, "scandir", lambda _path: Entries())
    monkeypatch.setattr(
        runner_client_module,
        "_GET_SESSION_ID",
        lambda process_id: 1001 if process_id in {1001, 1002} else 2001,
    )

    assert SubprocessRustRunner._private_posix_session_members(1001) == {1001, 1002}


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


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="Darwin runner execution is fail-closed under the proven no-fork sandbox",
)
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
        with pytest.raises(RunnerTaskCancelled, match="process tree stopped") as failure:
            future.result(timeout=10)

    # Cancellation is not reported merely because a kill was sent. The
    # watchdog confirms its inner Job/process group is empty first.
    assert not _pid_is_running(descendant_pid)
    assert not durable.exists()
    assert not runner_pending_result_path(durable, "task-cancel-01").exists()
    assert not list(runner.work_root.glob("request-*"))
    assert failure.value.cooperative_requested is False
    assert failure.value.cooperative_acknowledged is False
    assert failure.value.forced_tree_termination is True
    assert failure.value.control_cleanup_verified is True


def test_preexisting_or_mismatched_witness_state_never_claims_cooperative_cancel(
    tmp_path: Path,
) -> None:
    sandbox = (tmp_path / "sandbox").resolve()
    sandbox.mkdir()

    def config_for(raw_digest: str) -> SimpleNamespace:
        request_hash = "sha256:" + raw_digest
        return SimpleNamespace(
            task_id="execute-" + raw_digest,
            manifest={
                "action_id": "sandbox.execution.process-tree-cancellation-witness.v1",
                "behavior_id": "sandbox.execution.process-tree-cancellation-witness.v1",
                "params": {},
                "platform": "windows",
                "request_hash": request_hash,
            },
            profile={"platform": "windows", "sandbox_root": str(sandbox)},
        )

    def ready(config: SimpleNamespace, parent_process_id: int) -> Path:
        root = (
            sandbox / ".bluefire-cancellation-witness-v1" / config.task_id.removeprefix("execute-")
        )
        root.mkdir(parents=True)
        (root / "ready.json").write_text(
            json.dumps(
                {
                    "schema_version": "bluefire.process-tree-cancellation-ready.v1",
                    "task_id": config.task_id,
                    "request_hash": config.manifest["request_hash"],
                    "parent_process_id": parent_process_id,
                    "descendant_process_id": parent_process_id + 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return root

    preexisting = config_for("a" * 64)
    preexisting_root = ready(preexisting, 701)
    (preexisting_root / "cancel.ack").write_bytes(b"ack:" + b"0" * 64 + b"\n")
    requested = threading.Event()
    acknowledged = threading.Event()
    runner_watchdog_module._cooperative_cancellation(
        preexisting,
        requested,
        acknowledged,
        [701],
    )
    assert not requested.is_set()
    assert not acknowledged.is_set()
    assert not (preexisting_root / "cancel.request").exists()

    mismatched = config_for("b" * 64)
    mismatched_root = ready(mismatched, 801)
    runner_watchdog_module._cooperative_cancellation(
        mismatched,
        requested,
        acknowledged,
        [999],
    )
    assert not requested.is_set()
    assert not acknowledged.is_set()
    assert {entry.name for entry in mismatched_root.iterdir()} == {"ready.json"}


@pytest.mark.skipif(os.name != "nt", reason="Windows cancellation lease boundary")
def test_outer_cancellation_lease_owns_early_and_crash_cleanup(tmp_path: Path) -> None:
    digest = "c" * 64
    request_hash = "sha256:" + digest
    task_id = "execute-" + digest
    sandbox = (tmp_path / "sandbox").resolve()
    sandbox.mkdir()
    manifest = {
        "action_id": "sandbox.execution.process-tree-cancellation-witness.v1",
        "behavior_id": "sandbox.execution.process-tree-cancellation-witness.v1",
        "params": {},
        "platform": "windows",
        "request_hash": request_hash,
    }
    profile = {"platform": "windows", "sandbox_root": str(sandbox)}

    early = SubprocessRustRunner._prepare_cancellation_control(manifest, profile, task_id)
    assert early is not None
    early_root = sandbox / ".bluefire-cancellation-witness-v1" / digest
    assert {item.name for item in early_root.iterdir()} == {".lease"}
    assert early.cleanup() is True
    assert not early_root.exists()
    assert not early_root.parent.exists()

    crashed = SubprocessRustRunner._prepare_cancellation_control(manifest, profile, task_id)
    assert crashed is not None
    crashed_root = sandbox / ".bluefire-cancellation-witness-v1" / digest
    (crashed_root / "ready.json").write_text(
        json.dumps(
            {
                "schema_version": "bluefire.process-tree-cancellation-ready.v1",
                "task_id": task_id,
                "request_hash": request_hash,
                "parent_process_id": 701,
                "descendant_process_id": 702,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    assert crashed.cleanup() is True
    assert not crashed_root.exists()
    assert not crashed_root.parent.exists()


def test_outer_cancellation_cleanup_refuses_missing_lease(tmp_path: Path) -> None:
    digest = "f" * 64
    sandbox = (tmp_path / "sandbox").resolve()
    parent = sandbox / ".bluefire-cancellation-witness-v1"
    task = parent / digest
    task.mkdir(parents=True)
    sandbox_control = runner_client_module._PinnedPrivateDirectory(sandbox)
    parent_control = runner_client_module._PinnedPrivateDirectory(parent)
    task_control = runner_client_module._PinnedPrivateDirectory(task, delete=True)
    sandbox_control.__enter__()
    parent_control.__enter__()
    task_control.__enter__()
    lease = runner_client_module._CancellationControlLease(
        sandbox=sandbox_control,
        parent=parent_control,
        task=task_control,
        parent_created=True,
        task_id="execute-" + digest,
        request_hash="sha256:" + digest,
        token="e" * 64,
    )

    assert lease.cleanup() is False
    assert task.is_dir()
    assert parent.is_dir()


@pytest.mark.parametrize("replaced_name", ["ready.json", "cancel.request", "cancel.ack"])
def test_cancellation_cleanup_binds_immutable_live_handshake_identities(
    tmp_path: Path,
    replaced_name: str,
) -> None:
    digest = "d" * 64
    request_hash = "sha256:" + digest
    task_id = "execute-" + digest
    sandbox = (tmp_path / "sandbox").resolve()
    root = sandbox / ".bluefire-cancellation-witness-v1" / digest
    root.mkdir(parents=True)
    token = "e" * 64
    (root / ".lease").write_bytes(f"lease:{token}\n".encode("ascii"))
    ready_payload = (
        json.dumps(
            {
                "schema_version": "bluefire.process-tree-cancellation-ready.v1",
                "task_id": task_id,
                "request_hash": request_hash,
                "parent_process_id": 801,
                "descendant_process_id": 802,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    (root / "ready.json").write_bytes(ready_payload)
    config = SimpleNamespace(
        task_id=task_id,
        manifest={
            "action_id": "sandbox.execution.process-tree-cancellation-witness.v1",
            "behavior_id": "sandbox.execution.process-tree-cancellation-witness.v1",
            "params": {},
            "platform": "windows",
            "request_hash": request_hash,
        },
        profile={"platform": "windows", "sandbox_root": str(sandbox)},
        cancellation_lease_token=token,
    )
    requested = threading.Event()
    acknowledged = threading.Event()
    handshakes: list[Any] = []

    def acknowledge() -> None:
        request_path = root / "cancel.request"
        _wait_for_file(request_path)
        request = request_path.read_bytes()
        (root / "cancel.ack").write_bytes(b"ack:" + request[7:])

    responder = threading.Thread(target=acknowledge)
    responder.start()
    runner_watchdog_module._cooperative_cancellation(
        config,
        requested,
        acknowledged,
        [801],
        handshakes,
    )
    responder.join(timeout=5)
    assert not responder.is_alive()
    assert requested.is_set() and acknowledged.is_set()
    assert len(handshakes) == 1

    target = root / replaced_name
    original = target.read_bytes()
    target.unlink()
    target.write_bytes(original)
    assert (
        runner_watchdog_module._cleanup_cooperative_cancellation(
            config,
            requested,
            acknowledged,
            handshakes,
        )
        is False
    )
    assert target.read_bytes() == original


def test_private_file_identity_honors_nonmutating_permission_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-identity"
    root.mkdir()
    target = root / "record"
    target.write_bytes(b"record\n")
    observed: list[bool] = []
    with private_files_module._PinnedPrivateDirectory(root) as pinned:
        original = pinned._open_existing

        def observe_open(
            name: str,
            *,
            delete: bool = False,
            write_dac: bool = True,
        ) -> int:
            observed.append(write_dac)
            return original(name, delete=delete, write_dac=write_dac)

        monkeypatch.setattr(pinned, "_open_existing", observe_open)
        pinned.file_identity("record", maximum=32, apply_permissions=False)

    assert observed == [False]


def test_private_unlink_rejects_changed_metadata_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "private-unlink"
    root.mkdir()
    target = root / "record"
    target.write_bytes(b"record\n")
    with private_files_module._PinnedPrivateDirectory(root) as pinned:
        payload, identity, snapshot = pinned.read_with_snapshot_identity(
            "record", maximum=32, apply_permissions=False
        )
        time.sleep(0.01)
        target.write_bytes(payload)
        current = target.stat(follow_symlinks=False)
        os.utime(target, ns=(current.st_atime_ns, snapshot[1]))
        changed = target.stat(follow_symlinks=False)
        assert (changed.st_mtime_ns, changed.st_size) == (snapshot[1], snapshot[2])
        if changed.st_ctime_ns == snapshot[0]:
            os.utime(target, ns=(changed.st_atime_ns, snapshot[1] + 2_000_000_000))
            changed = target.stat(follow_symlinks=False)
            assert changed.st_mtime_ns != snapshot[1]
        with pytest.raises(OSError, match="metadata changed"):
            pinned.unlink(
                "record",
                maximum=32,
                expected=payload,
                expected_identity=identity,
                expected_snapshot=snapshot,
                apply_permissions=False,
            )

    assert target.read_bytes() == payload


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="Darwin runner execution is fail-closed under the proven no-fork sandbox",
)
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
            str(runner._watchdog_interpreter if sys.platform == "darwin" else runner.runner_binary),
            str(driver_path),
            str(runner.runner_binary),
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
        _wait_for_file(effect_marker, timeout=_NESTED_PROCESS_START_TIMEOUT_SECONDS)
        parent.kill()
        parent.wait(timeout=5)

        if os.name == "nt":
            rebound_parent = durable.parent.with_name("rebound-durable")
            with pytest.raises(OSError):
                durable.parent.rename(rebound_parent)
            assert durable.parent.is_dir()

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


def test_terminal_cleanup_refuses_hardlinked_status_without_touching_victim(
    tmp_path: Path,
) -> None:
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    task_id = "task-hardlink-status-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    control_root.mkdir()
    payload = json.dumps(
        {
            "schema_version": "bluefire.runner-watchdog-status.v1",
            "task_id": task_id,
            "state": "cancelled",
            "error_code": "cancelled",
            "watchdog_pid": 123,
        },
        sort_keys=True,
    ).encode("utf-8")
    victim = tmp_path / "victim-status.json"
    victim.write_bytes(payload)
    os.link(victim, control_root / "status.json")

    with pytest.raises(RunnerTransportError, match="not ready for reconciliation"):
        cleanup_runner_watchdog_terminal_state(durable, task_id)

    assert victim.read_bytes() == payload
    assert (control_root / "status.json").read_bytes() == payload


def test_terminal_cleanup_identity_binding_preserves_same_content_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    task_id = "task-status-victim-swap-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    control_root.mkdir()
    status_path = control_root / "status.json"
    payload = json.dumps(
        {
            "schema_version": "bluefire.runner-watchdog-status.v1",
            "task_id": task_id,
            "state": "cancelled",
            "error_code": "cancelled",
            "watchdog_pid": 123,
        },
        sort_keys=True,
    ).encode("utf-8")
    status_path.write_bytes(payload)
    victim = tmp_path / "same-content-victim.json"
    victim.write_bytes(payload)
    original_status = tmp_path / "original-status.json"
    original_read = runner_client_module._PinnedPrivateDirectory.read_with_identity
    swapped = False

    def swap_after_read(
        pinned: Any,
        name: str,
        *,
        maximum: int,
        expected_identity: tuple[int, int] | None = None,
    ) -> tuple[bytes, tuple[int, int]]:
        nonlocal swapped
        result = original_read(
            pinned,
            name,
            maximum=maximum,
            expected_identity=expected_identity,
        )
        if name == "status.json" and not swapped:
            swapped = True
            status_path.replace(original_status)
            victim.replace(status_path)
        return result

    monkeypatch.setattr(
        runner_client_module._PinnedPrivateDirectory,
        "read_with_identity",
        swap_after_read,
    )

    with pytest.raises(RunnerTransportError, match="not ready for reconciliation"):
        cleanup_runner_watchdog_terminal_state(durable, task_id)

    assert swapped is True
    assert status_path.read_bytes() == payload
    assert original_status.read_bytes() == payload


def test_existing_oversized_cancel_marker_is_refused_with_bounded_read(
    tmp_path: Path,
) -> None:
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    task_id = "task-oversized-cancel-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    control_root.mkdir()
    marker = control_root / "cancel"
    with marker.open("wb") as handle:
        handle.truncate(1024 * 1024)

    with pytest.raises(RunnerTransportError, match="signal is unavailable"):
        request_runner_task_cancel(durable, task_id)

    assert marker.stat().st_size == 1024 * 1024


def test_atomic_private_publication_uses_a_fixed_short_temporary_basename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "private-publication").resolve()
    root.mkdir()
    temporary_names: list[str] = []
    pinned_type = runner_client_module._PinnedPrivateDirectory
    original_open_new = pinned_type._open_new

    def record_open_new(pinned: Any, name: str) -> int:
        temporary_names.append(name)
        return original_open_new(pinned, name)

    monkeypatch.setattr(pinned_type, "_open_new", record_open_new)
    with pinned_type(root) as pinned:
        pinned.create(
            "a-very-long-semantic-destination-name.json",
            b"{}\n",
            maximum=32,
        )

    assert len(temporary_names) == 1
    temporary = temporary_names[0]
    assert temporary.startswith(".t-")
    assert len(temporary) == 15
    assert all(character in "0123456789abcdef" for character in temporary[3:])
    assert "destination" not in temporary


def test_cancel_staging_collision_cannot_claim_marker_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    task_id = "task-cancel-staging-collision-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    control_root.mkdir()

    def collide_staging(
        _pinned: private_files_module._PinnedPrivateDirectory,
        _name: str,
    ) -> int:
        raise FileExistsError("injected staging collision")

    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "_open_new",
        collide_staging,
    )

    with pytest.raises(RunnerTransportError, match="signal is unavailable"):
        request_runner_task_cancel(durable, task_id)
    assert tuple(control_root.iterdir()) == ()


@pytest.mark.skipif(os.name != "nt", reason="Windows consumable marker publication")
def test_cancel_marker_may_be_consumed_immediately_after_atomic_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    durable = (tmp_path / "durable" / "result.json").resolve()
    durable.parent.mkdir()
    task_id = "task-consumable-cancel-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    control_root.mkdir()
    marker = control_root / "cancel"
    published = threading.Event()
    consumed = threading.Event()
    consumer_errors: list[BaseException] = []
    pinned_type = private_files_module._PinnedPrivateDirectory
    real_rename = private_files_module._windows_rename_descriptor
    real_open_existing = pinned_type._open_existing

    def observe_rename(*args: Any, **kwargs: Any) -> None:
        real_rename(*args, **kwargs)
        published.set()

    def wait_for_consumption_before_reopen(
        pinned: private_files_module._PinnedPrivateDirectory,
        name: str,
        *,
        delete: bool = False,
        write_dac: bool = True,
    ) -> int:
        if name == "cancel" and published.is_set():
            assert consumed.wait(timeout=5)
        return real_open_existing(
            pinned,
            name,
            delete=delete,
            write_dac=write_dac,
        )

    def consume_marker() -> None:
        try:
            assert published.wait(timeout=5)
            deadline = time.monotonic() + 5
            while True:
                try:
                    marker.unlink()
                    consumed.set()
                    return
                except PermissionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
        except BaseException as exc:
            consumer_errors.append(exc)
            consumed.set()

    monkeypatch.setattr(private_files_module, "_windows_rename_descriptor", observe_rename)
    monkeypatch.setattr(pinned_type, "_open_existing", wait_for_consumption_before_reopen)
    consumer = threading.Thread(target=consume_marker, daemon=True)
    consumer.start()
    try:
        request_runner_task_cancel(durable, task_id)
    finally:
        consumer.join(timeout=5)

    assert not consumer.is_alive()
    assert consumer_errors == []
    assert consumed.is_set()
    assert not marker.exists()


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


@pytest.mark.skipif(os.name != "nt", reason="Windows directory lease regression")
def test_execute_task_retains_parent_guard_before_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SetupInterrupted(BaseException):
        pass

    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "result.json").resolve()
    rebound_parent = tmp_path / "rebound-durable"
    interruption = SetupInterrupted()

    def inspect_earliest_setup(
        _task_id: str,
        *,
        action_id: object,
    ) -> Mapping[str, str] | None:
        del action_id
        with pytest.raises(OSError):
            durable.parent.rename(rebound_parent)
        raise interruption

    monkeypatch.setattr(runner, "_receiver_environment", inspect_earliest_setup)

    with pytest.raises(SetupInterrupted) as raised:
        runner.execute_task(
            _manifest(),
            {},
            task_id="task-earliest-parent-lease-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert raised.value is interruption
    durable.parent.rename(rebound_parent)
    assert rebound_parent.is_dir()


def test_execute_task_preserves_primary_and_parent_guard_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "result.json").resolve()
    primary = RunnerPendingResultExists("primary setup failure")
    close_failure = OSError("parent guard close failed")
    real_close = private_files_module._PinnedPrivateDirectory.close
    close_failed = False

    def fail_prepare(_root: Path) -> None:
        raise primary

    def fail_parent_close(
        pinned: private_files_module._PinnedPrivateDirectory,
    ) -> None:
        nonlocal close_failed
        if pinned.path == durable.parent and not close_failed:
            close_failed = True
            real_close(pinned)
            raise close_failure
        real_close(pinned)

    monkeypatch.setattr(runner, "_prepare_watchdog_control", fail_prepare)
    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "close",
        fail_parent_close,
    )

    with pytest.raises(private_files_module._PrivateFileCleanupError) as raised:
        runner.execute_task(
            _manifest(),
            {},
            task_id="task-parent-close-failure-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )

    assert close_failed is True
    assert raised.value.failures == (primary, close_failure)


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
        _wait_for_file(effect_marker, timeout=_NESTED_PROCESS_START_TIMEOUT_SECONDS)
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
            str(runner._watchdog_interpreter if sys.platform == "darwin" else runner.runner_binary),
            str(driver_path),
            str(runner.runner_binary),
            str(runner.work_root),
            str(durable),
            str(manifest_path),
            str(_PARENT_LOSS_TEST_RUNNER_TIMEOUT_SECONDS),
        ],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    runner_pid: int | None = None
    try:
        _wait_for_file(runner_pid_path, timeout=_NESTED_PROCESS_START_TIMEOUT_SECONDS)
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
        _watchdog_interpreter=base._watchdog_interpreter,
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


def test_execute_task_authorizes_only_the_verified_durable_result(
    tmp_path: Path,
) -> None:
    durable = (tmp_path / "durable" / "authorized.json").resolve()
    durable.parent.mkdir()
    with private_files_module._PinnedPrivateDirectory(durable.parent) as guard:
        runner = _runner(tmp_path, durable_result_guard=guard)
        result = runner.execute_task(
            _manifest(),
            {},
            task_id="task-authorized-result-01",
            cancel_event=threading.Event(),
            durable_result_path=durable,
        )
        details = durable.stat(follow_symlinks=False)

        assert result["status"] == "succeeded"
        assert guard.authorized_cleanup_entries() == {
            durable.name: (details.st_dev, details.st_ino)
        }


def test_execute_task_does_not_authorize_an_invalid_result(
    tmp_path: Path,
) -> None:
    durable = (tmp_path / "durable" / "invalid.json").resolve()
    durable.parent.mkdir()
    with private_files_module._PinnedPrivateDirectory(durable.parent) as guard:
        runner = _runner(tmp_path, durable_result_guard=guard)
        with pytest.raises(RunnerTransportError):
            runner.execute_task(
                _full_manifest(result_override={"action_id": "sandbox.fixture.transform.v1"}),
                _full_profile(),
                task_id="task-invalid-authorization-01",
                cancel_event=threading.Event(),
                durable_result_path=durable,
            )

        assert guard.authorized_cleanup_entries() == {}


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


@pytest.mark.skipif(
    os.name == "nt" or sys.platform not in {"darwin", "linux"},
    reason="POSIX watchdog parent-death containment",
)
def test_posix_watchdog_pid_death_cannot_orphan_runner(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    durable = (tmp_path / "durable" / "posix-watchdog-crash.json").resolve()
    durable.parent.mkdir()
    runner_pid_path = (tmp_path / "posix-watchdog-crash-runner.pid").resolve()
    manifest_path = tmp_path / "posix-watchdog-crash-manifest.json"
    manifest_path.write_text(
        json.dumps(
            _manifest("self_pid_sleep", runner_pid_path=str(runner_pid_path)),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    driver_path = tmp_path / "posix-watchdog-crash-parent.py"
    driver_path.write_text(_PARENT_DRIVER, encoding="utf-8")
    parent = subprocess.Popen(  # nosec B603
        [
            str(runner._watchdog_interpreter if sys.platform == "darwin" else runner.runner_binary),
            str(driver_path),
            str(runner.runner_binary),
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
        assert os.getpgid(watchdog_pid) == watchdog_pid
        runner_group = os.getpgid(runner_pid)
        if sys.platform == "darwin":
            assert runner_group > 1
            assert runner_group != watchdog_pid
        else:
            assert runner_group == watchdog_pid
        assert os.getsid(runner_pid) == watchdog_pid

        parent.kill()
        parent.wait(timeout=5)
        assert _pid_is_running(watchdog_pid)
        assert _pid_is_running(runner_pid)
        os.kill(watchdog_pid, signal.SIGKILL)
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
                os.kill(process_id, signal.SIGKILL)


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
            str(runner._watchdog_interpreter if sys.platform == "darwin" else runner.runner_binary),
            str(driver_path),
            str(runner.runner_binary),
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


@pytest.mark.skipif(os.name != "nt", reason="Windows extended private path support")
def test_watchdog_control_uses_handle_acl_beyond_legacy_path_limit(
    tmp_path: Path,
) -> None:
    durable_parent = tmp_path / "durable"
    index = 0
    while len(os.fspath(durable_parent)) < 185:
        durable_parent /= f"segment-{index:02d}-" + "x" * 20
        index += 1
    durable_parent.mkdir(parents=True)
    durable = durable_parent / "result.json"
    assert len(os.fspath(durable)) < 240

    task_id = "task-extended-owner-acl-01"
    control_root = runner_watchdog_control_root(durable, task_id)
    assert os.fspath(control_root).startswith("\\\\?\\")
    assert len(os.fspath(control_root)) >= 260

    runner = _runner(tmp_path)
    direct_durable = durable_parent / "direct.json"
    direct_pending = runner_pending_result_path(
        direct_durable,
        "task-extended-direct-01",
    )
    assert len(os.fspath(direct_pending)) >= 260
    direct = runner._execute_task_locally(
        _manifest(),
        {},
        task_id="task-extended-direct-01",
        cancel_event=threading.Event(),
        durable_result_path=direct_durable,
    )
    assert direct["status"] == "succeeded"
    result = runner.execute_task(
        _manifest(),
        {},
        task_id=task_id,
        cancel_event=threading.Event(),
        durable_result_path=durable,
    )

    assert result["status"] == "succeeded"
    assert json.loads(durable.read_text(encoding="utf-8")) == result
    assert not control_root.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows owner ACL import boundary")
def test_windows_owner_acl_import_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "bluefire.windows_owner_acl", None)

    with pytest.raises(
        runner_trust_module.RunnerTrustError,
        match="Enrollment permissions could not be restricted",
    ):
        runner_trust_module._owner_private_handle(-1, directory=True)
