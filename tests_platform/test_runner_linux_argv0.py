"""Canonical startup metadata must never replace the held executable selector."""

from __future__ import annotations

import os
import stat
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import runner_client
from bluefire.runner_client import RunnerTransportError, SubprocessRustRunner


@pytest.fixture
def launch_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    runner = object.__new__(SubprocessRustRunner)
    runner.runner_binary = tmp_path / "runner"
    runner._watchdog_interpreter = tmp_path / "python"
    runner._watchdog_python_environment = None
    runner.parent_death_script = tmp_path / "runner_parent_death.py"
    runner.watchdog_script = tmp_path / "runner_watchdog.py"
    runner.work_root = tmp_path
    for path in (
        runner.runner_binary,
        runner._watchdog_interpreter,
        runner.parent_death_script,
        runner.watchdog_script,
    ):
        path.write_bytes(path.name.encode())
    digest = "sha256:" + "a" * 64
    runner.runner_binary_digest = digest
    runner._watchdog_interpreter_digest = digest
    runner.parent_death_script_digest = digest
    runner.watchdog_script_digest = digest
    descriptors = {
        path: os.open(path, os.O_RDONLY)
        for path in (runner.runner_binary, runner._watchdog_interpreter)
    }
    state = SimpleNamespace(
        runner=runner,
        descriptors=descriptors,
        calls=[],
        events=[],
        mutation=None,
        changed=False,
        selected=runner.runner_binary,
    )
    real_lstat = Path.lstat
    real_fstat = os.fstat

    def changed_details(details, **changes):
        values = {name: getattr(details, name) for name in dir(details) if name.startswith("st_")}
        return SimpleNamespace(**(values | changes))

    def visible(path):
        details = real_lstat(path)
        if state.changed and path == state.selected:
            if state.mutation[1] == "missing":
                raise FileNotFoundError("authored missing canonical path")
            if state.mutation[1] == "symlink":
                return changed_details(details, st_mode=stat.S_IFLNK | 0o700)
            if state.mutation[1] == "path":
                return changed_details(details, st_ino=details.st_ino + 1)
            if state.mutation[1] == "mode":
                return changed_details(details, st_mode=details.st_mode ^ 0o100)
        return details

    def opened(descriptor):
        details = real_fstat(descriptor)
        if state.changed and state.mutation[1] == "fd":
            return changed_details(details, st_ino=details.st_ino + 1)
        return details

    class Process:
        pid = 4242

        def kill(self):
            state.events.append("kill")

        def wait(self, *, timeout):
            assert timeout == runner_client._PROCESS_KILL_GRACE_SECONDS
            state.events.append("reap")
            return -9

    process = Process()

    class Control:
        reads = 0

        def fileno(self):
            return 105

        def settimeout(self, timeout):
            assert timeout == runner_client._WATCHDOG_START_GRACE_SECONDS

        def close(self):
            state.events.append("control-close")

        def recv(self, maximum):
            assert maximum == 256
            self.reads += 1
            if self.reads == 1:
                state.events.append("armed")
                if state.mutation is not None and state.mutation[0] == "prego":
                    state.changed = True
                return f"armed-v1:{'a' * 64}:{process.pid}:{os.getpid()}".encode()
            return b""

        def sendall(self, value):
            assert value == f"go-v1:{'a' * 64}".encode()
            state.events.append("go")

    @contextmanager
    def pinned(path, expected_digest, **_options):
        assert expected_digest == digest
        if path == runner.parent_death_script and state.mutation is not None:
            if state.mutation[0] == "prelaunch":
                state.changed = True
        descriptor = descriptors.get(path, 102)
        yield f"/proc/self/fd/{descriptor}", (descriptor,)

    def popen(arguments, **options):
        state.events.append("spawn")
        state.calls.append((arguments, options))
        return process

    monkeypatch.setattr(Path, "lstat", visible)
    monkeypatch.setattr(runner_client, "os", SimpleNamespace(**(vars(os) | {"fstat": opened})))
    monkeypatch.setattr(runner_client, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        runner_client,
        "socket",
        SimpleNamespace(
            AF_UNIX=1,
            SOCK_SEQPACKET=5,
            socketpair=lambda *_args: (Control(), Control()),
            timeout=TimeoutError,
        ),
    )
    monkeypatch.setattr(runner_client, "secrets", SimpleNamespace(token_hex=lambda _size: "a" * 64))
    monkeypatch.setattr(
        runner_client,
        "subprocess",
        SimpleNamespace(
            Popen=popen,
            DEVNULL=-3,
            PIPE=-1,
            SubprocessError=RuntimeError,
        ),
    )
    monkeypatch.setattr(runner_client, "file_hash", lambda _path: digest)
    monkeypatch.setattr(runner_client, "_pinned_launch_file", pinned)
    monkeypatch.setattr(runner_client, "_GET_PROCESS_GROUP_ID", lambda _pid: os.getpid())
    monkeypatch.setattr(runner_client, "_GET_SESSION_ID", lambda _pid: os.getpid())
    try:
        yield state
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def _launch(state, canonical=None, *, inherited=True, argv0=None):
    descriptor = state.descriptors[state.selected]
    return state.runner._spawn_linux_parent_death(
        [argv0 or f"/proc/self/fd/{descriptor}", "fixed", "argument with spaces"],
        stdout=-1,
        stderr=-1,
        canonical_argv0=canonical,
        environment={"LC_ALL": "C", "LANG": "C"},
        inherited_descriptors=(descriptor,) if inherited else (),
        options={"pass_fds": (descriptor,)},
    )


@pytest.mark.parametrize("role", ("runner", "watchdog"))
def test_parent_death_uses_canonical_metadata_but_the_original_held_descriptor(
    launch_boundary, role: str
) -> None:
    state = launch_boundary
    state.selected = (
        state.runner.runner_binary if role == "runner" else state.runner._watchdog_interpreter
    )
    descriptor = state.descriptors[state.selected]
    _launch(state, state.selected)
    arguments, options = state.calls[0]
    assert arguments[8] == str(descriptor)
    assert arguments[11:] == [str(state.selected), "fixed", "argument with spaces"]
    assert options == {
        "cwd": state.runner.work_root,
        "env": {"LC_ALL": "C", "LANG": "C"},
        "stdin": -3,
        "stdout": -1,
        "stderr": -1,
        "shell": False,
        "pass_fds": tuple(
            sorted({descriptor, state.descriptors[state.runner._watchdog_interpreter], 102, 105})
        ),
    }
    assert state.events[:3] == ["spawn", "control-close", "armed"]
    assert "go" in state.events and "kill" not in state.events and "reap" not in state.events


@pytest.mark.parametrize("canonical", ("missing", "unregistered", "wrong-role"))
def test_canonical_metadata_must_name_the_registered_held_identity(launch_boundary, canonical):
    state = launch_boundary
    candidate = {
        "missing": None,
        "unregistered": state.runner.work_root / "unregistered",
        "wrong-role": state.runner._watchdog_interpreter,
    }[canonical]
    with pytest.raises(RunnerTransportError):
        _launch(state, candidate)
    assert not state.calls and "go" not in state.events


@pytest.mark.parametrize("failure", ("missing-fd", "canonical-as-selector"))
def test_canonical_metadata_cannot_replace_descriptor_authority(launch_boundary, failure):
    state = launch_boundary
    with pytest.raises(RunnerTransportError, match="not descriptor-bound"):
        _launch(
            state,
            state.selected,
            inherited=failure != "missing-fd",
            argv0=str(state.selected) if failure == "canonical-as-selector" else None,
        )
    assert not state.calls and not state.events


@pytest.mark.parametrize("phase", ("prelaunch", "prego"))
@pytest.mark.parametrize("mutation", ("path", "fd", "mode", "symlink", "missing"))
def test_identity_changes_refuse_before_target_execution_and_reap_started_helper(
    launch_boundary, phase, mutation
):
    state = launch_boundary
    state.mutation = phase, mutation
    with pytest.raises(RunnerTransportError, match="containment failed"):
        _launch(state, state.selected)
    assert "go" not in state.events
    if phase == "prelaunch":
        assert not state.calls and "kill" not in state.events and "reap" not in state.events
    else:
        assert len(state.calls) == 1
        assert state.events.index("armed") < state.events.index("kill") < state.events.index("reap")


@pytest.mark.parametrize("method", ("watchdog", "invoke", "invoke-task"))
def test_each_call_site_supplies_its_own_canonical_role(launch_boundary, method):
    state = launch_boundary
    runner = state.runner
    captured = []

    class Captured(Exception):
        pass

    def spawn(arguments, **options):
        captured.append((arguments, options))
        raise Captured

    runner._spawn = spawn
    output = SimpleNamespace(identity=lambda: (1, 2), close=lambda: None)
    runner._durable_results = SimpleNamespace(open_pending=lambda _path: output)
    with pytest.raises(Captured):
        if method == "watchdog":
            runner._spawn_watchdog(
                runner.work_root / "config.json",
                receiver_environment={},
                task_id="authored",
                process_sink=[],
            )
        elif method == "invoke":
            runner._invoke([str(runner.runner_binary), "inventory"])
        else:
            runner._invoke_task(
                [str(runner.runner_binary), "execute"],
                cancel_event=threading.Event(),
                pending_result_path=runner.work_root / "pending",
                identity_sink=[],
                receiver_environment=None,
                cooperative_request_event=None,
                cooperative_ack_event=None,
                runner_process_id_sink=None,
                cancellation_lease_token=None,
                darwin_launch_started=None,
                darwin_launch_sealed=None,
            )
    arguments, options = captured[0]
    expected = runner._watchdog_interpreter if method == "watchdog" else runner.runner_binary
    assert options["canonical_argv0"] == expected
    assert arguments[0] == f"/proc/self/fd/{state.descriptors[expected]}"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="actual Linux pinned Python launch"
)
def test_actual_python_target_keeps_prefix_and_closes_executable_descriptors(
    tmp_path: Path,
) -> None:
    work = tmp_path / "authored-work"
    work.mkdir(mode=0o700)
    (work / "execute").write_text(
        """import json, os, sys
with open(sys.argv[sys.argv.index("--manifest") + 1], encoding="utf-8") as source:
    manifest = json.load(source)
held = os.stat("/proc/self/exe")
open_executables = 0
for name in os.listdir("/proc/self/fd"):
    try:
        observed = os.fstat(int(name))
    except OSError:
        continue
    open_executables += (observed.st_dev, observed.st_ino) == (held.st_dev, held.st_ino)
result = {
    "schema_version": "bluefire.runner-result.v1",
    "run_id": manifest["run_id"], "step_id": manifest["step_id"],
    "action_id": manifest["action_id"], "status": "succeeded",
    "startup": {
        "canonical_executable": os.path.realpath(sys.executable) == os.path.realpath("/proc/self/exe"),
        "prefix": sys.prefix == manifest["expected_prefix"],
        "base_prefix": sys.base_prefix == manifest["expected_prefix"],
        "stdlib": os.path.realpath(os.__file__) == manifest["expected_stdlib"],
        "executable_descriptors_closed": open_executables == 0,
    },
}
print(json.dumps(result))
""",
        encoding="utf-8",
    )
    # This witness checks base-runtime recovery, including from a --copies venv.
    # Select the same configured base executable as the watchdog constructor.
    runner = SubprocessRustRunner(
        Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True),
        work,
        timeout_seconds=5.0,
        output_limit_bytes=64 * 1024,
    )
    durable = tmp_path / "result.json"
    manifest: dict[str, Any] = {
        "schema_version": "bluefire.runner-manifest.v1",
        "run_id": "run-20260825T120000Z-0123456789abcdef",
        "step_id": "authored-startup",
        "action_id": "sandbox.fixture.create.v1",
        "expected_prefix": sys.base_prefix,
        "expected_stdlib": os.path.realpath(os.__file__),
    }
    result = runner.execute_task(
        manifest,
        {},
        task_id="task-canonical-startup-01",
        cancel_event=threading.Event(),
        durable_result_path=durable,
    )
    assert result["startup"] == {
        "canonical_executable": True,
        "prefix": True,
        "base_prefix": True,
        "stdlib": True,
        "executable_descriptors_closed": True,
    }
    assert durable.is_file()
    assert not runner_client.runner_pending_result_path(
        durable, "task-canonical-startup-01"
    ).exists()
    assert not runner_client.runner_watchdog_control_root(
        durable, "task-canonical-startup-01"
    ).exists()
