from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any

import pytest

if os.name == "nt":
    pytest.skip("Darwin parent-death tests require POSIX", allow_module_level=True)

import bluefire.runner_darwin_containment as darwin_containment
import bluefire.runner_parent_death as parent_death
import bluefire.runner_watchdog as runner_watchdog
from bluefire.runner_client import SubprocessRustRunner
from bluefire.util import file_hash

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_DRIVER = r"""
import json
import os
import socket
import subprocess
import sys


def receive_line(control):
    payload = bytearray()
    while len(payload) <= 256:
        chunk = control.recv(1)
        if not chunk:
            break
        payload.extend(chunk)
        if chunk == b"\n":
            return bytes(payload)
    raise OSError("invalid control record")


target_path = sys.argv[1]
target_code = sys.argv[2]
parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
target_descriptor = os.open(target_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
nonce = "a" * 64
helper_code = (
    "import os, sys; "
    "from bluefire.runner_parent_death import _run_darwin; "
    "os._exit(_run_darwin(sys.argv[1:]))"
)
helper = subprocess.Popen(
    [
        sys.executable,
        "-c",
        helper_code,
        str(os.getpid()),
        str(child_socket.fileno()),
        str(target_descriptor),
        nonce,
        "",
        target_path,
        "-I",
        "-B",
        "-c",
        target_code,
    ],
    cwd=sys.argv[3],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    shell=False,
    pass_fds=(child_socket.fileno(), target_descriptor),
)
child_socket.close()
os.close(target_descriptor)
armed = receive_line(parent_socket).decode("ascii")
parts = armed.rstrip("\n").split(":")
print(
    json.dumps(
        {
            "armed": armed,
            "helper_pid": helper.pid,
            "monitor_pid": int(parts[3]),
            "target_pid": int(parts[4]),
        },
        sort_keys=True,
    ),
    flush=True,
)
command = sys.stdin.readline().strip()
if command != "go":
    os._exit(75)
parent_socket.sendall(("go-v2:" + nonce + "\n").encode("ascii"))
try:
    executed = receive_line(parent_socket).decode("ascii")
except OSError:
    executed = None
print(json.dumps({"executed": executed}, sort_keys=True), flush=True)
return_code = helper.wait(timeout=20)
print(json.dumps({"helper_returncode": return_code}, sort_keys=True), flush=True)
"""


def _running(process_id: int) -> bool:
    if sys.platform.startswith("linux"):
        try:
            payload = (Path("/proc") / str(process_id) / "stat").read_bytes()
        except FileNotFoundError:
            return False
        close = payload.rfind(b")")
        return close < 0 or payload[close + 2 : close + 3] != b"Z"
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_running(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_darwin_watchdog_launch_link_normalizes_to_verified_canonical_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = tmp_path / "runner_watchdog.py"
    canonical.write_text("raise SystemExit(0)\n", encoding="utf-8")
    launch = tmp_path / (".bluefire-verified-launch-" + "d" * 64)
    os.link(canonical, launch)
    monkeypatch.setattr(runner_watchdog, "__file__", str(launch))
    monkeypatch.setattr(runner_watchdog.sys, "platform", "darwin")
    monkeypatch.setattr(
        runner_watchdog,
        "_validate_macos_launch_parent",
        lambda _path, _descriptor: os.geteuid(),
    )

    normalized, details = runner_watchdog._verified_watchdog_script(file_hash(canonical))

    assert normalized == canonical
    assert os.path.samestat(details, canonical.stat(follow_symlinks=False))
    assert details.st_nlink == 2


def _wait_until_stopped(*process_ids: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(not _running(process_id) for process_id in process_ids):
            return
        time.sleep(0.025)
    raise AssertionError(f"processes did not stop: {process_ids!r}")


def _wait_for_file(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return
        time.sleep(0.025)
    raise AssertionError(f"file was not published: {path}")


def _read_record(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, f"driver exited before publishing a record: {process.poll()}"
    value = json.loads(line)
    assert isinstance(value, dict)
    return value


def _launch_supervisor(
    tmp_path: Path,
    target_code: str,
) -> tuple[subprocess.Popen[str], Path, dict[str, Any]]:
    runtime = tmp_path / "python-runtime"
    launch = tmp_path / (".bluefire-verified-launch-" + "b" * 64)
    shutil.copyfile(sys.executable, runtime)
    runtime.chmod(0o700)
    os.link(runtime, launch)
    process = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            _DRIVER,
            str(launch),
            target_code,
            str(_REPOSITORY_ROOT),
        ],
        cwd=_REPOSITORY_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        start_new_session=True,
    )
    return process, launch, _read_record(process)


def _start_target(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdin is not None
    process.stdin.write("go\n")
    process.stdin.flush()
    return _read_record(process)


def _cleanup_driver(process: subprocess.Popen[str], identities: dict[str, Any]) -> None:
    # The unreaped direct child pins its private session/group identifier.
    # Never signal a recorded descendant identifier after it may be reused.
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


pytestmark = pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "fork"),
    reason="portable execution of the Darwin fork-and-lease supervisor",
)


def test_darwin_watchdog_eof_kills_the_runner_group(tmp_path: Path) -> None:
    process, _launch, identities = _launch_supervisor(tmp_path, "import time; time.sleep(60)")
    try:
        executed = _start_target(process)
        assert executed["executed"] == "executed-v2:" + "a" * 64 + "\n"
        process.kill()
        process.wait(timeout=5)
        _wait_until_stopped(
            identities["helper_pid"],
            identities["monitor_pid"],
            identities["target_pid"],
        )
        assert not _group_running(identities["monitor_pid"])
    finally:
        _cleanup_driver(process, identities)


def test_darwin_helper_loss_is_closed_by_the_monitor(tmp_path: Path) -> None:
    process, _launch, identities = _launch_supervisor(tmp_path, "import time; time.sleep(60)")
    try:
        assert _start_target(process)["executed"] is not None
        os.kill(identities["helper_pid"], signal.SIGKILL)
        _wait_until_stopped(identities["monitor_pid"], identities["target_pid"])
        assert not _group_running(identities["monitor_pid"])
        assert _read_record(process)["helper_returncode"] < 0
    finally:
        _cleanup_driver(process, identities)


def test_darwin_monitor_loss_is_closed_by_the_helper(tmp_path: Path) -> None:
    process, _launch, identities = _launch_supervisor(tmp_path, "import time; time.sleep(60)")
    try:
        assert _start_target(process)["executed"] is not None
        os.kill(identities["monitor_pid"], signal.SIGKILL)
        _wait_until_stopped(identities["helper_pid"], identities["target_pid"])
        assert not _group_running(identities["monitor_pid"])
        assert _read_record(process)["helper_returncode"] == 74
    finally:
        _cleanup_driver(process, identities)


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="Darwin production dynamically proves and enforces no-fork before exec",
)
def test_portable_darwin_supervisor_runner_exit_cleans_a_live_descendant(
    tmp_path: Path,
) -> None:
    descendant_path = tmp_path / "descendant.pid"
    target_code = (
        "import os, pathlib, subprocess, sys; "
        "child=subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(60)']); "
        f"path=pathlib.Path({str(descendant_path)!r}); "
        "path.write_text(str(child.pid), encoding='ascii'); "
        "os._exit(0)"
    )
    process, _launch, identities = _launch_supervisor(tmp_path, target_code)
    try:
        assert _start_target(process)["executed"] is not None
        _wait_for_file(descendant_path)
        descendant = int(descendant_path.read_text(encoding="ascii"))
        assert _read_record(process)["helper_returncode"] == 74
        _wait_until_stopped(descendant, identities["monitor_pid"], identities["target_pid"])
        assert not _group_running(identities["monitor_pid"])
    finally:
        _cleanup_driver(process, identities)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin Seatbelt dynamic proof")
def test_darwin_runner_inherits_a_dynamically_proven_no_fork_sandbox(
    tmp_path: Path,
) -> None:
    result = tmp_path / "fork-denied.txt"
    target_code = f"""
import json
import os
import pathlib
import subprocess
import sys

result = pathlib.Path({str(result)!r})
record = {{}}
try:
    child = os.fork()
except OSError as error:
    record["fork_errno"] = error.errno
else:
    if child == 0:
        os._exit(75)
    os.waitpid(child, 0)
    record["fork_succeeded"] = True
try:
    spawned = subprocess.run(
        [sys.executable, "-I", "-B", "-c", "raise SystemExit(0)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
except OSError as error:
    record["spawn_errno"] = error.errno
else:
    record["spawn_returncode"] = spawned.returncode
result.write_text(json.dumps(record, sort_keys=True), encoding="ascii")
os._exit(0 if set(record) == {{"fork_errno", "spawn_errno"}} else 75)
"""
    process, _launch, identities = _launch_supervisor(tmp_path, target_code)
    try:
        assert _start_target(process)["executed"] is not None
        assert _read_record(process)["helper_returncode"] == 0
        record = json.loads(result.read_text(encoding="ascii"))
        assert record.keys() == {"fork_errno", "spawn_errno"}
        assert set(record.values()) <= {1, 13}
        _wait_until_stopped(identities["monitor_pid"], identities["target_pid"])
        assert not _group_running(identities["monitor_pid"])
    finally:
        _cleanup_driver(process, identities)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin private runtime staging")
def test_default_darwin_watchdog_runtime_is_staged_away_from_framework_parent(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "runner-work"
    work_root.mkdir(mode=0o700)
    runner_binary = work_root / "python-runner"
    shutil.copyfile(sys.executable, runner_binary)
    runner_binary.chmod(0o700)
    source = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    source_details = source.stat(follow_symlinks=False)
    source_cache = source.parent / ".bluefire-watchdog-runtime-v1"
    source_cache_existed = source_cache.exists()

    runner = SubprocessRustRunner(runner_binary, work_root)

    staged = runner._watchdog_interpreter
    assert staged.parent == work_root / ".bluefire-watchdog-runtime-v1"
    assert staged != source
    assert staged.stat().st_nlink == 1
    assert stat.S_IMODE(staged.stat().st_mode) == 0o700
    assert file_hash(staged) == runner._watchdog_interpreter_digest
    current_source = source.stat(follow_symlinks=False)
    assert (
        current_source.st_dev,
        current_source.st_ino,
        current_source.st_mode,
        current_source.st_nlink,
        current_source.st_size,
        current_source.st_mtime_ns,
        current_source.st_ctime_ns,
    ) == (
        source_details.st_dev,
        source_details.st_ino,
        source_details.st_mode,
        source_details.st_nlink,
        source_details.st_size,
        source_details.st_mtime_ns,
        source_details.st_ctime_ns,
    )
    assert source_cache.exists() is source_cache_existed
    completed = subprocess.run(  # nosec B603
        [str(staged), "-I", "-B", "-c", "raise SystemExit(0)"],
        cwd=work_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0


def test_darwin_verified_target_substitution_never_executes(tmp_path: Path) -> None:
    marker = tmp_path / "unverified-executed"
    target_code = f"from pathlib import Path; Path({str(marker)!r}).touch()"
    process, launch, identities = _launch_supervisor(tmp_path, target_code)
    try:
        launch.unlink()
        shutil.copyfile(sys.executable, launch)
        launch.chmod(0o700)
        assert _start_target(process)["executed"] is None
        assert _read_record(process)["helper_returncode"] == 74
        assert not marker.exists()
        _wait_until_stopped(identities["monitor_pid"], identities["target_pid"])
    finally:
        _cleanup_driver(process, identities)


def test_darwin_handshake_rejects_a_group_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = "c" * 64
    armed = f"armed-v2:{nonce}:501:502:503:500\n".encode("ascii")
    groups = {501: 500, 502: 502, 503: 502}
    sessions = {501: 500, 502: 500, 503: 500}
    monkeypatch.setattr(darwin_containment.os, "getpid", lambda: 500)
    monkeypatch.setattr(darwin_containment, "_GET_PROCESS_GROUP_ID", groups.__getitem__)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", sessions.__getitem__)

    assert darwin_containment.validate_containment_identity(
        armed,
        nonce=nonce,
        helper_process=501,
    ) == (502, 503)

    groups[503] = 999

    with pytest.raises(OSError, match="identity is invalid"):
        darwin_containment.validate_containment_identity(
            armed,
            nonce=nonce,
            helper_process=501,
        )


def test_darwin_inventories_skip_unqueryable_unrelated_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_ids = {500, 501, 502}

    def session_id(process_id: int) -> int:
        if process_id == 501:
            raise PermissionError(1, "not permitted")
        return 500

    monkeypatch.setattr(darwin_containment.os, "getpid", lambda: 500)
    monkeypatch.setattr(darwin_containment, "_darwin_process_ids", lambda: process_ids)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", session_id)
    assert darwin_containment._private_session_members(500) == {500, 502}

    monkeypatch.setattr(parent_death, "_darwin_process_ids", lambda: process_ids)
    monkeypatch.setattr(parent_death, "_GET_SESSION_ID", session_id)
    monkeypatch.setattr(parent_death, "_GET_PROCESS_GROUP_ID", lambda process_id: process_id)
    assert parent_death._private_process_group_members(502, 500) == {502}


@pytest.mark.skipif(
    not all(hasattr(os, name) for name in ("fork", "waitid", "WNOWAIT", "WEXITED", "P_PID")),
    reason="POSIX unreaped-child identity proof",
)
def test_zombie_only_monitor_is_reaped_without_a_post_exit_group_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_descriptor, write_descriptor = os.pipe()
    os_namespace: Any = os
    fork_process = os_namespace.fork
    wait_for_child = os_namespace.waitid
    process_id = fork_process()
    if process_id == 0:
        os.close(read_descriptor)
        os.setpgid(0, 0)
        os.write(write_descriptor, b"R")
        os.close(write_descriptor)
        os._exit(0)
    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 1) == b"R"
        os.close(read_descriptor)
        wait_for_child(
            os_namespace.P_PID,
            process_id,
            os_namespace.WEXITED | os_namespace.WNOWAIT,
        )
        session_id = os.getsid(process_id)
        monkeypatch.setattr(
            parent_death,
            "_KILL_PROCESS_GROUP",
            lambda _group, _signal: pytest.fail("a zombie-only group was signalled"),
        )

        assert parent_death._terminate_pinned_monitor_group(process_id, session_id)
        with pytest.raises(ChildProcessError):
            os.waitpid(process_id, os.WNOHANG)
    finally:
        try:
            os.close(read_descriptor)
        except OSError:
            pass
        try:
            os.waitpid(process_id, os.WNOHANG)
        except ChildProcessError:
            pass


def test_darwin_watchdog_lease_is_held_until_groups_are_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "runner-work"
    work_root.mkdir()
    runner = SubprocessRustRunner(Path(sys.executable).resolve(strict=True), work_root)
    parent_lease, monitor_lease = socket.socketpair()

    class Process:
        pid = 501
        returncode: int | None = 0

        def poll(self) -> int:
            return 0

        def wait(self, *, timeout: float) -> int:
            assert timeout == 5.0
            return 0

    process = Process()
    runner._darwin_process_containments[process] = (  # type: ignore[index, assignment]
        darwin_containment.DarwinProcessContainment(
            session_id=500,
            monitor_group=502,
            target_process=503,
            parent_lease=parent_lease,
        )
    )
    monkeypatch.setattr(darwin_containment.os, "getpid", lambda: 500)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", lambda _pid: 500)
    monkeypatch.setattr(darwin_containment, "_private_session_members", lambda _session: {500})

    try:
        assert parent_lease.fileno() >= 0
        assert runner._release_darwin_private_process(  # type: ignore[arg-type]
            process,
            terminate=False,
        )
        assert parent_lease.fileno() == -1
        assert monitor_lease.recv(1) == b""
    finally:
        parent_lease.close()
        monitor_lease.close()
