from __future__ import annotations

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
from pathlib import Path
from typing import Any

import pytest

if os.name == "nt":
    pytest.skip("Darwin parent-death tests require POSIX", allow_module_level=True)

import bluefire.runner_client as runner_client_module
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
        "60",
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
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
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


def test_darwin_runtime_staging_creates_a_private_content_addressed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "python-runtime"
    payload = b"framework executable snapshot"
    source.write_bytes(payload)
    source.chmod(0o755)
    work_root = tmp_path / "runner-work"
    work_root.mkdir(mode=0o700)
    monkeypatch.setattr(darwin_containment.sys, "platform", "darwin")
    monkeypatch.setattr(
        darwin_containment,
        "_validate_macos_launch_parent",
        lambda _path, _descriptor: os.geteuid(),
    )
    monkeypatch.setattr(
        darwin_containment,
        "_validate_darwin_descriptor_security",
        lambda _descriptor: None,
    )

    staged, digest = darwin_containment.stage_watchdog_interpreter(source, work_root)

    assert source.read_bytes() == payload
    assert stat.S_IMODE(source.stat().st_mode) == 0o755
    assert staged.read_bytes() == payload
    assert staged.stat().st_nlink == 1
    assert stat.S_IMODE(staged.stat().st_mode) == 0o700
    assert file_hash(staged) == digest


def test_darwin_runtime_permissions_accept_only_root_or_admin_group_writable_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    permission_is_safe = darwin_containment._runtime_source_permissions_are_safe
    monkeypatch.setattr(darwin_containment, "_darwin_admin_group_id", lambda: 80)

    assert permission_is_safe(mode=stat.S_IFREG | 0o755, owner=501, group=20, effective_user=501)
    assert permission_is_safe(mode=stat.S_IFREG | 0o755, owner=0, group=0, effective_user=501)
    assert permission_is_safe(mode=stat.S_IFREG | 0o775, owner=0, group=0, effective_user=501)
    assert permission_is_safe(mode=stat.S_IFREG | 0o775, owner=0, group=80, effective_user=501)
    assert not permission_is_safe(
        mode=stat.S_IFREG | 0o755, owner=502, group=20, effective_user=501
    )
    assert not permission_is_safe(
        mode=stat.S_IFREG | 0o775, owner=501, group=20, effective_user=501
    )
    assert not permission_is_safe(mode=stat.S_IFREG | 0o775, owner=0, group=20, effective_user=501)
    assert not permission_is_safe(mode=stat.S_IFREG | 0o777, owner=0, group=0, effective_user=501)
    assert not permission_is_safe(mode=stat.S_IFREG | 0o4755, owner=0, group=0, effective_user=501)
    assert not permission_is_safe(mode=stat.S_IFREG | 0o2755, owner=0, group=0, effective_user=501)


def test_darwin_runtime_permissions_fail_closed_when_admin_group_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(darwin_containment, "_darwin_admin_group_id", lambda: None)

    assert not darwin_containment._runtime_source_permissions_are_safe(
        mode=stat.S_IFREG | 0o775,
        owner=0,
        group=80,
        effective_user=501,
    )


def test_darwin_runtime_source_applies_descriptor_filesystem_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "python-runtime"
    source.write_bytes(b"verified runtime")
    source.chmod(0o755)
    checked: list[tuple[int, int]] = []

    def validate(descriptor: int) -> None:
        details = os.fstat(descriptor)
        checked.append((details.st_dev, details.st_ino))

    monkeypatch.setattr(darwin_containment, "_validate_darwin_descriptor_security", validate)

    payload, _digest = darwin_containment._read_runtime_source(source)

    assert payload == b"verified runtime"
    assert checked == [(source.stat().st_dev, source.stat().st_ino)]


def test_darwin_runtime_source_rejects_foreign_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "foreign-runtime"
    source.write_bytes(b"foreign-owned runtime")
    source.chmod(0o755)
    actual_fstat = darwin_containment.os.fstat
    effective_user = 501
    foreign_user = 502

    def foreign_fstat(descriptor: int) -> os.stat_result:
        values = list(actual_fstat(descriptor))
        values[4] = foreign_user
        return os.stat_result(values)

    monkeypatch.setattr(darwin_containment.os, "geteuid", lambda: effective_user, raising=False)
    monkeypatch.setattr(darwin_containment.os, "fstat", foreign_fstat)

    with pytest.raises(OSError, match="Darwin runtime source is unsafe"):
        darwin_containment._read_runtime_source(source)


@pytest.mark.parametrize("unsafe_mode", (0o4775, 0o2775, 0o777))
def test_darwin_runtime_source_rejects_privileged_or_world_writable_mode(
    tmp_path: Path,
    unsafe_mode: int,
) -> None:
    source = tmp_path / "unsafe-runtime"
    source.write_bytes(b"unsafe")
    source.chmod(unsafe_mode)
    if stat.S_IMODE(source.stat().st_mode) != unsafe_mode:
        pytest.skip("filesystem does not preserve the requested executable mode")

    with pytest.raises(OSError, match="Darwin runtime source is unsafe"):
        darwin_containment._read_runtime_source(source)


def test_macos_launch_pin_serializes_processes_and_recovers_a_crashed_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = tmp_path / "verified-runner"
    canonical.write_bytes(b"immutable runner payload")
    canonical.chmod(0o700)
    digest = file_hash(canonical)
    attempted = tmp_path / "attempted"
    entered = tmp_path / "entered"
    outcome = tmp_path / "outcome"
    child_source = """
import os
import sys
from pathlib import Path
import bluefire.runner_darwin_containment as darwin_containment
from bluefire.util import file_hash

darwin_containment._validate_macos_launch_parent = lambda _path, _descriptor: os.geteuid()

path = Path(sys.argv[1])
attempted = Path(sys.argv[2])
entered = Path(sys.argv[3])
outcome = Path(sys.argv[4])
darwin_containment._MACOS_PIN_LOCK_TIMEOUT_SECONDS = float(sys.argv[5])
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    expected = os.fstat(descriptor)
    attempted.write_text("ready", encoding="ascii")
    try:
        with darwin_containment.macos_pinned_launch_path(
            path,
            descriptor,
            expected,
            file_hash(path),
        ):
            entered.write_text("entered", encoding="ascii")
    except OSError as exc:
        if str(exc) != "Darwin launch lock timed out":
            raise
        outcome.write_text("timed-out", encoding="ascii")
    else:
        outcome.write_text("entered", encoding="ascii")
finally:
    os.close(descriptor)
"""
    monkeypatch.setattr(
        darwin_containment,
        "_validate_macos_launch_parent",
        lambda _path, _descriptor: os.geteuid(),
    )
    descriptor = os.open(canonical, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    child: subprocess.Popen[str] | None = None
    try:
        expected = os.fstat(descriptor)
        with darwin_containment.macos_pinned_launch_path(
            canonical,
            descriptor,
            expected,
            digest,
        ):
            child = subprocess.Popen(  # nosec B603
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child_source,
                    str(canonical),
                    str(attempted),
                    str(entered),
                    str(outcome),
                    "0.25",
                ],
                cwd=_REPOSITORY_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
            _wait_for_file(attempted)
            _wait_for_file(outcome)
            assert outcome.read_text(encoding="ascii") == "timed-out"
            assert not entered.exists()
            completed_stderr = child.communicate(timeout=15)[1]
            assert child.returncode == 0, completed_stderr
    finally:
        os.close(descriptor)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)

    post_release_attempted = tmp_path / "post-release-attempted"
    post_release_entered = tmp_path / "post-release-entered"
    post_release_outcome = tmp_path / "post-release-outcome"
    post_release = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-B",
            "-c",
            child_source,
            str(canonical),
            str(post_release_attempted),
            str(post_release_entered),
            str(post_release_outcome),
            "2.0",
        ],
        cwd=_REPOSITORY_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=15,
    )
    assert post_release.returncode == 0, post_release.stderr
    assert post_release_attempted.read_text(encoding="ascii") == "ready"
    assert post_release_entered.read_text(encoding="ascii") == "entered"
    assert post_release_outcome.read_text(encoding="ascii") == "entered"

    crash_ready = tmp_path / "crash-ready"
    crash_source = """
import os
import sys
from pathlib import Path
from bluefire.runner_darwin_containment import macos_pinned_launch_path
import bluefire.runner_darwin_containment as darwin_containment
from bluefire.util import file_hash

darwin_containment._validate_macos_launch_parent = lambda _path, _descriptor: os.geteuid()

path = Path(sys.argv[1])
ready = Path(sys.argv[2])
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
expected = os.fstat(descriptor)
with macos_pinned_launch_path(path, descriptor, expected, file_hash(path)) as launch:
    ready.write_text(launch, encoding="utf-8")
    os._exit(0)
"""
    crashed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-B",
            "-c",
            crash_source,
            str(canonical),
            str(crash_ready),
        ],
        cwd=_REPOSITORY_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=15,
    )
    assert crashed.returncode == 0, crashed.stderr
    stale_launch = Path(crash_ready.read_text(encoding="utf-8"))
    assert stale_launch.is_file()
    assert canonical.stat().st_nlink == 2

    descriptor = os.open(canonical, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        expected = os.fstat(descriptor)
        with darwin_containment.macos_pinned_launch_path(
            canonical,
            descriptor,
            expected,
            digest,
        ) as recovered_launch:
            assert Path(recovered_launch).is_file()
            assert Path(recovered_launch) != stale_launch
            assert not stale_launch.exists()
    finally:
        os.close(descriptor)

    assert canonical.stat().st_nlink == 1
    assert not list(tmp_path.glob(".bluefire-verified-launch-*"))


def test_darwin_launch_link_append_interruption_transfers_cleanup_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = tmp_path / "runner"
    canonical.write_bytes(b"runner")
    canonical.chmod(0o700)
    launch = tmp_path / (".bluefire-verified-launch-" + "a" * 64)
    os.link(canonical, launch)

    class InterruptingSink(list[tuple[int, str, tuple[int, int]]]):
        def append(self, value: tuple[int, str, tuple[int, int]]) -> None:
            super().append(value)
            raise KeyboardInterrupt

    sink = InterruptingSink()
    monkeypatch.setattr(
        runner_client_module,
        "_validate_darwin_launch_parent",
        lambda _path, _descriptor: os.geteuid(),
    )

    with pytest.raises(KeyboardInterrupt):
        runner_client_module._clone_darwin_launch_link(str(launch), sink)

    assert len(sink) == 1
    parent_descriptor, clone_name, _identity = sink[0]
    os.fstat(parent_descriptor)
    assert (tmp_path / clone_name).is_file()
    resources = runner_client_module._DarwinLaunchResources(
        argv=[],
        options={},
        descriptors=[],
        links=sink,
    )
    assert resources.close_links() is True
    assert not (tmp_path / clone_name).exists()
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


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


def test_darwin_inventories_fail_closed_for_unqueryable_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_ids = {500, 501, 502}

    def session_id(process_id: int) -> int:
        if process_id == 501:
            raise PermissionError(1, "not permitted")
        return 500

    monkeypatch.setattr(darwin_containment.os, "getpid", lambda: 500)
    monkeypatch.setattr(darwin_containment.sys, "platform", "darwin")
    monkeypatch.setattr(darwin_containment, "_darwin_process_ids", lambda: process_ids)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", session_id)
    monkeypatch.setattr(
        darwin_containment,
        "_GET_PROCESS_GROUP_ID",
        lambda process_id: process_id,
    )
    assert darwin_containment._private_session_members(500) is None
    assert darwin_containment._private_process_group_members(502, 500) is None

    monkeypatch.setattr(parent_death, "_darwin_process_ids", lambda: process_ids)
    monkeypatch.setattr(parent_death, "_GET_SESSION_ID", session_id)
    monkeypatch.setattr(parent_death, "_GET_PROCESS_GROUP_ID", lambda process_id: process_id)
    assert parent_death._private_process_group_members(502, 500) is None


@pytest.mark.parametrize("failure", ("helper-eof", "deadline"))
def test_stalled_darwin_exec_transition_stops_the_exact_target(
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exec_read, exec_write = os.pipe()
    lease_read, lease_write = os.pipe()
    parent_control, monitor_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    stopped: list[tuple[int, bool]] = []
    target_process = 612
    try:
        if failure == "helper-eof":
            os.close(lease_write)
            lease_write = -1
        else:
            times = iter((0.0, parent_death._START_TIMEOUT_SECONDS + 1.0))
            monkeypatch.setattr(parent_death.time, "monotonic", lambda: next(times))
        monkeypatch.setattr(
            parent_death,
            "_terminate_direct_child",
            lambda process_id, *, force=False: (
                stopped.append((process_id, force)) is None,
                0,
            ),
        )

        assert (
            parent_death._confirm_darwin_exec_or_stop(
                target_process,
                exec_read,
                lease_read,
                monitor_control,
            )
            is False
        )
        assert stopped == [(target_process, True)]
    finally:
        for descriptor in (exec_read, exec_write, lease_read, lease_write):
            if descriptor >= 0:
                os.close(descriptor)
        parent_control.close()
        monitor_control.close()


def test_held_open_supervisor_status_pipe_times_out_boundedly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_read, status_write = os.pipe()
    polls: list[tuple[tuple[int, ...], float]] = []
    times = iter((0.0, 2.0))

    def not_ready(
        readers: list[int],
        _writers: list[int],
        _exceptional: list[int],
        timeout: float,
    ) -> tuple[list[int], list[int], list[int]]:
        polls.append((tuple(readers), timeout))
        return [], [], []

    try:
        monkeypatch.setattr(parent_death.time, "monotonic", lambda: next(times))
        monkeypatch.setattr(parent_death.select, "select", not_ready)

        with pytest.raises(OSError, match="supervisor record timed out"):
            parent_death._read_line_descriptor(
                status_read,
                maximum=32,
                deadline=1.0,
            )

        assert polls == [((status_read,), parent_death._POLL_SECONDS)]
    finally:
        os.close(status_read)
        os.close(status_write)


def test_parent_death_no_fork_probe_success_cleanup_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Function:
        def __init__(self, result: int | None = None) -> None:
            self.result = result
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *_args: object) -> int | None:
            return self.result

    class Sandbox:
        sandbox_init = Function(0)
        sandbox_free_error = Function(None)

    process_id = 613
    waits: list[tuple[int, int]] = []
    signals: list[tuple[int, int]] = []
    times = iter((0.0, 3.0, 3.0, 9.0))
    monkeypatch.setattr(parent_death.sys, "platform", "darwin")
    monkeypatch.setattr(parent_death.ctypes, "CDLL", lambda *_args, **_kwargs: Sandbox())
    monkeypatch.setattr(parent_death, "_FORK_PROCESS", lambda: process_id)
    monkeypatch.setattr(
        parent_death.os,
        "waitpid",
        lambda candidate, options: (waits.append((candidate, options)) is None and 0, 0),
    )
    monkeypatch.setattr(
        parent_death.os,
        "kill",
        lambda candidate, signum: signals.append((candidate, signum)),
    )
    monkeypatch.setattr(parent_death.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(parent_death.time, "sleep", lambda _seconds: None)

    assert parent_death._apply_darwin_no_fork_sandbox() is False
    assert signals == [(process_id, parent_death._SIGKILL)]
    assert waits == [
        (process_id, parent_death._WAIT_NO_HANG),
        (process_id, parent_death._WAIT_NO_HANG),
    ]


def test_watchdog_no_fork_probe_success_cleanup_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Function:
        def __init__(self, result: int | None = None) -> None:
            self.result = result
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *_args: object) -> int | None:
            return self.result

    class Sandbox:
        sandbox_init = Function(0)
        sandbox_free_error = Function(None)

    class Runtime:
        fork = Function(614)

    process_id = 614
    waits: list[tuple[int, int]] = []
    signals: list[tuple[int, int]] = []
    times = iter((0.0, 3.0, 3.0, 9.0))
    monkeypatch.setattr(darwin_containment.sys, "platform", "darwin")
    monkeypatch.setattr(
        darwin_containment.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: Sandbox(),
    )
    monkeypatch.setattr(
        darwin_containment.ctypes,
        "PyDLL",
        lambda *_args, **_kwargs: Runtime(),
    )
    monkeypatch.setattr(
        darwin_containment.os,
        "waitpid",
        lambda candidate, options: (waits.append((candidate, options)) is None and 0, 0),
    )
    monkeypatch.setattr(
        darwin_containment.os,
        "kill",
        lambda candidate, signum: signals.append((candidate, signum)),
    )
    monkeypatch.setattr(darwin_containment.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(darwin_containment.time, "sleep", lambda _seconds: None)

    assert darwin_containment.apply_macos_no_fork_sandbox() is False
    assert signals == [(process_id, darwin_containment._FORCE_KILL_SIGNAL)]
    assert waits == [(process_id, os.WNOHANG), (process_id, os.WNOHANG)]


@pytest.mark.parametrize("interrupt_callback", (False, True))
def test_generic_no_fork_launch_publishes_proof_before_go(
    tmp_path: Path,
    interrupt_callback: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_binary = tmp_path / "runner"
    runner_binary.write_bytes(b"verified runner")
    runner_binary.chmod(0o700)
    launch_path = tmp_path / (".bluefire-verified-launch-" + "e" * 64)
    os.link(runner_binary, launch_path)
    interpreter = tmp_path / "interpreter"
    interpreter.write_bytes(b"interpreter")
    interpreter.chmod(0o700)
    helper = tmp_path / "runner_parent_death.py"
    helper.write_bytes(b"helper")
    helper.chmod(0o700)
    events: list[str] = []
    helper_threads: list[threading.Thread] = []

    class Process:
        pid = 615
        returncode: int | None = None

    class Launch:
        def __init__(self, path: Path) -> None:
            self.path = path

        def __enter__(self) -> tuple[str, tuple[int, ...]]:
            return str(self.path), ()

        def __exit__(self, *_args: object) -> None:
            return None

    class ProofSink(list[Any]):
        def append(self, value: Any) -> None:
            events.append("sink")
            super().append(value)

    process = Process()
    proof_sink = ProofSink()

    def popen(arguments: list[str], **_options: Any) -> Any:
        child_descriptor = int(arguments[12])
        nonce = arguments[14]
        child_control = socket.fromfd(
            child_descriptor,
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        def helper_handshake() -> None:
            try:
                child_control.sendall(
                    f"armed-nofork-v1:{nonce}:{process.pid}:{os.getpid()}\n".encode("ascii")
                )
                command = child_control.recv(128)
                events.append(
                    "go" if command == f"go-nofork-v1:{nonce}\n".encode("ascii") else "eof"
                )
            finally:
                child_control.close()

        thread = threading.Thread(target=helper_handshake)
        helper_threads.append(thread)
        thread.start()
        return process

    def publish(_process: Any) -> None:
        events.append("callback")
        if interrupt_callback:
            raise KeyboardInterrupt

    monkeypatch.setattr(darwin_containment.sys, "platform", "darwin")
    monkeypatch.setattr(darwin_containment, "_GET_PROCESS_GROUP_ID", lambda pid: pid)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", lambda pid: pid)

    def call() -> Any:
        return darwin_containment.spawn_no_fork_exec(
            [str(launch_path), "inventory", "--json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            environment={},
            inherited_descriptors=(),
            options={"start_new_session": True},
            runner_binary=runner_binary,
            runner_binary_digest=file_hash(runner_binary),
            work_root=tmp_path,
            watchdog_interpreter=interpreter,
            watchdog_interpreter_digest=file_hash(interpreter),
            parent_death_script=helper,
            parent_death_script_digest=file_hash(helper),
            pinned_launch_file=lambda path, _digest, **_kwargs: Launch(path),
            start_grace_seconds=2.0,
            popen_factory=popen,
            proof_sink=proof_sink,
            proof_callback=publish,
        )

    try:
        if interrupt_callback:
            with pytest.raises(KeyboardInterrupt):
                call()
        else:
            assert call() is process
    finally:
        for thread in helper_threads:
            thread.join(timeout=2)

    assert proof_sink == [process]
    assert events == (
        ["sink", "callback", "eof"] if interrupt_callback else ["sink", "callback", "go"]
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor launch")
def test_descriptor_bootstrap_runs_helper_without_reclosing_its_source_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    echo = shutil.which("echo")
    if echo is None:
        pytest.skip("echo executable is unavailable")
    runner_binary = tmp_path / "runner"
    shutil.copy2(Path(echo).resolve(), runner_binary)
    runner_binary.chmod(0o700)
    launch_path = tmp_path / (".bluefire-verified-launch-" + "f" * 64)
    os.link(runner_binary, launch_path)
    helper = tmp_path / "bootstrap_helper.py"
    helper.write_text(
        """
import os
import sys

mode = sys.argv[1]
expected_parent = int(sys.argv[2])
control_descriptor = int(sys.argv[3])
target_descriptor = int(sys.argv[4])
nonce = sys.argv[5]
close_descriptors = tuple(int(value) for value in sys.argv[6].split(',') if value)
target_arguments = sys.argv[7:]
if mode != '--darwin-no-fork-exec-v1' or os.getppid() != expected_parent:
    raise SystemExit(74)
os.write(
    control_descriptor,
    f'armed-nofork-v1:{nonce}:{os.getpid()}:{expected_parent}\\n'.encode('ascii'),
)
command = bytearray()
while not command.endswith(b'\\n'):
    chunk = os.read(control_descriptor, 1)
    if not chunk:
        raise SystemExit(74)
    command.extend(chunk)
if bytes(command) != f'go-nofork-v1:{nonce}\\n'.encode('ascii'):
    raise SystemExit(74)
for descriptor in sorted(set(close_descriptors) | {control_descriptor, target_descriptor}):
    os.set_inheritable(descriptor, False)
os.execve(target_arguments[0], target_arguments, dict(os.environ))
""".lstrip(),
        encoding="utf-8",
    )
    interpreter = Path(sys.executable).resolve()

    class Launch:
        def __init__(self, path: Path, *, descriptor_backed: bool) -> None:
            self.path = path
            self.descriptor_backed = descriptor_backed
            self.descriptor = -1

        def __enter__(self) -> tuple[str, tuple[int, ...]]:
            if not self.descriptor_backed:
                return str(self.path), ()
            self.descriptor = os.open(self.path, os.O_RDONLY)
            return str(self.descriptor), (self.descriptor,)

        def __exit__(self, *_args: object) -> None:
            if self.descriptor >= 0:
                os.close(self.descriptor)

    def pinned_launch(
        path: Path,
        digest: str,
        *,
        darwin_descriptor_backed: bool = False,
    ) -> Launch:
        assert file_hash(path) == digest
        return Launch(path, descriptor_backed=darwin_descriptor_backed)

    def popen(arguments: list[str], **options: Any) -> subprocess.Popen[bytes]:
        options.pop("_bluefire_descriptor_argument_indexes")
        options.pop("_bluefire_descriptor_list_argument_indexes")
        script_descriptor = int(arguments[7])
        close_descriptors = {int(value) for value in arguments[15].split(",") if value}
        assert script_descriptor in options["pass_fds"]
        assert script_descriptor not in close_descriptors
        return subprocess.Popen(arguments, **options)  # nosec B603

    monkeypatch.setattr(darwin_containment.sys, "platform", "darwin")
    monkeypatch.setattr(darwin_containment, "_GET_PROCESS_GROUP_ID", os.getpgid)
    monkeypatch.setattr(darwin_containment, "_GET_SESSION_ID", os.getsid)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = darwin_containment.spawn_no_fork_exec(
            [str(launch_path), "bootstrap-ok"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            environment=dict(os.environ),
            inherited_descriptors=(),
            options={"start_new_session": True},
            runner_binary=runner_binary,
            runner_binary_digest=file_hash(runner_binary),
            work_root=tmp_path,
            watchdog_interpreter=interpreter,
            watchdog_interpreter_digest=file_hash(interpreter),
            parent_death_script=helper,
            parent_death_script_digest=file_hash(helper),
            pinned_launch_file=pinned_launch,
            start_grace_seconds=5.0,
            popen_factory=popen,
            proof_sink=[],
            proof_callback=lambda _process: None,
        )
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0
        assert stdout == b"bootstrap-ok\n"
        assert stderr == b""
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_monitor_reap_deadline_retains_the_pinned_identity_for_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_id = 620
    monitor_id = 621
    records = iter((b"target-v1:622\n", b"exit-v1:0\n"))
    waits: list[tuple[int, int]] = []
    cleanups: list[tuple[int, int, bool]] = []
    times = iter((0.0, 0.0, 100.0, 100.0, 106.0))

    monkeypatch.setattr(
        parent_death,
        "_parse_arguments",
        lambda _arguments: (parent_id, 71, 72, "f" * 64, (), ["5", "/runner"]),
    )
    monkeypatch.setattr(parent_death, "_FORK_PROCESS", lambda: monitor_id)
    monkeypatch.setattr(parent_death, "_SET_PROCESS_GROUP", lambda *_args: None)
    monkeypatch.setattr(parent_death, "_GET_PROCESS_GROUP", lambda: parent_id)
    monkeypatch.setattr(
        parent_death,
        "_GET_PROCESS_GROUP_ID",
        lambda process_id: process_id,
    )
    monkeypatch.setattr(parent_death, "_GET_SESSION_ID", lambda _process_id: parent_id)
    monkeypatch.setattr(parent_death, "_KILL_PROCESS_GROUP", lambda *_args: None)
    monkeypatch.setattr(parent_death, "_private_darwin_target", lambda *_args: True)
    monkeypatch.setattr(parent_death, "_apply_darwin_no_fork_sandbox", lambda: True)
    monkeypatch.setattr(
        parent_death,
        "_private_process_group_members",
        lambda *_args: {monitor_id},
    )
    monkeypatch.setattr(
        parent_death,
        "_read_line_descriptor",
        lambda *_args, **_kwargs: next(records),
    )
    monkeypatch.setattr(parent_death.os, "getppid", lambda: parent_id)
    monkeypatch.setattr(parent_death.os, "getpid", lambda: 619)
    monkeypatch.setattr(parent_death.os, "pipe", lambda: (73, 74))
    monkeypatch.setattr(parent_death.os, "write", lambda *_args: 1)
    monkeypatch.setattr(
        parent_death.os,
        "waitpid",
        lambda process_id, options: (waits.append((process_id, options)) is None and 0, 0),
    )
    monkeypatch.setattr(parent_death.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(parent_death.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(parent_death, "_close_descriptor", lambda _descriptor: None)

    def cleanup(
        process_id: int,
        session_id: int,
        *,
        identity_pinned: bool = False,
    ) -> bool:
        cleanups.append((process_id, session_id, identity_pinned))
        return True

    monkeypatch.setattr(parent_death, "_terminate_pinned_monitor_group", cleanup)

    assert parent_death._run_darwin(["ignored"]) == 74
    assert waits == [(monitor_id, parent_death._WAIT_NO_HANG)]
    assert cleanups == [(monitor_id, parent_id, True)]


def test_reaped_failed_monitor_identity_is_never_used_for_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_id = 620
    monitor_id = 621
    records = iter((b"target-v1:622\n", b"exit-v1:0\n"))
    monkeypatch.setattr(
        parent_death,
        "_parse_arguments",
        lambda _arguments: (parent_id, 71, 72, "f" * 64, (), ["5", "/runner"]),
    )
    monkeypatch.setattr(parent_death, "_FORK_PROCESS", lambda: monitor_id)
    monkeypatch.setattr(parent_death, "_SET_PROCESS_GROUP", lambda *_args: None)
    monkeypatch.setattr(parent_death, "_GET_PROCESS_GROUP", lambda: parent_id)
    monkeypatch.setattr(
        parent_death,
        "_GET_PROCESS_GROUP_ID",
        lambda process_id: process_id,
    )
    monkeypatch.setattr(parent_death, "_GET_SESSION_ID", lambda _process_id: parent_id)
    monkeypatch.setattr(parent_death, "_KILL_PROCESS_GROUP", lambda *_args: None)
    monkeypatch.setattr(parent_death, "_private_darwin_target", lambda *_args: True)
    monkeypatch.setattr(parent_death, "_apply_darwin_no_fork_sandbox", lambda: True)
    monkeypatch.setattr(parent_death, "_private_process_group_members", lambda *_args: {monitor_id})
    monkeypatch.setattr(
        parent_death, "_read_line_descriptor", lambda *_args, **_kwargs: next(records)
    )
    monkeypatch.setattr(parent_death.os, "getppid", lambda: parent_id)
    monkeypatch.setattr(parent_death.os, "getpid", lambda: 619)
    monkeypatch.setattr(parent_death.os, "pipe", lambda: (73, 74))
    monkeypatch.setattr(parent_death.os, "write", lambda *_args: 1)
    monkeypatch.setattr(parent_death.os, "waitpid", lambda *_args: (monitor_id, 256))
    monkeypatch.setattr(parent_death, "_close_descriptor", lambda _descriptor: None)
    monkeypatch.setattr(
        parent_death,
        "_terminate_pinned_monitor_group",
        lambda *_args, **_kwargs: pytest.fail("a reaped monitor identity was reused"),
    )

    assert parent_death._run_darwin(["ignored"]) == 74


def test_pinned_zombie_monitor_group_drains_members_before_reaping_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventories = iter(({602}, set()))
    events: list[tuple[str, int]] = []

    def members(process_group: int, session_id: int) -> set[int]:
        assert (process_group, session_id) == (601, 600)
        return next(inventories)

    def signal_group(process_group: int, signum: int) -> None:
        assert signum == signal.SIGKILL
        events.append(("group", process_group))

    def reap_leader(process_id: int, *, force: bool = False) -> tuple[bool, int]:
        assert force is True
        events.append(("leader", process_id))
        return True, 0

    monkeypatch.setattr(parent_death, "_private_process_group_members", members)
    monkeypatch.setattr(parent_death, "_KILL_PROCESS_GROUP", signal_group)
    monkeypatch.setattr(parent_death, "_terminate_direct_child", reap_leader)
    monkeypatch.setattr(
        parent_death,
        "_GET_PROCESS_GROUP_ID",
        lambda _process: pytest.fail("a pinned Darwin zombie has no queryable PGID"),
    )
    monkeypatch.setattr(
        parent_death,
        "_GET_SESSION_ID",
        lambda _process: pytest.fail("a pinned Darwin zombie has no queryable SID"),
    )

    assert parent_death._terminate_pinned_monitor_group(
        601,
        600,
        identity_pinned=True,
    )
    assert events == [("group", 601), ("leader", 601)]


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
            pytest.fail("Darwin private release reaped through poll before proof")

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
    monkeypatch.setattr(
        runner_client_module,
        "_darwin_child_exited_without_reap",
        lambda _pid: True,
    )

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
