"""Darwin launch pinning and no-orphan runner containment."""

from __future__ import annotations

import ctypes
import errno
import os
import re
import secrets
import signal
import socket
import stat
import subprocess  # nosec B404
import sys
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Mapping

from .runner_private_files import _PinnedPrivateDirectory, _read_descriptor_bounded
from .runner_transport_errors import RunnerTransportError

_RUNNER_BINARY_LIMIT_BYTES = 256 * 1024 * 1024
_RUNTIME_DIRECTORY_NAME = ".bluefire-watchdog-runtime-v1"
_RUNTIME_NAME = re.compile(r"^python-sha256-([0-9a-f]{64})$")
_MAX_RETAINED_RUNTIMES = 4
_MAX_DARWIN_PROCESSES = 131_072
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
_GET_PROCESS_GROUP_ID = getattr(os, "getpgid", None)
_GET_SESSION_ID = getattr(os, "getsid", None)

PinnedLaunchFile = Callable[
    [Path, str],
    AbstractContextManager[tuple[str, tuple[int, ...]]],
]


@dataclass(frozen=True)
class DarwinProcessContainment:
    """Live parent lease and immutable identities for one Darwin runner."""

    session_id: int
    monitor_group: int
    target_process: int
    parent_lease: socket.socket


def _validate_macos_launch_parent(path: Path, descriptor: int) -> int:
    """Require a pathname that untrusted local users cannot redirect."""

    get_effective_user_id = getattr(os, "geteuid", None)
    if not path.is_absolute() or not callable(get_effective_user_id):
        raise OSError("launch input parent ownership is unavailable")
    effective_user_id = int(get_effective_user_id())
    opened = os.fstat(descriptor)
    child = opened
    current_path = path
    direct_parent = True
    while True:
        current = current_path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode):
            raise OSError("launch input ancestor is not a directory")
        mode = stat.S_IMODE(current.st_mode)
        if direct_parent:
            required = stat.S_IWUSR | stat.S_IXUSR
            if (
                not os.path.samestat(opened, current)
                or current.st_uid != effective_user_id
                or mode & (stat.S_IWGRP | stat.S_IWOTH)
                or mode & required != required
            ):
                raise OSError("launch input parent is not owner-controlled")
            direct_parent = False
        elif mode & (stat.S_IWGRP | stat.S_IWOTH):
            if not mode & stat.S_ISVTX or child.st_uid != effective_user_id:
                raise OSError("launch input ancestor permits replacement")
        parent = current_path.parent
        if parent == current_path:
            break
        child = current
        current_path = parent
    return effective_user_id


@contextmanager
def macos_pinned_launch_path(
    path: Path,
    descriptor: int,
    expected: os.stat_result,
    expected_digest: str,
) -> Iterator[str]:
    """Give Darwin execve a stable pathname for one verified open vnode."""

    parent_descriptor = -1
    linked_descriptor = -1
    linked_identity: tuple[int, int] | None = None
    link_name = f".bluefire-verified-launch-{secrets.token_hex(32)}"
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        parent_descriptor = os.open(path.parent, directory_flags)
        effective_user_id = _validate_macos_launch_parent(path.parent, parent_descriptor)
        os.link(
            path.name,
            link_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        linked_identity = (expected.st_dev, expected.st_ino)
        linked = os.stat(link_name, dir_fd=parent_descriptor, follow_symlinks=False)
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(linked.st_mode)
            or not os.path.samestat(linked, current)
            or not os.path.samestat(current, expected)
            or current.st_uid != effective_user_id
            or stat.S_IMODE(current.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or linked.st_nlink != 2
            or current.st_nlink != 2
            or linked.st_size != expected.st_size
            or linked.st_mtime_ns != expected.st_mtime_ns
        ):
            raise OSError("verified launch hard link identity changed")
        linked_descriptor = os.open(
            link_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(linked_descriptor)
        linked_payload = _read_descriptor_bounded(
            linked_descriptor,
            _RUNNER_BINARY_LIMIT_BYTES,
        )
        current_payload = _read_descriptor_bounded(
            descriptor,
            _RUNNER_BINARY_LIMIT_BYTES,
        )
        if (
            (opened.st_dev, opened.st_ino) != linked_identity
            or opened.st_nlink != 2
            or linked_payload != current_payload
            or "sha256:" + sha256(linked_payload).hexdigest() != expected_digest
        ):
            raise OSError("verified launch hard link content changed")
        _validate_macos_launch_parent(path.parent, parent_descriptor)
        launch_path = path.parent / link_name
        visible = launch_path.stat(follow_symlinks=False)
        current = os.fstat(descriptor)
        if (
            not os.path.samestat(visible, opened)
            or not os.path.samestat(current, opened)
            or current.st_nlink != 2
            or current.st_uid != effective_user_id
            or stat.S_IMODE(current.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or current.st_size != expected.st_size
            or current.st_mtime_ns != expected.st_mtime_ns
        ):
            raise OSError("verified launch pathname changed")
        yield str(launch_path)
    finally:
        if linked_descriptor >= 0:
            try:
                os.close(linked_descriptor)
            except OSError:
                pass
        if parent_descriptor >= 0 and linked_identity is not None:
            try:
                current_link = os.stat(
                    link_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current_link.st_dev, current_link.st_ino) == linked_identity:
                    os.unlink(link_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def _read_runtime_source(path: Path) -> tuple[bytes, str]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        visible = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not os.path.samestat(before, visible)
            or before.st_size <= 0
            or before.st_size > _RUNNER_BINARY_LIMIT_BYTES
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            raise OSError("Darwin runtime source is unsafe")
        payload = _read_descriptor_bounded(descriptor, _RUNNER_BINARY_LIMIT_BYTES)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not os.path.samestat(before, after)
            or not os.path.samestat(after, current)
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise OSError("Darwin runtime source changed while copied")
        return payload, "sha256:" + sha256(payload).hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def stage_watchdog_interpreter(runtime: Path, work_root: Path) -> tuple[Path, str]:
    """Copy Darwin's framework interpreter into one bounded private runtime cache."""

    if sys.platform != "darwin":
        raise RunnerTransportError("Darwin runtime staging is unavailable")
    try:
        payload, digest = _read_runtime_source(runtime)
        runtime_name = f"python-sha256-{digest.removeprefix('sha256:')}"
        runtime_root = work_root / _RUNTIME_DIRECTORY_NAME
        with _PinnedPrivateDirectory(work_root) as pinned_work:
            try:
                pinned_work.create_directory(_RUNTIME_DIRECTORY_NAME)
            except FileExistsError:
                pass
            with _PinnedPrivateDirectory(runtime_root, parent=pinned_work) as pinned_runtime:
                names = pinned_runtime.names(maximum=_MAX_RETAINED_RUNTIMES + 1)
                if any(_RUNTIME_NAME.fullmatch(name) is None for name in names):
                    raise OSError("Darwin runtime cache contains an unexpected entry")
                if runtime_name not in names:
                    if len(names) >= _MAX_RETAINED_RUNTIMES:
                        raise OSError("Darwin runtime cache retention bound was reached")
                    pinned_runtime.create(
                        runtime_name,
                        payload,
                        maximum=_RUNNER_BINARY_LIMIT_BYTES,
                        executable=True,
                    )
                staged_payload = pinned_runtime.read(
                    runtime_name,
                    maximum=_RUNNER_BINARY_LIMIT_BYTES,
                    apply_permissions=False,
                )
                details = pinned_runtime.entry_metadata(runtime_name)
                get_effective_user_id = getattr(os, "geteuid", None)
                if (
                    not callable(get_effective_user_id)
                    or details.st_uid != int(get_effective_user_id())
                    or details.st_nlink != 1
                    or stat.S_IMODE(details.st_mode) != 0o700
                    or staged_payload != payload
                    or "sha256:" + sha256(staged_payload).hexdigest() != digest
                ):
                    raise OSError("Darwin staged runtime identity is invalid")
        staged = runtime_root / runtime_name
        return staged.resolve(strict=True), digest
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("Darwin watchdog runtime could not be staged") from None


def _recv_control_line(control: socket.socket, *, maximum: int) -> bytes:
    payload = bytearray()
    while len(payload) <= maximum:
        chunk = control.recv(1)
        if not chunk:
            break
        payload.extend(chunk)
        if chunk == b"\n":
            break
    if not payload or len(payload) > maximum or not payload.endswith(b"\n"):
        raise OSError("invalid supervisor control")
    return bytes(payload)


def validate_containment_identity(
    armed: bytes,
    *,
    nonce: str,
    helper_process: int,
) -> tuple[int, int]:
    match = re.fullmatch(
        rb"armed-v2:([0-9a-f]{64}):([1-9][0-9]{0,9}):"
        rb"([1-9][0-9]{0,9}):([1-9][0-9]{0,9}):"
        rb"([1-9][0-9]{0,9})\n",
        armed,
    )
    if match is None or match.group(1).decode("ascii") != nonce:
        raise OSError("Darwin containment handshake is invalid")
    helper_identity, monitor_identity, target_identity, session_identity = (
        int(match.group(index)) for index in range(2, 6)
    )
    if (
        helper_identity != helper_process
        or session_identity != os.getpid()
        or not callable(_GET_PROCESS_GROUP_ID)
        or not callable(_GET_SESSION_ID)
        or _GET_PROCESS_GROUP_ID(helper_process) != os.getpid()
        or _GET_SESSION_ID(helper_process) != os.getpid()
        or _GET_PROCESS_GROUP_ID(monitor_identity) != monitor_identity
        or _GET_SESSION_ID(monitor_identity) != os.getpid()
        or _GET_PROCESS_GROUP_ID(target_identity) != monitor_identity
        or _GET_SESSION_ID(target_identity) != os.getpid()
    ):
        raise OSError("Darwin containment identity is invalid")
    return monitor_identity, target_identity


def _darwin_process_ids() -> set[int] | None:
    if sys.platform != "darwin":
        return None
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_all = library.proc_listallpids
        list_all.argtypes = [ctypes.c_void_p, ctypes.c_int]
        list_all.restype = ctypes.c_int
        required = int(list_all(None, 0))
        if required <= 0 or required > _MAX_DARWIN_PROCESSES:
            return None
        capacity = min(_MAX_DARWIN_PROCESSES, max(1024, required * 2))
        for _attempt in range(3):
            values = (ctypes.c_int * capacity)()
            count = int(list_all(values, ctypes.sizeof(values)))
            if count <= 0 or count > capacity:
                return None
            if count < capacity:
                return {int(value) for value in values[:count] if int(value) > 0}
            if capacity >= _MAX_DARWIN_PROCESSES:
                return None
            capacity = min(_MAX_DARWIN_PROCESSES, capacity * 2)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return None


def _private_session_members(session_id: int) -> set[int] | None:
    if not callable(_GET_SESSION_ID) or session_id != os.getpid():
        return None
    process_ids = _darwin_process_ids()
    if process_ids is None:
        return None
    members: set[int] = set()
    for process_id in process_ids:
        try:
            if _GET_SESSION_ID(process_id) == session_id:
                members.add(process_id)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                continue
            return None
    if os.getpid() not in members:
        return None
    return members


def _drain_private_session(
    process: subprocess.Popen[bytes],
    *,
    session_id: int,
    parent_lease: socket.socket,
    terminate: bool,
) -> bool:
    try:
        if (
            not callable(_GET_SESSION_ID)
            or session_id != os.getpid()
            or _GET_SESSION_ID(0) != session_id
        ):
            return False
    except OSError:
        return False
    if terminate:
        parent_lease.close()
    started = time.monotonic()
    graceful_deadline = started + _PROCESS_TERM_GRACE_SECONDS
    force_deadline = graceful_deadline + _PROCESS_TERM_GRACE_SECONDS
    final_deadline = graceful_deadline + _PROCESS_KILL_GRACE_SECONDS
    termination_sent = False
    force_sent = False
    while True:
        process.poll()
        members = _private_session_members(session_id)
        if members is None:
            return False
        targets = members - {os.getpid()}
        if not targets and process.returncode is not None:
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                return False
            return process.returncode is not None
        now = time.monotonic()
        if now >= final_deadline:
            return False
        # The helper is this process's direct child.  Its PID cannot be reused
        # until Popen reaps it, so signalling that one child after a fresh
        # poll is safe.  Session members are inventory only: macOS has no
        # pidfd-equivalent, and a getsid(pid)-then-kill(pid) sequence would be
        # an unsafe identity TOCTOU.
        signum: int | None = None
        if terminate and process.returncode is None:
            if now >= force_deadline and not force_sent:
                signum = _FORCE_KILL_SIGNAL
            elif now >= graceful_deadline and not termination_sent:
                signum = signal.SIGTERM
        if signum is not None:
            try:
                process.send_signal(signum)
            except ProcessLookupError:
                process.poll()
            except OSError:
                return False
            if signum == _FORCE_KILL_SIGNAL:
                force_sent = True
            else:
                termination_sent = True
        time.sleep(_PROCESS_POLL_SECONDS)


def release_process(
    process: subprocess.Popen[bytes],
    containment: DarwinProcessContainment,
    *,
    terminate: bool,
) -> bool:
    """Release only after every non-watchdog member of the private session is gone."""

    released = _drain_private_session(
        process,
        session_id=containment.session_id,
        parent_lease=containment.parent_lease,
        terminate=terminate,
    )
    if released:
        containment.parent_lease.close()
    return released


def _retain_failed_session(
    process: subprocess.Popen[bytes],
    *,
    session_id: int,
    parent_lease: socket.socket,
) -> None:
    parent_lease.close()
    while not _drain_private_session(
        process,
        session_id=session_id,
        parent_lease=parent_lease,
        terminate=True,
    ):
        time.sleep(_PROCESS_POLL_SECONDS)


def spawn_parent_death(
    argv: list[str],
    *,
    stdout: int | BinaryIO | None,
    stderr: int | BinaryIO | None,
    environment: Mapping[str, str],
    inherited_descriptors: tuple[int, ...],
    options: Mapping[str, Any],
    runner_binary: Path,
    runner_binary_digest: str,
    work_root: Path,
    watchdog_interpreter: Path,
    watchdog_interpreter_digest: str,
    parent_death_script: Path,
    parent_death_script_digest: str,
    pinned_launch_file: PinnedLaunchFile,
    start_grace_seconds: float,
) -> tuple[subprocess.Popen[bytes], DarwinProcessContainment]:
    """Start the verified Darwin helper and retain its watchdog lease."""

    if sys.platform != "darwin" or not argv:
        raise RunnerTransportError("Darwin parent-death containment is unavailable")
    target_path = Path(argv[0])
    target_descriptor = -1
    parent_socket: socket.socket | None = None
    child_socket: socket.socket | None = None
    try:
        if (
            not target_path.is_absolute()
            or target_path.parent != runner_binary.parent
            or not target_path.name.startswith(".bluefire-verified-launch-")
        ):
            raise OSError("Darwin target is not a verified launch path")
        target_descriptor = os.open(
            target_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(target_descriptor)
        visible = target_path.stat(follow_symlinks=False)
        expected = runner_binary.stat(follow_symlinks=False)
        get_effective_user_id = getattr(os, "geteuid", None)
        if (
            not callable(get_effective_user_id)
            or not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(opened, visible)
            or not os.path.samestat(opened, expected)
            or opened.st_nlink != 2
            or opened.st_uid != int(get_effective_user_id())
            or stat.S_IMODE(opened.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or _descriptor_digest(target_descriptor) != runner_binary_digest
        ):
            raise OSError("Darwin target identity changed")
        if (
            _path_digest(watchdog_interpreter) != watchdog_interpreter_digest
            or _path_digest(parent_death_script) != parent_death_script_digest
        ):
            raise OSError("Darwin containment helper identity changed")
        parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent_socket.settimeout(start_grace_seconds)
    except OSError:
        if target_descriptor >= 0:
            os.close(target_descriptor)
        raise RunnerTransportError("Darwin parent-death containment is unavailable") from None
    if parent_socket is None or child_socket is None:
        raise AssertionError("Darwin containment sockets were not initialized")

    process: subprocess.Popen[bytes] | None = None
    nonce = secrets.token_hex(32)
    try:
        with pinned_launch_file(
            watchdog_interpreter,
            watchdog_interpreter_digest,
        ) as interpreter_launch:
            with pinned_launch_file(
                parent_death_script,
                parent_death_script_digest,
            ) as helper_launch:
                helper_descriptors = interpreter_launch[1] + helper_launch[1]
                pass_fds = tuple(
                    sorted(
                        set(inherited_descriptors + helper_descriptors)
                        | {child_socket.fileno(), target_descriptor}
                    )
                )
                launch_options = dict(options)
                launch_options["pass_fds"] = pass_fds
                process = subprocess.Popen(  # nosec B603
                    [
                        interpreter_launch[0],
                        "-I",
                        "-B",
                        "-X",
                        "utf8",
                        helper_launch[0],
                        str(os.getpid()),
                        str(child_socket.fileno()),
                        str(target_descriptor),
                        nonce,
                        ",".join(str(value) for value in helper_descriptors),
                        *argv,
                    ],
                    cwd=work_root,
                    env=dict(environment),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    **launch_options,
                )
                child_socket.close()
                armed = _recv_control_line(parent_socket, maximum=192)
                monitor_process, target_process = validate_containment_identity(
                    armed,
                    nonce=nonce,
                    helper_process=process.pid,
                )
                parent_socket.sendall(f"go-v2:{nonce}\n".encode("ascii"))
                if _recv_control_line(parent_socket, maximum=96) != (
                    f"executed-v2:{nonce}\n".encode("ascii")
                ):
                    raise OSError("Darwin target execution failed")
        containment = DarwinProcessContainment(
            session_id=os.getpid(),
            monitor_group=monitor_process,
            target_process=target_process,
            parent_lease=parent_socket,
        )
        parent_socket = None
        return process, containment
    except (OSError, RunnerTransportError, socket.timeout):
        if process is not None:
            _retain_failed_session(
                process,
                session_id=os.getpid(),
                parent_lease=parent_socket,
            )
        raise RunnerTransportError("Darwin parent-death containment failed") from None
    finally:
        os.close(target_descriptor)
        if parent_socket is not None:
            parent_socket.close()
        child_socket.close()


def _descriptor_digest(descriptor: int) -> str:
    payload = _read_descriptor_bounded(descriptor, _RUNNER_BINARY_LIMIT_BYTES)
    return "sha256:" + sha256(payload).hexdigest()


def _path_digest(path: Path) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        return _descriptor_digest(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
