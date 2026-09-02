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
import threading
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Mapping

from .runner_private_files import _PinnedPrivateDirectory, _read_descriptor_bounded
from .runner_transport_errors import RunnerTransportError

_FILE_LOCK_MODULE: Any
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - unavailable on Windows
    _FILE_LOCK_MODULE = None
else:
    _FILE_LOCK_MODULE = _fcntl

_RUNNER_BINARY_LIMIT_BYTES = 256 * 1024 * 1024
_RUNTIME_DIRECTORY_NAME = ".bluefire-watchdog-runtime-v1"
_RUNTIME_NAME = re.compile(r"^python-sha256-([0-9a-f]{64})$")
_MAX_RETAINED_RUNTIMES = 4
_MAX_DARWIN_PROCESSES = 131_072
_DARWIN_NO_FORK_EXEC_MODE = "--darwin-no-fork-exec-v1"
_DARWIN_NO_FORK_PROFILE = b"(version 1)\n(allow default)\n(deny process-fork)\n"
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
_GET_PROCESS_GROUP_ID = getattr(os, "getpgid", None)
_GET_SESSION_ID = getattr(os, "getsid", None)
_MACOS_PIN_LOCK_TIMEOUT_SECONDS = 10.0
_MACOS_PIN_CLEANUP_RETRIES = 8
_MAX_DARWIN_LAUNCH_DIRECTORY_ENTRIES = 4096
_MAX_EXECUTION_TIMEOUT_SECONDS = 86_400.0
_MACOS_PIN_REGISTRY_LOCK = threading.RLock()
_MACOS_PIN_REGISTRY_CONDITION = threading.Condition(_MACOS_PIN_REGISTRY_LOCK)


@dataclass
class _MacOSPinnedLaunch:
    launch_path: str
    parent_descriptor: int
    link_name: str
    identity: tuple[int, int]
    owner_thread: int
    holders: set[object]


@dataclass(frozen=True)
class _MacOSPinReservation:
    owner_thread: int
    token: object
    created_at: float


_MACOS_PIN_REGISTRY: dict[tuple[int, int], _MacOSPinnedLaunch] = {}
_MACOS_PIN_PENDING: dict[tuple[int, int], _MacOSPinReservation] = {}


def apply_macos_no_fork_sandbox() -> bool:
    """Apply Seatbelt and prove its fork denial without Python atfork hooks."""

    if sys.platform != "darwin":
        return True
    error_buffer = ctypes.c_char_p()
    try:
        sandbox = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
        sandbox_init = sandbox.sandbox_init
        sandbox_init.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_char_p),
        ]
        sandbox_init.restype = ctypes.c_int
        sandbox_free_error = sandbox.sandbox_free_error
        sandbox_free_error.argtypes = [ctypes.c_void_p]
        sandbox_free_error.restype = None
        if sandbox_init(_DARWIN_NO_FORK_PROFILE, 0, ctypes.byref(error_buffer)) != 0:
            if error_buffer.value is not None:
                sandbox_free_error(error_buffer)
            return False
        if error_buffer.value is not None:
            sandbox_free_error(error_buffer)
        runtime = ctypes.PyDLL(None, use_errno=True)
        raw_fork = runtime.fork
        raw_fork.argtypes = []
        raw_fork.restype = ctypes.c_int
        ctypes.set_errno(0)
        probe = int(raw_fork())
        if probe == -1:
            return ctypes.get_errno() in {errno.EACCES, errno.EPERM}
        if probe == 0:
            os._exit(74)
        reaped = False
        deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        while True:
            try:
                waited, _status = os.waitpid(probe, getattr(os, "WNOHANG", 0))
            except ChildProcessError:
                reaped = True
                break
            except OSError:
                break
            if waited == probe:
                reaped = True
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(_PROCESS_POLL_SECONDS)
        if not reaped:
            try:
                os.kill(probe, _FORCE_KILL_SIGNAL)
            except OSError:
                pass
            kill_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
            while True:
                try:
                    waited, _status = os.waitpid(probe, getattr(os, "WNOHANG", 0))
                except (ChildProcessError, OSError):
                    break
                if waited == probe:
                    break
                if time.monotonic() >= kill_deadline:
                    break
                time.sleep(_PROCESS_POLL_SECONDS)
        return False
    except (AttributeError, OSError, TypeError, ValueError):
        return False


PinnedLaunchFile = Callable[..., AbstractContextManager[tuple[str, tuple[int, ...]]]]


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


def _acquire_macos_pin_lock(descriptor: int) -> None:
    file_lock = _FILE_LOCK_MODULE
    if file_lock is None:
        raise OSError("Darwin launch locking is unavailable")

    deadline = time.monotonic() + _MACOS_PIN_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            file_lock.flock(descriptor, file_lock.LOCK_EX | file_lock.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise OSError("Darwin launch lock timed out") from None
            time.sleep(_PROCESS_POLL_SECONDS)


def _release_macos_pin_lock(descriptor: int) -> None:
    file_lock = _FILE_LOCK_MODULE
    if file_lock is None:
        return

    try:
        file_lock.flock(descriptor, file_lock.LOCK_UN)
    except BaseException:
        # Closing the caller-owned descriptor immediately after this context
        # is the kernel-backed fallback release.
        pass


def _reserve_macos_pin_identity(
    identity: tuple[int, int],
    holder: object,
    *,
    allow_same_thread_reuse: bool,
) -> _MacOSPinnedLaunch | None:
    owner_thread = threading.get_ident()
    deadline = time.monotonic() + _MACOS_PIN_LOCK_TIMEOUT_SECONDS
    reserved = False
    selected: _MacOSPinnedLaunch | None = None
    try:
        with _MACOS_PIN_REGISTRY_CONDITION:
            while True:
                candidate = _MACOS_PIN_REGISTRY.get(identity)
                if (
                    allow_same_thread_reuse
                    and candidate is not None
                    and candidate.owner_thread == owner_thread
                ):
                    selected = candidate
                    candidate.holders.add(holder)
                    return candidate
                pending = _MACOS_PIN_PENDING.get(identity)
                if candidate is None and pending is None:
                    reserved = True
                    _MACOS_PIN_PENDING[identity] = _MacOSPinReservation(
                        owner_thread=owner_thread,
                        token=holder,
                        created_at=time.monotonic(),
                    )
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # The inode flock is the authoritative cross-thread and
                    # cross-process serializer.  A reservation whose owner was
                    # interrupted before its finalizer must not poison this
                    # process forever; retire it and proceed to the flock.
                    if candidate is None and pending is not None:
                        if _MACOS_PIN_PENDING.get(identity) is pending:
                            _MACOS_PIN_PENDING.pop(identity, None)
                            _MACOS_PIN_REGISTRY_CONDITION.notify_all()
                        deadline = time.monotonic() + _MACOS_PIN_LOCK_TIMEOUT_SECONDS
                        continue
                    raise OSError("Darwin in-process launch lock timed out")
                _MACOS_PIN_REGISTRY_CONDITION.wait(timeout=min(_PROCESS_POLL_SECONDS, remaining))
    except BaseException:
        with _MACOS_PIN_REGISTRY_CONDITION:
            if selected is not None:
                selected.holders.discard(holder)
            pending = _MACOS_PIN_PENDING.get(identity)
            if reserved and pending is not None and pending.token is holder:
                _MACOS_PIN_PENDING.pop(identity, None)
                _MACOS_PIN_REGISTRY_CONDITION.notify_all()
        raise


def _release_macos_pin_reservation(identity: tuple[int, int], token: object) -> None:
    with _MACOS_PIN_REGISTRY_CONDITION:
        pending = _MACOS_PIN_PENDING.get(identity)
        if pending is not None and pending.token is token:
            _MACOS_PIN_PENDING.pop(identity, None)
            _MACOS_PIN_REGISTRY_CONDITION.notify_all()


def _remove_macos_pin_link(
    parent_descriptor: int,
    name: str,
    identity: tuple[int, int],
) -> bool:
    for attempt in range(_MACOS_PIN_CLEANUP_RETRIES):
        try:
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                return True
            os.unlink(name, dir_fd=parent_descriptor)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            if attempt + 1 < _MACOS_PIN_CLEANUP_RETRIES:
                time.sleep(_PROCESS_POLL_SECONDS)
    return False


def _remove_stale_macos_pin_links(
    parent_descriptor: int,
    identity: tuple[int, int],
) -> None:
    entries_seen = 0
    with os.scandir(parent_descriptor) as entries:
        names = []
        for entry in entries:
            entries_seen += 1
            if entries_seen > _MAX_DARWIN_LAUNCH_DIRECTORY_ENTRIES:
                raise OSError("Darwin launch directory exceeds its entry bound")
            names.append(entry.name)
    for name in names:
        if re.fullmatch(r"\.bluefire-verified-launch-[0-9a-f]{64}", name) is None:
            continue
        try:
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (current.st_dev, current.st_ino) == identity and not _remove_macos_pin_link(
            parent_descriptor,
            name,
            identity,
        ):
            raise OSError("stale Darwin launch pin could not be removed")


@contextmanager
def macos_pinned_launch_path(
    path: Path,
    descriptor: int,
    expected: os.stat_result,
    expected_digest: str,
) -> Iterator[str]:
    """Give Darwin execve a cross-process serialized, recoverable vnode path."""

    identity = (expected.st_dev, expected.st_ino)
    holder = object()
    existing: _MacOSPinnedLaunch | None = None
    parent_descriptor = -1
    linked_descriptor = -1
    link_name = f".bluefire-verified-launch-{secrets.token_hex(32)}"
    lock_acquired = False
    lease: _MacOSPinnedLaunch | None = None
    try:
        existing = _reserve_macos_pin_identity(
            identity,
            holder,
            allow_same_thread_reuse=True,
        )
        if existing is not None:
            current = os.fstat(descriptor)
            visible = os.stat(
                existing.link_name,
                dir_fd=existing.parent_descriptor,
                follow_symlinks=False,
            )
            if not os.path.samestat(current, expected) or not os.path.samestat(current, visible):
                raise OSError("nested Darwin launch pin changed identity")
            yield existing.launch_path
            return

        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        parent_descriptor = os.open(path.parent, directory_flags)
        effective_user_id = _validate_macos_launch_parent(path.parent, parent_descriptor)
        _acquire_macos_pin_lock(descriptor)
        lock_acquired = True
        _remove_stale_macos_pin_links(parent_descriptor, identity)
        current = os.fstat(descriptor)
        canonical = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not os.path.samestat(current, expected)
            or not os.path.samestat(current, canonical)
            or current.st_nlink != 1
        ):
            raise OSError("verified launch canonical identity changed")
        os.link(
            path.name,
            link_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        linked = os.stat(link_name, dir_fd=parent_descriptor, follow_symlinks=False)
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(linked.st_mode)
            or not os.path.samestat(linked, current)
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
        linked_payload = _read_descriptor_bounded(linked_descriptor, _RUNNER_BINARY_LIMIT_BYTES)
        current_payload = _read_descriptor_bounded(descriptor, _RUNNER_BINARY_LIMIT_BYTES)
        if (
            (opened.st_dev, opened.st_ino) != identity
            or opened.st_nlink != 2
            or linked_payload != current_payload
            or "sha256:" + sha256(linked_payload).hexdigest() != expected_digest
        ):
            raise OSError("verified launch hard link content changed")
        _validate_macos_launch_parent(path.parent, parent_descriptor)
        launch_path = str(path.parent / link_name)
        lease = _MacOSPinnedLaunch(
            launch_path=launch_path,
            parent_descriptor=parent_descriptor,
            link_name=link_name,
            identity=identity,
            owner_thread=threading.get_ident(),
            holders={holder},
        )
        with _MACOS_PIN_REGISTRY_CONDITION:
            if identity in _MACOS_PIN_REGISTRY:
                raise OSError("Darwin launch pin registry changed unexpectedly")
            _MACOS_PIN_REGISTRY[identity] = lease
            pending = _MACOS_PIN_PENDING.get(identity)
            if pending is not None and pending.token is holder:
                _MACOS_PIN_PENDING.pop(identity, None)
            _MACOS_PIN_REGISTRY_CONDITION.notify_all()
        yield launch_path
    finally:
        try:
            try:
                with _MACOS_PIN_REGISTRY_CONDITION:
                    registered = _MACOS_PIN_REGISTRY.get(identity)
                    if registered is not None:
                        registered.holders.discard(holder)
                    if lease is not None and _MACOS_PIN_REGISTRY.get(identity) is lease:
                        if identity not in _MACOS_PIN_PENDING:
                            _MACOS_PIN_PENDING[identity] = _MacOSPinReservation(
                                owner_thread=threading.get_ident(),
                                token=holder,
                                created_at=time.monotonic(),
                            )
                        _MACOS_PIN_REGISTRY.pop(identity, None)
                    _MACOS_PIN_REGISTRY_CONDITION.notify_all()
            except BaseException:
                pass
            try:
                if linked_descriptor >= 0:
                    try:
                        os.close(linked_descriptor)
                    except BaseException:
                        pass
            finally:
                try:
                    if parent_descriptor >= 0:
                        try:
                            _remove_macos_pin_link(parent_descriptor, link_name, identity)
                        except BaseException:
                            pass
                        finally:
                            try:
                                os.close(parent_descriptor)
                            except BaseException:
                                pass
                finally:
                    if lock_acquired:
                        _release_macos_pin_lock(descriptor)
        finally:
            with _MACOS_PIN_REGISTRY_CONDITION:
                registered = _MACOS_PIN_REGISTRY.get(identity)
                if registered is not None:
                    registered.holders.discard(holder)
                if lease is not None and _MACOS_PIN_REGISTRY.get(identity) is lease:
                    _MACOS_PIN_REGISTRY.pop(identity, None)
                pending = _MACOS_PIN_PENDING.get(identity)
                if pending is not None and pending.token is holder:
                    _MACOS_PIN_PENDING.pop(identity, None)
                _MACOS_PIN_REGISTRY_CONDITION.notify_all()


def _read_runtime_source(path: Path) -> tuple[bytes, str]:
    descriptor = -1
    try:
        get_effective_user_id = getattr(os, "geteuid", None)
        if not callable(get_effective_user_id):
            raise OSError("Darwin runtime source ownership is unavailable")
        effective_user_id = int(get_effective_user_id())
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
            or not _runtime_source_permissions_are_safe(
                mode=before.st_mode,
                owner=before.st_uid,
                group=before.st_gid,
                effective_user=effective_user_id,
            )
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


def _runtime_source_permissions_are_safe(
    *,
    mode: int,
    owner: int,
    group: int,
    effective_user: int,
) -> bool:
    """Accept only the caller's or root's runtime, with one root-group exception."""

    if owner not in {0, effective_user}:
        return False
    if mode & (stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
        return False
    return not (mode & stat.S_IWGRP) or (owner == 0 and group == 0)


def _recover_staged_runtime_pins(runtime_root: Path) -> None:
    directory_descriptor = -1
    try:
        directory_descriptor = os.open(
            runtime_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_macos_launch_parent(runtime_root, directory_descriptor)
        with os.scandir(directory_descriptor) as entries:
            names = []
            for index, entry in enumerate(entries, start=1):
                if index > _MAX_DARWIN_LAUNCH_DIRECTORY_ENTRIES:
                    raise OSError("Darwin runtime cache exceeds its entry bound")
                names.append(entry.name)
        for name in names:
            if _RUNTIME_NAME.fullmatch(name) is None:
                continue
            descriptor = -1
            locked = False
            identity: tuple[int, int] | None = None
            reservation = object()
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode):
                    raise OSError("Darwin staged runtime is not regular")
                identity = (details.st_dev, details.st_ino)
                _reserve_macos_pin_identity(
                    identity,
                    reservation,
                    allow_same_thread_reuse=False,
                )
                _acquire_macos_pin_lock(descriptor)
                locked = True
                _remove_stale_macos_pin_links(
                    directory_descriptor,
                    identity,
                )
            finally:
                try:
                    try:
                        if locked:
                            _release_macos_pin_lock(descriptor)
                    finally:
                        if descriptor >= 0:
                            os.close(descriptor)
                finally:
                    if identity is not None:
                        _release_macos_pin_reservation(identity, reservation)
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


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
                _recover_staged_runtime_pins(runtime_root)
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


def spawn_no_fork_exec(
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
    popen_factory: Callable[..., subprocess.Popen[bytes]],
    proof_sink: list[subprocess.Popen[bytes]],
    proof_callback: Callable[[subprocess.Popen[bytes]], None],
) -> subprocess.Popen[bytes]:
    """Exec one generic Darwin runner only after a dynamic no-fork proof."""

    if sys.platform != "darwin" or not argv:
        raise RunnerTransportError("Darwin no-fork launch is unavailable")
    target_path = Path(argv[0])
    target_descriptor = -1
    parent_socket: socket.socket | None = None
    child_socket: socket.socket | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        if (
            not target_path.is_absolute()
            or target_path.parent != runner_binary.parent
            or not target_path.name.startswith(".bluefire-verified-launch-")
        ):
            raise OSError("Darwin no-fork target is not verified")
        target_descriptor = os.open(
            target_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(target_descriptor)
        visible = target_path.stat(follow_symlinks=False)
        canonical = runner_binary.stat(follow_symlinks=False)
        get_effective_user_id = getattr(os, "geteuid", None)
        if (
            not callable(get_effective_user_id)
            or not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(opened, visible)
            or not os.path.samestat(opened, canonical)
            or opened.st_nlink != 2
            or opened.st_uid != int(get_effective_user_id())
            or stat.S_IMODE(opened.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or _descriptor_digest(target_descriptor) != runner_binary_digest
            or _path_digest(watchdog_interpreter) != watchdog_interpreter_digest
            or _path_digest(parent_death_script) != parent_death_script_digest
        ):
            raise OSError("Darwin no-fork launch identity changed")
        parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent_socket.settimeout(start_grace_seconds)
        nonce = secrets.token_hex(32)
        with pinned_launch_file(
            watchdog_interpreter,
            watchdog_interpreter_digest,
        ) as interpreter_launch:
            with pinned_launch_file(
                parent_death_script,
                parent_death_script_digest,
                darwin_descriptor_backed=True,
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
                launch_options["_bluefire_descriptor_argument_indexes"] = (8, 9)
                launch_options["_bluefire_descriptor_list_argument_indexes"] = (11,)
                process = popen_factory(
                    [
                        interpreter_launch[0],
                        "-I",
                        "-B",
                        "-X",
                        "utf8",
                        helper_launch[0],
                        _DARWIN_NO_FORK_EXEC_MODE,
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
                child_socket = None
                armed = _recv_control_line(parent_socket, maximum=192)
                expected = f"armed-nofork-v1:{nonce}:{process.pid}:{os.getpid()}\n".encode("ascii")
                if (
                    armed != expected
                    or not callable(_GET_PROCESS_GROUP_ID)
                    or not callable(_GET_SESSION_ID)
                    or _GET_PROCESS_GROUP_ID(process.pid) != process.pid
                    or _GET_SESSION_ID(process.pid) != process.pid
                ):
                    raise OSError("Darwin no-fork launch proof is invalid")
                proof_sink.append(process)
                proof_callback(process)
                parent_socket.sendall(f"go-nofork-v1:{nonce}\n".encode("ascii"))
                if parent_socket.recv(64) != b"":
                    raise OSError("Darwin no-fork target execution failed")
        return process
    except (OSError, RunnerTransportError, socket.timeout):
        raise RunnerTransportError("Darwin no-fork launch failed") from None
    finally:
        if target_descriptor >= 0:
            os.close(target_descriptor)
        if parent_socket is not None:
            parent_socket.close()
        if child_socket is not None:
            child_socket.close()


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
    members = _private_session_members_for_leader(session_id)
    if members is None or os.getpid() not in members:
        return None
    return members


def _private_session_members_for_leader(session_id: int) -> set[int] | None:
    """Inventory an arbitrary private Darwin session, including alternate groups."""

    if sys.platform != "darwin" or not callable(_GET_SESSION_ID) or session_id <= 1:
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
            return None
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                return None
            return None
    return members


def _private_process_group_members(process_group: int, session_id: int) -> set[int] | None:
    """Inventory one Darwin group without requiring its zombie leader to be queryable."""

    if (
        sys.platform != "darwin"
        or not callable(_GET_PROCESS_GROUP_ID)
        or not callable(_GET_SESSION_ID)
    ):
        return None
    process_ids = _darwin_process_ids()
    if process_ids is None:
        return None
    members: set[int] = set()
    for process_id in process_ids:
        try:
            if (
                _GET_SESSION_ID(process_id) == session_id
                and _GET_PROCESS_GROUP_ID(process_id) == process_group
            ):
                members.add(process_id)
        except ProcessLookupError:
            continue
        except PermissionError:
            return None
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                return None
            return None
    return members


def _drain_private_session(
    process: subprocess.Popen[bytes],
    *,
    session_id: int,
    parent_lease: socket.socket,
    terminate: bool,
    child_exited_without_reap: Callable[[int], bool],
    release_verified: Callable[[subprocess.Popen[bytes]], None],
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
        try:
            leader_exited = child_exited_without_reap(process.pid)
        except (ChildProcessError, OSError):
            return False
        members = _private_session_members(session_id)
        if members is None:
            return False
        targets = members - {os.getpid(), process.pid}
        if not targets and leader_exited:
            # Publish the proven-empty session before the final wait.  If an
            # asynchronous exception lands after Popen has reaped the helper,
            # the caller can finish release without treating its PID as a
            # newly reusable, unverified identity.
            release_verified(process)
            return True
        now = time.monotonic()
        if now >= final_deadline:
            return False
        # The helper is this process's direct child.  WNOWAIT keeps its PID
        # unavailable for reuse, so signalling after non-reaping observation
        # is safe. Session members are inventory only: macOS has no
        # pidfd-equivalent, and a getsid(pid)-then-kill(pid) sequence would be
        # an unsafe identity TOCTOU.
        signum: int | None = None
        if terminate and not leader_exited:
            if now >= force_deadline and not force_sent:
                signum = _FORCE_KILL_SIGNAL
            elif now >= graceful_deadline and not termination_sent:
                signum = signal.SIGTERM
        if signum is not None:
            try:
                # WNOWAIT keeps this exact direct-child PID unreaped, so it
                # cannot be reused between observation and this signal.
                os.kill(process.pid, signum)
            except ProcessLookupError:
                pass
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
    child_exited_without_reap: Callable[[int], bool],
    release_verified: Callable[[subprocess.Popen[bytes]], None],
) -> bool:
    """Release only after every non-watchdog member of the private session is gone."""

    released = _drain_private_session(
        process,
        session_id=containment.session_id,
        parent_lease=containment.parent_lease,
        terminate=terminate,
        child_exited_without_reap=child_exited_without_reap,
        release_verified=release_verified,
    )
    if released:
        containment.parent_lease.close()
    return released


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
    execution_timeout_seconds: float,
    failure_sink: list[tuple[subprocess.Popen[bytes], DarwinProcessContainment]],
    popen_factory: Callable[..., subprocess.Popen[bytes]],
) -> tuple[subprocess.Popen[bytes], DarwinProcessContainment]:
    """Start the verified Darwin helper and retain its watchdog lease."""

    if (
        sys.platform != "darwin"
        or not argv
        or not 0 < execution_timeout_seconds <= _MAX_EXECUTION_TIMEOUT_SECONDS
    ):
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
    containment: DarwinProcessContainment | None = None
    nonce = secrets.token_hex(32)
    try:
        with pinned_launch_file(
            watchdog_interpreter,
            watchdog_interpreter_digest,
        ) as interpreter_launch:
            with pinned_launch_file(
                parent_death_script,
                parent_death_script_digest,
                darwin_descriptor_backed=True,
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
                # The Darwin launch worker duplicates inherited descriptors;
                # rewrite the fixed helper grammar to those owned copies.
                launch_options["_bluefire_descriptor_argument_indexes"] = (7, 8)
                launch_options["_bluefire_descriptor_list_argument_indexes"] = (10,)
                process = popen_factory(
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
                        format(execution_timeout_seconds, ".17g"),
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
    except BaseException as exc:
        if process is not None and parent_socket is not None and containment is None:
            containment = DarwinProcessContainment(
                session_id=os.getpid(),
                monitor_group=process.pid,
                target_process=process.pid,
                parent_lease=parent_socket,
            )
        if process is not None and containment is not None:
            # Transfer the live lease and Popen identity to the outer bounded
            # registry instead of blocking forever inside a failed handshake.
            failure_sink.append((process, containment))
            parent_socket = None
        if isinstance(exc, (OSError, RunnerTransportError, socket.timeout)):
            raise RunnerTransportError("Darwin parent-death containment failed") from None
        raise
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
