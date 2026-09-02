"""The only maintained Python transport allowed to launch the Rust runner."""

from __future__ import annotations

import ctypes
import errno
import json
import math
import os
import re
import secrets
import signal
import socket
import stat

# Only the fixed, absolute Rust runner boundary uses subprocess.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import weakref
from collections import deque
from contextlib import AbstractContextManager, contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Mapping, Protocol, cast, runtime_checkable

from .execution_contracts import (
    ExecutionContractError,
)
from .execution_contracts import (
    reject_forbidden_execution_keys as _reject_forbidden_execution_keys,
)
from .runner_darwin_containment import (
    _DARWIN_DESCRIPTOR_BOOTSTRAP,
    DarwinProcessContainment,
    macos_pinned_launch_path,
    stage_watchdog_interpreter,
)
from .runner_darwin_containment import (
    _private_process_group_members as _darwin_private_process_group_members,
)
from .runner_darwin_containment import (
    _private_session_members_for_leader as _darwin_private_session_members,
)
from .runner_darwin_containment import (
    _validate_macos_launch_parent as _validate_darwin_launch_parent,
)
from .runner_darwin_containment import (
    release_process as release_darwin_process,
)
from .runner_darwin_containment import spawn_no_fork_exec as spawn_darwin_no_fork_exec
from .runner_darwin_containment import (
    spawn_parent_death as spawn_darwin_parent_death,
)
from .runner_inventory import RunnerInventoryAuthorityError
from .runner_inventory import canonical_runner_inventory as _canonical_runner_inventory
from .runner_private_files import (
    _WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT as _WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT,
)
from .runner_private_files import (
    _GuardedBinaryFile as _GuardedBinaryFile,
)
from .runner_private_files import _is_link_or_reparse as _is_link_or_reparse
from .runner_private_files import (
    _PinnedPrivateDirectory as _PinnedPrivateDirectory,
)
from .runner_private_files import (
    _PrivateFileCleanupError as _PrivateFileCleanupError,
)
from .runner_private_files import (
    _read_descriptor_bounded as _read_descriptor_bounded,
)
from .runner_private_files import (
    _windows_extended_path as _windows_extended_path,
)
from .runner_private_files import (
    _windows_mark_delete_descriptor as _windows_mark_delete_descriptor,
)
from .runner_private_files import (
    _windows_open_descriptor as _windows_open_descriptor,
)
from .runner_private_files import (
    _windows_rename_descriptor as _windows_rename_descriptor,
)
from .runner_transport_errors import (
    RunnerDurableResultExists,
    RunnerPendingResultExists,
    RunnerReadinessError,
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
    RunnerTransportError,
)
from .util import canonical_json_bytes, content_hash, file_hash

_TASK_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RECEIVER_TASK_KEY = re.compile(r"^[0-9a-f]{64}$")
_PROCESS_POLL_SECONDS = 0.025
_PROCESS_TERM_GRACE_SECONDS = 2.0
_PROCESS_KILL_GRACE_SECONDS = 5.0
_WATCHDOG_START_GRACE_SECONDS = 10.0
_WATCHDOG_EXIT_GRACE_SECONDS = 12.0
_MAX_EXECUTION_TIMEOUT_SECONDS = 86_400.0
_WATCHDOG_CONFIG_LIMIT_BYTES = 8 * 1024 * 1024
_RUNNER_BINARY_LIMIT_BYTES = 256 * 1024 * 1024
_WATCHDOG_CONTROL_NAMES = frozenset({"config.json", "start", "cancel", "ready.json", "status.json"})
_WATCHDOG_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v2"
_LEGACY_WATCHDOG_STATUS_SCHEMA = "bluefire.runner-watchdog-status.v1"
_KILL_PROCESS_GROUP = getattr(os, "killpg", None)
_GET_PROCESS_GROUP = getattr(os, "getpgrp", None)
_GET_PROCESS_GROUP_ID = getattr(os, "getpgid", None)
_GET_SESSION_ID = getattr(os, "getsid", None)
_PIDFD_OPEN = getattr(os, "pidfd_open", None)
_PIDFD_SEND_SIGNAL = getattr(signal, "pidfd_send_signal", None)
_WAIT_ID = getattr(os, "waitid", None)
_PIDFD_ID_TYPE = getattr(os, "P_PIDFD", None)
_WAIT_EXITED = getattr(os, "WEXITED", 0)
_WAIT_NO_HANG = getattr(os, "WNOHANG", 0)
_WAIT_NO_REAP = getattr(os, "WNOWAIT", 0)
_FORCE_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
_DARWIN_P_PID = 1
_DARWIN_WAITID_OPTIONS = 0x0000_0001 | 0x0000_0004 | 0x0000_0020
_DARWIN_EMPTY_INVENTORY_CONFIRMATIONS = 2
_DARWIN_INDETERMINATE_LIMIT = 32
_DARWIN_RECONCILE_INTERVAL_SECONDS = 1.0
_DARWIN_WAITID_EINTR_RETRIES = 8
_RECEIVER_TASK_ID_ENV = "BLUEFIRE_RECEIVER_TASK_ID"
_RECEIVER_TASK_KEY_ENV = "BLUEFIRE_RECEIVER_TASK_KEY"
_RECEIVER_TASK_ENV_NAMES = frozenset({_RECEIVER_TASK_ID_ENV, _RECEIVER_TASK_KEY_ENV})
_RECEIVER_AUTH_ACTION_IDS = frozenset({"sandbox.network.loopback.v1", "sandbox.peer.handoff.v1"})
_CANCELLATION_ACTION_ID = "sandbox.execution.process-tree-cancellation-witness.v1"
_CANCELLATION_CONTROL_PARENT = ".bluefire-cancellation-witness-v1"
_CANCELLATION_READY_SCHEMA = "bluefire.process-tree-cancellation-ready.v1"
_CANCELLATION_READY_NAME = "ready.json"
_CANCELLATION_REQUEST_NAME = "cancel.request"
_CANCELLATION_ACK_NAME = "cancel.ack"
_CANCELLATION_LEASE_NAME = ".lease"
_CANCELLATION_LEASE_ENV = "BLUEFIRE_CANCELLATION_LEASE_TOKEN"
_CANCELLATION_STAGING_NAMES = frozenset(
    {".ready.json.bluefire-staging", ".cancel.ack.bluefire-staging"}
)
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class _DarwinSigInfo(ctypes.Structure):
    """Public Darwin ``siginfo_t`` prefix and reserved tail from ``sys/signal.h``."""

    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int32),
        ("si_uid", ctypes.c_uint32),
        ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_value", ctypes.c_void_p),
        ("si_band", ctypes.c_long),
        ("reserved", ctypes.c_ulong * 7),
    ]


class _DarwinWatchdogProof:
    """Parent-owned one-shot channel for an exact watchdog no-fork proof."""

    def __init__(self) -> None:
        # XNU's AF_UNIX implementation supports datagram socket pairs, but not
        # SOCK_SEQPACKET.  One datagram gives the proof an atomic record while
        # MSG_PEEK lets verification remain non-destructive until it is exact.
        family = getattr(socket, "AF_UNIX", socket.AF_INET)
        socket_type = socket.SOCK_DGRAM if hasattr(socket, "AF_UNIX") else socket.SOCK_STREAM
        self.reader, self.writer = socket.socketpair(
            family,
            socket_type,
        )
        self.reader.setblocking(False)
        self.read_descriptor = self.reader.fileno()
        self.write_descriptor = self.writer.fileno()
        self.nonce = secrets.token_hex(32)
        self.closed = False
        self.verified: bool | None = None
        self.lock = threading.Lock()

    def close_writer(self) -> None:
        self.write_descriptor = -1
        try:
            self.writer.close()
        except OSError:
            pass

    def close_reader(self) -> None:
        self.read_descriptor = -1
        self.closed = True
        try:
            self.reader.close()
        except OSError:
            pass

    def verify(self, process_id: int) -> bool:
        with self.lock:
            self.close_writer()
            if self.verified is not None:
                return self.verified
            if self.closed:
                return False
            try:
                payload = self.reader.recv(193, socket.MSG_PEEK)
            except BlockingIOError:
                return False
            except OSError:
                self.verified = False
                self.close_reader()
                return False
            expected = f"no-fork-v1:{self.nonce}:{process_id}\n".encode("ascii")
            self.verified = payload == expected
            self.close_reader()
            return self.verified


class _DarwinLaunchRequest:
    def __init__(
        self,
        *,
        owner: Any,
        token: object,
        process_sink: list[subprocess.Popen[bytes]],
        resources: _DarwinLaunchResources,
    ) -> None:
        self.owner = owner
        self.token = token
        self.process_sink = process_sink
        self.resources = resources
        self.done = threading.Event()
        self.accepted = threading.Event()
        self.abandoned = threading.Event()
        self.lock = threading.Lock()
        self.process: subprocess.Popen[bytes] | None = None
        self.error: BaseException | None = None


class _DarwinLaunchResources:
    """Worker-owned copies of every resource borrowed by Darwin Popen."""

    def __init__(
        self,
        *,
        argv: list[str],
        options: dict[str, Any],
        descriptors: list[int],
        links: list[tuple[int, str, tuple[int, int]]],
    ) -> None:
        self.argv = argv
        self.options = options
        self.descriptors = descriptors
        self.links = links
        self.lock = threading.Lock()

    def close_descriptors(self) -> None:
        descriptors = self.descriptors
        self.descriptors = []
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def close_links(self) -> bool:
        retained: list[tuple[int, str, tuple[int, int]]] = []
        with self.lock:
            links = self.links
            self.links = retained
        for parent_descriptor, name, identity in links:
            complete = False
            try:
                current = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(name, dir_fd=parent_descriptor)
                complete = True
            except FileNotFoundError:
                complete = True
            except BaseException:
                complete = False
            if not complete:
                retained.append((parent_descriptor, name, identity))
                continue
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
        return not retained

    def close(self) -> None:
        self.close_descriptors()
        self.close_links()

    def abandon_link_retries(self) -> None:
        links = self.links
        self.links = []
        for parent_descriptor, _name, _identity in links:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass

    def scrub_for_cleanup_retry(self) -> None:
        self.argv.clear()
        self.options.clear()
        self.close_descriptors()


def _clone_darwin_launch_link(
    argument: str,
    ownership_sink: list[tuple[int, str, tuple[int, int]]],
) -> str:
    """Create one worker-owned hard link to an already verified Darwin input."""

    source = Path(argument)
    parent_descriptor = -1
    source_descriptor = -1
    clone_name = f".bluefire-verified-launch-{secrets.token_hex(32)}"
    clone_identity: tuple[int, int] | None = None
    ownership_record: tuple[int, str, tuple[int, int]] | None = None
    try:
        if not source.is_absolute() or not source.name.startswith(".bluefire-verified-launch-"):
            raise OSError("Darwin launch path is not transferable")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        parent_descriptor = os.open(source.parent, directory_flags)
        effective_user = _validate_darwin_launch_parent(source.parent, parent_descriptor)
        source_descriptor = os.open(
            source.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(source_descriptor)
        visible = os.stat(
            source.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not os.path.samestat(opened, visible)
            or opened.st_nlink != 2
            or opened.st_uid != effective_user
            or stat.S_IMODE(opened.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise OSError("Darwin launch path identity is not transferable")
        clone_identity = (opened.st_dev, opened.st_ino)
        os.link(
            source.name,
            clone_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        ownership_record = (parent_descriptor, clone_name, clone_identity)
        ownership_sink.append(ownership_record)
        clone = os.stat(
            clone_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        current = os.fstat(source_descriptor)
        if not os.path.samestat(clone, current) or clone.st_nlink != 3 or current.st_nlink != 3:
            raise OSError("Darwin launch path transfer changed identity")
        transferred = str(source.parent / clone_name)
        parent_descriptor = -1
        return transferred
    finally:
        ownership_transferred = ownership_record is not None and any(
            candidate is ownership_record for candidate in ownership_sink
        )
        try:
            if source_descriptor >= 0:
                os.close(source_descriptor)
        finally:
            if parent_descriptor >= 0 and not ownership_transferred:
                try:
                    if clone_identity is not None:
                        try:
                            current = os.stat(
                                clone_name,
                                dir_fd=parent_descriptor,
                                follow_symlinks=False,
                            )
                            if (current.st_dev, current.st_ino) == clone_identity:
                                os.unlink(clone_name, dir_fd=parent_descriptor)
                        except OSError:
                            pass
                finally:
                    os.close(parent_descriptor)


def _prepare_darwin_launch_resources(
    argv: list[str],
    options: Mapping[str, Any],
    sink: list[_DarwinLaunchResources],
) -> _DarwinLaunchResources:
    """Duplicate borrowed descriptors and pin executable paths for the worker."""

    prepared_argv = list(argv)
    prepared_options = dict(options)
    descriptors: list[int] = []
    links: list[tuple[int, str, tuple[int, int]]] = []
    resources = _DarwinLaunchResources(
        argv=prepared_argv,
        options=prepared_options,
        descriptors=descriptors,
        links=links,
    )
    sink.append(resources)
    try:
        single_descriptor_indexes = tuple(
            prepared_options.pop("_bluefire_descriptor_argument_indexes", ())
        )
        list_descriptor_indexes = tuple(
            prepared_options.pop("_bluefire_descriptor_list_argument_indexes", ())
        )
        descriptor_map: dict[int, int] = {}
        inherited = tuple(int(value) for value in prepared_options.get("pass_fds", ()))
        for descriptor in inherited:
            duplicate = _duplicate_darwin_descriptor(descriptor)
            descriptors.append(duplicate)
            descriptor_map[descriptor] = duplicate
        if inherited:
            prepared_options["pass_fds"] = tuple(
                descriptor_map[descriptor] for descriptor in inherited
            )
        for name in ("stdin", "stdout", "stderr"):
            value = prepared_options.get(name)
            stream_descriptor: int | None = None
            if isinstance(value, int):
                if value >= 0:
                    stream_descriptor = value
            elif value is not None:
                stream_descriptor = int(value.fileno())
            if stream_descriptor is not None:
                duplicate = _duplicate_darwin_descriptor(stream_descriptor)
                descriptors.append(duplicate)
                prepared_options[name] = duplicate
        for raw_index in single_descriptor_indexes:
            index = int(raw_index)
            original = int(prepared_argv[index])
            if original not in descriptor_map:
                raise OSError("Darwin launch descriptor argument is not inherited")
            prepared_argv[index] = str(descriptor_map[original])
        for raw_index in list_descriptor_indexes:
            index = int(raw_index)
            original_values = tuple(
                int(value) for value in prepared_argv[index].split(",") if value
            )
            if any(value not in descriptor_map for value in original_values):
                raise OSError("Darwin launch descriptor list is not inherited")
            prepared_argv[index] = ",".join(str(descriptor_map[value]) for value in original_values)
        for index, argument in enumerate(prepared_argv):
            for prefix in ("/dev/fd/", "/proc/self/fd/"):
                if not argument.startswith(prefix):
                    continue
                original = int(argument.removeprefix(prefix))
                if original in descriptor_map:
                    prepared_argv[index] = prefix + str(descriptor_map[original])
                break
        for index, argument in enumerate(prepared_argv):
            if index != 0:
                continue
            candidate = Path(argument)
            if candidate.is_absolute() and candidate.name.startswith(".bluefire-verified-launch-"):
                prepared_argv[index] = _clone_darwin_launch_link(argument, links)
        return resources
    except BaseException:
        resources.close()
        raise


def _duplicate_darwin_descriptor(descriptor: int) -> int:
    """Duplicate a launch descriptor without ever returning stdio numbers."""

    low_descriptors: list[int] = []
    try:
        while True:
            duplicate = os.dup(descriptor)
            if duplicate > 2:
                return duplicate
            low_descriptors.append(duplicate)
    finally:
        for duplicate in low_descriptors:
            try:
                os.close(duplicate)
            except OSError:
                pass


_DARWIN_LIBC_WAIT_ID: Any = None
_DARWIN_INDETERMINATE_LOCK = threading.RLock()
_DARWIN_ACTIVE_PROCESSES: dict[subprocess.Popen[bytes], Any] = {}
_DARWIN_INDETERMINATE_PROCESSES: dict[subprocess.Popen[bytes], tuple[Any, bool, bool, bool]] = {}
_DARWIN_PENDING_PROCESS_SLOTS: set[object] = set()
_DARWIN_RECONCILER_THREAD: threading.Thread | None = None
_DARWIN_RECONCILER_WAKE = threading.Event()
_DARWIN_LAUNCH_REQUESTS: deque[_DarwinLaunchRequest] = deque()
_DARWIN_LAUNCH_CLEANUPS: deque[_DarwinLaunchResources] = deque()
_DARWIN_LAUNCH_CONDITION = threading.Condition()
_DARWIN_LAUNCH_THREAD: threading.Thread | None = None
if sys.platform == "darwin" and not callable(_WAIT_ID):
    try:
        _DARWIN_LIBC_WAIT_ID = ctypes.CDLL(None, use_errno=True).waitid
        _DARWIN_LIBC_WAIT_ID.argtypes = [
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.POINTER(_DarwinSigInfo),
            ctypes.c_int,
        ]
        _DARWIN_LIBC_WAIT_ID.restype = ctypes.c_int
    except (AttributeError, OSError):
        _DARWIN_LIBC_WAIT_ID = None


def _darwin_child_exited_without_reap(process_id: int) -> bool:
    """Observe one Darwin child with ``waitid(WNOWAIT)`` on every supported Python."""

    if process_id <= 1:
        raise OSError("invalid Darwin child identity")
    for _attempt in range(_DARWIN_WAITID_EINTR_RETRIES):
        observed_process = 0
        if callable(_WAIT_ID):
            try:
                observed = _WAIT_ID(
                    _DARWIN_P_PID,
                    process_id,
                    _DARWIN_WAITID_OPTIONS,
                )
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise
            if observed is not None:
                observed_process = int(getattr(observed, "si_pid", 0))
        elif callable(_DARWIN_LIBC_WAIT_ID):
            information = _DarwinSigInfo()
            ctypes.set_errno(0)
            if (
                int(
                    _DARWIN_LIBC_WAIT_ID(
                        _DARWIN_P_PID,
                        process_id,
                        ctypes.byref(information),
                        _DARWIN_WAITID_OPTIONS,
                    )
                )
                != 0
            ):
                error_number = ctypes.get_errno()
                if error_number == errno.EINTR:
                    continue
                raise OSError(error_number, os.strerror(error_number))
            observed_process = int(information.si_pid)
        else:
            raise OSError("Darwin waitid is unavailable")
        if observed_process == 0:
            return False
        if observed_process != process_id:
            raise OSError("Darwin waitid returned an unexpected child")
        return True
    raise OSError(errno.EINTR, os.strerror(errno.EINTR))


def _darwin_child_status_ownership_available() -> bool:
    """Require non-reaping observation and the default child-status owner."""

    child_signal = getattr(signal, "SIGCHLD", None)
    if not (callable(_WAIT_ID) or callable(_DARWIN_LIBC_WAIT_ID)) or not isinstance(
        child_signal, int
    ):
        return False
    try:
        return signal.getsignal(child_signal) == signal.SIG_DFL
    except (OSError, ValueError):
        return False


def _run_darwin_indeterminate_reconciler() -> None:
    """Retry only Darwin cleanups whose direct-child identity remains pinned."""

    candidate_index = 0
    while True:
        # Periodic scanning is the liveness backstop if an asynchronous
        # exception lands after a candidate is published but before wakeup.
        _DARWIN_RECONCILER_WAKE.wait(timeout=_DARWIN_RECONCILE_INTERVAL_SECONDS)
        with _DARWIN_INDETERMINATE_LOCK:
            candidates = [
                (process, owner, terminate, observe_only)
                for process, (owner, terminate, identity_lost, observe_only) in (
                    _DARWIN_INDETERMINATE_PROCESSES.items()
                )
                if not identity_lost
            ]
            if not candidates:
                _DARWIN_RECONCILER_WAKE.clear()
                continue
        process, owner, terminate, observe_only = candidates[candidate_index % len(candidates)]
        candidate_index += 1
        try:
            owner._reconcile_indeterminate_darwin_process(  # noqa: SLF001
                process,
                terminate=terminate,
                observe_only=observe_only,
            )
        except BaseException:
            # Retention is the safe state. A later bounded pass retries it.
            pass
        time.sleep(_DARWIN_RECONCILE_INTERVAL_SECONDS)


def _start_darwin_indeterminate_reconciler() -> None:
    global _DARWIN_RECONCILER_THREAD
    with _DARWIN_INDETERMINATE_LOCK:
        if _DARWIN_RECONCILER_THREAD is not None and _DARWIN_RECONCILER_THREAD.is_alive():
            _DARWIN_RECONCILER_WAKE.set()
            return
        reconciler = threading.Thread(
            target=_run_darwin_indeterminate_reconciler,
            name="bluefire-darwin-reconciler",
            daemon=True,
        )
        _DARWIN_RECONCILER_THREAD = reconciler
        try:
            reconciler.start()
        except RuntimeError:
            if _DARWIN_RECONCILER_THREAD is reconciler:
                _DARWIN_RECONCILER_THREAD = None
            raise RunnerTransportError("Darwin reconciliation worker is unavailable") from None
        _DARWIN_RECONCILER_WAKE.set()


def _run_darwin_launch_worker() -> None:
    requests_since_cleanup = 0
    while True:
        request: _DarwinLaunchRequest | None = None
        cleanup: _DarwinLaunchResources | None = None
        with _DARWIN_LAUNCH_CONDITION:
            while not _DARWIN_LAUNCH_REQUESTS and not _DARWIN_LAUNCH_CLEANUPS:
                _DARWIN_LAUNCH_CONDITION.wait(timeout=_DARWIN_RECONCILE_INTERVAL_SECONDS)
            cleanup_turn = bool(
                _DARWIN_LAUNCH_CLEANUPS
                and (
                    not _DARWIN_LAUNCH_REQUESTS
                    or requests_since_cleanup >= _DARWIN_WAITID_EINTR_RETRIES
                )
            )
            if not cleanup_turn:
                request = _DARWIN_LAUNCH_REQUESTS.popleft()
                request.accepted.set()
                requests_since_cleanup += 1
            else:
                cleanup = _DARWIN_LAUNCH_CLEANUPS.popleft()
                requests_since_cleanup = 0
        if cleanup is not None:
            if not cleanup.close_links():
                with _DARWIN_LAUNCH_CONDITION:
                    _DARWIN_LAUNCH_CLEANUPS.append(cleanup)
                    _DARWIN_LAUNCH_CONDITION.wait(timeout=_DARWIN_RECONCILE_INTERVAL_SECONDS)
            continue
        if request is None:
            continue
        _execute_darwin_launch_request(request)


def _execute_darwin_launch_request(request: _DarwinLaunchRequest) -> None:
    """Execute one accepted request using only its worker-owned resources."""

    resources = request.resources
    process: subprocess.Popen[bytes] | None = None
    try:
        with request.lock:
            if request.abandoned.is_set():
                raise RunnerTransportError("Darwin process launch was abandoned")
        process = request.owner._construct_registered_darwin_popen(  # noqa: SLF001
            request.token,
            request.process_sink,
            resources.argv,
            **resources.options,
        )
        with request.lock:
            request.process = process
    except BaseException as exc:
        with request.lock:
            if request.process_sink:
                request.process = request.process_sink[-1]
            process = request.process
            request.error = exc
    finally:
        with request.lock:
            process = request.process
            abandoned = request.abandoned.is_set()
        if abandoned and process is not None:
            try:
                request.owner._quarantine_interrupted_darwin_launch(process)  # noqa: SLF001
            except BaseException:
                pass
        _retire_darwin_launch_resources(resources)
        request.done.set()


def _retire_darwin_launch_resources(resources: _DarwinLaunchResources) -> None:
    """Close owned launch inputs and retain bounded private-link cleanup."""

    resources.close_descriptors()
    # argv[0] has crossed exec, the launch failed closed, or an unaccepted
    # request was cancelled. Keep retry ownership if transient cleanup cannot
    # remove its private launch pin.
    if not resources.close_links():
        resources.scrub_for_cleanup_retry()
        with _DARWIN_LAUNCH_CONDITION:
            if len(_DARWIN_LAUNCH_CLEANUPS) < _DARWIN_INDETERMINATE_LIMIT:
                _DARWIN_LAUNCH_CLEANUPS.append(resources)
            else:
                resources.abandon_link_retries()
            _DARWIN_LAUNCH_CONDITION.notify()


def _start_darwin_launch_worker() -> None:
    global _DARWIN_LAUNCH_THREAD
    with _DARWIN_INDETERMINATE_LOCK:
        if _DARWIN_LAUNCH_THREAD is not None and _DARWIN_LAUNCH_THREAD.is_alive():
            return
        worker = threading.Thread(
            target=_run_darwin_launch_worker,
            name="bluefire-darwin-launch",
            daemon=True,
        )
        _DARWIN_LAUNCH_THREAD = worker
        try:
            worker.start()
        except RuntimeError:
            if _DARWIN_LAUNCH_THREAD is worker:
                _DARWIN_LAUNCH_THREAD = None
            raise RunnerTransportError("Darwin launch worker is unavailable") from None


def _darwin_launch_worker_is_alive() -> bool:
    with _DARWIN_INDETERMINATE_LOCK:
        return _DARWIN_LAUNCH_THREAD is not None and _DARWIN_LAUNCH_THREAD.is_alive()


def _validated_receiver_task_environment(
    value: Mapping[str, str] | None,
    *,
    expected_task_id: str | None = None,
) -> dict[str, str]:
    if value is None or not value:
        return {}
    candidate = dict(value)
    task_id = candidate.get(_RECEIVER_TASK_ID_ENV)
    task_key = candidate.get(_RECEIVER_TASK_KEY_ENV)
    if (
        set(candidate) != _RECEIVER_TASK_ENV_NAMES
        or not isinstance(task_id, str)
        or _TASK_IDENTIFIER.fullmatch(task_id) is None
        or (expected_task_id is not None and task_id != expected_task_id)
        or not isinstance(task_key, str)
        or _RECEIVER_TASK_KEY.fullmatch(task_key) is None
    ):
        raise RunnerTransportError("runner receiver authentication is invalid")
    return {
        _RECEIVER_TASK_ID_ENV: task_id,
        _RECEIVER_TASK_KEY_ENV: task_key,
    }


def _consume_receiver_task_environment(*, expected_task_id: str) -> dict[str, str]:
    present = frozenset(name for name in _RECEIVER_TASK_ENV_NAMES if name in os.environ)
    candidate = {name: os.environ.pop(name) for name in present}
    if not present:
        return {}
    if present != _RECEIVER_TASK_ENV_NAMES:
        raise RunnerTransportError("runner receiver authentication is incomplete")
    return _validated_receiver_task_environment(
        candidate,
        expected_task_id=expected_task_id,
    )


@contextmanager
def _pinned_launch_file_impl(
    path: Path,
    expected_digest: str,
    *,
    darwin_descriptor_backed: bool = False,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Bind a launch path to the exact file descriptor that was verified."""

    descriptor = -1
    try:
        if os.name == "nt":
            descriptor = _windows_open_descriptor(path, directory=False)
        else:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            if sys.platform == "darwin" and darwin_descriptor_backed and descriptor <= 2:
                replacement = _duplicate_darwin_descriptor(descriptor)
                os.close(descriptor)
                descriptor = replacement
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink < 1
            or (sys.platform != "darwin" and details.st_nlink != 1)
        ):
            raise OSError("launch input is not a single-link regular file")
        payload = _read_descriptor_bounded(descriptor, _RUNNER_BINARY_LIMIT_BYTES)
        if "sha256:" + sha256(payload).hexdigest() != expected_digest:
            raise OSError("launch input digest changed")
        if os.name == "nt":
            yield str(path), ()
        elif sys.platform == "darwin" and darwin_descriptor_backed:
            if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
                raise OSError("descriptor-backed Darwin input offset is invalid")
            yield str(descriptor), (descriptor,)
        elif sys.platform == "darwin":
            with macos_pinned_launch_path(
                path,
                descriptor,
                details,
                expected_digest,
            ) as launch_path:
                yield launch_path, ()
        else:
            descriptor_path = next(
                (
                    candidate
                    for candidate in (
                        f"/proc/self/fd/{descriptor}",
                        f"/dev/fd/{descriptor}",
                    )
                    if os.path.exists(candidate)
                ),
                None,
            )
            if descriptor_path is None:
                raise OSError("descriptor-backed launch path is unavailable")
            descriptor_details = os.stat(descriptor_path)
            if (descriptor_details.st_dev, descriptor_details.st_ino) != (
                details.st_dev,
                details.st_ino,
            ):
                raise OSError("descriptor-backed launch identity changed")
            yield descriptor_path, (descriptor,)
    except OSError:
        raise RunnerTransportError("verified launch input is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def _pinned_launch_file(
    path: Path,
    expected_digest: str,
    *,
    darwin_descriptor_backed: bool = False,
) -> Iterator[tuple[str, tuple[int, ...]]]:
    """Bind one launch to its verified file while platform pinning is active."""

    with _pinned_launch_file_impl(
        path,
        expected_digest,
        darwin_descriptor_backed=darwin_descriptor_backed,
    ) as launch:
        yield launch


class _CancellationControlLease:
    """Trusted ownership of one request-bound cancellation namespace."""

    def __init__(
        self,
        *,
        sandbox: _PinnedPrivateDirectory,
        parent: _PinnedPrivateDirectory,
        task: _PinnedPrivateDirectory,
        parent_created: bool,
        task_id: str,
        request_hash: str,
        token: str,
    ) -> None:
        self.sandbox = sandbox
        self.parent = parent
        self.task = task
        self.parent_created = parent_created
        self.task_id = task_id
        self.request_hash = request_hash
        self.token = token
        self._closed = False

    def _validate_ready(self, payload: bytes) -> None:
        ready = SubprocessRustRunner._decode_json(payload, "runner cancellation readiness")
        if (
            set(ready)
            != {
                "schema_version",
                "task_id",
                "request_hash",
                "parent_process_id",
                "descendant_process_id",
            }
            or ready.get("schema_version") != _CANCELLATION_READY_SCHEMA
            or ready.get("task_id") != self.task_id
            or ready.get("request_hash") != self.request_hash
            or type(ready.get("parent_process_id")) is not int
            or int(ready["parent_process_id"]) <= 0
            or type(ready.get("descendant_process_id")) is not int
            or int(ready["descendant_process_id"]) <= 0
            or ready["parent_process_id"] == ready["descendant_process_id"]
        ):
            raise RunnerTransportError("runner cancellation readiness is invalid")

    def cleanup(self) -> bool:
        """Remove only protocol objects from the still-pinned owned task."""

        if self._closed:
            return False
        task_removed = False
        try:
            names = set(self.task.names(maximum=6))
            allowed = {
                _CANCELLATION_READY_NAME,
                _CANCELLATION_REQUEST_NAME,
                _CANCELLATION_ACK_NAME,
                _CANCELLATION_LEASE_NAME,
                *_CANCELLATION_STAGING_NAMES,
            }
            if not names <= allowed:
                return False
            records: dict[str, tuple[bytes, tuple[int, int]]] = {}
            for name in sorted(names):
                maximum = 2048 if name in _CANCELLATION_STAGING_NAMES else 1024
                records[name] = self.task.read_with_identity(name, maximum=maximum)
            ready_record = records.get(_CANCELLATION_READY_NAME)
            request_record = records.get(_CANCELLATION_REQUEST_NAME)
            ack_record = records.get(_CANCELLATION_ACK_NAME)
            lease_record = records.get(_CANCELLATION_LEASE_NAME)
            if lease_record is None or lease_record[0] != (f"lease:{self.token}\n".encode("ascii")):
                return False
            if ready_record is not None:
                self._validate_ready(ready_record[0])
            if request_record is not None:
                if re.fullmatch(rb"cancel:[0-9a-f]{64}\n", request_record[0]) is None:
                    return False
                if ready_record is None:
                    return False
            if ack_record is not None:
                if request_record is None or ack_record[0] != b"ack:" + request_record[0][7:]:
                    return False
            for name in sorted(records):
                payload, identity = records[name]
                maximum = 2048 if name in _CANCELLATION_STAGING_NAMES else 1024
                self.task.unlink(
                    name,
                    maximum=maximum,
                    expected=payload,
                    expected_identity=identity,
                )
            if self.task.names(maximum=1):
                return False
            self.task.remove()
            self.task.close()
            task_removed = True
            if self.parent_created and not self.parent.names(maximum=1):
                parent_path = self.parent.path
                parent_identity = self.parent.directory_identity()
                self.parent.close()
                with _PinnedPrivateDirectory(
                    parent_path,
                    delete=True,
                    expected_identity=parent_identity,
                ) as removable_parent:
                    if not removable_parent.names(maximum=1):
                        removable_parent.remove()
            return True
        except (OSError, RunnerTransportError, ValueError):
            return False
        finally:
            if not task_removed:
                self.task.close()
            self.parent.close()
            self.sandbox.close()
            self._closed = True

    def close(self) -> None:
        if self._closed:
            return
        self.task.close()
        self.parent.close()
        self.sandbox.close()
        self._closed = True


@runtime_checkable
class RunnerTransport(Protocol):
    def inventory(self) -> Mapping[str, Any]: ...

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


@runtime_checkable
class TaskAwareRunnerTransport(RunnerTransport, Protocol):
    """Runner transport that durably identifies and cancels one exact task."""

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]: ...


def execution_task_identity(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> tuple[str, str]:
    """Bind one task identifier to the exact canonical execute payload."""

    request_hash = content_hash({"manifest": dict(manifest), "profile": dict(profile)})
    return "execute-" + request_hash.removeprefix("sha256:"), request_hash


def canonical_runner_inventory(inventory: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and normalize the stable identity-bearing runner inventory."""

    try:
        return cast(Mapping[str, Any], _canonical_runner_inventory(inventory))
    except RunnerInventoryAuthorityError as exc:
        raise RunnerReadinessError(str(exc)) from exc


def runner_inventory_digest(inventory: Mapping[str, Any]) -> str:
    """Return the canonical digest used by the approval and dispatch gates."""

    return str(content_hash(canonical_runner_inventory(inventory)))


def runner_transport_identity(
    runner: RunnerTransport,
    inventory: Mapping[str, Any],
) -> Mapping[str, str]:
    """Build a secret-safe identity for the exact transport and runner binary."""

    canonical = canonical_runner_inventory(inventory)
    identity = {
        "transport": f"{type(runner).__module__}.{type(runner).__qualname__}",
        "runner_id": str(canonical["runner_id"]),
        "runner_version": str(canonical["runner_version"]),
        "platform": str(canonical["platform"]),
    }
    raw_binary = getattr(runner, "runner_binary", None)
    if isinstance(raw_binary, Path):
        try:
            binary = raw_binary.resolve(strict=True)
            if not binary.is_file():
                raise OSError("runner binary is not a file")
            identity["runner_binary_digest"] = file_hash(binary)
        except OSError as exc:
            raise RunnerReadinessError("Runner identity could not be verified.") from exc
    else:
        identity_probe = getattr(runner, "transport_identity", None)
        if callable(identity_probe):
            try:
                transport_identity = identity_probe()
            except (OSError, RunnerTransportError, TypeError, ValueError) as exc:
                raise RunnerReadinessError("Runner identity could not be verified.") from exc
            if (
                not isinstance(transport_identity, Mapping)
                or transport_identity.get("schema_version")
                != "bluefire.runner-transport-identity.v1"
                or transport_identity.get("runner_id") != canonical["runner_id"]
                or transport_identity.get("inventory_digest") != content_hash(canonical)
            ):
                raise RunnerReadinessError("Runner identity could not be verified.")
            binary_digest = transport_identity.get("runner_binary_digest")
            if binary_digest is not None:
                if (
                    not isinstance(binary_digest, str)
                    or _SHA256_DIGEST.fullmatch(binary_digest) is None
                ):
                    raise RunnerReadinessError("Runner identity could not be verified.")
                identity["runner_binary_digest"] = binary_digest
    return identity


class InventoryBoundRunner:
    """Fail closed if the approved runner identity or inventory changes.

    Inventory is checked when orchestration claims the approval and again
    immediately before every action dispatch. The underlying transport error is
    never exposed because it may contain local paths or process diagnostics.
    """

    def __init__(
        self,
        runner: RunnerTransport,
        *,
        expected_inventory_digest: str,
        expected_identity_digest: str,
        recovery_identity: Mapping[str, Any],
        dispatch_lease: Callable[[], AbstractContextManager[Any]] | None = None,
    ) -> None:
        self.runner = runner
        self.expected_inventory_digest = expected_inventory_digest
        self.expected_identity_digest = expected_identity_digest
        self.recovery_identity = dict(recovery_identity)
        self.dispatch_lease = dispatch_lease

    @property
    def runner_binary(self) -> Any:
        return getattr(self.runner, "runner_binary", None)

    @property
    def runner_binary_digest(self) -> Any:
        return getattr(self.runner, "runner_binary_digest", None)

    def inventory(self) -> Mapping[str, Any]:
        try:
            inventory = self.runner.inventory()
            canonical = canonical_runner_inventory(inventory)
            identity = runner_transport_identity(self.runner, inventory)
        except (AttributeError, OSError, RunnerTransportError, TypeError, ValueError) as exc:
            raise RunnerReadinessError(
                "Runner became unavailable after approval; no action was dispatched."
            ) from exc
        if content_hash(canonical) != self.expected_inventory_digest:
            raise RunnerReadinessError(
                "Runner inventory changed after approval; submit a new Execute request."
            )
        if content_hash(identity) != self.expected_identity_digest:
            raise RunnerReadinessError(
                "Runner identity changed after approval; submit a new Execute request."
            )
        return inventory

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.inventory()
        with self._dispatch_authority():
            return self.runner.execute(manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Preserve the approval-time inventory gate for task-aware dispatch."""

        self.inventory()
        with self._dispatch_authority():
            operation = getattr(self.runner, "execute_task", None)
            if not callable(operation):
                raise RunnerTransportError(
                    "Runner transport does not support task-aware execution."
                )
            result = operation(
                manifest,
                profile,
                task_id=task_id,
                cancel_event=cancel_event,
                durable_result_path=durable_result_path,
            )
        if not isinstance(result, Mapping):
            raise RunnerTransportError("runner result must be a JSON object")
        return result

    @contextmanager
    def _dispatch_authority(self) -> Iterator[None]:
        if self.dispatch_lease is None:
            yield
            return
        manager: AbstractContextManager[Any]
        try:
            manager = self.dispatch_lease()
            manager.__enter__()
        except Exception as exc:
            raise RunnerReadinessError(
                "Action-package catalog changed before dispatch; submit a new Execute request."
            ) from exc
        try:
            # The lease remains held across the underlying effect. Release
            # errors are handled by its owner-private close path and cannot be
            # misreported as a pre-dispatch refusal after an effect occurred.
            yield
        finally:
            manager.__exit__(None, None, None)


def reject_forbidden_execution_keys(value: Any, *, path: str = "$") -> None:
    """Preserve the transport-facing error while sharing neutral validation."""

    try:
        _reject_forbidden_execution_keys(value, path=path)
    except ExecutionContractError as exc:
        raise RunnerTransportError(str(exc)) from exc


def runner_pending_result_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic crash-recovery path for a task's runner stdout.

    The task identifier is hashed into a fixed filename, so it can never select
    a path.  A server that restarts after its parent process was interrupted can
    use this helper to find and reconcile a complete, parseable runner result.
    """

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    return destination.with_name(f".bluefire-result-{identity}.pending")


def runner_watchdog_control_root(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the deterministic private control directory for one runner task."""

    if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
        raise RunnerTransportError("runner task identity is invalid")
    destination = Path(durable_result_path).expanduser()
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise RunnerTransportError("runner durable result destination is invalid")
    try:
        destination = destination.resolve(strict=False)
    except OSError:
        raise RunnerTransportError("runner durable result destination is invalid") from None
    identity = sha256(f"{task_id}\0{destination.name}".encode("utf-8")).hexdigest()
    root = destination.parent / f".bluefire-watchdog-{identity}"
    if os.name == "nt" and len(os.fspath(root)) >= _WINDOWS_LEGACY_PRIVATE_ROOT_LIMIT:
        return _windows_extended_path(root)
    return root


def runner_watchdog_cancel_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's deterministic cancellation marker path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "cancel"


def runner_watchdog_ready_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's private watchdog-readiness record path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "ready.json"


def runner_watchdog_status_path(
    durable_result_path: str | Path,
    task_id: str,
) -> Path:
    """Return the task's durable terminal watchdog-status path."""

    return runner_watchdog_control_root(durable_result_path, task_id) / "status.json"


def request_runner_task_cancel(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Durably request cancellation for an already-started watchdog task."""

    root = runner_watchdog_control_root(durable_result_path, task_id)
    try:
        with _PinnedPrivateDirectory(root) as pinned:
            try:
                pinned.create("cancel", b"cancel\n", maximum=32, consumable=True)
            except FileExistsError:
                try:
                    existing = pinned.read("cancel", maximum=32)
                except FileNotFoundError:
                    # The trusted watchdog consumed the marker between the
                    # non-replacing collision and validation. Its terminal
                    # status remains the only proof that cancellation won.
                    pass
                else:
                    if existing != b"cancel\n":
                        raise OSError("invalid cancellation marker") from None
    except (OSError, RunnerTransportError):
        raise RunnerTransportError("runner cancellation signal is unavailable") from None


def cleanup_runner_watchdog_terminal_state(
    durable_result_path: str | Path,
    task_id: str,
) -> None:
    """Remove only a terminal watchdog record after durable task reconciliation."""

    root = runner_watchdog_control_root(durable_result_path, task_id)
    deadline = time.monotonic() + 0.5
    expected_status_identity: tuple[int, int] | None = None
    expected_status_payload: bytes | None = None
    while True:
        try:
            with _PinnedPrivateDirectory(root, delete=True) as pinned:
                if pinned.names() != ("status.json",):
                    raise OSError("watchdog task is not terminal")
                payload, status_identity = pinned.read_with_identity(
                    "status.json",
                    maximum=4096,
                    expected_identity=expected_status_identity,
                )
                if expected_status_identity is None:
                    expected_status_identity = status_identity
                    expected_status_payload = payload
                elif (
                    status_identity != expected_status_identity
                    or payload != expected_status_payload
                ):
                    raise OSError("watchdog terminal status identity changed")
                status = SubprocessRustRunner._decode_json(
                    payload,
                    "runner watchdog status",
                )
                if (
                    status.get("schema_version")
                    not in {_WATCHDOG_STATUS_SCHEMA, _LEGACY_WATCHDOG_STATUS_SCHEMA}
                    or status.get("task_id") != task_id
                    or status.get("state") not in {"succeeded", "failed", "cancelled"}
                ):
                    raise OSError("invalid watchdog status")
                pinned.unlink(
                    "status.json",
                    maximum=4096,
                    expected=payload,
                    expected_identity=status_identity,
                )
                pinned.remove()
                return
        except (OSError, RunnerTransportError):
            if time.monotonic() >= deadline:
                raise RunnerTransportError(
                    "runner watchdog state is not ready for reconciliation"
                ) from None
            time.sleep(0.01)


class SubprocessRustRunner:
    """Invoke one preconfigured runner binary with a fixed argument grammar."""

    def __init__(
        self,
        runner_binary: str | Path,
        work_root: str | Path,
        *,
        timeout_seconds: float = 35.0,
        output_limit_bytes: int = 2 * 1024 * 1024,
        receiver_task_key_factory: Callable[[str], bytes] | None = None,
        durable_result_guard: _PinnedPrivateDirectory | None = None,
        _kill_child_on_job_close: bool = False,
        _watchdog_interpreter: str | Path | None = None,
    ) -> None:
        binary = Path(runner_binary).expanduser()
        if not binary.is_absolute() or not binary.is_file():
            raise RunnerTransportError("runner binary must be an existing absolute file")
        root = Path(work_root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        self.runner_binary = binary.resolve(strict=True)
        try:
            self.runner_binary_digest = file_hash(self.runner_binary)
        except OSError:
            raise RunnerTransportError("Runner identity could not be verified.") from None
        self.work_root = root.resolve(strict=True)
        self.timeout_seconds = timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self._receiver_task_key_factory = receiver_task_key_factory
        self._durable_result_guard = durable_result_guard
        self._kill_child_on_job_close = bool(_kill_child_on_job_close)
        runtime = Path(
            _watchdog_interpreter
            if _watchdog_interpreter is not None
            else getattr(sys, "_base_executable", sys.executable)
        ).expanduser()
        if not runtime.is_absolute() or not runtime.is_file():
            raise RunnerTransportError("Runner watchdog runtime is unavailable.")
        runtime = runtime.resolve(strict=True)
        try:
            if sys.platform == "darwin" and _watchdog_interpreter is None:
                runtime, runtime_digest = stage_watchdog_interpreter(runtime, self.work_root)
            else:
                runtime_digest = file_hash(runtime)
        except OSError:
            raise RunnerTransportError("Runner watchdog runtime is unavailable.") from None
        self._watchdog_interpreter = runtime
        self._watchdog_interpreter_digest = runtime_digest
        try:
            script = Path(__file__).resolve(strict=True).with_name("runner_watchdog.py")
            details = script.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or _is_link_or_reparse(script)
            ):
                raise OSError("unsafe packaged watchdog script")
            self.watchdog_script = script
            self.watchdog_script_digest = file_hash(script)
            parent_death_script = script.with_name("runner_parent_death.py")
            parent_death_details = parent_death_script.lstat()
            if (
                not stat.S_ISREG(parent_death_details.st_mode)
                or parent_death_details.st_nlink != 1
                or _is_link_or_reparse(parent_death_script)
            ):
                raise OSError("unsafe packaged parent-death helper")
            self.parent_death_script = parent_death_script
            self.parent_death_script_digest = file_hash(parent_death_script)
        except OSError:
            raise RunnerTransportError("Packaged runner watchdog is unavailable.") from None
        self._windows_jobs: dict[int, int] = {}
        self._windows_jobs_lock = threading.Lock()
        self._released_windows_processes: weakref.WeakSet[subprocess.Popen[bytes]] = (
            weakref.WeakSet()
        )
        self._linux_process_containments: weakref.WeakKeyDictionary[
            subprocess.Popen[bytes], tuple[int, int, int, int, int]
        ] = weakref.WeakKeyDictionary()
        self._released_linux_processes: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()
        self._released_darwin_processes: weakref.WeakSet[subprocess.Popen[bytes]] = (
            weakref.WeakSet()
        )
        self._darwin_release_verified: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()
        self._darwin_reap_indeterminate: weakref.WeakSet[subprocess.Popen[bytes]] = (
            weakref.WeakSet()
        )
        self._darwin_identity_lost: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()
        self._darwin_no_fork_proven: weakref.WeakSet[subprocess.Popen[bytes]] = weakref.WeakSet()
        self._darwin_watchdog_proofs: weakref.WeakKeyDictionary[
            subprocess.Popen[bytes], _DarwinWatchdogProof
        ] = weakref.WeakKeyDictionary()
        self._darwin_process_containments: weakref.WeakKeyDictionary[
            subprocess.Popen[bytes], DarwinProcessContainment
        ] = weakref.WeakKeyDictionary()
        if sys.platform == "darwin":
            if not _darwin_child_status_ownership_available():
                raise RunnerTransportError("Darwin unreaped process observation is unavailable")
            _start_darwin_indeterminate_reconciler()
            _start_darwin_launch_worker()
        if (
            not 0 < timeout_seconds <= _MAX_EXECUTION_TIMEOUT_SECONDS
            or not math.isfinite(timeout_seconds)
            or not 4096 <= output_limit_bytes <= _WATCHDOG_CONFIG_LIMIT_BYTES
            or (receiver_task_key_factory is not None and not callable(receiver_task_key_factory))
        ):
            raise RunnerTransportError("runner transport bounds are invalid")

    def _reserve_darwin_process_slot(self, token: object) -> bool:
        with _DARWIN_INDETERMINATE_LOCK:
            if (
                len(set(_DARWIN_ACTIVE_PROCESSES) | set(_DARWIN_INDETERMINATE_PROCESSES))
                + len(_DARWIN_PENDING_PROCESS_SLOTS)
                >= _DARWIN_INDETERMINATE_LIMIT
            ):
                return False
            _DARWIN_PENDING_PROCESS_SLOTS.add(token)
        return True

    def _register_darwin_process_slot(
        self,
        token: object,
        process: subprocess.Popen[bytes],
    ) -> None:
        with _DARWIN_INDETERMINATE_LOCK:
            active_owner = _DARWIN_ACTIVE_PROCESSES.get(process)
            if active_owner is self:
                _DARWIN_PENDING_PROCESS_SLOTS.discard(token)
                return
            if token not in _DARWIN_PENDING_PROCESS_SLOTS or active_owner is not None:
                raise AssertionError("Darwin process reservation is invalid")
            # Insert the strong process pin before discarding the reservation.
            # If an asynchronous exception lands between these operations, the
            # idempotent retry above completes the same transition safely.
            _DARWIN_ACTIVE_PROCESSES[process] = self
            try:
                _DARWIN_PENDING_PROCESS_SLOTS.discard(token)
            except BaseException:
                set.discard(_DARWIN_PENDING_PROCESS_SLOTS, token)
                raise

    @staticmethod
    def _cancel_darwin_process_slot(token: object) -> None:
        with _DARWIN_INDETERMINATE_LOCK:
            try:
                _DARWIN_PENDING_PROCESS_SLOTS.discard(token)
            except BaseException:
                set.discard(_DARWIN_PENDING_PROCESS_SLOTS, token)
                raise

    def _drop_active_darwin_process(self, process: subprocess.Popen[bytes]) -> None:
        with _DARWIN_INDETERMINATE_LOCK:
            if _DARWIN_ACTIVE_PROCESSES.get(process) is self:
                _DARWIN_ACTIVE_PROCESSES.pop(process, None)

    def _drop_owned_darwin_process(self, process: subprocess.Popen[bytes]) -> None:
        """Release ownership while keeping any interrupted transition discoverable."""

        with _DARWIN_INDETERMINATE_LOCK:
            if _DARWIN_ACTIVE_PROCESSES.get(process) is self:
                _DARWIN_ACTIVE_PROCESSES.pop(process, None)
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            if state is not None and state[0] is self:
                _DARWIN_INDETERMINATE_PROCESSES.pop(process, None)

    def _darwin_process_is_indeterminate(self, process: subprocess.Popen[bytes]) -> bool:
        with _DARWIN_INDETERMINATE_LOCK:
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            return state is not None and state[0] is self

    def _refresh_darwin_no_fork_proof(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        if process in self._darwin_no_fork_proven:
            return True
        proof = self._darwin_watchdog_proofs.get(process)
        if proof is None or not proof.verify(process.pid):
            return False
        self._darwin_no_fork_proven.add(process)
        self._darwin_watchdog_proofs.pop(process, None)
        return True

    def _construct_registered_darwin_popen(
        self,
        token: object,
        process_sink: list[subprocess.Popen[bytes]],
        argv: list[str],
        **options: Any,
    ) -> subprocess.Popen[bytes]:
        """Construct Popen under a provisional strong pin before child creation."""

        process: subprocess.Popen[bytes] = cast(
            Any,
            subprocess.Popen.__new__(subprocess.Popen),
        )
        initialized = False
        try:
            self._register_darwin_process_slot(token, process)
            subprocess.Popen.__init__(process, argv, **options)
            initialized = True
            process_sink.append(process)
            return process
        except BaseException:
            process_id = getattr(process, "pid", None)
            child_created = bool(getattr(process, "_child_created", False))
            terminal_status = getattr(process, "returncode", None)
            if terminal_status is None and (
                initialized or (child_created and isinstance(process_id, int) and process_id > 1)
            ):
                if not process_sink or process_sink[-1] is not process:
                    try:
                        process_sink.append(process)
                    except Exception:
                        pass
                self._quarantine_interrupted_darwin_launch(process)
            else:
                self._drop_active_darwin_process(process)
            raise

    def _spawn_registered_darwin_popen(
        self,
        token: object,
        process_sink: list[subprocess.Popen[bytes]],
        argv: list[str],
        **options: Any,
    ) -> subprocess.Popen[bytes]:
        """Launch on the prestarted worker and complete ownership before return."""

        _start_darwin_launch_worker()
        resource_sink: list[_DarwinLaunchResources] = []
        resources: _DarwinLaunchResources | None = None
        request: _DarwinLaunchRequest | None = None
        worker_owned = False
        try:
            # Clone every borrowed fd and launch link before publication. Once
            # queued, the worker touches only these owned copies, so caller
            # unwind may safely close the originals at any later boundary.
            resources = _prepare_darwin_launch_resources(argv, options, resource_sink)
            request = _DarwinLaunchRequest(
                owner=self,
                token=token,
                process_sink=process_sink,
                resources=resources,
            )
            with _DARWIN_LAUNCH_CONDITION:
                _DARWIN_LAUNCH_REQUESTS.append(request)
                _DARWIN_LAUNCH_CONDITION.notify()
            launch_deadline = time.monotonic() + _WATCHDOG_START_GRACE_SECONDS
            while not request.done.wait(_PROCESS_POLL_SECONDS):
                if not _darwin_launch_worker_is_alive():
                    raise RunnerTransportError("Darwin launch worker stopped unexpectedly")
                if time.monotonic() >= launch_deadline:
                    raise RunnerTransportError("Darwin process launch exceeded its deadline")
            with request.lock:
                error = request.error
                process = request.process
            if error is not None:
                raise error
            if process is None:
                raise AssertionError("Darwin launch worker returned without a process")
            return process
        except BaseException:
            if resources is None and resource_sink:
                resources = resource_sink[-1]
            # Transfer ownership to the worker without waiting indefinitely.
            # If it eventually creates a child, its finalizer observes this
            # marker and moves that child into bounded reconciliation.
            process = None
            if request is not None:
                with request.lock:
                    request.abandoned.set()
                    process = request.process
            self._cancel_darwin_process_slot(token)
            if request is not None:
                with _DARWIN_LAUNCH_CONDITION:
                    if request in _DARWIN_LAUNCH_REQUESTS:
                        # The worker has not accepted this request, so remove
                        # it before the outer frame releases its governor token.
                        _DARWIN_LAUNCH_REQUESTS.remove(request)
                        worker_owned = False
                    else:
                        # The worker publishes acceptance while holding this
                        # same condition. A request missing from both states
                        # never crossed the publication boundary.
                        worker_owned = request.accepted.is_set()
                if not worker_owned and resources is not None:
                    _retire_darwin_launch_resources(resources)
                with request.lock:
                    process = request.process
            elif resources is not None:
                _retire_darwin_launch_resources(resources)
            if process is not None:
                self._quarantine_interrupted_darwin_launch(process)
            raise

    def _quarantine_interrupted_darwin_launch(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        has_containment = process in self._darwin_process_containments
        try:
            has_no_fork_proof = self._refresh_darwin_no_fork_proof(process)
        except BaseException:
            has_no_fork_proof = False
        # A child that has not transferred containment or a dynamic no-fork
        # proof can still be recovered safely, but must never be signalled by
        # numeric identity.  Its unreaped child PID pins the private session
        # identifier while observe-only reconciliation proves it empty.
        observe_only = not has_containment and not has_no_fork_proof
        self._retain_indeterminate_darwin_process(
            process,
            terminate=True,
            observe_only=observe_only,
        )

    def _restore_darwin_private_reconciliation(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        restart = False
        with _DARWIN_INDETERMINATE_LOCK:
            self._darwin_identity_lost.discard(process)
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            if state is not None and state[0] is self:
                _DARWIN_INDETERMINATE_PROCESSES[process] = (self, True, False, False)
                restart = True
        if restart:
            _start_darwin_indeterminate_reconciler()

    def _result_parent_guard(self, parent: Path) -> _PinnedPrivateDirectory:
        live = self._durable_result_guard
        if live is None:
            return _PinnedPrivateDirectory(parent)
        if live.path != parent or live.delete or live.share_delete:
            raise RunnerTransportError(
                "runner durable result guard cannot provide an exclusive watchdog handoff"
            )
        identity = live.directory_identity()
        mount_identity = live.directory_mount_identity()
        return _PinnedPrivateDirectory(
            parent,
            expected_identity=identity,
            expected_mount_identity=mount_identity,
        )

    def inventory(self) -> Mapping[str, Any]:
        output = self._invoke([str(self.runner_binary), "inventory", "--json"])
        return self._decode_json(output, "runner inventory")

    def execute(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
            request_root = Path(directory)
            manifest_path = request_root / "manifest.json"
            profile_path = request_root / "profile.json"
            manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
            output = self._invoke(
                [
                    str(self.runner_binary),
                    "execute",
                    "--manifest",
                    str(manifest_path),
                    "--profile",
                    str(profile_path),
                    "--json",
                ]
            )
        return self._validate_result(output, manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
    ) -> Mapping[str, Any]:
        """Run one task through an independent crash-surviving watchdog process."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if not callable(getattr(cancel_event, "is_set", None)):
            raise RunnerTransportError("runner cancellation signal is invalid")
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )

        destination, pending, handoff_guard = self._durable_paths(
            durable_result_path,
            task_id,
            retain_parent_guard=True,
        )
        if handoff_guard is None:
            raise AssertionError("durable result parent guard was not retained")
        watchdog: subprocess.Popen[bytes] | None = None
        spawned_watchdogs: list[subprocess.Popen[bytes]] = []
        cancellation_control: _CancellationControlLease | None = None
        cancellation_error: RunnerTaskCancelled | None = None
        control_root: Path | None = None
        try:
            receiver_environment = self._receiver_environment(
                task_id,
                action_id=manifest.get("action_id"),
            )
            control_root = runner_watchdog_control_root(destination, task_id)
            config_path = control_root / "config.json"
            start_path = control_root / "start"
            cancellation_control = self._prepare_cancellation_control(manifest, profile, task_id)
            result_parent_identity = handoff_guard.directory_identity()
            result_parent_mount_identity = handoff_guard.directory_mount_identity()
            self._prepare_watchdog_control(control_root)
            try:
                current_binary_digest = file_hash(self.runner_binary)
            except OSError:
                raise RunnerTransportError("Runner identity could not be verified.") from None
            if current_binary_digest != self.runner_binary_digest:
                raise RunnerTransportError("Runner identity changed after construction.")
            config = {
                "schema_version": "bluefire.runner-watchdog-config.v5",
                "task_id": task_id,
                "runner_binary": str(self.runner_binary),
                "runner_binary_digest": self.runner_binary_digest,
                "parent_death_script_digest": self.parent_death_script_digest,
                "watchdog_script_digest": self.watchdog_script_digest,
                "watchdog_interpreter": str(self._watchdog_interpreter),
                "watchdog_interpreter_digest": self._watchdog_interpreter_digest,
                "work_root": str(self.work_root),
                "timeout_seconds": self.timeout_seconds,
                "output_limit_bytes": self.output_limit_bytes,
                "durable_result_path": str(destination),
                "durable_result_parent_identity": list(result_parent_identity),
                "durable_result_parent_mount_identity": result_parent_mount_identity,
                "manifest": dict(manifest),
                "profile": dict(profile),
                "cancellation_lease_token": (
                    cancellation_control.token if cancellation_control is not None else None
                ),
            }
            self._write_private_control_file(
                config_path,
                canonical_json_bytes(config) + b"\n",
                maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
            )
            try:
                current_binary_digest = file_hash(self.runner_binary)
            except OSError:
                raise RunnerTransportError("Runner identity could not be verified.") from None
            if current_binary_digest != self.runner_binary_digest:
                raise RunnerTransportError("Runner identity changed before watchdog launch.")
            watchdog = self._spawn_watchdog(
                config_path,
                receiver_environment=receiver_environment,
                task_id=task_id,
                process_sink=spawned_watchdogs,
            )
            # `_spawn_watchdog` returns only after Windows job assignment. The
            # watchdog refuses to launch Rust until this exclusive gate exists.
            self._write_private_control_file(start_path, b"start\n", maximum=32)
            result = self._await_watchdog(
                watchdog,
                manifest=manifest,
                profile=profile,
                task_id=task_id,
                destination=destination,
                pending=pending,
                cancel_event=cancel_event,
            )
            if self._durable_result_guard is not None:
                try:
                    self._durable_result_guard.authorize_cleanup_entry(
                        destination.name,
                        maximum=self.output_limit_bytes,
                    )
                except (OSError, RunnerTransportError):
                    raise RunnerDurableResultExists(
                        "Runner durable result exists but its cleanup identity requires "
                        "reconciliation."
                    ) from None
            return result
        except RunnerTaskCancelled as exc:
            cancellation_error = exc
            raise
        except BaseException:
            if watchdog is None and spawned_watchdogs:
                watchdog = spawned_watchdogs[-1]
            if watchdog is not None and not self._process_exited_without_reap(watchdog):
                try:
                    request_runner_task_cancel(destination, task_id)
                except RunnerTransportError:
                    pass
                stop_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while (
                    not self._process_exited_without_reap(watchdog)
                    and time.monotonic() < stop_deadline
                ):
                    time.sleep(_PROCESS_POLL_SECONDS)
                if not self._process_exited_without_reap(watchdog):
                    if sys.platform == "darwin":
                        if not self._release_darwin_process_group(watchdog):
                            raise RunnerPendingResultExists(
                                "Runner watchdog containment is indeterminate and requires "
                                "reconciliation."
                            ) from None
                    elif os.name != "nt":
                        # The armed Rust child dies if its watchdog does, but an
                        # active watchdog can still commit a recoverable result.
                        # Preserve that authority until reconciliation.
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        ) from None
                    elif not self._terminate_process_tree(watchdog):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        ) from None
                elif os.name == "nt" and not self._finish_windows_job(watchdog):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
                elif os.name != "nt" and not self._finish_posix_process_group(watchdog):
                    raise RunnerTransportError(
                        "Runner watchdog containment could not be released"
                    ) from None
            raise
        finally:
            try:
                containment_released = watchdog is None
                if watchdog is not None and self._process_exited_without_reap(watchdog):
                    containment_released = (
                        self._finish_windows_job(watchdog)
                        if os.name == "nt"
                        else self._finish_posix_process_group(watchdog)
                    )
                cancellation_cleanup = cancellation_control is None
                if cancellation_control is not None:
                    if containment_released:
                        cancellation_cleanup = cancellation_control.cleanup()
                    else:
                        cancellation_control.close()
                if cancellation_error is not None:
                    cancellation_error.control_cleanup_verified = bool(
                        cancellation_error.control_cleanup_verified and cancellation_cleanup
                    )
                if containment_released and control_root is not None:
                    self._cleanup_watchdog_control(control_root)
            finally:
                handoff_guard.__exit__(*sys.exc_info())

    def _execute_task_locally(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
        receiver_environment: Mapping[str, str] | None = None,
        cooperative_request_event: threading.Event | None = None,
        cooperative_ack_event: threading.Event | None = None,
        runner_process_id_sink: list[int] | None = None,
        cancellation_lease_token: str | None = None,
        darwin_launch_started: Callable[[], None] | None = None,
        darwin_launch_sealed: Callable[[], None] | None = None,
    ) -> Mapping[str, Any]:
        """Watchdog-only fixed-runner execution and durable-result commit."""

        reject_forbidden_execution_keys(manifest)
        reject_forbidden_execution_keys(profile)
        if cancel_event.is_set():
            raise RunnerTaskCancelled(
                "Runner task did not start because cancellation was requested."
            )
        destination, pending, retained_guard = self._durable_paths(
            durable_result_path,
            task_id,
        )
        if retained_guard is not None:
            raise AssertionError("unexpected retained durable result parent guard")
        pending_identities: list[tuple[int, int]] = []
        try:
            with tempfile.TemporaryDirectory(prefix="request-", dir=self.work_root) as directory:
                request_root = Path(directory)
                manifest_path = request_root / "manifest.json"
                profile_path = request_root / "profile.json"
                manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
                profile_path.write_bytes(canonical_json_bytes(profile) + b"\n")
                output, pending_identity = self._invoke_task(
                    [
                        str(self.runner_binary),
                        "execute",
                        "--manifest",
                        str(manifest_path),
                        "--profile",
                        str(profile_path),
                        "--json",
                    ],
                    cancel_event=cancel_event,
                    pending_result_path=pending,
                    identity_sink=pending_identities,
                    receiver_environment=receiver_environment,
                    cooperative_request_event=cooperative_request_event,
                    cooperative_ack_event=cooperative_ack_event,
                    runner_process_id_sink=runner_process_id_sink,
                    cancellation_lease_token=cancellation_lease_token,
                    darwin_launch_started=darwin_launch_started,
                    darwin_launch_sealed=darwin_launch_sealed,
                )
            result = self._validate_result(output, manifest, profile)
            self._promote_pending_result(
                pending,
                destination,
                pending_expected=output,
                pending_identity=pending_identity,
                final_payload=canonical_json_bytes(dict(result)) + b"\n",
            )
            return result
        except (RunnerDurableResultExists, RunnerPendingResultExists):
            raise
        except BaseException:
            self._remove_pending_result(
                pending,
                expected_identity=(pending_identities[-1] if pending_identities else None),
            )
            raise

    @staticmethod
    def _prepare_watchdog_control(root: Path) -> None:
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            created = root.stat(follow_symlinks=False)
            with _PinnedPrivateDirectory(root, expected_identity=(created.st_dev, created.st_ino)):
                pass
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner watchdog state is unavailable") from None

    @staticmethod
    def _prepare_cancellation_control(
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
    ) -> _CancellationControlLease | None:
        if os.name != "nt" or manifest.get("action_id") != _CANCELLATION_ACTION_ID:
            return None
        request_hash = manifest.get("request_hash")
        expected_task_id = (
            "execute-" + request_hash.removeprefix("sha256:")
            if isinstance(request_hash, str) and _SHA256_DIGEST.fullmatch(request_hash)
            else None
        )
        sandbox_raw = profile.get("sandbox_root")
        if (
            manifest.get("behavior_id") != _CANCELLATION_ACTION_ID
            or manifest.get("params") != {}
            or manifest.get("platform") != "windows"
            or profile.get("platform") != "windows"
            or expected_task_id is None
            or not isinstance(request_hash, str)
            or task_id != expected_task_id
            or not isinstance(sandbox_raw, str)
        ):
            raise RunnerTransportError("runner cancellation control contract is invalid")

        sandbox_control: _PinnedPrivateDirectory | None = None
        parent_control: _PinnedPrivateDirectory | None = None
        task_control: _PinnedPrivateDirectory | None = None
        parent_created = False
        task_created = False
        parent_path: Path | None = None
        task_path: Path | None = None
        lease: _CancellationControlLease | None = None
        completed = False
        try:
            sandbox = Path(sandbox_raw)
            if not sandbox.is_absolute():
                raise OSError("cancellation sandbox is not absolute")
            sandbox = sandbox.resolve(strict=True)
            sandbox_control = _PinnedPrivateDirectory(sandbox)
            sandbox_control.__enter__()
            parent_path = sandbox / _CANCELLATION_CONTROL_PARENT
            if parent_path.exists():
                parent_control = _PinnedPrivateDirectory(parent_path)
                parent_control.__enter__()
            else:
                parent_path.mkdir(mode=0o700, parents=False, exist_ok=False)
                parent_created = True
                parent_control = _PinnedPrivateDirectory(parent_path)
                parent_control.__enter__()
            task_path = parent_path / request_hash.removeprefix("sha256:")
            task_path.mkdir(mode=0o700, parents=False, exist_ok=False)
            task_created = True
            task_control = _PinnedPrivateDirectory(task_path, delete=True)
            task_control.__enter__()
            if task_control.names(maximum=1):
                raise OSError("cancellation task is not empty")
            token = secrets.token_hex(32)
            lease = _CancellationControlLease(
                sandbox=sandbox_control,
                parent=parent_control,
                task=task_control,
                parent_created=parent_created,
                task_id=task_id,
                request_hash=request_hash,
                token=token,
            )
            task_control.create(
                _CANCELLATION_LEASE_NAME,
                f"lease:{token}\n".encode("ascii"),
                maximum=72,
            )
            completed = True
            return lease
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner cancellation state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner cancellation state is unavailable") from None
        finally:
            if not completed:
                if lease is not None:
                    lease.cleanup()
                    task_control = None
                    parent_control = None
                    sandbox_control = None
                elif task_control is not None:
                    try:
                        if not task_control.names(maximum=1):
                            task_control.remove()
                    except (OSError, RunnerTransportError):
                        pass
                    task_control.close()
                elif task_created and task_path is not None:
                    try:
                        task_path.rmdir()
                    except OSError:
                        pass
                if parent_control is not None:
                    if parent_created and parent_path is not None:
                        try:
                            if not parent_control.names(maximum=1):
                                parent_identity = parent_control.directory_identity()
                                parent_control.close()
                                with _PinnedPrivateDirectory(
                                    parent_path,
                                    delete=True,
                                    expected_identity=parent_identity,
                                ) as removable_parent:
                                    if not removable_parent.names(maximum=1):
                                        removable_parent.remove()
                        except (OSError, RunnerTransportError):
                            pass
                    parent_control.close()
                elif parent_created and parent_path is not None:
                    try:
                        parent_path.rmdir()
                    except OSError:
                        pass
                if sandbox_control is not None:
                    sandbox_control.close()

    @staticmethod
    def _write_private_control_file(path: Path, payload: bytes, *, maximum: int) -> None:
        if not 0 < len(payload) <= maximum:
            raise RunnerTransportError("runner watchdog state exceeds its size limit")
        try:
            with _PinnedPrivateDirectory(path.parent) as pinned:
                pinned.create(path.name, payload, maximum=maximum)
        except FileExistsError:
            raise RunnerPendingResultExists(
                "Runner watchdog state requires reconciliation before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner watchdog state is unavailable") from None

    def _receiver_environment(self, task_id: str, *, action_id: object) -> dict[str, str]:
        if not isinstance(task_id, str) or _TASK_IDENTIFIER.fullmatch(task_id) is None:
            raise RunnerTransportError("runner task identity is invalid")
        factory = self._receiver_task_key_factory
        if factory is None or action_id not in _RECEIVER_AUTH_ACTION_IDS:
            return {}
        try:
            task_key = factory(task_id)
        except BaseException:
            raise RunnerTransportError("runner receiver authentication is unavailable") from None
        if type(task_key) is not bytes or len(task_key) != 32:
            raise RunnerTransportError("runner receiver authentication is invalid")
        return _validated_receiver_task_environment(
            {
                _RECEIVER_TASK_ID_ENV: task_id,
                _RECEIVER_TASK_KEY_ENV: task_key.hex(),
            },
            expected_task_id=task_id,
        )

    def _spawn_watchdog(
        self,
        config_path: Path,
        *,
        receiver_environment: Mapping[str, str],
        task_id: str,
        process_sink: list[subprocess.Popen[bytes]],
    ) -> subprocess.Popen[bytes]:
        try:
            interpreter = self._watchdog_interpreter
            interpreter_digest = self._watchdog_interpreter_digest
            if file_hash(interpreter) != interpreter_digest:
                raise OSError("Python runtime identity changed")
        except OSError:
            raise RunnerTransportError("Runner watchdog runtime is unavailable") from None
        script = self.watchdog_script
        try:
            current_digest = file_hash(script)
        except OSError:
            raise RunnerTransportError("Packaged runner watchdog is unavailable") from None
        if current_digest != self.watchdog_script_digest:
            raise RunnerTransportError("Packaged runner watchdog identity changed")
        proof = _DarwinWatchdogProof() if sys.platform == "darwin" else None
        process: subprocess.Popen[bytes] | None = None
        try:
            with _pinned_launch_file(interpreter, interpreter_digest) as interpreter_launch:
                with _pinned_launch_file(
                    script,
                    self.watchdog_script_digest,
                    darwin_descriptor_backed=sys.platform == "darwin",
                ) as script_launch:
                    if proof is not None:
                        inherited_descriptors = (
                            interpreter_launch[1] + script_launch[1] + (proof.write_descriptor,)
                        )
                    else:
                        inherited_descriptors = interpreter_launch[1] + script_launch[1]
                    descriptor_indexes: tuple[int, ...]
                    if sys.platform == "darwin" and proof is not None:
                        watchdog_arguments = [
                            interpreter_launch[0],
                            "-I",
                            "-B",
                            "-X",
                            "utf8",
                            "-c",
                            _DARWIN_DESCRIPTOR_BOOTSTRAP,
                            script_launch[0],
                            str(script),
                            self.watchdog_script_digest,
                            str(config_path),
                            str(proof.write_descriptor),
                            proof.nonce,
                        ]
                        descriptor_indexes = (7, 11)
                    else:
                        watchdog_arguments = [
                            interpreter_launch[0],
                            "-I",
                            "-B",
                            "-X",
                            "utf8",
                            script_launch[0],
                            str(config_path),
                        ]
                        descriptor_indexes = ()
                    process = self._spawn(
                        watchdog_arguments,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        receiver_environment=receiver_environment,
                        inherited_descriptors=inherited_descriptors,
                        darwin_allow_fork=sys.platform == "darwin",
                        darwin_descriptor_argument_indexes=descriptor_indexes,
                        process_sink=process_sink,
                    )
                    if proof is not None:
                        self._darwin_watchdog_proofs[process] = proof
                    try:
                        self._await_watchdog_readiness(process, config_path.parent, task_id)
                    except BaseException:
                        if not self._terminate_process_tree(process):
                            raise RunnerTransportError(
                                "Runner watchdog process tree could not be stopped safely"
                            ) from None
                        raise
            return process
        finally:
            if proof is not None:
                try:
                    if process is None and process_sink:
                        process = process_sink[-1]
                    if process is not None:
                        self._darwin_watchdog_proofs[process] = proof
                    else:
                        proof.close_reader()
                finally:
                    proof.close_writer()

    def _await_watchdog_readiness(
        self,
        process: subprocess.Popen[bytes],
        control_root: Path,
        task_id: str,
    ) -> None:
        deadline = time.monotonic() + _WATCHDOG_START_GRACE_SECONDS
        while time.monotonic() < deadline:
            if self._process_exited_without_reap(process):
                raise RunnerTransportError("Runner watchdog exited before readiness")
            try:
                with _PinnedPrivateDirectory(control_root) as pinned:
                    payload = pinned.read("ready.json", maximum=4096)
                ready = SubprocessRustRunner._decode_json(payload, "runner watchdog readiness")
                watchdog_pid = ready.get("watchdog_pid")
                exact_shape = set(ready) == {
                    "schema_version",
                    "task_id",
                    "watchdog_pid",
                }
                exact_identity = (
                    type(watchdog_pid) is int
                    and 1 <= watchdog_pid <= 2**31 - 1
                    and watchdog_pid == process.pid
                )
                if (
                    exact_shape
                    and ready.get("schema_version") == "bluefire.runner-watchdog-ready.v1"
                    and ready.get("task_id") == task_id
                    and exact_identity
                ):
                    return
                raise RunnerTransportError("Runner watchdog readiness is invalid")
            except FileNotFoundError:
                time.sleep(_PROCESS_POLL_SECONDS)
            except OSError as exc:
                windows_error = getattr(exc, "winerror", None)
                if windows_error is None:
                    windows_error = exc.errno
                if os.name == "nt" and windows_error in {32, 33}:
                    time.sleep(_PROCESS_POLL_SECONDS)
                    continue
                raise RunnerTransportError("Runner watchdog readiness is unavailable") from None
        raise RunnerTransportError("Runner watchdog did not become ready")

    def _await_watchdog(
        self,
        process: subprocess.Popen[bytes],
        *,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        task_id: str,
        destination: Path,
        pending: Path,
        cancel_event: threading.Event,
    ) -> Mapping[str, Any]:
        deadline = (
            time.monotonic()
            + self.timeout_seconds
            + _WATCHDOG_START_GRACE_SECONDS
            + _WATCHDOG_EXIT_GRACE_SECONDS
        )
        cancellation_requested = False
        while True:
            if self._process_exited_without_reap(process):
                if os.name == "nt" and not self._finish_windows_job(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                break
            if cancel_event.is_set() and not cancellation_requested:
                request_runner_task_cancel(destination, task_id)
                cancellation_requested = True
            if time.monotonic() >= deadline:
                if not cancellation_requested:
                    request_runner_task_cancel(destination, task_id)
                    cancellation_requested = True
                grace_deadline = time.monotonic() + _WATCHDOG_EXIT_GRACE_SECONDS
                while (
                    not self._process_exited_without_reap(process)
                    and time.monotonic() < grace_deadline
                ):
                    time.sleep(_PROCESS_POLL_SECONDS)
                if not self._process_exited_without_reap(process):
                    if sys.platform == "darwin":
                        if not self._release_darwin_process_group(process):
                            raise RunnerPendingResultExists(
                                "Runner watchdog containment is indeterminate and requires "
                                "reconciliation."
                            )
                    elif os.name != "nt":
                        raise RunnerPendingResultExists(
                            "Runner watchdog remains active and requires reconciliation."
                        )
                    elif not self._terminate_process_tree(process):
                        raise RunnerTransportError(
                            "Runner watchdog process tree could not be stopped safely"
                        )
                if os.name == "nt" and not self._finish_windows_job(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                if os.name != "nt" and not self._finish_posix_process_group(process):
                    raise RunnerTransportError("Runner watchdog containment could not be released")
                raise RunnerTransportError("Runner watchdog exceeded its terminal deadline")
            time.sleep(_PROCESS_POLL_SECONDS)

        status_path = runner_watchdog_status_path(destination, task_id)
        status: Mapping[str, Any] | None = None
        try:
            with _PinnedPrivateDirectory(status_path.parent) as pinned:
                payload = pinned.read(status_path.name, maximum=4096)
            status = self._decode_json(payload, "runner watchdog status")
        except (OSError, RunnerTransportError):
            status = None
        if status is not None and (
            status.get("schema_version") != _WATCHDOG_STATUS_SCHEMA
            or status.get("task_id") != task_id
        ):
            status = None
        code = status.get("error_code") if status is not None else None
        state = status.get("state") if status is not None else None
        if code == "cancelled":
            expected_fields = {
                "schema_version",
                "task_id",
                "state",
                "error_code",
                "watchdog_pid",
                "cooperative_requested",
                "cooperative_acknowledged",
                "forced_tree_termination",
                "control_cleanup_verified",
            }
            requested = status.get("cooperative_requested") if status is not None else None
            acknowledged = status.get("cooperative_acknowledged") if status is not None else None
            forced = status.get("forced_tree_termination") if status is not None else None
            cleanup_verified = (
                status.get("control_cleanup_verified") if status is not None else None
            )
            if (
                status is None
                or set(status) != expected_fields
                or state != "cancelled"
                or type(requested) is not bool
                or type(acknowledged) is not bool
                or type(forced) is not bool
                or type(cleanup_verified) is not bool
                or (acknowledged and not requested)
            ):
                raise RunnerTransportError("runner cancellation proof is invalid")
            raise RunnerTaskCancelled(
                "Runner task was cancelled after its process tree stopped.",
                cooperative_requested=requested,
                cooperative_acknowledged=acknowledged,
                forced_tree_termination=forced,
                control_cleanup_verified=cleanup_verified,
            )
        if code == "timed_out":
            raise RunnerTaskTimedOut("Runner task timed out after its process tree stopped.")
        if code == "output_limit":
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if code == "durable_result_exists":
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            )
        pending_present = self._private_name_exists(pending)
        destination_present = self._private_name_exists(destination)
        if code == "pending_result_exists" or pending_present:
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            )
        if code == "unsupported_result_schema":
            raise RunnerTransportError("runner returned an unsupported result schema")
        if code == "invalid_json":
            raise RunnerTransportError("runner result is not valid UTF-8 JSON")
        if code == "invalid_result":
            raise RunnerTransportError("runner returned a result that did not match its request")
        if state == "succeeded" or (status is None and destination_present):
            output = self._read_private_result(destination)
            return self._validate_result(output, manifest, profile)
        raise RunnerTransportError("Runner watchdog failed before publishing a valid result")

    def _read_private_result(self, path: Path) -> bytes:
        try:
            with self._result_parent_guard(path.parent) as pinned:
                return pinned.read(path.name, maximum=self.output_limit_bytes)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    def _private_name_exists(self, path: Path) -> bool:
        try:
            with self._result_parent_guard(path.parent) as pinned:
                return pinned.has_name(path.name)
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result is unavailable") from None

    @staticmethod
    def _cleanup_watchdog_control(root: Path) -> None:
        try:
            with _PinnedPrivateDirectory(root, delete=True) as pinned:
                names = pinned.names()
                if any(name not in _WATCHDOG_CONTROL_NAMES for name in names):
                    return
                identities = {
                    name: pinned.file_identity(
                        name,
                        maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                        apply_permissions=False,
                    )
                    for name in names
                }
                for name, identity in identities.items():
                    pinned.unlink(
                        name,
                        maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                        expected_identity=identity,
                    )
                pinned.remove()
        except (OSError, RunnerTransportError):
            return

    def _validate_result(
        self,
        output: bytes,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        result = self._decode_json(output, "runner result")
        expected: dict[str, Any] = {"schema_version": "bluefire.runner-result.v1"}
        for field in (
            "request_id",
            "run_id",
            "step_id",
            "behavior_id",
            "action_id",
            "runner_id",
            "runner_profile_id",
            "platform",
            "request_hash",
            "policy_digest",
        ):
            if field in manifest:
                expected[field] = manifest[field]
        profile_bindings = {
            "runner_id": "runner_id",
            "runner_profile_id": "profile_id",
            "platform": "platform",
            "policy_digest": "policy_digest",
        }
        for result_field, profile_field in profile_bindings.items():
            if profile_field not in profile:
                continue
            profile_value = profile[profile_field]
            manifest_value = manifest.get(result_field)
            if result_field in manifest and manifest_value != profile_value:
                raise RunnerTransportError(
                    f"runner request {result_field} does not match its profile"
                )
            expected[result_field] = profile_value
        for field, value in expected.items():
            if result.get(field) != value:
                if field == "schema_version":
                    raise RunnerTransportError("runner returned an unsupported result schema")
                raise RunnerTransportError(f"runner result {field} does not match the request")
        return result

    def _invoke(self, argv: list[str]) -> bytes:
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        spawned_processes: list[subprocess.Popen[bytes]] = []
        process: subprocess.Popen[bytes] | None = None
        started_readers: list[threading.Thread] = []

        def drain(stream, destination: bytearray) -> None:
            if stream is None:
                return
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = self.output_limit_bytes - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()

        try:
            with _pinned_launch_file(self.runner_binary, self.runner_binary_digest) as launch:
                process = self._spawn(
                    [launch[0], *argv[1:]],
                    stdout=subprocess.PIPE,
                    inherited_descriptors=launch[1],
                    process_sink=spawned_processes,
                )
            readers = [
                threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
                threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
            ]
            for reader in readers:
                reader.start()
                started_readers.append(reader)
            return_code = self._monitor_process(process, overflow=overflow)
        except BaseException:
            if process is None and spawned_processes:
                process = spawned_processes[-1]
            if process is not None and not self._stop_process_tree(process):
                raise RunnerTransportError(
                    "Runner process tree could not be stopped safely"
                ) from None
            raise
        finally:
            for reader in started_readers:
                reader.join(timeout=_PROCESS_KILL_GRACE_SECONDS)

        if overflow.is_set():
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        # The runner deliberately uses 3 for policy refusal/control blocking
        # and 4 for an action-level failed/partial result. Both still carry a
        # valid, signed-by-content JSON TaskResult on stdout and must reach the
        # evidence layer intact. Exit code 2 (or anything unexpected) is a
        # transport/CLI failure.
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError(f"Rust runner exited with unexpected status {return_code}")
        return bytes(stdout)

    def _invoke_task(
        self,
        argv: list[str],
        *,
        cancel_event: threading.Event,
        pending_result_path: Path,
        identity_sink: list[tuple[int, int]],
        receiver_environment: Mapping[str, str] | None,
        cooperative_request_event: threading.Event | None,
        cooperative_ack_event: threading.Event | None,
        runner_process_id_sink: list[int] | None,
        cancellation_lease_token: str | None,
        darwin_launch_started: Callable[[], None] | None,
        darwin_launch_sealed: Callable[[], None] | None,
    ) -> tuple[bytes, tuple[int, int]]:
        output = self._open_pending_result(pending_result_path)
        guarded_output = cast(_GuardedBinaryFile, output)
        identity_sink.append(guarded_output.identity())
        stderr = bytearray()
        overflow = threading.Event()
        process: subprocess.Popen[bytes] | None = None
        spawned_processes: list[subprocess.Popen[bytes]] = []
        try:
            with _pinned_launch_file(
                self.runner_binary,
                self.runner_binary_digest,
            ) as launch:
                if darwin_launch_started is not None:
                    darwin_launch_started()
                process = self._spawn(
                    [launch[0], *argv[1:]],
                    stdout=output,
                    receiver_environment=receiver_environment,
                    cancellation_lease_token=cancellation_lease_token,
                    inherited_descriptors=launch[1],
                    process_sink=spawned_processes,
                )
                if darwin_launch_sealed is not None:
                    darwin_launch_sealed()
            if runner_process_id_sink is not None:
                if runner_process_id_sink:
                    raise RunnerTransportError("runner process identity sink is not empty")
                runner_process_id_sink.append(process.pid)

            def drain_stderr(stream: BinaryIO | None) -> None:
                if stream is None:
                    return
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    remaining = self.output_limit_bytes - len(stderr)
                    if remaining > 0:
                        stderr.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()

            reader = threading.Thread(
                target=drain_stderr,
                args=(process.stderr,),
                name="bluefire-runner-stderr",
                daemon=True,
            )
            reader.start()
            try:
                return_code = self._monitor_process(
                    process,
                    cancel_event=cancel_event,
                    overflow=overflow,
                    output_descriptor=output.fileno(),
                    cooperative_request_event=cooperative_request_event,
                    cooperative_ack_event=cooperative_ack_event,
                )
            finally:
                reader.join(timeout=_PROCESS_KILL_GRACE_SECONDS)
            output.flush()
            os.fsync(output.fileno())
            guarded_output.validate_identity()
            pending_identity = guarded_output.identity()
            output.seek(0)
            result_output = output.read(self.output_limit_bytes + 1)
        except BaseException as exc:
            if process is None and spawned_processes:
                process = spawned_processes[-1]
            if process is not None and not self._stop_process_tree(process):
                raise RunnerTransportError(
                    "Runner process tree could not be stopped safely"
                ) from None
            if isinstance(exc, RunnerTransportError):
                raise
            if isinstance(exc, OSError):
                raise RunnerTransportError("Rust runner transport failed") from None
            raise
        finally:
            output.close()

        if overflow.is_set() or len(result_output) > self.output_limit_bytes:
            raise RunnerTransportError("Rust runner exceeded the transport output limit")
        if return_code not in {0, 3, 4}:
            raise RunnerTransportError("Rust runner exited with an unexpected status")
        return result_output, pending_identity

    def _spawn_linux_parent_death(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None,
        environment: Mapping[str, str],
        inherited_descriptors: tuple[int, ...],
        options: Mapping[str, Any],
    ) -> subprocess.Popen[bytes]:
        if not sys.platform.startswith("linux") or not hasattr(socket, "SOCK_SEQPACKET"):
            raise RunnerTransportError("Linux parent-death containment is unavailable")
        target_match = re.fullmatch(r"/(?:proc/self|dev)/fd/([0-9]+)", argv[0])
        target_descriptor = int(target_match.group(1)) if target_match is not None else -1
        if target_descriptor not in inherited_descriptors:
            raise RunnerTransportError("Linux parent-death target is not descriptor-bound")
        try:
            runtime = self._watchdog_interpreter
            runtime_digest = self._watchdog_interpreter_digest
            if file_hash(runtime) != runtime_digest:
                raise OSError("parent-death runtime identity changed")
            if file_hash(self.parent_death_script) != self.parent_death_script_digest:
                raise OSError("parent-death helper identity changed")
            parent_socket, child_socket = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
            )
            parent_socket.settimeout(_WATCHDOG_START_GRACE_SECONDS)
        except OSError:
            raise RunnerTransportError("Linux parent-death containment is unavailable") from None
        process: subprocess.Popen[bytes] | None = None
        nonce = secrets.token_hex(32)
        try:
            with _pinned_launch_file(runtime, runtime_digest) as interpreter_launch:
                with _pinned_launch_file(
                    self.parent_death_script,
                    self.parent_death_script_digest,
                ) as helper_launch:
                    helper_descriptors = interpreter_launch[1] + helper_launch[1]
                    pass_fds = tuple(
                        sorted(
                            set(inherited_descriptors + helper_descriptors)
                            | {child_socket.fileno()}
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
                        cwd=self.work_root,
                        env=dict(environment),
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        **launch_options,
                    )
                    child_socket.close()
                    armed = parent_socket.recv(256)
                    expected = f"armed-v1:{nonce}:{process.pid}:{os.getpid()}".encode("ascii")
                    if (
                        armed != expected
                        or not callable(_GET_PROCESS_GROUP_ID)
                        or not callable(_GET_SESSION_ID)
                        or _GET_PROCESS_GROUP_ID(process.pid) != os.getpid()
                        or _GET_SESSION_ID(process.pid) != os.getpid()
                    ):
                        raise OSError("parent-death handshake is invalid")
                    parent_socket.sendall(f"go-v1:{nonce}".encode("ascii"))
                    if parent_socket.recv(256) != b"":
                        raise OSError("parent-death target execution failed")
            return process
        except (OSError, socket.timeout):
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
                except (OSError, subprocess.SubprocessError):
                    pass
            raise RunnerTransportError("Linux parent-death containment failed") from None
        finally:
            parent_socket.close()
            child_socket.close()

    def _spawn_darwin_parent_death(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None,
        environment: Mapping[str, str],
        inherited_descriptors: tuple[int, ...],
        options: Mapping[str, Any],
        darwin_slot: object,
        process_sink: list[subprocess.Popen[bytes]],
    ) -> subprocess.Popen[bytes]:
        failed_processes: list[tuple[subprocess.Popen[bytes], DarwinProcessContainment]] = []

        def registered_popen(
            arguments: list[str], **launch_options: Any
        ) -> subprocess.Popen[bytes]:
            return self._spawn_registered_darwin_popen(
                darwin_slot,
                process_sink,
                arguments,
                **launch_options,
            )

        try:
            process, containment = spawn_darwin_parent_death(
                argv,
                stdout=stdout,
                stderr=stderr,
                environment=environment,
                inherited_descriptors=inherited_descriptors,
                options=options,
                runner_binary=self.runner_binary,
                runner_binary_digest=self.runner_binary_digest,
                work_root=self.work_root,
                watchdog_interpreter=self._watchdog_interpreter,
                watchdog_interpreter_digest=self._watchdog_interpreter_digest,
                parent_death_script=self.parent_death_script,
                parent_death_script_digest=self.parent_death_script_digest,
                pinned_launch_file=_pinned_launch_file,
                start_grace_seconds=_WATCHDOG_START_GRACE_SECONDS,
                execution_timeout_seconds=self.timeout_seconds,
                failure_sink=failed_processes,
                popen_factory=registered_popen,
            )
        except BaseException:
            if failed_processes:
                failed_process, failed_containment = failed_processes[-1]
                self._darwin_process_containments[failed_process] = failed_containment
                self._restore_darwin_private_reconciliation(failed_process)
            raise
        self._darwin_process_containments[process] = containment
        return process

    def _spawn_darwin_no_fork_exec(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None,
        environment: Mapping[str, str],
        inherited_descriptors: tuple[int, ...],
        options: Mapping[str, Any],
        darwin_slot: object,
        process_sink: list[subprocess.Popen[bytes]],
    ) -> subprocess.Popen[bytes]:
        proven_processes: list[subprocess.Popen[bytes]] = []

        def registered_popen(
            arguments: list[str],
            **launch_options: Any,
        ) -> subprocess.Popen[bytes]:
            return self._spawn_registered_darwin_popen(
                darwin_slot,
                process_sink,
                arguments,
                **launch_options,
            )

        try:
            return spawn_darwin_no_fork_exec(
                argv,
                stdout=stdout,
                stderr=stderr,
                environment=environment,
                inherited_descriptors=inherited_descriptors,
                options=options,
                runner_binary=self.runner_binary,
                runner_binary_digest=self.runner_binary_digest,
                work_root=self.work_root,
                watchdog_interpreter=self._watchdog_interpreter,
                watchdog_interpreter_digest=self._watchdog_interpreter_digest,
                parent_death_script=self.parent_death_script,
                parent_death_script_digest=self.parent_death_script_digest,
                pinned_launch_file=_pinned_launch_file,
                start_grace_seconds=_WATCHDOG_START_GRACE_SECONDS,
                popen_factory=registered_popen,
                proof_sink=proven_processes,
                proof_callback=self._darwin_no_fork_proven.add,
            )
        finally:
            for proven in proven_processes:
                self._darwin_no_fork_proven.add(proven)

    @staticmethod
    def _linux_process_identity(process_id: int) -> tuple[int, int, int, int]:
        try:
            payload = (Path("/proc") / str(process_id) / "stat").read_bytes()
        except FileNotFoundError:
            raise ProcessLookupError(process_id) from None
        except OSError:
            raise RunnerTransportError("Linux process identity is unavailable") from None
        close = payload.rfind(b")")
        fields = payload[close + 2 :].split() if 0 < close < len(payload) - 2 else []
        try:
            identity = (
                process_id,
                int(fields[19]),
                int(fields[2]),
                int(fields[3]),
            )
        except (IndexError, ValueError):
            raise RunnerTransportError("Linux process identity is invalid") from None
        if (
            not 0 < len(payload) <= 4096
            or identity[0] <= 0
            or identity[1] <= 0
            or identity[2] < 0
            or identity[3] < 0
        ):
            raise RunnerTransportError("Linux process identity is invalid")
        return identity

    def _register_linux_private_process(self, process: subprocess.Popen[bytes]) -> None:
        descriptor = -1
        try:
            if not callable(_PIDFD_OPEN):
                raise OSError("pidfd_open unavailable")
            before = self._linux_process_identity(process.pid)
            descriptor = int(_PIDFD_OPEN(process.pid, 0))
            after = self._linux_process_identity(process.pid)
            if before != after or before[2:] != (process.pid, process.pid):
                raise OSError("private process identity mismatch")
            self._linux_process_containments[process] = (*before, descriptor)
            descriptor = -1
        except (OSError, ProcessLookupError, RunnerTransportError):
            try:
                process.kill()
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except (OSError, subprocess.SubprocessError):
                pass
            raise RunnerTransportError("Linux private process containment is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _complete_verified_darwin_release(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        """Finish a reap only after an empty Darwin identity was published."""

        if process not in self._darwin_release_verified:
            return False
        with _DARWIN_INDETERMINATE_LOCK:
            if process in self._darwin_reap_indeterminate:
                if process.returncode is None:
                    self._darwin_identity_lost.add(process)
                    self._retain_indeterminate_darwin_process(
                        process,
                        identity_lost=True,
                    )
                    return False
                self._released_darwin_processes.add(process)
                self._darwin_reap_indeterminate.discard(process)
                return True
            if process.returncode is not None:
                self._released_darwin_processes.add(process)
                return True
            # Publish fail-closed state before waitpid can reap. If an
            # arbitrary BaseException lands before Popen publishes
            # returncode, no later call may wait on the reusable numeric PID.
            if (
                _DARWIN_ACTIVE_PROCESSES.get(process) is self
                and process not in _DARWIN_INDETERMINATE_PROCESSES
            ):
                _DARWIN_INDETERMINATE_PROCESSES[process] = (
                    self,
                    False,
                    False,
                    False,
                )
                _DARWIN_RECONCILER_WAKE.set()
            self._darwin_reap_indeterminate.add(process)
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                self._darwin_reap_indeterminate.discard(process)
                return False
            if process.returncode is None:
                self._darwin_identity_lost.add(process)
                self._retain_indeterminate_darwin_process(
                    process,
                    identity_lost=True,
                )
                return False
            self._released_darwin_processes.add(process)
            self._darwin_reap_indeterminate.discard(process)
            return True

    def _close_darwin_process_containment(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        containment = self._darwin_process_containments.get(process)
        if containment is None:
            return True
        try:
            containment.parent_lease.close()
        except OSError:
            return False
        self._darwin_process_containments.pop(process, None)
        return True

    def _process_exited_without_reap(
        self,
        process: subprocess.Popen[bytes],
        *,
        _reconciling: bool = False,
    ) -> bool:
        if process in self._released_linux_processes:
            return process.returncode is not None
        if process in self._released_darwin_processes:
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return process.returncode is not None
        if sys.platform == "darwin" and self._complete_verified_darwin_release(process):
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return True
        containment = self._linux_process_containments.get(process)
        if containment is None and sys.platform == "darwin":
            darwin_private = process in self._darwin_process_containments
            if process in self._darwin_identity_lost:
                return False
            if self._darwin_process_is_indeterminate(process) and not _reconciling:
                return False
            if process.returncode is not None:
                if darwin_private:
                    return True
                self._darwin_identity_lost.add(process)
                self._retain_indeterminate_darwin_process(process, identity_lost=True)
                return False
            try:
                return _darwin_child_exited_without_reap(process.pid)
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    return False
                if not darwin_private:
                    # Once non-reaping child observation fails, a numeric PGID
                    # may be reusable. Quarantine it permanently without any
                    # signal attempt; the global slot governor bounds fallout.
                    self._darwin_identity_lost.add(process)
                    self._retain_indeterminate_darwin_process(process, identity_lost=True)
                return False
            except ChildProcessError:
                if not darwin_private:
                    self._darwin_identity_lost.add(process)
                    self._retain_indeterminate_darwin_process(process, identity_lost=True)
                return False
        if containment is None:
            return process.poll() is not None
        if (
            not callable(_WAIT_ID)
            or _PIDFD_ID_TYPE is None
            or not _WAIT_EXITED
            or not _WAIT_NO_HANG
            or not _WAIT_NO_REAP
        ):
            raise RunnerTransportError("Linux unreaped process observation is unavailable")
        try:
            observed = _WAIT_ID(
                _PIDFD_ID_TYPE,
                containment[4],
                _WAIT_EXITED | _WAIT_NO_HANG | _WAIT_NO_REAP,
            )
        except (ChildProcessError, OSError):
            raise RunnerTransportError("Linux process was reaped before containment") from None
        if observed is None:
            return False
        if int(getattr(observed, "si_pid", 0)) != process.pid:
            raise RunnerTransportError("Linux exit identity is invalid")
        return True

    def _spawn(
        self,
        argv: list[str],
        *,
        stdout: int | BinaryIO | None,
        stderr: int | BinaryIO | None = subprocess.PIPE,
        receiver_environment: Mapping[str, str] | None = None,
        cancellation_lease_token: str | None = None,
        inherited_descriptors: tuple[int, ...] = (),
        darwin_allow_fork: bool = False,
        darwin_descriptor_argument_indexes: tuple[int, ...] = (),
        process_sink: list[subprocess.Popen[bytes]],
    ) -> subprocess.Popen[bytes]:
        if process_sink:
            raise RunnerTransportError("runner process ownership sink is not empty")
        if sys.platform == "darwin" and not _darwin_child_status_ownership_available():
            raise RunnerTransportError("Darwin child status ownership is unavailable")
        darwin_slot: object | None = object() if sys.platform == "darwin" else None
        environment: dict[str, str] = {"LC_ALL": "C", "LANG": "C"}
        environment.update(_validated_receiver_task_environment(receiver_environment))
        if cancellation_lease_token is not None:
            if _RECEIVER_TASK_KEY.fullmatch(cancellation_lease_token) is None:
                raise RunnerTransportError("runner cancellation lease is invalid")
            environment[_CANCELLATION_LEASE_ENV] = cancellation_lease_token
        options: dict[str, Any] = {}
        windows_job: int | None = None
        windows_suspended = False
        process: subprocess.Popen[bytes] | None = None
        if os.name == "nt":
            system_directory = self._windows_system_directory()
            windows_root = system_directory.parent
            environment.update(
                {
                    "SYSTEMROOT": str(windows_root),
                    "WINDIR": str(windows_root),
                    "TEMP": str(self.work_root),
                    "TMP": str(self.work_root),
                }
            )
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
            if self._kill_child_on_job_close:
                # The inner Rust process must not execute even one instruction
                # until it is a member of the watchdog-owned kill-on-close Job.
                options["creationflags"] |= getattr(subprocess, "CREATE_SUSPENDED", 0x0000_0004)
                windows_suspended = True
            windows_job = self._create_windows_job()
        else:
            if self._kill_child_on_job_close:
                try:
                    private_session = bool(
                        callable(_GET_PROCESS_GROUP)
                        and callable(_GET_SESSION_ID)
                        and _GET_PROCESS_GROUP() == os.getpid() == _GET_SESSION_ID(0)
                    )
                except OSError:
                    private_session = False
                if not private_session:
                    raise RunnerTransportError("POSIX watchdog process containment is unavailable")
                # The watchdog is already the leader of a private session and
                # group. Its child inherits both and arms a kernel parent-death
                # signal before the verified runner inode executes.
            else:
                if sys.platform.startswith("linux") and (
                    not callable(_PIDFD_OPEN)
                    or not callable(_PIDFD_SEND_SIGNAL)
                    or not callable(_WAIT_ID)
                    or _PIDFD_ID_TYPE is None
                    or not _WAIT_EXITED
                    or not _WAIT_NO_HANG
                    or not _WAIT_NO_REAP
                ):
                    raise RunnerTransportError("Linux private process containment is unavailable")
                options["start_new_session"] = True
            options["pass_fds"] = inherited_descriptors
            if sys.platform == "darwin" and darwin_descriptor_argument_indexes:
                options["_bluefire_descriptor_argument_indexes"] = (
                    darwin_descriptor_argument_indexes
                )
        try:
            if darwin_slot is not None and not self._reserve_darwin_process_slot(darwin_slot):
                raise RunnerTransportError("Darwin process containment capacity is exhausted")
            # argv[0] is a validated absolute executable path and the grammar is fixed.
            if (
                self._kill_child_on_job_close
                and os.name != "nt"
                and sys.platform.startswith("linux")
            ):
                process = self._spawn_linux_parent_death(
                    argv,
                    stdout=stdout,
                    stderr=stderr,
                    environment=environment,
                    inherited_descriptors=inherited_descriptors,
                    options=options,
                )
            elif self._kill_child_on_job_close and sys.platform == "darwin":
                if darwin_slot is None:
                    raise AssertionError("Darwin process reservation is unavailable")
                process = self._spawn_darwin_parent_death(
                    argv,
                    stdout=stdout,
                    stderr=stderr,
                    environment=environment,
                    inherited_descriptors=inherited_descriptors,
                    options=options,
                    darwin_slot=darwin_slot,
                    process_sink=process_sink,
                )
            elif self._kill_child_on_job_close and os.name != "nt":
                raise RunnerTransportError("POSIX parent-death containment is unavailable")
            elif sys.platform == "darwin":
                if darwin_slot is None:
                    raise AssertionError("Darwin process reservation is unavailable")
                if darwin_allow_fork:
                    process = self._spawn_registered_darwin_popen(
                        darwin_slot,
                        process_sink,
                        argv,
                        cwd=self.work_root,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        **options,
                    )
                else:
                    process = self._spawn_darwin_no_fork_exec(
                        argv,
                        stdout=stdout,
                        stderr=stderr,
                        environment=environment,
                        inherited_descriptors=inherited_descriptors,
                        options=options,
                        darwin_slot=darwin_slot,
                        process_sink=process_sink,
                    )
            else:
                process = subprocess.Popen(  # nosec B603
                    argv,
                    cwd=self.work_root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    **options,
                )
            if darwin_slot is not None:
                self._register_darwin_process_slot(darwin_slot, process)
                darwin_slot = None
            if (
                os.name != "nt"
                and sys.platform.startswith("linux")
                and not self._kill_child_on_job_close
            ):
                self._register_linux_private_process(process)
            if windows_job is not None:
                self._assign_windows_job(windows_job, process)
                windows_job = None  # ownership moved to `_windows_jobs`
            if windows_suspended:
                try:
                    self._resume_windows_process(process)
                except RunnerTransportError:
                    if not self._terminate_windows_process_tree(process):
                        raise RunnerTransportError(
                            "Windows process containment could not stop a suspended child"
                        ) from None
                    raise
            if not process_sink:
                process_sink.append(process)
            elif process_sink[-1] is not process:
                raise AssertionError("runner process ownership sink is invalid")
            return process
        except (OSError, ValueError):
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise RunnerTransportError("Rust runner could not be started") from None
        except RunnerTransportError:
            if windows_job is not None:
                self._close_windows_handle(windows_job)
            raise
        except BaseException:
            if sys.platform == "darwin" and process is not None:
                if darwin_slot is not None:
                    self._register_darwin_process_slot(darwin_slot, process)
                    darwin_slot = None
                self._quarantine_interrupted_darwin_launch(process)
            raise
        finally:
            if darwin_slot is not None:
                if process is None and process_sink:
                    process = process_sink[-1]
                if process is None:
                    self._cancel_darwin_process_slot(darwin_slot)
                else:
                    self._register_darwin_process_slot(darwin_slot, process)
                    self._quarantine_interrupted_darwin_launch(process)

    def _monitor_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        cancel_event: threading.Event | None = None,
        overflow: threading.Event,
        output_descriptor: int | None = None,
        cooperative_request_event: threading.Event | None = None,
        cooperative_ack_event: threading.Event | None = None,
    ) -> int:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            if self._process_exited_without_reap(process):
                released = (
                    self._finish_windows_job(process)
                    if os.name == "nt"
                    else self._finish_posix_process_group(process)
                )
                if not released and self._kill_child_on_job_close:
                    if sys.platform == "darwin":
                        self._retain_indeterminate_darwin_process(process, terminate=True)
                    else:
                        self._retain_failed_process_tree(process)
                        released = True
                if not released:
                    raise RunnerTransportError("Runner process tree state could not be released")
                if process.returncode is None:
                    raise RunnerTransportError("Runner process exit status is unavailable")
                return process.returncode
            output_unsafe = False
            if output_descriptor is not None:
                try:
                    details = os.fstat(output_descriptor)
                    output_unsafe = (
                        not stat.S_ISREG(details.st_mode)
                        or details.st_nlink != 1
                        or details.st_size > self.output_limit_bytes
                    )
                except OSError:
                    output_unsafe = True
            if overflow.is_set() or output_unsafe:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner exceeded the transport output limit")
            if cancel_event is not None and cancel_event.is_set():
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTaskCancelled(
                    "Runner task was cancelled after its process tree stopped.",
                    cooperative_requested=(
                        cooperative_request_event is not None and cooperative_request_event.is_set()
                    ),
                    cooperative_acknowledged=(
                        cooperative_ack_event is not None and cooperative_ack_event.is_set()
                    ),
                    forced_tree_termination=True,
                )
            if time.monotonic() >= deadline:
                if not self._stop_process_tree(process):
                    raise RunnerTransportError("Runner process tree could not be stopped safely")
                raise RunnerTransportError("Rust runner transport timed out")
            time.sleep(_PROCESS_POLL_SECONDS)

    def _stop_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        """Stop a tree, retaining watchdog containment until emptiness is certain."""

        if self._terminate_process_tree(process):
            return True
        if not self._kill_child_on_job_close:
            return False
        if sys.platform == "darwin":
            self._retain_indeterminate_darwin_process(process, terminate=True)
            return False
        self._retain_failed_process_tree(process)
        return True

    def _retain_failed_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        """Fail closed while a watchdog-owned Job or process group is unresolved.

        This intentionally has no local deadline.  The request host can still
        cancel the outer watchdog containment on Windows; on POSIX it leaves the
        watchdog running as indeterminate recovery state.  Publishing a terminal
        task status while Rust descendants remain unconfirmed would be unsafe.
        """

        while not self._terminate_process_tree(process):
            time.sleep(_PROCESS_POLL_SECONDS)

    def _terminate_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name == "nt":
            return self._terminate_windows_process_tree(process)
        return self._terminate_posix_process_tree(process)

    @staticmethod
    def _posix_process_group_exists(process_group: int) -> bool:
        if not callable(_KILL_PROCESS_GROUP):
            return False
        try:
            _KILL_PROCESS_GROUP(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _terminate_posix_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if process in self._released_linux_processes:
            return process.returncode is not None
        if process in self._released_darwin_processes:
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return process.returncode is not None
        if self._kill_child_on_job_close:
            return self._terminate_inherited_posix_process_tree(process)
        if process in self._linux_process_containments:
            return self._release_linux_private_process(process, terminate=True)
        if sys.platform == "darwin":
            return self._release_darwin_process_group(process)
        if not callable(_KILL_PROCESS_GROUP):
            return False
        process_group = process.pid
        try:
            _KILL_PROCESS_GROUP(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= graceful_deadline:
                break
            process.poll()
            time.sleep(_PROCESS_POLL_SECONDS)
        if self._posix_process_group_exists(process_group):
            try:
                _KILL_PROCESS_GROUP(process_group, _FORCE_KILL_SIGNAL)
            except ProcessLookupError:
                pass
            except OSError:
                return False
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False
        stopped_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
        while self._posix_process_group_exists(process_group):
            if time.monotonic() >= stopped_deadline:
                return False
            time.sleep(_PROCESS_POLL_SECONDS)
        return process.poll() is not None

    def _drain_darwin_process_group(
        self,
        process: subprocess.Popen[bytes],
        *,
        _reconciling: bool = False,
    ) -> bool:
        """Terminate one private Darwin group while its child leader pins the PGID."""

        if self._complete_verified_darwin_release(process):
            return True
        if process in self._darwin_identity_lost:
            return False
        if self._darwin_process_is_indeterminate(process) and not _reconciling:
            return False
        if not self._refresh_darwin_no_fork_proof(process):
            return False
        if process.returncode is not None:
            self._darwin_identity_lost.add(process)
            self._retain_indeterminate_darwin_process(process, identity_lost=True)
            return False
        process_group = process.pid
        graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        final_deadline = graceful_deadline + _PROCESS_KILL_GRACE_SECONDS
        termination_sent = False
        force_sent = False
        empty_inventories = 0
        while True:
            try:
                leader_exited = self._process_exited_without_reap(
                    process,
                    _reconciling=_reconciling,
                )
            except RunnerTransportError:
                return False
            if process in self._darwin_identity_lost:
                return False
            members = _darwin_private_process_group_members(process_group, process_group)
            session_members = _darwin_private_session_members(process_group)
            if members is None or session_members is None:
                return False
            other_members = members - {process_group}
            other_session_members = session_members - {process_group}
            if leader_exited and not other_members and not other_session_members:
                empty_inventories += 1
                if empty_inventories >= _DARWIN_EMPTY_INVENTORY_CONFIRMATIONS:
                    self._darwin_release_verified.add(process)
                    return self._complete_verified_darwin_release(process)
                time.sleep(_PROCESS_POLL_SECONDS)
                continue
            empty_inventories = 0

            now = time.monotonic()
            if now >= final_deadline:
                return False
            if leader_exited and not other_members:
                time.sleep(_PROCESS_POLL_SECONDS)
                continue
            if not callable(_KILL_PROCESS_GROUP):
                return False
            signum: int | None = None
            if not termination_sent:
                signum = signal.SIGTERM
                termination_sent = True
            elif now >= graceful_deadline and not force_sent:
                signum = _FORCE_KILL_SIGNAL
                force_sent = True
            if signum is not None:
                try:
                    # The unreaped direct child keeps this same-numbered PGID
                    # unavailable for reuse until the inventory is empty.
                    _KILL_PROCESS_GROUP(process_group, signum)
                except ProcessLookupError:
                    # A member may have exited after inventory.  Re-inventory
                    # while the unreaped child still pins the identifier.
                    pass
                except OSError:
                    return False
            time.sleep(_PROCESS_POLL_SECONDS)

    def _release_darwin_process_group(self, process: subprocess.Popen[bytes]) -> bool:
        """Drain once or retain the Popen identity as bounded indeterminate state."""

        if process in self._released_darwin_processes:
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return process.returncode is not None
        if self._darwin_process_is_indeterminate(process):
            self._retain_indeterminate_darwin_process(process)
            return False
        if self._drain_darwin_process_group(process):
            self._drop_owned_darwin_process(process)
            return True
        self._retain_indeterminate_darwin_process(process)
        return False

    def _retain_indeterminate_darwin_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: bool = False,
        identity_lost: bool = False,
        observe_only: bool = False,
    ) -> bool:
        start_reconciler = False
        with _DARWIN_INDETERMINATE_LOCK:
            active_owner = _DARWIN_ACTIVE_PROCESSES.get(process)
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            if active_owner is not self or (state is not None and state[0] is not self):
                return False
            if state is not None:
                terminate = bool(terminate or state[1])
                identity_lost = bool(identity_lost or state[2])
                observe_only = bool(observe_only or state[3])
            _DARWIN_INDETERMINATE_PROCESSES[process] = (
                self,
                terminate,
                identity_lost,
                observe_only,
            )
            start_reconciler = not identity_lost
        if start_reconciler:
            _start_darwin_indeterminate_reconciler()
        return True

    def _drop_indeterminate_darwin_process(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        with _DARWIN_INDETERMINATE_LOCK:
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            if state is not None and state[0] is self:
                _DARWIN_INDETERMINATE_PROCESSES.pop(process, None)

    def _reconcile_indeterminate_darwin_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: bool,
        observe_only: bool = False,
    ) -> bool:
        with _DARWIN_INDETERMINATE_LOCK:
            state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
            if state is None or state[0] is not self or state[2]:
                return False
            terminate = bool(terminate or state[1])
            observe_only = bool(observe_only or state[3])
        if observe_only:
            has_containment = process in self._darwin_process_containments
            try:
                has_no_fork_proof = self._refresh_darwin_no_fork_proof(process)
            except BaseException:
                has_no_fork_proof = False
            if has_containment or has_no_fork_proof:
                with _DARWIN_INDETERMINATE_LOCK:
                    state = _DARWIN_INDETERMINATE_PROCESSES.get(process)
                    if state is None or state[0] is not self or state[2]:
                        return False
                    terminate = bool(terminate or state[1])
                    _DARWIN_INDETERMINATE_PROCESSES[process] = (
                        self,
                        terminate,
                        False,
                        False,
                    )
                    observe_only = False
        if self._complete_verified_darwin_release(process):
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return True
        containment = self._darwin_process_containments.get(process)
        if observe_only:
            released = self._reconcile_observe_only_darwin_process(process)
        elif containment is None:
            released = self._drain_darwin_process_group(process, _reconciling=True)
        else:
            released = release_darwin_process(
                process,
                containment,
                terminate=terminate,
                child_exited_without_reap=_darwin_child_exited_without_reap,
                release_verified=self._darwin_release_verified.add,
            )
            if released:
                released = self._complete_verified_darwin_release(process)
                if released:
                    released = self._close_darwin_process_containment(process)
        if released:
            self._drop_owned_darwin_process(process)
        return bool(released)

    def _reconcile_observe_only_darwin_process(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        """Reap a lease-closed helper without ever signaling a numeric identity."""

        if self._complete_verified_darwin_release(process):
            return True

        session_id = os.getpid() if self._kill_child_on_job_close else process.pid
        try:
            if self._kill_child_on_job_close and (
                not callable(_GET_SESSION_ID) or _GET_SESSION_ID(0) != session_id
            ):
                return False
            exited = _darwin_child_exited_without_reap(process.pid)
        except OSError as exc:
            if exc.errno == errno.EINTR:
                return False
            self._darwin_identity_lost.add(process)
            self._retain_indeterminate_darwin_process(
                process,
                terminate=True,
                identity_lost=True,
                observe_only=True,
            )
            return False
        except ChildProcessError:
            self._darwin_identity_lost.add(process)
            self._retain_indeterminate_darwin_process(
                process,
                terminate=True,
                identity_lost=True,
                observe_only=True,
            )
            return False
        if not exited:
            return False
        for confirmation in range(_DARWIN_EMPTY_INVENTORY_CONFIRMATIONS):
            members = _darwin_private_session_members(session_id)
            if members is None or members - {session_id, process.pid}:
                return False
            if confirmation + 1 < _DARWIN_EMPTY_INVENTORY_CONFIRMATIONS:
                time.sleep(_PROCESS_POLL_SECONDS)
        self._darwin_release_verified.add(process)
        return self._complete_verified_darwin_release(process)

    def _linux_private_session_identities(
        self,
        containment: tuple[int, int, int, int, int],
    ) -> list[tuple[int, int, int, int]] | None:
        identities: list[tuple[int, int, int, int]] = []
        try:
            with os.scandir("/proc") as entries:
                for entry in entries:
                    if not entry.name.isdecimal():
                        continue
                    try:
                        identity = self._linux_process_identity(int(entry.name))
                    except ProcessLookupError:
                        continue
                    if identity[3] == containment[3]:
                        identities.append(identity)
        except (OSError, RunnerTransportError):
            return None
        if containment[:4] not in identities:
            return None
        return identities

    @staticmethod
    def _signal_linux_process_identity(
        identity: tuple[int, int, int, int],
        signum: int,
    ) -> bool:
        descriptor = -1
        try:
            if not callable(_PIDFD_OPEN) or not callable(_PIDFD_SEND_SIGNAL):
                return False
            before = SubprocessRustRunner._linux_process_identity(identity[0])
            if before != identity:
                return False
            descriptor = int(_PIDFD_OPEN(identity[0], 0))
            try:
                after = SubprocessRustRunner._linux_process_identity(identity[0])
            except ProcessLookupError:
                return True
            if after != identity:
                return False
            _PIDFD_SEND_SIGNAL(descriptor, signum, None, 0)
            return True
        except ProcessLookupError:
            return True
        except (OSError, RunnerTransportError):
            return False
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _signal_linux_private_leader(
        self,
        containment: tuple[int, int, int, int, int],
        signum: int,
    ) -> bool:
        try:
            if (
                not callable(_PIDFD_SEND_SIGNAL)
                or self._linux_process_identity(containment[0]) != containment[:4]
            ):
                return False
            _PIDFD_SEND_SIGNAL(containment[4], signum, None, 0)
            return True
        except ProcessLookupError:
            return True
        except (OSError, RunnerTransportError):
            return False

    def _release_linux_private_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: bool,
    ) -> bool:
        containment = self._linux_process_containments.get(process)
        if containment is None:
            return False
        if terminate and not self._process_exited_without_reap(process):
            if not self._signal_linux_private_leader(containment, signal.SIGTERM):
                return False
            graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
            while (
                not self._process_exited_without_reap(process)
                and time.monotonic() < graceful_deadline
            ):
                time.sleep(_PROCESS_POLL_SECONDS)
            if not self._process_exited_without_reap(process):
                if not self._signal_linux_private_leader(containment, _FORCE_KILL_SIGNAL):
                    return False
        exit_deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
        while not self._process_exited_without_reap(process) and time.monotonic() < exit_deadline:
            time.sleep(_PROCESS_POLL_SECONDS)
        if not self._process_exited_without_reap(process):
            return False

        descendant_grace = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        descendant_deadline = descendant_grace + _PROCESS_KILL_GRACE_SECONDS
        while True:
            identities = self._linux_private_session_identities(containment)
            if identities is None:
                return False
            targets = [identity for identity in identities if identity != containment[:4]]
            if not targets:
                break
            now = time.monotonic()
            if now >= descendant_deadline:
                return False
            signum = _FORCE_KILL_SIGNAL if now >= descendant_grace else signal.SIGTERM
            if not all(
                self._signal_linux_process_identity(identity, signum) for identity in targets
            ):
                return False
            time.sleep(_PROCESS_POLL_SECONDS)
        try:
            process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False
        self._linux_process_containments.pop(process, None)
        self._released_linux_processes.add(process)
        os.close(containment[4])
        return process.returncode is not None

    def _release_darwin_private_process(
        self,
        process: subprocess.Popen[bytes],
        *,
        terminate: bool,
    ) -> bool:
        if self._complete_verified_darwin_release(process):
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return True
        if self._darwin_process_is_indeterminate(process):
            self._retain_indeterminate_darwin_process(process, terminate=terminate)
            return False
        containment = self._darwin_process_containments.get(process)
        if containment is None:
            return False
        if not release_darwin_process(
            process,
            containment,
            terminate=terminate,
            child_exited_without_reap=_darwin_child_exited_without_reap,
            release_verified=self._darwin_release_verified.add,
        ):
            self._retain_indeterminate_darwin_process(process, terminate=terminate)
            return False
        if not self._complete_verified_darwin_release(process):
            self._retain_indeterminate_darwin_process(process, terminate=terminate)
            return False
        if not self._close_darwin_process_containment(process):
            self._retain_indeterminate_darwin_process(process, terminate=terminate)
            return False
        self._drop_owned_darwin_process(process)
        return True

    @staticmethod
    def _private_posix_session_members(session_id: int) -> set[int] | None:
        """Enumerate one Linux-private watchdog session without trusting names."""

        if not sys.platform.startswith("linux") or not callable(_GET_SESSION_ID):
            return None
        members: set[int] = set()
        try:
            with os.scandir("/proc") as entries:
                for entry in entries:
                    if not entry.name.isdecimal():
                        continue
                    process_id = int(entry.name)
                    try:
                        if _GET_SESSION_ID(process_id) == session_id:
                            members.add(process_id)
                    except ProcessLookupError:
                        continue
        except OSError:
            return None
        return members

    @staticmethod
    def _signal_private_posix_session_members(
        session_id: int,
        process_ids: set[int],
        signum: int,
    ) -> bool:
        """Signal immutable process identities while excluding the watchdog itself."""

        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
        if (
            not callable(pidfd_open)
            or not callable(pidfd_send_signal)
            or not callable(_GET_SESSION_ID)
        ):
            return False
        current_process = os.getpid()
        for process_id in sorted(process_ids - {current_process}, reverse=True):
            descriptor = -1
            try:
                descriptor = pidfd_open(process_id, 0)
                if _GET_SESSION_ID(process_id) != session_id:
                    continue
                pidfd_send_signal(descriptor, signum, None, 0)
            except ProcessLookupError:
                continue
            except OSError:
                return False
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        return True

    def _terminate_inherited_posix_process_tree(
        self,
        process: subprocess.Popen[bytes],
    ) -> bool:
        """Stop every child in the watchdog's private session without killing it."""

        if process in self._darwin_process_containments:
            return self._release_darwin_private_process(process, terminate=True)
        if sys.platform == "darwin":
            # An interrupted parent-death handshake has no transferable lease.
            # Never poll, wait, or signal its numeric helper identity here;
            # lease closure plus observe-only reconciliation is the safe path.
            self._retain_indeterminate_darwin_process(
                process,
                terminate=True,
                observe_only=True,
            )
            return False

        try:
            if not callable(_GET_PROCESS_GROUP) or not callable(_GET_SESSION_ID):
                return False
            process_group = _GET_PROCESS_GROUP()
            session_id = _GET_SESSION_ID(0)
            if process_group != os.getpid() or session_id != os.getpid():
                return False
        except OSError:
            return False

        graceful_deadline = time.monotonic() + _PROCESS_TERM_GRACE_SECONDS
        force = False
        stopped_deadline = graceful_deadline + _PROCESS_KILL_GRACE_SECONDS
        while True:
            process.poll()
            members = self._private_posix_session_members(session_id)
            if members is None or os.getpid() not in members:
                return False
            targets = members - {os.getpid()}
            if not targets:
                return process.poll() is not None
            now = time.monotonic()
            if now >= stopped_deadline:
                return False
            if now >= graceful_deadline:
                force = True
            if not self._signal_private_posix_session_members(
                session_id,
                targets,
                _FORCE_KILL_SIGNAL if force else signal.SIGTERM,
            ):
                return False
            time.sleep(_PROCESS_POLL_SECONDS)

    def _finish_posix_process_group(self, process: subprocess.Popen[bytes]) -> bool:
        if process in self._released_darwin_processes:
            if not self._close_darwin_process_containment(process):
                return False
            self._drop_owned_darwin_process(process)
            return process.returncode is not None
        if process in self._darwin_process_containments:
            return self._release_darwin_private_process(process, terminate=False)
        if self._kill_child_on_job_close:
            return self._terminate_inherited_posix_process_tree(process)
        if process in self._released_linux_processes:
            return process.returncode is not None
        if process in self._linux_process_containments:
            return self._release_linux_private_process(process, terminate=False)
        if sys.platform == "darwin":
            return self._release_darwin_process_group(process)
        if not self._posix_process_group_exists(process.pid):
            # A short-lived process can close stdout and leave its process
            # group just before waitpid publishes the exit to Popen.poll().
            # Reap that exact child for a bounded interval instead of
            # misreporting an already-drained group as a containment failure.
            try:
                process.wait(timeout=_PROCESS_TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                return False
            return process.returncode is not None
        return self._terminate_posix_process_tree(process)

    def _terminate_windows_process_tree(self, process: subprocess.Popen[bytes]) -> bool:
        if sys.platform != "win32":
            return False
        if process in self._released_windows_processes:
            return self._release_windows_job(process.pid) and process.poll() is not None
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process.pid)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            terminated = bool(terminate_job(job, 1))
            if terminated:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except (AttributeError, OSError, subprocess.SubprocessError, ValueError):
            terminated = False
        if not terminated or not self._wait_for_empty_windows_job(job):
            return False
        self._released_windows_processes.add(process)
        return self._release_windows_job(process.pid) and process.poll() is not None

    def _create_windows_job(self) -> int:
        if sys.platform != "win32":
            raise RunnerTransportError("Windows process containment is unavailable")
        job = 0
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_job = kernel32.CreateJobObjectW
            create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            create_job.restype = wintypes.HANDLE

            raw_job = create_job(None, None)
            if not raw_job:
                raise OSError("job creation failed")
            job = int(raw_job)
            # The request-server's outer watchdog job intentionally survives
            # handle closure. Inside the watchdog, the Rust child job uses
            # KILL_ON_JOB_CLOSE so a watchdog crash cannot orphan execution.
            if self._kill_child_on_job_close:
                self._set_windows_job_kill_on_close(job)
            return job
        except (AttributeError, OSError, TypeError, ValueError):
            if job:
                self._close_windows_handle(job)
            raise RunnerTransportError("Windows process containment is unavailable") from None
        except RunnerTransportError:
            if job:
                self._close_windows_handle(job)
            raise

    @staticmethod
    def _set_windows_job_kill_on_close(job: int) -> None:
        if sys.platform != "win32":
            raise RunnerTransportError("Windows process containment is unavailable")
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("per_process_user_time_limit", ctypes.c_longlong),
                    ("per_job_user_time_limit", ctypes.c_longlong),
                    ("limit_flags", wintypes.DWORD),
                    ("minimum_working_set_size", ctypes.c_size_t),
                    ("maximum_working_set_size", ctypes.c_size_t),
                    ("active_process_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t),
                    ("priority_class", wintypes.DWORD),
                    ("scheduling_class", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    ("read_operation_count", ctypes.c_ulonglong),
                    ("write_operation_count", ctypes.c_ulonglong),
                    ("other_operation_count", ctypes.c_ulonglong),
                    ("read_transfer_count", ctypes.c_ulonglong),
                    ("write_transfer_count", ctypes.c_ulonglong),
                    ("other_transfer_count", ctypes.c_ulonglong),
                ]

            class ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("basic_limit_information", BasicLimitInformation),
                    ("io_info", IoCounters),
                    ("process_memory_limit", ctypes.c_size_t),
                    ("job_memory_limit", ctypes.c_size_t),
                    ("peak_process_memory_used", ctypes.c_size_t),
                    ("peak_job_memory_used", ctypes.c_size_t),
                ]

            details = ExtendedLimitInformation()
            details.basic_limit_information.limit_flags = 0x0000_2000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            set_information = kernel32.SetInformationJobObject
            set_information.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            set_information.restype = wintypes.BOOL
            if not set_information(
                job,
                9,
                ctypes.byref(details),
                ctypes.sizeof(details),
            ):
                raise OSError("job close containment is unavailable")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows process containment is unavailable") from None

    @staticmethod
    def _resume_windows_process(process: subprocess.Popen[bytes]) -> None:
        """Resume the one primary thread of a CREATE_SUSPENDED child."""

        if sys.platform != "win32":
            raise RunnerTransportError("Windows suspended process start failed")
        snapshot = 0
        thread_handle = 0
        try:
            import ctypes
            from ctypes import wintypes

            class ThreadEntry32(ctypes.Structure):
                _fields_ = [
                    ("size", wintypes.DWORD),
                    ("usage", wintypes.DWORD),
                    ("thread_id", wintypes.DWORD),
                    ("owner_process_id", wintypes.DWORD),
                    ("base_priority", wintypes.LONG),
                    ("priority_delta", wintypes.LONG),
                    ("flags", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_snapshot = kernel32.CreateToolhelp32Snapshot
            create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            create_snapshot.restype = wintypes.HANDLE
            first_thread = kernel32.Thread32First
            first_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            first_thread.restype = wintypes.BOOL
            next_thread = kernel32.Thread32Next
            next_thread.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
            next_thread.restype = wintypes.BOOL
            open_thread = kernel32.OpenThread
            open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_thread.restype = wintypes.HANDLE
            resume_thread = kernel32.ResumeThread
            resume_thread.argtypes = [wintypes.HANDLE]
            resume_thread.restype = wintypes.DWORD

            raw_snapshot = create_snapshot(0x0000_0004, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if not raw_snapshot or int(raw_snapshot) == invalid_handle:
                raise OSError("thread snapshot unavailable")
            snapshot = int(raw_snapshot)
            entry = ThreadEntry32()
            entry.size = ctypes.sizeof(entry)
            available = bool(first_thread(snapshot, ctypes.byref(entry)))
            candidates: list[int] = []
            while available:
                if entry.owner_process_id == process.pid:
                    candidates.append(int(entry.thread_id))
                available = bool(next_thread(snapshot, ctypes.byref(entry)))
            if len(candidates) != 1:
                raise OSError("suspended child thread identity is ambiguous")
            raw_thread = open_thread(0x0002, False, candidates[0])
            if not raw_thread:
                raise OSError("suspended child thread is unavailable")
            thread_handle = int(raw_thread)
            previous_count = int(resume_thread(thread_handle))
            if previous_count != 1:
                raise OSError("suspended child was not resumed exactly once")
        except (AttributeError, OSError, TypeError, ValueError):
            raise RunnerTransportError("Windows suspended process start failed") from None
        finally:
            if thread_handle:
                SubprocessRustRunner._close_windows_handle(thread_handle)
            if snapshot:
                SubprocessRustRunner._close_windows_handle(snapshot)

    def _assign_windows_job(
        self,
        job: int,
        process: subprocess.Popen[bytes],
    ) -> None:
        process_handle = 0
        try:
            if sys.platform != "win32":
                raise OSError("Windows Job Objects are unavailable")
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            assign_process = kernel32.AssignProcessToJobObject
            assign_process.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            assign_process.restype = wintypes.BOOL
            terminate_process = kernel32.TerminateProcess
            terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_process.restype = wintypes.BOOL

            raw_process_handle = open_process(0x0001 | 0x0100 | 0x1000, False, process.pid)
            if not raw_process_handle:
                raise OSError("process handle unavailable")
            process_handle = int(raw_process_handle)
            if not assign_process(job, process_handle):
                terminate_process(process_handle, 1)
                raise OSError("job assignment failed")
            with self._windows_jobs_lock:
                self._windows_jobs[process.pid] = job
        except (AttributeError, OSError, TypeError, ValueError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            raise RunnerTransportError("Windows process containment is unavailable") from None
        finally:
            if process_handle:
                self._close_windows_handle(process_handle)

    def _release_windows_job(self, process_id: int) -> bool:
        with self._windows_jobs_lock:
            job = self._windows_jobs.pop(process_id, None)
        return job is None or self._close_windows_handle(job)

    def _finish_windows_job(self, process: subprocess.Popen[bytes]) -> bool:
        if sys.platform != "win32":
            return False
        process_id = process.pid
        if process in self._released_windows_processes:
            return self._release_windows_job(process_id) and process.poll() is not None
        with self._windows_jobs_lock:
            job = self._windows_jobs.get(process_id)
        if job is None:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            descendants_stopped = bool(terminate_job(job, 1))
        except (AttributeError, TypeError, ValueError):
            descendants_stopped = False
        if not descendants_stopped or not self._wait_for_empty_windows_job(job):
            return False
        self._released_windows_processes.add(process)
        return self._release_windows_job(process_id)

    @staticmethod
    def _wait_for_empty_windows_job(job: int) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            class BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("total_user_time", ctypes.c_longlong),
                    ("total_kernel_time", ctypes.c_longlong),
                    ("period_user_time", ctypes.c_longlong),
                    ("period_kernel_time", ctypes.c_longlong),
                    ("total_page_fault_count", wintypes.DWORD),
                    ("total_processes", wintypes.DWORD),
                    ("active_processes", wintypes.DWORD),
                    ("total_terminated_processes", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.QueryInformationJobObject
            query.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            query.restype = wintypes.BOOL
            deadline = time.monotonic() + _PROCESS_KILL_GRACE_SECONDS
            while True:
                details = BasicAccountingInformation()
                returned = wintypes.DWORD()
                if not query(
                    job,
                    1,
                    ctypes.byref(details),
                    ctypes.sizeof(details),
                    ctypes.byref(returned),
                ):
                    return False
                if details.active_processes == 0:
                    return True
                if time.monotonic() >= deadline:
                    return False
                time.sleep(_PROCESS_POLL_SECONDS)
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def _close_windows_handle(handle: int) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            return bool(close_handle(handle))
        except (AttributeError, TypeError, ValueError):
            return False

    @staticmethod
    def _windows_system_directory() -> Path:
        if os.name != "nt":
            raise RunnerTransportError("Windows process control is unavailable")
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer)
            )
            if length <= 0 or length >= len(buffer):
                raise OSError("system directory lookup failed")
            directory = Path(buffer.value).resolve(strict=True)
            if not directory.is_dir():
                raise OSError("system directory is unavailable")
            return directory
        except (AttributeError, OSError, ValueError):
            raise RunnerTransportError("Windows process control is unavailable") from None

    def _durable_paths(
        self,
        durable_result_path: str | Path,
        task_id: str,
        *,
        retain_parent_guard: bool = False,
    ) -> tuple[Path, Path, _PinnedPrivateDirectory | None]:
        destination = Path(durable_result_path).expanduser()
        if not destination.is_absolute() or destination.name in {"", ".", ".."}:
            raise RunnerTransportError("runner durable result destination is invalid")
        try:
            requested_parent = destination.parent
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if _is_link_or_reparse(destination.parent):
                raise OSError("durable result parent is linked")
            metadata = destination.parent.stat(follow_symlinks=False)
            parent = destination.parent.resolve(strict=True)
            if (
                os.path.normcase(os.path.normpath(str(requested_parent)))
                != os.path.normcase(os.path.normpath(str(parent)))
                or not parent.is_dir()
                or _is_link_or_reparse(parent)
            ):
                raise OSError("durable result parent is not a directory")
            destination = parent / destination.name
            pending = runner_pending_result_path(destination, task_id)
            pinned = self._result_parent_guard(parent)
            try:
                pinned.__enter__()
                if pinned.directory_identity() != (metadata.st_dev, metadata.st_ino):
                    raise OSError("durable result parent identity changed")
                if pinned.has_name(destination.name):
                    raise RunnerDurableResultExists(
                        "Runner durable result already exists and requires reconciliation."
                    )
                if pinned.has_name(pending.name):
                    raise RunnerPendingResultExists(
                        "Runner pending result requires recovery before the task can start."
                    )
            except BaseException as exc:
                pinned.__exit__(type(exc), exc, exc.__traceback__)
                raise
            if not retain_parent_guard:
                pinned.__exit__(None, None, None)
        except RunnerDurableResultExists:
            raise
        except RunnerPendingResultExists:
            raise
        except _PrivateFileCleanupError:
            raise
        except (OSError, RunnerTransportError):
            raise RunnerTransportError("runner durable result destination is unavailable") from None
        return destination, pending, pinned if retain_parent_guard else None

    def _open_pending_result(self, path: Path) -> BinaryIO:
        pinned = self._result_parent_guard(path.parent)
        try:
            pinned.__enter__()
            return cast(
                BinaryIO,
                pinned.open_new(path.name, maximum=_WATCHDOG_CONFIG_LIMIT_BYTES),
            )
        except FileExistsError:
            pinned.close()
            raise RunnerPendingResultExists(
                "Runner pending result requires recovery before the task can start."
            ) from None
        except (OSError, RunnerTransportError):
            pinned.close()
            raise RunnerTransportError("runner pending result is unavailable") from None

    def _promote_pending_result(
        self,
        pending: Path,
        destination: Path,
        *,
        pending_expected: bytes,
        pending_identity: tuple[int, int],
        final_payload: bytes,
    ) -> None:
        final_created = False
        try:
            if pending.parent != destination.parent:
                raise OSError("durable result directories differ")
            with self._result_parent_guard(destination.parent) as pinned:
                checked, checked_identity = pinned.read_with_identity(
                    pending.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected_identity=pending_identity,
                )
                if checked != pending_expected or checked_identity != pending_identity:
                    raise OSError("runner pending result identity changed")
                pinned.create(
                    destination.name,
                    final_payload,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                )
                final_created = True
                pinned.unlink(
                    pending.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected=pending_expected,
                    expected_identity=pending_identity,
                )
        except FileExistsError:
            raise RunnerDurableResultExists(
                "Runner durable result already exists and requires reconciliation."
            ) from None
        except (OSError, RunnerTransportError):
            if final_created:
                raise RunnerDurableResultExists(
                    "Runner durable result may be committed and requires reconciliation."
                ) from None
            raise RunnerTransportError("runner durable result could not be committed") from None

    def _remove_pending_result(
        self,
        path: Path,
        *,
        expected_identity: tuple[int, int] | None,
    ) -> None:
        if expected_identity is None:
            return
        try:
            with self._result_parent_guard(path.parent) as pinned:
                pinned.unlink(
                    path.name,
                    maximum=_WATCHDOG_CONFIG_LIMIT_BYTES,
                    expected_identity=expected_identity,
                )
        except (OSError, RunnerTransportError):
            pass

    @staticmethod
    def _decode_json(payload: bytes, label: str) -> Mapping[str, Any]:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, child in pairs:
                if key in value:
                    raise ValueError("duplicate JSON object key")
                value[key] = child
            return value

        def finite_float(raw: str) -> float:
            value = float(raw)
            if not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            return value

        def reject_constant(_raw: str) -> Any:
            raise ValueError("non-standard JSON constant")

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
                parse_float=finite_float,
            )
        except (RecursionError, UnicodeDecodeError, ValueError) as exc:
            raise RunnerTransportError(f"{label} is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise RunnerTransportError(f"{label} must be a JSON object")
        return value


__all__ = [
    "InventoryBoundRunner",
    "RunnerTransport",
    "RunnerTransportError",
    "RunnerReadinessError",
    "RunnerDurableResultExists",
    "RunnerPendingResultExists",
    "RunnerTaskCancelled",
    "RunnerTaskTimedOut",
    "SubprocessRustRunner",
    "TaskAwareRunnerTransport",
    "canonical_runner_inventory",
    "execution_task_identity",
    "reject_forbidden_execution_keys",
    "runner_inventory_digest",
    "runner_pending_result_path",
    "runner_transport_identity",
    "request_runner_task_cancel",
    "cleanup_runner_watchdog_terminal_state",
    "runner_watchdog_cancel_path",
    "runner_watchdog_control_root",
    "runner_watchdog_ready_path",
    "runner_watchdog_status_path",
]
