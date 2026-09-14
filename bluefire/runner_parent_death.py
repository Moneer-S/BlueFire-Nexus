"""Fail-closed POSIX parent-death launcher for one pinned runner inode."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import math
import os
import re
import select
import signal
import socket
import stat
import sys
import time

_NONCE = re.compile(r"^[0-9a-f]{64}$")
_PR_SET_PDEATHSIG = 1
_SIGKILL = 9
_POLL_SECONDS = 0.025
_TERM_GRACE_SECONDS = 2.0
_KILL_GRACE_SECONDS = 5.0
_START_TIMEOUT_SECONDS = 10.0
_MAX_EXECUTION_TIMEOUT_SECONDS = 86_400.0
_KILL_PROCESS_GROUP = getattr(os, "killpg", None)
_SET_PROCESS_GROUP = getattr(os, "setpgid", None)
_GET_PROCESS_GROUP = getattr(os, "getpgrp", None)
_GET_PROCESS_GROUP_ID = getattr(os, "getpgid", None)
_GET_SESSION_ID = getattr(os, "getsid", None)
_GET_EFFECTIVE_USER_ID = getattr(os, "geteuid", None)
_FORK_PROCESS = getattr(os, "fork", None)
_WAIT_NO_HANG = getattr(os, "WNOHANG", 0)
_MAX_DARWIN_PROCESSES = 131_072
_DARWIN_NO_FORK_PROFILE = b"(version 1)\n(allow default)\n(deny process-fork)\n"
_DARWIN_NO_FORK_EXEC_MODE = "--darwin-no-fork-exec-v1"


def _private_target(descriptor: int) -> bool:
    details = os.fstat(descriptor)
    if (
        descriptor <= 2
        or not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        return False
    get_xattr = getattr(os, "getxattr", None)
    if not callable(get_xattr):
        return False
    try:
        capability = get_xattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno not in {
            errno.ENODATA,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
            getattr(errno, "ENOATTR", errno.ENODATA),
        }:
            return False
        capability = b""
    return not capability


def _arm_parent_death(expected_parent: int) -> bool:
    try:
        library = ctypes.CDLL(None, use_errno=True)
        prctl = library.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        return (
            os.getppid() == expected_parent
            and prctl(_PR_SET_PDEATHSIG, _SIGKILL, 0, 0, 0) == 0
            and os.getppid() == expected_parent
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _close_on_exec(descriptors: tuple[int, ...]) -> None:
    operation = getattr(fcntl, "fcntl", None)
    get_flags = getattr(fcntl, "F_GETFD", None)
    set_flags = getattr(fcntl, "F_SETFD", None)
    close_on_exec = getattr(fcntl, "FD_CLOEXEC", None)
    if not callable(operation) or get_flags is None or set_flags is None or close_on_exec is None:
        raise OSError("descriptor controls unavailable")
    for descriptor in descriptors:
        flags = operation(descriptor, get_flags)
        operation(descriptor, set_flags, flags | close_on_exec)


def _parse_arguments(
    arguments: list[str],
) -> tuple[int, int, int, str, tuple[int, ...], list[str]] | None:
    if len(arguments) < 6:
        return None
    try:
        expected_parent = int(arguments[0])
        control_descriptor = int(arguments[1])
        target_descriptor = int(arguments[2])
        nonce = arguments[3]
        close_descriptors = tuple(int(value) for value in arguments[4].split(",") if value)
        target_arguments = arguments[5:]
    except ValueError:
        return None
    if (
        expected_parent <= 1
        or control_descriptor <= 2
        or target_descriptor <= 2
        or control_descriptor == target_descriptor
        or _NONCE.fullmatch(nonce) is None
        or not target_arguments
    ):
        return None
    return (
        expected_parent,
        control_descriptor,
        target_descriptor,
        nonce,
        close_descriptors,
        target_arguments,
    )


def _run_linux(arguments: list[str]) -> int:
    parsed = _parse_arguments(arguments)
    if parsed is None or os.execve not in os.supports_fd:
        return 74
    (
        expected_parent,
        control_descriptor,
        target_descriptor,
        nonce,
        close_descriptors,
        target_arguments,
    ) = parsed
    try:
        control = socket.socket(fileno=control_descriptor)
        if not _private_target(target_descriptor) or not _arm_parent_death(expected_parent):
            return 74
        armed = f"armed-v1:{nonce}:{os.getpid()}:{expected_parent}".encode("ascii")
        control.sendall(armed)
        if control.recv(256) != f"go-v1:{nonce}".encode("ascii"):
            return 74
        if os.getppid() != expected_parent:
            return 74
        _close_on_exec(
            tuple(sorted(set(close_descriptors) | {control_descriptor, target_descriptor}))
        )
        try:
            os.execve(target_descriptor, target_arguments, dict(os.environ))
        except OSError:
            control.sendall(b"failed-v1")
            return 74
    except (OSError, TypeError, ValueError):
        return 74


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _read_line_descriptor(descriptor: int, *, maximum: int, deadline: float) -> bytes:
    payload = bytearray()
    while len(payload) <= maximum:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError("supervisor record timed out")
        try:
            readable, _, _ = select.select(
                [descriptor],
                [],
                [],
                min(_POLL_SECONDS, remaining),
            )
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            raise
        if not readable:
            continue
        chunk = os.read(descriptor, 1)
        if not chunk:
            break
        payload.extend(chunk)
        if chunk == b"\n":
            break
    if not payload or len(payload) > maximum or not payload.endswith(b"\n"):
        raise OSError("invalid supervisor record")
    return bytes(payload)


def _recv_line(control: socket.socket, *, maximum: int) -> bytes:
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


def _terminate_direct_child(process_id: int, *, force: bool = False) -> tuple[bool, int | None]:
    """Signal and reap exactly one unreaped direct child."""

    if process_id <= 1:
        return False, None
    graceful_deadline = time.monotonic() + (0.0 if force else _TERM_GRACE_SECONDS)
    final_deadline = graceful_deadline + _KILL_GRACE_SECONDS
    signum = _SIGKILL if force else int(getattr(signal, "SIGTERM", 15))
    while True:
        try:
            waited, status_value = os.waitpid(process_id, _WAIT_NO_HANG)
        except ChildProcessError:
            return False, None
        except OSError:
            return False, None
        if waited == process_id:
            return True, status_value
        if waited != 0:
            return False, None
        try:
            # `process_id` is still our unreaped direct child.  It therefore
            # cannot be reused between waitpid and this signal.
            os.kill(process_id, signum)
        except ProcessLookupError:
            pass
        except OSError:
            return False, None
        now = time.monotonic()
        if now >= final_deadline:
            return False, None
        if now >= graceful_deadline:
            signum = _SIGKILL
        time.sleep(_POLL_SECONDS)


def _darwin_process_ids() -> set[int] | None:
    if sys.platform.startswith("linux"):
        try:
            with os.scandir("/proc") as entries:
                return {
                    int(entry.name)
                    for entry in entries
                    if entry.name.isdecimal() and int(entry.name) > 0
                }
        except OSError:
            return None
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


def _private_process_group_members(process_group: int, session_id: int) -> set[int] | None:
    if not callable(_GET_PROCESS_GROUP_ID) or not callable(_GET_SESSION_ID):
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


def _terminate_pinned_monitor_group(
    monitor_process: int,
    session_id: int,
    *,
    identity_pinned: bool = False,
) -> bool:
    """Drain a group while its direct-child leader remains unreaped and un-reusable.

    ``identity_pinned`` is set only by the fork owner after it has placed its
    still-unreaped direct child in the private session and same-numbered
    process group.  Darwin stops exposing ``getpgid``/``getsid`` for a zombie,
    but that unreaped child still prevents its PID/PGID from being reused.
    """

    if monitor_process <= 1 or not callable(_KILL_PROCESS_GROUP):
        return False
    if not identity_pinned:
        try:
            if (
                not callable(_GET_PROCESS_GROUP_ID)
                or not callable(_GET_SESSION_ID)
                or _GET_PROCESS_GROUP_ID(monitor_process) != monitor_process
                or _GET_SESSION_ID(monitor_process) != session_id
            ):
                return False
        except OSError:
            return False
    deadline = time.monotonic() + _KILL_GRACE_SECONDS
    while True:
        members = _private_process_group_members(monitor_process, session_id)
        if members is None:
            return False
        other_members = members - {monitor_process}
        if not other_members:
            # Never signal the numeric group after reaping its leader.  Stop
            # or reap that exact direct child while its PID still pins the
            # now-empty group identifier.
            stopped, _status = _terminate_direct_child(monitor_process, force=True)
            return stopped
        try:
            # The unreaped direct-child group leader pins this PGID, so this
            # group signal cannot race into a reused or unrelated process.
            _KILL_PROCESS_GROUP(monitor_process, _SIGKILL)
        except ProcessLookupError:
            return False
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)


def _private_darwin_target(path: str, descriptor: int) -> bool:
    try:
        if not os.path.isabs(path):
            return False
        opened = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
        return (
            stat.S_ISREG(opened.st_mode)
            and stat.S_ISREG(visible.st_mode)
            and os.path.samestat(opened, visible)
            and opened.st_nlink == 2
            and visible.st_nlink == 2
            and callable(_GET_EFFECTIVE_USER_ID)
            and opened.st_uid == int(_GET_EFFECTIVE_USER_ID())
            and not opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        )
    except (AttributeError, OSError):
        return False


def _apply_darwin_no_fork_sandbox() -> bool:
    """Apply and dynamically prove Darwin's inherited no-fork Seatbelt rule."""

    if sys.platform != "darwin":
        return True
    error_buffer = ctypes.c_char_p()
    try:
        library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
        sandbox_init = library.sandbox_init
        sandbox_init.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_char_p),
        ]
        sandbox_init.restype = ctypes.c_int
        sandbox_free_error = library.sandbox_free_error
        sandbox_free_error.argtypes = [ctypes.c_void_p]
        sandbox_free_error.restype = None
        result = sandbox_init(
            _DARWIN_NO_FORK_PROFILE,
            0,
            ctypes.byref(error_buffer),
        )
        if error_buffer.value is not None:
            sandbox_free_error(error_buffer)
        if result != 0 or not callable(_FORK_PROCESS):
            return False
        try:
            probe = _FORK_PROCESS()
        except OSError as exc:
            return exc.errno in {errno.EACCES, errno.EPERM}
        if probe == 0:
            os._exit(74)
        reaped = False
        deadline = time.monotonic() + _TERM_GRACE_SECONDS
        while True:
            try:
                waited, _status = os.waitpid(probe, _WAIT_NO_HANG)
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
            time.sleep(_POLL_SECONDS)
        if not reaped:
            try:
                os.kill(probe, _SIGKILL)
            except OSError:
                pass
            kill_deadline = time.monotonic() + _KILL_GRACE_SECONDS
            while True:
                try:
                    waited, _status = os.waitpid(probe, _WAIT_NO_HANG)
                except (ChildProcessError, OSError):
                    break
                if waited == probe:
                    break
                if time.monotonic() >= kill_deadline:
                    break
                time.sleep(_POLL_SECONDS)
        return False
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _run_darwin_no_fork_exec(arguments: list[str]) -> int:
    if len(arguments) < 6:
        return 74
    try:
        expected_parent = int(arguments[0])
        control_descriptor = int(arguments[1])
        target_descriptor = int(arguments[2])
        nonce = arguments[3]
        close_descriptors = tuple(int(value) for value in arguments[4].split(",") if value)
        target_arguments = arguments[5:]
    except ValueError:
        return 74
    if (
        expected_parent <= 1
        or control_descriptor <= 2
        or target_descriptor <= 2
        or control_descriptor == target_descriptor
        or _NONCE.fullmatch(nonce) is None
        or not target_arguments
        or not callable(_GET_PROCESS_GROUP)
        or not callable(_GET_SESSION_ID)
    ):
        return 74
    control: socket.socket | None = None
    try:
        identity = os.getpid()
        if (
            os.getppid() != expected_parent
            or _GET_PROCESS_GROUP() != identity
            or _GET_SESSION_ID(0) != identity
            or not _private_darwin_target(target_arguments[0], target_descriptor)
            or not _apply_darwin_no_fork_sandbox()
        ):
            return 74
        control = socket.socket(fileno=control_descriptor)
        control.settimeout(_START_TIMEOUT_SECONDS)
        control.sendall(f"armed-nofork-v1:{nonce}:{identity}:{expected_parent}\n".encode("ascii"))
        if _recv_line(control, maximum=96) != f"go-nofork-v1:{nonce}\n".encode("ascii"):
            return 74
        if (
            os.getppid() != expected_parent
            or _GET_PROCESS_GROUP() != identity
            or _GET_SESSION_ID(0) != identity
            or not _private_darwin_target(target_arguments[0], target_descriptor)
        ):
            return 74
        _close_on_exec(
            tuple(sorted(set(close_descriptors) | {control_descriptor, target_descriptor}))
        )
        try:
            os.execve(target_arguments[0], target_arguments, dict(os.environ))
        except OSError:
            control.sendall(b"failed-nofork-v1\n")
    except (OSError, TypeError, ValueError):
        return 74
    finally:
        if control is not None:
            try:
                control.close()
            except OSError:
                pass
    return 74


def _darwin_exec_target(
    *,
    expected_parent: int,
    expected_monitor: int,
    control_descriptor: int,
    helper_lease_descriptor: int,
    status_descriptor: int,
    start_descriptor: int,
    exec_status_descriptor: int,
    target_descriptor: int,
    close_descriptors: tuple[int, ...],
    target_arguments: list[str],
) -> None:
    target_path = target_arguments[0]
    try:
        for descriptor in (
            control_descriptor,
            helper_lease_descriptor,
            status_descriptor,
        ):
            _close_descriptor(descriptor)
        if (
            not callable(_SET_PROCESS_GROUP)
            or not callable(_GET_PROCESS_GROUP)
            or not callable(_GET_SESSION_ID)
        ):
            raise OSError("Darwin process-group controls are unavailable")
        _SET_PROCESS_GROUP(0, expected_monitor)
        if (
            os.getppid() != expected_monitor
            or _GET_PROCESS_GROUP() != expected_monitor
            or _GET_SESSION_ID(0) != expected_parent
            or os.read(start_descriptor, 1) != b"G"
            or not _private_darwin_target(target_path, target_descriptor)
            or not _apply_darwin_no_fork_sandbox()
        ):
            os.write(exec_status_descriptor, b"failed-v1\n")
            os._exit(74)
        _close_descriptor(start_descriptor)
        _close_on_exec(
            tuple(sorted(set(close_descriptors) | {exec_status_descriptor, target_descriptor}))
        )
        try:
            os.execve(target_path, target_arguments, dict(os.environ))
        except OSError:
            os.write(exec_status_descriptor, b"failed-v1\n")
    except (OSError, TypeError, ValueError):
        try:
            os.write(exec_status_descriptor, b"failed-v1\n")
        except OSError:
            pass
    os._exit(74)


def _await_darwin_exec_status(
    exec_status_descriptor: int,
    helper_lease_descriptor: int,
    control: socket.socket,
) -> bool:
    """Wait boundedly for exec-close while retaining both parent leases."""

    deadline = time.monotonic() + _START_TIMEOUT_SECONDS
    control_descriptor = control.fileno()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            readable, _, _ = select.select(
                [exec_status_descriptor, helper_lease_descriptor, control_descriptor],
                [],
                [],
                min(_POLL_SECONDS, remaining),
            )
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return False
        if exec_status_descriptor in readable:
            try:
                return os.read(exec_status_descriptor, 64) == b""
            except OSError:
                return False
        if helper_lease_descriptor in readable:
            try:
                if os.read(helper_lease_descriptor, 1) != b"":
                    return False
            except OSError:
                return False
            return False
        if control_descriptor in readable:
            try:
                if control.recv(1) != b"":
                    return False
            except OSError:
                return False
            return False


def _confirm_darwin_exec_or_stop(
    target_process: int,
    exec_status_descriptor: int,
    helper_lease_descriptor: int,
    control: socket.socket,
) -> bool:
    if _await_darwin_exec_status(
        exec_status_descriptor,
        helper_lease_descriptor,
        control,
    ):
        return True
    stopped, _status = _terminate_direct_child(target_process, force=True)
    if not stopped:
        raise OSError("Darwin target did not stop after a failed exec transition")
    return False


def _darwin_monitor(
    *,
    expected_parent: int,
    expected_helper: int,
    control_descriptor: int,
    helper_lease_descriptor: int,
    status_descriptor: int,
    target_descriptor: int,
    nonce: str,
    close_descriptors: tuple[int, ...],
    target_arguments: list[str],
) -> None:
    start_read = start_write = exec_status_read = exec_status_write = -1
    target_process = -1
    try:
        if (
            not callable(_SET_PROCESS_GROUP)
            or not callable(_GET_PROCESS_GROUP)
            or not callable(_GET_PROCESS_GROUP_ID)
            or not callable(_GET_SESSION_ID)
            or not callable(_FORK_PROCESS)
        ):
            raise OSError("Darwin process controls are unavailable")
        _SET_PROCESS_GROUP(0, 0)
        monitor_identity = os.getpid()
        start_read, start_write = os.pipe()
        exec_status_read, exec_status_write = os.pipe()
        target_process = _FORK_PROCESS()
        if target_process == 0:
            _close_descriptor(start_write)
            _close_descriptor(exec_status_read)
            _darwin_exec_target(
                expected_parent=expected_parent,
                expected_monitor=monitor_identity,
                control_descriptor=control_descriptor,
                helper_lease_descriptor=helper_lease_descriptor,
                status_descriptor=status_descriptor,
                start_descriptor=start_read,
                exec_status_descriptor=exec_status_write,
                target_descriptor=target_descriptor,
                close_descriptors=close_descriptors,
                target_arguments=target_arguments,
            )
        _close_descriptor(start_read)
        start_read = -1
        _close_descriptor(exec_status_write)
        exec_status_write = -1
        _SET_PROCESS_GROUP(target_process, monitor_identity)
        if (
            not _apply_darwin_no_fork_sandbox()
            or os.read(helper_lease_descriptor, 1) != b"S"
            or os.getppid() != expected_helper
            or _GET_PROCESS_GROUP() != os.getpid()
            or _GET_SESSION_ID(0) != expected_parent
            or _GET_PROCESS_GROUP_ID(target_process) != monitor_identity
            or _GET_SESSION_ID(target_process) != expected_parent
        ):
            raise OSError("Darwin supervisor identity mismatch")
        os.write(status_descriptor, f"target-v1:{target_process}\n".encode("ascii"))
        control = socket.socket(fileno=control_descriptor)
        control.settimeout(_START_TIMEOUT_SECONDS)
        armed = (
            f"armed-v2:{nonce}:{expected_helper}:{os.getpid()}:{target_process}:{expected_parent}\n"
        ).encode("ascii")
        control.sendall(armed)
        if _recv_line(control, maximum=96) != f"go-v2:{nonce}\n".encode("ascii"):
            raise OSError("Darwin supervisor start gate is invalid")
        os.write(start_write, b"G")
        _close_descriptor(start_write)
        start_write = -1
        if not _confirm_darwin_exec_or_stop(
            target_process,
            exec_status_read,
            helper_lease_descriptor,
            control,
        ):
            target_process = -1
            raise OSError("Darwin target execution failed")
        _close_descriptor(exec_status_read)
        exec_status_read = -1
        control.sendall(f"executed-v2:{nonce}\n".encode("ascii"))
        control.settimeout(None)

        interrupted = [False]

        def request_cleanup(_signum: int, _frame: object) -> None:
            interrupted[0] = True

        for signum in (
            getattr(signal, "SIGTERM", None),
            getattr(signal, "SIGINT", None),
            getattr(signal, "SIGHUP", None),
        ):
            if isinstance(signum, int):
                signal.signal(signum, request_cleanup)

        target_status: int | None = None
        lease_lost = False
        while target_status is None and not lease_lost:
            waited, status_value = os.waitpid(target_process, _WAIT_NO_HANG)
            if waited == target_process:
                target_status = status_value
                target_process = -1
                break
            readable, _, _ = select.select(
                [control_descriptor, helper_lease_descriptor],
                [],
                [],
                _POLL_SECONDS,
            )
            if interrupted[0]:
                lease_lost = True
            for descriptor in readable:
                if descriptor == control_descriptor:
                    if control.recv(1) != b"":
                        raise OSError("unexpected Darwin supervisor control")
                elif os.read(helper_lease_descriptor, 1) != b"":
                    raise OSError("unexpected Darwin helper lease payload")
                lease_lost = True

        if lease_lost:
            stopped, target_status = _terminate_direct_child(target_process, force=True)
            target_process = -1
            if not stopped:
                raise OSError("Darwin runner could not be stopped")
            os._exit(74)

        if target_status is None:
            raise OSError("Darwin runner status is unavailable")
        exit_code = os.waitstatus_to_exitcode(target_status)
        if not 0 <= exit_code <= 255:
            exit_code = 74
        os.write(status_descriptor, f"exit-v1:{exit_code}\n".encode("ascii"))
        # Keep the monitor alive as the pinned group leader until the helper
        # proves that the no-fork target left no other group member.  EOF is
        # the helper's release acknowledgement.
        if os.read(helper_lease_descriptor, 1) != b"":
            raise OSError("unexpected Darwin helper release payload")
        os._exit(0)
    except BaseException:
        if target_process > 1:
            _terminate_direct_child(target_process, force=True)
        os._exit(74)


def _run_darwin(arguments: list[str]) -> int:
    parsed = _parse_arguments(arguments)
    if (
        parsed is None
        or not callable(_FORK_PROCESS)
        or not callable(_SET_PROCESS_GROUP)
        or not callable(_GET_PROCESS_GROUP)
        or not callable(_GET_PROCESS_GROUP_ID)
        or not callable(_GET_SESSION_ID)
        or not callable(_KILL_PROCESS_GROUP)
    ):
        return 74
    (
        expected_parent,
        control_descriptor,
        target_descriptor,
        nonce,
        close_descriptors,
        target_arguments,
    ) = parsed
    try:
        execution_timeout_seconds = float(target_arguments[0])
    except (IndexError, ValueError):
        return 74
    target_arguments = target_arguments[1:]
    if (
        not math.isfinite(execution_timeout_seconds)
        or not 0 < execution_timeout_seconds <= _MAX_EXECUTION_TIMEOUT_SECONDS
        or not target_arguments
        or os.getppid() != expected_parent
        or _GET_PROCESS_GROUP() != expected_parent
        or _GET_SESSION_ID(0) != expected_parent
        or not _private_darwin_target(target_arguments[0], target_descriptor)
    ):
        return 74
    helper_lease_read = helper_lease_write = status_read = status_write = -1
    monitor_process = -1
    monitor_group_pinned = False
    try:
        helper_lease_read, helper_lease_write = os.pipe()
        status_read, status_write = os.pipe()
        helper_identity = os.getpid()
        monitor_process = _FORK_PROCESS()
        if monitor_process == 0:
            _close_descriptor(helper_lease_write)
            _close_descriptor(status_read)
            _darwin_monitor(
                expected_parent=expected_parent,
                expected_helper=helper_identity,
                control_descriptor=control_descriptor,
                helper_lease_descriptor=helper_lease_read,
                status_descriptor=status_write,
                target_descriptor=target_descriptor,
                nonce=nonce,
                close_descriptors=close_descriptors,
                target_arguments=target_arguments,
            )
        _SET_PROCESS_GROUP(monitor_process, monitor_process)
        if not _apply_darwin_no_fork_sandbox():
            raise OSError("Darwin helper no-fork containment is unavailable")
        os.write(helper_lease_write, b"S")
        # This helper owns the still-unreaped direct child.  Successful
        # placement pins the same-numbered PGID even if the monitor later
        # becomes a Darwin zombie that getpgid/getsid no longer expose.
        monitor_group_pinned = True
        if (
            _GET_PROCESS_GROUP_ID(monitor_process) != monitor_process
            or _GET_SESSION_ID(monitor_process) != expected_parent
        ):
            raise OSError("Darwin monitor group identity is invalid")
        _close_descriptor(control_descriptor)
        _close_descriptor(helper_lease_read)
        _close_descriptor(status_write)
        helper_lease_read = status_write = -1
        target_record = _read_line_descriptor(
            status_read,
            maximum=64,
            deadline=time.monotonic() + _START_TIMEOUT_SECONDS,
        )
        match = re.fullmatch(rb"target-v1:([1-9][0-9]{0,9})\n", target_record)
        if match is None:
            raise OSError("Darwin target identity is unavailable")
        exit_record = _read_line_descriptor(
            status_read,
            maximum=32,
            deadline=(
                time.monotonic()
                + _START_TIMEOUT_SECONDS
                + execution_timeout_seconds
                + _TERM_GRACE_SECONDS
                + _KILL_GRACE_SECONDS
            ),
        )
        match = re.fullmatch(rb"exit-v1:([0-9]{1,3})\n", exit_record)
        if match is None:
            raise OSError("Darwin monitor returned an invalid exit record")
        group_members = _private_process_group_members(monitor_process, expected_parent)
        if group_members != {monitor_process}:
            raise OSError("Darwin no-fork containment left an unexpected process")
        _close_descriptor(helper_lease_write)
        helper_lease_write = -1
        reap_deadline = time.monotonic() + _KILL_GRACE_SECONDS
        waited = 0
        monitor_status = -1
        while time.monotonic() < reap_deadline:
            waited, monitor_status = os.waitpid(monitor_process, _WAIT_NO_HANG)
            if waited == monitor_process:
                monitor_process = -1
                break
            if waited != 0:
                raise OSError("Darwin monitor wait returned an unexpected child")
            time.sleep(_POLL_SECONDS)
        if monitor_process > 1 or monitor_status != 0:
            raise OSError("Darwin monitor failed")
        exit_code = int(match.group(1))
        if not 0 <= exit_code <= 255:
            raise OSError("Darwin runner cleanup is incomplete")
        return exit_code
    except (OSError, ValueError):
        _close_descriptor(helper_lease_write)
        helper_lease_write = -1
        if monitor_process > 1:
            if not _terminate_pinned_monitor_group(
                monitor_process,
                expected_parent,
                identity_pinned=monitor_group_pinned,
            ):
                return 74
        return 74
    finally:
        for descriptor in (
            helper_lease_read,
            helper_lease_write,
            status_read,
            status_write,
            target_descriptor,
            *close_descriptors,
        ):
            if descriptor > 2:
                _close_descriptor(descriptor)


def _run(arguments: list[str]) -> int:
    if sys.platform.startswith("linux"):
        return _run_linux(arguments)
    if sys.platform == "darwin":
        if arguments and arguments[0] == _DARWIN_NO_FORK_EXEC_MODE:
            return _run_darwin_no_fork_exec(arguments[1:])
        return _run_darwin(arguments)
    return 74


if __name__ == "__main__":
    try:
        _code = _run(sys.argv[1:])
    except BaseException:
        _code = 74
    os._exit(_code)
