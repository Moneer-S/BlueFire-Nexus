"""Linux-only, post-exec parent-death launcher for one pinned runner inode."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import re
import socket
import stat
import sys

_NONCE = re.compile(r"^[0-9a-f]{64}$")
_PR_SET_PDEATHSIG = 1
_SIGKILL = 9


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
        if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
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


def _run(arguments: list[str]) -> int:
    if not sys.platform.startswith("linux") or len(arguments) < 6:
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
        or os.execve not in os.supports_fd
    ):
        return 74
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


if __name__ == "__main__":
    try:
        _code = _run(sys.argv[1:])
    except BaseException:
        _code = 74
    os._exit(_code)
