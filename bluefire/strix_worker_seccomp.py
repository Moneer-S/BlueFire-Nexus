"""Evidence and self-test wrapper for the fixed worker seccomp bootstrap.

The early runtime loads ``strix_worker_seccomp_bootstrap.py`` from a sealed,
absolute path while Python is still in ``-I -S`` mode.  This package module is
only imported afterward for evidence and bounded qualification helpers.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import socket
from typing import Sequence

from . import strix_worker_seccomp_bootstrap as _bootstrap

INSTALLATION_SCHEMA = _bootstrap.INSTALLATION_SCHEMA
POLICY_BYTES = _bootstrap.POLICY_BYTES
POLICY_DIGEST = _bootstrap.POLICY_DIGEST
POLICY_SCHEMA = _bootstrap.POLICY_SCHEMA
InstalledSeccompPolicy = _bootstrap.InstalledSeccompPolicy
StrixWorkerSeccompError = _bootstrap.StrixWorkerSeccompError


def arm_installed_worker_seccomp(
    *, expected_policy_digest: str = POLICY_DIGEST
) -> InstalledSeccompPolicy:
    """Compatibility name for post-arm evidence consumers."""

    return _bootstrap.arm(expected_policy_digest=expected_policy_digest)


def _raw_syscall(number: int, *arguments: object) -> tuple[int, int]:
    library = ctypes.CDLL(None, use_errno=True)
    function = library.syscall
    function.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = int(function(number, *arguments))
    return result, ctypes.get_errno()


def _seccomp_self_test(*, require_private_boundary: bool) -> dict[str, object]:
    installation = _bootstrap.arm()

    # Import after arming so the proof exercises glibc's clone3 fallback and
    # the allowed legacy same-TGID pthread clone.
    import threading

    observed: list[str] = []
    thread = threading.Thread(target=lambda: observed.append("thread-ran"), daemon=False)
    thread.start()
    thread.join(timeout=2)
    if thread.is_alive() or observed != ["thread-ran"]:
        raise StrixWorkerSeccompError("ordinary worker thread did not run under seccomp")

    clone3_result, clone3_errno = _raw_syscall(_bootstrap._SYS_CLONE3, 0, 0)
    clone_result, clone_errno = _raw_syscall(_bootstrap._SYS_CLONE, 17, 0, 0, 0, 0)
    fork_result, fork_errno = _raw_syscall(_bootstrap._SYS_FORK)
    vfork_result, vfork_errno = _raw_syscall(_bootstrap._SYS_VFORK)
    unshare_result, unshare_errno = _raw_syscall(272, 0)
    argv = (ctypes.c_char_p * 2)(b"/bin/true", None)
    envp = (ctypes.c_char_p * 1)(None)
    exec_result, exec_errno = _raw_syscall(_bootstrap._SYS_EXECVE, b"/bin/true", argv, envp)
    required = (
        (clone3_result, clone3_errno) == (-1, errno.ENOSYS)
        and (clone_result, clone_errno) == (-1, errno.EPERM)
        and (fork_result, fork_errno) == (-1, errno.EPERM)
        and (vfork_result, vfork_errno) == (-1, errno.EPERM)
        and (unshare_result, unshare_errno) == (-1, errno.EPERM)
        and (exec_result, exec_errno) == (-1, errno.EPERM)
    )
    if not required:
        raise StrixWorkerSeccompError(
            "worker seccomp escape probe did not match the required refusal"
        )

    network_escape_refused: bool | None = None
    filesystem_escape_refused: bool | None = None
    if require_private_boundary:
        filesystem_escape_refused = not os.path.exists("/etc/passwd") and not os.path.exists(
            "/proc/self/fd"
        )
        if not filesystem_escape_refused:
            raise StrixWorkerSeccompError("worker private-root escape probe failed")
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.25)
        try:
            result = probe.connect_ex(("192.0.2.1", 443))
        finally:
            probe.close()
        network_escape_refused = result in {errno.ENETUNREACH, errno.EHOSTUNREACH}
        if not network_escape_refused:
            raise StrixWorkerSeccompError("worker non-loopback network escape probe failed")

    return {
        "schema_version": "bluefire.strix-worker-seccomp-self-test.v1",
        "installation": installation.to_dict(),
        "thread_allowed": True,
        "clone3_refused_as_unsupported": True,
        "process_clone_refused": True,
        "fork_refused": True,
        "vfork_refused": True,
        "exec_refused": True,
        "namespace_change_refused": True,
        "filesystem_escape_refused": filesystem_escape_refused,
        "network_escape_refused": network_escape_refused,
    }


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--private-boundary-self-test", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.self_test == arguments.private_boundary_self_test:
        parser.error("choose exactly one self-test mode")
    result = _seccomp_self_test(require_private_boundary=arguments.private_boundary_self_test)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess proof on Linux
    raise SystemExit(_main())


__all__ = [
    "INSTALLATION_SCHEMA",
    "POLICY_BYTES",
    "POLICY_DIGEST",
    "POLICY_SCHEMA",
    "InstalledSeccompPolicy",
    "StrixWorkerSeccompError",
    "arm_installed_worker_seccomp",
]
