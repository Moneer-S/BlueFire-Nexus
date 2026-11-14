"""Site-independent post-exec lockdown for the fixed Linux Strix worker.

This file is copied byte-for-byte into the pinned runtime closure as
``/bootstrap/worker_lockdown.py``.  It must remain importable under
``python -I -S`` without adding site-packages.  The fixed bootstrap loads the
already-verified bytes by absolute path, calls :func:`arm`, and only then makes
the pinned application packages importable.
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys

try:  # The exact Python 3.12 closure must provide its closure-local _sha2 module.
    import _sha2 as _sha  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - build-time import on Python 3.10/3.11
    if sys.version_info[:2] >= (3, 12):
        raise
    import _sha256 as _sha  # type: ignore[import-not-found]

POLICY_SCHEMA = "bluefire.strix-worker-seccomp-policy.v1"
INSTALLATION_SCHEMA = "bluefire.strix-worker-seccomp-installation.v1"

_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000

_BPF_LD_W_ABS = 0x20
_BPF_ALU_AND_K = 0x54
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06

_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_TSYNC = 1
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000

# Canonical Linux UAPI numbers.  Python's ``errno.ENOSYS`` is 40 on Windows,
# so using the host module value would make the serialized policy digest vary
# even though the filter is explicitly a Linux x86_64 artifact.
_LINUX_EPERM = 1
_LINUX_ENOSYS = 38

_PR_GET_SECCOMP = 21
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39

_SYS_SECCOMP = 317
_SYS_GETTID = 186
_SYS_CLONE = 56
_SYS_FORK = 57
_SYS_VFORK = 58
_SYS_EXECVE = 59
_SYS_CLONE3 = 435

_CLONE_VM = 0x00000100
_CLONE_SIGHAND = 0x00000800
_CLONE_THREAD = 0x00010000
_CLONE_REQUIRED = _CLONE_VM | _CLONE_SIGHAND | _CLONE_THREAD
_CLONE_EXIT_SIGNAL = 0x000000FF
_CLONE_FORBIDDEN = (
    0x00001000
    | 0x00002000
    | 0x00004000
    | 0x00008000
    | 0x00020000
    | 0x00400000
    | 0x00800000
    | 0x02000000
    | 0x04000000
    | 0x08000000
    | 0x10000000
    | 0x20000000
    | 0x40000000
    | 0x80000000
)

_DENIED_SYSCALLS = (
    _SYS_FORK,
    _SYS_VFORK,
    _SYS_EXECVE,
    101,
    155,
    161,
    163,
    165,
    166,
    167,
    168,
    169,
    170,
    171,
    172,
    173,
    175,
    176,
    179,
    246,
    248,
    249,
    250,
    272,
    298,
    303,
    304,
    308,
    310,
    311,
    312,
    313,
    320,
    321,
    322,
    323,
    424,
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
    428,
    429,
    430,
    431,
    432,
    433,
    438,
    442,
)


class StrixWorkerSeccompError(RuntimeError):
    """Raised when the exact post-exec policy cannot be established."""


class _Instruction:
    __slots__ = ("code", "jt", "jf", "value")

    def __init__(self, code: int, jt: int, jf: int, value: int) -> None:
        self.code = code
        self.jt = jt
        self.jf = jf
        self.value = value

    def bytes(self) -> bytes:
        return struct.pack("<HBBI", self.code, self.jt, self.jf, self.value)


class _Jump:
    __slots__ = ("code", "value", "when_true", "when_false")

    def __init__(self, code: int, value: int, when_true: str, when_false: str) -> None:
        self.code = code
        self.value = value
        self.when_true = when_true
        self.when_false = when_false


class _Assembler:
    def __init__(self) -> None:
        self.rows: list[_Instruction | _Jump] = []
        self.labels: dict[str, int] = {}

    def label(self, name: str) -> None:
        if name in self.labels:
            raise AssertionError("duplicate seccomp label")
        self.labels[name] = len(self.rows)

    def statement(self, code: int, value: int) -> None:
        self.rows.append(_Instruction(code, 0, 0, value))

    def jump(self, code: int, value: int, when_true: str, when_false: str) -> None:
        self.rows.append(_Jump(code, value, when_true, when_false))

    def finish(self) -> tuple[_Instruction, ...]:
        result = []
        for index, row in enumerate(self.rows):
            if isinstance(row, _Instruction):
                result.append(row)
                continue
            offsets = []
            for target in (row.when_true, row.when_false):
                if target not in self.labels:
                    raise AssertionError("missing seccomp label")
                offset = self.labels[target] - index - 1
                if not 0 <= offset <= 255:
                    raise AssertionError("seccomp branch is out of range")
                offsets.append(offset)
            result.append(_Instruction(row.code, offsets[0], offsets[1], row.value))
        return tuple(result)


def _errno_result(number: int) -> int:
    return _SECCOMP_RET_ERRNO | number


def _build_policy() -> tuple[_Instruction, ...]:
    builder = _Assembler()
    builder.statement(_BPF_LD_W_ABS, 4)
    builder.jump(_BPF_JMP_JEQ_K, _AUDIT_ARCH_X86_64, "load_nr", "kill")
    builder.label("load_nr")
    builder.statement(_BPF_LD_W_ABS, 0)
    builder.jump(_BPF_JMP_JSET_K, _X32_SYSCALL_BIT, "kill", "check_clone3")
    builder.label("check_clone3")
    builder.jump(_BPF_JMP_JEQ_K, _SYS_CLONE3, "clone3_enosys", "check_clone")
    builder.label("check_clone")
    builder.jump(_BPF_JMP_JEQ_K, _SYS_CLONE, "clone_high", "denied_0")
    for index, syscall_number in enumerate(_DENIED_SYSCALLS):
        builder.label(f"denied_{index}")
        following = f"denied_{index + 1}" if index + 1 < len(_DENIED_SYSCALLS) else "allow"
        builder.jump(_BPF_JMP_JEQ_K, syscall_number, "eperm", following)
    builder.label("clone_high")
    builder.statement(_BPF_LD_W_ABS, 20)
    builder.jump(_BPF_JMP_JEQ_K, 0, "clone_signal", "eperm")
    builder.label("clone_signal")
    builder.statement(_BPF_LD_W_ABS, 16)
    builder.statement(_BPF_ALU_AND_K, _CLONE_EXIT_SIGNAL)
    builder.jump(_BPF_JMP_JEQ_K, 0, "clone_required", "eperm")
    builder.label("clone_required")
    builder.statement(_BPF_LD_W_ABS, 16)
    builder.statement(_BPF_ALU_AND_K, _CLONE_REQUIRED)
    builder.jump(_BPF_JMP_JEQ_K, _CLONE_REQUIRED, "clone_forbidden", "eperm")
    builder.label("clone_forbidden")
    builder.statement(_BPF_LD_W_ABS, 16)
    builder.statement(_BPF_ALU_AND_K, _CLONE_FORBIDDEN)
    builder.jump(_BPF_JMP_JEQ_K, 0, "allow", "eperm")
    builder.label("clone3_enosys")
    builder.statement(_BPF_RET_K, _errno_result(_LINUX_ENOSYS))
    builder.label("eperm")
    builder.statement(_BPF_RET_K, _errno_result(_LINUX_EPERM))
    builder.label("allow")
    builder.statement(_BPF_RET_K, _SECCOMP_RET_ALLOW)
    builder.label("kill")
    builder.statement(_BPF_RET_K, _SECCOMP_RET_KILL_PROCESS)
    return builder.finish()


_POLICY = _build_policy()
POLICY_BYTES = b"".join(instruction.bytes() for instruction in _POLICY)
POLICY_DIGEST = "sha256:" + _sha.sha256(POLICY_BYTES).hexdigest()


class InstalledSeccompPolicy:
    """Kernel-observed installation evidence, never reusable authority."""

    __slots__ = (
        "schema_version",
        "policy_schema",
        "policy_digest",
        "audit_arch",
        "no_new_privileges",
        "seccomp_mode",
        "tsync",
        "clone3_errno",
        "process_creation_errno",
    )

    def __init__(self, seccomp_mode: int) -> None:
        self.schema_version = INSTALLATION_SCHEMA
        self.policy_schema = POLICY_SCHEMA
        self.policy_digest = POLICY_DIGEST
        self.audit_arch = "linux-x86_64"
        self.no_new_privileges = True
        self.seccomp_mode = seccomp_mode
        self.tsync = True
        self.clone3_errno = _LINUX_ENOSYS
        self.process_creation_errno = _LINUX_EPERM

    def to_dict(self) -> dict[str, object]:
        return {slot: getattr(self, slot) for slot in self.__slots__}


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("value", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_SockFilter)),
    ]


_INSTALLED: InstalledSeccompPolicy | None = None


def arm(*, expected_policy_digest: str = POLICY_DIGEST) -> InstalledSeccompPolicy:
    """Install NNP + the exact TSYNC filter in the fresh process leader."""

    global _INSTALLED
    if expected_policy_digest != POLICY_DIGEST:
        raise StrixWorkerSeccompError("worker seccomp policy identity does not match")
    if _INSTALLED is not None:
        return _INSTALLED
    if sys.platform != "linux" or os.uname().machine.lower() not in {"x86_64", "amd64"}:
        raise StrixWorkerSeccompError("worker seccomp requires Linux x86_64")

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
    syscall = library.syscall
    syscall.restype = ctypes.c_long
    if syscall(_SYS_GETTID) != os.getpid():
        raise StrixWorkerSeccompError("worker seccomp must be armed by the process leader")

    filters = (_SockFilter * len(_POLICY))(
        *(_SockFilter(row.code, row.jt, row.jf, row.value) for row in _POLICY)
    )
    program = _SockFprog(len(_POLICY), filters)
    ctypes.set_errno(0)
    if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise StrixWorkerSeccompError(
            "worker no-new-privileges was refused: errno " + str(ctypes.get_errno())
        )
    ctypes.set_errno(0)
    if (
        syscall(
            _SYS_SECCOMP,
            _SECCOMP_SET_MODE_FILTER,
            _SECCOMP_FILTER_FLAG_TSYNC,
            ctypes.byref(program),
        )
        != 0
    ):
        raise StrixWorkerSeccompError(
            "worker seccomp installation was refused: errno " + str(ctypes.get_errno())
        )
    no_new_privileges = prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    seccomp_mode = prctl(_PR_GET_SECCOMP, 0, 0, 0, 0)
    if no_new_privileges != 1 or seccomp_mode != _SECCOMP_MODE_FILTER:
        raise StrixWorkerSeccompError("worker seccomp kernel state could not be verified")
    _INSTALLED = InstalledSeccompPolicy(seccomp_mode)
    return _INSTALLED


__all__ = [
    "INSTALLATION_SCHEMA",
    "POLICY_BYTES",
    "POLICY_DIGEST",
    "POLICY_SCHEMA",
    "InstalledSeccompPolicy",
    "StrixWorkerSeccompError",
    "arm",
]
