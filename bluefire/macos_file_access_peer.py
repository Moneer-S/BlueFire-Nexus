"""Darwin consistency observations of a child already owned by the creator.

Neither process metadata nor a start timestamp adopts a process or mints live
authority. The fixed creator must retain its original Popen and unreaped child.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from .macos_file_access_contract import MacOSFileAccessContractError

MONOTONIC_CLOCK = "darwin-mach-absolute-ns"
_IDS = ("real_uid", "effective_uid", "saved_uid", "real_gid", "effective_gid", "saved_gid")


class _BSDInfo(ctypes.Structure):
    # Public proc_bsdinfo, XNU ac9718fb, bsd/sys/proc_info.h. Real SDK layout
    # qualification remains separate from this local declaration's assertions.
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("exit_status", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("parent_pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("real_uid", ctypes.c_uint32),
        ("real_gid", ctypes.c_uint32),
        ("saved_uid", ctypes.c_uint32),
        ("saved_gid", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("command", ctypes.c_char * 16),
        ("name", ctypes.c_char * 32),
        ("open_files", ctypes.c_uint32),
        ("process_group", ctypes.c_uint32),
        ("job_control", ctypes.c_uint32),
        ("terminal", ctypes.c_uint32),
        ("terminal_group", ctypes.c_uint32),
        ("nice", ctypes.c_int32),
        ("start_seconds", ctypes.c_uint64),
        ("start_microseconds", ctypes.c_uint64),
    ]


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def _refuse() -> MacOSFileAccessContractError:
    return MacOSFileAccessContractError("Original Darwin child consistency is unavailable.")


def _supported_runtime() -> bool:
    if sys.platform != "darwin" or ctypes.sizeof(ctypes.c_void_p) != 8:
        return False
    system = os.uname()
    return bool(
        system.machine == "arm64"
        and re.fullmatch(r"25\.[0-9]+\.[0-9]+", system.release)
        and ctypes.sizeof(_BSDInfo) == 136
        and _BSDInfo.start_seconds.offset == 120
        and _BSDInfo.start_microseconds.offset == 128
        and ctypes.sizeof(_Timebase) == 8
        and _Timebase.denom.offset == 4
    )


def darwin_clock_ns() -> int:
    """Use the native wire clock explicitly, without Python clock inference."""
    if not _supported_runtime():
        raise _refuse()
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        clock = library.mach_absolute_time
        clock.argtypes, clock.restype = [], ctypes.c_uint64
        timebase = library.mach_timebase_info
        timebase.argtypes, timebase.restype = [ctypes.POINTER(_Timebase)], ctypes.c_int
        scale = _Timebase()
        if timebase(ctypes.byref(scale)) != 0 or not scale.numer or not scale.denom:
            raise _refuse()
        value = int(clock()) * int(scale.numer) // int(scale.denom)
        if not 0 < value < 2**64:
            raise _refuse()
        return value
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        raise _refuse() from None


def _query_bsd(process_id: int) -> _BSDInfo:
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    query = library.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    facts = _BSDInfo()
    if query(process_id, 3, 0, ctypes.byref(facts), ctypes.sizeof(facts)) != ctypes.sizeof(facts):
        raise _refuse()
    return facts


@dataclass(frozen=True)
class MacOSChildConsistency:
    process_id: int
    parent_id: int
    start: tuple[int, int]
    ids: tuple[int, int, int, int, int, int]

    def identity_document(self) -> dict[str, Any]:
        return {
            "pid": self.process_id,
            "parent_pid": self.parent_id,
            "start_seconds": self.start[0],
            "start_microseconds": self.start[1],
            "ids": dict(zip(_IDS, self.ids, strict=True)),
            "scope": "known_child_consistency_only",
        }


def observe_owned_child(
    process: subprocess.Popen[bytes],
    *,
    expected_ids: Mapping[str, int],
    expected_start: tuple[int, int] | None = None,
) -> MacOSChildConsistency:
    """Check six IDs of an already-retained direct child without reaping it.

    Supplementary groups and executable identity require their separate fixed
    launch/native observations. This function does not establish either one.
    """
    from .runner_client import (
        _darwin_child_exited_without_reap,
        _darwin_child_status_ownership_available,
    )

    try:
        getuid = getattr(os, "getuid", None)
        geteuid = getattr(os, "geteuid", None)
        if (
            not _supported_runtime()
            or not callable(getuid)
            or not callable(geteuid)
            or getuid() != 0
            or geteuid() != 0
            or not isinstance(process, subprocess.Popen)
            or type(process.pid) is not int
            or not 1 < process.pid < 2**31
            or process.returncode is not None
            or not _darwin_child_status_ownership_available()
            or set(expected_ids) != set(_IDS)
            or any(
                type(value) is not int or not 0 < value < 2**32 - 1
                for value in expected_ids.values()
            )
            or not expected_ids["real_uid"]
            == expected_ids["effective_uid"]
            == expected_ids["saved_uid"]
            or not expected_ids["real_gid"]
            == expected_ids["effective_gid"]
            == expected_ids["saved_gid"]
        ):
            raise _refuse()
        if expected_start is not None and (
            type(expected_start) is not tuple
            or len(expected_start) != 2
            or any(type(value) is not int for value in expected_start)
            or not 0 < expected_start[0] < 2**64
            or not 0 <= expected_start[1] < 1_000_000
        ):
            raise _refuse()
        if _darwin_child_exited_without_reap(process.pid):
            raise _refuse()
        parent = os.getpid()
        facts = _query_bsd(process.pid)
        ids = (
            facts.real_uid,
            facts.uid,
            facts.saved_uid,
            facts.real_gid,
            facts.gid,
            facts.saved_gid,
        )
        start = (facts.start_seconds, facts.start_microseconds)
        if (
            facts.pid != process.pid
            or facts.parent_pid != parent
            or not facts.flags & 0x10
            or facts.flags & 0x7
            or not 1 <= facts.status <= 4
            or ids != tuple(expected_ids[key] for key in _IDS)
            or not start[0]
            or not 0 <= start[1] < 1_000_000
            or (expected_start is not None and start != expected_start)
            or process.returncode is not None
            or not _darwin_child_status_ownership_available()
            or _darwin_child_exited_without_reap(process.pid)
        ):
            raise _refuse()
        return MacOSChildConsistency(process.pid, parent, start, ids)
    except (AttributeError, ChildProcessError, OSError, OverflowError, TypeError, ValueError):
        raise _refuse() from None
