"""Exact Darwin monotonic clock and process-layout primitives."""

from __future__ import annotations

import ctypes
import os
import re
import sys

from .macos_file_access_contract import MacOSFileAccessContractError

MONOTONIC_CLOCK = "darwin-mach-absolute-ns"


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
