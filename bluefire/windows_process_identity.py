"""Native Windows process creation identity and liveness inspection.

The retained creation timestamp distinguishes a current process from a reused
PID. This boundary only inspects an existing process; it never launches or
terminates one.
"""

from __future__ import annotations

import ctypes
import os
from typing import Any, Mapping, cast

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102


class WindowsProcessIdentityError(ValueError):
    """A native process identity or its current liveness cannot be established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WindowsProcessIdentityError(message)


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields, f"{label} is invalid")
    return cast(Mapping[str, Any], value)


def _filetime_value(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _open_process(process_id: int, *, absent_ok: bool) -> int | None:
    _require(os.name == "nt", "Windows process identity proof is unavailable")
    _require(type(process_id) is int and process_id > 0, "process identity is invalid")
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    handle = open_process(
        _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE,
        0,
        process_id,
    )
    if handle:
        return int(handle)
    error = cast(Any, ctypes).get_last_error()
    if absent_ok and error in {87, 1168}:
        return None
    raise WindowsProcessIdentityError(f"Windows process identity cannot be opened ({error})")


def _close_handle(handle: int) -> None:
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        raise WindowsProcessIdentityError("Windows process identity handle could not be closed")


def _process_creation_time(handle: int) -> int:
    from ctypes import wintypes

    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    get_times = kernel32.GetProcessTimes
    get_times.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    get_times.restype = ctypes.c_int
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not get_times(
        ctypes.c_void_p(handle),
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise WindowsProcessIdentityError("Windows process creation identity is unavailable")
    value = _filetime_value(created)
    _require(value > 0, "Windows process creation identity is invalid")
    return value


def _process_handle_running(handle: int) -> bool:
    kernel32 = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
    wait = kernel32.WaitForSingleObject
    wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    wait.restype = ctypes.c_uint32
    result = int(wait(ctypes.c_void_p(handle), 0))
    if result == _WAIT_TIMEOUT:
        return True
    if result == _WAIT_OBJECT_0:
        return False
    raise WindowsProcessIdentityError("Windows process liveness probe failed")


def capture_process_identity(process_id: int) -> Mapping[str, int]:
    handle = _open_process(process_id, absent_ok=False)
    assert handle is not None
    try:
        identity = {
            "process_id": process_id,
            "creation_time_100ns": _process_creation_time(handle),
        }
        _require(_process_handle_running(handle), "Windows process is not running")
        return identity
    finally:
        _close_handle(handle)


def process_identity_running(identity: Mapping[str, Any]) -> bool:
    row = _exact(identity, {"process_id", "creation_time_100ns"}, "process identity")
    process_id = row.get("process_id")
    created = row.get("creation_time_100ns")
    _require(
        type(process_id) is int and process_id > 0 and type(created) is int and created > 0,
        "process identity is invalid",
    )
    handle = _open_process(cast(int, process_id), absent_ok=True)
    if handle is None:
        return False
    try:
        if _process_creation_time(handle) != created:
            return False
        return _process_handle_running(handle)
    finally:
        _close_handle(handle)
