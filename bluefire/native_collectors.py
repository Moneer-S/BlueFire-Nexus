"""Bounded, read-only native process observation backends.

The collector layer calls these functions after an action has been selected and
executed; this module never launches, modifies, or terminates a process.  Only a
single caller-supplied PID is inspected, with fixed byte, entry, and time bounds.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping


class NativeProcessError(RuntimeError):
    """Raised when a native process identity cannot be observed safely."""


_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_MAX_PATH = 32_768
_MAX_PROCESS_ENTRIES = 16_384
_MAX_PROC_STAT_BYTES = 16 * 1024


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def native_process_readiness() -> Mapping[str, Any]:
    """Describe the native backend available on the current platform."""

    if sys.platform == "win32" and os.name == "nt":
        return {
            "ready": True,
            "platform": "windows",
            "backend": "CreateToolhelp32Snapshot/GetProcessTimes",
        }
    if sys.platform.startswith("linux") and Path("/proc/self/stat").is_file():
        return {
            "ready": True,
            "platform": "linux",
            "backend": "/proc/<pid>/stat",
        }
    return {
        "ready": False,
        "platform": sys.platform,
        "backend": "unavailable",
    }


def observe_native_process(
    process_id: int,
    *,
    expected_parent_process_id: int | None,
    timeout_seconds: float,
) -> Mapping[str, Any]:
    """Observe one exact PID without enumerating unbounded host state."""

    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise NativeProcessError("process_id must be a positive integer")
    if expected_parent_process_id is not None and (
        isinstance(expected_parent_process_id, bool)
        or not isinstance(expected_parent_process_id, int)
        or expected_parent_process_id <= 0
    ):
        raise NativeProcessError("expected_parent_process_id must be a positive integer")
    if not 0 < timeout_seconds <= 60:
        raise NativeProcessError("native process timeout is invalid")
    deadline = time.monotonic() + timeout_seconds
    if sys.platform == "win32" and os.name == "nt":
        return _observe_windows_process(
            process_id,
            expected_parent_process_id=expected_parent_process_id,
            deadline=deadline,
        )
    if sys.platform.startswith("linux"):
        return _observe_linux_process(
            process_id,
            expected_parent_process_id=expected_parent_process_id,
            deadline=deadline,
        )
    raise NativeProcessError("no native process observer is available on this platform")


def _observe_windows_process(
    process_id: int,
    *,
    expected_parent_process_id: int | None,
    deadline: float,
) -> Mapping[str, Any]:
    if sys.platform != "win32":
        raise NativeProcessError("the Windows process observer is unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W))
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W))
    process_next.restype = wintypes.BOOL
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    get_process_times.restype = wintypes.BOOL
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    snapshot = create_snapshot(_TH32CS_SNAPPROCESS, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot in (None, 0, invalid_handle):
        raise NativeProcessError("the Windows process snapshot is unavailable")
    entry = _ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
    found: tuple[int, str] | None = None
    inspected = 0
    try:
        available = bool(process_first(snapshot, ctypes.byref(entry)))
        while available and inspected < _MAX_PROCESS_ENTRIES:
            if time.monotonic() > deadline:
                raise NativeProcessError("native process observation timed out")
            inspected += 1
            if int(entry.th32ProcessID) == process_id:
                found = (int(entry.th32ParentProcessID), str(entry.szExeFile))
                break
            available = bool(process_next(snapshot, ctypes.byref(entry)))
    finally:
        close_handle(snapshot)
    if found is None:
        raise NativeProcessError("the requested PID was absent from the Windows snapshot")
    parent_process_id, snapshot_name = found
    if expected_parent_process_id is not None and parent_process_id != expected_parent_process_id:
        raise NativeProcessError("the requested PID does not have the expected parent")

    handle = open_process(_PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
    if handle in (None, 0):
        raise NativeProcessError("the requested PID could not be identity-pinned")
    creation = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    image_buffer = ctypes.create_unicode_buffer(_MAX_PATH)
    image_length = wintypes.DWORD(len(image_buffer))
    try:
        if time.monotonic() > deadline or not get_process_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise NativeProcessError("the requested PID creation identity is unavailable")
        if not query_image(handle, 0, image_buffer, ctypes.byref(image_length)):
            raise NativeProcessError("the requested PID image identity is unavailable")
    finally:
        close_handle(handle)
    executable_name = Path(image_buffer.value).name
    if not executable_name or executable_name.casefold() != snapshot_name.casefold():
        raise NativeProcessError("the requested PID identity changed during observation")
    creation_filetime = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    return {
        "platform": "windows",
        "native_api": "CreateToolhelp32Snapshot/GetProcessTimes",
        "process_id": process_id,
        "parent_process_id": parent_process_id,
        "executable_name": executable_name,
        "creation_identity": str(creation_filetime),
        "entries_inspected": inspected,
        "entry_limit": _MAX_PROCESS_ENTRIES,
    }


def _read_proc_stat(path: Path) -> tuple[int, int, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise NativeProcessError("the requested PID stat record is unavailable") from exc
    if not raw or len(raw) > _MAX_PROC_STAT_BYTES:
        raise NativeProcessError("the requested PID stat record is invalid")
    try:
        text = raw.decode("utf-8")
        close = text.rindex(")")
        open_index = text.index("(")
        process_id = int(text[:open_index].strip())
        executable_name = text[open_index + 1 : close]
        fields = text[close + 1 :].strip().split()
        parent_process_id = int(fields[1])
        start_ticks = int(fields[19])
    except (UnicodeError, ValueError, IndexError) as exc:
        raise NativeProcessError("the requested PID stat record is malformed") from exc
    if not executable_name or any(ord(character) < 32 for character in executable_name):
        raise NativeProcessError("the requested PID executable name is invalid")
    return process_id, parent_process_id, f"{start_ticks}:{executable_name}"


def _observe_linux_process(
    process_id: int,
    *,
    expected_parent_process_id: int | None,
    deadline: float,
) -> Mapping[str, Any]:
    stat_path = Path("/proc") / str(process_id) / "stat"
    first_pid, parent_process_id, first_identity = _read_proc_stat(stat_path)
    if first_pid != process_id:
        raise NativeProcessError("the requested PID stat identity does not match")
    if expected_parent_process_id is not None and parent_process_id != expected_parent_process_id:
        raise NativeProcessError("the requested PID does not have the expected parent")
    if time.monotonic() > deadline:
        raise NativeProcessError("native process observation timed out")
    try:
        executable_name = Path(os.readlink(stat_path.parent / "exe")).name
    except OSError as exc:
        raise NativeProcessError("the requested PID image identity is unavailable") from exc
    second_pid, second_parent, second_identity = _read_proc_stat(stat_path)
    if (
        second_pid != process_id
        or second_parent != parent_process_id
        or second_identity != first_identity
        or not executable_name
    ):
        raise NativeProcessError("the requested PID identity changed during observation")
    return {
        "platform": "linux",
        "native_api": "/proc/<pid>/stat",
        "process_id": process_id,
        "parent_process_id": parent_process_id,
        "executable_name": executable_name,
        "creation_identity": first_identity.split(":", 1)[0],
        "bytes_limit": _MAX_PROC_STAT_BYTES,
    }


__all__ = [
    "NativeProcessError",
    "native_process_readiness",
    "observe_native_process",
]
