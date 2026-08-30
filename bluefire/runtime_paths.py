"""Trusted operating-system runtime path discovery."""

from __future__ import annotations

import ctypes
import os
import tempfile
import uuid
from ctypes import wintypes
from pathlib import Path

_TOKEN_KNOWN_FOLDER_ACCESS = 0x0008 | 0x0004  # TOKEN_QUERY | TOKEN_IMPERSONATE


def runtime_temp_parent() -> Path:
    """Resolve temp storage from the process token, not environment aliases."""

    if os.name != "nt":
        return Path(tempfile.gettempdir()).resolve(strict=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    shell32.SHGetKnownFolderPath.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
    ole32.CoTaskMemFree.restype = None
    token = wintypes.HANDLE()
    value = wintypes.LPWSTR()
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            _TOKEN_KNOWN_FOLDER_ACCESS,
            ctypes.byref(token),
        ):
            raise OSError("the process token is unavailable")
        local_app_data = ctypes.create_string_buffer(
            uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le
        )
        if (
            shell32.SHGetKnownFolderPath(
                ctypes.byref(local_app_data),
                0,
                token,
                ctypes.byref(value),
            )
            != 0
            or not value.value
        ):
            raise OSError("the process-token temp root is unavailable")
        parent = (Path(value.value) / "Temp").resolve(strict=True)
        if not parent.is_dir():
            raise OSError("the process-token temp root is invalid")
        return parent
    finally:
        if value:
            ole32.CoTaskMemFree(value)
        if token:
            kernel32.CloseHandle(token)


__all__ = ["runtime_temp_parent"]
