"""Trusted operating-system runtime path discovery."""

from __future__ import annotations

import ctypes
import os
import stat
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path

_TOKEN_KNOWN_FOLDER_ACCESS = 0x0008 | 0x0004  # TOKEN_QUERY | TOKEN_IMPERSONATE


def _windows_directory() -> Path:
    if os.name != "nt":
        raise OSError("the Windows directory is unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetWindowsDirectoryW.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    kernel32.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(kernel32.GetWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("the Windows directory is unavailable")
    candidate = Path(os.path.abspath(buffer.value))
    try:
        details = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise OSError("the Windows directory is unavailable") from exc
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        candidate != resolved
        or not stat.S_ISDIR(details.st_mode)
        or candidate.is_symlink()
        or bool(int(getattr(details, "st_file_attributes", 0)) & reparse)
    ):
        raise OSError("the Windows directory is unsafe")
    return resolved


def _git_candidates() -> Sequence[Path]:
    if os.name == "nt":
        windows = _windows_directory()
        return (windows.parent / "Program Files" / "Git" / "cmd" / "git.exe",)
    return (Path("/usr/bin/git"),)


def trusted_git_executable() -> Path:
    """Resolve Git only from fixed operating-system installation paths."""

    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for candidate in _git_candidates():
        try:
            details = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if (
            candidate.is_absolute()
            and candidate == resolved
            and candidate.name.casefold() in {"git", "git.exe"}
            and stat.S_ISREG(details.st_mode)
            and not candidate.is_symlink()
            and not bool(int(getattr(details, "st_file_attributes", 0)) & reparse)
            and os.access(resolved, os.X_OK)
            and (
                os.name == "nt"
                or (
                    int(getattr(details, "st_uid", -1)) == 0
                    and not details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                )
            )
        ):
            return resolved
    raise OSError("the fixed Git executable is unavailable")


def trusted_git_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a bounded, config-free environment for fixed Git commands."""

    values = os.environ if environ is None else environ
    environment = {
        name: values[name]
        for name in ("TEMP", "TMP")
        if isinstance(values.get(name), str) and values[name]
    }
    if os.name == "nt":
        windows = os.fspath(_windows_directory())
        environment.update({"SystemRoot": windows, "SYSTEMROOT": windows, "WINDIR": windows})
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    return environment


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


__all__ = ["runtime_temp_parent", "trusted_git_environment", "trusted_git_executable"]
