"""Trusted operating-system runtime path discovery."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path

_TOKEN_KNOWN_FOLDER_ACCESS = 0x0008 | 0x0004  # TOKEN_QUERY | TOKEN_IMPERSONATE


def _windows_directory() -> Path:
    if sys.platform != "win32":
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

    if sys.platform != "win32":
        return Path(tempfile.gettempdir()).resolve(strict=True)
    # userenv!GetUserProfileDirectoryW answers from the token's own profile
    # record. SHGetKnownFolderPath cannot be used for this: the known-folder
    # values are REG_EXPAND_SZ and are expanded against the calling process
    # environment block, so a caller that redirects USERPROFILE silently moves
    # every known folder with it. That is precisely the aliasing this function
    # exists to refuse, and it also made the resolved root depend on whether
    # the redirected profile happened to have AppData\Local yet.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
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
    userenv.GetUserProfileDirectoryW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    userenv.GetUserProfileDirectoryW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            _TOKEN_KNOWN_FOLDER_ACCESS,
            ctypes.byref(token),
        ):
            raise OSError("the process token is unavailable")
        size = wintypes.DWORD(0)
        userenv.GetUserProfileDirectoryW(token, None, ctypes.byref(size))
        if not 0 < size.value <= 32_768:
            raise OSError("the process-token temp root is unavailable")
        buffer = ctypes.create_unicode_buffer(size.value)
        if not userenv.GetUserProfileDirectoryW(token, buffer, ctypes.byref(size)):
            raise OSError("the process-token temp root is unavailable")
        profile = buffer.value
        if not profile:
            raise OSError("the process-token temp root is unavailable")
        parent = (Path(profile) / "AppData" / "Local" / "Temp").resolve(strict=True)
        if not parent.is_dir():
            raise OSError("the process-token temp root is invalid")
        return parent
    finally:
        if token:
            kernel32.CloseHandle(token)


__all__ = ["runtime_temp_parent", "trusted_git_environment", "trusted_git_executable"]
