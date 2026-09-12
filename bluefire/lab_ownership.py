"""Stable host identities and exact registration ownership for disposable labs."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
from pathlib import Path

from .windows_owner_acl import _windows_mark_delete_descriptor, _windows_open_descriptor

REGISTRY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"


def identity_format() -> str:
    return "windows-file-id-info.v1" if sys.platform == "win32" else "posix-stat.v1"


def _ordinary(details: os.stat_result, *, directory: bool) -> None:
    good_type = (
        stat.S_ISDIR(details.st_mode)
        if directory
        else stat.S_ISREG(details.st_mode) and details.st_nlink == 1
    )
    if not good_type or int(getattr(details, "st_file_attributes", 0)) & 0x400:
        raise ValueError("lab state must use ordinary, unlinked files and directories")


def _windows_file_identity(descriptor: int) -> tuple[int, int]:
    """Read the full 64-bit volume and 128-bit file ID on every Python version."""

    import msvcrt
    from ctypes import wintypes

    class FileIdInfo(ctypes.Structure):
        _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong), ("FileId", ctypes.c_ubyte * 16)]

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    operation = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    operation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    operation.restype = wintypes.BOOL
    handle = msvcrt.get_osfhandle(descriptor)
    information = FileIdInfo()
    if handle == -1 or not operation(
        wintypes.HANDLE(handle), 18, ctypes.byref(information), ctypes.sizeof(information)
    ):
        raise OSError("full Windows lab file identity is unavailable")
    attributes = FileAttributeTagInfo()
    if (
        not operation(
            wintypes.HANDLE(handle), 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        )
        or attributes.FileAttributes & 0x400
    ):
        raise OSError("ordinary Windows lab file identity is unavailable")
    return int(information.VolumeSerialNumber), int.from_bytes(information.FileId, "little")


def descriptor_identity(descriptor: int, *, directory: bool = False) -> tuple[int, int]:
    details = os.fstat(descriptor)
    _ordinary(details, directory=directory)
    if sys.platform == "win32":
        return _windows_file_identity(descriptor)
    return int(details.st_dev), int(details.st_ino)


def identity(path: Path, *, directory: bool) -> tuple[int, int]:
    _ordinary(path.lstat(), directory=directory)
    if sys.platform == "win32":
        descriptor = _windows_open_descriptor(path, directory=directory, share_write=True)
    else:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | (getattr(os, "O_DIRECTORY", 0) if directory else 0),
        )
    try:
        return descriptor_identity(descriptor, directory=directory)
    finally:
        os.close(descriptor)


def registration(name: str) -> tuple[str, Path] | None:
    if sys.platform != "win32":
        raise ValueError("WSL registration requires Windows")
    import winreg

    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    matches = []
    with root:
        count = winreg.QueryInfoKey(root)[0]
        if not 0 <= count <= 256:
            raise ValueError("WSL registration inventory exceeds its bound")
        for index in range(count):
            key = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, key, 0, winreg.KEY_READ) as entry:
                if winreg.QueryValueEx(entry, "DistributionName")[0] != name:
                    continue
                version = winreg.QueryValueEx(entry, "Version")[0]
                base = winreg.QueryValueEx(entry, "BasePath")[0]
                if version != 2 or not isinstance(base, str):
                    raise ValueError("owned distribution registration is not WSL2")
                # Keep the literal absolute path: resolving a reparse point here
                # would conceal the unsafe object from the storage identity check.
                path = Path(base)
                if not path.is_absolute() or path != path.resolve(strict=True):
                    raise ValueError("owned distribution storage path is not canonical")
                matches.append((key, path))
    if len(matches) > 1:
        raise ValueError("owned distribution name is ambiguous")
    return matches[0] if matches else None


def path_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def remove_empty_storage(path: Path, expected: tuple[int, int]) -> bool:
    """Remove only the identified empty directory; retained files fail closed."""

    try:
        if path_absent(path):
            return True
        if sys.platform == "win32":
            descriptor = _windows_open_descriptor(
                path, directory=True, delete=True, share_write=True
            )
            try:
                if descriptor_identity(descriptor, directory=True) != expected:
                    return False
                # This operation targets the pinned directory, never a replacement
                # at its pathname. Windows refuses deletion while children remain.
                _windows_mark_delete_descriptor(descriptor)
            finally:
                os.close(descriptor)
        else:
            if identity(path, directory=True) != expected or any(path.iterdir()):
                return False
            path.rmdir()
        return path_absent(path)
    except (OSError, ValueError):
        return False
