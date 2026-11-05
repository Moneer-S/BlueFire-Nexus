"""Platform file identity primitives shared across trusted boundaries."""

from __future__ import annotations

import ctypes
import os
import stat
import sys
from typing import Any


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


def _windows_file_identity(
    descriptor: int, *, platform: str, ctypes_module: Any
) -> tuple[int, int]:
    """Read the full 64-bit volume and 128-bit file ID on every Python version."""

    if platform != "win32":
        raise OSError("native Windows file identity is available only on Windows")

    import msvcrt
    from ctypes import wintypes

    class FileIdInfo(ctypes_module.Structure):
        _fields_ = [
            ("VolumeSerialNumber", ctypes_module.c_ulonglong),
            ("FileId", ctypes_module.c_ubyte * 16),
        ]

    class FileAttributeTagInfo(ctypes_module.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    operation = ctypes_module.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandleEx
    operation.argtypes = (
        wintypes.HANDLE,
        ctypes_module.c_int,
        ctypes_module.c_void_p,
        wintypes.DWORD,
    )
    operation.restype = wintypes.BOOL
    handle = msvcrt.get_osfhandle(descriptor)
    information = FileIdInfo()
    if handle == -1 or not operation(
        wintypes.HANDLE(handle),
        18,
        ctypes_module.byref(information),
        ctypes_module.sizeof(information),
    ):
        raise OSError("full Windows lab file identity is unavailable")
    attributes = FileAttributeTagInfo()
    if (
        not operation(
            wintypes.HANDLE(handle),
            9,
            ctypes_module.byref(attributes),
            ctypes_module.sizeof(attributes),
        )
        or attributes.FileAttributes & 0x400
    ):
        raise OSError("ordinary Windows lab file identity is unavailable")
    return int(information.VolumeSerialNumber), int.from_bytes(information.FileId, "little")


def descriptor_identity(descriptor: int, *, directory: bool = False) -> tuple[int, int]:
    details = os.fstat(descriptor)
    _ordinary(details, directory=directory)
    if sys.platform == "win32":
        return _windows_file_identity(descriptor, platform=sys.platform, ctypes_module=ctypes)
    return int(details.st_dev), int(details.st_ino)
