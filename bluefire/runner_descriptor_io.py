"""Bounded inspection of caller-owned open descriptors; no pathname reopening."""

from __future__ import annotations

import ctypes
import os
import stat
import sys

_LINUX_AT_EMPTY_PATH = 0x1000
_LINUX_STATX_MNT_ID = 0x1000


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


def _descriptor_mount_identity(descriptor: int) -> int | None:
    """Return Linux's mount ID for an already-open descriptor."""

    if not sys.platform.startswith("linux"):
        return None
    import ctypes
    import errno

    buffer = (ctypes.c_ubyte * 256)()
    try:
        statx = ctypes.CDLL(None, use_errno=True).statx
    except AttributeError:
        raise OSError(errno.ENOSYS, "descriptor mount identity is unavailable") from None
    statx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
    )
    statx.restype = ctypes.c_int
    if (
        statx(
            descriptor,
            b"",
            _LINUX_AT_EMPTY_PATH,
            _LINUX_STATX_MNT_ID,
            ctypes.byref(buffer),
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, "descriptor mount identity is unavailable")
    mask = int.from_bytes(bytes(buffer[0:4]), "little")
    mount_id = int.from_bytes(bytes(buffer[144:152]), "little")
    if not mask & _LINUX_STATX_MNT_ID or mount_id <= 0:
        raise OSError(errno.ENOSYS, "descriptor mount identity is unavailable")
    return mount_id


def _read_descriptor_bounded(descriptor: int, maximum: int) -> bytes:
    if isinstance(maximum, bool) or maximum < 0:
        raise OSError("invalid bounded read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= maximum:
        block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(payload)))
        if not block:
            break
        payload.extend(block)
    if len(payload) > maximum:
        raise OSError("private file exceeds its size limit")
    return bytes(payload)
