"""Read-only Windows file handles for the fixed reader and setup verifier.

These internal primitives do not establish enrollment or authorize a pathname.
The enrolled caller must supply only its fixed recipe, hold all ancestors, and
own a process deadline around potentially blocking native calls.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, cast

from .runner_descriptor_io import descriptor_identity
from .windows_owner_acl import _handle_from_descriptor, _windows_extended_path


class WindowsFileHandleError(RuntimeError):
    """A path-free failure to inspect an ordinary, held local NTFS object."""


class WindowsDataOpenDenied(WindowsFileHandleError):
    """Only the explicit data-open call returned Win32 ERROR_ACCESS_DENIED."""


@dataclass(frozen=True)
class WindowsFileFacts:
    identity: tuple[int, int]
    final_path: str = field(repr=False)
    directory: bool
    size: int
    links: int
    attributes: int
    created: int
    written: int
    changed: int


class _Basic(ctypes.Structure):
    _fields_ = [
        ("created", ctypes.c_int64),
        ("accessed", ctypes.c_int64),
        ("written", ctypes.c_int64),
        ("changed", ctypes.c_int64),
        ("attributes", ctypes.c_uint32),
    ]


class _Standard(ctypes.Structure):
    _fields_ = [
        ("allocation", ctypes.c_int64),
        ("size", ctypes.c_int64),
        ("links", ctypes.c_uint32),
        ("delete_pending", ctypes.c_ubyte),
        ("directory", ctypes.c_ubyte),
    ]


class _Tag(ctypes.Structure):
    _fields_ = [("attributes", ctypes.c_uint32), ("tag", ctypes.c_uint32)]


def _kernel() -> ctypes.CDLL:
    if sys.platform != "win32":
        raise WindowsFileHandleError("Windows resource observation is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetVolumeInformationByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    kernel.GetVolumeInformationByHandleW.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = (wintypes.HANDLE,)
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)
    kernel.GetDriveTypeW.restype = wintypes.UINT
    return kernel


def open_observation(path: Path, *, directory: bool, data: bool = False) -> int:
    """Fresh noninherited open, with no write/delete access or sharing.

    The returned descriptor belongs to the caller. Only a data-open denial is
    distinguished; missing files, traversal and metadata failures stay unknown.
    """
    if type(directory) is not bool or type(data) is not bool or (directory and data):
        raise WindowsFileHandleError("Windows resource open request is invalid")
    kernel = _kernel()
    import msvcrt

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or len(path.drive) != 2
        or path.drive[1] != ":"
        or not path.drive[0].isascii()
        or not path.drive[0].isalpha()
        or kernel.GetDriveTypeW(path.drive + "\\") != 3
    ):
        raise WindowsFileHandleError("Windows resource is not on a fixed local drive")
    handle = kernel.CreateFileW(
        os.fspath(_windows_extended_path(path)),
        0x20080 | int(data),
        1,
        None,
        3,
        0x00200000 | (0x02000000 if directory else 0x80),
        None,
    )
    if handle in (None, 0, wintypes.HANDLE(-1).value):
        error = cast(Any, ctypes).get_last_error()
        if data and error == 5:
            raise WindowsDataOpenDenied("Windows resource data open was denied")
        raise WindowsFileHandleError("Windows resource open is unavailable")
    descriptor = None
    try:
        open_osfhandle: Callable[[int, int], int] = cast(Any, msvcrt).open_osfhandle
        descriptor = open_osfhandle(
            int(handle), os.O_RDONLY | cast(Any, os).O_BINARY | cast(Any, os).O_NOINHERIT
        )
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise WindowsFileHandleError("Windows resource descriptor is inheritable")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        elif not kernel.CloseHandle(handle):
            raise WindowsFileHandleError("Windows resource handle cleanup failed") from None
        raise


def _query(kernel: ctypes.CDLL, handle: int, kind: int, result: ctypes.Structure) -> None:
    if not kernel.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle), kind, ctypes.byref(result), ctypes.sizeof(result)
    ):
        raise WindowsFileHandleError("Windows resource metadata is unavailable")


def inspect_observation(descriptor: int, *, directory: bool) -> WindowsFileFacts:
    """Inspect a held local NTFS object; no data read or permission change."""
    if type(directory) is not bool:
        raise WindowsFileHandleError("Windows resource kind is invalid")
    kernel = _kernel()
    handle = _handle_from_descriptor(descriptor)
    basic, standard, tag = _Basic(), _Standard(), _Tag()
    _query(kernel, handle, 0, basic)
    _query(kernel, handle, 1, standard)
    _query(kernel, handle, 9, tag)
    if (
        kernel.GetFileType(wintypes.HANDLE(handle)) != 1
        or standard.directory not in (0, 1)
        or bool(standard.directory) is not directory
        or standard.delete_pending
        or standard.size < 0
        or (not directory and standard.links != 1)
        or basic.attributes != tag.attributes
        or tag.attributes & (0x400 | 0x1000)
        or tag.tag
    ):
        raise WindowsFileHandleError("Windows resource is not an ordinary held object")
    name = ctypes.create_unicode_buffer(512)
    length = int(kernel.GetFinalPathNameByHandleW(handle, name, len(name), 0))
    if not 0 < length < len(name):
        raise WindowsFileHandleError("Windows resource final path is unavailable")
    final_path = ctypes.wstring_at(name, length)
    filesystem = ctypes.create_unicode_buffer(32)
    flags = wintypes.DWORD()
    if (
        not kernel.GetVolumeInformationByHandleW(
            handle, None, 0, None, None, ctypes.byref(flags), filesystem, len(filesystem)
        )
        or filesystem.value != "NTFS"
        or not flags.value & 8
    ):
        raise WindowsFileHandleError("Windows resource is not on an ACL-capable NTFS volume")
    identity = descriptor_identity(descriptor, directory=directory)
    if identity[1] == 0:
        raise WindowsFileHandleError("Windows resource file identity is unavailable")
    return WindowsFileFacts(
        identity,
        final_path,
        directory,
        int(standard.size),
        int(standard.links),
        int(tag.attributes),
        int(basic.created),
        int(basic.written),
        int(basic.changed),
    )
