"""Descriptor-only preservation evidence for Windows and supported Linux ext4.

These filesystem-assigned identifiers are not an ownership or integrity proof.
Cloned/administratively modified filesystems can repeat them; ext4 generations
are 32-bit values, not cryptographic nonces. Callers retain authenticated records,
content/metadata checks, and their separate live mount and pathname guards.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys

from .runner_descriptor_io import _ordinary, descriptor_identity

_FAILURE = "Historical durable descriptor identity could not be verified."
_UNAVAILABLE = "Durable descriptor identity is unavailable for this filesystem or platform."
_UNSUPPORTED_IOCTL = {errno.ENOTTY, errno.EOPNOTSUPP, errno.ENOSYS}
_EXT_MAGIC = 0xEF53
# Linux LP64 _IOR('f', 44, struct fsuuid) and _IOR('f', 3, long).
# The UUID header is 8 bytes, but its flexible payload requires a 24-byte buffer.
# GETVERSION encodes sizeof(long), while ext4 writes a 32-bit int.
# https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/ext4.h
# https://github.com/torvalds/linux/blob/v6.6/fs/ext4/ioctl.c#L1082-L1108
# https://github.com/torvalds/linux/blob/v6.6/fs/ext4/ioctl.c#L1158-L1160
_GETFSUUID = 0x8008662C
_GETVERSION = 0x80086603


class DurableIdentityUnavailable(OSError):
    """The platform lacks a supported durable identity, not a validation failure."""


class _LinuxStatFS64(ctypes.Structure):
    """The 120-byte Linux x86_64/aarch64 LP64 statfs ABI only.

    Layout: Linux v6.6 include/uapi/asm-generic/statfs.h and glibc's
    sysdeps/unix/sysv/linux/bits/statfs.h. f_fsid is never identity evidence.
    """

    _fields_ = [
        ("f_type", ctypes.c_int64),
        ("f_bsize", ctypes.c_int64),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_namelen", ctypes.c_int64),
        ("f_frsize", ctypes.c_int64),
        ("f_flags", ctypes.c_int64),
        ("f_spare", ctypes.c_int64 * 4),
    ]


def _require_linux_abi() -> None:
    uname = getattr(os, "uname", None)
    if not callable(uname):
        raise DurableIdentityUnavailable(_UNAVAILABLE)
    if (
        uname().machine not in {"x86_64", "aarch64"}
        or sys.byteorder != "little"
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
        or ctypes.sizeof(ctypes.c_int) != 4
        or ctypes.sizeof(_LinuxStatFS64) != 120
        or _LinuxStatFS64.f_fsid.offset != 56
        or _LinuxStatFS64.f_flags.offset != 80
    ):
        raise DurableIdentityUnavailable(_UNAVAILABLE)


def _filesystem_type(descriptor: int) -> int:
    try:
        operation = ctypes.CDLL(None, use_errno=True).fstatfs
    except AttributeError:
        raise DurableIdentityUnavailable(_UNAVAILABLE) from None
    operation.argtypes = (ctypes.c_int, ctypes.POINTER(_LinuxStatFS64))
    operation.restype = ctypes.c_int
    result = _LinuxStatFS64()
    if operation(descriptor, ctypes.byref(result)) != 0:
        error = ctypes.get_errno()
        if error == errno.ENOSYS:
            raise DurableIdentityUnavailable(_UNAVAILABLE)
        raise OSError(_FAILURE)
    return int(result.f_type)


def _ioctl(descriptor: int, request: int, buffer: bytearray) -> None:
    # Python 3.11 fcntl.ioctl(..., mutable_buffer, True) returns the syscall code
    # and copies the returned bytes into the same bounded buffer.
    try:
        import fcntl
    except ImportError:
        raise DurableIdentityUnavailable(_UNAVAILABLE) from None
    operation = getattr(fcntl, "ioctl", None)
    if not callable(operation):
        raise DurableIdentityUnavailable(_UNAVAILABLE)
    try:
        result = operation(descriptor, request, buffer, True)
    except OSError as error:
        if error.errno in _UNSUPPORTED_IOCTL:
            raise DurableIdentityUnavailable(_UNAVAILABLE) from None
        raise OSError(_FAILURE) from None
    if type(result) is not int or result != 0:
        raise ValueError(_FAILURE)


def _ext4_identifiers(descriptor: int, sentinel: int) -> tuple[bytes, int]:
    uuid_buffer = bytearray((16).to_bytes(4, "little") + bytes(4) + bytes([sentinel]) * 16)
    _ioctl(descriptor, _GETFSUUID, uuid_buffer)
    if (
        len(uuid_buffer) != 24
        or uuid_buffer[:8] != (16).to_bytes(4, "little") + bytes(4)
        or not any(uuid_buffer[8:])
    ):
        raise ValueError(_FAILURE)
    generation_buffer = bytearray([sentinel] * 8)
    _ioctl(descriptor, _GETVERSION, generation_buffer)
    if len(generation_buffer) != 8 or generation_buffer[4:] != bytes([sentinel]) * 4:
        raise ValueError(_FAILURE)
    # Zero is a valid 32-bit generation; it is never substituted for a failed ioctl.
    return bytes(uuid_buffer[8:]), int.from_bytes(generation_buffer[:4], "little")


def durable_descriptor_identity(descriptor: int, *, directory: bool = False) -> dict[str, str]:
    """Inspect one caller-owned descriptor without reopening, closing or writing it.

    Linux support is limited to little-endian x86_64/aarch64 LP64 ext-family
    mounts implementing ext4's UUID and inode-generation getters. Unsupported
    capabilities raise DurableIdentityUnavailable; malformed evidence fails hard.
    """
    if type(descriptor) is not int or not 0 <= descriptor < 2**31 or type(directory) is not bool:
        raise ValueError(_FAILURE)
    try:
        before = os.fstat(descriptor)
        _ordinary(before, directory=directory)
        identity: dict[str, str]
        if sys.platform == "win32":
            volume, file_id = descriptor_identity(descriptor, directory=directory)
            if (
                type(volume) is not int
                or not 0 <= volume < 2**64
                or type(file_id) is not int
                or not 0 < file_id < 2**128
            ):
                raise ValueError(_FAILURE)
            identity = {
                "format": "windows-file-id-info.v1",
                "volume_serial_number": f"{volume:016x}",
                "file_id": f"{file_id:032x}",
            }
        elif sys.platform == "linux":
            _require_linux_abi()
            if _filesystem_type(descriptor) != _EXT_MAGIC:
                raise DurableIdentityUnavailable(_UNAVAILABLE)
            # Different payload sentinels detect successful but partial/unwritten
            # getters. A real zero generation remains valid when all 4 bytes copy.
            uuid, generation = _ext4_identifiers(descriptor, 0x5A)
            if type(before.st_ino) is not int or not 0 < before.st_ino < 2**64:
                raise ValueError(_FAILURE)
            if _ext4_identifiers(descriptor, 0xA5) != (uuid, generation):
                raise ValueError(_FAILURE)
            identity = {
                "format": "linux-ext4-inode-generation.v1",
                "filesystem_uuid": uuid.hex(),
                "inode": str(before.st_ino),
                "generation": f"{generation:08x}",
            }
        else:
            raise DurableIdentityUnavailable(_UNAVAILABLE)
        after = os.fstat(descriptor)
        _ordinary(after, directory=directory)
        if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode), before.st_nlink) != (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_nlink,
        ):
            raise ValueError(_FAILURE)
        return identity
    except DurableIdentityUnavailable:
        raise
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        raise OSError(_FAILURE) from None
