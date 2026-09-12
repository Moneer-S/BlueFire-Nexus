"""Bounded inspection of caller-owned open descriptors; no pathname reopening."""

from __future__ import annotations

import os
import sys

_LINUX_AT_EMPTY_PATH = 0x1000
_LINUX_STATX_MNT_ID = 0x1000


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
