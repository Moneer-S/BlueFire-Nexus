"""Bounded read-only enrollment primitives, not enrollment or setup authority.

Native calls require an external hard deadline: cooperative checks cannot stop a
blocked Win32 call. No function here creates accounts, reads credentials, changes
ACLs, opens a supplied path, or establishes a verified execution context.
"""

from __future__ import annotations

import ctypes
import hashlib
import math
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, NoReturn

from .windows_file_access_admission import (
    WindowsEnrollmentNativeError as WindowsEnrollmentNativeError,
)
from .windows_file_access_admission import (
    file_identity_wire as file_identity_wire,
)
from .windows_file_access_policy import (
    DIRECTORY_READER_ACCESS,
    FILE_OWNER_ACCESS,
    FILE_READER_ACCESS,
    WindowsFileAccessPolicyError,
    _account_sid,
)

_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_MAX_BUFFER = 65536
_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_POINTER_LIMIT = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 16
_SUPPORTED_ACCOUNT_FLAGS = 0x1 | 0x200 | 0x40 | 0x10000


def _refuse(message: str = "Windows protected enrollment observation failed") -> NoReturn:
    raise WindowsEnrollmentNativeError(message)


def _local_sid(value: str) -> None:
    try:
        _account_sid(value)
    except WindowsFileAccessPolicyError:
        raise WindowsEnrollmentNativeError(
            "Windows enrollment account identity is invalid"
        ) from None


def _sid(raw: bytes, offset: int, end: int) -> tuple[str, int]:
    if offset < 0 or offset + 8 > end or end > len(raw):
        _refuse()
    revision, count = raw[offset : offset + 2]
    size = 8 + 4 * count
    if revision != 1 or not 1 <= count <= 15 or offset + size > end:
        _refuse()
    authority = int.from_bytes(raw[offset + 2 : offset + 8], "big")
    numbers = struct.unpack_from("<" + "I" * count, raw, offset + 8)
    return "S-1-" + str(authority) + "".join(f"-{number}" for number in numbers), size


def verify_protected_metadata_descriptor(
    raw: bytes, enrolled_owner_sid: str, *, directory: bool
) -> str:
    """Check the exact selected OWNER+DACL recipe; return only its byte digest.

    Group and SACL fields are explicitly refused. SYSTEM or Administrators must own
    the metadata; an enrolled-user owner would retain implicit WRITE_DAC. The caller
    must independently establish the held object's identity and protected location.
    """
    _local_sid(enrolled_owner_sid)
    if type(raw) is not bytes or not 20 <= len(raw) <= _MAX_BUFFER or type(directory) is not bool:
        _refuse()
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from("<BBHIIII", raw)
    if revision != 1 or reserved or control != 0x9004 or group or sacl:
        _refuse()
    if owner < 20 or owner % 4 or dacl < 20 or dacl % 4:
        _refuse()
    owner_sid, owner_size = _sid(raw, owner, len(raw))
    if owner_sid not in (_SYSTEM, _ADMINISTRATORS) or dacl + 8 > len(raw):
        _refuse()
    acl_revision, sbz1, acl_size, count, sbz2 = struct.unpack_from("<BBHHH", raw, dacl)
    if (
        acl_revision != 2
        or sbz1
        or sbz2
        or count != 3
        or acl_size < 8
        or dacl + acl_size > len(raw)
    ):
        _refuse()
    # Account for every descriptor byte, independent of owner/DACL layout order.
    regions = sorted([(owner, owner + owner_size), (dacl, dacl + acl_size)])
    if regions[0][0] != 20 or regions[0][1] != regions[1][0] or regions[1][1] != len(raw):
        _refuse()
    cursor = dacl + 8
    owner_mask = DIRECTORY_READER_ACCESS if directory else FILE_READER_ACCESS
    for expected_sid, expected_mask in (
        (_SYSTEM, FILE_OWNER_ACCESS),
        (_ADMINISTRATORS, FILE_OWNER_ACCESS),
        (enrolled_owner_sid, owner_mask),
    ):
        if cursor + 8 > dacl + acl_size:
            _refuse()
        ace_type, flags, size, mask = struct.unpack_from("<BBHI", raw, cursor)
        if ace_type or flags or size < 16 or size % 4 or cursor + size > dacl + acl_size:
            _refuse()
        sid, sid_size = _sid(raw, cursor + 8, cursor + size)
        if size != 8 + sid_size or sid != expected_sid or mask != expected_mask:
            _refuse()
        cursor += size
    if cursor != dacl + acl_size:
        _refuse()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class LocalReaderAccount:
    """A bounded local SAM observation, not a credential or enrolled context."""

    account_name: str = field(repr=False)
    reader_sid: str = field(repr=False)
    flags: int


class _UserInfo23(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("full_name", ctypes.c_void_p),
        ("comment", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("sid", ctypes.c_void_p),
    ]


class _Gate:
    def __init__(self, deadline: float, cancelled: Callable[[], bool]) -> None:
        now = time.monotonic()
        if (
            type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or not now < deadline <= now + 5.0
            or not callable(cancelled)
        ):
            _refuse("Windows enrollment deadline is invalid")
        self.deadline = deadline
        self.cancelled = cancelled
        self.check()

    def check(self) -> None:
        try:
            stopped = self.cancelled()
        except Exception:
            raise WindowsEnrollmentNativeError(
                "Windows enrollment cancellation is unavailable"
            ) from None
        if type(stopped) is not bool or stopped or time.monotonic() >= self.deadline:
            _refuse("Windows enrollment observation stopped")


def _sam_api() -> ctypes.CDLL:
    if sys.platform != "win32":
        _refuse("Windows local account APIs are unavailable")
    api = ctypes.WinDLL("netapi32.dll", use_last_error=True, winmode=0x800)
    api.NetUserGetInfo.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    )
    api.NetUserGetInfo.restype = ctypes.c_uint32
    api.NetApiBufferSize.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    api.NetApiBufferSize.restype = ctypes.c_uint32
    api.NetApiBufferFree.argtypes = (ctypes.c_void_p,)
    api.NetApiBufferFree.restype = ctypes.c_uint32
    return api


def _relative(pointer: int | None, start: int, length: int, minimum: int, alignment: int) -> int:
    if pointer is None or pointer % alignment or not start + minimum <= pointer < start + length:
        _refuse()
    return pointer - start


def _utf16(raw: bytes, offset: int, maximum: int) -> str:
    for end in range(offset, min(len(raw) - 1, offset + (maximum + 1) * 2), 2):
        if raw[end : end + 2] == b"\0\0":
            try:
                return raw[offset:end].decode("utf-16-le", errors="strict")
            except UnicodeError:
                raise WindowsEnrollmentNativeError(
                    "Windows local account data is invalid"
                ) from None
    _refuse()


def _account_from_buffer(
    pointer: int, length: int, name: str, expected_sid: str
) -> LocalReaderAccount:
    minimum = ctypes.sizeof(_UserInfo23)
    if (
        not 0 < pointer < _POINTER_LIMIT
        or not minimum <= length <= _MAX_BUFFER
        or pointer + length > _POINTER_LIMIT
    ):
        _refuse()
    # Copy only after the API has supplied a bounded allocation size; never follow
    # unvalidated native pointers. All subsequent interpretation is of this copy.
    raw = ctypes.string_at(pointer, length)
    info = _UserInfo23.from_buffer_copy(raw)
    name_offset = _relative(info.name, pointer, length, minimum, 2)
    if _utf16(raw, name_offset, 19) != name:
        _refuse("Windows local account name differs from generation")
    for optional in (info.full_name, info.comment):
        if optional:
            _utf16(raw, _relative(optional, pointer, length, minimum, 2), 1024)
    sid, _ = _sid(raw, _relative(info.sid, pointer, length, minimum, 4), length)
    _local_sid(sid)
    if sid != expected_sid or info.flags & ~_SUPPORTED_ACCOUNT_FLAGS or not info.flags & 0x200:
        _refuse("Windows local account differs from enrollment")
    return LocalReaderAccount(name, sid, int(info.flags))


def resolve_local_reader_account(
    generation: str,
    expected_reader_sid: str,
    *,
    deadline: float,
    cancelled: Callable[[], bool],
) -> LocalReaderAccount:
    """Map only the fixed derived account through local NetUserGetInfo level 23.

    The expected SID must come from independently retained setup authority. Matching
    it establishes this local lookup only, not account ownership, token restriction,
    credentials, protected setup, or execution readiness. The buffer is always freed;
    failed cleanup overrides otherwise useful facts, including native API failures.
    """
    if type(generation) is not str or _GENERATION.fullmatch(generation) is None:
        _refuse("Windows enrollment generation is invalid")
    _local_sid(expected_reader_sid)
    gate = _Gate(deadline, cancelled)
    name = "bf_" + generation[:16]
    pointer = ctypes.c_void_p()
    api = None
    try:
        api = _sam_api()
        gate.check()
        status = api.NetUserGetInfo(None, name, 23, ctypes.byref(pointer))
        gate.check()
        if status != 0 or not pointer.value:
            _refuse("Windows local account lookup is unavailable")
        size = ctypes.c_uint32()
        gate.check()
        status = api.NetApiBufferSize(pointer, ctypes.byref(size))
        gate.check()
        if status != 0:
            _refuse("Windows local account buffer is unavailable")
        result = _account_from_buffer(pointer.value, size.value, name, expected_reader_sid)
        gate.check()
        return result
    except WindowsEnrollmentNativeError:
        raise
    except Exception:
        raise WindowsEnrollmentNativeError("Windows local account observation failed") from None
    finally:
        if api is not None and pointer.value:
            try:
                failed = api.NetApiBufferFree(pointer) != 0
            except Exception:
                failed = True
            if failed:
                raise WindowsEnrollmentNativeError("Windows local account cleanup failed") from None
        gate.check()


def _security_api() -> tuple[ctypes.CDLL, ctypes.CDLL]:
    if sys.platform != "win32":
        _refuse("Windows protected metadata APIs are unavailable")
    api = ctypes.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    api.GetSecurityInfo.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    api.GetSecurityInfo.restype = ctypes.c_uint32
    api.GetSecurityDescriptorLength.argtypes = (ctypes.c_void_p,)
    api.GetSecurityDescriptorLength.restype = ctypes.c_uint32
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p
    return api, kernel


def observe_protected_metadata_descriptor(
    handle: int,
    enrolled_owner_sid: str,
    *,
    directory: bool,
    deadline: float,
    cancelled: Callable[[], bool],
) -> str:
    """Observe OWNER+DACL on a borrowed held handle, without mutation or reopening.

    No handle ownership is transferred. The caller must retain/freshly recheck the
    object and its fixed ancestors; this selected descriptor is not an anchor proof.
    """
    _local_sid(enrolled_owner_sid)
    if type(handle) is not int or not 0 < handle < _POINTER_LIMIT or type(directory) is not bool:
        _refuse()
    gate = _Gate(deadline, cancelled)
    descriptor = ctypes.c_void_p()
    kernel = None
    try:
        api, kernel = _security_api()
        gate.check()
        status = api.GetSecurityInfo(handle, 1, 5, None, None, None, None, ctypes.byref(descriptor))
        gate.check()
        if status != 0 or not descriptor.value or not 0 < descriptor.value < _POINTER_LIMIT:
            _refuse()
        gate.check()
        size = int(api.GetSecurityDescriptorLength(descriptor))
        gate.check()
        if not 20 <= size <= _MAX_BUFFER:
            _refuse()
        result = verify_protected_metadata_descriptor(
            ctypes.string_at(descriptor, size), enrolled_owner_sid, directory=directory
        )
        gate.check()
        return result
    except WindowsEnrollmentNativeError:
        raise
    except Exception:
        raise WindowsEnrollmentNativeError(
            "Windows protected metadata observation failed"
        ) from None
    finally:
        if kernel is not None and descriptor.value:
            try:
                failed = bool(kernel.LocalFree(descriptor))
            except Exception:
                failed = True
            if failed:
                raise WindowsEnrollmentNativeError(
                    "Windows protected metadata cleanup failed"
                ) from None
        gate.check()
