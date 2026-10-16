"""Read-only Windows process identity snapshots, without logon or impersonation."""

from __future__ import annotations

import ctypes
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, cast

_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p
_BOOL = ctypes.c_int32
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_STATISTICS = 10
_TOKEN_SESSION_ID = 12
_TOKEN_ELEVATION = 20
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_NO_TOKEN = 1008
_MAX_TOKEN_INFORMATION = 4096


class WindowsSessionFactsError(RuntimeError):
    """An identity observation failed, without disclosing local principal values."""


@dataclass(frozen=True)
class WindowsPrincipalFacts:
    """Private observations, not enrollment, access or continuing authorization."""

    process_id: int
    process_created_filetime: int
    user_sid: str = field(repr=False)
    token_id: int = field(repr=False)
    authentication_id: int = field(repr=False)
    modified_id: int = field(repr=False)
    session_id: int
    elevated: bool

    def validate(self) -> None:
        ranges = (
            (self.process_id, 1, 2**32 - 1),
            (self.process_created_filetime, 1, 2**64 - 1),
            (self.token_id, 1, 2**64 - 1),
            (self.authentication_id, 1, 2**64 - 1),
            (self.modified_id, 1, 2**64 - 1),
            (self.session_id, 0, 2**32 - 1),
        )
        if (
            any(type(value) is not int or not low <= value <= high for value, low, high in ranges)
            or type(self.elevated) is not bool
            or type(self.user_sid) is not str
            or len(self.user_sid) > 184
            or re.fullmatch(r"S-1-(?:[0-9]+|0x[0-9a-f]{12})(?:-[0-9]+){1,15}", self.user_sid)
            is None
        ):
            raise WindowsSessionFactsError("Windows principal expectation is invalid")
        authority, *subauthorities = self.user_sid.split("-")[2:]
        if int(authority, 16 if authority.startswith("0x") else 10) > 2**48 - 1 or any(
            int(value) > 2**32 - 1 for value in subauthorities
        ):
            raise WindowsSessionFactsError("Windows principal SID exceeds its native bounds")


class _Luid(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", ctypes.c_int32)]

    def value(self) -> int:
        return ((int(self.high) & 0xFFFFFFFF) << 32) | int(self.low)


class _Filetime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _Statistics(ctypes.Structure):
    _fields_ = [
        ("token_id", _Luid),
        ("authentication_id", _Luid),
        ("expiration_time", ctypes.c_int64),
        ("token_type", ctypes.c_int32),
        ("impersonation_level", ctypes.c_int32),
        ("dynamic_charged", _DWORD),
        ("dynamic_available", _DWORD),
        ("group_count", _DWORD),
        ("privilege_count", _DWORD),
        ("modified_id", _Luid),
    ]


class _TokenUser(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", _DWORD)]


def _decode_user_sid(buffer: ctypes.Array, length: int) -> str:
    minimum = ctypes.sizeof(_TokenUser)
    if not minimum <= length <= ctypes.sizeof(buffer):
        raise WindowsSessionFactsError("Windows token user response is invalid")
    user = _TokenUser.from_buffer_copy(buffer)
    offset = int(user.sid or 0) - ctypes.addressof(buffer)
    # TOKEN_USER contains a pointer; prove the entire SID is inside the returned
    # buffer before reading it. No native pointer is followed speculatively.
    if offset < minimum or offset > length - 8:
        raise WindowsSessionFactsError("Windows token user response is invalid")
    header = bytes(buffer[offset : offset + 8])
    revision, count = header[:2]
    if revision != 1 or not 1 <= count <= 15 or offset + 8 + count * 4 > length:
        raise WindowsSessionFactsError("Windows token user response is invalid")
    authority = int.from_bytes(header[2:8], "big")
    authority_text = str(authority) if authority <= 0xFFFFFFFF else f"0x{authority:012x}"
    parts = ["S", "1", authority_text]
    for index in range(count):
        start = offset + 8 + index * 4
        parts.append(str(int.from_bytes(bytes(buffer[start : start + 4]), "little")))
    return "-".join(parts)


class _WindowsApi:
    kernel: ctypes.CDLL
    security: ctypes.CDLL

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WindowsSessionFactsError("Windows process identity is unavailable")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        for name in ("GetCurrentProcess", "GetCurrentThread"):
            function = getattr(self.kernel, name)
            function.argtypes = ()
            function.restype = _HANDLE
        self.kernel.GetCurrentProcessId.argtypes = ()
        self.kernel.GetCurrentProcessId.restype = _DWORD
        self.kernel.GetProcessTimes.argtypes = (
            _HANDLE,
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
            ctypes.POINTER(_Filetime),
        )
        self.kernel.GetProcessTimes.restype = _BOOL
        self.kernel.CloseHandle.argtypes = (_HANDLE,)
        self.kernel.CloseHandle.restype = _BOOL
        self.security.OpenProcessToken.argtypes = (_HANDLE, _DWORD, ctypes.POINTER(_HANDLE))
        self.security.OpenProcessToken.restype = _BOOL
        self.security.OpenThreadToken.argtypes = (
            _HANDLE,
            _DWORD,
            _BOOL,
            ctypes.POINTER(_HANDLE),
        )
        self.security.OpenThreadToken.restype = _BOOL
        self.security.GetTokenInformation.argtypes = (
            _HANDLE,
            ctypes.c_int32,
            ctypes.c_void_p,
            _DWORD,
            ctypes.POINTER(_DWORD),
        )
        self.security.GetTokenInformation.restype = _BOOL

    def _close(self, token: _HANDLE) -> None:
        if not self.kernel.CloseHandle(token):
            raise WindowsSessionFactsError("Windows identity handle cleanup failed")

    @contextmanager
    def process_token(self) -> Iterator[int]:
        token = _HANDLE()
        try:
            opened = self.security.OpenProcessToken(
                self.kernel.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
            )
            value = token.value
            if not opened or value is None or value in (0, _HANDLE(-1).value):
                raise WindowsSessionFactsError("Windows process token is unavailable")
            yield value
        finally:
            if token.value not in (None, 0, _HANDLE(-1).value):
                self._close(token)

    def require_no_thread_token(self) -> None:
        token = _HANDLE()
        opened = self.security.OpenThreadToken(
            self.kernel.GetCurrentThread(), _TOKEN_QUERY, True, ctypes.byref(token)
        )
        error = cast(Any, ctypes).get_last_error()
        supplied_handle = token.value not in (None, 0, _HANDLE(-1).value)
        if supplied_handle:
            self._close(token)
        if opened or supplied_handle or token.value == _HANDLE(-1).value:
            raise WindowsSessionFactsError("Windows thread identity is not primary-only")
        if error != _ERROR_NO_TOKEN:
            raise WindowsSessionFactsError("Windows thread identity is unavailable")

    def process_generation(self) -> tuple[int, int]:
        created, exited, kernel, user = (_Filetime() for _ in range(4))
        process_id = int(self.kernel.GetCurrentProcessId())
        if not self.kernel.GetProcessTimes(
            self.kernel.GetCurrentProcess(),
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise WindowsSessionFactsError("Windows process generation is unavailable")
        creation_time = (int(created.high) << 32) | int(created.low)
        if process_id <= 0 or creation_time <= 0:
            raise WindowsSessionFactsError("Windows process generation is invalid")
        return process_id, creation_time

    def information(self, token: int, kind: int) -> tuple[ctypes.Array, int]:
        length = _DWORD()
        fixed_size = {
            _TOKEN_STATISTICS: ctypes.sizeof(_Statistics),
            _TOKEN_SESSION_ID: ctypes.sizeof(_DWORD),
            _TOKEN_ELEVATION: ctypes.sizeof(_DWORD),
        }.get(kind)
        if fixed_size is not None:
            length.value = fixed_size
        elif kind == _TOKEN_USER:
            result = self.security.GetTokenInformation(
                _HANDLE(token), kind, None, 0, ctypes.byref(length)
            )
            if (
                result
                or cast(Any, ctypes).get_last_error() != _ERROR_INSUFFICIENT_BUFFER
                or not 1 <= length.value <= _MAX_TOKEN_INFORMATION
            ):
                raise WindowsSessionFactsError("Windows token information is unavailable")
        else:
            raise WindowsSessionFactsError("Windows token information class is unsupported")
        buffer = ctypes.create_string_buffer(length.value)
        capacity = len(buffer)
        if (
            not self.security.GetTokenInformation(
                _HANDLE(token), kind, buffer, capacity, ctypes.byref(length)
            )
            or not 1 <= length.value <= capacity
        ):
            raise WindowsSessionFactsError("Windows token information changed or is invalid")
        return buffer, int(length.value)

    def statistics(self, token: int) -> tuple[int, int, int]:
        buffer, length = self.information(token, _TOKEN_STATISTICS)
        if length != ctypes.sizeof(_Statistics):
            raise WindowsSessionFactsError("Windows token statistics are invalid")
        stats = _Statistics.from_buffer_copy(buffer)
        values = (
            stats.token_id.value(),
            stats.authentication_id.value(),
            stats.modified_id.value(),
        )
        if stats.token_type != 1 or any(value <= 0 for value in values):
            raise WindowsSessionFactsError("Windows token statistics are invalid")
        return values

    def user_sid(self, token: int) -> str:
        return _decode_user_sid(*self.information(token, _TOKEN_USER))

    def dword(self, token: int, kind: int) -> int:
        buffer, length = self.information(token, kind)
        if length != ctypes.sizeof(_DWORD):
            raise WindowsSessionFactsError("Windows token scalar is invalid")
        return int(_DWORD.from_buffer_copy(buffer).value)


def _observe(api: _WindowsApi) -> WindowsPrincipalFacts:
    api.require_no_thread_token()
    generation = api.process_generation()
    with api.process_token() as token:
        initial = api.statistics(token)
        sid = api.user_sid(token)
        session = api.dword(token, _TOKEN_SESSION_ID)
        elevation = api.dword(token, _TOKEN_ELEVATION)
        if elevation not in (0, 1):
            raise WindowsSessionFactsError("Windows token elevation is invalid")
        if api.statistics(token) != initial:
            raise WindowsSessionFactsError("Windows process token changed during observation")
        # A held token does not prove it remains the process's primary token.
        # Reopen it and compare its instance and modification identifiers too.
        with api.process_token() as current:
            if api.statistics(current) != initial:
                raise WindowsSessionFactsError("Windows primary token changed during observation")
        if api.process_generation() != generation:
            raise WindowsSessionFactsError("Windows process changed during observation")
        api.require_no_thread_token()
    observed = WindowsPrincipalFacts(*generation, sid, *initial, session, bool(elevation))
    observed.validate()
    return observed


def current_process_principal() -> WindowsPrincipalFacts:
    """Observe this process only; never log on, impersonate, launch or modify it.

    The two-ended checks detect observed changes, not transient changes restored
    between checks or changes after return. A later access operation must bind
    its own identity and held resource; this snapshot cannot authorize it.
    """
    try:
        return _observe(_WindowsApi())
    except WindowsSessionFactsError:
        raise
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        raise WindowsSessionFactsError("Windows process identity observation failed") from None
