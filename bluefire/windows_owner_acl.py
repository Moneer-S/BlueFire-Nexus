"""Handle-bound Windows owner-only ACL application and verification."""

from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes

_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x0000_0001
_DACL_SECURITY_INFORMATION = 0x0000_0004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x8000_0000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_FILE_ALL_ACCESS = 0x001F_01FF
_SDDL_REVISION_1 = 1
_SID = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_OWNER = 4


class WindowsOwnerAclError(RuntimeError):
    """A path-free failure to apply or verify an exact private DACL."""


class _Acl(ctypes.Structure):
    _fields_ = [
        ("revision", wintypes.BYTE),
        ("sbz1", wintypes.BYTE),
        ("size", wintypes.WORD),
        ("ace_count", wintypes.WORD),
        ("sbz2", wintypes.WORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("ace_type", wintypes.BYTE),
        ("ace_flags", wintypes.BYTE),
        ("ace_size", wintypes.WORD),
    ]


class _AccessAllowedAce(ctypes.Structure):
    _fields_ = [
        ("header", _AceHeader),
        ("mask", wintypes.DWORD),
        ("sid_start", wintypes.DWORD),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class _TokenOwner(ctypes.Structure):
    _fields_ = [("owner", ctypes.c_void_p)]


def _current_token_sids() -> tuple[str, str]:
    """Return the process token's user and default-owner SIDs."""

    if os.name != "nt":
        raise WindowsOwnerAclError("Windows owner identity is unavailable")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise WindowsOwnerAclError("Windows owner identity is unavailable")

        def token_sid(information_class: int) -> str:
            size = wintypes.DWORD()
            advapi32.GetTokenInformation(
                token,
                information_class,
                None,
                0,
                ctypes.byref(size),
            )
            minimum = (
                ctypes.sizeof(_TokenUser)
                if information_class == _TOKEN_USER
                else ctypes.sizeof(_TokenOwner)
            )
            if size.value < minimum:
                raise WindowsOwnerAclError("Windows owner identity is unavailable")
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(
                token,
                information_class,
                buffer,
                size.value,
                ctypes.byref(size),
            ):
                raise WindowsOwnerAclError("Windows owner identity is unavailable")
            if information_class == _TOKEN_USER:
                sid_pointer = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents.user.sid
            else:
                sid_pointer = ctypes.cast(buffer, ctypes.POINTER(_TokenOwner)).contents.owner
            sid_text = wintypes.LPWSTR()
            try:
                if not sid_pointer or not advapi32.ConvertSidToStringSidW(
                    sid_pointer,
                    ctypes.byref(sid_text),
                ):
                    raise WindowsOwnerAclError("Windows owner identity is unavailable")
                sid = sid_text.value or ""
                if _SID.fullmatch(sid) is None:
                    raise WindowsOwnerAclError("Windows owner identity is unavailable")
                return sid
            finally:
                if sid_text:
                    kernel32.LocalFree(sid_text)

        return token_sid(_TOKEN_USER), token_sid(_TOKEN_OWNER)
    except WindowsOwnerAclError:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise WindowsOwnerAclError("Windows owner identity is unavailable") from None
    finally:
        if token:
            kernel32.CloseHandle(token)


def current_user_sid() -> str:
    """Return the current process-token user SID without executing a helper process."""

    return _current_token_sids()[0]


def current_owner_sid() -> str:
    """Return the process token's default owner SID for newly created objects."""

    return _current_token_sids()[1]


def _handle_from_descriptor(descriptor: int) -> int:
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise WindowsOwnerAclError("Windows private-object descriptor is invalid")
    try:
        import msvcrt

        handle = int(msvcrt.get_osfhandle(descriptor))
    except (ImportError, OSError, ValueError):
        raise WindowsOwnerAclError("Windows private-object handle is unavailable") from None
    if handle in {-1, 0}:
        raise WindowsOwnerAclError("Windows private-object handle is unavailable")
    return handle


def _configure_apis() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    advapi32.EqualSid.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = (ctypes.c_void_p,)
    advapi32.IsValidSid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    return advapi32, kernel32


def _converted_descriptor(
    advapi32: ctypes.WinDLL,
    sddl: str,
) -> ctypes.c_void_p:
    descriptor = ctypes.c_void_p()
    if (
        not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            None,
        )
        or not descriptor.value
    ):
        raise WindowsOwnerAclError("Windows private DACL construction failed")
    return descriptor


def _converted_sid(advapi32: ctypes.WinDLL, sid: str) -> ctypes.c_void_p:
    pointer = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(pointer)) or not pointer.value:
        raise WindowsOwnerAclError("Windows owner identity conversion failed")
    return pointer


def _descriptor_dacl(
    advapi32: ctypes.WinDLL,
    descriptor: ctypes.c_void_p,
) -> ctypes.c_void_p:
    present = wintypes.BOOL()
    defaulted = wintypes.BOOL()
    dacl = ctypes.c_void_p()
    if (
        not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        )
        or not present.value
        or not dacl.value
    ):
        raise WindowsOwnerAclError("Windows private DACL is unavailable")
    return dacl


def _select_current_owner(
    advapi32: ctypes.WinDLL,
    kernel32: ctypes.WinDLL,
    *,
    handle: int,
    access_sid: ctypes.c_void_p,
    default_owner_sid: ctypes.c_void_p,
) -> ctypes.c_void_p:
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        status = advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if status != 0 or not descriptor.value or not owner.value:
            raise WindowsOwnerAclError("Windows private-object owner verification failed")
        if advapi32.EqualSid(owner, access_sid):
            return access_sid
        if advapi32.EqualSid(owner, default_owner_sid):
            return default_owner_sid
        raise WindowsOwnerAclError("Windows private-object owner verification failed")
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def _verify_owner_private_acl(
    advapi32: ctypes.WinDLL,
    kernel32: ctypes.WinDLL,
    *,
    handle: int,
    observed_owner_sid: ctypes.c_void_p,
    access_sid: ctypes.c_void_p,
    directory: bool,
) -> ctypes.c_void_p:
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status != 0 or not descriptor.value or not owner.value or not dacl.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise WindowsOwnerAclError("Windows private DACL verification failed")
    verified = False
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        verified_dacl = ctypes.c_void_p()
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        ace_pointer = ctypes.c_void_p()
        if (
            not advapi32.EqualSid(owner, observed_owner_sid)
            or not advapi32.GetSecurityDescriptorDacl(
                descriptor,
                ctypes.byref(present),
                ctypes.byref(verified_dacl),
                ctypes.byref(defaulted),
            )
            or not present.value
            or verified_dacl.value != dacl.value
            or not advapi32.GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            )
            or not control.value & _SE_DACL_PROTECTED
            or acl.ace_count != 1
            or not advapi32.GetAce(dacl, 0, ctypes.byref(ace_pointer))
            or not ace_pointer.value
        ):
            raise WindowsOwnerAclError("Windows private DACL verification failed")
        ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
        sid_pointer = ctypes.c_void_p(int(ace_pointer.value) + _AccessAllowedAce.sid_start.offset)
        expected_flags = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE if directory else 0
        if (
            ace.header.ace_type != _ACCESS_ALLOWED_ACE_TYPE
            or ace.header.ace_flags != expected_flags
            or ace.header.ace_size < ctypes.sizeof(_AccessAllowedAce)
            or ace.mask != _FILE_ALL_ACCESS
            or not advapi32.IsValidSid(sid_pointer)
            or not advapi32.EqualSid(sid_pointer, access_sid)
        ):
            raise WindowsOwnerAclError("Windows private DACL verification failed")
        verified = True
    except (ValueError, OSError):
        raise WindowsOwnerAclError("Windows private DACL verification failed") from None
    finally:
        if not verified and descriptor.value:
            kernel32.LocalFree(descriptor)
    return descriptor


def _apply_owner_private_acl(
    descriptor: int,
    *,
    access_sid: str,
    owner_sid: str,
    directory: bool,
) -> None:
    if (
        os.name != "nt"
        or _SID.fullmatch(access_sid) is None
        or _SID.fullmatch(owner_sid) is None
        or not isinstance(directory, bool)
    ):
        raise WindowsOwnerAclError("Windows owner-private ACL input is invalid")
    handle = _handle_from_descriptor(descriptor)
    input_descriptor = ctypes.c_void_p()
    access_sid_pointer = ctypes.c_void_p()
    owner_sid_pointer = ctypes.c_void_p()
    observed_owner_sid = ctypes.c_void_p()
    verified_descriptor = ctypes.c_void_p()
    try:
        advapi32, kernel32 = _configure_apis()
        inheritance = "OICI" if directory else ""
        input_descriptor = _converted_descriptor(
            advapi32,
            f"D:P(A;{inheritance};FA;;;{access_sid})",
        )
        access_sid_pointer = _converted_sid(advapi32, access_sid)
        owner_sid_pointer = _converted_sid(advapi32, owner_sid)
        observed_owner_sid = _select_current_owner(
            advapi32,
            kernel32,
            handle=handle,
            access_sid=access_sid_pointer,
            default_owner_sid=owner_sid_pointer,
        )
        dacl = _descriptor_dacl(advapi32, input_descriptor)
        status = advapi32.SetSecurityInfo(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if status != 0:
            raise WindowsOwnerAclError("Windows private DACL application failed")
        verified_descriptor = _verify_owner_private_acl(
            advapi32,
            kernel32,
            handle=handle,
            observed_owner_sid=observed_owner_sid,
            access_sid=access_sid_pointer,
            directory=directory,
        )
    except WindowsOwnerAclError:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise WindowsOwnerAclError("Windows private DACL operation failed") from None
    finally:
        local_free = locals().get("kernel32")
        if local_free is not None:
            for pointer in (
                verified_descriptor,
                owner_sid_pointer,
                access_sid_pointer,
                input_descriptor,
            ):
                if pointer.value:
                    local_free.LocalFree(pointer)


def apply_owner_private_acl(descriptor: int, *, directory: bool) -> None:
    """Replace one pinned object's DACL and verify its token-private result."""

    if os.name != "nt" or not isinstance(directory, bool):
        raise WindowsOwnerAclError("Windows owner-private ACL input is invalid")
    access_sid, owner_sid = _current_token_sids()
    _apply_owner_private_acl(
        descriptor,
        access_sid=access_sid,
        owner_sid=owner_sid,
        directory=directory,
    )


__all__ = [
    "WindowsOwnerAclError",
    "apply_owner_private_acl",
    "current_owner_sid",
    "current_user_sid",
]
