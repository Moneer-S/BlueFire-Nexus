"""Read-only, handle-bound verification of the finite generated-file DACL."""

from __future__ import annotations

import ctypes
import hashlib
import sys
from ctypes import wintypes
from typing import Literal

from . import windows_owner_acl as native
from .windows_file_access_policy import (
    DIRECTORY_READER_ACCESS,
    FILE_OWNER_ACCESS,
    FILE_READER_ACCESS,
    FILE_READER_METADATA,
    WindowsFileAccessPolicy,
)

_SELECTED_SECURITY = 0x5  # Owner and DACL only; no group or SACL claim.
_MAX_DESCRIPTOR_BYTES = 65536


class WindowsFileAccessDaclError(RuntimeError):
    """A finite, path-free failure to verify the selected security descriptor."""


class WindowsReaderMaskMismatch(WindowsFileAccessDaclError):
    """An otherwise exact file recipe has the other supported reader mask."""


def _inside(pointer: int | None, size: int, start: int, length: int) -> bool:
    return pointer is not None and size >= 0 and start <= pointer <= start + length - size


def _sid_inside(pointer: int | None, start: int, length: int) -> bool:
    if not _inside(pointer, 8, start, length):
        return False
    assert pointer is not None
    header = ctypes.string_at(pointer, 8)
    return header[0] == 1 and header[1] <= 15 and _inside(pointer, 8 + header[1] * 4, start, length)


def _verify_descriptor(
    security: ctypes.CDLL,
    descriptor: ctypes.c_void_p,
    owner: ctypes.c_void_p,
    dacl: ctypes.c_void_p,
    expected_owner: ctypes.c_void_p,
    expected_reader: ctypes.c_void_p,
    reader_mask: int,
) -> str:
    if not descriptor.value or not security.IsValidSecurityDescriptor(descriptor):
        raise WindowsFileAccessDaclError("Windows resource descriptor is invalid")
    length = int(security.GetSecurityDescriptorLength(descriptor))
    if not 20 <= length <= _MAX_DESCRIPTOR_BYTES:
        raise WindowsFileAccessDaclError("Windows resource descriptor exceeds its bound")
    start = descriptor.value
    control, revision = wintypes.WORD(), wintypes.DWORD()
    if (
        not security.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        )
        or control.value & 0x9004 != 0x9004
    ):
        raise WindowsFileAccessDaclError("Windows resource DACL is not protected and present")
    if not _sid_inside(owner.value, start, length) or not security.EqualSid(owner, expected_owner):
        raise WindowsFileAccessDaclError("Windows resource owner differs from enrollment")
    if not _inside(dacl.value, ctypes.sizeof(native._Acl), start, length):
        raise WindowsFileAccessDaclError("Windows resource DACL is absent or invalid")
    assert dacl.value is not None
    acl = native._Acl.from_buffer_copy(ctypes.string_at(dacl, ctypes.sizeof(native._Acl)))
    if (
        acl.revision != 2
        or acl.ace_count != 2
        or acl.size < ctypes.sizeof(native._Acl)
        or not _inside(dacl.value, acl.size, start, length)
        or not security.IsValidAcl(dacl)
    ):
        raise WindowsFileAccessDaclError("Windows resource DACL differs from the finite recipe")
    expected_start = dacl.value + ctypes.sizeof(native._Acl)
    other_reader_mask = False
    for index, mask, sid in [
        (0, FILE_OWNER_ACCESS, expected_owner),
        (1, reader_mask, expected_reader),
    ]:
        pointer = ctypes.c_void_p()
        if (
            not security.GetAce(dacl, index, ctypes.byref(pointer))
            or pointer.value != expected_start
            or not _inside(
                pointer.value, ctypes.sizeof(native._AccessAllowedAce), dacl.value, acl.size
            )
        ):
            raise WindowsFileAccessDaclError("Windows resource ACE is invalid")
        assert pointer.value is not None
        ace = native._AccessAllowedAce.from_buffer_copy(
            ctypes.string_at(pointer, ctypes.sizeof(native._AccessAllowedAce))
        )
        sid_address = pointer.value + native._AccessAllowedAce.sid_start.offset
        if (
            ace.header.ace_type != 0
            or ace.header.ace_flags != 0
            or not _inside(pointer.value, ace.header.ace_size, dacl.value, acl.size)
            or not _sid_inside(sid_address, pointer.value, ace.header.ace_size)
            or not security.EqualSid(ctypes.c_void_p(sid_address), sid)
        ):
            raise WindowsFileAccessDaclError("Windows resource ACE differs from the finite recipe")
        sid_length = 8 + ctypes.string_at(sid_address, 2)[1] * 4
        if ace.header.ace_size != native._AccessAllowedAce.sid_start.offset + sid_length:
            raise WindowsFileAccessDaclError("Windows resource ACE has unsupported trailing data")
        if ace.mask != mask:
            if (
                index == 1
                and reader_mask in (FILE_READER_ACCESS, FILE_READER_METADATA)
                and ace.mask in (FILE_READER_ACCESS, FILE_READER_METADATA)
            ):
                other_reader_mask = True
            else:
                raise WindowsFileAccessDaclError(
                    "Windows resource ACE differs from the finite recipe"
                )
        expected_start += ace.header.ace_size
    # Reject spare bytes/hidden entries as well as broader or inherited grants.
    if expected_start != dacl.value + acl.size:
        raise WindowsFileAccessDaclError("Windows resource DACL has unsupported trailing data")
    if other_reader_mask:
        raise WindowsReaderMaskMismatch("Windows resource has the other finite reader state")
    return "sha256:" + hashlib.sha256(ctypes.string_at(descriptor, length)).hexdigest()


def verify_resource_dacl(
    handle: int,
    policy: WindowsFileAccessPolicy,
    *,
    state: Literal["readable", "metadata_only", "directory"],
) -> str:
    """Verify a caller-held resource, returning its selected descriptor digest.

    This does not open a pathname or change permissions. The caller must bind the
    held object to its enrolled resource and check it again after a fresh read.
    A successful descriptor check does not itself prove effective access.
    """
    if (
        sys.platform != "win32"
        or type(handle) is not int
        or not 0 < handle < (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        or type(policy) is not WindowsFileAccessPolicy
        or state not in ("readable", "metadata_only", "directory")
    ):
        raise WindowsFileAccessDaclError("Windows resource DACL observation is unavailable")
    masks = {
        "readable": FILE_READER_ACCESS,
        "metadata_only": FILE_READER_METADATA,
        "directory": DIRECTORY_READER_ACCESS,
    }
    descriptor, owner, dacl = (ctypes.c_void_p() for _ in range(3))
    allocated = []
    kernel = None
    try:
        security, kernel = native._configure_apis()
        security.IsValidSecurityDescriptor.argtypes = (ctypes.c_void_p,)
        security.IsValidSecurityDescriptor.restype = wintypes.BOOL
        security.GetSecurityDescriptorLength.argtypes = (ctypes.c_void_p,)
        security.GetSecurityDescriptorLength.restype = wintypes.DWORD
        for sid in (policy.owner_sid, policy.reader_sid):
            allocated.append(native._converted_sid(security, sid))
        status = security.GetSecurityInfo(
            wintypes.HANDLE(handle),
            1,
            _SELECTED_SECURITY,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if status != 0:
            raise WindowsFileAccessDaclError("Windows resource descriptor is unavailable")
        return _verify_descriptor(
            security, descriptor, owner, dacl, allocated[0], allocated[1], masks[state]
        )
    except WindowsFileAccessDaclError:
        raise
    except (AttributeError, OSError, TypeError, ValueError, native.WindowsOwnerAclError):
        raise WindowsFileAccessDaclError("Windows resource DACL observation failed") from None
    finally:
        if kernel is not None:
            failed = False
            for pointer in [descriptor, *reversed(allocated)]:
                if pointer.value and kernel.LocalFree(pointer):
                    failed = True
            if failed:
                raise WindowsFileAccessDaclError("Windows descriptor cleanup failed")
