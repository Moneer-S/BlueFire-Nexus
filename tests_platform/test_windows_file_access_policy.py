from __future__ import annotations

import ctypes
import sys

import pytest

from bluefire.windows_file_access_policy import (
    DIRECTORY_READER_ACCESS,
    FILE_OWNER_ACCESS,
    FILE_READER_ACCESS,
    FILE_READER_METADATA,
    WindowsFileAccessPolicy,
    WindowsFileAccessPolicyError,
)

OWNER = "S-1-5-21-101-202-303-1001"
READER = "S-1-5-21-101-202-303-1002"


def test_exact_recipe_changes_only_reader_data_access():
    policy = WindowsFileAccessPolicy(OWNER, READER)
    prefix = f"O:{OWNER}D:P(A;;0x001f01ff;;;{OWNER})"
    assert policy.file_sddl("readable") == prefix + f"(A;;0x00120089;;;{READER})"
    assert policy.file_sddl("metadata_only") == prefix + f"(A;;0x00120080;;;{READER})"
    assert policy.directory_sddl() == prefix + f"(A;;0x001200a0;;;{READER})"
    assert FILE_READER_ACCESS ^ FILE_READER_METADATA == 0x9
    assert DIRECTORY_READER_ACCESS & 0x1 == 0
    assert DIRECTORY_READER_ACCESS & 0x20
    assert "S-1-" not in repr(policy)


@pytest.mark.parametrize(
    "reader",
    [
        OWNER,
        "S-1-5-21-101-202-304-1002",
        "S-1-5-21-101-202-303-500",
        "S-1-5-21-101-202-303-01002",
        "S-1-5-21-101-202-303-4294967296",
        "S-1-5-21-0-202-303-1002",
        "S-1-5-18",
        "S-1-5-32-544",
        "WD",
        READER + "(A;;GA;;;WD)",
        READER + "\n",
        "",
        None,
        True,
    ],
)
def test_ambiguous_builtin_cross_authority_or_unbounded_pair_refused(reader):
    with pytest.raises(WindowsFileAccessPolicyError):
        WindowsFileAccessPolicy(OWNER, reader)
    with pytest.raises(WindowsFileAccessPolicyError):
        WindowsFileAccessPolicy(reader, OWNER)


@pytest.mark.parametrize("state", ["0600", "revoked", "readable\n", None, 0])
def test_posix_or_unrecognized_state_is_not_reinterpreted(state):
    with pytest.raises(WindowsFileAccessPolicyError, match="state is unsupported"):
        WindowsFileAccessPolicy(OWNER, READER).file_sddl(state)


@pytest.mark.skipif(sys.platform != "win32", reason="native read-only SDDL conversion")
@pytest.mark.parametrize(
    "state,expected_mask",
    [
        ("readable", FILE_READER_ACCESS),
        ("metadata_only", FILE_READER_METADATA),
        ("directory", DIRECTORY_READER_ACCESS),
    ],
)
def test_windows_parses_exact_protected_noninherited_two_ace_recipe(state, expected_mask):
    from bluefire import windows_owner_acl as acl

    policy = WindowsFileAccessPolicy(OWNER, READER)
    sddl = policy.directory_sddl() if state == "directory" else policy.file_sddl(state)
    security, kernel = acl._configure_apis()
    descriptor = acl._converted_descriptor(security, sddl)
    pointers = []
    try:
        owner = acl._converted_sid(security, OWNER)
        pointers.append(owner)
        reader = acl._converted_sid(security, READER)
        pointers.append(reader)
        dacl = acl._descriptor_dacl(security, descriptor)
        control, revision = ctypes.c_uint16(), ctypes.c_uint32()
        assert security.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        )
        assert control.value & acl._SE_DACL_PROTECTED
        header = ctypes.cast(dacl, ctypes.POINTER(acl._Acl)).contents
        assert header.ace_count == 2
        for index, mask, sid in [(0, FILE_OWNER_ACCESS, owner), (1, expected_mask, reader)]:
            pointer = ctypes.c_void_p()
            assert security.GetAce(dacl, index, ctypes.byref(pointer))
            ace = ctypes.cast(pointer, ctypes.POINTER(acl._AccessAllowedAce)).contents
            assert (ace.header.ace_type, ace.header.ace_flags, ace.mask) == (0, 0, mask)
            observed_sid = ctypes.c_void_p(pointer.value + acl._AccessAllowedAce.sid_start.offset)
            assert security.EqualSid(observed_sid, sid)
    finally:
        for pointer in reversed(pointers):
            assert not kernel.LocalFree(pointer)
        assert not kernel.LocalFree(descriptor)
