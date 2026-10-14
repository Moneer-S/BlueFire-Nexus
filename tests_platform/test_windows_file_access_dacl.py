from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_dacl as dacl
from bluefire import windows_owner_acl as native
from bluefire.windows_file_access_policy import WindowsFileAccessPolicy

OWNER = "S-1-5-21-101-202-303-1001"
READER = "S-1-5-21-101-202-303-1002"
POLICY = WindowsFileAccessPolicy(OWNER, READER)


@pytest.mark.parametrize("pointer,size", [(None, 1), (99, 1), (111, 1), (100, 11), (100, -1)])
def test_native_pointer_bounds_refuse_without_dereference(pointer, size):
    assert not dacl._inside(pointer, size, 100, 10)


def test_sid_bounds_are_checked_before_a_native_pointer_is_followed():
    assert not dacl._sid_inside(None, 100, 10)
    assert not dacl._sid_inside(99, 100, 10)
    assert not dacl._sid_inside(103, 100, 10)
    buffer = ctypes.create_string_buffer(b"\x01\x10" + b"\0" * 66, 68)
    assert not dacl._sid_inside(ctypes.addressof(buffer), ctypes.addressof(buffer), 68)
    buffer[1] = b"\x02"
    assert dacl._sid_inside(ctypes.addressof(buffer), ctypes.addressof(buffer), 16)
    assert not dacl._sid_inside(ctypes.addressof(buffer), ctypes.addressof(buffer), 15)


@pytest.mark.parametrize("handle", [None, True, 0, -1, 1 << 128])
def test_invalid_handle_cannot_reach_native_api(monkeypatch, handle):
    monkeypatch.setattr(dacl.sys, "platform", "win32")
    monkeypatch.setattr(native, "_configure_apis", lambda: pytest.fail("must refuse first"))
    with pytest.raises(dacl.WindowsFileAccessDaclError):
        dacl.verify_resource_dacl(handle, POLICY, state="readable")


class SecurityProxy:
    def __init__(self, real, sddl, *, error=0, bad_ace=False):
        self.real = real
        self.sddl = sddl
        self.error = error
        self.bad_ace = bad_ace
        self.selections = []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def GetSecurityInfo(self, handle, kind, selection, owner, group, acl, sacl, output):
        self.selections.append(selection)
        assert handle.value == 123 and kind == 1
        assert group is None and sacl is None
        descriptor = native._converted_descriptor(self.real, self.sddl)
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = descriptor
        self.real.GetSecurityDescriptorOwner.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        )
        self.real.GetSecurityDescriptorOwner.restype = wintypes.BOOL
        defaulted = wintypes.BOOL()
        assert self.real.GetSecurityDescriptorOwner(descriptor, owner, ctypes.byref(defaulted))
        try:
            actual_dacl = native._descriptor_dacl(self.real, descriptor)
        except native.WindowsOwnerAclError:
            actual_dacl = ctypes.c_void_p()
        ctypes.cast(acl, ctypes.POINTER(ctypes.c_void_p))[0] = actual_dacl
        return self.error

    def GetAce(self, acl, index, pointer):
        if self.bad_ace:
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = 1
            return True
        return self.real.GetAce(acl, index, pointer)


def _mock_descriptor_source(monkeypatch, sddl, *, error=0, bad_ace=False, cleanup_failure=False):
    security, kernel = native._configure_apis()
    proxy = SecurityProxy(security, sddl, error=error, bad_ace=bad_ace)
    freed = []

    def free(pointer):
        result = kernel.LocalFree(pointer)
        freed.append(pointer.value)
        assert not result
        return 1 if cleanup_failure else None

    monkeypatch.setattr(native, "_configure_apis", lambda: (proxy, SimpleNamespace(LocalFree=free)))
    return proxy, freed


@pytest.mark.skipif(sys.platform != "win32", reason="native descriptor parsing, no file effects")
def test_only_exact_alternative_mask_is_a_recognized_recovery_state(monkeypatch):
    _mock_descriptor_source(monkeypatch, POLICY.file_sddl("metadata_only"))
    with pytest.raises(dacl.WindowsReaderMaskMismatch):
        dacl.verify_resource_dacl(123, POLICY, state="readable")


@pytest.mark.skipif(sys.platform != "win32", reason="native descriptor parsing, no file effects")
def test_cleanup_failure_is_not_a_recognized_alternative_state(monkeypatch):
    _mock_descriptor_source(monkeypatch, POLICY.file_sddl("metadata_only"), cleanup_failure=True)
    with pytest.raises(dacl.WindowsFileAccessDaclError) as caught:
        dacl.verify_resource_dacl(123, POLICY, state="readable")
    assert not isinstance(caught.value, dacl.WindowsReaderMaskMismatch)


@pytest.mark.skipif(sys.platform != "win32", reason="native descriptor parsing, no file effects")
@pytest.mark.parametrize("state", ["readable", "metadata_only", "directory"])
def test_verifies_native_descriptor_without_opening_or_mutating_a_file(monkeypatch, state):
    text = POLICY.directory_sddl() if state == "directory" else POLICY.file_sddl(state)
    proxy, freed = _mock_descriptor_source(monkeypatch, text)
    result = dacl.verify_resource_dacl(123, POLICY, state=state)
    assert result.startswith("sha256:") and len(result) == 71
    assert proxy.selections == [5]
    assert len(freed) == 3 and len(set(freed)) == 3


@pytest.mark.skipif(sys.platform != "win32", reason="native descriptor parsing, no file effects")
@pytest.mark.parametrize(
    "text",
    [
        f"O:{OWNER}D:(A;;FA;;;{OWNER})(A;;FR;;;{READER})",
        f"O:{OWNER}D:P(A;;FA;;;{OWNER})",
        f"O:{OWNER}D:P(A;;FA;;;{OWNER})(A;;FA;;;{READER})",
        f"O:{OWNER}D:P(A;;FA;;;{OWNER})(A;;FR;;;{READER})(A;;FR;;;WD)",
        f"O:{OWNER}D:P(A;;FR;;;{READER})(A;;FA;;;{OWNER})",
        f"O:{READER}D:P(A;;FA;;;{OWNER})(A;;FR;;;{READER})",
        f"O:{OWNER}D:P(A;OI;FA;;;{OWNER})(A;;FR;;;{READER})",
        f"O:{OWNER}D:P(A;;FA;;;{OWNER})(D;;FR;;;{READER})",
        POLICY.file_sddl("metadata_only"),
        POLICY.directory_sddl(),
    ],
)
def test_broader_inherited_reordered_changed_or_unprotected_descriptor_refused(monkeypatch, text):
    _, freed = _mock_descriptor_source(monkeypatch, text)
    with pytest.raises(dacl.WindowsFileAccessDaclError):
        dacl.verify_resource_dacl(123, POLICY, state="readable")
    assert len(freed) == 3


@pytest.mark.skipif(sys.platform != "win32", reason="native descriptor parsing, no file effects")
@pytest.mark.parametrize("failure", ["api", "pointer", "cleanup"])
def test_native_refusal_and_cleanup_failure_never_report_success(monkeypatch, failure):
    _, freed = _mock_descriptor_source(
        monkeypatch,
        POLICY.file_sddl("readable"),
        error=5 if failure == "api" else 0,
        bad_ace=failure == "pointer",
        cleanup_failure=failure == "cleanup",
    )
    with pytest.raises(dacl.WindowsFileAccessDaclError):
        dacl.verify_resource_dacl(123, POLICY, state="readable")
    assert len(freed) == 3


def test_other_platforms_do_not_attempt_windows_descriptor_calls(monkeypatch):
    monkeypatch.setattr(dacl.sys, "platform", "linux")
    with pytest.raises(dacl.WindowsFileAccessDaclError, match="unavailable"):
        dacl.verify_resource_dacl(123, POLICY, state="readable")
