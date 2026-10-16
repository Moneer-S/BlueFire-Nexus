from __future__ import annotations

import ctypes
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_control as control
from bluefire.windows_file_access_dacl import WindowsFileAccessDaclError
from bluefire.windows_file_access_handles import WindowsFileFacts
from bluefire.windows_file_access_policy import WindowsFileAccessPolicy
from bluefire.windows_file_access_read import WindowsResourceExpectation
from bluefire.windows_session_facts import WindowsPrincipalFacts

PAYLOAD = b'{"record":1}\n'
READER = WindowsPrincipalFacts(41, 123456, "S-1-5-21-101-202-303-1002", 10, 20, 30, 2, False)
OWNER = replace(READER, process_id=42, user_sid="S-1-5-21-101-202-303-1001", token_id=11)
RESOURCE = WindowsResourceExpectation(
    "a" * 32,
    WindowsFileAccessPolicy(OWNER.user_sid, READER.user_sid),
    ((1, 1), (1, 2), (1, 3), (1, 4)),
    (1, 5),
    len(PAYLOAD),
    "sha256:" + hashlib.sha256(PAYLOAD).hexdigest(),
    1,
    "readable",
)
BEFORE = "sha256:" + "b" * 64
AFTER = "sha256:" + "c" * 64
REQUEST = control.WindowsControlRequest(RESOURCE, OWNER, BEFORE, "metadata_only")


class FakeController:
    def __init__(self):
        self.owner = OWNER
        self.paths = []
        self.positions = {}
        self.before = BEFORE
        self.applied = 0
        self.closed = False
        self.close_fails = False
        self.apply_fails = False
        self.fresh_denied = False
        self.changed_identity = False
        self.changed_before = False
        self.target_dacl_fails = False
        self.corrupt_after = False
        self.target = None
        self.admissions = 0

    def principal(self):
        return self.owner

    def open(self, path, *, directory, data=False):
        if data and self.fresh_denied:
            raise OSError("Fresh owner denied")
        self.paths.append((path, directory, data))
        return len(self.paths)

    def open_control(self, path):
        assert len(self.paths) == 4
        return self.open(path, directory=False)

    def facts(self, descriptor, *, directory):
        path, actual_directory, _ = self.paths[descriptor - 1]
        assert actual_directory is directory
        index = min(descriptor, 5)
        return WindowsFileFacts(
            (1, 99 if self.changed_identity and not directory else index),
            "\\\\?\\" + path,
            directory,
            0 if directory else len(PAYLOAD),
            1,
            16 if directory else 32,
            1,
            2,
            4 if self.changed_before or (self.applied and not directory) else 3,
        )

    def dacl(self, descriptor, policy, state):
        assert policy == RESOURCE.policy
        if state == "directory":
            return "sha256:" + "a" * 64
        if self.applied:
            assert state == self.target
            if self.target_dacl_fails:
                raise OSError("Target descriptor differs")
            return AFTER
        assert state == RESOURCE.state
        return self.before

    def seek(self, descriptor):
        self.positions[descriptor] = 0

    def read(self, descriptor, maximum):
        payload = b"x" * len(PAYLOAD) if self.corrupt_after and self.applied else PAYLOAD
        start = self.positions[descriptor]
        result = payload[start : start + maximum]
        self.positions[descriptor] += len(result)
        return result

    def apply(self, descriptor, policy, target):
        assert descriptor == 5 and policy == RESOURCE.policy
        assert self.admissions == 1
        self.applied += 1
        self.target = target
        if self.apply_fails:
            raise OSError("Native result unavailable")

    def close(self):
        self.closed = True
        if self.close_fails:
            raise OSError("Closure unavailable")

    def admit(self):
        self.admissions += 1


@pytest.fixture
def native(monkeypatch):
    result = FakeController()
    monkeypatch.setattr(control, "_Controller", lambda: result)
    return result


def test_hardening_changes_once_then_freshly_reads_as_owner(native):
    result = control.transition_windows_file_access(REQUEST, admit=native.admit)
    assert result.target == "metadata_only"
    assert result.before_descriptor_sha256 == BEFORE and result.after_descriptor_sha256 == AFTER
    assert result.fresh_owner_read and result.read_handles_closed
    assert (
        result.preserved_sha256 == RESOURCE.sha256
        and result.file_identity == RESOURCE.file_identity
    )
    assert native.applied == 1 and native.closed
    assert len(native.paths) == 6 and native.paths[-1][2] is True
    assert not hasattr(result, "non_owner_denied")


def test_explicit_restore_uses_the_same_finite_boundary(native, monkeypatch):
    resource = replace(RESOURCE, state="metadata_only")
    original = native.dacl

    def dacl(descriptor, policy, state):
        if not native.applied and state == "metadata_only":
            return BEFORE
        return original(descriptor, policy, state)

    monkeypatch.setattr(native, "dacl", dacl)
    result = control.transition_windows_file_access(
        replace(REQUEST, resource=resource, target="readable"), admit=native.admit
    )
    assert result.target == "readable" and native.applied == 1 and native.closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner", READER),
        ("owner", replace(OWNER, elevated=True)),
        ("previous_descriptor_sha256", "unknown"),
        ("target", "readable"),
        ("target", "all"),
    ],
)
def test_invalid_request_never_opens_or_changes_a_resource(native, field, value):
    with pytest.raises(control.WindowsControlError) as caught:
        control.transition_windows_file_access(
            replace(REQUEST, **{field: value}), admit=native.admit
        )
    assert not caught.value.change_may_have_occurred
    assert not native.paths and native.applied == 0 and native.closed


def test_changed_owner_or_previous_dacl_cannot_be_overwritten(native):
    native.before = AFTER
    with pytest.raises(control.WindowsControlError) as caught:
        control.transition_windows_file_access(REQUEST, admit=native.admit)
    assert not caught.value.change_may_have_occurred and native.applied == 0 and native.closed


@pytest.mark.parametrize("change", ["owner", "identity", "metadata", "descriptor", "revoke"])
def test_recheck_after_admission_refuses_any_changed_prerequisite(native, change):
    def admit():
        native.admit()
        if change == "owner":
            native.owner = replace(OWNER, modified_id=31)
        elif change == "identity":
            native.changed_identity = True
        elif change == "metadata":
            native.changed_before = True
        elif change == "descriptor":
            native.before = AFTER
        else:
            raise RuntimeError("Admission revoked")

    with pytest.raises(control.WindowsControlError) as caught:
        control.transition_windows_file_access(REQUEST, admit=admit)
    assert not caught.value.change_may_have_occurred and native.applied == 0 and native.closed


@pytest.mark.parametrize(
    "failure", ["apply_fails", "fresh_denied", "target_dacl_fails", "corrupt_after", "close_fails"]
)
def test_post_dispatch_uncertainty_requires_reconciliation_without_rollback(native, failure):
    setattr(native, failure, True)
    with pytest.raises(control.WindowsControlError) as caught:
        control.transition_windows_file_access(REQUEST, admit=native.admit)
    assert caught.value.change_may_have_occurred
    assert native.applied == 1 and native.target == "metadata_only" and native.closed


def test_deadline_after_mutation_preserves_uncertainty(native, monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(control.time, "monotonic", lambda: clock[0])
    original = native.apply

    def apply(*args):
        original(*args)
        clock[0] = 15.0

    monkeypatch.setattr(native, "apply", apply)
    with pytest.raises(control.WindowsControlError) as caught:
        control.transition_windows_file_access(REQUEST, admit=native.admit)
    assert caught.value.change_may_have_occurred and native.applied == 1 and native.closed


@pytest.mark.parametrize("native_error,free_error", [(0, False), (5, False), (0, True)])
def test_native_setter_selects_only_protected_dacl_and_releases_descriptor(
    monkeypatch, native_error, free_error
):
    calls, freed = [], []

    def convert(text, revision, output, length):
        assert (
            text == RESOURCE.policy.file_sddl("metadata_only") and revision == 1 and length is None
        )
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 123
        return True

    def apply(handle, kind, flags, owner, group, dacl, sacl):
        calls.append((handle.value, kind, flags, owner, group, dacl.value, sacl))
        return native_error

    def free(pointer):
        freed.append(pointer.value)
        return 1 if free_error else None

    monkeypatch.setattr(
        control.native,
        "_configure_apis",
        lambda: (
            SimpleNamespace(
                ConvertStringSecurityDescriptorToSecurityDescriptorW=convert, SetSecurityInfo=apply
            ),
            SimpleNamespace(LocalFree=free),
        ),
    )
    monkeypatch.setattr(control.native, "_descriptor_dacl", lambda *_: ctypes.c_void_p(456))
    if native_error or free_error:
        with pytest.raises(OSError):
            control._set_selected_dacl(99, RESOURCE.policy, "metadata_only")
    else:
        control._set_selected_dacl(99, RESOURCE.policy, "metadata_only")
    assert calls == [(99, 1, 0x80000004, None, None, 456, None)]
    assert freed == [123]


@pytest.mark.parametrize("present", ["original", "target"])
def test_recovery_observes_state_with_read_only_handles_and_never_replays(
    native, monkeypatch, present
):
    def dacl(descriptor, policy, state):
        if state == "directory":
            return "sha256:" + "a" * 64
        actual = "readable" if present == "original" else "metadata_only"
        if state != actual:
            raise control.WindowsReaderMaskMismatch("Other exact state")
        return BEFORE if present == "original" else AFTER

    monkeypatch.setattr(native, "dacl", dacl)
    monkeypatch.setattr(
        native, "open_control", lambda *_: pytest.fail("Recovery cannot request WRITE_DAC")
    )
    monkeypatch.setattr(native, "apply", lambda *_: pytest.fail("Recovery cannot mutate"))
    result = control.reconcile_windows_file_access(REQUEST)
    assert result.state == present + "_observed"
    assert result.fresh_owner_read and result.read_handles_closed and native.closed
    assert len(native.paths) == 5 and native.paths[-1][2] is True
    assert native.admissions == 0


@pytest.mark.parametrize("failure", ["descriptor", "identity", "contents", "closure", "owner"])
def test_recovery_drift_and_incomplete_evidence_remain_unresolved(native, monkeypatch, failure):
    if failure == "descriptor":
        native.before = AFTER
    elif failure == "identity":
        native.changed_identity = True
    elif failure == "contents":
        monkeypatch.setattr(native, "read", lambda *_: b"")
    elif failure == "closure":
        native.close_fails = True
    else:
        native.owner = READER
    with pytest.raises(control.WindowsControlError) as caught:
        control.reconcile_windows_file_access(REQUEST)
    assert caught.value.change_may_have_occurred
    assert native.applied == 0 and native.closed


def test_recovery_never_retries_an_unavailable_or_unclosed_descriptor(native, monkeypatch):
    selections = []

    def dacl(descriptor, policy, state):
        selections.append(state)
        if state == "directory":
            return "sha256:" + "a" * 64
        raise WindowsFileAccessDaclError("Descriptor cleanup is unknown")

    monkeypatch.setattr(native, "dacl", dacl)
    with pytest.raises(control.WindowsControlError):
        control.reconcile_windows_file_access(REQUEST)
    assert selections == ["directory", "readable"]
    assert native.applied == 0 and native.closed
