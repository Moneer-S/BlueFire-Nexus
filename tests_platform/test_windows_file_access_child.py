from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

import pytest

from bluefire import windows_file_access_child as child

GENERATION = child.WindowsPeerGeneration(41, 123456)
PROCESS_HANDLE = 100
JOB_HANDLE = 200


class FakeApi:
    def __init__(self):
        self.generations = [GENERATION] * 4
        self.running = [True] * 4
        self.inherited = set()
        self.membership = [True] * 4
        self.expected_job = JOB_HANDLE
        self.calls = []

    def require_noninherited(self, handle):
        self.calls.append(("noninherited", handle))
        if handle in self.inherited:
            raise child.WindowsChildBindingError("inherited")

    def require_running(self, handle):
        self.calls.append(("running", handle))
        if not self.running.pop(0):
            raise child.WindowsChildBindingError("exited")

    def generation(self, handle):
        self.calls.append(("generation", handle))
        return self.generations.pop(0)

    def require_member(self, process_handle, job_handle):
        self.calls.append(("member", process_handle, job_handle))
        if job_handle != self.expected_job or not self.membership.pop(0):
            raise child.WindowsChildBindingError("wrong Job")


class FakeNativeCall:
    def __init__(self):
        self.argtypes = None
        self.restype = None
        self.member = True
        self.result = 1
        self.calls = []

    def __call__(self, process_handle, job_handle, output):
        self.calls.append((process_handle, job_handle))
        ctypes.cast(output, ctypes.POINTER(wintypes.BOOL)).contents.value = self.member
        return self.result


class FakeKernel:
    def __init__(self):
        self.IsProcessInJob = FakeNativeCall()


def install(monkeypatch, api):
    monkeypatch.setattr(child, "_Api", lambda: api)


def native_api(monkeypatch, kernel):
    monkeypatch.setattr(child.peer._Api, "__init__", lambda api: setattr(api, "kernel", kernel))
    return child._Api()


def test_is_process_in_job_uses_exact_windows_abi_and_handles(monkeypatch):
    kernel = FakeKernel()
    api = native_api(monkeypatch, kernel)
    native = kernel.IsProcessInJob
    assert native.argtypes == (
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    assert native.restype is wintypes.BOOL
    if sys.platform == "win32":
        assert ctypes.sizeof(wintypes.BOOL) == ctypes.sizeof(wintypes.DWORD) == 4

    api.require_member(PROCESS_HANDLE, JOB_HANDLE)
    native.member = False
    with pytest.raises(child.WindowsChildBindingError):
        api.require_member(PROCESS_HANDLE, JOB_HANDLE)
    native.member = True
    native.result = 0
    with pytest.raises(child.WindowsChildBindingError):
        api.require_member(PROCESS_HANDLE, JOB_HANDLE)
    assert native.calls == [(PROCESS_HANDLE, JOB_HANDLE)] * 3


def test_capture_and_recheck_match_retained_generation_and_exact_job(monkeypatch):
    api = FakeApi()
    install(monkeypatch, api)
    expected = child.capture_retained_child(
        PROCESS_HANDLE, JOB_HANDLE, expected_pid=GENERATION.process_id
    )
    assert expected == GENERATION
    child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=expected)
    assert [call for call in api.calls if call[0] == "member"] == [
        ("member", PROCESS_HANDLE, JOB_HANDLE)
    ] * 4


def test_capture_rejects_a_pid_different_from_the_spawned_child(monkeypatch):
    install(monkeypatch, FakeApi())
    with pytest.raises(child.WindowsChildBindingError, match="process ID differs"):
        child.capture_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected_pid=42)


@pytest.mark.parametrize(
    "generations,running,membership",
    [
        ([GENERATION, child.WindowsPeerGeneration(41, 123457)], [True, True], [True, True]),
        ([GENERATION, GENERATION], [True, False], [True, True]),
        ([GENERATION, GENERATION], [True, True], [True, False]),
    ],
)
def test_capture_rechecks_generation_liveness_and_membership(
    monkeypatch, generations, running, membership
):
    api = FakeApi()
    api.generations = generations
    api.running = running
    api.membership = membership
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.capture_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected_pid=41)


@pytest.mark.parametrize(
    "changed",
    [child.WindowsPeerGeneration(42, 123456), child.WindowsPeerGeneration(41, 123457)],
)
def test_pid_or_creation_time_replacement_refuses(monkeypatch, changed):
    api = FakeApi()
    api.generations[1] = changed
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


def test_nonmember_refuses(monkeypatch):
    api = FakeApi()
    api.membership[0] = False
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


def test_membership_change_between_observations_refuses(monkeypatch):
    api = FakeApi()
    api.membership[1] = False
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


def test_membership_in_another_job_does_not_satisfy_exact_job(monkeypatch):
    api = FakeApi()
    api.expected_job = JOB_HANDLE + 1
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


def test_child_exit_between_observations_refuses(monkeypatch):
    api = FakeApi()
    api.running[1] = False
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


@pytest.mark.parametrize("handle", [PROCESS_HANDLE, JOB_HANDLE])
def test_inherited_handle_refuses(monkeypatch, handle):
    api = FakeApi()
    api.inherited.add(handle)
    install(monkeypatch, api)
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)


@pytest.mark.parametrize(
    "process_handle,job_handle,expected_pid",
    [
        (True, JOB_HANDLE, 41),
        (PROCESS_HANDLE, True, 41),
        (0, JOB_HANDLE, 41),
        (PROCESS_HANDLE, 0, 41),
        (-2, JOB_HANDLE, 41),
        (ctypes.c_void_p(-1).value, JOB_HANDLE, 41),
        (PROCESS_HANDLE, ctypes.c_void_p(-2).value, 41),
        (ctypes.c_void_p(-4).value, JOB_HANDLE, 41),
        (ctypes.c_void_p(-5).value, JOB_HANDLE, 41),
        (ctypes.c_void_p(-6).value, JOB_HANDLE, 41),
        (PROCESS_HANDLE, ctypes.c_void_p(-4).value, 41),
        (PROCESS_HANDLE, ctypes.c_void_p(-5).value, 41),
        (PROCESS_HANDLE, ctypes.c_void_p(-6).value, 41),
        (1 << (ctypes.sizeof(ctypes.c_void_p) * 8), JOB_HANDLE, 41),
        (PROCESS_HANDLE, JOB_HANDLE, True),
        (PROCESS_HANDLE, JOB_HANDLE, 0),
        (PROCESS_HANDLE, JOB_HANDLE, 1 << 32),
    ],
)
def test_invalid_or_pseudo_inputs_do_not_construct_api(
    monkeypatch, process_handle, job_handle, expected_pid
):
    monkeypatch.setattr(child, "_Api", lambda: pytest.fail("native API must not be created"))
    with pytest.raises(child.WindowsChildBindingError):
        child.capture_retained_child(process_handle, job_handle, expected_pid=expected_pid)


@pytest.mark.parametrize(
    "expected",
    [
        child.WindowsPeerGeneration(True, 123456),
        child.WindowsPeerGeneration(41, True),
        child.WindowsPeerGeneration(0, 123456),
        child.WindowsPeerGeneration(41, 0),
        child.WindowsPeerGeneration(1 << 32, 123456),
        child.WindowsPeerGeneration(41, 1 << 64),
        object(),
    ],
)
def test_invalid_expected_generation_does_not_construct_api(monkeypatch, expected):
    monkeypatch.setattr(child, "_Api", lambda: pytest.fail("native API must not be created"))
    with pytest.raises(child.WindowsChildBindingError):
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=expected)


def test_api_exception_is_sanitized_and_fails_closed(monkeypatch):
    class BrokenApi(FakeApi):
        def require_member(self, process_handle, job_handle):
            raise OSError("private native detail")

    install(monkeypatch, BrokenApi())
    with pytest.raises(child.WindowsChildBindingError) as error:
        child.require_retained_child(PROCESS_HANDLE, JOB_HANDLE, expected=GENERATION)
    assert str(error.value) == "Windows child binding observation failed"
