"""In-memory OS-handoff fakes, never DLL loading, process launch or identity effects."""

from __future__ import annotations

import ctypes
import sys
from types import SimpleNamespace

import pytest

from bluefire import _windows_file_access_setup_binding as binding


@pytest.fixture
def msvcrt(monkeypatch):
    fake = SimpleNamespace(get_osfhandle=lambda fd: fd)
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    return fake


def supervision():
    return {
        "schema_version": binding.SCHEMA,
        "parent_handle": 100,
        "parent_pid": 41,
        "parent_created_filetime": 500,
        "stdin_object": 101,
        "stdout_object": 102,
        "stderr_object": 103,
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "job",
        "parent",
        "reuse",
        "creation",
        "stdio",
        "inherit",
        "exited",
        "close",
        "close_raise",
    ],
)
def test_child_actual_binding_and_all_query_copies_closed_before_effects(
    monkeypatch, msvcrt, fault
):
    closed = []

    class Api:
        def __init__(self):
            self.kernel = SimpleNamespace(
                GetCurrentProcess=lambda: -1, GetFileType=lambda h: 3, CloseHandle=self.close
            )

        def close(self, handle):
            closed.append(handle)
            if fault == "close_raise" and handle == 102:
                raise OSError("synthetic close")
            return not (fault == "close" and handle == 102)

        def require_noninherited(self, handle):
            if fault == "inherit":
                raise RuntimeError("inherited")

        def actual_parent(self):
            return 42 if fault == "parent" else 41

        def generation(self, handle):
            if handle == -1:
                return binding.peer.WindowsPeerGeneration(71, 400 if fault == "creation" else 600)
            return binding.peer.WindowsPeerGeneration(41, 501 if fault == "reuse" else 500)

        def require_running(self, handle):
            assert handle == 100
            if fault == "exited":
                raise RuntimeError("Parent exited")

        def current_job(self):
            if fault == "job":
                raise RuntimeError("not owned immediate Job")

        def compare(self, actual, copied):
            return fault != "stdio" and actual == copied + 100

    monkeypatch.setattr(binding, "_Api", Api)
    monkeypatch.setattr(binding.os, "getpid", lambda: 71)
    monkeypatch.setattr(msvcrt, "get_osfhandle", lambda fd: fd)
    # Patch only this module's sys binding; pytest keeps its actual capture streams.
    monkeypatch.setattr(
        binding,
        "sys",
        SimpleNamespace(
            stdin=SimpleNamespace(fileno=lambda: 201),
            stdout=SimpleNamespace(fileno=lambda: 202),
            stderr=SimpleNamespace(fileno=lambda: 203),
        ),
    )
    if fault:
        with pytest.raises((RuntimeError, binding.contract.NativeWireError)):
            with binding.require_child_handoff(supervision()):
                pytest.fail("Invalid OS handoff must not provision")
    else:
        with binding.require_child_handoff(supervision()):
            assert closed == [103, 102, 101, 100]
    assert closed == [103, 102, 101, 100]


@pytest.mark.parametrize(
    "field,value",
    [
        ("parent_handle", True),
        ("parent_handle", -1),
        ("parent_handle", 0),
        ("parent_handle", 2**64 - 1),
        ("stdin_object", 100),
        ("parent_pid", 0),
        ("parent_created_filetime", 0),
        ("schema_version", "caller-trusted"),
    ],
)
def test_bad_handle_or_parent_scalars_refused_without_abi(field, value):
    row = supervision()
    row[field] = value
    with pytest.raises(binding.contract.NativeWireError):
        binding._document(row)


@pytest.mark.parametrize(
    "fault", [None, "not_member", "limits_size", "breakaway", "no_kill", "many", "other_pid"]
)
def test_real_query_wrapper_uses_null_job_and_exact_single_child_limits(monkeypatch, fault):
    calls = []
    api = object.__new__(binding._Api)

    def member(process, job, result):
        assert process == -1 and job is None
        result._obj.value = int(fault != "not_member")
        return True

    def query(job, kind, output, size, returned):
        assert job is None
        calls.append(kind)
        returned._obj.value = size
        if kind == 9:
            assert size == ctypes.sizeof(binding._ExtendedLimits)
            output._obj.basic.flags = 0x2000
            if fault == "limits_size":
                returned._obj.value -= 1
            if fault == "breakaway":
                output._obj.basic.flags |= 0x800
            if fault == "no_kill":
                output._obj.basic.flags = 0
        else:
            assert kind == 3 and size == ctypes.sizeof(binding._ProcessList)
            output._obj.assigned = output._obj.listed = 2 if fault == "many" else 1
            output._obj.ids[0] = 72 if fault == "other_pid" else 71
        return True

    api.kernel = SimpleNamespace(
        GetCurrentProcess=lambda: -1, IsProcessInJob=member, QueryInformationJobObject=query
    )
    monkeypatch.setattr(binding.os, "getpid", lambda: 71)
    if fault:
        with pytest.raises(binding.contract.NativeWireError):
            api.current_job()
    else:
        api.current_job()
        assert calls == [9, 3]


def test_transfer_copies_parent_query_and_zero_access_stdio_never_job(monkeypatch, msvcrt):
    copied = []

    class Api:
        kernel = SimpleNamespace(GetCurrentProcess=lambda: -1, GetFileType=lambda handle: 3)

        def require_running(self, handle):
            assert handle == 900

        def require_noninherited(self, handle):
            assert handle == 900

        def generation(self, handle):
            assert handle == -1
            return binding.peer.WindowsPeerGeneration(41, 500)

        def duplicate(self, source, target, access):
            copied.append((source, target, access))
            return 99 + len(copied)

    monkeypatch.setattr(binding, "_Api", Api)
    monkeypatch.setattr(msvcrt, "get_osfhandle", lambda fd: fd + 1000)
    assert binding.transfer_to_child(900, (1, 2, 3)) == supervision()
    assert copied == [(-1, 900, 0x101000), (1001, 900, 0), (1002, 900, 0), (1003, 900, 0)]


@pytest.mark.parametrize("fault", [None, "missing", "close"])
def test_actual_parent_snapshot_is_fixed_bounded_and_closed(monkeypatch, fault):
    api = object.__new__(binding._Api)
    closed = []

    def first(snapshot, item):
        assert snapshot == 201 and item._obj.size == ctypes.sizeof(binding._ProcessEntry)
        item._obj.pid, item._obj.parent = 71, 41
        return fault != "missing"

    def close(handle):
        closed.append(handle)
        return fault != "close"

    api.kernel = SimpleNamespace(
        CreateToolhelp32Snapshot=lambda flags, pid: 201, Process32FirstW=first, CloseHandle=close
    )
    monkeypatch.setattr(binding.os, "getpid", lambda: 71)
    if fault:
        with pytest.raises(binding.contract.NativeWireError):
            api.actual_parent()
    else:
        assert api.actual_parent() == 41
    assert closed == [201]


@pytest.mark.parametrize("failure", [False, True])
def test_actual_duplicate_wrapper_never_inherits_or_requests_same_access(failure):
    api = object.__new__(binding._Api)
    calls = []

    def duplicate(source_process, source, target_process, output, access, inherit, options):
        calls.append((source_process, source, target_process, access, inherit, options))
        output._obj.value = 200
        return not failure

    api.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1, DuplicateHandle=duplicate)
    if failure:
        with pytest.raises(binding.contract.NativeWireError):
            api.duplicate(100, 900, 0)
    else:
        assert api.duplicate(100, 900, 0) == 200
    assert calls == [(-1, 100, 900, 0, False, 0)]
