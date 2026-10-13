"""Fixed setup-child OS handoff, not authentication of arbitrary same-owner code.

The trusted packaged parent exclusively owns the Job and assigns the suspended
child. No Job handle reaches the child: even a query copy would keep kill-on-close
from taking effect on parent death. Child queries its immediate Job by NULL handle.
"""

from __future__ import annotations

import ctypes
import os
import sys
from contextlib import contextmanager
from typing import Any, Iterator

from . import _windows_file_access_native_contract as contract
from . import windows_file_access_peer as peer

SCHEMA = "bluefire.windows-file-setup-supervision.v1"
_KEYS = ("parent_handle", "stdin_object", "stdout_object", "stderr_object")


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", ctypes.c_uint32),
        ("min_working", ctypes.c_size_t),
        ("max_working", ctypes.c_size_t),
        ("active_limit", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t),
        ("priority", ctypes.c_uint32),
        ("scheduling", ctypes.c_uint32),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits),
        ("io", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class _ProcessList(ctypes.Structure):
    _fields_ = [
        ("assigned", ctypes.c_uint32),
        ("listed", ctypes.c_uint32),
        ("ids", ctypes.c_size_t * 1),
    ]


class _ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("usage", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("heap", ctypes.c_size_t),
        ("module", ctypes.c_uint32),
        ("threads", ctypes.c_uint32),
        ("parent", ctypes.c_uint32),
        ("priority", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("executable", ctypes.c_wchar * 260),
    ]


def _document(value: Any) -> dict[str, Any]:
    row = contract._exact(
        value,
        "schema_version parent_handle parent_pid parent_created_filetime "
        "stdin_object stdout_object stderr_object",
    )
    contract._require(row["schema_version"] == SCHEMA)
    maximum = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 0x10000
    for key in _KEYS:
        contract._int(row[key], 1, maximum - 1)
    contract._require(len({row[key] for key in _KEYS}) == 4)
    contract._int(row["parent_pid"], 1, 2**32 - 1)
    contract._int(row["parent_created_filetime"], 1, 2**64 - 1)
    return row


class _Api(peer._Api):
    def __init__(self) -> None:
        super().__init__()
        k = self.kernel
        k.GetCurrentProcess.argtypes, k.GetCurrentProcess.restype = (), ctypes.c_void_p
        k.CloseHandle.argtypes, k.CloseHandle.restype = (ctypes.c_void_p,), ctypes.c_int32
        k.DuplicateHandle.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.c_int32,
            ctypes.c_uint32,
        )
        k.DuplicateHandle.restype = ctypes.c_int32
        k.IsProcessInJob.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int32),
        )
        k.IsProcessInJob.restype = ctypes.c_int32
        k.QueryInformationJobObject.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        )
        k.QueryInformationJobObject.restype = ctypes.c_int32
        compare = ctypes.WinDLL("kernelbase.dll", use_last_error=True, winmode=0x800)
        compare.CompareObjectHandles.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        compare.CompareObjectHandles.restype = ctypes.c_int32
        self.compare = compare.CompareObjectHandles
        k.CreateToolhelp32Snapshot.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
        k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        for name in ("Process32FirstW", "Process32NextW"):
            function = getattr(k, name)
            function.argtypes = (ctypes.c_void_p, ctypes.POINTER(_ProcessEntry))
            function.restype = ctypes.c_int32

    def duplicate(self, source: int, target: int, access: int) -> int:
        output = ctypes.c_void_p()
        contract._require(
            self.kernel.DuplicateHandle(
                self.kernel.GetCurrentProcess(),
                source,
                target,
                ctypes.byref(output),
                access,
                False,
                0,
            )
            != 0
        )
        if output.value is None:
            raise RuntimeError("Setup handle duplication is unavailable")
        return int(output.value)

    def current_job(self) -> None:
        member = ctypes.c_int32()
        contract._require(
            self.kernel.IsProcessInJob(self.kernel.GetCurrentProcess(), None, ctypes.byref(member))
            and member.value == 1
        )
        limits, returned = _ExtendedLimits(), ctypes.c_uint32()
        contract._require(
            self.kernel.QueryInformationJobObject(
                None, 9, ctypes.byref(limits), ctypes.sizeof(limits), ctypes.byref(returned)
            )
            and returned.value == ctypes.sizeof(limits)
            and limits.basic.flags == 0x2000
        )
        processes = _ProcessList()
        contract._require(
            self.kernel.QueryInformationJobObject(
                None, 3, ctypes.byref(processes), ctypes.sizeof(processes), ctypes.byref(returned)
            )
            and returned.value == ctypes.sizeof(processes)
            and processes.assigned == processes.listed == 1
            and processes.ids[0] == os.getpid()
        )

    def actual_parent(self) -> int:
        snapshot = self.kernel.CreateToolhelp32Snapshot(2, 0)
        contract._require(snapshot not in (None, 0, ctypes.c_void_p(-1).value))
        try:
            item = _ProcessEntry()
            item.size = ctypes.sizeof(item)
            available = self.kernel.Process32FirstW(snapshot, ctypes.byref(item))
            for _ in range(65536):
                contract._require(bool(available))
                if item.pid == os.getpid():
                    return int(item.parent)
                available = self.kernel.Process32NextW(snapshot, ctypes.byref(item))
            raise RuntimeError("Setup process inventory exceeds its bound")
        finally:
            contract._require(bool(self.kernel.CloseHandle(snapshot)))


def transfer_to_child(
    process_handle: int, pipe_descriptors: tuple[int, int, int]
) -> dict[str, Any]:
    """Copy only query/comparison handles into the already assigned suspended child.

    If a native duplicate succeeds before an error, only child exit resolves that
    remote handle. Never close a remote numeric value in the parent's handle table.
    """
    import msvcrt

    api = _Api()
    api.require_running(process_handle)
    api.require_noninherited(process_handle)
    current = api.kernel.GetCurrentProcess()
    parent = api.generation(current)
    values = [api.duplicate(current, process_handle, 0x101000)]
    for descriptor in pipe_descriptors:
        handle = msvcrt.get_osfhandle(descriptor)
        contract._require(api.kernel.GetFileType(handle) == 3)
        values.append(api.duplicate(handle, process_handle, 0))
    contract._require(api.generation(current) == parent)
    return _document(
        {
            "schema_version": SCHEMA,
            "parent_pid": parent.process_id,
            "parent_created_filetime": parent.created_filetime,
            **dict(zip(_KEYS, values, strict=True)),
        }
    )


@contextmanager
def require_child_handoff(value: Any) -> Iterator[None]:
    """Verify actual current Job, retained parent and stdio objects before effects."""
    import msvcrt

    row = _document(value)
    api = _Api()
    handles = [row[key] for key in _KEYS]
    try:
        for handle in handles:
            api.require_noninherited(handle)
        expected = peer.WindowsPeerGeneration(row["parent_pid"], row["parent_created_filetime"])
        contract._require(expected.process_id != os.getpid())
        actual_child = api.generation(api.kernel.GetCurrentProcess())
        contract._require(
            api.actual_parent() == expected.process_id
            and expected.created_filetime < actual_child.created_filetime
        )
        api.require_running(handles[0])
        contract._require(api.generation(handles[0]) == expected)
        api.current_job()
        for stream, copied in zip((sys.stdin, sys.stdout, sys.stderr), handles[1:], strict=True):
            actual = msvcrt.get_osfhandle(stream.fileno())
            contract._require(
                actual not in handles
                and api.kernel.GetFileType(actual) == 3
                and api.compare(actual, copied)
            )
        api.require_running(handles[0])
        contract._require(api.generation(handles[0]) == expected)
        api.current_job()
        contract._require(
            api.actual_parent() == expected.process_id
            and api.generation(api.kernel.GetCurrentProcess()) == actual_child
        )
    finally:
        failed = False
        for handle in reversed(handles):
            try:
                failed = not api.kernel.CloseHandle(handle) or failed
            except Exception:
                failed = True
        contract._require(not failed)
    # All copies are closed before provisioning; only the parent's owned Job
    # handle remains. The parent's monitor, not these clock scalars, enforces time.
    yield
