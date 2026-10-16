from __future__ import annotations

import ctypes
from ctypes import wintypes
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import runner_windows_containment as containment
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.windows_file_access_child import WindowsChildBindingError, WindowsPeerGeneration

PROCESS_ID = 42
PROCESS_HANDLE = 100
JOB_HANDLE = 200
SNAPSHOT_HANDLE = 300
THREAD_HANDLE = 400
THREAD_ID = 7
GENERATION = WindowsPeerGeneration(PROCESS_ID, 123456)


class NativeCall:
    def __init__(self, name: str, events: list[tuple[Any, ...]], result: Any):
        self.name = name
        self.events = events
        self.result = result
        self.argtypes = None
        self.restype = None

    def __call__(self, *args: Any):
        self.events.append((self.name, *args))
        return self.result(*args) if callable(self.result) else self.result


class FakeKernel:
    def __init__(self):
        self.events: list[tuple[Any, ...]] = []
        self.process_id = PROCESS_ID
        self.wait_result = 258
        self.inherited: set[int] = set()
        self.assign_result = 1
        self.thread_owner = PROCESS_ID
        self.calls = {
            "GetProcessId": NativeCall("GetProcessId", self.events, self.get_process_id),
            "WaitForSingleObject": NativeCall(
                "WaitForSingleObject", self.events, lambda *_: self.wait_result
            ),
            "GetHandleInformation": NativeCall(
                "GetHandleInformation", self.events, self.get_handle_information
            ),
            "AssignProcessToJobObject": NativeCall(
                "AssignProcessToJobObject", self.events, lambda *_: self.assign_result
            ),
            "OpenProcess": NativeCall("OpenProcess", self.events, self.forbid_open_process),
            "CreateToolhelp32Snapshot": NativeCall(
                "CreateToolhelp32Snapshot", self.events, SNAPSHOT_HANDLE
            ),
            "Thread32First": NativeCall("Thread32First", self.events, self.first_thread),
            "Thread32Next": NativeCall("Thread32Next", self.events, 0),
            "OpenThread": NativeCall("OpenThread", self.events, THREAD_HANDLE),
            "GetProcessIdOfThread": NativeCall(
                "GetProcessIdOfThread", self.events, lambda *_: self.thread_owner
            ),
            "ResumeThread": NativeCall("ResumeThread", self.events, 1),
            "TerminateJobObject": NativeCall("TerminateJobObject", self.events, 1),
            "QueryInformationJobObject": NativeCall(
                "QueryInformationJobObject", self.events, self.query_job
            ),
        }

    def __getattr__(self, name: str):
        try:
            return self.calls[name]
        except KeyError:
            raise AssertionError(f"unexpected kernel API: {name}") from None

    def get_process_id(self, handle: int) -> int:
        return self.process_id

    def get_handle_information(self, handle: int, output: Any) -> int:
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD)).contents.value = int(
            handle in self.inherited
        )
        return 1

    def first_thread(self, _snapshot: int, output: Any) -> int:
        entry = output._obj
        entry.owner_process_id = PROCESS_ID
        entry.thread_id = THREAD_ID
        return 1

    @staticmethod
    def query_job(_job: int, _kind: int, details: Any, _size: int, returned: Any) -> int:
        details._obj.active_processes = 0
        returned._obj.value = 1
        return 1

    @staticmethod
    def forbid_open_process(*_args: Any) -> None:
        raise AssertionError("retained assignment must not reopen by PID")


class FakeProcess:
    def __init__(self, pid: int = PROCESS_ID, handle: int = PROCESS_HANDLE):
        self.pid = pid
        self._handle = handle
        self.returncode = None
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return self.returncode


class ClosedHandle(int):
    closed = True


@pytest.fixture
def fake_windows(monkeypatch: pytest.MonkeyPatch):
    kernel = FakeKernel()
    closes: list[int] = []
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False)
    monkeypatch.setattr(containment, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(
        containment.WindowsJobContainment,
        "close_handle",
        staticmethod(lambda handle: closes.append(handle) or True),
    )
    return kernel, closes


def test_assign_retained_uses_borrowed_handle_without_open_or_close(fake_windows):
    kernel, closes = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)

    owner.assign_retained(JOB_HANDLE, process)

    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert ("AssignProcessToJobObject", JOB_HANDLE, PROCESS_HANDLE) in kernel.events
    assert not any(event[0] == "OpenProcess" for event in kernel.events)
    assert not any(
        event[0] == "GetProcessId" and event[1] != PROCESS_HANDLE for event in kernel.events
    )
    assert closes == []


@pytest.mark.parametrize(
    "handle",
    [
        None,
        0,
        True,
        -1,
        (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1,
        object(),
        ClosedHandle(100),
    ],
)
def test_invalid_or_closed_borrowed_handle_never_reaches_the_kernel(fake_windows, handle):
    kernel, closes = fake_windows
    owner = containment.WindowsJobContainment(kill_on_close=True)
    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, FakeProcess(handle=handle))
    assert not kernel.events and not closes
    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}


@pytest.mark.parametrize("pid", [0, -1, True, 1 << 32, "42"])
def test_invalid_process_id_is_rejected_before_job_adoption(fake_windows, pid):
    kernel, closes = fake_windows
    owner = containment.WindowsJobContainment(kill_on_close=True)

    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, FakeProcess(pid=pid))

    assert owner._jobs == {}
    assert kernel.events == [] and closes == []


def test_finish_drains_transferred_job_after_borrowed_handle_refusal(fake_windows):
    kernel, closes = fake_windows
    process = FakeProcess(handle=None)
    owner = containment.WindowsJobContainment(kill_on_close=True)

    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, process)
    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert not kernel.events

    assert owner.finish_retained(process, JOB_HANDLE) is True

    assert [event[0] for event in kernel.events] == [
        "TerminateJobObject",
        "QueryInformationJobObject",
    ]
    assert kernel.events[0][1:] == (JOB_HANDLE, 1)
    query = kernel.events[1]
    assert query[1:3] == (JOB_HANDLE, 1)
    assert query[3]._obj.active_processes == 0 and query[5]._obj.value == 1
    assert closes == [JOB_HANDLE]
    assert process.poll_calls == 0
    assert owner._jobs == {}
    assert owner.finish_retained(process, JOB_HANDLE) is True
    assert process.poll_calls == 0


def test_adoption_is_non_native_and_idempotent_only_for_exact_live_transfer(fake_windows):
    kernel, closes = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner.adopt_retained_job(JOB_HANDLE, process)
    owner.adopt_retained_job(JOB_HANDLE, process)
    assert owner._retained_jobs == {process: (PROCESS_ID, JOB_HANDLE)}
    assert not kernel.events and not closes
    owner.assign_retained(JOB_HANDLE, process)
    before = list(kernel.events)
    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, process)
    assert kernel.events == before


def test_rejected_collision_cannot_drain_other_process_job(fake_windows):
    kernel, closes = fake_windows
    process, rejected = FakeProcess(), FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner.adopt_retained_job(JOB_HANDLE, process)
    with pytest.raises(RunnerTransportError):
        owner.adopt_retained_job(JOB_HANDLE, rejected)
    assert owner.finish_retained(rejected, JOB_HANDLE) is False
    assert owner.finish_retained(process, JOB_HANDLE + 1) is False
    assert not kernel.events and not closes
    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}


def test_changed_pid_and_released_job_cannot_be_readopted(fake_windows):
    kernel, _ = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner.adopt_retained_job(JOB_HANDLE, process)
    process.pid += 1
    with pytest.raises(RunnerTransportError):
        owner.adopt_retained_job(JOB_HANDLE, process)
    assert owner.finish_retained(process, JOB_HANDLE) is False
    assert not kernel.events
    process.pid = PROCESS_ID
    assert owner.finish_retained(process, JOB_HANDLE) is True
    with pytest.raises(RunnerTransportError):
        owner.adopt_retained_job(JOB_HANDLE, process)
    assert owner._jobs == {}


def test_drain_retains_job_until_threads_stop_and_failed_close_retries_without_poll(
    fake_windows, monkeypatch
):
    kernel, closes = fake_windows
    process = FakeProcess(handle=None)
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner.adopt_retained_job(JOB_HANDLE, process)
    close_results = iter([False, OSError("close still unavailable"), True])

    def close(handle):
        closes.append(handle)
        result = next(close_results)
        if isinstance(result, OSError):
            raise result
        return result

    def no_poll():
        raise AssertionError("Job drainage cannot use a detached parent handle")

    monkeypatch.setattr(process, "poll", no_poll)
    monkeypatch.setattr(owner, "close_handle", close)
    assert owner.drain_retained(process, JOB_HANDLE) is True
    assert not closes and owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert owner.drain_retained(process, JOB_HANDLE) is True
    assert owner.finish_retained(process, JOB_HANDLE) is False
    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert owner.finish_retained(process, JOB_HANDLE) is False
    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert owner.finish_retained(process, JOB_HANDLE) is True
    assert owner.finish_retained(process, JOB_HANDLE) is True
    assert [event[0] for event in kernel.events] == [
        "TerminateJobObject",
        "QueryInformationJobObject",
    ] * 3
    assert closes == [JOB_HANDLE, JOB_HANDLE, JOB_HANDLE]
    assert owner._jobs == {}


def test_late_assignment_after_provisional_drain_requires_fresh_final_drain(fake_windows):
    kernel, closes = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    members = []

    def assignment(job, handle):
        assert (job, handle) == (JOB_HANDLE, PROCESS_HANDLE)
        assert owner.drain_retained(process, JOB_HANDLE) is True
        assert not closes and process not in owner._retained_drained
        members.append(handle)
        return 1

    def terminate(job, _exit_code):
        assert job == JOB_HANDLE
        members.clear()
        return 1

    def query(job, _kind, details, _size, returned):
        assert job == JOB_HANDLE
        details._obj.active_processes = len(members)
        returned._obj.value = 1
        return 1

    kernel.calls["AssignProcessToJobObject"].result = assignment
    kernel.calls["TerminateJobObject"].result = terminate
    kernel.calls["QueryInformationJobObject"].result = query
    owner.assign_retained(JOB_HANDLE, process)
    assert members == [PROCESS_HANDLE]
    assert owner.finish_retained(process, JOB_HANDLE) is True
    assert not members and closes == [JOB_HANDLE]
    assert [event[0] for event in kernel.events].count("TerminateJobObject") == 2
    assert [event[0] for event in kernel.events].count("QueryInformationJobObject") == 2


@pytest.mark.parametrize(
    "fault",
    ["handle_pid", "exited", "inherited_process", "inherited_job", "assignment"],
)
def test_assign_retained_refuses_bad_or_unassignable_child_and_retains_job(fake_windows, fault):
    kernel, _ = fake_windows
    process = FakeProcess()
    if fault == "handle_pid":
        kernel.process_id = PROCESS_ID + 1
    elif fault == "exited":
        kernel.wait_result = 0
    elif fault == "inherited_process":
        kernel.inherited.add(PROCESS_HANDLE)
    elif fault == "inherited_job":
        kernel.inherited.add(JOB_HANDLE)
    else:
        kernel.assign_result = 0
    owner = containment.WindowsJobContainment(kill_on_close=True)

    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, process)

    assert owner._jobs == {PROCESS_ID: JOB_HANDLE}
    assert not any(event[0] == "OpenProcess" for event in kernel.events)
    if fault != "assignment":
        assert not any(event[0] == "AssignProcessToJobObject" for event in kernel.events)


@pytest.mark.parametrize("job", [0, True, (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1])
def test_assign_retained_rejects_invalid_job_handles_before_kernel_calls(fake_windows, job):
    kernel, _ = fake_windows
    owner = containment.WindowsJobContainment(kill_on_close=True)

    with pytest.raises(RunnerTransportError):
        owner.assign_retained(job, FakeProcess())

    assert kernel.events == []
    assert owner._jobs == {}


@pytest.mark.parametrize("collision", ["pid", "job"])
def test_assign_retained_refuses_existing_pid_or_owned_job_collision(fake_windows, collision):
    kernel, _ = fake_windows
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner._jobs[PROCESS_ID if collision == "pid" else PROCESS_ID + 1] = (
        JOB_HANDLE + 1 if collision == "pid" else JOB_HANDLE
    )

    with pytest.raises(RunnerTransportError):
        owner.assign_retained(JOB_HANDLE, FakeProcess())

    assert kernel.events == []


def _install_child_check(monkeypatch, events, *, fail_call=None):
    calls = []

    def require(process_handle, job_handle, *, expected):
        calls.append((process_handle, job_handle, expected))
        events.append(("generation_job_recheck", process_handle, job_handle))
        if fail_call == len(calls):
            raise WindowsChildBindingError("fake retained binding changed")

    monkeypatch.setattr("bluefire.windows_file_access_child.require_retained_child", require)
    return calls


def test_resume_retained_rechecks_immediately_before_resume_with_query_and_resume_rights(
    fake_windows, monkeypatch
):
    kernel, closes = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner._jobs[PROCESS_ID] = JOB_HANDLE
    checks = _install_child_check(monkeypatch, kernel.events)

    owner.resume_retained(process, JOB_HANDLE, GENERATION)

    assert len(checks) == 2
    assert checks == [(PROCESS_HANDLE, JOB_HANDLE, GENERATION)] * 2
    opened = next(event for event in kernel.events if event[0] == "OpenThread")
    assert opened[1] == 0x0800 | 0x0002
    owner_check = next(
        i for i, event in enumerate(kernel.events) if event[0] == "GetProcessIdOfThread"
    )
    recheck = [i for i, event in enumerate(kernel.events) if event[0] == "generation_job_recheck"][
        -1
    ]
    resume = next(i for i, event in enumerate(kernel.events) if event[0] == "ResumeThread")
    assert owner_check < recheck < resume
    assert resume >= 0 and closes == [THREAD_HANDLE, SNAPSHOT_HANDLE]


@pytest.mark.parametrize("fault", ["generation", "job", "thread_owner", "recheck"])
def test_resume_retained_refuses_stale_bindings_before_resuming(fake_windows, monkeypatch, fault):
    kernel, _ = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner._jobs[PROCESS_ID] = JOB_HANDLE + 1 if fault == "job" else JOB_HANDLE
    generation = (
        WindowsPeerGeneration(PROCESS_ID + 1, GENERATION.created_filetime)
        if fault == "generation"
        else GENERATION
    )
    checks = _install_child_check(
        monkeypatch, kernel.events, fail_call=2 if fault == "recheck" else None
    )
    if fault == "thread_owner":
        kernel.thread_owner = PROCESS_ID + 1

    expected_error = WindowsChildBindingError if fault == "recheck" else RunnerTransportError
    with pytest.raises(expected_error):
        owner.resume_retained(process, JOB_HANDLE, generation)

    assert not any(event[0] == "ResumeThread" for event in kernel.events)
    if fault == "generation":
        assert checks == [] and kernel.events == []
    elif fault == "job":
        assert checks == [] and kernel.events == []
    elif fault == "thread_owner":
        assert len(checks) == 1
    else:
        assert len(checks) == 2
        events = [event[0] for event in kernel.events]
        assert events.index("GetProcessIdOfThread") < events.index("generation_job_recheck", 1)


def test_legacy_resume_without_callback_keeps_resume_only_right_and_no_owner_query(fake_windows):
    kernel, closes = fake_windows

    containment.WindowsJobContainment.resume_suspended(FakeProcess())

    opened = next(event for event in kernel.events if event[0] == "OpenThread")
    assert opened[1] == 0x0002
    assert not any(event[0] == "GetProcessIdOfThread" for event in kernel.events)
    assert any(event[0] == "ResumeThread" for event in kernel.events)
    assert closes == [THREAD_HANDLE, SNAPSHOT_HANDLE]


def test_failed_temporary_close_is_owned_by_process_and_cleanup_retries_only_that_handle(
    fake_windows, monkeypatch
):
    kernel, closes = fake_windows
    process = FakeProcess()
    owner = containment.WindowsJobContainment(kill_on_close=True)
    owner._jobs[PROCESS_ID] = JOB_HANDLE
    checks = _install_child_check(monkeypatch, kernel.events)
    outcomes = {
        THREAD_HANDLE: iter([False, True]),
        SNAPSHOT_HANDLE: iter([OSError("first close failed"), OSError("retry close failed"), True]),
    }

    def close(handle):
        closes.append(handle)
        result = next(outcomes[handle])
        if isinstance(result, OSError):
            raise result
        return result

    monkeypatch.setattr(containment.WindowsJobContainment, "close_handle", staticmethod(close))
    with pytest.raises(RunnerTransportError, match="handles remain open"):
        owner.resume_retained(process, JOB_HANDLE, GENERATION)

    assert len(checks) == 2 and any(event[0] == "ResumeThread" for event in kernel.events)
    assert owner._retained_start_handles == {process: [THREAD_HANDLE, SNAPSHOT_HANDLE]}
    assert closes == [THREAD_HANDLE, SNAPSHOT_HANDLE]
    assert owner.close_retained_start_handles(process) is False
    assert owner._retained_start_handles == {process: [SNAPSHOT_HANDLE]}
    assert owner.close_retained_start_handles(process) is True
    assert process not in owner._retained_start_handles
    assert closes == [
        THREAD_HANDLE,
        SNAPSHOT_HANDLE,
        THREAD_HANDLE,
        SNAPSHOT_HANDLE,
        SNAPSHOT_HANDLE,
    ]
