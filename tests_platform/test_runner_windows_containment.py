from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import runner_client as client_module
from bluefire import runner_windows_containment as windows_module
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.runner_windows_containment import WindowsJobContainment


class KernelCall:
    def __init__(self, kernel: FakeKernel, name: str, result: Any) -> None:
        self.kernel = kernel
        self.name = name
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.kernel.calls.append((self.name, args))
        return self.result(*args) if callable(self.result) else self.result


class FakeKernel:
    """No host Win32 API is reachable through this fixture."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.next_job = 100
        self.active_processes = 0
        self.CreateJobObjectW = KernelCall(self, "create", self.create)
        self.SetInformationJobObject = KernelCall(self, "limits", 1)
        self.OpenProcess = KernelCall(self, "open_process", 200)
        self.AssignProcessToJobObject = KernelCall(self, "assign", 1)
        self.TerminateProcess = KernelCall(self, "terminate_process", 1)
        self.TerminateJobObject = KernelCall(self, "terminate_job", 1)
        self.QueryInformationJobObject = KernelCall(self, "query", self.query)
        self.CloseHandle = KernelCall(self, "close", 1)
        self.CreateToolhelp32Snapshot = KernelCall(self, "snapshot", 300)
        self.Thread32First = KernelCall(self, "first_thread", self.first_thread)
        self.Thread32Next = KernelCall(self, "next_thread", 0)
        self.OpenThread = KernelCall(self, "open_thread", 400)
        self.ResumeThread = KernelCall(self, "resume", 1)

    def create(self, *_args: Any) -> int:
        self.next_job += 1
        return self.next_job

    def query(self, _job: int, _kind: int, details: Any, *_args: Any) -> int:
        details._obj.active_processes = self.active_processes
        return 1

    @staticmethod
    def first_thread(_snapshot: int, entry: Any) -> int:
        entry._obj.owner_process_id = 42
        entry._obj.thread_id = 7
        return 1


class FakeProcess:
    pid = 42

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.killed = False
        self.waits: list[float] = []

    def wait(self, timeout: float) -> int:
        self.waits.append(timeout)
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True


@pytest.fixture
def kernel(monkeypatch: pytest.MonkeyPatch) -> FakeKernel:
    result = FakeKernel()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: result, raising=False)
    monkeypatch.setattr(windows_module, "sys", SimpleNamespace(platform="win32"))
    ticks = iter(range(100))
    monkeypatch.setattr(
        windows_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _seconds: None),
    )
    return result


def _spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kernel: FakeKernel
) -> tuple[SubprocessRustRunner, FakeProcess, list[Any]]:
    runner = object.__new__(SubprocessRustRunner)
    runner.work_root = tmp_path
    runner._kill_child_on_job_close = True
    runner._windows_containment = WindowsJobContainment(kill_on_close=True)
    process = FakeProcess()
    sink: list[Any] = []

    def popen(_argv: list[str], **options: Any) -> FakeProcess:
        assert options["shell"] is False
        assert options["creationflags"] & 4
        kernel.calls.append(("spawn_suspended", ()))
        return process

    monkeypatch.setattr(client_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(client_module, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(
        client_module,
        "subprocess",
        SimpleNamespace(Popen=popen, DEVNULL=-3, CREATE_SUSPENDED=4),
    )
    monkeypatch.setattr(runner._windows_containment, "system_directory", lambda: tmp_path)
    return runner, process, sink


@pytest.mark.parametrize("kill_on_close", [False, True])
def test_jobs_apply_only_the_requested_parent_death_policy(
    kernel: FakeKernel, kill_on_close: bool
) -> None:
    owner = WindowsJobContainment(kill_on_close=kill_on_close)
    job = owner.create_job()
    limits = [args for name, args in kernel.calls if name == "limits"]
    assert len(limits) == int(kill_on_close)
    if limits:
        assert limits[0][0] == job
        assert limits[0][1] == 9
        assert limits[0][2]._obj.basic_limit_information.limit_flags == 0x0000_2000
    assert owner.close_handle(job) is True


def test_failed_job_policy_closes_the_new_handle(kernel: FakeKernel) -> None:
    kernel.SetInformationJobObject.result = 0
    with pytest.raises(RunnerTransportError, match="containment"):
        WindowsJobContainment(kill_on_close=True).create_job()
    assert ("close", (101,)) in kernel.calls


def test_transport_assigns_suspended_child_before_resuming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kernel: FakeKernel
) -> None:
    runner, process, sink = _spawn(tmp_path, monkeypatch, kernel)
    assert runner._spawn(["fixed-runner"], stdout=-1, process_sink=sink) is process
    names = [name for name, _args in kernel.calls]
    assert names.index("limits") < names.index("spawn_suspended")
    assert names.index("spawn_suspended") < names.index("assign") < names.index("resume")
    assert runner._windows_containment._jobs == {42: 101}
    assert sink == [process]
    assert ("close", (200,)) in kernel.calls
    assert ("close", (300,)) in kernel.calls
    assert ("close", (400,)) in kernel.calls


def test_assignment_failure_never_resumes_and_releases_unassigned_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kernel: FakeKernel
) -> None:
    runner, process, sink = _spawn(tmp_path, monkeypatch, kernel)
    kernel.AssignProcessToJobObject.result = 0
    with pytest.raises(RunnerTransportError, match="containment"):
        runner._spawn(["fixed-runner"], stdout=-1, process_sink=sink)
    assert process.killed and process.waits == [5.0]
    assert not sink and not runner._windows_containment._jobs
    assert not any(name == "resume" for name, _args in kernel.calls)
    assert ("close", (200,)) in kernel.calls
    assert ("close", (101,)) in kernel.calls


@pytest.mark.parametrize("previous_suspend_count", [0, 2, 0xFFFFFFFF])
def test_inexact_resume_stops_the_owned_job_before_reporting_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kernel: FakeKernel,
    previous_suspend_count: int,
) -> None:
    runner, process, sink = _spawn(tmp_path, monkeypatch, kernel)
    kernel.ResumeThread.result = previous_suspend_count
    with pytest.raises(RunnerTransportError, match="suspended process start"):
        runner._spawn(["fixed-runner"], stdout=-1, process_sink=sink)
    assert ("terminate_job", (101, 1)) in kernel.calls
    assert ("close", (101,)) in kernel.calls
    assert process.waits == [5.0]
    assert not runner._windows_containment._jobs and not sink


def test_nonempty_job_is_retained_until_a_later_verified_drain(kernel: FakeKernel) -> None:
    owner = WindowsJobContainment(kill_on_close=True)
    process = FakeProcess()
    job = owner.create_job()
    owner.assign(job, process)  # type: ignore[arg-type]
    kernel.active_processes = 1
    assert owner.finish(process) is False  # type: ignore[arg-type]
    assert owner._jobs == {process.pid: job}
    assert ("close", (job,)) not in kernel.calls
    kernel.active_processes = 0
    assert owner.finish(process) is True  # type: ignore[arg-type]
    assert owner._jobs == {}
    assert ("close", (job,)) in kernel.calls


def test_failed_termination_retains_the_owned_job(kernel: FakeKernel) -> None:
    owner = WindowsJobContainment(kill_on_close=True)
    process = FakeProcess()
    job = owner.create_job()
    owner.assign(job, process)  # type: ignore[arg-type]
    kernel.TerminateJobObject.result = 0
    assert owner.terminate(process) is False  # type: ignore[arg-type]
    assert owner._jobs == {process.pid: job}
    assert not process.waits
    assert ("close", (job,)) not in kernel.calls


def test_containment_state_is_private_to_each_owner(kernel: FakeKernel) -> None:
    first = WindowsJobContainment(kill_on_close=False)
    second = WindowsJobContainment(kill_on_close=False)
    first_process, second_process = FakeProcess(), FakeProcess()
    first_job, second_job = first.create_job(), second.create_job()
    first.assign(first_job, first_process)  # type: ignore[arg-type]
    second.assign(second_job, second_process)  # type: ignore[arg-type]
    assert first.finish(first_process) is True  # type: ignore[arg-type]
    assert second._jobs == {second_process.pid: second_job}
    assert ("close", (second_job,)) not in kernel.calls


def test_wrong_platform_does_not_create_or_claim_containment(
    monkeypatch: pytest.MonkeyPatch, kernel: FakeKernel
) -> None:
    monkeypatch.setattr(windows_module, "sys", SimpleNamespace(platform="linux"))
    owner = WindowsJobContainment(kill_on_close=True)
    with pytest.raises(RunnerTransportError, match="unavailable"):
        owner.create_job()
    assert owner.finish(FakeProcess()) is False  # type: ignore[arg-type]
    assert owner.terminate(FakeProcess()) is False  # type: ignore[arg-type]
    assert not kernel.calls
