from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from bluefire import runner_linux_containment as linux_module
from bluefire.runner_linux_containment import LinuxPrivateProcessContainment
from bluefire.runner_transport_errors import RunnerTransportError


class Process:
    pid = 701
    returncode = None

    def __init__(self, kernel):
        self.kernel = kernel
        self.wait_failure = None

    def poll(self):
        raise AssertionError("owned leader must never be polled/reaped before session drainage")

    def kill(self):
        self.kernel.events.append(("kill", self.pid))

    def wait(self, *, timeout):
        self.kernel.events.append(("reap", self.pid))
        if self.wait_failure:
            raise self.wait_failure
        self.returncode = 0
        return 0


class Kernel:
    def __init__(self):
        self.events = []
        self.identities = {701: (701, 7001, 701, 701)}
        self.descriptors = {}
        self.next_descriptor = 90
        self.exited = True

    def identity(self, pid):
        if pid not in self.identities:
            raise ProcessLookupError(pid)
        return self.identities[pid]

    def open(self, pid, flags):
        assert flags == 0
        self.next_descriptor += 1
        self.descriptors[self.next_descriptor] = pid
        self.events.append(("open", pid, self.next_descriptor))
        return self.next_descriptor

    def close(self, descriptor):
        self.events.append(("close", descriptor))
        del self.descriptors[descriptor]

    def waitid(self, kind, descriptor, flags):
        assert kind == 3 and flags == 0x01000005
        self.events.append(("observe", descriptor))
        return SimpleNamespace(si_pid=self.descriptors[descriptor]) if self.exited else None

    def signal(self, descriptor, signum, info, flags):
        assert info is None and flags == 0
        pid = self.descriptors[descriptor]
        self.events.append(("signal", pid, signum))
        if pid == 701:
            self.exited = True
        else:
            del self.identities[pid]

    def scandir(self, path):
        assert path == "/proc"
        self.events.append(("scan",))
        entries = [SimpleNamespace(name=str(pid)) for pid in self.identities]

        class Entries:
            def __enter__(self):
                return iter(entries)

            def __exit__(self, *_args):
                return None

        return Entries()


@pytest.fixture
def contained(monkeypatch):
    kernel = Kernel()
    monkeypatch.setattr(
        LinuxPrivateProcessContainment, "process_identity", staticmethod(kernel.identity)
    )
    monkeypatch.setattr(
        linux_module, "os", SimpleNamespace(close=kernel.close, scandir=kernel.scandir)
    )
    monkeypatch.setattr(linux_module, "_PIDFD_OPEN", kernel.open)
    monkeypatch.setattr(linux_module, "_PIDFD_SEND_SIGNAL", kernel.signal)
    monkeypatch.setattr(linux_module, "_WAIT_ID", kernel.waitid)
    monkeypatch.setattr(linux_module, "_PIDFD_ID_TYPE", 3)
    monkeypatch.setattr(linux_module, "_WAIT_EXITED", 4)
    monkeypatch.setattr(linux_module, "_WAIT_NO_HANG", 1)
    monkeypatch.setattr(linux_module, "_WAIT_NO_REAP", 0x01000000)
    ticks = iter(range(100))
    monkeypatch.setattr(
        linux_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _delay: None),
    )
    owner = LinuxPrivateProcessContainment()
    process = Process(kernel)
    owner.register(process)
    return owner, process, kernel


@pytest.mark.parametrize("terminate", [False, True])
def test_owned_session_drains_before_reaping_and_closes_each_pidfd(contained, terminate):
    owner, process, kernel = contained
    kernel.identities[702] = (702, 7002, 799, 701)
    kernel.identities[703] = (703, 7003, 703, 703)
    kernel.exited = not terminate
    assert owner.release(process, terminate=terminate)
    assert not owner.contains(process) and owner.was_released(process)
    assert not kernel.descriptors
    events = kernel.events
    reap = events.index(("reap", 701))
    assert next(i for i, event in enumerate(events) if event[:2] == ("signal", 702)) < reap
    assert next(i for i, event in enumerate(events) if event[0] == "observe") < reap
    assert events.index(("close", 91)) > reap
    assert not any(event[:2] == ("signal", 703) for event in events)
    assert owner.exited_without_reap(process)


@pytest.mark.parametrize(
    "missing",
    [
        "_PIDFD_OPEN",
        "_PIDFD_SEND_SIGNAL",
        "_WAIT_ID",
        "_PIDFD_ID_TYPE",
        "_WAIT_EXITED",
        "_WAIT_NO_HANG",
        "_WAIT_NO_REAP",
    ],
)
def test_platform_availability_requires_every_identity_and_nonreap_primitive(
    contained, monkeypatch, missing
):
    owner, _process, _kernel = contained
    assert owner.available()
    monkeypatch.setattr(linux_module, missing, None)
    assert not owner.available()


@pytest.mark.parametrize("failure", [ChildProcessError(), OSError("waitid failed"), "wrong_pid"])
def test_exit_observation_failure_retains_pidfd_without_reaping(contained, monkeypatch, failure):
    owner, process, kernel = contained

    def fail(*_args):
        if failure == "wrong_pid":
            return SimpleNamespace(si_pid=999)
        raise failure

    monkeypatch.setattr(linux_module, "_WAIT_ID", fail)
    with pytest.raises(RunnerTransportError):
        owner.release(process, terminate=False)
    assert owner.contains(process) and not owner.was_released(process)
    assert kernel.descriptors == {91: 701}
    assert not any(event[0] in {"reap", "close", "signal"} for event in kernel.events)


@pytest.mark.parametrize("failure", ["scan", "signal", "reap"])
def test_uncertain_drain_retains_owned_leader_for_later_reconciliation(
    contained, monkeypatch, failure
):
    owner, process, kernel = contained
    if failure == "scan":
        monkeypatch.setattr(owner, "_session_identities", lambda _identity: None)
    elif failure == "signal":
        kernel.identities[702] = (702, 7002, 799, 701)
        monkeypatch.setattr(owner, "_signal_identity", lambda *_args: False)
    else:
        process.wait_failure = subprocess.TimeoutExpired("owned child", 5)
    assert owner.release(process, terminate=False) is False
    assert owner.contains(process) and not owner.was_released(process)
    assert kernel.descriptors == {91: 701}
    assert ("close", 91) not in kernel.events


def test_terminated_leader_identity_mismatch_never_signals_or_reaps(contained):
    owner, process, kernel = contained
    kernel.exited = False
    kernel.identities[701] = (701, 9999, 701, 701)
    assert owner.release(process, terminate=True) is False
    assert kernel.descriptors == {91: 701}
    assert not any(event[0] in {"signal", "reap", "close"} for event in kernel.events)


def test_pidfd_close_failure_is_propagated_after_confirmed_drain(contained, monkeypatch):
    owner, process, kernel = contained
    close = kernel.close

    def fail_after_close(descriptor):
        close(descriptor)
        raise OSError("injected close failure after descriptor release")

    monkeypatch.setattr(linux_module.os, "close", fail_after_close)
    with pytest.raises(OSError, match="injected close failure"):
        owner.release(process, terminate=False)
    assert owner.was_released(process) and not owner.contains(process)
    assert not kernel.descriptors
    assert kernel.events.index(("reap", 701)) < kernel.events.index(("close", 91))
    assert owner.exited_without_reap(process)
    assert kernel.events.count(("close", 91)) == 1


def test_process_ownership_is_private_to_each_owner(contained):
    owner, process, kernel = contained
    other = LinuxPrivateProcessContainment()
    assert not other.contains(process) and not other.was_released(process)
    assert other.release(process, terminate=True) is False
    assert kernel.descriptors == {91: 701} and owner.contains(process)
