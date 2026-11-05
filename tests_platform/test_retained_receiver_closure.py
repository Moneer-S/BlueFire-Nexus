"""Exact receiver-session drainage, including descendants and PID reuse."""

from __future__ import annotations

import ctypes
import os
import select
import signal
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from bluefire import retained_receiver_closure as closure
from bluefire import runner_linux_containment as linux
from bluefire.runner_linux_containment import LinuxPrivateProcessContainment


class SessionKernel:
    def __init__(self):
        self.identities = {
            701: (701, 7001, 701, 701),
            702: (702, 7002, 799, 701),
            703: (703, 7003, 703, 703),
        }
        self.descriptors = {}
        self.signals = []
        self.on_open = lambda _pid: None
        self.on_scan = lambda _count: None
        self.on_signal = lambda _pid, _signum: None
        self.ignore_term = set()
        self.ignore_all = set()
        self.scans = 0
        self.ticks = 0.0

    def identity(self, pid):
        if pid not in self.identities:
            raise ProcessLookupError(pid)
        return self.identities[pid]

    def open(self, pid, flags):
        assert flags == 0
        identity = self.identity(pid)
        descriptor = len(self.descriptors) + 90
        self.descriptors[descriptor] = identity
        self.on_open(pid)
        return descriptor

    def send(self, descriptor, signum, info, flags):
        assert info is None and flags == 0
        identity = self.descriptors[descriptor]
        assert self.identities.get(identity[0]) == identity
        pid = identity[0]
        self.signals.append((identity, signum))
        if pid not in self.ignore_all and not (signum == 15 and pid in self.ignore_term):
            del self.identities[pid]
        self.on_signal(pid, signum)

    def scandir(self, path):
        assert path == "/proc"
        self.scans += 1
        self.on_scan(self.scans)
        entries = [SimpleNamespace(name=str(pid)) for pid in self.identities]

        class Entries:
            def __enter__(self):
                return iter(entries)

            def __exit__(self, *_args):
                return None

        return Entries()

    def monotonic(self):
        self.ticks += 0.25
        return self.ticks


@pytest.fixture
def session_kernel(monkeypatch):
    kernel = SessionKernel()
    monkeypatch.setattr(closure, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(closure, "os", SimpleNamespace(scandir=kernel.scandir))
    monkeypatch.setattr(
        closure, "time", SimpleNamespace(monotonic=kernel.monotonic, sleep=lambda _delay: None)
    )
    monkeypatch.setattr(closure, "_KILL_SIGNAL", 9)
    monkeypatch.setattr(LinuxPrivateProcessContainment, "available", staticmethod(lambda: True))
    monkeypatch.setattr(
        LinuxPrivateProcessContainment, "process_identity", staticmethod(kernel.identity)
    )
    monkeypatch.setattr(linux, "_PIDFD_OPEN", kernel.open)
    monkeypatch.setattr(linux, "_PIDFD_SEND_SIGNAL", kernel.send)
    monkeypatch.setattr(
        linux, "os", SimpleNamespace(close=lambda descriptor: kernel.descriptors.pop(descriptor))
    )
    return kernel


def test_drains_every_exact_member_and_leaves_another_session_untouched(session_kernel):
    proof = closure.close_exact_receiver(701, "7001")
    assert proof == {
        "schema_version": "bluefire.receiver-closure-proof.v1",
        "process_id": 701,
        "creation_identity": "7001",
        "session_member_count": 0,
        "verified_closed": True,
    }
    assert [identity[0] for identity, _ in session_kernel.signals] == [702, 701]
    assert session_kernel.identities == {703: (703, 7003, 703, 703)}
    assert not session_kernel.descriptors


@pytest.mark.parametrize(
    "leader",
    [
        (701, 9999, 701, 701),
        (701, 7001, 799, 701),
        (701, 7001, 701, 799),
    ],
)
def test_wrong_leader_generation_or_session_signals_nothing(session_kernel, leader):
    session_kernel.identities[701] = leader
    with pytest.raises(OSError, match="identity changed"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals


def test_wrong_saved_creation_identity_signals_nothing(session_kernel):
    with pytest.raises(OSError, match="identity changed"):
        closure.close_exact_receiver(701, "6999")
    assert not session_kernel.signals


def test_orphan_session_refuses_without_signaling_numeric_sid_members(session_kernel):
    del session_kernel.identities[701]
    with pytest.raises(OSError, match="leader is absent"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals
    assert 702 in session_kernel.identities


def test_older_orphan_member_is_ambiguous_and_signals_nothing(session_kernel):
    del session_kernel.identities[701]
    session_kernel.identities[702] = (702, 6999, 799, 701)
    with pytest.raises(OSError, match="leader is absent"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals


@pytest.mark.parametrize("changed", [(702, 9999, 799, 701), (702, 7002, 799, 999)])
def test_member_reuse_or_session_change_during_pidfd_open_refuses_without_signal(
    session_kernel,
    changed,
):
    session_kernel.on_open = lambda pid: (
        session_kernel.identities.update({702: changed}) if pid == 702 else None
    )
    with pytest.raises(OSError, match="exact receiver session member"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals
    assert not session_kernel.descriptors


def test_reused_leader_before_orphan_signal_refuses_without_signal(session_kernel):
    del session_kernel.identities[701]
    session_kernel.on_scan = lambda _count: session_kernel.identities.update(
        {
            701: (701, 9999, 701, 701),
        }
    )
    with pytest.raises(OSError, match="identity changed"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals


def test_term_ignoring_descendant_receives_kill_before_closure(session_kernel):
    session_kernel.ignore_term.add(702)
    assert closure.close_exact_receiver(701, "7001")["verified_closed"] is True
    assert ((702, 7002, 799, 701), 15) in session_kernel.signals
    assert ((702, 7002, 799, 701), 9) in session_kernel.signals
    assert all(identity[0] != 703 for identity, _ in session_kernel.signals)


def test_descendant_born_during_shutdown_is_discovered_and_drained(session_kernel):
    def spawn(pid, _signum):
        if pid == 702:
            session_kernel.identities[704] = (704, 7004, 799, 701)

    session_kernel.on_signal = spawn
    assert closure.close_exact_receiver(701, "7001")["verified_closed"] is True
    assert [identity[0] for identity, _ in session_kernel.signals] == [702, 704, 701]


def test_leader_loss_with_new_members_refuses_further_signals(session_kernel):
    def lose_leader(_pid, _signum):
        session_kernel.identities.pop(701, None)
        session_kernel.identities[704] = (704, 9004, 799, 701)

    session_kernel.on_signal = lose_leader
    with pytest.raises(OSError, match="leader is absent"):
        closure.close_exact_receiver(701, "7001")
    assert [identity[0] for identity, _ in session_kernel.signals] == [702]


def test_descendant_appearing_after_first_empty_scan_prevents_early_proof(session_kernel):
    del session_kernel.identities[701]
    del session_kernel.identities[702]

    def appear(count):
        if count == 2:
            session_kernel.identities[704] = (704, 7004, 799, 701)

    session_kernel.on_scan = appear
    with pytest.raises(OSError, match="leader is absent"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals


def test_unkillable_member_refuses_closure_after_bounded_escalation(session_kernel):
    session_kernel.ignore_all.add(702)
    with pytest.raises(OSError, match="still has live members"):
        closure.close_exact_receiver(701, "7001")
    assert session_kernel.ticks <= 6
    assert any(signum == 9 for _, signum in session_kernel.signals)
    assert 702 in session_kernel.identities


def test_other_platform_refuses_before_any_signal(session_kernel, monkeypatch):
    monkeypatch.setattr(closure, "sys", SimpleNamespace(platform="win32"))
    with pytest.raises(OSError, match="unavailable on this platform"):
        closure.close_exact_receiver(701, "7001")
    assert not session_kernel.signals


_LEADER_PROGRAM = """
import os, signal, subprocess, sys, threading, time
mode = sys.argv[1]
child_code = "import signal,time; "
if mode == "ignore_term":
    child_code += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
child_code += "print('ready', flush=True); time.sleep(60)"
child = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.PIPE, text=True)
assert child.stdout.readline().strip() == "ready"
if mode != "orphan":
    threading.Thread(target=child.wait, daemon=True).start()
def stop(_signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child.wait()
    os._exit(0)
signal.signal(signal.SIGTERM, stop)
print(child.pid, flush=True)
sys.stdin.readline()
if mode == "orphan":
    os._exit(0)
time.sleep(60)
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="real Linux pidfd sessions")
@pytest.mark.parametrize("mode", ["descendant", "ignore_term", "orphan"])
@pytest.mark.timeout(20)
def test_real_receiver_session_drains_descendant_and_preserves_unrelated_process(mode, monkeypatch):
    if not LinuxPrivateProcessContainment.available():
        pytest.skip("pidfd closure unavailable")
    # Own reaping in the test, including the deliberate orphan case; production
    # recovery relies on the host's normal orphan reaper after parent loss.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    leader = unrelated = None
    reaper = None
    child_identity = leader_identity = unrelated_identity = None
    signals = []
    original_signal = LinuxPrivateProcessContainment._signal_identity

    def observed_signal(identity, signum):
        signals.append((identity, signum))
        return original_signal(identity, signum)

    monkeypatch.setattr(
        LinuxPrivateProcessContainment, "_signal_identity", staticmethod(observed_signal)
    )
    try:
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        unrelated_identity = LinuxPrivateProcessContainment.process_identity(unrelated.pid)
        leader = subprocess.Popen(
            [sys.executable, "-c", _LEADER_PROGRAM, mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        assert select.select([leader.stdout], [], [], 5)[0], "receiver did not publish its child"
        child_pid = int(leader.stdout.readline())
        leader_identity = LinuxPrivateProcessContainment.process_identity(leader.pid)
        child_identity = LinuxPrivateProcessContainment.process_identity(child_pid)
        with pytest.raises(OSError, match="identity changed"):
            closure.close_exact_receiver(leader.pid, str(leader_identity[1] + 1))
        assert not signals
        assert LinuxPrivateProcessContainment.process_identity(leader.pid) == leader_identity
        assert LinuxPrivateProcessContainment.process_identity(child_pid) == child_identity
        leader.stdin.write("go\n")
        leader.stdin.flush()
        if mode == "orphan":
            leader.wait(timeout=5)
            reaper = threading.Thread(target=lambda: os.waitpid(child_pid, 0), daemon=True)
        else:
            reaper = threading.Thread(target=leader.wait, daemon=True)
        reaper.start()
        if mode == "orphan":
            with pytest.raises(OSError, match="leader is absent"):
                closure.close_exact_receiver(leader.pid, str(leader_identity[1]))
            assert not signals
            assert LinuxPrivateProcessContainment.process_identity(child_pid) == child_identity
            assert unrelated.poll() is None
            return
        proof = closure.close_exact_receiver(leader.pid, str(leader_identity[1]))
        reaper.join(timeout=5)
        assert not reaper.is_alive()
        assert proof["verified_closed"] is True and proof["session_member_count"] == 0
        with pytest.raises(ProcessLookupError):
            LinuxPrivateProcessContainment.process_identity(child_pid)
        assert LinuxPrivateProcessContainment.process_identity(unrelated.pid) == unrelated_identity
        assert unrelated.poll() is None
        if mode == "ignore_term":
            assert (child_identity, signal.SIGKILL) in signals
        if mode == "orphan":
            assert all(identity[0] != leader.pid for identity, _ in signals)
    finally:
        for identity in (child_identity, leader_identity, unrelated_identity):
            if identity is not None:
                original_signal(identity, signal.SIGKILL)
        if leader is not None:
            leader.wait(timeout=5)
        if unrelated is not None:
            unrelated.wait(timeout=5)
        if reaper is not None:
            reaper.join(timeout=5)
        libc.prctl(36, previous.value, 0, 0, 0)
