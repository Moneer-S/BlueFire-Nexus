from __future__ import annotations

import ctypes
import subprocess
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_peer as peer
from bluefire import runner_client
from bluefire.macos_file_access_contract import MacOSFileAccessContractError


@pytest.fixture
def child(monkeypatch):
    process = object.__new__(subprocess.Popen)
    process._child_created = False
    process.pid, process.returncode = 71, None
    facts = peer._BSDInfo()
    facts.pid, facts.parent_pid, facts.flags, facts.status = 71, 70, 0x10, 2
    facts.uid = facts.real_uid = facts.saved_uid = 502
    facts.gid = facts.real_gid = facts.saved_gid = 20
    facts.start_seconds, facts.start_microseconds = 100, 123
    monkeypatch.setattr(peer, "_supported_runtime", lambda: True)
    monkeypatch.setattr(peer.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(peer.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(peer.os, "getpid", lambda: 70)
    monkeypatch.setattr(peer, "_query_bsd", lambda _: facts)
    monkeypatch.setattr(runner_client, "_darwin_child_status_ownership_available", lambda: True)
    observations = []

    def status(pid):
        observations.append(pid)
        return False

    monkeypatch.setattr(runner_client, "_darwin_child_exited_without_reap", status)
    ids = {name: 502 if name.endswith("uid") else 20 for name in peer._IDS}
    return process, facts, ids, observations


def test_known_child_checks_without_reaping(child):
    process, _facts, ids, observations = child
    result = peer.observe_owned_child(process, expected_ids=ids, expected_start=(100, 123))
    assert observations == [71, 71]
    assert process.returncode is None
    assert result.identity_document() == {
        "pid": 71,
        "parent_pid": 70,
        "start_seconds": 100,
        "start_microseconds": 123,
        "ids": ids,
        "scope": "known_child_consistency_only",
    }
    assert not hasattr(result, "authority")


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", 72),
        ("parent_pid", 69),
        ("uid", 501),
        ("real_uid", 0),
        ("saved_uid", 0),
        ("gid", 21),
        ("saved_gid", 0),
        ("flags", 0),
        ("flags", 0x12),
        ("flags", 0x14),
        ("status", 5),
        ("start_seconds", 101),
        ("start_microseconds", 1_000_000),
    ],
)
def test_changed_known_child_is_refused(child, field, value):
    process, facts, ids, _ = child
    setattr(facts, field, value)
    with pytest.raises(MacOSFileAccessContractError):
        peer.observe_owned_child(process, expected_ids=ids, expected_start=(100, 123))


@pytest.mark.parametrize("when", [0, 1])
def test_child_exit_at_either_observation_is_refused(child, monkeypatch, when):
    process, _facts, ids, _ = child
    states = iter([when == 0, True])
    monkeypatch.setattr(runner_client, "_darwin_child_exited_without_reap", lambda _: next(states))
    with pytest.raises(MacOSFileAccessContractError):
        peer.observe_owned_child(process, expected_ids=ids)


def test_unavailable_child_ownership_never_becomes_adoption(child, monkeypatch):
    process, _facts, ids, _ = child

    def absent(_):
        raise ChildProcessError("Not our original child")

    monkeypatch.setattr(runner_client, "_darwin_child_exited_without_reap", absent)
    with pytest.raises(MacOSFileAccessContractError):
        peer.observe_owned_child(process, expected_ids=ids)


@pytest.mark.parametrize(
    "change", ["reaped", "wrong_type", "bool_uid", "groups", "split_uid", "root"]
)
def test_nonowned_or_ambiguous_input_refused(child, monkeypatch, change):
    process, _facts, ids, _ = child
    if change == "reaped":
        process.returncode = 0
    elif change == "wrong_type":
        process = SimpleNamespace(pid=71, returncode=None)
    elif change == "bool_uid":
        ids["real_uid"] = True
    elif change == "groups":
        ids["groups"] = [20]
    elif change == "split_uid":
        ids["saved_uid"] = 503
    else:
        monkeypatch.setattr(peer.os, "getuid", lambda: 501)
    with pytest.raises(MacOSFileAccessContractError):
        peer.observe_owned_child(process, expected_ids=ids)


def test_runtime_gate_is_platform_and_layout_specific(monkeypatch):
    monkeypatch.setattr(peer.sys, "platform", "darwin")
    monkeypatch.setattr(
        peer.os, "uname", lambda: SimpleNamespace(machine="arm64", release="25.1.0"), raising=False
    )
    assert peer._supported_runtime()
    monkeypatch.setattr(
        peer.os, "uname", lambda: SimpleNamespace(machine="x86_64", release="25.1.0")
    )
    assert not peer._supported_runtime()
    monkeypatch.setattr(
        peer.os, "uname", lambda: SimpleNamespace(machine="arm64", release="24.1.0")
    )
    assert not peer._supported_runtime()


class _Call:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


def test_clock_uses_explicit_shared_integer_conversion(monkeypatch):
    monkeypatch.setattr(peer, "_supported_runtime", lambda: True)

    def timebase(pointer):
        pointer._obj.numer, pointer._obj.denom = 125, 3
        return 0

    library = SimpleNamespace(
        mach_absolute_time=_Call(lambda: 10), mach_timebase_info=_Call(timebase)
    )
    monkeypatch.setattr(peer.ctypes, "CDLL", lambda *a, **k: library)
    assert peer.darwin_clock_ns() == 416
    assert peer.MONOTONIC_CLOCK == "darwin-mach-absolute-ns"


@pytest.mark.parametrize("returned", [0, 135, 137, -1])
def test_public_process_query_requires_full_exact_layout(monkeypatch, returned):
    query = _Call(lambda *_: returned)
    monkeypatch.setattr(peer.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(proc_pidinfo=query))
    with pytest.raises(MacOSFileAccessContractError):
        peer._query_bsd(71)
    assert ctypes.sizeof(peer._BSDInfo) == 136


def test_public_process_query_reads_declared_fields(monkeypatch):
    def observe(pid, flavor, argument, pointer, size):
        assert (pid, flavor, argument, size) == (71, 3, 0, 136)
        pointer._obj.pid, pointer._obj.parent_pid = 71, 70
        pointer._obj.start_seconds, pointer._obj.start_microseconds = 100, 123
        return size

    query = _Call(observe)
    monkeypatch.setattr(peer.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(proc_pidinfo=query))
    facts = peer._query_bsd(71)
    assert (facts.pid, facts.parent_pid, facts.start_seconds, facts.start_microseconds) == (
        71,
        70,
        100,
        123,
    )
    expected = {
        "pid": 12,
        "parent_pid": 16,
        "uid": 20,
        "gid": 24,
        "real_uid": 28,
        "real_gid": 32,
        "saved_uid": 36,
        "saved_gid": 40,
        "start_seconds": 120,
        "start_microseconds": 128,
    }
    assert {name: getattr(peer._BSDInfo, name).offset for name in expected} == expected


@pytest.mark.parametrize(
    "numer,denom,ticks,status",
    [(0, 1, 1, 0), (1, 0, 1, 0), (1, 1, 0, 0), (1, 1, 1, 1), (2**32 - 1, 1, 2**64 - 1, 0)],
)
def test_invalid_or_overflowing_clock_is_refused(monkeypatch, numer, denom, ticks, status):
    monkeypatch.setattr(peer, "_supported_runtime", lambda: True)

    def timebase(pointer):
        pointer._obj.numer, pointer._obj.denom = numer, denom
        return status

    library = SimpleNamespace(
        mach_absolute_time=_Call(lambda: ticks), mach_timebase_info=_Call(timebase)
    )
    monkeypatch.setattr(peer.ctypes, "CDLL", lambda *a, **k: library)
    with pytest.raises(MacOSFileAccessContractError):
        peer.darwin_clock_ns()
