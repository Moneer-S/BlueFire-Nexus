from __future__ import annotations

import ctypes
import subprocess
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_clock as clock
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
    "field,value,site",
    [
        ("pid", 72, "peer_pid_mismatch"),
        ("parent_pid", 69, "peer_parent_mismatch"),
        ("uid", 501, "peer_observed_ids_mismatch"),
        ("real_uid", 0, "peer_observed_ids_mismatch"),
        ("saved_uid", 0, "peer_observed_ids_mismatch"),
        ("gid", 21, "peer_observed_ids_mismatch"),
        ("saved_gid", 0, "peer_observed_ids_mismatch"),
        ("flags", 0, "peer_status_flags_missing"),
        ("flags", 0x12, "peer_status_flags_invalid"),
        ("flags", 0x14, "peer_status_flags_invalid"),
        ("status", 5, "peer_status_invalid"),
        ("start_seconds", 101, "peer_start_mismatch"),
        ("start_microseconds", 1_000_000, "peer_start_invalid"),
    ],
)
def test_changed_known_child_is_refused(child, field, value, site):
    process, facts, ids, _ = child
    setattr(facts, field, value)
    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer.observe_owned_child(process, expected_ids=ids, expected_start=(100, 123))
    assert caught.value._safe_startup_observation_site == site
    assert str(caught.value) == "Original Darwin child consistency is unavailable."


@pytest.mark.parametrize("when", [0, 1])
def test_child_exit_at_either_observation_is_refused(child, monkeypatch, when):
    process, _facts, ids, _ = child
    states = iter([when == 0, True])
    monkeypatch.setattr(runner_client, "_darwin_child_exited_without_reap", lambda _: next(states))
    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer.observe_owned_child(process, expected_ids=ids)
    assert caught.value._safe_startup_observation_site == (
        "peer_child_exited_before_query" if when == 0 else "peer_child_exited_after_query"
    )


def test_unavailable_child_ownership_never_becomes_adoption(child, monkeypatch):
    process, _facts, ids, _ = child

    def absent(_):
        raise ChildProcessError("Not our original child")

    monkeypatch.setattr(runner_client, "_darwin_child_exited_without_reap", absent)
    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer.observe_owned_child(process, expected_ids=ids)
    assert caught.value._safe_startup_observation_site == "unknown"
    assert "Not our original child" not in str(caught.value)


@pytest.mark.parametrize(
    "change,site",
    [
        ("reaped", "peer_process_already_reaped"),
        ("wrong_type", "peer_process_type_invalid"),
        ("bool_uid", "peer_identity_value_invalid"),
        ("groups", "peer_identity_keys_invalid"),
        ("split_uid", "peer_uid_mismatch"),
        ("root", "peer_real_uid_not_root"),
    ],
)
def test_nonowned_or_ambiguous_input_refused(child, monkeypatch, change, site):
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
    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer.observe_owned_child(process, expected_ids=ids)
    assert caught.value._safe_startup_observation_site == site


def test_untagged_contract_error_is_normalized_without_trusting_string_tag(child):
    process, _facts, ids, _ = child

    class ForgedIds(dict):
        def __iter__(self):
            error = MacOSFileAccessContractError("private raw detail")
            error._safe_startup_observation_site = "peer_uid_mismatch"
            raise error

    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer.observe_owned_child(process, expected_ids=ForgedIds(ids))

    assert str(caught.value) == "Original Darwin child consistency is unavailable."
    assert not hasattr(caught.value, "_safe_startup_observation_site")
    assert "private raw detail" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_runtime_gate_is_platform_and_layout_specific(monkeypatch):
    monkeypatch.setattr(clock.sys, "platform", "darwin")
    monkeypatch.setattr(
        clock.os, "uname", lambda: SimpleNamespace(machine="arm64", release="25.1.0"), raising=False
    )
    assert peer._supported_runtime()
    monkeypatch.setattr(
        clock.os, "uname", lambda: SimpleNamespace(machine="x86_64", release="25.1.0")
    )
    assert not peer._supported_runtime()
    monkeypatch.setattr(
        clock.os, "uname", lambda: SimpleNamespace(machine="arm64", release="24.1.0")
    )
    assert not peer._supported_runtime()


class _Call:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


def test_clock_uses_explicit_shared_integer_conversion(monkeypatch):
    monkeypatch.setattr(clock, "_supported_runtime", lambda: True)

    def timebase(pointer):
        pointer._obj.numer, pointer._obj.denom = 125, 3
        return 0

    library = SimpleNamespace(
        mach_absolute_time=_Call(lambda: 10), mach_timebase_info=_Call(timebase)
    )
    monkeypatch.setattr(clock.ctypes, "CDLL", lambda *a, **k: library)
    assert clock.darwin_clock_ns() == 416
    assert peer.MONOTONIC_CLOCK == "darwin-mach-absolute-ns"
    assert peer.darwin_clock_ns is clock.darwin_clock_ns


@pytest.mark.parametrize("returned", [0, 135, 137, -1])
def test_public_process_query_requires_full_exact_layout(monkeypatch, returned):
    query = _Call(lambda *_: returned)
    monkeypatch.setattr(peer.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(proc_pidinfo=query))
    with pytest.raises(MacOSFileAccessContractError) as caught:
        peer._query_bsd(71)
    assert caught.value._safe_startup_observation_site == "peer_bsd_query_failed"
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
    monkeypatch.setattr(clock, "_supported_runtime", lambda: True)

    def timebase(pointer):
        pointer._obj.numer, pointer._obj.denom = numer, denom
        return status

    library = SimpleNamespace(
        mach_absolute_time=_Call(lambda: ticks), mach_timebase_info=_Call(timebase)
    )
    monkeypatch.setattr(clock.ctypes, "CDLL", lambda *a, **k: library)
    with pytest.raises(MacOSFileAccessContractError):
        clock.darwin_clock_ns()
