"""Worker ordering and channel failure tests without sockets or child processes."""

from __future__ import annotations

import copy
import sys
import time
from types import SimpleNamespace

import pytest

from bluefire import receiver_session_channel as channel
from bluefire import receiver_session_worker as worker
from bluefire.receiver_session_contract import ReceiverSessionError, task_frame
from tests_platform.test_receiver_session import GENERATION, TASK_ID, documents


def worker_double(monkeypatch, tmp_path, *, failure=None, parent_input=b""):
    prepared, _binding, task, _terminal = documents()
    events = []
    frames = []

    class Receiver:
        session_id = "4" * 64
        policy_decisions = []

        def __init__(self, config):
            events.append("listen")
            assert config.authentication_key == b"k" * 32
            assert config.host == "127.0.0.1" and config.content_policy

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            events.append("close")

        def bind_policy_task(self, task_id, digest, size, *, deadline):
            events.append("bind")
            assert (task_id, digest, size) == (TASK_ID, task["sha256"], task["size_bytes"])
            assert deadline == prepared["deadline_ns"] / 1_000_000_000

        def stop(self):
            events.append("stop")

        def serve(self):
            events.append("serve")
            return {
                "schema_version": "bluefire.loopback-receiver-summary.v1",
                "reason": "explicit_stop",
                "connections_handled": 0,
                "challenges_issued": 0,
                "requests_accepted": 0,
                "requests_refused": 0,
            }

    class Thread:
        def __init__(self, *, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

    def arm(parent):
        events.append("arm")
        assert parent == 900
        return failure != "arm"

    def read(_descriptor, *, deadline_ns):
        if not any(frame["kind"] == "ready" for frame in frames):
            events.append("prepare")
            assert events == ["arm", "armed", "prepare"]
            if failure == "prepare_eof":
                raise ReceiverSessionError("channel closed")
            result = copy.deepcopy(prepared)
            if failure == "prepare_expired":
                result["deadline_ns"] = time.monotonic_ns() - 1
            return result
        events.append("task")
        if failure == "bind_eof":
            raise ReceiverSessionError("channel closed")
        binding = frames[-1]["binding"]
        assert deadline_ns == prepared["deadline_ns"]
        return task_frame(
            binding,
            task_id=TASK_ID,
            digest=task["sha256"],
            size=task["size_bytes"],
            review_digest=binding["review_digest"],
            now_ns=time.monotonic_ns(),
        )

    def write(_descriptor, frame):
        events.append(frame["kind"])
        frames.append(frame)

    def enrollment(path, *, require_active):
        events.append("enrollment")
        assert path == tmp_path / "enrollment" and require_active
        return SimpleNamespace(hmac_key=lambda: b"k" * 32)

    monkeypatch.setattr(worker, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        worker,
        "os",
        SimpleNamespace(getpid=lambda: 901, getppid=lambda: 900, read=lambda *_args: parent_input),
    )
    monkeypatch.setitem(
        sys.modules, "bluefire.runner_parent_death", SimpleNamespace(_arm_parent_death=arm)
    )
    monkeypatch.setattr(worker, "worker_generation", lambda: GENERATION)
    monkeypatch.setattr(worker, "read_frame", read)
    monkeypatch.setattr(worker, "write_frame", write)
    monkeypatch.setattr(worker, "managed_product_root", lambda: tmp_path)
    monkeypatch.setattr(worker, "load_local_enrollment", enrollment)
    monkeypatch.setattr(worker, "LoopbackArtifactReceiver", Receiver)
    monkeypatch.setattr(worker, "threading", SimpleNamespace(Thread=Thread))
    monkeypatch.setattr(
        worker,
        "LinuxPrivateProcessContainment",
        SimpleNamespace(process_identity=lambda _pid: (901, 123456)),
    )
    return prepared, events, frames


@pytest.mark.parametrize("parent_input", [b"", b"x"], ids=["parent_eof", "extra_frame"])
def test_worker_arms_before_authority_and_stops_on_eof_or_extra_input(
    monkeypatch, tmp_path, parent_input
):
    prepared, events, frames = worker_double(monkeypatch, tmp_path, parent_input=parent_input)
    assert worker.run(["--parent", "900", "--launch", prepared["launch_id"]]) == 0
    assert events == [
        "arm",
        "armed",
        "prepare",
        "enrollment",
        "listen",
        "ready",
        "task",
        "bind",
        "bound",
        "stop",
        "serve",
        "terminal",
        "close",
    ]
    assert [frame["kind"] for frame in frames] == ["armed", "ready", "bound", "terminal"]
    assert frames[-1]["decision"] is None
    assert frames[-1]["summary"]["requests_accepted"] == 0
    assert b"k" * 32 not in repr(frames).encode()


@pytest.mark.parametrize("failure", ["arm", "prepare_eof", "prepare_expired", "bind_eof"])
def test_worker_refuses_missing_authority_and_closes_any_prepared_listener(
    monkeypatch, tmp_path, failure
):
    prepared, events, frames = worker_double(monkeypatch, tmp_path, failure=failure)
    arguments = ["--parent", "900", "--launch", prepared["launch_id"]]
    if failure == "arm":
        assert worker.run(arguments) == 74
    else:
        with pytest.raises(ReceiverSessionError):
            worker.run(arguments)
    if failure == "bind_eof":
        assert events[-1] == "close"
        assert "bind" not in events and "serve" not in events
    else:
        assert "enrollment" not in events and "listen" not in events
    assert all(frame["kind"] != "terminal" for frame in frames)


def test_channel_consumes_one_frame_and_refuses_truncated_terminal(monkeypatch):
    payload = bytearray(b'{"kind":"one"}\n{"kind":"two"}\n')
    monkeypatch.setattr(channel.select, "select", lambda *_args: ([17], [], []))
    monkeypatch.setattr(
        channel.os, "read", lambda *_args: bytes([payload.pop(0)]) if payload else b""
    )
    assert channel.read_frame(17, deadline_ns=time.monotonic_ns() + 1_000_000_000) == {
        "kind": "one"
    }
    assert payload == b'{"kind":"two"}\n'
    with pytest.raises(ReceiverSessionError, match="incomplete"):
        channel.require_eof(17)
    payload[:] = b'{"kind":'
    with pytest.raises(ReceiverSessionError, match="closed"):
        channel.read_frame(17, deadline_ns=time.monotonic_ns() + 1_000_000_000)


def test_channel_write_is_nonblocking_and_retries_only_within_deadline(monkeypatch):
    events = []
    output = bytearray()
    writes = 0

    def write(_descriptor, payload):
        nonlocal writes
        writes += 1
        if writes == 1:
            raise BlockingIOError()
        output.extend(payload[:2])
        return min(2, len(payload))

    monkeypatch.setattr(
        channel,
        "os",
        SimpleNamespace(set_blocking=lambda *args: events.append(args), write=write),
    )
    monkeypatch.setattr(channel.select, "select", lambda *_args: ([], [17], []))
    channel.write_frame(17, {"kind": "one"})
    assert events == [(17, False)]
    assert bytes(output) == b'{"kind":"one"}\n'
    times = iter([0, 6_000_000_000])
    monkeypatch.setattr(channel.time, "monotonic_ns", lambda: next(times))
    with pytest.raises(ReceiverSessionError, match="expired"):
        channel.write_frame(17, {"kind": "one"})


def test_channel_refuses_missing_nonblocking_capability_before_writing(monkeypatch):
    writes = []
    monkeypatch.setattr(channel, "os", SimpleNamespace(write=lambda *args: writes.append(args)))
    with pytest.raises(ReceiverSessionError, match="nonblocking channel is unavailable"):
        channel.write_frame(17, {"kind": "one"})
    assert writes == []
