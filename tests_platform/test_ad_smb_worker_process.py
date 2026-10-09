"""Fake pipes/processes/jobs only; never launch a native process or invoke SMB."""

import io
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_worker_process as process
from bluefire import ad_smb_worker_wire as wire
from bluefire.ad_smb_contract import AdSmbError
from bluefire.util import canonical_json_bytes
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_worker_wire import packet, ready_row, terminal_row


class Sink(io.BytesIO):
    def close(self):
        if not self.closed:
            self.retained = self.getvalue()
        super().close()


class Child:
    def __init__(self, value, *, stdout=None, stderr=b"", code=0, error=False):
        self.pid = 123
        self.returncode = code
        self.stdin = Sink()
        terminal = terminal_row(value)
        if not error:
            terminal["result"] = {"synthetic_observation": True}
        self.stdout = (
            io.BytesIO(
                bytes(
                    wire.frame(canonical_json_bytes(ready_row(value)), wire.READY_MAX)
                    + wire.frame(canonical_json_bytes(terminal), value.output_limit)
                )
            )
            if stdout is None
            else stdout
        )
        self.stderr = io.BytesIO(stderr)
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        assert timeout == 5
        if self.returncode is None:
            raise RuntimeError("synthetic wait failure")
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = 1


class Jobs:
    def __init__(self, *, cleanup=True, kill_on_close=True):
        assert kill_on_close is True
        self.cleanup = cleanup
        self.calls = []

    def finish(self, child):
        self.calls.append("finish")
        child.returncode = child.returncode if child.returncode is not None else 1
        return self.cleanup

    def terminate(self, child):
        self.calls.append("terminate")
        child.returncode = 1
        if hasattr(child.stdout, "release"):
            child.stdout.release.set()
        return self.cleanup

    def system_directory(self):
        return Path("C:/Windows/System32")

    def create_job(self):
        self.calls.append("create")
        return 42

    def assign(self, job, child):
        assert job == 42
        self.calls.append("assign")

    def resume_suspended(self, child):
        assert "assign" in self.calls
        self.calls.append("resume")

    def close_handle(self, value):
        assert value == 42
        self.calls.append("close")
        return self.cleanup


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr(process, "_utc", lambda: NOW + timedelta(seconds=1))


def supervise(child, value, jobs=None, admit=lambda: None, cancellation=None, credential=None):
    return process._supervise(
        child,
        jobs or Jobs(),
        value,
        credential,
        admit,
        cancellation or threading.Event(),
        started=time.monotonic(),
    )


def test_valid_member_protocol_natural_exit_and_owned_cleanup():
    value, calls = packet(), []
    child, jobs = Child(value), Jobs()
    result = supervise(child, value, jobs, admit=lambda: calls.append("revalidated"))
    assert result.issue is None and result.cleanup == "verified" and result.dispatch == "attempted"
    assert result.terminal["result"]["synthetic_observation"] is True
    assert calls == ["revalidated", "revalidated"] and jobs.calls == ["finish"]
    assert b"BFADBEG1" in child.stdin.retained
    assert all(stream.closed for stream in (child.stdin, child.stdout, child.stderr))


@pytest.mark.parametrize(
    "kind",
    ["bad_ready", "oversized_ready", "extra_output", "stderr", "nonzero", "cleanup", "admission"],
)
def test_failure_never_becomes_success_or_releases_secret(kind):
    value = packet()
    child, jobs = Child(value), Jobs(cleanup=kind != "cleanup")
    calls = []
    if kind == "bad_ready":
        row = ready_row(value)
        row["pid"] = 999
        child.stdout = io.BytesIO(wire.frame(canonical_json_bytes(row), wire.READY_MAX))
    elif kind == "oversized_ready":
        child.stdout = io.BytesIO((wire.READY_MAX + 1).to_bytes(4, "little"))
    elif kind == "extra_output":
        child.stdout = io.BytesIO(child.stdout.getvalue() + b"extra")
    elif kind == "stderr":
        child.stderr = io.BytesIO(b"synthetic-sensitive-details")
    elif kind == "nonzero":
        child.returncode = 2

    def admit():
        calls.append("admit")
        if kind == "admission":
            raise AdSmbError("synthetic-sensitive-details")

    result = supervise(child, value, jobs, admit=admit)
    assert result.terminal is None and result.issue is not None
    assert "synthetic-sensitive" not in repr(result)
    if kind in {"bad_ready", "oversized_ready", "admission"}:
        assert b"BFADBEG1" not in child.stdin.retained
    if kind == "cleanup":
        assert result.cleanup == "unknown"


def test_ready_admission_failure_never_invokes_one_use_resolver():
    value = packet("baseline")
    child = Child(value)
    calls = []

    class Credential:
        def begin(self):
            pytest.fail("credential must not resolve before admission")

    def refuse():
        calls.append("admit")
        if len(calls) == 2:
            raise AdSmbError("changed original reservation")

    result = supervise(child, value, admit=refuse, credential=Credential())
    assert result.dispatch == "not_started" and result.terminal is None
    assert calls == ["admit", "admit"]


@pytest.mark.parametrize("trigger", ["cancel", "deadline"])
def test_blocked_pipe_ends_under_owned_job_and_does_not_extend_deadline(trigger):
    value = packet()
    raw = value.to_dict()
    raw["remaining_ms"] = 10
    value = wire.WorkerPacket(canonical_json_bytes(raw))

    class Blocked(io.BytesIO):
        release = threading.Event()

        def read(self, _size=-1):
            assert self.release.wait(2)
            return b""

    child, jobs, cancel = Child(value, stdout=Blocked(), code=None), Jobs(), threading.Event()
    if trigger == "cancel":
        cancel.set()
    result = supervise(child, value, jobs, cancellation=cancel)
    assert result.issue in {"cancelled", "deadline"}
    assert result.cleanup == "verified" and jobs.calls == ["terminate"]
    assert result.dispatch == "not_started"


def test_expiry_after_private_resolution_prevents_begin_and_wipes_buffer():
    value = packet("baseline")
    child, cancel, buffer = Child(value), threading.Event(), bytearray(b"private-buffer")

    class Credential:
        def begin(self):
            cancel.set()
            return buffer

    result = supervise(child, value, cancellation=cancel, credential=Credential())
    assert result.terminal is None and result.dispatch == "not_started"
    assert buffer == bytearray(len(buffer))
    assert b"private-buffer" not in child.stdin.retained


def launch_fakes(monkeypatch, value, *, failure=None):
    child, jobs, captured = Child(value), Jobs(cleanup=failure != "close"), {}
    monkeypatch.setattr(process.sys, "platform", "win32")
    monkeypatch.setattr(process, "WindowsJobContainment", lambda **kwargs: jobs)
    monkeypatch.setattr(process, "_validated_enrollment_root", lambda root: root)

    @contextmanager
    def storage(*args, **kwargs):
        yield None

    @contextmanager
    def pinned(path, expected):
        assert expected == pin("5")
        yield str(path), ()

    def spawn(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        if failure == "spawn":
            raise OSError("not retained")
        return child

    if failure in {"assign", "resume"}:

        def fail(*args):
            raise OSError("not retained")

        monkeypatch.setattr(jobs, "assign" if failure == "assign" else "resume_suspended", fail)
    monkeypatch.setattr(process, "_PinnedDirectory", storage)
    monkeypatch.setattr(process, "_pinned_launch_file", pinned)
    monkeypatch.setattr(process.subprocess, "Popen", spawn)
    return child, jobs, captured


@pytest.mark.parametrize("failure", [None, "spawn", "assign", "resume", "close"])
def test_fixed_launch_assigns_before_resume_with_clean_env_and_cleanup(monkeypatch, failure):
    value = packet()
    child, jobs, captured = launch_fakes(monkeypatch, value, failure=failure)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-must-not-inherit")
    result = process.run_worker(
        value,
        runner_binary=Path("C:/fixed/runner.exe"),
        runner_digest=pin("5"),
        work_root=Path("C:/fixed/private"),
        credential=None,
        revalidate_original=lambda: None,
        cancellation_event=threading.Event(),
    )
    assert captured["argv"] == ["C:\\fixed\\runner.exe", "ad-smb-worker"]
    assert set(captured["env"]) == {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LC_ALL", "LANG"}
    assert captured["creationflags"] & 4 and captured["close_fds"] is True
    assert captured["stdin"] == process.subprocess.PIPE and captured["shell"] is False
    if failure is None:
        assert jobs.calls[:3] == ["create", "assign", "resume"] and result.terminal is not None
    else:
        assert result.terminal is None and result.issue is not None
    if failure == "close":
        assert result.cleanup == "unknown"
    if failure in {"spawn", "assign"}:
        assert "close" in jobs.calls


def test_platform_refusal_precedes_any_spawn(monkeypatch):
    monkeypatch.setattr(process.sys, "platform", "linux")
    monkeypatch.setattr(
        process.subprocess, "Popen", lambda *_args, **_kw: pytest.fail("no process")
    )
    with pytest.raises(AdSmbError):
        process.run_worker(
            packet(),
            runner_binary=Path("C:/fixed/runner.exe"),
            runner_digest=pin("5"),
            work_root=Path("C:/fixed/private"),
            credential=None,
            revalidate_original=lambda: None,
            cancellation_event=threading.Event(),
        )


def test_delayed_packet_does_not_restart_its_monotonic_interval(monkeypatch):
    value = packet()
    value = wire.WorkerPacket(canonical_json_bytes(value.to_dict()), time.monotonic() - 60)
    monkeypatch.setattr(process.sys, "platform", "win32")
    monkeypatch.setattr(process, "_utc", lambda: NOW - timedelta(seconds=10))
    monkeypatch.setattr(
        process.subprocess,
        "Popen",
        lambda *_args, **_kw: pytest.fail("expired packet must not spawn"),
    )
    result = process.run_worker(
        value,
        runner_binary=Path("C:/fixed/runner.exe"),
        runner_digest=pin("5"),
        work_root=Path("C:/fixed/private"),
        credential=None,
        revalidate_original=lambda: None,
        cancellation_event=threading.Event(),
    )
    assert result.issue == "deadline" and result.dispatch == "not_started"


def test_pipe_close_failure_prevents_verified_cleanup():
    value = packet()
    child = Child(value)

    class FailsClose(Sink):
        def close(self):
            raise OSError("synthetic private pipe failure")

    child.stderr = FailsClose()
    result = supervise(child, value)
    assert result.cleanup == "unknown" and result.terminal is None
    assert "synthetic private" not in repr(result)


@pytest.mark.parametrize("stall", ["admit", "post_ready", "credential"])
def test_stalled_local_callback_is_bounded_and_cleanup_remains_unknown(stall, monkeypatch):
    value = packet("baseline")
    raw = value.to_dict()
    raw["remaining_ms"] = 1000
    value = wire.WorkerPacket(canonical_json_bytes(raw), 100.0)
    child, entered, release = Child(value), threading.Event(), threading.Event()
    secret = bytearray(b"synthetic-private-one-use")
    calls = []
    monkeypatch.setattr(
        process, "time", SimpleNamespace(monotonic=lambda: 200.0 if entered.is_set() else 100.0)
    )

    def admit():
        calls.append("admit")
        if stall == "admit" or (stall == "post_ready" and len(calls) == 2):
            entered.set()
            assert release.wait(3)

    class Credential:
        def begin(self):
            if stall == "credential":
                entered.set()
                assert release.wait(3)
            return secret

    try:
        result = supervise(child, value, admit=admit, credential=Credential())
        assert entered.is_set()
        assert result.cleanup == "unknown" and result.issue == "cleanup_unknown"
        assert result.dispatch == "not_started" and result.terminal is None
    finally:
        release.set()
        deadline = time.monotonic() + 2
        while (
            any(t.name == "ad-worker-pipe" and t.is_alive() for t in threading.enumerate())
            and time.monotonic() < deadline
        ):
            time.sleep(0.005)
        assert not any(t.name == "ad-worker-pipe" and t.is_alive() for t in threading.enumerate())
        delivered = child.stdin.retained if child.stdin.closed else child.stdin.getvalue()
        assert b"synthetic-private-one-use" not in delivered
        if stall == "admit":
            assert delivered == b""
        if stall == "credential":
            assert secret == bytearray(len(secret))
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


@pytest.mark.parametrize("raw", [b"\x01", b"\x04\0\0\0{}", (2**32 - 1).to_bytes(4, "little")])
def test_partial_or_oversized_frame_refuses_without_begin(raw):
    value = packet()
    child = Child(value, stdout=io.BytesIO(raw))
    calls = []
    result = supervise(child, value, admit=lambda: calls.append("admit"))
    assert result.terminal is None and result.dispatch == "not_started"
    assert calls == ["admit"]
    assert b"BFADBEG1" not in child.stdin.retained


def test_stderr_flood_stops_at_one_byte_over_finite_cap():
    value = packet()

    class Counted(io.BytesIO):
        count = 0

        def read(self, size=-1):
            raw = super().read(size)
            self.count += len(raw)
            return raw

    child = Child(value)
    child.stderr = Counted(b"x" * 100000)
    result = supervise(child, value)
    assert result.terminal is None and result.issue in {"output_bound", "unexpected_stderr"}
    assert child.stderr.count <= 65537


def test_deadline_consumed_during_ready_never_admits(monkeypatch):
    value = packet()
    child = Child(value)
    original = process.ready

    def expire(*args):
        original(*args)
        monkeypatch.setattr(process, "_utc", lambda: NOW + timedelta(seconds=31))

    monkeypatch.setattr(process, "ready", expire)
    calls = []
    result = supervise(child, value, admit=lambda: calls.append("admit"))
    assert result.terminal is None and result.dispatch == "not_started"
    assert calls == ["admit"]
    assert b"BFADBEG1" not in child.stdin.retained


@pytest.mark.parametrize(
    "code,error,cleanup",
    [(4, True, True), (0, True, True), (2, True, True), (4, False, True), (4, True, False)],
)
def test_only_exact_native_error_exit_pair_retains_bounded_failure(code, error, cleanup):
    value = packet()
    child = Child(value, code=code, error=error)
    result = supervise(child, value, Jobs(cleanup=cleanup))
    if (code, error, cleanup) == (4, True, True):
        assert result.terminal["result"]["code"] == "native_unavailable"
        assert result.terminal["result"]["possible_effects"] is False
        assert result.issue == "native_error" and result.cleanup == "verified"
    else:
        assert result.terminal is None and result.issue is not None


def test_native_error_retains_true_possible_effects_without_success_claim():
    value = packet()
    row = terminal_row(value)
    row["result"]["possible_effects"] = True
    child = Child(
        value,
        code=4,
        stdout=io.BytesIO(
            wire.frame(canonical_json_bytes(ready_row(value)), wire.READY_MAX)
            + wire.frame(canonical_json_bytes(row), value.output_limit)
        ),
    )
    result = supervise(child, value)
    assert result.issue == "native_error" and result.terminal["result"]["possible_effects"] is True


def test_initial_cancelled_admission_sends_no_public_or_begin():
    value = packet()
    child, cancel = Child(value), threading.Event()

    def admit():
        cancel.set()

    result = supervise(child, value, admit=admit, cancellation=cancel)
    assert result.dispatch == "not_started" and result.terminal is None
    assert child.stdin.retained == b""


def test_native_error_with_stderr_never_retains_terminal():
    value = packet()
    child = Child(value, code=4, error=True, stderr=b"synthetic-private-failure")
    result = supervise(child, value)
    assert result.terminal is None and result.issue == "unexpected_stderr"
    assert "synthetic-private" not in repr(result)
