"""Strictly fake process/Job/handle exchanges; no subprocess or native calls."""

from __future__ import annotations

import struct
import threading
from datetime import datetime, timedelta

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as module
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_file_access_peer import WindowsPeerGeneration
from tests_platform.test_windows_file_access_native_wire import NOW, envelopes, fixture, reseal


class Handle(int):
    def __new__(cls, value=4001):
        result = int.__new__(cls, value)
        result.closed = False
        result.calls = 0
        result.fail = False
        return result

    def Close(self):
        self.calls += 1
        if self.closed:
            return
        self.closed = True
        if self.fail:
            raise OSError("synthetic close ambiguity")


class Pipe:
    def __init__(self, data=b"", eof=None):
        self.data, self.eof = data, eof
        self.offset = 0
        self.closed = False
        self.writes = []
        self.fail_close = False

    def read(self, count):
        result = self.data[self.offset : self.offset + count]
        self.offset += len(result)
        if not result and self.eof is not None:
            self.eof()
        return result

    def write(self, data):
        assert not self.closed
        self.writes.append(bytes(data))
        return len(data)

    def flush(self):
        pass

    def close(self):
        if self.fail_close:
            self.fail_close = False
            raise OSError("synthetic retryable pipe close")
        self.closed = True


def framed(raw):
    return struct.pack("<I", len(raw)) + raw


class Process:
    pid = 4242

    def __init__(self, ready, terminal, code=0):
        self._handle = Handle()
        self.returncode = None
        self.code = code
        self.stdin = Pipe()
        self.stdout = Pipe(framed(ready) + framed(terminal), self.exit)
        self.stderr = Pipe()
        self.kills = self.waits = 0
        self.resumed = False

    def exit(self):
        if self.returncode is None:
            self.returncode = self.code

    def poll(self):
        return self.returncode

    def kill(self):
        assert not self._handle.closed
        self.kills += 1
        self.returncode = 1

    def wait(self, timeout):
        self.waits += 1
        assert self.returncode is not None
        return self.returncode


class Containment:
    def __init__(self):
        self.calls = []
        self.assignment_failure = self.resume_failure = False
        self.drain_failure = self.start_failure = False
        self.adoption_failure = self.finish_failure = False

    def adopt_retained_job(self, job, process):
        self.calls.append("adopt")
        if (
            self.adoption_failure
            or type(process.pid) is not int
            or not 0 < process.pid <= 0xFFFFFFFF
        ):
            raise OSError("synthetic ownership collision")

    def assign_retained(self, job, process):
        self.calls.append("assign")
        if self.assignment_failure or process._handle.closed:
            raise OSError("synthetic assignment failure")

    def resume_retained(self, process, job, generation):
        self.calls.append("resume")
        process.resumed = True
        if self.resume_failure:
            raise OSError("synthetic temporary-handle close failure")

    def drain_retained(self, process, job):
        self.calls.append("drain")
        if process.resumed:
            process.returncode = process.returncode if process.returncode is not None else 1
        return not self.drain_failure

    def finish_retained(self, process, job):
        self.calls.append("finish")
        return not self.finish_failure

    def close_retained_start_handles(self, process):
        self.calls.append("start-close")
        return not self.start_failure


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(module, "_utc", lambda: NOW)
    monkeypatch.setattr(module, "_monotonic", lambda: 100.0)
    monkeypatch.setattr(module, "_JOIN_SECONDS", 0.02)
    calls = []

    def capture(handle, job, *, expected_pid):
        calls.append("capture")
        assert type(handle) is int and handle == 4001 and job == 5001 and expected_pid == 4242
        return WindowsPeerGeneration(4242, 123456)

    def require(handle, job, *, expected):
        calls.append("require")
        assert handle == 4001 and job == 5001 and expected == WindowsPeerGeneration(4242, 123456)

    monkeypatch.setattr(module.child, "capture_retained_child", capture)
    monkeypatch.setattr(module.child, "require_retained_child", require)
    context, expected = fixture()
    original = wire.validate_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_packet(
        original, challenge="f" * 64, clock=NOW, monotonic_now=100, original_monotonic_deadline=104
    )
    retained = wire.validate_retained_packet(original, packet._raw)
    ready, terminal = envelopes(retained)
    return original, packet, ready, terminal, calls


def run(
    setup,
    *,
    process=None,
    containment=None,
    revalidate=None,
    producer=None,
    cancellation=None,
    evidence_sink=None,
):
    original, packet, ready, terminal, _ = setup
    process = process or Process(canonical_json_bytes(ready), canonical_json_bytes(terminal))
    containment = containment or Containment()
    buffers = []
    admissions = []

    def admit():
        admissions.append(True)
        if revalidate is not None:
            revalidate()

    def begin(prefix):
        if producer is not None:
            result = producer(prefix)
        else:
            result = bytearray(framed(prefix + b"\x01\0A\0"))
        buffers.append(result)
        return result

    outcome = module.supervise_suspended(
        process,
        owned_job=5001,
        containment=containment,
        prepared_packet=packet,
        original_reservation=original,
        revalidate_original=admit,
        begin_producer=begin,
        cancellation_event=cancellation or threading.Event(),
        evidence_sink=evidence_sink or (lambda stage, data, code, clock: None),
    )
    return outcome, process, containment, admissions, buffers


def test_owned_exchange_validates_actual_exit_and_closes_every_transferred_resource(setup):
    outcome, process, containment, admissions, buffers = run(setup)
    assert outcome.projection.outcome == "allowed" and not outcome.settled
    assert outcome.cleanup == "verified" and outcome.cleanup_owner is None
    assert outcome.projection.owned_job_cleanup == "unverified"
    assert len(admissions) == 3 and len(buffers) == 1 and not any(buffers[0])
    assert containment.calls == ["adopt", "assign", "resume", "drain", "finish", "start-close"]
    assert setup[4] == ["capture", "require", "require", "require", "require"]
    assert process._handle.closed and process._handle.calls == 1
    assert all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))
    assert len(process.stdin.writes) == 2


def test_received_private_begin_is_erased_before_terminal_read(setup):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    private, checked = [], []
    read = process.stdout.read

    def producer(prefix):
        data = bytearray(framed(prefix + b"\x01\0A\0"))
        private.append(data)
        return data

    def observe_read(count):
        if len(process.stdin.writes) == 2:
            checked.append(True)
            assert private and not any(private[0])
        return read(count)

    process.stdout.read = observe_read
    result = run(setup, process=process, producer=producer)[0]
    assert checked and result.projection.outcome == "allowed" and result.cleanup == "verified"


def test_admission_change_during_begin_producer_prevents_begin_and_wipes_buffer(setup):
    admission = {"valid": True}
    captured = []

    def revalidate():
        if not admission["valid"]:
            raise RuntimeError("synthetic saved claim changed")

    def producer(prefix):
        admission["valid"] = False
        value = bytearray(framed(prefix + b"\x01\0A\0"))
        captured.append(value)
        return value

    result, process, _, admissions, buffers = run(setup, revalidate=revalidate, producer=producer)
    assert result.issue == "admission_refused" and result.dispatch == "not_started"
    assert result.projection is None and result.cleanup == "verified"
    assert len(admissions) == 3 and len(buffers) == 1 and buffers[0] is captured[0]
    assert not any(captured[0])
    assert len(process.stdin.writes) == 1


@pytest.mark.parametrize(
    "outcome,code", [("data_access_denied", 0), ("unknown", 4), ("allowed", 4)]
)
def test_denied_unknown_and_wrong_actual_exit_never_settle(setup, outcome, code):
    original, packet, _, _, _ = setup
    retained = wire.validate_retained_packet(original, packet._raw)
    ready, terminal = envelopes(retained, outcome)
    process = Process(canonical_json_bytes(ready), canonical_json_bytes(terminal), code)
    result = run(setup, process=process)[0]
    assert not result.settled and result.cleanup == "verified"
    if outcome == "allowed":
        assert result.projection is None and result.issue == "worker_failed"
    else:
        assert result.projection.outcome == outcome
        assert result.projection.observation_complete is (outcome == "data_access_denied")


def test_bad_ready_prevents_second_admission_and_begin_producer(setup):
    _, _, ready, terminal, _ = setup
    ready["readiness_scope"] = "authenticated"
    process = Process(canonical_json_bytes(ready), canonical_json_bytes(terminal))
    result, process, _, admissions, buffers = run(setup, process=process)
    assert result.projection is None and len(admissions) == 1 and buffers == []
    assert len(process.stdin.writes) == 1 and result.cleanup == "verified"


def test_cancellation_inside_second_admission_prevents_producer_and_begin_write(setup):
    cancellation = threading.Event()
    count = []

    def revalidate():
        count.append(True)
        if len(count) == 2:
            cancellation.set()

    result, process, _, _, buffers = run(setup, revalidate=revalidate, cancellation=cancellation)
    assert buffers == [] and len(process.stdin.writes) == 1
    assert result.issue == "cancelled" and result.projection is None


def test_identity_drift_after_ready_prevents_begin(setup, monkeypatch):
    def refused(*args, **kwargs):
        raise RuntimeError("synthetic drift")

    monkeypatch.setattr(module.child, "require_retained_child", refused)
    result, process, _, admissions, buffers = run(setup)
    assert len(admissions) == 1 and buffers == [] and len(process.stdin.writes) == 1
    assert result.projection is None


@pytest.mark.parametrize("fault", ["prefix", "length", "units", "immutable"])
def test_invalid_begin_is_never_written_and_owned_mutable_buffer_is_erased(setup, fault):
    captured = []

    def producer(prefix):
        data = bytearray(framed(prefix + b"\x01\0A\0"))
        if fault == "prefix":
            data[4] ^= 1
        elif fault == "length":
            data[0] ^= 1
        elif fault == "units":
            data[128:130] = b"\0\0"
        captured.append(data)
        return bytes(data) if fault == "immutable" else data

    result, process, _, _, _ = run(setup, producer=producer)
    assert len(process.stdin.writes) == 1 and result.projection is None
    if fault != "immutable":
        assert not any(captured[0])


def test_initial_assignment_failure_kills_suspended_parent_without_resume(setup):
    containment = Containment()
    containment.assignment_failure = True
    result, process, _, admissions, buffers = run(setup, containment=containment)
    assert not process.resumed and process.kills == 1 and process.waits >= 1
    assert containment.calls == ["adopt", "assign", "drain", "finish", "start-close"]
    assert admissions == buffers == [] and result.cleanup == "verified"


def test_blocked_assignment_retains_resources_until_cleanup_only_retry(setup):
    cancellation, release = threading.Event(), threading.Event()
    assigned = threading.Event()
    worker_threads = []
    containment = Containment()
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    owner = None

    def blocked_assignment(job, assigned_process):
        containment.calls.append("assign")
        worker_threads.append(threading.current_thread())
        assigned.set()
        cancellation.set()
        release.wait()

    containment.assign_retained = blocked_assignment
    try:
        result, process, containment, admissions, buffers = run(
            setup,
            process=process,
            containment=containment,
            cancellation=cancellation,
        )
        owner = result.cleanup_owner
        assert assigned.is_set() and owner is not None
        assert result.cleanup == "unknown" and not process._handle.closed
        assert process._handle.calls == 0 and not process.resumed
        assert not any(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))
        assert "finish" not in containment.calls
        assert process.stdin.writes == [] and admissions == buffers == []
        assert owner.exchange is not None and owner.exchange.is_alive()
    finally:
        release.set()
        for thread in worker_threads:
            thread.join(timeout=1)
        if owner is not None:
            if owner.exchange is not None:
                owner.exchange.join(timeout=1)
            if owner.errors is not None:
                owner.errors.join(timeout=1)
            owner.retry_cleanup()

    assert owner is not None and owner.retry_cleanup()
    assert all(not thread.is_alive() for thread in worker_threads)
    assert process._handle.closed and process._handle.calls == 1
    assert all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))
    assert containment.calls.count("assign") == 1 and "resume" not in containment.calls
    assert "finish" in containment.calls
    assert process.stdin.writes == [] and admissions == buffers == []


def test_post_resume_temporary_handle_failure_prevents_admission_and_begin(setup):
    containment = Containment()
    containment.resume_failure = True
    result, process, _, admissions, buffers = run(setup, containment=containment)
    assert process.resumed and admissions == buffers == []
    assert len(process.stdin.writes) == 0 and result.projection is None
    assert "start-close" in containment.calls


@pytest.mark.parametrize("stage", ["drain", "finish"])
def test_failed_job_drain_or_close_retains_same_owner_for_cleanup_only_retry(setup, stage):
    containment = Containment()
    setattr(containment, stage + "_failure", True)
    result, process, _, admissions, buffers = run(setup, containment=containment)
    owner = result.cleanup_owner
    assert result.cleanup == "unknown" and owner is not None and not process._handle.closed
    assert len(admissions) == 3 and len(buffers) == 1
    setattr(containment, stage + "_failure", False)
    assert owner.retry_cleanup()
    assert len(admissions) == 3 and len(buffers) == 1 and process._handle.closed
    assert containment.calls.count("assign") == containment.calls.count("resume") == 1


def test_failed_pipe_or_start_handle_closure_retains_retry_ownership(setup):
    containment = Containment()
    containment.start_failure = True
    result, process, _, admissions, buffers = run(setup, containment=containment)
    owner = result.cleanup_owner
    assert owner is not None and not process._handle.closed
    containment.start_failure = False
    process.stdout.fail_close = True
    assert not owner.retry_cleanup() and not process._handle.closed
    assert owner.retry_cleanup() and process._handle.closed
    assert len(admissions) == 3 and len(buffers) == 1


def test_throwing_handle_close_never_becomes_verified_from_later_noop(setup):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    process._handle.fail = True
    result = run(setup, process=process)[0]
    owner = result.cleanup_owner
    assert owner is not None and process._handle.closed and process._handle.calls == 1
    assert not owner.retry_cleanup() and process._handle.calls == 1


@pytest.mark.parametrize(
    "state", ["closed", "detached", "zero", "pseudo", "max_pseudo", "large_pid"]
)
def test_initially_unusable_handle_refuses_admission_and_remains_unknown(setup, state):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    handle = process._handle
    if state == "closed":
        handle.closed = True
    elif state == "detached":
        process._handle = None
    elif state == "zero":
        process._handle = Handle(0)
    elif state == "max_pseudo":
        process._handle = Handle((1 << (struct.calcsize("P") * 8)) - 1)
    elif state == "large_pid":
        process.pid = 0x100000000
    else:
        process._handle = Handle(-1)
    interactions = []

    def forbidden(*args, **kwargs):
        interactions.append(True)
        raise AssertionError("initially unusable handle must never be polled")

    process.poll = process.kill = process.wait = forbidden
    result, process, containment, admissions, buffers = run(setup, process=process)
    assert not process.resumed and containment.calls == (
        ["adopt"] if state == "large_pid" else ["adopt", "drain"]
    )
    assert admissions == buffers == [] and interactions == []
    assert result.cleanup_owner is not None and result.cleanup == "unknown"
    assert handle.calls == 0 and process.kills == process.waits == 0


def test_cancellation_before_start_still_adopts_and_drains_owned_job(setup):
    cancellation = threading.Event()
    cancellation.set()
    result, process, containment, admissions, buffers = run(setup, cancellation=cancellation)
    assert containment.calls == ["adopt", "drain", "finish", "start-close"]
    assert admissions == buffers == [] and not process.resumed and process.kills == 1
    assert result.issue == "cancelled" and result.cleanup == "verified"


def test_ownership_collision_never_drains_another_recorded_job(setup):
    containment = Containment()
    containment.adoption_failure = True
    result, process, _, admissions, buffers = run(setup, containment=containment)
    assert containment.calls == ["adopt"] and admissions == buffers == []
    assert not process.resumed and process.kills == 1 and not process._handle.closed
    assert result.cleanup_owner is not None and result.cleanup == "unknown"
    assert not result.cleanup_owner.retry_cleanup() and containment.calls == ["adopt"]


def test_failed_parent_stop_never_skips_owned_job_drain(setup):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    containment = Containment()
    containment.assignment_failure = True

    def fail_kill():
        raise OSError("synthetic parent-stop failure")

    process.kill = fail_kill
    result = run(setup, process=process, containment=containment)[0]
    assert containment.calls == ["adopt", "assign", "drain"]
    assert result.cleanup_owner is not None and not process._handle.closed
    process.kill = lambda: setattr(process, "returncode", 1)
    assert result.cleanup_owner.retry_cleanup()
    assert containment.calls[-2:] == ["finish", "start-close"]


@pytest.mark.parametrize("rollback", [False, True])
def test_original_deadline_or_wall_rollback_inside_admission_prevents_write(
    setup, monkeypatch, rollback
):
    def expired():
        if rollback:
            monkeypatch.setattr(module, "_utc", lambda: NOW - timedelta(seconds=2))
        else:
            monkeypatch.setattr(module, "_monotonic", lambda: 104.0)

    result, process, _, admissions, buffers = run(setup, revalidate=expired)
    assert len(admissions) == 1 and buffers == [] and process.stdin.writes == []
    assert result.issue == "deadline" and result.projection is None


@pytest.mark.parametrize("fault", ["extra_frame", "truncated", "stderr", "stderr_overflow"])
def test_extra_truncated_output_or_stderr_never_projects_success(setup, fault):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    if fault == "extra_frame":
        process.stdout.data += framed(b"{}")
    elif fault == "truncated":
        process.stdout.data = process.stdout.data[:-1]
    else:
        process.stderr.data = b"synthetic" if fault == "stderr" else b"x" * 1025
    result = run(setup, process=process)[0]
    assert result.projection is None and not result.settled
    assert result.cleanup == "verified"


def test_resealed_different_original_packet_is_not_substituted_for_trusted_reservation(setup):
    context, expected = fixture()
    context["manifest"]["approval"]["approved_by"] = "different-synthetic-reviewer"
    reseal(context)
    different = wire.validate_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_packet(
        different, challenge="f" * 64, clock=NOW, monotonic_now=100, original_monotonic_deadline=104
    )
    ready, terminal = envelopes(wire.validate_retained_packet(different, packet._raw))
    result, process, containment, admissions, buffers = run(
        (setup[0], packet, ready, terminal, setup[4])
    )
    assert containment.calls == ["adopt", "drain", "finish", "start-close"]
    assert not process.resumed and admissions == buffers == [] and process.stdin.writes == []
    assert result.projection is None and result.issue == "binding_refused"


def test_aggregate_stdout_includes_both_frame_prefixes(setup):
    context, expected = fixture()
    maximum = len(canonical_json_bytes(setup[2])) + len(canonical_json_bytes(setup[3])) + 7
    context["manifest"]["limits"]["max_stdout_bytes"] = maximum
    context["profile"]["policy_digest"] = ""
    profile_digest = content_hash(context["profile"])
    context["profile"]["policy_digest"] = profile_digest
    context["manifest"]["policy_digest"] = profile_digest
    context["manifest"]["params"]["windows_file_read_request"]["host"][
        "profile_digest"
    ] = profile_digest
    expected["host"]["profile_digest"] = profile_digest
    reseal(context)
    original = wire.validate_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_packet(
        original, challenge="f" * 64, clock=NOW, monotonic_now=100, original_monotonic_deadline=104
    )
    ready, terminal = envelopes(wire.validate_retained_packet(original, packet._raw))
    changed = (original, packet, ready, terminal, setup[4])
    result, process, _, _, _ = run(changed)
    assert result.projection is None and result.issue == "output_bound"
    assert process.stdout.offset <= maximum and result.cleanup == "verified"


def test_blocked_producer_returns_unknown_and_stopped_gate_prevents_late_begin(setup):
    cancellation, release = threading.Event(), threading.Event()
    private, prefixes = [], []
    owner = None

    def producer(prefix):
        prefixes.append(prefix)
        data = bytearray(framed(prefix + b"\x01\0A\0"))
        private.append(data)
        cancellation.set()
        release.wait()
        return data

    try:
        result, process, containment, _, _ = run(
            setup, producer=producer, cancellation=cancellation
        )
        owner = result.cleanup_owner
        assert owner is not None and not process._handle.closed
        assert len(process.stdin.writes) == 1
        assert "drain" in containment.calls and "finish" not in containment.calls
    finally:
        release.set()
        if owner is not None:
            owner.exchange.join(timeout=1)
            owner.errors.join(timeout=1)
            owner.retry_cleanup()
    assert owner is not None and owner.retry_cleanup()
    assert len(process.stdin.writes) == 1 and not any(private[0]) and not any(prefixes[0])


@pytest.mark.parametrize("blocked", ["admission", "read"])
def test_blocked_admission_or_pipe_read_retains_handles_and_prevents_late_begin(setup, blocked):
    cancellation, release = threading.Event(), threading.Event()
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    owner = None

    def admission():
        if blocked == "admission":
            cancellation.set()
            release.wait()

    if blocked == "read":
        read = process.stdout.read

        def blocked_read(count):
            cancellation.set()
            release.wait()
            return read(count)

        process.stdout.read = blocked_read
    try:
        result, process, containment, _, buffers = run(
            setup, process=process, revalidate=admission, cancellation=cancellation
        )
        owner = result.cleanup_owner
        assert owner is not None and not process._handle.closed and buffers == []
        assert "drain" in containment.calls and "finish" not in containment.calls
        assert len(process.stdin.writes) == (1 if blocked == "read" else 0)
    finally:
        release.set()
        if owner is not None:
            owner.exchange.join(timeout=1)
            owner.errors.join(timeout=1)
            owner.retry_cleanup()
    assert owner is not None and owner.retry_cleanup()
    assert len(process.stdin.writes) == (1 if blocked == "read" else 0)


def test_blocked_job_drain_retains_owner_without_claiming_finally_verified_cleanup(setup):
    containment = Containment()
    release = threading.Event()
    drain = containment.drain_retained
    owner = None

    def blocked_drain(process, job):
        release.wait()
        return drain(process, job)

    containment.drain_retained = blocked_drain
    try:
        result, process, _, admissions, buffers = run(setup, containment=containment)
        owner = result.cleanup_owner
        assert owner is not None and result.cleanup == "unknown" and not process._handle.closed
        assert "finish" not in containment.calls
        assert len(admissions) == 3 and len(buffers) == 1
    finally:
        release.set()
        if owner is not None:
            owner.closer.join(timeout=1)
    assert owner is not None and owner.retry_cleanup()
    assert process._handle.closed and len(admissions) == 3 and len(buffers) == 1


def _start_supervisor(setup, *, process, cancellation, evidence_sink, producer=None):
    state = {"done": threading.Event()}

    def invoke():
        try:
            state["result"] = run(
                setup,
                process=process,
                cancellation=cancellation,
                evidence_sink=evidence_sink,
                producer=producer,
            )
        except BaseException as error:
            state["error"] = error
        finally:
            state["done"].set()

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    return thread, state


def _join_supervisor(thread, state):
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "error" not in state


def test_public_evidence_sink_receives_exact_ordered_payloads_without_begin_secret(setup):
    _, packet, ready, terminal, _ = setup
    events, private, private_payloads = [], [], []

    def sink(stage, data, code, clock):
        events.append((stage, data, code, clock))

    def producer(prefix):
        value = bytearray(framed(prefix + b"\x01\0A\0"))
        private.append(value)
        private_payloads.append(bytes(value))
        return value

    result, process, _, _, buffers = run(setup, evidence_sink=sink, producer=producer)
    assert result.projection is not None and result.dispatch == "attempted"
    assert [row[0] for row in events] == ["packet", "ready", "terminal"]
    assert [row[1] for row in events] == [
        packet._raw,
        canonical_json_bytes(ready),
        canonical_json_bytes(terminal),
    ]
    assert [row[2] for row in events] == [None, None, 0]
    assert all(isinstance(row[3], datetime) for row in events)
    assert len(private) == len(buffers) == 1 and not any(private[0])
    assert all(row[1] != private_payloads[0] for row in events)
    assert len(process.stdin.writes) == 2


def test_packet_evidence_failure_prevents_public_write_and_begin(setup):
    events, produced = [], []

    def sink(stage, data, code, clock):
        events.append(stage)
        if stage == "packet":
            raise OSError("synthetic packet persistence failure")

    result, process, _, admissions, buffers = run(
        setup, evidence_sink=sink, producer=lambda prefix: produced.append(prefix)
    )
    assert events == ["packet"] and produced == buffers == []
    assert process.stdin.writes == [] and len(admissions) == 1
    assert result.issue == "evidence_refused" and result.dispatch == "not_started"


def test_ready_evidence_failure_allows_only_public_packet_and_prevents_begin(setup):
    events, produced = [], []

    def sink(stage, data, code, clock):
        events.append(stage)
        if stage == "ready":
            raise OSError("synthetic Ready persistence failure")

    result, process, _, admissions, buffers = run(
        setup, evidence_sink=sink, producer=lambda prefix: produced.append(prefix)
    )
    assert events == ["packet", "ready"]
    assert len(process.stdin.writes) == 1 and produced == buffers == []
    assert len(admissions) == 1
    assert result.issue == "evidence_refused" and result.dispatch == "not_started"


def test_terminal_evidence_failure_keeps_dispatch_unknown_after_begin(setup):
    events, private = [], []

    def sink(stage, data, code, clock):
        events.append(stage)
        if stage == "terminal":
            raise OSError("synthetic terminal persistence failure")

    def producer(prefix):
        value = bytearray(framed(prefix + b"\x01\0A\0"))
        private.append(value)
        return value

    result, process, _, _, buffers = run(setup, evidence_sink=sink, producer=producer)
    assert events == ["packet", "ready", "terminal"]
    assert len(process.stdin.writes) == 2 and len(private) == len(buffers) == 1
    assert not any(private[0])
    assert result.issue == "evidence_refused" and result.dispatch == "unknown"
    assert result.projection is None and not result.settled


def test_ready_evidence_callback_cancellation_prevents_begin(setup):
    cancellation, events, produced = threading.Event(), [], []

    def sink(stage, data, code, clock):
        events.append(stage)
        if stage == "ready":
            cancellation.set()

    result, process, _, _, buffers = run(
        setup,
        cancellation=cancellation,
        evidence_sink=sink,
        producer=lambda prefix: produced.append(prefix),
    )
    assert events == ["packet", "ready"]
    assert len(process.stdin.writes) == 1 and produced == buffers == []
    assert result.issue == "cancelled" and result.dispatch == "not_started"


@pytest.mark.parametrize(
    "blocked,expected_writes,expected_stages,expected_dispatch",
    [
        ("packet", 0, ["packet"], "not_started"),
        ("ready", 1, ["packet", "ready"], "not_started"),
        ("terminal", 2, ["packet", "ready", "terminal"], "unknown"),
    ],
)
def test_blocked_evidence_sink_retains_resources_and_cleanup_retry_never_replays(
    setup, blocked, expected_writes, expected_stages, expected_dispatch
):
    cancellation = threading.Event()
    entered, release = threading.Event(), threading.Event()
    events, private, produced = [], [], []
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))

    def sink(stage, data, code, clock):
        events.append(stage)
        if stage == blocked:
            entered.set()
            cancellation.set()
            release.wait(timeout=2)

    def producer(prefix):
        produced.append(True)
        value = bytearray(framed(prefix + b"\x01\0A\0"))
        private.append(value)
        return value

    thread, state = _start_supervisor(
        setup,
        process=process,
        cancellation=cancellation,
        evidence_sink=sink,
        producer=producer,
    )
    owner = None
    try:
        assert entered.wait(timeout=1)
        assert state["done"].wait(timeout=1)
        result, process, containment, _, buffers = state["result"]
        owner = result.cleanup_owner
        assert owner is not None and result.cleanup == "unknown"
        assert result.dispatch == expected_dispatch
        assert len(process.stdin.writes) == expected_writes
        assert events == expected_stages
        assert len(produced) == (1 if blocked == "terminal" else 0)
        assert buffers == private
        assert not process._handle.closed and "finish" not in containment.calls
        assert not process.stdout.closed and not process.stderr.closed
        if blocked != "terminal":
            assert not process.stdin.closed
        assert not owner.retry_cleanup()
        assert events == expected_stages and len(process.stdin.writes) == expected_writes
    finally:
        release.set()
        _join_supervisor(thread, state)
        if owner is None and "result" in state:
            owner = state["result"][0].cleanup_owner
        if owner is not None:
            for worker in (owner.exchange, owner.errors, owner.closer):
                if worker is not None:
                    worker.join(timeout=2)
            owner.retry_cleanup()

    assert owner is not None and owner.retry_cleanup()
    assert events == expected_stages and len(process.stdin.writes) == expected_writes
    assert len(produced) == (1 if blocked == "terminal" else 0)
    if private:
        assert not any(private[0])


def test_terminal_evidence_waits_for_stderr_completion_and_actual_exit(setup):
    process = Process(canonical_json_bytes(setup[2]), canonical_json_bytes(setup[3]))
    stderr_entered, stderr_release, exited = threading.Event(), threading.Event(), threading.Event()
    original_read, original_exit = process.stderr.read, process.exit
    events = []

    def blocked_stderr_read(count):
        stderr_entered.set()
        stderr_release.wait(timeout=2)
        return original_read(count)

    def observed_exit():
        original_exit()
        exited.set()

    process.stderr.read = blocked_stderr_read
    process.stdout.eof = observed_exit
    thread, state = _start_supervisor(
        setup,
        process=process,
        cancellation=threading.Event(),
        evidence_sink=lambda stage, data, code, clock: events.append(stage),
    )
    try:
        assert stderr_entered.wait(timeout=1)
        assert exited.wait(timeout=1) and process.returncode == 0
        assert "terminal" not in events
    finally:
        stderr_release.set()
        _join_supervisor(thread, state)
        result, process, _, _, _ = state["result"]
    assert events == ["packet", "ready", "terminal"]
    assert result.projection is not None and result.dispatch == "attempted"


@pytest.mark.parametrize("fault", ["protocol", "exitcode"])
def test_invalid_terminal_protocol_or_exit_never_reaches_evidence_sink(setup, fault):
    process = Process(
        canonical_json_bytes(setup[2]),
        b"{}" if fault == "protocol" else canonical_json_bytes(setup[3]),
        4 if fault == "exitcode" else 0,
    )
    events = []
    result, _, _, _, _ = run(
        setup,
        process=process,
        evidence_sink=lambda stage, data, code, clock: events.append(stage),
    )
    assert events == ["packet", "ready"]
    assert result.projection is None and result.dispatch == "unknown"
    assert result.issue in {"protocol_refused", "worker_failed"}
