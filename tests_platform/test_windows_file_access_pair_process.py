"""Pair supervisor fakes only: no process launch, credential or native API."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as module
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_pair_wire as pair
from tests_platform import test_windows_file_access_process as fake


@pytest.fixture
def setup(monkeypatch):
    original_setup = fake.setup.__wrapped__(monkeypatch)
    original, packet, retained = pair.prepared()
    ready, terminal = pair.envelopes(retained)
    return (original, packet, ready, terminal, original_setup[4]), original_setup


def run(
    setup,
    *,
    process=None,
    containment=None,
    original=None,
    packet=None,
    entry=module.supervise_pair_suspended,
    cancellation=None,
    sink=None,
    admission=None,
    producer=None,
    release_launch_resources=None,
    retain_cleanup_owner=None,
):
    row = setup[0]
    process = process or fake.Process(canonical_json_bytes(row[2]), canonical_json_bytes(row[3]))
    containment = containment or fake.Containment()
    events, buffers, admissions = [], [], []

    def persist(stage, payload, code, clock):
        events.append((stage, payload, code, clock))
        if sink is not None:
            sink(stage, payload, code, clock)

    def revalidate():
        admissions.append(True)
        if admission is not None:
            admission()

    def begin(prefix):
        assert bytes(prefix[:8]) == b"BFWFBEG2"
        value = (
            producer(prefix)
            if producer is not None
            else bytearray(fake.framed(prefix + b"\x01\0A\0"))
        )
        buffers.append(value)
        return value

    arguments = {
        "owned_job": 5001,
        "containment": containment,
        "original_reservation": original or row[0],
        "prepared_packet": packet or row[1],
        "revalidate_original": revalidate,
        "begin_producer": begin,
        "cancellation_event": cancellation or threading.Event(),
        "evidence_sink": persist,
    }
    if release_launch_resources is not None:
        arguments["release_launch_resources"] = release_launch_resources
    if retain_cleanup_owner is not None:
        arguments["retain_cleanup_owner"] = retain_cleanup_owner
    result = entry(process, **arguments)
    return result, process, containment, events, buffers, admissions


def partial(retained):
    ready, terminal = pair.envelopes(retained)
    proof = terminal["result"]
    proof.update(
        outcome="unknown",
        issue="native_failure",
        failed_stage="owner_read",
        resource_pair_rechecked=False,
    )
    proof["owner"].update(
        outcome="unknown",
        issue="native_failure",
        failed_stage="owner_read",
        bytes_read=0,
        observed_sha256=None,
        resource_rechecked=False,
    )
    return ready, terminal


@pytest.mark.parametrize("fault", ["thread_constructor", "thread_start"])
def test_pair_retains_cleanup_owner_before_thread_fault_and_drains_without_begin(
    setup, monkeypatch, fault
):
    class InjectedFault(BaseException):
        pass

    original_thread = threading.Thread
    original_start = threading.Thread.start
    created = []
    retained = []
    process = fake.Process(canonical_json_bytes(setup[0][2]), canonical_json_bytes(setup[0][3]))
    containment = fake.Containment()

    def retain(owner):
        retained.append((owner, containment.calls.copy(), tuple(created)))

    def construct(*args, **kwargs):
        name = kwargs.get("name")
        created.append(name)
        if fault == "thread_constructor" and name == "windows-read-exchange":
            raise InjectedFault()
        return original_thread(*args, **kwargs)

    def start(thread):
        if fault == "thread_start" and thread.name == "windows-read-exchange":
            raise InjectedFault()
        return original_start(thread)

    monkeypatch.setattr(module.threading, "Thread", construct)
    monkeypatch.setattr(original_thread, "start", start)
    result, process, containment, events, buffers, _ = run(
        setup,
        process=process,
        containment=containment,
        retain_cleanup_owner=retain,
    )

    assert len(retained) == 1
    inner_owner, calls_at_handoff, threads_at_handoff = retained[0]
    assert calls_at_handoff == [] and threads_at_handoff == ()
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert inner_owner.adopted and inner_owner.verified
    assert containment.calls == ["adopt", "drain", "finish", "start-close"]
    assert not process.resumed and process.stdin.writes == []
    assert events == buffers == []
    expected_threads = (
        ["windows-read-exchange", "windows-read-cleanup"]
        if fault == "thread_constructor"
        else ["windows-read-exchange", "windows-read-stderr", "windows-read-cleanup"]
    )
    assert created == expected_threads


def test_pair_retain_callback_failure_starts_no_protocol_threads_and_still_cleans(
    setup, monkeypatch
):
    class InjectedFault(BaseException):
        pass

    original_thread = threading.Thread
    created = []
    retained = []
    process = fake.Process(canonical_json_bytes(setup[0][2]), canonical_json_bytes(setup[0][3]))
    containment = fake.Containment()

    def retain(owner):
        retained.append(owner)
        raise InjectedFault()

    def construct(*args, **kwargs):
        name = kwargs.get("name")
        created.append(name)
        return original_thread(*args, **kwargs)

    monkeypatch.setattr(module.threading, "Thread", construct)
    result, process, containment, events, buffers, _ = run(
        setup,
        process=process,
        containment=containment,
        retain_cleanup_owner=retain,
    )

    assert len(retained) == 1 and retained[0].adopted and retained[0].verified
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert created == ["windows-read-cleanup"]
    assert containment.calls == ["adopt", "drain", "finish", "start-close"]
    assert not process.resumed and process.stdin.writes == []
    assert events == buffers == []


@pytest.mark.parametrize("reader", ["allowed", "data_access_denied"])
def test_pair_complete_uses_exact_existing_owner_and_public_sink_without_settlement(setup, reader):
    row = setup[0]
    ready, terminal = pair.envelopes(
        wire.validate_pair_retained_packet(row[0], row[1]._raw), reader
    )
    ready_bytes, terminal_bytes = canonical_json_bytes(ready), canonical_json_bytes(terminal)
    process = fake.Process(ready_bytes, terminal_bytes)
    result, process, containment, events, buffers, admissions = run(setup, process=process)
    assert type(result.projection) is wire.PairNativeProjection
    assert result.projection.outcome == result.projection.reader_outcome == reader
    assert result.projection.owner_outcome == "allowed" and result.projection.observation_complete
    assert result.cleanup == "verified" and result.cleanup_owner is None and not result.settled
    assert result.projection.owned_job_cleanup == "unverified"
    assert not result.projection.settled and not result.projection.independent_observation
    assert [event[:3] for event in events] == [
        ("packet", row[1]._raw, None),
        ("ready", ready_bytes, None),
        ("terminal", terminal_bytes, 0),
    ]
    assert len(admissions) == 3 and len(buffers) == 1 and not any(buffers[0])
    assert len(process.stdin.writes) == 2
    assert process.stdin.writes[1][4:12] == b"BFWFBEG2"
    assert all(b"BFWFBEG2" not in event[1] for event in events)
    assert containment.calls == ["adopt", "assign", "resume", "drain", "finish", "start-close"]
    assert row[4] == ["capture", "require", "require", "require", "require"]
    assert process._handle.closed and process._handle.calls == 1
    assert all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))


@pytest.mark.parametrize("entry_pair", [False, True])
def test_explicit_entry_never_selects_version_from_packet_and_still_drains(setup, entry_pair):
    wrong = setup[1] if entry_pair else setup[0]
    result, process, containment, events, buffers, admissions = run(
        setup,
        original=wrong[0],
        packet=wrong[1],
        entry=module.supervise_pair_suspended if entry_pair else module.supervise_suspended,
    )
    assert result.dispatch == "not_started" and result.projection is None
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert not process.resumed and "assign" not in containment.calls
    assert containment.calls == ["adopt", "drain", "finish", "start-close"]
    assert events == buffers == admissions == [] and process.stdin.writes == []


def test_different_pair_original_refuses_before_assignment_even_when_individually_valid(setup):
    context, expected = pair.fixture()
    expected["control_revision"] += 1
    context["manifest"]["params"]["windows_file_read_request"]["control_revision"] += 1
    pair.v1.reseal(context)
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    result, process, containment, events, buffers, admissions = run(setup, original=original)
    assert result.dispatch == "not_started" and result.cleanup == "verified"
    assert "assign" not in containment.calls and not process.resumed
    assert events == buffers == admissions == []


def test_in_window_partial_preserves_reader_truth_and_whole_exit_four(setup):
    row = setup[0]
    ready, terminal = partial(wire.validate_pair_retained_packet(row[0], row[1]._raw))
    result, _, _, events, _, _ = run(
        setup, process=fake.Process(canonical_json_bytes(ready), canonical_json_bytes(terminal), 4)
    )
    assert result.projection.reader_outcome == "allowed"
    assert result.projection.owner_outcome == "unknown" and result.projection.outcome == "unknown"
    assert result.dispatch == "attempted" and result.issue == "worker_failed"
    assert not result.settled and not result.projection.observation_complete
    assert result.cleanup == "verified" and events[-1][2] == 4


@pytest.mark.parametrize("partial_pair,code", [(True, 0), (False, 4)])
def test_wrong_actual_exit_never_persists_pair_terminal(setup, partial_pair, code):
    row = setup[0]
    retained = wire.validate_pair_retained_packet(row[0], row[1]._raw)
    ready, terminal = partial(retained) if partial_pair else pair.envelopes(retained)
    result, _, _, events, _, _ = run(
        setup,
        process=fake.Process(canonical_json_bytes(ready), canonical_json_bytes(terminal), code),
    )
    assert result.projection is None and result.dispatch == "unknown" and not result.settled
    assert [event[0] for event in events] == ["packet", "ready"]


@pytest.mark.parametrize("fault", ["deadline", "rollback"])
def test_late_partial_is_historically_parseable_but_live_supervisor_never_extends_interval(
    setup, monkeypatch, fault
):
    row = setup[0]
    retained = wire.validate_pair_retained_packet(row[0], row[1]._raw)
    ready, terminal = pair.envelopes(retained)
    terminal["observed_at"] = None
    terminal["result"].update(outcome="unknown", issue="deadline", failed_stage="complete")
    ready_bytes, terminal_bytes = canonical_json_bytes(ready), canonical_json_bytes(terminal)
    historical = wire.validate_pair_terminal(
        row[0],
        retained,
        ready_bytes,
        terminal_bytes,
        clock=pair.v1.NOW + timedelta(days=1),
        returncode=4,
    )
    assert historical.reader_outcome == historical.owner_outcome == "allowed"
    assert not historical.observation_complete
    process = fake.Process(ready_bytes, terminal_bytes, 4)
    original_read = process.stdout.read

    def late_read(count):
        value = original_read(count)
        if len(process.stdin.writes) == 2:
            if fault == "deadline":
                monkeypatch.setattr(module, "_monotonic", lambda: 105.0)
            else:
                monkeypatch.setattr(module, "_utc", lambda: pair.v1.NOW - timedelta(seconds=2))
        return value

    process.stdout.read = late_read
    result, _, _, events, _, _ = run(setup, process=process)
    assert result.projection is None and result.dispatch == "unknown" and result.issue == "deadline"
    assert result.cleanup == "verified" and not result.settled
    assert [event[0] for event in events] == ["packet", "ready"]
    assert row[1]._original_deadline == row[1]._deadline == 104.0


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
def test_pair_evidence_failure_preserves_order_and_never_retries_effects(setup, stage):
    def refused(observed, *_):
        if observed == stage:
            raise RuntimeError("synthetic persistence refusal")

    result, process, _, events, buffers, _ = run(setup, sink=refused)
    assert result.projection is None and result.issue == "evidence_refused"
    assert result.cleanup == "verified" and not result.settled
    assert [event[0] for event in events] == ["packet", "ready", "terminal"][
        : ["packet", "ready", "terminal"].index(stage) + 1
    ]
    assert len(process.stdin.writes) == {"packet": 0, "ready": 1, "terminal": 2}[stage]
    assert len(buffers) == (1 if stage == "terminal" else 0)
    assert result.dispatch == ("unknown" if stage == "terminal" else "not_started")


def test_pair_identity_drift_after_ready_prevents_credential_delivery(setup, monkeypatch):
    def drift(*_, **__):
        raise OSError("synthetic generation drift")

    monkeypatch.setattr(module.child, "require_retained_child", drift)
    result, process, _, events, buffers, admissions = run(setup)
    assert result.projection is None and result.issue == "binding_refused"
    assert buffers == [] and len(admissions) == 1 and len(process.stdin.writes) == 1
    assert [event[0] for event in events] == ["packet", "ready"]
    assert result.cleanup == "verified"


def test_pair_admission_change_during_begin_producer_prevents_begin_and_wipes_buffer(setup):
    admission = {"valid": True}
    captured = []

    def changed():
        if not admission["valid"]:
            raise RuntimeError("synthetic saved claim changed")

    def producer(prefix):
        admission["valid"] = False
        value = bytearray(fake.framed(prefix + b"\x01\0A\0"))
        captured.append(value)
        return value

    result, process, _, events, buffers, calls = run(setup, admission=changed, producer=producer)
    assert result.issue == "admission_refused" and result.dispatch == "not_started"
    assert result.projection is None and result.cleanup == "verified"
    assert len(calls) == 3 and len(buffers) == 1 and buffers[0] is captured[0]
    assert not any(captured[0])
    assert len(process.stdin.writes) == 1 and [event[0] for event in events] == ["packet", "ready"]


@pytest.mark.parametrize("behavior", ["false", "raises", "nonbool"])
def test_pair_launch_release_must_return_exact_true(setup, behavior):
    calls = []

    def release():
        calls.append(True)
        if behavior == "raises":
            raise RuntimeError("synthetic launch cleanup refusal")
        return False if behavior == "false" else 1

    result, process, containment, _, _, _ = run(setup, release_launch_resources=release)
    assert result.cleanup == "unknown" and result.cleanup_owner is not None
    assert result.cleanup_owner.cleanup_receipt is None
    assert result.dispatch == "attempted" and result.projection is not None
    assert len(process.stdin.writes) == 2
    assert process._handle.closed
    assert all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr"))
    assert containment.calls[-2:] == ["finish", "start-close"]
    assert calls
    assert not result.cleanup_owner.retry_cleanup()
    assert result.cleanup_owner.cleanup_receipt is None and len(calls) == 2


def test_pair_launch_release_retries_after_all_child_resources_close(setup):
    calls = []

    def release():
        active_child_threads = {
            thread.name
            for thread in threading.enumerate()
            if thread.is_alive() and thread.name in {"windows-read-exchange", "windows-read-stderr"}
        }
        calls.append(
            (
                process._handle.closed,
                all(getattr(process, name).closed for name in ("stdin", "stdout", "stderr")),
                not active_child_threads,
                containment.calls[-2:] == ["finish", "start-close"],
            )
        )
        return len(calls) > 1

    process = fake.Process(canonical_json_bytes(setup[0][2]), canonical_json_bytes(setup[0][3]))
    containment = fake.Containment()
    result, process, containment, _, _, _ = run(
        setup,
        process=process,
        containment=containment,
        release_launch_resources=release,
    )
    owner = result.cleanup_owner
    assert owner is not None and result.cleanup == "unknown" and owner.cleanup_receipt is None
    assert calls == [(True, True, True, True)]
    assert len(process.stdin.writes) == 2
    assert owner.retry_cleanup()
    assert calls == [(True, True, True, True), (True, True, True, True)]
    assert owner.cleanup_receipt is not None and len(process.stdin.writes) == 2


def test_pair_blocked_launch_release_keeps_owner_and_no_receipt_until_return(setup):
    entered, release = threading.Event(), threading.Event()
    process = fake.Process(canonical_json_bytes(setup[0][2]), canonical_json_bytes(setup[0][3]))
    containment = fake.Containment()
    calls = []

    def release_launch():
        calls.append(True)
        entered.set()
        release.wait(timeout=3)
        return True

    try:
        result, process, containment, _, _, _ = run(
            setup,
            process=process,
            containment=containment,
            release_launch_resources=release_launch,
        )
        owner = result.cleanup_owner
        assert entered.is_set() and owner is not None
        assert result.cleanup == "unknown" and owner.cleanup_receipt is None
        assert process._handle.closed
        assert len(process.stdin.writes) == 2 and calls == [True]
        assert owner.closer is not None and owner.closer.is_alive()
    finally:
        release.set()
        if "owner" in locals() and owner.closer is not None:
            owner.closer.join(timeout=2)
    assert owner.retry_cleanup()
    assert owner.cleanup_receipt is not None and len(process.stdin.writes) == 2 and calls == [True]


def test_pair_unknown_credential_cleanup_keeps_overall_cleanup_unknown(setup):
    credential_cleanup = {"state": "unknown"}
    calls = []

    def producer(_prefix):
        raise RuntimeError("synthetic DPAPI cleanup unknown")

    def release():
        calls.append(credential_cleanup["state"])
        return credential_cleanup["state"] == "verified"

    result, process, _, _, _, _ = run(setup, producer=producer, release_launch_resources=release)
    owner = result.cleanup_owner
    assert owner is not None and result.cleanup == "unknown" and owner.cleanup_receipt is None
    assert result.dispatch == "not_started" and len(process.stdin.writes) == 1
    assert calls == ["unknown"]
    credential_cleanup["state"] = "verified"
    assert owner.retry_cleanup()
    assert owner.cleanup_receipt is not None and calls == ["unknown", "verified"]
    assert len(process.stdin.writes) == 1


def test_wrong_version_ready_prevents_second_admission_and_begin(setup):
    row = setup[0]
    wrong = dict(row[2], schema_version="bluefire.windows-file-worker-ready.v1")
    result, process, _, events, buffers, admissions = run(
        setup, process=fake.Process(canonical_json_bytes(wrong), canonical_json_bytes(row[3]))
    )
    assert result.projection is None and buffers == [] and len(admissions) == 1
    assert [event[0] for event in events] == ["packet"]
    assert len(process.stdin.writes) == 1 and result.cleanup == "verified"


def test_pair_aggregate_stdout_limit_includes_both_prefixes(setup):
    row = setup[0]
    context, expected = pair.fixture()
    ready_size = len(canonical_json_bytes(row[2]))
    terminal_size = len(canonical_json_bytes(row[3]))
    limit = ready_size + terminal_size + 7
    context["profile"]["limits"]["max_stdout_bytes"] = limit
    context["manifest"]["limits"]["max_stdout_bytes"] = limit
    context["profile"]["policy_digest"] = ""
    context["profile"]["policy_digest"] = content_hash(context["profile"])
    context["manifest"]["policy_digest"] = context["profile"]["policy_digest"]
    expected["host"]["profile_digest"] = context["profile"]["policy_digest"]
    context["manifest"]["params"]["windows_file_read_request"]["host"]["profile_digest"] = expected[
        "host"
    ]["profile_digest"]
    pair.v1.reseal(context)
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_pair_packet(
        original,
        challenge="f" * 64,
        clock=pair.v1.NOW,
        monotonic_now=100,
        original_monotonic_deadline=104,
    )
    ready, terminal = pair.envelopes(wire.validate_pair_retained_packet(original, packet._raw))
    result, _, _, events, _, _ = run(
        setup,
        original=original,
        packet=packet,
        process=fake.Process(canonical_json_bytes(ready), canonical_json_bytes(terminal)),
    )
    assert (
        result.projection is None
        and result.issue == "output_bound"
        and result.cleanup == "verified"
    )
    assert [event[0] for event in events] == ["packet", "ready"]


def test_blocked_pair_sink_retains_owner_and_cleanup_retry_cannot_deliver_begin(setup):
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    cancellation = threading.Event()
    result_holder = []

    def blocked(stage, *_):
        if stage == "ready":
            entered.set()
            cancellation.set()
            release.wait(timeout=2)

    def supervise():
        try:
            result_holder.append(run(setup, cancellation=cancellation, sink=blocked))
        finally:
            done.set()

    thread = threading.Thread(target=supervise)
    owner = None
    thread.start()
    try:
        assert entered.wait(1) and done.wait(1)
        result, process, containment, events, buffers, _ = result_holder[0]
        owner = result.cleanup_owner
        assert owner is not None and result.cleanup == "unknown" and not result.settled
        assert not process._handle.closed and "finish" not in containment.calls
        assert not owner.retry_cleanup()
        assert len(process.stdin.writes) == 1 and buffers == []
        assert [event[0] for event in events] == ["packet", "ready"]
    finally:
        release.set()
        thread.join(timeout=2)
        assert not thread.is_alive()
        if owner is None and result_holder:
            owner = result_holder[0][0].cleanup_owner
        if owner is not None:
            for worker in (owner.exchange, owner.errors, owner.closer):
                if worker is not None:
                    worker.join(timeout=2)
            owner.retry_cleanup()
    assert owner is not None and owner.retry_cleanup()
    assert len(process.stdin.writes) == 1 and buffers == []
    assert [event[0] for event in events] == ["packet", "ready"]
