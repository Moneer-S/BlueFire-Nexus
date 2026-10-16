"""Owned cleanup receipts with fake handles/processes only; no native effects."""

from __future__ import annotations

import json
import threading
from dataclasses import FrozenInstanceError
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as module
from bluefire._windows_file_access_cleanup_proof import (
    OwnedCleanupReceipt,
    validate_retained_cleanup,
)
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_pair_process as pair_process
from tests_platform import test_windows_file_access_pair_wire as pair
from tests_platform import test_windows_file_access_process as fake


@pytest.fixture(params=["reader_v1", "pair_v2"])
def source(request, monkeypatch):
    original, packet, ready, terminal, _ = fake.setup.__wrapped__(monkeypatch)
    if request.param == "pair_v2":
        original, packet, retained = pair.prepared()
        ready, terminal = pair.envelopes(retained)
    return SimpleNamespace(
        protocol=request.param, original=original, packet=packet, ready=ready, terminal=terminal
    )


def run(source, *, process=None, containment=None, cancellation=None, sink=None, original=None):
    process = process or fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)
    )
    containment = containment or fake.Containment()
    events, buffers, admissions = [], [], []

    def evidence(stage, raw, code, clock):
        events.append((stage, raw, code, clock))
        if sink is not None:
            sink(stage, raw, code, clock)

    def begin(prefix):
        value = bytearray(fake.framed(prefix + b"\x01\0A\0"))
        buffers.append(value)
        return value

    entry = (
        module.supervise_pair_suspended
        if source.protocol == "pair_v2"
        else module.supervise_suspended
    )
    outcome = entry(
        process,
        owned_job=5001,
        containment=containment,
        prepared_packet=source.packet,
        original_reservation=original or source.original,
        revalidate_original=lambda: admissions.append(True),
        begin_producer=begin,
        cancellation_event=cancellation or threading.Event(),
        evidence_sink=evidence,
    )
    return SimpleNamespace(
        outcome=outcome,
        process=process,
        containment=containment,
        events=events,
        buffers=buffers,
        admissions=admissions,
    )


def test_positive_closure_receipt_is_exact_immutable_and_separate_from_read(source):
    result = run(source)
    receipt = result.outcome.cleanup_receipt
    assert type(receipt) is OwnedCleanupReceipt
    packet = json.loads(source.packet._raw)
    assert receipt.document() == {
        "schema_version": "bluefire.windows-file-owned-cleanup.v1",
        "provenance": "runner_owned_cleanup",
        "protocol": source.protocol,
        "task_id": packet["task_id"],
        "transport_request_hash": packet["request_hash"],
        "packet_digest": content_hash(packet),
        "original_requested_at": packet["manifest"]["requested_at"],
        "original_expires_at": packet["manifest"]["expires_at"],
        "observed_at": fake.NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "child_generation_captured": True,
        "begin_attempted": True,
        "supported_terminal_returncode": 0,
        "cleanup": "verified",
        "settled": False,
    }
    assert receipt._packet == source.packet._raw and len(receipt._packet) <= wire.PUBLIC_MAX
    assert len(receipt._raw) <= 4096 and b"BFWFBEG" not in receipt._raw + receipt._packet
    assert result.outcome.cleanup == "verified" and result.outcome.cleanup_owner is None
    assert (
        not result.outcome.settled and result.outcome.projection.owned_job_cleanup == "unverified"
    )
    assert all(not any(buffer) for buffer in result.buffers)
    assert "C:\\" not in str(receipt.document()) and "4242" not in str(receipt.document())
    assert "sha256" not in repr(receipt)
    row = receipt.document()
    row["settled"] = True
    assert receipt.document()["settled"] is False
    with pytest.raises(FrozenInstanceError):
        receipt._raw = b"changed"


def test_receipt_constructor_and_mapping_cannot_claim_supervisor_authority():
    with pytest.raises(TypeError):
        OwnedCleanupReceipt()
    with pytest.raises(TypeError):
        OwnedCleanupReceipt(verified=True)
    with pytest.raises(wire.NativeWireError):
        OwnedCleanupReceipt.document({"cleanup": "verified"})
    legacy = module.ProcessOutcome(None, "not_started", "unknown", None, None)
    assert legacy.cleanup_receipt is None and not legacy.settled


@pytest.mark.parametrize("fault", ["cancel", "expired", "assignment", "capture"])
def test_before_capture_closure_is_not_generation_or_read_admission(source, monkeypatch, fault):
    cancellation = threading.Event()
    containment = fake.Containment()
    if fault == "cancel":
        cancellation.set()
    elif fault == "expired":
        monkeypatch.setattr(module, "_utc", lambda: fake.NOW + timedelta(seconds=6))
    elif fault == "assignment":
        containment.assignment_failure = True
    else:

        def refused(*args, **kwargs):
            raise OSError("synthetic capture refusal")

        monkeypatch.setattr(module.child, "capture_retained_child", refused)
    result = run(source, cancellation=cancellation, containment=containment)
    row = result.outcome.cleanup_receipt.document()
    assert result.outcome.cleanup == "verified" and result.outcome.projection is None
    assert not row["child_generation_captured"] and not row["begin_attempted"]
    assert row["supported_terminal_returncode"] is None
    assert not result.process.resumed and result.buffers == result.events == []


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
def test_persistence_failure_keeps_physical_receipt_without_business_success(source, stage):
    def refused(observed, *_):
        if observed == stage:
            raise RuntimeError("synthetic persistence refusal")

    result = run(source, sink=refused)
    row = result.outcome.cleanup_receipt.document()
    assert row["child_generation_captured"] and row["begin_attempted"] == (stage == "terminal")
    assert result.outcome.projection is None and result.outcome.issue == "evidence_refused"
    assert result.outcome.cleanup == "verified" and not result.outcome.settled
    assert [event[0] for event in result.events] == ["packet", "ready", "terminal"][
        : ["packet", "ready", "terminal"].index(stage) + 1
    ]


@pytest.mark.parametrize("code", [0, 4, 1, -1, 4294967295, True, "0"])
def test_receipt_reports_only_supported_actual_exit_codes(source, code):
    process = fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal), code
    )
    result = run(source, process=process)
    expected = code if type(code) is int and code in (0, 4) else None
    assert result.outcome.cleanup_receipt.document()["supported_terminal_returncode"] == expected


def test_in_window_partial_pair_preserves_exit_four_and_reader_truth(monkeypatch):
    original_setup = fake.setup.__wrapped__(monkeypatch)
    original, packet, retained = pair.prepared()
    ready, terminal = pair_process.partial(retained)
    result = pair_process.run(
        ((original, packet, ready, terminal, original_setup[4]), original_setup),
        process=fake.Process(canonical_json_bytes(ready), canonical_json_bytes(terminal), 4),
    )[0]
    assert result.cleanup_receipt.document()["supported_terminal_returncode"] == 4
    assert result.projection.reader_outcome == "allowed" and result.projection.outcome == "unknown"
    assert result.issue == "worker_failed" and not result.settled


@pytest.mark.parametrize("fault", ["protocol", "original", "packet"])
def test_invalid_attribution_still_cleans_without_receipt(source, fault):
    if fault == "protocol":
        source.protocol = "reader_v1" if source.protocol == "pair_v2" else "pair_v2"
        original = source.original
    elif fault == "original":
        context, expected = pair.fixture() if source.protocol == "pair_v2" else fake.fixture()
        expected["control_revision"] += 1
        context["manifest"]["params"]["windows_file_read_request"]["control_revision"] += 1
        fake.reseal(context)
        validate = (
            wire.validate_pair_original_reservation
            if source.protocol == "pair_v2"
            else wire.validate_original_reservation
        )
        original = validate(context, expected_binding=expected)
    else:
        original = source.original
        source.packet = object()
    result = run(source, original=original)
    assert result.outcome.cleanup == "verified" and result.outcome.cleanup_receipt is None
    assert result.outcome.projection is None and result.events == result.buffers == []
    assert not result.process.resumed


@pytest.mark.parametrize("fault", ["drain", "finish", "start", "pipe"])
def test_retryable_closure_issues_same_cached_receipt_without_new_work(source, fault):
    containment = fake.Containment()
    process = fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)
    )
    if fault == "pipe":
        process.stdout.fail_close = True
    else:
        setattr(containment, fault + "_failure", True)
    result = run(source, process=process, containment=containment)
    owner = result.outcome.cleanup_owner
    assert owner is not None and owner.cleanup_receipt is result.outcome.cleanup_receipt is None
    before = (
        len(result.events),
        len(result.buffers),
        len(result.admissions),
        len(process.stdin.writes),
    )
    if fault != "pipe":
        setattr(containment, fault + "_failure", False)
    assert owner.retry_cleanup()
    receipt = owner.cleanup_receipt
    assert type(receipt) is OwnedCleanupReceipt
    calls = list(containment.calls)
    assert owner.retry_cleanup() and owner.cleanup_receipt is receipt
    assert containment.calls == calls
    assert before == (
        len(result.events),
        len(result.buffers),
        len(result.admissions),
        len(process.stdin.writes),
    )
    assert all(
        thread is None or not thread.is_alive()
        for thread in (owner.exchange, owner.errors, owner.closer)
    )


@pytest.mark.parametrize("fault", ["handle", "pipe"])
def test_ambiguous_closed_resource_never_issues_receipt_on_retry(source, fault):
    process = fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)
    )
    if fault == "handle":
        process._handle.fail = True
    else:

        def close():
            process.stdout.closed = True
            raise OSError("synthetic ambiguous closed pipe")

        process.stdout.close = close
    result = run(source, process=process)
    owner = result.outcome.cleanup_owner
    assert owner is not None and result.outcome.cleanup_receipt is None
    assert not owner.retry_cleanup() and owner.cleanup_receipt is None


@pytest.mark.parametrize("clock", ["later", "rollback", "invalid"])
def test_cleanup_clock_does_not_renew_read_interval_or_change_physical_truth(
    source, monkeypatch, clock
):
    process = fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)
    )
    close = process._handle.Close
    observed = (
        fake.NOW + timedelta(seconds=6)
        if clock == "later"
        else fake.NOW - timedelta(milliseconds=500)
    )
    if clock == "invalid":
        observed = fake.NOW.replace(tzinfo=None)

    def after_close():
        close()
        monkeypatch.setattr(module, "_utc", lambda: observed)

    process._handle.Close = after_close
    result = run(source, process=process)
    assert result.outcome.cleanup == "verified" and not result.outcome.settled
    if clock == "later":
        row = result.outcome.cleanup_receipt.document()
        assert wire._time(row["observed_at"]) > wire._time(row["original_expires_at"])
        assert result.outcome.projection.observation_complete and result.outcome.issue is None
        assert result.events[-1][0] == "terminal" and result.events[-1][3] == fake.NOW
        assert len(result.buffers) == 1 and len(result.admissions) == 3
    else:
        assert result.outcome.cleanup_receipt is None


def test_late_before_begin_keeps_cleanup_but_never_dispatches_read(source, monkeypatch):
    def late(stage, *_):
        if stage == "ready":
            monkeypatch.setattr(module, "_utc", lambda: fake.NOW + timedelta(seconds=6))

    result = run(source, sink=late)
    row = result.outcome.cleanup_receipt.document()
    assert row["child_generation_captured"] and not row["begin_attempted"]
    assert result.outcome.projection is None and result.outcome.issue == "deadline"
    assert result.outcome.dispatch == "not_started" and not result.outcome.settled
    assert result.buffers == [] and len(result.admissions) == 1
    assert [event[0] for event in result.events] == ["packet", "ready"]


def test_live_exchange_blocks_receipt_until_cleanup_only_retry(source):
    release, entered = threading.Event(), threading.Event()
    cancellation = threading.Event()
    owner = None

    def blocked(stage, *_):
        if stage == "ready":
            entered.set()
            cancellation.set()
            release.wait()

    try:
        result = run(source, sink=blocked, cancellation=cancellation)
        owner = result.outcome.cleanup_owner
        assert entered.is_set() and owner is not None
        assert result.outcome.cleanup_receipt is None and owner.cleanup_receipt is None
        assert owner.exchange.is_alive() and not owner.retry_cleanup()
        before = (len(result.events), len(result.buffers), len(result.process.stdin.writes))
    finally:
        release.set()
        if owner is not None:
            for worker in (owner.exchange, owner.errors, owner.closer):
                if worker is not None:
                    worker.join(timeout=2)
            owner.retry_cleanup()
    assert owner is not None and owner.retry_cleanup()
    assert type(owner.cleanup_receipt) is OwnedCleanupReceipt
    assert before == (len(result.events), len(result.buffers), len(result.process.stdin.writes))


@pytest.mark.parametrize("worker", ["stderr", "closer"])
def test_live_other_workers_block_receipt_even_after_positive_closure_flags(
    source, monkeypatch, worker
):
    release, entered = threading.Event(), threading.Event()
    cancellation = threading.Event()
    process = fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)
    )
    owner = None
    if worker == "closer":
        cleanup = module.CleanupOwner._cleanup

        def delayed(self):
            cleanup(self)
            entered.set()
            release.wait()

        monkeypatch.setattr(module.CleanupOwner, "_cleanup", delayed)
    else:

        def delayed_read(count):
            entered.set()
            cancellation.set()
            release.wait()
            return b""

        process.stderr.read = delayed_read
    try:
        result = run(source, process=process, cancellation=cancellation)
        owner = result.outcome.cleanup_owner
        assert entered.is_set() and owner is not None
        assert result.outcome.cleanup_receipt is None and owner.cleanup_receipt is None
        assert not owner.retry_cleanup()
        if worker == "closer":
            assert owner.verified and owner.closer.is_alive()
    finally:
        release.set()
        if owner is not None:
            for thread in (owner.exchange, owner.errors, owner.closer):
                if thread is not None:
                    thread.join(timeout=2)
            owner.retry_cleanup()
    assert owner is not None and owner.retry_cleanup()
    assert type(owner.cleanup_receipt) is OwnedCleanupReceipt


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "schema",
        "protocol",
        "boolean",
        "begin",
        "exit",
        "task",
        "hash",
        "packet",
        "receipt_bound",
        "packet_bound",
        "clock",
    ],
)
def test_historical_parser_is_closed_bounded_and_never_constructs_authority(source, change):
    receipt = run(source).outcome.cleanup_receipt
    row, packet = receipt.document(), receipt._packet
    assert type(validate_retained_cleanup(receipt._raw, packet)) is dict
    if change == "extra":
        row["verified"] = True
    elif change == "schema":
        row["schema_version"] += ".unknown"
    elif change == "protocol":
        row["protocol"] = "pair_v2" if source.protocol == "reader_v1" else "reader_v1"
    elif change == "boolean":
        row["child_generation_captured"] = 1
    elif change == "begin":
        row["child_generation_captured"] = False
    elif change == "exit":
        row["supported_terminal_returncode"] = True
    elif change == "task":
        row["task_id"] = "execute-" + "0" * 64
    elif change == "hash":
        row["packet_digest"] = "sha256:" + "0" * 64
    elif change == "packet":
        parsed = json.loads(packet)
        parsed["begin"] = "forbidden"
        packet = canonical_json_bytes(parsed)
    elif change == "packet_bound":
        packet = b" " * (wire.PUBLIC_MAX + 1)
    elif change == "clock":
        row["observed_at"] = (
            (fake.NOW - timedelta(seconds=2))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    raw = canonical_json_bytes(row)
    if change == "receipt_bound":
        raw = b" " * 4097
    with pytest.raises(wire.NativeWireError):
        validate_retained_cleanup(raw, packet)


def test_last_observed_clock_retains_concurrent_max_without_altering_clock_values(
    source, monkeypatch
):
    containment = fake.Containment()
    containment.finish_failure = True
    result = run(source, containment=containment)
    owner = result.outcome.cleanup_owner
    assert owner is not None
    later = fake.NOW + timedelta(milliseconds=500)
    entered, release = threading.Event(), threading.Event()
    values = []

    def clock():
        if threading.current_thread().name == "later-clock":
            entered.set()
            return later
        assert entered.wait(1)
        assert release.wait(1)
        return fake.NOW

    monkeypatch.setattr(module, "_utc", clock)

    def observe():
        values.append(owner._clock())

    first = threading.Thread(target=observe, name="later-clock")
    second = threading.Thread(target=observe, name="earlier-clock")
    try:
        first.start()
        second.start()
        first.join(timeout=1)
    finally:
        release.set()
        first.join(timeout=1)
        second.join(timeout=1)
        monkeypatch.setattr(module, "_utc", lambda: later)
        owner.containment.finish_failure = False
        owner.retry_cleanup()
    assert not first.is_alive() and not second.is_alive()
    assert values == [later, fake.NOW] and owner._last_wall_clock == later
    assert owner.retry_cleanup() and type(owner.cleanup_receipt) is OwnedCleanupReceipt


def test_failed_clock_attribution_cannot_be_reissued_with_a_new_time(source, monkeypatch):
    containment = fake.Containment()
    containment.finish_failure = True
    owner = run(source, containment=containment).outcome.cleanup_owner
    assert owner is not None
    containment.finish_failure = False
    monkeypatch.setattr(module, "_utc", lambda: fake.NOW - timedelta(milliseconds=500))
    assert owner.retry_cleanup() and owner.cleanup_receipt is None
    monkeypatch.setattr(module, "_utc", lambda: fake.NOW + timedelta(seconds=1))
    assert owner.retry_cleanup() and owner.cleanup_receipt is None
