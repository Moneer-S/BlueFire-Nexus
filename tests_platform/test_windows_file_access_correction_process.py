"""Synthetic v3 process/evidence joins; no process, credentials or Windows I/O."""

from __future__ import annotations

import struct
import threading
from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as evidence
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as supervisor
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes
from tests_platform import test_file_access_native_evidence as storage_fake
from tests_platform import test_windows_file_access_correction_wire as correction
from tests_platform import test_windows_file_access_process as process_fake


@pytest.fixture
def setup(monkeypatch, tmp_path):
    process_fake.setup.__wrapped__(monkeypatch)
    original, packet, retained = correction.prepared()
    context = wire._reservation(original, wire._CORRECTION)
    expected = wire._document(original._expected)
    store = ProductStore(tmp_path / "correction.db")
    storage_fake.insert_claim(store, context)
    return store, original, packet, retained, context, expected


def run(
    setup,
    *,
    reader="data_access_denied",
    fail_stage=None,
    containment=None,
    entry=None,
    producer=None,
):
    store, original, packet, retained, context, expected = setup
    ready, terminal = correction.envelopes(retained, reader)
    process = process_fake.Process(canonical_json_bytes(ready), canonical_json_bytes(terminal))
    containment = containment or process_fake.Containment()
    buffers, stages = [], []

    def sink(stage, raw, code, clock):
        stages.append(stage)
        if stage == fail_stage:
            raise ProductStoreError("Synthetic persistence refusal")
        evidence.record(
            store,
            context["task_id"],
            context["transport_request_hash"],
            expected,
            stage,
            raw,
            code,
            clock,
            _protocol=evidence._Protocol.CORRECTION_V3,
        )

    def begin(prefix):
        if producer is None:
            assert len(prefix) == 156 and prefix[:8] == b"BFWFBEG3"
            assert prefix[124:156] == bytes.fromhex(expected["correction_binding_digest"][7:])
            value = bytearray(process_fake.framed(prefix + b"\x01\0A\0"))
        else:
            value = producer(prefix)
        buffers.append(value)
        return value

    result = (entry or supervisor.supervise_correction_suspended)(
        process,
        owned_job=5001,
        containment=containment,
        prepared_packet=packet,
        original_reservation=original,
        revalidate_original=lambda: None,
        begin_producer=begin,
        cancellation_event=threading.Event(),
        evidence_sink=sink,
    )
    return result, process, containment, stages, buffers


def query(setup, *, clock=correction.v1.NOW, protocol=evidence._Protocol.CORRECTION_V3):
    store, _, _, _, context, expected = setup
    return evidence.query(
        store,
        context["task_id"],
        context["transport_request_hash"],
        expected,
        clock,
        _protocol=protocol,
    )


@pytest.mark.parametrize("reader", ["data_access_denied", "allowed"])
def test_correction_result_and_closure_are_distinct_from_effect_and_settlement(setup, reader):
    result, process, containment, stages, buffers = run(setup, reader=reader)
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert result.dispatch == "attempted" and not result.settled
    assert result.projection.reader_outcome == reader
    assert result.projection.owner_outcome == "allowed"
    assert stages == ["packet", "ready", "terminal"]
    assert len(buffers) == 1 and not any(buffers[0])
    assert process._handle.closed and len(process.stdin.writes) == 2
    trail = query(setup)
    assert type(trail) is evidence.CorrectionNativeTaskEvidence
    assert trail.owned_job_cleanup == "unverified" and not trail.settled
    assert not trail.projection.independent_observation
    store, _, _, _, context, expected = setup
    joined = evidence.record_cleanup(
        store,
        context["task_id"],
        context["transport_request_hash"],
        expected,
        result.cleanup_receipt,
        correction.v1.NOW,
        _protocol=evidence._Protocol.CORRECTION_V3,
    )
    assert joined.owned_job_cleanup == "verified" and not joined.settled
    assert result.cleanup_receipt.document()["protocol"] == "correction_v3"
    calls = list(containment.calls)
    assert query(setup, clock=correction.v1.NOW + timedelta(days=1)) == trail
    assert containment.calls == calls


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
def test_correction_persistence_failure_never_retries_begin_or_settles(setup, stage):
    result, process, _, stages, buffers = run(setup, fail_stage=stage)
    assert result.projection is None and result.issue == "evidence_refused"
    assert result.cleanup == "verified" and not result.settled
    assert len(process.stdin.writes) == {"packet": 0, "ready": 1, "terminal": 2}[stage]
    assert len(buffers) == (1 if stage == "terminal" else 0)
    assert query(setup).terminal_bytes is None
    assert stages[-1] == stage


@pytest.mark.parametrize(
    "fault",
    [
        "short_legacy_124_prefix",
        "corrupted_correction_digest",
        "missing_correction_digest",
        "units_zero",
        "units_257",
        "claimed_length_over_max",
        "oversized_actual_frame",
        "immutable_buffer",
    ],
)
def test_malformed_v3_begin_is_rejected_before_private_write_and_wiped(setup, fault):
    def malformed(prefix):
        if fault == "short_legacy_124_prefix":
            short = bytearray(prefix[:124])
            short[:8] = b"BFWFBEG2"
            payload = short + struct.pack("<H", 1) + b"A\0"
            return bytearray(process_fake.framed(payload))
        if fault == "corrupted_correction_digest":
            changed = bytearray(prefix)
            changed[124] ^= 1
            return bytearray(process_fake.framed(changed + struct.pack("<H", 1) + b"A\0"))
        if fault == "missing_correction_digest":
            return bytearray(process_fake.framed(prefix[:124] + struct.pack("<H", 1) + b"A\0"))
        if fault == "units_zero":
            return bytearray(process_fake.framed(prefix + struct.pack("<H", 0) + b"A\0"))
        if fault == "units_257":
            return bytearray(process_fake.framed(prefix + struct.pack("<H", 257) + b"A\0" * 257))
        if fault == "claimed_length_over_max":
            value = bytearray(process_fake.framed(prefix + struct.pack("<H", 1) + b"A\0"))
            struct.pack_into("<I", value, 0, wire.BEGIN_MAX + 1)
            return value
        value = bytearray(process_fake.framed(prefix + struct.pack("<H", 1) + b"A\0"))
        if fault == "oversized_actual_frame":
            value.extend(b"\0")
            return value
        return bytes(value)

    result, process, _, stages, buffers = run(setup, producer=malformed)
    assert result.issue == "begin_refused" and result.dispatch == "not_started"
    assert (
        result.projection is None and result.cleanup == "verified" and result.cleanup_owner is None
    )
    assert len(buffers) == 1 and len(process.stdin.writes) == 1
    assert stages == ["packet", "ready"]
    if isinstance(buffers[0], bytearray):
        assert not any(buffers[0])
    assert query(setup).terminal_bytes is None


def test_v3_begin_accepts_exact_maximum_utf16_frame_in_fake_pipe(setup):
    def maximum(prefix):
        return bytearray(
            process_fake.framed(prefix + struct.pack("<H", 256) + ("A" * 256).encode("utf-16le"))
        )

    result, process, _, stages, buffers = run(setup, reader="allowed", producer=maximum)
    private_write = process.stdin.writes[1]
    assert result.issue is None and result.dispatch == "attempted" and result.projection is not None
    assert result.cleanup == "verified" and result.cleanup_owner is None
    assert stages == ["packet", "ready", "terminal"] and len(process.stdin.writes) == 2
    assert struct.unpack_from("<I", private_write)[0] == 156 + 2 + (2 * 256)
    assert private_write[4 + 156 : 4 + 158] == struct.pack("<H", 256)
    assert len(private_write) == 4 + 156 + 2 + (2 * 256)
    assert struct.unpack_from("<I", private_write)[0] <= wire.BEGIN_MAX
    assert len(buffers) == 1 and not any(buffers[0])


@pytest.mark.parametrize("protocol", [evidence._Protocol.READER_V1, evidence._Protocol.PAIR_V2])
def test_correction_evidence_cannot_be_read_as_legacy_protocol(setup, protocol):
    with pytest.raises(ProductStoreError):
        query(setup, protocol=protocol)


@pytest.mark.parametrize(
    "entry", [supervisor.supervise_suspended, supervisor.supervise_pair_suspended]
)
def test_legacy_supervisor_refuses_correction_before_assignment_and_drains(setup, entry):
    result, process, containment, stages, buffers = run(setup, entry=entry)
    assert result.dispatch == "not_started" and result.projection is None
    assert result.cleanup == "verified" and not process.resumed
    assert "assign" not in containment.calls
    assert not stages and not buffers and process.stdin.writes == []


def test_correction_cleanup_failure_remains_owned_without_a_receipt(setup):
    class RefusedCleanup(process_fake.Containment):
        def drain_retained(self, *args, **kwargs):
            raise RuntimeError("Synthetic cleanup failure")

    result, _, _, _, _ = run(setup, containment=RefusedCleanup())
    assert result.cleanup == "unknown" and result.cleanup_owner is not None
    assert result.cleanup_receipt is None and not result.settled
