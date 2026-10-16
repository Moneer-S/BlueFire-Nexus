"""Real temporary ledger plus fake supervisor resources; no native processes."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as evidence
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_process as supervisor
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes
from tests_platform.test_file_access_native_evidence import saved as saved
from tests_platform.test_windows_file_access_native_wire import NOW, envelopes
from tests_platform.test_windows_file_access_process import Containment, Process, run
from tests_platform.test_windows_file_access_process import setup as setup


def sink_for(saved):
    return evidence.native_evidence_sink(
        saved["store"],
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )


def retained(saved, *, clock=NOW, binding=None):
    return saved["store"].file_access_native_evidence(
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"] if binding is None else binding,
        clock=clock,
    )


@pytest.mark.parametrize(
    "outcome,code", [("allowed", 0), ("data_access_denied", 0), ("unknown", 4)]
)
def test_fake_supervisor_durably_records_three_stages_and_historical_reopen_never_replays(
    saved, setup, monkeypatch, outcome, code
):
    original, packet, _, _, _ = setup
    assert packet._raw == saved["public"]
    ready, terminal = envelopes(wire.validate_retained_packet(original, packet._raw), outcome)
    process = Process(canonical_json_bytes(ready), canonical_json_bytes(terminal), code)
    sink = sink_for(saved)
    result, process, containment, admissions, buffers = run(
        setup, process=process, evidence_sink=sink
    )
    assert result.projection.outcome == outcome and not result.settled
    assert result.cleanup == "verified" and len(admissions) == 3 and len(buffers) == 1
    assert not any(buffers[0]) and len(process.stdin.writes) == 2
    observed = retained(saved)
    assert observed.packet_bytes == packet._raw
    assert observed.ready_bytes == canonical_json_bytes(ready)
    assert observed.terminal_bytes == canonical_json_bytes(terminal)
    assert observed.actual_returncode == code and observed.projection.outcome == outcome
    assert not observed.settled and observed.owned_job_cleanup == "unverified"
    assert observed.projection.observation_complete is (outcome != "unknown")
    calls = list(containment.calls)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical lookup cannot execute or deliver another Begin")

    monkeypatch.setattr(supervisor, "supervise_suspended", forbidden)
    saved["store"] = ProductStore(saved["path"])
    recovered = retained(saved, clock=NOW + timedelta(days=1))
    assert recovered == observed and containment.calls == calls
    assert len(admissions) == 3 and len(buffers) == 1 and len(process.stdin.writes) == 2
    assert saved["context"]["manifest"]["expires_at"] == "2026-10-12T12:00:05Z"


@pytest.mark.parametrize("failed_stage", ["packet", "ready", "terminal"])
def test_storage_failure_stops_begin_or_retains_unknown_partial_trail(
    saved, setup, monkeypatch, failed_stage
):
    real_record = evidence.record
    attempts = []

    def failing_record(store, task, transport, binding, stage, data, code, clock):
        attempts.append(stage)
        if stage == failed_stage:
            raise ProductStoreError("synthetic storage unavailable")
        return real_record(store, task, transport, binding, stage, data, code, clock)

    sink = sink_for(saved)
    monkeypatch.setattr(evidence, "record", failing_record)
    result, process, _, admissions, buffers = run(setup, evidence_sink=sink)
    trail = retained(saved)
    assert result.projection is None and result.issue == "evidence_refused" and not result.settled
    assert result.cleanup == "verified" and trail.terminal_bytes is trail.projection is None
    assert not trail.settled and trail.owned_job_cleanup == "unverified"
    if failed_stage == "packet":
        assert attempts == ["packet"] and trail.packet_bytes is trail.ready_bytes is None
        assert process.stdin.writes == [] and buffers == [] and len(admissions) == 1
        assert result.dispatch == "not_started"
    elif failed_stage == "ready":
        assert attempts == ["packet", "ready"] and trail.packet_bytes == saved["public"]
        assert trail.ready_bytes is None and len(process.stdin.writes) == 1 and buffers == []
        assert len(admissions) == 1 and result.dispatch == "not_started"
    else:
        assert attempts == ["packet", "ready", "terminal"]
        assert trail.packet_bytes == saved["public"] and trail.ready_bytes == saved["ready"]
        assert len(process.stdin.writes) == 2 and len(buffers) == 1 and not any(buffers[0])
        assert len(admissions) == 3 and result.dispatch == "unknown"


@pytest.mark.parametrize("fault", ["missing", "full_pair_hash", "original_binding"])
def test_factory_refuses_missing_or_wrong_claim_before_resource_transfer(saved, setup, fault):
    process = Process(saved["ready"], saved["terminal"])
    containment = Containment()
    task = saved["context"]["task_id"]
    transport = saved["context"]["transport_request_hash"]
    binding = copy.deepcopy(saved["expected"])
    if fault == "missing":
        task = "execute-" + "0" * 64
    elif fault == "full_pair_hash":
        transport = "sha256:" + "0" * 64
    else:
        binding["control_revision"] += 1
    with pytest.raises(ProductStoreError) as error:
        evidence.native_evidence_sink(
            saved["store"], task, transport_request_hash=transport, expected_binding=binding
        )
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert containment.calls == [] and setup[4] == [] and not process.resumed
    assert not process._handle.closed and process._handle.calls == 0
    assert process.stdin.writes == [] and process.kills == process.waits == 0
    assert retained(saved).packet_bytes is None


def test_factory_captures_immutable_original_binding_not_later_mutated_input(saved, setup):
    original_binding = copy.deepcopy(saved["expected"])
    sink = sink_for(saved)
    saved["expected"]["generation"] = "0" * 32
    saved["expected"]["control_revision"] += 1
    saved["expected"]["credential_binding_digest"] = "sha256:" + "1" * 64
    saved["expected"]["host"]["channel_digest"] = "sha256:" + "0" * 64
    saved["expected"]["resource"]["file_identity"]["file_id"] = "f" * 32
    result, process, _, admissions, buffers = run(setup, evidence_sink=sink)
    assert result.projection.outcome == "allowed" and result.cleanup == "verified"
    assert len(admissions) == 3 and len(buffers) == 1 and len(process.stdin.writes) == 2
    observed = retained(saved, binding=original_binding)
    assert observed.packet_bytes == saved["public"] and observed.terminal_bytes == saved["terminal"]
    assert not observed.settled and observed.owned_job_cleanup == "unverified"
    with pytest.raises(ProductStoreError):
        retained(saved)
