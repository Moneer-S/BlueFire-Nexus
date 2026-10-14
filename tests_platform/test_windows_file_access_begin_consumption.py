"""Ready-once lock over synthetic durable claims; no credential/native calls."""

from __future__ import annotations

import copy
import threading
from dataclasses import replace
from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as native
from bluefire import product_store_windows_correction_retest as correction
from bluefire import windows_file_access_native_wire as wire
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from tests_platform import test_windows_file_access_pair_durable_evidence as ledger
from tests_platform import test_windows_file_access_pair_wire as pair
from tests_platform.test_windows_file_access_native_wire import NOW


@pytest.fixture
def saved(tmp_path):
    value = ledger.seeded(tmp_path / "ready.db")
    _, value["prepared"], _ = pair.prepared()
    assert value["prepared"]._raw == value["public"]
    ledger.put(value, "packet")
    return value


def consume(saved, **overrides):
    arguments = dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        prepared_packet=saved["prepared"],
        ready_bytes=saved["ready"],
        clock=NOW,
        monotonic_now=100.0,
    )
    arguments.update(overrides)
    return saved["store"].consume_windows_file_access_pair_ready(
        saved["context"]["task_id"], **arguments
    )


def test_ready_commits_once_before_allowance_and_historical_lookup_never_mints(saved):
    validate = consume(saved)
    assert callable(validate)
    validate(NOW, 100.0)
    trail = ledger.query(saved)
    assert trail.ready_bytes == saved["ready"] and trail.terminal_bytes is None
    assert not trail.settled and trail.owned_job_cleanup == "unverified"
    with pytest.raises(ProductStoreError):
        consume(saved)
    saved["store"] = ProductStore(saved["path"])
    with pytest.raises(ProductStoreError):
        consume(saved)
    assert ledger.query(saved, clock=NOW + timedelta(days=1)).ready_bytes == saved["ready"]


def test_ordinary_ready_persistence_permanently_blocks_new_allowance(saved):
    ledger.put(saved, "ready")
    with pytest.raises(ProductStoreError):
        consume(saved)
    assert ledger.put(saved, "ready") == ledger.query(saved)


def test_baseline_ready_never_takes_correction_liveness_or_creates_its_allowance(
    saved, monkeypatch
):
    def forbidden(*args, **kwargs):
        pytest.fail("Baseline Ready must never take correction liveness")

    monkeypatch.setattr(correction, "live_context", forbidden)
    arguments = dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        prepared_packet=saved["prepared"],
        clock=NOW,
        monotonic_now=100.0,
    )
    with pytest.raises(ProductStoreError):
        correction.consume_ready(
            saved["store"], saved["context"]["task_id"], ready_bytes=saved["ready"], **arguments
        )
    with pytest.raises(ProductStoreError):
        correction.revalidate_original(saved["store"], saved["context"]["task_id"], **arguments)
    assert ledger.query(saved).ready_bytes is None
    allowance = consume(saved)
    allowance(NOW, 100.0)
    with pytest.raises(ProductStoreError):
        consume(saved)


@pytest.mark.parametrize(
    "clock,mono",
    [
        (NOW - timedelta(seconds=2), 100.0),
        (NOW + timedelta(seconds=5), 100.0),
        (NOW, 104.0),
        (NOW, float("nan")),
        (NOW, True),
    ],
)
def test_original_wall_and_monotonic_limits_never_renew(saved, clock, mono):
    with pytest.raises(ProductStoreError):
        consume(saved, clock=clock, monotonic_now=mono)
    assert ledger.query(saved).ready_bytes is None
    validate = consume(saved)
    with pytest.raises(ProductStoreError):
        validate(clock, mono)


@pytest.mark.parametrize("fault", ["ready", "binding", "v1", "packet"])
def test_bad_original_binding_or_protocol_rolls_back_without_allowance(saved, fault):
    kwargs = {}
    if fault == "ready":
        kwargs["ready_bytes"] = saved["ready"] + b"garbage"
    elif fault == "binding":
        altered = copy.deepcopy(saved["expected"])
        altered["control_revision"] += 1
        kwargs["expected_binding"] = altered
    elif fault == "v1":
        with pytest.raises(wire.NativeWireError):
            replace(saved["original"], _protocol=wire._V1)
        return
    else:
        with pytest.raises(wire.NativeWireError):
            replace(saved["prepared"], _raw=b"{}")
        return
    with pytest.raises((ProductStoreError, wire.NativeWireError)):
        consume(saved, **kwargs)
    assert ledger.query(saved).ready_bytes is None


def test_captured_binding_cannot_be_retargeted_and_final_validation_sees_stop(saved):
    binding = copy.deepcopy(saved["expected"])
    validate = consume(saved, expected_binding=binding)
    binding["control_revision"] = 123
    validate(NOW, 100.0)
    job_id = saved["context"]["manifest"]["run_id"]
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET progress_json=? WHERE job_id=?", ('{"stopped":true}', job_id)
        )
    with pytest.raises(ProductStoreError):
        validate(NOW, 100.0)


def test_record_failure_rolls_back_lock_and_returns_no_predicate(saved, monkeypatch):
    original = native._record_at

    def refused(*args, **kwargs):
        original(*args, **kwargs)
        raise ValueError("synthetic failure after insert")

    monkeypatch.setattr(native, "_record_at", refused)
    with pytest.raises(ProductStoreError):
        consume(saved)
    assert ledger.query(saved).ready_bytes is None
    monkeypatch.setattr(native, "_record_at", original)
    consume(saved)(NOW, 100.0)


def test_two_controllers_obtain_exactly_one_postcommit_allowance(saved):
    barrier = threading.Barrier(2)
    outcomes = []

    def attempt():
        target = dict(saved, store=ProductStore(saved["path"]))
        barrier.wait(timeout=5)
        try:
            outcomes.append(consume(target))
        except ProductStoreError:
            outcomes.append(None)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert sum(callable(item) for item in outcomes) == 1
    assert ledger.query(saved).ready_bytes == saved["ready"]


def test_query_cannot_supply_callable_and_same_connection_is_required(saved):
    context = native._context(
        saved["store"],
        saved["context"]["task_id"],
        saved["context"]["transport_request_hash"],
        saved["expected"],
        _protocol=native._Protocol.PAIR_V2,
    )
    with saved["store"]._connection() as connection:
        with pytest.raises(ValueError):
            native._record_at(connection, context, "ready", saved["ready"], None, NOW)
    assert not callable(ledger.query(saved))
    assert ledger.query(saved).ready_bytes is None


@pytest.mark.parametrize("state", ["stopped", "complete", "unknown"])
def test_current_original_revalidation_refuses_stopped_or_finished_owner(saved, state):
    arguments = dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        prepared_packet=saved["prepared"],
        clock=NOW,
        monotonic_now=100.0,
    )
    store, task = saved["store"], saved["context"]["task_id"]
    assert store.revalidate_windows_file_access_pair_original(task, **arguments) is None
    validate = consume(saved)
    assert store.revalidate_windows_file_access_pair_original(task, **arguments) is None
    job = saved["context"]["manifest"]["run_id"]
    with store._connection(write=True) as connection:
        if state == "stopped":
            connection.execute(
                "UPDATE jobs SET progress_json=? WHERE job_id=?", ('{"stopped":true}', job)
            )
        elif state == "complete":
            connection.execute("UPDATE jobs SET state='succeeded' WHERE job_id=?", (job,))
        else:
            from bluefire.product_store_serialization import canonical_json
            from bluefire.util import content_hash

            document = {"state": "unknown", "evidence_digest": "sha256:" + "1" * 64}
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (job, canonical_json(document), content_hash(document)),
            )
    with pytest.raises(ProductStoreError):
        store.revalidate_windows_file_access_pair_original(task, **arguments)
    with pytest.raises(ProductStoreError):
        validate(NOW, 100.0)


def test_positive_physical_closure_without_ready_blocks_new_begin(saved, monkeypatch):
    from types import SimpleNamespace

    from tests_platform import test_windows_file_access_cleanup_proof as process_fake
    from tests_platform import test_windows_file_access_process as fake

    fake.setup.__wrapped__(monkeypatch)
    ready, terminal = pair.envelopes(saved["retained"])
    source = SimpleNamespace(
        protocol="pair_v2",
        original=saved["original"],
        packet=saved["prepared"],
        ready=ready,
        terminal=terminal,
    )

    def stop_after_packet(stage, *_):
        if stage == "ready":
            raise ProductStoreError("synthetic storage refusal")

    result = process_fake.run(source, sink=stop_after_packet)
    saved["store"].record_file_access_native_pair_cleanup(
        saved["context"]["task_id"],
        receipt=result.outcome.cleanup_receipt,
        **ledger.common(saved),
    )
    with pytest.raises(ProductStoreError):
        consume(saved)
    assert ledger.query(saved).ready_bytes is None
