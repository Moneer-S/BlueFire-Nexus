"""Fresh retest admission after synthetic, retained effect and physical closure."""

from __future__ import annotations

from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as native
from bluefire import product_store_windows_correction as journal
from bluefire import product_store_windows_correction_retest as retest
from bluefire import product_store_windows_file_access as windows
from bluefire import windows_file_access_correction_admission as admission
from bluefire import windows_file_access_correction_observation as observation
from bluefire import windows_file_access_native_wire as wire
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes
from tests_platform import test_windows_file_access_correction_journal as journal_fake
from tests_platform import test_windows_file_access_correction_wire as wire_fake
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_control_process import terminal
from tests_platform.test_windows_file_access_correction_journal import retained as retained
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


@pytest.fixture
def candidate(retained):
    v = retained
    # Test-local stand-ins for concrete observer and supervisor producers.
    v.postimage = object.__new__(observation.VerifiedWindowsCorrectionPostimage)
    for key, value in {
        "_raw": v.checked_setup._raw,
        "_receipt": v.checked_setup._receipt,
        "_setup": v.checked_setup,
        "_binding": canonical_json_bytes(v.prepared["binding"]),
        "_descriptor_sha256": "sha256:" + "e" * 64,
    }.items():
        object.__setattr__(v.postimage, key, value)
    v.original, v.expected = admission.build_retest_original(
        v.prepared["binding"],
        v.checked_setup,
        issued_at_ms=ISSUED + 3000,
        reviewed_by="synthetic-operator",
    )
    return v


def close_control(v):
    journal_fake.begin(v)
    receipt = journal_fake.receipt(v)
    row = receipt.document()
    row.update(dispatch="attempted", terminal=terminal(v.prepared["binding"]))
    object.__setattr__(receipt, "_raw", canonical_json_bytes(row))
    journal.record_control_closure(v.store, v.job, receipt)


def register(v, **changes):
    args = dict(
        checked=v.postimage,
        original=v.original,
        expected_binding=v.expected,
        now_ms=ISSUED + 3000,
        revalidate=lambda: None,
    )
    retest.register_retest(v.store, v.job, **{**args, **changes})


def ready_args(v):
    reservation = wire.validate_correction_original_reservation(
        v.original, expected_binding=v.expected
    )
    packet = wire.prepare_correction_packet(
        reservation,
        challenge="f" * 64,
        clock=at_ms(ISSUED + 3000),
        monotonic_now=100.0,
        original_monotonic_deadline=105.0,
    )
    retained_packet = wire.validate_correction_retained_packet(reservation, packet._raw)
    ready, _ = wire_fake.envelopes(retained_packet)
    args = dict(
        transport_request_hash=v.original["transport_request_hash"],
        expected_binding=v.expected,
        prepared_packet=packet,
        ready_bytes=canonical_json_bytes(ready),
        clock=at_ms(ISSUED + 3000),
        monotonic_now=100.0,
    )
    return args


def record_packet(v, args):
    native.record(
        v.store,
        v.original["task_id"],
        v.original["transport_request_hash"],
        v.expected,
        "packet",
        args["prepared_packet"]._raw,
        None,
        args["clock"],
        _protocol=native._Protocol.CORRECTION_V3,
    )


def test_retest_requires_effect_terminal_and_child_closure_not_dispatch(candidate):
    v = candidate
    with pytest.raises(ProductStoreError):
        register(v)
    journal_fake.begin(v)
    with pytest.raises(ProductStoreError):
        register(v)
    journal.record_control_closure(v.store, v.job, journal_fake.receipt(v))
    with pytest.raises(ProductStoreError):
        register(v)


@pytest.mark.parametrize("fault", ["postimage", "descriptor", "time", "original", "expected"])
def test_changed_postimage_or_fresh_task_refuses_claim(candidate, fault):
    v = candidate
    close_control(v)
    changes = {}
    if fault == "postimage":
        changes["checked"] = v.checked_setup
    elif fault == "descriptor":
        object.__setattr__(v.postimage, "_descriptor_sha256", "sha256:" + "9" * 64)
    elif fault == "time":
        changes["now_ms"] = v.prepared["expires_at_ms"]
    elif fault == "original":
        changes["original"] = {**v.original, "task_id": "different"}
    else:
        changes["expected_binding"] = {
            **v.expected,
            "correction_binding_digest": "sha256:" + "8" * 64,
        }
    with pytest.raises(ProductStoreError):
        register(v, **changes)
    with v.store._connection() as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM file_access_task_claims WHERE job_id=?", (v.job,)
            ).fetchone()[0]
            == 0
        )


def test_claim_and_ready_are_once_only_across_store_reopen(candidate):
    v = candidate
    close_control(v)
    register(v)
    with pytest.raises(ProductStoreError):
        register(v)
    args = ready_args(v)
    with pytest.raises(ProductStoreError):
        retest.consume_ready(v.store, v.original["task_id"], **args)
    record_packet(v, args)
    current = {key: value for key, value in args.items() if key != "ready_bytes"}
    retest.revalidate_original(v.store, v.original["task_id"], **current)
    allowance = retest.consume_ready(v.store, v.original["task_id"], **args)
    allowance(at_ms(ISSUED + 3001), 100.001)
    v.store = ProductStore(v.path)
    with pytest.raises(ProductStoreError):
        retest.consume_ready(v.store, v.original["task_id"], **args)
    with pytest.raises(ProductStoreError):
        allowance(at_ms(v.prepared["expires_at_ms"]), 105.0)


def test_v2_ready_api_cannot_consume_correction_claim(candidate, monkeypatch):
    v = candidate
    close_control(v)
    register(v)
    args = ready_args(v)
    record_packet(v, args)

    def forbidden(*args, **kwargs):
        pytest.fail("Correction Ready must never take baseline liveness")

    monkeypatch.setattr(windows, "_live", forbidden)
    with pytest.raises(ProductStoreError):
        v.store.consume_windows_file_access_pair_ready(v.original["task_id"], **args)
    with pytest.raises(ProductStoreError):
        windows.consume_pair_ready(
            v.store,
            v.original["task_id"],
            args["transport_request_hash"],
            args["expected_binding"],
            args["prepared_packet"],
            args["ready_bytes"],
            args["clock"],
            args["monotonic_now"],
            _protocol=native._Protocol.CORRECTION_V3,
        )
    trail = native.query(
        v.store,
        v.original["task_id"],
        args["transport_request_hash"],
        args["expected_binding"],
        args["clock"],
        _protocol=native._Protocol.CORRECTION_V3,
    )
    assert trail.ready_bytes is None
    allowance = retest.consume_ready(v.store, v.original["task_id"], **args)
    allowance(at_ms(ISSUED + 3001), 100.001)
    with pytest.raises(ProductStoreError):
        retest.consume_ready(v.store, v.original["task_id"], **args)


def test_historical_read_never_recreates_ready_after_expiry(candidate, monkeypatch):
    v = candidate
    close_control(v)
    register(v)
    args = ready_args(v)
    record_packet(v, args)
    retest.consume_ready(v.store, v.original["task_id"], **args)

    def forbidden(*_, **__):
        raise AssertionError("historical evidence must not prepare or observe")

    monkeypatch.setattr(wire, "prepare_correction_packet", forbidden)
    monkeypatch.setattr(observation, "observe_correction_postimage", forbidden)
    trail = native.query(
        v.store,
        v.original["task_id"],
        v.original["transport_request_hash"],
        v.expected,
        args["clock"] + timedelta(days=1),
        _protocol=native._Protocol.CORRECTION_V3,
    )
    assert type(trail) is native.CorrectionNativeTaskEvidence
    assert trail.ready_bytes == args["ready_bytes"] and trail.terminal_bytes is None
    with pytest.raises(ProductStoreError):
        retest.consume_ready(v.store, v.original["task_id"], **args)
