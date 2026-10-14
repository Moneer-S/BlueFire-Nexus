"""Synthetic correction publication joins durable control, v3 task and closure."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from bluefire import product_store_file_access_native_evidence as native
from bluefire import product_store_windows_correction_publication as publication
from bluefire import product_store_windows_correction_retest as retest
from bluefire import windows_file_access_correction_observation as observation
from bluefire import windows_file_access_native_wire as wire
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_correction_retest as retest_fake
from tests_platform import test_windows_file_access_correction_wire as wire_fake
from tests_platform import test_windows_file_access_process as process_driver
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved
from tests_platform.test_windows_file_access_correction_retest import candidate
from tests_platform.test_windows_file_access_correction_journal import retained
from tests_platform.test_windows_file_access_pair_provenance import paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle


def no_terminal(value, monkeypatch):
    retest_fake.close_control(value)
    retest_fake.register(value)
    args = retest_fake.ready_args(value)
    retest_fake.record_packet(value, args)
    retest.consume_ready(value.store, value.original["task_id"], **args)
    return args


def execute(
    value,
    monkeypatch,
    *,
    reader="data_access_denied",
    owner_failure=False,
    unknown_terminal=False,
    cleanup_unknown=False,
):
    retest_fake.close_control(value)
    retest_fake.register(value)
    args = retest_fake.ready_args(value)
    retest_fake.record_packet(value, args)
    ready_time = at_ms(ISSUED + 3000)
    observed_time = at_ms(ISSUED + 4000)
    allowance = retest.consume_ready(
        value.store,
        value.original["task_id"],
        **args,
    )
    allowance(ready_time, 100.001)

    process_driver.setup.__wrapped__(monkeypatch)
    monkeypatch.setattr(process_driver.module, "_utc", lambda: observed_time)
    monkeypatch.setattr(process_driver.module, "_monotonic", lambda: 100.002)
    original_reservation = wire.validate_correction_original_reservation(
        value.original, expected_binding=value.expected
    )
    retained = wire.validate_correction_retained_packet(
        original_reservation, args["prepared_packet"]._raw
    )
    ready, terminal = wire_fake.envelopes(retained, reader=reader)
    resource = value.prepared["binding"]["target_resource"]
    terminal["observed_at"] = observed_time.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    terminal["result"]["owner"].update(
        bytes_read=resource["size_bytes"], observed_sha256=resource["sha256"]
    )
    returncode = 0
    if unknown_terminal:
        returncode = 4
        terminal["observed_at"] = None
        terminal["result"].update(
            outcome="unknown",
            issue="deadline",
            failed_stage="complete",
            resource_pair_rechecked=False,
        )
    if owner_failure:
        returncode = 4
        result = terminal["result"]
        result.update(
            outcome="unknown",
            issue="native_failure",
            failed_stage="owner_read",
            resource_pair_rechecked=False,
        )
        result["owner"].update(
            outcome="unknown",
            issue="native_failure",
            failed_stage="owner_read",
            bytes_read=0,
            observed_sha256=None,
            resource_rechecked=False,
        )
    process = process_driver.Process(
        canonical_json_bytes(ready), canonical_json_bytes(terminal), code=returncode
    )
    containment = process_driver.Containment()
    if cleanup_unknown:
        containment.finish_failure = True
    buffers = []

    def begin(prefix):
        value = bytearray(process_driver.framed(prefix + b"\x01\0A\0"))
        buffers.append(value)
        return value

    def sink(stage, raw, code, clock):
        native.record(
            value.store,
            value.original["task_id"],
            value.original["transport_request_hash"],
            value.expected,
            stage,
            raw,
            code,
            clock,
            _protocol=native._Protocol.CORRECTION_V3,
        )

    def revalidate():
        allowance(observed_time, 100.003)

    result = process_driver.module.supervise_correction_suspended(
        process,
        owned_job=5001,
        containment=containment,
        prepared_packet=args["prepared_packet"],
        original_reservation=original_reservation,
        revalidate_original=revalidate,
        begin_producer=begin,
        cancellation_event=threading.Event(),
        evidence_sink=sink,
    )
    if result.cleanup_receipt is not None:
        native.record_cleanup(
            value.store,
            value.original["task_id"],
            value.original["transport_request_hash"],
            value.expected,
            result.cleanup_receipt,
            observed_time,
            _protocol=native._Protocol.CORRECTION_V3,
        )
    return SimpleNamespace(
        args=args,
        result=result,
        process=process,
        containment=containment,
        buffers=buffers,
        observed_time=observed_time,
    )


def add_unknown_outcome(value):
    outcome = {"state": "unknown", "evidence_digest": content_hash({"original": value.job})}
    value.store.finish_file_access_operation(value.job, outcome=outcome)
    return revision_rows(value)[1]["document_digest"]


def revision_rows(value):
    with value.store._connection() as connection:
        revisions = connection.execute(
            "SELECT count(*) FROM file_access_revisions WHERE job_id=?", (value.job,)
        ).fetchone()[0]
        outcome = connection.execute(
            "SELECT document_json,document_digest FROM file_access_outcomes WHERE job_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (value.job,),
        ).fetchone()
    return revisions, outcome


def test_publication_requires_denied_reader_allowed_owner_and_both_closures(candidate, monkeypatch):
    value = candidate
    execution = execute(value, monkeypatch)
    assert execution.result.projection.reader_outcome == "data_access_denied"
    assert execution.result.projection.owner_outcome == "allowed"
    assert execution.result.cleanup == "verified" and execution.result.cleanup_receipt is not None
    assert not execution.result.settled
    assert all(not any(buffer) for buffer in execution.buffers)
    expected_digest = add_unknown_outcome(value)
    revision = publication.publish(
        value.store,
        value.job,
        clock=execution.observed_time,
        expected_outcome_digest=expected_digest,
    )
    assert revision["schema_version"] == publication.CONTROL_SCHEMA
    assert revision["status"] == "hardened"
    assert revision["correction"]["owned_control_cleanup"] == "verified"
    assert revision["retest"]["non_owner"] == "data_access_denied"
    assert revision["retest"]["owner"] == "allowed"
    assert revision["retest"]["native_cleanup"] == "verified"
    assert revision["retest"]["owned_job_cleanup"] == "verified"
    assert (
        publication.publish(
            value.store,
            value.job,
            clock=execution.observed_time,
            expected_outcome_digest=expected_digest,
        )
        == revision
    )
    assert revision_rows(value)[0] == 1


def test_first_publication_without_prior_outcome_digest(candidate, monkeypatch):
    value = candidate
    execution = execute(value, monkeypatch)
    revision = publication.publish(value.store, value.job, clock=execution.observed_time)
    assert revision["status"] == "hardened"
    assert revision["retest"]["owned_job_cleanup"] == "verified"
    assert revision_rows(value)[0] == 1


@pytest.mark.parametrize(
    "kind",
    ["allowed_reader", "unknown", "owner_failure", "no_terminal", "cleanup_unknown"],
)
def test_incomplete_or_non_denied_retest_never_publishes(candidate, monkeypatch, kind):
    value = candidate
    if kind == "no_terminal":
        no_terminal(value, monkeypatch)
        clock = at_ms(ISSUED + 4000)
    else:
        execution = execute(
            value,
            monkeypatch,
            reader="allowed" if kind == "allowed_reader" else "data_access_denied",
            owner_failure=kind == "owner_failure",
            unknown_terminal=kind == "unknown",
            cleanup_unknown=kind == "cleanup_unknown",
        )
        clock = execution.observed_time
    expected_digest = add_unknown_outcome(value)
    with pytest.raises(ProductStoreError):
        publication.publish(
            value.store, value.job, clock=clock, expected_outcome_digest=expected_digest
        )
    assert revision_rows(value)[0] == 0


def test_publish_uses_exact_unknown_outcome_cas(candidate, monkeypatch):
    value = candidate
    execution = execute(value, monkeypatch)
    expected_digest = add_unknown_outcome(value)
    with pytest.raises(ProductStoreError):
        publication.publish(
            value.store,
            value.job,
            clock=execution.observed_time,
            expected_outcome_digest="sha256:" + "0" * 64,
        )
    assert revision_rows(value)[0] == 0
    assert (
        publication.publish(
            value.store,
            value.job,
            clock=execution.observed_time,
            expected_outcome_digest=expected_digest,
        )["status"]
        == "hardened"
    )


def test_publication_transaction_rolls_back_revision_if_outcome_insert_fails(
    candidate, monkeypatch
):
    value = candidate
    execution = execute(value, monkeypatch)
    expected_digest = add_unknown_outcome(value)
    with value.store._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER synthetic_abort_outcome BEFORE INSERT ON file_access_outcomes "
            "BEGIN SELECT RAISE(ABORT, 'synthetic outcome failure'); END"
        )
    with pytest.raises(ProductStoreError):
        publication.publish(
            value.store,
            value.job,
            clock=execution.observed_time,
            expected_outcome_digest=expected_digest,
        )
    count, outcome = revision_rows(value)
    assert count == 0 and outcome[1] == expected_digest


def test_expired_historical_publication_never_prepares_or_observes_again(candidate, monkeypatch):
    value = candidate
    execution = execute(value, monkeypatch)
    expected_digest = add_unknown_outcome(value)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("historical publication must not prepare or observe")

    monkeypatch.setattr(wire, "prepare_correction_packet", forbidden)
    monkeypatch.setattr(observation, "observe_correction_postimage", forbidden)
    historical = at_ms(value.prepared["expires_at_ms"] + 1)
    trail = native.query(
        value.store,
        value.original["task_id"],
        value.original["transport_request_hash"],
        value.expected,
        historical,
        _protocol=native._Protocol.CORRECTION_V3,
    )
    assert trail.projection.reader_outcome == "data_access_denied"
    assert trail.owned_job_cleanup == "unverified"
    revision = publication.publish(
        value.store,
        value.job,
        clock=historical,
        expected_outcome_digest=expected_digest,
    )
    assert revision["status"] == "hardened"
    assert revision["retest"]["owned_job_cleanup"] == "verified"
    assert (
        publication.publish(
            value.store,
            value.job,
            clock=historical,
            expected_outcome_digest=expected_digest,
        )
        == revision
    )
