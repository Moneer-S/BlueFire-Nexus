"""Real SQLite and fake supervisor receipts only; no admission/native effects."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as evidence
from bluefire import windows_file_access_native_wire as wire
from bluefire._windows_file_access_cleanup_proof import OwnedCleanupReceipt
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_file_access_native_evidence as legacy
from tests_platform import test_windows_file_access_cleanup_proof as process_fake
from tests_platform import test_windows_file_access_pair_durable_evidence as pair_ledger
from tests_platform.test_windows_file_access_native_wire import NOW


@pytest.fixture(params=["reader_v1", "pair_v2"])
def saved(request, tmp_path, monkeypatch):
    source = process_fake.source.__wrapped__(request, monkeypatch)
    target = (
        pair_ledger.seeded(tmp_path / "cleanup.db")
        if request.param == "pair_v2"
        else legacy.saved.__wrapped__(tmp_path)
    )
    assert target["public"] == source.packet._raw
    return {**target, "source": source, "protocol": request.param}


def common(saved, *, clock=NOW):
    return dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        clock=clock,
    )


def sink_for(saved):
    factory = (
        evidence.native_pair_evidence_sink
        if saved["protocol"] == "pair_v2"
        else evidence.native_evidence_sink
    )
    return factory(
        saved["store"],
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )


def query(saved, *, clock=NOW):
    lookup = (
        saved["store"].file_access_native_pair_cleanup_evidence
        if saved["protocol"] == "pair_v2"
        else saved["store"].file_access_native_cleanup_evidence
    )
    return lookup(saved["context"]["task_id"], **common(saved, clock=clock))


def put(saved, receipt, *, clock=NOW):
    method = (
        saved["store"].record_file_access_native_pair_cleanup
        if saved["protocol"] == "pair_v2"
        else saved["store"].record_file_access_native_cleanup
    )
    return method(saved["context"]["task_id"], receipt=receipt, **common(saved, clock=clock))


def native_query(saved):
    return pair_ledger.query(saved) if saved["protocol"] == "pair_v2" else legacy.query(saved)


def produce(saved, *, sink=None, **kwargs):
    result = process_fake.run(saved["source"], sink=sink, **kwargs)
    assert type(result.outcome.cleanup_receipt) is OwnedCleanupReceipt
    return result


def cleanup_document(saved, receipt):
    proof = receipt.document()
    return dict(
        schema_version="bluefire.windows-file-owned-cleanup-evidence.v1",
        protocol=saved["protocol"],
        task_id=saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        claim_digest=content_hash(saved["claim"]),
        packet_digest=proof["packet_digest"],
        receipt_utf8=receipt._raw.decode("utf-8"),
        private_packet_utf8=receipt._packet.decode("utf-8"),
    )


def append_raw(saved, document, *, digest=None):
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_owned_process_closures VALUES(?,?,?)",
            (
                saved["context"]["task_id"],
                canonical_json(document),
                digest or content_hash(document),
            ),
        )


def test_cleanup_is_explicit_separate_immutable_join_and_historical_only(saved, monkeypatch):
    initial = query(saved)
    assert initial.receipt_bytes is initial.private_packet_bytes is None
    assert initial.owned_job_cleanup == "unverified" and not initial.settled
    result = produce(saved, sink=sink_for(saved))
    receipt = result.outcome.cleanup_receipt
    joined = put(saved, receipt)
    assert joined.owned_job_cleanup == "verified" and not joined.settled
    assert not joined.independent_observation
    assert joined.receipt_bytes == receipt._raw and joined.private_packet_bytes == saved["public"]
    assert joined.native_evidence == native_query(saved)
    assert joined.native_evidence.owned_job_cleanup == "unverified"
    assert joined.native_evidence.projection.owned_job_cleanup == "unverified"
    assert not joined.native_evidence.projection.independent_observation
    assert b"BFWFBEG" not in joined.receipt_bytes + joined.private_packet_bytes
    with pytest.raises(FrozenInstanceError):
        joined.receipt_bytes = b"changed"
    with pytest.raises((AttributeError, TypeError)):
        joined.owned_job_cleanup = "unverified"
    assert joined.owned_job_cleanup == "verified"
    calls = list(result.containment.calls)

    def forbidden(*_, **__):
        raise AssertionError("historical validation cannot mint a supervisor receipt")

    monkeypatch.setattr(OwnedCleanupReceipt, "document", forbidden)
    saved["store"] = ProductStore(saved["path"])
    assert query(saved, clock=NOW + timedelta(days=1)) == joined
    assert result.containment.calls == calls and len(result.buffers) == 1
    assert not any(result.buffers[0]) and len(result.process.stdin.writes) == 2


@pytest.mark.parametrize("failed_stage", ["packet", "ready", "terminal"])
def test_physical_cleanup_after_storage_failure_never_fabricates_missing_public_stages(
    saved, failed_stage
):
    sink = sink_for(saved)

    def refused(stage, *arguments):
        if stage == failed_stage:
            raise ProductStoreError("synthetic storage refusal")
        sink(stage, *arguments)

    result = produce(saved, sink=refused)
    assert result.outcome.projection is None and result.outcome.issue == "evidence_refused"
    joined = put(saved, result.outcome.cleanup_receipt)
    trail = joined.native_evidence
    assert joined.owned_job_cleanup == "verified" and not joined.settled
    assert trail.terminal_bytes is trail.projection is None
    assert (trail.packet_bytes is None) is (failed_stage == "packet")
    assert (trail.ready_bytes is None) is (failed_stage != "terminal")
    assert (
        len(result.process.stdin.writes) == {"packet": 0, "ready": 1, "terminal": 2}[failed_stage]
    )
    assert not trail.settled and trail.owned_job_cleanup == "unverified"
    with saved["store"]._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[
            0
        ] == ({"packet": 0, "ready": 1, "terminal": 2}[failed_stage])


def test_before_capture_closure_does_not_invent_generation_or_begin(saved):
    cancel = threading.Event()
    cancel.set()
    result = produce(saved, cancellation=cancel)
    proof = result.outcome.cleanup_receipt.document()
    assert not proof["child_generation_captured"] and not proof["begin_attempted"]
    joined = put(saved, result.outcome.cleanup_receipt)
    assert joined.owned_job_cleanup == "verified" and joined.native_evidence.packet_bytes is None
    assert joined.native_evidence.projection is None and not joined.settled


def test_unknown_native_outcome_stays_unknown_after_verified_physical_cleanup(saved):
    source = copy.copy(saved["source"])
    if saved["protocol"] == "pair_v2":
        _, source.terminal = process_fake.pair_process.partial(
            wire.validate_pair_retained_packet(source.original, source.packet._raw)
        )
    else:
        _, source.terminal = legacy.envelopes(
            wire.validate_retained_packet(source.original, source.packet._raw), "unknown"
        )
    process = process_fake.fake.Process(
        canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal), 4
    )
    result = process_fake.run(source, process=process, sink=sink_for(saved))
    joined = put(saved, result.outcome.cleanup_receipt)
    assert joined.owned_job_cleanup == "verified"
    assert joined.native_evidence.projection.outcome == "unknown"
    assert joined.native_evidence.actual_returncode == 4
    assert not joined.native_evidence.projection.observation_complete and not joined.settled


@pytest.mark.parametrize("value", [None, True, {"cleanup": "verified"}, b"{}"])
def test_record_requires_exact_producer_receipt_not_caller_assertions(saved, value):
    with pytest.raises(ProductStoreError) as error:
        put(saved, value)
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert query(saved).owned_job_cleanup == "unverified"


def test_explicit_wrong_protocol_record_and_query_never_upgrade_original(saved):
    receipt = produce(saved).outcome.cleanup_receipt
    store = saved["store"]
    record = (
        store.record_file_access_native_cleanup
        if saved["protocol"] == "pair_v2"
        else store.record_file_access_native_pair_cleanup
    )
    lookup = (
        store.file_access_native_cleanup_evidence
        if saved["protocol"] == "pair_v2"
        else store.file_access_native_pair_cleanup_evidence
    )
    with pytest.raises(ProductStoreError):
        record(saved["context"]["task_id"], receipt=receipt, **common(saved))
    with pytest.raises(ProductStoreError):
        lookup(saved["context"]["task_id"], **common(saved))
    assert query(saved).receipt_bytes is None


@pytest.mark.parametrize("fault", ["missing", "transport", "binding"])
def test_cleanup_exact_original_identity_and_binding_are_required(saved, fault):
    receipt = produce(saved).outcome.cleanup_receipt
    arguments = common(saved)
    task = saved["context"]["task_id"]
    if fault == "missing":
        task = "execute-" + "0" * 64
    elif fault == "transport":
        arguments["transport_request_hash"] = "sha256:" + "0" * 64
    else:
        arguments["expected_binding"] = copy.deepcopy(saved["expected"])
        arguments["expected_binding"]["control_revision"] += 1
    method = (
        saved["store"].record_file_access_native_pair_cleanup
        if saved["protocol"] == "pair_v2"
        else saved["store"].record_file_access_native_cleanup
    )
    with pytest.raises(ProductStoreError):
        method(task, receipt=receipt, **arguments)
    assert query(saved).receipt_bytes is None


@pytest.mark.parametrize("fault", ["generation", "begin", "exit", "exit_null", "packet"])
def test_terminal_join_requires_same_exact_packet_capture_begin_and_whole_exit(saved, fault):
    good = produce(saved, sink=sink_for(saved))
    receipt = good.outcome.cleanup_receipt
    if fault == "generation":
        cancel = threading.Event()
        cancel.set()
        receipt = produce(saved, cancellation=cancel).outcome.cleanup_receipt
    elif fault == "begin":

        def refused(stage, *_):
            if stage == "ready":
                raise ProductStoreError("synthetic no Begin")

        receipt = produce(saved, sink=refused).outcome.cleanup_receipt
    elif fault in ("exit", "exit_null"):
        process = process_fake.fake.Process(
            saved["ready"], saved["terminal"], 4 if fault == "exit" else 1
        )
        receipt = produce(saved, process=process).outcome.cleanup_receipt
    else:
        source = copy.copy(saved["source"])
        source.packet = replace(
            source.packet, _raw=json.dumps(json.loads(source.packet._raw), indent=1).encode("utf-8")
        )
        receipt = process_fake.run(source).outcome.cleanup_receipt
    with pytest.raises(ProductStoreError):
        put(saved, receipt)
    assert query(saved).receipt_bytes is None
    assert native_query(saved).projection.observation_complete


def test_closure_observed_after_read_expiry_is_not_a_new_read_deadline(saved, monkeypatch):
    result = produce(saved)
    document = cleanup_document(saved, result.outcome.cleanup_receipt)
    proof = json.loads(document["receipt_utf8"])
    proof["observed_at"] = (
        (NOW + timedelta(seconds=6)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    document["receipt_utf8"] = canonical_json_bytes(proof).decode("utf-8")
    append_raw(saved, document)
    with pytest.raises(ProductStoreError):
        query(saved)
    later = NOW + timedelta(days=1)
    joined = query(saved, clock=later)
    assert joined.owned_job_cleanup == "verified" and joined.native_evidence.packet_bytes is None
    assert proof["original_expires_at"] == "2026-10-12T12:00:05Z"
    with pytest.raises(wire.NativeWireError):
        (wire.pair_public_frame if saved["protocol"] == "pair_v2" else wire.public_frame)(
            saved["source"].packet, clock=later, monotonic_now=106
        )


def test_exact_retry_revalidates_full_chain_and_future_clock(saved):
    result = produce(saved, sink=sink_for(saved))
    receipt = result.outcome.cleanup_receipt
    expected = put(saved, receipt)
    assert put(saved, receipt, clock=NOW + timedelta(days=1)) == expected
    with pytest.raises(ProductStoreError):
        put(saved, receipt, clock=NOW - timedelta(seconds=1))
    with pytest.raises(ProductStoreError):
        query(saved, clock=NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "protocol",
        "claim",
        "packet",
        "extra",
        "receipt_extra",
        "bool_exit",
        "settled",
        "digest",
        "gap",
    ],
)
def test_cleanup_query_rejects_corruption_without_minting_trust(saved, fault):
    receipt = produce(saved).outcome.cleanup_receipt
    document = cleanup_document(saved, receipt)
    digest = None
    if fault == "schema":
        document["schema_version"] = "other"
    elif fault == "protocol":
        document["protocol"] = "reader_v1" if saved["protocol"] == "pair_v2" else "pair_v2"
    elif fault in ("claim", "packet"):
        document[fault + "_digest"] = "sha256:" + "0" * 64
    elif fault == "extra":
        document["unexpected"] = True
    elif fault in ("receipt_extra", "bool_exit", "settled"):
        proof = json.loads(document["receipt_utf8"])
        proof[
            {
                "receipt_extra": "unexpected",
                "bool_exit": "supported_terminal_returncode",
                "settled": "settled",
            }[fault]
        ] = True
        document["receipt_utf8"] = canonical_json_bytes(proof).decode("utf-8")
    elif fault == "digest":
        digest = "sha256:" + "0" * 64
    else:
        fake_row = {"schema_version": "corrupt"}
        legacy.append_raw(saved, "ready", fake_row)
    append_raw(saved, document, digest=digest)
    for attempt in (lambda: query(saved), lambda: put(saved, receipt)):
        with pytest.raises(ProductStoreError):
            attempt()


@pytest.mark.parametrize("fault", ["row", "receipt", "packet", "utf8", "duplicate", "begin"])
def test_cleanup_text_is_bounded_before_decode_and_no_private_frames_are_stored(
    saved, monkeypatch, fault
):
    receipt = produce(saved).outcome.cleanup_receipt
    document = cleanup_document(saved, receipt)
    if fault == "row":
        document["receipt_utf8"] = "x" * (evidence._ROW_MAX + 1)
    elif fault == "receipt":
        document["receipt_utf8"] = "x" * 4097
    elif fault == "packet":
        document["private_packet_utf8"] = "x" * (wire.PUBLIC_MAX + 1)
    elif fault == "utf8":
        document["receipt_utf8"] = "\ud800"
    elif fault == "duplicate":
        document["receipt_utf8"] = '{"cleanup":"verified",' + document["receipt_utf8"][1:]
    else:
        document["private_packet_utf8"] = "BFWFBEG2" + "synthetic-private-frame"
    if fault == "utf8":
        # A JSON escape models malformed decoded UTF-8 without storing invalid SQL text.
        encoded = json.dumps(document, ensure_ascii=True)
        with saved["store"]._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO file_access_owned_process_closures VALUES(?,?,?)",
                (saved["context"]["task_id"], encoded, "sha256:" + "0" * 64),
            )
    else:
        append_raw(saved, document)
    observed = []
    original = evidence._row_document

    def spy(row, maximum):
        observed.append(row["document_json"])
        return original(row, maximum)

    monkeypatch.setattr(evidence, "_row_document", spy)
    with pytest.raises(ProductStoreError):
        query(saved)
    if fault == "row":
        assert observed[-1] is None


def test_write_rechecks_claim_in_same_transaction_and_does_not_call_os_cleanup(saved, monkeypatch):
    result = produce(saved)
    receipt = result.outcome.cleanup_receipt
    calls = list(result.containment.calls)
    real = evidence._recheck

    def drift(connection, context):
        assert connection.in_transaction
        real(connection, replace(context, claim_digest="sha256:" + "0" * 64))

    monkeypatch.setattr(evidence, "_recheck", drift)
    with pytest.raises(ProductStoreError):
        put(saved, receipt)
    assert result.containment.calls == calls


def test_storage_failure_retains_positive_receipt_without_false_os_cleanup_unknown(
    saved, monkeypatch
):
    result = produce(saved)
    receipt = result.outcome.cleanup_receipt
    real = evidence._cleanup_load

    def failure(*_, **__):
        raise sqlite3.OperationalError("synthetic storage failure")

    monkeypatch.setattr(evidence, "_cleanup_load", failure)
    with pytest.raises(ProductStoreError):
        put(saved, receipt)
    assert result.outcome.cleanup == "verified" and result.outcome.cleanup_receipt is receipt
    monkeypatch.setattr(evidence, "_cleanup_load", real)
    assert put(saved, receipt).owned_job_cleanup == "verified"


@pytest.mark.parametrize("conflicting", [False, True])
def test_two_store_instances_race_exact_or_conflicting_cleanup_without_partial_rows(
    saved, conflicting
):
    receipt = produce(saved).outcome.cleanup_receipt
    other = receipt
    if conflicting:
        cancel = threading.Event()
        cancel.set()
        other = produce(saved, cancellation=cancel).outcome.cleanup_receipt
    targets = (saved, {**saved, "store": ProductStore(saved["path"])})
    start = threading.Event()
    results, failures = [], []

    def save(target, value):
        try:
            assert start.wait(2)
            results.append(put(target, value))
        except Exception as error:
            failures.append(error)

    threads = [
        threading.Thread(target=save, args=(target, value))
        for target, value in zip(targets, (receipt, other), strict=True)
    ]
    try:
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(10)
        assert not any(thread.is_alive() for thread in threads)
    finally:
        start.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(10)
    assert len(results) == (1 if conflicting else 2)
    assert len(failures) == (1 if conflicting else 0)
    assert all(type(error) is ProductStoreError for error in failures)
    assert query(saved).owned_job_cleanup == "verified"
    with saved["store"]._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_access_owned_process_closures"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 0
        )


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_new_table_remains_append_only_on_reopen(saved, operation):
    receipt = produce(saved).outcome.cleanup_receipt
    expected = put(saved, receipt)
    saved["store"] = ProductStore(saved["path"])
    sql = (
        "UPDATE file_access_owned_process_closures SET document_digest='changed'"
        if operation == "UPDATE"
        else "DELETE FROM file_access_owned_process_closures"
    )
    with (
        pytest.raises(sqlite3.IntegrityError),
        saved["store"]._connection(write=True) as connection,
    ):
        connection.execute(sql)
    assert query(saved) == expected


def test_compatible_native_persistence_retry_after_cleanup_does_not_dispatch_again(saved):
    result = produce(saved)
    receipt = result.outcome.cleanup_receipt
    put(saved, receipt)
    assert native_query(saved).packet_bytes is None
    sink = sink_for(saved)
    later = NOW + timedelta(days=1)
    calls = list(result.containment.calls)
    for stage, payload, code in (
        ("packet", saved["public"], None),
        ("ready", saved["ready"], None),
        ("terminal", saved["terminal"], 0),
    ):
        sink(stage, payload, code, later)
        sink(stage, payload, code, later)
    joined = query(saved, clock=later)
    assert joined.owned_job_cleanup == "verified" and not joined.settled
    assert joined.native_evidence.projection.observation_complete
    assert joined.native_evidence.owned_job_cleanup == "unverified"
    assert result.containment.calls == calls and len(result.buffers) == 1


@pytest.mark.parametrize("fault", ["packet", "generation", "begin", "exit"])
def test_native_append_after_cleanup_rolls_back_inconsistent_join(saved, fault):
    if fault == "generation":
        cancel = threading.Event()
        cancel.set()
        receipt = produce(saved, cancellation=cancel).outcome.cleanup_receipt
    elif fault == "begin":

        def refused(stage, *_):
            if stage == "ready":
                raise ProductStoreError("synthetic before Begin")

        receipt = produce(saved, sink=refused).outcome.cleanup_receipt
    elif fault == "exit":
        receipt = produce(
            saved, process=process_fake.fake.Process(saved["ready"], saved["terminal"], 4)
        ).outcome.cleanup_receipt
    else:
        receipt = produce(saved).outcome.cleanup_receipt
    put(saved, receipt)
    sink = sink_for(saved)
    if fault == "packet":
        data = json.dumps(json.loads(saved["public"]), indent=1).encode("utf-8")
        with pytest.raises(ProductStoreError):
            sink("packet", data, None, NOW)
        assert native_query(saved).packet_bytes is None
    else:
        sink("packet", saved["public"], None, NOW)
        sink("ready", saved["ready"], None, NOW)
        with pytest.raises(ProductStoreError):
            sink("terminal", saved["terminal"], 0, NOW)
        assert native_query(saved).terminal_bytes is None
    assert query(saved).owned_job_cleanup == "verified"


def test_native_exact_repeat_also_refuses_corrupt_saved_cleanup(saved):
    result = produce(saved, sink=sink_for(saved))
    document = cleanup_document(saved, result.outcome.cleanup_receipt)
    document["claim_digest"] = "sha256:" + "0" * 64
    append_raw(saved, document)
    with pytest.raises(ProductStoreError):
        sink_for(saved)("packet", saved["public"], None, NOW)


@pytest.mark.parametrize("compatible", [False, True])
def test_cleanup_and_terminal_race_validate_join_before_commit(saved, compatible):
    sink = sink_for(saved)
    sink("packet", saved["public"], None, NOW)
    sink("ready", saved["ready"], None, NOW)
    if compatible:
        receipt = produce(saved).outcome.cleanup_receipt
    else:
        receipt = produce(
            saved, process=process_fake.fake.Process(saved["ready"], saved["terminal"], 4)
        ).outcome.cleanup_receipt
    alternate = {**saved, "store": ProductStore(saved["path"])}
    start = threading.Event()
    results, failures = [], []

    def save_cleanup():
        try:
            assert start.wait(2)
            results.append(("cleanup", put(alternate, receipt)))
        except Exception as error:
            failures.append(error)

    def save_terminal():
        try:
            assert start.wait(2)
            sink("terminal", saved["terminal"], 0, NOW)
            results.append(("terminal", None))
        except Exception as error:
            failures.append(error)

    threads = [threading.Thread(target=save_cleanup), threading.Thread(target=save_terminal)]
    try:
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(10)
        assert not any(thread.is_alive() for thread in threads)
    finally:
        start.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(10)
    assert len(results) == (2 if compatible else 1)
    assert len(failures) == (0 if compatible else 1)
    assert all(type(error) is ProductStoreError for error in failures)
    joined = query(saved)
    assert not joined.settled and not joined.independent_observation
    if compatible:
        assert joined.owned_job_cleanup == "verified" and joined.native_evidence.terminal_bytes
    else:
        assert (joined.receipt_bytes is not None) != (
            joined.native_evidence.terminal_bytes is not None
        )


@pytest.mark.parametrize(
    "fault",
    [
        "receipt_half",
        "packet_half",
        "empty_receipt",
        "empty_packet",
        "mutable_receipt",
        "private_frame",
        "wrong_type",
        "wrong_task",
        "wrong_protocol",
    ],
)
def test_cleanup_snapshot_rejects_impossible_consistency_states_without_creating_authority(
    saved, fault
):
    receipt = produce(saved).outcome.cleanup_receipt
    native = native_query(saved)
    receipt_bytes, packet = receipt._raw, receipt._packet
    if fault == "receipt_half":
        packet = None
    elif fault == "packet_half":
        receipt_bytes = None
    elif fault == "empty_receipt":
        receipt_bytes = b""
    elif fault == "empty_packet":
        packet = b""
    elif fault == "mutable_receipt":
        receipt_bytes = bytearray(receipt_bytes)
    elif fault == "private_frame":
        packet = b"BFWFBEG2synthetic-private"
    elif fault == "wrong_type":
        native = object()
    elif fault == "wrong_task":
        native = replace(
            native, task_id="execute-" + "0" * 64, transport_request_hash="sha256:" + "0" * 64
        )
    else:
        opposite = (
            evidence.NativeTaskEvidence
            if saved["protocol"] == "pair_v2"
            else evidence.PairNativeTaskEvidence
        )
        native = opposite(
            native.task_id,
            native.transport_request_hash,
            native.claim_digest,
            None,
            None,
            None,
            None,
            None,
        )
    with pytest.raises(ValueError):
        evidence.NativeCleanupEvidence(native, receipt_bytes, packet)
    assert native_query(saved).owned_job_cleanup == "unverified"
