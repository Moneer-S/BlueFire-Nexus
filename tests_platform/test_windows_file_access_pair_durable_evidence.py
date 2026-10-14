"""Real SQLite with synthetic admitted-claim fixtures, never Windows admission."""

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
from bluefire import windows_file_access_process as supervisor
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_file_access_native_evidence as legacy
from tests_platform import test_windows_file_access_pair_process as process_fake
from tests_platform import test_windows_file_access_pair_wire as pair
from tests_platform.test_windows_file_access_native_wire import NOW


def packet_bytes(context):
    return canonical_json_bytes(
        {
            "schema_version": "bluefire.windows-file-worker-request.v2",
            "challenge": "f" * 64,
            "task_id": context["task_id"],
            "request_hash": context["transport_request_hash"],
            "manifest": context["manifest"],
            "profile": context["profile"],
            "remaining_ms": 4000,
        }
    )


def seeded(path, context=None, expected=None, **claim_options):
    if context is None:
        context, expected = pair.fixture()
    store = ProductStore(path)
    # The shared SQL fixture bypasses production admission intentionally. It
    # inserts an original claim without weakening any append-only trigger.
    claim = legacy.insert_claim(store, context, **claim_options)
    public = packet_bytes(context)
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    retained = wire.validate_pair_retained_packet(original, public)
    ready, terminal = pair.envelopes(retained)
    return dict(
        store=store,
        path=path,
        context=context,
        expected=expected,
        claim=claim,
        public=public,
        ready=canonical_json_bytes(ready),
        terminal=canonical_json_bytes(terminal),
        original=original,
        retained=retained,
    )


@pytest.fixture
def saved(tmp_path):
    return seeded(tmp_path / "pair-evidence.db")


@pytest.fixture
def setup(monkeypatch):
    return process_fake.setup.__wrapped__(monkeypatch)


def common(saved, *, clock=NOW):
    return dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        clock=clock,
    )


def sink_for(saved):
    return evidence.native_pair_evidence_sink(
        saved["store"],
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )


def put(saved, stage, *, data=None, code=0, clock=NOW):
    task, store = saved["context"]["task_id"], saved["store"]
    if stage == "packet":
        return store.record_file_access_native_pair_packet(
            task,
            public_bytes=saved["public"] if data is None else data,
            **common(saved, clock=clock),
        )
    if stage == "ready":
        return store.record_file_access_native_pair_ready(
            task, ready_bytes=saved["ready"] if data is None else data, **common(saved, clock=clock)
        )
    return store.record_file_access_native_pair_terminal(
        task,
        terminal_bytes=saved["terminal"] if data is None else data,
        actual_returncode=code,
        **common(saved, clock=clock),
    )


def query(saved, *, clock=NOW):
    return saved["store"].file_access_native_pair_evidence(
        saved["context"]["task_id"], **common(saved, clock=clock)
    )


def packet_document(saved):
    return dict(
        schema_version="bluefire.windows-file-pair-task-evidence.v2",
        task_id=saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        claim_digest=content_hash(saved["claim"]),
        stage="packet",
        packet_digest=wire._binding(saved["retained"])["packet_digest"],
        previous_digest=None,
        payload_utf8=saved["public"].decode("utf-8"),
        actual_returncode=None,
    )


@pytest.mark.parametrize("reader", ["allowed", "data_access_denied", "partial", "error", "late"])
def test_fake_supervisor_pair_trail_reopens_after_expiry_without_replay_or_job_claim(
    saved, setup, monkeypatch, reader
):
    ready, terminal = pair.envelopes(
        saved["retained"], "data_access_denied" if reader == "data_access_denied" else "allowed"
    )
    code = 0
    if reader == "partial":
        ready, terminal = process_fake.partial(saved["retained"])
        code = 4
    elif reader == "error":
        terminal["observed_at"] = None
        terminal["result"] = {
            "schema_version": "bluefire.windows-file-worker-error.v2",
            "code": "native_failed",
            "possible_effects": True,
        }
        code = 4
    elif reader == "late":
        terminal["observed_at"] = None
        terminal["result"].update(outcome="unknown", issue="deadline", failed_stage="complete")
        code = 4
    data = canonical_json_bytes(terminal)
    sink = sink_for(saved)
    process = process_fake.fake.Process(canonical_json_bytes(ready), data, code)
    result, process, containment, _, buffers, admissions = process_fake.run(
        setup, process=process, sink=sink
    )
    assert result.cleanup == "verified" and not result.settled
    assert result.projection.observation_complete is (code == 0)
    assert result.issue == (None if code == 0 else "worker_failed")
    snapshot = query(saved)
    assert type(snapshot) is evidence.PairNativeTaskEvidence
    assert type(snapshot.projection) is wire.PairNativeProjection
    assert snapshot.packet_bytes == saved["public"] and snapshot.terminal_bytes == data
    assert snapshot.actual_returncode == code and not snapshot.settled
    assert snapshot.owned_job_cleanup == snapshot.projection.owned_job_cleanup == "unverified"
    assert snapshot.projection.reader_outcome == (
        None
        if reader == "error"
        else "data_access_denied" if reader == "data_access_denied" else "allowed"
    )
    assert not snapshot.projection.independent_observation
    with pytest.raises(FrozenInstanceError):
        snapshot.owned_job_cleanup = "verified"
    calls = list(containment.calls)

    def forbidden(*_, **__):
        raise AssertionError("historical query must never dispatch")

    monkeypatch.setattr(supervisor, "supervise_pair_suspended", forbidden)
    saved["store"] = ProductStore(saved["path"])
    assert query(saved, clock=NOW + timedelta(days=1)) == snapshot
    assert containment.calls == calls and len(admissions) == 3 and len(buffers) == 1
    assert not any(buffers[0]) and len(process.stdin.writes) == 2
    for stage in ("packet", "ready", "terminal"):
        assert (
            put(
                saved,
                stage,
                data=data if stage == "terminal" else None,
                code=code,
                clock=NOW + timedelta(days=1),
            )
            == snapshot
        )


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
def test_pair_storage_failure_prevents_begin_or_keeps_partial_unknown(
    saved, setup, monkeypatch, stage
):
    original_record = evidence.record

    def refuse(store, task, transport, binding, observed, data, code, clock, **kwargs):
        if stage == observed:
            raise ProductStoreError("synthetic storage failure")
        return original_record(
            store, task, transport, binding, observed, data, code, clock, **kwargs
        )

    sink = sink_for(saved)
    monkeypatch.setattr(evidence, "record", refuse)
    result, process, _, _, buffers, _ = process_fake.run(setup, sink=sink)
    snapshot = query(saved)
    assert result.projection is None and result.issue == "evidence_refused"
    assert result.cleanup == "verified" and not result.settled
    assert snapshot.terminal_bytes is snapshot.projection is None
    assert snapshot.owned_job_cleanup == "unverified"
    assert len(process.stdin.writes) == {"packet": 0, "ready": 1, "terminal": 2}[stage]
    assert len(buffers) == (1 if stage == "terminal" else 0)
    assert result.dispatch == ("unknown" if stage == "terminal" else "not_started")


@pytest.mark.parametrize("api", ["factory", "packet", "query"])
@pytest.mark.parametrize("pair_claim", [False, True])
def test_wrong_version_api_refuses_original_claim_without_rows(saved, tmp_path, api, pair_claim):
    if pair_claim:
        target = saved
        factory = evidence.native_evidence_sink
        record = target["store"].record_file_access_native_packet
        lookup = target["store"].file_access_native_evidence
    else:
        context, expected = pair.v1.fixture()
        store = ProductStore(tmp_path / "v1.db")
        legacy.insert_claim(store, context)
        target = dict(
            store=store, context=context, expected=expected, public=legacy.public_packet(context)
        )
        factory = evidence.native_pair_evidence_sink
        record = store.record_file_access_native_pair_packet
        lookup = store.file_access_native_pair_evidence
    task = target["context"]["task_id"]
    with pytest.raises(ProductStoreError):
        if api == "factory":
            factory(
                target["store"],
                task,
                transport_request_hash=target["context"]["transport_request_hash"],
                expected_binding=target["expected"],
            )
        elif api == "packet":
            record(task, public_bytes=target["public"], **common(target))
        else:
            lookup(task, **common(target))
    with target["store"]._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 0
        )


@pytest.mark.parametrize("fault", ["schema", "unknown", "previous", "digest", "stage", "gap"])
def test_pair_query_and_earlier_retry_reject_corrupt_or_wrong_version_chain(saved, fault):
    document = packet_document(saved)
    stage = "packet"
    override = None
    if fault == "schema":
        document["schema_version"] = "bluefire.windows-file-task-evidence.v1"
    elif fault == "unknown":
        document["unexpected"] = True
    elif fault == "previous":
        document["previous_digest"] = "sha256:" + "0" * 64
    elif fault == "digest":
        override = "sha256:" + "0" * 64
    elif fault == "stage":
        stage = "closure"
        document["stage"] = stage
    else:
        stage = "ready"
        document["stage"] = stage
        document["payload_utf8"] = saved["ready"].decode("utf-8")
    legacy.append_raw(saved, stage, document, digest_override=override)
    for call in (lambda: query(saved), lambda: put(saved, "packet")):
        with pytest.raises(ProductStoreError) as error:
            call()
        assert error.value.__cause__ is None and error.value.__suppress_context__


@pytest.mark.parametrize("stage", ["ready", "terminal"])
def test_pair_predecessor_is_required(saved, stage):
    with pytest.raises(ProductStoreError):
        put(saved, stage)
    assert query(saved).packet_bytes is None


@pytest.mark.parametrize("fault", ["missing", "hash", "binding", "claim_digest", "oversized"])
def test_pair_factory_refuses_wrong_original_before_resource_transfer(saved, tmp_path, fault):
    task = saved["context"]["task_id"]
    transport = saved["context"]["transport_request_hash"]
    binding = copy.deepcopy(saved["expected"])
    if fault == "missing":
        task = "execute-" + "0" * 64
    elif fault == "hash":
        transport = "sha256:" + "0" * 64
    elif fault == "binding":
        binding["control_revision"] += 1
    else:
        options = (
            {"digest_override": "sha256:" + "0" * 64}
            if fault == "claim_digest"
            else {"oversized": True}
        )
        saved = seeded(tmp_path / "bad-claim.db", **options)
    with pytest.raises(ProductStoreError):
        evidence.native_pair_evidence_sink(
            saved["store"], task, transport_request_hash=transport, expected_binding=binding
        )


def test_pair_factory_captures_original_binding_bytes_and_claim_recheck_is_transactional(
    saved, monkeypatch
):
    sink = sink_for(saved)
    expected = copy.deepcopy(saved["expected"])
    saved["expected"]["generation"] = "0" * 32
    saved["expected"]["host"]["channel_digest"] = "sha256:" + "0" * 64
    sink("packet", saved["public"], None, NOW)
    saved["expected"] = expected
    assert query(saved).packet_bytes == saved["public"]
    recheck = evidence._recheck
    seen = []

    def changed(connection, context):
        assert connection.in_transaction
        seen.append(True)
        recheck(connection, replace(context, claim_digest="sha256:" + "0" * 64))

    monkeypatch.setattr(evidence, "_recheck", changed)
    with pytest.raises(ProductStoreError):
        sink("ready", saved["ready"], None, NOW)
    assert seen == [True]
    with saved["store"]._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 1
        )


@pytest.mark.parametrize("partial,code", [(False, 4), (True, 0), (False, True)])
def test_pair_terminal_requires_actual_whole_exit_and_never_fabricates_phase_exit(
    saved, partial, code
):
    ready, terminal = (
        process_fake.partial(saved["retained"]) if partial else pair.envelopes(saved["retained"])
    )
    put(saved, "packet")
    put(saved, "ready", data=canonical_json_bytes(ready))
    with pytest.raises(ProductStoreError):
        put(saved, "terminal", data=canonical_json_bytes(terminal), code=code)
    assert query(saved).terminal_bytes is None


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
@pytest.mark.parametrize("fault", ["oversized", "utf16", "duplicate", "trailing"])
def test_pair_public_bytes_are_bounded_strict_and_never_private(saved, stage, fault):
    if stage != "packet":
        put(saved, "packet")
    if stage == "terminal":
        put(saved, "ready")
    data = saved["public" if stage == "packet" else stage]
    if fault == "oversized":
        data = b"{" + b" " * evidence._MAXIMUM[stage]
    elif fault == "utf16":
        data = data.decode("utf-8").encode("utf-16")
    elif fault == "duplicate":
        data = b'{"schema_version":"duplicate",' + data[1:]
    else:
        data += b"\0"
    with pytest.raises(ProductStoreError):
        put(saved, stage, data=data)


def test_pair_snapshot_exact_projection_class_does_not_relax_v1(saved):
    put(saved, "packet")
    put(saved, "ready")
    result = put(saved, "terminal")
    arguments = (
        result.task_id,
        result.transport_request_hash,
        result.claim_digest,
        result.packet_bytes,
        result.ready_bytes,
        result.terminal_bytes,
        result.actual_returncode,
    )
    with pytest.raises(ValueError):
        evidence.NativeTaskEvidence(*arguments, result.projection)
    projection = wire.NativeProjection(result.projection._terminal, "allowed", True, "verified")
    with pytest.raises(ValueError):
        evidence.PairNativeTaskEvidence(*arguments, projection)


@pytest.mark.parametrize("conflicting", [False, True])
def test_pair_two_store_writers_preserve_exact_immutable_bytes(saved, conflicting):
    second = (
        json.dumps(json.loads(saved["public"]), indent=1).encode("utf-8")
        if conflicting
        else saved["public"]
    )
    stores = (saved["store"], ProductStore(saved["path"]))
    start = threading.Event()
    results, failures = [], []

    def write(store, data):
        try:
            assert start.wait(2)
            results.append(
                store.record_file_access_native_pair_packet(
                    saved["context"]["task_id"], public_bytes=data, **common(saved)
                )
            )
        except Exception as error:
            failures.append(error)

    threads = [
        threading.Thread(target=write, args=(store, data))
        for store, data in zip(stores, (saved["public"], second), strict=True)
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
    snapshot = query(saved)
    assert snapshot.packet_bytes in (saved["public"], second)
    assert snapshot.ready_bytes is snapshot.terminal_bytes is None


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE file_access_task_evidence SET stage='ready'",
        "DELETE FROM file_access_task_evidence",
        "UPDATE file_access_task_claims SET document_digest='changed'",
    ],
)
def test_pair_existing_append_only_guards_remain_enabled(saved, sql):
    put(saved, "packet")
    with (
        pytest.raises(sqlite3.IntegrityError),
        saved["store"]._connection(write=True) as connection,
    ):
        connection.execute(sql)
    assert query(saved).packet_bytes == saved["public"]


def test_pair_packet_full_identity_high_bits_and_metadata_are_not_upgraded(saved, tmp_path):
    context, expected = pair.fixture()
    identity = {"volume_serial": "fedcba9876543210", "file_id": "fedcba98765432100123456789abcdef"}
    context["manifest"]["params"]["windows_file_read_request"]["resource"][
        "file_identity"
    ] = identity
    expected["resource"]["file_identity"] = copy.deepcopy(identity)
    pair.v1.reseal(context)
    changed = seeded(tmp_path / "high-bits.db", context, expected)
    result = put(changed, "packet")
    row = json.loads(result.packet_bytes)
    assert (
        row["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"]
        == identity
    )
    assert not result.settled and result.owned_job_cleanup == "unverified"
    assert query(changed, clock=NOW + timedelta(days=1)) == result


@pytest.mark.parametrize("pair_claim", [False, True])
def test_bounded_claim_read_never_calls_unbounded_historical_lookup(
    tmp_path, monkeypatch, pair_claim
):
    target = seeded(tmp_path / "pair.db") if pair_claim else legacy.saved.__wrapped__(tmp_path)
    calls = []

    def formerly_unbounded(*_, **__):
        # Simulate the old second lookup observing a larger, changed claim.
        # The replacement must not invoke or decode this second observation.
        calls.append(True)
        return {"task": {"unexpected": "x" * (evidence._CLAIM_MAX + 1)}}

    monkeypatch.setattr(target["store"], "file_access_task_record", formerly_unbounded)
    if pair_claim:
        sink = sink_for(target)
        sink("packet", target["public"], None, NOW)
        assert query(target).packet_bytes == target["public"]
    else:
        sink = evidence.native_evidence_sink(
            target["store"],
            target["context"]["task_id"],
            transport_request_hash=target["context"]["transport_request_hash"],
            expected_binding=target["expected"],
        )
        sink("packet", target["public"], None, NOW)
        assert legacy.query(target).packet_bytes == target["public"]
    assert calls == []


@pytest.mark.parametrize("pair_claim", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        "row_task",
        "row_job",
        "row_step",
        "row_request",
        "claim_request",
        "claim_step",
        "claim_job",
        "claim_transport",
    ],
)
def test_bounded_original_read_retains_all_sql_and_manifest_column_guards(
    tmp_path, pair_claim, fault
):
    context, expected = pair.fixture() if pair_claim else pair.v1.fixture()
    store = ProductStore(tmp_path / "mismatched-original.db")
    manifest = context["manifest"]
    claim = {
        "job_id": manifest["run_id"],
        "task_id": context["task_id"],
        "step_id": manifest["step_id"],
        "request_hash": manifest["request_hash"],
        "transport_request_hash": context["transport_request_hash"],
        "manifest": manifest,
        "runner_profile": context["profile"],
    }
    columns = {key: claim[key] for key in ("task_id", "job_id", "step_id", "request_hash")}
    names = {
        "task": "task_id",
        "job": "job_id",
        "step": "step_id",
        "request": "request_hash",
        "transport": "transport_request_hash",
    }
    where, short = fault.split("_")
    field = names[short]
    replacement = (
        "execute-" + "0" * 64
        if short == "task"
        else (
            "sha256:" + "0" * 64
            if short in ("request", "transport")
            else "synthetic-different-" + short
        )
    )
    (columns if where == "row" else claim)[field] = replacement
    with store._connection(write=True) as connection:
        for job in {manifest["run_id"], columns["job_id"]}:
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
                "VALUES(?,'file_access.operation','queued','{}','{}',?,?)",
                (job, NOW.isoformat(), NOW.isoformat()),
            )
            operation = {"schema_version": "synthetic.native-original-fixture.v1"}
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (
                    job,
                    job,
                    "synthetic-enrollment",
                    "baseline",
                    canonical_json(operation),
                    content_hash(operation),
                ),
            )
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                columns["task_id"],
                columns["job_id"],
                columns["step_id"],
                columns["request_hash"],
                canonical_json(claim),
                content_hash(claim),
            ),
        )
    factory = evidence.native_pair_evidence_sink if pair_claim else evidence.native_evidence_sink
    with pytest.raises(ProductStoreError):
        factory(
            store,
            columns["task_id"],
            transport_request_hash=context["transport_request_hash"],
            expected_binding=expected,
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 0
        )


@pytest.mark.parametrize("pair_claim", [False, True])
def test_oversized_original_is_sql_gated_before_decode_without_second_lookup(
    tmp_path, monkeypatch, pair_claim
):
    context, expected = pair.fixture() if pair_claim else pair.v1.fixture()
    store = ProductStore(tmp_path / "oversized-original.db")
    legacy.insert_claim(store, context, oversized=True)
    observed = []
    read = evidence._row_document

    def bounded(row, maximum):
        observed.append(row["document_json"])
        return read(row, maximum)

    monkeypatch.setattr(evidence, "_row_document", bounded)

    def forbidden(*_, **__):
        raise AssertionError("no unbounded historical reread")

    monkeypatch.setattr(store, "file_access_task_record", forbidden)
    factory = evidence.native_pair_evidence_sink if pair_claim else evidence.native_evidence_sink
    with pytest.raises(ProductStoreError):
        factory(
            store,
            context["task_id"],
            transport_request_hash=context["transport_request_hash"],
            expected_binding=expected,
        )
    assert observed == [None]
