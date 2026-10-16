"""Synthetic durable claim/evidence fixtures only; no Windows admission/effects."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

from bluefire import product_store_file_access_native_evidence as evidence
from bluefire import windows_file_access_native_wire as wire
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_native_wire import NOW, envelopes, fixture, reseal


def insert_claim(store, context, *, digest_override=None, oversized=False):
    manifest = context["manifest"]
    job_id = manifest["run_id"]
    claim = {
        "job_id": job_id,
        "task_id": context["task_id"],
        "step_id": manifest["step_id"],
        "request_hash": manifest["request_hash"],
        "transport_request_hash": context["transport_request_hash"],
        "manifest": manifest,
        "runner_profile": context["profile"],
    }
    # Test-local durable fixture, deliberately NOT a Windows registration path.
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
            "VALUES(?,'file_access.operation','queued','{}','{}',?,?)",
            (job_id, NOW.isoformat(), NOW.isoformat()),
        )
        operation = {"schema_version": "synthetic.native-original-fixture.v1"}
        connection.execute(
            "INSERT OR IGNORE INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                job_id,
                job_id,
                "synthetic-enrollment",
                "baseline",
                canonical_json(operation),
                content_hash(operation),
            ),
        )
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                claim["task_id"],
                job_id,
                claim["step_id"],
                claim["request_hash"],
                canonical_json(claim) + (" " * evidence._CLAIM_MAX if oversized else ""),
                digest_override or content_hash(claim),
            ),
        )
    return claim


def public_packet(context):
    # Retained synthetic bytes, not a new preparation or renewed reservation.
    return canonical_json_bytes(
        {
            "schema_version": "bluefire.windows-file-worker-request.v1",
            "challenge": "f" * 64,
            "task_id": context["task_id"],
            "request_hash": context["transport_request_hash"],
            "manifest": context["manifest"],
            "profile": context["profile"],
            "remaining_ms": 4000,
        }
    )


@pytest.fixture
def saved(tmp_path):
    path = tmp_path / "native-evidence.db"
    store = ProductStore(path)
    context, expected = fixture()
    claim = insert_claim(store, context)
    public = public_packet(context)
    original = wire.validate_original_reservation(context, expected_binding=expected)
    ready, terminal = envelopes(wire.validate_retained_packet(original, public))
    return dict(
        store=store,
        path=path,
        context=context,
        expected=expected,
        claim=claim,
        public=public,
        ready=canonical_json_bytes(ready),
        terminal=canonical_json_bytes(terminal),
    )


def common(saved, *, clock=NOW):
    return dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        clock=clock,
    )


def put(saved, stage, *, data=None, code=0, clock=NOW):
    store, task = saved["store"], saved["context"]["task_id"]
    if stage == "packet":
        return store.record_file_access_native_packet(
            task,
            public_bytes=saved["public"] if data is None else data,
            **common(saved, clock=clock),
        )
    if stage == "ready":
        return store.record_file_access_native_ready(
            task, ready_bytes=saved["ready"] if data is None else data, **common(saved, clock=clock)
        )
    return store.record_file_access_native_terminal(
        task,
        terminal_bytes=saved["terminal"] if data is None else data,
        actual_returncode=code,
        **common(saved, clock=clock),
    )


def query(saved, *, clock=NOW):
    return saved["store"].file_access_native_evidence(
        saved["context"]["task_id"], **common(saved, clock=clock)
    )


def append_raw(saved, stage, document, *, digest_override=None):
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_evidence VALUES(?,?,?,?)",
            (
                saved["context"]["task_id"],
                stage,
                canonical_json(document),
                digest_override or content_hash(document),
            ),
        )


def packet_document(saved):
    original = wire.validate_original_reservation(
        saved["context"], expected_binding=saved["expected"]
    )
    packet = wire.validate_retained_packet(original, saved["public"])
    return {
        "schema_version": "bluefire.windows-file-task-evidence.v1",
        "task_id": saved["context"]["task_id"],
        "transport_request_hash": saved["context"]["transport_request_hash"],
        "claim_digest": content_hash(saved["claim"]),
        "stage": "packet",
        "packet_digest": wire._binding(packet)["packet_digest"],
        "previous_digest": None,
        "payload_utf8": saved["public"].decode("utf-8"),
        "actual_returncode": None,
    }


def test_partial_and_complete_snapshots_are_immutable_unsettled_public_bytes(saved):
    empty = query(saved)
    assert empty.packet_bytes is empty.ready_bytes is empty.terminal_bytes is None
    first = put(saved, "packet")
    assert first.packet_bytes == saved["public"] and first.projection is None
    second = put(saved, "ready")
    assert second.ready_bytes == saved["ready"] and second.terminal_bytes is None
    result = put(saved, "terminal")
    assert result.terminal_bytes == saved["terminal"] and result.actual_returncode == 0
    assert result.projection.outcome == "allowed" and result.projection.observation_complete
    assert not result.settled and result.owned_job_cleanup == "unverified"
    assert not result.projection.settled and result.projection.owned_job_cleanup == "unverified"
    with pytest.raises(FrozenInstanceError):
        result.packet_bytes = b"changed"
    assert query(saved) == result


def test_native_evidence_ignores_legacy_terminal_payload_while_default_lookup_validates_it(saved):
    store, context = saved["store"], saved["context"]
    payload = "{" + " " * (evidence._CLAIM_MAX + 1)
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_terminals VALUES(?,?,?)",
            (context["task_id"], payload, "sha256:" + "0" * 64),
        )
    claimed = store.file_access_task_record(
        context["task_id"], context["transport_request_hash"], include_terminal=False
    )
    assert claimed["task"] == saved["claim"] and claimed["terminal"] is None
    assert query(saved).packet_bytes is None
    assert put(saved, "packet").packet_bytes == saved["public"]
    with pytest.raises(ProductStoreError):
        store.file_access_task_record(context["task_id"], context["transport_request_hash"])


def test_stage_order_and_exact_repeats_after_terminal(saved):
    for stage in ("ready", "terminal"):
        with pytest.raises(ProductStoreError):
            put(saved, stage)
    put(saved, "packet")
    with pytest.raises(ProductStoreError):
        put(saved, "terminal")
    put(saved, "ready")
    completed = put(saved, "terminal")
    for stage in ("packet", "ready", "terminal"):
        assert put(saved, stage) == completed
    with saved["store"]._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 3
        )


@pytest.mark.parametrize("stage", ["packet", "ready", "terminal"])
def test_exact_byte_immutability_refuses_semantically_equal_reformatting(saved, stage):
    for prior in ("packet", "ready", "terminal"):
        put(saved, prior)
    source = saved["public" if stage == "packet" else stage]
    pretty = json.dumps(json.loads(source), indent=1).encode("utf-8")
    with pytest.raises(ProductStoreError):
        put(saved, stage, data=pretty)
    assert query(saved).packet_bytes == saved["public"]


def test_preserves_noncanonical_public_json_bytes_exactly(saved):
    pretty = json.dumps(json.loads(saved["public"]), indent=1).encode("utf-8")
    result = put(saved, "packet", data=pretty)
    assert result.packet_bytes == pretty and query(saved).packet_bytes == pretty


@pytest.mark.parametrize(
    "outcome,code", [("allowed", 0), ("data_access_denied", 0), ("unknown", 4)]
)
def test_historical_terminal_after_original_expiry_survives_reopen_without_replay(
    saved, outcome, code
):
    original = wire.validate_original_reservation(
        saved["context"], expected_binding=saved["expected"]
    )
    _, terminal = envelopes(wire.validate_retained_packet(original, saved["public"]), outcome)
    put(saved, "packet")
    put(saved, "ready")
    later = NOW + timedelta(days=1)
    result = put(saved, "terminal", data=canonical_json_bytes(terminal), code=code, clock=later)
    saved["store"] = ProductStore(saved["path"])
    recovered = query(saved, clock=later)
    assert recovered == result and recovered.projection.outcome == outcome
    assert recovered.projection.observation_complete is (outcome != "unknown")
    assert not recovered.settled and recovered.owned_job_cleanup == "unverified"
    assert saved["context"]["manifest"]["expires_at"] == "2026-10-12T12:00:05Z"


@pytest.mark.parametrize(
    "observed",
    ["2026-10-12T11:59:59.000000Z", "2026-10-12T12:00:05.000000Z", "2026-10-12T12:00:02.000000Z"],
)
def test_original_window_and_future_observation_refused(saved, observed):
    put(saved, "packet")
    put(saved, "ready")
    terminal = json.loads(saved["terminal"])
    terminal["observed_at"] = observed
    with pytest.raises(ProductStoreError):
        put(saved, "terminal", data=canonical_json_bytes(terminal))
    assert query(saved).terminal_bytes is None


def test_clock_rollback_rechecks_existing_terminal_even_on_earlier_repeat(saved):
    for stage in ("packet", "ready", "terminal"):
        put(saved, stage)
    rollback = NOW - timedelta(microseconds=1)
    with pytest.raises(ProductStoreError):
        query(saved, clock=rollback)
    with pytest.raises(ProductStoreError):
        put(saved, "packet", clock=rollback)
    with pytest.raises(ProductStoreError):
        query(saved, clock=NOW.replace(tzinfo=None))


def test_bounded_worker_error_with_null_observation_is_retained_unknown(saved):
    put(saved, "packet")
    put(saved, "ready")
    terminal = json.loads(saved["terminal"])
    terminal["observed_at"] = None
    terminal["result"] = {
        "schema_version": "bluefire.windows-file-worker-error.v1",
        "code": "native_failed",
        "possible_effects": True,
    }
    result = put(
        saved,
        "terminal",
        data=canonical_json_bytes(terminal),
        code=4,
        clock=NOW + timedelta(days=1),
    )
    assert result.projection.outcome == "unknown" and not result.projection.observation_complete
    assert not result.settled and result.owned_job_cleanup == "unverified"


@pytest.mark.parametrize("fault", ["independent", "owned_exit", "float", "resource"])
def test_malformed_native_proof_never_becomes_durable_success(saved, fault):
    put(saved, "packet")
    put(saved, "ready")
    terminal = json.loads(saved["terminal"])
    proof = terminal["result"]
    if fault == "independent":
        proof["independent_observation"] = True
    elif fault == "owned_exit":
        proof["cleanup"]["owned_process_exit_required"] = True
    elif fault == "float":
        proof["bytes_read"] = 13.0
    else:
        proof["resource_rechecked"] = False
    with pytest.raises(ProductStoreError):
        put(saved, "terminal", data=canonical_json_bytes(terminal))
    assert query(saved).terminal_bytes is None


@pytest.mark.parametrize("code", [4, True, 0.0, 7])
def test_actual_exit_code_cannot_upgrade_or_conflict_with_complete_proof(saved, code):
    put(saved, "packet")
    put(saved, "ready")
    with pytest.raises(ProductStoreError):
        put(saved, "terminal", code=code)
    assert query(saved).terminal_bytes is None


def test_requires_existing_exact_private_claim_not_manifest_seal_or_fresh_binding(saved):
    store, context = saved["store"], saved["context"]
    args = common(saved)
    args["transport_request_hash"] = context["manifest"]["request_hash"]
    with pytest.raises(ProductStoreError):
        store.record_file_access_native_packet(
            context["task_id"], public_bytes=saved["public"], **args
        )
    with pytest.raises(ProductStoreError):
        store.file_access_native_evidence("execute-" + "0" * 64, **common(saved))
    altered = copy.deepcopy(saved["expected"])
    altered["control_revision"] += 1
    args = common(saved)
    args["expected_binding"] = altered
    with pytest.raises(ProductStoreError):
        store.record_file_access_native_packet(
            context["task_id"], public_bytes=saved["public"], **args
        )


def test_nonprivate_saved_claim_is_refused_by_native_evidence_helper(saved):
    store = ProductStore(saved["path"].with_name("nonprivate.db"))
    context = copy.deepcopy(saved["context"])
    context["manifest"]["action_id"] = "file_read"
    reseal(context)
    insert_claim(store, context)
    with pytest.raises(ProductStoreError):
        store.record_file_access_native_packet(
            context["task_id"],
            transport_request_hash=context["transport_request_hash"],
            expected_binding=saved["expected"],
            public_bytes=public_packet(context),
            clock=NOW,
        )


@pytest.mark.parametrize(
    "data",
    [
        b"BFWFBEG1private",
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"password":"synthetic"}',
        b'{"x":1,"x":2}',
        b"x" * (wire.PUBLIC_MAX + 1),
    ],
    ids=["private-begin", "invalid-utf8", "bom", "private-field", "duplicate-key", "oversize"],
)
def test_private_frames_malformed_utf8_duplicates_and_oversize_never_persist(saved, data):
    with pytest.raises(ProductStoreError) as error:
        put(saved, "packet", data=data)
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "synthetic" not in str(error.value) and query(saved).packet_bytes is None


@pytest.mark.parametrize(
    "fault", ["gap", "stage", "predecessor", "claim", "digest", "unknown_field", "oversize"]
)
def test_query_and_earlier_repeat_refuse_corrupt_or_gapped_append_only_evidence(saved, fault):
    document = packet_document(saved)
    stage = "packet"
    if fault == "gap":
        stage = document["stage"] = "ready"
        document["payload_utf8"] = saved["ready"].decode("utf-8")
    elif fault == "stage":
        stage = document["stage"] = "unexpected"
    elif fault == "predecessor":
        document["previous_digest"] = "sha256:" + "0" * 64
    elif fault == "claim":
        document["claim_digest"] = "sha256:" + "0" * 64
    elif fault == "unknown_field":
        document["password"] = "synthetic"
    elif fault == "oversize":
        document["payload_utf8"] = "x" * (evidence._ROW_MAX + 1)
    append_raw(
        saved, stage, document, digest_override="sha256:" + "0" * 64 if fault == "digest" else None
    )
    with pytest.raises(ProductStoreError):
        query(saved)
    with pytest.raises(ProductStoreError):
        put(saved, "packet")


def test_existing_append_only_triggers_prohibit_evidence_update_and_delete(saved):
    put(saved, "packet")
    for statement in (
        "UPDATE file_access_task_evidence SET stage='ready'",
        "DELETE FROM file_access_task_evidence",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            with saved["store"]._connection(write=True) as connection:
                connection.execute(statement)
    assert query(saved).packet_bytes == saved["public"]


def test_full_pair_transport_and_saved_claim_integrity_are_rechecked(saved):
    store = ProductStore(saved["path"].with_name("altered-claim.db"))
    context = copy.deepcopy(saved["context"])
    context["manifest"]["approval"]["approved_by"] = "different-synthetic-reviewer"
    reseal(context)
    insert_claim(store, context, digest_override=content_hash(saved["claim"]))
    with pytest.raises(ProductStoreError):
        store.file_access_native_evidence(
            context["task_id"],
            transport_request_hash=context["transport_request_hash"],
            expected_binding=saved["expected"],
            clock=NOW,
        )


def test_ready_plus_terminal_aggregate_includes_both_frame_prefixes(saved):
    store = ProductStore(saved["path"].with_name("bounded-output.db"))
    context, expected = fixture()
    maximum = len(saved["ready"]) + len(saved["terminal"]) + 7
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
    claim = insert_claim(store, context)
    public = public_packet(context)
    original = wire.validate_original_reservation(context, expected_binding=expected)
    ready, terminal = envelopes(wire.validate_retained_packet(original, public))
    changed = {
        **saved,
        "store": store,
        "context": context,
        "expected": expected,
        "claim": claim,
        "public": public,
        "ready": canonical_json_bytes(ready),
        "terminal": canonical_json_bytes(terminal),
    }
    put(changed, "packet")
    put(changed, "ready")
    with pytest.raises(ProductStoreError):
        put(changed, "terminal")
    assert query(changed).terminal_bytes is None


def test_full_width_native_identities_are_retained_without_numeric_conversion(saved):
    store = ProductStore(saved["path"].with_name("full-width-identities.db"))
    context, expected = fixture()
    identity = "fedcba98765432100123456789abcdef"
    context["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"][
        "file_id"
    ] = identity
    expected["resource"]["file_identity"]["file_id"] = identity
    reseal(context)
    claim = insert_claim(store, context)
    public = public_packet(context)
    changed = {
        **saved,
        "store": store,
        "context": context,
        "expected": expected,
        "claim": claim,
        "public": public,
    }
    result = put(changed, "packet")
    resource = json.loads(result.packet_bytes)["manifest"]["params"]["windows_file_read_request"][
        "resource"
    ]
    assert resource["file_identity"] == {"volume_serial": "fedcba9876543210", "file_id": identity}
    assert result.packet_bytes == public and query(changed).packet_bytes == public


@pytest.mark.parametrize("kind", ["claim", "evidence"])
def test_sql_byte_gate_refuses_oversized_text_before_returning_it_to_decoder(
    saved, monkeypatch, kind
):
    if kind == "claim":
        store = ProductStore(saved["path"].with_name("oversized-claim.db"))
        insert_claim(store, saved["context"], oversized=True)
        saved = {**saved, "store": store}
    else:
        document = packet_document(saved)
        document["payload_utf8"] = "x" * (evidence._ROW_MAX + 1)
        append_raw(saved, "packet", document)
    decoded = []
    original = evidence._row_document

    def observe(row, maximum):
        target = ("stage" in row.keys()) if kind == "evidence" else maximum == evidence._CLAIM_MAX
        if target:
            decoded.append(row["document_json"])
        return original(row, maximum)

    monkeypatch.setattr(evidence, "_row_document", observe)
    with pytest.raises(ProductStoreError):
        query(saved)
    assert decoded == [None]


@pytest.mark.parametrize("conflicting", [False, True])
def test_two_store_instances_race_exact_or_conflicting_packet_writes_without_partial_trail(
    saved, conflicting
):
    stores = (saved["store"], ProductStore(saved["path"]))
    second = (
        json.dumps(json.loads(saved["public"]), indent=1).encode("utf-8")
        if conflicting
        else saved["public"]
    )
    start, lock = threading.Event(), threading.Lock()
    results, failures = [], []

    def save(store, data):
        try:
            if not start.wait(timeout=2):
                raise AssertionError("synthetic race was not released")
            result = store.record_file_access_native_packet(
                saved["context"]["task_id"], public_bytes=data, **common(saved)
            )
            with lock:
                results.append(result)
        except Exception as error:
            with lock:
                failures.append(error)

    threads = [
        threading.Thread(target=save, args=(store, data))
        for store, data in zip(stores, (saved["public"], second), strict=True)
    ]
    try:
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
    finally:
        start.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=10)
    assert len(results) == (1 if conflicting else 2)
    assert len(failures) == (1 if conflicting else 0)
    assert all(type(error) is ProductStoreError for error in failures)
    retained = query(saved)
    assert retained.packet_bytes in (saved["public"], second)
    assert retained.ready_bytes is retained.terminal_bytes is retained.projection is None
    with saved["store"]._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM file_access_task_evidence").fetchone()[0] == 1
        )
