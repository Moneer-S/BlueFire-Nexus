"""Atomic Windows baseline over real SQLite and in-memory setup/process fakes."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from bluefire import product_store_file_access_native_evidence as native
from bluefire import windows_file_access_native_wire as wire
from bluefire import windows_file_access_pair_admission as admission
from bluefire import windows_file_access_process as supervisor
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_cleanup_proof as process_fake
from tests_platform import test_windows_file_access_pair_provenance as provenance
from tests_platform import test_windows_file_access_pair_wire as pair_wire
from tests_platform import test_windows_file_access_process as fake
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def at_ms(milliseconds):
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc)


@pytest.fixture
def saved(tmp_path, paired, monkeypatch):
    _, checked, _ = paired
    path = tmp_path / "baseline.db"
    store = ProductStore(path)
    selection = {
        "enrollment_id": json.loads(checked._raw)["enrollment_id"],
        "enrollment_digest": content_hash(json.loads(checked._raw)),
    }
    imported = store.import_windows_file_access_pair_setup(
        checked, selection=selection, now_ms=ISSUED + 1
    )
    original = provenance.original_review(imported)
    job, created = store.create_file_access_operation(
        original["submitted_request"],
        review_document=original["review"],
        review_context=original["review_context"],
        enrollment_id=imported["enrollment_id"],
        now_ms=ISSUED + 1,
    )
    assert created
    job_id = job["job_id"]
    prepared = admission.build_preparation(job_id, original, imported, issued_at_ms=ISSUED + 2)
    store.prepare_file_access_operation(job_id, prepared, now_ms=ISSUED + 2)
    context = prepared["original"]
    store.register_file_access_task(
        job_id,
        task_id=context["task_id"],
        step_id="read_generated_pair",
        manifest=context["manifest"],
        runner_profile=context["profile"],
        now_ms=ISSUED + 2,
        validate_context=lambda: None,
    )
    reservation = wire.validate_pair_original_reservation(
        context, expected_binding=prepared["expected_binding"]
    )
    packet = wire.prepare_pair_packet(
        reservation,
        challenge="f" * 64,
        clock=at_ms(ISSUED + 2),
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    retained = wire.validate_pair_retained_packet(reservation, packet._raw)
    ready, terminal = pair_wire.envelopes(retained)
    terminal["observed_at"] = (
        at_ms(ISSUED + 1000).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    resource = prepared["expected_binding"]["resource"]
    for phase in ("reader", "owner"):
        terminal["result"][phase].update(
            bytes_read=resource["size_bytes"], observed_sha256=resource["sha256"]
        )
    fake.setup.__wrapped__(monkeypatch)
    clock = at_ms(ISSUED + 2000)
    monkeypatch.setattr(supervisor, "_utc", lambda: clock)
    source = SimpleNamespace(
        protocol="pair_v2", original=reservation, packet=packet, ready=ready, terminal=terminal
    )
    return dict(
        store=store,
        path=path,
        imported=imported,
        operation=original,
        preparation=prepared,
        context=context,
        expected=prepared["expected_binding"],
        job=job_id,
        source=source,
        clock=clock,
        selection=selection,
    )


def common(saved):
    return dict(
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
        clock=saved["clock"],
    )


def produce(saved, *, persist_cleanup=True, sink=None):
    default = native.native_pair_evidence_sink(
        saved["store"],
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )
    result = process_fake.run(saved["source"], sink=sink or default)
    assert result.outcome.cleanup == "verified" and result.outcome.cleanup_receipt is not None
    if persist_cleanup:
        saved["store"].record_file_access_native_pair_cleanup(
            saved["context"]["task_id"], receipt=result.outcome.cleanup_receipt, **common(saved)
        )
    return result


def publish(saved, **kwargs):
    return saved["store"].publish_windows_file_access_baseline(
        saved["job"], clock=saved["clock"], **kwargs
    )


def counts(saved):
    with saved["store"]._connection() as connection:
        return tuple(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("file_access_revisions", "file_access_outcomes")
        )


def test_atomic_readable_baseline_requires_both_reads_and_both_cleanup_boundaries(saved):
    result = produce(saved)
    revision = publish(saved)
    assert counts(saved) == (1, 1) and revision["revision"] == 2
    assert revision["baseline"]["non_owner"] == revision["baseline"]["owner"] == "allowed"
    assert (
        revision["baseline"]["native_cleanup"]
        == revision["baseline"]["owned_job_cleanup"]
        == "verified"
    )
    assert not revision["baseline"]["independent_observation"]
    assert "record_count" not in canonical_json(revision) and "worker_uid" not in canonical_json(
        revision
    )
    assert (
        result.outcome.projection.owned_job_cleanup == "unverified" and not result.outcome.settled
    )
    assert publish(saved) == revision and counts(saved) == (1, 1)
    projected = saved["store"].windows_file_access_pair_control_projection(
        saved["imported"]["control_owner_id"], clock=saved["clock"]
    )
    assert projected["status"] == "baseline_verified" and projected["allowed_operations"] == []
    assert projected["baseline"] == revision["baseline"]


def test_connected_fake_ready_once_exchange_publishes_only_after_physical_closure(saved):
    source, store, task = saved["source"], saved["store"], saved["context"]["task_id"]
    sink = native.native_pair_evidence_sink(
        store,
        task,
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )
    allowance, buffers = [], []
    current = dict(common(saved), prepared_packet=source.packet, monotonic_now=100.0)

    def persist(stage, data, code, clock):
        if stage == "ready":
            allowance.append(
                store.consume_windows_file_access_pair_ready(task, ready_bytes=data, **current)
            )
        else:
            sink(stage, data, code, clock)

    def validate():
        store.revalidate_windows_file_access_pair_original(task, **current)
        if allowance:
            allowance[0](saved["clock"], 100.0)

    def fake_begin(prefix):
        assert len(allowance) == 1 and len(prefix) == 124 and not buffers
        allowance[0](saved["clock"], 100.0)
        value = bytearray(fake.framed(prefix + b"\x01\0A\0"))
        buffers.append(value)
        allowance[0](saved["clock"], 100.0)
        return value

    result = supervisor.supervise_pair_suspended(
        fake.Process(canonical_json_bytes(source.ready), canonical_json_bytes(source.terminal)),
        owned_job=5001,
        containment=fake.Containment(),
        prepared_packet=source.packet,
        original_reservation=source.original,
        revalidate_original=validate,
        begin_producer=fake_begin,
        cancellation_event=threading.Event(),
        evidence_sink=persist,
    )
    assert result.projection.outcome == "allowed" and result.cleanup == "verified"
    assert len(buffers) == 1 and not any(buffers[0])
    with pytest.raises(ProductStoreError):
        publish(saved)
    store.record_file_access_native_pair_cleanup(
        task, receipt=result.cleanup_receipt, **common(saved)
    )
    assert publish(saved)["status"] == "baseline_verified"
    with pytest.raises(ProductStoreError):
        store.consume_windows_file_access_pair_ready(
            task, ready_bytes=canonical_json_bytes(source.ready), **current
        )


def test_historical_reopen_does_not_reprepare_launch_or_decrypt(saved, monkeypatch):
    produce(saved)
    expected = publish(saved)
    saved["store"] = ProductStore(saved["path"])

    def forbidden(*_, **__):
        raise AssertionError("historical recovery must not execute or reprepare")

    monkeypatch.setattr(admission, "validate_preparation", forbidden)
    monkeypatch.setattr(supervisor, "supervise_pair_suspended", forbidden)
    monkeypatch.setattr(wire, "prepare_pair_packet", forbidden)
    saved["clock"] += timedelta(days=2)
    assert publish(saved) == expected
    assert (
        saved["store"].windows_file_access_pair_control_projection(
            saved["imported"]["control_owner_id"], clock=saved["clock"]
        )["baseline"]
        == expected["baseline"]
    )


def test_original_unknown_outcome_requires_exact_compare_and_swap(saved):
    produce(saved)
    saved["store"].finish_file_access_operation(
        saved["job"], outcome={"state": "unknown", "evidence_digest": "sha256:" + "9" * 64}
    )
    with saved["store"]._connection() as connection:
        before = json.loads(
            connection.execute(
                "SELECT document_json FROM file_access_outcomes WHERE job_id=? ORDER BY sequence DESC LIMIT 1",
                (saved["job"],),
            ).fetchone()[0]
        )
    digest = content_hash(before)
    with pytest.raises(ProductStoreError):
        publish(saved)
    with pytest.raises(ProductStoreError):
        publish(saved, expected_outcome_digest="sha256:" + "8" * 64)
    revision = saved["store"].recover_windows_file_access_baseline(
        saved["job"], expected_outcome_digest=digest, clock=saved["clock"] + timedelta(days=1)
    )
    assert counts(saved) == (1, 2)
    assert publish(saved, expected_outcome_digest=digest) == revision


@pytest.mark.parametrize("stage", ["none", "packet", "ready", "terminal_without_cleanup"])
def test_missing_evidence_never_publishes_partial_revision(saved, stage):
    source, store, task = saved["source"], saved["store"], saved["context"]["task_id"]
    if stage != "none":
        store.record_file_access_native_pair_packet(
            task, public_bytes=source.packet._raw, **common(saved)
        )
    if stage in ("ready", "terminal_without_cleanup"):
        store.record_file_access_native_pair_ready(
            task, ready_bytes=canonical_json_bytes(source.ready), **common(saved)
        )
    if stage == "terminal_without_cleanup":
        store.record_file_access_native_pair_terminal(
            task,
            terminal_bytes=canonical_json_bytes(source.terminal),
            actual_returncode=0,
            **common(saved),
        )
    with pytest.raises(ProductStoreError):
        publish(saved)
    assert counts(saved) == (0, 0)


@pytest.mark.parametrize("fault", ["denied", "owner_unknown", "cleanup", "wrong_exit", "future"])
def test_non_complete_or_contradictory_native_evidence_cannot_publish(saved, fault):
    terminal = saved["source"].terminal
    process = None
    if fault == "denied":
        terminal["result"]["outcome"] = "data_access_denied"
        terminal["result"]["reader"].update(
            outcome="data_access_denied", bytes_read=0, observed_sha256=None
        )
    elif fault in ("owner_unknown", "cleanup"):
        terminal["result"].update(
            outcome="unknown", issue="native_failure", failed_stage="owner_read"
        )
        terminal["result"]["owner"].update(
            outcome="unknown",
            issue="native_failure",
            failed_stage="owner_read",
            resource_rechecked=False,
        )
        if fault == "cleanup":
            terminal["result"].update(issue="cleanup_unknown", failed_stage="cleanup")
            terminal["result"]["cleanup"].update(
                handles_released=False, owned_process_exit_required=True
            )
        process = fake.Process(
            canonical_json_bytes(saved["source"].ready), canonical_json_bytes(terminal), 4
        )
    elif fault == "wrong_exit":
        process = fake.Process(
            canonical_json_bytes(saved["source"].ready), canonical_json_bytes(terminal), 4
        )
    else:
        terminal["observed_at"] = (
            at_ms(ISSUED + 6000).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
    sink = native.native_pair_evidence_sink(
        saved["store"],
        saved["context"]["task_id"],
        transport_request_hash=saved["context"]["transport_request_hash"],
        expected_binding=saved["expected"],
    )
    result = process_fake.run(saved["source"], sink=sink, process=process)
    saved["store"].record_file_access_native_pair_cleanup(
        saved["context"]["task_id"], receipt=result.outcome.cleanup_receipt, **common(saved)
    )
    with pytest.raises(ProductStoreError):
        publish(saved)
    assert counts(saved) == (0, 0)


def test_generic_finish_cannot_bypass_pair_baseline_proof(saved):
    for state in ("complete", "settled_partial"):
        with pytest.raises(ProductStoreError):
            saved["store"].finish_file_access_operation(
                saved["job"], outcome={"state": state, "evidence_digest": "sha256:" + "1" * 64}
            )
    assert counts(saved) == (0, 0)


def test_revision_and_outcome_insert_roll_back_together(saved):
    produce(saved)
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "CREATE TRIGGER synthetic_outcome_refusal BEFORE INSERT ON file_access_outcomes BEGIN SELECT RAISE(ABORT,'synthetic'); END"
        )
    with pytest.raises(ProductStoreError):
        publish(saved)
    assert counts(saved) == (0, 0)


def test_exact_concurrent_publication_is_idempotent(saved):
    produce(saved)
    barrier, results = threading.Barrier(2), []

    def attempt():
        target = dict(saved, store=ProductStore(saved["path"]))
        barrier.wait(timeout=5)
        results.append(publish(target))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert len(results) == 2 and results[0] == results[1] and counts(saved) == (1, 1)


@pytest.mark.parametrize("field", ["control_digest", "evidence_digest", "extra"])
def test_projection_rechecks_full_immutable_outcome_not_just_status(saved, field):
    produce(saved)
    revision = publish(saved)
    outcome = dict(
        state="complete",
        control_digest=content_hash(revision),
        native_baseline=revision["baseline"],
        evidence_digest=revision["baseline"]["baseline_digest"],
    )
    outcome[field] = "sha256:" + "7" * 64
    # A test-local extra append preserves the append-only triggers and models
    # inconsistent durable input; the query must not promote it to a baseline.
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
            (saved["job"], canonical_json(outcome), content_hash(outcome)),
        )
    with pytest.raises(ProductStoreError):
        saved["store"].windows_file_access_pair_control_projection(
            saved["imported"]["control_owner_id"], clock=saved["clock"]
        )


def test_no_revision_projection_remains_unresolved_and_has_no_business_permission(saved):
    projected = saved["store"].windows_file_access_pair_control_projection(
        saved["imported"]["control_owner_id"], clock=saved["clock"]
    )
    assert projected["task_usage_state"] == "unresolved" and projected["allowed_operations"] == []


def test_pair_import_is_never_selected_by_v1_lookup(saved):
    with pytest.raises(ProductStoreError):
        saved["store"].get_windows_file_access_import(saved["selection"])
    assert (
        saved["store"].get_windows_file_access_pair_import(saved["selection"]) == saved["imported"]
    )


def test_extra_claim_refuses_publication_without_partial_outcome(saved):
    produce(saved)
    # Deliberately inconsistent extra durable input, not a second admitted read.
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
            (
                "synthetic-extra-claim",
                saved["job"],
                "read_owner_separately",
                "sha256:" + "0" * 64,
                "{}",
                content_hash({}),
            ),
        )
    with pytest.raises(ProductStoreError):
        publish(saved)
    assert counts(saved) == (0, 0)


def test_future_query_clock_and_wrong_cas_digest_cannot_upgrade_baseline(saved):
    produce(saved)
    with pytest.raises(ProductStoreError):
        saved["store"].publish_windows_file_access_baseline(saved["job"], clock=at_ms(ISSUED + 500))
    assert counts(saved) == (0, 0)
    publish(saved)
    with pytest.raises(ProductStoreError):
        publish(saved, expected_outcome_digest="sha256:" + "8" * 64)
    with pytest.raises(ProductStoreError):
        saved["store"].windows_file_access_pair_control_projection(
            saved["imported"]["control_owner_id"], clock=at_ms(ISSUED + 500)
        )


@pytest.mark.parametrize("operation", ["harden", "rollback", "reset", "baseline"])
def test_committed_windows_baseline_never_enables_linux_mutation_recipe(saved, operation):
    produce(saved)
    revision = publish(saved)
    original = provenance.original_review(saved["imported"])
    request = original["submitted_request"]
    request["submission_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    request["review"]["operation"] = operation
    review = original["review"]
    review.update(operation=operation, control_digest=content_hash(revision))
    review["review_digest"] = content_hash(
        {k: v for k, v in review.items() if k != "review_digest"}
    )
    request["review_digest"] = review["review_digest"]
    with pytest.raises(ProductStoreError):
        saved["store"].create_file_access_operation(
            request,
            review_document=review,
            review_context=original["review_context"],
            enrollment_id=saved["imported"]["enrollment_id"],
            now_ms=ISSUED + 2000,
        )
    assert counts(saved) == (1, 1)
