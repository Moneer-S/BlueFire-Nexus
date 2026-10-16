"""Durable correction locks over SQLite and synthetic, fully retained baselines."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from bluefire import product_store_windows_correction as journal
from bluefire import windows_file_access_correction_admission as admission
from bluefire import windows_file_access_correction_control_process as control_process
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_baseline_publication as baseline
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_admission import harden_original
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


@pytest.fixture
def retained(saved, paired):
    baseline.produce(saved)
    prior = baseline.publish(saved)
    context = admission.correction_context(saved["imported"], prior, "sha256:" + "7" * 64)
    original, job = harden_original(
        dict(imported=saved["imported"], control=prior, context=context)
    )
    original["submitted_request"]["submission_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    job = "job-" + original["submitted_request"]["submission_id"].replace("-", "")
    original["created_at_ms"] = ISSUED + 2500
    prepared = admission.build_preparation(
        job, original, saved["imported"], prior, issued_at_ms=ISSUED + 2500
    )
    # Seed only the reviewed private intent. No public correction route exists yet.
    with saved["store"]._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) "
            "VALUES(?,'file_access.operation','queued','{}','{}',?,?)",
            (job, saved["clock"].isoformat(), saved["clock"].isoformat()),
        )
        connection.execute(
            "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                job,
                prepared["control_owner_id"],
                saved["imported"]["enrollment_id"],
                "harden",
                canonical_json(original),
                content_hash(original),
            ),
        )
        connection.execute(
            "INSERT INTO file_access_preparations VALUES(?,?,?)",
            (job, canonical_json(prepared), content_hash(prepared)),
        )
    return SimpleNamespace(
        store=saved["store"],
        path=saved["path"],
        saved=saved,
        job=job,
        prepared=prepared,
        checked_setup=paired[1],
    )


def begin(value, **changes):
    args = dict(
        binding_digest=value.prepared["binding_digest"],
        now_ms=ISSUED + 2501,
        revalidate=lambda: None,
    )
    return journal.begin_dispatch(value.store, value.job, **{**args, **changes})


def receipt(value, *, dispatch="unknown"):
    # A fake trusted producer, not a deserializer or production construction path.
    row = {
        "schema_version": control_process.RECEIPT_SCHEMA,
        "binding_digest": value.prepared["binding_digest"],
        "dispatch": dispatch,
        "process_cleanup": "verified",
        "terminal": None,
        "settled": False,
    }
    result = object.__new__(control_process.OwnedCorrectionControlReceipt)
    object.__setattr__(result, "_raw", canonical_json_bytes(row))
    object.__setattr__(result, "_binding", canonical_json_bytes(value.prepared["binding"]))
    return result


def test_one_durable_dispatch_never_restores_allowance_after_reopen(retained):
    value = retained
    current = begin(value)
    current(ISSUED + 2502)
    assert journal.has_dispatch(value.store, value.job)
    assert set(journal.control_evidence(value.store, value.job)) == {"dispatch"}
    value.store = ProductStore(value.path)
    with pytest.raises(ProductStoreError):
        begin(value)
    with pytest.raises(ProductStoreError):
        current(value.prepared["expires_at_ms"])


def test_revalidation_failure_leaves_no_dispatch(retained):
    def refuse():
        raise ValueError("synthetic admission refusal")

    with pytest.raises(ProductStoreError):
        begin(retained, revalidate=refuse)
    assert not journal.has_dispatch(retained.store, retained.job)
    assert journal.control_evidence(retained.store, retained.job) == {}


@pytest.mark.parametrize("fault", ["expired", "binding", "stopped", "outcome", "claim"])
def test_dispatch_refuses_changed_current_authority(retained, fault):
    v = retained
    options = {}
    if fault == "expired":
        options["now_ms"] = v.prepared["expires_at_ms"]
    elif fault == "binding":
        options["binding_digest"] = "sha256:" + "9" * 64
    else:
        with v.store._connection(write=True) as connection:
            if fault == "stopped":
                connection.execute(
                    "UPDATE jobs SET progress_json=? WHERE job_id=?",
                    (canonical_json({"stopped": True}), v.job),
                )
            elif fault == "outcome":
                result = {"state": "unknown", "evidence_digest": "sha256:" + "8" * 64}
                connection.execute(
                    "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                    (v.job, canonical_json(result), content_hash(result)),
                )
            else:
                connection.execute(
                    "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                    (
                        "synthetic-early-task",
                        v.job,
                        "read_generated_pair_correction",
                        "x",
                        "{}",
                        "x",
                    ),
                )
    with pytest.raises(ProductStoreError):
        begin(v, **options)
    assert not journal.has_dispatch(v.store, v.job)


def test_baseline_rejoined_not_trusted_from_self_hashed_revision(retained):
    v = retained
    false_outcome = {
        "state": "complete",
        "native_baseline": {},
        "evidence_digest": "sha256:" + "6" * 64,
    }
    with v.store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
            (v.saved["job"], canonical_json(false_outcome), content_hash(false_outcome)),
        )
    with pytest.raises(ProductStoreError):
        begin(v)
    assert not journal.has_dispatch(v.store, v.job)


def test_closure_is_separate_typed_idempotent_and_never_settlement(retained):
    v = retained
    current = begin(v)
    closed = receipt(v)
    with pytest.raises(ProductStoreError):
        journal.record_control_closure(v.store, v.job, closed.document())
    event = journal.record_control_closure(v.store, v.job, closed)
    assert journal.record_control_closure(v.store, v.job, closed) == event
    assert event["payload"]["terminal"] is None and event["payload"]["settled"] is False
    assert set(journal.control_evidence(v.store, v.job)) == {"dispatch", "closure"}
    with pytest.raises(ProductStoreError):
        current(ISSUED + 2502)
    with pytest.raises(ProductStoreError):
        journal.record_control_closure(v.store, v.job, receipt(v, dispatch="not_started"))


def test_dispatch_without_native_task_cannot_be_dismissed_as_no_effect(retained):
    begin(retained)
    for state in ("refused_no_effect", "complete", "settled_partial"):
        with pytest.raises(ProductStoreError):
            retained.store.finish_file_access_operation(
                retained.job, outcome={"state": state, "evidence_digest": content_hash([])}
            )
    retained.store.finish_file_access_operation(
        retained.job, outcome={"state": "unknown", "evidence_digest": content_hash([])}
    )
    assert journal.has_dispatch(retained.store, retained.job)


def test_simultaneous_dispatch_commits_exactly_one_lock(retained):
    barrier, outcomes = threading.Barrier(2), []

    def attempt():
        value = SimpleNamespace(**{**vars(retained), "store": ProductStore(retained.path)})
        barrier.wait(timeout=5)
        try:
            begin(value)
            outcomes.append("admitted")
        except ProductStoreError:
            outcomes.append("refused")

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert sorted(outcomes) == ["admitted", "refused"]


def test_oversized_prior_revision_is_capped_by_sql_before_decode(retained, monkeypatch):
    v = retained
    oversized = json.dumps({"padding": "x" * (journal.wire.PUBLIC_MAX + 1)})
    # Deliberately corrupt only this disposable database to exercise bounded reads.
    with v.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER file_access_revisions_no_update")
        connection.execute(
            "UPDATE file_access_revisions SET document_json=?,document_digest=? WHERE job_id=?",
            (oversized, content_hash(json.loads(oversized)), v.saved["job"]),
        )
    observed = []
    original = journal.native._row_document

    def inspect(row, maximum):
        if row is not None and row["document_json"] is None:
            observed.append("sql-null")
        return original(row, maximum)

    monkeypatch.setattr(journal.native, "_row_document", inspect)
    with pytest.raises(ProductStoreError):
        begin(v)
    assert observed == ["sql-null"]
    assert not journal.has_dispatch(v.store, v.job)
