"""Correction reservations use original SQLite baseline proof, not supplied labels."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import product_store_windows_correction as journal
from bluefire import windows_file_access_correction_admission as admission
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform import test_windows_file_access_baseline_publication as baseline
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_admission import harden_original
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


@pytest.fixture
def reviewed(saved):
    baseline.produce(saved)
    prior = baseline.publish(saved)
    context = admission.correction_context(saved["imported"], prior, "sha256:" + "7" * 64)
    original, _ = harden_original(dict(imported=saved["imported"], control=prior, context=context))
    original["submitted_request"]["submission_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    original["created_at_ms"] = ISSUED + 2500
    return SimpleNamespace(saved=saved, original=original, prior=prior, store=saved["store"])


def reserve(value, *, now_ms=ISSUED + 2500, original=None):
    row = original or value.original
    return value.store.create_file_access_operation(
        row["submitted_request"],
        review_document=row["review"],
        review_context=row["review_context"],
        enrollment_id=value.saved["imported"]["enrollment_id"],
        now_ms=now_ms,
    )


def prepare(value):
    job, created = reserve(value)
    assert created
    return job["job_id"], admission.build_preparation(
        job["job_id"],
        value.original,
        value.saved["imported"],
        value.prior,
        issued_at_ms=ISSUED + 2501,
    )


def test_exact_reservation_and_preparation_are_immutable_and_do_not_dispatch(reviewed):
    v = reviewed
    job, prepared = prepare(v)
    assert reserve(v)[1] is False
    v.store.prepare_file_access_operation(job, prepared, now_ms=ISSUED + 2501)
    v.store.prepare_file_access_operation(job, prepared, now_ms=ISSUED + 2502)
    assert v.store.file_access_preparation(job)["document"] == prepared
    assert not journal.has_dispatch(v.store, job)
    with v.store._connection() as connection:
        assert journal.original_at(v.store, connection, job)[1] == prepared
    different = deepcopy(prepared)
    different["binding"]["previous_descriptor_sha256"] = "sha256:" + "8" * 64
    with pytest.raises(ProductStoreError):
        v.store.prepare_file_access_operation(job, different, now_ms=ISSUED + 2502)


@pytest.mark.parametrize("fault", ["context", "expired", "baseline_outcome", "pending"])
def test_reservation_requires_exact_live_context_and_settled_retained_baseline(reviewed, fault):
    v = reviewed
    original = deepcopy(v.original)
    now = ISSUED + 2500
    if fault == "context":
        original["review_context"]["baseline_digest"] = "sha256:" + "8" * 64
        review = original["review"]
        review["context_digest"] = content_hash(original["review_context"])
        review["review_digest"] = content_hash(
            {k: x for k, x in review.items() if k != "review_digest"}
        )
        original["submitted_request"]["review_digest"] = review["review_digest"]
    elif fault == "expired":
        now = original["review"]["expires_at_ms"]
    elif fault == "pending":
        reserve(v)
        original["submitted_request"]["submission_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    else:
        outcome = {"state": "complete", "evidence_digest": "sha256:" + "9" * 64}
        with v.store._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (v.saved["job"], canonical_json(outcome), content_hash(outcome)),
            )
    with pytest.raises(ProductStoreError):
        reserve(v, now_ms=now, original=original)


@pytest.mark.parametrize("fault", ["binding", "expired", "stopped", "outcome", "early_claim"])
def test_preparation_requires_unchanged_live_reservation_before_any_claim(reviewed, fault):
    v = reviewed
    job, prepared = prepare(v)
    now = ISSUED + 2501
    if fault == "binding":
        prepared["binding"]["prior_control_digest"] = "sha256:" + "8" * 64
    elif fault == "expired":
        now = prepared["expires_at_ms"]
    elif fault == "outcome":
        v.store.finish_file_access_operation(
            job, outcome={"state": "refused_no_effect", "evidence_digest": content_hash([])}
        )
    else:
        with v.store._connection(write=True) as connection:
            if fault == "stopped":
                connection.execute(
                    "UPDATE jobs SET progress_json=? WHERE job_id=?",
                    (canonical_json({"stopped": True}), job),
                )
            else:
                connection.execute(
                    "INSERT INTO file_access_task_claims VALUES(?,?,?,?,?,?)",
                    ("early-synthetic-claim", job, "early", "x", "{}", "x"),
                )
    with pytest.raises(ProductStoreError):
        v.store.prepare_file_access_operation(job, prepared, now_ms=now)
    with v.store._connection() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM file_access_preparations WHERE job_id=?", (job,)
            ).fetchone()
            is None
        )
