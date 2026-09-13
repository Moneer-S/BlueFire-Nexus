"""File-only persistence checks using deterministic v4 provider software responses."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.adaptive_runtime import propose_reviewed_method
from bluefire.config import AutonomyLevel
from bluefire.product_store import ProductStore, ProductStoreError
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_adaptive_runtime import runtime as runtime


@pytest.fixture
def review_record(runtime):
    arguments, provider_config = runtime
    result = propose_reviewed_method(
        **{
            **arguments,
            "plan": replace(arguments["plan"], autonomy=AutonomyLevel.ASSIST),
        },
        provider=Provider(provider_config),
    )
    assert result.record["schema_version"] == "bluefire.ai-proposal-record.v4"
    assert result.record["application_status"] == "awaiting_operator_approval"
    return result.record


def _create_review(store, record):
    job = store.create_job("scenario.run", {"mode": "execute"})
    review = store.create_ai_proposal_review(
        job_id=job["job_id"], source_run_id=record["run_id"], record=record
    )
    return job, review


def _resolve_review(store, job, review, *, resolution=None):
    return store.resolve_ai_proposal_review(
        review["proposal_record_id"],
        job_id=job["job_id"],
        decision="accepted",
        decided_by="test-reviewer",
        expected_state_digest=review["state_digest"],
        expected_plan_digest=review["plan_digest"],
        expected_proposal_digest=review["proposal_digest"],
        resolution={"decision": "accepted"} if resolution is None else resolution,
    )


def test_v4_review_reopens_with_exact_identity_and_one_time_resolution(tmp_path, review_record):
    database = tmp_path / "product.db"
    store = ProductStore(database)
    job, review = _create_review(store, review_record)
    reopened = ProductStore(database)
    assert reopened.get_ai_proposal_review(review["proposal_record_id"]) == review
    assert reopened.list_ai_proposal_reviews(job["job_id"]) == [review]
    duplicate = reopened.create_ai_proposal_review(
        job_id=job["job_id"],
        source_run_id=review_record["run_id"],
        record=deepcopy(review_record),
    )
    assert duplicate == review
    accepted = _resolve_review(reopened, job, review)
    persisted = ProductStore(database).get_ai_proposal_review(review["proposal_record_id"])
    assert persisted == accepted
    assert persisted["record"] == review_record
    assert persisted["record"]["registered_step"] == review_record["registered_step"]
    assert persisted["status"] == "accepted"
    with pytest.raises(ProductStoreError, match="stale or already resolved"):
        _resolve_review(store, job, review)


@pytest.mark.parametrize("operation", ["create", "resolve"])
def test_review_write_rollback_stays_in_caller_owned_transaction(
    tmp_path, monkeypatch, review_record, operation
):
    database = tmp_path / "product.db"
    store = ProductStore(database)
    job = store.create_job("scenario.run", {"mode": "execute"})
    review = None
    if operation == "resolve":
        review = store.create_ai_proposal_review(
            job_id=job["job_id"],
            source_run_id=review_record["run_id"],
            record=review_record,
        )
    original_connection = store._connection
    requests = []

    @contextmanager
    def interrupt_write(*, write=False):
        requests.append(write)
        with original_connection(write=write) as connection:
            yield connection
            if write:
                raise RuntimeError("Authored interruption before transaction commit.")

    monkeypatch.setattr(store, "_connection", interrupt_write)
    with pytest.raises(RuntimeError, match="before transaction commit"):
        if operation == "create":
            store.create_ai_proposal_review(
                job_id=job["job_id"],
                source_run_id=review_record["run_id"],
                record=review_record,
            )
        else:
            _resolve_review(store, job, review)
    assert requests == [True]
    persisted = ProductStore(database).list_ai_proposal_reviews(job["job_id"])
    assert persisted == ([] if review is None else [review])


@pytest.mark.parametrize("mutation", ["method", "authorization", "secret"])
def test_invalid_v4_review_is_refused_before_persistence(tmp_path, review_record, mutation):
    store = ProductStore(tmp_path / "product.db")
    job = store.create_job("scenario.run", {"mode": "execute"})
    changed = deepcopy(review_record)
    if mutation == "method":
        changed["registered_step"]["action_id"] = "sandbox.discovery.list.v1"
    elif mutation == "authorization":
        changed["authorization_digest"] = "sha256:" + "f" * 64
    else:
        changed["private_token"] = "authored-sensitive-test-value"
    with pytest.raises(ProductStoreError):
        store.create_ai_proposal_review(
            job_id=job["job_id"], source_run_id=changed["run_id"], record=changed
        )
    assert store.list_ai_proposal_reviews(job["job_id"]) == []


def test_secret_bearing_resolution_leaves_exact_review_pending(tmp_path, review_record):
    store = ProductStore(tmp_path / "product.db")
    job, review = _create_review(store, review_record)
    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        _resolve_review(store, job, review, resolution={"api_key": "authored-test-value"})
    assert store.get_ai_proposal_review(review["proposal_record_id"]) == review
