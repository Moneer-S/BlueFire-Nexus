"""Exact-key replay closure never clears uncertainty by assuming a missing job."""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from bluefire.application_errors import APIError
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.replay_preparation import replay_job_submission
from bluefire.util import content_hash
from tests_platform.test_replay_jobs import awaiting, submission
from tests_platform.test_replay_preparation import forbid, source_run
from tests_platform.test_replay_preparation import service as service

SOURCE = "run-20260906T120000Z-0123456789abcdef"


def stale_request():
    return {
        "submission_id": str(uuid.uuid4()),
        "preparation_id": "replay-preparation-" + "a" * 64,
        "preparation_context": {
            "schema_version": "bluefire.replay-preparation-context.v1",
            "runner_readiness": None,
        },
    }


def test_close_missing_source_requires_no_review_approval_or_execution(service, monkeypatch):
    payload = stale_request()
    for name in ("prepare_replay", "_action_catalog_boundary", "_review_submitted_replay_locked"):
        monkeypatch.setattr(service, name, forbid)
    monkeypatch.setattr(service.store, "get_run", forbid)
    monkeypatch.setattr(service.product_store, "create_approval_request", forbid)
    monkeypatch.setattr(service.job_controller, "submit", forbid)
    result = service.resolve_replay_submission(SOURCE, payload)
    assert result["schema_version"] == "bluefire.replay-submission-resolution.v1"
    assert result["outcome"] == "closed"
    assert result["source_run_id"] == SOURCE
    assert result["submission_id"] == payload["submission_id"]
    submitted = {k: v for k, v in payload.items() if k != "submission_id"}
    assert result["submitted_request"] == submitted
    assert result["intent_digest"] == content_hash({"source_run_id": SOURCE, "request": submitted})
    job = result["job"]
    assert job["job_id"] == "job-" + payload["submission_id"].replace("-", "")
    assert job["kind"] == "scenario.replay"
    assert job["state"] == "cancelled"
    assert job["result_ref"] is None
    assert job["request"]["schema_version"] == "bluefire.closed-replay-submission.v1"
    assert job["error"]["code"] == "closed_submission"
    assert "approval_request_id" not in job["request"]
    assert service.resolve_replay_submission(SOURCE, payload) == result
    assert service.active_jobs()["jobs"] == []
    assert service.product_store.recover_interrupted_jobs() == 0
    with pytest.raises(APIError) as rejected:
        service.submit_replay(SOURCE, payload)
    assert rejected.value.code == "replay_submission_closed"
    with pytest.raises(APIError):
        service.retry_job(job["job_id"])
    assert len(service.product_store.list_jobs()) == 1


@pytest.mark.parametrize("changed", ["source", "intent", "kind"])
def test_close_refuses_reused_identity_without_mutating_first_row(service, changed):
    payload = stale_request()
    submission_id, digest, submitted = replay_job_submission(SOURCE, payload)
    kind = "scenario.run" if changed == "kind" else "scenario.replay"
    before, _ = service.product_store.create_idempotent_job(
        kind, {"preserved": "original"}, submission_id=submission_id, intent_digest=digest
    )
    source = "run-20260906T120000Z-fedcba9876543210" if changed == "source" else SOURCE
    if changed == "intent":
        payload["defense_change"] = "Different intent"
    with pytest.raises(APIError) as rejected:
        service.resolve_replay_submission(source, payload)
    assert rejected.value.code == "replay_submission_resolution_refused"
    assert service.product_store.get_job(before["job_id"]) == before


@pytest.mark.parametrize("invalid", [None, "not-a-uuid", "B42F4BDD-4F5F-453D-A60A-A985EDFB7B4C", 4])
def test_close_rejects_malformed_uuid_without_persistence(service, invalid):
    payload = {**stale_request(), "submission_id": invalid}
    with pytest.raises(APIError):
        service.resolve_replay_submission(SOURCE, payload)
    assert service.product_store.list_jobs() == []


@pytest.mark.parametrize("extra", [{"approval": {"confirmed": True}}, {"unrelated": "data"}])
def test_close_rejects_authority_and_unknown_payload_fields(service, extra):
    with pytest.raises(APIError):
        service.resolve_replay_submission(SOURCE, {**stale_request(), **extra})
    assert service.product_store.list_jobs() == []


def test_close_returns_existing_execute_job_without_changing_approval(service):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    published = service.submit_replay(source["run_id"], payload)
    job_id = published["job"]["job_id"]
    awaiting(service, job_id)
    before = service.product_store.get_job(job_id)
    approval_id = before["request"]["approval_request_id"]
    approval = service.product_store.get_approval_request(approval_id)
    result = service.resolve_replay_submission(source["run_id"], payload)
    assert result["outcome"] == "existing"
    assert result["job"] == before
    assert service.product_store.get_job(job_id) == before
    assert service.product_store.get_approval_request(approval_id) == approval
    assert approval["status"] == "pending"
    assert service.resolve_replay_submission(source["run_id"], payload) == result
    assert service.submit_replay(source["run_id"], payload)["job"]["job_id"] == job_id


def test_close_wins_against_delayed_execute_publication_and_withdraws_unused_approval(
    service, monkeypatch
):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    entered, release = threading.Event(), threading.Event()
    create = service.product_store.create_idempotent_job
    approval_ids = []

    def held(kind, request, **kwargs):
        approval_ids.append(request["approval_request_id"])
        entered.set()
        assert release.wait(10)
        return create(kind, request, **kwargs)

    monkeypatch.setattr(service.product_store, "create_idempotent_job", held)
    monkeypatch.setattr(service, "_execute_replay_job", forbid)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(service.submit_replay, source["run_id"], payload)
        try:
            assert entered.wait(10)
            result = service.resolve_replay_submission(source["run_id"], payload)
            assert result["outcome"] == "closed"
        finally:
            release.set()
        with pytest.raises(APIError) as rejected:
            future.result(timeout=10)
    assert rejected.value.code == "replay_submission_closed"
    assert service.product_store.get_approval_request(approval_ids[0])["status"] == "withdrawn"
    assert service.active_jobs()["jobs"] == []
    assert len(service.product_store.list_jobs()) == 1
    assert service.product_store.get_job(result["job"]["job_id"]) == result["job"]


def test_separate_store_connections_serialize_close_against_publication(tmp_path):
    first = ProductStore(tmp_path / "product.sqlite3")
    second = ProductStore(first.path)
    for _ in range(12):
        payload = stale_request()
        submission_id, digest, submitted = replay_job_submission(SOURCE, payload)
        rendezvous = threading.Barrier(2)

        def close(
            rendezvous=rendezvous, submitted=submitted, submission_id=submission_id, digest=digest
        ):
            rendezvous.wait(timeout=5)
            return first.close_replay_submission(
                SOURCE, submitted, submission_id=submission_id, intent_digest=digest
            )

        def publish(rendezvous=rendezvous, submission_id=submission_id, digest=digest):
            rendezvous.wait(timeout=5)
            return second.create_idempotent_job(
                "scenario.replay",
                {"original": True},
                submission_id=submission_id,
                intent_digest=digest,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            close_future, publish_future = pool.submit(close), pool.submit(publish)
            closed = close_future.result(timeout=10)
            published, created = publish_future.result(timeout=10)
        assert closed == published
        assert first.get_job(closed["job_id"]) == published
        assert created == (published["state"] == "queued")
        assert (
            first.close_replay_submission(
                SOURCE, submitted, submission_id=submission_id, intent_digest=digest
            )
            == published
        )
    assert len(first.list_jobs()) == 12


def test_store_refuses_wrong_digest_and_closure_survives_restart(tmp_path):
    store = ProductStore(tmp_path / "product.sqlite3")
    payload = stale_request()
    submission_id, digest, submitted = replay_job_submission(SOURCE, payload)
    with pytest.raises(ProductStoreError):
        store.close_replay_submission(
            SOURCE, submitted, submission_id=submission_id, intent_digest="sha256:" + "0" * 64
        )
    closed = store.close_replay_submission(
        SOURCE, submitted, submission_id=submission_id, intent_digest=digest
    )
    restarted = ProductStore(store.path)
    assert restarted.recover_interrupted_jobs() == 0
    assert (
        restarted.close_replay_submission(
            SOURCE, deepcopy(submitted), submission_id=submission_id, intent_digest=digest
        )
        == closed
    )
    assert restarted.create_idempotent_job(
        "scenario.replay", {}, submission_id=submission_id, intent_digest=digest
    ) == (closed, False)


def test_resolution_refuses_inconsistent_terminal_marker(service):
    payload = stale_request()
    closed = service.resolve_replay_submission(SOURCE, payload)
    store = service.product_store
    store.transition_job(
        closed["job"]["job_id"],
        "cancelled",
        progress={"phase": "closed_submission", "effects_started": True},
    )
    with pytest.raises(APIError) as rejected:
        service.resolve_replay_submission(SOURCE, payload)
    assert rejected.value.code == "replay_submission_resolution_refused"
