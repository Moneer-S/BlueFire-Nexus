"""Durable file-access admission with inert callbacks; no native task is dispatched."""

from types import SimpleNamespace

import pytest

from bluefire.job_runtime import JobQueueFull, JobRuntimeError, JobState, RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_file_access import KIND
from bluefire.util import content_hash


@pytest.fixture
def submission(tmp_path):
    store = ProductStore(tmp_path / "factory.db")
    enrollment = {
        "enrollment_id": "file-enrollment-" + "b" * 32,
        "root": {"path": str(tmp_path / "retained")},
        "expires_at_ms": 1_800_000,
    }
    enrollment_digest = content_hash(enrollment)
    store.save_file_access_enrollment(enrollment, expected_document_digest=enrollment_digest)
    context = {"enrollment_digest": enrollment_digest}
    review_body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": "create",
        "control_owner_id": None,
        "context_digest": content_hash(context),
        "enrollment_digest": enrollment_digest,
        "control_digest": None,
        "expires_at_ms": 1_800_000,
        "effect": "Authored reservation fixture; no file operation runs.",
    }
    review = {**review_body, "review_digest": content_hash(review_body)}
    request = {
        "submission_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "review": {"operation": "create", "control_owner_id": None},
        "review_digest": review["review_digest"],
        "reviewed_by": "Authored operator",
    }
    calls = []

    def reserve():
        calls.append("reserve")
        return store.create_file_access_operation(
            request,
            review_document=review,
            review_context=context,
            enrollment_id=enrollment["enrollment_id"],
            now_ms=1000,
        )

    return SimpleNamespace(
        store=store,
        request=request,
        reserve=reserve,
        calls=calls,
        identity={
            "submission_id": request["submission_id"],
            "intent_digest": content_hash(request),
        },
    )


def hold_slot(context, request):
    while True:
        context.cooperative_wait(1)


def test_capacity_refusal_does_not_call_factory_or_reserve_resource(submission):
    with RunJobController(submission.store, max_workers=1, max_pending_jobs=1) as controller:
        held = controller.submit("scenario.run", {}, callback=hold_slot)
        controller.wait_for_state(held["job_id"], {JobState.RUNNING}, timeout=5)
        with pytest.raises(JobQueueFull, match="capacity"):
            controller.submit(
                KIND,
                submission.request,
                callback=lambda *_: None,
                submission_factory=submission.reserve,
                **submission.identity,
            )
        assert submission.calls == []
        assert submission.store.get_job_submission(KIND, **submission.identity) is None
        assert [job["job_id"] for job in submission.store.list_jobs()] == [held["job_id"]]


def test_factory_failure_releases_capacity_without_a_durable_reservation(submission):
    received = []

    def refused():
        raise ProductStoreError("Authored reservation refusal")

    with RunJobController(submission.store, max_workers=1, max_pending_jobs=1) as controller:
        with pytest.raises(ProductStoreError, match="reservation refusal"):
            controller.submit(
                KIND,
                submission.request,
                callback=lambda *_: None,
                submission_factory=refused,
                **submission.identity,
            )
        assert submission.store.get_job_submission(KIND, **submission.identity) is None
        assert submission.store.list_jobs() == []
        queued = controller.submit(
            KIND,
            submission.request,
            callback=lambda _context, marker: received.append(marker),
            submission_factory=submission.reserve,
            **submission.identity,
        )
        completed = controller.wait(queued["job_id"], timeout=5)
    assert completed["state"] == "completed"
    assert received == [queued["request"]]
    assert received[0]["schema_version"] == "bluefire.file-access-operation-request.v1"
    assert submission.calls == ["reserve"]
    assert submission.store.file_access_operation_records(queued["job_id"])["tasks"] == []


def test_scheduling_failure_preserves_reservation_and_exact_replay_without_dispatch(
    submission, monkeypatch
):
    callbacks = []

    def cannot_schedule(*args, **kwargs):
        raise RuntimeError("Authored scheduling failure")

    with RunJobController(submission.store, max_workers=1, max_pending_jobs=1) as controller:
        with monkeypatch.context() as patch:
            patch.setattr(controller._executor, "submit", cannot_schedule)
            with pytest.raises(RuntimeError, match="scheduling failure"):
                controller.submit(
                    KIND,
                    submission.request,
                    callback=lambda *_: callbacks.append("dispatch"),
                    submission_factory=submission.reserve,
                    **submission.identity,
                )
            saved = submission.store.get_job_submission(KIND, **submission.identity)
            assert saved["state"] == "failed"
            assert saved["error"]["code"] == "job_scheduling_failed"
            assert saved["progress"]["submitted_request"] == submission.request
            replay = controller.submit(
                KIND,
                submission.request,
                callback=lambda *_: callbacks.append("dispatch"),
                submission_factory=submission.reserve,
                **submission.identity,
            )
            assert replay == saved
            assert controller.active_job_ids == ()
        admitted = controller.submit("scenario.run", {}, callback=lambda *_: None)
        assert controller.wait(admitted["job_id"], timeout=5)["state"] == "completed"
    records = submission.store.file_access_operation_records(saved["job_id"])
    assert records["document"]["submitted_request"] == submission.request
    assert records["preparation"] is None and records["tasks"] == []
    assert callbacks == [] and submission.calls == ["reserve"]


@pytest.mark.parametrize("corruption", ["snapshot", "created", "raised_after_reservation"])
def test_invalid_factory_result_cannot_leave_an_accepted_operation_queued(submission, corruption):
    callbacks = []

    def invalid_factory():
        saved, created = submission.reserve()
        if corruption == "raised_after_reservation":
            raise RuntimeError("Authored failure after reservation")
        if corruption == "created":
            return saved, 1
        return {**saved, "kind": "scenario.run"}, created

    with RunJobController(submission.store, max_workers=1, max_pending_jobs=1) as controller:
        with pytest.raises((JobRuntimeError, RuntimeError)):
            controller.submit(
                KIND,
                submission.request,
                callback=lambda *_: callbacks.append("dispatch"),
                submission_factory=invalid_factory,
                **submission.identity,
            )
        saved = submission.store.get_job_submission(KIND, **submission.identity)
        assert saved["state"] == "failed"
        assert saved["error"]["code"] == "job_scheduling_failed"
        replay = controller.submit(
            KIND,
            submission.request,
            callback=lambda *_: callbacks.append("dispatch"),
            submission_factory=submission.reserve,
            **submission.identity,
        )
        assert replay == saved
        assert controller.active_job_ids == ()
    assert callbacks == [] and submission.calls == ["reserve"]
    assert submission.store.file_access_operation_records(saved["job_id"])["tasks"] == []


def test_exact_unknown_operation_replay_needs_no_capacity_factory_or_new_effect(submission):
    saved, _ = submission.reserve()
    failed = submission.store.transition_job(
        saved["job_id"], "failed", error={"code": "authored_uncertainty"}
    )
    submission.store.finish_file_access_operation(
        saved["job_id"], outcome={"state": "unknown", "evidence_digest": content_hash([])}
    )
    before = submission.store.file_access_operation_records(saved["job_id"])
    callbacks = []
    with RunJobController(submission.store, max_workers=1, max_pending_jobs=1) as controller:
        held = controller.submit("scenario.run", {}, callback=hold_slot)
        controller.wait_for_state(held["job_id"], {JobState.RUNNING}, timeout=5)
        replay = controller.submit(
            KIND,
            submission.request,
            callback=lambda *_: callbacks.append("dispatch"),
            submission_factory=submission.reserve,
            **submission.identity,
        )
        assert replay == failed
        assert controller.active_job_ids == (held["job_id"],)
    assert submission.calls == ["reserve"] and callbacks == []
    assert submission.store.file_access_operation_records(saved["job_id"]) == before
    assert before["outcome"]["state"] == "unknown"
