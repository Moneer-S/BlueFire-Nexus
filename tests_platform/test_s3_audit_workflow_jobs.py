"""Application receipt fixtures only; no native, SDK, credentials or AWS proof.

The fixture models authenticated host replies to exercise saved-workflow joins.
Its runner-reported labels are test inputs, never independent execution evidence.
"""

import uuid
from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import product_store_s3_access as records
from bluefire import s3_access_results as results
from bluefire import s3_audit_collection_contract as audit
from bluefire import s3_audit_reviews as reviews
from bluefire import s3_audit_wire as wire
from bluefire import s3_audit_workflow as workflow
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore
from bluefire.s3_access_audit import correlate_read_pair
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_access_recovery import execution_manifest, validate_recovery_context
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.util import content_hash
from tests_platform.test_s3_access_jobs import (
    NOW,
    SyntheticExecutor,
    create,
    stage,
    through_baseline,
    wait_for_stage,
)
from tests_platform.test_s3_audit_admission import audit_admitted, original_context
from tests_platform.test_s3_audit_collection_contract import listing_rows, source_row


class ReceiptExecutor(SyntheticExecutor):
    def __init__(self):
        super().__init__()
        _request, context = original_context(audit_admitted())
        self.profile = context["profile"]
        self.identity = context["transport_identity"]
        self.receipts = {}
        self.recovered = []
        self.collection_supported = True

    def environments(self):
        return [{**super().environments()[0], "audit_source": source_row(self.scope)}]

    def readiness(self, scope):
        return {**super().readiness(scope), "runner_profile_id": self.profile["profile_id"]}

    def supports_operation(self, scope, operation):
        assert scope.digest == self.scope.digest
        return self.ready and self.collection_supported and operation == "collect_audit"

    def execute(self, request, *, authorization, cancellation_event, before_dispatch, run_id):
        manifest = execution_manifest(request, authorization, self.profile, run_id=run_id)
        transport_hash = content_hash({"manifest": manifest, "profile": self.profile})
        context = {
            "schema_version": "bluefire.s3-original-task.v2",
            "request_digest": request.digest,
            "manifest": manifest,
            "profile": deepcopy(self.profile),
            "transport_identity": deepcopy(self.identity),
            "transport_request_hash": transport_hash,
            "task_id": "execute-" + transport_hash.removeprefix("sha256:"),
        }
        before_dispatch(context)
        if request.to_dict()["operation"] == "collect_audit":
            assert not cancellation_event.is_set()
            self.calls.append((request.to_dict(), deepcopy(authorization)))
            execution = self._collection(request)
        else:
            execution = super().execute(
                request,
                authorization=authorization,
                cancellation_event=cancellation_event,
            )
            execution.update(
                provenance="runner_reported",
                reservation_digest=content_hash({"request": request.digest}),
            )
        self.receipts[context["task_id"]] = deepcopy(execution)
        return execution

    def _collection(self, request):
        raw = request.to_dict()
        reservation = content_hash({"request": request.digest})
        found = audit.discovery(
            self.scope,
            raw["audit"],
            request_digest=request.digest,
            reservation_digest=reservation,
            listings=listing_rows(self.scope, raw["audit"], count=0),
        )
        originals = raw["audit"]["original_pair"]["reads"]
        correlated = correlate_read_pair(
            S3WorkerRequest.from_mapping(originals[0]["request"]),
            originals[0]["result"],
            S3WorkerRequest.from_mapping(originals[1]["request"]),
            originals[1]["result"],
            [],
            delivery_state="incomplete",
        )
        calls = [
            {
                "operation": operation,
                "role": role,
                "request_id": f"collection-{index}",
                "http_status": 200,
            }
            for index, (_, operation, role) in enumerate(wire.operation_plan(raw, selected_count=0))
        ]
        for index in range(len(calls) - 3):
            calls[index + 3]["request_id"] = f"list-request-{index}"
        result = {
            "schema_version": wire.RESULT_SCHEMA,
            "request_digest": request.digest,
            "outcome": "observed",
            "problem": None,
            "send_permits_consumed": len(calls),
            "calls": calls,
            "runtime_isolation_proven": False,
            "data": {
                "schema_version": wire.OBSERVATION_SCHEMA,
                "collection_digest": content_hash(raw["audit"]),
                "pair_digest": content_hash(raw["audit"]["original_pair"]),
                "audit_source_digest": raw["audit_authority_digest"],
                "reservation_digest": reservation,
                "discovery": found["durable"],
                "objects": [],
                "usage": {
                    "sdk_body_bytes": 1000,
                    "compressed_bytes": 0,
                    "expanded_bytes": 0,
                    "files": 0,
                    "events": 0,
                },
                "normalized_digest": content_hash(correlated["audit"]),
                "correlations": correlated["correlations"],
                "delivery_state": "incomplete",
                "effective_access_claim": False,
                "log_integrity_proven": False,
            },
        }
        return {
            "schema_version": "bluefire.s3-execution.v1",
            "request_digest": request.digest,
            "admission": {"accepted": True, "problem": None},
            "dispatch": "permit_issued",
            "send_debits": len(calls),
            "result": result,
            "cleanup": self.cleanup,
            "provenance": "runner_reported",
            "reservation_digest": reservation,
        }

    def recover_original(self, request, original):
        checked = validate_recovery_context(request, original)
        self.recovered.append(checked["task_id"])
        return {"status": "finalized", "execution": deepcopy(self.receipts[checked["task_id"]])}


@pytest.fixture
def app(tmp_path):
    store, runs = ProductStore(tmp_path / "product.db"), RunStore(tmp_path / "runs")
    with RunJobController(store, max_workers=1) as controller:
        service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
        executor = ReceiptExecutor()
        yield S3AccessJobs(service, executor, clock=lambda: NOW), executor


@pytest.fixture
def released(app, monkeypatch):
    monkeypatch.setattr(workflow, "DISPATCH_RELEASED", True)
    return app


def submit(jobs, owner, phase):
    reviewed = jobs.review(owner, {"phase": phase})
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": phase,
        "review_digest": reviewed["review_digest"],
        "reviewed_by": "test operator",
    }
    jobs.submit(owner, request)
    identifier = "job-" + uuid.UUID(request["submission_id"]).hex
    return wait_for_stage(jobs, identifier), request


def test_collection_remains_closed_with_distinct_actual_original_run_ids(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    value = jobs.read(owner)
    assert value["schema_version"] == "bluefire.s3-exercise.v3"
    assert "audit_baseline" not in value["allowed_phases"]
    slot = value["audit_collection"]["slots"][0]
    assert slot["problem"] == "collection_not_enabled"
    pair = slot["original_pair"]
    assert len({row["run_id"] for row in pair["reads"]}) == 2
    child = jobs.store.get_job(pair["operation_job_id"])
    for row in pair["reads"]:
        context = child["progress"]["original_tasks"][row["run_id"]]
        assert context["schema_version"] == "bluefire.s3-original-task.v2"
        assert context["manifest"]["run_id"] == row["run_id"]
        assert row["manifest_digest"] == content_hash(context["manifest"])
    assert len(executor.calls) == 3


@pytest.mark.parametrize("support", [False, None])
def test_missing_native_collection_support_keeps_original_reads(released, support):
    jobs, executor = released
    owner = through_baseline(jobs)
    calls = len(executor.calls)
    if support is None:
        executor.supports_operation = None
    else:
        executor.collection_supported = False
    value = jobs.read(owner)
    assert "audit_baseline" not in value["allowed_phases"]
    slot = value["audit_collection"]["slots"][0]
    assert slot["problem"] == "collection_not_enabled"
    assert len(slot["original_pair"]["reads"]) == 2
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "audit_baseline"})
    assert len(executor.calls) == calls
    assert jobs._owner(owner)["progress"]["audit_slots"] == {}


def test_paired_collection_journey_has_two_immutable_reviews_and_no_reload_dispatch(released):
    jobs, executor = released
    owner = through_baseline(jobs)
    baseline, first_request = stage(jobs, owner, "audit_baseline")
    assert baseline["policy_state"] == "baseline"
    stage(jobs, owner, "apply")
    stage(jobs, owner, "retest")
    final, _request = stage(jobs, owner, "audit_retest")
    assert final["policy_state"] == "hardened"
    assert final["audit"] == "authenticated_retrieval"
    assert final["independent_observations"] == 0 and final["live_outcome_verified"] is False
    history = reviews.list_reviews(jobs, owner)
    assert history["schema_version"] == "bluefire.s3-audit-reviews.v2"
    assert [row["phase"] for row in history["collections"]] == ["baseline", "retest"]
    assert history["reviews"] == [] and history["maximum_collections"] == 2
    for row in history["collections"]:
        detail = reviews.read_review(jobs, owner, row["review_id"])
        assert detail["schema_version"] == "bluefire.s3-audit-collected-review.v1"
        assert detail["receipt"]["result"]["data"]["delivery_state"] == "incomplete"
        assert detail["log_integrity_proven"] is False and detail["effective_access_claim"] is False
        assert detail["raw_bytes_retained"] is False
        assert (
            detail["reservation_digest"]
            == detail["receipt"]["result"]["data"]["reservation_digest"]
        )
        assert detail["collection_run_id"] not in row["original_run_ids"]
        assert len(row["statuses"]) == 3
    before = len(executor.calls)
    assert jobs.read(owner) == final
    jobs.submit(owner, first_request)
    assert reviews.list_reviews(jobs, owner) == history
    assert len(executor.calls) == before
    assert final["audit_collection"]["held"]["batches"] == 0
    assert final["audit_collection"]["reserved"]["api_calls"] == 18
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "audit_baseline"})
    with pytest.raises(ProductStoreError):
        jobs.submit(owner, {**first_request, "reviewed_by": "different reviewer"})


def test_audit_holds_reserve_reads_and_both_collections_before_inspection(app):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    review = jobs.review(owner, {"phase": "inspect"})
    assert review["required_remaining"]["api_calls"] == 38
    assert review["required_remaining"]["sessions"] == 6
    assert review["required_remaining"]["business_attempts"] == 6
    assert jobs.read(owner)["audit_collection"]["held"]["api_calls"] == 18
    assert executor.calls == []


def test_insufficient_combined_authority_refuses_without_any_dispatch(app):
    jobs, executor = app
    raw = executor.scope.to_dict()
    raw["limits"]["api_calls"] = 37
    executor.scope = S3AccessScope.from_mapping(raw)
    owner = create(jobs)["workflow_job_id"]
    assert jobs.read(owner)["allowed_phases"] == []
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "inspect"})
    assert executor.calls == []


def test_collection_preserves_policy_recovery_holds_and_policy_state(released):
    jobs, _executor = released
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    stage(jobs, owner, "retest")
    review = jobs.review(owner, {"phase": "audit_baseline"})
    assert review["required_remaining"]["api_calls"] == 24
    assert review["required_remaining"]["rollbacks"] == 1
    after, _request = stage(jobs, owner, "audit_baseline")
    assert after["policy_state"] == "hardened"
    assert "rollback" in after["allowed_phases"]


def test_shortened_collection_manifest_preserves_actual_issue_and_deadline(released):
    jobs, _executor = released
    owner = through_baseline(jobs)
    jobs.clock = lambda: NOW + timedelta(seconds=1795)
    review = jobs.review(owner, {"phase": "audit_baseline"})
    child, _request = submit(jobs, owner, "audit_baseline")
    assert child["state"] == "completed"
    run_id = child["progress"]["run_ids"][0]
    context = child["progress"]["original_tasks"][run_id]
    raw = child["request"]["worker_requests"][0]
    assert raw["audit"]["issued_at"] == "2026-10-09T00:29:55Z"
    assert raw["deadline"] == review["audit_collection"]["collection_expires_at"]
    assert context["manifest"]["requested_at"] == raw["audit"]["issued_at"]
    assert context["manifest"]["expires_at"] == raw["deadline"]
    assert context["manifest"]["limits"]["timeout_ms"] == 5000


@pytest.mark.parametrize("changed", ["source", "host"])
def test_changed_source_or_original_host_never_dispatches_collection(
    released, monkeypatch, changed
):
    jobs, executor = released
    owner = through_baseline(jobs)
    count = len(executor.calls)
    if changed == "source":
        original = executor.environments

        def changed_environments():
            rows = original()
            rows[0]["audit_source"]["audit_source_id"] = "replacement-trail"
            return rows

        monkeypatch.setattr(executor, "environments", changed_environments)
        with pytest.raises(S3AccessError):
            jobs.review(owner, {"phase": "audit_baseline"})
    else:
        executor.identity["inventory_digest"] = "sha256:" + "b" * 64
        child, _request = submit(jobs, owner, "audit_baseline")
        assert child["state"] == "failed"
        assert jobs.read(owner)["saved_result_recovery_available"] is True
    assert len(executor.calls) == count


def test_original_task_recovery_after_publication_failure_does_not_repeat_or_renew(
    released, monkeypatch
):
    jobs, executor = released
    owner = through_baseline(jobs)
    original = jobs._publish_run

    def fail_collection(run_id, owner_id, operation_id, request, execution):
        if request.to_dict()["operation"] == "collect_audit":
            raise RuntimeError("local publication interrupted")
        return original(run_id, owner_id, operation_id, request, execution)

    monkeypatch.setattr(jobs, "_publish_run", fail_collection)
    child, _request = submit(jobs, owner, "audit_baseline")
    assert child["state"] == "failed"
    before = len(executor.calls)
    original_payload = deepcopy(child["request"]["worker_requests"])
    assert jobs.read(owner)["saved_result_recovery_available"] is True
    jobs.stop(owner, {})
    jobs.clock = lambda: NOW + timedelta(hours=2)
    executor.ready = False
    executor.collection_supported = False
    monkeypatch.setattr(jobs, "_publish_run", original)
    recovered = jobs.recover(owner, {})
    assert recovered["active_job"] is None and recovered["stopped"] is True
    assert recovered["audit"] == "authenticated_retrieval"
    assert len(executor.calls) == before and len(executor.recovered) == 1
    assert jobs.store.get_job(child["job_id"])["request"]["worker_requests"] == original_payload
    assert len(reviews.list_reviews(jobs, owner)["collections"]) == 1
    jobs.recover(owner, {})
    assert len(executor.recovered) == 1


def test_unknown_cleanup_consumes_collection_slot_without_opening_other_work(released):
    jobs, executor = released
    owner = through_baseline(jobs)
    executor.cleanup = "unknown"
    state, _request = stage(jobs, owner, "audit_baseline")
    assert state["audit_collection"]["slots"][0]["state"] == "failed"
    assert state["audit_collection"]["reserved"]["api_calls"] == 9
    assert state["allowed_phases"] == []
    assert reviews.list_reviews(jobs, owner)["collections"] == []
    count = len(executor.calls)
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "audit_baseline"})
    assert len(executor.calls) == count


@pytest.mark.parametrize("changed", ["slot", "receipt", "manifest"])
def test_collected_history_rejects_changed_original_joins(released, changed):
    jobs, _executor = released
    owner = through_baseline(jobs)
    stage(jobs, owner, "audit_baseline")
    current = jobs._owner(owner)
    collected_id = current["progress"]["audit_slots"]["baseline"]["operation_job_id"]
    with jobs.store._connection(write=True) as connection:
        if changed == "slot":
            slots = deepcopy(current["progress"]["audit_slots"])
            slots["baseline"]["pair_digest"] = "sha256:" + "f" * 64
            records.patch(connection, current, {"audit_slots": slots})
        else:
            identifier = (
                collected_id
                if changed == "receipt"
                else current["progress"]["audit_read_slots"]["baseline"]["operation_job_id"]
            )
            child = records.job_at(jobs.store, connection, identifier)
            if changed == "receipt":
                receipt = deepcopy(child["progress"]["collected_review"])
                receipt["reservation_digest"] = "sha256:" + "f" * 64
                records.patch(connection, child, {"collected_review": receipt})
            else:
                contexts = deepcopy(child["progress"]["original_tasks"])
                contexts[next(iter(contexts))]["manifest"]["run_id"] = (
                    "run-20261009T000000Z-" + "f" * 16
                )
                records.patch(connection, child, {"original_tasks": contexts})
    with pytest.raises((S3AccessError, ProductStoreError)):
        reviews.read_review(jobs, owner, collected_id)


def test_historical_audited_owner_keeps_recovery_without_adopting_collection(released):
    jobs, _executor = released
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    current = deepcopy(jobs._owner(owner))
    for key in ("audit_workflow", "audit_read_slots", "audit_slots"):
        del current["progress"][key]
    assert workflow.retained(current) is False
    assert set(results.allowed_phases(current)) == {"rollback", "reconcile"}
    assert results.required_remaining(current, "rollback")["api_calls"] == 6
    assert (
        workflow.projection(current, {}, {})["slots"][0]["problem"] == "historical_authority_absent"
    )


def test_historical_audited_owner_submits_existing_recovery_without_minting_slots(released):
    jobs, executor = released
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    current = jobs._owner(owner)
    historical = deepcopy(current["progress"])
    for key in ("audit_workflow", "audit_read_slots", "audit_slots"):
        del historical[key]
    with jobs.store._connection(write=True) as connection:
        connection.execute(
            "UPDATE jobs SET progress_json = ? WHERE job_id = ?",
            (records.canonical_json(historical), owner),
        )
    before = len(executor.calls)
    for phase in ("baseline", "retest", "audit_baseline", "audit_retest"):
        with pytest.raises(S3AccessError):
            jobs.submit(
                owner,
                {
                    "submission_id": str(uuid.uuid4()),
                    "phase": phase,
                    "review_digest": "sha256:" + "0" * 64,
                    "reviewed_by": "test operator",
                },
            )
    assert len(executor.calls) == before
    restored, _request = stage(jobs, owner, "rollback")
    assert restored["policy_state"] == "baseline"
    assert len(executor.calls) == before + 1
    saved = jobs._owner(owner)
    assert not {"audit_workflow", "audit_read_slots", "audit_slots"} & set(saved["progress"])
    assert (
        saved["progress"]["reserved"]["rollbacks"] == historical["reserved"].get("rollbacks", 0) + 1
    )
    assert restored["operations"][:-1] == [
        {key: value for key, value in row.items() if key != "executions"}
        for row in historical["operations"]
    ]


def test_original_task_v1_recovery_contract_remains_unchanged():
    request, context = original_context(audit_admitted())
    assert validate_recovery_context(request, context) == context
    assert (
        context["manifest"]["run_id"]
        == context["manifest"]["params"]["workflow_approval"]["operation_job_id"]
    )


def test_expired_audit_source_does_not_offer_or_create_a_new_exercise(app, monkeypatch):
    jobs, executor = app
    original = executor.environments

    def expiring_environment():
        rows = original()
        rows[0]["audit_source"]["expires_at"] = "2026-10-09T00:01:00Z"
        return rows

    monkeypatch.setattr(executor, "environments", expiring_environment)
    initial = jobs.environments()["environments"][0]
    assert initial["available"] is True
    jobs.clock = lambda: NOW + timedelta(minutes=1)
    expired = jobs.environments()["environments"][0]
    assert expired["available"] is False
    assert expired["runtime"]["available"] is True
    assert expired["problem"] == "The enrolled audit source has expired."
    assert expired["context_digest"] == initial["context_digest"]
    with pytest.raises(S3AccessError, match="not ready"):
        create(jobs)
    assert jobs.list_exercises()["exercises"] == []
    assert executor.calls == []


def test_source_expiry_keeps_saved_results_and_existing_recovery_available(released, monkeypatch):
    jobs, executor = released
    original = executor.environments

    def expiring_environment():
        rows = original()
        rows[0]["audit_source"]["expires_at"] = "2026-10-09T00:01:00Z"
        return rows

    monkeypatch.setattr(executor, "environments", expiring_environment)
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    before = deepcopy(jobs.read(owner)["operations"])
    jobs.clock = lambda: NOW + timedelta(minutes=1)
    expired = jobs.read(owner)
    assert expired["operations"] == before
    assert set(expired["allowed_phases"]) == {"rollback", "reconcile"}
    for phase in ("rollback", "reconcile", "reconcile_fixtures", "cleanup"):
        jobs._fresh(jobs._owner(owner), phase)
    for phase in ("retest", "audit_baseline"):
        with pytest.raises(S3AccessError):
            jobs.review(owner, {"phase": phase})
    restored, _request = stage(jobs, owner, "rollback")
    assert restored["policy_state"] == "baseline"
    assert restored["operations"][:-1] == before
    assert reviews.list_reviews(jobs, owner)["reads"]
    executor.ready = False
    with pytest.raises(S3AccessError):
        jobs._fresh(jobs._owner(owner), "cleanup")
    executor.ready = True
    jobs.clock = lambda: NOW + timedelta(hours=2)
    with pytest.raises(S3AccessError):
        jobs._fresh(jobs._owner(owner), "cleanup")
