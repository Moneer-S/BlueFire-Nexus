"""Saved product journeys with an explicit synthetic executor; no cloud or credentials."""

import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from bluefire import product_store_s3_access as records
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore, RunStoreError
from bluefire.s3_access_contract import S3AccessError, S3AccessScope
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_access_policy import plan_hardening
from bluefire.s3_access_wire import operation_plan
from tests_platform.test_s3_access_policy import fixture

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


class SyntheticExecutor:
    def __init__(self):
        self.scope, self.policy = fixture()
        self.calls = []
        self.hardened = False
        self.ready = True
        self.cleanup = "verified"
        self.uncertain_write = False
        self.drift = False
        self.probe_always_reads = False

    def environments(self):
        return [
            {
                "environment_id": "test-environment",
                "display_name": "Synthetic S3 environment",
                "scope": self.scope.to_dict(),
                "baseline_policy": self.policy,
                "exclusive_writer_digest": "sha256:" + "e" * 64,
            }
        ]

    def readiness(self, scope):
        assert scope.digest == self.scope.digest
        return {
            "available": self.ready,
            "problem": None if self.ready else "runtime_unavailable",
            "runner_profile_id": "synthetic-s3",
            "worker_generation": "sha256:" + "c" * 64,
            "runtime_digest": "sha256:" + "d" * 64,
        }

    def execute(self, request, *, authorization, cancellation_event, before_dispatch=None):
        assert authorization["request_digest"] == request.digest
        assert authorization["scope_digest"] == self.scope.digest
        assert not cancellation_event.is_set()
        source = request.to_dict()
        self.calls.append((source, deepcopy(authorization)))
        operation = source["operation"]
        calls = [
            {
                "operation": op,
                "role": role,
                "request_id": f"synthetic-{len(self.calls)}-{index}",
                "http_status": 200,
            }
            for index, (_, op, role) in enumerate(operation_plan(request))
        ]
        change = plan_hardening(self.scope, self.policy).to_dict()
        if operation == "apply_policy":
            self.hardened = True
        elif operation == "rollback_policy":
            self.hardened = False
        if operation in {"probe_read", "legitimate_read"}:
            reader = "probe" if operation == "probe_read" else "legitimate"
            objects = [
                {"result": "read", **{key: value for key, value in obj.items() if key != "key"}}
                for obj in source["scope"]["objects"][: 1 if reader == "probe" else 2]
            ]
            if reader == "probe" and self.hardened and not self.probe_always_reads:
                objects = [{"purpose": "primary", "result": "service_denied"}]
                calls[-1].update(http_status=403, error_code="AccessDenied")
            data = {"reader": reader, "objects": objects, "effective_access_claim": False}
        else:
            data = {
                "policy_digest": (
                    change["after_digest"] if self.hardened else change["before_digest"]
                ),
                "structural_review": (
                    "supported_baseline" if operation == "inspect_policy" else "exact_readback"
                ),
            }
            if operation == "reconcile_policy":
                data["structural_review"] = (
                    "drift"
                    if self.drift
                    else "matched_after" if self.hardened else "matched_before"
                )
                if self.drift:
                    data["policy_digest"] = "sha256:" + "f" * 64
        worker = {
            "schema_version": "bluefire.s3-worker-result.v1",
            "request_digest": request.digest,
            "outcome": "observed",
            "data": data,
            "problem": None,
            "send_permits_consumed": len(calls),
            "calls": calls,
            "runtime_isolation_proven": False,
        }
        unknown = self.uncertain_write and operation == "apply_policy"
        if unknown:
            worker.update(
                outcome="reconcile_required", data=None, problem="write_outcome_unsettled"
            )
        return {
            "schema_version": "bluefire.s3-execution.v1",
            "request_digest": request.digest,
            "admission": {"accepted": True, "problem": None},
            "dispatch": "unknown" if unknown else "permit_issued",
            "send_debits": len(calls),
            "result": worker,
            "cleanup": self.cleanup,
            "provenance": "synthetic",
            "reservation_digest": "sha256:" + "a" * 64,
        }


@pytest.fixture
def app(tmp_path):
    store = ProductStore(tmp_path / "product.db")
    runs = RunStore(tmp_path / "runs")
    with RunJobController(store, max_workers=1) as controller:
        service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
        executor = SyntheticExecutor()
        jobs = S3AccessJobs(service, executor, clock=lambda: NOW)
        yield jobs, executor


def create(jobs):
    context = jobs.environments()["environments"][0]
    return jobs.create(
        {
            "submission_id": str(uuid.uuid4()),
            "environment_id": "test-environment",
            "context_digest": context["context_digest"],
        }
    )


def stage(jobs, owner_id, phase):
    review = jobs.review(owner_id, {"phase": phase})
    request = {
        "submission_id": str(uuid.uuid4()),
        "phase": phase,
        "review_digest": review["review_digest"],
        "reviewed_by": "test operator",
    }
    jobs.submit(owner_id, request)
    job = jobs.controller.wait("job-" + uuid.UUID(request["submission_id"]).hex, timeout=5)
    assert job["state"] == "completed", job
    return jobs.read(owner_id), request


def through_baseline(jobs):
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "inspect")
    stage(jobs, owner, "baseline")
    return owner


def test_saved_full_journey_is_synthetic_and_reload_never_dispatches(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    applied, original = stage(jobs, owner, "apply")
    assert applied["policy_state"] == "hardened"
    retest, _ = stage(jobs, owner, "retest")
    assert retest["operations"][-1]["outcome"]["state"] == "denied_with_legitimate_reads"
    assert retest["operations"][-1]["outcome"]["provenance"] == "synthetic"
    assert retest["independent_observations"] == 0 and retest["live_outcome_verified"] is False
    calls = len(executor.calls)
    assert jobs.read(owner) == retest
    jobs.submit(owner, original)
    assert len(executor.calls) == calls
    assert len({row[0]["request_id"] for row in executor.calls}) == calls
    assert len({row[0]["launch_id"] for row in executor.calls}) == calls
    rolled_back, _ = stage(jobs, owner, "rollback")
    assert rolled_back["policy_state"] == "baseline"
    assert rolled_back["allowed_phases"] == []
    for operation in rolled_back["operations"]:
        for run_id in operation["run_ids"]:
            assert jobs.runs.validate_bundle(run_id)["valid"] is True
            assert jobs.runs.get_run(run_id)["evidence"]["records"][0]["provenance"] == "synthetic"


def test_changed_duplicate_submission_refuses_without_new_dispatch(app):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    _, request = stage(jobs, owner, "inspect")
    with pytest.raises(ProductStoreError):
        jobs.submit(owner, {**request, "reviewed_by": "another operator"})
    assert len(executor.calls) == 1


def test_uncertain_write_requires_fresh_read_only_reconcile_not_reapply(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    executor.uncertain_write = True
    uncertain, _ = stage(jobs, owner, "apply")
    assert uncertain["allowed_phases"] == ["reconcile"]
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "apply"})
    reconciled, _ = stage(jobs, owner, "reconcile")
    assert reconciled["policy_state"] == "hardened"
    assert executor.calls[-1][0]["operation"] == "reconcile_policy"
    assert executor.calls[-1][0]["exclusive_writer_digest"] is None


def test_cleanup_unknown_never_enables_next_stage(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    executor.cleanup = "unknown"
    state, _ = stage(jobs, owner, "apply")
    assert state["policy_state"] == "uncertain"
    assert state["allowed_phases"] == []
    assert state["operations"][-1]["outcome"]["cleanup"] == "unknown"


def test_stale_review_refuses_after_stop(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    review = jobs.review(owner, {"phase": "apply"})
    jobs.stop(owner, {})
    with pytest.raises(S3AccessError):
        jobs.submit(
            owner,
            {
                "submission_id": str(uuid.uuid4()),
                "phase": "apply",
                "review_digest": review["review_digest"],
                "reviewed_by": "test",
            },
        )
    assert all(row[0]["operation"] != "apply_policy" for row in executor.calls)


def test_unavailable_runtime_preserves_saved_result_readability(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    executor.ready = False
    state = jobs.read(owner)
    assert len(state["operations"]) == 2 and state["allowed_phases"] == [] and state["problem"]


def test_policy_drift_never_becomes_reconciled_success(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    executor.uncertain_write = True
    stage(jobs, owner, "apply")
    executor.drift = True
    state, _ = stage(jobs, owner, "reconcile")
    assert state["policy_state"] == "drift"
    assert "rollback" not in state["allowed_phases"]


def test_unchanged_probe_success_is_a_failed_defensive_outcome(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    executor.probe_always_reads = True
    state, _ = stage(jobs, owner, "retest")
    assert state["operations"][-1]["outcome"]["state"] == "defense_not_confirmed"


def test_different_duplicate_outcome_rejected_atomically(app):
    jobs, _ = app
    owner = through_baseline(jobs)
    stored = jobs._owner(owner)["progress"]["operations"][0]
    records.finish(jobs.store, stored["operation_job_id"], stored["executions"], stored["run_ids"])
    altered = deepcopy(stored["executions"])
    altered[0]["reservation_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ProductStoreError, match="different immutable"):
        records.finish(jobs.store, stored["operation_job_id"], altered, stored["run_ids"])
    assert jobs._owner(owner)["progress"]["operations"][0] == stored


def test_run_tamper_blocks_future_reviews(app):
    jobs, _ = app
    owner = through_baseline(jobs)
    run_id = jobs._owner(owner)["progress"]["operations"][0]["run_ids"][0]
    jobs.runs.write_json(run_id, "evidence.json", {"records": []})
    with pytest.raises(RunStoreError, match="integrity"):
        jobs.review(owner, {"phase": "apply"})


def submit_failed_stage(jobs, owner, phase):
    review = jobs.review(owner, {"phase": phase})
    submission_id = str(uuid.uuid4())
    jobs.submit(
        owner,
        {
            "submission_id": submission_id,
            "phase": phase,
            "review_digest": review["review_digest"],
            "reviewed_by": "test operator",
        },
    )
    job = jobs.controller.wait("job-" + uuid.UUID(submission_id).hex, timeout=5)
    assert job["state"] == "failed", job
    return job


def test_recover_sealed_result_after_outcome_commit_failure_never_dispatches(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)
    original = records.finish
    monkeypatch.setattr(
        records,
        "finish",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("simulated database outage")),
    )
    job = submit_failed_stage(jobs, owner, "apply")
    assert jobs.read(owner)["saved_result_recovery_available"] is True
    assert jobs.read(owner)["operations"][-1]["phase"] == "baseline"
    calls = len(executor.calls)
    monkeypatch.setattr(records, "finish", original)
    recovered = jobs.recover(owner, {})
    assert recovered["policy_state"] == "hardened"
    assert recovered["operations"][-1]["operation_job_id"] == job["job_id"]
    assert jobs.recover(owner, {}) == recovered
    assert len(executor.calls) == calls
    assert jobs.store.get_job(job["job_id"])["state"] == "failed"


def test_outcome_transaction_rolls_back_before_reopen_and_original_result_recovery(
    app, monkeypatch
):
    jobs, executor = app
    owner = through_baseline(jobs)
    original = records.patch

    def database_failure(connection, document, update):
        original(connection, document, update)
        if "operations" in update:
            raise RuntimeError("failure after update but before transaction commit")

    monkeypatch.setattr(records, "patch", database_failure)
    job = submit_failed_stage(jobs, owner, "apply")
    reopened = ProductStore(jobs.store.path)
    retained = reopened.get_job(owner)
    assert retained["progress"]["pending_operation"] == job["job_id"]
    assert retained["progress"]["operations"][-1]["phase"] == "baseline"
    assert retained["progress"]["policy_state"] == "baseline"
    calls = len(executor.calls)
    monkeypatch.setattr(records, "patch", original)
    jobs.store = reopened
    recovered = jobs.recover(owner, {})
    assert recovered["policy_state"] == "hardened"
    assert recovered["active_job"] is None
    assert len(executor.calls) == calls
    assert reopened.get_job(job["job_id"])["state"] == "failed"


def test_partial_retest_preserves_cleanup_if_second_request_never_started(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    original = executor.execute

    def lose_readiness_after_probe(request, **kwargs):
        result = original(request, **kwargs)
        executor.ready = False
        return result

    monkeypatch.setattr(executor, "execute", lose_readiness_after_probe)
    submit_failed_stage(jobs, owner, "retest")
    executor.ready = True
    state = jobs.read(owner)
    assert state["operations"][-1]["outcome"]["cleanup"] == "verified"
    assert state["operations"][-1]["outcome"]["complete"] is False
    assert state["operations"][-1]["outcome"]["state"] == "failed"
    assert state["allowed_phases"] == ["reconcile"]


def test_exception_after_second_dispatch_slot_keeps_cleanup_unknown(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    original = executor.execute

    def unknown_second_dispatch(request, **kwargs):
        if request.to_dict()["operation"] == "legitimate_read":
            raise RuntimeError("no confirmed native response")
        return original(request, **kwargs)

    monkeypatch.setattr(executor, "execute", unknown_second_dispatch)
    job = submit_failed_stage(jobs, owner, "retest")
    state = jobs.read(owner)
    assert len(job["progress"]["run_ids"]) == 2
    assert state["active_job"]["job_id"] == job["job_id"]
    assert state["operations"][-1]["phase"] == "apply"
    assert state["saved_result_recovery_available"] is True
    assert state["allowed_phases"] == []
    calls = len(executor.calls)
    with pytest.raises(S3AccessError, match="sealed result"):
        jobs.recover(owner, {})
    assert len(executor.calls) == calls
    assert jobs.read(owner) == state


def test_result_published_before_callback_failure_remains_recoverable(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)
    original = jobs._finalize_run

    def published_then_failed(*args):
        original(*args)
        raise RuntimeError("process failed after immutable run publication")

    monkeypatch.setattr(jobs, "_finalize_run", published_then_failed)
    job = submit_failed_stage(jobs, owner, "apply")
    state = jobs.read(owner)
    assert state["saved_result_recovery_available"] is True
    assert state["active_job"]["job_id"] == job["job_id"]
    assert state["policy_state"] == "baseline"
    calls = len(executor.calls)
    recovered = jobs.recover(owner, {})
    assert recovered["policy_state"] == "hardened"
    assert recovered["operations"][-1]["run_ids"] == job["progress"]["run_ids"]
    assert recovered["active_job"] is None
    assert jobs.recover(owner, {}) == recovered
    assert len(executor.calls) == calls


@pytest.mark.parametrize("phase", ["inspect", "baseline"])
@pytest.mark.parametrize("admitted", [False, True])
def test_refused_read_stage_requires_fresh_review_without_refunding_budget(
    app, monkeypatch, phase, admitted
):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    if phase == "baseline":
        stage(jobs, owner, "inspect")
    original = executor.execute

    def refused(request, **kwargs):
        return {
            "schema_version": "bluefire.s3-execution.v1",
            "request_digest": request.digest,
            "admission": {
                "accepted": admitted,
                "problem": None if admitted else "admission_refused",
            },
            "dispatch": "not_started",
            "send_debits": 0,
            "result": None,
            "cleanup": "verified",
            "provenance": "synthetic",
            "reservation_digest": "sha256:" + "b" * 64 if admitted else None,
        }

    before = jobs.read(owner)["remaining"]
    monkeypatch.setattr(executor, "execute", refused)
    refused_state, prior = stage(jobs, owner, phase)
    assert refused_state["allowed_phases"] == [phase]
    assert refused_state["operations"][-1]["outcome"]["cleanup"] == "verified"
    assert refused_state["remaining"]["api_calls"] < before["api_calls"]
    with pytest.raises(S3AccessError, match="fresh review"):
        jobs.submit(owner, {**prior, "submission_id": str(uuid.uuid4())})
    monkeypatch.setattr(executor, "execute", original)
    retried, fresh = stage(jobs, owner, phase)
    assert fresh["submission_id"] != prior["submission_id"]
    assert fresh["review_digest"] != prior["review_digest"]
    assert retried["remaining"]["api_calls"] < refused_state["remaining"]["api_calls"]
    assert retried["operations"][-1]["outcome"]["state"] == "observed"
    calls = len(executor.calls)
    jobs.submit(owner, prior)
    assert len(executor.calls) == calls


def test_partial_baseline_retries_with_new_requests_and_retains_first_read(app, monkeypatch):
    jobs, executor = app
    owner = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "inspect")
    original = executor.execute

    def lose_readiness_after_probe(request, **kwargs):
        value = original(request, **kwargs)
        executor.ready = False
        return value

    monkeypatch.setattr(executor, "execute", lose_readiness_after_probe)
    job = submit_failed_stage(jobs, owner, "baseline")
    executor.ready = True
    partial = jobs.read(owner)
    assert partial["allowed_phases"] == ["baseline"]
    assert partial["operations"][-1]["run_ids"] == job["progress"]["run_ids"]
    assert partial["operations"][-1]["outcome"]["cleanup"] == "verified"
    assert partial["operations"][-1]["outcome"]["facts"][0]["result"] == "read"
    monkeypatch.setattr(executor, "execute", original)
    retried, _ = stage(jobs, owner, "baseline")
    assert retried["allowed_phases"] == []
    assert "required fresh access checks" in retried["problem"]
    assert retried["operations"][-2] == partial["operations"][-1]
    assert len({row[0]["request_id"] for row in executor.calls}) == len(executor.calls)
    assert retried["remaining"]["sessions"] < partial["remaining"]["sessions"]
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "apply"})


@pytest.mark.parametrize("api_calls,allowed", [(24, False), (31, False), (32, True)])
def test_apply_requires_fresh_checks_and_recovery_capacity(app, api_calls, allowed):
    jobs, executor = app
    scope = executor.scope.to_dict()
    scope["limits"]["api_calls"] = api_calls
    executor.scope = S3AccessScope.from_mapping(scope)
    owner = through_baseline(jobs)
    state = jobs.read(owner)
    assert ("apply" in state["allowed_phases"]) is allowed
    assert state["remaining"]["api_calls"] == api_calls - 11
    calls = len(executor.calls)
    if allowed:
        review = jobs.review(owner, {"phase": "apply"})
        assert review["reserved"]["api_calls"] == 4
        assert review["required_remaining"]["api_calls"] == 21
        assert review["required_remaining"]["rollbacks"] == 1
    else:
        assert "recovery allowance" in state["problem"]
        with pytest.raises(S3AccessError):
            jobs.review(owner, {"phase": "apply"})
    assert len(executor.calls) == calls


def test_reconciliation_preserves_restore_and_uncertain_restore_inspection(app, monkeypatch):
    jobs, executor = app
    scope = executor.scope.to_dict()
    scope["limits"]["api_calls"] = 32
    executor.scope = S3AccessScope.from_mapping(scope)
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    before_retest, _ = stage(jobs, owner, "reconcile")
    assert before_retest["remaining"]["api_calls"] == 15
    assert "reconcile" not in before_retest["allowed_phases"]
    assert "retest" in before_retest["allowed_phases"]
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "reconcile"})
    reconciled, _ = stage(jobs, owner, "retest")
    assert reconciled["remaining"]["api_calls"] == 6
    assert reconciled["allowed_phases"] == ["rollback"]
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "reconcile"})
    original = executor.execute

    def lose_restore_ack(request, **kwargs):
        value = original(request, **kwargs)
        if request.to_dict()["operation"] == "rollback_policy":
            value["dispatch"] = "unknown"
            value["result"].update(
                outcome="reconcile_required", data=None, problem="write_outcome_unsettled"
            )
        return value

    monkeypatch.setattr(executor, "execute", lose_restore_ack)
    unsettled, _ = stage(jobs, owner, "rollback")
    assert unsettled["remaining"]["api_calls"] == 2
    assert unsettled["remaining"]["rollbacks"] == 0
    assert unsettled["allowed_phases"] == ["reconcile"]
    settled, _ = stage(jobs, owner, "reconcile")
    assert settled["policy_state"] == "baseline"
    assert settled["remaining"]["api_calls"] == 0
    assert settled["allowed_phases"] == []


def test_successful_restore_readback_is_terminal_without_extra_dispatch(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    restored, _ = stage(jobs, owner, "rollback")
    assert restored["operations"][-1]["outcome"]["state"] == "observed"
    assert restored["allowed_phases"] == []
    calls = len(executor.calls)
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "reconcile"})
    assert len(executor.calls) == calls


@pytest.mark.parametrize("ready", [True, False])
def test_expired_business_window_preserves_only_ready_recovery_phases(app, ready):
    jobs, executor = app
    owner = through_baseline(jobs)
    stage(jobs, owner, "apply")
    scope = executor.scope.to_dict()
    jobs.clock = lambda: NOW + timedelta(seconds=scope["limits"]["business_seconds"] + 1)
    executor.ready = ready
    calls = len(executor.calls)
    state = jobs.read(owner)
    assert state["allowed_phases"] == (["rollback", "reconcile"] if ready else [])
    assert len(executor.calls) == calls
    with pytest.raises(S3AccessError):
        jobs.review(owner, {"phase": "retest"})
    if ready:
        review = jobs.review(owner, {"phase": "rollback"})
        assert review["phase"] == "rollback"
        restored, _ = stage(jobs, owner, "rollback")
        assert restored["policy_state"] == "baseline"
        assert executor.calls[-1][0]["operation"] == "rollback_policy"
        assert len(executor.calls) == calls + 1
    else:
        assert "unavailable" in state["problem"]
        with pytest.raises(S3AccessError):
            jobs.review(owner, {"phase": "rollback"})
        assert len(executor.calls) == calls


def test_admission_refusal_retains_known_zero_dispatch_and_cleanup(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)

    def refused(request, **kwargs):
        return {
            "schema_version": "bluefire.s3-execution.v1",
            "request_digest": request.digest,
            "admission": {"accepted": False, "problem": "admission_refused"},
            "dispatch": "not_started",
            "send_debits": 0,
            "result": None,
            "cleanup": "verified",
            "provenance": "synthetic",
            "reservation_digest": None,
        }

    monkeypatch.setattr(executor, "execute", refused)
    state, _ = stage(jobs, owner, "apply")
    outcome = state["operations"][-1]["outcome"]
    assert outcome["state"] == "failed" and outcome["cleanup"] == "verified"
    assert state["allowed_phases"] == ["reconcile"]


def test_other_exercise_cannot_overwrite_hardened_bucket(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    second = create(jobs)["workflow_job_id"]
    stage(jobs, owner, "apply")
    review = jobs.review(second, {"phase": "inspect"})
    calls = len(executor.calls)
    with pytest.raises(ProductStoreError, match="bucket reserved"):
        jobs.submit(
            second,
            {
                "submission_id": str(uuid.uuid4()),
                "phase": "inspect",
                "review_digest": review["review_digest"],
                "reviewed_by": "test",
            },
        )
    assert len(executor.calls) == calls
