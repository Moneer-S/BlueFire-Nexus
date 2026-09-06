"""Durable replay tests: Simulate and a deliberately nonexecuting fake runner."""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy

import pytest

from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.job_runtime import JobCancelled, JobState
from bluefire.orchestrator import Orchestrator
from bluefire.product_store import ProductStoreError
from bluefire.runner_transport_errors import RunnerTaskCancelled
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_replay_preparation import ROOT, SCOPE, forbid, source_run
from tests_platform.test_replay_preparation import service as service


def submission(service, source, *, options=None):
    options = options or ({"target_scope": SCOPE} if source["mode"] == "execute" else {})
    prepared = service.prepare_replay(source["run_id"], options)
    return {
        **prepared["replay_request"],
        "preparation_id": prepared["preparation_id"],
        "preparation_context": prepared["preparation_context"],
        "submission_id": str(uuid.uuid4()),
    }


def awaiting(service, job_id):
    return service.job_controller.wait_for_state(job_id, {JobState.AWAITING_APPROVAL}, timeout=10)


def test_simulate_replay_job_returns_finalized_result_with_original_lineage(service):
    source = source_run(service)
    payload = submission(
        service, source, options={"parameter_overrides": {"create_fixture": {"record_count": 3}}}
    )
    created = service.submit_replay(source["run_id"], payload)
    job_id = created["job"]["job_id"]
    assert created["job"]["kind"] == "scenario.replay"
    assert created["approval_request"] is None
    completed = service.job_controller.wait(job_id, timeout=10)
    assert completed["state"] == "completed"
    result = service.detail(completed["result_ref"])
    assert service.store.validate_bundle(result["run_id"])["valid"] is True
    assert result["scenario"] == created["preparation"]["scenario"]
    assert result["plan"] == created["preflight"]["plan"]
    assert result["replay"] == created["preparation"]["lineage"]
    assert result["replay"]["source_run_id"] == source["run_id"]
    assert service.job(job_id)["request"]["replay_preparation"]["preflight"] == created["preflight"]
    assert service.submit_replay(source["run_id"], payload)["job"]["job_id"] == job_id
    assert len(service.store.list_runs()) == 2


def test_concurrent_duplicate_submissions_publish_one_callback_and_refuse_changed_reuse(
    service, monkeypatch
):
    source = source_run(service)
    payload = submission(service, source)
    entered, release = threading.Event(), threading.Event()
    calls = []
    original = service._replay_locked

    def held(*args, **kwargs):
        calls.append(args[0])
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "_replay_locked", held)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: service.submit_replay(source["run_id"], deepcopy(payload)), range(2)
                )
            )
        assert results[0]["job"]["job_id"] == results[1]["job"]["job_id"]
        assert entered.wait(10)
        assert len(calls) == 1
        with pytest.raises(APIError) as error:
            service.submit_replay(source["run_id"], {**payload, "defense_change": "changed reuse"})
        assert error.value.code == "replay_job_refused"
    finally:
        release.set()
    service.job_controller.wait(results[0]["job"]["job_id"], timeout=10)
    assert len(calls) == 1


def test_execute_replay_job_consumes_one_fresh_approval_and_claims_it_once(service):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    created = service.submit_replay(source["run_id"], payload)
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    profile = service._profile("sandbox-execute.v1", service._mode({"mode": "execute"}))
    runner, sandbox = service.runner_factory(profile)
    assert runner.execute_calls == 0
    assert not (sandbox / ".bluefire-executions").exists()
    assert created["approval_request"]["status"] == "pending"
    assert created["approval_request"]["approved_by"] is None
    assert "nonce" not in created["approval_request"]
    assert service.active_jobs()["jobs"][0]["kind"] == "scenario.replay"
    duplicated = service.submit_replay(source["run_id"], payload)
    assert (
        duplicated["approval_request"]["approval_id"] == created["approval_request"]["approval_id"]
    )
    approved = service.approve_job(job_id, {"approved_by": "replay-reviewer"})
    assert approved["approval_request"]["status"] == "consumed"
    completed = service.job_controller.wait(job_id, timeout=10)
    assert completed["state"] == "completed", completed
    assert runner.execute_calls > 0  # The fixture refuses every action; no native effect exists.
    count = runner.execute_calls
    pending_id = created["approval_request"]["approval_id"]
    assert service.product_store.get_approval_request(pending_id)["status"] == "claimed"
    with pytest.raises(APIError):
        service.approve_job(job_id, {"approved_by": "duplicate-reviewer"})
    assert service.submit_replay(source["run_id"], payload)["job"]["job_id"] == job_id
    assert runner.execute_calls == count
    result = service.detail(completed["result_ref"])
    assert service.store.validate_bundle(result["run_id"])["valid"]
    assert result["replay"] == created["preparation"]["lineage"]


@pytest.mark.parametrize("phase", ["submission", "approval", "dispatch"])
def test_source_drift_is_refused_before_effect_release_at_each_phase(service, monkeypatch, phase):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    if phase != "submission":
        created = service.submit_replay(source["run_id"], payload)
        job_id = created["job"]["job_id"]
        awaiting(service, job_id)
    original = service.store.get_run

    def drift(run_id):
        return {**original(run_id), "changed_source": True}

    monkeypatch.setattr(service, "_replay_locked", forbid)
    if phase == "dispatch":
        original_execute = service._execute_replay_job

        def changed_after_approval(*args, **kwargs):
            monkeypatch.setattr(service.store, "get_run", drift)
            return original_execute(*args, **kwargs)

        monkeypatch.setattr(service, "_execute_replay_job", changed_after_approval)
        service.approve_job(job_id, {"approved_by": "reviewer"})
        assert service.job_controller.wait(job_id, timeout=10)["state"] == "failed"
    else:
        monkeypatch.setattr(service.store, "get_run", drift)
        with pytest.raises(APIError):
            if phase == "submission":
                service.submit_replay(source["run_id"], payload)
            else:
                service.approve_job(job_id, {"approved_by": "reviewer"})
        if phase == "approval":
            assert service.job(job_id)["approval_request"]["status"] == "pending"


def test_replay_job_progress_pause_resume_and_cancel_use_owned_context(service, monkeypatch):
    source = source_run(service)
    entered, proceed = threading.Event(), threading.Event()

    def controlled(_source, _payload, *, checkpoint, cancel_event, **_kwargs):
        entered.set()
        assert proceed.wait(10)
        checkpoint({"phase": "replaying", "completed_steps": 1})
        assert cancel_event.wait(10)
        raise JobCancelled("bounded fake replay cancellation confirmed")

    monkeypatch.setattr(service, "_replay_locked", controlled)
    created = service.submit_replay(source["run_id"], submission(service, source))
    job_id = created["job"]["job_id"]
    try:
        assert entered.wait(10)
        service.pause_job(job_id)
        proceed.set()
        paused = service.job_controller.wait_for_state(job_id, {JobState.PAUSED}, timeout=10)
        assert paused["progress"]["completed_steps"] == 1
        assert paused["result_ref"] is None
        service.resume_job(job_id)
        service.cancel_job(job_id)
        assert service.job_controller.wait(job_id, timeout=10)["state"] == "cancelled"
        assert service.job(job_id)["result_ref"] is None
    finally:
        proceed.set()


def test_restart_returns_existing_interrupted_job_and_retry_creates_fresh_approval(
    service, monkeypatch, tmp_path
):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    created = service.submit_replay(source["run_id"], payload)
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    service.close()
    # File-only crash fixture: restore the last persisted pre-dispatch state.
    with service.product_store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='awaiting_approval' WHERE job_id=?", (job_id,))
    restarted = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", runner_factory=service.runner_factory
    )
    try:
        monkeypatch.setattr(restarted, "_replay_locked", forbid)
        recovered = restarted.submit_replay(source["run_id"], payload)
        assert recovered["job"]["job_id"] == job_id
        assert recovered["job"]["state"] == "interrupted"
        assert restarted.active_jobs()["jobs"] == []
        with pytest.raises(APIError):
            restarted.approve_job(job_id, {"approved_by": "stale"})
        retried = restarted.retry_job(job_id)
        awaiting(restarted, retried["job"]["job_id"])
        assert retried["job"]["job_id"] != job_id
        assert (
            retried["approval_request"]["approval_id"] != created["approval_request"]["approval_id"]
        )
        assert retried["approval_request"]["status"] == "pending"
        lineage = retried["source_job"]["progress"]["retry_lineage"][-1]
        assert lineage["request_digest"] == content_hash(retried["job"]["request"])
    finally:
        restarted.close()


@pytest.mark.parametrize(
    "cancelled", [AIProviderCancelled(), RunnerTaskCancelled("bounded transport cancellation")]
)
def test_replay_forwards_cancellation_to_orchestrator_and_retains_cancelled_state(
    service, monkeypatch, cancelled
):
    source = source_run(service)
    payload = submission(service, source)
    entered = threading.Event()

    def cancelled_run(_self, _scenario, *, checkpoint, cancel_event, **_kwargs):
        checkpoint({"completed_steps": 1})
        entered.set()
        assert cancel_event.wait(10)
        raise cancelled

    monkeypatch.setattr(Orchestrator, "run", cancelled_run)
    job_id = service.submit_replay(source["run_id"], payload)["job"]["job_id"]
    assert entered.wait(10)
    service.cancel_job(job_id)
    result = service.job_controller.wait(job_id, timeout=10)
    assert result["state"] == "cancelled"
    assert result["result_ref"] is None
    assert result["progress"]["completed_steps"] == 1


def test_retry_refuses_unsettled_execute_workspace(service, monkeypatch):
    source = source_run(service, execute=True)
    created = service.submit_replay(source["run_id"], submission(service, source))
    job_id = created["job"]["job_id"]
    awaiting(service, job_id)
    service.cancel_job(job_id)
    service.job_controller.wait(job_id, timeout=10)
    with service.product_store._connection(write=True) as connection:
        connection.execute("UPDATE jobs SET state='interrupted' WHERE job_id=?", (job_id,))

    def unsettled(_request):
        from bluefire.product_store import ProductStoreError

        raise ProductStoreError("Execute workspace cleanup is active or deferred")

    monkeypatch.setattr(service, "_assert_execute_retry_settled", unsettled)
    monkeypatch.setattr(service, "prepare_replay", forbid)
    with pytest.raises(APIError, match="could not be retried"):
        service.retry_job(job_id)


def test_replay_proposal_review_retains_intermediate_result_until_continuation_finishes(
    service, monkeypatch
):
    from tests_platform.test_ai_integration import AlternateProposalProvider

    source = source_run(service)
    monkeypatch.setattr(
        service,
        "ai_provider_factory",
        lambda config, provider_id: AlternateProposalProvider(config.provider(provider_id)),
    )
    payload = submission(service, source, options={"autonomy": "assist"})
    created = service.submit_replay(source["run_id"], payload)
    job_id = created["job"]["job_id"]
    pending = awaiting(service, job_id)
    assert pending["result_ref"] is not None
    assert pending["state"] == "awaiting_approval"
    intermediate = service.detail(pending["result_ref"])
    assert intermediate["status"] == "awaiting_approval"
    assert intermediate["replay"]["source_run_id"] == source["run_id"]
    review_id = pending["progress"]["proposal_record_id"]
    review = service.proposal_review(job_id, review_id)
    service.accept_proposal_review(
        job_id,
        review_id,
        {
            "decided_by": "replay-proposal-reviewer",
            "state_digest": review["state_digest"],
            "plan_digest": review["plan_digest"],
            "proposal_digest": review["proposal_digest"],
        },
    )
    completed = service.job_controller.wait(job_id, timeout=10)
    assert completed["state"] == "completed", completed["error"]
    assert completed["result_ref"] != pending["result_ref"]
    final = service.detail(completed["result_ref"])
    assert final["replay"]["proposal_resolution"]["proposal_record_id"] == review_id
    assert service.store.validate_bundle(final["run_id"])["valid"]


@pytest.mark.parametrize(
    "change", ["approval", "missing_uuid", "invalid_uuid", "checkpoint", "missing_preparation"]
)
def test_replay_job_rejects_unreviewed_submission_fields(service, monkeypatch, change):
    source = source_run(service)
    payload = submission(service, source)
    if change == "approval":
        payload["approval"] = {"confirmed": True, "approved_by": "caller"}
    elif change == "missing_uuid":
        del payload["submission_id"]
    elif change == "invalid_uuid":
        payload["submission_id"] = "caller-key"
    elif change == "checkpoint":
        payload["from_step_id"] = "discover_records"
    else:
        del payload["preparation_context"]
    monkeypatch.setattr(service.job_controller, "submit", forbid)
    with pytest.raises(APIError) as error:
        service.submit_replay(source["run_id"], payload)
    assert error.value.code == "replay_job_refused"


@pytest.mark.parametrize("failure", ["capacity", "closed", "store", "schedule"])
def test_failed_publication_withdraws_only_the_new_pending_approval(service, monkeypatch, failure):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    approvals = []
    create = service.product_store.create_approval_request

    def capture(**kwargs):
        value = create(**kwargs)
        approvals.append(value)
        return value

    def fail(*_args, **_kwargs):
        raise ProductStoreError("bounded publication fault")

    monkeypatch.setattr(service.product_store, "create_approval_request", capture)
    if failure == "capacity":
        monkeypatch.setattr(service.job_controller._capacity, "acquire", lambda **_kwargs: False)
    elif failure == "closed":
        service.job_controller.shutdown()
    elif failure == "store":
        monkeypatch.setattr(service.product_store, "create_idempotent_job", fail)
    else:
        monkeypatch.setattr(service.job_controller._executor, "submit", fail)
    with pytest.raises(APIError):
        service.submit_replay(source["run_id"], payload)
    assert len(approvals) == 1
    withdrawn = service.product_store.get_approval_request(approvals[0]["approval_id"])
    assert withdrawn["status"] == "withdrawn"
    assert withdrawn["nonce"] is None
    assert service.job_controller.active_job_ids == ()


@pytest.mark.parametrize("publication", ["response_failure", "race_winner"])
def test_publication_reconciliation_preserves_the_winning_jobs_approval(
    service, monkeypatch, publication
):
    source = source_run(service, execute=True)
    payload = submission(service, source)
    approvals = []
    create = service.product_store.create_approval_request
    submit = service.job_controller.submit

    def capture(**kwargs):
        value = create(**kwargs)
        approvals.append(value)
        return value

    def publish(kind, request, **kwargs):
        if publication == "race_winner":
            pending = approvals[0]
            winner = create(
                **{
                    field: pending[field]
                    for field in (
                        "run_id",
                        "state_digest",
                        "plan_digest",
                        "profile_id",
                        "target_scope_digest",
                        "maximum_tier",
                        "expires_at",
                    )
                }
            )
            request = {**request, "approval_request_id": winner["approval_id"]}
        job = submit(kind, request, **kwargs)
        if publication == "response_failure":
            raise ProductStoreError("publication succeeded before response failed")
        return job

    monkeypatch.setattr(service.product_store, "create_approval_request", capture)
    monkeypatch.setattr(service.job_controller, "submit", publish)
    if publication == "response_failure":
        with pytest.raises(APIError):
            service.submit_replay(source["run_id"], payload)
    else:
        service.submit_replay(source["run_id"], payload)
    recovered = service.submit_replay(source["run_id"], payload)
    awaiting(service, recovered["job"]["job_id"])
    assert recovered["approval_request"]["status"] == "pending"
    own = service.product_store.get_approval_request(approvals[0]["approval_id"])
    assert own["status"] == ("pending" if publication == "response_failure" else "withdrawn")
    assert len(service.product_store.list_jobs()) == 1


@pytest.mark.parametrize("lock_kind", ["local", "shared"])
@pytest.mark.parametrize("phase", ["review", "dispatch"])
def test_replay_cancellation_interrupts_catalog_wait_without_releasing_other_owner(
    service, monkeypatch, lock_kind, phase
):
    source = source_run(service)
    payload = submission(service, source)
    waiting, proceed, held, release, attempted = (threading.Event() for _ in range(5))
    execute = service._execute_replay_job
    review = service._review_replay_job
    local_lock = service._action_catalog_lock
    shared_lease = service.product_store.action_package_catalog_lease

    class TrackingLock:
        def acquire(self, *args, **kwargs):
            if proceed.is_set() and threading.current_thread() is not holder:
                attempted.set()
            return local_lock.acquire(*args, **kwargs)

        def release(self):
            return local_lock.release()

        def __enter__(self):
            self.acquire()
            return self

        def __exit__(self, *_args):
            self.release()

    @contextmanager
    def tracking_lease(**kwargs):
        if proceed.is_set() and kwargs.get("cancel_event") is not None:
            attempted.set()
        with shared_lease(**kwargs):
            yield

    def gate_execute(*args, **kwargs):
        if phase == "review":
            waiting.set()
            assert proceed.wait(10)
        return execute(*args, **kwargs)

    def gate_review(*args, **kwargs):
        result = review(*args, **kwargs)
        if phase == "dispatch":
            waiting.set()
            assert proceed.wait(10)
        return result

    def hold():
        lock = (
            service._action_catalog_lock
            if lock_kind == "local"
            else service.product_store.action_package_catalog_lease()
        )
        with lock:
            held.set()
            assert release.wait(10)

    monkeypatch.setattr(service, "_execute_replay_job", gate_execute)
    monkeypatch.setattr(service, "_review_replay_job", gate_review)
    monkeypatch.setattr(service, "_replay_locked", forbid)
    if lock_kind == "local":
        monkeypatch.setattr(service, "_action_catalog_lock", TrackingLock())
    else:
        monkeypatch.setattr(service.product_store, "action_package_catalog_lease", tracking_lease)
    job_id = service.submit_replay(source["run_id"], payload)["job"]["job_id"]
    holder = threading.Thread(target=hold)
    try:
        assert waiting.wait(10)
        holder.start()
        assert held.wait(10)
        proceed.set()
        assert attempted.wait(10)
        service.cancel_job(job_id)
        assert service.job_controller.wait(job_id, timeout=3)["state"] == "cancelled"
        assert holder.is_alive()
    finally:
        proceed.set()
        release.set()
        if holder.ident is not None:
            holder.join(10)
    assert not holder.is_alive()
