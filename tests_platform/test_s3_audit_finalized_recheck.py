"""Original-task query fixtures, not native closure or cloud execution evidence."""

from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import product_store_s3_access as records
from bluefire import s3_access_executor as executor_module
from bluefire import s3_audit_workflow as workflow
from bluefire.job_runtime import RunJobController
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_jobs import S3AccessJobs
from tests_platform.test_s3_access_jobs import NOW, SyntheticExecutor, stage, through_baseline
from tests_platform.test_s3_audit_workflow_jobs import ReceiptExecutor, submit


@pytest.fixture
def app(tmp_path, monkeypatch):
    store, runs = ProductStore(tmp_path / "product.db"), RunStore(tmp_path / "runs")
    with RunJobController(store, max_workers=1) as controller:
        service = SimpleNamespace(product_store=store, store=runs, job_controller=controller)
        executor = ReceiptExecutor()
        monkeypatch.setattr(workflow, "DISPATCH_RELEASED", True)
        yield S3AccessJobs(service, executor, clock=lambda: NOW), executor


def unknown_collection(app, phase="baseline"):
    jobs, executor = app
    owner = through_baseline(jobs)
    if phase == "retest":
        stage(jobs, owner, "audit_baseline")
        stage(jobs, owner, "apply")
        stage(jobs, owner, "retest")
    executor.cleanup = "unknown"
    state, _request = stage(jobs, owner, "audit_" + phase)
    operation = state["audit_collection"]["slots"][0 if phase == "baseline" else 1][
        "operation_job_id"
    ]
    return owner, operation


def retained_snapshot(jobs, owner):
    value = jobs._owner(owner)
    children = [
        jobs.store.get_job(row["operation_job_id"]) for row in value["progress"]["operations"]
    ]
    runs = [
        jobs.runs.get_run(run_id)
        for row in value["progress"]["operations"]
        for run_id in row["run_ids"]
    ]
    return deepcopy({"owner": value, "children": children, "runs": runs})


@pytest.mark.parametrize("phase", ["baseline", "retest"])
def test_manual_recheck_preserves_unknown_result_and_authority_after_reload(app, phase):
    jobs, executor = app
    owner, operation = unknown_collection(app, phase)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    expected = jobs.read(owner)
    assert expected["active_job"] is None
    assert expected["saved_result_recovery_available"] is True
    assert expected["allowed_phases"] == []
    for _ in range(3):
        assert jobs.read(owner) == expected
    assert executor.recovered == []
    assert jobs.recover(owner, {}) == expected
    reloaded = S3AccessJobs(jobs.service, executor, clock=lambda: NOW)
    assert reloaded.recover(owner, {}) == expected
    assert len(executor.recovered) == 2
    child = jobs.store.get_job(operation)
    context = child["progress"]["original_tasks"][child["progress"]["run_ids"][0]]
    assert executor.recovered == [context["task_id"], context["task_id"]]
    assert executor.calls == calls
    assert retained_snapshot(jobs, owner) == before
    assert "collected_review" not in child["progress"]


def test_recheck_uses_original_interval_after_stop_expiry_and_runtime_unavailability(
    app, monkeypatch
):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    jobs.stop(owner, {})
    jobs.clock = lambda: NOW + timedelta(hours=3)
    executor.ready = False
    child = jobs.store.get_job(operation)
    run_id = child["progress"]["run_ids"][0]
    expected_context = deepcopy(child["progress"]["original_tasks"][run_id])
    expected_request = deepcopy(child["request"]["worker_requests"][0])
    original_recover = executor.recover_original
    seen = []

    def recover(request, context):
        seen.append((request.to_dict(), deepcopy(context)))
        return original_recover(request, context)

    monkeypatch.setattr(executor, "recover_original", recover)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    value = jobs.recover(owner, {})
    assert value["stopped"] is True and value["allowed_phases"] == []
    assert value["saved_result_recovery_available"] is True
    assert seen == [(expected_request, expected_context)]
    assert retained_snapshot(jobs, owner) == before
    assert executor.calls == calls


@pytest.mark.parametrize("status", ["running", "absent", "unavailable", "unexpected"])
def test_unavailable_original_task_does_not_change_saved_unknown_result(app, monkeypatch, status):
    jobs, executor = app
    owner, _operation = unknown_collection(app)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    monkeypatch.setattr(
        executor,
        "recover_original",
        lambda _request, _context: {
            "status": status,
            "execution": None,
        },
    )
    with pytest.raises(S3AccessError, match="Cleanup remains unresolved"):
        jobs.recover(owner, {})
    assert retained_snapshot(jobs, owner) == before
    assert executor.calls == calls
    assert jobs.read(owner)["allowed_phases"] == []


@pytest.mark.parametrize("change", ["cleanup", "result", "reservation", "extra_response"])
def test_recheck_refuses_changed_execution_even_when_cleanup_is_now_verified(
    app, monkeypatch, change
):
    jobs, executor = app
    owner, _operation = unknown_collection(app)
    original_recover = executor.recover_original

    def recover(request, context):
        response = original_recover(request, context)
        value = response["execution"]
        if change == "cleanup":
            value["cleanup"] = "verified"
        elif change == "result":
            value["result"]["data"]["usage"]["sdk_body_bytes"] += 1
        elif change == "reservation":
            value["reservation_digest"] = "sha256:" + "f" * 64
        else:
            response["closure_verified"] = True
        return response

    monkeypatch.setattr(executor, "recover_original", recover)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    with pytest.raises(S3AccessError):
        jobs.recover(owner, {})
    assert retained_snapshot(jobs, owner) == before
    assert executor.calls == calls


@pytest.mark.parametrize("change", ["task_id", "manifest", "host", "slot"])
def test_changed_original_task_join_is_rejected_before_any_host_recheck(app, change):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    with jobs.store._connection(write=True) as connection:
        if change == "slot":
            current = records.owner_at(jobs.store, connection, owner)
            slots = deepcopy(current["progress"]["audit_slots"])
            slots["baseline"]["pair_digest"] = "sha256:" + "f" * 64
            records.patch(connection, current, {"audit_slots": slots})
        else:
            child = records.job_at(jobs.store, connection, operation)
            contexts = deepcopy(child["progress"]["original_tasks"])
            context = contexts[child["progress"]["run_ids"][0]]
            if change == "task_id":
                context["task_id"] = "execute-" + "f" * 64
            elif change == "manifest":
                context["manifest"]["requested_at"] = "2026-10-11T00:00:00Z"
            else:
                context["transport_identity"]["inventory_digest"] = "sha256:" + "f" * 64
            records.patch(connection, child, {"original_tasks": contexts})
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    with pytest.raises((S3AccessError, ProductStoreError)):
        jobs.recover(owner, {})
    assert executor.recovered == []
    assert retained_snapshot(jobs, owner) == before
    assert executor.calls == calls


def test_missing_original_checkpoint_remains_readable_without_claiming_recheck_eligibility(app):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    with jobs.store._connection(write=True) as connection:
        child = records.job_at(jobs.store, connection, operation)
        records.patch(connection, child, {"original_tasks": {}})
    before = retained_snapshot(jobs, owner)
    value = jobs.read(owner)
    assert value["saved_result_recovery_available"] is False
    assert value["allowed_phases"] == []
    assert jobs.recover(owner, {}) == value
    assert executor.recovered == []
    assert retained_snapshot(jobs, owner) == before


def test_pending_result_recovery_precedes_finalized_unknown_recheck(app, monkeypatch):
    jobs, executor = app
    owner = through_baseline(jobs)
    executor.cleanup = "unknown"
    publish = jobs._publish_run

    def fail_collection(run_id, owner_id, operation_id, request, execution):
        if request.to_dict()["operation"] == "collect_audit":
            raise RuntimeError("local publication interrupted")
        return publish(run_id, owner_id, operation_id, request, execution)

    monkeypatch.setattr(jobs, "_publish_run", fail_collection)
    child, _request = submit(jobs, owner, "audit_baseline")
    assert child["state"] == "failed"
    assert jobs.read(owner)["active_job"]["job_id"] == child["job_id"]
    monkeypatch.setattr(jobs, "_publish_run", publish)
    calls = deepcopy(executor.calls)
    recovered = jobs.recover(owner, {})
    assert recovered["active_job"] is None
    assert recovered["saved_result_recovery_available"] is True
    assert recovered["allowed_phases"] == []
    assert len(executor.recovered) == 1
    before = retained_snapshot(jobs, owner)
    assert jobs.recover(owner, {}) == recovered
    assert len(executor.recovered) == 2
    assert executor.calls == calls
    assert retained_snapshot(jobs, owner) == before


def test_clean_finalized_collection_is_not_rechecked(app):
    jobs, executor = app
    owner = through_baseline(jobs)
    expected, _request = stage(jobs, owner, "audit_baseline")
    assert expected["saved_result_recovery_available"] is False
    before = retained_snapshot(jobs, owner)
    assert jobs.recover(owner, {}) == expected
    assert executor.recovered == []
    assert retained_snapshot(jobs, owner) == before


def test_legacy_finalized_unknown_result_keeps_existing_recovery_semantics(app, monkeypatch):
    audited_jobs, _executor = app
    executor = SyntheticExecutor()
    jobs = S3AccessJobs(audited_jobs.service, executor, clock=lambda: NOW)
    owner = through_baseline(jobs)
    executor.cleanup = "unknown"
    value, _request = stage(jobs, owner, "apply")
    assert value["schema_version"] == "bluefire.s3-exercise.v1"
    assert value["active_job"] is None
    assert value["saved_result_recovery_available"] is False

    def unexpected_recheck(_request, _context):
        pytest.fail("A historical ordinary outcome must not become a collection recheck.")

    monkeypatch.setattr(executor, "recover_original", unexpected_recheck, raising=False)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    assert jobs.recover(owner, {}) == value
    assert executor.calls == calls
    assert retained_snapshot(jobs, owner) == before


@pytest.mark.parametrize("change", ["slot", "context", "checkpoint_removed", "operation"])
def test_recheck_revalidates_saved_lineage_after_the_original_query(app, monkeypatch, change):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    before = retained_snapshot(jobs, owner)
    calls = deepcopy(executor.calls)
    child = jobs.store.get_job(operation)
    run_id = child["progress"]["run_ids"][0]
    context = deepcopy(child["progress"]["original_tasks"][run_id])
    original_recover = executor.recover_original
    fixture_state = []

    def recover(request, original):
        response = original_recover(request, original)
        with jobs.store._connection(write=True) as connection:
            current = records.owner_at(jobs.store, connection, owner)
            if change == "slot":
                slots = deepcopy(current["progress"]["audit_slots"])
                slots["baseline"]["pair_digest"] = "sha256:" + "f" * 64
                records.patch(connection, current, {"audit_slots": slots})
            elif change in {"context", "checkpoint_removed"}:
                saved = records.job_at(jobs.store, connection, operation)
                contexts = deepcopy(saved["progress"]["original_tasks"])
                if change == "context":
                    contexts[run_id]["task_id"] = "execute-" + "f" * 64
                else:
                    del contexts[run_id]
                records.patch(connection, saved, {"original_tasks": contexts})
            else:
                operations = deepcopy(current["progress"]["operations"])
                selected = next(row for row in operations if row["operation_job_id"] == operation)
                selected["outcome_digest"] = "sha256:" + "f" * 64
                records.patch(connection, current, {"operations": operations})
        fixture_state.append(retained_snapshot(jobs, owner))
        return response

    monkeypatch.setattr(executor, "recover_original", recover)
    with pytest.raises((S3AccessError, ProductStoreError)) as caught:
        jobs.recover(owner, {})
    if change == "checkpoint_removed":
        assert "changed during its original-task check" in str(caught.value)
    assert executor.recovered == [context["task_id"]]
    assert executor.calls == calls
    assert len(fixture_state) == 1
    assert retained_snapshot(jobs, owner) == fixture_state[0]
    assert fixture_state[0]["runs"] == before["runs"]
    progress = jobs._owner(owner)["progress"]
    for name in ("pending_operation", "reserved", "stopped", "audit_workflow", "audit_read_slots"):
        assert progress[name] == before["owner"]["progress"][name]
    if change != "slot":
        assert progress["audit_slots"] == before["owner"]["progress"]["audit_slots"]
    assert "collected_review" not in jobs.store.get_job(operation)["progress"]


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        "private malformed original response",
        {"status": "finalized"},
        {"status": "finalized", "execution": None},
        {"status": "finalized", "execution": []},
        {"status": "finalized", "execution": {}},
        {"status": "finalized", "execution": "private malformed execution"},
    ],
)
def test_malformed_finalized_recheck_response_preserves_all_saved_state(app, monkeypatch, response):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    before = retained_snapshot(jobs, owner)
    expected = jobs.read(owner)
    calls = deepcopy(executor.calls)
    child = jobs.store.get_job(operation)
    run_id = child["progress"]["run_ids"][0]
    context = deepcopy(child["progress"]["original_tasks"][run_id])
    seen = []

    def recover(request, original):
        seen.append((request.to_dict(), deepcopy(original)))
        return deepcopy(response)

    monkeypatch.setattr(executor, "recover_original", recover)
    with pytest.raises(S3AccessError) as caught:
        jobs.recover(owner, {})
    assert "private" not in str(caught.value)
    assert len(str(caught.value)) < 256
    assert seen == [(child["request"]["worker_requests"][0], context)]
    assert retained_snapshot(jobs, owner) == before
    assert jobs.read(owner) == expected
    assert expected["active_job"] is None and expected["allowed_phases"] == []
    assert executor.calls == calls
    assert "collected_review" not in jobs.store.get_job(operation)["progress"]


@pytest.mark.parametrize("error_type", [OSError, TimeoutError, RuntimeError])
def test_original_transport_failure_is_sanitized_without_changing_saved_authority(
    app,
    monkeypatch,
    error_type,
):
    jobs, executor = app
    owner, operation = unknown_collection(app)
    before = retained_snapshot(jobs, owner)
    expected = jobs.read(owner)
    calls = deepcopy(executor.calls)
    child = jobs.store.get_job(operation)
    run_id = child["progress"]["run_ids"][0]
    context = deepcopy(child["progress"]["original_tasks"][run_id])
    queried = []
    profiles = []

    class Client:
        def transport_identity(self):
            return deepcopy(context["transport_identity"])

        def recover(self, task_id, request_hash):
            queried.append((task_id, request_hash))
            raise error_type("private transport endpoint and credential detail")

        def execute_task(self, *args, **kwargs):
            pytest.fail("A finalized original-task recheck must not dispatch work.")

        def s3_access_environments(self):
            pytest.fail("A finalized original-task recheck must not discover a new environment.")

    client = Client()

    def client_for_profile(profile_id):
        profiles.append(profile_id)
        return client, None

    monkeypatch.setattr(executor_module, "AuthenticatedRunnerClient", Client)
    service = SimpleNamespace(
        runner_lifecycle=SimpleNamespace(client_for_profile=client_for_profile)
    )
    configured = executor_module.configured_executor(service)
    monkeypatch.setattr(executor, "recover_original", configured.recover_original)
    with pytest.raises(S3AccessError, match="Cleanup remains unresolved") as caught:
        jobs.recover(owner, {})
    assert "private" not in str(caught.value)
    assert len(str(caught.value)) < 256
    assert profiles == [context["profile"]["profile_id"]]
    assert queried == [(context["task_id"], context["transport_request_hash"])]
    assert retained_snapshot(jobs, owner) == before
    assert jobs.read(owner) == expected
    assert expected["active_job"] is None and expected["allowed_phases"] == []
    assert executor.calls == calls
    assert "collected_review" not in jobs.store.get_job(operation)["progress"]
