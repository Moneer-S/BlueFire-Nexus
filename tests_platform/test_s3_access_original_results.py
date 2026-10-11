"""Original-result adoption with a synthetic transport; never cloud execution."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from bluefire import product_store_s3_access as records
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore, RunStoreError
from bluefire.runner_contracts import seal_profile
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_access_recovery import execution_manifest, validate_recovery_context
from bluefire.s3_access_wire import S3WorkerRequest
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_s3_access_admission import admitted_fixture
from tests_platform.test_s3_access_jobs import (
    NOW,
    create,
    submit_failed_stage,
    through_baseline,
)
from tests_platform.test_s3_access_jobs import (
    app as app,
)


def context_for(request, approval):
    profile = seal_profile({**admitted_fixture()["profile"], "profile_id": "synthetic-s3"})
    manifest = execution_manifest(request, approval, profile)
    request_hash = content_hash({"manifest": manifest, "profile": profile})
    return validate_recovery_context(
        request,
        {
            "schema_version": "bluefire.s3-original-task.v1",
            "request_digest": request.digest,
            "task_id": "execute-" + request_hash.removeprefix("sha256:"),
            "transport_request_hash": request_hash,
            "manifest": manifest,
            "profile": profile,
            "transport_identity": {
                "schema_version": "bluefire.runner-transport-identity.v1",
                "runner_id": profile["runner_id"],
                "client_id": "synthetic.client",
                "transport": "mutual-tls-loopback",
                "tls": "TLSv1.3",
                **{
                    key: "sha256:" + "a" * 64
                    for key in (
                        "server_fingerprint",
                        "client_fingerprint",
                        "authenticated_peer_fingerprint",
                        "enrollment_generation",
                        "runner_binary_digest",
                        "inventory_digest",
                    )
                },
            },
        },
    )


@pytest.fixture
def transport_app(app, monkeypatch):
    jobs, executor = app
    ordinary = executor.execute
    state = SimpleNamespace(
        lose=None,
        status="finalized",
        saved={},
        recoveries=[],
        contexts={},
        alter_context=None,
        recovered_override=None,
        recovered=Event(),
    )

    def execute(request, *, authorization, cancellation_event, before_dispatch):
        original = context_for(request, authorization)
        if state.alter_context:
            original = state.alter_context(request, authorization, original)
        before_dispatch(original)
        child = jobs.store.get_job(authorization["operation_job_id"])
        run_id = child["progress"]["current_run_id"]
        assert child["progress"]["original_tasks"][run_id] == original
        state.contexts[request.digest] = original
        value = ordinary(
            request, authorization=authorization, cancellation_event=cancellation_event
        )
        state.saved[request.digest] = deepcopy(value)
        if request.to_dict()["operation"] == state.lose:
            raise ConnectionError("synthetic lost original response")
        return value

    def recover(request, context):
        assert context == state.contexts[request.digest]
        state.recoveries.append(request.digest)
        state.recovered.set()
        return {
            "status": state.status,
            "execution": (
                deepcopy(state.recovered_override or state.saved[request.digest])
                if state.status == "finalized"
                else None
            ),
        }

    monkeypatch.setattr(executor, "execute", execute)
    monkeypatch.setattr(executor, "recover_original", recover, raising=False)
    return jobs, executor, state


def lost_apply(transport_app):
    jobs, executor, state = transport_app
    owner = through_baseline(jobs)
    state.lose = "apply_policy"
    child = submit_failed_stage(jobs, owner, "apply")
    run_id = child["progress"]["run_ids"][0]
    request = S3WorkerRequest.from_mapping(child["request"]["worker_requests"][0])
    assert jobs.runs.get_run(run_id)["status"] == "created"
    return owner, child, run_id, request


@contextmanager
def restarted_service(transport_app):
    jobs, executor, _ = transport_app
    jobs.controller.shutdown()

    def forbidden_runner(*_args, **_kwargs):
        raise AssertionError("The synthetic recovery test must not contact a native runner.")

    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=jobs.runs.root,
        product_db_path=jobs.store.path,
        runner_factory=forbidden_runner,
        runner_lifecycle=SimpleNamespace(client_for_profile=forbidden_runner),
        s3_access_executor=executor,
    )
    try:
        service.s3_access.clock = lambda: NOW + timedelta(days=1)
        yield service
    finally:
        service.close()


def test_real_service_startup_interruption_preserves_original_recovery(transport_app):
    jobs, executor, state = transport_app
    owner, child, run_id, request = lost_apply(transport_app)
    checkpoint = deepcopy(child["progress"]["original_tasks"])
    executor.ready = False
    calls = deepcopy(executor.calls)
    with restarted_service(transport_app) as service:
        assert service.recovered_runs == 1
        interrupted = service.store.get_run(run_id)
        assert interrupted["status"] == "interrupted"
        assert [row["event_type"] for row in interrupted["events"]] == [
            "run.created",
            "run.interrupted",
        ]
        assert (
            service.product_store.get_job(child["job_id"])["progress"]["original_tasks"]
            == checkpoint
        )
        recovered = service.recover_s3_access(owner, {})
        assert recovered["policy_state"] == "hardened" and recovered["active_job"] is None
        assert recovered["allowed_phases"] == []
        final = service.store.get_run(run_id)
        assert final["events"][:2] == interrupted["events"]
        assert sum(row["event_type"] == "run.finalized" for row in final["events"]) == 1
        assert service.store.validate_bundle(run_id)["valid"]
        assert service.recover_s3_access(owner, {}) == recovered
        assert service.store.get_run(run_id) == final
    assert state.recoveries == [request.digest] and executor.calls == calls


@pytest.mark.parametrize(
    "boundary",
    [
        "s3.execution.result",
        "evidence.json",
        "detections.json",
        "result.json",
        "run.finalized",
        "manifest.json",
    ],
)
@pytest.mark.parametrize("after_restart", [False, True])
def test_each_partial_publication_boundary_refuses_recovery_without_rewrite(
    transport_app, monkeypatch, boundary, after_restart
):
    jobs, executor, state = transport_app
    owner, child, run_id, request = lost_apply(transport_app)
    original_write, original_event = jobs.runs.write_json, jobs.runs.append_event

    def write(identifier, name, value):
        if identifier == run_id and boundary == name == "manifest.json":
            raise RuntimeError("synthetic interruption before manifest publication")
        result = original_write(identifier, name, value)
        if identifier == run_id and boundary == name:
            raise RuntimeError("synthetic interruption after local file publication")
        return result

    def event(identifier, name, value):
        result = original_event(identifier, name, value)
        if identifier == run_id and boundary == name:
            raise RuntimeError("synthetic interruption after local event publication")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(jobs.runs, "write_json", write)
        patch.setattr(jobs.runs, "append_event", event)
        with pytest.raises(RuntimeError, match="synthetic interruption"):
            jobs._finalize_run(run_id, owner, child["job_id"], request, state.saved[request.digest])
    if after_restart:
        assert jobs.runs.recover_interrupted_runs() == 1
    folder = jobs.runs.root / run_id
    before = {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()}
    calls = deepcopy(executor.calls)
    with pytest.raises((RunStoreError, S3AccessError)):
        jobs.recover(owner, {})
    assert {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()} == before
    assert state.recoveries == [] and executor.calls == calls
    assert jobs.store.get_job(owner)["progress"]["pending_operation"] == child["job_id"]


@pytest.mark.parametrize(
    "name", ["evidence.json", "detections.json", "scenario.json", "result.json"]
)
def test_pristine_guard_refuses_extra_file_content_after_startup(transport_app, name):
    jobs, executor, state = transport_app
    owner, _, run_id, _ = lost_apply(transport_app)
    value = dict(jobs.runs.read_json(run_id, name))
    value["unexpected_partial_field"] = True
    jobs.runs.write_json(run_id, name, value)
    assert jobs.runs.recover_interrupted_runs() == 1
    before = jobs.runs.get_run(run_id)
    calls = deepcopy(executor.calls)
    with pytest.raises(S3AccessError, match="differs"):
        jobs.recover(owner, {})
    assert jobs.runs.get_run(run_id) == before
    assert state.recoveries == [] and executor.calls == calls


def test_lost_original_is_adopted_after_reopen_and_expiry_without_dispatch(transport_app):
    jobs, executor, state = transport_app
    owner, child, run_id, request = lost_apply(transport_app)
    jobs.store = ProductStore(jobs.store.path)
    jobs.clock = lambda: NOW + timedelta(days=1)
    executor.ready = False
    calls = deepcopy(executor.calls)
    recovered = jobs.recover(owner, {})
    assert recovered["policy_state"] == "hardened"
    assert recovered["active_job"] is None and recovered["allowed_phases"] == []
    assert recovered["operations"][-1]["run_ids"] == [run_id]
    assert state.recoveries == [request.digest]
    assert executor.calls == calls
    assert jobs.runs.validate_bundle(run_id)["valid"]
    assert jobs.store.get_job(child["job_id"])["state"] == "failed"
    assert jobs.recover(owner, {}) == recovered
    assert state.recoveries == [request.digest]


@pytest.mark.parametrize("status", ["running", "absent", "unavailable"])
def test_nonterminal_original_remains_pending_unknown_without_replay(transport_app, status):
    jobs, executor, state = transport_app
    owner, _, run_id, request = lost_apply(transport_app)
    state.status = status
    before = jobs.read(owner)
    calls = deepcopy(executor.calls)
    with pytest.raises(S3AccessError, match="no finalized result"):
        jobs.recover(owner, {})
    assert jobs.read(owner) == before
    assert jobs.runs.get_run(run_id)["status"] == "created"
    assert state.recoveries == [request.digest] and executor.calls == calls


def test_checkpoint_transaction_failure_prevents_dispatch(transport_app, monkeypatch):
    jobs, executor, _ = transport_app
    owner = create(jobs)["workflow_job_id"]
    ordinary = records.patch

    def fail_commit(connection, row, update):
        ordinary(connection, row, update)
        if "original_tasks" in update:
            raise RuntimeError("synthetic failure before checkpoint commit")

    monkeypatch.setattr(records, "patch", fail_commit)
    child = submit_failed_stage(jobs, owner, "inspect")
    reopened = ProductStore(jobs.store.path)
    assert not reopened.get_job(child["job_id"])["progress"].get("original_tasks")
    assert executor.calls == []
    assert jobs.read(owner)["active_job"]["job_id"] == child["job_id"]


def test_identical_checkpoint_repeats_but_different_original_refuses(transport_app, monkeypatch):
    jobs, executor, _ = transport_app
    owner = create(jobs)["workflow_job_id"]
    ordinary = records.retain_original_task

    def repeated(store, operation_id, run_id, request, context):
        ordinary(store, operation_id, run_id, request, context)
        ordinary(store, operation_id, run_id, request, context)
        changed = deepcopy(context)
        changed["transport_identity"]["inventory_digest"] = "sha256:" + "b" * 64
        ordinary(store, operation_id, run_id, request, changed)

    monkeypatch.setattr(records, "retain_original_task", repeated)
    child = submit_failed_stage(jobs, owner, "inspect")
    assert executor.calls == []
    retained = next(iter(child["progress"]["original_tasks"].values()))
    assert retained["transport_identity"]["inventory_digest"] == "sha256:" + "a" * 64


def test_resealed_wrong_review_cannot_be_retained(transport_app):
    jobs, executor, state = transport_app
    owner = create(jobs)["workflow_job_id"]
    state.alter_context = lambda request, approval, _: context_for(
        request, {**approval, "reviewed_by": "another synthetic reviewer"}
    )
    child = submit_failed_stage(jobs, owner, "inspect")
    assert not child["progress"].get("original_tasks")
    assert executor.calls == []


def test_changed_initial_run_refuses_before_authenticated_recovery(transport_app):
    jobs, executor, state = transport_app
    owner, _, run_id, _ = lost_apply(transport_app)
    plan = dict(jobs.runs.read_json(run_id, "plan.json"))
    plan["schema_version"] = "wrong"
    jobs.runs.write_json(run_id, "plan.json", plan)
    calls = deepcopy(executor.calls)
    with pytest.raises(S3AccessError, match="unsealed S3 run differs"):
        jobs.recover(owner, {})
    assert state.recoveries == [] and executor.calls == calls
    assert jobs.runs.read_json(run_id, "plan.json") == plan


def test_partial_finalization_is_not_overwritten(transport_app):
    jobs, _, state = transport_app
    owner, _, run_id, _ = lost_apply(transport_app)
    result = dict(jobs.runs.read_json(run_id, "result.json"))
    result["status"] = "failed"
    jobs.runs.write_json(run_id, "result.json", result)
    with pytest.raises(RunStoreError, match="not sealed"):
        jobs.recover(owner, {})
    assert jobs.runs.read_json(run_id, "result.json") == result
    assert state.recoveries == []


def test_sealed_integrity_failure_is_not_overwritten(transport_app, monkeypatch):
    jobs, _, state = transport_app
    owner = through_baseline(jobs)
    ordinary = records.finish
    monkeypatch.setattr(
        records,
        "finish",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("publication failure")),
    )
    child = submit_failed_stage(jobs, owner, "apply")
    monkeypatch.setattr(records, "finish", ordinary)
    run_id = child["progress"]["run_ids"][0]
    manifest = jobs.runs.read_json(run_id, "manifest.json")
    jobs.runs.write_json(run_id, "evidence.json", {"records": []})
    with pytest.raises(RunStoreError, match="integrity"):
        jobs.recover(owner, {})
    assert jobs.runs.read_json(run_id, "manifest.json") == manifest
    assert jobs.runs.read_json(run_id, "evidence.json") == {"records": []}
    assert state.recoveries == []


def test_original_with_unknown_cleanup_is_saved_but_stays_blocked(transport_app):
    jobs, executor, state = transport_app
    owner, _, _, request = lost_apply(transport_app)
    state.saved[request.digest]["cleanup"] = "unknown"
    calls = deepcopy(executor.calls)
    recovered = jobs.recover(owner, {})
    assert recovered["operations"][-1]["outcome"]["cleanup"] == "unknown"
    assert recovered["policy_state"] == "uncertain" and recovered["allowed_phases"] == []
    assert executor.calls == calls


def test_wrong_original_result_does_not_finalize_local_run(transport_app):
    jobs, _, state = transport_app
    owner, _, run_id, request = lost_apply(transport_app)
    state.recovered_override = deepcopy(state.saved[request.digest])
    state.recovered_override["request_digest"] = "sha256:" + "f" * 64
    with pytest.raises(S3AccessError):
        jobs.recover(owner, {})
    assert jobs.runs.get_run(run_id)["status"] == "created"


@pytest.mark.parametrize(
    "provenance,dispatch,admitted,worker,expected",
    [
        ("runner_reported", "not_started", False, False, "control_blocked"),
        ("runner_reported", "not_started", True, False, "control_blocked"),
        ("runner_reported", "unknown", True, False, "unknown"),
        ("runner_reported", "unknown", True, True, "unknown"),
        ("runner_reported", "permit_issued", True, False, "unknown"),
        ("runner_reported", "permit_issued", True, True, "executed"),
        ("synthetic", "unknown", True, False, "synthetic"),
    ],
)
def test_stored_evidence_does_not_promote_permits_or_refusal_to_execution(
    transport_app, provenance, dispatch, admitted, worker, expected
):
    jobs, _, state = transport_app
    owner = create(jobs)["workflow_job_id"]
    state.lose = "inspect_policy"
    child = submit_failed_stage(jobs, owner, "inspect")
    run_id = child["progress"]["run_ids"][0]
    request = S3WorkerRequest.from_mapping(child["request"]["worker_requests"][0])
    value = state.saved[request.digest]
    value.update(provenance=provenance, dispatch=dispatch)
    value["admission"] = {
        "accepted": admitted,
        "problem": None if admitted else "admission_refused",
    }
    if not worker:
        value["result"] = None
        value["send_debits"] = 1 if dispatch == "permit_issued" else 0
    if not admitted:
        value["reservation_digest"] = None
    jobs.recover(owner, {})
    evidence = jobs.runs.get_run(run_id)["evidence"]["records"][0]
    assert evidence["provenance"] == expected
    assert "do not prove completed sends" in evidence["limitations"][0]
    assert "refusal is not defensive effectiveness" in evidence["limitations"][1]


def test_recover_and_original_completion_serialize_one_local_publication(
    transport_app, monkeypatch
):
    jobs, executor, state = transport_app
    owner, child, run_id, request = lost_apply(transport_app)
    other = S3AccessJobs(
        SimpleNamespace(
            product_store=ProductStore(jobs.store.path),
            store=RunStore(jobs.runs.root),
            job_controller=jobs.controller,
        ),
        executor,
        clock=lambda: NOW,
    )
    entered, release = Event(), Event()
    ordinary = jobs._publish_run

    def paused_publication(*arguments):
        entered.set()
        assert release.wait(4)
        ordinary(*arguments)

    monkeypatch.setattr(jobs, "_publish_run", paused_publication)
    calls = deepcopy(executor.calls)
    with ThreadPoolExecutor(max_workers=2) as pool:
        original = pool.submit(
            jobs._finalize_run, run_id, owner, child["job_id"], request, state.saved[request.digest]
        )
        assert entered.wait(2)
        recovery = pool.submit(other.recover, owner, {})
        try:
            assert state.recovered.wait(2)
        finally:
            release.set()
        original.result(timeout=4)
        recovered = recovery.result(timeout=4)
    assert recovered["policy_state"] == "hardened"
    assert jobs.runs.validate_bundle(run_id)["valid"]
    assert sum(row["event_type"] == "run.finalized" for row in jobs.runs.read_events(run_id)) == 1
    assert executor.calls == calls
