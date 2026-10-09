"""Real loopback routes and persistence with a synthetic original-task transport."""

from copy import deepcopy

import pytest

from bluefire.s3_access_service import S3AccessServiceMixin
from tests_platform.test_api import StubService, json_body, request, running_server
from tests_platform.test_s3_access_jobs import app as app
from tests_platform.test_s3_access_original_results import lost_apply, restarted_service
from tests_platform.test_s3_access_original_results import transport_app as transport_app


class RecoveryService(S3AccessServiceMixin, StubService):
    def __init__(self, jobs):
        super().__init__()
        self.s3_access = jobs


def test_original_result_is_adopted_through_authenticated_api_after_reopen(transport_app):
    jobs, executor, state = transport_app
    owner, child, run_id, original = lost_apply(transport_app)
    checkpoint = deepcopy(child["progress"]["original_tasks"])
    executor.ready = False
    calls = deepcopy(executor.calls)
    path = f"/api/v1/s3-access/exercises/{owner}"

    with restarted_service(transport_app) as service, running_server(service) as (server, _):
        assert service.recovered_runs == 1
        interrupted = service.store.get_run(run_id)
        assert interrupted["status"] == "interrupted"
        assert (
            service.product_store.get_job(child["job_id"])["progress"]["original_tasks"]
            == checkpoint
        )
        status, _, body = request(server, "GET", path)
        assert status == 200 and json_body(body)["active_job"]["job_id"] == child["job_id"]
        assert state.recoveries == [] and executor.calls == calls
        status, _, body = request(server, "POST", path + "/recover", body={})
        recovered = json_body(body)
        assert status == 200 and recovered["policy_state"] == "hardened"
        assert recovered["active_job"] is None and recovered["allowed_phases"] == []
        assert recovered["operations"][-1]["run_ids"] == [run_id]
        assert jobs.runs.validate_bundle(run_id)["valid"]
        events = jobs.runs.read_events(run_id)
        assert events[:2] == interrupted["events"]
        assert sum(row["event_type"] == "run.finalized" for row in events) == 1
        for method, suffix in (("GET", ""), ("POST", "/recover")):
            status, _, body = request(
                server, method, path + suffix, body={} if method == "POST" else None
            )
            assert status == 200 and json_body(body) == recovered
        assert jobs.runs.read_events(run_id) == events
    assert server.socket.fileno() == -1
    assert state.recoveries == [original.digest] and executor.calls == calls
    assert jobs.store.get_job(child["job_id"])["progress"]["original_tasks"] == checkpoint


@pytest.mark.parametrize("original_status", ["running", "absent", "unavailable"])
def test_unresolved_original_api_result_preserves_pending_without_replay(
    transport_app, original_status
):
    jobs, executor, state = transport_app
    owner, child, run_id, original = lost_apply(transport_app)
    state.status = original_status
    before = jobs.read(owner)
    calls = deepcopy(executor.calls)
    path = f"/api/v1/s3-access/exercises/{owner}"
    with running_server(RecoveryService(jobs)) as (server, _):
        status, _, body = request(server, "POST", path + "/recover", body={})
        assert status == 409 and json_body(body)["error"]["code"] == "s3_access_refused"
        assert "unsafe to repeat" in json_body(body)["error"]["message"]
        status, _, body = request(server, "GET", path)
        assert status == 200 and json_body(body) == before
    assert server.socket.fileno() == -1
    assert jobs.runs.get_run(run_id)["status"] == "created"
    assert jobs.store.get_job(child["job_id"])["state"] == "failed"
    assert state.recoveries == [original.digest] and executor.calls == calls


def test_unauthenticated_recovery_never_calls_original_host_or_executor(transport_app):
    jobs, executor, state = transport_app
    owner, child, run_id, _ = lost_apply(transport_app)
    executor.calls.clear()
    before = jobs.store.get_job(child["job_id"])
    with running_server(RecoveryService(jobs), authenticate=False) as (server, _):
        status, _, _ = request(
            server, "POST", f"/api/v1/s3-access/exercises/{owner}/recover", body={}
        )
        assert status == 401
    assert server.socket.fileno() == -1
    assert state.recoveries == [] and executor.calls == []
    assert jobs.store.get_job(child["job_id"]) == before
    assert jobs.runs.get_run(run_id)["status"] == "created"
