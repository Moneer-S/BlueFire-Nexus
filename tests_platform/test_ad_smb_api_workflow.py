"""Authenticated HTTP with real AD persistence and explicitly synthetic execution."""

import uuid
from copy import deepcopy
from datetime import timedelta

from bluefire.ad_smb_jobs import AdSmbJobs
from bluefire.ad_smb_service import AdSmbServiceMixin
from bluefire.service import BlueFireService
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_jobs import create, submit
from tests_platform.test_ad_smb_jobs import workspace as workspace
from tests_platform.test_api import StubService, json_body, request, running_server
from tests_platform.test_service import ROOT as PROJECT_ROOT
from tests_platform.test_service import ReadyInventoryRunner, RecordingRunnerLifecycle

ROOT = "/api/v1/ad-smb"


class WorkflowService(AdSmbServiceMixin, StubService):
    def __init__(self, jobs):
        super().__init__()
        self.ad_smb = jobs


def test_actual_service_ad_startup_and_restart_never_admit_or_start_runner(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    lifecycle = RecordingRunnerLifecycle(ReadyInventoryRunner(), sandbox)
    for _ in range(2):
        service = BlueFireService(
            project_root=PROJECT_ROOT,
            runs_dir=tmp_path / "runs",
            product_db_path=tmp_path / "product.sqlite3",
            runner_lifecycle=lifecycle,
        )
        try:
            with running_server(service) as (server, _):
                status, _, body = request(server, "GET", ROOT + "/environments")
                assert status == 200
                assert json_body(body) == {
                    "environments": [],
                    "native_execution_available": False,
                }
                status, _, body = request(server, "GET", ROOT + "/workflows")
                assert status == 200 and json_body(body) == {"workflows": []}
                status, _, body = request(
                    server,
                    "POST",
                    ROOT + "/workflows",
                    body={
                        "submission_id": str(uuid.uuid4()),
                        "environment_id": "ad-env-" + "a" * 32,
                    },
                )
                assert status == 409 and json_body(body)["error"]["code"] == "ad_smb_refused"
            assert server.socket.fileno() == -1
            assert lifecycle.calls == []
        finally:
            service.close()


def test_default_unavailable_ad_api_cannot_create_a_workflow(workspace):
    _jobs, executor, service = workspace
    unavailable = AdSmbJobs(service, clock=lambda: NOW)
    with running_server(WorkflowService(unavailable)) as (server, _):
        status, _, body = request(server, "GET", ROOT + "/environments")
        assert status == 200
        assert json_body(body) == {"environments": [], "native_execution_available": False}
        status, _, body = request(
            server,
            "POST",
            ROOT + "/workflows",
            body={"submission_id": str(uuid.uuid4()), "environment_id": "ad-env-" + "a" * 32},
        )
        assert status == 409 and json_body(body)["error"]["code"] == "ad_smb_refused"
        status, _, body = request(server, "GET", ROOT + "/workflows")
        assert status == 200 and json_body(body) == {"workflows": []}
    assert executor.calls == [] and executor.recovered == []
    assert server.socket.fileno() == -1


def test_saved_ad_stages_round_trip_through_authenticated_api(workspace):
    jobs, executor, service = workspace
    with running_server(WorkflowService(jobs)) as (server, _):
        intent = {"submission_id": str(uuid.uuid4()), "environment_id": "ad-env-" + "a" * 32}
        status, _, body = request(server, "POST", ROOT + "/workflows", body=intent)
        assert status == 200
        saved = json_body(body)
        identifier = saved["workflow"]["job_id"]
        path = ROOT + "/workflows/" + identifier
        status, _, body = request(server, "POST", ROOT + "/workflows", body=intent)
        assert status == 200 and json_body(body) == saved
        for phase in ("inspect", "baseline", "harden", "retest", "rollback", "audit"):
            status, _, body = request(server, "POST", path + "/review", body={"phase": phase})
            assert status == 200
            review = json_body(body)
            command = {
                "submission_id": str(uuid.uuid4()),
                "phase": phase,
                "review_digest": review["review_digest"],
                "reviewed_by": "fixture-operator",
            }
            status, _, body = request(server, "POST", path + "/operations", body=command)
            assert status == 200
            operation = json_body(body)
            terminal = service.job_controller.wait(operation["job_id"], timeout=10)
            assert terminal["state"] == "completed", terminal
            assert service.store.validate_bundle(terminal["result_ref"])["valid"]
            status, _, body = request(server, "GET", path)
            assert status == 200
            state = json_body(body)
            assert state["workflow"]["progress"]["operations"][-1]["phase"] == phase
            assert state["effective_access_claim"] is False
        assert len(executor.calls) == 10
        calls = deepcopy(executor.calls)
        status, _, body = request(server, "POST", path + "/recover", body={})
        assert status == 200 and json_body(body) == state
        status, _, body = request(server, "GET", ROOT + "/workflows")
        assert status == 200 and json_body(body) == {"workflows": [state]}
        assert executor.calls == calls and executor.recovered == []
    assert server.socket.fileno() == -1


def test_ad_api_recovers_only_original_terminal_after_expiry(workspace):
    jobs, executor, service = workspace
    identifier = create(jobs)
    executor.crash = True
    child, _ = submit(jobs, identifier, "inspect")
    assert child["state"] == "failed"
    original = deepcopy(child["progress"]["tasks"])
    calls = deepcopy(executor.calls)
    reopened = AdSmbJobs(service, executor, clock=lambda: NOW + timedelta(days=1))
    executor.environments = lambda: (_ for _ in ()).throw(AssertionError("unexpected discovery"))
    path = ROOT + "/workflows/" + identifier
    with running_server(WorkflowService(reopened), authenticate=False) as (server, _):
        status, _, _ = request(server, "POST", path + "/recover", body={})
        assert status == 401 and executor.recovered == []
    with running_server(WorkflowService(reopened)) as (server, _):
        status, _, body = request(server, "GET", path)
        assert status == 200
        assert json_body(body)["workflow"]["progress"]["pending_operation"] == child["job_id"]
        assert executor.calls == calls and executor.recovered == []
        status, _, body = request(server, "POST", path + "/recover", body={})
        assert status == 200
        recovered = json_body(body)
        assert recovered["workflow"]["progress"]["pending_operation"] is None
        run_id = recovered["workflow"]["progress"]["operations"][-1]["run_id"]
        assert service.store.validate_bundle(run_id)["valid"]
        events = service.store.read_events(run_id)
        status, _, body = request(server, "POST", path + "/recover", body={})
        assert status == 200 and json_body(body) == recovered
        assert service.store.read_events(run_id) == events
    assert executor.calls == calls and len(executor.recovered) == 1
    retained = service.product_store.get_job(child["job_id"])["progress"]["tasks"]
    assert retained[0]["context"] == original[0]["context"]
    assert retained[0]["execution"] is None and retained[0]["recovery"] is not None
    assert server.socket.fileno() == -1
