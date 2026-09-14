"""Ordinary run UUIDs publish one job/approval and never repeat execution on retry."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from bluefire.application_errors import APIError
from bluefire.contracts import ExecutionMode
from bluefire.job_runtime import JobState
from bluefire.product_store_errors import ProductStoreError
from bluefire.service import BlueFireService
from tests_platform.test_service import ReadyInventoryRunner

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    runner = ReadyInventoryRunner()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        runner_factory=lambda profile: (runner, sandbox),
    )
    yield service
    service.close()


def request(service, mode="simulate"):
    body = {
        "submission_id": str(uuid.uuid4()),
        "scenario_id": "scenario.sandbox.research.chain.v1",
        "mode": mode,
        "autonomy": "off",
    }
    if mode == "execute":
        profile = next(
            row for row in service.config.runner_profiles if row.mode is ExecutionMode.EXECUTE
        )
        body.update(runner_profile_id=profile.id, target_scope={"scope_refs": list(profile.scope)})
    return body


def approval_count(service):
    with service.product_store._connection() as connection:
        return connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]


def test_simulation_exact_uuid_does_not_resubmit_after_completion(service, monkeypatch):
    body = request(service)
    first = service.submit_run(body)
    job = service.job_controller.wait(first["job"]["job_id"], timeout=15)
    assert job["state"] == "completed"
    assert len(service.store.list_runs()) == 1

    def forbidden(*args, **kwargs):
        pytest.fail("Exact retry must not preflight or submit again")

    monkeypatch.setattr(service, "preflight", forbidden)
    monkeypatch.setattr(service.job_controller, "submit", forbidden)
    duplicate = service.submit_run(body)
    assert duplicate["job"]["job_id"] == job["job_id"]
    assert duplicate["job"]["result_ref"] == job["result_ref"]
    assert duplicate["job"]["request"]["_run_submission_request"] == {
        key: value for key, value in body.items() if key != "submission_id"
    }
    with pytest.raises(APIError):
        service.submit_run({**body, "autonomy": "assist"})
    assert approval_count(service) == 0


def test_concurrent_execute_uuid_owns_one_pending_approval_without_effects(service):
    body = request(service, "execute")
    barrier = threading.Barrier(2)

    def submit():
        barrier.wait(5)
        return service.submit_run(body)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: submit(), range(2)))
    assert len({row["job"]["job_id"] for row in results}) == 1
    assert len({row["approval_request"]["approval_id"] for row in results}) == 1
    job = service.job_controller.wait_for_state(
        results[0]["job"]["job_id"], {JobState.AWAITING_APPROVAL}, timeout=5
    )
    assert job["state"] == "awaiting_approval"
    assert approval_count(service) == 1 and service.store.list_runs() == []
    assert all(
        row["approval_request"]["status"] == "pending" and "nonce" not in row["approval_request"]
        for row in results
    )


def test_job_insertion_failure_rolls_back_pending_approval_and_closes_uuid(service, monkeypatch):
    body = request(service, "execute")
    original = service.product_store._job_from_row
    failed = []

    def fail_once(row):
        if row["kind"] == "scenario.run" and row["state"] == "queued" and not failed:
            failed.append(True)
            raise ProductStoreError("Injected post-insert failure")
        return original(row)

    monkeypatch.setattr(service.product_store, "_job_from_row", fail_once)
    response = service.submit_run(body)
    assert failed and response["job"]["state"] == "failed"
    assert response["job"]["progress"]["phase"] == "closed_submission"
    assert approval_count(service) == 0 and service.store.list_runs() == []
    assert service.submit_run(body)["job"] == response["job"]


def test_refused_preflight_uuid_cannot_become_late_success(service, monkeypatch):
    body = request(service)
    original = service.preflight
    monkeypatch.setattr(
        service, "preflight", lambda _: {"problems": ["Selected graph is unavailable."]}
    )
    failed = service.submit_run(body)
    assert failed["job"]["state"] == "failed"
    monkeypatch.setattr(service, "preflight", original)
    assert service.submit_run(body)["job"] == failed["job"]
    assert service.store.list_runs() == []
