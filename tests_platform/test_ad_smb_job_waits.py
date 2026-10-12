"""Bounded test-only waits for persisted synthetic AD jobs."""

import traceback

import pytest

from bluefire.job_runtime import JobWaitTimeout
from tests_platform.test_ad_smb_jobs import JOB_WAIT_TIMEOUT, create, submit, wait_for_ad_job
from tests_platform.test_ad_smb_jobs import workspace as workspace


class FakeController:
    def __init__(self, result=None, error=None, snapshot=None):
        self.result = result
        self.error = error
        self.saved_snapshot = snapshot or {}
        self.wait_calls = []
        self.snapshot_calls = []

    def wait(self, job_id, *, timeout):
        self.wait_calls.append((job_id, timeout))
        if self.error is not None:
            raise self.error
        return self.result

    def snapshot(self, job_id):
        self.snapshot_calls.append(job_id)
        return self.saved_snapshot


def test_wait_for_ad_job_uses_finite_bound_and_skips_snapshot_on_success():
    assert JOB_WAIT_TIMEOUT == 30
    result = {"job_id": "job-test", "state": "failed"}
    controller = FakeController(result=result)

    assert wait_for_ad_job(controller, "job-test") is result
    assert controller.wait_calls == [("job-test", JOB_WAIT_TIMEOUT)]
    assert controller.snapshot_calls == []


def test_wait_for_ad_job_reports_one_allowlisted_snapshot_on_timeout():
    controller = FakeController(
        error=JobWaitTimeout("private timeout detail"),
        snapshot={
            "state": "running",
            "progress": {"phase": "running"},
            "request": {
                "ad_smb": {"phase": "inspect"},
                "credential": "private-request-value",
            },
            "error": {"message": "private-error-value"},
        },
    )

    with pytest.raises(
        AssertionError,
        match=rf"within {JOB_WAIT_TIMEOUT}s \(state='running', phase='inspect'\)",
    ) as caught:
        wait_for_ad_job(controller, "job-test")

    assert controller.wait_calls == [("job-test", JOB_WAIT_TIMEOUT)]
    assert controller.snapshot_calls == ["job-test"]
    message = str(caught.value)
    assert "private timeout detail" not in message
    assert "private-request-value" not in message
    assert "private-error-value" not in message
    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    assert "private timeout detail" not in rendered
    assert "private-request-value" not in rendered
    assert "private-error-value" not in rendered


def test_wait_for_ad_job_redacts_unrecognized_snapshot_values():
    controller = FakeController(
        error=JobWaitTimeout("timeout"),
        snapshot={
            "state": "state-with-private-data",
            "progress": {"phase": "inspect"},
            "request": {"ad_smb": {"phase": "phase-with-private-data"}},
        },
    )

    with pytest.raises(AssertionError, match="state='unknown', phase='unknown'") as caught:
        wait_for_ad_job(controller, "job-test")

    assert controller.snapshot_calls == ["job-test"]
    assert "state-with-private-data" not in str(caught.value)
    assert "phase-with-private-data" not in str(caught.value)


@pytest.mark.parametrize(
    "saved_request",
    [None, [], "private-request", {}, {"ad_smb": None}, {"ad_smb": []}, {"ad_smb": "private"}],
)
def test_wait_for_ad_job_refuses_malformed_nested_phase_without_progress_fallback(saved_request):
    controller = FakeController(
        error=JobWaitTimeout("timeout"),
        snapshot={"state": "running", "progress": {"phase": "inspect"}, "request": saved_request},
    )

    with pytest.raises(AssertionError, match="state='running', phase='unknown'"):
        wait_for_ad_job(controller, "job-test")

    assert controller.wait_calls == [("job-test", JOB_WAIT_TIMEOUT)]
    assert controller.snapshot_calls == ["job-test"]


@pytest.mark.parametrize("phase", ["inspect", "baseline", "harden", "retest", "rollback", "audit"])
def test_wait_for_ad_job_reports_only_fixed_nested_ad_stages(phase):
    controller = FakeController(
        error=JobWaitTimeout("timeout"),
        snapshot={
            "state": "planning",
            "progress": {"phase": "planning"},
            "request": {"ad_smb": {"phase": phase}},
        },
    )

    with pytest.raises(AssertionError, match=rf"state='planning', phase='{phase}'"):
        wait_for_ad_job(controller, "job-test")

    assert controller.wait_calls == [("job-test", JOB_WAIT_TIMEOUT)]
    assert controller.snapshot_calls == ["job-test"]


def test_wait_for_ad_job_uses_real_controller_snapshot_ad_request(workspace, monkeypatch):
    jobs, _executor, service = workspace
    child, _ = submit(jobs, create(jobs), "inspect")
    controller = service.job_controller
    original_snapshot = controller.snapshot
    snapshot = original_snapshot(child["job_id"])
    assert snapshot["request"]["ad_smb"]["phase"] == "inspect"
    assert snapshot["state"] == snapshot["progress"]["phase"] == "completed"
    wait_calls, snapshot_calls = [], []

    def timeout(job_id, *, timeout):
        wait_calls.append((job_id, timeout))
        raise JobWaitTimeout("private timeout detail")

    def recorded_snapshot(job_id):
        snapshot_calls.append(job_id)
        return original_snapshot(job_id)

    monkeypatch.setattr(controller, "wait", timeout)
    monkeypatch.setattr(controller, "snapshot", recorded_snapshot)
    with pytest.raises(AssertionError, match="state='completed', phase='inspect'") as caught:
        wait_for_ad_job(controller, child["job_id"])

    assert wait_calls == [(child["job_id"], JOB_WAIT_TIMEOUT)]
    assert snapshot_calls == [child["job_id"]]
    assert child["job_id"] not in str(caught.value)
    assert snapshot["request"]["ad_smb"]["workflow_job_id"] not in str(caught.value)


def test_wait_for_ad_job_does_not_swallow_unrelated_controller_errors():
    controller = FakeController(error=RuntimeError("controller error"))

    with pytest.raises(RuntimeError, match="controller error"):
        wait_for_ad_job(controller, "job-test")

    assert controller.snapshot_calls == []
