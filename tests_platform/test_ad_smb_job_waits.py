"""Bounded test-only waits for persisted synthetic AD jobs."""

import traceback

import pytest

from bluefire.job_runtime import JobWaitTimeout
from tests_platform.test_ad_smb_jobs import JOB_WAIT_TIMEOUT, wait_for_ad_job


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
            "progress": {"phase": "inspect"},
            "request": {"credential": "private-request-value"},
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
            "progress": {"phase": "phase-with-private-data"},
        },
    )

    with pytest.raises(AssertionError, match="state='unknown', phase='unknown'") as caught:
        wait_for_ad_job(controller, "job-test")

    assert controller.snapshot_calls == ["job-test"]
    assert "state-with-private-data" not in str(caught.value)
    assert "phase-with-private-data" not in str(caught.value)


def test_wait_for_ad_job_does_not_swallow_unrelated_controller_errors():
    controller = FakeController(error=RuntimeError("controller error"))

    with pytest.raises(RuntimeError, match="controller error"):
        wait_for_ad_job(controller, "job-test")

    assert controller.snapshot_calls == []
