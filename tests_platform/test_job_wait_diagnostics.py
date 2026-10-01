"""Authored timeout snapshots; no service, provider, or worker execution."""

import json
import threading
from types import SimpleNamespace

import pytest

from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController
from tests_platform import job_wait_diagnostics as diagnostic
from tests_platform import test_replay_jobs as replay

PRIVATE = "PRIVATE_PROVIDER_PATH_JOB_ID_ERROR_MUST_NOT_APPEAR"


def actual_timeout(snapshot):
    reads = []

    def read(job_id):
        reads.append(job_id)
        return snapshot

    controller = RunJobController.__new__(RunJobController)
    controller._condition = threading.Condition()
    controller._store = SimpleNamespace(get_job=read)
    try:
        controller.wait_for_state(PRIVATE, {JobState.AWAITING_APPROVAL}, timeout=0)
    except JobWaitTimeout as timeout:
        timeout.args = (PRIVATE,)
        return timeout, reads
    pytest.fail("the authored job must time out")


def emit(timeout, capsys, *, stage="replay_approval"):
    with pytest.raises(JobWaitTimeout) as caught:
        with diagnostic.diagnose_job_wait(stage):
            raise timeout
    assert caught.value is timeout
    output = capsys.readouterr().out
    assert PRIVATE not in output
    return json.loads(output.removeprefix("Job wait diagnostic: "))


@pytest.mark.parametrize("state", ["queued", "running", "failed", "completed"])
def test_real_wait_snapshot_distinguishes_active_and_terminal_states_without_reread(
    monkeypatch, capsys, state
):
    snapshot = {
        "state": state,
        "job_id": PRIVATE,
        "result_ref": PRIVATE,
        "error": {
            "code": "execution_callback_failed",
            "exception_type": "ProductStoreError",
            "message": PRIVATE,
        },
        "progress": {
            "phase": state,
            "plan": PRIVATE,
            "children": PRIVATE,
            "proposal_record_id": PRIVATE,
        },
    }
    timeout, reads = actual_timeout(snapshot)
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    report = emit(timeout, capsys)
    assert reads == [PRIVATE]
    assert report["last_wait_job"] == {
        "available": True,
        "state": state,
        "phase": state,
        "error_code": "execution_callback_failed",
        "error_type": "ProductStoreError",
        "has_error": True,
        "has_result_ref": True,
        "has_plan_field": True,
        "has_children_field": True,
        "has_proposal_review_field": True,
    }


@pytest.mark.parametrize("lookalike_frame", [False, True])
def test_absent_or_named_lookalike_frame_cannot_supply_a_snapshot(
    monkeypatch, capsys, lookalike_frame
):
    timeout = JobWaitTimeout(PRIVATE)

    def wait_for_state():
        snapshot = {"state": "failed", "progress": {"phase": PRIVATE}}
        assert snapshot
        raise timeout

    if lookalike_frame:
        try:
            wait_for_state()
        except JobWaitTimeout:
            pass
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    assert emit(timeout, capsys)["last_wait_job"] == {"available": False}


@pytest.mark.parametrize("malformed", [False, True])
def test_missing_or_malformed_snapshot_fields_emit_only_unknowns(monkeypatch, capsys, malformed):
    snapshot = {"state": "running"}
    timeout, reads = actual_timeout(snapshot)
    snapshot.clear()
    if malformed:
        snapshot.update(state=[PRIVATE], progress=[PRIVATE], error=PRIVATE)
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    report = emit(timeout, capsys, stage=PRIVATE)["last_wait_job"]
    assert reads == [PRIVATE]
    assert report == {
        "available": True,
        "state": "unknown",
        "phase": "unknown",
        "error_code": "unknown",
        "error_type": "unknown",
        "has_error": malformed,
        "has_result_ref": False,
        "has_plan_field": False,
        "has_children_field": False,
        "has_proposal_review_field": False,
    }


def test_process_thread_labels_and_error_fields_are_private_and_bounded(monkeypatch, capsys):
    snapshot = {
        "state": "running",
        "error": {"code": PRIVATE, "exception_type": PRIVATE, "message": PRIVATE},
        "progress": {"phase": PRIVATE},
        "request": {"credential": PRIVATE},
    }
    timeout, _ = actual_timeout(snapshot)
    frame = None
    longest = max(diagnostic.FUNCTIONS, key=len)
    for index in range(100):
        frame = SimpleNamespace(
            f_code=SimpleNamespace(co_name=longest if index % 2 else PRIVATE, co_filename=PRIVATE),
            f_lineno=PRIVATE,
            f_locals={"credential": PRIVATE},
            f_back=frame,
        )
    monkeypatch.setattr(
        diagnostic.sys, "_current_frames", lambda: {index: frame for index in range(100)}
    )
    with pytest.raises(JobWaitTimeout):
        with diagnostic.diagnose_job_wait(PRIVATE):
            raise timeout
    output = capsys.readouterr().out
    assert PRIVATE not in output and "credential" not in output
    assert len(output.encode()) < 8192
    report = json.loads(output.removeprefix("Job wait diagnostic: "))
    assert report["stage"] == "unknown"
    assert report["last_wait_job"]["phase"] == "unknown"
    assert report["last_wait_job"]["error_code"] == "unknown"
    assert report["last_wait_job"]["error_type"] == "unknown"
    assert report["process_threads_truncated"] is True
    assert len(report["process_thread_functions"]) == 8
    assert all(len(stack) == 24 for stack in report["process_thread_functions"])
    assert all(set(stack) == {longest, "unknown"} for stack in report["process_thread_functions"])


@pytest.mark.parametrize(
    "options",
    [
        {"parameter_overrides": {"create_fixture": {"record_count": 3}}},
        {"from_step_id": "discover_records"},
    ],
)
@pytest.mark.parametrize("diagnostic_fails", [False, True])
def test_actual_terminal_wait_preserves_deadline_options_and_caller_cleanup(
    monkeypatch, capsys, options, diagnostic_fails
):
    timeout, _ = actual_timeout({"state": "running", "progress": {"phase": "running"}})
    order = []
    source = {"run_id": "source"}
    payload = {"submission_id": "submission"}

    def submission(actual_service, actual_source, *, options):
        assert actual_service is service and actual_source is source
        assert options is original_options
        return payload

    def submit_replay(run_id, actual_payload):
        assert run_id == "source" and actual_payload is payload
        return {"job": {"job_id": "replay", "kind": "scenario.replay"}, "approval_request": None}

    def wait(job_id, *, timeout):
        assert job_id == "replay" and timeout == 10
        order.append(job_id)
        raise original

    original = timeout
    original_options = options
    service = SimpleNamespace(
        submit_replay=submit_replay,
        job_controller=SimpleNamespace(wait=wait),
        close=lambda: order.append("close"),
    )
    monkeypatch.setattr(replay, "source_run", lambda _service: source)
    monkeypatch.setattr(replay, "submission", submission)
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    if diagnostic_fails:

        def unavailable(*_args):
            raise KeyboardInterrupt(PRIVATE)

        monkeypatch.setattr(diagnostic, "_report", unavailable)
    with pytest.raises(JobWaitTimeout) as caught:
        try:
            replay.test_simulate_replay_job_returns_finalized_result_with_original_lineage(
                service, options
            )
        finally:
            service.close()
    assert caught.value is original
    assert order == ["replay", "close"]
    output = capsys.readouterr().out
    assert PRIVATE not in output
    if diagnostic_fails:
        assert output == ""
    else:
        assert (
            json.loads(output.removeprefix("Job wait diagnostic: "))["stage"] == "replay_terminal"
        )


def test_output_failure_cannot_replace_original_timeout(monkeypatch):
    timeout, _ = actual_timeout({"state": "running"})

    def failed_print(*_args, **_kwargs):
        raise OSError(PRIVATE)

    monkeypatch.setattr(diagnostic, "print", failed_print, raising=False)
    with pytest.raises(JobWaitTimeout) as caught:
        with diagnostic.diagnose_job_wait("graph_parent"):
            raise timeout
    assert caught.value is timeout


def test_success_and_other_exceptions_do_not_run_diagnostics(monkeypatch):
    def unexpected(*_args):
        pytest.fail("diagnostics reached without a job wait timeout")

    monkeypatch.setattr(diagnostic, "_report", unexpected)
    with diagnostic.diagnose_job_wait("graph_parent"):
        result = "unchanged"
    assert result == "unchanged"
    original = ValueError(PRIVATE)
    with pytest.raises(ValueError) as caught:
        with diagnostic.diagnose_job_wait("graph_parent"):
            raise original
    assert caught.value is original
