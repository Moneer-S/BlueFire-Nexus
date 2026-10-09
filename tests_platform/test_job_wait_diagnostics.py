"""Authored timeout snapshots; no service, provider, or worker execution."""

import json
import threading
from types import SimpleNamespace

import pytest

from bluefire.job_runtime import JobState, JobWaitTimeout, RunJobController
from tests_platform import job_wait_diagnostics as diagnostic
from tests_platform import test_graph_ai_jobs as graph
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


def emit(timeout, capsys, *, stage="replay_approval", report_section=True):
    sections = []
    sink = (lambda *args: sections.append(args)) if report_section else None
    with pytest.raises(JobWaitTimeout) as caught:
        with diagnostic.diagnose_job_wait(stage, sink):
            raise timeout
    assert caught.value is timeout
    captured = capsys.readouterr()
    assert captured.err == ""
    if report_section:
        assert captured.out == ""
        assert len(sections) == 1
        when, title, payload = sections[0]
        assert (when, title) == ("call", "Job wait diagnostic")
    else:
        assert sections == []
        assert captured.out.startswith("Job wait diagnostic: ")
        assert len(captured.out.encode()) < 8192
        payload = captured.out.removeprefix("Job wait diagnostic: ")
    assert PRIVATE not in payload
    return json.loads(payload)


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


@pytest.mark.parametrize("report_section", [False, True])
def test_process_thread_labels_and_error_fields_are_private_and_bounded(
    monkeypatch, capsys, report_section
):
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
    report = emit(timeout, capsys, stage=PRIVATE, report_section=report_section)
    output = json.dumps(report, sort_keys=True)
    assert PRIVATE not in output and "credential" not in output
    assert len(output.encode()) < 8192
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
    sections = []
    request = SimpleNamespace(
        node=SimpleNamespace(add_report_section=lambda *args: sections.append(args))
    )
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
                service, options, request
            )
        finally:
            service.close()
    assert caught.value is original
    assert order == ["replay", "close"]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    if diagnostic_fails:
        assert sections == []
    else:
        assert len(sections) == 1
        when, title, payload = sections[0]
        assert (when, title) == ("call", "Job wait diagnostic")
        assert PRIVATE not in payload
        assert json.loads(payload)["stage"] == "replay_terminal"


@pytest.mark.parametrize("stage", ["graph_parent", "graph_child", "replay_approval"])
@pytest.mark.parametrize("diagnostic_fails", [False, True])
def test_actual_wait_helpers_preserve_timeout_deadlines_and_caller_cleanup(
    monkeypatch, capsys, stage, diagnostic_fails
):
    timeout, _ = actual_timeout({"state": "running", "progress": {"phase": "running"}})
    order = []
    parent = {
        "job_id": "parent",
        "state": "completed",
        "progress": {"children": {"step-1": {"job_id": "child"}}},
    }

    def wait(job_id, *, timeout):
        assert timeout == 15
        order.append(job_id)
        if stage == "graph_child" and job_id == "parent":
            return parent
        raise original

    def wait_for_state(job_id, states, *, timeout):
        assert timeout == 10 and states == {JobState.AWAITING_APPROVAL}
        order.append(job_id)
        raise original

    original = timeout
    service = SimpleNamespace(
        submit_assistance_turn=lambda _body: {"job": parent},
        job_controller=SimpleNamespace(wait=wait, wait_for_state=wait_for_state),
        close=lambda: order.append("close"),
    )
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    if diagnostic_fails:

        def unavailable(*_args):
            raise KeyboardInterrupt(PRIVATE)

        monkeypatch.setattr(diagnostic, "_report", unavailable)
    with pytest.raises(JobWaitTimeout) as caught:
        try:
            if stage == "replay_approval":
                replay.awaiting(service, "replay")
            else:
                graph.proposed(service, {})
        finally:
            service.close()
    assert caught.value is original
    assert (
        order
        == {
            "graph_parent": ["parent", "close"],
            "graph_child": ["parent", "child", "close"],
            "replay_approval": ["replay", "close"],
        }[stage]
    )
    output = capsys.readouterr().out
    assert PRIVATE not in output
    if diagnostic_fails:
        assert output == ""
    else:
        assert json.loads(output.removeprefix("Job wait diagnostic: "))["stage"] == stage


def test_output_failure_cannot_replace_original_timeout(monkeypatch):
    timeout, _ = actual_timeout({"state": "running"})

    def failed_print(*_args, **_kwargs):
        raise OSError(PRIVATE)

    monkeypatch.setattr(diagnostic, "print", failed_print, raising=False)
    with pytest.raises(JobWaitTimeout) as caught:
        with diagnostic.diagnose_job_wait("graph_parent"):
            raise timeout
    assert caught.value is timeout


def test_report_sink_failure_cannot_replace_original_timeout_or_cleanup(monkeypatch, capsys):
    timeout, _ = actual_timeout({"state": "running"})
    order = []

    def failed_report(*_args):
        order.append("sink")
        raise OSError(PRIVATE)

    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    with pytest.raises(JobWaitTimeout) as caught:
        try:
            with diagnostic.diagnose_job_wait("graph_parent", failed_report):
                raise timeout
        finally:
            order.append("cleanup")
    assert caught.value is timeout
    assert order == ["sink", "cleanup"]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_pytest_report_section_retains_exact_payload_without_stdout(monkeypatch, request, capsys):
    timeout, reads = actual_timeout({"state": "running", "progress": {"phase": "planning"}})
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    before = len(request.node._report_sections)
    expected = diagnostic._report(timeout, "replay_terminal")
    with pytest.raises(JobWaitTimeout) as caught:
        with diagnostic.diagnose_job_wait("replay_terminal", request.node.add_report_section):
            raise timeout
    assert caught.value is timeout
    assert reads == [PRIVATE]
    assert request.node._report_sections[before:] == [("call", "Job wait diagnostic", expected)]
    assert PRIVATE not in expected
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize(
    "stage",
    ["assist_rejection_approval", "assist_cancellation_approval"],
)
@pytest.mark.parametrize("sink_fails", [False, True])
def test_assist_wait_stage_labels_are_allowlisted_and_payload_stays_private(
    monkeypatch, capsys, stage, sink_fails
):
    timeout, reads = actual_timeout(
        {
            "state": "running",
            "job_id": PRIVATE,
            "progress": {"phase": "running", "proposal_record_id": PRIVATE},
        }
    )
    monkeypatch.setattr(diagnostic.sys, "_current_frames", lambda: {})
    sections = []
    cleanup = []

    def report_section(*args):
        if sink_fails:
            raise OSError(PRIVATE)
        sections.append(args)

    with pytest.raises(JobWaitTimeout) as caught:
        try:
            with diagnostic.diagnose_job_wait(stage, report_section):
                raise timeout
        finally:
            cleanup.append("service-close")

    assert caught.value is timeout
    assert reads == [PRIVATE]
    assert cleanup == ["service-close"]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    if sink_fails:
        assert sections == []
        return
    assert len(sections) == 1
    when, title, payload = sections[0]
    assert (when, title) == ("call", "Job wait diagnostic")
    assert PRIVATE not in payload
    report = json.loads(payload)
    assert report["stage"] == stage
    assert report["last_wait_job"]["available"] is True
    assert report["last_wait_job"]["state"] == "running"
    assert report["last_wait_job"]["phase"] == "running"
    assert report["last_wait_job"]["has_proposal_review_field"] is True


@pytest.mark.parametrize("report_section", [False, True])
def test_success_and_other_exceptions_do_not_run_diagnostics(monkeypatch, report_section):
    def unexpected(*_args):
        pytest.fail("diagnostics reached without a job wait timeout")

    monkeypatch.setattr(diagnostic, "_report", unexpected)
    with diagnostic.diagnose_job_wait("graph_parent", unexpected if report_section else None):
        result = "unchanged"
    assert result == "unchanged"
    original = ValueError(PRIVATE)
    with pytest.raises(ValueError) as caught:
        with diagnostic.diagnose_job_wait("graph_parent", unexpected if report_section else None):
            raise original
    assert caught.value is original
