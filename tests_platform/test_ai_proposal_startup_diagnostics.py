from __future__ import annotations

import json
from subprocess import TimeoutExpired
from typing import Any

import pytest

from tests_platform import ai_proposal_startup_diagnostics as diagnostics
from tests_platform.ai_proposal_startup_diagnostics import (
    ProposalStartupRecorder,
    proposal_process_diagnostic,
    proposal_process_phase,
    proposal_process_timeout,
    proposal_startup_assertion,
)


def test_launch_wrapper_preserves_arguments_return_and_cached_phases() -> None:
    recorder = ProposalStartupRecorder()
    command = ["private-command"]
    environment = {"AUTHORED_TEST_CONTEXT": "private-value"}
    process = object()
    assert recorder.snapshot()["launch_state"] == "absent"

    def delegate(*args: Any, **kwargs: Any) -> object:
        assert args == (command,)
        assert args[0] is command and kwargs["env"] is environment
        assert kwargs["shell"] is False
        assert recorder.snapshot()["launch_state"] == "attempting"
        assert recorder.snapshot()["launch_attempts"] == 1
        return process

    assert recorder.wrap_popen(delegate)(command, env=environment, shell=False) is process
    assert recorder.snapshot()["launch_state"] == "launched"
    assert recorder.snapshot()["launch_returns"] == 1
    assert recorder.snapshot()["launch_failures"] == 0


@pytest.mark.parametrize(
    "error,category",
    [
        (OSError("private-os-detail"), "os_error"),
        (AssertionError("private-assertion-detail"), "assertion_error"),
        (KeyboardInterrupt("private-interrupt-detail"), "other_exception"),
    ],
)
def test_launch_failure_preserves_exact_exception_and_only_records_category(
    error: BaseException, category: str
) -> None:
    recorder = ProposalStartupRecorder()

    def delegate() -> None:
        raise error

    with pytest.raises(type(error)) as caught:
        recorder.wrap_popen(delegate)()
    assert caught.value is error
    assert recorder.snapshot()["launch_state"] == "failed"
    assert recorder.snapshot()["launch_failures"] == 1
    assert recorder.snapshot()["launch_failure_category"] == category
    assert "private" not in json.dumps(recorder.snapshot())


def test_transition_projects_returned_phase_without_retaining_or_rereading_store() -> None:
    recorder = ProposalStartupRecorder()
    progress = {"phase": "planning", "raw": "private-progress"}
    result = {"state": "running", "progress": progress, "request": "private-request"}
    calls = []

    def transition(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append((args, kwargs))
        assert kwargs["progress"] is progress
        return result

    returned = recorder.wrap_transition(transition)("private-job-id", "running", progress=progress)
    assert returned is result
    assert calls == [(("private-job-id", "running"), {"progress": progress})]
    # Reporting has no reference to this mutable record or to a store getter.
    result.clear()
    progress.clear()
    assert recorder.snapshot()["job_state"] == "running"
    assert recorder.snapshot()["job_phase"] == "planning"
    assert "private" not in json.dumps(recorder.snapshot())


def test_failed_transition_preserves_exception_and_last_returned_phase() -> None:
    recorder = ProposalStartupRecorder()
    recorder.wrap_transition(lambda: {"state": "queued", "progress": {"phase": "queued"}})()
    error = RuntimeError("private-store-detail")

    def transition() -> None:
        raise error

    with pytest.raises(RuntimeError) as caught:
        recorder.wrap_transition(transition)()
    assert caught.value is error
    assert recorder.snapshot()["job_state"] == "queued"
    assert recorder.snapshot()["job_phase"] == "queued"


def test_untrusted_mapping_is_not_inspected() -> None:
    class Unreadable(dict[str, Any]):
        def get(self, *args: Any, **kwargs: Any) -> Any:
            pytest.fail("diagnostics invoked a mapping getter")

    recorder = ProposalStartupRecorder()
    result = Unreadable(state="private-state", progress="private-progress")
    assert recorder.wrap_transition(lambda: result)() is result
    assert recorder.snapshot()["job_state"] == "unknown"
    assert recorder.snapshot()["job_phase"] == "unknown"


def test_recorder_failure_cannot_change_delegation_or_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = ProposalStartupRecorder()

    def broken(*args: Any) -> None:
        raise KeyboardInterrupt("private-recorder-failure")

    for name in ("_launch_entered", "_launch_returned", "_launch_failed", "_transition_returned"):
        monkeypatch.setattr(recorder, name, broken)
    value = object()
    assert recorder.wrap_popen(lambda: value)() is value
    assert recorder.wrap_transition(lambda: value)() is value
    original = OSError("private-original-error")

    def fail() -> None:
        raise original

    with pytest.raises(OSError) as caught:
        recorder.wrap_popen(fail)()
    assert caught.value is original


def test_real_report_section_is_bounded_private_safe_and_precedes_cleanup(
    request: pytest.FixtureRequest, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = ProposalStartupRecorder()
    recorder.wrap_transition(
        lambda: {"state": "private-state", "progress": {"phase": "private-path"}}
    )()
    recorder.launch_attempts = 10**100
    recorder.launch_returns = -1
    recorder.launch_failures = True
    recorder.launch_failure_category = "private-token"
    recorder.launch_state = "private-url"
    original = AssertionError("proposal never reached the local endpoint")
    previous = len(request.node._report_sections)
    cleaned = []
    with pytest.raises(AssertionError) as caught:
        try:
            with proposal_startup_assertion(request.node, recorder):
                raise original
        finally:
            assert len(request.node._report_sections) == previous + 1
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]
    when, heading, content = request.node._report_sections[-1]
    assert (when, heading) == ("call", "AI proposal startup")
    assert len(content) < 512 and "private" not in content
    assert json.loads(content) == {
        "schema_version": 1,
        "snapshot": "best_effort_cached",
        "launch_state": "unknown",
        "launch_attempts": 32,
        "launch_returns": 0,
        "launch_failures": 0,
        "launch_failure_category": "unknown",
        "job_state": "unknown",
        "job_phase": "unknown",
    }
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("sink_error", [RuntimeError("sink unavailable"), KeyboardInterrupt()])
def test_failing_sink_preserves_original_assertion_and_cleanup(sink_error: BaseException) -> None:
    class Node:
        def add_report_section(self, *args: Any) -> None:
            raise sink_error

    original = AssertionError("original readiness assertion")
    cleaned = []
    with pytest.raises(AssertionError) as caught:
        try:
            with proposal_startup_assertion(Node(), ProposalStartupRecorder()):
                raise original
        finally:
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]


def test_snapshot_failure_preserves_original_assertion_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = ProposalStartupRecorder()

    def broken() -> None:
        raise RuntimeError("private-snapshot-detail")

    monkeypatch.setattr(recorder, "snapshot", broken)
    original = AssertionError("original readiness assertion")
    cleaned = []
    with pytest.raises(AssertionError) as caught:
        try:
            with proposal_startup_assertion(object(), recorder):
                raise original
        finally:
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]


def test_success_and_other_exceptions_add_no_report_or_output(
    request: pytest.FixtureRequest, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = ProposalStartupRecorder()
    previous = len(request.node._report_sections)
    with proposal_startup_assertion(request.node, recorder):
        pass
    original = ValueError("not the readiness assertion")
    with pytest.raises(ValueError) as caught:
        with proposal_startup_assertion(request.node, recorder):
            raise original
    assert caught.value is original
    assert len(request.node._report_sections) == previous
    assert capsys.readouterr() == ("", "")


def test_child_phase_projects_only_allowlisted_returned_status(capsys) -> None:
    proposal_process_phase(
        "submitted",
        {
            "state": "running",
            "progress": {"phase": "planning", "request": "private-payload"},
            "job_id": "private-identifier",
        },
    )
    captured = capsys.readouterr()
    assert captured.out == "" and len(captured.err) < 256
    assert "private" not in captured.err
    assert json.loads(captured.err.removeprefix(diagnostics._PROCESS_PREFIX)) == {
        "phase": "submitted",
        "job_state": "running",
        "job_phase": "planning",
    }


def test_child_phase_rejects_untrusted_mappings_and_unknown_labels(capsys) -> None:
    class Unreadable(dict):
        def get(self, *args, **kwargs):
            pytest.fail("diagnostics invoked an untrusted getter")

    proposal_process_phase("private-phase", Unreadable(state="running"))
    captured = capsys.readouterr()
    assert "private" not in captured.err
    assert json.loads(captured.err.removeprefix(diagnostics._PROCESS_PREFIX)) == {
        "phase": "unknown",
        "job_state": "unknown",
        "job_phase": "unknown",
    }


@pytest.mark.parametrize("failure", [OSError("private-sink-error"), KeyboardInterrupt()])
def test_child_phase_sink_failure_is_best_effort(monkeypatch, failure) -> None:
    class BrokenStream:
        def write(self, value):
            raise failure

    monkeypatch.setattr(diagnostics.sys, "stderr", BrokenStream())
    proposal_process_phase("child_started")


@pytest.mark.parametrize("as_bytes", [False, True])
def test_process_timeout_exposes_sanitized_phases_and_preserves_exception(
    request, as_bytes
) -> None:
    values = [
        {"phase": "waiting_parent", "job_state": "running", "job_phase": "planning"},
        {
            "phase": "private-phase",
            "job_state": "private-status",
            "job_phase": "private-path",
            "untrusted_payload": "private-value",
        },
        {"phase": "parent_wait_timeout", "job_state": False, "job_phase": ["private"]},
    ]
    captured = "private-traceback\n" + "\n".join(
        diagnostics._PROCESS_PREFIX + json.dumps(value) for value in values
    )
    captured += "\n" + diagnostics._PROCESS_PREFIX + "not-json-private"
    captured = captured.encode() if as_bytes else captured
    original = TimeoutExpired(["private-command"], 40, output=b"private-output", stderr=captured)
    previous = len(request.node._report_sections)
    cleaned = []
    with pytest.raises(TimeoutExpired) as caught:
        try:
            with proposal_process_timeout(request.node):
                raise original
        finally:
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]
    assert original.cmd == ["private-command"] and original.timeout == 40
    assert original.output == b"private-output" and original.stderr is captured
    assert len(request.node._report_sections) == previous + 1
    when, title, content = request.node._report_sections[-1]
    assert (when, title) == ("call", "AI proposal process timeout")
    assert "private" not in content and len(content) < 1024
    assert json.loads(content) == {
        "schema_version": 1,
        "snapshot": "best_effort_captured_child_phases",
        "last_phase": "parent_wait_timeout",
        "job_waits": [],
        "events": [
            values[0],
            {"phase": "unknown", "job_state": "unknown", "job_phase": "unknown"},
            {"phase": "parent_wait_timeout", "job_state": "unknown", "job_phase": "unknown"},
        ],
    }


def test_process_timeout_bounds_captured_output_and_event_count() -> None:
    line = diagnostics._PROCESS_PREFIX + json.dumps({"phase": "waiting_child"}) + "\n"
    output = b"private" * 10000 + (line * 40).encode() + b"\xff\xfe"
    report = diagnostics._process_timeout_snapshot(TimeoutExpired("unused", 40, stderr=output))
    assert len(report["events"]) == 16
    assert report["last_phase"] == "waiting_child"
    assert "private" not in json.dumps(report) and len(json.dumps(report)) < 2048


@pytest.mark.parametrize("output", [None, True, {}, "no child phases", b"\xff\xfe"])
def test_process_timeout_without_known_child_output_reports_unknown(output) -> None:
    report = diagnostics._process_timeout_snapshot(TimeoutExpired("unused", 40, stderr=output))
    assert report["events"] == [] and report["last_phase"] == "unknown"


@pytest.mark.parametrize("failure", [RuntimeError("private-sink-error"), KeyboardInterrupt()])
def test_process_timeout_report_failure_preserves_exact_timeout(failure) -> None:
    class Node:
        def add_report_section(self, *args):
            raise failure

    original = TimeoutExpired("private-command", 40)
    with pytest.raises(TimeoutExpired) as caught:
        with proposal_process_timeout(Node()):
            raise original
    assert caught.value is original


def test_process_timeout_snapshot_failure_and_other_exceptions_preserve_behavior(
    monkeypatch, request
) -> None:
    def broken(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(diagnostics, "_process_timeout_snapshot", broken)
    previous = len(request.node._report_sections)
    original = TimeoutExpired("private-command", 40)
    with pytest.raises(TimeoutExpired) as caught:
        with proposal_process_timeout(request.node):
            raise original
    assert caught.value is original
    with proposal_process_timeout(request.node):
        pass
    other = ValueError("not a timeout")
    with pytest.raises(ValueError) as caught:
        with proposal_process_timeout(request.node):
            raise other
    assert caught.value is other
    assert len(request.node._report_sections) == previous


@pytest.mark.parametrize("as_bytes", [False, True])
def test_process_timeout_retains_only_safe_wait_status_and_function_evidence(request, as_bytes):
    wait = {
        "stage": "graph_child",
        "last_wait_job": {
            "available": True,
            "state": "running",
            "phase": "finalizing",
            "error_code": "execution_callback_failed",
            "error_type": "private-exception",
            "has_error": True,
            "has_result_ref": "private-value",
            "has_children_field": False,
            "request": "private-request",
        },
        "process_thread_functions": [["wait_for_state", "private-function", True, {}]],
        "process_threads_truncated": "private-value",
        "private-path": "private-payload",
    }
    stdout = "private-traceback\nJob wait diagnostic: " + json.dumps(wait) + "\n"
    stderr = diagnostics._PROCESS_PREFIX + json.dumps({"phase": "child_wait_timeout"}) + "\n"
    if as_bytes:
        stdout, stderr = stdout.encode(), stderr.encode()
    original = TimeoutExpired("private-command", 40, stderr=stderr)
    original.stdout = stdout
    with pytest.raises(TimeoutExpired) as caught:
        with proposal_process_timeout(request.node):
            raise original
    assert caught.value is original and original.output is stdout and original.stderr is stderr
    content = request.node._report_sections[-1][2]
    assert "private" not in content and len(content) < 2048
    report = json.loads(content)
    assert report["last_phase"] == "child_wait_timeout"
    assert report["job_waits"] == [
        {
            "stage": "graph_child",
            "last_wait_job": {
                "available": True,
                "state": "running",
                "phase": "finalizing",
                "error_code": "execution_callback_failed",
                "error_type": "unknown",
                "has_error": True,
                "has_result_ref": False,
                "has_plan_field": False,
                "has_children_field": False,
                "has_proposal_review_field": False,
            },
            "process_thread_functions": [["wait_for_state", "unknown", "unknown", "unknown"]],
            "process_threads_truncated": False,
        }
    ]
    assert json.loads(proposal_process_diagnostic(stdout, stderr)) == report


def test_real_wait_helper_output_is_retained_for_unexpected_child_exit(capsys):
    from bluefire.job_runtime import JobWaitTimeout
    from tests_platform.job_wait_diagnostics import diagnose_job_wait

    with pytest.raises(JobWaitTimeout):
        with diagnose_job_wait("graph_parent"):
            raise JobWaitTimeout("private-error")
    captured = capsys.readouterr()
    report = json.loads(proposal_process_diagnostic(captured.out, captured.err))
    assert len(report["job_waits"]) == 1
    assert report["job_waits"][0]["stage"] == "graph_parent"
    assert report["job_waits"][0]["process_thread_functions"]
    assert "private" not in json.dumps(report)


@pytest.mark.parametrize(
    "output",
    [
        None,
        True,
        {},
        b"\xff\xfe",
        "Job wait diagnostic: not-json-private",
        "Job wait diagnostic: []",
        "Job wait diagnostic: null",
        "Job wait diagnostic: " + "[" * 2000,
        "Job wait diagnostic: " + json.dumps({"private": "value" * 2000}),
    ],
)
def test_wait_output_rejects_malformed_oversized_and_non_record_content(output):
    report = json.loads(proposal_process_diagnostic(output, None))
    assert report["job_waits"] == [] and "private" not in json.dumps(report)


def test_wait_output_caps_records_threads_and_functions_and_sanitizes_fields():
    wait = {
        "stage": "private-stage",
        "last_wait_job": {"available": "private-value", "state": "private-state"},
        "process_thread_functions": [["wait"] * 25] * 9,
        "process_threads_truncated": False,
    }
    line = "Job wait diagnostic: " + json.dumps(wait) + "\n"
    report = json.loads(proposal_process_diagnostic("private" * 10000 + "\n" + line * 4, None))
    assert len(report["job_waits"]) == 2
    for value in report["job_waits"]:
        assert value["stage"] == "unknown" and value["last_wait_job"] == {"available": False}
        assert len(value["process_thread_functions"]) == 8
        assert all(len(frame) == 24 for frame in value["process_thread_functions"])
        assert value["process_threads_truncated"] is True
    assert "private" not in json.dumps(report) and len(json.dumps(report)) < 8192


def test_unexpected_exit_diagnostic_failure_returns_constant_without_masking_assertion(monkeypatch):
    def broken(*args):
        raise KeyboardInterrupt("private-failure")

    monkeypatch.setattr(diagnostics, "_process_output_snapshot", broken)
    message = proposal_process_diagnostic("private-output", "private-error")
    assert message == '{"schema_version": 1, "snapshot": "unavailable"}'
    with pytest.raises(AssertionError) as caught:
        assert 1 == 77, message
    assert str(caught.value).startswith(message) and "private" not in str(caught.value)


def test_real_graph_crash_assertion_cannot_reveal_completed_process_repr(
    monkeypatch, tmp_path, request
):
    import subprocess

    from tests_platform import test_graph_ai_jobs as graph

    stdout = b'private-output\nJob wait diagnostic: {"stage":"graph_child"}\n'
    stderr = (
        b'private-error\nBlueFire proposal phase: {"phase":"waiting_child",'
        b'"job_state":"running","job_phase":"private-phase"}\n'
    )
    completed = subprocess.CompletedProcess(
        ["private-command", "private-argument"], 1, stdout=stdout, stderr=stderr
    )
    calls = []

    def no_child(*args, **kwargs):
        calls.append(True)
        assert kwargs["timeout"] == 40 and kwargs["capture_output"] is True
        return completed

    monkeypatch.setattr(subprocess, "run", no_child)
    with pytest.raises(AssertionError) as caught:
        graph.test_process_loss_after_proposal_publication_recovers_native_review_without_model(
            tmp_path, "chat_completions", request
        )
    assert calls == [True]
    text = str(caught.value)
    assert "private" not in text and "CompletedProcess" not in text
    assert '"last_phase": "waiting_child"' in text
    assert '"stage": "graph_child"' in text
    assert "assert 1 == 77" in text
