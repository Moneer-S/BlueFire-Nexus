from __future__ import annotations

import json
from typing import Any

import pytest

from tests_platform.ai_proposal_startup_diagnostics import (
    ProposalStartupRecorder,
    proposal_startup_assertion,
)


def test_launch_wrapper_preserves_arguments_return_and_cached_phases() -> None:
    recorder = ProposalStartupRecorder()
    command = ["private-command"]
    environment = {"PRIVATE_SECRET": "private-value"}
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
