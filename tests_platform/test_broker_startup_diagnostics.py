from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from tests_platform import broker_startup_diagnostics as diagnostic


def test_transition_wrapper_preserves_arguments_return_and_projects_cached_state() -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    result = {
        "state": "running",
        "progress": {"phase": "planning", "private": "raw-progress"},
        "error": None,
        "request": "private-request",
    }
    args = ("private-job-id", "running")
    kwargs = {"progress": result["progress"]}
    calls = []

    def delegate(*received_args: Any, **received_kwargs: Any) -> object:
        calls.append((received_args, received_kwargs))
        return result

    assert recorder.wrap_transition(delegate)(*args, **kwargs) is result
    assert calls == [(args, kwargs)]
    assert recorder.snapshot(1) == {
        "schema_version": 1,
        "snapshot": "best_effort_cached",
        "job_state": "running",
        "job_phase": "planning",
        "error_class": "none",
        "transitions_seen": 1,
        "broker_phase": "request_seen",
        "broker_request_count": 1,
    }
    assert "private" not in json.dumps(recorder.snapshot(1))


def test_transition_wrapper_preserves_original_exception() -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    original = RuntimeError("private transition detail")

    def delegate() -> None:
        raise original

    with pytest.raises(RuntimeError) as caught:
        recorder.wrap_transition(delegate)()
    assert caught.value is original
    assert recorder.transitions_seen == 0
    assert recorder.snapshot(0)["job_state"] == "unknown"


@pytest.mark.parametrize(
    "code,expected",
    [
        ("execution_callback_failed", "execution_callback_failed"),
        ("run_cleanup_deferred", "run_cleanup_deferred"),
        ("private-code", "unknown"),
    ],
)
def test_error_classification_is_allowlisted_and_does_not_retain_message(
    code: str, expected: str
) -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    recorder.wrap_transition(
        lambda: {
            "state": "failed",
            "progress": {"phase": "failed"},
            "error": {"code": code, "message": "private error message"},
        }
    )()
    report = recorder.snapshot(0)
    assert report["error_class"] == expected
    assert "private" not in json.dumps(report)


def test_late_submission_projection_cannot_overwrite_racing_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    projection_started = threading.Event()
    release_projection = threading.Event()
    original_projection = recorder._project_submission

    def pause_submission_projection(result: object) -> tuple[str, str, str]:
        projection_started.set()
        if not release_projection.wait(2):
            raise RuntimeError("test interleave was not released")
        return original_projection(result)

    monkeypatch.setattr(recorder, "_project_submission", pause_submission_projection)
    worker = threading.Thread(
        target=recorder.record_submission,
        args=({"state": "queued", "progress": {"phase": "queued"}},),
    )
    worker.start()
    try:
        assert projection_started.wait(2)
        recorder.wrap_transition(
            lambda: {
                "state": "running",
                "progress": {"phase": "running"},
                "error": None,
            }
        )()
    finally:
        release_projection.set()
        worker.join(2)
    assert not worker.is_alive()
    assert recorder.snapshot(0)["job_state"] == "running"
    assert recorder.snapshot(0)["job_phase"] == "running"


def test_submission_projection_failure_is_quiet_and_does_not_skip_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    monkeypatch.setattr(
        recorder,
        "_project_submission",
        lambda _result: (_ for _ in ()).throw(KeyboardInterrupt("private recorder failure")),
    )
    cleaned = []
    try:
        recorder.record_submission({"state": "queued"})
    finally:
        cleaned.append(True)
    assert cleaned == [True]
    assert recorder.snapshot(0)["job_state"] == "unknown"


def test_unobserved_snapshot_and_absent_error_remain_unknown() -> None:
    recorder = diagnostic.BrokerStartupRecorder()
    assert recorder.snapshot(0)["error_class"] == "unknown"
    recorder.record_submission({"state": "queued", "progress": {"phase": "queued"}})
    report = recorder.snapshot(0)
    assert report["job_state"] == "queued"
    assert report["error_class"] == "unknown"


def test_untrusted_shapes_and_unbounded_counts_are_normalized() -> None:
    class Unreadable(dict[str, Any]):
        def get(self, *_args: Any, **_kwargs: Any) -> object:
            pytest.fail("diagnostic invoked a mapping getter")

    assert diagnostic._project(Unreadable()) == ("unknown", "unknown", "unknown")
    recorder = diagnostic.BrokerStartupRecorder()
    report = recorder.snapshot(10**100)
    assert report["broker_request_count"] == 32
    assert report["job_state"] == report["job_phase"] == report["error_class"] == "unknown"


def test_assertion_report_is_private_bounded_and_precedes_cleanup() -> None:
    class Node:
        def __init__(self) -> None:
            self.sections = []

        def add_report_section(self, *args: str) -> None:
            self.sections.append(args)

    class Channel:
        requests = ["private request payload"]

    recorder = diagnostic.BrokerStartupRecorder()
    recorder.record_submission(
        {
            "state": "private-state",
            "progress": {"phase": "private-phase"},
            "error": {"code": "private-code", "message": "private-message"},
        }
    )
    node = Node()
    original = AssertionError("broker proposal did not start")
    cleaned = []
    with pytest.raises(AssertionError) as caught:
        try:
            with diagnostic.broker_startup_assertion(node, recorder, Channel()):
                raise original
        finally:
            assert len(node.sections) == 1
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]
    when, heading, content = node.sections[0]
    assert (when, heading) == ("call", "Broker job startup")
    assert len(content) < 512
    assert "private" not in content
    assert json.loads(content) == {
        "schema_version": 1,
        "snapshot": "best_effort_cached",
        "job_state": "unknown",
        "job_phase": "unknown",
        "error_class": "unknown",
        "transitions_seen": 0,
        "broker_phase": "request_seen",
        "broker_request_count": 1,
    }


def test_snapshot_and_sink_failures_preserve_assertion_and_cleanup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Channel:
        requests = []
        entered = threading.Event()

    class BrokenNode:
        def add_report_section(self, *_args: object) -> None:
            raise KeyboardInterrupt("private sink detail")

    for failure_site in ("snapshot", "sink"):
        recorder = diagnostic.BrokerStartupRecorder()
        node: Any = BrokenNode()
        if failure_site == "snapshot":
            monkeypatch.setattr(
                recorder,
                "snapshot",
                lambda *_args: (_ for _ in ()).throw(RuntimeError("private snapshot detail")),
            )
        original = AssertionError("original broker-entry assertion")
        cleaned = []
        with pytest.raises(AssertionError) as caught:
            try:
                with diagnostic.broker_startup_assertion(node, recorder, Channel()):
                    raise original
            finally:
                cleaned.append(True)
        assert caught.value is original and cleaned == [True]
    assert capsys.readouterr() == ("", "")


def test_success_adds_no_report_or_output(capsys: pytest.CaptureFixture[str]) -> None:
    class Node:
        def add_report_section(self, *_args: object) -> None:
            pytest.fail("successful assertion emitted diagnostic")

    class Channel:
        requests = []
        entered = threading.Event()

    with diagnostic.broker_startup_assertion(Node(), diagnostic.BrokerStartupRecorder(), Channel()):
        pass
    assert capsys.readouterr() == ("", "")
