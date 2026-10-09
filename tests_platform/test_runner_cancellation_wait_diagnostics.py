from __future__ import annotations

import json
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

import pytest

from bluefire.runner_transport_errors import (
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
)
from tests_platform import runner_cancellation_wait_diagnostics as diagnostic


class SectionNode:
    def __init__(self) -> None:
        self.sections = []

    def add_report_section(self, *args: str) -> None:
        self.sections.append(args)


def test_wrapper_preserves_arguments_return_and_caches_allowlisted_response_state() -> None:
    recorder = diagnostic.CancellationWaitRecorder()
    payload = {"private": "request-payload"}
    result = {"state": "cancelling", "private": "response-payload"}
    args = (payload,)
    kwargs = {"abort_event": object()}
    calls = []

    def delegate(*received_args: Any, **received_kwargs: Any) -> object:
        calls.append((received_args, received_kwargs))
        return result

    assert recorder.wrap("cancel", delegate)(*args, **kwargs) is result
    assert calls == [(args, kwargs)]
    result["state"] = "private-state"
    phase = recorder.snapshot()["phases"]["cancel"]
    assert phase == {
        "state": "returned",
        "entered": 1,
        "returned": 1,
        "raised": 0,
        "error": "none",
        "response_state": "cancelling",
    }
    assert "private" not in json.dumps(recorder.snapshot())


@pytest.mark.parametrize(
    "error,error_category",
    [
        (RunnerTaskCancelled("private detail"), "cancelled"),
        (RunnerTaskTimedOut("private detail"), "runner_timeout"),
        (RunnerAuthenticationError("private detail"), "authentication"),
        (RunnerConnectionError("private detail"), "connection"),
        (FutureTimeoutError("private detail"), "future_timeout"),
        (TimeoutError("private detail"), "future_timeout"),
        (OSError("private detail"), "os_error"),
        (ValueError("private detail"), "other_exception"),
    ],
)
def test_wrapper_preserves_exact_exception_and_records_only_allowlisted_category(
    error: BaseException, error_category: str
) -> None:
    recorder = diagnostic.CancellationWaitRecorder()

    def delegate(*_args: Any, **_kwargs: Any) -> None:
        raise error

    with pytest.raises(type(error)) as caught:
        recorder.wrap("execute", delegate)("private-arg", timeout=8)
    assert caught.value is error
    phase = recorder.snapshot()["phases"]["execute"]
    assert phase == {
        "state": "raised",
        "entered": 1,
        "returned": 0,
        "raised": 1,
        "error": error_category,
        "response_state": "unknown",
    }
    assert "private" not in json.dumps(recorder.snapshot())


def test_response_mapping_subclass_is_not_inspected() -> None:
    class Unreadable(dict[str, Any]):
        def get(self, *_args: Any, **_kwargs: Any) -> object:
            pytest.fail("diagnostic inspected a custom response mapping")

    recorder = diagnostic.CancellationWaitRecorder()
    result = Unreadable(state="completed")
    assert recorder.wrap("recover", lambda: result)() is result
    assert recorder.snapshot()["phases"]["recover"]["response_state"] == "unknown"


def test_snapshot_normalizes_malformed_cache_values_and_saturates_counts() -> None:
    recorder = diagnostic.CancellationWaitRecorder()
    recorder._phases["cancel"] = (
        "private-state",
        10**100,
        -1,
        True,
        "private-error",
        "private-response",
    )
    recorder._phases["recover"] = ("malformed",)
    report = recorder.snapshot()
    assert report["phases"]["cancel"] == {
        "state": "unknown",
        "entered": 32,
        "returned": 0,
        "raised": 0,
        "error": "unknown",
        "response_state": "unknown",
    }
    assert report["phases"]["recover"] == {
        "state": "absent",
        "entered": 0,
        "returned": 0,
        "raised": 0,
        "error": "none",
        "response_state": "unknown",
    }
    assert "private" not in json.dumps(report)


def test_real_pending_future_timeout_has_unknown_origin_report() -> None:
    future: Future[object] = Future()
    recorder = diagnostic.CancellationWaitRecorder()
    node = SectionNode()
    original: FutureTimeoutError | None = None
    with pytest.raises(FutureTimeoutError) as caught:
        with diagnostic.cancellation_future_wait(node, recorder):
            try:
                recorder.wrap("worker", future.result)(timeout=0)
            except FutureTimeoutError as error:
                original = error
                raise
    assert caught.value is original
    when, heading, content = node.sections[0]
    report = json.loads(content)
    assert (when, heading) == ("call", "Runner cancellation wait")
    assert report["timeout_origin"] == "unknown"
    assert report["phases"]["worker"]["error"] == "future_timeout"
    assert len(content) < 1024
    assert "private" not in content


def test_worker_raised_timeout_error_keeps_unknown_origin_label() -> None:
    def worker() -> None:
        raise TimeoutError("private worker timeout detail")

    recorder = diagnostic.CancellationWaitRecorder()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker)
        with pytest.raises(TimeoutError):
            recorder.wrap("worker", future.result)(timeout=2)
    report = recorder.snapshot()
    assert report["timeout_origin"] == "unknown"
    assert report["phases"]["worker"]["error"] == "future_timeout"
    assert "private" not in json.dumps(report)


def test_recorder_failure_preserves_delegate_result_and_exception_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = diagnostic.CancellationWaitRecorder()
    monkeypatch.setattr(
        recorder,
        "_entered",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("private recorder failure")),
    )
    value = object()
    assert recorder.wrap("execute", lambda: value)() is value
    original = RuntimeError("original delegate exception")
    cleaned = []

    def delegate() -> None:
        raise original

    with pytest.raises(RuntimeError) as caught:
        try:
            recorder.wrap("execute", delegate)()
        finally:
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]


@pytest.mark.parametrize("failure_site", ["snapshot", "sink"])
def test_report_failures_preserve_exact_timeout_and_cleanup(
    failure_site: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenNode:
        def add_report_section(self, *_args: object) -> None:
            raise KeyboardInterrupt("private sink failure")

    recorder = diagnostic.CancellationWaitRecorder()
    if failure_site == "snapshot":
        monkeypatch.setattr(
            recorder,
            "snapshot",
            lambda: (_ for _ in ()).throw(RuntimeError("private snapshot failure")),
        )
    original = FutureTimeoutError("original Future timeout")
    cleaned = []
    with pytest.raises(FutureTimeoutError) as caught:
        try:
            with diagnostic.cancellation_future_wait(BrokenNode(), recorder):
                raise original
        finally:
            cleaned.append(True)
    assert caught.value is original and cleaned == [True]


def test_success_adds_no_report_or_output(capsys: pytest.CaptureFixture[str]) -> None:
    class Node:
        def add_report_section(self, *_args: object) -> None:
            pytest.fail("successful call emitted diagnostic")

    recorder = diagnostic.CancellationWaitRecorder()
    value = object()
    with diagnostic.cancellation_future_wait(Node(), recorder):
        assert recorder.wrap("execute", lambda: value)() is value
    assert capsys.readouterr() == ("", "")
