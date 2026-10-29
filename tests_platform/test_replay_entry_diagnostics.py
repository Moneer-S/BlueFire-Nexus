"""Replay entry diagnostics preserve the bounded wait and mask private thread data."""

import json
from types import SimpleNamespace

import pytest

from tests_platform import job_wait_diagnostics as diagnostics
from tests_platform import test_replay_cancellation_settlement as replay

PRIVATE = "private-task C:\\private\\run secret=fixture-private"


class EntryEvent:
    def __init__(self, result=False, error=None):
        self.result = result
        self.error = error
        self.timeouts = []

    def wait(self, timeout):
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return self.result


def test_entry_success_keeps_ten_second_wait_and_emits_nothing(monkeypatch):
    def unexpected(*_args):
        pytest.fail("successful entry must not inspect diagnostics")

    monkeypatch.setattr(replay, "job_wait_report", unexpected)
    event = EntryEvent(result=True)
    replay._assert_replay_execution_entry(event, unexpected)
    assert event.timeouts == [10]


def test_entry_failure_has_bounded_sanitized_process_paths_without_store_reads(monkeypatch):
    class Frame:
        def __init__(self, name, parent=None):
            self.f_code = SimpleNamespace(co_name=name)
            self.f_back = parent

        @property
        def f_locals(self):
            pytest.fail("process stack diagnostics must not read worker locals")

    frame = Frame(PRIVATE)
    for _ in range(30):
        frame = Frame("_execute_replay_job", frame)
    monkeypatch.setattr(diagnostics.sys, "_current_frames", lambda: {n: frame for n in range(10)})
    event = EntryEvent()
    sections = []
    with pytest.raises(AssertionError):
        replay._assert_replay_execution_entry(event, lambda *row: sections.append(row))
    assert event.timeouts == [10]
    assert len(sections) == 1
    when, title, payload = sections[0]
    assert (when, title) == ("call", "Replay execution entry diagnostic")
    report = json.loads(payload)
    assert report["stage"] == "replay_execution_entry"
    assert report["last_wait_job"] == {"available": False}
    assert report["process_threads_truncated"] is True
    assert len(report["process_thread_functions"]) == 8
    assert all(len(stack) == 24 for stack in report["process_thread_functions"])
    assert all(
        set(stack) <= diagnostics.FUNCTIONS | {"unknown"}
        for stack in report["process_thread_functions"]
    )
    assert len(payload) < 8192
    assert PRIVATE not in payload


def test_entry_failure_masks_unrecognized_function_names(monkeypatch):
    frame = SimpleNamespace(f_code=SimpleNamespace(co_name=PRIVATE), f_back=None)
    monkeypatch.setattr(diagnostics.sys, "_current_frames", lambda: {PRIVATE: frame})
    sections = []
    with pytest.raises(AssertionError):
        replay._assert_replay_execution_entry(EntryEvent(), lambda *row: sections.append(row))
    report = json.loads(sections[0][2])
    assert report["process_thread_functions"] == [["unknown"]]
    assert PRIVATE not in sections[0][2]


@pytest.mark.parametrize("boundary", ["projection", "section"])
@pytest.mark.parametrize("diagnostic_error", [RuntimeError(PRIVATE), KeyboardInterrupt()])
def test_diagnostic_failures_preserve_original_assertion(monkeypatch, boundary, diagnostic_error):
    original = AssertionError("entry assertion")
    event = EntryEvent(error=original)

    def fail(*_args):
        raise diagnostic_error

    if boundary == "projection":
        monkeypatch.setattr(replay, "job_wait_report", fail)
    with pytest.raises(AssertionError) as raised:
        replay._assert_replay_execution_entry(event, fail)
    assert raised.value is original
    assert event.timeouts == [10]


def test_entry_non_assertion_error_is_not_converted_or_reported(monkeypatch):
    original = RuntimeError("entry wait failed")

    def unexpected(*_args):
        pytest.fail("non-assertion exception must pass through")

    monkeypatch.setattr(replay, "job_wait_report", unexpected)
    event = EntryEvent(error=original)
    with pytest.raises(RuntimeError) as raised:
        replay._assert_replay_execution_entry(event, unexpected)
    assert raised.value is original
    assert event.timeouts == [10]
