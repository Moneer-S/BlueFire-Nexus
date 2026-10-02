"""Proposed negative tests: authored fakes only, no sockets or subprocesses."""

import json
import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bluefire.ai_wire import AIProviderTransportError
from tests_platform import http_deadline_diagnostics as diagnostic
from tests_platform import test_ai_transport_deadline as original


class PrivateTrap:
    def __getattr__(self, _name):
        raise AssertionError("private attribute inspected")

    def __repr__(self):
        raise AssertionError("private object formatted")

    def __str__(self):
        raise AssertionError("private object stringified")

    def __bool__(self):
        raise AssertionError("private object truth-tested")

    def __iter__(self):
        raise AssertionError("private object iterated")

    def __len__(self):
        raise AssertionError("private object counted")


def test_unknown_values_are_not_formatted_or_inspected_and_lists_are_bounded():
    private = PrivateTrap()
    phases = {name: private for name in diagnostic.PHASES}
    phases["private-token:/authored/path"] = private
    observed = diagnostic.evidence(private, phases, [private] * 2000, private, [private])
    assert observed["route"] == "unknown"
    assert observed["phases"] == dict.fromkeys(diagnostic.PHASES)
    assert observed["entered_flag_cached"] is None
    assert observed["worker_count"] == "multiple"
    assert observed["worker_returncode_categories"] == ["unknown", "unknown"]
    assert observed["workers_truncated"] is True
    assert observed["recorded_path_count"] == "one"
    assert "private-token" not in json.dumps(observed)
    unavailable = diagnostic.evidence(private, private, private, private, private)
    assert unavailable["worker_count"] == unavailable["recorded_path_count"] == "unknown"
    assert unavailable["worker_returncode_categories"] == []


@pytest.mark.parametrize(
    "cached,expected",
    [
        (None, "none"),
        (0, "zero"),
        (-15, "negative"),
        (124, "positive"),
        (True, "unknown"),
        ("private-token:/authored/path", "unknown"),
    ],
)
def test_only_exact_popen_cache_is_read_without_process_methods(monkeypatch, cached, expected):
    # An unstarted exact Popen object exercises the cache branch without a child.
    process = object.__new__(diagnostic._POPEN_TYPE)
    process._child_created = False  # Popen.__del__ must do no process work either.
    process.returncode = cached

    def forbidden(*_args, **_kwargs):
        raise AssertionError("diagnostic performed a process operation")

    for method in ("poll", "wait", "communicate", "terminate", "kill"):
        monkeypatch.setattr(diagnostic._POPEN_TYPE, method, forbidden)
    entered = threading.Event()
    monkeypatch.setattr(entered, "is_set", forbidden)
    monkeypatch.setattr(entered, "wait", forbidden)
    observed = diagnostic.evidence("slow-body", diagnostic.new_phases(), [process], entered, [])
    assert observed["worker_returncode_categories"] == [expected]
    assert observed["entered_flag_cached"] is False
    assert "private-token" not in json.dumps(observed)


def test_exact_pytest_report_section_is_retained_without_stdout(monkeypatch, request, capsys):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("diagnostic must not use stdout")

    monkeypatch.setattr(diagnostic, "print", forbidden, raising=False)
    before = len(request.node._report_sections)
    diagnostic._report(
        request.node.add_report_section,
        "slow-body",
        diagnostic.new_phases(),
        [],
        threading.Event(),
        [],
    )
    expected = {
        "stage": "http_deadline_assertion",
        "observation": "cached_nonatomic",
        "route": "slow-body",
        "phases": {
            "spawn_called": False,
            "spawn_returned": False,
            "handler_entered": False,
            "request_body_read": False,
            "slow_header_write_completed": False,
            "non_drip_headers_completed": False,
            "slow_body_write_completed": False,
        },
        "entered_flag_cached": False,
        "recorded_path_count": "zero",
        "worker_count": "zero",
        "worker_returncode_categories": [],
        "workers_truncated": False,
        "writer_progress": "not_observed",
        "tcp_accept_progress": "not_observed",
        "worker_import_progress": "not_observed",
    }
    assert request.node._report_sections[before:] == [
        ("call", "HTTP deadline diagnostic", json.dumps(expected, sort_keys=True))
    ]
    output = capsys.readouterr()
    assert output.out == output.err == ""


@contextmanager
def original_fixture_harness(monkeypatch):
    """Drive the unchanged teardown bodies using inert process/server/thread fakes."""
    calls = []
    reports = []
    request = SimpleNamespace(
        node=SimpleNamespace(stash={}, add_report_section=lambda *section: reports.append(section))
    )

    class Server:
        def __init__(self, address, handler):
            assert address == ("127.0.0.1", 0)
            self.server_port = 1234

        def serve_forever(self, **_kwargs):
            raise AssertionError("fake thread must not execute server work")

        def shutdown(self):
            calls.append("server_shutdown")

        def server_close(self):
            calls.append("server_close")

    class Thread:
        def __init__(self, *, target, kwargs):
            assert kwargs == {"poll_interval": 0.02}

        def start(self):
            calls.append("thread_start")

        def join(self, *, timeout):
            assert timeout == 2
            calls.append("thread_join")

        def is_alive(self):
            calls.append("thread_alive_check")
            return False

    class Reader:
        def is_alive(self):
            calls.append("reader_alive_check")
            return False

    class Process:
        returncode = 0
        stdout = SimpleNamespace(closed=True)
        stdout_thread = Reader()

        def poll(self):
            calls.append("worker_poll")
            return self.returncode

    process = Process()
    monkeypatch.setattr(original, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(original.threading, "Thread", Thread)
    monkeypatch.setattr(original.subprocess, "Popen", lambda *_args, **_kwargs: process)
    endpoint_fixture = original.endpoint.__wrapped__(request)
    endpoint = next(endpoint_fixture)
    workers_fixture = original.workers.__wrapped__(monkeypatch, request)
    workers = next(workers_fixture)
    ticks = iter((100.0, 100.9))
    monkeypatch.setattr(original, "time", SimpleNamespace(monotonic=lambda: next(ticks)))

    def post(url, *, timeout):
        assert url in {endpoint[0] + "/slow-headers", endpoint[0] + "/slow-body"}
        assert timeout == 0.8
        original.subprocess.Popen(
            [getattr(sys, "_base_executable", sys.executable), "authored-worker"],
            shell=False,
            env={},
        )
        raise AIProviderTransportError(
            "private exception text", retryable=True, code="request_timed_out"
        )

    monkeypatch.setattr(original, "_post", post)
    try:
        yield SimpleNamespace(
            request=request,
            endpoint=endpoint,
            workers=workers,
            process=process,
            calls=calls,
            reports=reports,
        )
    finally:
        try:
            with pytest.raises(StopIteration):
                next(workers_fixture)
        finally:
            with pytest.raises(StopIteration):
                next(endpoint_fixture)


@pytest.mark.parametrize("route", ["slow-headers", "slow-body"])
@pytest.mark.parametrize("report_failure", ["none", "inspection", "sink"])
def test_actual_caller_preserves_same_assertion_and_original_cleanup(
    monkeypatch, capsys, route, report_failure
):
    failure = AssertionError("private original exception text")
    reported = []
    real_report = diagnostic._report

    def report(*args):
        reported.append(True)
        real_report(*args)

    def broken(*_args, **_kwargs):
        raise KeyboardInterrupt("private diagnostic failure")

    monkeypatch.setattr(diagnostic, "_report", report)
    if report_failure == "inspection":
        monkeypatch.setattr(diagnostic, "evidence", broken)

    with original_fixture_harness(monkeypatch) as harness:
        if report_failure == "sink":
            monkeypatch.setattr(harness.request.node, "add_report_section", broken)

        def original_failure():
            raise failure

        monkeypatch.setattr(harness.endpoint[1], "is_set", original_failure)
        with pytest.raises(AssertionError) as refused:
            original.test_deadline_covers_drip_headers_and_body(
                route, harness.endpoint, harness.workers, harness.request
            )
        assert refused.value is failure
    assert reported == [True]
    assert harness.calls == [
        "thread_start",
        "worker_poll",
        "reader_alive_check",
        "server_shutdown",
        "server_close",
        "thread_join",
        "thread_alive_check",
    ]
    output = capsys.readouterr()
    assert output.out == output.err == ""
    if report_failure == "none":
        assert len(harness.reports) == 1
        when, title, payload = harness.reports[0]
        assert (when, title) == ("call", "HTTP deadline diagnostic")
        assert "private" not in payload
        observed = json.loads(payload)
        assert observed["route"] == route
        assert observed["phases"]["spawn_called"] is True
        assert observed["phases"]["spawn_returned"] is True
    else:
        assert harness.reports == []


@pytest.mark.parametrize("route", ["slow-headers", "slow-body"])
def test_original_false_entry_assertion_still_fails_and_reports(monkeypatch, capsys, route):
    with original_fixture_harness(monkeypatch) as harness:
        with pytest.raises(AssertionError):
            original.test_deadline_covers_drip_headers_and_body(
                route, harness.endpoint, harness.workers, harness.request
            )
    output = capsys.readouterr()
    assert output.out == output.err == ""
    assert len(harness.reports) == 1
    when, title, payload = harness.reports[0]
    assert (when, title) == ("call", "HTTP deadline diagnostic")
    observed = json.loads(payload)
    assert observed["entered_flag_cached"] is False
    assert observed["recorded_path_count"] == "zero"
    assert "worker_poll" in harness.calls and harness.calls[-1] == "thread_alive_check"


def test_original_worker_capture_still_refuses_credential_arguments(monkeypatch, capsys):
    with original_fixture_harness(monkeypatch) as harness:
        with pytest.raises(AssertionError):
            original.subprocess.Popen(
                [getattr(sys, "_base_executable", sys.executable), "test-only-value"],
                shell=False,
                env={},
            )
        assert harness.workers == []
        assert original._http_deadline_phases(harness.request)["spawn_called"] is False
    assert capsys.readouterr().out == ""
    assert harness.reports == []


@pytest.mark.parametrize("route", ["slow-headers", "slow-body"])
def test_actual_successful_caller_does_not_report(monkeypatch, route):
    monkeypatch.setattr(
        diagnostic, "_report", lambda *_args: pytest.fail("success must not report")
    )
    with original_fixture_harness(monkeypatch) as harness:
        harness.endpoint[1].set()
        harness.endpoint[2].append(f"/{route}")
        original.test_deadline_covers_drip_headers_and_body(
            route, harness.endpoint, harness.workers, harness.request
        )
    assert "worker_poll" in harness.calls and harness.calls[-1] == "thread_alive_check"
    assert harness.reports == []


def test_original_worker_cleanup_refusal_still_runs_endpoint_cleanup(monkeypatch):
    calls = None
    with pytest.raises(AssertionError, match="HTTP worker survived request completion"):
        with original_fixture_harness(monkeypatch) as harness:
            calls = harness.calls
            harness.endpoint[1].set()
            harness.endpoint[2].append("/slow-body")
            original.test_deadline_covers_drip_headers_and_body(
                "slow-body", harness.endpoint, harness.workers, harness.request
            )
            harness.process.returncode = None
    assert calls[-4:] == ["server_shutdown", "server_close", "thread_join", "thread_alive_check"]


def test_non_assertion_exception_is_not_reported_or_replaced(monkeypatch):
    failure = RuntimeError("private original exception")
    monkeypatch.setattr(
        diagnostic, "_report", lambda *_args: pytest.fail("non-assertion must not report")
    )
    with pytest.raises(RuntimeError) as refused:
        with diagnostic.diagnose_http_deadline(
            PrivateTrap(), PrivateTrap(), PrivateTrap(), PrivateTrap(), PrivateTrap(), PrivateTrap()
        ):
            raise failure
    assert refused.value is failure
