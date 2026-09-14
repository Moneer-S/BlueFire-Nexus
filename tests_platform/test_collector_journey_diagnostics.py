"""Deterministic diagnostic tests; no subprocess, receiver or native execution."""

from __future__ import annotations

import json
import threading

import pytest

from bluefire.collector_journey import REPORT_PATHS, _write_json
from bluefire.collector_journey_diagnostics import (
    FAILURE_REPORT,
    CollectorJourneyDiagnostic,
    DiagnosticSubprocessRustRunner,
    observe,
)
from bluefire.run_store import RunStore
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_transport_errors import RunnerTaskTimedOut

PRIVATE = "private-value-in-test"
ACTION = "sandbox.fixture.create.v1"
PROFILE = "runner-profile.fixture.v1"


def diagnostic():
    return CollectorJourneyDiagnostic(
        step_ids=frozenset({"create_fixture", "cleanup_workspace"}),
        action_ids=frozenset({ACTION, "sandbox.cleanup.v1"}),
        profile_ids=frozenset({PROFILE}),
    )


def notes(error):
    result = getattr(error, "__notes__", [])
    assert bool(result) == callable(getattr(error, "add_note", None))
    return "".join(result)


def inputs():
    return (
        {
            "step_id": "create_fixture",
            "action_id": ACTION,
            "runner_profile_id": PROFILE,
            "limits": {"timeout_ms": 29500},
            "params": {"credential": PRIVATE},
        },
        {
            "limits": {"timeout_ms": 35000},
            "sandbox_root": f"C:/{PRIVATE}",
            "credential_reference": PRIVATE,
        },
    )


def observed_runner(observer):
    # Construction itself is deliberately bypassed only in this software test.
    runner = object.__new__(DiagnosticSubprocessRustRunner)
    runner.diagnostic = observer
    runner.timeout_seconds = 35.0
    return runner


@pytest.mark.parametrize("fails", [False, True])
def test_observer_delegates_once_with_exact_arguments_and_original_result_or_exception(
    tmp_path, monkeypatch, fails
):
    observer = diagnostic()
    runner = observed_runner(observer)
    manifest, profile = inputs()
    cancel = threading.Event()
    destination = tmp_path / PRIVATE
    cause = ValueError(PRIVATE)
    failure = RunnerTaskTimedOut(PRIVATE)
    failure.__cause__ = cause
    result = {"status": "success", "output": {"credential": PRIVATE}}
    calls = []

    def delegate(self, supplied_manifest, supplied_profile, **kwargs):
        calls.append((self, supplied_manifest, supplied_profile, kwargs))
        if fails:
            raise failure
        return result

    monkeypatch.setattr(SubprocessRustRunner, "execute_task", delegate)
    kwargs = dict(task_id=PRIVATE, cancel_event=cancel, durable_result_path=destination)
    if fails:
        with pytest.raises(RunnerTaskTimedOut) as caught:
            runner.execute_task(manifest, profile, **kwargs)
        assert caught.value is failure and caught.value.__cause__ is cause
        assert observer.last_unsuccessful_attempt["exception_type"] == "RunnerTaskTimedOut"
        assert observer.last_attempt["result_returned"] is False
    else:
        assert runner.execute_task(manifest, profile, **kwargs) is result
        assert observer.last_unsuccessful_attempt is None
    assert len(calls) == 1
    assert calls[0][0] is runner and calls[0][1] is manifest and calls[0][2] is profile
    assert calls[0][3] == kwargs and calls[0][3]["cancel_event"] is cancel
    assert observer.last_attempt["requested_timeout_ms"] == 29500
    assert observer.last_attempt["profile_timeout_ms"] == 35000
    assert observer.last_attempt["transport_timeout_ms"] == 35000
    assert PRIVATE not in json.dumps(observer.last_attempt)
    assert not destination.exists()


def test_successful_cleanup_does_not_hide_prior_failed_attempt_or_persisted_step(tmp_path):
    observer = diagnostic()
    observer.phase = "baseline"
    manifest, profile = inputs()
    store = RunStore(tmp_path / "runs")
    run_id = store._new_run_id()
    manifest["run_id"] = run_id
    observe(observer.begin, manifest, profile, 35.0)
    observe(
        observer.finish,
        {"status": "failed", "error": {"code": "fixture_write_failed", "message": PRIVATE}},
        None,
    )
    observe(
        observer.begin,
        {**manifest, "step_id": "cleanup_workspace", "action_id": "sandbox.cleanup.v1"},
        profile,
        35.0,
    )
    observe(observer.finish, {"status": "success", "output": PRIVATE}, None)
    path = store.root / run_id
    path.mkdir()
    document = {
        "steps": [
            {
                "step_id": "create_fixture",
                "action_id": ACTION,
                "status": "failed",
                "runner_status": "failed",
                "error": {"code": "runner_transport_failed", "message": PRIVATE},
            },
            {
                "step_id": "cleanup_workspace",
                "action_id": "sandbox.cleanup.v1",
                "status": "success",
                "runner_status": "success",
            },
        ],
        "output": PRIVATE,
        "credential_reference": PRIVATE,
    }
    result_path = path / "result.json"
    original = json.dumps(document).encode()
    result_path.write_bytes(original)
    observe(observer.capture_steps, store)
    assert result_path.read_bytes() == original
    assert observer.steps["completed_step_count"] == 2
    assert observer.steps["last_step"]["step_id"] == "cleanup_workspace"
    assert observer.steps["last_unsuccessful_step"]["step_id"] == "create_fixture"
    assert observer.last_attempt["step_id"] == "cleanup_workspace"
    assert observer.last_unsuccessful_attempt["error_code"] == "fixture_write_failed"
    failure = ValueError(PRIVATE)
    observer.cleanup_failed("runtime_close_remove", OSError(PRIVATE))
    observer.attach(failure, tmp_path, _write_json)
    report = json.loads((tmp_path / FAILURE_REPORT).read_bytes())
    assert report["passed"] is False and report["diagnostic_only"] is True
    assert report["cleanup_failures"] == [
        {"stage": "runtime_close_remove", "exception_type": "OSError"}
    ]
    assert report["last_unsuccessful_attempt"]["runner_status"] == "failed"
    assert FAILURE_REPORT not in REPORT_PATHS
    assert PRIVATE not in json.dumps(report) and PRIVATE not in notes(failure)
    assert len(notes(failure)) < 4200


def test_unknown_values_and_diagnostic_io_never_disclose_or_replace_failure(tmp_path):
    observer = diagnostic()
    manifest, profile = inputs()
    observe(
        observer.begin,
        {**manifest, "step_id": PRIVATE, "action_id": PRIVATE, "runner_profile_id": PRIVATE},
        profile,
        35.0,
    )
    observe(
        observer.finish, {"status": PRIVATE, "error": {"code": PRIVATE, "message": PRIVATE}}, None
    )
    cause = RuntimeError(PRIVATE)
    original = ValueError(PRIVATE)
    original.__cause__ = cause
    calls = []

    def failed_write(path, report):
        calls.append(report)
        raise OSError(PRIVATE)

    observer.attach(original, tmp_path, failed_write)
    assert original.__cause__ is cause and len(calls) == 1
    assert PRIVATE not in json.dumps(calls) and PRIVATE not in notes(original)
    assert calls[0]["last_attempt"]["step_id"] is None
    assert calls[0]["last_attempt"]["error_code"] == "other_error"
    assert not (tmp_path / FAILURE_REPORT).exists()


def test_observation_error_does_not_mask_delegate_failure(monkeypatch):
    observer = diagnostic()
    runner = observed_runner(observer)
    original = ValueError(PRIVATE)

    def fail(*args, **kwargs):
        raise original

    monkeypatch.setattr(observer, "begin", fail)
    monkeypatch.setattr(observer, "finish", fail)
    monkeypatch.setattr(SubprocessRustRunner, "execute_task", fail)
    with pytest.raises(ValueError) as caught:
        runner.execute_task(
            *inputs(), task_id="test", cancel_event=threading.Event(), durable_result_path="unused"
        )
    assert caught.value is original


@pytest.mark.parametrize("mode", ["oversized", "malformed", "too_many_steps", "too_many_runs"])
def test_partial_readback_is_bounded_and_explicitly_unavailable(tmp_path, mode):
    observer = diagnostic()
    store = RunStore(tmp_path / "runs")
    paths = []
    for _ in range(3 if mode == "too_many_runs" else 1):
        path = store.root / store._new_run_id()
        path.mkdir()
        paths.append(path / "result.json")
    data = b"x" * (1024 * 1024 + 1) if mode == "oversized" else b"invalid"
    if mode == "too_many_steps":
        data = json.dumps({"steps": [{}] * 257}).encode()
    for path in paths:
        path.write_bytes(data)
    observe(observer.capture_steps, store)
    assert observer.steps == {"readback": "unavailable"}
    assert all(path.read_bytes() == data for path in paths)


def test_failure_report_is_exclusive_and_cleanup_diagnostics_are_bounded(tmp_path):
    observer = diagnostic()
    existing = tmp_path / FAILURE_REPORT
    existing.write_bytes(b"original failure report")
    for _ in range(12):
        observer.cleanup_failed("receiver_stop", OSError(PRIVATE))
    failure = ValueError(PRIVATE)
    observer.attach(failure, tmp_path, _write_json)
    assert existing.read_bytes() == b"original failure report"
    assert observer.cleanup_failure_count == 12 and len(observer.cleanup_failures) == 8
    assert len(notes(failure)) < 4200


def test_readback_selects_known_transport_run_not_random_suffix_order(tmp_path):
    observer = diagnostic()
    store = RunStore(tmp_path / "runs")
    run_ids = ["run-20260912T120000Z-" + suffix * 16 for suffix in ("0", "f")]
    for run_id in run_ids:
        path = store.root / run_id
        path.mkdir()
        (path / "result.json").write_text(
            json.dumps({"steps": [] if run_id == run_ids[0] else [{}]})
        )
    observer._run_id = run_ids[0]
    observe(observer.capture_steps, store)
    assert observer.steps["selection"] == "known_transport_run"
    assert observer.steps["completed_step_count"] == 0
    observer._run_id = None
    observe(observer.capture_steps, store)
    assert observer.steps == {"readback": "unavailable"}
