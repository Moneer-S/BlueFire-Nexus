"""Actual wait traceback with authored status only; no subprocess or filesystem effects."""

import json
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests_platform import test_runner_cancellation as target

SENSITIVE = "private-credential-environment-task-path"
PREFIX = "Runner watchdog failure evidence: "


def actual_failure(monkeypatch, *, state="failed", code="runner_failure", exit_code=22, depth=0):
    reads = []
    status = {
        "schema_version": target.runner_client_module._WATCHDOG_STATUS_SCHEMA,
        "task_id": SENSITIVE,
        "state": state,
        "error_code": code,
        "private": {"credential": SENSITIVE},
    }

    class Pinned:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _name, *, maximum):
            assert maximum == 4096
            reads.append("existing_status_read")
            return json.dumps(status).encode()

    monkeypatch.setattr(target.runner_client_module, "_PinnedPrivateDirectory", Pinned)
    runner = target.SubprocessRustRunner.__new__(target.SubprocessRustRunner)
    runner.timeout_seconds = 1
    runner._process_exited_without_reap = lambda _process: True
    runner._finish_posix_process_group = lambda _process: True
    runner._windows_containment = SimpleNamespace(finish=lambda _process: True)
    runner._durable_results = SimpleNamespace(exists=lambda _path: False)
    process = subprocess.Popen.__new__(subprocess.Popen)
    process._child_created = False
    process.returncode = exit_code
    destination = (Path(SENSITIVE) / "result.json").absolute()
    pending = (Path(SENSITIVE) / "pending.json").absolute()
    assert destination.is_absolute() and pending.is_absolute()

    def descend(remaining):
        if remaining:
            return descend(remaining - 1)
        return runner._await_watchdog(
            process,
            manifest={"credential": SENSITIVE},
            profile={"credential": SENSITIVE},
            task_id=SENSITIVE,
            destination=destination,
            pending=pending,
            cancel_event=threading.Event(),
        )

    try:
        descend(depth)
    except target.RunnerTransportError as error:
        assert str(error) == "Runner watchdog failed before publishing a valid result"
        error.args = (SENSITIVE,)
        original = error
    else:
        pytest.fail("authored terminal failure must raise")
    assert reads == ["existing_status_read"]
    monkeypatch.setattr(
        target.runner_client_module,
        "_PinnedPrivateDirectory",
        lambda *_args, **_kwargs: pytest.fail("diagnostics must not read status again"),
    )
    process.poll = lambda: pytest.fail("diagnostics must not poll or reap")
    process.wait = lambda **_kwargs: pytest.fail("diagnostics must not wait or reap")
    return original


@pytest.mark.parametrize(
    "state,code,exit_code,expected",
    [
        (
            "failed",
            "runner_failure",
            22,
            {"state": "failed", "error_code": "runner_failure", "exit_category": "failed"},
        ),
        (
            "failed",
            "runner_identity_changed",
            22,
            {"state": "failed", "error_code": "runner_identity_changed", "exit_category": "failed"},
        ),
        (
            SENSITIVE,
            SENSITIVE,
            123456,
            {"state": "unknown", "error_code": "unknown", "exit_category": "other"},
        ),
        (
            {"credential": SENSITIVE},
            [SENSITIVE],
            True,
            {"state": "unknown", "error_code": "unknown", "exit_category": "unavailable"},
        ),
    ],
)
def test_actual_wait_snapshot_emits_only_finite_labels(
    monkeypatch, capsys, state, code, exit_code, expected
):
    error = actual_failure(monkeypatch, state=state, code=code, exit_code=exit_code)
    target._watchdog_failure_evidence(error)
    captured = capsys.readouterr()
    assert captured.err == "" and SENSITIVE not in captured.out
    assert "result.json" not in captured.out and "pending.json" not in captured.out
    assert len(captured.out.encode()) < 512
    assert json.loads(captured.out.removeprefix(PREFIX)) == {
        "wait_frame_found": True,
        "status_available": True,
        **expected,
    }


@pytest.mark.parametrize("mode", ["deep", "same_name"])
def test_traceback_scan_is_bounded_and_requires_the_exact_wait_code(monkeypatch, capsys, mode):
    if mode == "deep":
        error = actual_failure(monkeypatch, depth=40)
    else:

        def _await_watchdog():
            status = {"state": "failed", "error_code": "runner_failure", "private": SENSITIVE}
            raise target.RunnerTransportError(status)

        try:
            _await_watchdog()
        except target.RunnerTransportError as caught:
            error = caught
    target._watchdog_failure_evidence(error)
    captured = capsys.readouterr()
    assert SENSITIVE not in captured.out and captured.err == ""
    assert json.loads(captured.out.removeprefix(PREFIX)) == {
        "wait_frame_found": False,
        "status_available": False,
    }


@pytest.mark.parametrize("output_fails", [False, True])
def test_representative_failure_keeps_original_exception_and_completed_cleanup(
    monkeypatch, tmp_path, capsys, output_fails
):
    original = actual_failure(monkeypatch)
    order = []

    def execute_task(manifest, profile, **kwargs):
        assert manifest == target._manifest() and profile == {}
        assert kwargs["task_id"] == "task-success-01"
        assert isinstance(kwargs["cancel_event"], threading.Event)
        assert (
            kwargs["durable_result_path"] == (tmp_path / "durable" / "task-result.json").resolve()
        )
        try:
            raise original
        finally:
            order.append("existing_cleanup")

    monkeypatch.setattr(target, "_runner", lambda _path: SimpleNamespace(execute_task=execute_task))
    report = target._watchdog_failure_evidence

    def evidence(error):
        order.append("diagnostic")
        report(error)

    monkeypatch.setattr(target, "_watchdog_failure_evidence", evidence)
    if output_fails:

        def refused_output(*_args, **_kwargs):
            raise RuntimeError(SENSITIVE)

        monkeypatch.setattr(target, "print", refused_output, raising=False)
    with pytest.raises(target.RunnerTransportError) as caught:
        target.test_execute_task_promotes_complete_stdout_and_preserves_execute_contract(tmp_path)
    assert caught.value is original
    assert order == ["existing_cleanup", "diagnostic"]
    captured = capsys.readouterr()
    assert SENSITIVE not in captured.out and str(tmp_path) not in captured.out
    assert captured.err == ""
    if output_fails:
        assert captured.out == ""
    else:
        assert json.loads(captured.out.removeprefix(PREFIX))["error_code"] == "runner_failure"
