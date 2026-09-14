from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_process_proof as process_proof_module
from bluefire.cross_platform_process_proof import ProcessProofError
from bluefire.runner_client import RunnerTaskCancelled


class _WaitingCancellationRunner:
    def __init__(self) -> None:
        self.execute_thread_id: int | None = None
        self.cancel_event: threading.Event | None = None

    def execute_task(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: Path,
    ) -> Mapping[str, Any]:
        del task_id, durable_result_path
        self.execute_thread_id = threading.get_ident()
        self.cancel_event = cancel_event
        deadline = time.monotonic() + 2.0
        while not cancel_event.is_set():
            if time.monotonic() >= deadline:
                raise AssertionError("the cancellation readiness poll did not signal the runner")
            time.sleep(0.001)
        raise RunnerTaskCancelled(
            "the test runner confirmed cancellation",
            cooperative_requested=True,
            cooperative_acknowledged=True,
            forced_tree_termination=True,
            control_cleanup_verified=True,
        )


class _EarlyFailureRunner:
    def __init__(self) -> None:
        self.cancel_event: threading.Event | None = None

    def execute_task(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: Path,
    ) -> Mapping[str, Any]:
        del task_id, durable_result_path
        self.cancel_event = cancel_event
        raise RuntimeError("synthetic execute failure")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessProofError(message)


def _ready_control(tmp_path: Path) -> Path:
    control = tmp_path / "control"
    control.mkdir()
    (control / "ready.json").write_bytes(b"{}\n")
    return control


def _install_ready_identity_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        process_proof_module,
        "_ready_record",
        lambda *_args, **_kwargs: {
            "parent_process_id": 101,
            "descendant_process_id": 202,
        },
    )
    monkeypatch.setattr(
        process_proof_module,
        "capture_process_identity",
        lambda process_id: {
            "process_id": process_id,
            "creation_time_100ns": process_id * 10,
        },
    )
    monkeypatch.setattr(process_proof_module, "process_identity_running", lambda _identity: True)


def _execute(
    runner: Any,
    control_root: Path,
    tmp_path: Path,
) -> tuple[RunnerTaskCancelled, Mapping[str, Any], Mapping[str, Any]]:
    return process_proof_module._execute_cancellation_task(
        runner,
        {"request_hash": "sha256:" + "a" * 64},
        {},
        task_id="execute-" + "a" * 64,
        request_hash="sha256:" + "a" * 64,
        control_root=control_root,
        durable_result_path=tmp_path / "durable" / "result.json",
        require=_require,
    )


def test_cancellation_launcher_and_readiness_poll_stay_on_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    control = _ready_control(tmp_path)
    _install_ready_identity_stubs(monkeypatch)
    runner = _WaitingCancellationRunner()
    caller_thread_id = threading.get_ident()

    cancellation, parent, descendant = _execute(runner, control, tmp_path)

    assert runner.execute_thread_id == caller_thread_id
    assert cancellation.cooperative_acknowledged is True
    assert parent == {"process_id": 101, "creation_time_100ns": 1010}
    assert descendant == {"process_id": 202, "creation_time_100ns": 2020}
    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


def test_early_execute_failure_signals_cancellation_without_a_worker(tmp_path: Path) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    runner = _EarlyFailureRunner()

    with pytest.raises(RuntimeError, match="synthetic execute failure"):
        _execute(runner, tmp_path / "absent-control", tmp_path)

    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


def test_readiness_poll_failure_cancels_runner_without_a_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    control = _ready_control(tmp_path)
    runner = _WaitingCancellationRunner()

    def fail_readiness(*_args: object, **_kwargs: object) -> Mapping[str, Any]:
        raise ProcessProofError("synthetic readiness failure")

    monkeypatch.setattr(process_proof_module, "_ready_record", fail_readiness)

    with pytest.raises(ProcessProofError, match="synthetic readiness failure"):
        _execute(runner, control, tmp_path)

    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


def test_missing_readiness_is_bounded_on_the_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    runner = _WaitingCancellationRunner()
    monkeypatch.setattr(process_proof_module, "_CANCELLATION_READY_TIMEOUT_SECONDS", 0.05)
    started = time.monotonic()

    with pytest.raises(ProcessProofError, match="never started"):
        _execute(runner, tmp_path / "absent-control", tmp_path)

    assert time.monotonic() - started < 1.0
    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before
