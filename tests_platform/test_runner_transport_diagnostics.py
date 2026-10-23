"""Finite transport diagnostics never change native execution or failure outcomes."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

import bluefire.runner_client as client
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_transport_errors import (
    TRANSPORT_FAILURE_REASONS,
    DiagnosedRunnerTransportError,
    RunnerTransportError,
    transport_failure_reason,
    watchdog_transport_failure_reason,
)
from bluefire.runner_watchdog import _classify_failure
from bluefire.runner_watchdog_status import validate_runner_watchdog_terminal_status


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("runner cancellation control contract is invalid", "cancellation_contract_invalid"),
        ("runner cancellation state is unavailable", "cancellation_state_unavailable"),
        ("private directory is unavailable or unsafe", "private_state_unavailable"),
        ("runner watchdog state is unavailable", "watchdog_state_unavailable"),
        ("Runner identity could not be verified.", "runner_identity_unavailable"),
        ("Runner identity changed before watchdog launch.", "runner_identity_changed"),
        ("Runner watchdog runtime is unavailable", "watchdog_runtime_unavailable"),
        ("Packaged runner watchdog is unavailable", "watchdog_script_unavailable"),
        ("Packaged runner watchdog identity changed", "watchdog_identity_changed"),
        ("verified launch input is unavailable", "launch_input_unavailable"),
        ("Windows process containment is unavailable", "windows_containment_unavailable"),
        ("Windows suspended process start failed", "windows_suspended_start_failed"),
        ("Windows process control is unavailable", "windows_process_control_unavailable"),
        ("Rust runner could not be started", "process_launch_failed"),
        ("Rust runner transport failed", "runner_io_failed"),
        ("runner durable result is unavailable", "durable_result_unavailable"),
        ("runner pending result is unavailable", "pending_result_unavailable"),
        ("runner durable result could not be committed", "durable_result_commit_failed"),
        ("Runner watchdog exited before readiness", "watchdog_exited_before_ready"),
        ("Runner watchdog readiness is invalid", "watchdog_readiness_invalid"),
        ("Runner watchdog readiness is unavailable", "watchdog_readiness_unavailable"),
        ("Runner watchdog did not become ready", "watchdog_readiness_timeout"),
        ("Runner watchdog exceeded its terminal deadline", "watchdog_terminal_timeout"),
        ("Rust runner exited with an unexpected status", "runner_unexpected_exit"),
        ("Runner process tree state could not be released", "process_tree_release_failed"),
        ("Runner process tree could not be stopped safely", "process_tree_stop_failed"),
        ("Rust runner transport timed out", "timed_out"),
        ("Rust runner exceeded the transport output limit", "output_limit"),
        ("runner returned an unsupported result schema", "unsupported_result_schema"),
        ("runner result is not valid UTF-8 JSON", "invalid_json"),
        ("runner returned a result that did not match its request", "invalid_result"),
    ],
)
def test_known_failure_reason_survives_watchdog_classification(message: str, reason: str) -> None:
    error = RunnerTransportError(message)
    assert transport_failure_reason(error) == reason
    assert _classify_failure(error) == reason
    assert watchdog_transport_failure_reason(_classify_failure(error)) == reason
    assert 1 <= len(reason) <= 64


@pytest.mark.parametrize(
    "message",
    [
        "PRIVATE_SYNTHETIC_SECRET_42",  # pragma: allowlist secret - synthetic sentinel
        r"C:\private\unreviewed-runtime\python.exe",
        "Windows process containment is unavailable C:\\private",
        "Windows process containment is unavailable\nPRIVATE_SYNTHETIC_SECRET_42",
        "windows process containment is unavailable",
        "runner result at a private path is missing",
        "unreviewed timed out message",
        "",
    ],
)
def test_unrecognized_messages_only_produce_finite_labels(message: str) -> None:
    error = RunnerTransportError(message)
    assert transport_failure_reason(error) == "other_transport"
    code = _classify_failure(error)
    assert code in TRANSPORT_FAILURE_REASONS | {"runner_failure"}
    reason = watchdog_transport_failure_reason(code)
    assert reason in TRANSPORT_FAILURE_REASONS
    assert "private" not in reason and "SECRET" not in reason


@pytest.mark.parametrize("reason", ["unknown", "C:\\private", "", None, [], {}])
def test_untrusted_diagnosed_reason_is_rechecked(reason: Any) -> None:
    error = DiagnosedRunnerTransportError("original failure", transport_failure_reason=reason)
    assert transport_failure_reason(error) == "other_transport"
    error.transport_failure_reason = reason
    assert transport_failure_reason(error) == "other_transport"
    assert str(error) == "original failure"


def _failed_status() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.runner-watchdog-status.v2",
        "task_id": "execute-" + "a" * 64,
        "state": "failed",
        "error_code": "windows_suspended_start_failed",
        "watchdog_pid": 123,
    }


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        ("windows_suspended_start_failed", "windows_suspended_start_failed"),
        ("windows_containment_unavailable", "windows_containment_unavailable"),
        ("start_timeout", "watchdog_start_timeout"),
        ("runner_identity_changed", "runner_identity_changed"),
        ("watchdog_failure", "watchdog_failure"),
        ("runner_failure", "other_transport"),
        ("unrecognized_failure", "other_transport"),
        ("PRIVATE_SYNTHETIC_SECRET_42", "other_transport"),
    ],
)
def test_failed_status_keeps_v2_shape_and_projects_only_finite_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str, reason: str
) -> None:
    status = _failed_status()
    status["error_code"] = code
    assert validate_runner_watchdog_terminal_status(status, task_id=status["task_id"]) == status
    error = _await_failed_status(tmp_path, monkeypatch, status)
    assert transport_failure_reason(error) == reason
    assert str(error) == "Runner watchdog failed before publishing a valid result"


@pytest.mark.parametrize("corruption", ["task", "pid", "pid_bool", "schema", "extra", "missing"])
def test_unbound_or_malformed_failed_status_never_qualifies_reason_or_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    status = _failed_status()
    if corruption == "task":
        status["task_id"] = "execute-" + "b" * 64
    elif corruption == "pid":
        status["watchdog_pid"] = 456
    elif corruption == "pid_bool":
        status["watchdog_pid"] = True
    elif corruption == "schema":
        status["schema_version"] = "unknown"
    elif corruption == "extra":
        status["unreviewed"] = "PRIVATE_SYNTHETIC_SECRET_42"
    else:
        status.pop("watchdog_pid")
    error = _await_failed_status(tmp_path, monkeypatch, status, destination_present=True)
    assert transport_failure_reason(error) == "other_transport"


def _await_failed_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: dict[str, Any],
    *,
    destination_present: bool = False,
) -> RunnerTransportError:
    destination = tmp_path / "result.json"
    runner = object.__new__(SubprocessRustRunner)
    runner.timeout_seconds = 1
    runner._windows_containment = SimpleNamespace(finish=lambda _process: True)
    runner._process_exited_without_reap = lambda _process: True
    runner._finish_posix_process_group = lambda _process: True

    def unexpected_read(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("failed status must not produce a successful result")

    runner._durable_results = SimpleNamespace(
        exists=lambda path: destination_present and path == destination,
        read=unexpected_read,
    )

    @contextmanager
    def pinned(_path: Path) -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(read=lambda *_args, **_kwargs: json.dumps(status).encode())

    monkeypatch.setattr(client, "_PinnedPrivateDirectory", pinned)
    with pytest.raises(RunnerTransportError) as failure:
        runner._await_watchdog(
            SimpleNamespace(pid=123),
            manifest={},
            profile={},
            task_id="execute-" + "a" * 64,
            destination=destination,
            pending=tmp_path / "pending.json",
            cancel_event=threading.Event(),
        )
    return failure.value


def test_legacy_v1_failure_retains_existing_bound_durable_result_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = _failed_status()
    status["schema_version"] = "bluefire.runner-watchdog-status.v1"
    destination = tmp_path / "result.json"
    runner = object.__new__(SubprocessRustRunner)
    runner.timeout_seconds = 1
    runner.output_limit_bytes = 4096
    runner._process_exited_without_reap = lambda _process: True
    runner._finish_posix_process_group = lambda _process: True
    runner._windows_containment = SimpleNamespace(finish=lambda _process: True)
    result = {"status": "success", "source": "existing validated durable result"}
    reads = []

    def read(path: Path, *, maximum: int) -> bytes:
        assert path == destination and maximum == 4096
        reads.append(path)
        return b"existing-bound-result"

    runner._durable_results = SimpleNamespace(exists=lambda path: path == destination, read=read)

    def validate(payload: bytes, manifest: Any, profile: Any) -> dict[str, str]:
        assert payload == b"existing-bound-result" and manifest == {"own": 1} and profile == {}
        return result

    runner._validate_result = validate

    @contextmanager
    def pinned(_path: Path) -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(read=lambda *_args, **_kwargs: json.dumps(status).encode())

    monkeypatch.setattr(client, "_PinnedPrivateDirectory", pinned)
    assert (
        runner._await_watchdog(
            SimpleNamespace(pid=123),
            manifest={"own": 1},
            profile={},
            task_id=status["task_id"],
            destination=destination,
            pending=tmp_path / "pending.json",
            cancel_event=threading.Event(),
        )
        == result
    )
    assert reads == [destination]
