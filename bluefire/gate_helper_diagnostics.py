"""Content-free diagnostics for bounded acceptance helper processes.

Only fixed classifications, sizes and hashes leave the temporary output directory.
Helper output and exception messages may contain credentials or host paths and are
never copied into these diagnostic records.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from .gate_private_diagnostics import retain_private_output

DIAGNOSTIC_SCHEMA = "bluefire.gate-helper-diagnostic.v1"
JOURNEY_SCHEMA = "bluefire.gate-helper-failure.v1"
_MAX_OUTPUT = 8192
_STAGES = {
    "run_linux_journey": "linux_execution",
    "create_disposable_wsl_distribution": "linux_clone",
    "_stream_clone": "linux_clone",
    "_close_runtime": "runtime_cleanup",
    "_start_receiver": "receiver_start",
    "_receiver_report": "receiver_observation",
    "transport_recovery": "transport_recovery",
    "process_tree_cancellation": "process_tree_cancellation",
    "_execute_cancellation_task": "process_tree_cancellation",
    "macos_report": "macos_contract",
    "platform_readiness_report": "platform_readiness",
    "run_cross_platform_gate_journey": "report_validation",
    "produce_cross_platform_evidence": "evidence_production",
}
_FAILURES = frozenset(
    {
        "runner_deadline",
        "readiness_timeout",
        "timeout",
        "io_failure",
        "validation_failure",
        "runtime_failure",
        "unexpected_failure",
    }
)


class GateHelperFailure(ValueError):
    """A fixed diagnostic classification; never carries helper output."""


def protocol_failure_classification(summary: Any, exit_code: int, passed: bool) -> str | None:
    if passed:
        return None
    if isinstance(summary, Mapping) and summary.get("status") == "failed":
        return "helper_reported_failure"
    return "nonzero_exit" if exit_code != 0 else "unexpected_protocol"


def _exception_projection(exc: BaseException) -> dict[str, str]:
    """Project a known stage and failure kind, without traceback paths or messages."""
    stage = "evidence_production"
    trace = exc.__traceback__
    while trace is not None:
        stage = _STAGES.get(trace.tb_frame.f_code.co_name, stage)
        if trace.tb_frame.f_globals.get(
            "__name__"
        ) == "bluefire.cross_platform_linux_distribution" and trace.tb_frame.f_code.co_name in {
            "cleanup",
            "probe_distribution_absence",
            "_remove_empty_storage",
        }:
            stage = "linux_cleanup"
        trace = trace.tb_next
    if str(exc) == "Runner watchdog exceeded its terminal deadline":
        classification = "runner_deadline"
    elif str(exc) == "the packaged Rust cancellation witness never started":
        classification = "readiness_timeout"
    elif isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        classification = "timeout"
    elif isinstance(exc, OSError):
        classification = "io_failure"
    elif isinstance(exc, (ValueError, TypeError)):
        classification = "validation_failure"
    elif isinstance(exc, RuntimeError):
        classification = "runtime_failure"
    else:
        classification = "unexpected_failure"
    return {"stage": stage, "classification": classification}


def exception_diagnostic(exc: BaseException) -> Mapping[str, str]:
    diagnostic = {"schema_version": JOURNEY_SCHEMA, **_exception_projection(exc)}
    previous = exc.__cause__ or exc.__context__
    if previous is not None and previous is not exc:
        diagnostic.update(
            {"previous_" + key: value for key, value in _exception_projection(previous).items()}
        )
    return diagnostic


def output_diagnostic(payload: bytes, *, size: int | None = None) -> Mapping[str, Any]:
    return {
        "size_bytes": len(payload) if size is None else size,
        "captured_bytes": len(payload),
        "captured_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def json_classification(payload: bytes) -> tuple[str, Any]:
    if not payload.strip():
        return "empty_output", None
    try:
        value = payload.decode("utf-8")
    except UnicodeError:
        return "invalid_utf8", None

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    def invalid_constant(_value: str) -> Any:
        raise ValueError("nonfinite JSON number")

    try:
        parsed = json.loads(value, object_pairs_hook=strict_object, parse_constant=invalid_constant)
    except (ValueError, RecursionError):
        return "invalid_json", None
    return ("json_object" if isinstance(parsed, dict) else "non_object_json"), parsed


def _read_output(path: Path) -> tuple[bytes, int | None]:
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
            return b"", None
        with path.open("rb") as stream:
            return stream.read(_MAX_OUTPUT + 1), details.st_size
    except OSError:
        return b"", None


def record_helper_outcome(
    path: Path | None,
    *,
    stdout_path: Path,
    stderr_path: Path,
    exit_code: int | None,
    failure_reason: str | None,
    timeout_seconds: int,
    expected_schema: str | None,
    expected_reports: Sequence[str] | None,
    repository: Path,
    evidence_dir: Path,
    command: Sequence[str],
) -> tuple[str, bytes]:
    """Retain bounded output fingerprints and classify before scratch cleanup."""
    stdout, stdout_size = _read_output(stdout_path)
    stderr, stderr_size = _read_output(stderr_path)
    process = "completed" if exit_code == 0 else "nonzero_exit"
    # Only match prefixes produced by _execute_workflow; never publish its text.
    if failure_reason and failure_reason.startswith("workflow exceeded its "):
        process = "timeout"
    elif failure_reason and failure_reason.startswith("workflow could not start:"):
        process = "launch_failure"
    elif failure_reason == "helper process I/O failed":
        process = "process_io_failure"
    elif failure_reason and not failure_reason.startswith("workflow exited with code "):
        process = "containment_failure"
    elif exit_code is None:
        process = "launch_failure"
    output, summary = json_classification(stdout)
    if stdout_size is None or stderr_size is None:
        output = "output_unavailable"
    elif max(stdout_size, stderr_size) > _MAX_OUTPUT:
        output = "output_bound_exceeded"
    elif isinstance(summary, dict):
        if expected_schema is not None and summary.get("schema_version") != expected_schema:
            output = "wrong_schema"
        elif summary.get("status") == "failed" and "reports" not in summary:
            output = "helper_reported_failure"
        elif expected_reports is not None and summary.get("reports") != list(expected_reports):
            output = "wrong_report_selection"
        elif summary.get("status") == "failed":
            output = "helper_reported_failure"
    diagnostic: dict[str, Any] = {
        "schema_version": DIAGNOSTIC_SCHEMA,
        "process": process,
        "output": output,
        "exit_code": exit_code,
        "timeout_seconds": timeout_seconds,
        "stdout": {**output_diagnostic(stdout), "size_bytes": stdout_size},
        "stderr": {**output_diagnostic(stderr), "size_bytes": stderr_size},
    }
    diagnostic["private_capture"] = retain_private_output(
        repository=repository,
        evidence_dir=evidence_dir,
        stdout=stdout,
        stderr=stderr,
        source={
            "kind": "helper_process",
            "command": list(command),
            "stdout_source": str(stdout_path),
            "stderr_source": str(stderr_path),
            "exit_code": exit_code,
            "timeout_seconds": timeout_seconds,
            "process": process,
            "output": output,
            "stdout_total_bytes": stdout_size,
            "stderr_total_bytes": stderr_size,
        },
    )
    if isinstance(summary, dict) and summary.get("error_code") in (
        "deep_behavior_journey_unproven",
        "deep_behavior_journey_internal_failure",
        "operator_ui_journey_unproven",
        "operator_ui_journey_internal_failure",
    ):
        diagnostic["helper_error_code"] = summary["error_code"]
    _, journey = json_classification(stderr)
    if (
        isinstance(journey, dict)
        and (set(journey) - {"private_exception_capture"})
        in (
            {"schema_version", "stage", "classification"},
            {
                "schema_version",
                "stage",
                "classification",
                "previous_stage",
                "previous_classification",
            },
        )
        and journey.get("schema_version") == JOURNEY_SCHEMA
        and (
            "private_exception_capture" not in journey
            or journey["private_exception_capture"] in ("retained", "unavailable")
        )
        and isinstance(journey.get("stage"), str)
        and journey.get("stage") in {*_STAGES.values(), "linux_cleanup"}
        and isinstance(journey.get("classification"), str)
        and journey.get("classification") in _FAILURES
        and (
            "previous_stage" not in journey
            or (
                isinstance(journey["previous_stage"], str)
                and journey["previous_stage"] in {*_STAGES.values(), "linux_cleanup"}
            )
        )
        and (
            "previous_classification" not in journey
            or (
                isinstance(journey["previous_classification"], str)
                and journey["previous_classification"] in _FAILURES
            )
        )
    ):
        diagnostic["journey"] = journey
    if path is not None:
        # O_EXCL refuses stale files and symlinks rather than replacing evidence.
        descriptor = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(diagnostic, stream, sort_keys=True)
            stream.write("\n")
    classification = output if output != "json_object" else process
    if process not in {"completed", "nonzero_exit"}:
        classification = process
    return classification, stdout


def helper_failure_detail(exc: BaseException) -> str:
    if isinstance(exc, GateHelperFailure):
        return str(exc)
    if isinstance(exc, UnicodeError):
        return "invalid_utf8"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json"
    if isinstance(exc, OSError):
        return "helper_io_failure"
    return "helper_validation_failure"
