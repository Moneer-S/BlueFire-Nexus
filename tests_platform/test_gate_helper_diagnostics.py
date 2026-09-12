from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bluefire import defense_frontier_gate
from bluefire.gate_helper_diagnostics import JOURNEY_SCHEMA, GateHelperFailure, exception_diagnostic
from bluefire.product_acceptance_process import WorkflowOutcome
from tools import run_cross_platform_gate_journey as cross_helper


@pytest.mark.parametrize(
    ("stdout", "exit_code", "failure", "classification"),
    [
        (b"", 1, "workflow exited with code 1: private stderr", "empty_output"),
        (b"\xff", 1, "workflow exited with code 1: private stderr", "invalid_utf8"),
        (b'{"truncated":', 1, "workflow exited with code 1", "invalid_json"),
        (b"warning before JSON\n{}", 0, None, "invalid_json"),
        (b"[]", 0, None, "non_object_json"),
        (b'{"status":"passed","status":"failed"}', 0, None, "invalid_json"),
        (b'{"value":NaN}', 0, None, "invalid_json"),
        (b'{"schema_version":"other"}', 0, None, "wrong_schema"),
        (b'{"schema_version":"expected","reports":["other"]}', 0, None, "wrong_report_selection"),
        (b"x" * 8193, 1, "workflow exited with code 1", "output_bound_exceeded"),
        (b"{}", -1, "workflow exceeded its 17-second timeout", "timeout"),
        (
            b"{}",
            0,
            "workflow output streams did not close after termination",
            "containment_failure",
        ),
        (b"{}", None, None, "launch_failure"),
        (b"{}", None, "workflow could not start: private path", "launch_failure"),
        (b"{}", None, "helper process I/O failed", "process_io_failure"),
    ],
)
def test_shared_helper_preserves_content_free_failure_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    exit_code: int | None,
    failure: str | None,
    classification: str,
) -> None:
    private = b"secret=not-public-example-value C:\\private\\operator-data"

    def execute(_command: Any, **kwargs: Any) -> WorkflowOutcome:
        kwargs["stdout_path"].write_bytes(stdout)
        kwargs["stderr_path"].write_bytes(private)
        return WorkflowOutcome(exit_code, failure)

    monkeypatch.setattr(defense_frontier_gate, "_execute_workflow", execute)
    diagnostic_path = tmp_path / "diagnostic.json"
    with pytest.raises(GateHelperFailure, match=classification):
        defense_frontier_gate._run_bounded_helper_process(
            ["fixed-helper"],
            repository=tmp_path,
            environment={"TMP": str(tmp_path)},
            timeout_seconds=17,
            diagnostic_path=diagnostic_path,
            expected_schema="expected",
            expected_reports=["expected.json"],
        )
    raw = diagnostic_path.read_text(encoding="utf-8")
    diagnostic = json.loads(raw)
    assert diagnostic["exit_code"] == exit_code
    assert diagnostic["timeout_seconds"] == 17
    assert diagnostic["stdout"]["size_bytes"] == len(stdout)
    assert diagnostic["stdout"]["captured_bytes"] <= 8193
    assert diagnostic["stderr"]["size_bytes"] == len(private)
    assert "operator-data" not in raw and "not-public" not in raw and str(tmp_path) not in raw
    assert classification in {diagnostic["process"], diagnostic["output"]}


def test_nonzero_valid_failure_keeps_protocol_and_safe_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = json.dumps({"schema_version": "expected", "status": "failed", "reports": []}).encode()
    stage = {
        "schema_version": JOURNEY_SCHEMA,
        "stage": "process_tree_cancellation",
        "classification": "runner_deadline",
    }

    def execute(_command: Any, **kwargs: Any) -> WorkflowOutcome:
        kwargs["stdout_path"].write_bytes(stdout)
        kwargs["stderr_path"].write_text(json.dumps(stage), encoding="utf-8")
        return WorkflowOutcome(1, "workflow exited with code 1: ignored text")

    monkeypatch.setattr(defense_frontier_gate, "_execute_workflow", execute)
    path = tmp_path / "diagnostic.json"
    code, output = defense_frontier_gate._run_bounded_helper_process(
        ["fixed-helper"],
        repository=tmp_path,
        environment={"TMP": str(tmp_path)},
        timeout_seconds=17,
        diagnostic_path=path,
        expected_schema="expected",
        expected_reports=[],
    )
    assert code == 1 and output == stdout
    diagnostic = json.loads(path.read_text(encoding="utf-8"))
    assert diagnostic["journey"] == stage
    assert diagnostic["output"] == "helper_reported_failure"
    with pytest.raises(FileExistsError):
        defense_frontier_gate._run_bounded_helper_process(
            ["fixed-helper"],
            repository=tmp_path,
            environment={"TMP": str(tmp_path)},
            timeout_seconds=17,
            diagnostic_path=path,
        )
    assert json.loads(path.read_text(encoding="utf-8")) == diagnostic


def test_cross_platform_helper_reports_stage_without_exception_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def process_tree_cancellation(*_args: Any) -> Any:
        raise RuntimeError("secret=not-public-example-value C:\\private\\failure")

    monkeypatch.setattr(cross_helper, "run_cross_platform_gate_journey", process_tree_cancellation)
    result = cross_helper.main(["--repository", str(tmp_path), "--evidence-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert result == 1
    assert json.loads(captured.out)["status"] == "failed"
    assert json.loads(captured.err) == {
        "schema_version": JOURNEY_SCHEMA,
        "stage": "process_tree_cancellation",
        "classification": "runtime_failure",
    }
    assert "private" not in captured.out + captured.err
    assert "not-public" not in captured.out + captured.err


def test_helper_caller_never_passes_for_nonzero_valid_protocol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def process(_command: Any, **_kwargs: Any) -> tuple[int, bytes]:
        return (
            1,
            json.dumps(
                {
                    "schema_version": defense_frontier_gate.HELPER_SCHEMA,
                    "status": "passed",
                    "reports": list(defense_frontier_gate.REPORT_PATHS),
                    "run_count": 3,
                }
            ).encode(),
        )

    monkeypatch.setattr(defense_frontier_gate, "_run_bounded_helper_process", process)
    report = defense_frontier_gate._run_helper(tmp_path, tmp_path)
    assert report["protocol_valid"] is True
    assert report["exit_code"] == 1
    assert report["passed"] is False
    assert report["failure_classification"] == "nonzero_exit"


def test_cleanup_exception_keeps_the_original_failed_stage() -> None:
    def process_tree_cancellation() -> None:
        raise RuntimeError("Runner watchdog exceeded its terminal deadline")

    def _close_runtime() -> None:
        raise OSError("private storage unavailable")

    try:
        try:
            process_tree_cancellation()
        finally:
            _close_runtime()
    except OSError as exc:
        diagnostic = exception_diagnostic(exc)
    assert diagnostic == {
        "schema_version": JOURNEY_SCHEMA,
        "stage": "runtime_cleanup",
        "classification": "io_failure",
        "previous_stage": "process_tree_cancellation",
        "previous_classification": "runner_deadline",
    }


def test_short_failure_summary_preserves_only_registered_error_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = json.dumps(
        {
            "schema_version": "expected",
            "status": "failed",
            "error_code": "deep_behavior_journey_unproven",
            "message": "private secret=not-public-example-value",
        }
    ).encode()

    def execute(_command: Any, **kwargs: Any) -> WorkflowOutcome:
        kwargs["stdout_path"].write_bytes(stdout)
        kwargs["stderr_path"].write_text(
            json.dumps(
                {
                    "schema_version": JOURNEY_SCHEMA,
                    "stage": ["private"],
                    "classification": "io_failure",
                }
            ),
            encoding="utf-8",
        )
        return WorkflowOutcome(1, "workflow exited with code 1")

    monkeypatch.setattr(defense_frontier_gate, "_execute_workflow", execute)
    path = tmp_path / "diagnostic.json"
    code, _ = defense_frontier_gate._run_bounded_helper_process(
        ["fixed-helper"],
        repository=tmp_path,
        environment={"TMP": str(tmp_path)},
        timeout_seconds=17,
        diagnostic_path=path,
        expected_schema="expected",
        expected_reports=["result.json"],
    )
    diagnostic = json.loads(path.read_text())
    assert code == 1
    assert diagnostic["output"] == "helper_reported_failure"
    assert diagnostic["helper_error_code"] == "deep_behavior_journey_unproven"
    assert "journey" not in diagnostic
    assert "not-public" not in path.read_text()
