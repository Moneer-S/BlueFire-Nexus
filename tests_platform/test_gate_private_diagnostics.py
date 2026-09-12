from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bluefire import defense_frontier_gate, operator_ui_gate, product_acceptance_process
from bluefire.gate_helper_diagnostics import GateHelperFailure
from bluefire.gate_private_diagnostics import PRIVATE_DIAGNOSTICS_ENV, private_capture_root
from bluefire.product_acceptance_process import WorkflowOutcome
from tools import run_cross_platform_gate_journey as cross_helper


@pytest.fixture
def private_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    evidence = tmp_path / "acceptance" / "gate-11"
    private = tmp_path / "private"
    for path in (repository, evidence, private):
        path.mkdir(parents=True)
    monkeypatch.setenv(PRIVATE_DIAGNOSTICS_ENV, str(private))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    return repository, evidence, private


def test_original_invalid_output_survives_outside_public_bundle(
    private_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, private = private_case
    stdout = b'Unexpected text before {"truncated":'
    stderr = b"secret=not-public-example-value C:\\private\\operator-data\n" + b"x" * 9000

    def execute(_command: Any, **kwargs: Any) -> WorkflowOutcome:
        kwargs["stdout_path"].write_bytes(stdout)
        kwargs["stderr_path"].write_bytes(stderr)
        return WorkflowOutcome(1, "workflow exited with code 1")

    monkeypatch.setattr(defense_frontier_gate, "_execute_workflow", execute)
    diagnostic = evidence / "helper-process-diagnostic.json"
    with pytest.raises(GateHelperFailure, match="output_bound_exceeded"):
        defense_frontier_gate._run_bounded_helper_process(
            ["fixed-interpreter", "fixed-helper"],
            repository=repository,
            environment={"TMP": str(evidence)},
            timeout_seconds=17,
            diagnostic_path=diagnostic,
            expected_schema="expected",
        )
    public = diagnostic.read_text(encoding="utf-8")
    report = json.loads(public)
    capture = private / report["private_capture"]["capture_id"]
    assert capture.parent == private
    assert (capture / "stdout.bin").read_bytes() == stdout
    assert (capture / "stderr.bin").read_bytes() == stderr[:8192]
    source = json.loads((capture / "source.json").read_text())
    assert source["source"]["command"] == ["fixed-interpreter", "fixed-helper"]
    assert source["source"]["exit_code"] == 1
    assert source["source"]["stderr_total_bytes"] == len(stderr)
    assert source["stderr_truncated"] is True
    assert source["stderr_bytes"] == 8192
    assert "not-public" not in public and str(private) not in public
    assert "Unexpected text" not in public


@pytest.mark.parametrize("location", ["source", "bundle", "nonempty"])
def test_private_capture_refuses_source_bundle_and_unowned_directory(
    private_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    repository, evidence, private = private_case
    target = {"source": repository, "bundle": evidence, "nonempty": private}[location]
    if location == "nonempty":
        (private / "existing-user-file").write_text("preserve", encoding="utf-8")
    monkeypatch.setenv(PRIVATE_DIAGNOSTICS_ENV, str(target))
    with pytest.raises(ValueError):
        private_capture_root(repository, evidence)
    assert not (target / ".bluefire-private-diagnostics.json").exists()


def test_capture_option_is_explicit_and_refused_in_ci(
    private_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, private = private_case
    assert product_acceptance_process._workflow_environment()[PRIVATE_DIAGNOSTICS_ENV] == str(
        private
    )
    monkeypatch.setenv("CI", "true")
    with pytest.raises(ValueError, match="CI"):
        product_acceptance_process._workflow_environment()
    with pytest.raises(ValueError, match="CI"):
        private_capture_root(repository, evidence)
    assert not tuple(private.iterdir())


def test_cross_platform_original_exception_is_retained_only_privately(
    private_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, evidence, private = private_case

    def failure(*_args: Any) -> Any:
        raise RuntimeError("original-failure secret=not-public-example-value")

    monkeypatch.setattr(cross_helper, "run_cross_platform_gate_journey", failure)
    assert (
        cross_helper.main(["--repository", str(repository), "--evidence-dir", str(evidence)]) == 1
    )
    public = capsys.readouterr()
    assert "not-public" not in public.out + public.err
    captures = list(private.glob("capture-*/stderr.bin"))
    assert len(captures) == 1
    assert b"original-failure secret=not-public-example-value" in captures[0].read_bytes()


def test_frontend_timeout_preserves_partial_output_before_tempfiles_close(
    private_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, private = private_case
    frontend = repository / "frontend"
    frontend.mkdir()

    def timeout(_command: Any, **kwargs: Any) -> Any:
        kwargs["stdout"].write(b"partial unit output")
        kwargs["stderr"].write(b"private unit diagnostic")
        raise subprocess.TimeoutExpired("private command", 17)

    monkeypatch.setattr(operator_ui_gate.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        operator_ui_gate._run_node_command(
            repository / "node",
            frontend / "vitest.mjs",
            (),
            frontend=frontend,
            environment={},
            timeout_seconds=17,
            evidence_dir=evidence,
        )
    captures = list(private.glob("capture-*/source.json"))
    assert len(captures) == 1
    source = json.loads(captures[0].read_text())
    assert source["source"]["classification"] == "timeout"
    assert source["source"]["exit_code"] is None
    assert (captures[0].parent / "stdout.bin").read_bytes() == b"partial unit output"
