from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from bluefire import operator_ui_gate
from bluefire.gate_frontend_report import vitest_inventory


@pytest.fixture
def frontend_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    frontend = repository / "frontend"
    for relative in ("typescript/bin/tsc", "eslint/bin/eslint.js", "vitest/vitest.mjs"):
        script = frontend / "node_modules" / relative
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("tool", encoding="utf-8")
    test = frontend / "example.test.ts"
    test.write_text("test", encoding="utf-8")
    node = tmp_path / "node.exe"
    node.write_text("tool", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(operator_ui_gate.shutil, "which", lambda _: str(node))
    monkeypatch.setattr(operator_ui_gate, "_runtime_temp_parent", lambda: runtime)
    return repository, evidence, test


def _report(test: Path, statuses: list[str]) -> bytes:
    return json.dumps(
        {
            "testResults": [
                {
                    "name": str(test),
                    "assertionResults": [
                        {
                            "status": status,
                            "title": f"case{index}",
                            "ancestorTitles": ["Example"],
                            "failureMessages": [
                                "secret=not-public-example-value C:\\private\\operator-data"
                            ],
                        }
                        for index, status in enumerate(statuses)
                    ],
                }
            ]
        }
    ).encode()


def _runner(payload: bytes, code: int) -> Callable[..., Any]:
    def run(_node: Path, script: Path, *_args: Any, **_kwargs: Any) -> Any:
        if script.name == "vitest.mjs":
            return SimpleNamespace(
                returncode=code, stdout=payload, stderr=b"secret=not-public-example-value"
            )
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    return run


def test_nonzero_unit_exit_retains_observed_pass_fail_skip_inventory(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, test = frontend_case
    monkeypatch.setattr(
        operator_ui_gate,
        "_run_node_command",
        _runner(_report(test, ["passed", "failed", "pending"]), 1),
    )
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False
    assert report["exit_codes"] == {"typecheck": 0, "lint": 0, "unit": 1}
    assert report["tests"] == 3
    assert report["passed_tests"] == ["example.test.ts::Example::case0"]
    assert report["failed_tests"] == ["example.test.ts::Example::case1"]
    assert report["skipped_tests"] == ["example.test.ts::Example::case2"]
    for path in evidence.iterdir():
        raw = path.read_text(encoding="utf-8")
        assert "not-public" not in raw and "operator-data" not in raw and str(repository) not in raw
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert diagnostic["inventory_known"] is True
    assert diagnostic["classification"] == "frontend_failed"


@pytest.mark.parametrize(
    ("payload", "classification"),
    [
        (b"", "empty_output"),
        (b'{"testResults":', "invalid_json"),
        (b"\xff", "invalid_utf8"),
        (b"[]", "non_object_json"),
    ],
)
def test_invalid_unit_report_keeps_exit_code_and_unknown_inventory(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    classification: str,
) -> None:
    repository, evidence, _ = frontend_case
    monkeypatch.setattr(operator_ui_gate, "_run_node_command", _runner(payload, 1))
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False
    assert report["exit_codes"] == {"typecheck": 0, "lint": 0, "unit": 1}
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert diagnostic["classification"] == classification
    assert diagnostic["inventory_known"] is False


def test_unit_timeout_keeps_prior_results_and_stage(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, _ = frontend_case

    def run(_node: Path, script: Path, *_args: Any, **_kwargs: Any) -> Any:
        if script.name == "vitest.mjs":
            raise subprocess.TimeoutExpired("private command", 300)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(operator_ui_gate, "_run_node_command", run)
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False
    assert report["exit_codes"] == {"typecheck": 0, "lint": 0, "unit": None}
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert diagnostic["stage"] == "unit" and diagnostic["classification"] == "timeout"


@pytest.mark.parametrize("status", ["failed", "pending"])
def test_zero_exit_does_not_approve_failed_or_skipped_assertions(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    repository, evidence, test = frontend_case
    monkeypatch.setattr(operator_ui_gate, "_run_node_command", _runner(_report(test, [status]), 0))
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False
    assert report["tests"] == 1


@pytest.mark.parametrize("title", ["secret=not-public-example-value", "C:\\private\\operator-data"])
def test_test_identity_cannot_smuggle_sensitive_output(
    frontend_case: tuple[Path, Path, Path],
    title: str,
) -> None:
    repository, _, test = frontend_case
    report = json.loads(_report(test, ["failed"]))
    report["testResults"][0]["assertionResults"][0]["title"] = title
    with pytest.raises(ValueError, match="unsafe"):
        vitest_inventory(report, repository / "frontend")
