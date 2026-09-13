from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from bluefire import gate_frontend_report, operator_ui_gate
from bluefire.gate_frontend_report import vitest_inventory
from bluefire.runner_transport_errors import RunnerTransportError


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


def test_failed_unit_messages_are_retained_in_complete_bounded_private_parts(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, test = frontend_case
    payload = json.loads(_report(test, ["passed", "failed"]))
    failed = payload["testResults"][0]["assertionResults"][1]
    failed["failureMessages"] = ["first failure detail " * 800, "last failure detail"]
    failed["duration"] = 5012.5
    original = json.dumps(payload).encode()
    captured: list[dict[str, Any]] = []

    def retain(**kwargs: Any) -> dict[str, Any]:
        captured.append(kwargs)
        return {"status": "retained", "capture_id": f"private-part-{len(captured)}"}

    monkeypatch.setattr(operator_ui_gate, "_run_node_command", _runner(original, 1))
    monkeypatch.setattr(
        operator_ui_gate, "retain_private_output", lambda **_: {"status": "not_configured"}
    )
    monkeypatch.setattr(gate_frontend_report, "private_capture_root", lambda *_: evidence)
    monkeypatch.setattr(gate_frontend_report, "retain_private_output", retain)
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False and report["failed_tests"] == [
        "example.test.ts::Example::case1"
    ]
    joined = b"".join(item["stdout"] for item in captured)
    assert len(captured) > 1
    assert all(len(item["stdout"]) <= 8192 and item["stderr"] == b"" for item in captured)
    assert json.loads(joined) == {
        "failures": [
            {
                "test_id": "example.test.ts::Example::case1",
                "duration_ms": 5012.5,
                "failure_messages": failed["failureMessages"],
            }
        ]
    }
    for index, item in enumerate(captured):
        assert item["source"]["part"] == index
        assert item["source"]["parts"] == len(captured)
        assert item["source"]["projection_sha256"] == "sha256:" + hashlib.sha256(joined).hexdigest()
        assert (
            item["source"]["original_stdout"]["captured_sha256"]
            == "sha256:" + hashlib.sha256(original).hexdigest()
        )
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert diagnostic["unit_failures"]["status"] == "retained"
    assert diagnostic["unit_failures"]["failure_count"] == 1
    for path in evidence.iterdir():
        assert "failure detail" not in path.read_text()


def test_private_failure_projection_refusal_preserves_observed_test_failure(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, test = frontend_case
    monkeypatch.setattr(
        operator_ui_gate, "_run_node_command", _runner(_report(test, ["failed"]), 1)
    )
    monkeypatch.setattr(
        operator_ui_gate, "retain_private_output", lambda **_: {"status": "not_configured"}
    )
    monkeypatch.setattr(gate_frontend_report, "private_capture_root", lambda *_: evidence)

    def refused(**_: Any) -> Any:
        raise OSError("private fixture path must not enter public evidence")

    monkeypatch.setattr(gate_frontend_report, "retain_private_output", refused)
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False and report["failed_tests"] == [
        "example.test.ts::Example::case0"
    ]
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert diagnostic["unit_failures"] == {
        "status": "retention_failed",
        "error_type": "OSError",
        "captures": [],
    }
    assert (
        diagnostic["classification"] == "frontend_failed" and diagnostic["inventory_known"] is True
    )
    assert "private fixture path" not in json.dumps(diagnostic)


def test_failure_projection_requires_opt_in_and_preserves_the_existing_output_bound(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, test = frontend_case
    payload = json.loads(_report(test, ["failed"]))
    monkeypatch.setattr(gate_frontend_report, "private_capture_root", lambda *_: None)
    assert gate_frontend_report.retain_vitest_failures(
        payload, frontend=repository / "frontend", evidence_dir=evidence, source={}
    ) == {"status": "not_configured"}
    monkeypatch.setattr(gate_frontend_report, "private_capture_root", lambda *_: evidence)
    payload["testResults"][0]["assertionResults"][0]["failureMessages"] = ["x" * (4 * 1024 * 1024)]
    assert gate_frontend_report.retain_vitest_failures(
        payload, frontend=repository / "frontend", evidence_dir=evidence, source={}
    ) == {"status": "projection_bound_exceeded", "failure_count": 1}


def test_private_projection_ownership_refusal_retains_prior_part_and_test_inventory(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, evidence, test = frontend_case
    payload = json.loads(_report(test, ["failed"]))
    payload["testResults"][0]["assertionResults"][0]["failureMessages"] = ["failure detail " * 800]
    monkeypatch.setattr(
        operator_ui_gate, "_run_node_command", _runner(json.dumps(payload).encode(), 1)
    )
    monkeypatch.setattr(
        operator_ui_gate, "retain_private_output", lambda **_: {"status": "not_configured"}
    )
    monkeypatch.setattr(gate_frontend_report, "private_capture_root", lambda *_: evidence)
    calls = 0

    def retain(**_: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RunnerTransportError("private ownership refusal must not enter public evidence")
        return {"status": "retained", "capture_id": "private-part-1"}

    monkeypatch.setattr(gate_frontend_report, "retain_private_output", retain)
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False and report["failed_tests"] == [
        "example.test.ts::Example::case0"
    ]
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert (
        diagnostic["classification"] == "frontend_failed" and diagnostic["inventory_known"] is True
    )
    assert diagnostic["unit_failures"] == {
        "status": "retention_failed",
        "error_type": "RunnerTransportError",
        "captures": [{"status": "retained", "capture_id": "private-part-1"}],
    }
    assert calls == 2 and "private ownership refusal" not in json.dumps(diagnostic)


@pytest.mark.parametrize("error_class", [OSError, RunnerTransportError])
def test_process_diagnostic_refusal_cannot_erase_completed_unit_inventory(
    frontend_case: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    error_class: type[Exception],
) -> None:
    repository, evidence, test = frontend_case
    monkeypatch.setattr(
        operator_ui_gate, "_run_node_command", _runner(_report(test, ["passed", "failed"]), 1)
    )

    def refused(**_: Any) -> Any:
        raise error_class("private capture refusal must not enter public evidence")

    monkeypatch.setattr(operator_ui_gate, "retain_private_output", refused)
    report = operator_ui_gate._run_frontend_suite(repository, evidence)
    assert report["passed"] is False and report["tests"] == 2
    assert report["passed_tests"] == ["example.test.ts::Example::case0"]
    assert report["failed_tests"] == ["example.test.ts::Example::case1"]
    diagnostic = json.loads((evidence / "gate08-frontend-diagnostic.json").read_text())
    assert (
        diagnostic["classification"] == "frontend_failed" and diagnostic["inventory_known"] is True
    )
    assert diagnostic["outputs"]["unit"]["private_capture"] == {
        "status": "retention_failed",
        "error_type": error_class.__name__,
    }
    assert "private capture refusal" not in json.dumps(diagnostic)
