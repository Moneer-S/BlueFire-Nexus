"""Fail-closed release workflow for GATE-08 operator UI."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .architecture_gate import _run_pytest_suite
from .defense_frontier import _runtime_temp_parent
from .defense_frontier_gate import (
    _configure_isolated_browser_environment,
    _isolated_python_environment,
    _run_bounded_helper_process,
)
from .operator_ui_gate_validation import (
    CHECK_NAMES,
    OperatorUIGateValidationError,
    validate_persisted_operator_ui_gate,
)
from .operator_ui_journey import (
    BROWSER_REPORT,
    HELPER_SCHEMA,
    JOURNEY_REPORT,
    PRODUCT_DB_ARTIFACT,
    REPORT_PATHS,
    SCREENSHOT_ARTIFACTS,
    _write_json,
)
from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .util import content_hash

VERIFICATION_REPORT = "gate08-verification-report.json"
FRONTEND_REPORT = "gate08-frontend-suite.json"
VERIFICATION_SCHEMA = "bluefire.operator-ui-gate-verification.v1"
FRONTEND_SCHEMA = "bluefire.operator-ui-frontend-suite.v1"
_MAX_FRONTEND_OUTPUT_BYTES = 4 * 1024 * 1024

_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
)
_CONTRACT_TESTS = ("tests_platform/test_operator_ui_gate.py",)
_EXPECTED_CONTRACT_TEST_COUNT = 16
_EXPECTED_CONTRACT_TESTS_SHA256 = (
    "sha256:6826aaac1461b350c67fb53612e40fa219ae80090a13c275e67403c0e5d1b898"
)
_EXPECTED_FRONTEND_TEST_COUNT = 101
_EXPECTED_FRONTEND_TESTS_SHA256 = (
    "sha256:7fa135e64e857710a0e385f01c661998e7ede42d4582ee5d437affcb579b5da5"
)

_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str]] = {
    "GATE-08-SCENARIO-AUTHORING": (
        "dynamic",
        "scenario_authoring",
        (BROWSER_REPORT, JOURNEY_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.authoring.production-roundtrip-version.v1",
    ),
    "GATE-08-GRAPH-EDITOR": (
        "dynamic",
        "graph_editor",
        (*SCREENSHOT_ARTIFACTS[:1], BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.graph.resizable-typed-history.v1",
    ),
    "GATE-08-LAYERS-BRANCHES-PARAMETERS": (
        "dynamic",
        "layers_branches_parameters",
        (*SCREENSHOT_ARTIFACTS[:1], BROWSER_REPORT, VERIFICATION_REPORT),
        "GATE-08.layers.environment-behavior-evidence.v1",
    ),
    "GATE-08-SAFETY-COLLECTORS-DETECTIONS": (
        "dynamic",
        "safety_collectors_detections",
        (BROWSER_REPORT, JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-08.safety.collector-detection-controls.v1",
    ),
    "GATE-08-AI-REPLAY-DIFF": (
        "dynamic",
        "ai_replay_diff",
        (*SCREENSHOT_ARTIFACTS[1:], BROWSER_REPORT, JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-08.diff.ai-proposal-replay-compare.v1",
    ),
    "GATE-08-ACCESSIBILITY-PALETTE": (
        "dynamic",
        "accessibility_palette",
        (*SCREENSHOT_ARTIFACTS[:1], BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.accessibility.keyboard-command-palette.v1",
    ),
    "GATE-08-MODE-AUTONOMY-PROVIDERS": (
        "dynamic",
        "mode_autonomy_providers",
        (BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.configuration.mode-autonomy-provider.v1",
    ),
    "GATE-08-RUNNER-PACK-MANAGEMENT": (
        "dynamic",
        "runner_pack_management",
        (BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.management.runner-profile-signed-pack.v1",
    ),
    "GATE-08-LIVE-WORKFLOW": (
        "dynamic",
        "live_workflow",
        (*SCREENSHOT_ARTIFACTS[1:], BROWSER_REPORT, JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-08.live.production-preflight-run-review.v1",
    ),
    "GATE-08-PROVENANCE-SETTINGS": (
        "dynamic",
        "provenance_settings",
        (BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.settings.strict-backend-effective.v1",
    ),
    "GATE-08-NO-RAW-SHELL-APPROVAL": (
        "structural",
        "no_raw_shell_approval",
        (FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.safety.human-first-no-shell.v1",
    ),
    "GATE-08-CANONICAL-REQUESTS": (
        "dynamic",
        "canonical_requests",
        (BROWSER_REPORT, FRONTEND_REPORT, VERIFICATION_REPORT),
        "GATE-08.requests.visible-controls-canonical.v1",
    ),
}


@dataclass(frozen=True)
class Gate08Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _run_helper(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        os.fspath(repository / "tools" / "run_operator_ui_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_operator_ui_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate08-helper-", dir=evidence_dir) as temporary:
            temporary_root = Path(temporary)
            environment = _isolated_python_environment(
                temporary_root,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            _configure_isolated_browser_environment(temporary_root, environment)
            node_raw = shutil.which("node")
            if node_raw is None:
                raise RuntimeError("the GATE-08 Node runtime is unavailable")
            node = Path(node_raw).resolve(strict=True)
            if not node.is_file():
                raise RuntimeError("the GATE-08 Node runtime is invalid")
            environment["BLUEFIRE_GATE_NODE"] = os.fspath(node)
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=420,
            )
            summary = json.loads(output.decode("utf-8"))
        protocol_valid = bool(
            isinstance(summary, Mapping)
            and set(summary)
            == {"schema_version", "status", "reports", "run_count", "blocking_check"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("reports") == list(REPORT_PATHS)
            and summary.get("run_count") == 4
            and summary.get("blocking_check") is None
        )
        return {
            "passed": returncode == 0 and protocol_valid,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": protocol_valid,
        }
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, TypeError, ValueError):
        return {
            "passed": False,
            "exit_code": None,
            "command": reported,
            "protocol_valid": False,
        }


def _frontend_environment(temporary_root: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(
            marker in key.upper()
            for marker in (
                "TOKEN",
                "SECRET",
                "PASSWORD",
                "CREDENTIAL",
                "API_KEY",
                "AUTHORIZATION",
                "COOKIE",
            )
        )
    }
    isolated_home = temporary_root / "home"
    local = isolated_home / "AppData" / "Local"
    roaming = isolated_home / "AppData" / "Roaming"
    local.mkdir(parents=True)
    roaming.mkdir(parents=True)
    environment.update(
        {
            "HOME": os.fspath(isolated_home),
            "USERPROFILE": os.fspath(isolated_home),
            "LOCALAPPDATA": os.fspath(local),
            "APPDATA": os.fspath(roaming),
            "TEMP": os.fspath(temporary_root),
            "TMP": os.fspath(temporary_root),
            "TMPDIR": os.fspath(temporary_root),
            "VITE_DEMO_MODE": "false",
            "NO_COLOR": "1",
        }
    )
    return environment


def _run_node_command(
    node: Path,
    script: Path,
    arguments: Sequence[str],
    *,
    frontend: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(node), os.fspath(script), *arguments]
    # File-backed output prevents a failed Node worker from retaining an
    # inherited pipe and hanging the gate after its bounded parent exits.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        completed = subprocess.run(
            command,
            cwd=frontend,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=timeout_seconds,
        )
        outputs: list[bytes] = []
        for stream in (stdout, stderr):
            stream.flush()
            stream.seek(0, os.SEEK_END)
            if stream.tell() > _MAX_FRONTEND_OUTPUT_BYTES:
                raise ValueError("frontend suite output exceeded its bound")
            stream.seek(0)
            outputs.append(stream.read(_MAX_FRONTEND_OUTPUT_BYTES + 1))
    return subprocess.CompletedProcess(
        command,
        completed.returncode,
        stdout=outputs[0],
        stderr=outputs[1],
    )


def _vitest_ids(value: Any, frontend: Path) -> list[str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("testResults"), list):
        raise ValueError("Vitest JSON report is invalid")
    test_ids: list[str] = []
    for result in value["testResults"]:
        if not isinstance(result, Mapping) or not isinstance(result.get("assertionResults"), list):
            raise ValueError("Vitest file result is invalid")
        raw_name = result.get("name")
        if not isinstance(raw_name, str):
            raise ValueError("Vitest file identity is invalid")
        path = Path(raw_name).resolve(strict=True)
        try:
            relative = path.relative_to(frontend).as_posix()
        except ValueError as exc:
            raise ValueError("Vitest result escaped the frontend root") from exc
        for assertion in result["assertionResults"]:
            if (
                not isinstance(assertion, Mapping)
                or assertion.get("status") != "passed"
                or not isinstance(assertion.get("title"), str)
                or not isinstance(assertion.get("ancestorTitles"), list)
                or not all(isinstance(item, str) for item in assertion["ancestorTitles"])
            ):
                raise ValueError("Vitest assertion did not pass exactly")
            parts = [relative, *assertion["ancestorTitles"], assertion["title"]]
            test_ids.append("::".join(parts))
    return sorted(test_ids)


def _run_frontend_suite(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    frontend = repository / "frontend"
    node_raw = shutil.which("node")
    if node_raw is None:
        return {"passed": False, "reason": "node_unavailable"}
    node = Path(node_raw).resolve(strict=True)
    scripts = {
        "typecheck": frontend / "node_modules" / "typescript" / "bin" / "tsc",
        "lint": frontend / "node_modules" / "eslint" / "bin" / "eslint.js",
        "unit": frontend / "node_modules" / "vitest" / "vitest.mjs",
    }
    if not node.is_file() or any(not path.is_file() for path in scripts.values()):
        return {"passed": False, "reason": "frontend_toolchain_unavailable"}
    reported = {
        "typecheck": ["{node}", "typescript/bin/tsc", "-b", "--pretty", "false"],
        "lint": ["{node}", "eslint/bin/eslint.js", ".", "--max-warnings", "0"],
        "unit": [
            "{node}",
            "vitest/vitest.mjs",
            "run",
            "--configLoader",
            "runner",
            "--reporter=json",
        ],
    }
    try:
        with tempfile.TemporaryDirectory(
            prefix=".gate08-frontend-", dir=_runtime_temp_parent()
        ) as raw:
            temporary = Path(raw)
            environment = _frontend_environment(temporary)
            typecheck = _run_node_command(
                node,
                scripts["typecheck"],
                ("-b", "--pretty", "false"),
                frontend=frontend,
                environment=environment,
                timeout_seconds=180,
            )
            lint = _run_node_command(
                node,
                scripts["lint"],
                (".", "--max-warnings", "0"),
                frontend=frontend,
                environment=environment,
                timeout_seconds=180,
            )
            unit = _run_node_command(
                node,
                scripts["unit"],
                ("run", "--configLoader", "runner", "--reporter=json"),
                frontend=frontend,
                environment=environment,
                timeout_seconds=300,
            )
            parsed = json.loads(unit.stdout.decode("utf-8")) if unit.returncode == 0 else None
            test_ids = _vitest_ids(parsed, frontend) if parsed is not None else []
        report = {
            "schema_version": FRONTEND_SCHEMA,
            "passed": typecheck.returncode == lint.returncode == unit.returncode == 0,
            "commands": reported,
            "exit_codes": {
                "typecheck": typecheck.returncode,
                "lint": lint.returncode,
                "unit": unit.returncode,
            },
            "tests": len(test_ids),
            "passed_tests": test_ids,
            "failed_tests": [],
            "skipped_tests": [],
        }
    except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError, ValueError):
        report = {
            "schema_version": FRONTEND_SCHEMA,
            "passed": False,
            "commands": reported,
            "exit_codes": {"typecheck": None, "lint": None, "unit": None},
            "tests": 0,
            "passed_tests": [],
            "failed_tests": ["frontend_suite_failed"],
            "skipped_tests": [],
        }
    _write_json(evidence_dir / FRONTEND_REPORT, report)
    return report


def _frontend_suite_is_exact(value: Any) -> bool:
    tests = value.get("passed_tests") if isinstance(value, Mapping) else None
    return bool(
        isinstance(value, Mapping)
        and set(value)
        == {
            "schema_version",
            "passed",
            "commands",
            "exit_codes",
            "tests",
            "passed_tests",
            "failed_tests",
            "skipped_tests",
        }
        and value.get("schema_version") == FRONTEND_SCHEMA
        and value.get("passed") is True
        and value.get("exit_codes") == {"typecheck": 0, "lint": 0, "unit": 0}
        and value.get("tests") == _EXPECTED_FRONTEND_TEST_COUNT
        and isinstance(tests, list)
        and tests == sorted(tests)
        and len(tests) == len(set(tests)) == _EXPECTED_FRONTEND_TEST_COUNT
        and content_hash(tests) == _EXPECTED_FRONTEND_TESTS_SHA256
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _suite_is_exact(value: Any) -> bool:
    passed = value.get("passed_tests") if isinstance(value, Mapping) else None
    return bool(
        isinstance(value, Mapping)
        and value.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and value.get("suite_id") == "operator-ui-contracts"
        and value.get("command")
        == [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *_CONTRACT_TESTS,
            "--junitxml={temporary}",
        ]
        and value.get("exit_code") == 0
        and value.get("passed") is True
        and value.get("tests") == _EXPECTED_CONTRACT_TEST_COUNT
        and isinstance(passed, list)
        and passed == sorted(passed)
        and len(passed) == len(set(passed)) == _EXPECTED_CONTRACT_TEST_COUNT
        and content_hash(passed) == _EXPECTED_CONTRACT_TESTS_SHA256
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _acceptance_binding() -> Mapping[str, str]:
    fields = (
        ("acceptance_id", "BLUEFIRE_ACCEPTANCE_ID"),
        ("gate_id", "BLUEFIRE_ACCEPTANCE_GATE_ID"),
        ("contract_sha256", "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256"),
        ("repository_commit", "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT"),
        ("repository_tree", "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE"),
        ("release", "BLUEFIRE_ACCEPTANCE_RELEASE"),
    )
    values: dict[str, str] = {}
    for field, name in fields:
        value = os.environ.get(name)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError(f"required acceptance binding {name} is unavailable")
        values[field] = value
    if values["gate_id"] != "GATE-08" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-08 acceptance binding is invalid")
    return acceptance_run_binding(**values)


def _proof(
    assertion_id: str,
    kind: str,
    test_id: str,
    artifacts: Sequence[str],
    bundles: Sequence[Mapping[str, str]],
) -> Mapping[str, Any]:
    return {
        "kind": kind,
        "status": "passed",
        "test_id": test_id,
        "assertion_ids": [assertion_id],
        "evidence_artifacts": list(artifacts),
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "run_bundles": [dict(bundle) for bundle in bundles],
        "environment_limitations": [],
    }


def _failure(issues: Sequence[object]) -> Gate08Outcome:
    absolute = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
    safe: list[str] = []
    for issue in issues:
        raw = str(issue)
        value = (
            "validation failure [private-path-redacted]"
            if absolute.search(raw)
            else " ".join(raw.split())
        )
        safe.append((value or "unknown validation failure")[:240])
    reason = "GATE-08 failed checks: " + ", ".join(dict.fromkeys(safe))
    return Gate08Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def run_gate_08(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate08Outcome:
    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected:
        return _failure(("locked GATE-08 assertion set mismatch",))
    owned = (
        *REPORT_PATHS,
        *SCREENSHOT_ARTIFACTS,
        PRODUCT_DB_ARTIFACT,
        VERIFICATION_REPORT,
        FRONTEND_REPORT,
    )
    if any((destination / name).exists() for name in owned):
        return _failure(("GATE-08 evidence directory contains stale owned artifacts",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    frontend = _run_frontend_suite(repository, destination)
    suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="operator-ui-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=300,
    )
    issues: list[object] = []
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    if helper.get("passed") is not True:
        issues.append("operator UI production browser helper failed")
    if not _frontend_suite_is_exact(frontend):
        issues.append("operator UI frontend typecheck, lint, or exact unit suite failed")
    if not _suite_is_exact(suite):
        issues.append("operator UI focused Python contract suite failed or skipped")
    try:
        checks, bundles = validate_persisted_operator_ui_gate(repository, destination)
        if set(checks) != CHECK_NAMES:
            raise ValueError("GATE-08 semantic check inventory is incomplete")
        failed = sorted(name for name, passed in checks.items() if not passed)
        if failed:
            issues.append("unproven semantic checks: " + ", ".join(failed))
    except (LookupError, OSError, TypeError, ValueError, OperatorUIGateValidationError) as exc:
        issues.append(exc)
    try:
        binding = _acceptance_binding()
        for bundle in bundles:
            validated_run_bundle(
                destination,
                destination.parent,
                bundle,
                expected_binding=binding,
                not_before=started,
                not_after=finished,
            )
    except (LookupError, OSError, TypeError, ValueError) as exc:
        issues.append(exc)
    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": not issues,
        "checks": dict(checks),
        "helper": helper,
        "frontend_suite": {
            "path": FRONTEND_REPORT,
            "passed": _frontend_suite_is_exact(frontend),
            "tests": frontend.get("tests") if isinstance(frontend, Mapping) else None,
        },
        "contract_suite": suite,
        "run_bundles": [dict(bundle) for bundle in bundles],
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
    }
    try:
        _write_json(destination / VERIFICATION_REPORT, verification)
    except (OSError, TypeError, ValueError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)
    proofs = tuple(
        _proof(assertion_id, kind, test_id, artifacts, bundles)
        for assertion_id, (kind, _check, artifacts, test_id) in _EXPECTED_ASSERTIONS.items()
    )
    return Gate08Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = ["FRONTEND_REPORT", "Gate08Outcome", "VERIFICATION_REPORT", "run_gate_08"]
