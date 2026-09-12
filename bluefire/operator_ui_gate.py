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
from .gate_frontend_report import retain_vitest_failures, vitest_inventory
from .gate_helper_diagnostics import (
    GateHelperFailure,
    helper_failure_detail,
    json_classification,
    output_diagnostic,
    protocol_failure_classification,
)
from .gate_private_diagnostics import (
    PRIVATE_DIAGNOSTICS_ENV,
    private_capture_root,
    retain_private_output,
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
from .runner_transport_errors import RunnerTransportError
from .util import content_hash

VERIFICATION_REPORT = "gate08-verification-report.json"
FRONTEND_REPORT = "gate08-frontend-suite.json"
VERIFICATION_SCHEMA = "bluefire.operator-ui-gate-verification.v1"
FRONTEND_SCHEMA = "bluefire.operator-ui-frontend-suite.v1"
_MAX_FRONTEND_OUTPUT_BYTES = 4 * 1024 * 1024

_ACCEPTANCE_ENVIRONMENT = (
    PRIVATE_DIAGNOSTICS_ENV,
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
    "sha256:085c8106d70faac649ab4a0c38a5cff4bc7797a9acc96cb8f3335c98db001c01"
)
_EXPECTED_FRONTEND_TEST_COUNT = 1194
_EXPECTED_FRONTEND_TESTS_SHA256 = (
    "sha256:9aca1ab99309c2a9a742b5f5d7b8625861252fcf40253d0c09a29b77e8255997"
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
                diagnostic_path=evidence_dir / "helper-process-diagnostic.json",
                expected_schema=HELPER_SCHEMA,
                expected_reports=REPORT_PATHS,
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
            "failure_classification": protocol_failure_classification(
                summary, returncode, returncode == 0 and protocol_valid
            ),
        }
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        return {
            "passed": False,
            "exit_code": None,
            "command": reported,
            "protocol_valid": False,
            "failure_classification": helper_failure_detail(exc),
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
    evidence_dir: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(node), os.fspath(script), *arguments]
    # File-backed output prevents a failed Node worker from retaining an
    # inherited pipe and hanging the gate after its bounded parent exits.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:

        def preserve_failure_output(classification: str, exit_code: int | None) -> None:
            captures: list[bytes] = []
            sizes: list[int] = []
            for stream in (stdout, stderr):
                stream.flush()
                stream.seek(0, os.SEEK_END)
                sizes.append(stream.tell())
                stream.seek(0)
                captures.append(stream.read(8193))
            retain_private_output(
                repository=frontend.parent,
                evidence_dir=evidence_dir or frontend.parent,
                stdout=captures[0],
                stderr=captures[1],
                source={
                    "kind": "frontend_process",
                    "command": command,
                    "classification": classification,
                    "exit_code": exit_code,
                    "timeout_seconds": timeout_seconds,
                    "stdout_total_bytes": sizes[0],
                    "stderr_total_bytes": sizes[1],
                },
            )

        try:
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
        except subprocess.TimeoutExpired:
            preserve_failure_output("timeout", None)
            raise
        outputs: list[bytes] = []
        for stream in (stdout, stderr):
            stream.flush()
            stream.seek(0, os.SEEK_END)
            if stream.tell() > _MAX_FRONTEND_OUTPUT_BYTES:
                preserve_failure_output("output_bound_exceeded", completed.returncode)
                raise GateHelperFailure("output_bound_exceeded")
            stream.seek(0)
            outputs.append(stream.read(_MAX_FRONTEND_OUTPUT_BYTES + 1))
    return subprocess.CompletedProcess(
        command,
        completed.returncode,
        stdout=outputs[0],
        stderr=outputs[1],
    )


def _vitest_ids(value: Any, frontend: Path) -> list[str]:
    inventory = vitest_inventory(value, frontend)
    if inventory["failed"] or inventory["skipped"]:
        raise ValueError("Vitest assertion did not pass exactly")
    return inventory["passed"]


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
    exit_codes: dict[str, int | None] = {"typecheck": None, "lint": None, "unit": None}
    diagnostic: dict[str, Any] = {
        "schema_version": "bluefire.gate-frontend-diagnostic.v1",
        "stage": "typecheck",
        "classification": "not_started",
        "inventory_known": False,
        "outputs": {},
    }

    def observe(stage: str, result: subprocess.CompletedProcess[bytes]) -> None:
        exit_codes[stage] = result.returncode
        diagnostic["outputs"][stage] = {
            "stdout": output_diagnostic(result.stdout),
            "stderr": output_diagnostic(result.stderr),
        }
        try:
            capture = retain_private_output(
                repository=repository,
                evidence_dir=evidence_dir,
                stdout=result.stdout,
                stderr=result.stderr,
                source={
                    "kind": "frontend_process",
                    "stage": stage,
                    "exit_code": result.returncode,
                    "command": [str(node), str(scripts[stage]), *reported[stage][2:]],
                },
            )
        except (OSError, ValueError, TypeError, RunnerTransportError) as error:
            # Optional diagnostic retention cannot erase the completed process result.
            capture = {"status": "retention_failed", "error_type": type(error).__name__}
        diagnostic["outputs"][stage]["private_capture"] = capture

    try:
        private_capture_root(repository, evidence_dir)
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
                evidence_dir=evidence_dir,
            )
            observe("typecheck", typecheck)
            diagnostic["stage"] = "lint"
            lint = _run_node_command(
                node,
                scripts["lint"],
                (".", "--max-warnings", "0"),
                frontend=frontend,
                environment=environment,
                timeout_seconds=180,
                evidence_dir=evidence_dir,
            )
            observe("lint", lint)
            diagnostic["stage"] = "unit"
            unit = _run_node_command(
                node,
                scripts["unit"],
                ("run", "--configLoader", "runner", "--reporter=json"),
                frontend=frontend,
                environment=environment,
                timeout_seconds=300,
                evidence_dir=evidence_dir,
            )
            observe("unit", unit)
            classification, parsed = json_classification(unit.stdout)
            if classification != "json_object":
                raise GateHelperFailure(classification)
            inventory = vitest_inventory(parsed, frontend)
            diagnostic["inventory_known"] = True
            if unit.returncode != 0 or inventory["failed"] or parsed.get("numFailedTestSuites", 0):
                diagnostic["unit_failures"] = retain_vitest_failures(
                    parsed,
                    frontend=frontend,
                    evidence_dir=evidence_dir,
                    source={
                        "stage": "unit",
                        "exit_code": unit.returncode,
                        "command": [str(node), str(scripts["unit"]), *reported["unit"][2:]],
                        "original_stdout": output_diagnostic(unit.stdout),
                    },
                )
            passed = (
                typecheck.returncode == lint.returncode == unit.returncode == 0
                and not inventory["failed"]
                and not inventory["skipped"]
                and parsed.get("success") is not False
                and not parsed.get("numFailedTests", 0)
                and not parsed.get("numPendingTests", 0)
                and not parsed.get("numFailedTestSuites", 0)
            )
            diagnostic["classification"] = "completed" if passed else "frontend_failed"
        report = {
            "schema_version": FRONTEND_SCHEMA,
            "passed": passed,
            "commands": reported,
            "exit_codes": exit_codes,
            "tests": sum(len(identifiers) for identifiers in inventory.values()),
            "passed_tests": inventory["passed"],
            "failed_tests": inventory["failed"],
            "skipped_tests": inventory["skipped"],
        }
    except (
        OSError,
        subprocess.TimeoutExpired,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        diagnostic["classification"] = (
            "timeout" if isinstance(exc, subprocess.TimeoutExpired) else helper_failure_detail(exc)
        )
        report = {
            "schema_version": FRONTEND_SCHEMA,
            "passed": False,
            "commands": reported,
            "exit_codes": exit_codes,
            "tests": 0,
            "passed_tests": [],
            "failed_tests": ["frontend_suite_failed"],
            "skipped_tests": [],
        }
    _write_json(evidence_dir / FRONTEND_REPORT, report)
    _write_json(evidence_dir / "gate08-frontend-diagnostic.json", diagnostic)
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
        issues.append(
            "operator UI production browser helper failed: "
            + str(helper.get("failure_classification", "unclassified"))
        )
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
