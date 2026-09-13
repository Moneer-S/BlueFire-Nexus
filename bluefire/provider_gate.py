"""Executable signed-provider acceptance workflow for GATE-02."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import bluefire.provider_gate_validation as _validation

from .architecture_gate import _run_pytest_suite
from .util import content_hash as content_hash

JOURNEY_SCHEMA = _validation.JOURNEY_SCHEMA
STRUCTURAL_SCHEMA = _validation.STRUCTURAL_SCHEMA
VERIFICATION_SCHEMA = _validation.VERIFICATION_SCHEMA
_API_MANAGEMENT_TESTS = _validation._API_MANAGEMENT_TESTS
_CLI_MANAGEMENT_TESTS = _validation._CLI_MANAGEMENT_TESTS
_EXPECTED_PROVIDER_CONTRACT_TESTS = _validation._EXPECTED_PROVIDER_CONTRACT_TESTS
_EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256 = _validation._EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256
_EXPECTED_UI_TESTS = _validation._EXPECTED_UI_TESTS
_FRONTEND_SUITE_SCHEMA = _validation._FRONTEND_SUITE_SCHEMA
_MINIMUM_PROVIDER_CONTRACT_TESTS = _validation._MINIMUM_PROVIDER_CONTRACT_TESTS
_PROVIDER_ACTION_ID = _validation._PROVIDER_ACTION_ID
_PROVIDER_BEHAVIOR_ID = _validation._PROVIDER_BEHAVIOR_ID
_PROVIDER_CONTRACT_TESTS = _validation._PROVIDER_CONTRACT_TESTS
_PYTEST_SUITE_SCHEMA = _validation._PYTEST_SUITE_SCHEMA
_REQUIRED_PROVIDER_CONTRACT_TESTS = _validation._REQUIRED_PROVIDER_CONTRACT_TESTS
_check_map = _validation._check_map
_expected_pytest_command = _validation._expected_pytest_command
_is_sha256_digest = _validation._is_sha256_digest
_pytest_identifier = _validation._pytest_identifier
_suite_test_passed = _validation._suite_test_passed
_validate_frontend_suite = _validation._validate_frontend_suite
_validate_helper_report = _validation._validate_helper_report
_validate_inventory_binding = _validation._validate_inventory_binding
_validate_journey = _validation._validate_journey
_validate_packaged_runner = _validation._validate_packaged_runner
_validate_pytest_suite = _validation._validate_pytest_suite
_validate_structural = _validation._validate_structural

_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str]] = {
    "GATE-02-NEW-PROVIDER-ARTIFACT": (
        "dynamic",
        "new_provider_artifact",
        ("provider-journey-report.json",),
        "GATE-02.new-provider-artifact.real-rust.v1",
    ),
    "GATE-02-CORE-INDEPENDENCE": (
        "structural",
        "core_independence",
        ("provider-structural-report.json",),
        "GATE-02.core-independence.audit.v1",
    ),
    "GATE-02-MANIFEST-INTEGRITY": (
        "structural",
        "manifest_integrity",
        ("provider-structural-report.json",),
        "GATE-02.manifest-integrity.audit.v1",
    ),
    "GATE-02-SAFE-CONTRACT": (
        "structural",
        "safe_contract",
        ("provider-structural-report.json",),
        "GATE-02.safe-contract.audit.v1",
    ),
    "GATE-02-LIFECYCLE": (
        "dynamic",
        "lifecycle",
        ("provider-journey-report.json",),
        "GATE-02.lifecycle.real-service.v1",
    ),
    "GATE-02-INVENTORY-COMPATIBILITY": (
        "dynamic",
        "inventory_compatibility",
        ("provider-journey-report.json",),
        "GATE-02.inventory-compatibility.real-runner.v1",
    ),
    "GATE-02-MANAGEMENT-PARITY": (
        "dynamic",
        "management_parity",
        ("provider-verification-report.json",),
        "GATE-02.management-parity.ui-api-cli.v1",
    ),
    "GATE-02-TAMPER-REFUSAL": (
        "dynamic",
        "tamper_refusal",
        ("provider-journey-report.json", "provider-verification-report.json"),
        "GATE-02.tamper-refusal.dynamic.v1",
    ),
    "GATE-02-LIMITS-CLEANUP": (
        "dynamic",
        "limits_cleanup",
        ("provider-journey-report.json", "provider-verification-report.json"),
        "GATE-02.limits-cleanup.real-runtime.v1",
    ),
    "GATE-02-NO-MODEL-SHELL": (
        "structural",
        "no_model_shell",
        ("provider-structural-report.json",),
        "GATE-02.no-model-shell.source-audit.v1",
    ),
}


@dataclass(frozen=True)
class Gate02Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is unavailable or invalid") from exc
    if not isinstance(value, Mapping):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _validate_verification(report: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate persisted evidence while preserving test-time lock overrides."""

    return _validation._validate_verification(
        report,
        expected_provider_contract_tests=_EXPECTED_PROVIDER_CONTRACT_TESTS,
        expected_provider_contract_tests_sha256=_EXPECTED_PROVIDER_CONTRACT_TESTS_SHA256,
    )


def _run_with_bounded_stdout(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    maximum_stdout_bytes: int,
) -> tuple[int, bytes]:
    with tempfile.TemporaryFile() as output:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
        output.flush()
        output.seek(0, os.SEEK_END)
        if output.tell() > maximum_stdout_bytes:
            raise ValueError("subprocess output exceeded its bound")
        output.seek(0)
        return process.returncode, output.read(maximum_stdout_bytes + 1)


def _run_helper(repository: Path, evidence_dir: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        os.fspath(repository / "tools" / "run_provider_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        exit_code, stdout = _run_with_bounded_stdout(
            command,
            cwd=repository,
            environment=environment,
            timeout_seconds=300,
            maximum_stdout_bytes=8_192,
        )
        summary = json.loads(stdout.decode("utf-8"))
        if not isinstance(summary, Mapping):
            raise ValueError("provider helper output is not an object")
        expected_structural = [
            "core_independence",
            "manifest_integrity",
            "no_model_shell",
            "safe_contract",
        ]
        expected_journey = [
            "inventory_compatibility",
            "lifecycle",
            "limits_cleanup",
            "new_provider_artifact",
            "tamper_refusal",
        ]
        passing_summary = (
            set(summary)
            == {
                "schema_version",
                "status",
                "structural_checks",
                "journey_checks",
                "run_count",
            }
            and summary.get("schema_version") == JOURNEY_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("structural_checks") == expected_structural
            and summary.get("journey_checks") == expected_journey
            and summary.get("run_count") == 3
        )
        result: dict[str, Any] = {
            "passed": exit_code == 0 and passing_summary,
            "exit_code": exit_code,
            "command": ["{python}", "tools/run_provider_gate_journey.py", "{fixed-arguments}"],
            "protocol_valid": passing_summary,
        }
        if not result["passed"]:
            failure_summary = (
                set(summary)
                == {
                    "schema_version",
                    "status",
                    "error_type",
                    "error_code",
                    "message",
                }
                and summary.get("schema_version") == JOURNEY_SCHEMA
                and summary.get("status") == "failed"
                and isinstance(summary.get("error_code"), str)
                and isinstance(summary.get("message"), str)
                and 1 <= len(str(summary["error_code"])) <= 64
                and str(summary["error_code"]).replace("_", "").isalnum()
                and 1 <= len(str(summary["message"])) <= 200
                and all(ord(character) >= 32 for character in str(summary["message"]))
                and "\\" not in str(summary["message"])
            )
            result["failure_code"] = (
                summary["error_code"]
                if failure_summary
                else "provider_gate_helper_protocol_invalid"
            )
            result["failure_message"] = (
                summary["message"]
                if failure_summary
                else "provider helper returned an invalid summary"
            )
        return result
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        return {
            "passed": False,
            "exit_code": None,
            "command": ["{python}", "tools/run_provider_gate_journey.py", "{fixed-arguments}"],
            "failure_type": type(exc).__name__,
            "failure_code": "provider_gate_helper_protocol_invalid",
        }


def _run_vitest(repository: Path) -> dict[str, Any]:
    frontend = repository / "frontend"
    node = shutil.which("node")
    entrypoint = frontend / "node_modules" / "vitest" / "vitest.mjs"
    command = [
        node or "node",
        os.fspath(entrypoint),
        "run",
        "tests/action-packages.test.tsx",
        "--configLoader",
        "runner",
        "--reporter=json",
    ]
    if node is None or not entrypoint.is_file():
        return {
            "schema_version": "bluefire.provider-frontend-check.v1",
            "suite_id": "provider-management-ui",
            "command": ["{node}", "{vitest}", "run", "tests/action-packages.test.tsx"],
            "exit_code": None,
            "passed": False,
            "tests": 0,
            "passed_tests": [],
            "failed_tests": ["frontend-runtime-unavailable"],
        }
    environment = dict(os.environ)
    environment["NO_COLOR"] = "1"
    try:
        exit_code, stdout = _run_with_bounded_stdout(
            command,
            cwd=frontend,
            environment=environment,
            timeout_seconds=180,
            maximum_stdout_bytes=8 * 1024 * 1024,
        )
        value = json.loads(stdout.decode("utf-8"))
        if not isinstance(value, Mapping):
            raise ValueError("Vitest JSON is not an object")
        raw_results = value.get("testResults")
        if not isinstance(raw_results, list):
            raise ValueError("Vitest JSON has no test results")
        assertions = [
            assertion
            for result in raw_results
            if isinstance(result, Mapping)
            for assertion in result.get("assertionResults", [])
            if isinstance(assertion, Mapping)
        ]
        passed_tests = sorted(
            str(item.get("fullName")) for item in assertions if item.get("status") == "passed"
        )
        failed_tests = sorted(
            str(item.get("fullName")) for item in assertions if item.get("status") != "passed"
        )
        total = value.get("numTotalTests")
        passed = (
            exit_code == 0
            and value.get("success") is True
            and isinstance(total, int)
            and total == len(_EXPECTED_UI_TESTS)
            and len(passed_tests) == total
            and frozenset(passed_tests) == _EXPECTED_UI_TESTS
            and not failed_tests
        )
        return {
            "schema_version": "bluefire.provider-frontend-check.v1",
            "suite_id": "provider-management-ui",
            "command": ["{node}", "{vitest}", "run", "tests/action-packages.test.tsx"],
            "exit_code": exit_code,
            "passed": passed,
            "tests": total if isinstance(total, int) else 0,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
        }
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        return {
            "schema_version": "bluefire.provider-frontend-check.v1",
            "suite_id": "provider-management-ui",
            "command": ["{node}", "{vitest}", "run", "tests/action-packages.test.tsx"],
            "exit_code": None,
            "passed": False,
            "tests": 0,
            "passed_tests": [],
            "failed_tests": [type(exc).__name__],
        }


def _proof(
    assertion_id: str,
    kind: str,
    test_id: str,
    artifacts: Sequence[str],
    bundles: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    return {
        "kind": kind,
        "status": "passed",
        "test_id": test_id,
        "assertion_ids": [assertion_id],
        "evidence_artifacts": list(artifacts),
        "run_ids": [item["run_id"] for item in bundles],
        "run_bundles": [dict(item) for item in bundles],
        "environment_limitations": [],
    }


def run_gate_02(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate02Outcome:
    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected_kinds = {name: row[0] for name, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected_kinds:
        return Gate02Outcome(
            status="failed",
            proofs=(),
            failure_reason="locked GATE-02 assertion set mismatch",
        )

    helper = _run_helper(repository, destination)
    provider_suite = _run_pytest_suite(
        repository,
        destination,
        suite_id="provider-contracts",
        tests=_PROVIDER_CONTRACT_TESTS,
        timeout_seconds=300,
    )
    api_suite = _run_pytest_suite(
        repository,
        destination,
        suite_id="provider-management-api",
        tests=_API_MANAGEMENT_TESTS,
        timeout_seconds=90,
    )
    cli_suite = _run_pytest_suite(
        repository,
        destination,
        suite_id="provider-management-cli",
        tests=_CLI_MANAGEMENT_TESTS,
        timeout_seconds=90,
    )
    frontend_suite = _run_vitest(repository)

    structural_path = destination / "provider-structural-report.json"
    journey_path = destination / "provider-journey-report.json"
    structural: Mapping[str, Any] = {}
    journey: Mapping[str, Any] = {}
    journey_checks: Mapping[str, Any] = {}
    bundles: tuple[dict[str, str], ...] = ()
    report_issues: list[str] = []
    try:
        structural = _load_json(structural_path)
        _validate_structural(structural)
    except (KeyError, TypeError, ValueError) as exc:
        report_issues.append(str(exc))
    try:
        journey = _load_json(journey_path)
        journey_checks, bundles = _validate_journey(journey)
    except (KeyError, TypeError, ValueError) as exc:
        report_issues.append(str(exc))

    management_passed = (
        api_suite["passed"] is True
        and cli_suite["passed"] is True
        and frontend_suite["passed"] is True
    )
    api_route_coverage = all(
        _suite_test_passed(api_suite, selector) for selector in _API_MANAGEMENT_TESTS[:2]
    )
    cli_request_coverage = all(
        _suite_test_passed(cli_suite, selector) for selector in _CLI_MANAGEMENT_TESTS[:2]
    )
    api_real_lifecycle = _suite_test_passed(api_suite, _API_MANAGEMENT_TESTS[2])
    cli_real_lifecycle = _suite_test_passed(cli_suite, _CLI_MANAGEMENT_TESTS[3])
    tamper_passed = (
        provider_suite["passed"] is True
        and isinstance(journey_checks.get("tamper_refusal"), Mapping)
        and journey_checks["tamper_refusal"].get("passed") is True
    )
    limits_passed = (
        provider_suite["passed"] is True
        and isinstance(journey_checks.get("limits_cleanup"), Mapping)
        and journey_checks["limits_cleanup"].get("passed") is True
    )
    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": helper["passed"] is True
        and provider_suite["passed"] is True
        and management_passed
        and tamper_passed
        and limits_passed
        and not report_issues,
        "helper": helper,
        "suites": {
            "provider_contracts": provider_suite,
            "management_api": api_suite,
            "management_cli": cli_suite,
            "management_ui": frontend_suite,
        },
        "checks": {
            "management_parity": {
                "passed": management_passed,
                "channels": {
                    "ui_request_wiring": frontend_suite["passed"] is True,
                    "api_route_to_lifecycle_authority": api_route_coverage,
                    "cli_request_to_lifecycle_authority": cli_request_coverage,
                    "api_real_signed_provider_lifecycle": api_real_lifecycle,
                    "cli_real_signed_provider_lifecycle": cli_real_lifecycle,
                    "real_signed_provider_lifecycle_service": helper["passed"] is True,
                },
            },
            "tamper_refusal": {
                "passed": tamper_passed,
                "real_service_refusal": bool(tamper_passed),
                "contract_regressions": provider_suite["passed"] is True,
            },
            "limits_cleanup": {
                "passed": limits_passed,
                "real_rust_limit_run": bool(limits_passed),
                "contract_regressions": provider_suite["passed"] is True,
            },
        },
    }
    verification_path = destination / "provider-verification-report.json"
    _write_json(verification_path, verification)
    try:
        persisted_verification = _load_json(verification_path)
        verification_checks = _validate_verification(persisted_verification)
    except (KeyError, TypeError, ValueError) as exc:
        report_issues.append(str(exc))
        verification_checks = {}

    if helper["passed"] is not True:
        failure_code = helper.get("failure_code")
        failure_message = helper.get("failure_message")
        if (
            isinstance(failure_code, str)
            and 1 <= len(failure_code) <= 64
            and failure_code.replace("_", "").isalnum()
            and isinstance(failure_message, str)
            and 1 <= len(failure_message) <= 200
            and all(ord(character) >= 32 for character in failure_message)
            and "\\" not in failure_message
        ):
            report_issues.append(
                f"provider real-run helper failed [{failure_code}]: {failure_message}"
            )
        else:
            report_issues.append("provider real-run helper failed")
    if provider_suite["passed"] is not True:
        report_issues.append("provider contract regression suite failed")
    if api_suite["passed"] is not True:
        report_issues.append("provider API management suite failed")
    if cli_suite["passed"] is not True:
        report_issues.append("provider CLI management suite failed")
    if frontend_suite["passed"] is not True:
        report_issues.append("provider UI management suite failed")
    if report_issues:
        return Gate02Outcome(
            status="failed",
            proofs=(),
            failure_reason="GATE-02 failed checks: " + ", ".join(dict.fromkeys(report_issues)),
        )

    proofs: list[Mapping[str, Any]] = []
    for assertion_id, (kind, check_name, artifacts, test_id) in _EXPECTED_ASSERTIONS.items():
        checks = (
            verification_checks
            if check_name == "management_parity"
            else structural["checks"] if kind == "structural" else journey_checks
        )
        if (
            not isinstance(checks.get(check_name), Mapping)
            or checks[check_name].get("passed") is not True
        ):
            return Gate02Outcome(
                status="failed",
                proofs=(),
                failure_reason=f"GATE-02 failed check: {assertion_id}",
            )
        attached_bundles: Sequence[Mapping[str, str]] = ()
        if assertion_id == "GATE-02-NEW-PROVIDER-ARTIFACT":
            attached_bundles = bundles[:2]
        elif assertion_id == "GATE-02-LIMITS-CLEANUP":
            attached_bundles = bundles[2:]
        proofs.append(_proof(assertion_id, kind, test_id, artifacts, attached_bundles))
    return Gate02Outcome(status="passed", proofs=tuple(proofs), failure_reason=None)


__all__ = ["Gate02Outcome", "run_gate_02"]
