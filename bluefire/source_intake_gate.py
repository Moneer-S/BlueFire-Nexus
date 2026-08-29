"""Fail-closed release workflow for GATE-09 reviewed source intake."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
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
from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .runner_bootstrap import current_architecture
from .source_intake_gate_validation import (
    CHECK_NAMES,
    SourceIntakeGateValidationError,
    validate_persisted_source_intake_gate,
)
from .source_intake_journey import (
    BROWSER_INTAKE_ARTIFACT,
    BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    BROWSER_REPORT,
    EXECUTION_REPORT,
    HELPER_SCHEMA,
    INTAKE_ARTIFACT,
    INTAKE_REPORT,
    PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    PRODUCT_DB_ARTIFACT,
    REPORT_PATHS,
    SAFETY_REPORT,
    _is_link_or_reparse,
    _write_json,
)
from .util import content_hash

VERIFICATION_REPORT = "gate09-verification-report.json"
VERIFICATION_SCHEMA = "bluefire.source-intake-gate-verification.v1"
_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
)
_CONTRACT_TESTS = (
    "tests_platform/test_research.py",
    "tests_platform/test_source_intake.py",
    "tests_platform/test_source_intake_package.py",
    "tests_platform/test_source_intake_product_surface.py",
    "tests_platform/test_source_intake_browser_contract.py",
    "tests_platform/test_source_intake_gate.py",
)

# Updated only from the sorted JUnit inventory emitted by _run_pytest_suite.
_EXPECTED_CONTRACT_TEST_COUNT = 141
_EXPECTED_CONTRACT_TESTS_SHA256 = (
    "sha256:a1267ee2ce93ab4dd9e958eff25020f1c7a04fc0e642107465312f258fe5906a"
)

_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str]] = {
    "GATE-09-CLASSIFICATION-MODEL": (
        "structural",
        "classification_model",
        (INTAKE_REPORT, VERIFICATION_REPORT),
        "GATE-09.classification.six-reviewed-source-uses.v1",
    ),
    "GATE-09-PINNED-METADATA-IMPORT": (
        "dynamic",
        "pinned_metadata_import",
        (
            INTAKE_REPORT,
            INTAKE_ARTIFACT,
            PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
            PRODUCT_DB_ARTIFACT,
            VERIFICATION_REPORT,
        ),
        "GATE-09.intake.pinned-t1082-projection.v1",
    ),
    "GATE-09-EXECUTABLE-ADAPTER": (
        "dynamic",
        "executable_adapter",
        (EXECUTION_REPORT, PRODUCT_DB_ARTIFACT, VERIFICATION_REPORT),
        "GATE-09.execution.independent-compiled-action.v1",
    ),
    "GATE-09-SOURCE-LICENSE-REVIEW": (
        "structural",
        "source_license_review",
        (INTAKE_REPORT, INTAKE_ARTIFACT, VERIFICATION_REPORT),
        "GATE-09.review.exact-source-license.v1",
    ),
    "GATE-09-ATTRIBUTION-INTEGRITY-TRANSFORM": (
        "structural",
        "attribution_integrity_transform",
        (INTAKE_REPORT, INTAKE_ARTIFACT, VERIFICATION_REPORT),
        "GATE-09.transform.content-addressed-disposition.v1",
    ),
    "GATE-09-UI-PROVENANCE": (
        "dynamic",
        "ui_provenance",
        (
            BROWSER_REPORT,
            BROWSER_INTAKE_ARTIFACT,
            BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
            PRODUCT_DB_ARTIFACT,
            VERIFICATION_REPORT,
        ),
        "GATE-09.ui.production-source-provenance.v1",
    ),
    "GATE-09-THIRD-PARTY-NOTICES": (
        "structural",
        "third_party_notices",
        (INTAKE_REPORT, VERIFICATION_REPORT),
        "GATE-09.notices.pinned-license-attribution.v1",
    ),
    "GATE-09-SAFE-INTAKE": (
        "dynamic",
        "safe_intake",
        (SAFETY_REPORT, INTAKE_ARTIFACT, VERIFICATION_REPORT),
        "GATE-09.safety.refuse-unreviewed-content.v1",
    ),
}


@dataclass(frozen=True)
class Gate09Outcome:
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
        os.fspath(repository / "tools" / "run_source_intake_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_source_intake_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate09-helper-", dir=evidence_dir) as temporary:
            temporary_root = Path(temporary)
            environment = _isolated_python_environment(
                temporary_root,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            _configure_isolated_browser_environment(temporary_root, environment)
            if os.name == "nt":
                environment["PROCESSOR_ARCHITECTURE"] = {
                    "x86_64": "AMD64",
                    "aarch64": "ARM64",
                }[current_architecture()]
            node_raw = shutil.which("node")
            if node_raw is None:
                raise RuntimeError("the Gate 09 Node runtime is unavailable")
            node = Path(node_raw).resolve(strict=True)
            if not node.is_file():
                raise RuntimeError("the Gate 09 Node runtime is invalid")
            environment["BLUEFIRE_GATE_NODE"] = os.fspath(node)
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=360,
            )
            summary = json.loads(output.decode("utf-8"))
        protocol_valid = bool(
            isinstance(summary, Mapping)
            and set(summary)
            == {"schema_version", "status", "reports", "run_count", "blocking_check"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("reports") == list(REPORT_PATHS)
            and summary.get("run_count") == 1
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
    if values["gate_id"] != "GATE-09" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-09 acceptance binding is invalid")
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


def _suite_is_exact(value: Any) -> bool:
    expected_fields = {
        "schema_version",
        "suite_id",
        "command",
        "exit_code",
        "passed",
        "tests",
        "passed_tests",
        "failed_tests",
        "skipped_tests",
    }
    passed_tests = value.get("passed_tests") if isinstance(value, Mapping) else None
    test_count = value.get("tests") if isinstance(value, Mapping) else None
    expected_modules = {
        test.removesuffix(".py").replace("/", ".").replace("\\", ".") for test in _CONTRACT_TESTS
    }
    return bool(
        isinstance(value, Mapping)
        and set(value) == expected_fields
        and value.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and value.get("suite_id") == "source-intake-contracts"
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
        and isinstance(test_count, int)
        and not isinstance(test_count, bool)
        and test_count == _EXPECTED_CONTRACT_TEST_COUNT
        and isinstance(passed_tests, list)
        and passed_tests == sorted(passed_tests)
        and len(passed_tests) == test_count
        and len(set(passed_tests)) == test_count
        and all(isinstance(item, str) and item for item in passed_tests)
        and {item.partition("::")[0] for item in passed_tests} == expected_modules
        and content_hash(passed_tests) == _EXPECTED_CONTRACT_TESTS_SHA256
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _failure(issues: Sequence[object]) -> Gate09Outcome:
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
    reason = "GATE-09 failed checks: " + ", ".join(dict.fromkeys(safe))
    return Gate09Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def run_gate_09(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate09Outcome:
    raw_repository = repository_root or Path.cwd()
    try:
        repository_details = raw_repository.lstat()
        destination_details = evidence_dir.lstat()
    except OSError:
        return _failure(("GATE-09 roots are absent or unreadable",))
    if (
        not stat.S_ISDIR(repository_details.st_mode)
        or _is_link_or_reparse(repository_details)
        or not stat.S_ISDIR(destination_details.st_mode)
        or _is_link_or_reparse(destination_details)
    ):
        return _failure(("GATE-09 roots are unsafe",))
    repository = raw_repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected:
        return _failure(("locked GATE-09 assertion set mismatch",))
    if any(
        (destination / name).exists()
        for name in (*REPORT_PATHS, "runs", "intake", VERIFICATION_REPORT)
    ):
        return _failure(("GATE-09 evidence directory contains stale owned artifacts",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="source-intake-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=480,
    )
    issues: list[object] = []
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    if helper.get("passed") is not True:
        issues.append("source-intake helper failed or returned an invalid protocol")
    if not _suite_is_exact(suite):
        issues.append("source-intake focused regression suite failed or skipped")
    try:
        checks, bundles = validate_persisted_source_intake_gate(
            repository,
            destination,
            not_before=started,
            not_after=finished,
        )
        if set(checks) != CHECK_NAMES:
            raise ValueError("GATE-09 semantic check inventory is incomplete")
        failed_checks = sorted(name for name, passed in checks.items() if not passed)
        if failed_checks:
            issues.append("unproven semantic checks: " + ", ".join(failed_checks))
    except (LookupError, OSError, TypeError, ValueError, SourceIntakeGateValidationError) as exc:
        issues.append(exc)
    try:
        binding = _acceptance_binding()
        for bundle in bundles:
            normalized, _artifact = validated_run_bundle(
                destination,
                destination.parent,
                bundle,
                expected_binding=binding,
                not_before=started,
                not_after=finished,
            )
            if normalized["run_id"] != bundle["run_id"] or normalized["path"] != bundle["path"]:
                raise ValueError("the GATE-09 run-bundle reference changed during validation")
    except (LookupError, OSError, TypeError, ValueError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)
    try:
        final_checks, final_bundles = validate_persisted_source_intake_gate(
            repository,
            destination,
            not_before=started,
            not_after=finished,
        )
        if final_checks != checks or final_bundles != bundles:
            raise ValueError("GATE-09 evidence changed after independent verification")
    except (LookupError, OSError, TypeError, ValueError, SourceIntakeGateValidationError) as exc:
        return _failure((exc,))

    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": True,
        "helper": {
            key: helper.get(key) for key in ("passed", "exit_code", "command", "protocol_valid")
        },
        "suite": suite,
        "checks": dict(checks),
        "run_ids": [bundle["run_id"] for bundle in bundles],
    }
    try:
        _write_json(destination / VERIFICATION_REPORT, verification)
    except (OSError, TypeError, ValueError) as exc:
        return _failure((exc,))
    proofs = tuple(
        _proof(assertion_id, kind, test_id, artifacts, bundles)
        for assertion_id, (kind, check, artifacts, test_id) in _EXPECTED_ASSERTIONS.items()
        if checks.get(check) is True
    )
    if len(proofs) != 8 or len({proof["test_id"] for proof in proofs}) != 8:
        return _failure(("GATE-09 proof cardinality is not exact",))
    return Gate09Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = ["Gate09Outcome", "VERIFICATION_REPORT", "run_gate_09"]
