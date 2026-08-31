"""Fail-closed release workflow for GATE-03 deep-behavior packs."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .architecture_gate import _run_pytest_suite
from .deep_behavior_gate_validation import (
    ASSERTION_REPORTS,
    CHECK_NAMES,
    HELPER_SCHEMA,
    JOURNEY_REPORT_PATHS,
    REPORT_PATHS,
    VERIFICATION_REPORT,
    VERIFICATION_SCHEMA,
    DeepBehaviorGateValidationError,
    validate_deep_behavior_reports,
    validate_deep_behavior_verification,
    validate_linux_unavailable_report,
)
from .deep_behavior_journey import _write_json
from .defense_frontier_gate import (
    _isolated_python_environment,
    _run_bounded_helper_process,
)
from .product_acceptance_run_bundle import acceptance_run_binding
from .runner_bootstrap import current_architecture
from .runtime_paths import runtime_temp_parent
from .util import content_hash

_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
    "BLUEFIRE_GATE11_LINUX_WHEELHOUSE",
)
_CONTRACT_TESTS = (
    "tests_platform/test_deep_behavior_gate.py",
    "tests_platform/test_deep_behavior_gate_validation.py",
    "tests_platform/test_deep_behavior_journey.py",
    "tests_platform/test_cloud_identity_pack.py",
    "tests_platform/test_deep_endpoint_pack.py",
    "tests_platform/test_deep_behavior_simulation.py",
    "tests_platform/test_cross_platform_linux_worker_security.py",
    (
        "tests_platform/test_runner_cancellation.py::"
        "test_receiver_task_key_crosses_watchdog_only_through_fixed_scrubbed_environment"
    ),
)
_EXPECTED_SUITE_TEST_COUNT = 97
_EXPECTED_SUITE_TESTS_SHA256 = (
    "sha256:93b3bf53d78313e4ea2a5b1a728b00b9dea5bb9c4bcc1ffee1f1f71d2693a37d"
)

_ASSERTION_CHECKS = {
    "GATE-03-ENDPOINT-PHASES": "endpoint_phases",
    "GATE-03-AUTHORIZED-CREDENTIALS": "authorized_credentials",
    "GATE-03-DISPOSABLE-LATERAL": "disposable_lateral",
    "GATE-03-EVASION-TELEMETRY": "evasion_telemetry",
    "GATE-03-ENDPOINT-CLEANUP": "endpoint_cleanup",
    "GATE-03-LINUX-EFFECTS": "linux_effects",
    "GATE-03-LINUX-OBSERVATION": "linux_observation",
    "GATE-03-LINUX-ALTERNATE-CLEANUP": "linux_alternate_cleanup",
    "GATE-03-CLOUD-PROFILE-SECRETS": "cloud_profile_secrets",
    "GATE-03-CLOUD-ENUM-CONTROL": "cloud_enum_control",
    "GATE-03-CLOUD-CLEANUP-AUDIT": "cloud_cleanup_audit",
    "GATE-03-CLOUD-SIMULATE-EXECUTE": "cloud_simulate_execute",
    "GATE-03-CLOUD-DETERMINISTIC-INTEGRATION": "cloud_deterministic_integration",
    "GATE-03-CLOUD-MANUAL-SMOKE-CONTRACT": "cloud_manual_smoke_contract",
    "GATE-03-NO-RAW-CREDENTIALS": "no_raw_credentials",
}
_BUNDLE_INDEXES: Mapping[str, tuple[int, ...]] = {
    **{
        assertion_id: (0,)
        for assertion_id in (
            "GATE-03-ENDPOINT-PHASES",
            "GATE-03-AUTHORIZED-CREDENTIALS",
            "GATE-03-DISPOSABLE-LATERAL",
            "GATE-03-EVASION-TELEMETRY",
            "GATE-03-ENDPOINT-CLEANUP",
        )
    },
    "GATE-03-LINUX-EFFECTS": (1,),
    "GATE-03-LINUX-OBSERVATION": (1,),
    "GATE-03-LINUX-ALTERNATE-CLEANUP": (2,),
    **{
        assertion_id: (3, 4)
        for assertion_id in (
            "GATE-03-CLOUD-PROFILE-SECRETS",
            "GATE-03-CLOUD-ENUM-CONTROL",
            "GATE-03-CLOUD-CLEANUP-AUDIT",
            "GATE-03-CLOUD-SIMULATE-EXECUTE",
            "GATE-03-CLOUD-DETERMINISTIC-INTEGRATION",
            "GATE-03-CLOUD-MANUAL-SMOKE-CONTRACT",
        )
    },
    "GATE-03-NO-RAW-CREDENTIALS": (0, 1, 2, 3, 4),
}


@dataclass(frozen=True)
class Gate03Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _run_helper(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        os.fspath(repository / "tools" / "run_deep_behavior_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_deep_behavior_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate03-helper-", dir=evidence_dir) as raw:
            temporary = Path(raw)
            environment = _isolated_python_environment(
                temporary,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            isolated_home = temporary / "home"
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
                }
            )
            if os.name == "nt":
                environment["PROCESSOR_ARCHITECTURE"] = {
                    "x86_64": "AMD64",
                    "aarch64": "ARM64",
                }[current_architecture()]
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=1_500,
            )
            summary = json.loads(
                output.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        valid = bool(
            isinstance(summary, Mapping)
            and set(summary)
            == {"schema_version", "status", "blocking_check", "reports", "run_count"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") in {"passed", "failed"}
            and summary.get("reports") == list(JOURNEY_REPORT_PATHS)
            and type(summary.get("run_count")) is int
            and summary.get("run_count") in {0, 5}
            and summary.get("blocking_check") in {None, "linux_primary"}
        )
        passed = bool(
            valid
            and returncode == 0
            and summary.get("status") == "passed"
            and summary.get("blocking_check") is None
            and summary.get("run_count") == 5
        )
        return {
            "schema_version": summary.get("schema_version") if valid else None,
            "status": summary.get("status") if valid else "failed",
            "blocking_check": summary.get("blocking_check") if valid else None,
            "reports": summary.get("reports") if valid else [],
            "run_count": summary.get("run_count") if valid else 0,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": valid,
            "passed": passed,
        }
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, TypeError, ValueError):
        return {
            "schema_version": None,
            "status": "failed",
            "blocking_check": None,
            "reports": [],
            "run_count": 0,
            "exit_code": None,
            "command": reported,
            "protocol_valid": False,
            "passed": False,
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
    if values["gate_id"] != "GATE-03" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-03 acceptance binding is invalid")
    return acceptance_run_binding(**values)


def _suite_is_exact(value: Any) -> bool:
    passed = value.get("passed_tests") if isinstance(value, Mapping) else None
    return bool(
        isinstance(value, Mapping)
        and set(value)
        == {
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
        and value.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and value.get("suite_id") == "deep-behavior-contracts"
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
        and value.get("tests") == _EXPECTED_SUITE_TEST_COUNT
        and isinstance(passed, list)
        and passed == sorted(passed)
        and len(passed) == len(set(passed)) == _EXPECTED_SUITE_TEST_COUNT
        and content_hash(passed) == _EXPECTED_SUITE_TESTS_SHA256
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _failure(issues: Sequence[object]) -> Gate03Outcome:
    absolute = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
    values: list[str] = []
    for issue in issues:
        raw = str(issue)
        safe = (
            "validation failure [private-path-redacted]"
            if absolute.search(raw)
            else " ".join(raw.split())
        )
        values.append((safe or "unknown validation failure")[:300])
    reason = "GATE-03 failed checks: " + ", ".join(dict.fromkeys(values))
    return Gate03Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def _proof(
    assertion_id: str,
    kind: str,
    report: str,
    bundles: Sequence[Mapping[str, str]],
) -> Mapping[str, Any]:
    slug = assertion_id.removeprefix("GATE-03-").casefold().replace("_", "-")
    return {
        "kind": kind,
        "status": "passed",
        "test_id": f"GATE-03.{slug}.v1",
        "assertion_ids": [assertion_id],
        "evidence_artifacts": [report, "pack-inventory.json", VERIFICATION_REPORT],
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "run_bundles": [dict(bundle) for bundle in bundles],
        "environment_limitations": [],
    }


def run_gate_03(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate03Outcome:
    raw_repository = repository_root or Path.cwd()
    try:
        repository_details = raw_repository.lstat()
        destination_details = evidence_dir.lstat()
    except OSError:
        return _failure(("GATE-03 roots are absent or unreadable",))
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISDIR(repository_details.st_mode)
        or stat.S_ISLNK(repository_details.st_mode)
        or int(getattr(repository_details, "st_file_attributes", 0)) & reparse
        or not stat.S_ISDIR(destination_details.st_mode)
        or stat.S_ISLNK(destination_details.st_mode)
        or int(getattr(destination_details, "st_file_attributes", 0)) & reparse
    ):
        return _failure(("GATE-03 roots are unsafe",))
    repository = raw_repository.resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: proof for assertion_id, proof, _report in ASSERTION_REPORTS}
    if contract != expected or set(_ASSERTION_CHECKS) != set(expected):
        return _failure(("locked GATE-03 assertion set mismatch",))
    if any((destination / name).exists() for name in (*REPORT_PATHS, "runs")):
        return _failure(("GATE-03 evidence directory contains stale owned artifacts",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    if helper.get("blocking_check") == "linux_primary":
        try:
            reason = validate_linux_unavailable_report(destination, repository)
        except (OSError, TypeError, ValueError, DeepBehaviorGateValidationError) as exc:
            return _failure(("Linux helper failed without typed availability evidence", exc))
        if reason.startswith("GATE-11 "):
            reason = "GATE-03 " + reason.removeprefix("GATE-11 ")
        return Gate03Outcome(status="failed", proofs=(), failure_reason=reason)
    if helper.get("passed") is not True:
        return _failure(("deep-behavior helper failed or returned an invalid protocol",))

    suite = _run_pytest_suite(
        repository,
        runtime_temp_parent(),
        suite_id="deep-behavior-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=480,
    )
    issues: list[object] = []
    if not _suite_is_exact(suite):
        issues.append("deep-behavior focused regression suite failed, changed, or skipped")
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    try:
        checks, bundles = validate_deep_behavior_reports(
            destination,
            repository,
            expected_binding=_acceptance_binding(),
            not_before=started,
            not_after=finished,
        )
        if set(checks) != CHECK_NAMES or any(value is not True for value in checks.values()):
            raise DeepBehaviorGateValidationError("GATE-03 semantic check inventory is incomplete")
        if len(bundles) != 5:
            raise DeepBehaviorGateValidationError("GATE-03 requires exactly five run bundles")
    except (LookupError, OSError, TypeError, ValueError, DeepBehaviorGateValidationError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)

    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": True,
        "helper": {
            key: helper.get(key)
            for key in (
                "schema_version",
                "status",
                "reports",
                "run_count",
                "blocking_check",
                "exit_code",
                "command",
                "protocol_valid",
            )
        },
        "suite": suite,
        "checks": dict(checks),
        "run_ids": [bundle["run_id"] for bundle in bundles],
        "reports": list(JOURNEY_REPORT_PATHS),
        "proof_kinds": ["dynamic", "structural"],
    }
    try:
        _write_json(destination / VERIFICATION_REPORT, verification)
        validate_deep_behavior_verification(
            destination,
            expected_checks=checks,
            expected_run_ids=[bundle["run_id"] for bundle in bundles],
            expected_suite_tests=tuple(suite.get("passed_tests", ())),
        )
        final_checks, final_bundles = validate_deep_behavior_reports(
            destination,
            repository,
            expected_binding=_acceptance_binding(),
            not_before=started,
            not_after=finished,
        )
        if final_checks != checks or final_bundles != bundles:
            raise DeepBehaviorGateValidationError("GATE-03 evidence changed after validation")
    except (OSError, TypeError, ValueError, DeepBehaviorGateValidationError) as exc:
        return _failure((exc,))

    proof_rows = {
        assertion_id: (proof, report) for assertion_id, proof, report in ASSERTION_REPORTS
    }
    proofs = tuple(
        _proof(
            assertion_id,
            proof_rows[assertion_id][0],
            proof_rows[assertion_id][1],
            tuple(bundles[index] for index in _BUNDLE_INDEXES[assertion_id]),
        )
        for assertion_id in _ASSERTION_CHECKS
        if checks.get(_ASSERTION_CHECKS[assertion_id]) is True
    )
    if len(proofs) != 15 or len({proof["test_id"] for proof in proofs}) != 15:
        return _failure(("GATE-03 proof inventory is incomplete",))
    return Gate03Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = ["Gate03Outcome", "run_gate_03"]
