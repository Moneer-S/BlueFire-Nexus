"""Fail-closed release workflow for GATE-12 professional readiness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
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
from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .release_readiness_artifacts import persisted_artifact_hashes
from .release_readiness_journey import HELPER_SCHEMA, JOURNEY_REPORT, REPORT_PATHS
from .release_readiness_suites import run_full_release_suites
from .release_readiness_validation import (
    CHECK_NAMES,
    OPSEC_REPORT,
    OPSEC_SCHEMA,
    SBOM_REPORT,
    STRUCTURAL_REPORT,
    SUITE_REPORT,
    UPSTREAM_REPORT,
    VERIFICATION_REPORT,
    VERIFICATION_SCHEMA,
    ReleaseReadinessValidationError,
    audit_release_structure,
    exact_contract_suite,
    read_json,
    validate_opsec_report,
    validate_release_journey,
    validate_suite_report,
    validate_upstream_closure,
    validate_verification_report,
)
from .runner_bootstrap import current_architecture
from .util import content_hash

_MAX_REPORT_BYTES = 32 * 1024 * 1024
_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
    "BLUEFIRE_ACCEPTANCE_PLAYWRIGHT_BROWSERS_PATH",
)
_CONTRACT_TESTS = ("tests_platform/test_release_readiness_gate.py",)
_EXPECTED_CONTRACT_TEST_COUNT = 19
_EXPECTED_CONTRACT_TESTS_SHA256 = (
    "sha256:e72ce002f19e650f847c21da4121822100c88ecd1fcca59e232bbffea5dbc362"
)

_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str, bool]] = {
    "GATE-12-README-PRODUCT-LOOP": (
        "structural",
        "readme_product_loop",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.readme.actual-product-loop.v1",
        False,
    ),
    "GATE-12-SANITIZED-SCREENSHOTS": (
        "dynamic",
        "sanitized_screenshots",
        (
            JOURNEY_REPORT,
            "operator/screenshots/operator-builder.png",
            "operator/screenshots/operator-run-review.png",
            "operator/screenshots/operator-compare.png",
            VERIFICATION_REPORT,
        ),
        "GATE-12.screenshots.fresh-production-sanitized.v1",
        True,
    ),
    "GATE-12-FRONTIER-COMPARE-ARTIFACT": (
        "dynamic",
        "frontier_compare_artifact",
        (JOURNEY_REPORT, "frontier/gate04-comparison-report.json", VERIFICATION_REPORT),
        "GATE-12.frontier.replay-compare-real.v1",
        True,
    ),
    "GATE-12-CAPABILITY-CLASSIFICATION": (
        "structural",
        "capability_classification",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.capabilities.truthful-classification.v1",
        False,
    ),
    "GATE-12-COMPLETE-DOCS": (
        "structural",
        "complete_docs",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.docs.complete-operator-developer-set.v1",
        False,
    ),
    "GATE-12-GITHUB-METADATA": (
        "structural",
        "github_metadata",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.github.recommendations-no-remote-write.v1",
        False,
    ),
    "GATE-12-CLEAN-PACKAGE-INSTALL": (
        "dynamic",
        "clean_package_install",
        (UPSTREAM_REPORT, VERIFICATION_REPORT),
        "GATE-12.package.same-commit-gate01-revalidation.v1",
        False,
    ),
    "GATE-12-FULL-SUITES": (
        "dynamic",
        "full_suites",
        (SUITE_REPORT, SBOM_REPORT, UPSTREAM_REPORT, VERIFICATION_REPORT),
        "GATE-12.suites.python-rust-frontend-security-e2e.v1",
        False,
    ),
    "GATE-12-SECURITY-OPSEC": (
        "dynamic",
        "security_opsec",
        (OPSEC_REPORT, SBOM_REPORT, VERIFICATION_REPORT),
        "GATE-12.opsec.tracked-tree-and-security-scans.v1",
        False,
    ),
    "GATE-12-CLEAN-WORKTREE": (
        "structural",
        "clean_worktree",
        (STRUCTURAL_REPORT, SUITE_REPORT, VERIFICATION_REPORT),
        "GATE-12.git.commit-tree-clean-source-preserved.v1",
        False,
    ),
    "GATE-12-RIGHTS-AUDIT": (
        "structural",
        "rights_audit",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.rights.complete-reviewed-inventory.v1",
        False,
    ),
    "GATE-12-LICENSE-DECISION": (
        "structural",
        "license_decision",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-12.license.retain-mit-until-authorized.v1",
        False,
    ),
}

_FORBIDDEN_TRACKED_SUFFIXES = frozenset(
    {".db", ".sqlite", ".sqlite3", ".log", ".trace", ".key", ".pem", ".p12", ".pfx"}
)
_PRIVATE_PATH = re.compile(r"(?i)(?:[A-Z]:[\\/]Users[\\/][^\\/\s]+|/(?:home|Users)/[^/\s]+)")
_PROMPT_MARKERS = (
    "anti_" + "larping_acceptance_contract",
    "bluefire_real_" + "product_completion_prompt",
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class Gate12Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _safe_directory_root(raw: Path, context: str) -> Path:
    try:
        unresolved = Path(os.path.abspath(raw))
        raw_details = raw.lstat()
        resolved = raw.resolve(strict=True)
        resolved_details = resolved.lstat()
    except OSError as exc:
        raise ValueError(f"{context} is unavailable") from exc
    if (
        unresolved != resolved
        or not stat.S_ISDIR(raw_details.st_mode)
        or stat.S_ISLNK(raw_details.st_mode)
        or bool(int(getattr(raw_details, "st_file_attributes", 0)) & _REPARSE_POINT)
        or not stat.S_ISDIR(resolved_details.st_mode)
        or stat.S_ISLNK(resolved_details.st_mode)
        or bool(int(getattr(resolved_details, "st_file_attributes", 0)) & _REPARSE_POINT)
    ):
        raise ValueError(f"{context} is not a direct regular directory")
    return resolved


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    if len(payload) > _MAX_REPORT_BYTES or path.exists() or not path.parent.is_dir():
        raise ValueError("a GATE-12 report path is stale or unbounded")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError("a GATE-12 report path is unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("a GATE-12 report write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)


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
        if not isinstance(value, str) or not value or len(value) > 512 or "\0" in value:
            raise ValueError(f"required acceptance binding {name} is unavailable")
        values[field] = value
    if values["gate_id"] != "GATE-12" or values["release"] != "true":
        raise ValueError("GATE-12 requires a bound release acceptance run")
    return {key: str(value) for key, value in acceptance_run_binding(**values).items()}


def _run_helper(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        os.fspath(repository / "tools/run_release_readiness_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_release_readiness_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate12-helper-", dir=evidence_dir) as raw:
            temporary = Path(raw)
            environment = _isolated_python_environment(
                temporary,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            _configure_isolated_browser_environment(temporary, environment)
            node_raw = shutil.which("node")
            if node_raw is None:
                raise RuntimeError("the GATE-12 Node runtime is unavailable")
            node = Path(node_raw).resolve(strict=True)
            environment["BLUEFIRE_GATE_NODE"] = os.fspath(node)
            environment["PROCESSOR_ARCHITECTURE"] = {
                "x86_64": "AMD64",
                "aarch64": "ARM64",
            }[current_architecture()]
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=1200,
            )
            summary = json.loads(output.decode("utf-8"))
        valid = bool(
            isinstance(summary, Mapping)
            and set(summary)
            == {
                "schema_version",
                "status",
                "reports",
                "run_count",
                "screenshot_count",
                "blocking_check",
            }
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("reports") == list(REPORT_PATHS)
            and summary.get("run_count") == 7
            and summary.get("screenshot_count") == 3
            and summary.get("blocking_check") is None
        )
        return {
            "passed": returncode == 0 and valid,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": valid,
        }
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return {
            "passed": False,
            "exit_code": None,
            "command": reported,
            "protocol_valid": False,
        }


def _tracked_files(repository: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), "ls-files", "-z"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ValueError("the tracked release inventory is unavailable")
    try:
        result = [item.decode("utf-8", "strict") for item in completed.stdout.split(b"\0") if item]
    except UnicodeError as exc:
        raise ValueError("the tracked release inventory is not UTF-8") from exc
    if not result or result != sorted(set(result)):
        raise ValueError("the tracked release inventory is invalid")
    return result


def _opsec_report(
    repository: Path,
    evidence_dir: Path,
    suites: Mapping[str, Any],
) -> Mapping[str, Any]:
    tracked = _tracked_files(repository)
    forbidden: list[str] = []
    private_hits: list[str] = []
    hashed: list[tuple[str, str]] = []
    allowed_path_fixture = "tests_platform/test_defense_frontier_validation.py"
    for relative in tracked:
        path = repository / relative
        details = path.lstat()
        if (
            stat.S_ISLNK(details.st_mode)
            or bool(int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT)
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            forbidden.append(relative + ":unsafe-entry")
            continue
        lowered = relative.replace("\\", "/").casefold()
        parts = lowered.split("/")
        if path.suffix.casefold() in _FORBIDDEN_TRACKED_SUFFIXES or any(
            part in {"node_modules", "__pycache__", ".pytest_cache", "runs", "build"}
            for part in parts
        ):
            forbidden.append(relative + ":generated-or-private-artifact")
        payload = path.read_bytes()
        hashed.append((relative, "sha256:" + hashlib.sha256(payload).hexdigest()))
        if len(payload) > 4 * 1024 * 1024 or b"\0" in payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            continue
        if relative != allowed_path_fixture and _PRIVATE_PATH.search(text):
            private_hits.append(relative + ":absolute-user-path")
        if any(marker in text for marker in _PROMPT_MARKERS):
            private_hits.append(relative + ":private-directive")
    suite_rows = suites.get("suites")
    indexed = (
        {
            str(row.get("suite_id")): row
            for row in suite_rows
            if isinstance(row, Mapping) and isinstance(row.get("suite_id"), str)
        }
        if isinstance(suite_rows, list)
        else {}
    )
    scans = {
        name: indexed.get("security." + name, {}).get("passed") is True
        for name in ("gitleaks", "detect-secrets", "bandit", "pip-audit")
    }
    sbom_safe = False
    try:
        sbom_path = evidence_dir / SBOM_REPORT
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))

        def unsafe_identity(value: Any) -> bool:
            if isinstance(value, str):
                return _PRIVATE_PATH.search(value) is not None or any(
                    marker in value for marker in _PROMPT_MARKERS
                )
            if isinstance(value, Mapping):
                return any(
                    unsafe_identity(key) or unsafe_identity(item) for key, item in value.items()
                )
            if isinstance(value, list):
                return any(unsafe_identity(item) for item in value)
            return False

        sbom_safe = isinstance(sbom, Mapping) and not unsafe_identity(sbom)
    except (KeyError, OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        sbom_safe = False
    return {
        "schema_version": OPSEC_SCHEMA,
        "passed": not forbidden and not private_hits and all(scans.values()) and sbom_safe,
        "tracked_file_count": len(tracked),
        "forbidden_tracked_artifacts": sorted(forbidden),
        "private_identity_hits": sorted(private_hits),
        "scans": scans,
        "sbom_safe": sbom_safe,
        "source_digest": content_hash(hashed),
    }


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
        "run_ids": [str(bundle["run_id"]) for bundle in bundles],
        "run_bundles": [dict(bundle) for bundle in bundles],
        "environment_limitations": [],
    }


def _revalidate_persisted_evidence(
    repository: Path,
    destination: Path,
    binding: Mapping[str, str],
    *,
    upstream: Mapping[str, Any],
    structural: Mapping[str, Any],
    suites: Mapping[str, Any],
    opsec: Mapping[str, Any],
    journey_checks: Mapping[str, bool],
    bundles: Sequence[Mapping[str, str]],
    journey_started: datetime,
    journey_finished: datetime,
) -> Mapping[str, str]:
    persisted_upstream = read_json(destination / UPSTREAM_REPORT, "GATE-12 upstream closure")
    regenerated_upstream = validate_upstream_closure(repository, destination.parent, binding)
    if persisted_upstream != upstream or regenerated_upstream != upstream:
        raise ValueError("the persisted upstream closure changed after validation")

    persisted_suites = read_json(destination / SUITE_REPORT, "GATE-12 full-suite report")
    if persisted_suites != suites or not validate_suite_report(persisted_suites):
        raise ValueError("the persisted full-suite report changed or failed validation")

    final_checks, final_bundles = validate_release_journey(repository, destination)
    if final_checks != journey_checks or tuple(final_bundles) != tuple(bundles):
        raise ValueError("the persisted release journey changed after validation")
    for bundle in final_bundles:
        normalized, _artifact = validated_run_bundle(
            destination,
            destination.parent,
            bundle,
            expected_binding=binding,
            not_before=journey_started,
            not_after=journey_finished,
        )
        if normalized["run_id"] != bundle["run_id"] or normalized["path"] != bundle["path"]:
            raise ValueError("a persisted GATE-12 run reference changed during final validation")

    persisted_structure = read_json(
        destination / STRUCTURAL_REPORT,
        "GATE-12 release structure",
    )
    final_structure = audit_release_structure(repository, binding)
    if persisted_structure != structural or final_structure != structural:
        raise ValueError("release execution changed the committed source or structure evidence")

    persisted_opsec = read_json(destination / OPSEC_REPORT, "GATE-12 OPSEC report")
    final_opsec = _opsec_report(repository, destination, persisted_suites)
    if (
        persisted_opsec != opsec
        or final_opsec != opsec
        or not validate_opsec_report(persisted_opsec)
    ):
        raise ValueError("the persisted security or OPSEC evidence changed after validation")
    return persisted_artifact_hashes(destination)


def _failure(issues: Sequence[object]) -> Gate12Outcome:
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
    return Gate12Outcome(
        status="failed",
        proofs=(),
        failure_reason=("GATE-12 failed checks: " + ", ".join(dict.fromkeys(safe)))[:1800],
    )


def run_gate_12(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate12Outcome:
    try:
        repository = _safe_directory_root(repository_root or Path.cwd(), "GATE-12 repository")
        destination = _safe_directory_root(evidence_dir, "GATE-12 evidence root")
    except (OSError, ValueError) as exc:
        return _failure((exc,))
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected:
        return _failure(("locked GATE-12 assertion set mismatch",))
    owned = (
        JOURNEY_REPORT,
        UPSTREAM_REPORT,
        STRUCTURAL_REPORT,
        SUITE_REPORT,
        OPSEC_REPORT,
        VERIFICATION_REPORT,
        SBOM_REPORT,
        "frontier",
        "operator",
    )
    if any((destination / name).exists() for name in owned):
        return _failure(("GATE-12 evidence directory contains stale owned artifacts",))

    issues: list[object] = []
    checks: dict[str, bool] = {}
    journey_checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    try:
        binding = _acceptance_binding()
        upstream = validate_upstream_closure(repository, destination.parent, binding)
        _write_json(destination / UPSTREAM_REPORT, upstream)
    except (OSError, RuntimeError, TypeError, ValueError, ReleaseReadinessValidationError) as exc:
        return _failure((exc,))

    try:
        structural = audit_release_structure(repository, binding)
        _write_json(destination / STRUCTURAL_REPORT, structural)
    except (OSError, RuntimeError, TypeError, ValueError, ReleaseReadinessValidationError) as exc:
        return _failure((exc,))
    structural_checks = structural.get("checks")
    if not isinstance(structural_checks, Mapping):
        return _failure(("the release structure check inventory is unavailable",))

    journey_started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    journey_finished = datetime.now(timezone.utc)
    if helper.get("passed") is not True:
        issues.append("fresh defense-frontier or production-browser journey failed")
    try:
        journey_checks, bundles = validate_release_journey(repository, destination)
        checks.update(journey_checks)
        for bundle in bundles:
            normalized, _artifact = validated_run_bundle(
                destination,
                destination.parent,
                bundle,
                expected_binding=binding,
                not_before=journey_started,
                not_after=journey_finished,
            )
            if normalized["run_id"] != bundle["run_id"] or normalized["path"] != bundle["path"]:
                raise ValueError("a GATE-12 run reference changed during validation")
    except (OSError, RuntimeError, TypeError, ValueError, ReleaseReadinessValidationError) as exc:
        issues.append(exc)

    journey = (
        read_json(destination / JOURNEY_REPORT, "GATE-12 release journey") if not issues else {}
    )
    try:
        suites = run_full_release_suites(
            repository,
            destination,
            upstream=upstream,
            journey=journey,
        )
        _write_json(destination / SUITE_REPORT, suites)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _failure((exc,))
    if not validate_suite_report(suites):
        issues.append("the complete Python, Rust, frontend, security, or E2E suite failed")
    opsec = _opsec_report(repository, destination, suites)
    _write_json(destination / OPSEC_REPORT, opsec)
    if not validate_opsec_report(opsec):
        issues.append("the tracked-tree security or OPSEC review failed")

    contract_suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="release-readiness-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=300,
    )
    if not exact_contract_suite(
        contract_suite,
        expected_count=_EXPECTED_CONTRACT_TEST_COUNT,
        expected_digest=_EXPECTED_CONTRACT_TESTS_SHA256,
    ):
        issues.append("the exact GATE-12 focused contract suite failed or drifted")

    artifact_hashes: Mapping[str, str] = {}
    if not issues:
        try:
            artifact_hashes = _revalidate_persisted_evidence(
                repository,
                destination,
                binding,
                upstream=upstream,
                structural=structural,
                suites=suites,
                opsec=opsec,
                journey_checks=journey_checks,
                bundles=bundles,
                journey_started=journey_started,
                journey_finished=journey_finished,
            )
        except (
            LookupError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            ReleaseReadinessValidationError,
        ) as exc:
            issues.append(exc)

    for name in (
        "readme_product_loop",
        "capability_classification",
        "complete_docs",
        "github_metadata",
        "clean_worktree",
        "rights_audit",
        "license_decision",
    ):
        checks[name] = structural_checks.get(name) is True
    checks["clean_package_install"] = (
        upstream.get("clean_package_install", {}).get("validated_reports") is True
    )
    checks["full_suites"] = validate_suite_report(suites)
    checks["security_opsec"] = validate_opsec_report(opsec)
    if set(checks) != CHECK_NAMES:
        issues.append("the GATE-12 semantic check inventory is incomplete")
    failed_checks = sorted(name for name, passed in checks.items() if not passed)
    if failed_checks:
        issues.append("unproven semantic checks: " + ", ".join(failed_checks))

    verification = {
        "schema_version": VERIFICATION_SCHEMA,
        "passed": not issues,
        "checks": checks,
        "helper": helper,
        "contract_suite": contract_suite,
        "upstream_report": UPSTREAM_REPORT,
        "structure_report": STRUCTURAL_REPORT,
        "suite_report": SUITE_REPORT,
        "opsec_report": OPSEC_REPORT,
        "artifact_hashes": dict(artifact_hashes),
        "run_bundles": [dict(bundle) for bundle in bundles],
        "started_at": journey_started.isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    try:
        _write_json(destination / VERIFICATION_REPORT, verification)
        if not issues:
            validate_verification_report(
                destination / VERIFICATION_REPORT,
                expected_bundles=bundles,
                expected_count=_EXPECTED_CONTRACT_TEST_COUNT,
                expected_digest=_EXPECTED_CONTRACT_TESTS_SHA256,
                not_before=journey_started,
                not_after=datetime.now(timezone.utc),
            )
    except (OSError, TypeError, ValueError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)
    proofs = tuple(
        _proof(
            assertion_id,
            kind,
            test_id,
            artifacts,
            bundles if attach_runs else (),
        )
        for assertion_id, (
            kind,
            _check,
            artifacts,
            test_id,
            attach_runs,
        ) in _EXPECTED_ASSERTIONS.items()
    )
    return Gate12Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = ["Gate12Outcome", "run_gate_12"]
