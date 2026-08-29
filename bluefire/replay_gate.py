"""Fail-closed release workflow for GATE-06 materialized replay."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .architecture_gate import _run_pytest_suite
from .defense_frontier import _runtime_temp_parent
from .defense_frontier_gate import _isolated_python_environment, _run_bounded_helper_process
from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .replay_gate_validation import (
    CHECK_NAMES,
    ReplayGateValidationError,
    validate_persisted_replay_gate,
)
from .replay_journey import (
    COMPARISON_REPORT,
    CORRUPTION_REPORT,
    HELPER_SCHEMA,
    JOURNEY_REPORT,
    REPORT_PATHS,
    _write_json,
)
from .runner_bootstrap import current_architecture

VERIFICATION_REPORT = "gate06-verification-report.json"
VERIFICATION_SCHEMA = "bluefire.replay-gate-verification.v1"
_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
)
_CONTRACT_TESTS = (
    "tests_platform/test_replay_selection.py",
    "tests_platform/test_comparison.py",
    "tests_platform/test_replay_gate.py",
)
_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str]] = {
    "GATE-06-CHECKPOINT-INTEGRITY": (
        "structural",
        "checkpoint_integrity",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.checkpoint.content-addressed-authority.v1",
    ),
    "GATE-06-MATERIALIZED-STATE": (
        "dynamic",
        "materialized_state",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.material.prefix-recreation.v1",
    ),
    "GATE-06-SCOPE-CLEANUP-BINDING": (
        "dynamic",
        "scope_cleanup_binding",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.restore.scope-cleanup.v1",
    ),
    "GATE-06-APPROVAL-REGENERATION": (
        "dynamic",
        "approval_regeneration",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.approval.fresh-candidates.v1",
    ),
    "GATE-06-CORRUPTION-REFUSAL": (
        "dynamic",
        "corruption_refusal",
        (CORRUPTION_REPORT, VERIFICATION_REPORT),
        "GATE-06.corruption.pre-dispatch-refusal.v1",
    ),
    "GATE-06-EXACT-REPLAY": (
        "dynamic",
        "exact_replay",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.exact-from-node.v1",
    ),
    "GATE-06-NODE-RESTART": (
        "dynamic",
        "node_restart",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.state-dependent-node.v1",
    ),
    "GATE-06-PARAMETER-OVERRIDE": (
        "dynamic",
        "parameter_override",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.typed-parameter.v1",
    ),
    "GATE-06-ACTION-SUBSTITUTION": (
        "dynamic",
        "action_substitution",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.compatible-action.v1",
    ),
    "GATE-06-AUTONOMY-CHANGE": (
        "dynamic",
        "autonomy_change",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.autonomy-change.v1",
    ),
    "GATE-06-PROFILE-CHANGE": (
        "dynamic",
        "profile_change",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.compatible-profile.v1",
    ),
    "GATE-06-DEFENSE-METADATA": (
        "dynamic",
        "defense_metadata",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-06.replay.defense-lineage.v1",
    ),
    "GATE-06-COMPARISON-DIMENSIONS": (
        "dynamic",
        "comparison_dimensions",
        (COMPARISON_REPORT, VERIFICATION_REPORT),
        "GATE-06.comparison.eight-dimensions.v1",
    ),
}


@dataclass(frozen=True)
class Gate06Outcome:
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
        os.fspath(repository / "tools" / "run_replay_gate_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_replay_gate_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate06-helper-", dir=evidence_dir) as temporary:
            temporary_root = Path(temporary)
            environment = _isolated_python_environment(
                temporary_root,
                passthrough=_ACCEPTANCE_ENVIRONMENT,
            )
            isolated_home = temporary_root / "home"
            isolated_local = isolated_home / "AppData" / "Local"
            isolated_roaming = isolated_home / "AppData" / "Roaming"
            isolated_local.mkdir(parents=True)
            isolated_roaming.mkdir(parents=True)
            environment.update(
                {
                    "HOME": os.fspath(isolated_home),
                    "USERPROFILE": os.fspath(isolated_home),
                    "LOCALAPPDATA": os.fspath(isolated_local),
                    "APPDATA": os.fspath(isolated_roaming),
                }
            )
            environment["PROCESSOR_ARCHITECTURE"] = {
                "x86_64": "AMD64",
                "aarch64": "ARM64",
            }[current_architecture()]
            returncode, output = _run_bounded_helper_process(
                command,
                repository=repository,
                environment=environment,
                timeout_seconds=420,
            )
            summary = json.loads(output.decode("utf-8"))
        valid = (
            isinstance(summary, Mapping)
            and set(summary) == {"schema_version", "status", "reports", "run_count"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("reports") == list(REPORT_PATHS)
            and summary.get("run_count") == 4
        )
        return {
            "passed": returncode == 0 and valid,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": valid,
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
    if values["gate_id"] != "GATE-06" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-06 acceptance binding is invalid")
    return dict(acceptance_run_binding(**values))


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


def _failure(issues: Sequence[object]) -> Gate06Outcome:
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
    reason = "GATE-06 failed checks: " + ", ".join(dict.fromkeys(safe))
    return Gate06Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def run_gate_06(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate06Outcome:
    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected:
        return _failure(("locked GATE-06 assertion set mismatch",))
    if any((destination / name).exists() for name in (*REPORT_PATHS, VERIFICATION_REPORT)):
        return _failure(("GATE-06 evidence directory contains stale owned reports",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="materialized-replay-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=300,
    )
    issues: list[object] = []
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    if helper.get("passed") is not True:
        issues.append("replay helper failed or returned an invalid protocol")
    if suite.get("passed") is not True:
        issues.append("replay focused regression suite failed or skipped")
    try:
        checks, bundles = validate_persisted_replay_gate(repository, destination)
        if set(checks) != CHECK_NAMES or not all(checks.values()):
            raise ValueError("GATE-06 semantic check inventory is incomplete")
    except (OSError, TypeError, ValueError, ReplayGateValidationError) as exc:
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
                raise ValueError("a GATE-06 run bundle reference changed during validation")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        issues.append(exc)
    if issues:
        return _failure(issues)
    try:
        final_checks, final_bundles = validate_persisted_replay_gate(repository, destination)
        if final_checks != checks or final_bundles != bundles:
            raise ValueError("GATE-06 evidence changed after verification")
    except (OSError, TypeError, ValueError, ReplayGateValidationError) as exc:
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
    if len(proofs) != 13 or len({proof["test_id"] for proof in proofs}) != 13:
        return _failure(("GATE-06 proof cardinality is not exact",))
    return Gate06Outcome(status="passed", proofs=proofs, failure_reason=None)


__all__ = ["Gate06Outcome", "VERIFICATION_REPORT", "run_gate_06"]
