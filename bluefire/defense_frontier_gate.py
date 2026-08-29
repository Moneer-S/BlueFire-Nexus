"""Fail-closed release workflow for the GATE-04 defense frontier."""

from __future__ import annotations

import ctypes
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
from .defense_frontier import (
    COMPARISON_REPORT,
    DEFENSE_REPORT,
    HELPER_SCHEMA,
    JOURNEY_REPORT,
    REPORT_PATHS,
    STRUCTURAL_REPORT,
    _runtime_temp_parent,
)
from .defense_frontier_validation import (
    DefenseFrontierValidationError,
    validate_persisted_frontier,
)
from .product_acceptance_process import _execute_workflow
from .product_acceptance_run_bundle import acceptance_run_binding, validated_run_bundle
from .runner_bootstrap import current_architecture

VERIFICATION_REPORT = "gate04-verification-report.json"
VERIFICATION_SCHEMA = "bluefire.defense-frontier-verification.v1"
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_ACCEPTANCE_ENVIRONMENT = (
    "BLUEFIRE_ACCEPTANCE_ID",
    "BLUEFIRE_ACCEPTANCE_GATE_ID",
    "BLUEFIRE_ACCEPTANCE_CONTRACT_SHA256",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_COMMIT",
    "BLUEFIRE_ACCEPTANCE_REPOSITORY_TREE",
    "BLUEFIRE_ACCEPTANCE_RELEASE",
)
_CONTRACT_TESTS = (
    "tests_platform/test_defense_frontier_validation.py",
    "tests_platform/test_comparison.py",
)
_EXPECTED_ASSERTIONS: Mapping[str, tuple[str, str, tuple[str, ...], str, bool]] = {
    "GATE-04-CANONICAL-BLOCK": (
        "dynamic",
        "canonical_block",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.canonical-block.native-execute.v1",
        True,
    ),
    "GATE-04-INDEPENDENT-OBSERVATION": (
        "dynamic",
        "independent_observation",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.independent-observation.filesystem.v1",
        True,
    ),
    "GATE-04-STRUCTURED-PLANNER-STATE": (
        "dynamic",
        "structured_planner_state",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.structured-planner-state.bound.v1",
        True,
    ),
    "GATE-04-VALID-ALTERNATE-SELECTION": (
        "dynamic",
        "valid_alternate_selection",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.valid-alternate.registered-edge.v1",
        True,
    ),
    "GATE-04-POLICY-APPROVAL": (
        "dynamic",
        "policy_approval",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.policy-approval.fresh-claimed.v1",
        True,
    ),
    "GATE-04-ALTERNATE-OBJECTIVE": (
        "dynamic",
        "alternate_objective",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.alternate-objective.local-export.v1",
        True,
    ),
    "GATE-04-EVIDENCE-DETECTION-DELTA": (
        "dynamic",
        "evidence_detection_delta",
        (JOURNEY_REPORT, COMPARISON_REPORT, VERIFICATION_REPORT),
        "GATE-04.evidence-detection-delta.observed.v1",
        True,
    ),
    "GATE-04-DEFENSE-CHANGE": (
        "dynamic",
        "defense_change",
        (DEFENSE_REPORT, VERIFICATION_REPORT),
        "GATE-04.defense-change.profile-control.v1",
        True,
    ),
    "GATE-04-REPLAY": (
        "dynamic",
        "replay",
        (JOURNEY_REPORT, DEFENSE_REPORT, VERIFICATION_REPORT),
        "GATE-04.replay.controlled-native.v1",
        True,
    ),
    "GATE-04-COMPARE-EXPLANATION": (
        "dynamic",
        "compare_explanation",
        (COMPARISON_REPORT, VERIFICATION_REPORT),
        "GATE-04.compare.frontier-explanation.v1",
        True,
    ),
    "GATE-04-DETERMINISTIC-PROVIDER": (
        "dynamic",
        "deterministic_provider",
        (JOURNEY_REPORT, VERIFICATION_REPORT),
        "GATE-04.provider.deterministic-offline.v1",
        True,
    ),
    "GATE-04-REAL-PROVIDER-CONTRACT": (
        "structural",
        "real_provider_contract",
        (STRUCTURAL_REPORT, VERIFICATION_REPORT),
        "GATE-04.provider.openai-compatible-contract.v1",
        False,
    ),
}


@dataclass(frozen=True)
class Gate04Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _isolated_python_environment(
    temporary_directory: Path,
    *,
    passthrough: Sequence[str] = (),
) -> dict[str, str]:
    """Build the minimum environment required by an isolated Python child."""

    temporary = os.fspath(temporary_directory.resolve(strict=True))
    environment = {
        name: value
        for name in passthrough
        if isinstance((value := os.environ.get(name)), str)
        and 0 < len(value) <= 4_096
        and "\0" not in value
    }
    if os.name == "nt":
        buffer = ctypes.create_unicode_buffer(32_768)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_windows_directory = kernel32.GetWindowsDirectoryW
        get_windows_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint)
        get_windows_directory.restype = ctypes.c_uint
        length = get_windows_directory(buffer, len(buffer))
        if length == 0 or length >= len(buffer):
            raise RuntimeError("Windows system root is unavailable")
        system_root = Path(buffer.value).resolve(strict=True)
        system_directory = (system_root / "System32").resolve(strict=True)
        if not system_root.is_dir() or not system_directory.is_dir():
            raise RuntimeError("Windows system directories are unavailable")
        environment.update(
            {
                "SystemRoot": os.fspath(system_root),
                "WINDIR": os.fspath(system_root),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "PATH": os.fspath(system_directory),
            }
        )
    else:
        environment.update(
            {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
            }
        )
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "TEMP": temporary,
            "TMP": temporary,
            "TMPDIR": temporary,
        }
    )
    return environment


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    if len(payload) > _MAX_REPORT_BYTES or path.exists() or not path.parent.is_dir():
        raise ValueError("GATE-04 verification report path is unsafe")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("GATE-04 verification report path is unsafe")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("verification write made no progress")
            offset += written
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = bytearray()
        while len(observed) <= _MAX_REPORT_BYTES:
            block = os.read(descriptor, min(64 * 1024, _MAX_REPORT_BYTES + 1 - len(observed)))
            if not block:
                break
            observed.extend(block)
        current = os.fstat(descriptor)
        if (
            bytes(observed) != payload
            or (current.st_dev, current.st_ino) != identity
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_size != len(payload)
        ):
            raise ValueError("GATE-04 verification report changed during publication")
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            metadata = path.lstat()
            if identity == (metadata.st_dev, metadata.st_ino) and not path.is_symlink():
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _run_bounded_helper_process(
    command: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[int, bytes]:
    stdout_path = Path(environment["TMP"]) / "gate04-helper.stdout"
    stderr_path = Path(environment["TMP"]) / "gate04-helper.stderr"
    outcome = _execute_workflow(
        command,
        repository=repository,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    if outcome.exit_code is None or outcome.failure_reason is not None:
        raise OSError("GATE-04 helper process containment failed")
    if stdout_path.stat().st_size > 8_192 or stderr_path.stat().st_size > 8_192:
        raise ValueError("GATE-04 helper output exceeded its byte bound")
    return outcome.exit_code, stdout_path.read_bytes()


def _run_helper(repository: Path, evidence_dir: Path) -> Mapping[str, Any]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        os.fspath(repository / "tools" / "run_defense_frontier_journey.py"),
        "--repository",
        os.fspath(repository),
        "--evidence-dir",
        os.fspath(evidence_dir),
    ]
    reported = ["{python}", "tools/run_defense_frontier_journey.py", "{fixed-arguments}"]
    try:
        with tempfile.TemporaryDirectory(prefix=".gate04-helper-", dir=evidence_dir) as temporary:
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
                timeout_seconds=780,
            )
            summary = json.loads(output.decode("utf-8"))
        valid = (
            isinstance(summary, Mapping)
            and set(summary) == {"schema_version", "status", "reports", "run_count"}
            and summary.get("schema_version") == HELPER_SCHEMA
            and summary.get("status") == "passed"
            and summary.get("reports") == list(REPORT_PATHS)
            and summary.get("run_count") == 3
        )
        return {
            "passed": returncode == 0 and valid,
            "exit_code": returncode,
            "command": reported,
            "protocol_valid": valid,
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
            "failure_type": type(exc).__name__,
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
    if values["gate_id"] != "GATE-04" or values["release"] not in {"true", "false"}:
        raise ValueError("GATE-04 acceptance binding is invalid")
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


def _bounded_issue(value: object) -> str:
    raw = str(value)
    absolute_path = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
    if absolute_path.search(raw):
        return "validation failure [private-path-redacted]"
    text = " ".join(raw.split())
    return text[:240] if text else "unknown validation failure"


def _failure(issues: Sequence[object]) -> Gate04Outcome:
    unique = list(dict.fromkeys(_bounded_issue(issue) for issue in issues))
    reason = "GATE-04 failed checks: " + ", ".join(unique)
    return Gate04Outcome(status="failed", proofs=(), failure_reason=reason[:1800])


def run_gate_04(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate04Outcome:
    """Run the exact GATE-04 workflow and emit proofs only as one set."""

    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    contract_assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    expected = {assertion_id: row[0] for assertion_id, row in _EXPECTED_ASSERTIONS.items()}
    if contract_assertions != expected:
        return _failure(("locked GATE-04 assertion set mismatch",))
    if any((destination / name).exists() for name in (*REPORT_PATHS, VERIFICATION_REPORT)):
        return _failure(("GATE-04 evidence directory contains stale owned reports",))

    started = datetime.now(timezone.utc)
    helper = _run_helper(repository, destination)
    finished = datetime.now(timezone.utc)
    suite = _run_pytest_suite(
        repository,
        _runtime_temp_parent(),
        suite_id="defense-frontier-contracts",
        tests=_CONTRACT_TESTS,
        timeout_seconds=240,
    )
    issues: list[object] = []
    checks: Mapping[str, bool] = {}
    bundles: tuple[Mapping[str, str], ...] = ()
    if helper.get("passed") is not True:
        issues.append("defense frontier helper failed or returned an invalid protocol")
    if suite.get("passed") is not True:
        issues.append("defense frontier focused regression suite failed or skipped")
    try:
        checks, bundles = validate_persisted_frontier(repository, destination)
        if set(checks) != {row[1] for row in _EXPECTED_ASSERTIONS.values()} or not all(
            checks.values()
        ):
            raise ValueError("GATE-04 semantic check inventory is incomplete")
    except (OSError, TypeError, ValueError, DefenseFrontierValidationError) as exc:
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
                raise ValueError("a GATE-04 bundle reference changed during validation")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        issues.append(exc)

    if issues:
        return _failure(issues)

    try:
        final_checks, final_bundles = validate_persisted_frontier(repository, destination)
        if final_checks != checks or final_bundles != bundles:
            raise ValueError("GATE-04 evidence changed after verification")
    except (OSError, TypeError, ValueError, DefenseFrontierValidationError) as exc:
        return _failure((exc,))

    proofs: list[Mapping[str, Any]] = []
    for assertion_id, (
        kind,
        check_name,
        artifacts,
        test_id,
        attach_runs,
    ) in _EXPECTED_ASSERTIONS.items():
        if checks.get(check_name) is not True:
            return _failure((f"GATE-04 failed check: {assertion_id}",))
        proofs.append(
            _proof(
                assertion_id,
                kind,
                test_id,
                artifacts,
                bundles if attach_runs else (),
            )
        )
    if len(proofs) != 12 or len({proof["test_id"] for proof in proofs}) != 12:
        return _failure(("GATE-04 proof cardinality is not exact",))
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
    return Gate04Outcome(status="passed", proofs=tuple(proofs), failure_reason=None)


__all__ = ["Gate04Outcome", "run_gate_04"]
