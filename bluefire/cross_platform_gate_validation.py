"""Independent semantic validation for the GATE-11 platform proof set."""

from __future__ import annotations

import json
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast

from . import cross_platform_linux_cleanup_validation as linux_cleanup
from .cross_platform_artifact_validation import (
    CrossPlatformArtifactValidationError,
    linux_wheelhouse_unavailable,
    validate_gate_verification_document,
    validate_linux_repository_runner,
    validate_macos_structural_contract,
    validate_transport_recovery_report,
    validate_windows_wheel,
)
from .cross_platform_cancellation_validation import (
    FreshCancellationValidationError,
    run_fresh_cancellation_validation,
    validate_cancellation_report,
)
from .cross_platform_process_proof import (
    ProcessProofError,
    validate_posix_watchdog_containment_proof,
)
from .cross_platform_readiness import WSL_DISTRIBUTION_ID, probe_wsl2
from .cross_platform_run_validation import validate_persisted_run
from .product_acceptance_run_bundle import validated_run_bundle
from .util import canonical_json_bytes, content_hash

WINDOWS_REPORT = "windows-packaged-execute.json"
LINUX_REPORT = "linux-container-execute.json"
CANCELLATION_REPORT = "process-tree-cancellation.json"
RECEIVER_REPORT = "network-receiver.json"
RECOVERY_REPORT = "transport-recovery.json"
READINESS_REPORT = "platform-readiness.json"
MACOS_REPORT = "macos-contract.json"
CLASSIFICATION_REPORT = "proof-classification.json"
VERIFICATION_REPORT = "gate11-verification-report.json"

REPORT_PATHS = (
    WINDOWS_REPORT,
    LINUX_REPORT,
    CANCELLATION_REPORT,
    RECEIVER_REPORT,
    RECOVERY_REPORT,
    READINESS_REPORT,
    MACOS_REPORT,
    CLASSIFICATION_REPORT,
)

CHECK_NAMES = frozenset(
    {
        "windows_packaged_execute",
        "linux_container_execute",
        "process_tree_cancel",
        "network_receiver",
        "transport_recovery",
        "platform_readiness",
        "macos_contract",
        "proof_classification",
    }
)

ASSERTION_REPORTS: tuple[tuple[str, str, str], ...] = (
    ("GATE-11-WINDOWS-PACKAGED-EXECUTE", "dynamic", WINDOWS_REPORT),
    ("GATE-11-LINUX-CONTAINER-EXECUTE", "dynamic", LINUX_REPORT),
    ("GATE-11-PROCESS-TREE-CANCEL", "dynamic", CANCELLATION_REPORT),
    ("GATE-11-NETWORK-RECEIVER", "dynamic", RECEIVER_REPORT),
    ("GATE-11-TRANSPORT-RECOVERY", "dynamic", RECOVERY_REPORT),
    ("GATE-11-PLATFORM-READINESS", "dynamic", READINESS_REPORT),
    ("GATE-11-MACOS-CONTRACT", "structural", MACOS_REPORT),
    ("GATE-11-PROOF-CLASSIFICATION", "structural", CLASSIFICATION_REPORT),
)

CLASSIFICATION_LIMITATIONS = (
    "macOS evidence is structural because no macOS host is available.",
    (
        "The authenticated receiver is limited to a distinct same-host process on literal "
        "loopback; it is not LAN or remote transport."
    ),
    (
        "The disposable WSL2 execution distribution is stream-cloned from a dedicated "
        "persistent Gate 11 base; its registration and storage are removed after each run."
    ),
    (
        "The process-tree cancellation proof is Windows-specific and exercises one "
        "zero-parameter packaged Rust witness action; it is not a general process launcher."
    ),
)
LINUX_UNAVAILABLE_REASON = (
    "GATE-11 Linux/container dynamic runtime unavailable: the dedicated WSL2 base "
    "distribution BlueFire-Gate11-Base-v1 is unavailable"
)
LINUX_DEPENDENCIES_UNAVAILABLE_REASON = (
    "GATE-11 Linux dependency runtime unavailable: the fixed offline CPython 3.12 "
    "wheelhouse is unavailable or incompatible"
)

_SCHEMAS = {
    WINDOWS_REPORT: "bluefire.cross-platform-windows-execute.v1",
    LINUX_REPORT: "bluefire.cross-platform-linux-execute.v1",
    CANCELLATION_REPORT: "bluefire.cross-platform-process-cancellation.v2",
    RECEIVER_REPORT: "bluefire.cross-platform-network-receiver.v1",
    RECOVERY_REPORT: "bluefire.cross-platform-transport-recovery.v1",
    READINESS_REPORT: "bluefire.cross-platform-readiness.v1",
    MACOS_REPORT: "bluefire.cross-platform-macos-contract.v1",
    CLASSIFICATION_REPORT: "bluefire.cross-platform-proof-classification.v1",
}
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK_ID = re.compile(r"^execute-[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_REPORT_BYTES = 2 * 1024 * 1024
_PRIVATE_PATH = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
_FILE_URL = re.compile(r"file:(?://+|\\\\)", re.IGNORECASE)

_WINDOWS_ENVIRONMENT = "disposable"
_LINUX_ENVIRONMENT = "disposable-wsl2-distribution"


class CrossPlatformGateValidationError(ValueError):
    """Raised when persisted platform evidence cannot prove the locked claim."""


class LinuxRuntimeUnavailableError(CrossPlatformGateValidationError):
    """Typed failure for the one allowed-but-still-blocking Linux absence state."""


def _is_link_or_reparse(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CrossPlatformGateValidationError("a Gate 11 report contains duplicate keys")
        value[key] = item
    return value


def _read_report(root: Path, name: str) -> dict[str, Any]:
    path = root / name
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_REPORT_BYTES
        ):
            raise CrossPlatformGateValidationError(f"{name} is not a safe bounded report")
        payload = path.read_bytes()
        after = path.lstat()
    except CrossPlatformGateValidationError:
        raise
    except OSError as exc:
        raise CrossPlatformGateValidationError(f"{name} is unavailable") from exc
    identity = lambda row: (  # noqa: E731 - compact immutable identity projection
        int(row.st_dev),
        int(row.st_ino),
        int(row.st_size),
        int(row.st_mtime_ns),
        int(row.st_nlink),
    )
    if identity(before) != identity(after) or len(payload) != before.st_size:
        raise CrossPlatformGateValidationError(f"{name} changed while it was read")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CrossPlatformGateValidationError(f"{name} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CrossPlatformGateValidationError(f"{name} must contain one JSON object")
    expected = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    if payload != expected:
        raise CrossPlatformGateValidationError(f"{name} is not canonical Gate 11 JSON")
    return value


def _canonical_wsl_facts(value: Any, *, label: str) -> Mapping[str, Any]:
    row = _exact(
        value,
        {"provider", "probe_state", "configured", "distribution_id", "version", "facts_digest"},
        label,
    )
    state = row.get("probe_state")
    expected_pair = {
        "ready": (True, "2"),
        "absent": (False, None),
        "incompatible": (True, "1"),
        "indeterminate": (None, None),
    }.get(str(state))
    facts = {key: row.get(key) for key in row if key != "facts_digest"}
    if (
        expected_pair is None
        or row.get("provider") != "wsl2"
        or row.get("distribution_id") != WSL_DISTRIBUTION_ID
        or (row.get("configured"), row.get("version")) != expected_pair
        or row.get("facts_digest") != content_hash(facts)
    ):
        raise CrossPlatformGateValidationError(f"{label} is not a canonical WSL fact set")
    return row


def _reprobe_wsl() -> Mapping[str, Any]:
    try:
        return _canonical_wsl_facts(probe_wsl2(), label="independent WSL reprobe")
    except (OSError, ValueError) as exc:
        raise CrossPlatformGateValidationError(
            "the fixed WSL boundary could not be re-probed"
        ) from exc


def _path_free(value: Any) -> bool:
    if isinstance(value, Mapping):
        return all(_path_free(key) and _path_free(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_path_free(item) for item in value)
    return not isinstance(value, str) or (
        _PRIVATE_PATH.search(value) is None and _FILE_URL.search(value) is None
    )


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CrossPlatformGateValidationError(f"{label} fields do not match the schema")
    return value


def _schema(value: Mapping[str, Any], name: str, keys: set[str]) -> None:
    _exact(value, keys, name)
    if value.get("schema_version") != _SCHEMAS[name]:
        raise CrossPlatformGateValidationError(f"{name} schema is unsupported")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise CrossPlatformGateValidationError(f"{label} is not a SHA-256 binding")
    return value


def _run_reference(value: Any, label: str) -> Mapping[str, str]:
    row = _exact(value, {"run_id", "path"}, label)
    run_id = row.get("run_id")
    path = row.get("path")
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None or path != f"runs/{run_id}":
        raise CrossPlatformGateValidationError(f"{label} is not a canonical run reference")
    return {"run_id": run_id, "path": path}


def _receipt_run_reference(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise CrossPlatformGateValidationError("validated run reference is invalid")
    return _run_reference(
        {"run_id": value.get("run_id"), "path": value.get("path")},
        "validated run reference",
    )


def _runner(value: Any, expected: Mapping[str, Any], platform: str) -> Mapping[str, Any]:
    row = _exact(value, set(expected), f"{platform} runner")
    if (
        dict(row) != dict(expected)
        or row.get("runner_id") != "bluefire-rust-runner.v1"
        or not isinstance(row.get("runner_version"), str)
        or _VERSION.fullmatch(str(row["runner_version"])) is None
    ):
        raise CrossPlatformGateValidationError(
            f"{platform} report does not match independently verified runner resources"
        )
    _digest(row.get("binary_sha256"), f"{platform} runner digest")
    _digest(row.get("manifest_sha256"), f"{platform} manifest digest")
    return row


def _execution(value: Any, label: str) -> Mapping[str, Any]:
    row = _exact(
        value,
        {
            "run_id",
            "status",
            "objective_reached",
            "cleanup_success",
            "outstanding_receipt_count",
            "step_count",
        },
        label,
    )
    if (
        not isinstance(row.get("run_id"), str)
        or _RUN_ID.fullmatch(str(row["run_id"])) is None
        or row.get("status") != "completed"
        or row.get("objective_reached") is not True
        or row.get("cleanup_success") is not True
        or row.get("outstanding_receipt_count") != 0
        or type(row.get("step_count")) is not int
        or int(row["step_count"]) <= 0
    ):
        raise CrossPlatformGateValidationError(f"{label} did not complete and reconcile")
    return row


def _windows(
    value: Mapping[str, Any], runner: Mapping[str, Any]
) -> tuple[Mapping[str, str], Mapping[str, Any]]:
    _schema(
        value,
        WINDOWS_REPORT,
        {
            "schema_version",
            "passed",
            "proof_kind",
            "platform",
            "environment_type",
            "runner",
            "execution",
            "run_bundle",
        },
    )
    if (
        value.get("passed") is not True
        or value.get("proof_kind") != "dynamic"
        or value.get("platform") != "windows"
        or value.get("environment_type") != _WINDOWS_ENVIRONMENT
    ):
        raise CrossPlatformGateValidationError("Windows packaged Execute classification is invalid")
    _runner(value.get("runner"), runner, "windows")
    execution = _execution(value.get("execution"), "Windows packaged execution")
    bundle = _run_reference(value.get("run_bundle"), "Windows packaged run bundle")
    if execution["run_id"] != bundle["run_id"]:
        raise CrossPlatformGateValidationError("Windows execution and run bundle do not match")
    return bundle, execution


def _linux_boundary(
    value: Any,
    *,
    fresh_wsl: Mapping[str, Any],
    ready: bool,
    dependency: bool = False,
    repository: Path | None = None,
) -> Mapping[str, Any]:
    fact_keys = set("provider probe_state configured distribution_id version facts_digest".split())
    if not ready:
        row = _exact(
            value,
            fact_keys
            | {
                "source_distribution_persistent",
                "execution_distribution_disposable",
                "execution_distribution_created",
            },
            "unavailable WSL boundary",
        )
        if (
            {key: row.get(key) for key in fact_keys} != dict(fresh_wsl)
            or row.get("probe_state")
            not in ({"ready"} if dependency else {"absent", "incompatible"})
            or row.get("source_distribution_persistent")
            is not (fresh_wsl.get("configured") is True)
            or row.get("execution_distribution_disposable") is not True
            or row.get("execution_distribution_created") is not False
        ):
            raise CrossPlatformGateValidationError("the unavailable WSL boundary is not exact")
        return row
    source = repository or Path(__file__).resolve().parents[1]
    try:
        return cast(
            Mapping[str, Any],
            linux_cleanup.validate_linux_cleanup_boundary(source, value, fresh_wsl=fresh_wsl),
        )
    except (OSError, linux_cleanup.LinuxCleanupValidationError) as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc


def _linux_receiver(value: Any) -> Mapping[str, Any]:
    row = _exact(
        value,
        {"process_id", "process_distinct", "process_exited", "summary", "transfer"},
        "Linux receiver proof",
    )
    summary = _exact(
        row.get("summary"),
        set(
            "schema_version reason connections_handled challenges_issued requests_accepted "
            "requests_refused".split()
        ),
        "Linux receiver summary",
    )
    transfer = _exact(
        row.get("transfer"),
        set(
            "run_id step_id runner_task_id authenticated sha256 bytes destination_process_id".split()
        ),
        "Linux transfer",
    )
    byte_count = transfer.get("bytes")
    process_id = row.get("process_id")
    if (
        type(process_id) is not int
        or int(process_id) <= 0
        or row.get("process_distinct") is not True
        or row.get("process_exited") is not True
        or summary
        != {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
        or not isinstance(transfer.get("run_id"), str)
        or _RUN_ID.fullmatch(str(transfer["run_id"])) is None
        or transfer.get("step_id") != "internal_transport"
        or not isinstance(transfer.get("runner_task_id"), str)
        or _TASK_ID.fullmatch(str(transfer["runner_task_id"])) is None
        or transfer.get("authenticated") is not True
        or not isinstance(transfer.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(transfer["sha256"])) is None
        or type(byte_count) is not int
        or not 1 <= int(byte_count) <= 5 * 1024 * 1024
        or transfer.get("destination_process_id") != process_id
    ):
        raise CrossPlatformGateValidationError("Linux receiver transfer proof is invalid")
    return row


def _linux(
    value: Mapping[str, Any],
    runner: Mapping[str, Any],
    fresh_wsl: Mapping[str, Any],
    *,
    dependency_unavailable: bool = False,
    repository: Path | None = None,
) -> tuple[Mapping[str, str], Mapping[str, Any], Mapping[str, Any]]:
    dependency_report = "dependencies" in value
    _schema(
        value,
        LINUX_REPORT,
        {
            "schema_version",
            "passed",
            "proof_kind",
            "platform",
            "environment_type",
            "availability",
            "boundary",
            "runner",
            "watchdog_containment",
            "execution",
            "receiver",
            "run_bundle",
        }
        | ({"dependencies"} if dependency_report else set()),
    )
    availability = _exact(value.get("availability"), {"state", "code"}, "Linux availability")
    if (
        value.get("proof_kind") != "dynamic"
        or value.get("platform") != "linux"
        or value.get("environment_type") != _LINUX_ENVIRONMENT
    ):
        raise CrossPlatformGateValidationError("Linux Execute classification is invalid")
    if value.get("passed") is False:
        if dependency_report:
            expected_dependencies = [
                {"distribution": "cffi", "required": "==2.1.1", "observed_version": None},
                {"distribution": "cryptography", "required": ">=50,<51", "observed_version": None},
                {"distribution": "pycparser", "required": "==3.0", "observed_version": None},
                {"distribution": "PyNaCl", "required": ">=1.5,<2", "observed_version": None},
                {"distribution": "PyYAML", "required": ">=6.0.1,<7", "observed_version": None},
            ]
            if (
                dict(availability)
                != {"state": "unavailable", "code": "linux_dependencies_unavailable"}
                or fresh_wsl.get("probe_state") != "ready"
                or not dependency_unavailable
                or value.get("dependencies") != expected_dependencies
                or any(
                    value.get(key) is not None
                    for key in (
                        "runner",
                        "watchdog_containment",
                        "execution",
                        "receiver",
                        "run_bundle",
                    )
                )
            ):
                raise CrossPlatformGateValidationError(
                    "Linux dependency unavailability is malformed"
                )
            _linux_boundary(
                value.get("boundary"), fresh_wsl=fresh_wsl, ready=False, dependency=True
            )
            raise LinuxRuntimeUnavailableError(LINUX_DEPENDENCIES_UNAVAILABLE_REASON)
        expected_code = {
            "absent": "wsl_distribution_absent",
            "incompatible": "wsl_distribution_not_v2",
        }.get(str(fresh_wsl.get("probe_state")))
        if (
            expected_code is None
            or dict(availability) != {"state": "unavailable", "code": expected_code}
            or any(
                value.get(key) is not None
                for key in (
                    "runner",
                    "watchdog_containment",
                    "execution",
                    "receiver",
                    "run_bundle",
                )
            )
        ):
            raise CrossPlatformGateValidationError("Linux unavailable evidence is malformed")
        _linux_boundary(value.get("boundary"), fresh_wsl=fresh_wsl, ready=False)
        raise LinuxRuntimeUnavailableError(LINUX_UNAVAILABLE_REASON)
    if value.get("passed") is not True or dict(availability) != {"state": "ready", "code": None}:
        raise CrossPlatformGateValidationError("Linux Execute did not reach dynamic readiness")
    _linux_boundary(value.get("boundary"), fresh_wsl=fresh_wsl, ready=True, repository=repository)
    _runner(value.get("runner"), runner, "linux")
    try:
        validate_posix_watchdog_containment_proof(value.get("watchdog_containment"))
    except ProcessProofError as exc:
        raise CrossPlatformGateValidationError(
            "Linux watchdog containment proof is invalid"
        ) from exc
    receiver = _linux_receiver(value.get("receiver"))
    execution = _execution(value.get("execution"), "Linux disposable execution")
    bundle = _run_reference(value.get("run_bundle"), "Linux disposable run bundle")
    if (
        execution["run_id"] != bundle["run_id"]
        or receiver["transfer"]["run_id"] != execution["run_id"]
    ):
        raise CrossPlatformGateValidationError("Linux execution and run bundle do not match")
    return bundle, execution, receiver


def validate_linux_typed_unavailable_report(
    evidence_dir: Path, *, repository: Path | None = None
) -> str:
    """Return one stable reason only for an independently proven Linux blocker."""

    root = evidence_dir.resolve(strict=True)
    if {item.name for item in root.iterdir()} != {LINUX_REPORT}:
        raise CrossPlatformGateValidationError(
            "typed Linux unavailability retained non-Linux evidence"
        )
    fresh_wsl = _reprobe_wsl()
    source = (repository or Path(__file__).resolve().parents[1]).resolve(strict=True)
    try:
        dependency_unavailable = linux_wheelhouse_unavailable(source)
    except CrossPlatformArtifactValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc
    try:
        _linux(
            _read_report(root, LINUX_REPORT),
            {},
            fresh_wsl,
            dependency_unavailable=dependency_unavailable,
            repository=source,
        )
    except LinuxRuntimeUnavailableError as exc:
        return str(exc)
    raise CrossPlatformGateValidationError("Linux report did not declare typed unavailability")


def validate_linux_unavailable_report(evidence_dir: Path) -> str:
    """Compatibility wrapper for both exact typed Linux-unavailable states."""

    return validate_linux_typed_unavailable_report(evidence_dir)


def _cancellation(
    value: Mapping[str, Any],
    windows_runner: Mapping[str, Any],
    *,
    fresh_proof_factory: Callable[[Mapping[str, Any]], object] | None = None,
) -> None:
    try:
        validate_cancellation_report(
            value,
            windows_runner,
            fresh_proof_factory=fresh_proof_factory,
        )
    except FreshCancellationValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc


def _receiver(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _schema(
        value,
        RECEIVER_REPORT,
        {"schema_version", "passed", "proof_kind", "platform", "boundary", "receiver", "transfer"},
    )
    receiver = _exact(
        value.get("receiver"),
        set(
            "host mode process_id process_distinct process_exited requests_accepted "
            "terminal_disposition".split()
        ),
        "network receiver",
    )
    transfer = _exact(
        value.get("transfer"),
        set(
            "run_id step_id runner_task_id source_process_id destination_process_id "
            "authenticated bytes sha256".split()
        ),
        "network transfer",
    )
    byte_count = transfer.get("bytes")
    receiver_process_id = receiver.get("process_id")
    source_process_id = transfer.get("source_process_id")
    if (
        value.get("passed") is not True
        or value.get("proof_kind") != "dynamic"
        or value.get("platform") not in {"windows", "linux", "macos"}
        or value.get("platform") != "windows"
        or value.get("boundary") != "same-host-separate-process-loopback"
        or receiver.get("host") != "127.0.0.1"
        or receiver.get("mode") != "disposable_peer"
        or type(receiver_process_id) is not int
        or int(receiver_process_id) <= 0
        or receiver.get("process_distinct") is not True
        or receiver.get("process_exited") is not True
        or receiver.get("requests_accepted") != 1
        or receiver.get("terminal_disposition") != "exit_after_response"
        or not isinstance(transfer.get("run_id"), str)
        or _RUN_ID.fullmatch(str(transfer["run_id"])) is None
        or transfer.get("step_id") != "authorized_peer_handoff"
        or not isinstance(transfer.get("runner_task_id"), str)
        or _TASK_ID.fullmatch(str(transfer["runner_task_id"])) is None
        or type(source_process_id) is not int
        or int(source_process_id) <= 0
        or transfer.get("destination_process_id") != receiver_process_id
        or source_process_id == receiver_process_id
        or transfer.get("authenticated") is not True
        or type(byte_count) is not int
        or not 1 <= byte_count <= 5 * 1024 * 1024
    ):
        raise CrossPlatformGateValidationError("authenticated internal receiver proof is invalid")
    _digest(transfer.get("sha256"), "network transfer digest")
    return value


def _status_document(value: Any, windows_runner: Mapping[str, Any]) -> Mapping[str, Any]:
    status = _exact(
        value,
        {
            "schema_version",
            "state",
            "runner_id",
            "profile_id",
            "loopback_only",
            "enrollment",
            "process",
            "runner",
            "health",
        },
        "persisted runner readiness document",
    )
    runner = _exact(
        status.get("runner"),
        {
            "id",
            "source",
            "product_version",
            "runner_version",
            "platform",
            "architecture",
            "binary_digest",
            "managed_binary",
            "managed_sandbox",
            "inventory_schema",
            "action_sdk_version",
            "receipt_protocol",
        },
        "persisted readiness runner",
    )
    health = _exact(
        status.get("health"),
        {"transport", "tls", "runner_binary_digest", "inventory_digest", "accepting_execute"},
        "persisted readiness health",
    )
    if (
        status.get("schema_version") != "bluefire.runner-lifecycle-status.v1"
        or status.get("state") != "ready"
        or status.get("runner_id") != "bluefire-rust-runner.v1"
        or status.get("profile_id") != "sandbox-endpoint-deep-lab.v1"
        or status.get("loopback_only") is not True
        or status.get("enrollment") != "active"
        or status.get("process") != "authenticated"
        or runner.get("id") != windows_runner["runner_id"]
        or runner.get("source") != "packaged"
        or runner.get("product_version") != windows_runner["runner_version"]
        or runner.get("runner_version") != windows_runner["runner_version"]
        or runner.get("platform") != "windows"
        or runner.get("architecture") != "x86_64"
        or runner.get("binary_digest") != windows_runner["binary_sha256"]
        or runner.get("managed_binary") is not True
        or runner.get("managed_sandbox") is not True
        or runner.get("inventory_schema") != "bluefire.runner-inventory.v1"
        or runner.get("action_sdk_version") != "bluefire.runner-action-sdk.v1"
        or runner.get("receipt_protocol") != "bluefire.runner-receipt-wal.v2"
        or health.get("transport") != "mutual-tls-loopback"
        or health.get("tls") != "TLSv1.3"
        or health.get("runner_binary_digest") != windows_runner["binary_sha256"]
        or health.get("accepting_execute") is not True
    ):
        raise CrossPlatformGateValidationError("persisted runner readiness is not product-authored")
    _digest(health.get("inventory_digest"), "persisted readiness inventory digest")
    if not _path_free(status) or not 0 < len(canonical_json_bytes(status)) <= 64 * 1024:
        raise CrossPlatformGateValidationError("persisted runner readiness exposes a private path")
    return status


def _readiness(
    value: Mapping[str, Any],
    *,
    fresh_wsl: Mapping[str, Any],
    windows_runner: Mapping[str, Any],
) -> Mapping[str, Any]:
    _schema(
        value,
        READINESS_REPORT,
        {
            "schema_version",
            "passed",
            "proof_kind",
            "status_documents",
            "platforms",
            "wsl",
            "authorities",
            "platform_mismatches",
        },
    )
    rows = value.get("platforms")
    expected = [
        {"platform": "windows", "proof_kind": "dynamic", "state": "ready", "code": None},
        {"platform": "linux", "proof_kind": "dynamic", "state": "ready", "code": None},
        {
            "platform": "macos",
            "proof_kind": "structural",
            "state": "structural",
            "code": "macos_host_unavailable",
        },
    ]
    documents = _exact(
        value.get("status_documents"), {"service", "http", "cli"}, "readiness documents"
    )
    service_status = _status_document(documents.get("service"), windows_runner)
    http_status = _status_document(documents.get("http"), windows_runner)
    cli_status = _status_document(documents.get("cli"), windows_runner)
    identical = service_status == http_status == cli_status
    path_free = all(_path_free(row) for row in (service_status, http_status, cli_status))
    wsl = _exact(
        value.get("wsl"),
        set(fresh_wsl) | {"dynamic_execution"},
        "readiness WSL boundary",
    )
    authorities = _exact(
        value.get("authorities"),
        {"service", "http", "cli", "identical", "path_free", "status_digest"},
        "readiness product authorities",
    )
    mismatches = [
        {
            "requested_platform": requested,
            "actual_platform": "windows",
            "code": "platform_blocked",
            "dispatch_prevented": True,
        }
        for requested in ("linux", "macos")
    ]
    if (
        value.get("passed") is not True
        or value.get("proof_kind") != "dynamic"
        or rows != expected
        or {key: wsl.get(key) for key in fresh_wsl} != dict(fresh_wsl)
        or wsl.get("dynamic_execution") is not True
        or authorities
        != {
            "service": True,
            "http": True,
            "cli": True,
            "identical": identical,
            "path_free": path_free,
            "status_digest": content_hash(dict(service_status)),
        }
        or not identical
        or not path_free
        or value.get("platform_mismatches") != mismatches
    ):
        raise CrossPlatformGateValidationError("platform readiness conflates proof classes")
    return service_status


def _classification(value: Mapping[str, Any]) -> None:
    _schema(
        value,
        CLASSIFICATION_REPORT,
        {"schema_version", "passed", "proof_kind", "proofs", "limitations"},
    )
    expected = [
        {"assertion_id": assertion_id, "kind": kind, "state": "passed", "report": report}
        for assertion_id, kind, report in ASSERTION_REPORTS
    ]
    if (
        value.get("passed") is not True
        or value.get("proof_kind") != "structural"
        or value.get("proofs") != expected
        or value.get("limitations") != list(CLASSIFICATION_LIMITATIONS)
    ):
        raise CrossPlatformGateValidationError("Gate 11 proof classification is incomplete")


def validate_persisted_cross_platform_gate(
    repository: Path,
    evidence_dir: Path,
    *,
    expected_binding: Mapping[str, str],
    not_before: datetime,
    not_after: datetime,
) -> tuple[dict[str, bool], tuple[Mapping[str, str], ...]]:
    """Validate all eight claims and exactly two acceptance-bound run bundles."""

    root = evidence_dir.resolve(strict=True)
    source = repository.resolve(strict=True)
    reports = {name: _read_report(root, name) for name in REPORT_PATHS}
    try:
        windows_runner = validate_windows_wheel(root)
        linux_runner = validate_linux_repository_runner(source, expected_binding=expected_binding)
    except CrossPlatformArtifactValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc
    fresh_wsl = _reprobe_wsl()
    windows_bundle, windows_execution = _windows(reports[WINDOWS_REPORT], windows_runner)
    linux_bundle, linux_execution, linux_receiver = _linux(
        reports[LINUX_REPORT], linux_runner, fresh_wsl, repository=source
    )
    _cancellation(
        reports[CANCELLATION_REPORT],
        windows_runner,
        fresh_proof_factory=lambda report: run_fresh_cancellation_validation(
            source,
            root,
            windows_runner,
            report,
        ),
    )
    receiver = _receiver(reports[RECEIVER_REPORT])
    try:
        validate_transport_recovery_report(reports[RECOVERY_REPORT])
    except CrossPlatformArtifactValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc
    status = _readiness(
        reports[READINESS_REPORT], fresh_wsl=fresh_wsl, windows_runner=windows_runner
    )
    try:
        validate_macos_structural_contract(source, reports[MACOS_REPORT])
    except CrossPlatformArtifactValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc
    _classification(reports[CLASSIFICATION_REPORT])

    raw_bundles = (windows_bundle, linux_bundle)
    if windows_bundle["run_id"] == linux_bundle["run_id"]:
        raise CrossPlatformGateValidationError("Windows and Linux require distinct run bundles")
    normalized: list[Mapping[str, str]] = []
    run_facts: list[Mapping[str, Any]] = []
    rows = zip(
        ("windows", "linux"),
        raw_bundles,
        (windows_runner, linux_runner),
        (windows_execution, linux_execution),
        strict=True,
    )
    for platform, bundle, runner, execution in rows:
        try:
            validated, _artifact = validated_run_bundle(
                root,
                root.parent,
                bundle,
                expected_binding=expected_binding,
                not_before=not_before,
                not_after=not_after,
            )
        except (OSError, ValueError) as exc:
            raise CrossPlatformGateValidationError(
                f"{platform} run bundle failed validation"
            ) from exc
        try:
            facts = validate_persisted_run(
                root,
                bundle,
                repository=source,
                acceptance_binding=expected_binding,
                platform=platform,
                runner=runner,
                execution=execution,
            )
        except (OSError, ValueError) as exc:
            raise CrossPlatformGateValidationError(
                f"{platform} run proof failed semantic validation"
            ) from exc
        normalized.append(_receipt_run_reference(validated))
        run_facts.append(facts)
    windows_facts, linux_facts = run_facts
    health = status.get("health")
    linux_transfer = linux_receiver.get("transfer")
    if (
        receiver.get("transfer") != windows_facts.get("transfer")
        or linux_transfer
        != {
            "task_id": linux_facts["transfer"]["runner_task_id"],
            "sha256": linux_facts["transfer"]["sha256"].removeprefix("sha256:"),
            "bytes": linux_facts["transfer"]["bytes"],
        }
        or not isinstance(health, Mapping)
        or health.get("inventory_digest") != windows_facts.get("inventory_digest")
    ):
        raise CrossPlatformGateValidationError("reports are not bound to persisted Execute facts")
    checks = {name: True for name in CHECK_NAMES}
    return checks, tuple(normalized)


def validate_gate11_verification(
    evidence_dir: Path,
    *,
    expected_checks: Mapping[str, bool],
    expected_run_ids: Sequence[str],
    expected_suite_tests: Sequence[str],
) -> None:
    """Validate the final gate-owned verification report after atomic publication."""

    value = _read_report(evidence_dir.resolve(strict=True), VERIFICATION_REPORT)
    try:
        validate_gate_verification_document(
            value,
            expected_checks=expected_checks,
            expected_run_ids=expected_run_ids,
            expected_suite_tests=expected_suite_tests,
            report_paths=REPORT_PATHS,
        )
    except CrossPlatformArtifactValidationError as exc:
        raise CrossPlatformGateValidationError(str(exc)) from exc


__all__ = [
    "ASSERTION_REPORTS",
    "CANCELLATION_REPORT",
    "CHECK_NAMES",
    "CLASSIFICATION_LIMITATIONS",
    "CLASSIFICATION_REPORT",
    "CrossPlatformGateValidationError",
    "LINUX_REPORT",
    "LINUX_DEPENDENCIES_UNAVAILABLE_REASON",
    "LINUX_UNAVAILABLE_REASON",
    "LinuxRuntimeUnavailableError",
    "MACOS_REPORT",
    "READINESS_REPORT",
    "RECEIVER_REPORT",
    "RECOVERY_REPORT",
    "REPORT_PATHS",
    "VERIFICATION_REPORT",
    "WINDOWS_REPORT",
    "validate_gate11_verification",
    "validate_linux_typed_unavailable_report",
    "validate_linux_unavailable_report",
    "validate_persisted_cross_platform_gate",
]
