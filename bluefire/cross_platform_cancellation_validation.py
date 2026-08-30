"""Fresh, validator-owned dynamic authority for the Gate 11 cancellation claim."""

from __future__ import annotations

import hashlib
import io
import stat
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from .config import load_config
from .cross_platform_process_proof import (
    ACTION_ID,
    CANCELLATION_SCHEMA,
    PROFILE_ID,
    process_tree_cancellation,
)
from .cross_platform_recovery_report_validation import (
    ABSENCE_PROBES,
    process_identities_absent,
)
from .registry import load_builtin_registry
from .runner_client import _PinnedPrivateDirectory
from .util import content_hash

_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_RUNNER_BYTES = 128 * 1024 * 1024
_AUTHORITY = object()


class FreshCancellationValidationError(ValueError):
    """Raised when a validator-owned cancellation rerun cannot prove the claim."""


@dataclass(frozen=True)
class FreshCancellationProof:
    runner_binary_sha256: str
    fresh_report_sha256: str
    target_report_sha256: str
    target_request_hash: str
    target_identity_material_sha256: str
    _authority: object = field(repr=False, compare=False)


def _validated_runner_bytes(
    evidence_dir: Path,
    windows_runner: Mapping[str, Any],
) -> bytes:
    package = evidence_dir / "package"
    wheel_name = windows_runner.get("wheel_file")
    wheel_digest = windows_runner.get("wheel_sha256")
    binary_member = windows_runner.get("binary_member")
    binary_digest = windows_runner.get("binary_sha256")
    binary_size = windows_runner.get("binary_size")
    if (
        not isinstance(wheel_name, str)
        or not isinstance(wheel_digest, str)
        or not isinstance(binary_member, str)
        or not isinstance(binary_digest, str)
        or type(binary_size) is not int
    ):
        raise FreshCancellationValidationError("the validated Windows runner identity is invalid")
    try:
        with _PinnedPrivateDirectory(package) as pinned:
            if pinned.names(maximum=2) != (wheel_name,):
                raise OSError("the validated wheel inventory changed")
            wheel = pinned.read(wheel_name, maximum=_MAX_WHEEL_BYTES, apply_permissions=False)
        if "sha256:" + hashlib.sha256(wheel).hexdigest() != wheel_digest:
            raise OSError("the validated wheel bytes changed")
        with zipfile.ZipFile(io.BytesIO(wheel), "r") as archive:
            matches = [item for item in archive.infolist() if item.filename == binary_member]
            if len(matches) != 1:
                raise OSError("the validated runner member is unavailable")
            info = matches[0]
            unix_mode = int(info.external_attr) >> 16
            if (
                info.flag_bits & 1
                or stat.S_ISLNK(unix_mode)
                or info.file_size != binary_size
                or not 1 <= info.file_size <= _MAX_RUNNER_BYTES
                or info.compress_size <= 0
                or info.file_size > 1000 * info.compress_size
            ):
                raise OSError("the validated runner member is unsafe")
            binary = archive.read(info)
        if (
            len(binary) != binary_size
            or "sha256:" + hashlib.sha256(binary).hexdigest() != binary_digest
        ):
            raise OSError("the validated runner member identity changed")
        return binary
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        if isinstance(exc, FreshCancellationValidationError):
            raise
        raise FreshCancellationValidationError(
            "the validator could not retain the exact Windows runner bytes"
        ) from exc


def run_fresh_cancellation_validation(
    repository: Path,
    evidence_dir: Path,
    windows_runner: Mapping[str, Any],
    target_report: Mapping[str, Any],
) -> FreshCancellationProof:
    """Execute a new packaged witness while validation is in progress."""

    target_digest, target_request_hash, target_identity_digest = _target_report_binding(
        target_report
    )
    binary = _validated_runner_bytes(evidence_dir, windows_runner)
    expected_digest = str(windows_runner["binary_sha256"])
    try:
        config = load_config(repository / "config" / "bluefire.example.yaml")
        registry = load_builtin_registry()
        service = SimpleNamespace(config=config, registry=registry)
        with tempfile.TemporaryDirectory(prefix="bluefire-gate11-cancellation-validation-") as raw:
            root = Path(raw)
            resource = root / "resource"
            resource.mkdir()
            with _PinnedPrivateDirectory(resource) as pinned:
                pinned.create("bluefire-runner.exe", binary, maximum=_MAX_RUNNER_BYTES)
            runtime = root / "runtime"
            runtime.mkdir()
            report = process_tree_cancellation(
                runtime,
                resource,
                service,
                expected_runner_digest=expected_digest,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        raise FreshCancellationValidationError(
            "a fresh packaged process-tree cancellation rerun did not pass"
        ) from exc
    if (
        report.get("schema_version") != CANCELLATION_SCHEMA
        or report.get("passed") is not True
        or report.get("proof_kind") != "dynamic"
        or report.get("platform") != "windows"
        or report.get("action_id") != ACTION_ID
        or report.get("behavior_id") != ACTION_ID
        or report.get("profile_id") != PROFILE_ID
        or report.get("runner_binary_sha256") != expected_digest
    ):
        raise FreshCancellationValidationError(
            "the fresh cancellation rerun did not bind the reviewed action and runner"
        )
    return FreshCancellationProof(
        runner_binary_sha256=expected_digest,
        fresh_report_sha256=content_hash(dict(report)),
        target_report_sha256=target_digest,
        target_request_hash=target_request_hash,
        target_identity_material_sha256=target_identity_digest,
        _authority=_AUTHORITY,
    )


def validate_fresh_cancellation_proof(
    proof: object,
    *,
    expected_runner_digest: str,
    expected_report: Mapping[str, Any],
) -> None:
    target_digest, target_request_hash, target_identity_digest = _target_report_binding(
        expected_report
    )
    if (
        not isinstance(proof, FreshCancellationProof)
        or proof._authority is not _AUTHORITY
        or proof.runner_binary_sha256 != expected_runner_digest
        or not proof.fresh_report_sha256.startswith("sha256:")
        or len(proof.fresh_report_sha256) != 71
        or proof.target_report_sha256 != target_digest
        or proof.target_request_hash != target_request_hash
        or proof.target_identity_material_sha256 != target_identity_digest
    ):
        raise FreshCancellationValidationError(
            "process-tree cancellation requires a fresh validator-owned rerun"
        )


def _exact_mapping(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise FreshCancellationValidationError(f"{label} is invalid")
    return value


def _target_report_binding(value: Mapping[str, Any]) -> tuple[str, str, str]:
    row = _exact_mapping(
        value.get("cancellation"),
        set(
            "task_id request_hash terminal_state parent_process_identity "
            "descendant_process_identity cooperative_requested cooperative_acknowledged "
            "forced_tree_termination control_cleanup_verified control_state_removed "
            "parent_was_running descendant_was_running survivor_probe_count survivor_probes "
            "no_survivors identity_material_sha256".split()
        ),
        "target process-tree cancellation",
    )
    parent = _exact_mapping(
        row.get("parent_process_identity"),
        {"process_id", "creation_time_100ns"},
        "target cancellation parent identity",
    )
    descendant = _exact_mapping(
        row.get("descendant_process_identity"),
        {"process_id", "creation_time_100ns"},
        "target cancellation descendant identity",
    )
    request_hash = row.get("request_hash")
    identity_digest = row.get("identity_material_sha256")
    if (
        not isinstance(request_hash, str)
        or not isinstance(identity_digest, str)
        or not process_identities_absent(parent, descendant)
    ):
        raise FreshCancellationValidationError(
            "the fresh cancellation rerun is not bound to absent target identities"
        )
    return content_hash(dict(value)), request_hash, identity_digest


def validate_cancellation_report(
    value: Mapping[str, Any],
    windows_runner: Mapping[str, Any],
    *,
    fresh_proof_factory: Callable[[Mapping[str, Any]], object] | None,
) -> None:
    expected_top = {
        "schema_version",
        "passed",
        "proof_kind",
        "platform",
        "action_id",
        "behavior_id",
        "profile_id",
        "containment",
        "runner_binary_sha256",
        "cancellation",
    }
    if set(value) != expected_top or value.get("schema_version") != CANCELLATION_SCHEMA:
        raise FreshCancellationValidationError("process-tree cancellation report is invalid")
    row = _exact_mapping(
        value.get("cancellation"),
        set(
            "task_id request_hash terminal_state parent_process_identity "
            "descendant_process_identity cooperative_requested cooperative_acknowledged "
            "forced_tree_termination control_cleanup_verified control_state_removed "
            "parent_was_running descendant_was_running survivor_probe_count survivor_probes "
            "no_survivors identity_material_sha256".split()
        ),
        "process-tree cancellation",
    )
    parent = _exact_mapping(
        row.get("parent_process_identity"),
        {"process_id", "creation_time_100ns"},
        "cancellation parent identity",
    )
    descendant = _exact_mapping(
        row.get("descendant_process_identity"),
        {"process_id", "creation_time_100ns"},
        "cancellation descendant identity",
    )
    identities_valid = all(
        type(identity.get(field)) is int and int(identity[field]) > 0
        for identity in (parent, descendant)
        for field in ("process_id", "creation_time_100ns")
    )
    request_hash = row.get("request_hash")
    digest_valid = (
        isinstance(request_hash, str)
        and len(request_hash) == 71
        and request_hash.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in request_hash[7:])
    )
    identity_digest = None
    if identities_valid:
        material = (
            f"{parent['process_id']}:{parent['creation_time_100ns']}\n"
            f"{descendant['process_id']}:{descendant['creation_time_100ns']}\n"
        ).encode("ascii")
        identity_digest = "sha256:" + hashlib.sha256(material).hexdigest()
    if (
        value.get("passed") is not True
        or value.get("proof_kind") != "dynamic"
        or value.get("platform") != "windows"
        or value.get("action_id") != ACTION_ID
        or value.get("behavior_id") != ACTION_ID
        or value.get("profile_id") != PROFILE_ID
        or value.get("containment") != "windows-job-object-kill-on-close"
        or value.get("runner_binary_sha256") != windows_runner.get("binary_sha256")
        or not digest_valid
        or row.get("task_id") != "execute-" + str(request_hash)[7:]
        or row.get("terminal_state") != "cancelled"
        or not identities_valid
        or parent == descendant
        or row.get("identity_material_sha256") != identity_digest
        or any(
            row.get(key) is not True
            for key in (
                "cooperative_requested",
                "cooperative_acknowledged",
                "forced_tree_termination",
                "control_cleanup_verified",
                "control_state_removed",
                "parent_was_running",
                "descendant_was_running",
                "no_survivors",
            )
        )
        or row.get("survivor_probe_count") != len(ABSENCE_PROBES)
        or row.get("survivor_probes") != ABSENCE_PROBES
        or not process_identities_absent(parent, descendant)
    ):
        raise FreshCancellationValidationError("process-tree cancellation was not confirmed")
    if fresh_proof_factory is None:
        raise FreshCancellationValidationError(
            "process-tree cancellation requires a fresh validator-owned rerun"
        )
    validate_fresh_cancellation_proof(
        fresh_proof_factory(value),
        expected_runner_digest=str(windows_runner.get("binary_sha256")),
        expected_report=value,
    )


__all__ = [
    "FreshCancellationProof",
    "FreshCancellationValidationError",
    "run_fresh_cancellation_validation",
    "validate_cancellation_report",
    "validate_fresh_cancellation_proof",
]
