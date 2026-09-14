"""Independent validation of persisted Gate 11 Linux cleanup evidence."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, cast

from .cross_platform_linux_distribution import (
    ABSENCE_DELAYS_MS,
    probe_distribution_absence,
)
from .util import content_hash

LINUX_CLEANUP_VERIFIER = "tools/run_cross_platform_linux_verify_cleanup.py"

_FACT_KEYS = frozenset(
    "provider probe_state configured distribution_id version facts_digest".split()
)
_BOUNDARY_KEYS = _FACT_KEYS | frozenset(
    "source_distribution_persistent execution_distribution_id "
    "execution_distribution_disposable execution_distribution_removed "
    "distribution_storage_removed distribution_absence_probes workspace_disposable "
    "workspace_removed worker_process_exited workspace_name worker_process_id "
    "process_group_id session_id worker_start_time_ticks survivor_probes "
    "cleanup_verification".split()
)
_VERIFICATION_KEYS = frozenset(
    "schema_version workspace_name workspace_absent process_identities_absent "
    "process_identity_count identity_material identity_material_sha256 verifier_sha256 "
    "probe_delays_ms".split()
)
_IDENTITY_MATERIAL_KEYS = frozenset({"schema_version", "workspace_name", "process_identities"})
_IDENTITY_KEYS = frozenset({"process_id", "process_group_id", "session_id", "start_time_ticks"})
_WORKSPACE = re.compile(r"^bluefire-gate11-[0-9a-f]{16}$")
_EXECUTION_DISTRIBUTION = re.compile(r"^BlueFire-Gate11-Run-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ABSENCE_PROBES = [{"delay_ms": delay, "running": False} for delay in (0, 100, 250)]
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class LinuxCleanupValidationError(ValueError):
    """Raised when persisted Linux cleanup evidence is not independently bound."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LinuxCleanupValidationError(message)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LinuxCleanupValidationError(f"{label} fields do not match the schema")
    return value


def _file_identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_size),
        int(details.st_mtime_ns),
        int(details.st_nlink),
    )


def _repository_verifier(repository: Path) -> tuple[bytes, str]:
    root = repository.resolve(strict=True)
    _require(root.is_dir(), "the Gate 11 repository root is not a directory")
    path = root / Path(*LINUX_CLEANUP_VERIFIER.split("/"))
    try:
        before = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and not stat.S_ISLNK(before.st_mode)
            and not bool(int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT)
            and before.st_nlink == 1
            and 1 <= before.st_size <= 256 * 1024,
            "the committed Linux cleanup verifier is not a safe bounded file",
        )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _require(
                stat.S_ISREG(opened.st_mode)
                and opened.st_nlink == 1
                and _file_identity(opened) == _file_identity(before),
                "the committed Linux cleanup verifier identity changed",
            )
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                _require(size <= 256 * 1024, "the Linux cleanup verifier exceeded its bound")
                chunks.append(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = path.lstat()
    except LinuxCleanupValidationError:
        raise
    except OSError as exc:
        raise LinuxCleanupValidationError(
            "the committed Linux cleanup verifier is unavailable"
        ) from exc
    _require(
        size == opened.st_size
        and _file_identity(after) == _file_identity(opened)
        and _file_identity(current) == _file_identity(opened)
        and stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and not bool(int(getattr(current, "st_file_attributes", 0)) & _REPARSE_POINT),
        "the committed Linux cleanup verifier changed while hashing",
    )
    return b"".join(chunks), "sha256:" + digest.hexdigest()


def _positive_identity(value: Any, label: str) -> Mapping[str, int]:
    row = _exact(value, _IDENTITY_KEYS, label)
    _require(
        all(type(row.get(key)) is int and 0 < int(row[key]) < 2**63 for key in _IDENTITY_KEYS),
        f"{label} contains an invalid process identity",
    )
    return {key: int(row[key]) for key in sorted(_IDENTITY_KEYS)}


def validate_linux_cleanup_boundary(
    repository: Path,
    value: Any,
    *,
    fresh_wsl: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validate a ready WSL boundary and its persisted exact cleanup identities."""

    boundary = _exact(value, _BOUNDARY_KEYS, "ready WSL boundary")
    workspace_name = boundary.get("workspace_name")
    execution_distribution = boundary.get("execution_distribution_id")
    process_id = boundary.get("worker_process_id")
    start_ticks = boundary.get("worker_start_time_ticks")
    _require(
        {key: boundary.get(key) for key in _FACT_KEYS} == dict(fresh_wsl)
        and all(
            boundary.get(key) is True
            for key in (
                "source_distribution_persistent",
                "execution_distribution_disposable",
                "execution_distribution_removed",
                "distribution_storage_removed",
                "workspace_disposable",
                "workspace_removed",
                "worker_process_exited",
            )
        )
        and isinstance(execution_distribution, str)
        and _EXECUTION_DISTRIBUTION.fullmatch(execution_distribution) is not None
        and boundary.get("distribution_absence_probes")
        == [{"delay_ms": delay_ms, "registered": False} for delay_ms in ABSENCE_DELAYS_MS]
        and isinstance(workspace_name, str)
        and _WORKSPACE.fullmatch(workspace_name) is not None
        and type(process_id) is int
        and 0 < int(process_id) < 2**63
        and boundary.get("process_group_id") == process_id
        and boundary.get("session_id") == process_id
        and type(start_ticks) is int
        and 0 < int(start_ticks) < 2**63
        and boundary.get("survivor_probes") == _ABSENCE_PROBES,
        "the disposable Linux WSL2 boundary is invalid",
    )

    verification = _exact(
        boundary.get("cleanup_verification"),
        _VERIFICATION_KEYS,
        "independent Linux cleanup verification",
    )
    identity_material = _exact(
        verification.get("identity_material"),
        _IDENTITY_MATERIAL_KEYS,
        "Linux cleanup identity material",
    )
    raw_identities = identity_material.get("process_identities")
    _require(
        isinstance(raw_identities, list) and 1 <= len(raw_identities) <= 65536,
        "the Linux cleanup identity inventory is invalid",
    )
    identities = [
        _positive_identity(item, "Linux cleanup process identity")
        for item in cast(list[Any], raw_identities)
    ]
    worker_identity = _positive_identity(
        {
            "process_id": process_id,
            "process_group_id": boundary["process_group_id"],
            "session_id": boundary["session_id"],
            "start_time_ticks": start_ticks,
        },
        "Linux worker process identity",
    )
    identity_count = verification.get("process_identity_count")
    _source_payload, source_digest = _repository_verifier(repository)
    _require(
        identity_material.get("schema_version")
        == "bluefire.cross-platform-linux-cleanup-identities.v1"
        and identity_material.get("workspace_name") == workspace_name
        and verification.get("schema_version")
        == "bluefire.cross-platform-linux-cleanup-verification.v1"
        and verification.get("workspace_name") == workspace_name
        and verification.get("workspace_absent") is True
        and verification.get("process_identities_absent") is True
        and type(identity_count) is int
        and identity_count == len(identities)
        and identities == sorted(identities, key=lambda item: item["process_id"])
        and len({item["process_id"] for item in identities}) == len(identities)
        and worker_identity in identities
        and verification.get("identity_material_sha256") == content_hash(identity_material)
        and verification.get("verifier_sha256") == source_digest
        and verification.get("probe_delays_ms") == [0, 100, 250]
        and _SHA256.fullmatch(str(verification.get("identity_material_sha256"))) is not None
        and _SHA256.fullmatch(str(verification.get("verifier_sha256"))) is not None,
        "the persisted Linux cleanup verification is not independently bound",
    )
    observed = probe_distribution_absence(cast(str, execution_distribution))
    expected = boundary.get("distribution_absence_probes")
    _require(
        observed == expected,
        "the live WSL distribution absence result does not match persisted verification",
    )
    return boundary


__all__ = [
    "LINUX_CLEANUP_VERIFIER",
    "LinuxCleanupValidationError",
    "validate_linux_cleanup_boundary",
]
