"""Bounded source and artifact credential scans for official behavior packs."""

from __future__ import annotations

import base64
import hashlib
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from .util import content_hash, file_hash

SOURCE_SCAN_SCHEMA = "bluefire.deep-behavior-source-credential-scan.v1"
RUNTIME_SCAN_SCHEMA = "bluefire.deep-behavior-runtime-credential-scan.v1"

PACK_SOURCE_FILES = (
    "bluefire/catalog/actions.yaml",
    "bluefire/catalog/behaviors.yaml",
    "bluefire/cloud_identity_contracts.py",
    "bluefire/cloud_identity_manual_smoke.py",
    "bluefire/data/deep_behavior_packs.json",
    "bluefire/data/endpoint_deep_behavior_lab.yaml",
    "bluefire/data/gate11_linux_wheelhouse.json",
    "bluefire/data/linux_container_validation.yaml",
    "bluefire/cloud_identity_pack.py",
    "bluefire/cloud_identity_runtime.py",
    "bluefire/cloud_identity_validation.py",
    "bluefire/cross_platform_linux.py",
    "bluefire/cross_platform_linux_bundle_validation.py",
    "bluefire/deep_behavior_endpoint.py",
    "bluefire/deep_behavior_gate.py",
    "bluefire/deep_behavior_gate_validation.py",
    "bluefire/deep_behavior_journey.py",
    "bluefire/deep_behavior_packs.py",
    "bluefire/deep_behavior_secret_scan.py",
    "bluefire/receiver_auth.py",
    "bluefire/runner_client.py",
    "config/bluefire.example.yaml",
    "scenarios/endpoint_deep_behavior_lab.yaml",
    "scenarios/linux_container_validation.yaml",
    "tools/run_aws_identity_lab_smoke.py",
    "tools/run_cross_platform_linux_worker.py",
    "tools/run_cross_platform_source_intake_posix_probe.py",
    "tools/run_deep_behavior_gate_journey.py",
)

_AWS_ACCESS_KEY = re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")
_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_SECRET_ASSIGNMENT = re.compile(
    rb"(?i)(?:aws_secret_access_key|secret_access_key|client_secret|refresh_token)"
    rb"[ \t]{0,16}[:=][ \t]{0,16}['\"][A-Za-z0-9/+_=.-]{16,}['\"]"
)
_MAX_SOURCE_FILE = 2 * 1024 * 1024
_MAX_SOURCE_TOTAL = 16 * 1024 * 1024
_MAX_RUNTIME_TOTAL = 128 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class DeepBehaviorCredentialScanError(ValueError):
    """A pack source or runtime artifact could contain credential material."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DeepBehaviorCredentialScanError(message)


def _safe_payload(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    _require(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and not int(getattr(before, "st_file_attributes", 0)) & _REPARSE_POINT
        and before.st_nlink == 1
        and 0 < before.st_size <= maximum,
        "a credential-scan input is absent, unsafe, or unbounded",
    )
    payload = path.read_bytes()
    after = path.lstat()
    _require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)
        and len(payload) == before.st_size,
        "a credential-scan input changed while it was read",
    )
    return payload


def _forbidden_source_matches(payload: bytes) -> tuple[str, ...]:
    findings: list[str] = []
    if _AWS_ACCESS_KEY.search(payload):
        findings.append("aws_access_key_id")
    if _PRIVATE_KEY.search(payload):
        findings.append("private_key_block")
    if _SECRET_ASSIGNMENT.search(payload):
        findings.append("literal_secret_assignment")
    return tuple(findings)


def audit_deep_behavior_sources(repository: Path) -> Mapping[str, Any]:
    root = repository.resolve(strict=True)
    records: list[Mapping[str, Any]] = []
    total = 0
    findings: list[Mapping[str, str]] = []
    for relative in PACK_SOURCE_FILES:
        payload = _safe_payload(root / relative, _MAX_SOURCE_FILE)
        total += len(payload)
        _require(total <= _MAX_SOURCE_TOTAL, "the pack source scan exceeded its total bound")
        for finding in _forbidden_source_matches(payload):
            findings.append({"path": relative, "kind": finding})
        records.append(
            {
                "path": relative,
                "size_bytes": len(payload),
                "sha256": file_hash(root / relative),
            }
        )
    _require(not findings, "an official pack source contains credential-shaped material")
    return {
        "schema_version": SOURCE_SCAN_SCHEMA,
        "passed": True,
        "files": records,
        "files_scanned": len(records),
        "bytes_scanned": total,
        "forbidden_matches": [],
        "source_inventory_sha256": content_hash(records),
    }


def secret_encodings(secret: bytes) -> tuple[bytes, ...]:
    _require(type(secret) is bytes and 16 <= len(secret) <= 4096, "scan secret is invalid")
    encoded = {
        secret,
        secret.hex().encode("ascii"),
        secret.hex().upper().encode("ascii"),
        base64.b64encode(secret),
        base64.b32encode(secret),
        base64.urlsafe_b64encode(secret),
        base64.urlsafe_b64encode(secret).rstrip(b"="),
    }
    return tuple(sorted(encoded, key=lambda item: (len(item), item)))


def scan_runtime_secret_material(
    roots: Sequence[Path],
    secrets: Sequence[bytes],
) -> Mapping[str, Any]:
    _require(bool(roots) and bool(secrets), "runtime credential scan inputs are incomplete")
    encodings = tuple(value for secret in secrets for value in secret_encodings(secret))
    files = 0
    scanned = 0
    digests: list[str] = []
    for root in roots:
        boundary = root.resolve(strict=True)
        _require(boundary.is_dir() and not boundary.is_symlink(), "runtime scan root is unsafe")
        for path in sorted(boundary.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file():
                continue
            payload = _safe_payload(path, _MAX_RUNTIME_TOTAL)
            files += 1
            scanned += len(payload)
            _require(scanned <= _MAX_RUNTIME_TOTAL, "runtime credential scan exceeded its bound")
            _require(
                all(encoding not in payload for encoding in encodings),
                "runtime credential material leaked into persisted evidence",
            )
            digests.append(hashlib.sha256(payload).hexdigest())
    return {
        "schema_version": RUNTIME_SCAN_SCHEMA,
        "passed": True,
        "files_scanned": files,
        "bytes_scanned": scanned,
        "secret_count": len(secrets),
        "artifact_digest_set_sha256": content_hash(sorted(digests)),
        "matches": 0,
    }


__all__ = [
    "PACK_SOURCE_FILES",
    "RUNTIME_SCAN_SCHEMA",
    "SOURCE_SCAN_SCHEMA",
    "DeepBehaviorCredentialScanError",
    "audit_deep_behavior_sources",
    "scan_runtime_secret_material",
    "secret_encodings",
]
