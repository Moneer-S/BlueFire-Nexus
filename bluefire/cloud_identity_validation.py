"""Bounded secret scan and independent RunStore validation for the AWS lab."""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from .cloud_identity_contracts import (
    MAX_CREDENTIAL_BYTES,
    MIN_CREDENTIAL_BYTES,
    PACK_ID,
    PROFILE_ID,
    RUN_RESULT_SCHEMA,
    CloudIdentityPackError,
    SecretScanReport,
    require,
)
from .run_store import RunStore, RunStoreError

_EXPECTED_BUNDLE_FILES = frozenset(
    {
        "detections.json",
        "events.jsonl",
        "evidence.json",
        "manifest.json",
        "plan.json",
        "policy.json",
        "profile.json",
        "result.json",
        "scenario.json",
    }
)
_MAX_BUNDLE_FILES = 32
_MAX_BUNDLE_FILE_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link_or_reparse(details: Any) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _secret_encodings(secret: bytes) -> tuple[tuple[str, bytes], ...]:
    standard = base64.b64encode(secret)
    urlsafe = base64.urlsafe_b64encode(secret)
    values = (
        ("raw", secret),
        ("hex-lower", secret.hex().encode("ascii")),
        ("hex-upper", secret.hex().upper().encode("ascii")),
        ("base64", standard),
        ("base64-unpadded", standard.rstrip(b"=")),
        ("base64url", urlsafe),
        ("base64url-unpadded", urlsafe.rstrip(b"=")),
    )
    unique: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for name, value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append((name, value))
    return tuple(unique)


def scan_bundle_for_secret_material(
    bundle: str | Path,
    credentials: Sequence[bytes | bytearray | memoryview],
) -> SecretScanReport:
    """Scan a bounded, flat finalized bundle for runtime secret encodings."""

    root = Path(bundle).resolve(strict=True)
    require(root.is_dir(), "cloud run bundle is not a directory")
    patterns: list[tuple[str, bytes]] = []
    for credential in credentials:
        try:
            material = bytes(credential)
        except (TypeError, ValueError):
            raise CloudIdentityPackError("secret scan input is invalid") from None
        require(
            MIN_CREDENTIAL_BYTES <= len(material) <= MAX_CREDENTIAL_BYTES,
            "secret scan input is invalid",
        )
        patterns.extend(_secret_encodings(material))
    require(bool(patterns), "secret scan requires credential material")

    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CloudIdentityPackError("cloud run bundle cannot be scanned") from exc
    require(len(entries) <= _MAX_BUNDLE_FILES, "cloud run bundle file count is unbounded")
    total = 0
    files = 0
    for entry in entries:
        try:
            before = entry.lstat()
        except OSError as exc:
            raise CloudIdentityPackError("cloud run bundle contains an unreadable entry") from exc
        require(
            not _is_link_or_reparse(before)
            and stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 <= before.st_size <= _MAX_BUNDLE_FILE_BYTES,
            "cloud run bundle contains an unsafe or unbounded entry",
        )
        total += int(before.st_size)
        files += 1
        require(total <= _MAX_BUNDLE_BYTES, "cloud run bundle size is unbounded")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                entry,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            require(
                stat.S_ISREG(opened.st_mode)
                and opened.st_nlink == 1
                and opened.st_size == before.st_size
                and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                "cloud run bundle changed during secret scan",
            )
            payload = bytearray()
            while len(payload) <= _MAX_BUNDLE_FILE_BYTES:
                block = os.read(
                    descriptor, min(64 * 1024, _MAX_BUNDLE_FILE_BYTES + 1 - len(payload))
                )
                if not block:
                    break
                payload.extend(block)
            after = os.fstat(descriptor)
            current = entry.lstat()
        except OSError as exc:
            raise CloudIdentityPackError("cloud run bundle contains an unreadable entry") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        require(
            len(payload) == before.st_size
            and (after.st_dev, after.st_ino, after.st_size)
            == (before.st_dev, before.st_ino, before.st_size)
            and (current.st_dev, current.st_ino, current.st_size)
            == (before.st_dev, before.st_ino, before.st_size)
            and not _is_link_or_reparse(current)
            and current.st_nlink == 1,
            "cloud run bundle changed during secret scan",
        )
        for _encoding, pattern in patterns:
            if pattern in payload:
                raise CloudIdentityPackError("cloud run bundle contains credential material")
    return SecretScanReport(
        files_scanned=files,
        bytes_scanned=total,
        encodings_checked=tuple(sorted({name for name, _pattern in patterns})),
    )


def validate_cloud_identity_run_bundle(
    store: RunStore,
    run_id: str,
    *,
    expected_mode: str,
    expected_acceptance_binding: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    """Independently validate exact inventory, integrity, semantics, and binding."""

    require(expected_mode in {"simulate", "execute"}, "expected cloud run mode is invalid")
    run_path = (store.root / run_id).resolve(strict=True)
    require(run_path.parent == store.root, "cloud run path escaped its store")
    try:
        entries = sorted(run_path.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CloudIdentityPackError("cloud run bundle cannot be inventoried") from exc
    inventory: set[str] = set()
    for entry in entries:
        try:
            details = entry.lstat()
        except OSError as exc:
            raise CloudIdentityPackError("cloud run bundle cannot be inventoried") from exc
        require(
            not _is_link_or_reparse(details)
            and stat.S_ISREG(details.st_mode)
            and details.st_nlink == 1,
            "cloud run bundle inventory is unsafe",
        )
        inventory.add(entry.name)
    require(inventory == _EXPECTED_BUNDLE_FILES, "cloud run bundle inventory is not canonical")
    try:
        integrity = store.validate_bundle(run_id)
        run = store.get_run(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise CloudIdentityPackError("cloud run bundle failed integrity validation") from exc
    require(integrity.get("valid") is True, "cloud run bundle failed integrity validation")
    evidence = run.get("evidence")
    records = evidence.get("records") if isinstance(evidence, Mapping) else None
    expected_interface = "Simulate" if expected_mode == "simulate" else "Execute"
    require(
        run.get("schema_version") == RUN_RESULT_SCHEMA
        and run.get("status") == "succeeded"
        and run.get("mode") == expected_mode
        and run.get("pack_id") == PACK_ID
        and run.get("profile_id") == PROFILE_ID
        and run.get("cleanup_verified") is True
        and run.get("audit_verified") is True
        and run.get("credential_revoked") is (expected_mode == "execute")
        and isinstance(records, list)
        and [record.get("phase") for record in records if isinstance(record, Mapping)]
        == ["enumeration", "action", "revocation", "audit"]
        and all(
            isinstance(record, Mapping) and record.get("interface") == expected_interface
            for record in records
        ),
        "cloud run bundle semantics are invalid",
    )
    binding = run.get("acceptance_binding")
    if expected_acceptance_binding is not None:
        require(
            binding == expected_acceptance_binding,
            "cloud run bundle acceptance binding does not match",
        )
    elif binding is not None:
        require(isinstance(binding, Mapping), "cloud run bundle acceptance binding is invalid")
    manifest = integrity.get("manifest")
    if not isinstance(manifest, Mapping):
        raise CloudIdentityPackError("cloud run manifest is invalid")
    return {
        "schema_version": "bluefire.aws-identity-lab-bundle-validation.v1",
        "run_id": run_id,
        "mode": expected_mode,
        "bundle_hash": manifest.get("bundle_hash"),
        "acceptance_binding": dict(binding) if isinstance(binding, Mapping) else None,
        "cleanup_verified": True,
        "audit_verified": True,
    }


__all__ = ["scan_bundle_for_secret_material", "validate_cloud_identity_run_bundle"]
