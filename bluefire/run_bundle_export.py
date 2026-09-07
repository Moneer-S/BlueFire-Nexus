"""Bounded, read-only ZIP snapshots of finalized RunStore bundles."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import Any

from .run_store import RECOVERY_ID_RE, SAFE_BUNDLE_NAMES, RunStore, RunStoreError
from .util import content_hash

# Match the existing cloud run-bundle read bounds, including recovery material.
MAX_FILES = 32
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
_REQUIRED = SAFE_BUNDLE_NAMES - {"comparison.json", "manifest.json"} | {"events.jsonl"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RunStoreError(message)


def _identity(path: Path, *, directory: bool = False) -> tuple[int, ...]:
    details = path.lstat()
    _require(
        not stat.S_ISLNK(details.st_mode)
        and not (getattr(details, "st_file_attributes", 0) & 0x400)
        and (stat.S_ISDIR(details.st_mode) if directory else stat.S_ISREG(details.st_mode))
        and (directory or details.st_nlink == 1),
        "Bundle contains an unsafe file or directory.",
    )
    return _stat_identity(details)


def _stat_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_nlink,
    )


def _inventory(root: Path) -> dict[str, tuple[int, ...]]:
    inventory = {".": _identity(root, directory=True)}
    for entry in root.iterdir():
        if RECOVERY_ID_RE.fullmatch(entry.name):
            inventory[entry.name] = _identity(entry, directory=True)
            for child in entry.iterdir():
                _require(
                    child.name in {"record.json", "manifest.json"}, "Unexpected recovery file."
                )
                inventory[f"{entry.name}/{child.name}"] = _identity(child)
        else:
            _require(entry.name in SAFE_BUNDLE_NAMES | {"events.jsonl"}, "Unexpected bundle entry.")
            inventory[entry.name] = _identity(entry)
        _require(len(inventory) <= MAX_FILES * 2 + 1, "Bundle inventory exceeds export limit.")
    return inventory


def _read(path: Path, expected: tuple[int, ...]) -> bytes:
    _require(expected[2] <= MAX_FILE_BYTES, "Bundle file exceeds export limit.")
    _require(_identity(path) == expected, "Bundle changed during export.")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        _require(_stat_identity(os.fstat(descriptor)) == expected, "Bundle changed during export.")
        payload = bytearray()
        while len(payload) <= expected[2]:
            block = os.read(descriptor, min(65536, expected[2] + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        _require(
            len(payload) == expected[2]
            and _stat_identity(os.fstat(descriptor)) == expected
            and _identity(path) == expected,
            "Bundle changed during export.",
        )
        return bytes(payload)
    finally:
        os.close(descriptor)


def _object(payload: bytes) -> dict[str, Any]:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RunStoreError("Bundle JSON must be an object.")
    return value


def _validate_files(manifest: dict[str, Any], captured: dict[str, bytes]) -> None:
    expected = {
        name: {"hash": "sha256:" + hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
        for name, payload in captured.items()
    }
    _require(
        manifest.get("files") == expected and manifest.get("bundle_hash") == content_hash(expected),
        "Bundle bytes failed manifest integrity validation.",
    )


def export_run_bundle(store: RunStore, run_id: str) -> bytes:
    """Validate the captured bytes, then archive only that immutable snapshot."""
    try:
        root = store._run_path(run_id, must_exist=True)
        before = _inventory(root)
        names = [name for name in before if name != "." and not RECOVERY_ID_RE.fullmatch(name)]
        _require(len(names) <= MAX_FILES, "Bundle file count exceeds export limit.")
        _require(
            sum(before[name][2] for name in names) <= MAX_TOTAL_BYTES,
            "Bundle exceeds export limit.",
        )
        captured = {name: _read(root / name, before[name]) for name in sorted(names)}
        _require(
            _inventory(root) == before, "Bundle changed during export; retry once recovery settles."
        )
        original = {name: payload for name, payload in captured.items() if "/" not in name}
        _require(
            _REQUIRED | {"manifest.json"} <= original.keys(),
            "Only finalized complete bundles can be exported.",
        )
        manifest = _object(original.pop("manifest.json"))
        _require(
            manifest.get("run_id") == run_id and manifest.get("schema_version") == "1.0",
            "Invalid bundle identity.",
        )
        _validate_files(manifest, original)
        result = _object(original["result.json"])
        _require(
            result.get("run_id") == run_id and bool(result.get("finalized_at")),
            "Run is not finalized.",
        )
        previous_hash = None
        sequence = 0
        for line in original["events.jsonl"].decode("utf-8").splitlines():
            if line.strip():
                sequence += 1
                row = store._validated_event_row(
                    line, expected_sequence=sequence, previous_hash=previous_hash
                )
                previous_hash = str(row["event_hash"])
        for recovery_id in sorted(name for name in before if RECOVERY_ID_RE.fullmatch(name)):
            record_bytes = captured.get(f"{recovery_id}/record.json")
            manifest_bytes = captured.get(f"{recovery_id}/manifest.json")
            if record_bytes is None or manifest_bytes is None:
                raise RunStoreError("Recovery bundle is incomplete.")
            recovery = _object(manifest_bytes)
            record = _object(record_bytes)
            _validate_files(recovery, {"record.json": record_bytes})
            _require(
                recovery.get("schema_version") == "bluefire.run-recovery-manifest.v1"
                and recovery.get("run_id") == record.get("run_id") == run_id
                and recovery.get("recovery_id") == record.get("recovery_id") == recovery_id,
                "Recovery bundle identity is invalid.",
            )
            source = {
                key: value
                for key, value in record.items()
                if key not in {"recovery_id", "recorded_at"}
            }
            _require(
                recovery.get("source_digest") == content_hash(source),
                "Recovery source digest is invalid.",
            )
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in captured.items():
                archive.writestr(f"{run_id}/{name}", payload)
        return output.getvalue()
    except (OSError, ValueError, UnicodeError) as exc:
        if isinstance(exc, RunStoreError):
            raise
        raise RunStoreError("Run bundle could not be safely exported.") from exc
