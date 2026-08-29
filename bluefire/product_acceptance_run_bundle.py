"""Semantic verification for run bundles claimed by release-gate receipts."""

from __future__ import annotations

import hashlib
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .run_store import RECOVERY_ID_RE, RunStore, RunStoreError

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_REQUIRED_FINALIZED_FILES = frozenset(
    {
        "detections.json",
        "events.jsonl",
        "evidence.json",
        "plan.json",
        "policy.json",
        "profile.json",
        "result.json",
        "scenario.json",
    }
)
_RECOVERY_FILES = frozenset({"manifest.json", "record.json"})
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link_or_reparse(details: Any) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _entry_inventory(directory: Path, *, label: str) -> dict[str, tuple[Any, ...]]:
    inventory: dict[str, tuple[Any, ...]] = {}
    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise ValueError(f"{label} cannot be inventoried") from exc
    for entry in entries:
        try:
            details = entry.lstat()
        except OSError as exc:
            raise ValueError(f"{label} contains an unreadable entry") from exc
        if _is_link_or_reparse(details):
            raise ValueError(f"{label} contains a link or reparse point")
        if stat.S_ISREG(details.st_mode):
            if details.st_nlink != 1:
                raise ValueError(f"{label} contains a multiply-linked file")
            kind = "file"
        elif stat.S_ISDIR(details.st_mode):
            kind = "directory"
        else:
            raise ValueError(f"{label} contains a non-regular entry")
        inventory[entry.name] = (
            kind,
            int(details.st_dev),
            int(details.st_ino),
            int(details.st_size),
            int(details.st_mtime_ns),
            int(details.st_nlink),
        )
    return inventory


def _bundle_inventory(bundle: Path) -> dict[str, Any]:
    root = _entry_inventory(bundle, label="run bundle")
    recovery: dict[str, dict[str, tuple[Any, ...]]] = {}
    for name, identity in root.items():
        if identity[0] == "directory" and RECOVERY_ID_RE.fullmatch(name):
            recovery[name] = _entry_inventory(
                bundle / name,
                label="run recovery bundle",
            )
    return {"root": root, "recovery": recovery}


def _contained_bundle(gate_dir: Path, relative: Path, run_id: str) -> Path:
    root = gate_dir.resolve(strict=True)
    cursor = root
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("run bundle path must stay inside its gate directory")
    for index, part in enumerate(relative.parts):
        candidate = cursor / part
        try:
            details = candidate.lstat()
        except OSError as exc:
            raise ValueError("run bundle path is absent or unreadable") from exc
        if _is_link_or_reparse(details) or not stat.S_ISDIR(details.st_mode):
            raise ValueError("run bundle path contains an unsafe directory")
        cursor = candidate.resolve(strict=True)
        if not cursor.is_relative_to(root):
            raise ValueError("run bundle path must stay inside its gate directory")
        if index + 1 == len(relative.parts) and cursor.name != run_id:
            raise ValueError("run bundle directory name does not match its run_id")
    return cursor


def _validate_exact_inventory(
    inventory: Mapping[str, Any],
    *,
    manifest_files: Mapping[str, Any],
    recovery_ids: frozenset[str],
) -> None:
    raw_root = inventory.get("root")
    raw_recovery = inventory.get("recovery")
    if not isinstance(raw_root, Mapping) or not isinstance(raw_recovery, Mapping):
        raise ValueError("run bundle inventory is invalid")
    actual_files = {
        name
        for name, identity in raw_root.items()
        if isinstance(identity, tuple) and identity[0] == "file"
    }
    actual_directories = {
        name
        for name, identity in raw_root.items()
        if isinstance(identity, tuple) and identity[0] == "directory"
    }
    expected_files = set(manifest_files) | {"manifest.json"}
    if actual_files != expected_files:
        raise ValueError("run bundle regular-file inventory does not match its manifest")
    if actual_directories != recovery_ids or set(raw_recovery) != recovery_ids:
        raise ValueError("run bundle directory inventory is not canonical")
    for recovery_id in recovery_ids:
        nested = raw_recovery.get(recovery_id)
        if not isinstance(nested, Mapping):
            raise ValueError("run recovery bundle inventory is invalid")
        nested_files = {
            name
            for name, identity in nested.items()
            if isinstance(identity, tuple) and identity[0] == "file"
        }
        nested_directories = {
            name
            for name, identity in nested.items()
            if isinstance(identity, tuple) and identity[0] == "directory"
        }
        if nested_files != _RECOVERY_FILES or nested_directories:
            raise ValueError("run recovery bundle inventory is not canonical")


def acceptance_run_binding(
    acceptance_id: str,
    gate_id: str,
    contract_sha256: str,
    repository_commit: str,
    repository_tree: str,
    release: str,
) -> dict[str, str]:
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        "acceptance_id": acceptance_id,
        "gate_id": gate_id,
        "contract_sha256": contract_sha256,
        "repository_commit": repository_commit,
        "repository_tree": repository_tree,
        "release": release,
    }


def _manifest_artifact(run_dir: Path, manifest_path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with manifest_path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": manifest_path.resolve().relative_to(run_dir.resolve()).as_posix(),
        "sha256": "sha256:" + digest.hexdigest(),
        "size_bytes": manifest_path.stat().st_size,
        "role": "validated-run-bundle-manifest",
    }


def _utc_timestamp(raw: Any, label: str) -> datetime:
    if not isinstance(raw, str) or not raw.endswith("Z"):
        raise ValueError(f"run bundle {label} is not a UTC timestamp")
    try:
        value = datetime.fromisoformat(raw.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError(f"run bundle {label} is not a UTC timestamp") from exc
    if value.tzinfo != timezone.utc:
        raise ValueError(f"run bundle {label} is not a UTC timestamp")
    return value


def validated_run_bundle(
    gate_dir: Path,
    run_dir: Path,
    raw: Any,
    *,
    expected_binding: Mapping[str, str],
    not_before: datetime,
    not_after: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Require an intact, canonical, finalized bundle rather than a bare manifest."""

    if not isinstance(raw, Mapping) or set(raw) != {"run_id", "path"}:
        raise ValueError("run bundle reference fields do not match the schema")
    run_id = raw.get("run_id")
    path_text = raw.get("path")
    if not isinstance(run_id, str) or not _SAFE_IDENTIFIER.fullmatch(run_id):
        raise ValueError("run bundle reference has an invalid run_id")
    if not isinstance(path_text, str) or not path_text or len(path_text) > 1024:
        raise ValueError("run bundle reference path is invalid")
    relative = Path(path_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("run bundle path must stay inside its gate directory")
    bundle = _contained_bundle(gate_dir, relative, run_id)
    inventory_before = _bundle_inventory(bundle)

    store = RunStore(bundle.parent)
    try:
        validation = store.validate_bundle(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise ValueError(f"run bundle {run_id} failed validation: {exc}") from exc
    manifest = validation.get("manifest")
    if validation.get("valid") is not True or not isinstance(manifest, Mapping):
        raise ValueError(f"run bundle {run_id} failed content validation")
    files = manifest.get("files")
    if (
        manifest.get("schema_version") != "1.0"
        or manifest.get("run_id") != run_id
        or not isinstance(files, Mapping)
        or not _REQUIRED_FINALIZED_FILES <= set(files)
    ):
        raise ValueError(f"run bundle {run_id} is not a canonical finalized bundle")

    try:
        run = store.get_run(run_id)
    except (OSError, RunStoreError, ValueError) as exc:
        raise ValueError(f"run bundle {run_id} failed semantic validation: {exc}") from exc
    recovery_journal = run.get("recovery_journal", [])
    if not isinstance(recovery_journal, list) or any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("recovery_id"), str)
        or not RECOVERY_ID_RE.fullmatch(str(item["recovery_id"]))
        for item in recovery_journal
    ):
        raise ValueError(f"run bundle {run_id} has an invalid recovery inventory")
    recovery_ids = frozenset(str(item["recovery_id"]) for item in recovery_journal)
    if len(recovery_ids) != len(recovery_journal):
        raise ValueError(f"run bundle {run_id} has duplicate recovery identities")
    inventory_after = _bundle_inventory(bundle)
    if inventory_after != inventory_before:
        raise ValueError(f"run bundle {run_id} changed while it was being validated")
    _validate_exact_inventory(
        inventory_after,
        manifest_files=files,
        recovery_ids=recovery_ids,
    )
    events = run.get("events")
    created_at = _utc_timestamp(run.get("created_at"), "created_at")
    finalized_at = _utc_timestamp(run.get("finalized_at"), "finalized_at")
    if (
        run.get("run_id") != run_id
        or run.get("acceptance_binding") != expected_binding
        or not not_before <= created_at <= finalized_at <= not_after
        or not isinstance(events, list)
        or not events
        or not isinstance(events[0], Mapping)
        or events[0].get("event_type") != "run.created"
        or not isinstance(events[0].get("data"), Mapping)
        or events[0]["data"].get("created_at") != run.get("created_at")
        or not isinstance(events[-1], Mapping)
        or events[-1].get("event_type") != "run.finalized"
        or not isinstance(events[-1].get("data"), Mapping)
        or events[-1]["data"].get("finalized_at") != run.get("finalized_at")
    ):
        raise ValueError(
            f"run bundle {run_id} is stale, unbound, or has no canonical finalization record"
        )

    artifact = _manifest_artifact(run_dir, bundle / "manifest.json")
    normalized = {
        "run_id": run_id,
        "path": bundle.relative_to(gate_dir.resolve()).as_posix(),
        "manifest_sha256": artifact["sha256"],
    }
    return normalized, artifact


__all__ = ["acceptance_run_binding", "validated_run_bundle"]
