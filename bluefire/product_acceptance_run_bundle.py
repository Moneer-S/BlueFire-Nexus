"""Semantic verification for run bundles claimed by release-gate receipts."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .run_store import RunStore, RunStoreError

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
    bundle = (gate_dir / relative).resolve(strict=True)
    if (
        not bundle.is_relative_to(gate_dir.resolve())
        or not bundle.is_dir()
        or bundle.name != run_id
    ):
        raise ValueError("run bundle must be a contained directory named for its run_id")

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
