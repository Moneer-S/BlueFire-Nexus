"""Immutable, content-addressed run-comparison snapshots."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, resource_row, utc_now
from .util import content_hash

SCHEMA = "bluefire.saved-run-comparison.v1"
MAX_COMPARISON_RUNS = 32
MAX_SNAPSHOT_LIST = 100
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_SNAPSHOT_PREFIX = "run-comparison-"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")


class SnapshotNotFound(ProductStoreError):
    """Raised when a requested saved comparison does not exist."""

    pass


class SnapshotIntegrityError(ProductStoreError):
    """Raised when a persisted snapshot no longer matches its identity."""

    pass


class SnapshotStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def reject_generic_resource_write(kind: str, resource_id: str, document: Mapping[str, Any]) -> None:
    if kind == "comparison" and (
        resource_id.startswith(_SNAPSHOT_PREFIX)
        or (isinstance(document, Mapping) and document.get("schema_version") == SCHEMA)
    ):
        raise ProductStoreError("saved run comparisons are immutable")


def list_legacy_resources(store: SnapshotStore) -> list[Mapping[str, Any]]:
    with store._connection() as connection:
        rows = connection.execute("""SELECT * FROM resources
            WHERE kind = 'comparison' AND substr(resource_id, 1, 15) <> 'run-comparison-'
            ORDER BY resource_id""").fetchall()
    return [resource_row(row) for row in rows]


def save(
    store: SnapshotStore,
    comparison: Mapping[str, Any],
    source_bindings: list[Mapping[str, Any]],
) -> Mapping[str, Any]:
    identity = _identity(comparison, source_bindings)
    digest = content_hash(identity)
    snapshot_id = _SNAPSHOT_PREFIX + digest[7:]
    with store._connection(write=True) as connection:
        row = connection.execute(
            "SELECT * FROM resources WHERE kind = 'comparison' AND resource_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is not None:
            document = _decode_row(row)
            if (
                document["digest"] != digest
                or _identity(document["comparison"], document["source_bindings"]) != identity
            ):
                raise SnapshotIntegrityError("saved comparison identity conflicts with its content")
            return document

        created_at = utc_now()
        document = {
            "schema_version": SCHEMA,
            "snapshot_id": snapshot_id,
            "digest": digest,
            "created_at": created_at,
            **identity,
        }
        document_json = canonical_json(document)
        if len(document_json.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise ProductStoreError("saved comparison exceeds its snapshot byte limit")
        connection.execute(
            """INSERT INTO resources
            (kind, resource_id, document_json, digest, status, created_at, updated_at)
            VALUES ('comparison', ?, ?, ?, 'ready', ?, ?)""",
            (snapshot_id, document_json, digest, created_at, created_at),
        )
        return document


def get(store: SnapshotStore, snapshot_id: str) -> Mapping[str, Any]:
    if not isinstance(snapshot_id, str) or not re.fullmatch(
        r"run-comparison-[0-9a-f]{64}", snapshot_id
    ):
        raise SnapshotNotFound("saved comparison was not found")
    with store._connection() as connection:
        row = connection.execute(
            "SELECT * FROM resources WHERE kind = 'comparison' AND resource_id = ?",
            (snapshot_id,),
        ).fetchone()
    if row is None:
        raise SnapshotNotFound("saved comparison was not found")
    return _decode_row(row)


def list_recent(store: SnapshotStore) -> list[Mapping[str, Any]]:
    snapshots: list[Mapping[str, Any]] = []
    with store._connection() as connection:
        rows = connection.execute(
            """SELECT * FROM resources
            WHERE kind = 'comparison' AND resource_id GLOB 'run-comparison-[0-9a-f]*'
            ORDER BY created_at DESC, resource_id DESC LIMIT ?""",
            (MAX_SNAPSHOT_LIST,),
        )
        for row in rows:
            document = _decode_row(row)
            comparison = document["comparison"]
            snapshots.append(
                {
                    "snapshot_id": document["snapshot_id"],
                    "digest": document["digest"],
                    "created_at": document["created_at"],
                    "run_ids": comparison["run_ids"],
                    "baseline_run_id": comparison["baseline_run_id"],
                }
            )
    return snapshots


def _identity(
    comparison: Mapping[str, Any], source_bindings: list[Mapping[str, Any]]
) -> dict[str, Any]:
    if (
        not isinstance(comparison, Mapping)
        or comparison.get("schema_version") != "bluefire.comparison.v1"
    ):
        raise ProductStoreError("comparison response schema is invalid")
    run_ids = comparison.get("run_ids")
    if (
        not isinstance(run_ids, list)
        or not 2 <= len(run_ids) <= MAX_COMPARISON_RUNS
        or any(
            not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None for run_id in run_ids
        )
        or len(set(run_ids)) != len(run_ids)
        or not isinstance(source_bindings, list)
        or len(source_bindings) != len(run_ids)
    ):
        raise ProductStoreError("comparison source bindings are invalid")
    summaries = comparison.get("summaries")
    bindings: list[dict[str, str]] = []
    for index, (run_id, binding) in enumerate(zip(run_ids, source_bindings, strict=True)):
        if not isinstance(binding, Mapping) or set(binding) not in (
            {"run_id", "bundle_hash"},
            {"run_id", "bundle_hash", "capability_objective_digest"},
        ):
            raise ProductStoreError("comparison source binding fields are invalid")
        bound_id, bundle_hash = binding.get("run_id"), binding.get("bundle_hash")
        if (
            bound_id != run_id
            or not isinstance(bundle_hash, str)
            or _DIGEST.fullmatch(bundle_hash) is None
        ):
            raise ProductStoreError("comparison source binding identity is invalid")
        projection = (
            summaries[index].get("capability_objective")
            if isinstance(summaries, list)
            and len(summaries) == len(run_ids)
            and isinstance(summaries[index], Mapping)
            and summaries[index].get("run_id") == run_id
            else None
        )
        proof_digest = binding.get("capability_objective_digest")
        if projection is None:
            if proof_digest is not None:
                raise ProductStoreError("comparison source has no capability objective proof")
        elif (
            not isinstance(proof_digest, str)
            or _DIGEST.fullmatch(proof_digest) is None
            or proof_digest != content_hash(projection)
        ):
            raise ProductStoreError("comparison capability objective binding is invalid")
        bindings.append(dict(binding))
    if comparison.get("baseline_run_id") != run_ids[0]:
        raise ProductStoreError("comparison baseline does not match its ordered runs")
    comparison_id = comparison.get("comparison_id")
    body = {key: value for key, value in comparison.items() if key != "comparison_id"}
    if comparison_id != "comparison-" + content_hash(body)[7:27]:
        raise ProductStoreError("comparison response identity does not match its content")
    try:
        encoded = canonical_json(comparison).encode("utf-8")
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise ProductStoreError("comparison response exceeds its snapshot byte limit")
        frozen_comparison = json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProductStoreError("comparison response is not valid bounded JSON") from exc
    return {"comparison": frozen_comparison, "source_bindings": bindings}


def _decode_row(row: sqlite3.Row) -> Mapping[str, Any]:
    raw = str(row["document_json"])
    try:
        raw_size = len(raw.encode("utf-8"))
    except UnicodeError as exc:
        raise SnapshotIntegrityError("saved comparison document encoding is invalid") from exc
    if raw_size > MAX_SNAPSHOT_BYTES:
        raise SnapshotIntegrityError("saved comparison exceeds its storage byte limit")
    try:
        document = json.loads(raw)
    except (TypeError, ValueError, RecursionError) as exc:
        raise SnapshotIntegrityError("saved comparison document is unreadable") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "snapshot_id",
        "digest",
        "created_at",
        "comparison",
        "source_bindings",
    }:
        raise SnapshotIntegrityError("saved comparison document fields are invalid")
    try:
        identity = _identity(document["comparison"], document["source_bindings"])
    except (ProductStoreError, TypeError, ValueError, RecursionError) as exc:
        raise SnapshotIntegrityError("saved comparison identity is invalid") from exc
    digest = content_hash(identity)
    snapshot_id = _SNAPSHOT_PREFIX + digest[7:]
    if (
        document.get("schema_version") != SCHEMA
        or document.get("snapshot_id") != snapshot_id
        or document.get("digest") != digest
        or document.get("created_at") != row["created_at"]
        or row["resource_id"] != snapshot_id
        or row["digest"] != digest
        or row["kind"] != "comparison"
        or row["status"] != "ready"
        or row["updated_at"] != row["created_at"]
    ):
        raise SnapshotIntegrityError("saved comparison failed identity or digest validation")
    return document
