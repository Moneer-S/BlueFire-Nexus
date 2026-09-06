"""Append-only storage for bounded detector evaluations of immutable run evidence."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Mapping

from .product_store_errors import ProductStoreError
from .util import canonical_json_bytes, content_hash

EVALUATION_SCHEMA = "bluefire.detection-run-evaluation.v1"
_EVALUATION_ID = re.compile(r"^detection-evaluation-[0-9a-f]{64}$")
_CANDIDATE_ID = re.compile(r"^detection-[0-9a-f]{20}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_MAX_REPORT_BYTES = 256 * 1024
MAX_EVALUATIONS_PER_CANDIDATE = 256


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Run as part of the caller's existing schema-upgrade transaction."""
    if not connection.in_transaction:
        raise ProductStoreError("detection evaluation schema requires a transaction")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS detection_run_evaluations (
            evaluation_id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            report_json TEXT NOT NULL,
            digest TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS detection_run_evaluations_candidate
        ON detection_run_evaluations(candidate_id, created_at, evaluation_id)
        """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS detection_run_evaluations_no_update
        BEFORE UPDATE ON detection_run_evaluations
        BEGIN SELECT RAISE(ABORT, 'detection evaluations are immutable'); END
        """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS detection_run_evaluations_no_delete
        BEFORE DELETE ON detection_run_evaluations
        BEGIN SELECT RAISE(ABORT, 'detection evaluations are immutable'); END
        """)


def bind_report(document: Mapping[str, Any]) -> dict[str, Any]:
    if "evaluation_id" in document:
        raise ProductStoreError("evaluation identity must be derived from its report")
    return {**document, "evaluation_id": "detection-evaluation-" + content_hash(document)[7:]}


def _validated(document: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    if document.get("schema_version") != EVALUATION_SCHEMA:
        raise ProductStoreError("detection evaluation schema is invalid")
    evaluation_id = document.get("evaluation_id")
    candidate = document.get("candidate")
    source = document.get("source")
    created_at = document.get("created_at")
    if not isinstance(candidate, Mapping) or not isinstance(source, Mapping):
        raise ProductStoreError("detection evaluation source identities are missing")
    candidate_id = candidate.get("candidate_id")
    run_id = source.get("run_id")
    if (
        not isinstance(evaluation_id, str)
        or not _EVALUATION_ID.fullmatch(evaluation_id)
        or not isinstance(candidate_id, str)
        or not _CANDIDATE_ID.fullmatch(candidate_id)
        or not isinstance(run_id, str)
        or not _RUN_ID.fullmatch(run_id)
        or not isinstance(created_at, str)
        or not 1 <= len(created_at) <= 40
    ):
        raise ProductStoreError("detection evaluation identity is invalid")
    payload = dict(document)
    payload.pop("evaluation_id")
    if bind_report(payload)["evaluation_id"] != evaluation_id:
        raise ProductStoreError("detection evaluation identity does not match its content")
    encoded = canonical_json_bytes(document)
    if len(encoded) > _MAX_REPORT_BYTES:
        raise ProductStoreError("detection evaluation exceeds its report byte limit")
    return evaluation_id, candidate_id, run_id, encoded.decode("utf-8"), created_at


def save_report(connection: sqlite3.Connection, document: Mapping[str, Any]) -> Mapping[str, Any]:
    evaluation_id, candidate_id, run_id, encoded, created_at = _validated(document)
    existing = connection.execute(
        "SELECT * FROM detection_run_evaluations WHERE evaluation_id = ?", (evaluation_id,)
    ).fetchone()
    if existing is not None:
        return _read_row(existing)
    count = connection.execute(
        "SELECT COUNT(*) FROM detection_run_evaluations WHERE candidate_id = ?", (candidate_id,)
    ).fetchone()[0]
    if count >= MAX_EVALUATIONS_PER_CANDIDATE:
        raise ProductStoreError("candidate evaluation history limit reached")
    connection.execute(
        """INSERT INTO detection_run_evaluations
        (evaluation_id, candidate_id, run_id, report_json, digest, created_at)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (evaluation_id, candidate_id, run_id, encoded, content_hash(document), created_at),
    )
    return dict(document)


def list_reports(connection: sqlite3.Connection, candidate_id: str) -> list[Mapping[str, Any]]:
    if not isinstance(candidate_id, str) or not _CANDIDATE_ID.fullmatch(candidate_id):
        raise ProductStoreError("candidate evaluation identity is invalid")
    rows = connection.execute(
        """SELECT * FROM detection_run_evaluations WHERE candidate_id = ?
        ORDER BY created_at, evaluation_id LIMIT ?""",
        (candidate_id, MAX_EVALUATIONS_PER_CANDIDATE + 1),
    ).fetchall()
    if len(rows) > MAX_EVALUATIONS_PER_CANDIDATE:
        raise ProductStoreError("candidate evaluation history exceeds its limit")
    return [_read_row(row) for row in rows]


def _read_row(row: sqlite3.Row) -> Mapping[str, Any]:
    raw = str(row["report_json"])
    if len(raw.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ProductStoreError("persisted detection evaluation exceeds its byte limit")
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ProductStoreError("persisted detection evaluation is unreadable") from exc
    if not isinstance(document, dict):
        raise ProductStoreError("persisted detection evaluation is invalid")
    evaluation_id, candidate_id, run_id, _, created_at = _validated(document)
    if (evaluation_id, candidate_id, run_id, created_at) != (
        row["evaluation_id"],
        row["candidate_id"],
        row["run_id"],
        row["created_at"],
    ) or content_hash(document) != row["digest"]:
        raise ProductStoreError("persisted detection evaluation identity or digest is inconsistent")
    return document
