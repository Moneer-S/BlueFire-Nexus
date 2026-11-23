"""Canonical serialization and clock helpers for product persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Mapping


def utc_now() -> str:
    """Return the current UTC instant in canonical RFC 3339 form."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Serialize JSON deterministically and reject non-finite numbers."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def resource_row(row: sqlite3.Row) -> Mapping[str, Any]:
    """Decode a stored resource without changing its persisted metadata."""
    return {
        "kind": row["kind"],
        "id": row["resource_id"],
        "status": row["status"],
        "digest": row["digest"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "document": json.loads(row["document_json"]),
    }


__all__ = ["canonical_json", "resource_row", "utc_now"]
