"""Canonical serialization and clock helpers for product persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


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


__all__ = ["canonical_json", "utc_now"]
