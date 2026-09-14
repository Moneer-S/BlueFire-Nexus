"""Small deterministic serialization and hashing helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

_RFC3339_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<offset>Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON data deterministically without lossy fallbacks."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_iso8601_datetime(value: str) -> datetime:
    """Parse the bounded RFC 3339 timestamp form emitted across the Rust boundary."""

    match = _RFC3339_TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("timestamp is not bounded RFC 3339")
    fraction = match.group("fraction")
    normalized_fraction = "" if fraction is None else "." + (fraction + "000000")[:6]
    offset = "+00:00" if match.group("offset") == "Z" else match.group("offset")
    return datetime.fromisoformat(
        match.group("date") + "T" + match.group("time") + normalized_fraction + offset
    )


def content_hash(value: Any) -> str:
    """Return a sha256-prefixed digest for canonical JSON data."""

    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def file_hash(path: Path) -> str:
    """Return a sha256-prefixed digest without loading a whole file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def json_clone(value: Any) -> Any:
    """Validate and detach a value through strict JSON serialization."""

    return json.loads(canonical_json_bytes(value))
