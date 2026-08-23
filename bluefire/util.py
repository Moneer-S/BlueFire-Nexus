"""Small deterministic serialization and hashing helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON data deterministically without lossy fallbacks."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


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
