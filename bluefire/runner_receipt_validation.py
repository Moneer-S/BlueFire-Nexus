"""Bounded validation of runner recovery receipts and workspace paths."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from .runner_transport_errors import RunnerTransportError

RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "request_hash",
        "action_id",
        "runner_profile_id",
        "workspace_id",
        "created_at",
        "paths",
    }
)
RECEIPT_COMMIT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "runner_profile_id",
        "workspace_id",
        "committed_at",
    }
)
_OWNED_PATH_FIELDS = frozenset({"relative_path", "kind", "sha256", "size"})
_LOWER_HEX_DIGEST = frozenset("0123456789abcdef")
MAX_DISCOVERED_RECEIPTS = 512
MAX_RECEIPT_BYTES = 256 * 1024


def _is_lower_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _LOWER_HEX_DIGEST for character in value)
    )


def _safe_receipt_path(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 4096
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 for character in value)
    ):
        return None
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    for component in candidate.parts:
        trimmed = component.rstrip(". ")
        base = trimmed.split(".", 1)[0].upper()
        if (
            component.casefold() == ".bluefire"
            or component.endswith((".", " "))
            or base in {"CON", "PRN", "AUX", "NUL"}
            or (
                len(base) == 4
                and (base.startswith("COM") or base.startswith("LPT"))
                and base[-1] in "123456789"
            )
        ):
            return None
    normalized = candidate.as_posix()
    return normalized if normalized == value else None


def _valid_owned_receipt_paths(paths: Any, *, max_files: int, max_bytes: int) -> bool:
    if not isinstance(paths, list) or not paths or len(paths) > min(max_files * 8, 4096):
        return False
    seen: set[str] = set()
    files: list[str] = []
    directories: list[str] = []
    total_size = 0
    for raw in paths:
        if not isinstance(raw, dict) or set(raw) != _OWNED_PATH_FIELDS:
            return False
        relative = _safe_receipt_path(raw.get("relative_path"))
        kind = raw.get("kind")
        if relative is None or relative in seen or kind not in {"file", "directory"}:
            return False
        seen.add(relative)
        if kind == "file":
            digest = raw.get("sha256")
            size = raw.get("size")
            if (
                not _is_lower_hex_digest(digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= max_bytes
            ):
                return False
            files.append(relative)
            total_size += size
        elif raw.get("sha256") is not None or raw.get("size") is not None:
            return False
        else:
            directories.append(relative)
    if not files or len(files) > max_files or total_size > max_files * max_bytes:
        return False
    return all(any(file.startswith(directory + "/") for file in files) for directory in directories)


def _decode_receipt_document(payload: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_non_finite(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RunnerTransportError("runner receipt could not be decoded") from exc
    if not isinstance(document, dict):
        raise RunnerTransportError("runner receipt record is invalid")
    return document


__all__ = [
    "MAX_DISCOVERED_RECEIPTS",
    "MAX_RECEIPT_BYTES",
    "RECEIPT_COMMIT_FIELDS",
    "RECEIPT_FIELDS",
    "_decode_receipt_document",
    "_is_lower_hex_digest",
    "_safe_receipt_path",
    "_valid_owned_receipt_paths",
]
