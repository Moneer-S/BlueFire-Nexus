"""Bounded validation of runner recovery receipts and workspace paths."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .runner_private_files import _PinnedPrivateDirectory, _windows_extended_path
from .runner_transport_errors import RunnerTransportError
from .util import content_hash, parse_iso8601_datetime

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
_MAX_RECOVERY_FILES = 512
_MAX_RECOVERY_FILE_BYTES = 1024 * 1024 * 1024 * 1024


def _workspace_id_candidates(sandbox_root: Path) -> frozenset[str]:
    resolved = sandbox_root.resolve(strict=True)
    spellings = {str(resolved)}
    if os.name == "nt":
        raw = str(resolved)
        if raw.startswith("\\\\"):
            spellings.add("\\\\?\\UNC\\" + raw[2:])
        elif not raw.startswith("\\\\?\\"):
            spellings.add("\\\\?\\" + raw)
    return frozenset(
        hashlib.sha256(spelling.replace("\\", "/").encode("utf-8")).hexdigest()
        for spelling in spellings
    )


def discover_runner_receipts(
    sandbox_root: Path,
    *,
    expected_profile_id: str | None = None,
    expected_request_hash: str | None = None,
    expected_action_id: str | None = None,
    require_commit: bool = False,
    max_files: int = _MAX_RECOVERY_FILES,
    max_bytes: int = _MAX_RECOVERY_FILE_BYTES,
    _documents: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    if (expected_request_hash is None) != (expected_action_id is None):
        raise RunnerTransportError("runner receipt request filter is incomplete")
    if (
        not isinstance(require_commit, bool)
        or isinstance(max_files, bool)
        or not isinstance(max_files, int)
        or not 1 <= max_files <= _MAX_RECOVERY_FILES
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= _MAX_RECOVERY_FILE_BYTES
    ):
        raise RunnerTransportError("runner receipt discovery limits are invalid")
    receipt_root = sandbox_root / ".bluefire" / "receipts"
    try:
        (_windows_extended_path(receipt_root) if os.name == "nt" else receipt_root).lstat()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise RunnerTransportError("runner receipt directory could not be inspected") from exc
    try:
        workspace_ids = _workspace_id_candidates(sandbox_root)
        with contextlib.ExitStack() as stack:
            pinned = stack.enter_context(_PinnedPrivateDirectory(receipt_root))
            pinned_commits: _PinnedPrivateDirectory | None = None
            if require_commit:
                commit_root = sandbox_root / ".bluefire" / "receipt-commits"
                try:
                    (
                        _windows_extended_path(commit_root) if os.name == "nt" else commit_root
                    ).lstat()
                except FileNotFoundError:
                    return ()
                except OSError as exc:
                    raise RunnerTransportError(
                        "runner receipt commit directory could not be inspected"
                    ) from exc
                pinned_commits = stack.enter_context(_PinnedPrivateDirectory(commit_root))
            names = pinned.names(maximum=MAX_DISCOVERED_RECEIPTS)
            receipt_rows: list[tuple[datetime, str]] = []
            for name in names:
                entry = Path(name)
                receipt_id = entry.stem
                if entry.suffix != ".json" or not _is_lower_hex_digest(receipt_id):
                    raise RunnerTransportError("runner receipt entry is unsafe")
                try:
                    receipt_bytes = pinned.read(name, maximum=MAX_RECEIPT_BYTES)
                except (OSError, RunnerTransportError) as exc:
                    raise RunnerTransportError("runner receipt could not be read safely") from exc
                payload = _decode_receipt_document(receipt_bytes)
                workspace_id = payload.get("workspace_id")
                created_at = payload.get("created_at")
                if (
                    set(payload) != RECEIPT_FIELDS
                    or payload.get("schema_version") != "bluefire.receipt/v1"
                    or payload.get("receipt_id") != receipt_id
                    or not isinstance(payload.get("request_hash"), str)
                    or not isinstance(payload.get("action_id"), str)
                    or not isinstance(payload.get("runner_profile_id"), str)
                    or workspace_id not in workspace_ids
                    or not isinstance(created_at, str)
                    or not 1 <= len(created_at) <= 128
                    or not _valid_owned_receipt_paths(
                        payload.get("paths"), max_files=max_files, max_bytes=max_bytes
                    )
                ):
                    raise RunnerTransportError("runner receipt record is invalid")
                identity = {
                    "schema_version": "bluefire.receipt/v1",
                    "request_hash": payload["request_hash"],
                    "action_id": payload["action_id"],
                    "runner_profile_id": payload["runner_profile_id"],
                    "workspace_id": workspace_id,
                    "created_at": created_at,
                    "paths": payload["paths"],
                }
                if content_hash(identity) != f"sha256:{receipt_id}":
                    raise RunnerTransportError("runner receipt content digest is invalid")
                if (
                    expected_profile_id is not None
                    and payload.get("runner_profile_id") != expected_profile_id
                ):
                    raise RunnerTransportError("runner receipt belongs to another profile")
                if expected_request_hash is not None and (
                    payload.get("request_hash") != expected_request_hash
                    or payload.get("action_id") != expected_action_id
                ):
                    continue
                if pinned_commits is not None:
                    try:
                        commit_bytes = pinned_commits.read(
                            f"{receipt_id}.json", maximum=MAX_RECEIPT_BYTES
                        )
                    except FileNotFoundError:
                        continue
                    except (OSError, RunnerTransportError) as exc:
                        raise RunnerTransportError(
                            "runner receipt commit could not be read safely"
                        ) from exc
                    commit = _decode_receipt_document(commit_bytes)
                    committed_at = commit.get("committed_at")
                    if (
                        set(commit) != RECEIPT_COMMIT_FIELDS
                        or commit.get("schema_version") != "bluefire.receipt-commit/v1"
                        or commit.get("receipt_id") != receipt_id
                        or commit.get("runner_profile_id") != payload.get("runner_profile_id")
                        or commit.get("workspace_id") != workspace_id
                        or not isinstance(committed_at, str)
                        or not 1 <= len(committed_at) <= 128
                    ):
                        raise RunnerTransportError("runner receipt commit record is invalid")
                try:
                    parsed = parse_iso8601_datetime(created_at)
                except ValueError as exc:
                    raise RunnerTransportError("runner receipt timestamp is invalid") from exc
                if parsed.tzinfo is None:
                    raise RunnerTransportError("runner receipt timestamp is not timezone-aware")
                receipt_rows.append((parsed.astimezone(timezone.utc), receipt_id))
                if _documents is not None:
                    _documents[receipt_id] = dict(payload)
    except FileNotFoundError:
        raise RunnerTransportError("runner receipt directory changed during inspection") from None
    except RunnerTransportError:
        raise
    except OSError as exc:
        raise RunnerTransportError("runner receipt directory could not be read") from exc
    receipt_rows.sort()
    return tuple(receipt_id for _created_at, receipt_id in receipt_rows)


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
