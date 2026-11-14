"""Shared, side-effect-free primitives for Strix runtime closure assembly."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024**3
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class StrixRuntimeClosurePreparationError(RuntimeError):
    """The runtime closure could not be assembled exactly and safely."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _document_bytes(value: Any) -> bytes:
    return _canonical_json(value) + b"\n"


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_digest(value: str, label: str) -> str:
    normalized = value.removeprefix("sha256:")
    if _SHA256.fullmatch(normalized) is None:
        raise StrixRuntimeClosurePreparationError(f"{label} must be a SHA-256 digest")
    return normalized


def _strict_json(payload: bytes, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise StrixRuntimeClosurePreparationError(
                    f"{label} contains a duplicate JSON key"
                )
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StrixRuntimeClosurePreparationError(f"{label} is not canonical JSON") from exc


def _is_reparse(details: os.stat_result) -> bool:
    return bool(
        int(getattr(details, "st_file_attributes", 0))
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _read_regular(
    path: Path,
    maximum: int = MAX_FILE_BYTES,
    *,
    allow_empty: bool = True,
    allow_symlink: bool = False,
    allowed_roots: Iterable[Path] = (),
) -> bytes:
    logical = path
    try:
        logical_details = logical.lstat()
        resolved = logical.resolve(strict=True)
    except OSError as exc:
        raise StrixRuntimeClosurePreparationError(
            f"required input is unavailable: {logical.name}"
        ) from exc
    if stat.S_ISLNK(logical_details.st_mode) or _is_reparse(logical_details):
        if not allow_symlink:
            raise StrixRuntimeClosurePreparationError(
                f"input must not be a link: {logical.name}"
            )
        roots = tuple(root.resolve(strict=True) for root in allowed_roots)
        if not roots or not any(resolved == root or root in resolved.parents for root in roots):
            raise StrixRuntimeClosurePreparationError("input link escapes its reviewed root")
    try:
        before = resolved.lstat()
    except OSError as exc:
        raise StrixRuntimeClosurePreparationError("input cannot be inspected") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse(before)
        or before.st_size > maximum
        or (before.st_size == 0 and not allow_empty)
    ):
        raise StrixRuntimeClosurePreparationError("input is not a bounded regular file")
    try:
        payload = resolved.read_bytes()
        after = resolved.lstat()
    except OSError as exc:
        raise StrixRuntimeClosurePreparationError("input changed while read") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_ctime_ns", 0),
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_ctime_ns", 0),
    )
    if (
        len(payload) != before.st_size
        or identity_before != identity_after
        or not stat.S_ISREG(after.st_mode)
        or _is_reparse(after)
    ):
        raise StrixRuntimeClosurePreparationError("input identity changed while read")
    return payload


def _safe_relative(value: str, label: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise StrixRuntimeClosurePreparationError(f"{label} path is unsafe")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value.rstrip("/")
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(
            any(ord(character) < 32 or ord(character) == 127 for character in part)
            for part in path.parts
        )
    ):
        raise StrixRuntimeClosurePreparationError(f"{label} path is unsafe")
    return path


def _normalized_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _write_exclusive(path: Path, payload: bytes, mode: int = 0o444) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StrixRuntimeClosurePreparationError("closure write did not progress")
            view = view[written:]
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise StrixRuntimeClosurePreparationError("closure output is not standalone")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:  # pragma: no cover - exercised by the Windows contract tests
            path.chmod(mode)
    finally:
        os.close(descriptor)


def _copy_payload(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    mode: int = 0o444,
    destinations: dict[str, str],
) -> dict[str, Any]:
    path = _safe_relative(relative, "closure destination")
    casefolded = path.as_posix().casefold()
    if casefolded in destinations:
        raise StrixRuntimeClosurePreparationError(
            f"closure destination collides: {path.as_posix()}"
        )
    if len(payload) > MAX_FILE_BYTES:
        raise StrixRuntimeClosurePreparationError("closure member exceeds its byte bound")
    destination = root.joinpath(*path.parts)
    _write_exclusive(destination, payload, mode)
    destinations[casefolded] = path.as_posix()
    return {
        "path": path.as_posix(),
        "mode": mode,
        "size": len(payload),
        "content_digest": _digest_bytes(payload),
    }
