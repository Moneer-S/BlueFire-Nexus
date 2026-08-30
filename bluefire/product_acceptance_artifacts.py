"""Fail-closed file and public-text checks for acceptance evidence."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PRIVATE_PATH = re.compile(r"(?:^|[\s(\[{'\"=])(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|/[^\s])")
_FILE_URL = re.compile(r"file:(?://+|\\\\)", re.IGNORECASE)
_BINARY_PRIVATE_PATH = re.compile(
    rb"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s\x00]+[\\/]"
    rb"|/(?:home|Users|mnt/[A-Za-z]|opt|private|root|tmp|var/tmp|workspace|workspaces)/)"
)
_BINARY_FILE_URL = re.compile(rb"file:(?://+|\\\\)", re.IGNORECASE)
_TEXT_SCAN_LIMIT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class AcceptanceArtifactInspection:
    """A stable digest plus the public-text privacy verdict for one file."""

    path: Path
    sha256: str
    size_bytes: int
    contains_private_path: bool
    payload: bytes


def public_text_contains_private_path(value: str) -> bool:
    """Return whether text discloses a local absolute path or file URL."""

    return _PRIVATE_PATH.search(value) is not None or _FILE_URL.search(value) is not None


def _is_link_or_reparse(details: Any) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _identity(details: Any) -> tuple[int, ...]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_mode),
        int(details.st_size),
        int(details.st_mtime_ns),
        int(details.st_nlink),
        int(getattr(details, "st_file_attributes", 0)),
    )


def _regular_file(details: Any, *, label: str) -> None:
    if _is_link_or_reparse(details) or not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{label} is not a safe regular file")
    if details.st_nlink != 1:
        raise ValueError(f"{label} is a multiply-linked file")


def contained_regular_file(root: Path, raw: str, *, label: str) -> Path:
    """Resolve a relative file without traversing links or reparse points."""

    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise ValueError(f"{label} path is invalid")
    portable = raw.replace("\\", "/")
    relative = PurePosixPath(portable)
    if (
        relative.is_absolute()
        or PureWindowsPath(raw).is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path escapes its evidence directory")

    resolved_root = root.resolve(strict=True)
    cursor = resolved_root
    for index, part in enumerate(relative.parts):
        candidate = cursor / part
        try:
            details = candidate.lstat()
        except OSError as exc:
            raise ValueError(f"{label} is absent or unreadable") from exc
        final = index + 1 == len(relative.parts)
        if final:
            _regular_file(details, label=label)
        elif _is_link_or_reparse(details) or not stat.S_ISDIR(details.st_mode):
            raise ValueError(f"{label} path contains an unsafe directory")
        cursor = candidate.resolve(strict=True)
        if not cursor.is_relative_to(resolved_root):
            raise ValueError(f"{label} path escapes its evidence directory")
    return cursor


def inspect_regular_file(root: Path, raw: str, *, label: str) -> AcceptanceArtifactInspection:
    """Hash and privacy-scan one contained file while proving stable identity."""

    path = contained_regular_file(root, raw, label=label)
    try:
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely") from exc

    digest = hashlib.sha256()
    payload = bytearray()
    payload_complete = True
    binary_private_path = False
    binary_tail = b""
    try:
        opened = os.fstat(descriptor)
        _regular_file(before, label=label)
        _regular_file(opened, label=label)
        if _identity(before) != _identity(opened):
            raise ValueError(f"{label} identity changed while opening")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            combined = binary_tail + block
            if _BINARY_PRIVATE_PATH.search(combined) or _BINARY_FILE_URL.search(combined):
                binary_private_path = True
            binary_tail = combined[-512:]
            if payload_complete and len(payload) + len(block) <= _TEXT_SCAN_LIMIT_BYTES:
                payload.extend(block)
            else:
                payload.clear()
                payload_complete = False
        after_open = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} cannot be read safely") from exc
    finally:
        os.close(descriptor)

    try:
        after_path = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} disappeared while being read") from exc
    _regular_file(after_open, label=label)
    _regular_file(after_path, label=label)
    if _identity(opened) != _identity(after_open) or _identity(after_open) != _identity(after_path):
        raise ValueError(f"{label} identity changed while being read")
    if not payload_complete:
        raise ValueError(f"{label} exceeds the bounded public-evidence scan limit")

    text_private_path = False
    if b"\0" not in payload:
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            pass
        else:
            text_private_path = public_text_contains_private_path(text)
    return AcceptanceArtifactInspection(
        path=path,
        sha256="sha256:" + digest.hexdigest(),
        size_bytes=int(after_open.st_size),
        contains_private_path=binary_private_path or text_private_path,
        payload=bytes(payload),
    )


__all__ = [
    "AcceptanceArtifactInspection",
    "contained_regular_file",
    "inspect_regular_file",
    "public_text_contains_private_path",
]
