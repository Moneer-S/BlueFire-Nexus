"""Fail-closed file and public-text checks for acceptance evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PRIVATE_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]" r"|(?:^|[^A-Za-z0-9._~%+/\-])/(?:[^\s]|$))"
)
_FILE_URL = re.compile(r"(?<![A-Za-z0-9+.-])file:(?://+|\\\\)", re.IGNORECASE)
_REMOTE_HTTP_URI = re.compile(
    r"(?<![A-Za-z0-9+.-])https?://"
    r"(?:\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
    r"(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._~!$&'*+;=:@%/\-]*)?",
    re.IGNORECASE,
)
_AWS_PROFILE_URI = re.compile(
    r"(?<![A-Za-z0-9+.-])aws-profile://[A-Za-z0-9][A-Za-z0-9_.-]{0,63}" r"(?![A-Za-z0-9_.\-/])",
    re.IGNORECASE,
)
_PUBLIC_PATH_TEMPLATE = re.compile(r"\{(?:python|repository|run_dir|gate_dir|receipt)\}")
_JSON_PATH_ESCAPE = re.compile(r"\\u(?:002f|003a|005c)", re.IGNORECASE)
_BINARY_PRIVATE_PATH = re.compile(
    rb"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s\x00]+[\\/]"
    rb"|/(?:etc|home|Users|mnt/[A-Za-z]|opt|private|root|srv|tmp|usr|"
    rb"var/(?:lib|tmp)|workspace|workspaces)/)"
)
_BINARY_FILE_URL = re.compile(rb"(?<![A-Za-z0-9+.-])file:(?://+|\\\\)", re.IGNORECASE)
_TEXT_SCAN_LIMIT_BYTES = 64 * 1024 * 1024
_PUBLIC_ROUTE_KEYS = frozenset({"/ui/app.js", "/ui/styles.css"})
_MAX_JSON_SCAN_NODES = 1_000_000


def _wide_binary_patterns() -> tuple[re.Pattern[bytes], ...]:
    prefixes = [
        "file://",
        "file:\\\\",
        "/etc/",
        "/home/",
        "/Users/",
        "/opt/",
        "/private/",
        "/root/",
        "/srv/",
        "/tmp/",
        "/usr/",
        "/var/lib/",
        "/var/tmp/",
        "/workspace/",
        "/workspaces/",
    ]
    prefixes.extend(
        f"{letter}:{separator}"
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for separator in ("/", "\\")
    )
    prefixes.extend(f"/mnt/{letter}/" for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    patterns: list[re.Pattern[bytes]] = []
    for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        width = 2 if encoding.startswith("utf-16") else 4
        padding = b"\x00" * (width - 1)
        server_unit = (
            b"[A-Za-z0-9._-]" + padding if encoding.endswith("le") else padding + b"[A-Za-z0-9._-]"
        )
        unc = (
            re.escape("\\\\".encode(encoding))
            + b"(?:"
            + server_unit
            + b")+"
            + b"(?:"
            + re.escape("\\".encode(encoding))
            + b"|"
            + re.escape("/".encode(encoding))
            + b")"
        )
        encoded = [re.escape(item.encode(encoding)) for item in prefixes]
        patterns.append(re.compile(b"(?:" + b"|".join([*encoded, unc]) + b")", re.IGNORECASE))
    return tuple(patterns)


_WIDE_BINARY_PRIVATE_PATHS = _wide_binary_patterns()


class _JSONObjectPairs(list[tuple[str, Any]]):
    """JSON object representation that retains duplicate keys for privacy scans."""


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _json_value_contains_private_path(value: Any) -> bool:
    pending = [value]
    scanned = 0
    while pending:
        scanned += 1
        if scanned > _MAX_JSON_SCAN_NODES:
            return True
        item = pending.pop()
        if isinstance(item, _JSONObjectPairs):
            for key, child in item:
                if key not in _PUBLIC_ROUTE_KEYS and public_text_contains_private_path(key):
                    return True
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and public_text_contains_private_path(item):
            return True
    return False


def _decode_json_path_escapes(value: str) -> str:
    markers = {"002f": "/", "003a": ":", "005c": "\\"}
    unescaped = value.replace("\\/", "/")
    return _JSON_PATH_ESCAPE.sub(lambda match: markers[match.group()[-4:].casefold()], unescaped)


def _public_payload_contains_private_path(value: str) -> bool:
    """Scan JSON semantically, exempting only two exact object-key routes."""

    normalized = value.lstrip("\ufeff")
    try:
        parsed = json.loads(
            normalized,
            object_pairs_hook=_JSONObjectPairs,
            parse_constant=_reject_json_constant,
        )
        return _json_value_contains_private_path(parsed)
    except RecursionError:
        return True
    except json.JSONDecodeError:
        return public_text_contains_private_path(_decode_json_path_escapes(normalized))
    except (TypeError, ValueError):
        return True


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

    if _FILE_URL.search(value) is not None:
        return True
    without_templates = _PUBLIC_PATH_TEMPLATE.sub("relative", value)
    without_remote_uris = _REMOTE_HTTP_URI.sub(
        lambda match: " " * len(match.group()), without_templates
    )
    without_remote_uris = _AWS_PROFILE_URI.sub(
        lambda match: " " * len(match.group()), without_remote_uris
    )
    return _PRIVATE_PATH.search(without_remote_uris) is not None


def _wide_text_private_path(payload: bytes) -> tuple[bool, bool]:
    """Return whether a BOM was authoritative and whether any wide text is private."""

    authoritative_encoding: str | None = None
    if payload.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        authoritative_encoding = "utf-32"
    elif payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        authoritative_encoding = "utf-16"
    if authoritative_encoding is not None:
        try:
            value = payload.decode(authoritative_encoding)
        except UnicodeError:
            pass
        else:
            return True, _public_payload_contains_private_path(value)

    encodings: list[str] = []
    if len(payload) >= 2 and len(payload) % 2 == 0:
        encodings.extend(("utf-16-le", "utf-16-be"))
    if len(payload) >= 4 and len(payload) % 4 == 0:
        encodings.extend(("utf-32-le", "utf-32-be"))
    for encoding in dict.fromkeys(encodings):
        try:
            value = payload.decode(encoding)
        except UnicodeError:
            continue
        if _public_payload_contains_private_path(value):
            return False, True
    return False, False


def _wide_binary_contains_private_path(payload: bytes) -> bool:
    return any(pattern.search(payload) is not None for pattern in _WIDE_BINARY_PRIVATE_PATHS)


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
    text_scanned = False
    binary_fallback_required = True
    if b"\0" not in payload:
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            pass
        else:
            text_private_path = _public_payload_contains_private_path(text)
            text_scanned = True
            binary_fallback_required = False
    if not text_scanned:
        wide_authoritative, text_private_path = _wide_text_private_path(bytes(payload))
        if wide_authoritative:
            binary_fallback_required = False
    if binary_fallback_required and _wide_binary_contains_private_path(bytes(payload)):
        binary_private_path = True
    return AcceptanceArtifactInspection(
        path=path,
        sha256="sha256:" + digest.hexdigest(),
        size_bytes=int(after_open.st_size),
        contains_private_path=text_private_path
        or (binary_fallback_required and binary_private_path),
        payload=bytes(payload),
    )


__all__ = [
    "AcceptanceArtifactInspection",
    "contained_regular_file",
    "inspect_regular_file",
    "public_text_contains_private_path",
]
