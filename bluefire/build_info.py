"""Read-only artifact diagnostics; recorded identity is not security attestation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .version import __version__

_PACKAGE_ROOT = Path(__file__).resolve().parent
_UI_NAMES = ("app.js", "index.html", "styles.css")
_METADATA_FIELDS = {
    "schema_version",
    "version",
    "source_revision",
    "source_provenance",
    "ui_files",
    "ui_digest",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or not 0 < before.st_size <= maximum:
        raise ValueError("diagnostic resource unavailable")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise ValueError("diagnostic resource changed")
        parts = bytearray()
        while len(parts) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(parts)))
            if not chunk:
                break
            parts.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(parts) > maximum
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("diagnostic resource changed")
        return bytes(parts)
    finally:
        os.close(descriptor)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate metadata field")
        value[key] = item
    return value


def _metadata(payload: bytes) -> dict[str, Any]:
    value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    if (
        not isinstance(value, dict)
        or set(value) != _METADATA_FIELDS
        or value["schema_version"] != "bluefire.build-metadata.v1"
        or value["version"] != __version__
    ):
        raise ValueError("invalid build metadata")
    revision = value["source_revision"]
    if not (
        (revision is None and value["source_provenance"] == "unavailable")
        or (
            isinstance(revision, str)
            and re.fullmatch(r"[0-9a-f]{40}", revision)
            and value["source_provenance"] == "git_archive"
        )
    ):
        raise ValueError("invalid source identity")
    files = value["ui_files"]
    if not isinstance(files, list) or len(files) != len(_UI_NAMES):
        raise ValueError("invalid asset inventory")
    for item, name in zip(files, _UI_NAMES, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "sha256", "size"}
            or item["name"] != name
            or type(item["size"]) is not int
            or not 0 < item["size"] <= 8 * 1024 * 1024
            or not isinstance(item["sha256"], str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["sha256"])
        ):
            raise ValueError("invalid asset identity")
    if value["ui_digest"] != _digest(_canonical(files)):
        raise ValueError("invalid asset digest")
    return value


def build_info() -> dict[str, Any]:
    """Describe the loaded package and its fixed packaged assets, never Git/env."""
    files: list[dict[str, Any]] = []
    try:
        ui = _PACKAGE_ROOT / "ui"
        if ui.is_symlink() or not ui.is_dir():
            raise ValueError("asset directory unavailable")
        for name in _UI_NAMES:
            payload = _read_regular(ui / name, 8 * 1024 * 1024)
            files.append({"name": name, "sha256": _digest(payload), "size": len(payload)})
    except (OSError, ValueError):
        files = []
    ui_digest = _digest(_canonical(files)) if files else None
    metadata = None
    status = "unavailable"
    try:
        payload = _read_regular(_PACKAGE_ROOT / "_build_info.json", 16384)
        metadata = _metadata(payload)
        status = "embedded"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError, RecursionError):
        status = "invalid"
    return {
        "schema_version": "bluefire.build-info.v1",
        "product": {"name": "BlueFire Nexus", "version": __version__},
        "source": {
            "revision": metadata["source_revision"] if metadata else None,
            "provenance": metadata["source_provenance"] if metadata else "unavailable",
        },
        "build": {
            "metadata_status": status,
            "digest": _digest(_canonical(metadata)) if metadata else None,
        },
        "ui": {
            "digest": ui_digest,
            "files": files,
            "matches_build": ui_digest == metadata["ui_digest"] if metadata else None,
        },
    }
