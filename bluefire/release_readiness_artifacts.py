"""Bounded hashing for persisted GATE-12 evidence artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Mapping

from .release_readiness_journey import JOURNEY_REPORT

_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_FILES = 1_024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_ROOT_REPORTS = frozenset(
    {
        JOURNEY_REPORT,
        "gate12-upstream-closure.json",
        "gate12-release-structure.json",
        "gate12-full-suite.json",
        "gate12-opsec-report.json",
        "gate12-python-sbom.json",
    }
)


class ReleaseArtifactError(ValueError):
    """Raised when persisted release evidence cannot be safely hashed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseArtifactError(message)


def _unsafe(details: os.stat_result) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _identity(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_size),
        int(details.st_mtime_ns),
        int(details.st_nlink),
    )


def _digest(root: Path, path: Path) -> tuple[str, int]:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseArtifactError("a release artifact is unavailable") from exc
    _require(
        resolved.is_relative_to(root)
        and stat.S_ISREG(before.st_mode)
        and not _unsafe(before)
        and before.st_nlink == 1
        and 0 < before.st_size <= _MAX_ARTIFACT_BYTES,
        "a release artifact is unsafe, empty, or unbounded",
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                size += len(block)
                _require(size <= _MAX_ARTIFACT_BYTES, "a release artifact exceeded its bound")
                digest.update(block)
        after = path.lstat()
    except OSError as exc:
        raise ReleaseArtifactError("a release artifact could not be hashed") from exc
    _require(
        size == before.st_size and _identity(before) == _identity(after),
        "a release artifact changed while it was hashed",
    )
    return "sha256:" + digest.hexdigest(), size


def persisted_artifact_hashes(destination: Path) -> Mapping[str, str]:
    """Hash every owned artifact except the self-referential verification report."""

    try:
        raw_details = destination.lstat()
        root = destination.resolve(strict=True)
        root_details = root.lstat()
    except OSError as exc:
        raise ReleaseArtifactError("the GATE-12 artifact root is unavailable") from exc
    _require(
        Path(os.path.abspath(destination)) == root
        and stat.S_ISDIR(raw_details.st_mode)
        and not _unsafe(raw_details)
        and stat.S_ISDIR(root_details.st_mode)
        and not _unsafe(root_details),
        "the GATE-12 artifact root is unsafe",
    )
    files: dict[str, Path] = {relative: root / relative for relative in _ROOT_REPORTS}
    stack = [root / "frontier", root / "operator"]
    directory_count = 0
    while stack:
        directory = stack.pop()
        try:
            details = directory.lstat()
            resolved = directory.resolve(strict=True)
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise ReleaseArtifactError("an artifact directory is unavailable") from exc
        _require(
            resolved.is_relative_to(root)
            and stat.S_ISDIR(details.st_mode)
            and not _unsafe(details),
            "an artifact directory is unsafe",
        )
        directory_count += 1
        _require(directory_count <= _MAX_FILES, "the artifact directory inventory is unbounded")
        for entry in entries:
            try:
                entry_details = entry.lstat()
            except OSError as exc:
                raise ReleaseArtifactError("an artifact entry is unreadable") from exc
            _require(not _unsafe(entry_details), "an artifact entry is a link or reparse point")
            if stat.S_ISDIR(entry_details.st_mode):
                stack.append(entry)
            elif stat.S_ISREG(entry_details.st_mode):
                relative = entry.relative_to(root).as_posix()
                _require(relative not in files, "the artifact inventory is ambiguous")
                files[relative] = entry
            else:
                raise ReleaseArtifactError("an artifact entry has an unsupported type")
            _require(len(files) <= _MAX_FILES, "the artifact file inventory is unbounded")
    result: dict[str, str] = {}
    total = 0
    for relative in sorted(files):
        digest, size = _digest(root, files[relative])
        total += size
        _require(total <= _MAX_TOTAL_BYTES, "the artifact inventory exceeds its total bound")
        result[relative] = digest
    return result


__all__ = ["ReleaseArtifactError", "persisted_artifact_hashes"]
