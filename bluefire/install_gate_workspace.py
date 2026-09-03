"""Owner-private external workspace allocation for the GATE-01 workflow."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Protocol

from .runner_trust import RunnerTrustError


class _OwnerPrivate(Protocol):
    def __call__(self, path: Path, *, directory: bool) -> None: ...


@dataclass(frozen=True)
class WorkspaceDependencies:
    windows: bool
    runtime_root_max_chars: int
    workspace_directory: Pattern[str]
    runtime_directory: Pattern[str]
    runtime_temp_parent: Callable[[], Path]
    token_hex: Callable[[int], str]
    is_link_or_reparse: Callable[[Path], bool]
    owner_private: _OwnerPrivate
    bounded_remove: Callable[[Path, Path], bool]


def validated_directory(
    path: Path,
    *,
    label: str,
    is_link_or_reparse: Callable[[Path], bool],
) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        details = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(details.st_mode) or is_link_or_reparse(absolute) or resolved != absolute:
        raise ValueError(f"{label} is unsafe")
    return resolved


def validated_evidence_destination(
    path: Path,
    *,
    allowed_entries: frozenset[str],
    is_link_or_reparse: Callable[[Path], bool],
) -> Path:
    destination = validated_directory(
        path,
        label="Gate 01 evidence root",
        is_link_or_reparse=is_link_or_reparse,
    )
    entries = {entry.name: entry for entry in destination.iterdir()}
    unexpected = set(entries).difference(allowed_entries)
    if unexpected:
        raise ValueError("Gate 01 evidence directory contains stale or unsafe artifacts")
    for name, entry in entries.items():
        try:
            details = entry.lstat()
        except OSError as exc:
            raise ValueError("Gate 01 evidence directory contains unsafe artifacts") from exc
        expected_directory = name.startswith("runtime-")
        if (
            is_link_or_reparse(entry)
            or (expected_directory and not stat.S_ISDIR(details.st_mode))
            or (not expected_directory and not stat.S_ISREG(details.st_mode))
        ):
            raise ValueError("Gate 01 evidence directory contains unsafe artifacts")
    return destination


def _token_profile_fallback(token_temp: Path, *, windows: bool) -> Path | None:
    """Derive the token profile only from the fixed known-folder Temp layout."""

    if not windows or len(token_temp.parents) < 3:
        return None
    if (
        token_temp.name.casefold() != "temp"
        or token_temp.parent.name.casefold() != "local"
        or token_temp.parent.parent.name.casefold() != "appdata"
    ):
        return None
    return token_temp.parents[2]


def _short_external_parent(repository: Path, dependencies: WorkspaceDependencies) -> Path:
    token_temp = validated_directory(
        dependencies.runtime_temp_parent(),
        label="Gate 01 process-token temp root",
        is_link_or_reparse=dependencies.is_link_or_reparse,
    )
    candidates: list[tuple[Path, str]] = [(token_temp, "Gate 01 process-token temp root")]
    profile = _token_profile_fallback(token_temp, windows=dependencies.windows)
    if profile is not None:
        candidates.append((profile, "Gate 01 process-token profile root"))
    for candidate, label in candidates:
        parent = (
            token_temp
            if candidate == token_temp
            else validated_directory(
                candidate,
                label=label,
                is_link_or_reparse=dependencies.is_link_or_reparse,
            )
        )
        if parent == repository or parent.is_relative_to(repository):
            continue
        required_length = len(os.fspath(parent)) + 1 + len("b00000000")
        if not dependencies.windows or required_length <= dependencies.runtime_root_max_chars:
            return parent
    raise ValueError("Gate 01 process-token temp root is too deep for Windows runtime safety")


def _allocate_private_directory(
    parent: Path,
    *,
    prefix: str,
    dependencies: WorkspaceDependencies,
) -> Path:
    pattern = dependencies.workspace_directory if prefix == "a" else dependencies.runtime_directory
    for _attempt in range(32):
        candidate = parent / (prefix + dependencies.token_hex(4))
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ValueError("Gate 01 external workspace could not be allocated") from exc
        try:
            before = candidate.lstat()
            if dependencies.windows:
                dependencies.owner_private(candidate, directory=True)
            else:
                candidate.chmod(stat.S_IRWXU)
            after = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            if (
                not os.path.samestat(before, after)
                or not stat.S_ISDIR(after.st_mode)
                or dependencies.is_link_or_reparse(candidate)
                or resolved.parent != parent
                or pattern.fullmatch(candidate.name) is None
                or (os.name != "nt" and stat.S_IMODE(after.st_mode) != 0o700)
            ):
                raise ValueError("Gate 01 external workspace allocation was unsafe")
            return resolved
        except (OSError, RunnerTrustError):
            if not dependencies.bounded_remove(parent, candidate):
                raise ValueError("Gate 01 external workspace cleanup failed") from None
            raise ValueError("Gate 01 external workspace allocation was unsafe") from None
        except ValueError:
            if not dependencies.bounded_remove(parent, candidate):
                raise ValueError("Gate 01 external workspace cleanup failed") from None
            raise
    raise OSError("Gate 01 could not allocate an isolated external workspace")


def allocate_external_workspace(
    repository: Path,
    dependencies: WorkspaceDependencies,
) -> tuple[Path, Path, Path]:
    parent = _short_external_parent(repository, dependencies)
    workspace = _allocate_private_directory(parent, prefix="a", dependencies=dependencies)
    evidence = workspace / "g"
    try:
        evidence.mkdir(mode=0o700)
        if dependencies.windows:
            dependencies.owner_private(evidence, directory=True)
        else:
            evidence.chmod(stat.S_IRWXU)
        validated = validated_directory(
            evidence,
            label="Gate 01 external evidence root",
            is_link_or_reparse=dependencies.is_link_or_reparse,
        )
        if validated.is_relative_to(repository):
            raise ValueError("Gate 01 external evidence root is inside the checkout")
    except (OSError, RunnerTrustError, ValueError):
        if not dependencies.bounded_remove(parent, workspace):
            raise ValueError("Gate 01 external workspace cleanup failed") from None
        raise ValueError("Gate 01 external evidence root could not be secured") from None
    return parent, workspace, validated


def allocate_short_runtime_root(
    destination: Path,
    dependencies: WorkspaceDependencies,
    *,
    repository_root: Path | None = None,
) -> Path:
    """Allocate an exact helper-owned runtime without inheriting evidence path depth."""

    parent = validated_directory(
        destination.parent.parent,
        label="Gate 01 external runtime parent",
        is_link_or_reparse=dependencies.is_link_or_reparse,
    )
    required_length = len(os.fspath(parent)) + 1 + len("b00000000")
    if dependencies.windows and required_length > dependencies.runtime_root_max_chars:
        raise ValueError("Gate 01 acceptance output parent is too deep for Windows runtime safety")
    runtime = _allocate_private_directory(parent, prefix="b", dependencies=dependencies)
    if repository_root is not None and runtime.is_relative_to(repository_root.resolve(strict=True)):
        if not dependencies.bounded_remove(parent, runtime):
            raise ValueError("Gate 01 external runtime cleanup failed")
        raise ValueError("Gate 01 runtime allocation was inside the checkout")
    return runtime


__all__ = [
    "WorkspaceDependencies",
    "allocate_external_workspace",
    "allocate_short_runtime_root",
    "validated_directory",
    "validated_evidence_destination",
]
