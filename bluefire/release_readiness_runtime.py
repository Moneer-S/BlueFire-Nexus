"""Ephemeral runtime helpers for release-readiness suites."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .runtime_paths import runtime_temp_parent as temp_parent
from .runtime_paths import trusted_git_environment, trusted_git_executable

_PRIVATE_PATH = re.compile(
    r"(?i)(?:[A-Z]:[\\/]" + r"Users[\\/][^\\/\s]+|/(?:home|" + r"Users)/[^/\s]+)"
)
_CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
_CYCLONEDX_SERIAL = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CYCLONEDX_COMPONENT_TYPES = frozenset(
    {
        "application",
        "container",
        "cryptographic-asset",
        "data",
        "device",
        "device-driver",
        "file",
        "firmware",
        "framework",
        "library",
        "machine-learning-model",
        "operating-system",
        "platform",
    }
)
_MAX_SBOM_BYTES = 16 * 1024 * 1024
_MAX_SBOM_NODES = 250_000
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def suite_environment(values: Mapping[str, str]) -> dict[str, str]:
    """Remove the enclosing acceptance authority from nested release suites."""

    return {
        name: value
        for name, value in values.items()
        if not name.casefold().startswith("bluefire_acceptance_")
    }


def _direct_regular_file(details: os.stat_result) -> bool:
    return bool(
        stat.S_ISREG(details.st_mode)
        and not stat.S_ISLNK(details.st_mode)
        and not int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
        and details.st_nlink == 1
    )


def regular_file_identity(path: Path) -> tuple[int, int, int, int] | None:
    """Return a bounded identity only for a direct single-link regular file."""

    try:
        details = path.lstat()
    except OSError:
        return None
    if not _direct_regular_file(details):
        return None
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)


def remove_regular_file(path: Path, identity: tuple[int, int, int, int] | None) -> bool:
    """Remove a private scratch file only while its captured identity is unchanged."""

    if identity is None or regular_file_identity(path) != identity:
        return False
    try:
        path.unlink()
    except OSError:
        return False
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def read_bounded_regular_file(path: Path, *, allow_empty: bool = False) -> bytes | None:
    """Read one direct single-link file within the release-suite byte budget."""

    descriptor: int | None = None
    try:
        original = path.lstat()
        if (
            not _direct_regular_file(original)
            or (not allow_empty and original.st_size == 0)
            or original.st_size > _MAX_SBOM_BYTES
        ):
            return None
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not _direct_regular_file(opened)
            or (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino)
            or opened.st_size != original.st_size
        ):
            return None
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            return None
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) or not _direct_regular_file(final):
            return None
        return b"".join(chunks)
    except (OSError, RecursionError, TypeError, ValueError):
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _valid_cyclonedx(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    components = value.get("components")
    dependencies = value.get("dependencies")
    if (
        value.get("$schema") != _CYCLONEDX_SCHEMA
        or value.get("bomFormat") != "CycloneDX"
        or value.get("specVersion") != "1.6"
        or type(value.get("version")) is not int
        or value["version"] < 1
        or not isinstance(value.get("serialNumber"), str)
        or _CYCLONEDX_SERIAL.fullmatch(value["serialNumber"]) is None
        or not isinstance(value.get("metadata"), dict)
        or not isinstance(components, list)
        or not components
        or not isinstance(dependencies, list)
    ):
        return False
    references: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            return False
        reference = component.get("bom-ref")
        name = component.get("name")
        component_type = component.get("type")
        version = component.get("version")
        if (
            not isinstance(reference, str)
            or not reference.strip()
            or not isinstance(name, str)
            or not name.strip()
            or not isinstance(component_type, str)
            or component_type not in _CYCLONEDX_COMPONENT_TYPES
            or not isinstance(version, str)
            or not version.strip()
        ):
            return False
        if reference in references:
            return False
        references.add(reference)
    dependency_references: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            return False
        reference = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        if (
            not isinstance(reference, str)
            or reference not in references
            or reference in dependency_references
            or not isinstance(depends_on, list)
            or any(not isinstance(item, str) or item not in references for item in depends_on)
        ):
            return False
        dependency_references.add(reference)
    return True


def _scrub_and_validate_identity(value: dict[str, Any]) -> bool:
    pending: list[Any] = [value]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > _MAX_SBOM_NODES:
            return False
        if isinstance(node, dict):
            references = node.get("externalReferences")
            if isinstance(references, list):
                cleaned = [
                    item
                    for item in references
                    if not (
                        isinstance(item, dict)
                        and isinstance(item.get("url"), str)
                        and item["url"].strip().casefold().startswith("file:")
                    )
                ]
                if cleaned:
                    node["externalReferences"] = cleaned
                else:
                    node.pop("externalReferences")
            pending.extend(node.keys())
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str) and (
            node.strip().casefold().startswith("file:") or _PRIVATE_PATH.search(node) is not None
        ):
            return False
    return True


def _publish_bounded_json(destination: Path, value: dict[str, Any]) -> bool:
    try:
        payload = (
            json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True).encode(
                "utf-8"
            )
            + b"\n"
        )
        parent = destination.parent.lstat()
    except (OSError, RecursionError, TypeError, ValueError):
        return False
    if (
        len(payload) > _MAX_SBOM_BYTES
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or bool(int(getattr(parent, "st_file_attributes", 0)) & _REPARSE_POINT)
    ):
        return False
    descriptor: int | None = None
    temporary: Path | None = None
    created_identity: tuple[int, int] | None = None
    succeeded = False
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=".gate12-sbom-",
            suffix=".json",
            dir=destination.parent,
        )
        temporary = Path(raw_temporary)
        details = os.fstat(descriptor)
        if not _direct_regular_file(details):
            raise OSError("the SBOM destination is not a direct regular file")
        created_identity = (details.st_dev, details.st_ino)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("the SBOM write made no progress")
            offset += written
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            not _direct_regular_file(final)
            or (final.st_dev, final.st_ino) != created_identity
            or final.st_size != len(payload)
        ):
            raise OSError("the SBOM destination changed during publication")
        os.close(descriptor)
        descriptor = None
        staged = temporary.lstat()
        if not _direct_regular_file(staged) or (staged.st_dev, staged.st_ino) != created_identity:
            raise OSError("the staged SBOM changed before publication")
        os.link(temporary, destination, follow_symlinks=False)
        published = destination.lstat()
        if (
            not stat.S_ISREG(published.st_mode)
            or stat.S_ISLNK(published.st_mode)
            or bool(int(getattr(published, "st_file_attributes", 0)) & _REPARSE_POINT)
            or (published.st_dev, published.st_ino) != created_identity
            or published.st_nlink != 2
        ):
            raise OSError("the published SBOM identity is invalid")
        temporary.unlink()
        temporary = None
        persisted = destination.lstat()
        if not _direct_regular_file(persisted) or (
            persisted.st_dev,
            persisted.st_ino,
            persisted.st_size,
        ) != (*created_identity, len(payload)):
            raise OSError("the published SBOM identity changed")
        succeeded = True
    except (OSError, TypeError, ValueError):
        succeeded = False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                succeeded = False
    if not succeeded and created_identity is not None:
        for candidate in (destination, temporary):
            if candidate is None:
                continue
            try:
                current = candidate.lstat()
                if (current.st_dev, current.st_ino) == created_identity:
                    candidate.unlink()
            except OSError:
                pass
    return succeeded


def sanitize_sbom_file(source: Path, destination: Path) -> bool:
    """Publish a bounded CycloneDX SBOM after removing machine-local references."""

    payload = read_bounded_regular_file(source)
    if payload is None:
        return False
    try:
        value = json.loads(payload.decode("utf-8"))
    except (RecursionError, UnicodeError, ValueError, json.JSONDecodeError):
        return False
    if not _valid_cyclonedx(value) or not _scrub_and_validate_identity(value):
        return False
    return _publish_bounded_json(destination, value)


def _tracked_payload(repository: Path) -> bytes | None:
    try:
        unresolved = Path(os.path.abspath(os.fspath(repository)))
        repository_details = unresolved.lstat()
        repository = unresolved.resolve(strict=True)
        if (
            repository != unresolved
            or not stat.S_ISDIR(repository_details.st_mode)
            or stat.S_ISLNK(repository_details.st_mode)
            or bool(int(getattr(repository_details, "st_file_attributes", 0)) & _REPARSE_POINT)
        ):
            return None
        executable = os.fspath(trusted_git_executable())
        environment = trusted_git_environment()
        completed = subprocess.run(
            [executable, "-c", f"safe.directory={repository}", "ls-files", "-z"],
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout if completed.returncode == 0 else None


def tracked_paths(repository: Path) -> list[str]:
    """List scanner inputs, failing closed when fixed Git is unavailable."""

    return [path for path in tracked_inventory(repository) if path != ".secrets.baseline"]


def tracked_inventory(repository: Path) -> list[str]:
    """List every tracked path only when the fixed-Git inventory is exact."""

    payload = _tracked_payload(repository)
    if payload is None:
        return []
    try:
        result = [item.decode("utf-8", "strict") for item in payload.split(b"\0") if item]
    except UnicodeError:
        return []
    return result if result and result == sorted(set(result)) else []


def tracked_snapshot(repository: Path) -> dict[str, str]:
    """Hash the tracked tree, failing closed on Git, decoding, or file errors."""

    result: dict[str, str] = {}
    for relative in tracked_inventory(repository):
        content = read_bounded_regular_file(repository / relative, allow_empty=True)
        if content is None:
            return {}
        result[relative] = hashlib.sha256(content).hexdigest()
    return result


def initialize_scan_repository(root: Path, environment: Mapping[str, str]) -> bool:
    """Create an isolated Git index for the archived baseline hook."""

    try:
        executable = os.fspath(trusted_git_executable())
        git_environment = trusted_git_environment(environment)
    except OSError:
        return False
    for arguments in (("init", "--quiet"), ("add", "--", ".secrets.baseline")):
        try:
            completed = subprocess.run(
                [executable, *arguments],
                cwd=root,
                env=git_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if completed.returncode != 0:
            return False
    return True


__all__ = [
    "initialize_scan_repository",
    "read_bounded_regular_file",
    "regular_file_identity",
    "remove_regular_file",
    "sanitize_sbom_file",
    "suite_environment",
    "temp_parent",
    "tracked_inventory",
    "tracked_paths",
    "tracked_snapshot",
]
