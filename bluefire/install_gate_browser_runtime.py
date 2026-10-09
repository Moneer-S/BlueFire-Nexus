"""Explicit external-tool identity for the isolated Gate 01 browser probe."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

import yaml

NODE_BINARY_ENV = "BLUEFIRE_ACCEPTANCE_NODE_BINARY"
NODE_SHA256_ENV = "BLUEFIRE_ACCEPTANCE_NODE_SHA256"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_MAX_BYTES = 256 * 1024 * 1024
_MAX_FILES = 10000


def _file_digest(path: Path) -> tuple[str, int]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 0x400
        or info.st_size > _MAX_BYTES
    ):
        raise ValueError("browser tooling file is not bounded and regular")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > _MAX_BYTES:
                raise ValueError("browser tooling file exceeded its bound")
            digest.update(chunk)
    after = path.lstat()
    if (
        size != info.st_size
        or not os.path.samestat(info, after)
        or info.st_mtime_ns != after.st_mtime_ns
    ):
        raise ValueError("browser tooling changed while inspected")
    return digest.hexdigest(), size


def _package_identity(package: Path, version: str) -> dict[str, Any]:
    rows: list[tuple[str, str, int]] = []
    total = 0
    entries = 0

    def fail_unreadable(error: OSError) -> None:
        raise error

    for parent, directories, files in os.walk(package, followlinks=False, onerror=fail_unreadable):
        entries += len(directories) + len(files)
        if entries > _MAX_FILES:
            raise ValueError("browser dependency exceeds the inventory bound")
        for name in directories + files:
            path = Path(parent) / name
            if path.resolve(strict=True) != path or path.is_symlink():
                raise ValueError("browser dependency escapes its canonical package root")
            if getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("browser dependency contains a reparse point")
        for name in files:
            path = Path(parent) / name
            digest, size = _file_digest(path)
            total += size
            rows.append((path.relative_to(package).as_posix(), digest, size))
            if len(rows) > _MAX_FILES or total > _MAX_BYTES:
                raise ValueError("browser dependency exceeds the inventory bound")
    metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
    if (
        not isinstance(metadata, dict)
        or metadata.get("name") != "playwright-core"
        or metadata.get("version") != version
    ):
        raise ValueError("browser dependency does not match the locked declaration")
    module_digest, _ = _file_digest(package / "index.mjs")
    return {
        "declared_name": "playwright-core",
        "declared_version": version,
        "entry_sha256": module_digest,
        "observed_tree_sha256": hashlib.sha256(
            json.dumps(sorted(rows), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "observed_files": len(rows),
        "observed_bytes": total,
        "integrity_scope": "observed external tooling bytes, not lockfile byte attestation",
    }


def browser_probe_runtime(repository: Path, source: Path) -> tuple[Path, Path, dict[str, Any]]:
    """Require owner-selected Node bytes and confine the existing pnpm dependency."""
    configured = os.environ.get(NODE_BINARY_ENV, "")
    expected = os.environ.get(NODE_SHA256_ENV, "")
    if not configured or not Path(configured).is_absolute() or not _DIGEST.fullmatch(expected):
        raise ValueError("Gate 01 requires an explicit Node 22 path and expected SHA-256")
    try:
        executable = Path(configured).resolve(strict=True)
        node_digest, node_size = _file_digest(executable)
        if node_digest != expected:
            raise ValueError("configured Node bytes do not match the reviewed digest")
        locked = yaml.safe_load(
            (source / "frontend" / "pnpm-lock.yaml").read_text(encoding="utf-8")
        )
        test_version = locked["importers"]["."]["devDependencies"]["@playwright/test"]["version"]
        playwright_version = locked["snapshots"][f"@playwright/test@{test_version}"][
            "dependencies"
        ]["playwright"]
        version = locked["snapshots"][f"playwright@{playwright_version}"]["dependencies"][
            "playwright-core"
        ]
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError("invalid locked core version")
        dependency_root = (repository / "frontend" / "node_modules").resolve(strict=True)
        store = dependency_root / ".pnpm"
        package = store / f"playwright-core@{version}" / "node_modules" / "playwright-core"
        if store.resolve(strict=True) != store or package.resolve(strict=True) != package:
            raise ValueError("browser dependency escapes its canonical dependency root")
        identity = {
            "schema_version": "bluefire.gate01-browser-tooling.v1",
            "purpose": "acceptance harness only, not a shipped product runtime",
            "node": {"sha256": node_digest, "size_bytes": node_size, "explicit_digest_match": True},
            "playwright_core": _package_identity(package, version),
        }
        return executable, package / "index.mjs", identity
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        raise ValueError(
            "Gate 01 browser tooling identity or locked pnpm confinement failed"
        ) from exc


def verify_browser_probe_runtime(node: Path, module: Path, identity: Mapping[str, Any]) -> None:
    """Recheck the previously recorded bytes immediately before releasing the code."""
    try:
        validate_browser_tooling_report(identity)
        version = identity["playwright_core"]["declared_version"]
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError("invalid tooling version")
        if (
            not node.is_absolute()
            or node.resolve(strict=True) != node
            or not module.is_absolute()
            or module.resolve(strict=True) != module
            or module.name != "index.mjs"
            or module.parent.name != "playwright-core"
            or module.parent.parent.name != "node_modules"
            or module.parent.parent.parent.name != f"playwright-core@{version}"
            or module.parent.parent.parent.parent.name != ".pnpm"
        ):
            raise ValueError("invalid canonical tooling paths")
        digest, size = _file_digest(node)
        if identity["node"] != {
            "sha256": digest,
            "size_bytes": size,
            "explicit_digest_match": True,
        } or identity["playwright_core"] != _package_identity(module.parent, version):
            raise ValueError("browser tooling bytes changed before launch")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gate 01 browser tooling changed before launch") from exc


def validate_browser_tooling_report(value: Mapping[str, Any]) -> None:
    """Keep published tooling evidence bounded, path-free and epistemically explicit."""
    try:
        core = value["playwright_core"]
        node = value["node"]
        valid = (
            set(value) == {"schema_version", "purpose", "node", "playwright_core"}
            and value["schema_version"] == "bluefire.gate01-browser-tooling.v1"
            and value["purpose"] == "acceptance harness only, not a shipped product runtime"
            and set(node) == {"sha256", "size_bytes", "explicit_digest_match"}
            and node["explicit_digest_match"] is True
            and set(core)
            == {
                "declared_name",
                "declared_version",
                "entry_sha256",
                "observed_tree_sha256",
                "observed_files",
                "observed_bytes",
                "integrity_scope",
            }
            and core["declared_name"] == "playwright-core"
            and isinstance(core["declared_version"], str)
            and _VERSION.fullmatch(core["declared_version"]) is not None
            and core["integrity_scope"]
            == "observed external tooling bytes, not lockfile byte attestation"
            and all(
                isinstance(digest, str) and _DIGEST.fullmatch(digest) is not None
                for digest in (node["sha256"], core["entry_sha256"], core["observed_tree_sha256"])
            )
            and all(
                type(count) is int and 0 < count <= limit
                for count, limit in (
                    (node["size_bytes"], _MAX_BYTES),
                    (core["observed_bytes"], _MAX_BYTES),
                    (core["observed_files"], _MAX_FILES),
                )
            )
        )
        if not valid:
            raise ValueError("invalid external tooling report")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gate 01 browser tooling report is invalid") from exc
