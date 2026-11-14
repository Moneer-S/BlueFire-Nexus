"""Build the exact minimal BlueFire worker wheel used by pinned Strix.

The full ``bluefire-nexus`` wheel is intentionally not an input.  Its product
dependency set is different from the reviewed Strix runtime (notably its
cryptography and PyNaCl requirements).  This builder reads an exact committed
source revision and emits a deterministic, PEP 420 namespace wheel containing
only the reviewed worker-side modules and one prompt-policy resource.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ARTIFACT_SCHEMA = "bluefire.strix-worker-runtime-artifact.v1"
RESULT_SCHEMA = "bluefire.strix-worker-runtime-build-result.v1"
INSTALLED_DISTRIBUTIONS_SCHEMA = "bluefire.strix-installed-distributions.v1"
DISTRIBUTION = "bluefire-strix-worker"
NORMALIZED_DISTRIBUTION = "bluefire_strix_worker"
ENTRY_MODULE = "bluefire.strix_controlled_installed_worker"
PYTHON_REQUIRES = "==3.12.*"
WHEEL_TAG = "py3-none-any"
PYTHON_ABI = "cp312"
PLATFORM_TAG = "linux_x86_64"
BUILDER_VERSION = 1

MODULE_PATHS = (
    "bluefire/strix_adapter.py",
    "bluefire/strix_controlled_backend.py",
    "bluefire/strix_controlled_bootstrap.py",
    "bluefire/strix_controlled_installed_worker.py",
    "bluefire/strix_controlled_worker_channel.py",
    "bluefire/strix_controlled_worker_invocation.py",
    "bluefire/strix_controlled_worker_launch.py",
    "bluefire/strix_controlled_worker_packets.py",
    "bluefire/strix_controlled_worker_rpc.py",
    "bluefire/strix_policy_overlay.py",
    "bluefire/strix_startup_overlay.py",
    "bluefire/util.py",
)
RESOURCE_PATHS = ("bluefire/data/strix_prompt_policy_overlay.txt",)
REQUIRES_DIST = (
    "openai-agents==0.19.0",
    "strix-agent==1.7.0",
)
REQUIRED_INSTALLED_DISTRIBUTIONS = (
    ("docker", "7.1.0"),
    ("openai-agents", "0.19.0"),
    ("strix-agent", "1.7.0"),
)
LOCKED_RUNTIME_VERSIONS = {
    "openai-agents": "0.19.0",
    "strix-agent": "1.7.0",
}
FORBIDDEN_DISTRIBUTIONS = ("bluefire-nexus",)
ALLOWED_DYNAMIC_IMPORTS = (
    "agents.sandbox.session",
    "agents.sandbox.snapshot",
    "agents.sandbox.types",
    "bluefire.strix_controlled_backend",
    "strix.interface.main",
    "strix.runtime.backends",
)

_REVISION = re.compile(r"^[0-9a-f]{40}$")
_PRODUCT_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:rc(0|[1-9][0-9]*))?$"
)
_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"((?:(?:==|>=|<=|>|<)[0-9]+(?:\.[0-9]+)*(?:rc[0-9]+)?)(?:,(?:==|>=|<=|>|<)[0-9]+(?:\.[0-9]+)*(?:rc[0-9]+)?)*)$"
)
_SPECIFIER = re.compile(r"(==|>=|<=|>|<)([0-9]+(?:\.[0-9]+)*(?:rc[0-9]+)?)")
_MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_RESOURCE_BYTES = 512 * 1024
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


class StrixWorkerArtifactError(RuntimeError):
    """The dedicated worker artifact could not be produced exactly."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _version_key(value: str) -> tuple[tuple[int, ...], int, int]:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)*)(?:rc([0-9]+))?", value)
    if match is None:
        raise StrixWorkerArtifactError("runtime dependency version is unsupported")
    release = tuple(int(item) for item in match.group(1).split("."))
    rc = match.group(2)
    return release, 1 if rc is None else 0, 0 if rc is None else int(rc)


def _compare_versions(left: str, right: str) -> int:
    left_release, left_stable, left_rc = _version_key(left)
    right_release, right_stable, right_rc = _version_key(right)
    width = max(len(left_release), len(right_release))
    left_key = left_release + (0,) * (width - len(left_release))
    right_key = right_release + (0,) * (width - len(right_release))
    return (left_key > right_key) - (left_key < right_key) or (
        (left_stable, left_rc) > (right_stable, right_rc)
    ) - ((left_stable, left_rc) < (right_stable, right_rc))


def validate_locked_requirements(
    requirements: Iterable[str], locked_versions: Mapping[str, str]
) -> tuple[str, ...]:
    """Validate the small, marker-free runtime requirement grammar exactly."""

    normalized_locks = {_normalize_name(name): version for name, version in locked_versions.items()}
    rows = tuple(requirements)
    if rows != tuple(sorted(set(rows))):
        raise StrixWorkerArtifactError("runtime requirements must be unique and sorted")
    for requirement in rows:
        match = _REQUIREMENT.fullmatch(requirement)
        if match is None:
            raise StrixWorkerArtifactError("runtime requirement grammar is unsupported")
        name = _normalize_name(match.group(1))
        locked = normalized_locks.get(name)
        if locked is None:
            raise StrixWorkerArtifactError(f"runtime dependency {name} is not locked")
        specifiers = tuple(_SPECIFIER.findall(match.group(2)))
        if not specifiers:
            raise StrixWorkerArtifactError("runtime requirement has no specifier")
        for operator, expected in specifiers:
            comparison = _compare_versions(locked, expected)
            accepted = {
                "==": comparison == 0,
                ">=": comparison >= 0,
                "<=": comparison <= 0,
                ">": comparison > 0,
                "<": comparison < 0,
            }[operator]
            if not accepted:
                raise StrixWorkerArtifactError(
                    f"runtime dependency {name} does not satisfy its reviewed lock"
                )
    return rows


def installed_distributions_digest(rows: Iterable[Mapping[str, str]]) -> str:
    """Bind the exact installed distribution metadata and RECORD identities."""

    result: list[dict[str, str]] = []
    for value in rows:
        if len(result) >= 1024:
            raise StrixWorkerArtifactError("installed distribution inventory is oversized")
        if not isinstance(value, Mapping) or set(value) != {
            "name",
            "version",
            "metadata_digest",
            "record_digest",
        }:
            raise StrixWorkerArtifactError("installed distribution row is invalid")
        name = value["name"]
        version = value["version"]
        metadata_digest = value["metadata_digest"]
        record_digest = value["record_digest"]
        if (
            not isinstance(name, str)
            or name != _normalize_name(name)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None
            or not isinstance(version, str)
            or not version
            or len(version) > 128
            or not version.isascii()
            or any(ord(character) < 33 or ord(character) == 127 for character in version)
            or not isinstance(metadata_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata_digest)
            or not isinstance(record_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", record_digest)
        ):
            raise StrixWorkerArtifactError("installed distribution identity is invalid")
        result.append(
            {
                "name": name,
                "version": version,
                "metadata_digest": metadata_digest,
                "record_digest": record_digest,
            }
        )
    if not result:
        raise StrixWorkerArtifactError("installed distribution inventory is empty")
    if result != sorted(result, key=lambda item: item["name"]) or len(
        {item["name"] for item in result}
    ) != len(result):
        raise StrixWorkerArtifactError(
            "installed distribution identities must be unique and sorted"
        )
    if any(item["name"] in FORBIDDEN_DISTRIBUTIONS for item in result):
        raise StrixWorkerArtifactError("full BlueFire product distribution is forbidden")
    return _digest(
        _canonical_json(
            {
                "schema_version": INSTALLED_DISTRIBUTIONS_SCHEMA,
                "distributions": result,
            }
        )
    )


def _module_name(path: str) -> str:
    if not path.endswith(".py"):
        raise StrixWorkerArtifactError("worker module path is invalid")
    return path[:-3].replace("/", ".")


def _relative_import(module: str, level: int, target: str | None, alias: str) -> str:
    package = module.rpartition(".")[0]
    parts = package.split(".") if package else []
    if level < 1 or level > len(parts):
        raise StrixWorkerArtifactError("worker relative import escapes its package")
    base = parts[: len(parts) - level + 1]
    if target:
        base.extend(target.split("."))
    else:
        base.append(alias)
    return ".".join(base)


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_dynamic_imports(tree: ast.AST, path: str) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"__import__", "eval", "exec"}:
            # The reviewed startup overlay uses compile, but never a dynamic
            # import primitive. The fixed policy overlay resource is data.
            if name == "__import__":
                raise StrixWorkerArtifactError("worker uses an unreviewed import primitive")
            continue
        positions: tuple[int, ...]
        if name in {"module_loader", "importlib.import_module"}:
            positions = (0,)
        elif name == "_load":
            positions = (1,)
        else:
            continue
        found = False
        for index in positions:
            argument = node.args[index] if index < len(node.args) else None
            if isinstance(argument, ast.Constant):
                value = argument.value
                if isinstance(value, str) and _MODULE_NAME.fullmatch(value):
                    result.add(value)
                    found = True
        reviewed_loader_forward = (
            path == "bluefire/strix_controlled_bootstrap.py"
            and name == "module_loader"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "name"
        )
        if not found and not reviewed_loader_forward:
            raise StrixWorkerArtifactError("worker dynamic import is not a fixed literal")
    return result


def _validate_sources(
    sources: Mapping[str, bytes], *, stdlib_roots: frozenset[str]
) -> tuple[list[dict[str, Any]], str]:
    if set(sources) != set(MODULE_PATHS):
        raise StrixWorkerArtifactError("worker module inventory is not exact")
    known_modules = {_module_name(path) for path in MODULE_PATHS}
    graph: dict[str, dict[str, list[str]]] = {}
    all_dynamic: set[str] = set()
    for path in MODULE_PATHS:
        payload = sources[path]
        if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_SOURCE_BYTES:
            raise StrixWorkerArtifactError("worker module is empty or oversized")
        if b"\x00" in payload:
            raise StrixWorkerArtifactError("worker module contains a NUL byte")
        try:
            text = payload.decode("utf-8")
            tree = ast.parse(text, filename=path)
        except (UnicodeError, SyntaxError):
            raise StrixWorkerArtifactError("worker module is not valid UTF-8 Python") from None
        module = _module_name(path)
        local: set[str] = set()
        external: set[str] = set()
        for node in ast.walk(tree):
            candidates: list[str] = []
            if isinstance(node, ast.Import):
                candidates.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    candidates.extend(
                        _relative_import(module, node.level, node.module, alias.name)
                        for alias in node.names
                    )
                elif node.module:
                    candidates.append(node.module)
            for candidate in candidates:
                if candidate in known_modules:
                    local.add(candidate)
                    continue
                if candidate == "bluefire" or candidate.startswith("bluefire."):
                    raise StrixWorkerArtifactError(
                        "worker imports a BlueFire module outside its runtime closure"
                    )
                root = candidate.split(".", 1)[0]
                if root not in stdlib_roots and root != "__future__":
                    raise StrixWorkerArtifactError(
                        "worker imports an undeclared third-party module"
                    )
                external.add(candidate)
        dynamic = _literal_dynamic_imports(tree, path)
        all_dynamic.update(dynamic)
        graph[module] = {
            "local": sorted(local),
            "stdlib": sorted(external),
            "dynamic": sorted(dynamic),
        }
    if tuple(sorted(all_dynamic)) != ALLOWED_DYNAMIC_IMPORTS:
        raise StrixWorkerArtifactError("worker dynamic import inventory changed")
    reachable: set[str] = set()
    pending = [ENTRY_MODULE]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        if current not in graph:
            raise StrixWorkerArtifactError("worker entry module is unavailable")
        reachable.add(current)
        pending.extend(graph[current]["local"])
    if reachable != known_modules:
        raise StrixWorkerArtifactError("worker artifact contains an unreachable local module")
    rows = [
        {"path": path, "content_digest": _digest(sources[path]), "size": len(sources[path])}
        for path in MODULE_PATHS
    ]
    return rows, _digest(_canonical_json(graph))


def _validate_resources(resources: Mapping[str, bytes]) -> list[dict[str, Any]]:
    if set(resources) != set(RESOURCE_PATHS):
        raise StrixWorkerArtifactError("worker resource inventory is not exact")
    rows = []
    for path in RESOURCE_PATHS:
        payload = resources[path]
        if (
            not isinstance(payload, bytes)
            or not 0 < len(payload) <= _MAX_RESOURCE_BYTES
            or b"\x00" in payload
        ):
            raise StrixWorkerArtifactError("worker resource is empty, oversized, or binary")
        try:
            payload.decode("utf-8")
        except UnicodeError:
            raise StrixWorkerArtifactError("worker resource is not UTF-8") from None
        rows.append({"path": path, "content_digest": _digest(payload), "size": len(payload)})
    return rows


def _artifact_version(product_version: str, source_revision: str) -> str:
    if _PRODUCT_VERSION.fullmatch(product_version) is None:
        raise StrixWorkerArtifactError("product version is not a stable or RC version")
    if _REVISION.fullmatch(source_revision) is None:
        raise StrixWorkerArtifactError("worker source revision is invalid")
    return f"{product_version}+g{source_revision[:12]}"


def _metadata(version: str, source_revision: str) -> bytes:
    lines = [
        "Metadata-Version: 2.3",
        f"Name: {DISTRIBUTION}",
        f"Version: {version}",
        "Summary: Exact installed BlueFire controller worker for pinned Strix",
        "License: MIT",
        f"Requires-Python: {PYTHON_REQUIRES}",
        *[f"Requires-Dist: {item}" for item in REQUIRES_DIST],
        (
            "Project-URL: BlueFire Source, "
            "https://github.com/Moneer-S/BlueFire-Nexus/commit/" + source_revision
        ),
        "",
        "Dedicated controller worker artifact; not a standalone product package.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        f"Generator: bluefire-strix-worker-builder/{BUILDER_VERSION}\n"
        "Root-Is-Purelib: true\n"
        f"Tag: {WHEEL_TAG}\n\n"
    ).encode("ascii")


def _record(members: Mapping[str, bytes], record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(members):
        payload = members[path]
        writer.writerow((path, _record_hash(payload), str(len(payload))))
    writer.writerow((record_path, "", ""))
    return output.getvalue().encode("utf-8")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.flag_bits = 0x800
    return info


def _inventory_rows(value: Any, paths: tuple[str, ...], label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(paths):
        raise StrixWorkerArtifactError(f"worker {label} inventory is invalid")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "content_digest", "size"}:
            raise StrixWorkerArtifactError(f"worker {label} inventory row is invalid")
        path = item["path"]
        digest = item["content_digest"]
        size = item["size"]
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size <= 0
        ):
            raise StrixWorkerArtifactError(f"worker {label} identity is invalid")
        result.append({"path": path, "content_digest": digest, "size": size})
    if tuple(item["path"] for item in result) != paths:
        raise StrixWorkerArtifactError(f"worker {label} paths are not exact")
    return result


def inspect_artifact(
    path: Path, *, expected_source_revision: str | None = None
) -> dict[str, Any]:
    """Validate and identify an already-built dedicated worker wheel."""

    try:
        details = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise StrixWorkerArtifactError("worker artifact is unavailable") from exc
    if (
        not path.is_file()
        or path.is_symlink()
        or details.st_nlink != 1
        or not 0 < len(payload) <= _MAX_ARTIFACT_BYTES
    ):
        raise StrixWorkerArtifactError("worker artifact file identity is invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if (
                not names
                or len(names) != len(set(names))
                or len({name.casefold() for name in names}) != len(names)
                or names != sorted(names)
            ):
                raise StrixWorkerArtifactError("worker wheel member inventory is invalid")
            for info in infos:
                member = info.filename
                parts = member.split("/")
                if (
                    not member
                    or member.startswith("/")
                    or "\\" in member
                    or any(part in {"", ".", ".."} for part in parts)
                    or info.is_dir()
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.file_size > _MAX_SOURCE_BYTES
                    or info.external_attr >> 16 & 0o170777 != 0o100644
                ):
                    raise StrixWorkerArtifactError("worker wheel member is unsafe")
            members = {info.filename: archive.read(info) for info in infos}
    except (OSError, zipfile.BadZipFile, RuntimeError):
        raise StrixWorkerArtifactError("worker artifact is not an exact wheel") from None

    manifest_paths = [
        name for name in members if name.endswith(".dist-info/bluefire_worker_runtime.json")
    ]
    if len(manifest_paths) != 1:
        raise StrixWorkerArtifactError("worker artifact manifest is unavailable")
    manifest_path = manifest_paths[0]
    dist_info = manifest_path.rsplit("/", 1)[0]
    try:
        manifest = json.loads(members[manifest_path])
    except (UnicodeError, json.JSONDecodeError):
        raise StrixWorkerArtifactError("worker artifact manifest is invalid") from None
    manifest_fields = {
        "schema_version",
        "distribution",
        "version",
        "worker_source_revision",
        "entry_module",
        "entrypoint_digest",
        "requires_python",
        "python_abi",
        "platform_tag",
        "wheel_tag",
        "module_inventory",
        "resource_inventory",
        "requires_dist",
        "required_installed_distributions",
        "forbidden_distributions",
        "allowed_dynamic_imports",
        "import_graph_digest",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != manifest_fields
        or members[manifest_path] != _canonical_json(manifest) + b"\n"
        or manifest["schema_version"] != ARTIFACT_SCHEMA
        or manifest["distribution"] != DISTRIBUTION
        or manifest["entry_module"] != ENTRY_MODULE
        or manifest["requires_python"] != PYTHON_REQUIRES
        or manifest["python_abi"] != PYTHON_ABI
        or manifest["platform_tag"] != PLATFORM_TAG
        or manifest["wheel_tag"] != WHEEL_TAG
        or manifest["requires_dist"] != list(REQUIRES_DIST)
        or manifest["required_installed_distributions"]
        != [
            {"name": name, "version": version}
            for name, version in REQUIRED_INSTALLED_DISTRIBUTIONS
        ]
        or manifest["forbidden_distributions"] != list(FORBIDDEN_DISTRIBUTIONS)
        or manifest["allowed_dynamic_imports"] != list(ALLOWED_DYNAMIC_IMPORTS)
        or not isinstance(manifest["version"], str)
        or not isinstance(manifest["worker_source_revision"], str)
        or _REVISION.fullmatch(manifest["worker_source_revision"]) is None
        or not isinstance(manifest["import_graph_digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["import_graph_digest"]) is None
    ):
        raise StrixWorkerArtifactError("worker artifact contract does not match")
    source_revision = manifest["worker_source_revision"]
    version = manifest["version"]
    if (
        version != _artifact_version(version.split("+g", 1)[0], source_revision)
        or (expected_source_revision is not None and source_revision != expected_source_revision)
        or dist_info != f"{NORMALIZED_DISTRIBUTION}-{version}.dist-info"
        or path.name != f"{NORMALIZED_DISTRIBUTION}-{version}-{WHEEL_TAG}.whl"
    ):
        raise StrixWorkerArtifactError("worker artifact version or revision changed")
    module_rows = _inventory_rows(manifest["module_inventory"], MODULE_PATHS, "module")
    resource_rows = _inventory_rows(
        manifest["resource_inventory"], RESOURCE_PATHS, "resource"
    )
    inventory = module_rows + resource_rows
    for item in inventory:
        member = members.get(item["path"])
        if (
            member is None
            or len(member) != item["size"]
            or _digest(member) != item["content_digest"]
        ):
            raise StrixWorkerArtifactError("worker artifact member identity changed")
    entrypoint = next(
        item
        for item in module_rows
        if item["path"] == "bluefire/strix_controlled_installed_worker.py"
    )
    if manifest["entrypoint_digest"] != entrypoint["content_digest"]:
        raise StrixWorkerArtifactError("worker artifact entrypoint changed")

    metadata_path = f"{dist_info}/METADATA"
    wheel_path = f"{dist_info}/WHEEL"
    record_path = f"{dist_info}/RECORD"
    expected_members = {
        *MODULE_PATHS,
        *RESOURCE_PATHS,
        metadata_path,
        wheel_path,
        manifest_path,
        record_path,
    }
    if (
        set(members) != expected_members
        or members.get(metadata_path) != _metadata(version, source_revision)
        or members.get(wheel_path) != _wheel_metadata()
    ):
        raise StrixWorkerArtifactError("worker wheel layout or metadata changed")
    try:
        rows = list(csv.reader(io.StringIO(members[record_path].decode("utf-8"))))
    except (UnicodeError, csv.Error):
        raise StrixWorkerArtifactError("worker RECORD is invalid") from None
    if len(rows) != len(members) or any(len(row) != 3 for row in rows):
        raise StrixWorkerArtifactError("worker RECORD shape is invalid")
    record = {row[0]: (row[1], row[2]) for row in rows}
    if len(record) != len(rows) or set(record) != set(members) or record[record_path] != ("", ""):
        raise StrixWorkerArtifactError("worker RECORD inventory changed")
    for member_path, member in members.items():
        if member_path == record_path:
            continue
        if record[member_path] != (_record_hash(member), str(len(member))):
            raise StrixWorkerArtifactError("worker RECORD identity changed")
    return {
        "schema_version": "bluefire.strix-worker-runtime-identity.v1",
        "distribution": DISTRIBUTION,
        "version": version,
        "worker_source_revision": source_revision,
        "entry_module": ENTRY_MODULE,
        "entrypoint_digest": manifest["entrypoint_digest"],
        "artifact_digest": _digest(payload),
        "artifact_size": len(payload),
        "manifest_path": manifest_path,
        "manifest_digest": _digest(members[manifest_path]),
        "worker_record_digest": _digest(members[record_path]),
        "import_graph_digest": manifest["import_graph_digest"],
        "wheel_tag": WHEEL_TAG,
    }


def build_artifact_from_sources(
    *,
    sources: Mapping[str, bytes],
    resources: Mapping[str, bytes],
    source_revision: str,
    product_version: str,
    output_directory: Path,
    stdlib_roots: frozenset[str],
) -> dict[str, Any]:
    """Build one wheel from already authenticated source bytes."""

    if _REVISION.fullmatch(source_revision) is None:
        raise StrixWorkerArtifactError("worker source revision is invalid")
    validate_locked_requirements(REQUIRES_DIST, LOCKED_RUNTIME_VERSIONS)
    module_rows, graph_digest = _validate_sources(sources, stdlib_roots=stdlib_roots)
    resource_rows = _validate_resources(resources)
    version = _artifact_version(product_version, source_revision)
    dist_info = f"{NORMALIZED_DISTRIBUTION}-{version}.dist-info"
    manifest_path = f"{dist_info}/bluefire_worker_runtime.json"
    manifest = {
        "schema_version": ARTIFACT_SCHEMA,
        "distribution": DISTRIBUTION,
        "version": version,
        "worker_source_revision": source_revision,
        "entry_module": ENTRY_MODULE,
        "entrypoint_digest": _digest(sources["bluefire/strix_controlled_installed_worker.py"]),
        "requires_python": PYTHON_REQUIRES,
        "python_abi": PYTHON_ABI,
        "platform_tag": PLATFORM_TAG,
        "wheel_tag": WHEEL_TAG,
        "module_inventory": module_rows,
        "resource_inventory": resource_rows,
        "requires_dist": list(REQUIRES_DIST),
        "required_installed_distributions": [
            {"name": name, "version": version} for name, version in REQUIRED_INSTALLED_DISTRIBUTIONS
        ],
        "forbidden_distributions": list(FORBIDDEN_DISTRIBUTIONS),
        "allowed_dynamic_imports": list(ALLOWED_DYNAMIC_IMPORTS),
        "import_graph_digest": graph_digest,
    }
    members = {**sources, **resources}
    members[f"{dist_info}/METADATA"] = _metadata(version, source_revision)
    members[f"{dist_info}/WHEEL"] = _wheel_metadata()
    members[manifest_path] = _canonical_json(manifest) + b"\n"
    record_path = f"{dist_info}/RECORD"
    members[record_path] = _record(members, record_path)

    output_directory.mkdir(parents=True, exist_ok=True)
    filename = f"{NORMALIZED_DISTRIBUTION}-{version}-{WHEEL_TAG}.whl"
    destination = output_directory / filename
    if destination.exists():
        raise StrixWorkerArtifactError("worker artifact output already exists")
    try:
        with destination.open("xb") as raw:
            with zipfile.ZipFile(raw, "w", allowZip64=True, strict_timestamps=True) as archive:
                archive.comment = b""
                for path in sorted(members):
                    archive.writestr(_zip_info(path), members[path])
            raw.flush()
            os.fsync(raw.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    payload = destination.read_bytes()
    return {
        "schema_version": RESULT_SCHEMA,
        "artifact_path": str(destination),
        "artifact_digest": _digest(payload),
        "artifact_size": len(payload),
        "manifest_path": manifest_path,
        "manifest_digest": _digest(members[manifest_path]),
        "worker_record_digest": _digest(members[record_path]),
        "worker_source_revision": source_revision,
        "version": version,
        "entry_module": ENTRY_MODULE,
        "production_ready": False,
    }


def _git(repository: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StrixWorkerArtifactError("worker source repository is unavailable") from exc
    if process.returncode != 0:
        raise StrixWorkerArtifactError("worker source revision is unavailable")
    return process.stdout


def _git_blob(repository: Path, source_revision: str, path: str, maximum: int) -> bytes:
    size_payload = _git(repository, "cat-file", "-s", f"{source_revision}:{path}")
    try:
        size = int(size_payload.decode("ascii").strip())
    except (UnicodeError, ValueError):
        raise StrixWorkerArtifactError("worker source blob size is invalid") from None
    if not 0 < size <= maximum:
        raise StrixWorkerArtifactError("worker source blob is empty or oversized")
    payload = _git(repository, "show", f"{source_revision}:{path}")
    if len(payload) != size:
        raise StrixWorkerArtifactError("worker source blob changed while reading")
    return payload


def _product_version(payload: bytes) -> str:
    try:
        tree = ast.parse(payload.decode("utf-8"), filename="bluefire/version.py")
    except (UnicodeError, SyntaxError):
        raise StrixWorkerArtifactError("product version source is invalid") from None
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1 or _PRODUCT_VERSION.fullmatch(values[0]) is None:
        raise StrixWorkerArtifactError("product version source is ambiguous")
    return values[0]


def build_artifact(
    *, repository: Path, source_revision: str, output_directory: Path
) -> dict[str, Any]:
    if sys.platform != "linux" or sys.version_info[:3] != (3, 12, 14):
        raise StrixWorkerArtifactError("worker artifact build requires Linux CPython 3.12.14")
    repository = repository.resolve(strict=True)
    if _REVISION.fullmatch(source_revision) is None:
        raise StrixWorkerArtifactError("worker source revision is invalid")
    top = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip())
    if top.resolve(strict=True) != repository:
        raise StrixWorkerArtifactError("worker source repository root is not exact")
    _git(repository, "cat-file", "-e", source_revision + "^{commit}")
    sources = {
        path: _git_blob(repository, source_revision, path, _MAX_SOURCE_BYTES)
        for path in MODULE_PATHS
    }
    resources = {
        path: _git_blob(repository, source_revision, path, _MAX_RESOURCE_BYTES)
        for path in RESOURCE_PATHS
    }
    product_version = _product_version(
        _git_blob(repository, source_revision, "bluefire/version.py", 64 * 1024)
    )
    return build_artifact_from_sources(
        sources=sources,
        resources=resources,
        source_revision=source_revision,
        product_version=product_version,
        output_directory=output_directory,
        stdlib_roots=frozenset(sys.stdlib_module_names),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = build_artifact(
            repository=arguments.repository,
            source_revision=arguments.source_revision,
            output_directory=arguments.output_directory,
        )
    except StrixWorkerArtifactError as exc:
        print(f"Strix worker artifact build refused: {exc}", file=sys.stderr)
        return 1
    print(_canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
