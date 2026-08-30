"""Fail-closed, offline rights inventory for BlueFire release artifacts.

This module does not try to give legal advice.  It verifies that every dependency
and bundled asset in the reviewed release scope still has an explicit disposition
in committed policy.  Dependency or asset drift therefore requires a new review.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

POLICY_RELATIVE_PATH = Path("bluefire/data/release_rights_policy.json")


class RightsAuditError(ValueError):
    """Raised when release contents are not fully covered by reviewed policy."""


@dataclass(frozen=True)
class RightsAuditReport:
    decision: str
    project_license: str
    python_runtime_distributions: int
    python_optional_distributions: int
    frontend_runtime_packages: int
    frontend_locked_packages: int
    rust_release_crates: int
    rust_locked_crates: int
    classified_assets: int
    project_source_files: int
    unresolved_items: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "project_license": self.project_license,
            "python_runtime_distributions": self.python_runtime_distributions,
            "python_optional_distributions": self.python_optional_distributions,
            "frontend_runtime_packages": self.frontend_runtime_packages,
            "frontend_locked_packages": self.frontend_locked_packages,
            "rust_release_crates": self.rust_release_crates,
            "rust_locked_crates": self.rust_locked_crates,
            "classified_assets": self.classified_assets,
            "project_source_files": self.project_source_files,
            "unresolved_items": list(self.unresolved_items),
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RightsAuditError(message)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RightsAuditError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def _read_policy(repository: Path) -> dict[str, Any]:
    path = repository / POLICY_RELATIVE_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RightsAuditError("release rights policy is unreadable") from exc
    _require(isinstance(value, dict), "release rights policy must be an object")
    _require(
        value.get("schema_version") == "bluefire.release-rights-policy.v1", "bad policy schema"
    )
    return dict(value)


def _sha256(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise RightsAuditError(f"reviewed file is missing: {path.name}") from exc
    return hashlib.sha256(payload).hexdigest()


def _string_list(value: Any, context: str) -> list[str]:
    _require(isinstance(value, list), f"{context} must be a list")
    _require(all(isinstance(item, str) and item for item in value), f"{context} is invalid")
    _require(len(value) == len(set(value)), f"{context} contains duplicate entries")
    return list(value)


def _mapping(value: Any, context: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{context} must be an object")
    return dict(value)


def _toml_section(document: str, name: str) -> str:
    match = re.search(rf"(?ms)^\[{re.escape(name)}\]\s*$\n(.*?)(?=^\[|\Z)", document)
    if match is None:
        raise RightsAuditError(f"pyproject section [{name}] is missing")
    return match.group(1)


def _toml_string(section: str, key: str) -> str:
    match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^"]+)"\s*$', section)
    if match is None:
        raise RightsAuditError(f"pyproject field {key} must be a simple string")
    return match.group(1)


def _toml_list(section: str, key: str) -> list[str]:
    match = re.search(rf"(?ms)^{re.escape(key)}\s*=\s*(\[.*?\])\s*$", section)
    if match is None:
        raise RightsAuditError(f"pyproject field {key} must be a string list")
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as exc:
        raise RightsAuditError(f"pyproject field {key} is invalid") from exc
    return _string_list(value, f"pyproject {key}")


def _optional_requirements(document: str) -> dict[str, list[str]]:
    section = _toml_section(document, "project.optional-dependencies")
    values: dict[str, list[str]] = {}
    for match in re.finditer(r"(?ms)^([A-Za-z0-9_-]+)\s*=\s*(\[.*?\])\s*$", section):
        try:
            group = ast.literal_eval(match.group(2))
        except (SyntaxError, ValueError) as exc:
            raise RightsAuditError(
                f"optional dependency group {match.group(1)} is invalid"
            ) from exc
        values[match.group(1)] = _string_list(group, f"optional dependency group {match.group(1)}")
    return values


def _package_id(name: str, version: str) -> str:
    _require(bool(name) and bool(version), "dependency identity is incomplete")
    return f"{name}@{version}"


def _flatten_license_groups(value: Any, context: str) -> tuple[set[str], set[str]]:
    groups = _mapping(value, context)
    identities: set[str] = set()
    licenses: set[str] = set()
    for license_expression, raw_entries in groups.items():
        _require(
            isinstance(license_expression, str) and bool(license_expression),
            f"{context} license is invalid",
        )
        entries = _string_list(raw_entries, f"{context}.{license_expression}")
        overlap = identities.intersection(entries)
        if overlap:
            raise RightsAuditError(
                f"{context} classifies an item more than once: {sorted(overlap)[0]}"
            )
        identities.update(entries)
        licenses.add(license_expression)
    return identities, licenses


def _verify_license_expressions(licenses: Iterable[str], policy: Mapping[str, Any]) -> None:
    allowed = set(_string_list(policy.get("allowed_license_expressions"), "allowed licenses"))
    observed = set(licenses)
    unreviewed = observed - allowed
    if unreviewed:
        raise RightsAuditError(f"unreviewed license expression: {sorted(unreviewed)[0]}")
    forbidden = {"UNKNOWN", "NOASSERTION", "NONE", "UNLICENSED"}
    _require(not observed.intersection(forbidden), "an unresolved license classification was used")


def _verify_project_license(repository: Path, policy: Mapping[str, Any], pyproject: str) -> None:
    project = _toml_section(pyproject, "project")
    expected = _mapping(policy.get("project_license"), "project license")
    spdx_id = expected.get("spdx_id")
    _require(spdx_id == "MIT", "reviewed decision must retain the existing MIT license")
    _require(_toml_string(project, "license") == spdx_id, "pyproject project license drifted")
    required_license_files = _string_list(expected.get("license_files"), "project license files")
    _require(
        _toml_list(project, "license-files") == required_license_files, "license-files drifted"
    )
    for relative in required_license_files:
        _require((repository / relative).is_file(), f"required license file is missing: {relative}")
    license_path = repository / str(expected.get("primary_file"))
    _require(
        _sha256(license_path) == expected.get("sha256"), "project LICENSE changed after review"
    )
    license_text = license_path.read_text(encoding="utf-8")
    _require(
        "MIT License" in license_text and "Permission is hereby granted" in license_text,
        "bad MIT text",
    )

    decision = _mapping(policy.get("release_decision"), "release decision")
    _require(decision.get("decision") == "retain-mit", "unreviewed release license decision")
    _require(
        decision.get("agpl_commercial_relicense") == "not-authorized-by-repository-evidence",
        "relicense decision is not fail-closed",
    )
    _require(bool(decision.get("blocker")), "relicense blocker must be recorded")


def _verify_notices(repository: Path, policy: Mapping[str, Any]) -> None:
    notices = _mapping(policy.get("notices"), "notice policy")
    relative = notices.get("path")
    if not isinstance(relative, str) or not relative:
        raise RightsAuditError("notice path is invalid")
    try:
        document = (repository / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RightsAuditError("third-party notice is unreadable") from exc
    fragments = _string_list(notices.get("required_fragments"), "required notice fragments")
    missing = [fragment for fragment in fragments if fragment not in document]
    if missing:
        raise RightsAuditError(f"third-party notice is incomplete: {missing[0]}")


def _verify_python(
    repository: Path, policy: Mapping[str, Any], pyproject: str
) -> tuple[int, int, set[str]]:
    python_policy = _mapping(policy.get("python"), "python policy")
    project = _toml_section(pyproject, "project")
    actual_runtime = _toml_list(project, "dependencies")
    expected_runtime = _string_list(
        python_policy.get("declared_runtime_requirements"), "python requirements"
    )
    _require(actual_runtime == expected_runtime, "Python runtime requirement declarations drifted")

    expected_optional_rows = python_policy.get("optional_distributions")
    if not isinstance(expected_optional_rows, list):
        raise RightsAuditError("optional Python inventory must be a list")
    optional_requirements: list[str] = []
    optional_licenses: set[str] = set()
    for index, value in enumerate(expected_optional_rows):
        row = _mapping(value, f"optional Python inventory[{index}]")
        _require(
            row.get("shipping") == "environment-dependent", "optional package shipping is misstated"
        )
        _require(
            row.get("redistribution_review_required") is True,
            "optional package review must be required",
        )
        optional_requirements.append(str(row.get("requirement")))
        optional_licenses.add(str(row.get("license")))
    actual_optional = _optional_requirements(pyproject)
    _require(
        actual_optional.get("detections") == optional_requirements,
        "optional Python runtime inventory drifted",
    )
    expected_development = _string_list(
        python_policy.get("development_requirements"), "Python development requirements"
    )
    _require(
        actual_optional.get("dev") == expected_development, "Python development inventory drifted"
    )
    _require(set(actual_optional) == {"detections", "dev"}, "unreviewed Python optional group")

    wheelhouse_path = repository / str(python_policy.get("locked_runtime_source"))
    try:
        wheelhouse = json.loads(
            wheelhouse_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RightsAuditError("locked Python wheel inventory is unreadable") from exc
    wheel_rows = wheelhouse.get("wheels") if isinstance(wheelhouse, dict) else None
    if not isinstance(wheel_rows, list):
        raise RightsAuditError("locked Python wheel inventory is invalid")
    actual_wheels: dict[str, str] = {}
    for index, value in enumerate(wheel_rows):
        row = _mapping(value, f"wheelhouse[{index}]")
        identity = _package_id(str(row.get("distribution")), str(row.get("version")))
        digest = str(row.get("sha256"))
        _require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"bad wheel digest: {identity}")
        _require(identity not in actual_wheels, f"duplicate wheel: {identity}")
        actual_wheels[identity] = digest

    expected_wheels = python_policy.get("locked_runtime_distributions")
    if not isinstance(expected_wheels, list):
        raise RightsAuditError("locked Python policy must be a list")
    classified: dict[str, str] = {}
    runtime_licenses: set[str] = set()
    for index, value in enumerate(expected_wheels):
        row = _mapping(value, f"locked Python policy[{index}]")
        identity = _package_id(str(row.get("distribution")), str(row.get("version")))
        _require(identity not in classified, f"duplicate Python classification: {identity}")
        classified[identity] = str(row.get("sha256"))
        runtime_licenses.add(str(row.get("license")))
    _require(
        actual_wheels == classified, "locked Python dependency inventory is unclassified or stale"
    )
    return len(classified), len(expected_optional_rows), runtime_licenses | optional_licenses


def _frontend_identity(snapshot_key: str) -> str:
    base = snapshot_key.split("(", 1)[0]
    split_at = base.find("@", 1) if base.startswith("@") else base.rfind("@")
    _require(split_at > 0, f"bad pnpm package identity: {snapshot_key}")
    return base


def _frontend_runtime(lock: Mapping[str, Any]) -> set[str]:
    importers = _mapping(lock.get("importers"), "pnpm importers")
    root = _mapping(importers.get("."), "pnpm root importer")
    snapshots = _mapping(lock.get("snapshots"), "pnpm snapshots")
    roots = _mapping(root.get("dependencies"), "pnpm runtime dependencies")
    pending: list[str] = []
    for name, value in roots.items():
        row = _mapping(value, f"pnpm dependency {name}")
        pending.append(f"{name}@{row.get('version')}")
    visited: set[str] = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        _require(key in snapshots, f"pnpm runtime snapshot is missing: {key}")
        visited.add(key)
        snapshot = _mapping(snapshots[key], f"pnpm snapshot {key}")
        for field in ("dependencies", "optionalDependencies"):
            children = snapshot.get(field, {})
            _require(isinstance(children, dict), f"pnpm {key}.{field} is invalid")
            for name, reference in children.items():
                _require(
                    isinstance(reference, str), f"pnpm dependency reference for {name} is invalid"
                )
                _require(
                    not reference.startswith(("link:", "workspace:")),
                    "local runtime package is unreviewed",
                )
                pending.append(f"{name}@{reference}")
    return {_frontend_identity(key) for key in visited}


def _verify_frontend(repository: Path, policy: Mapping[str, Any]) -> tuple[int, int, set[str]]:
    frontend = _mapping(policy.get("frontend"), "frontend policy")
    lock_path = repository / "frontend/pnpm-lock.yaml"
    _require(
        _sha256(lock_path) == frontend.get("lockfile_sha256"), "pnpm lock changed after review"
    )
    try:
        lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RightsAuditError("pnpm lock is unreadable") from exc
    _require(isinstance(lock, dict), "pnpm lock must be an object")
    packages = _mapping(lock.get("packages"), "pnpm packages")
    expected_locked_count = frontend.get("locked_package_count")
    _require(len(packages) == expected_locked_count, "pnpm locked package count drifted")
    actual_runtime = _frontend_runtime(lock)
    reviewed_runtime, licenses = _flatten_license_groups(
        frontend.get("runtime_packages_by_license"), "frontend runtime licenses"
    )
    _require(
        actual_runtime == reviewed_runtime, "frontend runtime dependency is unclassified or stale"
    )

    package_path = repository / "frontend/package.json"
    try:
        package = json.loads(
            package_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RightsAuditError("frontend package manifest is unreadable") from exc
    direct = package.get("dependencies") if isinstance(package, dict) else None
    _require(
        direct == frontend.get("direct_requirements"),
        "frontend direct dependency declarations drifted",
    )
    development = package.get("devDependencies") if isinstance(package, dict) else None
    _require(
        development == frontend.get("development_requirements"),
        "frontend development dependency declarations drifted",
    )
    return len(reviewed_runtime), len(packages), licenses


def _cargo_packages(document: str) -> dict[tuple[str, str], dict[str, Any]]:
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for block in document.split("[[package]]")[1:]:
        name_match = re.search(r'(?m)^name = "([^"]+)"$', block)
        version_match = re.search(r'(?m)^version = "([^"]+)"$', block)
        if name_match is None or version_match is None:
            raise RightsAuditError("Cargo.lock package is malformed")
        key = (name_match.group(1), version_match.group(1))
        checksum = re.search(r'(?m)^checksum = "([0-9a-f]{64})"$', block)
        dependency_block = re.search(r"(?ms)^dependencies = \[\n(.*?)^\]$", block)
        dependencies = (
            []
            if dependency_block is None
            else re.findall(r'(?m)^ "([^"]+)",?$', dependency_block.group(1))
        )
        _require(key not in packages, f"duplicate Cargo.lock package: {_package_id(*key)}")
        packages[key] = {"external": checksum is not None, "dependencies": dependencies}
    return packages


def _cargo_direct_dependencies(document: str) -> list[str]:
    match = re.search(r"(?ms)^\[dependencies\]\s*$\n(.*?)(?=^\[|\Z)", document)
    if match is None:
        raise RightsAuditError("Cargo.toml dependencies are missing")
    names = re.findall(r"(?m)^([A-Za-z0-9_-]+)\s*=", match.group(1))
    _require(bool(names), "Cargo.toml release dependencies are empty")
    return names


def _resolve_cargo_dependency(
    value: str, packages: Mapping[tuple[str, str], Mapping[str, Any]]
) -> tuple[str, str]:
    possible_name, separator, possible_version = value.rpartition(" ")
    if separator and re.match(r"^\d", possible_version):
        key = (possible_name, possible_version)
        _require(key in packages, f"Cargo.lock dependency is missing: {value}")
        return key
    matches = [key for key in packages if key[0] == value]
    _require(len(matches) == 1, f"Cargo.lock dependency is ambiguous: {value}")
    return matches[0]


def _cargo_release_graph(
    packages: Mapping[tuple[str, str], Mapping[str, Any]], direct: Iterable[str]
) -> set[str]:
    pending = [_resolve_cargo_dependency(name, packages) for name in direct]
    visited: set[tuple[str, str]] = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        pending.extend(
            _resolve_cargo_dependency(value, packages) for value in packages[key]["dependencies"]
        )
    return {_package_id(*key) for key in visited if packages[key]["external"]}


def _verify_rust(repository: Path, policy: Mapping[str, Any]) -> tuple[int, int, set[str]]:
    rust = _mapping(policy.get("rust"), "Rust policy")
    lock_path = repository / "runner/Cargo.lock"
    _require(_sha256(lock_path) == rust.get("lockfile_sha256"), "Cargo.lock changed after review")
    lock_document = lock_path.read_text(encoding="utf-8")
    packages = _cargo_packages(lock_document)
    locked = {_package_id(*key) for key, value in packages.items() if value["external"]}
    classified, licenses = _flatten_license_groups(
        rust.get("locked_crates_by_license"), "Rust licenses"
    )
    _require(locked == classified, "Rust locked crate is unclassified or stale")

    manifest = (repository / "runner/Cargo.toml").read_text(encoding="utf-8")
    release_graph = _cargo_release_graph(packages, _cargo_direct_dependencies(manifest))
    reviewed_release_graph = set(_string_list(rust.get("release_graph"), "Rust release graph"))
    _require(release_graph == reviewed_release_graph, "Rust release dependency graph drifted")
    return len(reviewed_release_graph), len(classified), licenses


def _asset_files(repository: Path) -> set[str]:
    paths: set[str] = set()
    for relative_root in (
        "bluefire/catalog",
        "bluefire/data",
        "bluefire/native",
        "bluefire/ui",
        "docs/assets",
    ):
        root = repository / relative_root
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix not in {".pyc", ".pyo"}
            ):
                paths.add(path.relative_to(repository).as_posix())
    return paths


def _verify_assets(repository: Path, policy: Mapping[str, Any]) -> int:
    assets = _mapping(policy.get("assets"), "asset policy")
    categories = _mapping(assets.get("classifications"), "asset classifications")
    reviewed: set[str] = set()
    for classification, values in categories.items():
        _require(
            isinstance(classification, str) and bool(classification),
            "asset classification is invalid",
        )
        entries = _string_list(values, f"asset classification {classification}")
        overlap = reviewed.intersection(entries)
        if overlap:
            raise RightsAuditError(f"asset classified more than once: {sorted(overlap)[0]}")
        reviewed.update(entries)
    actual = _asset_files(repository)
    _require(actual == reviewed, "bundled/generated asset inventory is unclassified or stale")
    integrity = _mapping(assets.get("third_party_integrity"), "third-party asset integrity")
    for relative, digest in integrity.items():
        _require(re.fullmatch(r"[0-9a-f]{64}", str(digest)) is not None, "bad asset digest policy")
        _require(_sha256(repository / relative) == digest, f"third-party asset changed: {relative}")
    return len(reviewed)


def _project_source_count(repository: Path, policy: Mapping[str, Any]) -> int:
    source = _mapping(policy.get("project_authored_code"), "project source policy")
    roots = _string_list(source.get("roots"), "project source roots")
    extensions = set(_string_list(source.get("extensions"), "project source extensions"))
    _require(source.get("license") == "MIT", "project source license drifted")
    count = 0
    for relative_root in roots:
        root = repository / relative_root
        _require(root.is_dir(), f"project source root is missing: {relative_root}")
        for path in root.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix not in extensions:
                continue
            relative = path.relative_to(repository).as_posix().lower()
            _require(
                "/vendor/" not in f"/{relative}/" and "/third_party/" not in f"/{relative}/",
                f"unreviewed vendored source: {relative}",
            )
            count += 1
    _require(count > 0, "project-authored source inventory is empty")
    return count


def run_release_rights_audit(repository: str | Path) -> RightsAuditReport:
    """Verify reviewed release rights metadata against the current repository tree."""

    root = Path(repository).resolve()
    _require(root.is_dir(), "repository path does not exist")
    policy = _read_policy(root)
    unresolved = tuple(_string_list(policy.get("unresolved_items"), "unresolved items"))
    _require(not unresolved, "rights audit contains unresolved release items")
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    _verify_project_license(root, policy, pyproject)
    _verify_notices(root, policy)
    python_count, optional_count, python_licenses = _verify_python(root, policy, pyproject)
    frontend_count, frontend_locked, frontend_licenses = _verify_frontend(root, policy)
    rust_count, rust_locked, rust_licenses = _verify_rust(root, policy)
    _verify_license_expressions(python_licenses | frontend_licenses | rust_licenses, policy)
    asset_count = _verify_assets(root, policy)
    source_count = _project_source_count(root, policy)
    decision = _mapping(policy.get("release_decision"), "release decision")
    project_license = _mapping(policy.get("project_license"), "project license")
    return RightsAuditReport(
        decision=str(decision["decision"]),
        project_license=str(project_license["spdx_id"]),
        python_runtime_distributions=python_count,
        python_optional_distributions=optional_count,
        frontend_runtime_packages=frontend_count,
        frontend_locked_packages=frontend_locked,
        rust_release_crates=rust_count,
        rust_locked_crates=rust_locked,
        classified_assets=asset_count,
        project_source_files=source_count,
        unresolved_items=unresolved,
    )
