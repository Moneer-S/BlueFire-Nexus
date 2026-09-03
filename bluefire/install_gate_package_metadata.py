"""Static project and built-wheel metadata inspection for GATE-01."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any, Mapping

_RUNTIME_DISTRIBUTIONS = frozenset({"pyyaml", "cryptography", "pynacl"})
_REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(.*)$")
_REQUIREMENT_SPECIFIER = re.compile(r"^(?:~=|==|!=|<=|>=|<|>)[A-Za-z0-9][A-Za-z0-9.*+!_-]*$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _requirement_row(value: str) -> Mapping[str, str]:
    if ";" in value or "[" in value or "]" in value or "@" in value:
        raise ValueError("runtime dependency must be an unconditional distribution requirement")
    match = _REQUIREMENT_NAME.fullmatch(value.strip())
    if match is None:
        raise ValueError("runtime dependency requirement is invalid")
    name = _canonical_name(match.group(1))
    specifiers = [part.strip() for part in match.group(2).split(",") if part.strip()]
    if not specifiers or any(_REQUIREMENT_SPECIFIER.fullmatch(part) is None for part in specifiers):
        raise ValueError("runtime dependency specifier is invalid")
    return {"name": name, "specifier": ",".join(sorted(specifiers))}


def _project_section(document: str) -> str:
    match = re.search(r"(?ms)^\[project\]\s*$\n(.*?)(?=^\[|\Z)", document)
    if match is None:
        raise ValueError("packaging source has no project metadata")
    return match.group(1)


def _project_string(project: str, field: str) -> str:
    match = re.search(rf'(?m)^{re.escape(field)}\s*=\s*("(?:\\.|[^"\\])*")\s*$', project)
    if match is None:
        raise ValueError(f"packaging source has no {field} value")
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise ValueError(f"packaging source {field} value is invalid") from exc
    if not isinstance(value, str) or not value:
        raise ValueError(f"packaging source {field} value is invalid")
    return value


def _static_version_value(path: Path, *, filename: str) -> str:
    try:
        source_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("packaging source version module is unavailable") from exc
    if len(source_text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("packaging source version module exceeds its size bound")
    try:
        module = ast.parse(source_text, filename=filename)
    except SyntaxError as exc:
        raise ValueError("packaging source version module is invalid") from exc
    assignments = [
        node
        for node in module.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        )
        or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__version__"
        )
    ]
    if (
        len(assignments) != 1
        or not isinstance(assignments[0], ast.Assign)
        or len(assignments[0].targets) != 1
        or not isinstance(assignments[0].targets[0], ast.Name)
        or not isinstance(assignments[0].value, ast.Constant)
        or not isinstance(assignments[0].value.value, str)
        or not assignments[0].value.value
    ):
        raise ValueError("packaging source dynamic version value is invalid")
    return assignments[0].value.value


def _project_version(source: Path, document: str, project: str) -> str:
    if re.search(r"(?m)^version\s*=", project) is not None:
        return _project_string(project, "version")
    dynamic_match = re.search(r"(?ms)^dynamic\s*=\s*\[(.*?)\]\s*$", project)
    if dynamic_match is None:
        raise ValueError("packaging source has no version declaration")
    dynamic_body = dynamic_match.group(1)
    literals = re.findall(r'"(?:\\.|[^"\\])*"', dynamic_body)
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", dynamic_body)
    if remainder.strip(" \t\r\n,"):
        raise ValueError("packaging source dynamic metadata is invalid")
    try:
        dynamic_fields = [json.loads(literal) for literal in literals]
    except json.JSONDecodeError as exc:
        raise ValueError("packaging source dynamic metadata is invalid") from exc
    dynamic_section = re.search(
        r"(?ms)^\[tool\.setuptools\.dynamic\]\s*$\n(.*?)(?=^\[|\Z)", document
    )
    version_binding = (
        re.findall(
            r'(?m)^version\s*=\s*\{\s*attr\s*=\s*"bluefire\.__version__"\s*\}\s*$',
            dynamic_section.group(1),
        )
        if dynamic_section is not None
        else []
    )
    if dynamic_fields.count("version") != 1 or len(version_binding) != 1:
        raise ValueError("packaging source dynamic version binding is invalid")
    version_source = source / "bluefire" / "__init__.py"
    try:
        source_text = version_source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("packaging source version module is unavailable") from exc
    if len(source_text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("packaging source version module exceeds its size bound")
    try:
        module = ast.parse(source_text, filename="bluefire/__init__.py")
    except SyntaxError as exc:
        raise ValueError("packaging source version module is invalid") from exc
    direct_assignments = [
        node
        for node in module.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and (
            any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
            if isinstance(node, ast.Assign)
            else isinstance(node.target, ast.Name) and node.target.id == "__version__"
        )
    ]
    if direct_assignments:
        return _static_version_value(version_source, filename="bluefire/__init__.py")
    imports = [
        node
        for node in module.body
        if isinstance(node, ast.ImportFrom)
        and node.level == 1
        and node.module == "version"
        and len(node.names) == 1
        and node.names[0].name == "__version__"
        and node.names[0].asname is None
    ]
    if len(imports) != 1:
        raise ValueError("packaging source dynamic version value is invalid")
    return _static_version_value(
        source / "bluefire" / "version.py",
        filename="bluefire/version.py",
    )


def _project_dependencies(project: str) -> list[str]:
    match = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]\s*$", project)
    if match is None:
        raise ValueError("packaging source has no runtime dependencies")
    body = match.group(1)
    literals = re.findall(r'"(?:\\.|[^"\\])*"', body)
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", body)
    remainder = re.sub(r"(?m)#.*$", "", remainder)
    if remainder.strip(" \t\r\n,") or not literals:
        raise ValueError("packaging source runtime dependencies are invalid")
    try:
        values = [json.loads(literal) for literal in literals]
    except json.JSONDecodeError as exc:
        raise ValueError("packaging source runtime dependencies are invalid") from exc
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("packaging source runtime dependencies are invalid")
    return values


def _wheel_dependency_metadata_report(source: Path, wheel: Path) -> Mapping[str, Any]:
    document = (source / "pyproject.toml").read_text(encoding="utf-8")
    project = _project_section(document)
    project_name = _canonical_name(_project_string(project, "name"))
    project_version = _project_version(source, document, project)
    requires_python = _project_string(project, "requires-python")
    declared = sorted(
        (_requirement_row(requirement) for requirement in _project_dependencies(project)),
        key=lambda row: row["name"],
    )
    if {row["name"] for row in declared} != _RUNTIME_DISTRIBUTIONS:
        raise ValueError("declared BlueFire runtime dependency set is invalid")

    try:
        with zipfile.ZipFile(wheel, "r") as archive:
            metadata_members = [
                name
                for name in archive.namelist()
                if re.fullmatch(r"[^/]+\.dist-info/METADATA", name) is not None
            ]
            if len(metadata_members) != 1:
                raise ValueError("built wheel does not contain exactly one metadata record")
            metadata_bytes = archive.read(metadata_members[0])
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise ValueError("built wheel metadata is unavailable") from exc
    if len(metadata_bytes) > 1024 * 1024:
        raise ValueError("built wheel metadata exceeds its size bound")
    metadata = BytesParser(policy=email_policy).parsebytes(metadata_bytes)
    metadata_name = metadata.get("Name")
    metadata_version = metadata.get("Version")
    metadata_requires_python = metadata.get("Requires-Python")
    if (
        not isinstance(metadata_name, str)
        or not isinstance(metadata_version, str)
        or not isinstance(metadata_requires_python, str)
    ):
        raise ValueError("built wheel project metadata is incomplete")
    wheel_requirements: list[Mapping[str, str]] = []
    for requirement in metadata.get_all("Requires-Dist", []):
        if not isinstance(requirement, str):
            raise ValueError("built wheel dependency metadata is invalid")
        marker = requirement.partition(";")[2]
        if marker and re.search(r"\bextra\s*==", marker):
            continue
        wheel_requirements.append(_requirement_row(requirement))
    wheel_requirements.sort(key=lambda row: row["name"])
    if (
        project_name != "bluefire-nexus"
        or _canonical_name(metadata_name) != project_name
        or metadata_version != project_version
        or metadata_requires_python != requires_python
    ):
        raise ValueError("built wheel project metadata does not match the project declaration")
    if wheel_requirements != declared:
        raise ValueError(
            "built wheel Requires-Dist metadata does not match the project declaration"
        )
    return {
        "schema_version": "bluefire.gate01-wheel-dependency-metadata.v1",
        "verified": True,
        "project_name": project_name,
        "project_version": project_version,
        "requires_python": requires_python,
        "wheel_sha256": _sha256(wheel),
        "declared_runtime_dependencies": declared,
        "wheel_requires_dist": wheel_requirements,
    }


__all__ = ["_project_section", "_project_version", "_wheel_dependency_metadata_report"]
