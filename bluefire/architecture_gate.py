"""Executable architecture audit and dynamic proof workflow for GATE-10."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET  # nosec B405
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .defense_frontier import _runtime_temp_parent

POLICY_SCHEMA_VERSION = "bluefire.architecture-policy.v1"
REPORT_SCHEMA_VERSION = "bluefire.architecture-audit.v1"

_ASSERTION_CHECKS: Mapping[str, tuple[str, str, str, str]] = {
    "GATE-10-PYTHON-DECOMPOSITION": (
        "python_decomposition",
        "structural",
        "architecture-report.json",
        "GATE-10.python-decomposition.v1",
    ),
    "GATE-10-RUST-DECOMPOSITION": (
        "rust_decomposition",
        "structural",
        "architecture-report.json",
        "GATE-10.rust-decomposition.v1",
    ),
    "GATE-10-FILE-SIZE-BUDGET": (
        "file_size_budget",
        "structural",
        "architecture-report.json",
        "GATE-10.file-size-budget.v1",
    ),
    "GATE-10-DEPENDENCY-DIRECTION": (
        "dependency_direction",
        "structural",
        "architecture-report.json",
        "GATE-10.dependency-direction.v1",
    ),
    "GATE-10-IMPORT-CYCLES": (
        "import_cycles",
        "structural",
        "architecture-report.json",
        "GATE-10.import-cycles.v1",
    ),
    "GATE-10-PROPERTY-FUZZ": (
        "property_fuzz",
        "dynamic",
        "property-fuzz-report.json",
        "GATE-10.property-fuzz.v1",
    ),
    "GATE-10-CRYPTO-PRIMITIVES": (
        "crypto_primitives",
        "structural",
        "architecture-report.json",
        "GATE-10.crypto-primitives.v1",
    ),
    "GATE-10-RESPONSIBILITY-SEPARATION": (
        "responsibility_separation",
        "structural",
        "architecture-report.json",
        "GATE-10.responsibility-separation.v1",
    ),
    "GATE-10-BEHAVIOR-PRESERVATION": (
        "behavior_preservation",
        "dynamic",
        "behavior-preservation-report.json",
        "GATE-10.behavior-preservation.v1",
    ),
}

_PROPERTY_TESTS = ("tests_platform/test_gate10_properties.py",)
_BEHAVIOR_TESTS = (
    "tests_platform/test_action_packages.py::test_signing_and_canonicalization_are_deterministic",
    "tests_platform/test_authenticated_runner_transport.py::test_decoder_rejects_noncanonical_and_duplicate_key_json",
    "tests_platform/test_product_store.py::test_resources_round_trip_and_reject_plaintext_credentials",
    "tests_platform/test_service.py::test_simulate_run_and_replay_persist_autonomy_provider_and_lineage",
)


@dataclass(frozen=True)
class Gate10Outcome:
    status: str
    proofs: tuple[Mapping[str, Any], ...]
    failure_reason: str | None


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_policy(path: Path | None = None) -> dict[str, Any]:
    policy_path = path or Path(__file__).with_name("data") / "architecture_policy.json"
    try:
        value = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("GATE-10 architecture policy is unavailable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise ValueError("GATE-10 architecture policy schema is invalid")
    required = {
        "schema_version",
        "baseline_commit",
        "line_budgets",
        "production_roots",
        "python_layer_rules",
        "allowed_python_dependencies",
        "rust_layers",
        "allowed_rust_dependencies",
        "decomposition_hotspots",
        "responsibility_markers",
        "custom_crypto_markers",
        "maintained_crypto_markers",
    }
    if set(value) != required:
        raise ValueError("GATE-10 architecture policy fields are invalid")
    return value


def _source_paths(repository: Path, policy: Mapping[str, Any]) -> tuple[Path, ...]:
    paths: list[Path] = []
    roots = policy.get("production_roots")
    if not isinstance(roots, list):
        raise ValueError("GATE-10 production roots are invalid")
    for item in roots:
        if not isinstance(item, Mapping) or set(item) != {"path", "extensions"}:
            raise ValueError("GATE-10 production root entry is invalid")
        raw_root = item["path"]
        extensions = item["extensions"]
        if (
            not isinstance(raw_root, str)
            or not raw_root
            or not isinstance(extensions, list)
            or not extensions
            or any(not isinstance(extension, str) for extension in extensions)
        ):
            raise ValueError("GATE-10 production root entry is invalid")
        root = (repository / raw_root).resolve(strict=True)
        if not root.is_relative_to(repository) or not root.is_dir():
            raise ValueError("GATE-10 production root escapes the repository")
        for candidate in root.rglob("*"):
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and candidate.suffix in extensions
                and "__pycache__" not in candidate.parts
            ):
                paths.append(candidate.resolve(strict=True))
    return tuple(sorted(set(paths), key=lambda item: item.relative_to(repository).as_posix()))


def _line_number(text: str, token: str) -> int:
    offset = text.find(token)
    return 0 if offset < 0 else text.count("\n", 0, offset) + 1


def _git_object_exists(repository: Path, object_name: str) -> bool:
    try:
        process = subprocess.run(
            ["git", "cat-file", "-e", object_name],
            cwd=repository,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode == 0


def _size_audit(
    repository: Path,
    policy: Mapping[str, Any],
    paths: Sequence[Path],
) -> tuple[dict[str, Any], dict[str, str]]:
    budgets = policy.get("line_budgets")
    if not isinstance(budgets, Mapping) or set(budgets) != {
        "new_file",
        "existing_file",
        "exceptions",
    }:
        raise ValueError("GATE-10 line budgets are invalid")
    new_limit = budgets["new_file"]
    existing_limit = budgets["existing_file"]
    if type(new_limit) is not int or type(existing_limit) is not int:
        raise ValueError("GATE-10 line budgets are invalid")
    exceptions = budgets["exceptions"]
    if not isinstance(exceptions, list):
        raise ValueError("GATE-10 line-budget exceptions are invalid")
    exception_index: dict[str, Mapping[str, Any]] = {}
    for exception in exceptions:
        if not isinstance(exception, Mapping) or set(exception) != {
            "path",
            "max_lines",
            "reason",
            "reviewed_by",
            "expires_after",
        }:
            raise ValueError("GATE-10 line-budget exception is invalid")
        exception_index[str(exception["path"])] = exception

    baseline = policy.get("baseline_commit")
    if not isinstance(baseline, str) or re.fullmatch(r"[0-9a-f]{40}", baseline) is None:
        raise ValueError("GATE-10 baseline commit is invalid")
    baseline_available = _git_object_exists(repository, baseline + "^{commit}")
    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    languages: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(
                {"code": "source_unreadable", "path": relative, "detail": type(exc).__name__}
            )
            continue
        lines = len(text.splitlines())
        language = "python" if path.suffix == ".py" else "rust"
        languages[relative] = language
        if baseline_available:
            existing = _git_object_exists(repository, f"{baseline}:{relative}")
            classification = "existing" if existing else "new"
            limit = existing_limit if existing else new_limit
        else:
            classification = "unknown"
            limit = existing_limit
        exception = exception_index.get(relative)
        exception_applied = False
        if lines > limit and exception is not None:
            maximum = exception.get("max_lines")
            exception_applied = (
                type(maximum) is int
                and lines <= maximum
                and isinstance(exception.get("reason"), str)
                and bool(str(exception["reason"]).strip())
                and isinstance(exception.get("reviewed_by"), str)
                and bool(str(exception["reviewed_by"]).strip())
                and isinstance(exception.get("expires_after"), str)
                and bool(str(exception["expires_after"]).strip())
            )
        row = {
            "path": relative,
            "language": language,
            "classification": classification,
            "lines": lines,
            "limit": limit,
            "exception_applied": exception_applied,
        }
        rows.append(row)
        if classification == "unknown":
            findings.append({"code": "baseline_unavailable", "path": relative})
        elif lines > limit and not exception_applied:
            findings.append(
                {
                    "code": "line_budget_exceeded",
                    "path": relative,
                    "classification": classification,
                    "lines": lines,
                    "limit": limit,
                }
            )
    unused_exceptions = sorted(set(exception_index) - {row["path"] for row in rows})
    findings.extend(
        {"code": "unused_line_budget_exception", "path": path} for path in unused_exceptions
    )
    return {
        "passed": not findings,
        "baseline_commit": baseline,
        "baseline_available": baseline_available,
        "new_file_limit": new_limit,
        "existing_file_limit": existing_limit,
        "files": rows,
        "findings": findings,
    }, languages


def _python_module(relative: str) -> str:
    parts = list(Path(relative).with_suffix("").parts)
    return ".".join(parts)


def _known_dependency(candidate: str, known: set[str]) -> str | None:
    parts = candidate.split(".")
    for length in range(len(parts), 0, -1):
        module = ".".join(parts[:length])
        if module in known:
            return module
        package = module + ".__init__"
        if package in known:
            return package
    return None


def _python_dependencies(path: Path, module: str, known: set[str]) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    dependencies: set[str] = set()
    package = (
        module.removesuffix(".__init__")
        if module.endswith(".__init__")
        else module.rpartition(".")[0]
    )
    for node in ast.walk(tree):
        candidates: list[str] = []
        if isinstance(node, ast.Import):
            candidates.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                relative = "." * node.level + (node.module or "")
                try:
                    base = importlib.util.resolve_name(relative, package)
                except (ImportError, ValueError):
                    continue
                if node.module is None:
                    candidates.extend(base + "." + alias.name for alias in node.names)
                else:
                    candidates.append(base)
                    candidates.extend(base + "." + alias.name for alias in node.names)
            elif node.module:
                candidates.append(node.module)
                candidates.extend(node.module + "." + alias.name for alias in node.names)
        for candidate in candidates:
            dependency = _known_dependency(candidate, known)
            if dependency is not None and dependency != module:
                dependencies.add(dependency)
    return dependencies


def _strong_components(graph: Mapping[str, Sequence[str]]) -> list[list[str]]:
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    stacked: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        stacked.add(node)
        for dependency in graph.get(node, ()):  # deterministic input is sorted below
            if dependency not in indexes:
                visit(dependency)
                lowlinks[node] = min(lowlinks[node], lowlinks[dependency])
            elif dependency in stacked:
                lowlinks[node] = min(lowlinks[node], indexes[dependency])
        if lowlinks[node] != indexes[node]:
            return
        component: list[str] = []
        while stack:
            member = stack.pop()
            stacked.remove(member)
            component.append(member)
            if member == node:
                break
        components.append(sorted(component))

    for node in sorted(graph):
        if node not in indexes:
            visit(node)
    return sorted((item for item in components if len(item) > 1), key=lambda item: item[0])


def _match_python_layers(
    modules: Sequence[str], policy: Mapping[str, Any]
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    rules = policy.get("python_layer_rules")
    if not isinstance(rules, list):
        raise ValueError("GATE-10 Python layer rules are invalid")
    layers: dict[str, str] = {}
    findings: list[dict[str, Any]] = []
    for module in modules:
        matches: list[str] = []
        for rule in rules:
            if not isinstance(rule, Mapping) or set(rule) != {"layer", "patterns"}:
                raise ValueError("GATE-10 Python layer rule is invalid")
            layer = rule["layer"]
            patterns = rule["patterns"]
            if not isinstance(layer, str) or not isinstance(patterns, list):
                raise ValueError("GATE-10 Python layer rule is invalid")
            if any(
                isinstance(pattern, str) and fnmatch.fnmatchcase(module, pattern)
                for pattern in patterns
            ):
                matches.append(layer)
        if len(matches) == 1:
            layers[module] = matches[0]
        else:
            findings.append(
                {
                    "code": (
                        "module_layer_unclassified" if not matches else "module_layer_ambiguous"
                    ),
                    "module": module,
                    "layers": sorted(matches),
                }
            )
    return layers, findings


def _dependency_audit(
    repository: Path, policy: Mapping[str, Any], paths: Sequence[Path]
) -> dict[str, Any]:
    python_paths = {
        _python_module(path.relative_to(repository).as_posix()): path
        for path in paths
        if path.suffix == ".py"
    }
    known_python = set(python_paths)
    python_graph: dict[str, list[str]] = {}
    findings: list[dict[str, Any]] = []
    for module, path in sorted(python_paths.items()):
        try:
            python_graph[module] = sorted(_python_dependencies(path, module, known_python))
        except (OSError, UnicodeError, SyntaxError) as exc:
            python_graph[module] = []
            findings.append(
                {
                    "code": "python_dependency_parse_failed",
                    "module": module,
                    "detail": type(exc).__name__,
                }
            )
    python_layers, layer_findings = _match_python_layers(sorted(python_paths), policy)
    findings.extend(layer_findings)
    allowed_python = policy.get("allowed_python_dependencies")
    if not isinstance(allowed_python, Mapping):
        raise ValueError("GATE-10 allowed Python dependencies are invalid")
    for source, dependencies in python_graph.items():
        source_layer = python_layers.get(source)
        if source_layer is None:
            continue
        allowed = allowed_python.get(source_layer)
        if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
            raise ValueError("GATE-10 allowed Python dependencies are invalid")
        for dependency in dependencies:
            target_layer = python_layers.get(dependency)
            if target_layer is not None and target_layer not in allowed:
                findings.append(
                    {
                        "code": "python_dependency_direction",
                        "source": source,
                        "source_layer": source_layer,
                        "target": dependency,
                        "target_layer": target_layer,
                    }
                )

    rust_paths = {path.stem: path for path in paths if path.suffix == ".rs"}
    known_rust = set(rust_paths)
    rust_graph: dict[str, list[str]] = {}
    for module, path in sorted(rust_paths.items()):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            text = ""
            findings.append(
                {
                    "code": "rust_dependency_parse_failed",
                    "module": module,
                    "detail": type(exc).__name__,
                }
            )
        rust_graph[module] = sorted(
            dependency
            for dependency in set(re.findall(r"\bcrate::([a-z_][a-z0-9_]*)", text))
            if dependency in known_rust and dependency != module
        )
    rust_layers = policy.get("rust_layers")
    allowed_rust = policy.get("allowed_rust_dependencies")
    if not isinstance(rust_layers, Mapping) or not isinstance(allowed_rust, Mapping):
        raise ValueError("GATE-10 Rust dependency policy is invalid")
    for module in sorted(known_rust):
        if module not in rust_layers:
            findings.append({"code": "rust_module_layer_unclassified", "module": module})
    for source, dependencies in rust_graph.items():
        source_layer = rust_layers.get(source)
        allowed = allowed_rust.get(source_layer) if isinstance(source_layer, str) else None
        if not isinstance(allowed, list):
            continue
        for dependency in dependencies:
            target_layer = rust_layers.get(dependency)
            if isinstance(target_layer, str) and target_layer not in allowed:
                findings.append(
                    {
                        "code": "rust_dependency_direction",
                        "source": source,
                        "source_layer": source_layer,
                        "target": dependency,
                        "target_layer": target_layer,
                    }
                )
    python_cycles = _strong_components(python_graph)
    rust_cycles = _strong_components(rust_graph)
    direction_findings = [
        item
        for item in findings
        if "direction" in str(item.get("code"))
        or "layer" in str(item.get("code"))
        or "parse" in str(item.get("code"))
    ]
    return {
        "direction_passed": not direction_findings,
        "cycle_passed": not python_cycles and not rust_cycles,
        "findings": findings,
        "python": {
            "layers": dict(sorted(python_layers.items())),
            "edges": [
                {"source": source, "target": target}
                for source, targets in sorted(python_graph.items())
                for target in targets
            ],
            "cycles": python_cycles,
        },
        "rust": {
            "layers": dict(sorted((str(key), str(value)) for key, value in rust_layers.items())),
            "edges": [
                {"source": source, "target": target}
                for source, targets in sorted(rust_graph.items())
                for target in targets
            ],
            "cycles": rust_cycles,
        },
    }


def _responsibility_audit(
    repository: Path, policy: Mapping[str, Any], paths: Sequence[Path]
) -> dict[str, Any]:
    markers = policy.get("responsibility_markers")
    if not isinstance(markers, Mapping):
        raise ValueError("GATE-10 responsibility markers are invalid")
    assignments: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        text = path.read_text(encoding="utf-8")
        matched: dict[str, list[dict[str, Any]]] = {}
        for responsibility, raw_tokens in markers.items():
            if not isinstance(responsibility, str) or not isinstance(raw_tokens, list):
                raise ValueError("GATE-10 responsibility markers are invalid")
            hits = [
                {"token": token, "line": _line_number(text, token)}
                for token in raw_tokens
                if isinstance(token, str) and token in text
            ]
            if hits:
                matched[responsibility] = hits
        assignments.append({"path": relative, "responsibilities": matched})
        if len(matched) > 1:
            findings.append(
                {
                    "code": "responsibilities_co_located",
                    "path": relative,
                    "responsibilities": sorted(matched),
                }
            )
    return {"passed": not findings, "assignments": assignments, "findings": findings}


def _crypto_audit(
    repository: Path, policy: Mapping[str, Any], paths: Sequence[Path]
) -> dict[str, Any]:
    custom = policy.get("custom_crypto_markers")
    maintained = policy.get("maintained_crypto_markers")
    if not isinstance(custom, list) or not isinstance(maintained, list):
        raise ValueError("GATE-10 crypto markers are invalid")
    findings: list[dict[str, Any]] = []
    maintained_uses: list[dict[str, Any]] = []
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        text = path.read_text(encoding="utf-8")
        for marker in custom:
            if isinstance(marker, str) and marker in text:
                findings.append(
                    {
                        "code": "custom_crypto_arithmetic",
                        "path": relative,
                        "marker": marker,
                        "line": _line_number(text, marker),
                    }
                )
        for marker in maintained:
            if isinstance(marker, str) and marker in text:
                maintained_uses.append(
                    {"path": relative, "marker": marker, "line": _line_number(text, marker)}
                )
    return {
        "passed": not findings,
        "findings": findings,
        "maintained_primitive_uses": maintained_uses,
    }


def audit_repository(
    repository_root: Path,
    *,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    repository = repository_root.resolve(strict=True)
    policy = _load_policy(policy_path)
    paths = _source_paths(repository, policy)
    size, languages = _size_audit(repository, policy, paths)
    dependencies = _dependency_audit(repository, policy, paths)
    responsibilities = _responsibility_audit(repository, policy, paths)
    crypto = _crypto_audit(repository, policy, paths)
    hotspots = policy.get("decomposition_hotspots")
    if not isinstance(hotspots, Mapping):
        raise ValueError("GATE-10 decomposition hotspots are invalid")
    size_rows = {row["path"]: row for row in size["files"]}
    responsibility_findings = responsibilities["findings"]

    def decomposition(language: str) -> dict[str, Any]:
        raw_paths = hotspots.get(language)
        if not isinstance(raw_paths, list) or any(not isinstance(item, str) for item in raw_paths):
            raise ValueError("GATE-10 decomposition hotspots are invalid")
        findings: list[dict[str, Any]] = []
        for relative in raw_paths:
            row = size_rows.get(relative)
            if row is None:
                findings.append(
                    {
                        "code": "decomposition_hotspot_missing",
                        "path": relative,
                    }
                )
                continue
            if row["lines"] > row["limit"] and not row["exception_applied"]:
                findings.append(
                    {
                        "code": "undecomposed_hotspot",
                        "path": relative,
                        "lines": row["lines"],
                        "limit": row["limit"],
                    }
                )
        findings.extend(
            item
            for item in responsibility_findings
            if languages.get(str(item.get("path"))) == language
        )
        return {"passed": not findings, "findings": findings}

    checks = {
        "python_decomposition": decomposition("python"),
        "rust_decomposition": decomposition("rust"),
        "file_size_budget": {"passed": size["passed"], "findings": size["findings"]},
        "dependency_direction": {
            "passed": dependencies["direction_passed"],
            "findings": dependencies["findings"],
        },
        "import_cycles": {
            "passed": dependencies["cycle_passed"],
            "findings": [
                {"code": "python_import_cycle", "modules": cycle}
                for cycle in dependencies["python"]["cycles"]
            ]
            + [
                {"code": "rust_module_cycle", "modules": cycle}
                for cycle in dependencies["rust"]["cycles"]
            ],
        },
        "crypto_primitives": {"passed": crypto["passed"], "findings": crypto["findings"]},
        "responsibility_separation": {
            "passed": responsibilities["passed"],
            "findings": responsibilities["findings"],
        },
    }
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "policy_sha256": _sha256(_canonical_json_bytes(policy)),
        "checks": checks,
        "size_budget": size,
        "dependencies": dependencies,
        "responsibilities": responsibilities,
        "crypto": crypto,
    }


def _junit_summary(path: Path) -> dict[str, Any]:
    # The input is pytest-generated JUnit in an owner-private, process-token temp root.
    root = ET.parse(path).getroot()  # nosec B314
    cases = list(root.iter("testcase"))
    failed: list[str] = []
    skipped: list[str] = []
    passed: list[str] = []
    for case in cases:
        identifier = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
        if case.find("failure") is not None or case.find("error") is not None:
            failed.append(identifier)
        elif case.find("skipped") is not None:
            skipped.append(identifier)
        else:
            passed.append(identifier)
    return {
        "tests": len(cases),
        "passed_tests": sorted(passed),
        "failed_tests": sorted(failed),
        "skipped_tests": sorted(skipped),
    }


def _run_pytest_suite(
    repository: Path,
    evidence_dir: Path,
    *,
    suite_id: str,
    tests: Sequence[str],
    timeout_seconds: int,
) -> dict[str, Any]:
    reported_command = [
        "{python}",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        *tests,
        "--junitxml={temporary}",
    ]
    try:
        # Parametrized node IDs consume substantial Windows path budget. Use
        # the process-token-owned temp parent rather than an arbitrarily deep
        # evidence path or a caller-controlled TEMP alias.
        with tempfile.TemporaryDirectory(
            prefix=".pytest-", dir=_runtime_temp_parent()
        ) as temporary:
            temporary_root = Path(temporary)
            junit = temporary_root / "junit.xml"
            command = [
                sys.executable,
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-q",
                *tests,
                f"--junitxml={junit}",
            ]
            environment = dict(os.environ)
            environment.update(
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TEMP": temporary,
                    "TMP": temporary,
                    "TMPDIR": temporary,
                }
            )
            process = subprocess.run(
                command,
                cwd=repository,
                env=environment,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_seconds,
            )
            summary: dict[str, Any]
            if junit.is_file():
                summary = _junit_summary(junit)
            else:
                summary = {
                    "tests": 0,
                    "passed_tests": [],
                    "failed_tests": [],
                    "skipped_tests": [],
                }
            passed = (
                process.returncode == 0
                and summary["tests"] > 0
                and not summary["failed_tests"]
                and not summary["skipped_tests"]
            )
            report = {
                "schema_version": "bluefire.architecture-dynamic-check.v1",
                "suite_id": suite_id,
                "command": reported_command,
                "exit_code": process.returncode,
                "passed": passed,
                **summary,
            }
        # Leaving the context is part of the proof: pytest's temporary stores,
        # including product databases created by lifecycle tests, must be gone
        # before a passing suite report can be returned.
        return {
            **report,
            "passed": report["passed"] and not temporary_root.exists(),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "schema_version": "bluefire.architecture-dynamic-check.v1",
            "suite_id": suite_id,
            "command": reported_command,
            "exit_code": None,
            "passed": False,
            "tests": 0,
            "passed_tests": [],
            "failed_tests": [type(exc).__name__],
            "skipped_tests": [],
        }


def _proof(*, assertion_id: str, kind: str, artifact: str, test_id: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "status": "passed",
        "test_id": test_id,
        "assertion_ids": [assertion_id],
        "evidence_artifacts": [artifact],
        "run_ids": [],
        "run_bundles": [],
        "environment_limitations": [],
    }


def run_gate_10(
    gate: Any,
    evidence_dir: Path,
    *,
    repository_root: Path | None = None,
) -> Gate10Outcome:
    repository = (repository_root or Path.cwd()).resolve(strict=True)
    destination = evidence_dir.resolve(strict=True)
    architecture_path = destination / "architecture-report.json"
    property_path = destination / "property-fuzz-report.json"
    behavior_path = destination / "behavior-preservation-report.json"
    try:
        architecture = audit_repository(repository)
    except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
        architecture = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "policy_sha256": None,
            "checks": {
                name: {
                    "passed": False,
                    "findings": [
                        {"code": "architecture_audit_failed", "detail": type(exc).__name__}
                    ],
                }
                for name in {
                    "python_decomposition",
                    "rust_decomposition",
                    "file_size_budget",
                    "dependency_direction",
                    "import_cycles",
                    "crypto_primitives",
                    "responsibility_separation",
                }
            },
        }
    _write_json(architecture_path, architecture)
    property_report = _run_pytest_suite(
        repository,
        destination,
        suite_id="property-fuzz",
        tests=_PROPERTY_TESTS,
        timeout_seconds=300,
    )
    _write_json(property_path, property_report)
    behavior_report = _run_pytest_suite(
        repository,
        destination,
        suite_id="behavior-preservation",
        tests=_BEHAVIOR_TESTS,
        timeout_seconds=600,
    )
    _write_json(behavior_path, behavior_report)

    checks = dict(architecture["checks"])
    checks["property_fuzz"] = {
        "passed": property_report["passed"],
        "findings": [] if property_report["passed"] else [{"code": "property_fuzz_failed"}],
    }
    checks["behavior_preservation"] = {
        "passed": behavior_report["passed"],
        "findings": [] if behavior_report["passed"] else [{"code": "behavior_preservation_failed"}],
    }
    contract_assertions = {assertion.assertion_id for assertion in getattr(gate, "assertions", ())}
    expected_assertions = set(_ASSERTION_CHECKS)
    proofs: list[Mapping[str, Any]] = []
    blocked: list[str] = []
    if contract_assertions != expected_assertions:
        blocked.append("locked GATE-10 assertion set mismatch")
    for assertion_id, (check_name, kind, artifact, test_id) in _ASSERTION_CHECKS.items():
        check = checks.get(check_name)
        if (
            contract_assertions == expected_assertions
            and isinstance(check, Mapping)
            and check.get("passed") is True
        ):
            proofs.append(
                _proof(
                    assertion_id=assertion_id,
                    kind=kind,
                    artifact=artifact,
                    test_id=test_id,
                )
            )
        else:
            blocked.append(assertion_id)
    if blocked:
        return Gate10Outcome(
            status="failed",
            proofs=tuple(proofs),
            failure_reason="GATE-10 failed checks: " + ", ".join(blocked),
        )
    return Gate10Outcome(status="passed", proofs=tuple(proofs), failure_reason=None)


__all__ = [
    "Gate10Outcome",
    "audit_repository",
    "run_gate_10",
]
