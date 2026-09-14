"""Independent validators for the GATE-12 professional release artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .defense_frontier import COMPARISON_REPORT
from .defense_frontier import HELPER_SCHEMA as FRONTIER_HELPER_SCHEMA
from .defense_frontier import REPORT_PATHS as FRONTIER_REPORT_PATHS
from .defense_frontier_validation import validate_persisted_frontier
from .detection_gate_validation import CHECK_NAMES as DETECTION_CHECK_NAMES
from .detection_gate_validation import validate_persisted_detection_gate
from .install_gate import _validate_reports as validate_install_gate_reports
from .operator_ui_gate_validation import CHECK_NAMES as OPERATOR_CHECK_NAMES
from .operator_ui_gate_validation import validate_persisted_operator_ui_gate
from .operator_ui_journey import HELPER_SCHEMA as OPERATOR_HELPER_SCHEMA
from .operator_ui_journey import REPORT_PATHS as OPERATOR_REPORT_PATHS
from .operator_ui_journey import SCREENSHOT_ARTIFACTS
from .product_acceptance import _receipt_proof, load_release_contract
from .product_acceptance_run_bundle import acceptance_run_binding
from .release_readiness_artifacts import persisted_artifact_hashes
from .release_readiness_journey import JOURNEY_REPORT, JOURNEY_SCHEMA
from .release_rights_audit import run_release_rights_audit
from .source_intake_gate_validation import CHECK_NAMES as SOURCE_INTAKE_CHECK_NAMES
from .source_intake_gate_validation import validate_persisted_source_intake_gate
from .util import content_hash

UPSTREAM_REPORT = "gate12-upstream-closure.json"
STRUCTURAL_REPORT = "gate12-release-structure.json"
SUITE_REPORT = "gate12-full-suite.json"
OPSEC_REPORT = "gate12-opsec-report.json"
VERIFICATION_REPORT = "gate12-verification-report.json"
SBOM_REPORT = "gate12-python-sbom.json"

UPSTREAM_SCHEMA = "bluefire.release-readiness-upstream.v1"
STRUCTURAL_SCHEMA = "bluefire.release-readiness-structure.v1"
SUITE_SCHEMA = "bluefire.release-readiness-suite.v1"
OPSEC_SCHEMA = "bluefire.release-readiness-opsec.v1"
VERIFICATION_SCHEMA = "bluefire.release-readiness-verification.v1"

CHECK_NAMES = frozenset(
    {
        "readme_product_loop",
        "sanitized_screenshots",
        "frontier_compare_artifact",
        "capability_classification",
        "complete_docs",
        "github_metadata",
        "clean_package_install",
        "full_suites",
        "security_opsec",
        "clean_worktree",
        "rights_audit",
        "license_decision",
    }
)

_UPSTREAM_GATES = tuple(f"GATE-{index:02d}" for index in range(1, 12))
_PRODUCTION_BROWSER_REPORTS = {
    "GATE-07": ("gate07-browser-report.json", "bluefire.detection-production-browser.v1"),
    "GATE-08": ("gate08-browser-report.json", "bluefire.operator-production-browser.v1"),
    "GATE-09": ("gate09-browser-report.json", "bluefire.source-intake-production-browser.v1"),
}
_REQUIRED_DOCS: Mapping[str, tuple[str, ...]] = {
    "README.md": ("design", "Simulate", "Execute", "observe", "replay", "compare"),
    "docs/INSTALLATION.md": ("fresh environment", "bluefire ui", "runner bootstrap"),
    "docs/CONFIGURATION.md": ("simulate", "execute", "autonomy", "opaque"),
    "docs/OPERATOR_GUIDE.md": ("Design", "Observe", "Replay", "Compare", "cleanup"),
    "docs/EXTENSIONS.md": ("action package", "WASM", "plugin", "no host imports"),
    "docs/TROUBLESHOOTING.md": ("preflight", "collector", "browser", "cleanup"),
    "docs/RELEASE_CAPABILITIES.md": (
        "Shipped",
        "Environment-dependent",
        "Structural",
        "Restricted",
    ),
    "docs/GITHUB_METADATA.md": ("Recommendation only", "Description", "Topics", "Social preview"),
    "docs/ARCHITECTURE.md": ("control plane", "Rust runner"),
    "docs/RUNNER_DEPLOYMENT.md": ("bootstrap", "enrollment"),
    "docs/ACTION_SDK.md": ("Signed provider", "cleanup"),
    "docs/PLUGIN_SDK.md": ("declarative", "metadata-only"),
    "docs/AI_PLANNER.md": ("off", "assist", "auto"),
    "docs/EVIDENCE_MODEL.md": ("collector", "observed"),
    "docs/DETECTION_LAB.md": ("Sigma", "YARA", "SQLite"),
    "docs/REPLAY_COMPARE.md": ("checkpoint", "materialized", "Comparison"),
    "SECURITY.md": ("report", "security"),
    "docs/USER_GUIDE.md": ("Getting started", "Execute"),
}
_EXPECTED_SUITE_IDS = frozenset(
    {
        "python.compile",
        "python.pytest",
        "python.ruff",
        "python.black",
        "python.mypy",
        "rust.fmt",
        "rust.clippy",
        "rust.test",
        "rust.release",
        "frontend.typecheck",
        "frontend.lint",
        "frontend.unit",
        "frontend.build-parity",
        "frontend.e2e-demo",
        "frontend.production-detection",
        "frontend.production-operator",
        "frontend.production-source-intake",
        "security.gitleaks",
        "security.detect-secrets",
        "security.bandit",
        "security.pip-audit",
        "security.sbom",
    }
)
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "gate_id",
        "acceptance_id",
        "contract_sha256",
        "repository_commit",
        "repository_tree",
        "release",
        "harness_assessment",
        "timestamp",
        "status",
        "failure_reason",
        "proofs",
    }
)
_PRODUCTION_VALIDATORS = {
    "GATE-07": (DETECTION_CHECK_NAMES, 1),
    "GATE-08": (OPERATOR_CHECK_NAMES, 4),
    "GATE-09": (SOURCE_INTAKE_CHECK_NAMES, 1),
}


class ReleaseReadinessValidationError(ValueError):
    """Raised when persisted release evidence does not establish its claim."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseReadinessValidationError(message)


def _is_link_or_reparse(details: os.stat_result) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        int(getattr(details, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        details = path.lstat()
        _require(
            stat.S_ISREG(details.st_mode)
            and not _is_link_or_reparse(details)
            and details.st_nlink == 1
            and 0 < details.st_size <= _MAX_JSON_BYTES,
            f"{context} is absent, unsafe, or unbounded",
        )
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseReadinessValidationError(f"{context} is invalid JSON") from exc
    _require(isinstance(value, Mapping), f"{context} is not an object")
    return dict(value)


def _binding_fields(binding: Mapping[str, str]) -> Mapping[str, Any]:
    return {
        "acceptance_id": binding.get("acceptance_id"),
        "contract_sha256": binding.get("contract_sha256"),
        "repository_commit": binding.get("repository_commit"),
        "repository_tree": binding.get("repository_tree"),
        "release": binding.get("release") == "true",
    }


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _receipt_timestamp(value: Any, gate_id: str) -> datetime:
    _require(
        isinstance(value, str) and value.endswith("Z"),
        f"{gate_id} receipt timestamp is invalid",
    )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (AttributeError, ValueError) as exc:
        raise ReleaseReadinessValidationError(f"{gate_id} receipt timestamp is invalid") from exc
    _require(parsed.tzinfo == timezone.utc, f"{gate_id} receipt timestamp is invalid")
    return parsed


def _validate_upstream_receipt(
    acceptance_root: Path,
    gate_id: str,
    binding: Mapping[str, str],
    gate: Any,
) -> Mapping[str, Any]:
    gate_root = acceptance_root / gate_id.lower()
    receipt_path = gate_root / "gate-receipt.json"
    receipt = read_json(receipt_path, f"{gate_id} upstream receipt")
    proofs = receipt.get("proofs")
    _require(
        set(receipt) == _RECEIPT_FIELDS
        and receipt.get("schema_version") == "bluefire.product-gate-receipt.v1"
        and receipt.get("gate_id") == gate_id
        and all(receipt.get(key) == value for key, value in _binding_fields(binding).items())
        and receipt.get("status") == "passed"
        and receipt.get("failure_reason") is None
        and isinstance(proofs, list)
        and bool(proofs),
        f"{gate_id} upstream receipt is not a passing bound proof",
    )
    if not isinstance(proofs, list):
        raise ReleaseReadinessValidationError(f"{gate_id} upstream receipt proofs must be a list")
    receipt_timestamp = _receipt_timestamp(receipt.get("timestamp"), gate_id)
    expected_binding = acceptance_run_binding(
        acceptance_id=str(binding["acceptance_id"]),
        gate_id=gate_id,
        contract_sha256=str(binding["contract_sha256"]),
        repository_commit=str(binding["repository_commit"]),
        repository_tree=str(binding["repository_tree"]),
        release=str(binding["release"]),
    )
    assertions = {
        assertion.assertion_id: assertion.proof for assertion in getattr(gate, "assertions", ())
    }
    normalized_proofs: list[Mapping[str, Any]] = []
    artifacts: list[Mapping[str, Any]] = []
    proof_issues: list[str] = []
    for raw_proof in proofs:
        normalized, proof_artifacts, issues = _receipt_proof(
            raw_proof,
            gate_dir=gate_root,
            run_dir=acceptance_root,
            assertions=assertions,
            expected_binding=expected_binding,
            not_before=datetime.min.replace(tzinfo=timezone.utc),
            not_after=receipt_timestamp,
        )
        artifacts.extend(proof_artifacts)
        proof_issues.extend(issues)
        if normalized is not None:
            normalized_proofs.append(normalized)
    assertion_ids = [
        assertion_id
        for proof in normalized_proofs
        for assertion_id in proof.get("assertion_ids", ())
    ]
    test_ids = [str(proof.get("test_id")) for proof in normalized_proofs]
    run_ids = [str(run_id) for proof in normalized_proofs for run_id in proof.get("run_ids", ())]
    required_assertions = {assertion.assertion_id for assertion in getattr(gate, "assertions", ())}
    proof_types = {str(proof.get("kind")) for proof in normalized_proofs}
    unique_artifacts = {str(artifact.get("path")) for artifact in artifacts}
    _require(
        not proof_issues
        and len(normalized_proofs) == len(proofs)
        and len(test_ids) == len(set(test_ids))
        and len(test_ids) >= int(getattr(gate, "minimum_test_ids", 0))
        and len(assertion_ids) == len(set(assertion_ids))
        and set(assertion_ids) == required_assertions
        and set(getattr(gate, "required_proof", ())) <= proof_types
        and len(set(run_ids)) >= int(getattr(gate, "minimum_run_ids", 0))
        and len(unique_artifacts) >= int(getattr(gate, "minimum_evidence_artifacts", 0)),
        f"{gate_id} receipt proofs do not reconcile with the locked contract",
    )
    assessment = receipt.get("harness_assessment")
    proof_sha256 = assessment.get("proof_sha256") if isinstance(assessment, Mapping) else None
    _require(
        isinstance(assessment, Mapping)
        and set(assessment)
        == {
            "schema_version",
            "status",
            "failure_reason",
            "workflow_exit_code",
            "proof_sha256",
            "postflight",
        }
        and assessment.get("schema_version") == "bluefire.product-gate-assessment.v1"
        and assessment.get("status") == "passed"
        and assessment.get("failure_reason") is None
        and assessment.get("workflow_exit_code") == 0
        and isinstance(proof_sha256, str)
        and _SHA256.fullmatch(proof_sha256) is not None
        and proof_sha256 == _canonical_digest(normalized_proofs)
        and assessment.get("postflight") is None,
        f"{gate_id} has no passing harness assessment",
    )
    return {
        "gate_id": gate_id,
        "receipt": f"{gate_id.lower()}/gate-receipt.json",
        "receipt_sha256": "sha256:" + hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "proof_sha256": proof_sha256,
        "proof_count": len(proofs) if isinstance(proofs, list) else 0,
    }


def validate_upstream_closure(
    repository: Path,
    acceptance_root: Path,
    binding: Mapping[str, str],
) -> Mapping[str, Any]:
    """Revalidate prior gates from the same acceptance run, including Gate 01."""

    contract = load_release_contract()
    _require(
        contract.digest == binding.get("contract_sha256"),
        "the upstream receipt contract does not match the locked release contract",
    )
    definitions = {gate.gate_id: gate for gate in contract.gates}
    _require(
        set(_UPSTREAM_GATES) <= set(definitions),
        "the locked upstream gate definitions are incomplete",
    )
    rows = [
        _validate_upstream_receipt(
            acceptance_root,
            gate_id,
            binding,
            definitions[gate_id],
        )
        for gate_id in _UPSTREAM_GATES
    ]
    gate01_ids = validate_install_gate_reports(acceptance_root / "gate-01")
    _require(len(gate01_ids) == 2, "the clean installed-package journey is incomplete")

    production_results: dict[str, tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]] = {}
    validators = {
        "GATE-07": validate_persisted_detection_gate,
        "GATE-08": validate_persisted_operator_ui_gate,
        "GATE-09": validate_persisted_source_intake_gate,
    }
    for gate_id, (expected_checks, expected_runs) in _PRODUCTION_VALIDATORS.items():
        validator = validators[gate_id]
        checks, refs = validator(repository, acceptance_root / gate_id.lower())
        _require(
            isinstance(checks, Mapping)
            and set(checks) == set(expected_checks)
            and all(value is True for value in checks.values())
            and isinstance(refs, tuple)
            and len(refs) == expected_runs,
            f"{gate_id} persisted production journey did not independently revalidate",
        )
        production_results[gate_id] = (checks, refs)

    production_specs: list[dict[str, Any]] = []
    for gate_id, (relative, schema) in _PRODUCTION_BROWSER_REPORTS.items():
        report = read_json(
            acceptance_root / gate_id.lower() / relative, f"{gate_id} browser report"
        )
        _require(
            report.get("schema_version") == schema
            and report.get("production_browser_interaction") is True
            and report.get("demo_mode") is False,
            f"{gate_id} production browser proof is invalid",
        )
        production_specs.append(
            {
                "gate_id": gate_id,
                "report": f"{gate_id.lower()}/{relative}",
                "sha256": "sha256:"
                + hashlib.sha256(
                    (acceptance_root / gate_id.lower() / relative).read_bytes()
                ).hexdigest(),
                "semantic_check_count": len(production_results[gate_id][0]),
                "semantic_checks_sha256": content_hash(sorted(production_results[gate_id][0])),
                "run_count": len(production_results[gate_id][1]),
            }
        )
    return {
        "schema_version": UPSTREAM_SCHEMA,
        "passed": True,
        "repository_commit": binding["repository_commit"],
        "repository_tree": binding["repository_tree"],
        "gates": rows,
        "clean_package_install": {
            "gate_id": "GATE-01",
            "run_count": len(gate01_ids),
            "validated_reports": True,
            "source": "same-acceptance-final-committed-tree",
        },
        "production_playwright": production_specs,
        "repository_documented": (repository / "README.md").is_file(),
    }


def _png_dimensions(path: Path) -> tuple[int, int]:
    try:
        details = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise ReleaseReadinessValidationError("a final screenshot is unavailable") from exc
    _require(
        stat.S_ISREG(details.st_mode)
        and not _is_link_or_reparse(details)
        and details.st_nlink == 1
        and 33 <= len(payload) <= _MAX_SCREENSHOT_BYTES
        and payload[:8] == b"\x89PNG\r\n\x1a\n",
        "a final screenshot is unsafe, unbounded, or not PNG",
    )
    cursor = 8
    chunks: list[bytes] = []
    image_data: list[bytes] = []
    width = height = 0
    bit_depth = color_type = compression = png_filter = interlace = -1
    while cursor + 12 <= len(payload):
        length = struct.unpack(">I", payload[cursor : cursor + 4])[0]
        chunk_type = payload[cursor + 4 : cursor + 8]
        end = cursor + 12 + length
        _require(end <= len(payload), "a final screenshot has a truncated PNG chunk")
        chunk_data = payload[cursor + 8 : cursor + 8 + length]
        recorded_crc = struct.unpack(">I", payload[cursor + 8 + length : end])[0]
        expected_crc = zlib.crc32(chunk_data, zlib.crc32(chunk_type)) & 0xFFFFFFFF
        _require(recorded_crc == expected_crc, "a final screenshot has an invalid PNG checksum")
        chunks.append(chunk_type)
        if chunk_type == b"IHDR":
            _require(length == 13, "a final screenshot has an invalid PNG header")
            (
                width,
                height,
                bit_depth,
                color_type,
                compression,
                png_filter,
                interlace,
            ) = struct.unpack(">IIBBBBB", chunk_data)
        elif chunk_type == b"IDAT":
            image_data.append(chunk_data)
        elif chunk_type == b"IEND":
            _require(length == 0, "a final screenshot has an invalid PNG terminator")
        _require(
            chunk_type in {b"IHDR", b"IDAT", b"IEND"},
            "a final screenshot contains an unreviewed PNG chunk",
        )
        cursor = end
        if chunk_type == b"IEND":
            break
    _require(
        cursor == len(payload)
        and chunks[:1] == [b"IHDR"]
        and chunks[-1:] == [b"IEND"]
        and chunks.count(b"IHDR") == 1
        and chunks.count(b"IEND") == 1
        and bool(chunks[1:-1])
        and all(chunk == b"IDAT" for chunk in chunks[1:-1])
        and 1200 <= width <= 4096
        and 700 <= height <= 2160,
        "a final screenshot has invalid structure or dimensions",
    )
    _require(
        bit_depth == 8
        and color_type in {2, 6}
        and compression == 0
        and png_filter == 0
        and interlace == 0,
        "a final screenshot uses an unsupported PNG pixel format",
    )
    channels = 3 if color_type == 2 else 4
    stride = width * channels + 1
    expected_size = stride * height
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(b"".join(image_data), expected_size + 1)
    except zlib.error as exc:
        raise ReleaseReadinessValidationError(
            "a final screenshot has invalid compressed pixels"
        ) from exc
    _require(
        decoder.eof
        and not decoder.unused_data
        and not decoder.unconsumed_tail
        and len(pixels) == expected_size
        and all(pixels[offset] <= 4 for offset in range(0, expected_size, stride)),
        "a final screenshot has invalid or unbounded pixel data",
    )
    return width, height


def validate_release_journey(
    repository: Path,
    destination: Path,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    report = read_json(destination / JOURNEY_REPORT, "GATE-12 release journey report")
    expected_journeys = {
        "defense_frontier": {
            "helper_schema": FRONTIER_HELPER_SCHEMA,
            "reports": [f"frontier/{name}" for name in FRONTIER_REPORT_PATHS],
            "comparison_report": f"frontier/{COMPARISON_REPORT}",
            "run_count": 3,
        },
        "production_operator": {
            "helper_schema": OPERATOR_HELPER_SCHEMA,
            "reports": [f"operator/{name}" for name in OPERATOR_REPORT_PATHS],
            "screenshots": [f"operator/{name}" for name in SCREENSHOT_ARTIFACTS],
            "run_count": 4,
        },
    }
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "journeys",
            "run_bundles",
            "production_playwright_specs",
            "source_checkout_writes",
        }
        and report.get("schema_version") == JOURNEY_SCHEMA
        and report.get("passed") is True
        and report.get("journeys") == expected_journeys
        and report.get("production_playwright_specs")
        == ["frontend/tests/e2e/operator-production.spec.ts"]
        and report.get("source_checkout_writes") == [],
        "the GATE-12 release journey shape is invalid",
    )
    frontier_checks, frontier_refs = validate_persisted_frontier(
        repository, destination / "frontier"
    )
    operator_checks, operator_refs = validate_persisted_operator_ui_gate(
        repository, destination / "operator"
    )
    _require(
        bool(frontier_checks) and all(frontier_checks.values()),
        "the fresh defense-frontier journey has failed semantic checks",
    )
    _require(
        bool(operator_checks) and all(operator_checks.values()),
        "the fresh production-operator journey has failed semantic checks",
    )
    prefixed = tuple(
        {"run_id": str(row["run_id"]), "path": f"frontier/{row['path']}"} for row in frontier_refs
    ) + tuple(
        {"run_id": str(row["run_id"]), "path": f"operator/{row['path']}"} for row in operator_refs
    )
    _require(
        report.get("run_bundles") == list(prefixed)
        and len(prefixed) == 7
        and len({row["run_id"] for row in prefixed}) == 7
        and all(_RUN_ID.fullmatch(row["run_id"]) for row in prefixed),
        "the GATE-12 release run inventory is invalid",
    )
    screenshot_rows = []
    for relative in SCREENSHOT_ARTIFACTS:
        width, height = _png_dimensions(destination / "operator" / relative)
        screenshot_rows.append((relative, width, height))
    comparison = read_json(
        destination / "frontier" / COMPARISON_REPORT,
        "GATE-12 defense-frontier comparison",
    )
    checks = {
        "sanitized_screenshots": len(screenshot_rows) == len(SCREENSHOT_ARTIFACTS),
        "frontier_compare_artifact": comparison.get("passed") is True,
    }
    return checks, prefixed


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    _require(completed.returncode == 0, "release Git state is unavailable")
    return completed.stdout.decode("utf-8", "strict").strip()


def audit_release_structure(
    repository: Path,
    binding: Mapping[str, str],
) -> Mapping[str, Any]:
    documentation: dict[str, Any] = {}
    for relative, tokens in _REQUIRED_DOCS.items():
        path = repository / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
        documentation[relative] = {
            "present": bool(text),
            "required_tokens": list(tokens),
            "tokens_present": all(token.casefold() in text.casefold() for token in tokens),
            "sha256": (
                "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None
            ),
        }
    head = _git(repository, "rev-parse", "HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    status = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    rights = run_release_rights_audit(repository).to_dict()
    package = json.loads((repository / "frontend/package.json").read_text(encoding="utf-8"))
    cargo = (repository / "runner/Cargo.toml").read_text(encoding="utf-8")
    version = (repository / "bluefire/version.py").read_text(encoding="utf-8")
    frontend_version = package.get("version") if isinstance(package, Mapping) else None
    cargo_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', cargo)
    python_match = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"\s*$', version)
    versions = {
        "python": python_match.group(1) if python_match else None,
        "rust": cargo_match.group(1) if cargo_match else None,
        "frontend": frontend_version,
    }
    checks = {
        "readme_product_loop": documentation["README.md"]["tokens_present"],
        "capability_classification": documentation["docs/RELEASE_CAPABILITIES.md"][
            "tokens_present"
        ],
        "complete_docs": all(
            row["present"] and row["tokens_present"] for row in documentation.values()
        ),
        "github_metadata": documentation["docs/GITHUB_METADATA.md"]["tokens_present"],
        "clean_worktree": (
            status == ""
            and head == binding.get("repository_commit")
            and tree == binding.get("repository_tree")
            and _COMMIT.fullmatch(head) is not None
            and _COMMIT.fullmatch(tree) is not None
        ),
        "rights_audit": rights.get("unresolved_items") == [],
        "license_decision": rights.get("decision") == "retain-mit"
        and rights.get("project_license") == "MIT",
        "version_consistency": len(set(versions.values())) == 1 and None not in versions.values(),
    }
    return {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": all(checks.values()),
        "checks": checks,
        "documentation": documentation,
        "git": {
            "head_matches_acceptance": head == binding.get("repository_commit"),
            "tree_matches_acceptance": tree == binding.get("repository_tree"),
            "status_porcelain_empty": status == "",
        },
        "versions": versions,
        "rights_audit": rights,
    }


def validate_suite_report(value: Mapping[str, Any]) -> bool:
    rows = value.get("suites")
    toolchain = value.get("toolchain")
    if (
        set(value) != {"schema_version", "passed", "suites", "toolchain", "source_writes"}
        or value.get("schema_version") != SUITE_SCHEMA
        or value.get("passed") is not True
        or not isinstance(rows, list)
        or value.get("source_writes") != []
        or not isinstance(toolchain, Mapping)
        or set(toolchain)
        != {"python", "node_available", "cargo_available", "cargo_version_verified"}
        or not isinstance(toolchain.get("python"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(toolchain["python"])) is None
        or toolchain.get("node_available") is not True
        or toolchain.get("cargo_available") is not True
        or toolchain.get("cargo_version_verified") is not True
    ):
        return False
    identities = [row.get("suite_id") for row in rows if isinstance(row, Mapping)]
    if (
        len(rows) != len(_EXPECTED_SUITE_IDS)
        or any(not isinstance(identity, str) for identity in identities)
        or identities != sorted(_EXPECTED_SUITE_IDS)
    ):
        return False
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "suite_id",
                "command",
                "exit_code",
                "passed",
                "test_count",
                "passed_test_ids",
                "skipped_test_ids",
                "details",
            }
            or not isinstance(row.get("command"), list)
            or not all(isinstance(item, str) and item for item in row["command"])
            or row.get("exit_code") != 0
            or row.get("passed") is not True
            or type(row.get("test_count")) is not int
            or row["test_count"] < 0
            or not isinstance(row.get("passed_test_ids"), list)
            or not all(isinstance(item, str) and item for item in row["passed_test_ids"])
            or row["passed_test_ids"] != sorted(set(row["passed_test_ids"]))
            or not isinstance(row.get("skipped_test_ids"), list)
            or not all(isinstance(item, str) and item for item in row["skipped_test_ids"])
            or row["skipped_test_ids"] != sorted(set(row["skipped_test_ids"]))
            or not set(row["passed_test_ids"]).isdisjoint(row["skipped_test_ids"])
            or row["test_count"] != len(row["passed_test_ids"]) + len(row["skipped_test_ids"])
            or not isinstance(row.get("details"), Mapping)
        ):
            return False
    by_id = {str(row["suite_id"]): row for row in rows}
    counted_suites = {
        "python.pytest",
        "rust.test",
        "frontend.unit",
        "frontend.e2e-demo",
        "frontend.production-detection",
        "frontend.production-operator",
        "frontend.production-source-intake",
    }
    if any(by_id[suite]["test_count"] != 0 for suite in _EXPECTED_SUITE_IDS - counted_suites):
        return False
    production_ids = {
        "frontend.production-detection": "frontend/tests/e2e/detection-production.spec.ts",
        "frontend.production-operator": "frontend/tests/e2e/operator-production.spec.ts",
        "frontend.production-source-intake": "frontend/tests/e2e/source-intake-production.spec.ts",
    }
    return bool(
        len(by_id["python.pytest"]["passed_test_ids"]) >= 100
        and len(by_id["frontend.unit"]["passed_test_ids"]) >= 1
        and len(by_id["frontend.e2e-demo"]["passed_test_ids"]) >= 1
        and len(by_id["rust.test"]["passed_test_ids"]) >= 1
        and by_id["rust.test"]["skipped_test_ids"] == []
        and by_id["frontend.unit"]["skipped_test_ids"] == []
        and by_id["frontend.e2e-demo"]["skipped_test_ids"] == []
        and all(
            by_id[suite]["passed_test_ids"] == [test_id] and by_id[suite]["skipped_test_ids"] == []
            for suite, test_id in production_ids.items()
        )
    )


def validate_opsec_report(value: Mapping[str, Any]) -> bool:
    scans = value.get("scans")
    return bool(
        set(value)
        == {
            "schema_version",
            "passed",
            "tracked_file_count",
            "forbidden_tracked_artifacts",
            "private_identity_hits",
            "scans",
            "sbom_safe",
            "source_digest",
        }
        and value.get("schema_version") == OPSEC_SCHEMA
        and value.get("passed") is True
        and type(value.get("tracked_file_count")) is int
        and value["tracked_file_count"] > 0
        and value.get("forbidden_tracked_artifacts") == []
        and value.get("private_identity_hits") == []
        and value.get("sbom_safe") is True
        and isinstance(scans, Mapping)
        and set(scans) == {"gitleaks", "detect-secrets", "bandit", "pip-audit"}
        and all(item is True for item in scans.values())
        and isinstance(value.get("source_digest"), str)
        and _SHA256.fullmatch(str(value["source_digest"])) is not None
    )


def exact_contract_suite(
    value: Any,
    *,
    expected_count: int,
    expected_digest: str,
) -> bool:
    passed = value.get("passed_tests") if isinstance(value, Mapping) else None
    return bool(
        isinstance(value, Mapping)
        and value.get("schema_version") == "bluefire.architecture-dynamic-check.v1"
        and value.get("suite_id") == "release-readiness-contracts"
        and value.get("exit_code") == 0
        and value.get("passed") is True
        and value.get("tests") == expected_count
        and isinstance(passed, list)
        and passed == sorted(set(passed))
        and len(passed) == expected_count
        and content_hash(passed) == expected_digest
        and value.get("failed_tests") == []
        and value.get("skipped_tests") == []
    )


def _verification_timestamp(value: Any, context: str) -> datetime:
    _require(isinstance(value, str) and value.endswith("Z"), f"{context} is not UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (AttributeError, ValueError) as exc:
        raise ReleaseReadinessValidationError(f"{context} is not UTC") from exc
    _require(parsed.tzinfo == timezone.utc, f"{context} is not UTC")
    return parsed


def validate_verification_report(
    path: Path,
    *,
    expected_bundles: Sequence[Mapping[str, str]],
    expected_count: int,
    expected_digest: str,
    not_before: datetime,
    not_after: datetime,
) -> Mapping[str, Any]:
    """Re-read and strictly validate the final GATE-12 decision record."""

    report = read_json(path, "GATE-12 verification report")
    _require(
        set(report)
        == {
            "schema_version",
            "passed",
            "checks",
            "helper",
            "contract_suite",
            "upstream_report",
            "structure_report",
            "suite_report",
            "opsec_report",
            "artifact_hashes",
            "run_bundles",
            "started_at",
            "finished_at",
        }
        and report.get("schema_version") == VERIFICATION_SCHEMA
        and report.get("passed") is True,
        "the GATE-12 verification report shape is invalid",
    )
    checks = report.get("checks")
    _require(
        isinstance(checks, Mapping)
        and set(checks) == CHECK_NAMES
        and all(value is True for value in checks.values()),
        "the GATE-12 verification checks are incomplete",
    )
    helper = report.get("helper")
    _require(
        isinstance(helper, Mapping)
        and set(helper) == {"passed", "exit_code", "command", "protocol_valid"}
        and helper.get("passed") is True
        and helper.get("exit_code") == 0
        and helper.get("protocol_valid") is True
        and helper.get("command")
        == ["{python}", "tools/run_release_readiness_gate_journey.py", "{fixed-arguments}"],
        "the GATE-12 helper result is invalid",
    )
    _require(
        exact_contract_suite(
            report.get("contract_suite"),
            expected_count=expected_count,
            expected_digest=expected_digest,
        ),
        "the GATE-12 focused suite record is invalid",
    )
    _require(
        report.get("upstream_report") == UPSTREAM_REPORT
        and report.get("structure_report") == STRUCTURAL_REPORT
        and report.get("suite_report") == SUITE_REPORT
        and report.get("opsec_report") == OPSEC_REPORT,
        "the GATE-12 verification report references are invalid",
    )
    artifact_hashes = report.get("artifact_hashes")
    recomputed_hashes = persisted_artifact_hashes(path.parent)
    _require(
        isinstance(artifact_hashes, Mapping)
        and dict(artifact_hashes) == recomputed_hashes
        and all(
            isinstance(relative, str)
            and relative
            and isinstance(digest, str)
            and _SHA256.fullmatch(digest) is not None
            for relative, digest in artifact_hashes.items()
        ),
        "the GATE-12 verification artifact hashes are invalid or stale",
    )
    bundles = report.get("run_bundles")
    expected = [dict(item) for item in expected_bundles]
    _require(
        isinstance(bundles, list)
        and bundles == expected
        and len(bundles) == 7
        and len({item.get("run_id") for item in bundles if isinstance(item, Mapping)}) == 7
        and all(
            isinstance(item, Mapping)
            and set(item) == {"run_id", "path"}
            and isinstance(item.get("run_id"), str)
            and _RUN_ID.fullmatch(str(item["run_id"])) is not None
            and isinstance(item.get("path"), str)
            and str(item["path"])
            in {
                f"frontier/runs/{item['run_id']}",
                f"operator/runs/{item['run_id']}",
            }
            for item in bundles
        ),
        "the GATE-12 verification run inventory is invalid",
    )
    started = _verification_timestamp(report.get("started_at"), "verification start")
    finished = _verification_timestamp(report.get("finished_at"), "verification finish")
    _require(
        not_before.tzinfo == timezone.utc and not_after.tzinfo == timezone.utc,
        "the GATE-12 verification bounds are not UTC",
    )
    _require(
        not_before == started <= finished <= not_after,
        "the GATE-12 verification timestamps are invalid",
    )
    return report


__all__ = [
    "CHECK_NAMES",
    "OPSEC_REPORT",
    "OPSEC_SCHEMA",
    "ReleaseReadinessValidationError",
    "SBOM_REPORT",
    "STRUCTURAL_REPORT",
    "STRUCTURAL_SCHEMA",
    "SUITE_REPORT",
    "SUITE_SCHEMA",
    "UPSTREAM_REPORT",
    "UPSTREAM_SCHEMA",
    "VERIFICATION_REPORT",
    "VERIFICATION_SCHEMA",
    "audit_release_structure",
    "exact_contract_suite",
    "persisted_artifact_hashes",
    "read_json",
    "validate_opsec_report",
    "validate_release_journey",
    "validate_suite_report",
    "validate_upstream_closure",
    "validate_verification_report",
]
