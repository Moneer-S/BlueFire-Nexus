from __future__ import annotations

import copy
import json
import struct
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.release_readiness_artifacts as artifacts_module
import bluefire.release_readiness_gate as gate_module
import bluefire.release_readiness_journey as journey_module
import bluefire.release_readiness_validation as validation_module
from bluefire.release_readiness_suites import _production_rows
from bluefire.release_readiness_validation import (
    CHECK_NAMES,
    OPSEC_SCHEMA,
    STRUCTURAL_SCHEMA,
    SUITE_SCHEMA,
    UPSTREAM_SCHEMA,
    ReleaseReadinessValidationError,
    audit_release_structure,
    exact_contract_suite,
    validate_opsec_report,
    validate_release_journey,
    validate_suite_report,
    validate_upstream_closure,
)
from bluefire.util import content_hash


def _binding() -> dict[str, str]:
    return {
        "schema_version": "bluefire.product-acceptance-run-binding.v1",
        "acceptance_id": "acceptance-gate12-test",
        "gate_id": "GATE-12",
        "contract_sha256": "sha256:" + "1" * 64,
        "repository_commit": "2" * 40,
        "repository_tree": "3" * 40,
        "release": "true",
    }


def _gate() -> Any:
    return SimpleNamespace(
        assertions=tuple(
            SimpleNamespace(assertion_id=assertion_id, proof=row[0])
            for assertion_id, row in gate_module._EXPECTED_ASSERTIONS.items()
        )
    )


def _suite_report() -> dict[str, Any]:
    counts = {
        "python.pytest": 100,
        "rust.test": 1,
        "frontend.unit": 1,
        "frontend.e2e-demo": 1,
        "frontend.production-detection": 1,
        "frontend.production-operator": 1,
        "frontend.production-source-intake": 1,
    }
    production_ids = {
        "frontend.production-detection": "frontend/tests/e2e/detection-production.spec.ts",
        "frontend.production-operator": "frontend/tests/e2e/operator-production.spec.ts",
        "frontend.production-source-intake": "frontend/tests/e2e/source-intake-production.spec.ts",
    }
    rows = []
    for suite_id in sorted(validation_module._EXPECTED_SUITE_IDS):
        count = counts.get(suite_id, 0)
        passed = (
            [production_ids[suite_id]]
            if suite_id in production_ids
            else [f"{suite_id}::{index:03d}" for index in range(count)]
        )
        rows.append(
            {
                "suite_id": suite_id,
                "command": ["{tool}", suite_id],
                "exit_code": 0,
                "passed": True,
                "test_count": count,
                "passed_test_ids": passed,
                "skipped_test_ids": [],
                "details": {},
            }
        )
    return {
        "schema_version": SUITE_SCHEMA,
        "passed": True,
        "suites": rows,
        "toolchain": {
            "python": "3.12.0",
            "node_available": True,
            "cargo_available": True,
            "cargo_version_verified": True,
        },
        "source_writes": [],
    }


def _opsec_report() -> dict[str, Any]:
    return {
        "schema_version": OPSEC_SCHEMA,
        "passed": True,
        "tracked_file_count": 1,
        "forbidden_tracked_artifacts": [],
        "private_identity_hits": [],
        "scans": {
            "gitleaks": True,
            "detect-secrets": True,
            "bandit": True,
            "pip-audit": True,
        },
        "sbom_safe": True,
        "source_digest": "sha256:" + "4" * 64,
    }


def _production_upstream() -> list[dict[str, Any]]:
    return [
        {
            "gate_id": gate_id,
            "report": f"{gate_id.lower()}/{report}",
            "sha256": "sha256:" + character * 64,
            "semantic_check_count": 1,
            "semantic_checks_sha256": content_hash([f"{gate_id}.check"]),
            "run_count": run_count,
        }
        for gate_id, report, run_count, character in (
            ("GATE-07", "gate07-browser-report.json", 1, "7"),
            ("GATE-08", "gate08-browser-report.json", 4, "8"),
            ("GATE-09", "gate09-browser-report.json", 1, "9"),
        )
    ]


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


def _png(
    *,
    metadata_chunk: bytes | None = None,
    bad_crc: bool = False,
) -> bytes:
    header = struct.pack(">IIBBBBB", 1200, 700, 8, 2, 0, 0, 0)
    chunks = [_png_chunk(b"IHDR", header)]
    if metadata_chunk is not None:
        chunks.append(_png_chunk(metadata_chunk, b"C:/" + b"Users/private/operator"))
    pixels = (b"\0" + b"\0" * (1200 * 3)) * 700
    chunks.extend((_png_chunk(b"IDAT", zlib.compress(pixels)), _png_chunk(b"IEND", b"")))
    payload = b"\x89PNG\r\n\x1a\n" + b"".join(chunks)
    return payload[:-1] + bytes([payload[-1] ^ 1]) if bad_crc else payload


def _run_refs(
    count: int,
    prefix: str = "runs",
    *,
    start: int = 0,
) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "run_id": f"run-20260830T1200{value:02d}Z-{value:016x}",
            "path": f"{prefix}/run-20260830T1200{value:02d}Z-{value:016x}",
        }
        for value in range(start, start + count)
    )


def test_gate12_locked_assertion_contract_is_exact() -> None:
    expected_ids = {
        "GATE-12-README-PRODUCT-LOOP",
        "GATE-12-SANITIZED-SCREENSHOTS",
        "GATE-12-FRONTIER-COMPARE-ARTIFACT",
        "GATE-12-CAPABILITY-CLASSIFICATION",
        "GATE-12-COMPLETE-DOCS",
        "GATE-12-GITHUB-METADATA",
        "GATE-12-CLEAN-PACKAGE-INSTALL",
        "GATE-12-FULL-SUITES",
        "GATE-12-SECURITY-OPSEC",
        "GATE-12-CLEAN-WORKTREE",
        "GATE-12-RIGHTS-AUDIT",
        "GATE-12-LICENSE-DECISION",
    }

    assert set(gate_module._EXPECTED_ASSERTIONS) == expected_ids
    assert CHECK_NAMES == {row[1] for row in gate_module._EXPECTED_ASSERTIONS.values()}
    assert len({row[3] for row in gate_module._EXPECTED_ASSERTIONS.values()}) == 12
    assert {row[0] for row in gate_module._EXPECTED_ASSERTIONS.values()} == {
        "dynamic",
        "structural",
    }
    assert gate_module._EXPECTED_CONTRACT_TEST_COUNT == 19
    assert gate_module._EXPECTED_CONTRACT_TESTS_SHA256 == (
        "sha256:e72ce002f19e650f847c21da4121822100c88ecd1fcca59e232bbffea5dbc362"
    )


def test_release_journey_prefixes_only_exact_bundle_references() -> None:
    refs = list(_run_refs(2))

    assert journey_module._prefixed_bundles({"run_bundles": refs}, "frontier") == [
        {"run_id": row["run_id"], "path": f"frontier/{row['path']}"} for row in refs
    ]

    invalid = copy.deepcopy(refs)
    invalid[0]["unexpected"] = "field"
    with pytest.raises(journey_module.ReleaseReadinessJourneyError, match="reference"):
        journey_module._prefixed_bundles({"run_bundles": invalid}, "frontier")


def test_png_validator_accepts_pixels_and_refuses_metadata_or_bad_crc(tmp_path: Path) -> None:
    screenshot = tmp_path / "screenshot.png"
    screenshot.write_bytes(_png())
    assert validation_module._png_dimensions(screenshot) == (1200, 700)

    screenshot.write_bytes(_png(metadata_chunk=b"tEXt"))
    with pytest.raises(ReleaseReadinessValidationError, match="chunk"):
        validation_module._png_dimensions(screenshot)

    screenshot.write_bytes(_png(metadata_chunk=b"aaAa"))
    with pytest.raises(ReleaseReadinessValidationError, match="chunk"):
        validation_module._png_dimensions(screenshot)

    screenshot.write_bytes(_png(bad_crc=True))
    with pytest.raises(ReleaseReadinessValidationError, match="checksum"):
        validation_module._png_dimensions(screenshot)


def test_release_journey_validation_rechecks_both_producers_and_screenshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "gate-12"
    frontier = destination / "frontier"
    operator = destination / "operator"
    frontier.mkdir(parents=True)
    operator.mkdir()
    frontier_refs = _run_refs(3)
    operator_refs = _run_refs(4, "operator-runs", start=3)
    prefixed = [
        *({"run_id": row["run_id"], "path": f"frontier/{row['path']}"} for row in frontier_refs),
        *({"run_id": row["run_id"], "path": f"operator/{row['path']}"} for row in operator_refs),
    ]
    (destination / journey_module.JOURNEY_REPORT).write_text(
        json.dumps(
            {
                "schema_version": journey_module.JOURNEY_SCHEMA,
                "passed": True,
                "journeys": {
                    "defense_frontier": {
                        "helper_schema": validation_module.FRONTIER_HELPER_SCHEMA,
                        "reports": [
                            f"frontier/{name}" for name in validation_module.FRONTIER_REPORT_PATHS
                        ],
                        "comparison_report": (f"frontier/{validation_module.COMPARISON_REPORT}"),
                        "run_count": 3,
                    },
                    "production_operator": {
                        "helper_schema": validation_module.OPERATOR_HELPER_SCHEMA,
                        "reports": [
                            f"operator/{name}" for name in validation_module.OPERATOR_REPORT_PATHS
                        ],
                        "screenshots": [
                            f"operator/{name}" for name in validation_module.SCREENSHOT_ARTIFACTS
                        ],
                        "run_count": 4,
                    },
                },
                "run_bundles": prefixed,
                "production_playwright_specs": ["frontend/tests/e2e/operator-production.spec.ts"],
                "source_checkout_writes": [],
            }
        ),
        encoding="utf-8",
    )
    for relative in validation_module.SCREENSHOT_ARTIFACTS:
        path = operator / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_png())
    (frontier / validation_module.COMPARISON_REPORT).write_text(
        json.dumps({"passed": True}), encoding="utf-8"
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_frontier",
        lambda *_args: ({"frontier": True}, frontier_refs),
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_operator_ui_gate",
        lambda *_args: ({"operator": True}, operator_refs),
    )

    checks, bundles = validate_release_journey(tmp_path, destination)

    assert checks == {"sanitized_screenshots": True, "frontier_compare_artifact": True}
    assert bundles == tuple(prefixed)


def test_full_suite_validator_requires_the_exact_inventory() -> None:
    report = _suite_report()
    assert validate_suite_report(report)

    missing = copy.deepcopy(report)
    missing["suites"] = missing["suites"][:-1]
    assert not validate_suite_report(missing)

    duplicate = copy.deepcopy(report)
    duplicate["suites"].append(copy.deepcopy(duplicate["suites"][0]))
    assert not validate_suite_report(duplicate)

    inconsistent = copy.deepcopy(report)
    pytest_row = next(row for row in inconsistent["suites"] if row["suite_id"] == "python.pytest")
    pytest_row["passed_test_ids"] = []
    assert not validate_suite_report(inconsistent)

    unverified_toolchain = copy.deepcopy(report)
    unverified_toolchain["toolchain"]["cargo_version_verified"] = False
    assert not validate_suite_report(unverified_toolchain)


def test_opsec_validator_requires_every_scan_and_sanitized_sbom() -> None:
    report = _opsec_report()
    assert validate_opsec_report(report)

    report["sbom_safe"] = False
    assert not validate_opsec_report(report)
    report["sbom_safe"] = True
    report["scans"]["gitleaks"] = False
    assert not validate_opsec_report(report)


def test_exact_focused_suite_rejects_drift_failure_and_skips() -> None:
    passed = ["tests_platform.test_release_readiness_gate::test_one"]
    report = {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": "release-readiness-contracts",
        "exit_code": 0,
        "passed": True,
        "tests": 1,
        "passed_tests": passed,
        "failed_tests": [],
        "skipped_tests": [],
    }
    assert exact_contract_suite(report, expected_count=1, expected_digest=content_hash(passed))

    report["skipped_tests"] = ["not-allowed"]
    assert not exact_contract_suite(report, expected_count=1, expected_digest=content_hash(passed))


def test_verification_report_is_re_read_strictly_and_refuses_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    passed = ["tests_platform.test_release_readiness_gate::test_locked"]
    bundles = (
        *_run_refs(3, "frontier/runs"),
        *_run_refs(4, "operator/runs", start=3),
    )
    started = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    artifact_hashes = {"gate12-full-suite.json": "sha256:" + "a" * 64}
    monkeypatch.setattr(
        validation_module,
        "persisted_artifact_hashes",
        lambda _root: artifact_hashes,
    )
    report = {
        "schema_version": validation_module.VERIFICATION_SCHEMA,
        "passed": True,
        "checks": {name: True for name in CHECK_NAMES},
        "helper": {
            "passed": True,
            "exit_code": 0,
            "command": [
                "{python}",
                "tools/run_release_readiness_gate_journey.py",
                "{fixed-arguments}",
            ],
            "protocol_valid": True,
        },
        "contract_suite": {
            "schema_version": "bluefire.architecture-dynamic-check.v1",
            "suite_id": "release-readiness-contracts",
            "exit_code": 0,
            "passed": True,
            "tests": 1,
            "passed_tests": passed,
            "failed_tests": [],
            "skipped_tests": [],
        },
        "upstream_report": validation_module.UPSTREAM_REPORT,
        "structure_report": validation_module.STRUCTURAL_REPORT,
        "suite_report": validation_module.SUITE_REPORT,
        "opsec_report": validation_module.OPSEC_REPORT,
        "artifact_hashes": dict(artifact_hashes),
        "run_bundles": list(bundles),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": (started + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
    }
    path = tmp_path / validation_module.VERIFICATION_REPORT
    path.write_text(json.dumps(report), encoding="utf-8")

    validated = validation_module.validate_verification_report(
        path,
        expected_bundles=bundles,
        expected_count=1,
        expected_digest=content_hash(passed),
        not_before=started,
        not_after=started + timedelta(seconds=3),
    )
    assert validated["passed"] is True

    report["checks"]["security_opsec"] = False
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ReleaseReadinessValidationError, match="checks"):
        validation_module.validate_verification_report(
            path,
            expected_bundles=bundles,
            expected_count=1,
            expected_digest=content_hash(passed),
            not_before=started,
            not_after=started + timedelta(seconds=3),
        )

    report["checks"]["security_opsec"] = True
    report["artifact_hashes"]["gate12-full-suite.json"] = "sha256:" + "b" * 64
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ReleaseReadinessValidationError, match="hashes"):
        validation_module.validate_verification_report(
            path,
            expected_bundles=bundles,
            expected_count=1,
            expected_digest=content_hash(passed),
            not_before=started,
            not_after=started + timedelta(seconds=3),
        )


def test_persisted_artifact_hashes_bind_the_complete_owned_tree(tmp_path: Path) -> None:
    root_reports = {
        journey_module.JOURNEY_REPORT,
        validation_module.UPSTREAM_REPORT,
        validation_module.STRUCTURAL_REPORT,
        validation_module.SUITE_REPORT,
        validation_module.OPSEC_REPORT,
        validation_module.SBOM_REPORT,
    }
    for relative in root_reports:
        (tmp_path / relative).write_text(f"{relative}\n", encoding="utf-8")
    for directory in (tmp_path / "frontier", tmp_path / "operator"):
        (directory / "runs" / "one").mkdir(parents=True)
        (directory / "report.json").write_text("{}\n", encoding="utf-8")
        (directory / "runs" / "one" / "manifest.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / validation_module.VERIFICATION_REPORT).write_text("{}\n", encoding="utf-8")

    hashes = artifacts_module.persisted_artifact_hashes(tmp_path)

    assert set(hashes) == root_reports | {
        "frontier/report.json",
        "frontier/runs/one/manifest.json",
        "operator/report.json",
        "operator/runs/one/manifest.json",
    }
    assert validation_module.VERIFICATION_REPORT not in hashes
    assert all(value.startswith("sha256:") and len(value) == 71 for value in hashes.values())


def test_upstream_closure_revalidates_gate01_and_production_browser_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _binding()
    gates = []
    for index in range(1, 12):
        gate_id = f"GATE-{index:02d}"
        gate_dir = tmp_path / gate_id.lower()
        gate_dir.mkdir()
        artifact = gate_dir / "artifact.json"
        artifact.write_text("{}", encoding="utf-8")
        assertion_id = f"{gate_id}-ASSERTION"
        gate = SimpleNamespace(
            gate_id=gate_id,
            assertions=(SimpleNamespace(assertion_id=assertion_id, proof="dynamic"),),
            required_proof=("dynamic",),
            minimum_evidence_artifacts=1,
            minimum_run_ids=0,
            minimum_test_ids=1,
        )
        gates.append(gate)
        proof = {
            "kind": "dynamic",
            "status": "passed",
            "test_id": f"{gate_id}.test",
            "assertion_ids": [assertion_id],
            "evidence_artifacts": ["artifact.json"],
            "run_ids": [],
            "run_bundles": [],
            "environment_limitations": [],
        }
        normalized = {
            **proof,
            "evidence_artifacts": [f"{gate_id.lower()}/artifact.json"],
        }
        receipt = {
            "schema_version": "bluefire.product-gate-receipt.v1",
            "gate_id": gate_id,
            "acceptance_id": binding["acceptance_id"],
            "contract_sha256": binding["contract_sha256"],
            "repository_commit": binding["repository_commit"],
            "repository_tree": binding["repository_tree"],
            "release": True,
            "timestamp": "2026-08-30T12:00:00Z",
            "status": "passed",
            "failure_reason": None,
            "proofs": [proof],
            "harness_assessment": {
                "schema_version": "bluefire.product-gate-assessment.v1",
                "status": "passed",
                "failure_reason": None,
                "workflow_exit_code": 0,
                "proof_sha256": validation_module._canonical_digest([normalized]),
                "postflight": None,
            },
        }
        (gate_dir / "gate-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(
        validation_module,
        "load_release_contract",
        lambda: SimpleNamespace(digest=binding["contract_sha256"], gates=tuple(gates)),
    )
    for gate_id, (relative, schema) in validation_module._PRODUCTION_BROWSER_REPORTS.items():
        (tmp_path / gate_id.lower() / relative).write_text(
            json.dumps(
                {
                    "schema_version": schema,
                    "production_browser_interaction": True,
                    "demo_mode": False,
                }
            ),
            encoding="utf-8",
        )
    monkeypatch.setattr(
        validation_module, "validate_install_gate_reports", lambda _root: ("a", "b")
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_detection_gate",
        lambda *_args: (
            {name: True for name in validation_module.DETECTION_CHECK_NAMES},
            _run_refs(1),
        ),
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_operator_ui_gate",
        lambda *_args: (
            {name: True for name in validation_module.OPERATOR_CHECK_NAMES},
            _run_refs(4),
        ),
    )
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_source_intake_gate",
        lambda *_args: (
            {name: True for name in validation_module.SOURCE_INTAKE_CHECK_NAMES},
            _run_refs(1),
        ),
    )

    report = validate_upstream_closure(tmp_path, tmp_path, binding)

    assert report["schema_version"] == UPSTREAM_SCHEMA
    assert report["passed"] is True
    assert len(report["gates"]) == 11
    assert [row["gate_id"] for row in report["production_playwright"]] == [
        "GATE-07",
        "GATE-08",
        "GATE-09",
    ]
    assert all(row["semantic_check_count"] > 0 for row in report["production_playwright"])

    gate05 = tmp_path / "gate-05" / "gate-receipt.json"
    original = json.loads(gate05.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(original)
    tampered["harness_assessment"]["postflight"] = {"unreviewed": True}
    gate05.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ReleaseReadinessValidationError, match="assessment"):
        validate_upstream_closure(tmp_path, tmp_path, binding)

    tampered = copy.deepcopy(original)
    tampered["proofs"][0]["test_id"] = "GATE-05.changed"
    gate05.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ReleaseReadinessValidationError, match="assessment"):
        validate_upstream_closure(tmp_path, tmp_path, binding)

    gate05.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_detection_gate",
        lambda *_args: ({name: False for name in validation_module.DETECTION_CHECK_NAMES}, ()),
    )
    with pytest.raises(ReleaseReadinessValidationError, match="independently revalidate"):
        validate_upstream_closure(tmp_path, tmp_path, binding)


def test_release_structure_binds_commit_tree_docs_versions_and_rights(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for relative, tokens in validation_module._REQUIRED_DOCS.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(tokens), encoding="utf-8")
    (tmp_path / "frontend").mkdir(exist_ok=True)
    (tmp_path / "frontend/package.json").write_text(
        json.dumps({"version": "0.1.0"}), encoding="utf-8"
    )
    (tmp_path / "runner").mkdir()
    (tmp_path / "runner/Cargo.toml").write_text('[package]\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "bluefire").mkdir()
    (tmp_path / "bluefire/version.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    rights = SimpleNamespace(
        to_dict=lambda: {
            "decision": "retain-mit",
            "project_license": "MIT",
            "unresolved_items": [],
        }
    )
    monkeypatch.setattr(validation_module, "run_release_rights_audit", lambda _root: rights)

    def fake_git(_root: Path, *arguments: str) -> str:
        return {
            ("rev-parse", "HEAD"): "2" * 40,
            ("rev-parse", "HEAD^{tree}"): "3" * 40,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
        }[arguments]

    monkeypatch.setattr(validation_module, "_git", fake_git)

    report = audit_release_structure(tmp_path, _binding())

    assert report["schema_version"] == STRUCTURAL_SCHEMA
    assert report["passed"] is True
    assert all(report["checks"].values())


def test_opsec_report_scans_tracked_tree_and_decoded_sbom_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "module.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sbom = evidence / validation_module.SBOM_REPORT
    sbom.write_text(json.dumps({"components": [{"name": "safe"}]}), encoding="utf-8")
    monkeypatch.setattr(gate_module, "_tracked_files", lambda _root: ["module.py"])
    suites = {
        "suites": [
            {"suite_id": f"security.{name}", "passed": True}
            for name in ("gitleaks", "detect-secrets", "bandit", "pip-audit")
        ]
    }

    report = gate_module._opsec_report(tmp_path, evidence, suites)
    assert validate_opsec_report(report)

    private_path = "C:" + "/" + "Users/" + "private/installed-package"
    sbom.write_text(json.dumps({"components": [{"path": private_path}]}), encoding="utf-8")
    assert gate_module._opsec_report(tmp_path, evidence, suites)["passed"] is False


def test_production_suite_rows_bind_explicit_playwright_specs() -> None:
    upstream = {"production_playwright": _production_upstream()}
    journey = {"production_playwright_specs": ["frontend/tests/e2e/operator-production.spec.ts"]}

    rows = _production_rows(upstream, journey)

    assert len(rows) == 3
    assert all(row["passed"] and row["test_count"] == 1 for row in rows)
    assert {row["details"]["evidence_source"] for row in rows} == {
        "fresh-gate12-journey",
        "same-acceptance-upstream-gate",
    }

    upstream["production_playwright"][0]["semantic_check_count"] = 0
    rows = _production_rows(upstream, journey)
    assert not next(row for row in rows if row["suite_id"] == "frontend.production-detection")[
        "passed"
    ]


def test_final_revalidation_compares_every_persisted_decision_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream = {
        "schema_version": UPSTREAM_SCHEMA,
        "passed": True,
        "clean_package_install": {"validated_reports": True},
        "production_playwright": _production_upstream(),
    }
    structural = {"schema_version": STRUCTURAL_SCHEMA, "passed": True, "checks": {}}
    suites = _suite_report()
    opsec = _opsec_report()
    journey_checks = {"sanitized_screenshots": True, "frontier_compare_artifact": True}
    bundles = _run_refs(7)
    for relative, value in (
        (validation_module.UPSTREAM_REPORT, upstream),
        (validation_module.STRUCTURAL_REPORT, structural),
        (validation_module.SUITE_REPORT, suites),
        (validation_module.OPSEC_REPORT, opsec),
    ):
        (tmp_path / relative).write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(gate_module, "validate_upstream_closure", lambda *_args: upstream)
    monkeypatch.setattr(gate_module, "audit_release_structure", lambda *_args: structural)
    monkeypatch.setattr(
        gate_module,
        "validate_release_journey",
        lambda *_args: (journey_checks, bundles),
    )
    monkeypatch.setattr(
        gate_module,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: ({**raw}, {}),
    )
    monkeypatch.setattr(gate_module, "_opsec_report", lambda *_args: opsec)
    expected_hashes = {"gate12-full-suite.json": "sha256:" + "6" * 64}
    monkeypatch.setattr(gate_module, "persisted_artifact_hashes", lambda _root: expected_hashes)
    started = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)

    assert (
        gate_module._revalidate_persisted_evidence(
            tmp_path,
            tmp_path,
            _binding(),
            upstream=upstream,
            structural=structural,
            suites=suites,
            opsec=opsec,
            journey_checks=journey_checks,
            bundles=bundles,
            journey_started=started,
            journey_finished=started + timedelta(seconds=1),
        )
        == expected_hashes
    )

    changed = copy.deepcopy(suites)
    changed["passed"] = False
    (tmp_path / validation_module.SUITE_REPORT).write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="full-suite report changed"):
        gate_module._revalidate_persisted_evidence(
            tmp_path,
            tmp_path,
            _binding(),
            upstream=upstream,
            structural=structural,
            suites=suites,
            opsec=opsec,
            journey_checks=journey_checks,
            bundles=bundles,
            journey_started=started,
            journey_finished=started + timedelta(seconds=1),
        )


def _patch_passing_gate(
    monkeypatch: pytest.MonkeyPatch,
    destination: Path,
) -> tuple[dict[str, Any], tuple[dict[str, str], ...]]:
    binding = _binding()
    structural = {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": True,
        "checks": {
            "readme_product_loop": True,
            "capability_classification": True,
            "complete_docs": True,
            "github_metadata": True,
            "clean_worktree": True,
            "rights_audit": True,
            "license_decision": True,
            "version_consistency": True,
        },
    }
    upstream = {
        "schema_version": UPSTREAM_SCHEMA,
        "passed": True,
        "clean_package_install": {"validated_reports": True},
        "production_playwright": [],
    }
    bundles = _run_refs(7)
    journey = {"production_playwright_specs": ["frontend/tests/e2e/operator-production.spec.ts"]}
    monkeypatch.setattr(gate_module, "_acceptance_binding", lambda: binding)
    monkeypatch.setattr(gate_module, "validate_upstream_closure", lambda *_args: upstream)
    monkeypatch.setattr(gate_module, "audit_release_structure", lambda *_args: structural)
    monkeypatch.setattr(
        gate_module,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "{helper}"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(
        gate_module,
        "validate_release_journey",
        lambda *_args: (
            {"sanitized_screenshots": True, "frontier_compare_artifact": True},
            bundles,
        ),
    )
    monkeypatch.setattr(
        gate_module,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: ({**raw, "manifest_sha256": "sha256:" + "5" * 64}, {}),
    )
    monkeypatch.setattr(gate_module, "read_json", lambda *_args: journey)
    monkeypatch.setattr(
        gate_module, "run_full_release_suites", lambda *_args, **_kwargs: _suite_report()
    )
    monkeypatch.setattr(gate_module, "_opsec_report", lambda *_args: _opsec_report())
    monkeypatch.setattr(
        gate_module,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"schema_version": "bluefire.architecture-dynamic-check.v1"},
    )
    monkeypatch.setattr(gate_module, "exact_contract_suite", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        gate_module,
        "_revalidate_persisted_evidence",
        lambda *_args, **_kwargs: {"gate12-full-suite.json": "sha256:" + "6" * 64},
    )
    monkeypatch.setattr(gate_module, "validate_verification_report", lambda *_args, **_kwargs: {})
    return structural, bundles


def test_gate12_emits_unique_proofs_only_after_all_checks_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _structural, bundles = _patch_passing_gate(monkeypatch, tmp_path)

    outcome = gate_module.run_gate_12(_gate(), tmp_path, repository_root=tmp_path)

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 12
    assert len({proof["test_id"] for proof in outcome.proofs}) == 12
    assert {proof["assertion_ids"][0] for proof in outcome.proofs} == set(
        gate_module._EXPECTED_ASSERTIONS
    )
    run_bound = [proof for proof in outcome.proofs if proof["run_ids"]]
    assert len(run_bound) == 2
    assert all(len(proof["run_ids"]) == len(bundles) == 7 for proof in run_bound)


def test_gate12_refuses_stale_evidence_and_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe = tmp_path / "evidence-file"
    unsafe.write_text("not a directory", encoding="utf-8")
    outcome = gate_module.run_gate_12(_gate(), unsafe, repository_root=tmp_path)
    assert outcome.status == "failed"
    assert "regular directory" in str(outcome.failure_reason)

    (tmp_path / validation_module.VERIFICATION_REPORT).write_text("{}", encoding="utf-8")
    outcome = gate_module.run_gate_12(_gate(), tmp_path, repository_root=tmp_path)
    assert outcome.status == "failed"
    assert "stale" in str(outcome.failure_reason)

    (tmp_path / validation_module.VERIFICATION_REPORT).unlink()
    drifted = SimpleNamespace(assertions=())
    outcome = gate_module.run_gate_12(drifted, tmp_path, repository_root=tmp_path)
    assert outcome.status == "failed"
    assert "assertion set mismatch" in str(outcome.failure_reason)


def test_gate12_fails_closed_when_the_focused_suite_is_not_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_passing_gate(monkeypatch, tmp_path)
    monkeypatch.setattr(gate_module, "exact_contract_suite", lambda *_args, **_kwargs: False)

    outcome = gate_module.run_gate_12(_gate(), tmp_path, repository_root=tmp_path)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "focused contract suite" in str(outcome.failure_reason)


def test_gate12_refuses_evidence_changed_after_the_last_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_passing_gate(monkeypatch, tmp_path)

    def changed(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        raise ValueError("persisted full-suite report changed after validation")

    monkeypatch.setattr(gate_module, "_revalidate_persisted_evidence", changed)

    outcome = gate_module.run_gate_12(_gate(), tmp_path, repository_root=tmp_path)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "changed after validation" in str(outcome.failure_reason)


def test_gate12_production_modules_stay_within_architecture_budget() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "bluefire/release_readiness_gate.py",
        root / "bluefire/release_readiness_artifacts.py",
        root / "bluefire/release_readiness_journey.py",
        root / "bluefire/release_readiness_suites.py",
        root / "bluefire/release_readiness_validation.py",
        root / "tools/run_release_readiness_gate_journey.py",
    ]

    assert all(path.is_file() for path in paths)
    assert all(len(path.read_text(encoding="utf-8").splitlines()) <= 1_000 for path in paths)
