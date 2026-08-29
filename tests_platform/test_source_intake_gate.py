from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import bluefire.source_intake_gate as source_intake_gate
import bluefire.source_intake_journey as source_intake_journey
import tools.run_source_intake_gate_journey as journey_helper
from bluefire.contracts import ScenarioDefinition
from bluefire.product_acceptance import load_release_contract
from bluefire.source_intake import perform_source_intake
from bluefire.source_intake_gate_validation import (
    CHECK_NAMES,
    SourceIntakeGateValidationError,
    _expected_scenario,
    _validate_browser,
    _validate_registry,
    _validate_safety,
)
from bluefire.source_intake_journey import (
    BROWSER_INTAKE_ARTIFACT,
    BROWSER_INTAKE_DESTINATION_ID,
    BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    BROWSER_OPERATION_SEQUENCE,
    BROWSER_SCHEMA,
    HELPER_SCHEMA,
    INTAKE_ARTIFACT,
    PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
    PRODUCT_DB_ARTIFACT,
    REPORT_PATHS,
    SAFETY_SCHEMA,
)
from bluefire.source_intake_package import (
    ACTION_ID,
    BEHAVIOR_ID,
    INTAKE_ID,
    KEY_ID,
    LICENSE_ASSET,
    LICENSE_ID,
    PACKAGE_ID,
    PACKAGE_VERSION,
    PUBLISHER_ID,
    SOURCE_ASSET,
    SOURCE_COMMIT,
    SOURCE_ID,
    gate09_intake_request,
)
from bluefire.source_intake_receipt_validation import OPERATION_RECEIPT_SCHEMA
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]


def _gate() -> Any:
    return next(gate for gate in load_release_contract().gates if gate.gate_id == "GATE-09")


def test_gate09_helper_uses_the_internal_research_resource_kind() -> None:
    class RecordingService:
        def resources(self, kind: str) -> Mapping[str, Any]:
            assert kind == "research_source"
            return {
                "resources": [{"id": SOURCE_ID, "status": "pinned", "document": {"id": SOURCE_ID}}]
            }

    assert source_intake_journey._research_source(RecordingService()) == {"id": SOURCE_ID}


def test_gate09_validator_expects_the_canonical_persisted_scenario() -> None:
    record_sha256 = "sha256:" + "1" * 64

    canonical = ScenarioDefinition.from_mapping(
        source_intake_journey._scenario(record_sha256)
    ).to_dict()

    assert _expected_scenario(record_sha256) == canonical


def _browser_report(
    record_sha256: str,
    profile_id: str,
    operation_receipt_sha256: str,
) -> dict[str, Any]:
    provenance_reference = (
        f"urn:bluefire:source-intake:{INTAKE_ID}:sha256:{record_sha256.removeprefix('sha256:')}"
    )
    return {
        "schema_version": BROWSER_SCHEMA,
        "production_browser_interaction": True,
        "demo_mode": False,
        "origin": "http://127.0.0.1:43179",
        "source_id": SOURCE_ID,
        "source_project": "mitre/cti",
        "source_version": "19.2",
        "source_pin": SOURCE_COMMIT,
        "source_license": LICENSE_ID,
        "source_classification": "metadata_import",
        "source_content_handling": "vendored_declarative",
        "imported_paths": [
            f"bluefire/data/{SOURCE_ASSET}",
            f"bluefire/data/{LICENSE_ASSET}",
        ],
        "attribution_visible": True,
        "transformation_visible": True,
        "behavior_id": BEHAVIOR_ID,
        "technique_id": "T1082",
        "action_id": ACTION_ID,
        "activation_operation": "already_active_revalidated",
        "behavior_provenance_reference": provenance_reference,
        "behavior_provenance_visible": True,
        "execution_state": "action",
        "intake_destination_id": BROWSER_INTAKE_DESTINATION_ID,
        "intake_record_sha256": record_sha256,
        "intake_state_ref": (f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"),
        "operation_receipt_visible": True,
        "operation_receipt_sha256": operation_receipt_sha256,
        "operation_receipt_state_ref": (
            f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.operation-receipt.json"
        ),
        "operation_sequence": list(BROWSER_OPERATION_SEQUENCE),
        "runner_profile_id": profile_id,
        "observed_at": "2026-08-29T12:00:00Z",
    }


def _safety_report() -> dict[str, Any]:
    return {
        "schema_version": SAFETY_SCHEMA,
        "passed": True,
        "refused_without_output": {
            "source_digest_mismatch": True,
            "unknown_transformer": True,
            "executable_materialization_field": True,
            "multi_object_bundle": True,
        },
        "trusted_transformer": {
            "name": "mitre-attack-technique-v1",
            "version": "1.0.0",
            "runtime_discovery": False,
        },
        "external_content_executed": False,
        "network_intake": False,
    }


def _passing_gate_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Mapping[str, bool], tuple[Mapping[str, str], ...]]:
    checks = {name: True for name in CHECK_NAMES}
    bundle = {
        "run_id": "run-20260829T120000Z-0123456789abcdef",
        "path": "runs/run-20260829T120000Z-0123456789abcdef",
    }
    bundles = (bundle,)
    monkeypatch.setattr(
        source_intake_gate,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "tools/run_source_intake_gate_journey.py"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(
        source_intake_gate,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"passed": True, "suite_id": "source-intake-contracts"},
    )
    monkeypatch.setattr(source_intake_gate, "_suite_is_exact", lambda _value: True)
    monkeypatch.setattr(
        source_intake_gate,
        "validate_persisted_source_intake_gate",
        lambda *_args, **_kwargs: (checks, bundles),
    )
    monkeypatch.setattr(
        source_intake_gate,
        "_acceptance_binding",
        lambda: {"gate_id": "GATE-09"},
    )
    monkeypatch.setattr(
        source_intake_gate,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: (dict(raw), {}),
    )
    return checks, bundles


def test_gate09_locked_contract_matches_authoritative_workflow() -> None:
    contract = {assertion.assertion_id: assertion.proof for assertion in _gate().assertions}
    expected = {
        assertion_id: row[0]
        for assertion_id, row in source_intake_gate._EXPECTED_ASSERTIONS.items()
    }

    assert contract == expected
    assert len(contract) == 8
    assert set(contract.values()) == {"dynamic", "structural"}
    assert len({row[3] for row in source_intake_gate._EXPECTED_ASSERTIONS.values()}) == 8


def test_builtin_source_registry_is_exactly_pinned_and_reviewed() -> None:
    source = _validate_registry(ROOT)

    assert source["id"] == SOURCE_ID
    assert source["pin"] == SOURCE_COMMIT
    assert source["license"] == LICENSE_ID
    assert source["use_classification"] == "metadata_import"
    assert source["imported_paths"] == [
        f"bluefire/data/{SOURCE_ASSET}",
        f"bluefire/data/{LICENSE_ASSET}",
    ]


def test_gate09_asset_verification_refuses_replaced_oversize_before_read(
    tmp_path: Path,
) -> None:
    source = tmp_path / "reviewed-source.json"
    with source.open("wb") as handle:
        handle.truncate(1024 * 1024)

    with pytest.raises(source_intake_journey.SourceIntakeJourneyError, match="unavailable"):
        source_intake_journey._verified_file(source, 64, "sha256:" + "0" * 64)


def test_gate09_database_artifact_has_a_hard_64_mib_read_bound(tmp_path: Path) -> None:
    database = tmp_path / "bluefire-product.sqlite3"
    with database.open("wb") as handle:
        handle.truncate(source_intake_journey._MAX_DATABASE_BYTES + 1)

    with pytest.raises(source_intake_journey.SourceIntakeJourneyError, match="unbounded"):
        source_intake_journey._database_artifact(tmp_path)


def test_gate09_report_collision_never_deletes_the_racing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "gate09-report.json"
    original_open = source_intake_journey.os.open

    def collide(path: Path, flags: int, mode: int) -> int:
        if Path(path) == report:
            report.write_bytes(b"operator-owned")
        return original_open(path, flags, mode)

    monkeypatch.setattr(source_intake_journey.os, "open", collide)
    with pytest.raises(
        source_intake_journey.SourceIntakeJourneyError, match="could not be written"
    ):
        source_intake_journey._write_json(report, {"status": "passed"})

    assert report.read_bytes() == b"operator-owned"


def test_safety_report_requires_all_fail_closed_refusals() -> None:
    report = _safety_report()
    _validate_safety(report)

    tampered = copy.deepcopy(report)
    tampered["refused_without_output"]["unknown_transformer"] = False
    with pytest.raises(SourceIntakeGateValidationError, match="refusal"):
        _validate_safety(tampered)


def test_browser_report_requires_real_ui_provenance_and_exact_sequence(
    tmp_path: Path,
) -> None:
    transform = tmp_path / "transform"
    transform.mkdir()
    intake = perform_source_intake(
        (ROOT / "bluefire" / "data").resolve(),
        transform.resolve(),
        gate09_intake_request(),
    ).envelope
    evidence = tmp_path / "evidence"
    artifact = (
        evidence / "runs" / "source-intakes" / BROWSER_INTAKE_DESTINATION_ID / f"{INTAKE_ID}.json"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(canonical_json_bytes(intake))
    profile_id = "execute.windows-reviewed.v1"
    package = {
        "package_digest": "sha256:" + "1" * 64,
        "content_digest": "sha256:" + "2" * 64,
    }
    catalog = {"generation": 7, "catalog_digest": "sha256:" + "3" * 64}
    receipt = {
        "schema_version": OPERATION_RECEIPT_SCHEMA,
        "destination_id": BROWSER_INTAKE_DESTINATION_ID,
        "operator_id": "gate-09-browser-reviewer",
        "runner_profile_id": profile_id,
        "intake": {
            "intake_id": INTAKE_ID,
            "record_sha256": intake["record_sha256"],
            "output_sha256": content_hash(intake["record"]["output"]),
        },
        "artifact": {
            "state_ref": (f"source-intakes/{BROWSER_INTAKE_DESTINATION_ID}/{INTAKE_ID}.json"),
            "sha256": content_hash(intake),
            "size_bytes": len(canonical_json_bytes(intake)),
        },
        "package": {
            "package_id": PACKAGE_ID,
            "version": PACKAGE_VERSION,
            **package,
        },
        "activation": {
            "operation": "already_active_revalidated",
            "catalog_generation": catalog["generation"],
            "catalog_digest": catalog["catalog_digest"],
        },
        "completed_at": "2026-08-29T11:59:59Z",
    }
    receipt_path = evidence / BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    report = _browser_report(str(intake["record_sha256"]), profile_id, content_hash(receipt))
    _validate_browser(evidence, report, intake, profile_id, package, catalog)

    tampered = copy.deepcopy(report)
    tampered["source_pin"] = "0" * 40
    with pytest.raises(SourceIntakeGateValidationError, match="browser provenance"):
        _validate_browser(evidence, tampered, intake, profile_id, package, catalog)


def test_source_intake_suite_inventory_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    passed_tests = sorted(
        test.removesuffix(".py").replace("/", ".").replace("\\", ".") + "::test_bound"
        for test in source_intake_gate._CONTRACT_TESTS
    )
    monkeypatch.setattr(source_intake_gate, "_EXPECTED_CONTRACT_TEST_COUNT", len(passed_tests))
    monkeypatch.setattr(
        source_intake_gate,
        "_EXPECTED_CONTRACT_TESTS_SHA256",
        content_hash(passed_tests),
    )
    suite = {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": "source-intake-contracts",
        "command": [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *source_intake_gate._CONTRACT_TESTS,
            "--junitxml={temporary}",
        ],
        "exit_code": 0,
        "passed": True,
        "tests": len(passed_tests),
        "passed_tests": passed_tests,
        "failed_tests": [],
        "skipped_tests": [],
    }

    assert source_intake_gate._suite_is_exact(suite) is True
    suite["passed_tests"] = [*passed_tests[:-1], "tests_platform.unrelated::test_bound"]
    assert source_intake_gate._suite_is_exact(suite) is False


def test_gate09_emits_one_exact_proof_per_assertion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _checks, bundles = _passing_gate_dependencies(monkeypatch)

    outcome = source_intake_gate.run_gate_09(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 8
    assert len({proof["test_id"] for proof in outcome.proofs}) == 8
    assert {proof["kind"] for proof in outcome.proofs} == {"dynamic", "structural"}
    assert all(
        len(proof["assertion_ids"]) == 1
        and proof["run_ids"] == [bundles[0]["run_id"]]
        and proof["run_bundles"] == list(bundles)
        and proof["environment_limitations"] == []
        for proof in outcome.proofs
    )
    assert (evidence / source_intake_gate.VERIFICATION_REPORT).is_file()


def test_gate09_fails_closed_for_contract_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setattr(
        source_intake_gate,
        "_run_helper",
        lambda *_args: pytest.fail("helper must not run for a mismatched contract"),
    )

    outcome = source_intake_gate.run_gate_09(
        SimpleNamespace(assertions=()), evidence, repository_root=ROOT
    )

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "assertion set mismatch" in str(outcome.failure_reason)


def test_gate09_refuses_stale_owned_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "intake").mkdir()
    monkeypatch.setattr(
        source_intake_gate,
        "_run_helper",
        lambda *_args: pytest.fail("helper must not run with stale evidence"),
    )

    outcome = source_intake_gate.run_gate_09(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "failed"
    assert "stale owned artifacts" in str(outcome.failure_reason)


def test_gate09_rejects_incomplete_semantic_check_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    checks, bundles = _passing_gate_dependencies(monkeypatch)
    incomplete = dict(checks)
    incomplete.pop("safe_intake")
    monkeypatch.setattr(
        source_intake_gate,
        "validate_persisted_source_intake_gate",
        lambda *_args, **_kwargs: (incomplete, bundles),
    )

    outcome = source_intake_gate.run_gate_09(_gate(), evidence, repository_root=ROOT)

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "semantic check inventory" in str(outcome.failure_reason)


def test_gate09_failure_redacts_private_paths() -> None:
    outcome = source_intake_gate._failure((r"C:\private\operator\intake.json failed",))

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "C:\\private" not in str(outcome.failure_reason)
    assert "private-path-redacted" in str(outcome.failure_reason)


def test_fixed_helper_requires_every_persisted_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    def produce(_repository: Path, destination: Path) -> Mapping[str, object]:
        for relative in (
            *REPORT_PATHS,
            PRODUCT_DB_ARTIFACT,
            INTAKE_ARTIFACT,
            BROWSER_INTAKE_ARTIFACT,
            PRIMARY_INTAKE_OPERATION_RECEIPT_ARTIFACT,
            BROWSER_INTAKE_OPERATION_RECEIPT_ARTIFACT,
        ):
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"evidence")
        return {
            "schema_version": HELPER_SCHEMA,
            "status": "passed",
            "reports": list(REPORT_PATHS),
            "run_count": 1,
            "blocking_check": None,
        }

    monkeypatch.setattr(journey_helper, "produce_source_intake_gate_evidence", produce)
    summary = journey_helper.run_source_intake_gate_journey(ROOT, evidence)

    assert summary["status"] == "passed"
    (evidence / INTAKE_ARTIFACT).unlink()
    monkeypatch.setattr(
        journey_helper,
        "produce_source_intake_gate_evidence",
        lambda *_args: summary,
    )
    with pytest.raises(journey_helper.SourceIntakeJourneyError, match="omitted"):
        journey_helper.run_source_intake_gate_journey(ROOT, evidence)


def test_gate09_is_registered_in_static_dispatcher() -> None:
    import bluefire.product_gates as product_gates

    assert product_gates._WORKFLOWS["GATE-09"] is not None
    assert PACKAGE_ID == "bluefire-research.attack-system-information"
    assert PACKAGE_VERSION == "19.2.0"
    assert PUBLISHER_ID == "bluefire.source-intake"
    assert KEY_ID == "local-reviewed-t1082-v1"
