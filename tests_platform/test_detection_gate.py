from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Mapping

import pytest

import bluefire.detection_gate as detection_gate
import bluefire.detection_journey as detection_journey
import bluefire.product_gates as product_gates
from bluefire.detection_gate_management import _identity
from bluefire.detection_gate_validation import (
    CHECK_NAMES,
    DetectionGateValidationError,
    _browser_check,
    _candidate_inventory,
    _management_check,
    _notes_and_baseline,
    _query_execution,
    _run_evidence,
    _sha256_text,
    _yara_execution,
)
from bluefire.detection_journey import (
    BROWSER_OPERATION_SEQUENCE,
    BROWSER_SCHEMA,
    CANDIDATE_SCHEMA,
    HELPER_SCHEMA,
    REPORT_PATHS,
    SQLITE_SOURCE,
    YARA_SOURCE,
)
from bluefire.detections import DetectionCandidate
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_acceptance import load_release_contract
from bluefire.research import load_builtin_research_registry
from bluefire.run_store import RunStore
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]


def _candidate_document(response: Mapping[str, Any]) -> Mapping[str, Any]:
    resource = response["candidate"]
    assert isinstance(resource, Mapping)
    document = resource["document"]
    assert isinstance(document, Mapping)
    return document


def _hypothesis(language: str, title: str, marker: str) -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="sandbox.collection.stage.v1",
        title=title,
        target_language=language,
        logsource={"category": "file_event", "product": "generic"},
        selection={"artifact_type": "file_observation", "path|contains": marker},
        provenance={"source": "gate-07-test", "license": "Apache-2.0"},
    )


def _candidate_report() -> tuple[dict[str, Any], Mapping[str, DetectionCandidate]]:
    candidates = {
        "sigma": _hypothesis("sigma", "Sigma", "sigma/"),
        "yara": _hypothesis("yara", "YARA", "yara/"),
        "sqlite": _hypothesis("sqlite", "SQLite", "sqlite/"),
        "clone": _hypothesis("internal", "Clone", "clone/"),
        "rejected": _hypothesis("internal", "Rejected", "rejected/"),
        "browser": _hypothesis("sqlite", "Browser", "browser/"),
    }
    documents = {role: candidate.to_dict() for role, candidate in candidates.items()}
    comparison = {"schema_version": "test", "comparison_id": "test-comparison"}
    payload = {"candidates": documents, "comparison": comparison}
    return (
        {
            "schema_version": CANDIDATE_SCHEMA,
            "passed": True,
            **payload,
            "listed_candidate_ids": sorted(
                candidate.candidate_id for candidate in candidates.values()
            ),
            "snapshot_digest": content_hash(payload),
        },
        candidates,
    )


@pytest.fixture
def sqlite_browser_candidate(tmp_path: Path) -> Iterator[DetectionCandidate]:
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        created = _candidate_document(
            service.upsert_detection_hypothesis(
                {
                    "behavior_id": "sandbox.collection.stage.v1",
                    "title": "Gate 07 browser schema test",
                    "target_language": "sqlite",
                    "logsource": {"category": "file_event", "product": "generic"},
                    "selection": {
                        "artifact_type": "file_observation",
                        "path|contains": "staged/",
                    },
                    "provenance": {"source": "gate-07-test", "license": "Apache-2.0"},
                    "predicted_fields": ["artifact_type", "path"],
                }
            )
        )
        candidate_id = str(created["candidate_id"])
        service.parse_detection_candidate(
            candidate_id,
            {
                "source": (
                    "SELECT * FROM logs WHERE artifact_type = 'file_observation' "
                    "AND path LIKE '%staged/%'"
                )
            },
        )
        exercised = _candidate_document(
            service.exercise_detection_fixtures(
                candidate_id,
                {
                    "fixtures": [
                        {
                            "fixture_id": "gate07-browser-0123456789abcdef",
                            "artifact_type": "file_observation",
                            "path": "staged/browser-proof.txt",
                        }
                    ]
                },
            )
        )
        yield DetectionCandidate.from_mapping(exercised)
    finally:
        service.close()


def _browser_report(candidate: DetectionCandidate) -> dict[str, Any]:
    validation = candidate.validation
    fixture_ids = list(candidate.malicious_fixture_ids)
    return {
        "schema_version": BROWSER_SCHEMA,
        "production_browser_interaction": True,
        "demo_mode": False,
        "origin": "http://127.0.0.1:43177",
        "candidate_id": candidate.candidate_id,
        "visible_state": candidate.state.value,
        "query_digest": validation["query_sha256"],
        "backend": {
            "parser": candidate.parser_backend["name"],
            "parser_version": candidate.parser_backend["version"],
            "execution": validation["execution_backend"],
            "execution_version": validation["execution_backend_version"],
        },
        "evaluated_fixture_ids": fixture_ids,
        "matched_fixture_ids": fixture_ids,
        "operation_sequence": list(BROWSER_OPERATION_SEQUENCE),
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _benign_sqlite_candidate(tmp_path: Path) -> tuple[DetectionCandidate, EvidenceRecord]:
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        handle = service.store.create_run(scenario={}, plan={}, policy={}, profile={})
        record = EvidenceRecord.create(
            run_id=handle.run_id,
            step_id="stage",
            behavior_id="sandbox.collection.stage.v1",
            action_id="sandbox.collection.stage.v1",
            provenance=EvidenceProvenance.OBSERVED,
            producer="gate-07-test",
            runner_profile_id="profile.test",
            environment={"environment_type": "disposable"},
            content={
                "artifact_type": "file_observation",
                "path": "staged/observed.txt",
                "host.name": "test-host",
            },
            target_scope_ref="runner-profile:profile.test",
        )
        service.store.finalize(
            handle.run_id,
            result={"schema_version": "test", "status": "completed"},
            evidence=[record.to_dict()],
            detections=[],
        )
        created = _candidate_document(
            service.upsert_detection_hypothesis(
                {
                    "behavior_id": "sandbox.collection.stage.v1",
                    "title": "Gate 07 fresh field mapping test",
                    "target_language": "sqlite",
                    "logsource": {"category": "file_event", "product": "generic"},
                    "selection": {
                        "artifact_type": "file_observation",
                        "path|contains": "staged/",
                    },
                    "provenance": {"source": "gate-07-test", "license": "Apache-2.0"},
                    "predicted_fields": ["artifact_type", "path"],
                }
            )
        )
        candidate_id = str(created["candidate_id"])
        service.parse_detection_candidate(candidate_id, {"source": SQLITE_SOURCE})
        service.exercise_detection_fixtures(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "sqlite-malicious",
                        "artifact_type": "file_observation",
                        "path": "staged/malicious.txt",
                    }
                ]
            },
        )
        service.exercise_detection_observed(
            candidate_id,
            {"run_id": handle.run_id, "evidence_ids": [record.evidence_id]},
        )
        evaluated = _candidate_document(
            service.evaluate_detection_benign(
                candidate_id,
                {
                    "fixtures": [
                        {
                            "fixture_id": "sqlite-benign",
                            "artifact_type": "file_observation",
                            "path": "documents/benign.txt",
                            "unmodeled_signal": "reported",
                        }
                    ],
                    "notes": ["Reviewed benign fixture did not match."],
                },
            )
        )
        return DetectionCandidate.from_mapping(evaluated), record
    finally:
        service.close()


def _registered_baseline() -> Mapping[str, str]:
    source = load_builtin_research_registry().get("research.atomic-red-team.v1")
    return {
        "schema_version": "bluefire.public-baseline.v2",
        "research_source_id": source.id,
        "source_digest": content_hash(source.to_dict()),
        "pin": source.pin,
        "version": source.version,
        "exact_ref": source.exact_ref,
        "retrieved_at": source.retrieved_at,
        "license": source.license,
        "file_level_license_review": source.file_level_license_review,
        "trademark_considerations": source.trademark_considerations,
        "license_review": source.license_review.value,
        "relationship": source.relationship.value,
        "use_classification": source.use_classification.value,
        "use": "comparison",
        "attribution": source.attribution,
        "security_review": source.security_review,
        "last_verified_at": source.last_verified_at,
        "update_status": source.update_status,
    }


def test_detection_gate_workflow_is_registered() -> None:
    assert product_gates._WORKFLOWS["GATE-07"] is product_gates._gate_07_workflow


def test_detection_contract_suite_is_bound_to_exact_passed_node_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodes = sorted(
        test.removesuffix(".py").replace("/", ".") + "::test_inventory_binding"
        for test in detection_gate._CONTRACT_TESTS
    )
    monkeypatch.setattr(detection_gate, "_EXPECTED_CONTRACT_TEST_COUNT", len(nodes))
    monkeypatch.setattr(
        detection_gate,
        "_EXPECTED_CONTRACT_TESTS_SHA256",
        content_hash(nodes),
    )
    report = {
        "schema_version": "bluefire.architecture-dynamic-check.v1",
        "suite_id": "authoritative-detection-contracts",
        "command": [
            "{python}",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            *detection_gate._CONTRACT_TESTS,
            "--junitxml={temporary}",
        ],
        "exit_code": 0,
        "passed": True,
        "tests": len(nodes),
        "passed_tests": nodes,
        "failed_tests": [],
        "skipped_tests": [],
    }
    assert detection_gate._suite_is_exact(report) is True

    report["passed_tests"] = nodes[:-1]
    report["tests"] = len(nodes) - 1
    assert detection_gate._suite_is_exact(report) is False


def test_candidate_report_rehydrates_every_document_and_refuses_tampering() -> None:
    report, expected = _candidate_report()
    observed, comparison = _candidate_inventory(report)

    assert observed == expected
    assert comparison["comparison_id"] == "test-comparison"

    tampered = copy.deepcopy(report)
    tampered["candidates"]["sigma"]["title"] = "Rewritten after publication"
    tampered_payload = {
        "candidates": tampered["candidates"],
        "comparison": tampered["comparison"],
    }
    tampered["snapshot_digest"] = content_hash(tampered_payload)
    with pytest.raises(DetectionGateValidationError, match="rehydration"):
        _candidate_inventory(tampered)


def test_browser_report_is_bound_to_reexecuted_persisted_sqlite_candidate(
    sqlite_browser_candidate: DetectionCandidate,
) -> None:
    report = _browser_report(sqlite_browser_candidate)

    assert _browser_check(report, sqlite_browser_candidate) is True

    report["query_digest"] = "sha256:" + "0" * 64
    assert _browser_check(report, sqlite_browser_candidate) is False


def test_browser_report_rejects_extra_or_partial_claim_fields(
    sqlite_browser_candidate: DetectionCandidate,
) -> None:
    report = _browser_report(sqlite_browser_candidate)
    report["screenshot"] = "not-permitted"

    with pytest.raises(DetectionGateValidationError, match="fields"):
        _browser_check(report, sqlite_browser_candidate)


def test_browser_report_refuses_an_incomplete_lifecycle(
    sqlite_browser_candidate: DetectionCandidate,
) -> None:
    report = _browser_report(sqlite_browser_candidate)
    incomplete = replace(sqlite_browser_candidate, lifecycle_history=())

    with pytest.raises(DetectionGateValidationError, match="lifecycle"):
        _browser_check(report, incomplete)


def test_query_validation_refuses_persisted_field_mapping_tampering(tmp_path: Path) -> None:
    candidate, observed = _benign_sqlite_candidate(tmp_path)
    assert _query_execution(candidate, observed)[3]["mapped_fields"] == [
        "artifact_type",
        "path",
    ]

    mutations = {
        "mapped_fields": ["path"],
        "field_mapping": {"path": "path"},
        "unsupported_fields": ["fabricated_field"],
    }
    for field, value in mutations.items():
        document = copy.deepcopy(candidate.to_dict())
        document["validation"][field] = value
        tampered = DetectionCandidate.from_mapping(document)
        with pytest.raises(DetectionGateValidationError, match="metadata"):
            _query_execution(tampered, observed)


def test_notes_baseline_requires_the_exact_registered_enriched_v2_reference() -> None:
    candidate = replace(
        _hypothesis("sigma", "Baseline", "staged/"),
        false_positive_notes=("Reviewed benign fixture did not match.",),
        public_baselines=(_registered_baseline(),),
    )
    assert _notes_and_baseline(candidate) is True

    tampered = dict(_registered_baseline())
    tampered["security_review"] = "Producer-authored replacement."
    assert _notes_and_baseline(replace(candidate, public_baselines=(tampered,))) is False


def test_management_report_rejects_extra_nested_secret_or_path_fields(
    sqlite_browser_candidate: DetectionCandidate,
    tmp_path: Path,
) -> None:
    report = {
        "schema_version": "bluefire.detection-gate-management.v1",
        "passed": False,
        "shared_product_store": {},
        "service": {"operations": [], "candidate_ids": []},
        "api": {"private_path": str(tmp_path)},
        "cli": {},
        "ui": {},
        "browser_report": "gate07-browser-report.json",
    }
    with pytest.raises(DetectionGateValidationError, match="fields"):
        _management_check(
            ROOT,
            tmp_path,
            report,
            {},
            {"browser": sqlite_browser_candidate},
            {},
        )


def test_report_writer_does_not_unlink_a_raced_foreign_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "report.json"
    real_open = os.open
    real_write = os.write

    def raced_open(path: Path, *_args: Any, **_kwargs: Any) -> int:
        Path(path).write_text("foreign", encoding="utf-8")
        raise FileExistsError("raced")

    monkeypatch.setattr(detection_journey.os, "open", raced_open)
    with pytest.raises(FileExistsError):
        detection_journey._write_json(report, {"passed": True})
    assert report.read_text(encoding="utf-8") == "foreign"
    monkeypatch.setattr(detection_journey.os, "open", real_open)

    identity_probe = tmp_path / "identity-probe"
    identity_probe.write_bytes(b"gate07")
    with identity_probe.open("rb") as stream:
        assert _identity(identity_probe.stat(follow_symlinks=False)) == _identity(
            os.fstat(stream.fileno())
        )

    writes = 0

    def partial_then_fail(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(descriptor, payload[:5])
        raise OSError("forced partial write failure")

    monkeypatch.setattr(detection_journey.os, "write", partial_then_fail)
    partial_report = tmp_path / "partial-report.json"
    with pytest.raises(OSError, match="forced partial write failure"):
        detection_journey._write_json(partial_report, {"passed": True})
    assert partial_report.read_bytes() == b'{"pas'


def test_yara_validation_refuses_an_unreviewed_runtime_before_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = SimpleNamespace(
        target_language="yara",
        state=SimpleNamespace(value="benign_evaluated"),
        rule_source=YARA_SOURCE,
        parser_backend={"name": "YARA-Python", "version": "4.5.4"},
        validation={
            "backend": "YARA-Python",
            "version": "4.5.4",
            "compiled": True,
            "includes": False,
            "warnings_as_errors": True,
            "source_sha256": _sha256_text(YARA_SOURCE),
            "source_rule_executed": True,
            "executed_source_sha256": _sha256_text(YARA_SOURCE),
            "execution_backend": "YARA-Python",
            "execution_backend_version": "4.5.4",
        },
        malicious_fixture_ids=("yara-malicious",),
        benign_fixture_ids=("yara-benign",),
        malicious_fixtures=(
            {
                "fixture_id": "yara-malicious",
                "data": "prefix BLUEFIRE_GATE07_MALICIOUS_MARKER suffix",
            },
        ),
        benign_fixtures=({"fixture_id": "yara-benign", "data": "ordinary benign document"},),
    )
    monkeypatch.setattr(
        "bluefire.detection_gate_validation.metadata.version", lambda _name: "9.9.9"
    )

    with pytest.raises(DetectionGateValidationError, match="reviewed pin"):
        _yara_execution(candidate)


def test_yara_validation_binds_exact_bounded_fixture_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = SimpleNamespace(
        target_language="yara",
        state=SimpleNamespace(value="benign_evaluated"),
        rule_source=YARA_SOURCE,
        parser_backend={"name": "YARA-Python", "version": "4.5.4"},
        validation={
            "backend": "YARA-Python",
            "version": "4.5.4",
            "compiled": True,
            "includes": False,
            "warnings_as_errors": True,
            "source_sha256": _sha256_text(YARA_SOURCE),
            "source_rule_executed": True,
            "executed_source_sha256": _sha256_text(YARA_SOURCE),
            "execution_backend": "YARA-Python",
            "execution_backend_version": "4.5.4",
        },
        malicious_fixture_ids=("yara-malicious", "attacker-added"),
        benign_fixture_ids=("yara-benign",),
        malicious_fixtures=(
            {
                "fixture_id": "yara-malicious",
                "data": "prefix BLUEFIRE_GATE07_MALICIOUS_MARKER suffix",
            },
            {"fixture_id": "attacker-added", "data": "unbounded producer fixture"},
        ),
        benign_fixtures=({"fixture_id": "yara-benign", "data": "ordinary benign document"},),
    )
    monkeypatch.setattr(
        "bluefire.detection_gate_validation.metadata.version",
        lambda _name: (_ for _ in ()).throw(AssertionError("pin lookup should not run")),
    )

    with pytest.raises(DetectionGateValidationError, match="candidate"):
        _yara_execution(candidate)


def test_observed_run_rehydration_refuses_bundle_tampering(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_root = evidence_dir / "runs"
    run_root.mkdir(parents=True)
    store = RunStore(run_root)
    handle = store.create_run(scenario={}, plan={}, policy={}, profile={})
    record = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="gate-07-test",
        runner_profile_id="profile.test",
        environment={"environment_type": "disposable"},
        content={"artifact_type": "file_observation", "path": "staged/a.txt"},
        target_scope_ref="runner-profile:profile.test",
    )
    store.finalize(
        handle.run_id,
        result={"schema_version": "test", "status": "completed"},
        evidence=[record.to_dict()],
        detections=[],
    )
    assert store.get_run(handle.run_id)["created_at"] == handle.created_at
    journey = {
        "schema_version": "bluefire.detection-gate-journey.v1",
        "core_passed": True,
        "browser_pending": False,
        "run_id": handle.run_id,
        "run_bundle": {"run_id": handle.run_id, "path": f"runs/{handle.run_id}"},
        "observed_evidence_id": record.evidence_id,
        "roles": {},
        "states": {},
        "service_operations": [],
        "comparison_id": "comparison-test",
    }
    evidence_path = run_root / handle.run_id / "evidence.json"
    value = json.loads(evidence_path.read_text(encoding="utf-8"))
    value["records"][0]["content"]["path"] = "rewritten/a.txt"
    evidence_path.write_bytes(canonical_json_bytes(value) + b"\n")

    with pytest.raises(DetectionGateValidationError, match="run bundle"):
        _run_evidence(evidence_dir, journey)


def test_detection_helper_protocol_does_not_treat_browser_pending_as_passed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    browser_root = tmp_path / "playwright-browsers"
    browser_root.mkdir()
    node = tmp_path / "node.exe"
    node.write_bytes(b"node")
    captured: dict[str, str] = {}
    summary = {
        "schema_version": HELPER_SCHEMA,
        "status": "incomplete",
        "reports": list(REPORT_PATHS),
        "run_count": 1,
        "blocking_check": "production_browser_interaction",
    }

    def run_helper(*_args: Any, **kwargs: Any) -> tuple[int, bytes]:
        captured.update(kwargs["environment"])
        return 1, json.dumps(summary).encode("utf-8")

    monkeypatch.setenv(
        "BLUEFIRE_ACCEPTANCE_PLAYWRIGHT_BROWSERS_PATH",
        str(browser_root),
    )
    monkeypatch.setenv("BLUEFIRE_TEST_API_KEY", "must-not-cross-helper-boundary")
    monkeypatch.setattr(detection_gate.shutil, "which", lambda _name: str(node))
    monkeypatch.setattr(detection_gate, "_run_bounded_helper_process", run_helper)

    result = detection_gate._run_helper(ROOT, evidence)

    assert result["protocol_valid"] is True
    assert result["passed"] is False
    assert result["blocking_check"] == "production_browser_interaction"
    isolated_home = Path(captured["HOME"])
    assert Path(captured["PLAYWRIGHT_BROWSERS_PATH"]) == browser_root.resolve()
    assert isolated_home.parent == Path(captured["TEMP"])
    assert captured["USERPROFILE"] == str(isolated_home)
    assert Path(captured["LOCALAPPDATA"]) == isolated_home / "AppData" / "Local"
    assert Path(captured["APPDATA"]) == isolated_home / "AppData" / "Roaming"
    assert "BLUEFIRE_TEST_API_KEY" not in captured

    lifecycle = object()
    expected_root = evidence / ".gate07-managed-runner"

    def lifecycle_factory(root: Path) -> object:
        assert root == expected_root
        return lifecycle

    def service_factory(**kwargs: Any) -> Any:
        assert kwargs["runner_lifecycle"] is lifecycle
        raise detection_journey.DetectionJourneyError("stop after composition check")

    monkeypatch.setattr(detection_journey, "ManagedRunnerLifecycle", lifecycle_factory)
    monkeypatch.setattr(detection_journey, "BlueFireService", service_factory)
    with pytest.raises(
        detection_journey.DetectionJourneyError,
        match="stop after composition check",
    ):
        detection_journey.produce_detection_gate_evidence(ROOT, evidence)

    cli_root = tmp_path / "cli-runs"
    sigma = {
        "candidate_id": "detection-0123456789abcdefabcd",
        "definition_digest": "sha256:" + "1" * 64,
    }

    def cli_run(_command: list[str], **kwargs: Any) -> SimpleNamespace:
        expected_home = os.fspath(cli_root / ".gate07-cli-home")
        environment = kwargs["env"]
        assert environment["HOME"] == expected_home
        assert environment["USERPROFILE"] == expected_home
        assert environment["LOCALAPPDATA"] == expected_home
        assert environment["XDG_STATE_HOME"] == expected_home
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"candidate": {"document": sigma}}).encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(detection_journey.subprocess, "run", cli_run)
    cli = detection_journey._cli_evidence(ROOT, cli_root, sigma)
    assert cli["candidate_id"] == sigma["candidate_id"]


def test_detection_gate_emits_one_exact_proof_per_assertion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    gate = next(gate for gate in load_release_contract().gates if gate.gate_id == "GATE-07")
    checks = {name: True for name in CHECK_NAMES}
    bundles = ({"run_id": "run-proof-gate07", "path": "runs/run-proof-gate07"},)
    monkeypatch.setattr(
        detection_gate,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "tools/run_detection_gate_journey.py"],
            "protocol_valid": True,
            "blocking_check": None,
        },
    )
    monkeypatch.setattr(
        detection_gate,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {"passed": True, "suite_id": "detection"},
    )
    monkeypatch.setattr(detection_gate, "_suite_is_exact", lambda _value: True)
    monkeypatch.setattr(
        detection_gate,
        "validate_persisted_detection_gate",
        lambda *_args: (checks, bundles),
    )
    monkeypatch.setattr(detection_gate, "_acceptance_binding", lambda: {"gate_id": "GATE-07"})
    monkeypatch.setattr(
        detection_gate,
        "validated_run_bundle",
        lambda _gate, _root, raw, **_kwargs: (dict(raw), {}),
    )

    outcome = detection_gate.run_gate_07(gate, evidence, repository_root=ROOT)

    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 9
    assert len({proof["test_id"] for proof in outcome.proofs}) == 9
    assert {proof["kind"] for proof in outcome.proofs} == {"dynamic", "structural"}
    assert all(
        len(proof["assertion_ids"]) == 1
        and proof["run_ids"] == ["run-proof-gate07"]
        and proof["run_bundles"] == list(bundles)
        for proof in outcome.proofs
    )


def test_detection_gate_failure_redacts_private_paths() -> None:
    outcome = detection_gate._failure((r"C:\private\operator\browser.json failed",))

    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "C:\\private" not in str(outcome.failure_reason)
    assert "private-path-redacted" in str(outcome.failure_reason)
