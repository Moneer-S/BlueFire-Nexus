from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

import pytest

from bluefire import cli
from bluefire import product_store as store_module
from bluefire.application_errors import APIError
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.product_store import ProductStore, ProductStoreError
from bluefire.product_store_detection_evaluations import bind_report
from bluefire.service import BlueFireService
from tests_platform.test_api import request, running_server

ROOT = Path(__file__).resolve().parents[1]
QUESTION = "Does the query distinguish collection staging from safe staging in this bounded lab?"


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        yield instance
    finally:
        instance.close()


def query_candidate(
    service: BlueFireService,
    where: str = "path = 'staged/discovery.tar'",
    *,
    language: str = "sqlite",
) -> str:
    response = service.upsert_detection_hypothesis(
        {
            "behavior_id": "sandbox.collection.stage.v1",
            "title": "Bounded staging query",
            "target_language": language,
            "logsource": {"category": "file_event", "product": "generic"},
            "selection": {"artifact_type": "collector_observation", "path": "staged/discovery.tar"},
            "provenance": {"source": "unit-query"},
        }
    )
    candidate_id = response["candidate"]["id"]
    if language == "sqlite":
        service.parse_detection_candidate(
            candidate_id,
            {
                "source": f"SELECT * FROM logs WHERE artifact_type = 'collector_observation' AND {where}"
            },
        )
    return candidate_id


def observed_run(
    service: BlueFireService,
    tmp_path: Path,
    *,
    path: str = "staged/bundle.jsonl",
    missing: bool = False,
    synthetic_only: bool = False,
    unobserved_postcondition: bool = False,
) -> tuple[str, list[EvidenceRecord]]:
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.unit"},
    )
    root = tmp_path / handle.run_id
    root.mkdir()
    target = root / path
    target.parent.mkdir(parents=True)
    target.write_text("public unit bytes, not native execution proof\n")
    collector = FilesystemCollector(root)
    records = list(
        collector.collect(
            CollectionRequest(
                run_id=handle.run_id,
                step_id="stage",
                behavior_id="sandbox.collection.stage.v1",
                runner_profile_id="profile.unit",
                target_scope_ref="runner-profile:profile.unit",
                settings={"paths": [path, "staged/missing.jsonl"] if missing else [path]},
            )
        ).records
    )
    if synthetic_only:
        records = [
            EvidenceRecord.create(
                run_id=handle.run_id,
                step_id="stage",
                behavior_id="sandbox.collection.stage.v1",
                provenance=EvidenceProvenance.SYNTHETIC,
                producer="unit-simulation",
                content={"artifact_type": "collector_observation", "path": path},
                target_scope_ref="runner-profile:profile.unit",
            )
        ]
    result: dict[str, Any] = {
        "status": "completed",
        "mode": "simulate" if synthetic_only else "execute",
        "steps": [],
    }
    if unobserved_postcondition:
        result["objective_evaluation"] = {
            "observation_integrity": {"satisfied": False, "state": "incomplete"}
        }
    service.store.finalize(
        handle.run_id,
        result=result,
        evidence=[record.to_dict() for record in records],
        detections=[],
    )
    return handle.run_id, records


def evaluate(
    service: BlueFireService, candidate_id: str, run_id: str, role: str = "attack"
) -> dict[str, Any]:
    return dict(
        service.evaluate_detection_run(
            candidate_id, {"run_id": run_id, "question": QUESTION, "case_role": role}
        )["evaluation"]
    )


def test_real_query_revision_changes_same_observed_case_and_retains_all_case_roles(
    service: BlueFireService, tmp_path: Path
) -> None:
    baseline_id = query_candidate(service)
    run_id, records = observed_run(service, tmp_path)
    before = service.detection_candidate(baseline_id)
    miss = evaluate(service, baseline_id, run_id)
    assert miss["result"]["state"] == "not_matched"
    assert miss["result"]["match_count"] == 0
    assert miss["backend"]["executed"] is True
    assert service.detection_candidate(baseline_id) == before
    tuned = service.tune_detection_candidate(
        baseline_id,
        {
            "reason": "The archive-only baseline misses record staging.",
            "selection": {"artifact_type": "collector_observation", "path|contains": "staged/"},
        },
    )
    tuned_id = tuned["candidate"]["id"]
    service.parse_detection_candidate(
        tuned_id,
        {
            "source": "SELECT * FROM logs WHERE artifact_type = 'collector_observation' AND path LIKE 'staged/%'"
        },
    )
    hit = evaluate(service, tuned_id, run_id)
    assert hit["result"]["state"] == "matched"
    assert hit["result"]["matched_evidence_ids"] == [records[0].evidence_id]
    assert hit["candidate"]["query_sha256"] != miss["candidate"]["query_sha256"]
    assert hit["source"]["evidence_digest"] == miss["source"]["evidence_digest"]
    assert "public unit bytes" not in json.dumps(hit)
    # A genuine byte-observation of safe staging still matches the broader rule.
    # Declaring it benign must expose that result, never manufacture a clean pass.
    benign_run, _ = observed_run(service, tmp_path)
    benign = evaluate(service, tuned_id, benign_run, "benign")
    assert benign["result"]["state"] == "matched"
    assert benign["case_role_basis"] == "operator_declared"
    for role, path in (("replay", "staged/bundle.jsonl"), ("heldout", "staged/bundle.json")):
        case_run, _ = observed_run(service, tmp_path, path=path)
        assert evaluate(service, tuned_id, case_run, role)["result"]["state"] == "matched"
    retained = service.detection_run_evaluations(tuned_id)["evaluations"]
    assert {report["case_role"] for report in retained} == {"attack", "benign", "replay", "heldout"}
    assert service.detection_candidate(tuned_id)["candidate"]["status"] == "parsed"
    service.exercise_detection_observed(tuned_id, {"run_id": run_id})
    assert service.detection_candidate(tuned_id)["candidate"]["document"]["predicted_fields"] == []
    assert service.detection_run_evaluations(tuned_id)["evaluations"] == retained


@pytest.mark.parametrize(
    "options, diagnostic",
    [
        ({"missing": True}, "source_contains_evidence_gaps"),
        ({"synthetic_only": True}, "observed_evidence_unavailable"),
        ({"unobserved_postcondition": True}, "source_file_postconditions_unobserved"),
    ],
)
def test_missing_telemetry_cannot_become_a_zero_match_success(
    service: BlueFireService, tmp_path: Path, options: dict[str, bool], diagnostic: str
) -> None:
    candidate_id = query_candidate(service, "path LIKE 'staged/%'")
    run_id, _ = observed_run(service, tmp_path, **options)
    report = evaluate(service, candidate_id, run_id, "benign")
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["match_count"] is None
    assert diagnostic in report["result"]["diagnostic_codes"]
    assert report["backend"]["executed"] is False


def test_absent_required_fields_are_insufficient_even_when_query_can_execute(
    service: BlueFireService, tmp_path: Path
) -> None:
    candidate_id = query_candidate(service, "Image = 'collector-process'")
    run_id, _ = observed_run(service, tmp_path)
    report = evaluate(service, candidate_id, run_id)
    assert report["result"]["state"] == "insufficient_evidence"
    assert report["result"]["missing_fields"] == ["Image"]
    assert report["backend"]["executed"] is True


@pytest.mark.parametrize(
    "extra", [{"evidence_ids": []}, {"expected_match": False}, {"evidence": []}]
)
def test_evaluation_never_accepts_caller_evidence_or_expected_results(
    service: BlueFireService, extra: dict[str, Any]
) -> None:
    candidate_id = query_candidate(service)
    with pytest.raises(APIError) as caught:
        service.evaluate_detection_run(
            candidate_id, {"run_id": "unused", "question": QUESTION, "case_role": "benign", **extra}
        )
    assert caught.value.code == "detection_request_invalid"


def test_reports_are_append_only_and_revalidate_candidate_and_source_bindings(
    service: BlueFireService, tmp_path: Path
) -> None:
    candidate_id = query_candidate(service)
    run_id, _ = observed_run(service, tmp_path)
    report = evaluate(service, candidate_id, run_id)
    with sqlite3.connect(service.product_store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE detection_run_evaluations SET run_id = ?", ("different",))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM detection_run_evaluations")
    changed = {key: value for key, value in report.items() if key != "evaluation_id"}
    changed["candidate"] = {**report["candidate"], "definition_digest": "sha256:" + "0" * 64}
    service.product_store.save_detection_evaluation(bind_report(changed))
    with pytest.raises(APIError) as caught:
        service.detection_run_evaluations(candidate_id)
    assert caught.value.code == "detection_evaluation_candidate_mismatch"


def test_corrupt_source_bundle_blocks_evaluation_and_existing_report_reads(
    service: BlueFireService, tmp_path: Path
) -> None:
    candidate_id = query_candidate(service)
    run_id, _ = observed_run(service, tmp_path)
    evaluate(service, candidate_id, run_id)
    (service.store.root / run_id / "evidence.json").write_text('{"records":[]}')
    for operation in (
        lambda: evaluate(service, candidate_id, run_id),
        lambda: service.detection_run_evaluations(candidate_id),
    ):
        with pytest.raises(APIError) as caught:
            operation()
        assert caught.value.code == "detection_evaluation_source_invalid"


def test_retained_report_cannot_rebind_a_valid_source_digest(
    service: BlueFireService, tmp_path: Path
) -> None:
    candidate_id = query_candidate(service)
    run_id, _ = observed_run(service, tmp_path)
    report = evaluate(service, candidate_id, run_id)
    changed = {key: value for key, value in report.items() if key != "evaluation_id"}
    changed["source"] = {**report["source"], "evidence_digest": "sha256:" + "0" * 64}
    service.product_store.save_detection_evaluation(bind_report(changed))
    with pytest.raises(APIError) as caught:
        service.detection_run_evaluations(candidate_id)
    assert caught.value.code == "detection_evaluation_source_mismatch"


def test_authenticated_http_and_cli_use_real_immutable_evaluation_service(
    service: BlueFireService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate_id = query_candidate(service, "path LIKE 'staged/%'")
    run_id, _ = observed_run(service, tmp_path)
    body = {"run_id": run_id, "question": QUESTION, "case_role": "attack"}
    with running_server(service) as (server, _):
        path = f"/api/v1/detections/{candidate_id}"
        status, _, payload = request(server, "POST", path + "/evaluate-run", body=body)
        assert status == 200
        result = json.loads(payload)["evaluation"]
        assert result["result"]["state"] == "matched"
        status, _, payload = request(server, "GET", path + "/evaluations")
        assert status == 200
        assert json.loads(payload)["evaluations"] == [result]
        assert request(server, "POST", path + "/evaluations", body={})[0] == 405
        assert request(server, "GET", path + "/evaluate-run")[0] == 405
        assert (
            request(server, "POST", path + "/evaluate-run", body=body, authenticated=False)[0]
            == 401
        )
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    document = tmp_path / "evaluation-request.json"
    document.write_text(json.dumps({**body, "case_role": "replay"}))
    parser = cli._parser()
    result = cli._execute(
        parser.parse_args(["detections", "evaluate-run", candidate_id, str(document)])
    )
    assert result["evaluation"]["case_role"] == "replay"
    history = cli._execute(parser.parse_args(["detections", "evaluations", candidate_id]))
    assert len(history["evaluations"]) == 2


def test_installed_sigma_conversion_executes_against_independent_observation(
    service: BlueFireService, tmp_path: Path
) -> None:
    if not service.detection_health()["languages"]["sigma"]["ready"]:
        pytest.skip("The pinned pySigma SQLite adapter is not installed in this environment.")
    candidate_id = query_candidate(service, language="sigma")
    service.parse_detection_candidate(
        candidate_id,
        {"source": """
title: Bounded Staging Observation
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: file_event
detection:
  selection:
    artifact_type: collector_observation
    path|startswith: staged/
  condition: selection
level: low
"""},
    )
    run_id, records = observed_run(service, tmp_path)
    result = evaluate(service, candidate_id, run_id)
    assert result["backend"]["executed"] is True
    assert result["result"]["matched_evidence_ids"] == [records[0].evidence_id]
    assert result["candidate"]["parser_backend"]["name"] == "pySigma"


def make_checkpoint7(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as old:
        old.setattr(store_module, "SCHEMA_VERSION", 7)
        old.setattr(
            store_module.detection_evaluation_store, "initialize_schema", lambda _connection: None
        )
        checkpoint = ProductStore(path)
        checkpoint.set_setting("unit.preserved", {"value": "retained"})
        assert checkpoint.schema_version == 7


def test_checkpoint7_upgrade_preserves_state_and_adds_evaluations_transactionally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "checkpoint.sqlite3"
    make_checkpoint7(path, monkeypatch)
    upgraded = ProductStore(path)
    assert upgraded.schema_version == 8
    assert upgraded.get_setting("unit.preserved") == {"value": "retained"}
    assert upgraded.detection_evaluations("detection-" + "0" * 20) == []
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(7,), (8,)]


def test_failed_evaluation_schema_upgrade_rolls_back_table_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "checkpoint.sqlite3"
    make_checkpoint7(path, monkeypatch)
    initialize = store_module.detection_evaluation_store.initialize_schema

    def fail(connection: sqlite3.Connection) -> None:
        initialize(connection)
        raise sqlite3.OperationalError("unit migration failure")

    monkeypatch.setattr(store_module.detection_evaluation_store, "initialize_schema", fail)
    with pytest.raises(ProductStoreError, match="migration failed"):
        ProductStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 7
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'detection_run_evaluations'"
            ).fetchone()
            is None
        )
