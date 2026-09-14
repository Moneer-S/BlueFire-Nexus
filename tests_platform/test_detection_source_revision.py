from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bluefire.application_errors import APIError
from bluefire.detections import DetectionCandidate, DetectionError
from bluefire.service import BlueFireService
from tests_platform.test_detection_evaluations import evaluate, observed_run, query_candidate

ROOT = Path(__file__).resolve().parents[1]
SQL = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'"
REVISED = "SELECT fixture_id FROM logs WHERE observation_kind = 'collection_semantics'"


@pytest.fixture
def service(tmp_path: Path):
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    yield instance
    instance.close()


def parent(service: BlueFireService, language: str = "sqlite"):
    result = service.upsert_detection_hypothesis(
        {
            "behavior_id": "sandbox.collection.stage.v1",
            "title": "Observed staging rule",
            "target_language": language,
            "logsource": {"category": "file_event"},
            "selection": {"observation_kind": "filesystem"},
            "provenance": {"source": "operator", "license": "MIT"},
        }
    )
    if language == "sqlite":
        result = service.parse_detection_candidate(result["candidate"]["id"], {"source": SQL})
    return result["candidate"]


def revise(service, candidate_id, source=REVISED):
    return service.revise_detection_source(
        candidate_id, {"source": source, "reason": "Inspect independent contents observations"}
    )["candidate"]


def test_source_revision_is_atomic_parsed_and_source_bound_without_metadata_edit(service):
    before = parent(service)
    child = revise(service, before["id"])
    doc = child["document"]
    assert service.detection_candidate(before["id"])["candidate"] == before
    assert doc["revision"] == 2 and doc["revision_kind"] == "source"
    assert doc["parent_candidate_id"] == before["id"]
    assert doc["revision_root_id"] == before["id"]
    assert doc["definition_digest"] != before["document"]["definition_digest"]
    assert doc["selection"] == before["document"]["selection"]
    assert doc["logsource"] == before["document"]["logsource"]
    assert doc["provenance"] == before["document"]["provenance"]
    assert doc["state"] == "parsed" and doc["rule_source"] == REVISED
    assert (
        doc["validation"]["source_sha256"]
        == "sha256:" + hashlib.sha256(REVISED.encode()).hexdigest()
    )
    assert doc["validation"]["source_rule_executed"] is False
    assert doc["match_count"] == doc["benign_match_count"] == 0
    assert not doc["observed_evidence_ids"] and not doc["malicious_fixture_ids"]
    assert [row["action"] for row in doc["lifecycle_history"]] == ["revision_source", "parse"]
    assert DetectionCandidate.from_mapping(doc).to_dict() == doc
    with pytest.raises(DetectionError, match="definition_digest"):
        DetectionCandidate.from_mapping({**doc, "rule_source": SQL})
    assert service.detection_candidate(child["id"])["candidate"] == child
    comparison = service.compare_detection_candidates(before["id"], {"candidate_id": child["id"]})
    assert "rule_source_digest" in comparison["deltas"]["rule"]["changed_fields"]


@pytest.mark.parametrize(
    "source",
    [
        SQL,
        "",
        "DELETE FROM logs",
        "SELECT fixture_id FROM secrets",
        "SELECT unknown_field FROM logs",
    ],
)
def test_refused_source_does_not_publish_child_or_consume_revision(service, source):
    before = parent(service)
    with pytest.raises(APIError):
        revise(service, before["id"], source)
    assert service.detection_candidate(before["id"])["candidate"] == before
    assert len(service.product_store.list_resources("detection")) == 1
    assert revise(service, before["id"])["document"]["revision"] == 2


def test_textual_revision_can_keep_the_same_converted_query(service):
    before = parent(service)
    child = revise(service, before["id"], "\n" + SQL + "\n")
    assert child["document"]["rule_source"] != before["document"]["rule_source"]
    assert (
        child["document"]["validation"]["query_sha256"]
        == before["document"]["validation"]["query_sha256"]
    )
    assert (
        child["document"]["validation"]["source_sha256"]
        != before["document"]["validation"]["source_sha256"]
    )


def test_source_revision_evaluates_same_real_file_observations_without_fixtures_and_survives_restart(
    service, tmp_path
):
    # FilesystemCollector reads real temporary unit bytes; this is not native lab execution proof.
    baseline_id = query_candidate(service)
    run_id, records = observed_run(service, tmp_path)
    miss = evaluate(service, baseline_id, run_id)
    assert miss["result"]["state"] == "not_matched"
    child = revise(
        service,
        baseline_id,
        "SELECT * FROM logs WHERE artifact_type = 'collector_observation' AND observation_kind = 'filesystem'",
    )
    hit = evaluate(service, child["id"], run_id)
    assert hit["result"]["state"] == "matched"
    assert hit["result"]["matched_evidence_ids"] == [record.evidence_id for record in records]
    assert hit["source"] == miss["source"]
    assert hit["candidate"]["query_sha256"] != miss["candidate"]["query_sha256"]
    gap_run, _ = observed_run(service, tmp_path, missing=True)
    gap = evaluate(service, child["id"], gap_run)
    assert gap["result"]["state"] == "insufficient_evidence"
    assert gap["result"]["match_count"] is None
    reopened = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        assert reopened.detection_candidate(child["id"])["candidate"] == child
        assert reopened.detection_run_evaluations(baseline_id)["evaluations"] == [miss]
        assert {
            row["evaluation_id"]
            for row in reopened.detection_run_evaluations(child["id"])["evaluations"]
        } == {hit["evaluation_id"], gap["evaluation_id"]}
    finally:
        reopened.close()


def test_sigma_source_uses_installed_converter_and_unavailable_backend_publishes_nothing(
    service, monkeypatch
):
    before = parent(service, "sigma")
    sigma = "title: Independent staging\nstatus: test\nlogsource:\n  category: file_event\ndetection:\n  selection:\n    path|contains: staged/\n  condition: selection\nlevel: low\n"
    original = service.detection_lab.validator.parse_sigma

    def unavailable(*args):
        raise DetectionError("pySigma backend unavailable")

    monkeypatch.setattr(service.detection_lab.validator, "parse_sigma", unavailable)
    with pytest.raises(APIError) as error:
        revise(service, before["id"], sigma)
    assert error.value.status == 503
    assert len(service.product_store.list_resources("detection")) == 1
    monkeypatch.setattr(service.detection_lab.validator, "parse_sigma", original)
    if not service.detection_health()["languages"]["sigma"]["ready"]:
        pytest.skip("Reviewed pySigma backend is not installed")
    child = revise(service, before["id"], sigma)
    assert child["document"]["revision"] == 2
    assert child["document"]["state"] == "parsed"
    assert child["document"]["parser_backend"]["name"] == "pySigma"
    assert child["document"]["validation"]["source_rule_executed"] is False


def test_source_revision_rejects_language_and_caller_compiled_query(service):
    before = parent(service, "internal")
    with pytest.raises(APIError, match="Source revisions support"):
        revise(service, before["id"])
    with pytest.raises(APIError):
        service.revise_detection_source(
            before["id"],
            {"source": SQL, "reason": "no caller compiled data", "converted_query": SQL},
        )


@pytest.mark.parametrize("failure", [RuntimeError("parser failed"), KeyboardInterrupt()])
def test_parser_failure_rolls_back_revision_transaction(service, monkeypatch, failure):
    before = parent(service)
    original = service.detection_lab.validator.parse_sqlite

    def fail(*args):
        raise failure

    monkeypatch.setattr(service.detection_lab.validator, "parse_sqlite", fail)
    with pytest.raises(type(failure)):
        revise(service, before["id"])
    monkeypatch.setattr(service.detection_lab.validator, "parse_sqlite", original)
    assert len(service.product_store.list_resources("detection")) == 1
    assert revise(service, before["id"])["document"]["revision"] == 2


def test_legacy_revision_identity_snapshots_remain_byte_identical():
    fields = dict(
        behavior_id="sandbox.collection.stage.v1",
        title="Existing structured detector",
        target_language="internal",
        logsource={"category": "file_event"},
        selection={"path|contains": "staged/"},
        provenance={"source": "operator", "license": "MIT"},
    )
    origin = DetectionCandidate.hypothesis(**fields)
    clone = DetectionCandidate.hypothesis(
        **fields,
        revision=2,
        revision_root_id=origin.candidate_id,
        parent_candidate_id=origin.candidate_id,
        revision_kind="clone",
    )
    tune = DetectionCandidate.hypothesis(
        **dict(fields, selection={"path|contains": "export/"}),
        revision=3,
        revision_root_id=origin.candidate_id,
        parent_candidate_id=clone.candidate_id,
        revision_kind="tune",
    )
    assert [(item.candidate_id, item.definition_digest) for item in (origin, clone, tune)] == [
        (
            "detection-3d47cf35a58397a6ec59",
            "sha256:f22f4a83980031d3e56b0791faa9e5fed940917ec96287dc8beeb30bc8dc39ac",
        ),
        (
            "detection-0c3cf93c53543d31a849",
            "sha256:b3f403739519e38e0adba2ddd3ca36c214bd6de1b821202cf833ca5dad213f08",
        ),
        (
            "detection-424b2f3a11ca7e9ec9fc",
            "sha256:6750581253d1c2c41b8a22fa99c545b36a83697bc445ed3f21e54832536f7561",
        ),
    ]
