from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import pytest

from bluefire.application_errors import APIError
from bluefire.detections import DetectionCandidate, DetectionPipeline
from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        yield instance
    finally:
        instance.close()


def source_candidate() -> DetectionCandidate:
    pipeline = DetectionPipeline()
    candidate = DetectionCandidate.hypothesis(
        behavior_id="sandbox.collection.stage.v1",
        title="Run staging candidate",
        target_language="internal",
        logsource={"category": "file_event", "product": "generic"},
        selection={"artifact_type": "file_observation", "path|contains": "staged/"},
        provenance={"source": "run-generated"},
    )
    candidate = pipeline.exercise_fixtures(
        pipeline.parse(candidate),
        [
            {
                "fixture_id": "test-staging",
                "artifact_type": "file_observation",
                "path": "staged/bundle.jsonl",
            }
        ],
    )
    return pipeline.evaluate_benign(
        candidate,
        [
            {
                "fixture_id": "test-benign",
                "artifact_type": "file_observation",
                "path": "fixtures/sample.jsonl",
            }
        ],
    )


def finalized_source(service: BlueFireService, candidate: dict[str, Any]) -> str:
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.test"},
    )
    # These are explicit Simulate unit records, not claimed native observations.
    service.store.finalize(
        handle.run_id,
        result={"status": "completed", "mode": "simulate", "steps": []},
        evidence=[],
        detections=[candidate],
    )
    return handle.run_id


def test_import_same_rule_from_two_runs_clones_without_copying_lifecycle(
    service: BlueFireService,
) -> None:
    source = source_candidate()
    first_run = finalized_source(service, source.to_dict())
    second_run = finalized_source(service, source.to_dict())
    first = service.detection_hypothesis_from_run(
        {"run_id": first_run, "candidate_id": source.candidate_id}
    )
    assert first["operation"] == "created"
    first_document = first["candidate"]["document"]
    assert first_document["candidate_id"] == source.candidate_id
    assert first_document["state"] == "hypothesis"
    assert first_document["parser_backend"] == {}
    assert first_document["match_count"] == 0
    assert first_document["benign_match_count"] == 0
    assert first_document["malicious_fixture_ids"] == []
    assert first_document["observed_evidence_ids"] == []
    parsed = service.parse_detection_candidate(source.candidate_id, {})
    second = service.detection_hypothesis_from_run(
        {"run_id": second_run, "candidate_id": source.candidate_id}
    )
    assert second["operation"] == "cloned"
    clone = second["candidate"]["document"]
    assert clone["candidate_id"] != source.candidate_id
    assert clone["parent_candidate_id"] == source.candidate_id
    assert clone["revision_root_id"] == source.candidate_id
    assert clone["revision"] == 2
    assert clone["provenance"]["source_run_id"] == second_run
    assert clone["state"] == "hypothesis"
    assert clone["parser_backend"] == {}
    assert clone["validation"] == {}
    assert clone["match_count"] == 0
    assert service.detection_candidate(source.candidate_id) == parsed
    reused = service.detection_hypothesis_from_run(
        {"run_id": first_run, "candidate_id": source.candidate_id}
    )
    assert reused["operation"] == "reused"
    assert reused["candidate"] == parsed["candidate"]
    assert service.store.get_run(first_run)["detections"]["candidates"] == [source.to_dict()]


def test_import_refuses_candidate_identity_not_matching_its_definition(
    service: BlueFireService,
) -> None:
    source = source_candidate().to_dict()
    source["candidate_id"] = "detection-" + "0" * 20
    run_id = finalized_source(service, source)
    with pytest.raises(APIError) as caught:
        service.detection_hypothesis_from_run(
            {"run_id": run_id, "candidate_id": source["candidate_id"]}
        )
    assert caught.value.code == "detection_source_candidate_invalid"
    assert service.detection_candidates()["candidates"] == []


def test_import_refuses_corrupt_bundle_and_caller_supplied_definition(
    service: BlueFireService,
) -> None:
    source = source_candidate()
    run_id = finalized_source(service, source.to_dict())
    with pytest.raises(APIError) as caught:
        service.detection_hypothesis_from_run(
            {"run_id": run_id, "candidate_id": source.candidate_id, "state": "observed_exercised"}
        )
    assert caught.value.code == "detection_request_invalid"
    path = service.store.root / run_id / "detections.json"
    document = json.loads(path.read_text())
    document["candidates"][0]["title"] = "Changed after finalization"
    path.write_text(json.dumps(document))
    with pytest.raises(APIError) as caught:
        service.detection_hypothesis_from_run(
            {"run_id": run_id, "candidate_id": source.candidate_id}
        )
    assert caught.value.code == "detection_source_run_unavailable"
    assert service.detection_candidates()["candidates"] == []
