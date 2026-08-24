from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from bluefire.api import APIError
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        yield instance
    finally:
        instance.close()


def _hypothesis(language: str = "internal") -> dict[str, object]:
    return {
        "behavior_id": "sandbox.collection.stage.v1",
        "title": "Sandbox staging observation",
        "target_language": language,
        "logsource": {"category": "file_event", "product": "generic"},
        "selection": {
            "artifact_type": "file_observation",
            "path|contains": "staged/",
        },
        "provenance": {"source": "operator-authored", "license": "MIT"},
        "known_misses": ["Requires filesystem observation fields."],
        "predicted_fields": ["artifact_type", "path"],
    }


def _candidate_document(response: object) -> dict[str, object]:
    assert isinstance(response, dict)
    resource = response["candidate"]
    assert isinstance(resource, dict)
    document = resource["document"]
    assert isinstance(document, dict)
    return document


def _finalized_observed_run(service: BlueFireService) -> tuple[str, EvidenceRecord]:
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.test"},
    )
    record = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="sandbox-observer.v1",
        runner_profile_id="profile.test",
        environment={"environment_type": "disposable"},
        content={"artifact_type": "file_observation", "path": "staged/a.txt"},
        target_scope_ref="runner-profile:profile.test",
    )
    service.store.finalize(
        handle.run_id,
        result={"schema_version": "test", "status": "completed"},
        evidence=[record.to_dict()],
        detections=[],
    )
    return handle.run_id, record


def test_internal_detection_lifecycle_persists_every_transition_and_rehydrates(
    tmp_path: Path,
) -> None:
    runs_dir = tmp_path / "runs"
    product_db = tmp_path / "product.sqlite3"
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    created = service.upsert_detection_hypothesis(_hypothesis())
    candidate_id = str(_candidate_document(created)["candidate_id"])
    parsed = service.parse_detection_candidate(candidate_id, {})
    exercised = service.exercise_detection_fixtures(
        candidate_id,
        {
            "fixtures": [
                {
                    "fixture_id": "malicious-1",
                    "artifact_type": "file_observation",
                    "path": "staged/a.txt",
                }
            ]
        },
    )
    run_id, evidence = _finalized_observed_run(service)
    observed = service.exercise_detection_observed(
        candidate_id,
        {"run_id": run_id, "evidence_ids": [evidence.evidence_id]},
    )
    evaluated = service.evaluate_detection_benign(
        candidate_id,
        {
            "fixtures": [
                {
                    "fixture_id": "benign-1",
                    "artifact_type": "file_observation",
                    "path": "documents/a.txt",
                }
            ],
            "notes": ["The declared benign fixture did not match."],
        },
    )

    assert _candidate_document(parsed)["state"] == "parsed"
    assert _candidate_document(exercised)["state"] == "fixture_exercised"
    assert _candidate_document(observed)["state"] == "observed_exercised"
    document = _candidate_document(evaluated)
    assert document["state"] == "benign_evaluated"
    assert document["malicious_fixtures"][0]["fixture_id"] == "malicious-1"
    assert document["benign_fixtures"][0]["fixture_id"] == "benign-1"
    assert document["observed_evidence_ids"] == [evidence.evidence_id]
    assert [row["action"] for row in document["lifecycle_history"]] == [
        "hypothesis_upsert",
        "parse",
        "exercise_fixtures",
        "exercise_observed",
        "evaluate_benign",
    ]
    assert [row["sequence"] for row in document["lifecycle_history"]] == [1, 2, 3, 4, 5]
    assert document["field_drift"] == {
        "intersection": ["artifact_type", "path"],
        "observed_only": [],
        "predicted_only": [],
    }
    service.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        fetched = restarted.detection_candidate(candidate_id)
        listed = restarted.detection_candidates()
        assert _candidate_document(fetched) == document
        assert [row["id"] for row in listed["candidates"]] == [candidate_id]
    finally:
        restarted.close()


def test_spl_structural_success_stays_a_hypothesis_and_health_is_honest(
    service: BlueFireService,
) -> None:
    created = service.upsert_detection_hypothesis(_hypothesis("spl"))
    candidate_id = str(_candidate_document(created)["candidate_id"])
    checked = service.parse_detection_candidate(
        candidate_id,
        {"source": 'index=lab path="staged/*" | stats count by host'},
    )
    document = _candidate_document(checked)

    assert document["state"] == "hypothesis"
    assert document["validation"]["authoritative_backend_validated"] is False
    assert document["lifecycle_history"][-1]["outcome"] == "no_state_change"
    health = service.detection_health()
    assert health["ready"] is True
    assert health["languages"]["spl"]["authoritative"] is False
    assert health["languages"]["spl"]["lifecycle_ceiling"] == "hypothesis"

    with pytest.raises(APIError) as exercise:
        service.exercise_detection_fixtures(
            candidate_id,
            {"fixtures": [{"fixture_id": "malicious-1", "path": "staged/a.txt"}]},
        )
    assert exercise.value.status == 409
    assert exercise.value.code == "detection_transition_conflict"


def test_detection_writes_cannot_bypass_lifecycle_or_persist_plaintext_secrets(
    service: BlueFireService,
) -> None:
    with pytest.raises(APIError) as bypass:
        service.save_resource(
            "detection",
            "detection-0123456789abcdef0123",
            {"document": {"state": "benign_evaluated"}},
        )
    assert bypass.value.status == 409
    assert bypass.value.code == "detection_lifecycle_required"

    unsafe = _hypothesis()
    unsafe["provenance"] = {"source": "operator-authored", "token": "plaintext-secret"}
    with pytest.raises(APIError) as secret:
        service.upsert_detection_hypothesis(unsafe)
    assert secret.value.status == 422
    assert secret.value.code == "detection_persistence_rejected"

    oversized = _hypothesis()
    oversized["known_misses"] = ["x" * 1_001]
    with pytest.raises(APIError) as bounded:
        service.upsert_detection_hypothesis(oversized)
    assert bounded.value.status == 400
    assert bounded.value.code == "detection_hypothesis_invalid"


def test_observed_exercise_accepts_only_finalized_independently_observed_evidence(
    service: BlueFireService,
) -> None:
    candidate_id = str(
        _candidate_document(service.upsert_detection_hypothesis(_hypothesis()))["candidate_id"]
    )
    service.parse_detection_candidate(candidate_id, {})
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={},
    )
    with pytest.raises(APIError) as mutable:
        service.exercise_detection_observed(candidate_id, {"run_id": handle.run_id})
    assert mutable.value.status == 409
    assert mutable.value.code == "detection_run_not_immutable"

    synthetic = EvidenceRecord.create(
        run_id=handle.run_id,
        step_id="stage",
        behavior_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.SYNTHETIC,
        producer="simulator.v1",
        content={"artifact_type": "file_observation", "path": "staged/a.txt"},
        target_scope_ref="sandbox.workspace",
    )
    service.store.finalize(
        handle.run_id,
        result={"schema_version": "test", "status": "completed"},
        evidence=[synthetic.to_dict()],
        detections=[],
    )
    with pytest.raises(APIError) as provenance:
        service.exercise_detection_observed(
            candidate_id,
            {"run_id": handle.run_id, "evidence_ids": [synthetic.evidence_id]},
        )
    assert provenance.value.status == 422
    assert provenance.value.code == "detection_observed_evidence_required"


def test_explicit_rejection_is_terminal_and_audited(service: BlueFireService) -> None:
    created = service.upsert_detection_hypothesis(_hypothesis())
    candidate_id = str(_candidate_document(created)["candidate_id"])
    rejected = service.reject_detection_candidate(
        candidate_id,
        {"reason": "Selection is too broad.", "notes": ["Retain for audit only."]},
    )
    document = _candidate_document(rejected)
    assert document["state"] == "rejected"
    assert document["rejection_reason"] == "Selection is too broad."
    assert document["lifecycle_history"][-1]["outcome"] == "rejected"

    with pytest.raises(APIError) as terminal:
        service.reject_detection_candidate(candidate_id, {"reason": "Reject twice."})
    assert terminal.value.status == 409


def test_sigma_and_yara_use_authoritative_installed_backends(
    service: BlueFireService,
) -> None:
    pytest.importorskip("sigma")
    pytest.importorskip("yara")

    sigma_created = service.upsert_detection_hypothesis(_hypothesis("sigma"))
    sigma_id = str(_candidate_document(sigma_created)["candidate_id"])
    sigma_source = """
title: Sandbox staging observation
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: file_event
detection:
  selection:
    path|contains: 'staged/'
  condition: selection
falsepositives:
  - Approved fixture staging
level: low
"""
    sigma = _candidate_document(
        service.parse_detection_candidate(sigma_id, {"source": sigma_source})
    )
    assert sigma["state"] == "parsed"
    assert sigma["parser_backend"]["name"] == "pySigma"

    yara_created = service.upsert_detection_hypothesis(_hypothesis("yara"))
    yara_id = str(_candidate_document(yara_created)["candidate_id"])
    yara_source = """
rule bluefire_staging_marker {
  strings:
    $marker = "bluefire_fixture_marker" ascii
  condition:
    $marker
}
"""
    service.parse_detection_candidate(yara_id, {"source": yara_source})
    exercised = service.exercise_detection_fixtures(
        yara_id,
        {"fixtures": [{"fixture_id": "malicious-1", "data": "bluefire_fixture_marker"}]},
    )
    benign = service.evaluate_detection_benign(
        yara_id,
        {
            "fixtures": [{"fixture_id": "benign-1", "data": "ordinary text"}],
            "notes": ["The benign fixture did not match."],
        },
    )
    assert _candidate_document(exercised)["state"] == "fixture_exercised"
    assert _candidate_document(benign)["state"] == "benign_evaluated"
