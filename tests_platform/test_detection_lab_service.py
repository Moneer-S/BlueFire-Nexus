from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Iterator, Mapping

import pytest

from bluefire.api import APIError
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.service import BlueFireService
from bluefire.util import content_hash

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


def _public_baseline(
    service: BlueFireService,
    source_id: str = "research.atomic-red-team.v1",
) -> dict[str, str]:
    resource = service.resource("research_source", source_id)["resource"]
    assert isinstance(resource, Mapping)
    document = resource["document"]
    assert isinstance(document, Mapping)
    assert resource["status"] == "pinned"
    return {
        "schema_version": "bluefire.public-baseline.v1",
        "research_source_id": source_id,
        "source_digest": str(resource["digest"]),
        "pin": str(document["pin"]),
        "version": str(document["version"]),
        "license": str(document["license"]),
        "license_review": str(document["license_review"]),
        "relationship": str(document["relationship"]),
        "use": "comparison",
    }


def _finalized_observed_run(
    service: BlueFireService,
    *,
    path: str = "staged/a.txt",
) -> tuple[str, EvidenceRecord]:
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
        content={"artifact_type": "file_observation", "path": path},
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


def test_public_baselines_require_an_exact_registered_pinned_source(
    service: BlueFireService,
) -> None:
    baseline = _public_baseline(service)
    hypothesis = _hypothesis()
    hypothesis["public_baselines"] = [baseline]

    created = _candidate_document(service.upsert_detection_hypothesis(hypothesis))
    assert created["public_baselines"] == [baseline]

    source_id = baseline["research_source_id"]
    source = service.resource("research_source", source_id)["resource"]
    source_document = source["document"]
    assert isinstance(source_document, Mapping)
    baseline_v2 = {
        "schema_version": "bluefire.public-baseline.v2",
        "research_source_id": source_id,
        "source_digest": str(source["digest"]),
        "pin": str(source_document["pin"]),
        "version": str(source_document["version"]),
        "exact_ref": str(source_document["exact_ref"]),
        "retrieved_at": str(source_document["retrieved_at"]),
        "license": str(source_document["license"]),
        "file_level_license_review": str(source_document["file_level_license_review"]),
        "trademark_considerations": str(source_document["trademark_considerations"]),
        "license_review": str(source_document["license_review"]),
        "relationship": str(source_document["relationship"]),
        "use_classification": str(source_document["use_classification"]),
        "use": "comparison",
        "attribution": str(source_document["attribution"]),
        "security_review": str(source_document["security_review"]),
        "last_verified_at": str(source_document["last_verified_at"]),
        "update_status": str(source_document["update_status"]),
    }
    v2_hypothesis = _hypothesis()
    v2_hypothesis["selection"] = {
        "artifact_type": "file_observation",
        "path|startswith": "staged/",
    }
    v2_hypothesis["public_baselines"] = [baseline_v2]
    v2_created = _candidate_document(service.upsert_detection_hypothesis(v2_hypothesis))
    assert v2_created["public_baselines"] == [baseline_v2]

    with pytest.raises(APIError) as rewrite:
        service.save_resource(
            "research_source",
            source_id,
            {
                "document": {
                    **source_document,
                    "notes": "Attempted rewrite after a detection bound this digest.",
                },
                "status": "pinned",
            },
        )
    assert rewrite.value.status == 409
    assert rewrite.value.code == "research_source_integrity_conflict"

    with pytest.raises(APIError) as downgrade:
        service.save_resource(
            "research_source",
            source_id,
            {"document": source_document, "status": "draft"},
        )
    assert downgrade.value.status == 409
    assert downgrade.value.code == "research_source_integrity_conflict"
    assert _candidate_document(service.detection_candidate(str(created["candidate_id"]))) == created
    assert service.resource("research_source", source_id)["resource"] == source

    missing_source = _hypothesis()
    missing_source["public_baselines"] = [{**baseline, "research_source_id": "research.missing.v1"}]
    with pytest.raises(APIError) as missing:
        service.upsert_detection_hypothesis(missing_source)
    assert missing.value.status == 422
    assert missing.value.code == "detection_baseline_source_missing"

    mismatched_pin = _hypothesis()
    mismatched_pin["public_baselines"] = [{**baseline, "pin": "not-the-registered-pin"}]
    with pytest.raises(APIError) as mismatch:
        service.upsert_detection_hypothesis(mismatched_pin)
    assert mismatch.value.status == 422
    assert mismatch.value.code == "detection_baseline_source_mismatch"

    arbitrary = _hypothesis()
    arbitrary["public_baselines"] = [{"name": "unlinked public corpus"}]
    with pytest.raises(APIError) as invalid:
        service.upsert_detection_hypothesis(arbitrary)
    assert invalid.value.status == 400
    assert invalid.value.code == "detection_public_baseline_invalid"


def test_clone_tune_compare_and_revision_lineage_survive_restart(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    product_db = tmp_path / "product.sqlite3"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        root_hypothesis = _hypothesis()
        root_hypothesis["public_baselines"] = [_public_baseline(first)]
        root_id = str(
            _candidate_document(first.upsert_detection_hypothesis(root_hypothesis))["candidate_id"]
        )
        first.parse_detection_candidate(root_id, {})
        first.exercise_detection_fixtures(
            root_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "root-malicious",
                        "artifact_type": "file_observation",
                        "path": "staged/root.txt",
                    }
                ]
            },
        )
        root_run_id, root_evidence = _finalized_observed_run(first)
        first.exercise_detection_observed(
            root_id,
            {"run_id": root_run_id, "evidence_ids": [root_evidence.evidence_id]},
        )
        first.evaluate_detection_benign(
            root_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "root-benign",
                        "artifact_type": "file_observation",
                        "path": "documents/root.txt",
                    }
                ],
                "notes": ["Root benign fixture did not match."],
            },
        )
        root_snapshot = _candidate_document(first.detection_candidate(root_id))
        assert (
            _candidate_document(first.upsert_detection_hypothesis(root_hypothesis)) == root_snapshot
        )
        with pytest.raises(APIError) as immutable_definition:
            first.upsert_detection_hypothesis(
                {**root_hypothesis, "title": "Attempted in-place definition edit"}
            )
        assert immutable_definition.value.status == 409
        assert immutable_definition.value.code == "detection_revision_required"

        clone_document = _candidate_document(
            first.clone_detection_candidate(root_id, {"reason": "Create an editable revision."})
        )
        clone_id = str(clone_document["candidate_id"])
        assert clone_document["revision"] == 2
        assert clone_document["revision_root_id"] == root_id
        assert clone_document["parent_candidate_id"] == root_id
        assert clone_document["revision_kind"] == "clone"
        assert clone_document["state"] == "hypothesis"

        tuned_document = _candidate_document(
            first.tune_detection_candidate(
                clone_id,
                {
                    "reason": "Narrow the staging path to the archive fixture.",
                    "selection": {
                        "artifact_type": "file_observation",
                        "path|contains": "archive/",
                    },
                    "provenance": {
                        "source": "operator-tuned",
                        "license": "MIT",
                    },
                    "predicted_fields": ["artifact_type", "path", "user.name"],
                },
            )
        )
        tuned_id = str(tuned_document["candidate_id"])
        assert tuned_document["revision"] == 3
        assert tuned_document["revision_root_id"] == root_id
        assert tuned_document["parent_candidate_id"] == clone_id
        assert tuned_document["revision_kind"] == "tune"

        first.parse_detection_candidate(tuned_id, {})
        first.exercise_detection_fixtures(
            tuned_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "tuned-malicious",
                        "artifact_type": "file_observation",
                        "path": "archive/tuned.txt",
                    }
                ]
            },
        )
        tuned_run_id, tuned_evidence = _finalized_observed_run(first, path="archive/tuned.txt")
        first.exercise_detection_observed(
            tuned_id,
            {"run_id": tuned_run_id, "evidence_ids": [tuned_evidence.evidence_id]},
        )
        first.evaluate_detection_benign(
            tuned_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "tuned-benign",
                        "artifact_type": "file_observation",
                        "path": "documents/tuned.txt",
                    }
                ],
                "notes": ["Tuned benign fixture did not match."],
            },
        )

        comparison = first.compare_detection_candidates(root_id, {"candidate_id": tuned_id})
        comparison_id = comparison["comparison_id"]
        deltas = comparison["deltas"]
        assert isinstance(deltas, Mapping)
        assert comparison["revision_root_id"] == root_id
        assert deltas["source"]["changed"] is True
        assert "selection_digest" in deltas["rule"]["changed_fields"]
        assert deltas["fields"]["predicted"]["added"] == ["user.name"]
        assert deltas["lifecycle"]["changed"] is True
        assert deltas["fixtures"]["added_fixture_ids"] == ["tuned-malicious"]
        assert deltas["fixtures"]["removed_fixture_ids"] == ["root-malicious"]
        assert deltas["observed"]["evidence_ids"]["added"] == [tuned_evidence.evidence_id]
        assert deltas["observed"]["evidence_ids"]["removed"] == [root_evidence.evidence_id]
        assert deltas["benign"]["added_fixture_ids"] == ["tuned-benign"]
        assert deltas["benign"]["removed_fixture_ids"] == ["root-benign"]
        assert _candidate_document(first.detection_candidate(root_id)) == root_snapshot

        unrelated_hypothesis = _hypothesis()
        unrelated_hypothesis["selection"] = {
            "artifact_type": "file_observation",
            "path|contains": "unrelated/",
        }
        unrelated_id = str(
            _candidate_document(first.upsert_detection_hypothesis(unrelated_hypothesis))[
                "candidate_id"
            ]
        )
        with pytest.raises(APIError) as unrelated:
            first.compare_detection_candidates(root_id, {"candidate_id": unrelated_id})
        assert unrelated.value.code == "detection_revision_lineage_mismatch"
    finally:
        first.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        candidates = {
            str(resource["id"]): resource
            for resource in restarted.detection_candidates()["candidates"]
        }
        assert {root_id, clone_id, tuned_id}.issubset(candidates)
        assert _candidate_document(restarted.detection_candidate(clone_id))["revision"] == 2
        assert _candidate_document(restarted.detection_candidate(tuned_id))["revision"] == 3
        comparison = restarted.compare_detection_candidates(root_id, {"candidate_id": tuned_id})
        assert comparison["candidate"]["candidate_id"] == tuned_id
        assert comparison["comparison_id"] == comparison_id
    finally:
        restarted.close()


def test_revision_ordinals_are_atomic_across_service_instances(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    product_db = tmp_path / "product.sqlite3"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    second = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        root_id = str(
            _candidate_document(first.upsert_detection_hypothesis(_hypothesis()))["candidate_id"]
        )
        barrier = Barrier(2)

        def clone(service: BlueFireService, title: str) -> dict[str, object]:
            barrier.wait()
            return _candidate_document(
                service.clone_detection_candidate(
                    root_id,
                    {"reason": f"Create concurrent revision {title}.", "title": title},
                )
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(clone, first, "Concurrent A"),
                executor.submit(clone, second, "Concurrent B"),
            ]
            documents = [future.result() for future in futures]

        assert sorted(int(document["revision"]) for document in documents) == [2, 3]
        assert len({str(document["candidate_id"]) for document in documents}) == 2
        for document in documents:
            assert (
                _candidate_document(first.detection_candidate(str(document["candidate_id"])))
                == document
            )
    finally:
        first.close()
        second.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        fourth = _candidate_document(
            restarted.clone_detection_candidate(
                root_id,
                {"reason": "Continue the durable lineage.", "title": "Revision four"},
            )
        )
        assert fourth["revision"] == 4
        revisions = sorted(
            int(resource["document"]["revision"])
            for resource in restarted.detection_candidates()["candidates"]
        )
        assert revisions == [1, 2, 3, 4]
    finally:
        restarted.close()


def test_migration_backfills_mixed_v1_v2_lineage_without_rewriting_documents(
    tmp_path: Path,
) -> None:
    runs_dir = tmp_path / "runs"
    product_db = tmp_path / "product.sqlite3"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    root_id = str(
        _candidate_document(first.upsert_detection_hypothesis(_hypothesis()))["candidate_id"]
    )
    clone = _candidate_document(
        first.clone_detection_candidate(root_id, {"reason": "Persist a v2 child."})
    )
    clone_id = str(clone["candidate_id"])
    root = _candidate_document(first.detection_candidate(root_id))
    first.close()

    legacy_root = dict(root)
    legacy_root["schema_version"] = "bluefire.detection.v1"
    for field in (
        "revision",
        "revision_root_id",
        "parent_candidate_id",
        "revision_kind",
        "definition_digest",
    ):
        legacy_root.pop(field)
    document_json = json.dumps(
        legacy_root,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    with sqlite3.connect(product_db) as connection:
        connection.execute(
            """
            UPDATE resources SET document_json = ?, digest = ?
            WHERE kind = 'detection' AND resource_id = ?
            """,
            (document_json, content_hash(legacy_root), root_id),
        )
        connection.execute("DROP TABLE detection_revisions")
        connection.execute("DELETE FROM schema_migrations WHERE version = 5")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (4, 'legacy')"
        )

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        fetched_root = _candidate_document(restarted.detection_candidate(root_id))
        fetched_clone = _candidate_document(restarted.detection_candidate(clone_id))
        assert fetched_root["schema_version"] == "bluefire.detection.v1"
        assert fetched_root["candidate_id"] == root_id
        assert "revision" not in fetched_root
        assert fetched_clone["revision"] == 2

        third = _candidate_document(
            restarted.clone_detection_candidate(
                root_id,
                {"reason": "Allocate after migration backfill."},
            )
        )
        assert third["revision"] == 3
    finally:
        restarted.close()

    with sqlite3.connect(product_db) as connection:
        persisted_schema = json.loads(
            connection.execute(
                """
                SELECT document_json FROM resources
                WHERE kind = 'detection' AND resource_id = ?
                """,
                (root_id,),
            ).fetchone()[0]
        )["schema_version"]
    assert persisted_schema == "bluefire.detection.v1"


def test_comparison_id_changes_with_lifecycle_snapshot_and_survives_restart(
    tmp_path: Path,
) -> None:
    runs_dir = tmp_path / "runs"
    product_db = tmp_path / "product.sqlite3"
    first = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        root_id = str(
            _candidate_document(first.upsert_detection_hypothesis(_hypothesis()))["candidate_id"]
        )
        clone = _candidate_document(
            first.clone_detection_candidate(root_id, {"reason": "Compare lifecycle states."})
        )
        clone_id = str(clone["candidate_id"])
        initial = first.compare_detection_candidates(root_id, {"candidate_id": clone_id})
        repeated = first.compare_detection_candidates(root_id, {"candidate_id": clone_id})
        assert repeated["comparison_id"] == initial["comparison_id"]

        first.parse_detection_candidate(clone_id, {})
        progressed = first.compare_detection_candidates(root_id, {"candidate_id": clone_id})
        assert progressed["comparison_id"] != initial["comparison_id"]
        assert (
            progressed["baseline"]["definition_digest"] == initial["baseline"]["definition_digest"]
        )
        assert (
            progressed["candidate"]["definition_digest"]
            == initial["candidate"]["definition_digest"]
        )
    finally:
        first.close()

    restarted = BlueFireService(
        project_root=ROOT,
        runs_dir=runs_dir,
        product_db_path=product_db,
    )
    try:
        stable = restarted.compare_detection_candidates(root_id, {"candidate_id": clone_id})
        assert stable["comparison_id"] == progressed["comparison_id"]
    finally:
        restarted.close()


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


def test_yara_l_is_not_misrepresented_as_yara_python(service: BlueFireService) -> None:
    health = service.detection_health()["languages"]["yara-l"]
    assert health == {
        "ready": False,
        "authoritative": False,
        "backend": "No local YARA-L evaluator",
        "version": None,
    }

    created = service.upsert_detection_hypothesis(_hypothesis("yara-l"))
    candidate_id = str(_candidate_document(created)["candidate_id"])
    with pytest.raises(APIError) as refused:
        service.parse_detection_candidate(
            candidate_id,
            {"source": "rule not_really_yara_l { condition: true }"},
        )

    assert refused.value.status == 503
    assert refused.value.code == "detection_backend_unavailable"
    persisted = _candidate_document(service.detection_candidate(candidate_id))
    assert persisted["state"] == "hypothesis"
    assert persisted["lifecycle_history"] == created["candidate"]["document"]["lifecycle_history"]


def test_sigma_conversion_executes_fixtures_and_immutable_observed_evidence(
    service: BlueFireService,
) -> None:
    pytest.importorskip("sigma.backends.sqlite")

    health = service.detection_health()["languages"]
    assert health["sigma"]["authoritative"] is True
    assert health["sigma"]["backend"] == "pySigma SQLite"
    assert health["sqlite"]["authoritative"] is True
    assert health["sqlite"]["backend"] == "SQLite bounded executor"

    created = service.upsert_detection_hypothesis(_hypothesis("sigma"))
    candidate_id = str(_candidate_document(created)["candidate_id"])
    sigma_source = """
title: Sandbox staging execution
id: 22222222-2222-4222-8222-222222222222
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
    parsed = _candidate_document(
        service.parse_detection_candidate(candidate_id, {"source": sigma_source})
    )
    assert parsed["state"] == "parsed"
    assert parsed["validation"]["conversion_backend"] == "pySigma SQLite"
    assert parsed["validation"]["mapped_fields"] == ["path"]
    assert parsed["validation"]["unsupported_fields"] == []
    assert parsed["validation"]["source_rule_executed"] is False

    exercised = _candidate_document(
        service.exercise_detection_fixtures(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "sigma-malicious",
                        "artifact_type": "file_observation",
                        "path": "staged/a.txt",
                    },
                    {
                        "fixture_id": "sigma-nonmatch",
                        "artifact_type": "file_observation",
                        "path": "documents/a.txt",
                    },
                ]
            },
        )
    )
    assert exercised["state"] == "fixture_exercised"
    assert exercised["validation"]["source_rule_executed"] is True
    assert exercised["validation"]["evaluated_fixture_ids"] == [
        "sigma-malicious",
        "sigma-nonmatch",
    ]
    assert exercised["validation"]["matched_fixture_ids"] == ["sigma-malicious"]
    assert exercised["validation"]["executed_query_sha256"] == parsed["validation"]["query_sha256"]

    run_id, evidence = _finalized_observed_run(service, path="staged/observed.txt")
    observed = _candidate_document(
        service.exercise_detection_observed(
            candidate_id,
            {"run_id": run_id, "evidence_ids": [evidence.evidence_id]},
        )
    )
    assert observed["state"] == "observed_exercised"
    assert observed["observed_evidence_ids"] == [evidence.evidence_id]
    assert observed["validation"]["evaluated_evidence_ids"] == [evidence.evidence_id]
    assert observed["validation"]["matched_evidence_ids"] == [evidence.evidence_id]
    assert observed["validation"]["observed_exercise"] == {
        "run_id": run_id,
        "evidence_ids": [evidence.evidence_id],
        "immutable_bundle_validated": True,
        "source_rule_executed": True,
    }

    benign = _candidate_document(
        service.evaluate_detection_benign(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "sigma-benign",
                        "artifact_type": "file_observation",
                        "path": "documents/ordinary.txt",
                    }
                ],
                "notes": ["Approved document storage did not match."],
            },
        )
    )
    assert benign["state"] == "benign_evaluated"
    assert benign["benign_match_count"] == 0
    assert benign["validation"]["benign_evaluated_fixture_ids"] == ["sigma-benign"]
    assert benign["validation"]["benign_matched_fixture_ids"] == []
    assert benign["false_positive_notes"] == ["Approved document storage did not match."]


def test_native_sqlite_candidate_uses_the_same_bounded_execution_lifecycle(
    service: BlueFireService,
) -> None:
    created = service.upsert_detection_hypothesis(_hypothesis("sqlite"))
    candidate_id = str(_candidate_document(created)["candidate_id"])
    source = "SELECT * FROM logs WHERE artifact_type = 'file_observation' AND path LIKE '%staged/%'"

    parsed = _candidate_document(
        service.parse_detection_candidate(candidate_id, {"source": source})
    )
    assert parsed["state"] == "parsed"
    assert parsed["parser_backend"]["name"] == "SQLite bounded executor"
    assert parsed["validation"]["mapped_fields"] == ["artifact_type", "path"]
    assert parsed["validation"]["source_rule_executed"] is False

    exercised = _candidate_document(
        service.exercise_detection_fixtures(
            candidate_id,
            {
                "fixtures": [
                    {
                        "fixture_id": "sqlite-malicious",
                        "artifact_type": "file_observation",
                        "path": "staged/native.txt",
                        "unmapped_context": "retained only in fixture provenance",
                    }
                ]
            },
        )
    )
    assert exercised["state"] == "fixture_exercised"
    assert exercised["match_count"] == 1
    assert exercised["validation"]["last_execution"]["query_only"] is True
    assert exercised["validation"]["last_execution"]["authorizer"] is True
    assert exercised["validation"]["last_execution"]["unsupported_fixture_fields"] == [
        "unmapped_context"
    ]
    assert exercised["validation"]["matched_fixture_ids"] == ["sqlite-malicious"]


def test_native_sqlite_parse_rejects_non_select_and_missing_identity_output(
    service: BlueFireService,
) -> None:
    first = service.upsert_detection_hypothesis(_hypothesis("sqlite"))
    first_id = str(_candidate_document(first)["candidate_id"])
    rejected = _candidate_document(
        service.parse_detection_candidate(first_id, {"source": "DELETE FROM logs"})
    )
    assert rejected["state"] == "rejected"
    assert rejected["validation"]["source_rule_executed"] is False

    tuned_request = _hypothesis("sqlite")
    tuned_request["selection"] = {
        "artifact_type": "file_observation",
        "path|startswith": "staged/",
    }
    second = service.upsert_detection_hypothesis(tuned_request)
    second_id = str(_candidate_document(second)["candidate_id"])
    missing_identity = _candidate_document(
        service.parse_detection_candidate(second_id, {"source": "SELECT path FROM logs"})
    )
    assert missing_identity["state"] == "rejected"
    assert "fixture_id" in str(missing_identity["rejection_reason"])
