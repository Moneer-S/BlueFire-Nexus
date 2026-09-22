"""UI preset contract exercised against real collector output, not live lab proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bluefire import evidence as evidence_module
from bluefire.collectors import CollectionRequest, CollectionSemanticsCollector, FilesystemCollector
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from tests_platform.test_detection_evaluations import service as service

PRESETS = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "frontend/tests/fixtures/permission-preset-contract.json"
    ).read_text(encoding="utf-8")
)


def _candidate(service, condition, *, legacy=False):
    selection = dict(PRESETS[condition])
    if legacy:
        selection["artifact_type"] = "file_observation"
        del selection["observation_kind"]
    result = service.upsert_detection_hypothesis(
        {
            "behavior_id": "sandbox.permission.relax.v1",
            "title": f"{condition} {'legacy' if legacy else 'current'} contract",
            "target_language": "internal",
            "selection": selection,
            "predicted_fields": list(selection),
            "logsource": {"category": "file_event", "product": "generic"},
            "provenance": {"source": "unit-contract", "license": "MIT"},
        }
    )
    candidate_id = result["candidate"]["id"]
    service.parse_detection_candidate(candidate_id, {})
    return candidate_id


def _observations(service, tmp_path, monkeypatch, mode, *, status="available"):
    # Real file-handle collection with a deterministic metadata projection lets
    # Windows CI cover POSIX preset membership without claiming ACL observation.
    fields = {"permission_status": status, "effective_access": "not_evaluated"}
    if status == "available":
        fields.update(
            permission_mode_octal=f"{mode:04o}",
            group_write_bit=bool(mode & 0o020),
            other_write_bit=bool(mode & 0o002),
            non_owner_write_bit=bool(mode & 0o022),
        )
    monkeypatch.setattr(evidence_module, "observed_permission_fields", lambda metadata: fields)
    handle = service.store.create_run(
        scenario={"schema_version": "test"},
        plan={"schema_version": "test"},
        policy={"schema_version": "test"},
        profile={"id": "profile.unit"},
    )
    root = tmp_path / handle.run_id
    root.mkdir()
    (root / "sample.jsonl").write_text(
        '{"record_id":"synthetic-001","synthetic":true,"template":"telemetry-seed",'
        '"value":"telemetry-value-001"}\n'
    )
    request = CollectionRequest(
        run_id=handle.run_id,
        step_id="permission",
        behavior_id="sandbox.permission.relax.v1",
        runner_profile_id="profile.unit",
        target_scope_ref="runner-profile:profile.unit",
        settings={"paths": ["sample.jsonl"], "collect_after_step": "permission"},
    )
    records = [
        *FilesystemCollector(root).collect(request).records,
        *CollectionSemanticsCollector(root).collect(request).records,
    ]
    # An authored synthetic copy must not count as observed execution evidence.
    records.append(
        EvidenceRecord.create(
            run_id=handle.run_id,
            step_id="permission",
            behavior_id="sandbox.permission.relax.v1",
            provenance=EvidenceProvenance.SYNTHETIC,
            producer="unit-contract",
            content=dict(records[0].content),
            target_scope_ref="runner-profile:profile.unit",
        )
    )
    service.store.finalize(
        handle.run_id,
        result={"status": "completed", "mode": "simulate", "steps": []},
        evidence=[record.to_dict() for record in records],
        detections=[],
    )
    return handle.run_id, records


@pytest.mark.parametrize("condition", ["world_writable", "non_owner_writable"])
@pytest.mark.parametrize("mode", [0o640, 0o666, 0o660])
def test_ui_permission_presets_match_only_relevant_collector_observations(
    service, tmp_path, monkeypatch, condition, mode
):
    candidate_id = _candidate(service, condition)
    run_id, records = _observations(service, tmp_path, monkeypatch, mode)
    expected = bool(mode & (0o002 if condition == "world_writable" else 0o022))
    result = service.exercise_detection_observed(candidate_id, {"run_id": run_id})
    document = result["candidate"]["document"]
    assert document["state"] == ("observed_exercised" if expected else "parsed")
    assert document["match_count"] == int(expected)
    assert document["observed_evidence_ids"] == ([records[0].evidence_id] if expected else [])
    assert records[0].content["artifact_type"] == "collector_observation"
    assert records[0].content["observation_kind"] == "filesystem"
    assert records[1].content["observation_kind"] == "collection_semantics"
    assert records[2].provenance is EvidenceProvenance.SYNTHETIC


@pytest.mark.parametrize("condition", ["world_writable", "non_owner_writable"])
def test_unavailable_permission_fields_do_not_match_presets(
    service, tmp_path, monkeypatch, condition
):
    candidate_id = _candidate(service, condition)
    run_id, _ = _observations(service, tmp_path, monkeypatch, 0o666, status="unavailable_windows")
    result = service.exercise_detection_observed(candidate_id, {"run_id": run_id})
    assert result["candidate"]["document"]["state"] == "parsed"
    assert result["candidate"]["document"]["match_count"] == 0


def test_explicit_preset_tune_retains_the_legacy_miss(service, tmp_path, monkeypatch):
    legacy_id = _candidate(service, "world_writable", legacy=True)
    run_id, records = _observations(service, tmp_path, monkeypatch, 0o666)
    miss = service.exercise_detection_observed(legacy_id, {"run_id": run_id})
    assert miss["candidate"]["document"]["state"] == "parsed"
    tuned = service.tune_detection_candidate(
        legacy_id,
        {
            "reason": "Match independently collected filesystem permission observations.",
            "selection": PRESETS["world_writable"],
            "predicted_fields": list(PRESETS["world_writable"]),
        },
    )
    tuned_id = tuned["candidate"]["id"]
    service.parse_detection_candidate(tuned_id, {})
    hit = service.exercise_detection_observed(tuned_id, {"run_id": run_id})
    assert hit["candidate"]["document"]["observed_evidence_ids"] == [records[0].evidence_id]
    assert hit["candidate"]["document"]["parent_candidate_id"] == legacy_id
    assert service.detection_candidate(legacy_id) == miss
