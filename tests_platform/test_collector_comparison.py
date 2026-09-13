from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire.collector_comparison import (
    collector_session_delta,
    summarize_collector_session,
)
from bluefire.collectors import (
    CollectionRequest,
    CollectionSession,
    CollectorError,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
    LoopbackReceiverCollector,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord


def _summary(*, session_hash: str, observation_count: int) -> dict[str, Any]:
    return {
        "settings_hash": "sha256:" + "1" * 64,
        "session_hash": session_hash,
        "enabled_collectors": ["collector.filesystem.sandbox.v1"],
        "disabled_collectors": [],
        "health": {
            "collector.filesystem.sandbox.v1": {
                "readiness": "ready",
                "health_hash": "sha256:" + "2" * 64,
                "record_count": 1,
            }
        },
        "observation_count": observation_count,
    }


def test_delta_marks_verified_session_evidence_change() -> None:
    baseline = _summary(session_hash="sha256:" + "3" * 64, observation_count=1)
    candidate = _summary(session_hash="sha256:" + "4" * 64, observation_count=1)

    delta = collector_session_delta(baseline, candidate)

    assert delta["changed"] is True
    assert delta["session_changed"] is True
    assert delta["settings_changed"] is False
    assert delta["health_changed"] == []
    assert delta["observation_delta"] == 0
    assert delta["from_session_hash"] == baseline["session_hash"]
    assert delta["to_session_hash"] == candidate["session_hash"]


def test_delta_marks_observation_count_change_independently() -> None:
    summary = _summary(session_hash="sha256:" + "3" * 64, observation_count=1)
    candidate = {**summary, "observation_count": 2}

    delta = collector_session_delta(summary, candidate)

    assert delta["changed"] is True
    assert delta["session_changed"] is False
    assert delta["settings_changed"] is False
    assert delta["health_changed"] == []
    assert delta["observation_delta"] == 1


def test_delta_remains_unchanged_for_identical_summaries() -> None:
    summary = _summary(session_hash="sha256:" + "3" * 64, observation_count=1)

    delta = collector_session_delta(summary, dict(summary))

    assert delta["changed"] is False
    assert delta["session_changed"] is False
    assert delta["observation_delta"] == 0


def _session_bundle(
    tmp_path: Path,
    *,
    scheduled_step: str = "stage_records",
    request_overrides: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], EvidenceRecord]:
    run_id = "run-collector-comparison"
    step_id = "stage_records"
    behavior_id = "collection.independent-observation.v1"
    action_id = "sandbox.collection.stage.v1"
    profile_id = "profile.test.v1"
    target_scope_ref = f"runner-profile:{profile_id}"
    parent = EvidenceRecord.create(
        run_id=run_id,
        step_id=step_id,
        behavior_id=behavior_id,
        action_id=action_id,
        provenance=EvidenceProvenance.EXECUTED,
        producer="bluefire-rust-runner",
        runner_profile_id=profile_id,
        target_scope_ref=target_scope_ref,
        content={"runner_status": "success"},
    )
    observed = tmp_path / "observed.txt"
    observed.write_text("observed", encoding="utf-8")
    settings = CollectorRuntimeSettings(
        collectors={
            FilesystemCollector.descriptor.id: {
                "enabled": True,
                "settings": {
                    "collect_after_step": scheduled_step,
                    "paths": [observed.name],
                },
            },
            LoopbackReceiverCollector.descriptor.id: {
                "enabled": False,
                "settings": {},
            },
        }
    )
    request_values: dict[str, Any] = {
        "run_id": run_id,
        "step_id": step_id,
        "behavior_id": behavior_id,
        "action_id": action_id,
        "runner_profile_id": profile_id,
        "target_scope_ref": target_scope_ref,
        "parent_evidence_ids": (parent.evidence_id,),
    }
    request_values.update(request_overrides or {})
    session = CollectorRegistry((FilesystemCollector(tmp_path),)).collect_configured(
        settings,
        CollectionRequest(**request_values),
    )
    collector_records = [record for result in session.results.values() for record in result.records]
    evidence = [parent.to_dict(), *(record.to_dict() for record in collector_records)]
    step = {
        "step_id": step_id,
        "behavior_id": behavior_id,
        "action_id": action_id,
        "policy": {
            "step_id": step_id,
            "behavior_id": behavior_id,
            "action_id": action_id,
            "runner_profile_id": profile_id,
        },
        "evidence_ids": [parent.evidence_id, *(record.evidence_id for record in collector_records)],
    }
    return session.to_dict(), evidence, [step], parent


def test_summary_verifies_exact_session_step_and_parent_lineage(tmp_path: Path) -> None:
    session, evidence, steps, _parent = _session_bundle(tmp_path)

    summary = summarize_collector_session(
        session,
        evidence,
        "run-collector-comparison",
        steps,
    )

    assert summary["state"] == "verified"
    assert summary["observation_count"] == 1


def test_summary_rejects_session_record_without_step_membership(tmp_path: Path) -> None:
    session, evidence, steps, parent = _session_bundle(tmp_path)
    steps[0]["evidence_ids"] = [parent.evidence_id]

    with pytest.raises(CollectorError, match="step evidence membership"):
        summarize_collector_session(
            session,
            evidence,
            "run-collector-comparison",
            steps,
        )


def test_summary_rejects_session_record_at_unscheduled_step(tmp_path: Path) -> None:
    session, evidence, steps, _parent = _session_bundle(
        tmp_path,
        scheduled_step="different_step",
    )

    with pytest.raises(CollectorError, match="scheduled step"):
        summarize_collector_session(
            session,
            evidence,
            "run-collector-comparison",
            steps,
        )


@pytest.mark.parametrize(
    ("request_overrides", "message"),
    (
        ({"action_id": "sandbox.cleanup.v1"}, "persisted step"),
        (
            {
                "runner_profile_id": "profile.other.v1",
                "target_scope_ref": "runner-profile:profile.other.v1",
            },
            "scheduled policy profile",
        ),
        ({"parent_evidence_ids": ()}, "exact parent lineage"),
    ),
)
def test_summary_rejects_semantically_rehashed_lineage_tampering(
    tmp_path: Path,
    request_overrides: dict[str, Any],
    message: str,
) -> None:
    session, evidence, steps, _parent = _session_bundle(
        tmp_path,
        request_overrides=request_overrides,
    )

    with pytest.raises(CollectorError, match=message):
        summarize_collector_session(
            session,
            evidence,
            "run-collector-comparison",
            steps,
        )


def test_summary_rejects_semantically_rehashed_target_scope_tampering(
    tmp_path: Path,
) -> None:
    document, evidence, steps, _parent = _session_bundle(tmp_path)
    session = CollectionSession.from_mapping(document)
    collector_id, result = next(iter(session.results.items()))
    original = result.records[0]
    altered = EvidenceRecord.create(
        run_id=original.run_id,
        step_id=original.step_id,
        behavior_id=original.behavior_id,
        action_id=original.action_id,
        provenance=original.provenance,
        producer=original.producer,
        runner_profile_id=original.runner_profile_id,
        environment=original.environment,
        timestamp=original.timestamp,
        parent_evidence_ids=original.parent_evidence_ids,
        content=original.content,
        confidence=original.confidence,
        limitations=original.limitations,
        target_scope_ref="runner-profile:profile.other.v1",
    )
    altered_session = CollectionSession(
        settings=session.settings,
        results={collector_id: replace(result, records=(altered,))},
    )
    evidence[1] = altered.to_dict()
    steps[0]["evidence_ids"][1] = altered.evidence_id

    with pytest.raises(CollectorError, match="scheduled target scope"):
        summarize_collector_session(
            altered_session.to_dict(),
            evidence,
            "run-collector-comparison",
            steps,
        )


def test_summary_rejects_evidence_from_configured_disabled_collector(
    tmp_path: Path,
) -> None:
    session, evidence, steps, parent = _session_bundle(tmp_path)
    disabled = EvidenceRecord.create(
        run_id=parent.run_id,
        step_id=parent.step_id,
        behavior_id=parent.behavior_id,
        action_id=parent.action_id,
        provenance=EvidenceProvenance.UNKNOWN,
        producer=LoopbackReceiverCollector.descriptor.id,
        runner_profile_id=parent.runner_profile_id,
        target_scope_ref=parent.target_scope_ref,
        parent_evidence_ids=(parent.evidence_id,),
        content={"artifact_type": "evidence_gap", "reason": "tampered"},
    )
    evidence.append(disabled.to_dict())
    steps[0]["evidence_ids"].append(disabled.evidence_id)

    with pytest.raises(CollectorError, match="disabled collector"):
        summarize_collector_session(
            session,
            evidence,
            "run-collector-comparison",
            steps,
        )
