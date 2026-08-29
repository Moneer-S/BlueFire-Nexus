"""Integrity-checked collector session summaries for run comparison."""

from __future__ import annotations

from typing import Any, Mapping

from .collectors import CollectionSession, CollectorError
from .evidence import EvidenceError, EvidenceGraph, EvidenceRecord
from .util import content_hash


def summarize_collector_session(
    value: Any,
    run_evidence: Any = None,
    expected_run_id: Any = None,
    run_steps: Any = None,
) -> Mapping[str, Any]:
    if value is None:
        return {
            "state": "not_recorded",
            "settings_hash": None,
            "session_hash": None,
            "enabled_collectors": [],
            "disabled_collectors": [],
            "health": {},
            "observation_count": 0,
        }
    if not isinstance(value, Mapping):
        raise CollectorError("run collector session is invalid")
    session = CollectionSession.from_mapping(value)
    document = session.to_dict()
    if not isinstance(expected_run_id, str) or not expected_run_id:
        raise CollectorError("run collector session has no run identity")
    if not isinstance(run_evidence, list):
        raise CollectorError("run collector evidence is unavailable")
    try:
        if not all(isinstance(row, Mapping) for row in run_evidence):
            raise CollectorError("run collector evidence contains an invalid record")
        records = tuple(EvidenceRecord.from_mapping(row) for row in run_evidence)
        graph = EvidenceGraph()
        graph.extend(records)
    except EvidenceError as exc:
        raise CollectorError(f"run collector evidence is invalid: {exc}") from exc
    if any(record.run_id != expected_run_id for record in records):
        raise CollectorError("run collector evidence belongs to a different run")
    persisted = {record.evidence_id: record for record in records}
    if len(persisted) != len(records):
        raise CollectorError("run collector evidence contains duplicate identities")
    configured_ids = set(session.settings.collectors)
    disabled_ids = {
        collector_id
        for collector_id, row in session.settings.collectors.items()
        if row["enabled"] is False
    }
    if any(record.producer in disabled_ids for record in records):
        raise CollectorError("disabled collector produced persisted run evidence")
    session_ids = {
        record.evidence_id for result in session.results.values() for record in result.records
    }
    if not session_ids:
        raise CollectorError("collector session contains no attributable evidence")
    persisted_session_ids = {
        record.evidence_id for record in records if record.producer in session.results
    }
    if session_ids != persisted_session_ids:
        raise CollectorError("collector session omits or invents persisted collector evidence")
    scheduled_step = _scheduled_step_id(session)
    memberships = _step_evidence_memberships(run_steps)
    for result in session.results.values():
        for record in result.records:
            if record.run_id != expected_run_id or persisted.get(record.evidence_id) != record:
                raise CollectorError("collector session evidence is absent from the run bundle")
            _validate_record_lineage(
                record,
                scheduled_step=scheduled_step,
                persisted=persisted,
                memberships=memberships,
                configured_ids=configured_ids,
            )
    health = {
        collector_id: {
            "readiness": result.health.readiness.value,
            "health_hash": content_hash(
                {
                    "readiness": result.health.readiness.value,
                    "summary": result.health.summary,
                    "details": dict(result.health.details),
                }
            ),
            "record_count": len(result.records),
        }
        for collector_id, result in session.results.items()
    }
    return {
        "state": "verified",
        "settings_hash": document["settings_hash"],
        "session_hash": document["session_hash"],
        "enabled_collectors": list(document["enabled_collectors"]),
        "disabled_collectors": list(document["disabled_collectors"]),
        "health": health,
        "observation_count": sum(
            1
            for result in session.results.values()
            for record in result.records
            if record.provenance.value == "observed"
        ),
    }


def _scheduled_step_id(session: CollectionSession) -> str:
    scheduled = {
        row["settings"].get("collect_after_step")
        for row in session.settings.collectors.values()
        if row["enabled"] is True
    }
    if len(scheduled) != 1:
        raise CollectorError("collector session has no exact scheduled step")
    step_id = next(iter(scheduled))
    if not isinstance(step_id, str) or not step_id or len(step_id) > 200 or "\x00" in step_id:
        raise CollectorError("collector session scheduled step is invalid")
    return step_id


def _step_evidence_memberships(
    value: Any,
) -> Mapping[str, tuple[tuple[Mapping[str, Any], tuple[str, ...]], ...]]:
    if not isinstance(value, list) or len(value) > 100_000:
        raise CollectorError("run collector step evidence is unavailable")
    memberships: dict[str, list[tuple[Mapping[str, Any], tuple[str, ...]]]] = {}
    for row in value:
        if not isinstance(row, Mapping):
            raise CollectorError("run collector step evidence contains an invalid row")
        evidence_ids = row.get("evidence_ids")
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) > 100_000
            or any(
                not isinstance(evidence_id, str)
                or not evidence_id
                or len(evidence_id) > 200
                or "\x00" in evidence_id
                for evidence_id in evidence_ids
            )
            or len(set(evidence_ids)) != len(evidence_ids)
        ):
            raise CollectorError("run collector step evidence membership is invalid")
        frozen_ids = tuple(evidence_ids)
        for evidence_id in frozen_ids:
            memberships.setdefault(evidence_id, []).append((row, frozen_ids))
    return {evidence_id: tuple(rows) for evidence_id, rows in memberships.items()}


def _validate_record_lineage(
    record: EvidenceRecord,
    *,
    scheduled_step: str,
    persisted: Mapping[str, EvidenceRecord],
    memberships: Mapping[str, tuple[tuple[Mapping[str, Any], tuple[str, ...]], ...]],
    configured_ids: set[str],
) -> None:
    if record.step_id != scheduled_step:
        raise CollectorError("collector evidence does not match its scheduled step")
    owning_rows = memberships.get(record.evidence_id, ())
    if len(owning_rows) != 1:
        raise CollectorError("collector evidence has no exact step evidence membership")
    step, evidence_ids = owning_rows[0]
    if (
        step.get("step_id") != record.step_id
        or step.get("behavior_id") != record.behavior_id
        or step.get("action_id") != record.action_id
    ):
        raise CollectorError("collector evidence does not match its persisted step")
    policy = step.get("policy")
    if not isinstance(policy, Mapping) or any(
        policy.get(field) != expected
        for field, expected in (
            ("step_id", record.step_id),
            ("behavior_id", record.behavior_id),
            ("action_id", record.action_id),
            ("runner_profile_id", record.runner_profile_id),
        )
    ):
        raise CollectorError("collector evidence does not match its scheduled policy profile")
    if (
        record.runner_profile_id is None
        or record.target_scope_ref != f"runner-profile:{record.runner_profile_id}"
    ):
        raise CollectorError("collector evidence does not match its scheduled target scope")
    if len(record.parent_evidence_ids) != 1:
        raise CollectorError("collector evidence has no exact parent lineage")
    parent_id = record.parent_evidence_ids[0]
    if not evidence_ids or evidence_ids[0] != parent_id:
        raise CollectorError("collector evidence parent is not its persisted step authority")
    parent = persisted.get(parent_id)
    if parent is None or parent.producer in configured_ids:
        raise CollectorError("collector evidence parent is not independent step evidence")
    if any(
        actual != expected
        for actual, expected in (
            (parent.run_id, record.run_id),
            (parent.step_id, record.step_id),
            (parent.behavior_id, record.behavior_id),
            (parent.action_id, record.action_id),
            (parent.runner_profile_id, record.runner_profile_id),
            (parent.target_scope_ref, record.target_scope_ref),
        )
    ):
        raise CollectorError("collector evidence does not match its persisted parent lineage")


def collector_session_delta(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> Mapping[str, Any]:
    baseline_enabled_value = baseline.get("enabled_collectors")
    candidate_enabled_value = candidate.get("enabled_collectors")
    baseline_enabled = (
        {item for item in baseline_enabled_value if isinstance(item, str)}
        if isinstance(baseline_enabled_value, list)
        else set()
    )
    candidate_enabled = (
        {item for item in candidate_enabled_value if isinstance(item, str)}
        if isinstance(candidate_enabled_value, list)
        else set()
    )
    baseline_health_value = baseline.get("health")
    candidate_health_value = candidate.get("health")
    baseline_health: Mapping[str, Any] = (
        baseline_health_value if isinstance(baseline_health_value, Mapping) else {}
    )
    candidate_health: Mapping[str, Any] = (
        candidate_health_value if isinstance(candidate_health_value, Mapping) else {}
    )
    baseline_observations = baseline.get("observation_count")
    candidate_observations = candidate.get("observation_count")
    baseline_observation_count = (
        baseline_observations
        if isinstance(baseline_observations, int) and not isinstance(baseline_observations, bool)
        else 0
    )
    candidate_observation_count = (
        candidate_observations
        if isinstance(candidate_observations, int) and not isinstance(candidate_observations, bool)
        else 0
    )
    health_ids = sorted(set(baseline_health) | set(candidate_health))
    health_changed = [
        collector_id
        for collector_id in health_ids
        if baseline_health.get(collector_id) != candidate_health.get(collector_id)
    ]
    settings_changed = baseline.get("settings_hash") != candidate.get("settings_hash")
    session_changed = baseline.get("session_hash") != candidate.get("session_hash")
    observation_delta = candidate_observation_count - baseline_observation_count
    return {
        # The session hash covers the verified collector evidence, while the
        # explicit observation delta keeps the comparison honest even for a
        # partially populated or forward-compatible summary.
        "changed": bool(settings_changed or health_changed or session_changed or observation_delta),
        "settings_changed": settings_changed,
        "session_changed": session_changed,
        "collectors_enabled": sorted(candidate_enabled - baseline_enabled),
        "collectors_disabled": sorted(baseline_enabled - candidate_enabled),
        "health_changed": health_changed,
        "observation_delta": observation_delta,
        "from_settings_hash": baseline.get("settings_hash"),
        "to_settings_hash": candidate.get("settings_hash"),
        "from_session_hash": baseline.get("session_hash"),
        "to_session_hash": candidate.get("session_hash"),
    }


__all__ = ["collector_session_delta", "summarize_collector_session"]
