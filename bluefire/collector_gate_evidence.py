"""Shared strict evidence primitives for the collector acceptance validator."""

from __future__ import annotations

from typing import Any, Mapping

from .collectors import (
    CollectionSession,
    FilesystemCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
)
from .evidence import EvidenceProvenance, EvidenceRecord


class CollectorGateValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectorGateValidationError(message)


def _replay_collector_delta_valid(
    delta: Mapping[str, Any], baseline: CollectionSession, replay: CollectionSession
) -> bool:
    """Require the exact observations on the frontier and successful replay paths."""
    filesystem = FilesystemCollector.descriptor.id
    process = NativeProcessCollector.descriptor.id
    network = LoopbackReceiverCollector.descriptor.id
    for session, expected in (
        (baseline, {filesystem: 4, process: 1}),
        (replay, {filesystem: 3, process: 1, network: 1}),
    ):
        if set(session.results) != set(expected) or any(
            len(session.results[collector_id].records) != count
            or any(
                record.provenance is not EvidenceProvenance.OBSERVED
                for record in session.results[collector_id].records
            )
            for collector_id, count in expected.items()
        ):
            return False
    collector_delta = delta.get("collector_session_delta")
    if not isinstance(collector_delta, Mapping):
        return False
    # Replay adds a receiver observation but skips the baseline's fallback export.
    # Both have five observations; exact collector membership still must change.
    return (
        delta.get("collector_session_changed") is True
        and collector_delta.get("settings_changed") is True
        and collector_delta.get("session_changed") is True
        and collector_delta.get("collectors_enabled") == [network]
        and collector_delta.get("collectors_disabled") == []
        and type(collector_delta.get("observation_delta")) is int
        and collector_delta["observation_delta"] == 0
        and delta.get("replay_lineage_changed") is True
    )


def _observed(session: CollectionSession, collector_id: str) -> tuple[EvidenceRecord, ...]:
    result = session.results.get(collector_id)
    if result is None:
        raise CollectorGateValidationError(f"GATE-05 result is absent for {collector_id}")
    return tuple(
        record for record in result.records if record.provenance is EvidenceProvenance.OBSERVED
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _run_steps(run: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    raw_steps = run.get("steps")
    if not isinstance(raw_steps, list):
        raise CollectorGateValidationError("GATE-05 run steps are absent")
    valid_steps = [
        step
        for step in raw_steps
        if isinstance(step, Mapping) and isinstance(step.get("step_id"), str)
    ]
    steps = {str(step["step_id"]): step for step in valid_steps}
    _require(
        len(valid_steps) == len(raw_steps) == len(steps),
        "GATE-05 run steps are invalid or duplicated",
    )
    return steps


def _one_observation(
    session: CollectionSession, collector_id: str, *, path: str | None = None
) -> EvidenceRecord:
    result = session.results.get(collector_id)
    observed = _observed(session, collector_id)
    if path is not None:
        observed = tuple(record for record in observed if record.content.get("path") == path)
    _require(
        result is not None
        and result.health.readiness.value == "ready"
        and (path is not None or len(result.records) == 1)
        and len(observed) == 1,
        f"GATE-05 collector {collector_id} did not produce one healthy observation",
    )
    return observed[0]


def _validate_collection_lineage(
    record: EvidenceRecord,
    records_by_id: Mapping[str, EvidenceRecord],
    steps: Mapping[str, Mapping[str, Any]],
    *,
    require_executed: bool = False,
) -> tuple[EvidenceRecord, Mapping[str, Any]]:
    parent = (
        records_by_id.get(record.parent_evidence_ids[0])
        if len(record.parent_evidence_ids) == 1
        else None
    )
    step = steps.get(record.step_id)
    step_evidence_ids = step.get("evidence_ids") if isinstance(step, Mapping) else None
    _require(
        parent is not None
        and (
            (
                parent.producer == "bluefire-rust-runner"
                and parent.provenance is EvidenceProvenance.EXECUTED
            )
            or (
                not require_executed
                and parent.producer == "policy-engine.v1"
                and parent.provenance is EvidenceProvenance.CONTROL_BLOCKED
            )
        )
        and parent.run_id == record.run_id
        and parent.step_id == record.step_id
        and parent.behavior_id == record.behavior_id
        and parent.action_id == record.action_id
        and parent.runner_profile_id == record.runner_profile_id
        and parent.target_scope_ref == record.target_scope_ref
        and isinstance(step, Mapping)
        and step.get("behavior_id") == record.behavior_id
        and step.get("action_id") == record.action_id
        and isinstance(step_evidence_ids, list)
        and all(isinstance(item, str) for item in step_evidence_ids)
        and len(step_evidence_ids) == len(set(step_evidence_ids))
        and parent.evidence_id in step_evidence_ids
        and record.evidence_id in step_evidence_ids,
        "GATE-05 collector observation is not bound to its scheduled action evidence",
    )
    assert parent is not None
    assert isinstance(step, Mapping)
    return parent, step
