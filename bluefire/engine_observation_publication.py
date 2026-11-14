"""Atomic RunStore publication for controller-observed engine evidence.

This boundary accepts only already controller-attested independent observations.
It never interprets engine output, creates an observation from an engine assertion,
or writes ProductStore state.  A caller may pass the returned tuple into an
``EngineRuntimeSettlement`` only after this module has atomically published the
complete run and verified every record byte-for-byte through the ordinary
finalized-run projection check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .engine_attempt_contract import AttemptState, EngineAttemptRecord
from .engine_experiment import IndependentObservationRecord
from .engine_experiment_projection import verify_finalized_independent_observation
from .evidence import EvidenceProvenance
from .run_store import RunStore
from .tenant_record_experiment_controller import tenant_target_snapshot_ref
from .tenant_record_observer import checked_observation_content
from .util import canonical_json_bytes, content_hash, json_clone, parse_iso8601_datetime

_MAX_OBSERVATIONS = 256
_MAX_OBSERVATION_BYTES = 4 * 1024 * 1024


class EngineObservationPublicationError(ValueError):
    """A controller observation run could not be published and verified safely."""


@dataclass(frozen=True, slots=True)
class _FinalizedRunSource:
    run_id: str
    document: Mapping[str, Any] = field(repr=False)

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]:
        if run_id != self.run_id or require_finalized is not True:
            raise EngineObservationPublicationError(
                "finalized observation run identity is unavailable"
            )
        value = json_clone(self.document)
        if not isinstance(value, dict):
            raise EngineObservationPublicationError(
                "finalized observation run identity is unavailable"
            )
        return value


def publish_finalized_engine_observations(
    *,
    store: RunStore,
    record: EngineAttemptRecord,
    observations: tuple[IndependentObservationRecord, ...],
    finalized_at: str,
) -> tuple[IndependentObservationRecord, ...]:
    """Publish and verify one attempt's complete independent-observation run.

    The run identifier and all security-relevant scope come from the immutable
    attempt binding.  Publication is deterministic, so an exact retry reopens
    the same bundle while a partial or conflicting run remains untouched and is
    refused.  The function returns no partial result: every observation must be
    present byte-for-byte in the finalized bundle before the tuple is released.
    """

    try:
        return _publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=observations,
            finalized_at=finalized_at,
        )
    except EngineObservationPublicationError:
        raise
    except Exception:
        # Filesystem paths, target values, and nested exception prose must not
        # cross this controller boundary.
        raise EngineObservationPublicationError(
            "engine observation publication failed safely"
        ) from None


def _publish_finalized_engine_observations(
    *,
    store: RunStore,
    record: EngineAttemptRecord,
    observations: tuple[IndependentObservationRecord, ...],
    finalized_at: str,
) -> tuple[IndependentObservationRecord, ...]:
    if not isinstance(store, RunStore) or not isinstance(record, EngineAttemptRecord):
        raise EngineObservationPublicationError("observation publication input is invalid")
    checked_record = EngineAttemptRecord.from_mapping(record.to_dict())
    checked_binding = checked_record.binding
    if type(observations) is not tuple or not 1 <= len(observations) <= _MAX_OBSERVATIONS:
        raise EngineObservationPublicationError("observation publication count is invalid")

    created = _canonical_timestamp(checked_binding.created_at)
    finalized = _canonical_timestamp(finalized_at)
    created_time = parse_iso8601_datetime(created)
    finalized_time = parse_iso8601_datetime(finalized)
    if (
        checked_record.state
        not in {
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.CANCELLED,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }
        or checked_record.started_at is None
        or checked_record.ended_at is None
    ):
        raise EngineObservationPublicationError(
            "observation publication requires a terminal started attempt"
        )
    started_time = parse_iso8601_datetime(checked_record.started_at)
    ended_time = parse_iso8601_datetime(checked_record.ended_at)
    if not created_time <= started_time <= ended_time <= finalized_time:
        raise EngineObservationPublicationError("observation publication time is invalid")

    checked: list[IndependentObservationRecord] = []
    identities: set[str] = set()
    for observation in observations:
        if not isinstance(observation, IndependentObservationRecord):
            raise EngineObservationPublicationError(
                "observation publication requires controller-attested evidence"
            )
        observation.validate()
        evidence = observation.evidence
        content = checked_observation_content(evidence)
        environment = json_clone(evidence.environment)
        expected_target_snapshot = tenant_target_snapshot_ref(
            fixture_digest=environment["fixture_digest"],
            target_snapshot_id=content["target_snapshot_id"],
            service_generation=content["service_generation"],
        )
        observed_at = parse_iso8601_datetime(evidence.timestamp)
        if (
            observation.attempt_id != checked_binding.attempt_id
            or observation.check_id is not None
            or observation.check_input_digest is not None
            or observation.target_snapshot_ref != checked_binding.target_snapshot_ref
            or observation.target_snapshot_ref != expected_target_snapshot
            or evidence.run_id != checked_binding.run_id
            or evidence.target_scope_ref != checked_binding.scope_ref
            or evidence.provenance is not EvidenceProvenance.OBSERVED
            or evidence.content.get("independent_observation") is not True
            or evidence.content.get("engine_assertion") is not False
            or observed_at < started_time
            or observed_at > ended_time
        ):
            raise EngineObservationPublicationError(
                "observation publication differs from its exact attempt binding"
            )
        if evidence.evidence_id in identities:
            raise EngineObservationPublicationError(
                "observation publication repeats an evidence identity"
            )
        identities.add(evidence.evidence_id)
        checked.append(observation)

    ordered = tuple(
        sorted(
            checked,
            key=lambda item: (
                parse_iso8601_datetime(item.evidence.timestamp),
                item.evidence.evidence_id,
            ),
        )
    )
    evidence_rows = [item.evidence.to_dict() for item in ordered]
    if len(canonical_json_bytes(evidence_rows)) > _MAX_OBSERVATION_BYTES:
        raise EngineObservationPublicationError(
            "observation publication exceeds its reviewed byte bound"
        )

    observation_receipts = [item.controller_receipt_digest for item in ordered]
    evidence_digest = content_hash(evidence_rows)
    store.publish_finalized_run(
        checked_binding.run_id,
        created_at=created,
        finalized_at=finalized,
        scenario={
            "schema_version": "bluefire.engine-observation-scenario.v1",
            "experiment_id": checked_binding.experiment_id,
            "attempt_id": checked_binding.attempt_id,
            "objective_ref": checked_binding.objective_ref,
            "environment_ref": checked_binding.environment_ref,
            "target_snapshot_ref": checked_binding.target_snapshot_ref,
            "scope_ref": checked_binding.scope_ref,
        },
        plan={
            "schema_version": "bluefire.engine-observation-plan.v1",
            "attempt_id": checked_binding.attempt_id,
            "binding_digest": checked_binding.binding_digest,
            "observation_receipts": observation_receipts,
        },
        policy={
            "schema_version": "bluefire.engine-observation-policy.v1",
            "required_provenance": EvidenceProvenance.OBSERVED.value,
            "engine_assertions_admitted": False,
            "target_snapshot_ref": checked_binding.target_snapshot_ref,
            "scope_ref": checked_binding.scope_ref,
        },
        profile={
            "schema_version": "bluefire.engine-observation-profile.v1",
            "controller_attested": True,
            "observation_count": len(ordered),
        },
        result={
            "schema_version": "bluefire.engine-observation-result.v1",
            "status": "completed",
            "experiment_id": checked_binding.experiment_id,
            "attempt_id": checked_binding.attempt_id,
            "binding_digest": checked_binding.binding_digest,
            "attempt_state": checked_record.state.value,
            "attempt_started_at": checked_record.started_at,
            "attempt_ended_at": checked_record.ended_at,
            "target_snapshot_ref": checked_binding.target_snapshot_ref,
            "scope_ref": checked_binding.scope_ref,
            "observation_count": len(ordered),
            "observation_evidence_digest": evidence_digest,
        },
        evidence=evidence_rows,
        detections=(),
        replay={
            "schema_version": "bluefire.engine-observation-replay.v1",
            "kind": "controller_observation_publication",
            "attempt_id": checked_binding.attempt_id,
            "binding_digest": checked_binding.binding_digest,
            "observation_evidence_digest": evidence_digest,
        },
    )

    reopened = store.get_run(checked_binding.run_id, require_finalized=True)
    source = _FinalizedRunSource(checked_binding.run_id, reopened)
    for observation in ordered:
        verify_finalized_independent_observation(observation, source)
    return ordered


def _canonical_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 40:
        raise EngineObservationPublicationError("observation publication time is invalid")
    try:
        parsed = parse_iso8601_datetime(value)
    except ValueError:
        raise EngineObservationPublicationError("observation publication time is invalid") from None
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise EngineObservationPublicationError("observation publication time is invalid")
    return value
