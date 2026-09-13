"""Explicit per-producer filesystem scheduling under immutable managed settings."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from .collectors import (
    CollectionRequest,
    CollectionResult,
    CollectionSession,
    CollectorError,
    CollectorRegistry,
    CollectorRuntimeSettings,
    FilesystemCollector,
)
from .evidence import EvidenceProvenance, EvidenceRecord

FILESYSTEM_ID = FilesystemCollector.descriptor.id
AFTER_EACH_PRODUCER = "after_each_producer"


def uses_producer_schedule(settings: Mapping[str, Any]) -> bool:
    return settings.get("schedule") == AFTER_EACH_PRODUCER


def producer_settings(runtime: CollectorRuntimeSettings | None) -> CollectorRuntimeSettings | None:
    if runtime is None:
        return None
    row = runtime.collectors.get(FILESYSTEM_ID)
    if row is None or not row["enabled"] or not uses_producer_schedule(row["settings"]):
        return None
    return CollectorRuntimeSettings(
        collectors={FILESYSTEM_ID: runtime.to_dict()["collectors"][FILESYSTEM_ID]}
    )


def scheduled_settings(runtime: CollectorRuntimeSettings | None) -> CollectorRuntimeSettings | None:
    if producer_settings(runtime) is None:
        return runtime
    assert runtime is not None
    return CollectorRuntimeSettings(
        collectors={
            key: {
                "enabled": False if key == FILESYSTEM_ID else row["enabled"],
                "settings": row["settings"],
            }
            for key, row in runtime.to_dict()["collectors"].items()
        }
    )


def produced_paths(
    runtime: CollectorRuntimeSettings | None, execution: EvidenceRecord
) -> tuple[str, ...]:
    """Intersect approved paths with declarations emitted by the reviewed adapter.

    The caller supplies the newly created execution record, never uploaded evidence
    or runner output. No paths are inferred from the output artifact or file content.
    """
    settings = producer_settings(runtime)
    if (
        settings is None
        or execution.producer != "bluefire-rust-runner"
        or execution.provenance is not EvidenceProvenance.EXECUTED
        or execution.content.get("runner_status") not in {"success", "partial"}
    ):
        return ()
    allowed = settings.collectors[FILESYSTEM_ID]["settings"]["paths"]
    return tuple(
        dict.fromkeys(
            path
            for path in execution.content.get("expected_observable_paths", ())
            if path in allowed
        )
    )


def collect_produced_files(
    registry: CollectorRegistry,
    runtime: CollectorRuntimeSettings,
    execution: EvidenceRecord,
    *,
    sandbox: Path,
    authority: Mapping[str, Any],
    timeout_seconds: float,
) -> CollectionSession | None:
    paths = produced_paths(runtime, execution)
    if not paths:
        return None
    if execution.runner_profile_id is None:
        raise CollectorError("producer observation has no runner profile identity")
    settings = producer_settings(runtime)
    assert settings is not None
    if registry.authority_snapshot(runtime, expected_sandbox=sandbox) != authority:
        raise CollectorError("collector registry authority changed before producer observation")
    result = registry.collect(
        FILESYSTEM_ID,
        CollectionRequest(
            run_id=execution.run_id,
            step_id=execution.step_id,
            behavior_id=execution.behavior_id,
            action_id=execution.action_id,
            runner_profile_id=execution.runner_profile_id,
            target_scope_ref=execution.target_scope_ref,
            parent_evidence_ids=(execution.evidence_id,),
            settings={"paths": paths},
            timeout_seconds=timeout_seconds,
        ),
    )
    if not result.records or any(
        record.run_id != execution.run_id
        or record.step_id != execution.step_id
        or record.parent_evidence_ids != (execution.evidence_id,)
        for record in result.records
    ):
        raise CollectorError("producer collector evidence lineage is invalid")
    return CollectionSession(settings=settings, results={FILESYSTEM_ID: result})


def combine_sessions(
    runtime: CollectorRuntimeSettings,
    scheduled: CollectionSession | None,
    producer: CollectionSession | None,
    registry: CollectorRegistry,
    *,
    allow_partial: bool = False,
) -> CollectionSession:
    """Persist real phase results under the exact original approved settings."""
    expected_scheduled = scheduled_settings(runtime)
    expected_producer = producer_settings(runtime)
    if expected_producer is None:
        if scheduled is None or scheduled.settings != runtime:
            raise CollectorError("scheduled collection settings are incomplete")
        return scheduled
    results: dict[str, CollectionResult] = {}
    if scheduled is not None:
        if scheduled.settings != expected_scheduled:
            raise CollectorError("scheduled collection settings changed")
        results.update(scheduled.results)
    elif expected_scheduled is not None and any(
        row["enabled"] for row in expected_scheduled.collectors.values()
    ):
        if not allow_partial:
            raise CollectorError("configured collector schedule was not reached")
        for key, row in expected_scheduled.collectors.items():
            if row["enabled"]:
                results[key] = _not_triggered_result(registry, key)
    if producer is not None:
        if producer.settings != expected_producer:
            raise CollectorError("producer collection settings changed")
        results.update(producer.results)
    else:
        # Availability is checked independently; zero records explicitly means
        # no configured producer was reached, never a successful observation.
        results[FILESYSTEM_ID] = _not_triggered_result(registry, FILESYSTEM_ID)
    return CollectionSession(settings=runtime, results=results)


def _not_triggered_result(registry: CollectorRegistry, collector_id: str) -> CollectionResult:
    descriptor = next(row for row in registry.descriptors() if row.id == collector_id)
    health = next(row for row in registry.health() if row.collector_id == collector_id)
    return CollectionResult(
        descriptor=descriptor,
        health=replace(
            health,
            summary="Configured observation schedule was not triggered",
            details={**health.details, "schedule_state": "not_triggered", "observation_count": 0},
        ),
        records=(),
        elapsed_ms=0,
        limitations=(
            "Backend availability is reported separately; this result contains no observations.",
        ),
    )
