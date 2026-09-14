"""Real temporary-file observations; process/receiver evidence is a contract fixture.

These tests start no process, receiver, runner, or network connection. Full native
identity and byte bindings remain the responsibility of the GATE-05 journey.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bluefire.collector_comparison import collector_session_delta, summarize_collector_session
from bluefire.collector_gate_evidence import _replay_collector_delta_valid
from bluefire.collector_journey import _runtime_settings
from bluefire.collectors import (
    CollectionRequest,
    CollectionResult,
    CollectionSession,
    CollectorHealth,
    CollectorReadiness,
    FilesystemCollector,
    LoopbackReceiverCollector,
    NativeProcessCollector,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord


def _session(tmp_path: Path, *, replay: bool) -> tuple[CollectionSession, dict[str, Any]]:
    runtime = _runtime_settings(process_id=10, parent_process_id=9, network_enabled=replay)
    run_id = "run-replay" if replay else "run-baseline"
    evidence: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    filesystem_results = []
    results = {}
    paths = (
        ("create_fixture", "sandbox.fixture.create.v1", "fixtures/input.jsonl"),
        ("transform_fixture", "sandbox.fixture.transform.v1", "fixtures/transformed.jsonl"),
        ("stage_evidence", "sandbox.collection.stage.v1", "staged/bundle.jsonl"),
        ("preserve_approved_copy", "sandbox.export.local.v1", "exports/ephemeral/bundle.bin"),
    )
    if replay:
        paths = paths[:-1]
    for step_id, action_id, path in (
        *paths,
        ("try_internal_transport", "sandbox.network.loopback.v1", None),
    ):
        payload = b"public collector comparison fixture\n"
        parent = EvidenceRecord.create(
            run_id=run_id,
            step_id=step_id,
            behavior_id=action_id,
            action_id=action_id,
            producer="bluefire-rust-runner",
            provenance=EvidenceProvenance.EXECUTED,
            runner_profile_id="profile.fixture",
            target_scope_ref="runner-profile:profile.fixture",
            content={
                "runner_status": "success",
                "expected_observable_paths": [path] if path else [],
                "output": {
                    "artifact": path,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                },
            },
        )
        request = CollectionRequest(
            run_id=run_id,
            step_id=step_id,
            behavior_id=action_id,
            action_id=action_id,
            runner_profile_id=parent.runner_profile_id,
            target_scope_ref=parent.target_scope_ref,
            parent_evidence_ids=(parent.evidence_id,),
            settings={"paths": [path]} if path else {},
        )
        if path is not None:
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            collected = FilesystemCollector(tmp_path).collect(request)
            filesystem_results.append(collected)
            observations = list(collected.records)
        else:
            observations = []
            descriptors = [NativeProcessCollector.descriptor]
            if replay:
                descriptors.append(LoopbackReceiverCollector.descriptor)
            for descriptor in descriptors:
                record = EvidenceRecord.create(
                    run_id=run_id,
                    step_id=step_id,
                    behavior_id=action_id,
                    action_id=action_id,
                    producer=descriptor.id,
                    provenance=EvidenceProvenance.OBSERVED,
                    runner_profile_id=parent.runner_profile_id,
                    target_scope_ref=parent.target_scope_ref,
                    parent_evidence_ids=(parent.evidence_id,),
                    content={"fixture": "comparison membership only"},
                )
                observations.append(record)
                results[descriptor.id] = CollectionResult(
                    descriptor=descriptor,
                    health=CollectorHealth(
                        descriptor.id,
                        CollectorReadiness.READY,
                        "Contract fixture",
                        record.timestamp,
                        {},
                    ),
                    records=(record,),
                    elapsed_ms=0,
                )
        evidence.extend(item.to_dict() for item in (parent, *observations))
        steps.append(
            {
                "step_id": step_id,
                "behavior_id": action_id,
                "action_id": action_id,
                "policy": {
                    "step_id": step_id,
                    "behavior_id": action_id,
                    "action_id": action_id,
                    "runner_profile_id": parent.runner_profile_id,
                },
                "evidence_ids": [item.evidence_id for item in (parent, *observations)],
            }
        )
    results[FilesystemCollector.descriptor.id] = replace(
        filesystem_results[-1],
        records=tuple(record for result in filesystem_results for record in result.records),
    )
    session = CollectionSession(runtime, results)
    summary = summarize_collector_session(session.to_dict(), evidence, run_id, steps)
    return session, dict(summary)


@pytest.fixture
def comparison(tmp_path):
    baseline, baseline_summary = _session(tmp_path / "baseline", replay=False)
    replay, replay_summary = _session(tmp_path / "replay", replay=True)
    assert baseline_summary["observation_count"] == replay_summary["observation_count"] == 5
    delta = collector_session_delta(baseline_summary, replay_summary)
    return (
        baseline,
        replay,
        {
            "collector_session_changed": delta["changed"],
            "collector_session_delta": delta,
            "replay_lineage_changed": True,
        },
    )


def test_receiver_replaces_export_observation_without_changing_total(comparison):
    baseline, replay, delta = comparison
    assert delta["collector_session_delta"]["observation_delta"] == 0
    assert _replay_collector_delta_valid(delta, baseline, replay)


@pytest.mark.parametrize("count", [1, -1, 99, False, None])
def test_gate_refuses_rewritten_observation_delta(comparison, count):
    baseline, replay, delta = comparison
    delta["collector_session_delta"]["observation_delta"] = count
    assert not _replay_collector_delta_valid(delta, baseline, replay)


@pytest.mark.parametrize(
    "field,value",
    [
        ("collectors_enabled", []),
        ("collectors_disabled", [FilesystemCollector.descriptor.id]),
        ("settings_changed", False),
        ("session_changed", False),
    ],
)
def test_gate_requires_exact_collector_change(comparison, field, value):
    baseline, replay, delta = comparison
    delta["collector_session_delta"][field] = value
    assert not _replay_collector_delta_valid(delta, baseline, replay)


@pytest.mark.parametrize("field", ["collector_session_changed", "replay_lineage_changed"])
def test_gate_requires_session_and_replay_lineage_change(comparison, field):
    baseline, replay, delta = comparison
    delta[field] = False
    assert not _replay_collector_delta_valid(delta, baseline, replay)


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("change", ["missing", "extra", "unknown"])
def test_zero_net_delta_does_not_hide_incomplete_or_extra_evidence(comparison, side, change):
    sessions = list(comparison[:2])
    session = sessions[side]
    results = dict(session.results)
    collector_id = FilesystemCollector.descriptor.id
    result = results[collector_id]
    if change == "missing":
        records = result.records[:-1]
    elif change == "extra":
        records = (*result.records, result.records[-1])
    else:
        records = (
            *result.records[:-1],
            replace(result.records[-1], provenance=EvidenceProvenance.UNKNOWN),
        )
    results[collector_id] = replace(result, records=records)
    sessions[side] = CollectionSession(session.settings, results)
    assert not _replay_collector_delta_valid(copy.deepcopy(comparison[2]), *sessions)
