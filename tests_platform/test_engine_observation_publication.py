from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import bluefire.engine_observation_publication as publication_module
from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
)
from bluefire.engine_experiment import _controller_observation_record
from bluefire.engine_observation_publication import (
    EngineObservationPublicationError,
    publish_finalized_engine_observations,
)
from bluefire.evidence import EvidenceRecord
from bluefire.run_store import RunStore, RunStoreError
from bluefire.tenant_record_experiment_controller import TenantEngineObservation
from bluefire.tenant_record_observer import checked_observation_content
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import _tenant_observation

ATTEMPT_ID = "engine-attempt-" + "1" * 32
RUN_ID = "run-20261104T120000Z-" + "2" * 16
CREATED_AT = "2026-11-04T12:00:00Z"
FINALIZED_AT = "2026-11-04T12:04:00Z"


def _digest(label: str) -> str:
    return content_hash({"label": label})


def _observation(
    *,
    timestamp: str = "2026-11-04T12:03:30Z",
    attempt_id: str = ATTEMPT_ID,
    run_id: str = RUN_ID,
):
    evidence = _tenant_observation(
        owner_id=attempt_id,
        run_id=run_id,
        timestamp=timestamp,
        hardened=True,
    )
    content = checked_observation_content(evidence)
    observed = TenantEngineObservation(
        role=AttemptRole.ADAPTIVE_SEARCH,
        attempt_id=attempt_id,
        run_id=run_id,
        evidence=evidence,
        assessment=str(content["assessment"]),
        target_snapshot_id=str(content["target_snapshot_id"]),
        failure_mechanism=None,
    )
    return observed.independent_observation(), observed.target_snapshot_ref


def _binding(*, target_snapshot_ref: str, **changes: Any) -> EngineAttemptBinding:
    values: dict[str, Any] = {
        "schema_version": "bluefire.engine-attempt-binding.v1",
        "experiment_id": "experiment-" + "3" * 32,
        "attempt_id": ATTEMPT_ID,
        "run_id": RUN_ID,
        "role": "adaptive_search",
        "objective_ref": _digest("objective"),
        "environment_ref": _digest("environment"),
        "target_snapshot_ref": target_snapshot_ref,
        "scope_ref": _observation()[0].evidence.target_scope_ref,
        "scope_version": "owned-lab.v1",
        "engine_id": "strix",
        "engine_version": "1.7.0",
        "engine_revision": "a" * 40,
        "engine_package_digest": _digest("engine-package"),
        "policy_overlay_digest": _digest("policy-overlay"),
        "model_provider": "controlled-provider",
        "model_id": "controlled-model",
        "model_data_destination": "owned test gateway",
        "model_authorization_ref": _digest("model-authorization"),
        "wall_clock_seconds": 600,
        "action_limit": 24,
        "cost_limit_microunits": 0,
        "artifact_byte_limit": 1_048_576,
        "created_at": CREATED_AT,
        "parent_attempt_id": "engine-attempt-" + "4" * 32,
    }
    values.update(changes)
    return EngineAttemptBinding.from_mapping(values)


def _case(tmp_path: Path):
    observation, snapshot = _observation()
    binding = _binding(target_snapshot_ref=snapshot)
    return RunStore(tmp_path / "runs"), _record(binding), observation


def _record(
    binding: EngineAttemptBinding,
    *,
    started_at: str = "2026-11-04T12:02:00Z",
    ended_at: str = "2026-11-04T12:03:45Z",
) -> EngineAttemptRecord:
    queued = EngineAttemptRecord.create(binding)
    preflight = queued.transition(AttemptState.PREFLIGHT)
    running = preflight.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-observation-publication",
        timestamp=started_at,
    )
    return running.transition(
        AttemptState.COMPLETED,
        timestamp=ended_at,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )


def _bundle_bytes(store: RunStore) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in sorted((store.root / RUN_ID).iterdir(), key=lambda item: item.name)
    }


def test_publishes_complete_run_then_releases_exact_verified_tuple(tmp_path: Path) -> None:
    store, record, observation = _case(tmp_path)
    binding = record.binding

    result = publish_finalized_engine_observations(
        store=store,
        record=record,
        observations=(observation,),
        finalized_at=FINALIZED_AT,
    )

    assert result == (observation,)
    run = store.get_run(RUN_ID, require_finalized=True)
    assert run["run_id"] == RUN_ID
    assert run["scenario"] == {
        "schema_version": "bluefire.engine-observation-scenario.v1",
        "experiment_id": binding.experiment_id,
        "attempt_id": binding.attempt_id,
        "objective_ref": binding.objective_ref,
        "environment_ref": binding.environment_ref,
        "target_snapshot_ref": binding.target_snapshot_ref,
        "scope_ref": binding.scope_ref,
    }
    assert run["observation_count"] == 1
    assert run["evidence"]["records"] == [observation.evidence.to_dict()]
    assert run["detections"]["candidates"] == []
    assert [item["event_type"] for item in run["events"]] == [
        "run.created",
        "run.finalized",
    ]
    combined = b"".join(_bundle_bytes(store).values())
    assert b"controlled-model" not in combined
    assert b"owned test gateway" not in combined


def test_reversed_exact_retry_is_byte_identical_and_deterministically_ordered(
    tmp_path: Path,
) -> None:
    first, snapshot = _observation(timestamp="2026-11-04T12:03:00.5Z")
    second, second_snapshot = _observation(timestamp="2026-11-04T12:03:00Z")
    assert second_snapshot == snapshot
    store = RunStore(tmp_path / "runs")
    binding = _binding(target_snapshot_ref=snapshot)
    record = _record(binding)

    expected = publish_finalized_engine_observations(
        store=store,
        record=record,
        observations=(first, second),
        finalized_at=FINALIZED_AT,
    )
    before = _bundle_bytes(store)
    retried = publish_finalized_engine_observations(
        store=store,
        record=record,
        observations=(second, first),
        finalized_at=FINALIZED_AT,
    )

    assert expected == retried == (second, first)
    assert _bundle_bytes(store) == before


def test_conflicting_retry_refuses_without_replacing_original_bundle(tmp_path: Path) -> None:
    store, record, observation = _case(tmp_path)
    binding = record.binding
    publish_finalized_engine_observations(
        store=store,
        record=record,
        observations=(observation,),
        finalized_at=FINALIZED_AT,
    )
    before = _bundle_bytes(store)
    changed, snapshot = _observation(timestamp="2026-11-04T12:03:31Z")
    assert snapshot == binding.target_snapshot_ref

    with pytest.raises(EngineObservationPublicationError, match="failed safely"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(changed,),
            finalized_at=FINALIZED_AT,
        )

    assert _bundle_bytes(store) == before


def test_partial_existing_run_is_preserved_and_never_adopted(tmp_path: Path) -> None:
    store, record, observation = _case(tmp_path)
    partial = store.root / RUN_ID
    partial.mkdir(mode=0o700)
    marker = partial / "private-marker.txt"
    marker.write_text("retain me", encoding="utf-8")

    with pytest.raises(EngineObservationPublicationError, match="failed safely"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert marker.read_text(encoding="utf-8") == "retain me"
    assert sorted(path.name for path in partial.iterdir()) == ["private-marker.txt"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt_id", "engine-attempt-" + "5" * 32),
        ("run_id", "run-20261104T120000Z-" + "6" * 16),
        ("target_snapshot_ref", _digest("other-snapshot")),
        ("scope_ref", _digest("other-scope")),
    ],
)
def test_rejects_observation_that_differs_from_exact_binding(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    store, record, observation = _case(tmp_path)
    binding = EngineAttemptBinding.from_mapping({**record.binding.to_dict(), field: value})
    changed_record = _record(binding)

    with pytest.raises(EngineObservationPublicationError, match="exact attempt binding"):
        publish_finalized_engine_observations(
            store=store,
            record=changed_record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert not (store.root / binding.run_id).exists()


def test_rejects_raw_or_unattested_evidence_instead_of_upgrading_engine_output(
    tmp_path: Path,
) -> None:
    store, record, observation = _case(tmp_path)

    with pytest.raises(EngineObservationPublicationError, match="controller-attested"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation.evidence,),  # type: ignore[arg-type]
            finalized_at=FINALIZED_AT,
        )
    with pytest.raises(EngineObservationPublicationError, match="failed safely"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(replace(observation),),
            finalized_at=FINALIZED_AT,
        )


def test_rejects_controller_record_with_mismatched_environment_snapshot(tmp_path: Path) -> None:
    store, record, observation = _case(tmp_path)
    binding = record.binding
    source = observation.evidence
    changed_evidence = EvidenceRecord.create(
        run_id=source.run_id,
        step_id=source.step_id,
        behavior_id=source.behavior_id,
        action_id=source.action_id,
        provenance=source.provenance,
        producer=source.producer,
        runner_profile_id=source.runner_profile_id,
        environment={
            **source.environment,
            "fixture_digest": _digest("different-fixture"),
        },
        timestamp=source.timestamp,
        parent_evidence_ids=source.parent_evidence_ids,
        content=source.content,
        confidence=source.confidence,
        limitations=source.limitations,
        target_scope_ref=source.target_scope_ref,
    )
    forged = _controller_observation_record(
        target_snapshot_ref=binding.target_snapshot_ref,
        mechanism_ref=observation.mechanism_ref,
        attempt_id=binding.attempt_id,
        evidence=changed_evidence,
    )

    with pytest.raises(EngineObservationPublicationError, match="exact attempt binding"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(forged,),
            finalized_at=FINALIZED_AT,
        )


def test_rejects_duplicates_count_and_byte_bounds_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, record, observation = _case(tmp_path)
    with pytest.raises(EngineObservationPublicationError, match="repeats"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation, observation),
            finalized_at=FINALIZED_AT,
        )
    with pytest.raises(EngineObservationPublicationError, match="count"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,) * 257,
            finalized_at=FINALIZED_AT,
        )
    monkeypatch.setattr(publication_module, "_MAX_OBSERVATION_BYTES", 1)
    with pytest.raises(EngineObservationPublicationError, match="byte bound"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )
    assert not (store.root / RUN_ID).exists()


def test_rejects_observation_outside_binding_and_finalization_lifetime(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")
    early, snapshot = _observation(timestamp="2026-11-04T11:59:59Z")
    binding = _binding(target_snapshot_ref=snapshot)
    record = _record(binding)
    with pytest.raises(EngineObservationPublicationError, match="exact attempt binding"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(early,),
            finalized_at=FINALIZED_AT,
        )
    late, _snapshot = _observation(timestamp="2026-11-04T12:04:01Z")
    with pytest.raises(EngineObservationPublicationError, match="exact attempt binding"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(late,),
            finalized_at=FINALIZED_AT,
        )


@pytest.mark.parametrize(
    ("started_at", "ended_at"),
    [
        ("2026-11-04T12:03:31Z", "2026-11-04T12:03:45Z"),
        ("2026-11-04T12:02:00Z", "2026-11-04T12:03:29Z"),
    ],
)
def test_rejects_observation_outside_actual_attempt_lifecycle(
    tmp_path: Path,
    started_at: str,
    ended_at: str,
) -> None:
    store, record, observation = _case(tmp_path)
    changed_record = _record(
        record.binding,
        started_at=started_at,
        ended_at=ended_at,
    )

    with pytest.raises(EngineObservationPublicationError, match="exact attempt binding"):
        publish_finalized_engine_observations(
            store=store,
            record=changed_record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert not (store.root / RUN_ID).exists()


def test_rejects_nonterminal_attempt_record(tmp_path: Path) -> None:
    store, terminal, observation = _case(tmp_path)
    queued = EngineAttemptRecord.create(terminal.binding)
    running = queued.transition(AttemptState.PREFLIGHT).transition(
        AttemptState.RUNNING,
        upstream_session_id="session-observation-publication",
        timestamp="2026-11-04T12:02:00Z",
    )

    with pytest.raises(EngineObservationPublicationError, match="terminal started attempt"):
        publish_finalized_engine_observations(
            store=store,
            record=running,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert not (store.root / RUN_ID).exists()


def test_rejects_finalization_before_attempt_end(tmp_path: Path) -> None:
    store, record, observation = _case(tmp_path)

    with pytest.raises(EngineObservationPublicationError, match="time is invalid"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at="2026-11-04T12:03:44Z",
        )

    assert not (store.root / RUN_ID).exists()


@pytest.mark.parametrize("mode", ["absent", "mismatch", "unfinalized"])
def test_returns_no_observations_when_reopened_run_cannot_verify(
    tmp_path: Path,
    mode: str,
) -> None:
    class _UnverifiableRunStore(RunStore):
        def get_run(self, run_id: str, *, require_finalized: bool = False):
            value = dict(super().get_run(run_id, require_finalized=require_finalized))
            if mode == "unfinalized":
                raise RunStoreError("private path C:/secret/run is not finalized")
            envelope = dict(value["evidence"])
            records = list(envelope["records"])
            if mode == "absent":
                records = []
            else:
                records[0] = {**records[0], "producer": "forged-observer"}
            envelope["records"] = records
            value["evidence"] = envelope
            return value

    observation, snapshot = _observation()
    store = _UnverifiableRunStore(tmp_path / "runs")
    binding = _binding(target_snapshot_ref=snapshot)
    record = _record(binding)

    with pytest.raises(EngineObservationPublicationError) as failure:
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert "C:/secret" not in str(failure.value)
    assert "forged-observer" not in str(failure.value)
    assert RunStore.get_run(store, RUN_ID, require_finalized=True)["run_id"] == RUN_ID


def test_store_exception_prose_and_paths_are_sanitized(tmp_path: Path) -> None:
    class _LeakyRunStore(RunStore):
        def publish_finalized_run(self, *args, **kwargs):
            del args, kwargs
            raise RunStoreError("token=secret at C:/private/records.json")

    observation, snapshot = _observation()
    store = _LeakyRunStore(tmp_path / "runs")
    binding = _binding(target_snapshot_ref=snapshot)
    record = _record(binding)

    with pytest.raises(EngineObservationPublicationError) as failure:
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at=FINALIZED_AT,
        )

    assert str(failure.value) == "engine observation publication failed safely"
    assert failure.value.__cause__ is None


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-11-04T12:04:00+00:00",
        "2026-11-04T12:04:00.000Z",
        "not-a-time",
    ],
)
def test_requires_canonical_finalization_timestamp(tmp_path: Path, timestamp: str) -> None:
    store, record, observation = _case(tmp_path)
    with pytest.raises(EngineObservationPublicationError, match="time is invalid"):
        publish_finalized_engine_observations(
            store=store,
            record=record,
            observations=(observation,),
            finalized_at=timestamp,
        )
