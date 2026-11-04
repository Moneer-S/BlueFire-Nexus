from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import Any, Mapping

import pytest

from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptState,
    EngineEvidenceItem,
    EvidenceCategory,
)
from bluefire.engine_experiment import (
    CleanupState,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_experiment_workspace import (
    EngineExperimentSelectionNotFound,
    EngineExperimentWorkspaceError,
    checked_engine_experiment_workspace,
    present_engine_experiment_workspace,
    project_engine_experiment_workspace,
)
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import (
    BASELINE_ATTEMPT,
    INITIAL_SNAPSHOT,
    MECHANISM_REF,
    _defense,
    _digest,
    _new_experiment,
    _reserve_baseline,
    _settle_latest_attempt,
    _tenant_observation,
    build_completed_experiment,
)


class _RunSource:
    def __init__(self, experiment: EngineExperiment) -> None:
        self.documents: dict[str, Mapping[str, Any]] = {}
        run_ids = [entry.record.binding.run_id for entry in experiment.attempts] + [
            check.run_id for check in experiment.checks
        ]
        for run_id in run_ids:
            records = [
                observation.evidence.to_dict()
                for observation in experiment.independent_observations
                if observation.evidence.run_id == run_id
            ]
            self.documents[run_id] = {
                "run_id": run_id,
                "engine_summary": {
                    "claim": "ignore this untrusted engine summary",
                    "secret": "sk-this-must-never-appear",
                },
                "evidence": {"schema_version": "1.0", "records": records},
                "manifest": {"run_id": run_id},
            }

    def get_run(self, run_id: str, *, require_finalized: bool = False) -> Mapping[str, Any]:
        document = self.documents[run_id]
        if require_finalized and "manifest" not in document:
            raise ValueError("run is not finalized")
        return document


class _PresentationSource:
    def __init__(self, presentation: Mapping[str, Any]) -> None:
        self.presentation = presentation
        self.requests: list[tuple[str, int, str]] = []

    def get_engine_experiment_presentation(
        self,
        experiment_id: str,
        *,
        revision: int,
        experiment_digest: str,
    ) -> Mapping[str, Any]:
        self.requests.append((experiment_id, revision, experiment_digest))
        return copy.deepcopy(self.presentation)


class _RevisionPresentationSource:
    def __init__(self, presentations: Mapping[tuple[str, int, str], Mapping[str, Any]]) -> None:
        self.presentations = presentations
        self.requests: list[tuple[str, int, str]] = []

    def get_engine_experiment_presentation(
        self,
        experiment_id: str,
        *,
        revision: int,
        experiment_digest: str,
    ) -> Mapping[str, Any]:
        key = (experiment_id, revision, experiment_digest)
        self.requests.append(key)
        return copy.deepcopy(self.presentations[key])


def _selection(experiment: EngineExperiment, kind: str, index: int = 0) -> dict[str, Any]:
    if kind == "engine_attempt":
        entry = experiment.attempts[index]
        binding = entry.record.binding
        return {
            "kind": kind,
            "id": binding.attempt_id,
            "role": binding.role.value,
            "job_id": entry.job_id,
            "run_id": binding.run_id,
        }
    check = experiment.checks[index]
    return {
        "kind": kind,
        "id": check.check_id,
        "role": check.role.value,
        "job_id": check.job_id,
        "run_id": check.run_id,
    }


def _presentation(
    experiment: EngineExperiment,
    *,
    selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if experiment.attempts:
        binding = experiment.attempts[0].record.binding
        engine = {
            "id": binding.engine_id,
            "display_name": "Strix",
            "version": binding.engine_version,
            "revision": binding.engine_revision,
            "package_digest": binding.engine_package_digest,
            "sandbox_image_digest": _digest("b"),
        }
        model = {
            "provider": binding.model_provider,
            "id": binding.model_id,
            "data_destination": binding.model_data_destination,
            "authorization_digest": binding.model_authorization_ref,
            "test_provider": True,
        }
        limits = {
            "wall_clock_seconds": binding.wall_clock_seconds,
            "action_limit": binding.action_limit,
            "artifact_byte_limit": binding.artifact_byte_limit,
            "cost_limit_microunits": binding.cost_limit_microunits,
        }
    else:
        engine = {
            "id": "strix",
            "display_name": "Strix",
            "version": "1.7.0",
            "revision": "7" * 40,
            "package_digest": _digest("7"),
            "sandbox_image_digest": _digest("b"),
        }
        model = {
            "provider": "provider.test",
            "id": "test-model",
            "data_destination": "https://model.test/v1",
            "authorization_digest": _digest("9"),
            "test_provider": True,
        }
        limits = {
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "cost_limit_microunits": 1_000_000,
        }
    current_target = (
        None
        if experiment.current_target_snapshot_ref is None
        else {
            "snapshot_ref": experiment.current_target_snapshot_ref,
            "display_name": "Generated tenant-record target",
            "captured_at": experiment.updated_at,
        }
    )
    defense = experiment.defense_change
    defensive_change = (
        None
        if defense is None
        else {
            "change_id": defense.change_id,
            "state": defense.state.value,
            "kind": "identity",
            "summary": "Removed the generated engine identity from the fixture reader group.",
            "mechanism_ref": defense.mechanism_ref,
            "before_target_snapshot_ref": defense.before_target_snapshot_ref,
            "after_target_snapshot_ref": defense.after_target_snapshot_ref,
            "rollback_digest": defense.rollback_digest,
            "applied_at": defense.applied_at,
        }
    )
    return {
        "schema_version": "bluefire.engine-experiment-presentation.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "objective": {
            "objective_ref": experiment.objective_ref,
            "title": "Protect generated tenant records",
            "summary": "Test the original failure, apply a bounded defense, and retest it.",
        },
        "environment": {
            "environment_ref": experiment.environment_ref,
            "environment_id": "tenant-record-lab",
            "display_name": "Disposable tenant-record lab",
            "platform": "linux",
            "disposable": True,
        },
        "current_target": current_target,
        "engine_setup": {"engine": engine, "model": model},
        "authorization": {
            "scope_ref": experiment.scope_ref,
            "scope_version": experiment.scope_version,
            **limits,
        },
        "defensive_change": defensive_change,
        "selection": None if selection is None else dict(selection),
        "limitations": ["Controlled test-provider responses only."],
    }


def _unknown_defense_experiment() -> EngineExperiment:
    experiment = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=experiment.attempts[0].record.binding.run_id,
            timestamp="2026-11-04T12:03:00Z",
            hardened=False,
        ),
    )
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    )
    experiment = experiment.review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")
    return experiment.begin_defense_application(
        experiment.defense_change.change_id,  # type: ignore[union-attr]
        operation_receipt_digest=_digest("1"),
        started_at="2026-11-04T12:06:30Z",
    )


def _engine_evidence_experiment(
    *, session_id: str = "session-baseline-safe"
) -> EngineExperiment:
    experiment = _reserve_baseline(_new_experiment())
    record = experiment.attempts[0].record
    experiment = experiment.update_attempt_record(
        record.transition(AttemptState.PREFLIGHT), timestamp="2026-11-04T12:02:00Z"
    )
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id=session_id,
        timestamp="2026-11-04T12:02:00Z",
    )
    experiment = experiment.update_attempt_record(
        running, timestamp="2026-11-04T12:02:00Z"
    )
    evidence = EngineEvidenceItem.create(
        attempt_id=running.binding.attempt_id,
        run_id=running.binding.run_id,
        category=EvidenceCategory.ENGINE_ASSERTION,
        producer="strix",
        observed_at="2026-11-04T12:03:00Z",
        content={
            "summary": "engine says success from C:\\private\\report.json",
            "credential": "sk-this-must-never-appear",
        },
        source_artifact_digest=_digest("c"),
    )
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:04:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    return experiment.settle_attempt(
        completed,
        engine_evidence=(evidence,),
        artifact_manifest_ref=_digest("d"),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("e"),
        settled_at="2026-11-04T12:04:00Z",
    )


def test_projects_complete_workspace_with_exact_authority_and_digest() -> None:
    experiment = build_completed_experiment()
    presentation = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )
    source = _RunSource(experiment)

    workspace = project_engine_experiment_workspace(experiment, source, presentation)
    digest_body = copy.deepcopy(workspace)
    claimed = digest_body.pop("workspace_digest")

    assert claimed == content_hash(digest_body)
    assert workspace["projection"]["workflow_state"] == "complete"
    assert [row["execution_approval_id"] for row in workspace["projection"]["attempts"]] == [
        "approval-" + "a" * 32,
        "approval-" + "b" * 32,
    ]
    assert workspace["projection"]["attempts"][0]["delegation_digest"] != workspace[
        "authorization"
    ]["scope_ref"]
    assert workspace["actions"] == [
        {
            "kind": "open_comparison",
            "label": "Open outcome comparison",
            "enabled": True,
            "reason": "Reviews actual attempts, controller checks, unknowns, and cleanup together.",
            "primary": True,
        }
    ]
    assert workspace["selected_context"]["kind"] == "engine_attempt"
    assert workspace["selected_context"]["attempt"]["resume_supported"] is False
    assert checked_engine_experiment_workspace(
        workspace, experiment, source, presentation
    ) == workspace


def test_selected_controller_check_has_no_engine_or_model_provenance() -> None:
    experiment = build_completed_experiment()
    presentation = _presentation(
        experiment, selection=_selection(experiment, "controller_check")
    )

    workspace = project_engine_experiment_workspace(
        experiment, _RunSource(experiment), presentation
    )
    context = workspace["selected_context"]

    assert set(context) == {"kind", "check"}
    assert set(context["check"]) == {
        "check_id",
        "role",
        "job_id",
        "run_id",
        "performer",
        "mechanism_ref",
        "target_snapshot_ref",
        "input_digest",
        "result_digest",
        "state",
        "independent_evidence_refs",
        "created_at",
        "settled_at",
        "observations",
        "cleanup",
    }
    assert context["check"]["performer"] == "bluefire.controller"
    assert "engine" not in context["check"]
    assert "model" not in context["check"]
    assert context["check"]["observations"][0]["provenance"] == "control_blocked"


def test_unknown_target_is_null_and_only_reconciliation_is_actionable() -> None:
    experiment = _unknown_defense_experiment()
    presentation = _presentation(experiment)

    workspace = project_engine_experiment_workspace(
        experiment, _RunSource(experiment), presentation
    )

    assert workspace["current_target"] is None
    assert workspace["projection"]["workflow_state"] == "reconcile_defense"
    assert workspace["actions"][0]["kind"] == "reconcile_defense"
    assert workspace["actions"][0]["enabled"] is True
    assert all(action["kind"] != "apply_defense" for action in workspace["actions"])

    fabricated = copy.deepcopy(presentation)
    fabricated["current_target"] = {
        "snapshot_ref": experiment.initial_target_snapshot_ref,
        "display_name": "Fabricated current target",
        "captured_at": experiment.updated_at,
    }
    with pytest.raises(EngineExperimentWorkspaceError, match="fabricated"):
        project_engine_experiment_workspace(experiment, _RunSource(experiment), fabricated)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row.update({"extra": True}), "fields changed"),
        (
            lambda row: row.__setitem__("experiment_digest", _digest("0")),
            "identity changed",
        ),
        (
            lambda row: row["engine_setup"]["engine"].__setitem__("version", "9.9.9"),
            "setup changed",
        ),
        (
            lambda row: row["selection"].__setitem__("job_id", "job-" + "f" * 32),
            "selection changed",
        ),
        (
            lambda row: row["authorization"].__setitem__("action_limit", 21),
            "setup changed",
        ),
        (
            lambda row: row["defensive_change"].__setitem__("state", "rolled_back"),
            "defensive change presentation changed",
        ),
    ],
)
def test_rejects_presentation_identity_setup_selection_and_unknown_field_drift(
    mutate: Any, message: str
) -> None:
    experiment = build_completed_experiment()
    presentation = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )
    mutate(presentation)

    with pytest.raises(EngineExperimentWorkspaceError, match=message):
        project_engine_experiment_workspace(experiment, _RunSource(experiment), presentation)


def test_recomputed_workspace_rejects_stale_digest_and_nested_projection_drift() -> None:
    experiment = build_completed_experiment()
    source = _RunSource(experiment)
    presentation = _presentation(experiment)
    workspace = project_engine_experiment_workspace(experiment, source, presentation)

    stale = copy.deepcopy(workspace)
    stale["workspace_digest"] = _digest("f")
    with pytest.raises(EngineExperimentWorkspaceError, match="digest changed"):
        checked_engine_experiment_workspace(stale, experiment, source, presentation)

    projection_drift = copy.deepcopy(workspace)
    projection_drift["projection"]["attempts"][0]["unknown"] = "not allowed"
    body = copy.deepcopy(projection_drift)
    body.pop("workspace_digest")
    projection_drift["workspace_digest"] = content_hash(body)
    with pytest.raises(EngineExperimentWorkspaceError, match="workspace changed"):
        checked_engine_experiment_workspace(
            projection_drift, experiment, source, presentation
        )

def test_selected_attempt_omits_raw_engine_content_artifact_bodies_and_local_paths() -> None:
    experiment = _engine_evidence_experiment()
    presentation = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )

    workspace = project_engine_experiment_workspace(
        experiment, _RunSource(experiment), presentation
    )
    serialized = json.dumps(workspace, sort_keys=True)
    attempt = workspace["selected_context"]["attempt"]

    assert "sk-this-must-never-appear" not in serialized
    assert "C:\\\\private" not in serialized
    assert "engine says success" not in serialized
    assert attempt["findings"] == []
    assert attempt["artifacts"] == []
    assert attempt["usage"] == {
        "duration_ms": 120_000,
        "model_requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "tool_calls": 0,
        "cost_microusd": None,
    }
    assert attempt["observations"][0]["provenance"] == "engine_reported"
    assert "does not establish an independent outcome" in attempt["observations"][0][
        "summary"
    ]
    assert attempt["resume_supported"] is False


def test_selected_attempt_fails_closed_when_elapsed_time_exceeds_authorization() -> None:
    experiment = _reserve_baseline(_new_experiment())
    record = experiment.attempts[0].record
    experiment = experiment.update_attempt_record(
        record.transition(AttemptState.PREFLIGHT), timestamp="2026-11-04T12:02:00Z"
    )
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-overlong",
        timestamp="2026-11-04T12:02:00Z",
    )
    experiment = experiment.update_attempt_record(
        running, timestamp="2026-11-04T12:02:00Z"
    )
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:10:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    experiment = experiment.settle_attempt(
        completed,
        engine_evidence=(),
        artifact_manifest_ref=None,
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("e"),
        settled_at="2026-11-04T12:10:00Z",
    )
    presentation = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )

    with pytest.raises(EngineExperimentWorkspaceError, match="wall clock limit"):
        project_engine_experiment_workspace(experiment, _RunSource(experiment), presentation)


def test_private_upstream_session_identity_is_redacted() -> None:
    experiment = _engine_evidence_experiment(session_id="sk-private-session-123456")
    presentation = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )

    workspace = project_engine_experiment_workspace(
        experiment, _RunSource(experiment), presentation
    )
    serialized = json.dumps(workspace, sort_keys=True)

    assert workspace["selected_context"]["attempt"]["upstream_session_id"] is None
    assert "sk-private-session-123456" not in serialized
    assert "The private upstream session identity was withheld from this response." in workspace[
        "limitations"
    ]


def test_rejects_private_material_in_controller_supplied_display_metadata() -> None:
    experiment = _new_experiment()
    presentation = _presentation(experiment)
    presentation["objective"]["summary"] = "Open C:\\Users\\operator\\secret.txt"

    with pytest.raises(EngineExperimentWorkspaceError, match="private material"):
        project_engine_experiment_workspace(experiment, _RunSource(experiment), presentation)


def test_null_selection_does_not_substitute_an_attempt() -> None:
    experiment = build_completed_experiment()
    workspace = project_engine_experiment_workspace(
        experiment,
        _RunSource(experiment),
        _presentation(experiment, selection=None),
    )

    assert workspace["selected_context"] is None


def test_public_presenter_resolves_exact_attempt_and_check_links() -> None:
    experiment = build_completed_experiment()
    source = _RunSource(experiment)
    presentation_source = _PresentationSource(_presentation(experiment))

    attempt_workspace = present_engine_experiment_workspace(
        experiment,
        source,
        presentation_source,
        selected_attempt_id=experiment.attempts[1].record.binding.attempt_id,
    )
    check_workspace = present_engine_experiment_workspace(
        experiment,
        source,
        presentation_source,
        selected_check_id=experiment.checks[1].check_id,
    )

    assert presentation_source.requests == [
        (experiment.experiment_id, experiment.revision, experiment.digest)
    ] * 2
    assert attempt_workspace["selected_context"]["kind"] == "engine_attempt"
    assert attempt_workspace["selected_context"]["attempt"]["job_id"] == (
        experiment.attempts[1].job_id
    )
    assert attempt_workspace["selected_context"]["attempt"]["run_id"] == (
        experiment.attempts[1].record.binding.run_id
    )
    assert check_workspace["selected_context"]["kind"] == "controller_check"
    assert check_workspace["selected_context"]["check"]["performer"] == (
        "bluefire.trusted-client"
    )
    assert "engine" not in check_workspace["selected_context"]["check"]
    assert "model" not in check_workspace["selected_context"]["check"]


def test_public_presenter_reopens_revision_exact_historical_metadata() -> None:
    initial = _new_experiment()
    advanced = _reserve_baseline(initial)
    initial_key = (initial.experiment_id, initial.revision, initial.digest)
    advanced_key = (advanced.experiment_id, advanced.revision, advanced.digest)
    source = _RevisionPresentationSource(
        {
            initial_key: _presentation(initial),
            advanced_key: _presentation(advanced),
        }
    )

    initial_workspace = present_engine_experiment_workspace(
        initial, _RunSource(initial), source
    )
    advanced_workspace = present_engine_experiment_workspace(
        advanced, _RunSource(advanced), source
    )

    assert source.requests == [initial_key, advanced_key]
    assert initial_workspace["revision"] == initial.revision
    assert initial_workspace["experiment_digest"] == initial.digest
    assert advanced_workspace["revision"] == advanced.revision
    assert advanced_workspace["experiment_digest"] == advanced.digest
    assert initial_workspace["projection"]["attempts"] == []
    assert len(advanced_workspace["projection"]["attempts"]) == 1


def test_public_presenter_rejects_ambiguous_invalid_and_missing_selection() -> None:
    experiment = build_completed_experiment()
    source = _RunSource(experiment)
    presentation_source = _PresentationSource(_presentation(experiment))

    with pytest.raises(EngineExperimentWorkspaceError, match="not both"):
        present_engine_experiment_workspace(
            experiment,
            source,
            presentation_source,
            selected_attempt_id=experiment.attempts[0].record.binding.attempt_id,
            selected_check_id=experiment.checks[0].check_id,
        )
    with pytest.raises(EngineExperimentWorkspaceError, match="identity is invalid"):
        present_engine_experiment_workspace(
            experiment,
            source,
            presentation_source,
            selected_attempt_id="not-an-attempt",
        )
    with pytest.raises(EngineExperimentSelectionNotFound, match="unavailable"):
        present_engine_experiment_workspace(
            experiment,
            source,
            presentation_source,
            selected_attempt_id="engine-attempt-" + "f" * 32,
        )
    with pytest.raises(EngineExperimentSelectionNotFound, match="unavailable"):
        present_engine_experiment_workspace(
            experiment,
            source,
            presentation_source,
            selected_check_id="controller-check-" + "f" * 32,
        )


def test_public_presenter_does_not_accept_source_selected_context() -> None:
    experiment = build_completed_experiment()
    supplied = _presentation(
        experiment, selection=_selection(experiment, "engine_attempt")
    )

    with pytest.raises(EngineExperimentWorkspaceError, match="cannot choose"):
        present_engine_experiment_workspace(
            experiment,
            _RunSource(experiment),
            _PresentationSource(supplied),
        )


def test_public_presenter_validates_experiment_before_selection_not_found() -> None:
    experiment = build_completed_experiment()
    presentation_source = _PresentationSource(_presentation(experiment))
    corrupt = replace(experiment, schema_version="bluefire.engine-experiment.corrupt")

    with pytest.raises(EngineExperimentWorkspaceError, match="experiment state is invalid") as caught:
        present_engine_experiment_workspace(
            corrupt,
            _RunSource(experiment),
            presentation_source,
            selected_attempt_id="engine-attempt-" + "f" * 32,
        )

    assert not isinstance(caught.value, EngineExperimentSelectionNotFound)
    assert presentation_source.requests == []


def test_public_presenter_normalizes_non_json_presentation_source_data() -> None:
    experiment = build_completed_experiment()
    supplied = _presentation(experiment)
    supplied["limitations"] = {"not-json"}

    with pytest.raises(EngineExperimentWorkspaceError, match="presentation is invalid"):
        present_engine_experiment_workspace(
            experiment,
            _RunSource(experiment),
            _PresentationSource(supplied),
        )

