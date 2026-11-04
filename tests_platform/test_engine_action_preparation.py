from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

import pytest

from bluefire.engine_action_preparation import (
    EngineActionPreparationCoordinator,
    EngineActionPreparationPlan,
    EngineActionPreparationServiceError,
    EngineWorkspaceAction,
    PreparedEngineActionLimits,
)
from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION, EngineExperiment

EXPERIMENT_ID = "experiment-" + "1" * 32
DIGEST = "sha256:" + "a" * 64
WORKSPACE_DIGEST = "sha256:" + "b" * 64
REQUEST_REF = "sha256:" + "c" * 64
PREPARED_AT = "2026-11-04T12:00:00Z"
EXPIRES_AT = "2026-11-04T12:05:00Z"


def _experiment() -> EngineExperiment:
    return EngineExperiment.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref="sha256:" + "1" * 64,
        environment_ref="sha256:" + "2" * 64,
        scope_ref="sha256:" + "3" * 64,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref="sha256:" + "4" * 64,
        created_at=PREPARED_AT,
    )


def _workspace(
    experiment: EngineExperiment,
    *,
    action: str = "start_baseline",
    enabled: bool = True,
    reason: str = "Requires review.",
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-workspace.v1",
        "experiment_id": experiment.experiment_id,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "workspace_digest": WORKSPACE_DIGEST,
        "actions": [
            {
                "kind": action,
                "enabled": enabled,
                "reason": reason,
            }
        ],
    }


def _request(experiment: EngineExperiment) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-action-prepare-request.v1",
        "expected_revision": experiment.revision,
        "expected_digest": experiment.digest,
        "workspace_digest": WORKSPACE_DIGEST,
    }


class _History:
    def __init__(self, experiment: EngineExperiment) -> None:
        self.experiment = experiment
        self.created: list[Mapping[str, Any]] = []

    def get_engine_experiment(self, experiment_id: str, *, revision=None):
        assert experiment_id == self.experiment.experiment_id
        assert revision is None
        return {
            "document": self.experiment.to_dict(),
            "revision": self.experiment.revision,
            "digest": self.experiment.digest,
            "active": True,
        }

    def create_engine_action_preparation(self, **values: Any):
        self.created.append(values)
        return {"request_ref": REQUEST_REF}

    def prepared_engine_action(self, request_ref: str):
        assert request_ref == REQUEST_REF
        return {
            "schema_version": "bluefire.engine-prepared-action.v1",
            "request_ref": request_ref,
            "effects_started_at_preparation": False,
        }


class _WorkspaceSource:
    def __init__(self, rows: list[Mapping[str, Any]]) -> None:
        self.rows = rows
        self.calls = 0

    def workspace(self, experiment_id: str):
        assert experiment_id == EXPERIMENT_ID
        index = min(self.calls, len(self.rows) - 1)
        self.calls += 1
        return self.rows[index]


class _Preparer:
    def __init__(self) -> None:
        self.calls: list[
            tuple[EngineExperiment, Mapping[str, Any], EngineWorkspaceAction, str]
        ] = []

    def prepare(self, *, experiment, workspace, action, prepared_at):
        self.calls.append((experiment, workspace, action, prepared_at))

        def protected_factory(approval, submission_id):
            return None, {
                "schema_version": "bluefire.engine-action-authority.v1",
                "kind": "test-only",
                "document": {},
                "document_digest": DIGEST,
            }

        return EngineActionPreparationPlan(
            action=action,
            limits=PreparedEngineActionLimits(
                wall_clock_seconds=300,
                action_limit=20,
                artifact_byte_limit=4 * 1024 * 1024,
                cost_limit_microunits=1_000_000,
                target_scope_digest="sha256:" + "5" * 64,
                maximum_tier="controlled",
            ),
            expires_at=EXPIRES_AT,
            protected_factory=protected_factory,
            approval_request={"server_owned": True},
        )


def _coordinator(
    history: _History,
    workspace_source: _WorkspaceSource,
    preparer: _Preparer | None,
) -> EngineActionPreparationCoordinator:
    return EngineActionPreparationCoordinator(
        history=history,
        workspace_source=workspace_source,
        preparer=preparer,
        clock=lambda: PREPARED_AT,
    )


def test_prepare_derives_one_current_action_and_rereads_before_persisting() -> None:
    experiment = _experiment()
    history = _History(experiment)
    workspace = _workspace(experiment)
    source = _WorkspaceSource([workspace])
    preparer = _Preparer()

    result = _coordinator(history, source, preparer).prepare_request(
        EXPERIMENT_ID, _request(experiment)
    )

    assert result == {
        "schema_version": "bluefire.engine-prepared-action.v1",
        "request_ref": REQUEST_REF,
        "effects_started_at_preparation": False,
    }
    assert source.calls == 2
    assert len(preparer.calls) == 1
    prepared_experiment, prepared_workspace, action, prepared_at = preparer.calls[0]
    assert prepared_experiment.to_dict() == experiment.to_dict()
    assert prepared_workspace == workspace
    assert action is EngineWorkspaceAction.START_BASELINE
    assert prepared_at == PREPARED_AT
    assert len(history.created) == 1
    saved = history.created[0]
    assert saved["experiment_revision"] == experiment.revision
    assert saved["experiment_digest"] == experiment.digest
    assert saved["workspace_digest"] == WORKSPACE_DIGEST
    assert saved["action"] is EngineWorkspaceAction.START_BASELINE
    assert "request_ref" not in saved and "command" not in saved


def test_prepare_uses_trusted_atomic_retainer_after_rechecking_workspace() -> None:
    experiment = _experiment()
    history = _History(experiment)
    source = _WorkspaceSource([_workspace(experiment)])
    retained: list[Mapping[str, Any]] = []

    def retain_preparation(**values: Any) -> Mapping[str, Any]:
        assert source.calls == 2
        retained.append(values)
        return {"request_ref": REQUEST_REF}

    class RetainingPreparer(_Preparer):
        def prepare(self, **values):
            return replace(super().prepare(**values), retain_preparation=retain_preparation)

    result = _coordinator(history, source, RetainingPreparer()).prepare_request(
        EXPERIMENT_ID, _request(experiment)
    )

    assert result["request_ref"] == REQUEST_REF
    assert not history.created
    assert len(retained) == 1
    assert retained[0]["experiment_digest"] == experiment.digest
    assert retained[0]["workspace_digest"] == WORKSPACE_DIGEST
    assert retained[0]["prepared_at"] == PREPARED_AT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action", "start_adaptive_search"),
        ("request_ref", DIGEST),
        ("approval_nonce", "owner-secret"),
        ("command", "run anything"),
        ("evidence", {"claim": "success"}),
    ],
)
def test_prepare_rejects_browser_supplied_authority(field: str, value: Any) -> None:
    experiment = _experiment()
    history = _History(experiment)
    preparer = _Preparer()
    request = _request(experiment)
    request[field] = value

    with pytest.raises(EngineActionPreparationServiceError) as caught:
        _coordinator(
            history,
            _WorkspaceSource([_workspace(experiment)]),
            preparer,
        ).prepare_request(EXPERIMENT_ID, request)

    assert caught.value.code == "engine_request_invalid"
    assert history.created == [] and preparer.calls == []


def test_prepare_refuses_when_trusted_preparer_is_unavailable() -> None:
    experiment = _experiment()
    history = _History(experiment)

    with pytest.raises(EngineActionPreparationServiceError) as caught:
        _coordinator(
            history,
            _WorkspaceSource([_workspace(experiment)]),
            None,
        ).prepare_request(EXPERIMENT_ID, _request(experiment))

    assert caught.value.code == "engine_action_unavailable"
    assert history.created == []


@pytest.mark.parametrize("action", ["review_evidence", "choose_defense_disposition"])
def test_prepare_does_not_turn_navigation_or_choice_into_an_effect(action: str) -> None:
    experiment = _experiment()
    history = _History(experiment)
    preparer = _Preparer()

    with pytest.raises(EngineActionPreparationServiceError) as caught:
        _coordinator(
            history,
            _WorkspaceSource([_workspace(experiment, action=action)]),
            preparer,
        ).prepare_request(EXPERIMENT_ID, _request(experiment))

    assert caught.value.code == "engine_action_unavailable"
    assert history.created == [] and preparer.calls == []


def test_prepare_rejects_disabled_current_action() -> None:
    experiment = _experiment()
    history = _History(experiment)
    preparer = _Preparer()

    with pytest.raises(EngineActionPreparationServiceError) as caught:
        _coordinator(
            history,
            _WorkspaceSource([_workspace(experiment, enabled=False)]),
            preparer,
        ).prepare_request(EXPERIMENT_ID, _request(experiment))

    assert caught.value.code == "engine_action_unavailable"
    assert history.created == [] and preparer.calls == []


def test_prepare_discards_material_when_workspace_changes_during_review() -> None:
    experiment = _experiment()
    history = _History(experiment)
    preparer = _Preparer()
    initial = _workspace(experiment)
    changed = _workspace(experiment, reason="The prerequisite state changed.")

    with pytest.raises(EngineActionPreparationServiceError) as caught:
        _coordinator(
            history,
            _WorkspaceSource([initial, changed]),
            preparer,
        ).prepare_request(EXPERIMENT_ID, _request(experiment))

    assert caught.value.code == "engine_action_stale"
    assert history.created == []
    assert len(preparer.calls) == 1
