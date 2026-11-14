"""Coordinate server-owned review preparation for engine workspace actions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping

from .engine_action_contract import (
    _DIGEST,
    _PREPARE_V1_FIELDS,
    _PREPARE_V2_FIELDS,
    EngineActionPreparationError,
    EngineActionPreparationHistory,
    EngineActionPreparationPlan,
    EngineActionWorkspaceSource,
    EnginePreparedActionKind,
    EnginePreparedApprovalState,
    EnginePreparedEffectKind,
    EngineWorkspaceAction,
    PreparedEngineAction,
    PreparedEngineActionLimits,
    ProtectedActionFactory,
    ProtectedPreparationRetainer,
    TrustedEngineActionPreparer,
    _timestamp,
    engine_action_contract,
)
from .engine_experiment import EngineExperiment, EngineExperimentError
from .product_store_errors import ProductStoreError, ResourceConflictError
from .util import json_clone


class EngineActionPreparationServiceError(RuntimeError):
    """Privacy-safe product preparation failure with a stable API code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class EngineActionPreparationCoordinator:
    """Derive the sole current action and retain its exact review envelope."""

    def __init__(
        self,
        *,
        history: EngineActionPreparationHistory,
        workspace_source: EngineActionWorkspaceSource,
        preparer: TrustedEngineActionPreparer | None,
        clock: Callable[[], str],
    ) -> None:
        self._history = history
        self._workspace_source = workspace_source
        self._preparer = preparer
        self._clock = clock

    def prepare_request(self, experiment_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(request, Mapping):
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        schema = request.get("schema_version")
        selected_action: EngineWorkspaceAction | None = None
        if schema == "bluefire.engine-action-prepare-request.v1":
            valid_fields = set(request) == _PREPARE_V1_FIELDS
        elif schema == "bluefire.engine-action-prepare-request.v2":
            valid_fields = set(request) == _PREPARE_V2_FIELDS
            try:
                selected_action = EngineWorkspaceAction(request.get("action_kind"))
            except (TypeError, ValueError):
                valid_fields = False
        else:
            valid_fields = False
        if not valid_fields:
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        expected_revision = request.get("expected_revision")
        expected_digest = request.get("expected_digest")
        expected_workspace = request.get("workspace_digest")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or not 1 <= expected_revision <= 10_000
            or not isinstance(expected_digest, str)
            or _DIGEST.fullmatch(expected_digest) is None
            or not isinstance(expected_workspace, str)
            or _DIGEST.fullmatch(expected_workspace) is None
        ):
            raise EngineActionPreparationServiceError(
                "engine_request_invalid",
                "The engine action preparation request does not match the supported contract.",
            )
        if self._preparer is None:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The trusted engine action preparer is unavailable.",
            )
        try:
            record = self._history.get_engine_experiment(experiment_id)
            experiment = EngineExperiment._from_controller_mapping(record["document"])
            self._expect_head(
                record,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            workspace = dict(json_clone(self._workspace_source.workspace(experiment_id)))
            action = self._current_action(
                workspace,
                experiment=experiment,
                expected_workspace_digest=expected_workspace,
                requested_action=selected_action,
            )
            prepared_at = _timestamp(self._clock(), "engine action preparation time")
            plan = self._preparer.prepare(
                experiment=experiment,
                workspace=workspace,
                action=action,
                prepared_at=prepared_at,
            )
            if not isinstance(plan, EngineActionPreparationPlan) or plan.action is not action:
                raise EngineActionPreparationError("trusted preparer returned another action")
            # Rebuild the workspace after pure materialization.  Any run,
            # presentation, or experiment drift invalidates this review.
            fresh_record = self._history.get_engine_experiment(experiment_id)
            self._expect_head(
                fresh_record,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            fresh_workspace = dict(json_clone(self._workspace_source.workspace(experiment_id)))
            if fresh_workspace != workspace:
                raise ResourceConflictError("engine action workspace changed")
            retain_preparation = (
                self._history.create_engine_action_preparation
                if plan.retain_preparation is None
                else plan.retain_preparation
            )
            protected = retain_preparation(
                experiment_id=experiment.experiment_id,
                experiment_revision=experiment.revision,
                experiment_digest=experiment.digest,
                workspace_digest=expected_workspace,
                action=action,
                limits=plan.limits,
                prepared_at=prepared_at,
                expires_at=plan.expires_at,
                protected_factory=plan.protected_factory,
                approval_request=plan.approval_request,
            )
            return self._history.prepared_engine_action(str(protected["request_ref"]))
        except EngineActionPreparationServiceError:
            raise
        except ResourceConflictError as exc:
            raise EngineActionPreparationServiceError(
                "engine_action_stale",
                "The engine workspace changed before the action could be prepared.",
            ) from exc
        except (EngineActionPreparationError, EngineExperimentError, ProductStoreError) as exc:
            raise EngineActionPreparationServiceError(
                "engine_action_preparation_refused",
                "The current engine action could not be prepared safely.",
            ) from exc

    @staticmethod
    def _expect_head(
        record: Mapping[str, Any], *, expected_revision: int, expected_digest: str
    ) -> None:
        if (
            record.get("active") is not True
            or record.get("revision") != expected_revision
            or record.get("digest") != expected_digest
        ):
            raise ResourceConflictError("engine action experiment head changed")

    @staticmethod
    def _current_action(
        workspace: Mapping[str, Any],
        *,
        experiment: EngineExperiment,
        expected_workspace_digest: str,
        requested_action: EngineWorkspaceAction | None = None,
    ) -> EngineWorkspaceAction:
        if (
            workspace.get("schema_version") != "bluefire.engine-experiment-workspace.v1"
            or workspace.get("experiment_id") != experiment.experiment_id
            or workspace.get("revision") != experiment.revision
            or workspace.get("experiment_digest") != experiment.digest
            or workspace.get("workspace_digest") != expected_workspace_digest
        ):
            raise ResourceConflictError("engine action workspace binding changed")
        actions = workspace.get("actions")
        if not isinstance(actions, list) or not actions:
            raise EngineActionPreparationError("engine workspace action is ambiguous")
        if any(not isinstance(item, Mapping) for item in actions):
            raise EngineActionPreparationError("engine workspace action is invalid")
        kinds = [item.get("kind") for item in actions]
        if any(not isinstance(kind, str) for kind in kinds) or len(set(kinds)) != len(kinds):
            raise EngineActionPreparationError("engine workspace action is ambiguous")
        if requested_action is None:
            if len(actions) != 1:
                raise EngineActionPreparationError("engine workspace action is ambiguous")
            row = actions[0]
        else:
            matches = [item for item in actions if item.get("kind") == requested_action.value]
            if len(matches) != 1:
                raise EngineActionPreparationError(
                    "selected engine workspace action is unavailable"
                )
            row = matches[0]
        if not isinstance(row, Mapping) or row.get("enabled") is not True:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The current engine workspace action is unavailable.",
            )
        raw_kind = row.get("kind")
        if raw_kind in {
            "review_evidence",
            "open_comparison",
            "choose_defense_disposition",
        }:
            raise EngineActionPreparationServiceError(
                "engine_action_unavailable",
                "The current workspace action does not use an execution preparation.",
            )
        try:
            action = EngineWorkspaceAction(raw_kind)
        except (TypeError, ValueError) as exc:
            raise EngineActionPreparationError("engine workspace action is unsupported") from exc
        if requested_action is not None and action is not requested_action:
            raise EngineActionPreparationError("selected engine workspace action changed")
        return action


__all__ = [
    "EngineActionPreparationCoordinator",
    "EngineActionPreparationError",
    "EngineActionPreparationHistory",
    "EngineActionPreparationPlan",
    "EngineActionPreparationServiceError",
    "EngineActionWorkspaceSource",
    "EnginePreparedActionKind",
    "EnginePreparedApprovalState",
    "EnginePreparedEffectKind",
    "EngineWorkspaceAction",
    "PreparedEngineAction",
    "PreparedEngineActionLimits",
    "ProtectedActionFactory",
    "ProtectedPreparationRetainer",
    "TrustedEngineActionPreparer",
    "engine_action_contract",
]
