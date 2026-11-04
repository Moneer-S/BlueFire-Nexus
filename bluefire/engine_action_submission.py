"""Server-owned admission of one immutable, previously reviewed engine action."""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Protocol

from .engine_action_preparation import (
    EngineActionPreparationCoordinator,
    EngineActionWorkspaceSource,
    EnginePreparedActionKind,
    EngineWorkspaceAction,
)
from .engine_experiment import EngineExperiment
from .product_store_errors import ProductStoreError, ResourceConflictError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPERIMENT = re.compile(r"^experiment-[0-9a-f]{32}$")
_FIELDS = frozenset({"schema_version", "preparation_id", "protected_request_ref"})


class EngineActionSubmissionServiceError(RuntimeError):
    """A privacy-safe public admission failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PreparedActionHistory(Protocol):
    def get_protected_engine_action_preparation(self, request_ref: str) -> Mapping[str, Any]: ...

    def get_engine_action_acceptance(
        self, *, experiment_id: str, preparation_id: str, request_ref: str, reviewer: str
    ) -> Mapping[str, Any] | None: ...

    def recover_engine_action_acceptance(
        self, *, experiment_id: str, preparation_id: str, request_ref: str, reviewer: str
    ) -> Mapping[str, Any] | None: ...

    def accept_engine_action_preparation(
        self,
        *,
        experiment_id: str,
        preparation_id: str,
        request_ref: str,
        reviewer: str,
        validate_workspace: Callable[[Mapping[str, Any]], None],
    ) -> tuple[Mapping[str, Any], bool]: ...


class PreparedActionJobs(Protocol):
    def submit_prepared(
        self,
        *,
        request: Mapping[str, Any],
        submission_id: str,
        intent_digest: str,
        submission_factory: Callable[[], tuple[Mapping[str, Any], bool]],
    ) -> Mapping[str, Any]: ...


class EngineActionSubmissionCoordinator:
    """Resolve all authority locally and use the existing job controller gate."""

    def __init__(
        self,
        *,
        history: PreparedActionHistory,
        workspace_source: EngineActionWorkspaceSource,
        jobs: PreparedActionJobs,
        controller_jobs: PreparedActionJobs | None,
        reviewer: str,
    ) -> None:
        if (
            not isinstance(reviewer, str)
            or not 1 <= len(reviewer) <= 200
            or reviewer != reviewer.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in reviewer)
        ):
            raise ValueError("a stable trusted local operator identity is required")
        self._history = history
        self._workspace_source = workspace_source
        self._jobs = jobs
        self._controller_jobs = controller_jobs
        self._reviewer = reviewer

    def submit(self, *, experiment_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if (
            not isinstance(experiment_id, str)
            or _EXPERIMENT.fullmatch(experiment_id) is None
            or not isinstance(request, Mapping)
            or set(request) != _FIELDS
            or request.get("schema_version") != "bluefire.engine-action-submit.v1"
            or any(
                not isinstance(request.get(field), str) or _DIGEST.fullmatch(request[field]) is None
                for field in ("preparation_id", "protected_request_ref")
            )
        ):
            raise EngineActionSubmissionServiceError(
                "engine_request_invalid", "The prepared engine action request is invalid."
            )
        values = {
            "experiment_id": experiment_id,
            "preparation_id": request["preparation_id"],
            "request_ref": request["protected_request_ref"],
            "reviewer": self._reviewer,
        }
        try:
            accepted = self._history.get_engine_action_acceptance(**values)
            if accepted is not None:
                return accepted
            recovered = self._history.recover_engine_action_acceptance(**values)
            if recovered is not None:
                return recovered
            record = self._history.get_protected_engine_action_preparation(values["request_ref"])
            if record["experiment_id"] != experiment_id:
                raise ProductStoreError("prepared action belongs to another experiment")
            action = EngineWorkspaceAction(record["action_kind"])
            if action in {
                EngineWorkspaceAction.RECONCILE_DEFENSE,
                EngineWorkspaceAction.RECONCILE_ROLLBACK,
            }:
                raise ProductStoreError("prepared reconciliation is unavailable")

            def validate_workspace(retained: Mapping[str, Any]) -> None:
                experiment = EngineExperiment._from_controller_mapping(
                    retained["experiment_document"]
                )
                current = EngineActionPreparationCoordinator._current_action(
                    self._workspace_source.workspace(experiment_id),
                    experiment=experiment,
                    expected_workspace_digest=retained["workspace_digest"],
                )
                if current.value != retained["action_kind"]:
                    raise ResourceConflictError("prepared workspace action changed")

            def accept() -> tuple[Mapping[str, Any], bool]:
                return self._history.accept_engine_action_preparation(
                    **values, validate_workspace=validate_workspace
                )

            if record["preparation_kind"] == EnginePreparedActionKind.CONTROLLER_TRANSITION.value:
                accept()
            else:
                adapter = (
                    self._jobs
                    if record["preparation_kind"] == EnginePreparedActionKind.ENGINE_ATTEMPT.value
                    else self._controller_jobs
                )
                if adapter is None:
                    raise EngineActionSubmissionServiceError(
                        "engine_action_unavailable",
                        "The trusted engine action runtime is unavailable.",
                    )
                adapter.submit_prepared(
                    request=record["protected_request"]["job_request"],
                    submission_id=record["submission_id"],
                    intent_digest=record["intent_digest"],
                    submission_factory=accept,
                )
            accepted = self._history.get_engine_action_acceptance(**values)
            if accepted is None:
                raise ProductStoreError("prepared action has no durable acceptance")
            return accepted
        except EngineActionSubmissionServiceError:
            raise
        except ResourceConflictError as exc:
            raise EngineActionSubmissionServiceError(
                "engine_action_stale",
                "The engine workspace changed before the action was accepted.",
            ) from exc
        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise EngineActionSubmissionServiceError(
                "engine_action_submission_refused",
                "The prepared engine action could not be accepted safely.",
            ) from exc
