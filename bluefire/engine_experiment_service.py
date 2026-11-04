"""Product-facing coordinator for external-engine defense experiments.

This service composes the existing append-only ProductStore history, durable
job coordinator, trusted controller operations, and evidence projection.  It
does not execute an engine, mutate a target, mint independent observations, or
introduce another scheduler or persistence layer.
"""

from __future__ import annotations

import re
import uuid
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, TypeVar, cast

from .engine_attempt_contract import AttemptState, EngineAttemptBinding
from .engine_delegation import (
    EngineCapabilityDelegation,
    EngineDelegationError,
    EngineExecutionApprovalBinding,
)
from .engine_experiment import (
    DefenseState,
    EngineExperiment,
    EngineExperimentError,
    IndependentObservationRecord,
)
from .engine_experiment_assistance import (
    EngineExperimentAssistanceError,
    engine_experiment_assistance_context,
)
from .engine_experiment_jobs import EngineExperimentJobError, EngineExperimentJobs
from .engine_experiment_projection import (
    EngineRunSource,
    verify_finalized_independent_observation,
)
from .engine_experiment_workspace import (
    EngineExperimentPresentationSource,
    EngineExperimentSelectionNotFound,
    EngineExperimentWorkspaceError,
    present_engine_experiment_workspace,
)
from .job_runtime import JobRuntimeError
from .product_store_errors import ProductStoreError, ResourceConflictError
from .run_store import RunStoreError
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineExperimentServiceError(RuntimeError):
    """Stable, privacy-safe failure returned by the product service seam."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class EngineControllerOperationError(RuntimeError):
    """Raised by an injected trusted controller operation."""


class EngineControllerAction(str, Enum):
    """Effect-free controller decisions persisted synchronously."""

    REVIEW_DEFENSE = "review_defense"
    RETAIN_DEFENSE = "retain_defense"


class EngineControllerJobAction(str, Enum):
    """Controller effects that must run as visible, cancellable product jobs."""

    APPLY_DEFENSE = "apply_defense"
    RECONCILE_DEFENSE = "reconcile_defense"
    RUN_RETAINED_REPRODUCER = "run_retained_reproducer"
    RECONCILE_RETAINED_REPRODUCER = "reconcile_retained_reproducer"
    RUN_LEGITIMATE_USE = "run_legitimate_use"
    RECONCILE_LEGITIMATE_USE = "reconcile_legitimate_use"
    ROLLBACK_DEFENSE = "rollback_defense"
    RECONCILE_ROLLBACK = "reconcile_rollback"


class EngineExperimentHistory(Protocol):
    """Narrow existing ProductStore surface used by this coordinator."""

    def create_engine_experiment(
        self,
        experiment_id: str,
        document: Mapping[str, Any],
        *,
        validator: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Mapping[str, Any]: ...

    def save_engine_experiment(
        self,
        experiment_id: str,
        document: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_digest: str,
        validator: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> Mapping[str, Any]: ...

    def get_engine_experiment(
        self, experiment_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...

    def list_engine_experiments(self, *, limit: int = 100) -> list[Mapping[str, Any]]: ...

    def compare_and_swap_engine_attempt_observation(
        self,
        *,
        experiment_id: str,
        observation: Mapping[str, Any],
        expected_revision: int,
        expected_experiment_digest: str,
        timestamp: str,
    ) -> Mapping[str, Any]:
        """Atomically append one preverified controller observation."""

        ...


class TrustedEngineController(Protocol):
    """Protected controller boundary for effect-free review decisions.

    The public product request contains only a digest reference.  The injected
    controller resolves protected operation input and returns exactly one
    canonical state-machine transition.
    """

    def perform(
        self,
        *,
        action: EngineControllerAction,
        experiment: EngineExperiment,
        request_ref: str,
    ) -> EngineExperiment: ...


class EngineControllerJobs(Protocol):
    """Existing RunJobController-backed adapters for target/check effects."""

    def submit(
        self,
        *,
        action: EngineControllerJobAction,
        experiment: EngineExperiment,
        request_ref: str,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]: ...


class EngineJobLifecycle(Protocol):
    """Existing RunJobController cancellation surface."""

    def cancel(self, job_id: str) -> Mapping[str, Any]: ...


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")
_JOB_STATES = frozenset(
    {
        "queued",
        "planning",
        "awaiting_approval",
        "running",
        "paused",
        "cancelling",
        "cancelled",
        "completed",
        "failed",
        "interrupted",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "revision",
        "prior_digest",
        "digest",
        "document",
        "created_at",
        "active",
        "active_revision",
    }
)
_HEAD_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "active_revision",
        "active_digest",
        "created_at",
        "updated_at",
    }
)
_T = TypeVar("_T")


class EngineExperimentService:
    """Coordinate one installed attack, defense, and retest workspace."""

    def __init__(
        self,
        *,
        history: EngineExperimentHistory,
        run_source: EngineRunSource,
        jobs: EngineExperimentJobs,
        job_lifecycle: EngineJobLifecycle,
        controller: TrustedEngineController | None,
        clock: Callable[[], str],
        presentation_source: EngineExperimentPresentationSource,
        controller_jobs: EngineControllerJobs | None = None,
    ) -> None:
        self._history = history
        self._run_source = run_source
        self._jobs = jobs
        self._job_lifecycle = job_lifecycle
        self._controller = controller
        self._controller_jobs = controller_jobs
        self._clock = clock
        self._presentation_source = presentation_source

    def create(
        self,
        *,
        experiment_id: str,
        objective_ref: str,
        environment_ref: str,
        scope_ref: str,
        scope_version: str,
        target_snapshot_ref: str,
    ) -> Mapping[str, Any]:
        """Create an immutable experiment head and return its workspace."""

        def operation() -> Mapping[str, Any]:
            experiment = EngineExperiment.create(
                experiment_id=experiment_id,
                objective_ref=objective_ref,
                environment_ref=environment_ref,
                scope_ref=scope_ref,
                scope_version=scope_version,
                target_snapshot_ref=target_snapshot_ref,
                created_at=self._now(),
            )
            self._presentation_source.assert_engine_experiment_presentation_create_ready(experiment)
            try:
                record = self._history.create_engine_experiment(
                    experiment.experiment_id,
                    experiment.to_dict(),
                    validator=self._validate_document,
                )
            except ResourceConflictError:
                record = self._history.get_engine_experiment(experiment.experiment_id)
                existing = self._record(record)["experiment"]
                if not isinstance(existing, EngineExperiment) or (
                    existing.experiment_id != experiment.experiment_id
                    or existing.objective_ref != objective_ref
                    or existing.environment_ref != environment_ref
                    or existing.scope_ref != scope_ref
                    or existing.scope_version != scope_version
                    or existing.initial_target_snapshot_ref != target_snapshot_ref
                ):
                    raise
            return self._workspace_from_record(record)

        return self._mapped(operation)

    def create_request(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create from exact JSON while assigning time inside the trusted service."""

        fields = {
            "schema_version",
            "experiment_id",
            "objective_ref",
            "environment_ref",
            "scope_ref",
            "scope_version",
            "target_snapshot_ref",
        }
        if (
            not isinstance(request, Mapping)
            or set(request) != fields
            or request.get("schema_version") != "bluefire.engine-experiment-create.v1"
        ):
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The engine experiment request does not match the supported contract.",
            )
        return self.create(
            experiment_id=request["experiment_id"],
            objective_ref=request["objective_ref"],
            environment_ref=request["environment_ref"],
            scope_ref=request["scope_ref"],
            scope_version=request["scope_version"],
            target_snapshot_ref=request["target_snapshot_ref"],
        )

    def get(self, experiment_id: str, *, revision: int | None = None) -> Mapping[str, Any]:
        """Read one exact immutable revision without deriving conclusions."""

        return self._mapped(
            lambda: self._read_from_record(
                self._history.get_engine_experiment(experiment_id, revision=revision)
            )
        )

    def list(self, *, limit: int = 100) -> Mapping[str, Any]:
        """List bounded active heads without exposing experiment documents."""

        def operation() -> Mapping[str, Any]:
            heads = [
                self._head(value) for value in self._history.list_engine_experiments(limit=limit)
            ]
            return {
                "schema_version": "bluefire.engine-experiment-list.v1",
                "experiments": heads,
            }

        return self._mapped(operation)

    def workspace(
        self,
        experiment_id: str,
        *,
        revision: int | None = None,
        selected_attempt_id: str | None = None,
        selected_check_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Return evidence-derived UI state for one exact saved revision."""

        return self._mapped(
            lambda: self._workspace_from_record(
                self._history.get_engine_experiment(experiment_id, revision=revision),
                selected_attempt_id=selected_attempt_id,
                selected_check_id=selected_check_id,
            )
        )

    def assistance_context_request(
        self,
        experiment_id: str,
        selection: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Capture immutable analysis context from one exact saved workspace."""

        fields = {"kind", "experiment_id", "workspace_digest", "attempt_id", "check_id"}
        if (
            not isinstance(selection, Mapping)
            or set(selection) != fields
            or selection.get("kind") != "engine_experiment"
            or selection.get("experiment_id") != experiment_id
            or (selection.get("attempt_id") is not None and selection.get("check_id") is not None)
        ):
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The engine Assistant selection does not match the supported contract.",
            )

        def operation() -> Mapping[str, Any]:
            record = self._record(self._history.get_engine_experiment(experiment_id))
            experiment = cast(EngineExperiment, record["experiment"])
            selected_attempt_id = selection.get("attempt_id")
            selected_check_id = selection.get("check_id")
            if selected_attempt_id is not None and not isinstance(selected_attempt_id, str):
                raise EngineExperimentAssistanceError("engine Assistant selection is invalid")
            if selected_check_id is not None and not isinstance(selected_check_id, str):
                raise EngineExperimentAssistanceError("engine Assistant selection is invalid")
            workspace = present_engine_experiment_workspace(
                experiment,
                self._run_source,
                self._presentation_source,
                selected_attempt_id=selected_attempt_id,
                selected_check_id=selected_check_id,
            )
            presentation = self._assistance_presentation(
                experiment,
                selected_attempt_id=selected_attempt_id,
                selected_check_id=selected_check_id,
            )
            return engine_experiment_assistance_context(
                experiment,
                workspace,
                selection,
                run_source=self._run_source,
                presentation=presentation,
            )

        return self._mapped(operation)

    def submit_attempt(
        self,
        *,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        approval_binding: EngineExecutionApprovalBinding,
        approval_id: str,
        approval_nonce: str,
        approved_by: str,
        submission_id: str,
        intent_digest: str,
        expected_revision: int,
        expected_digest: str,
    ) -> Mapping[str, Any]:
        """Submit one already admitted attempt through the existing job runtime."""

        def operation() -> Mapping[str, Any]:
            current = self._active(binding.experiment_id)
            self._expect(
                current, expected_revision=expected_revision, expected_digest=expected_digest
            )
            return self._jobs.submit(
                experiment_id=binding.experiment_id,
                binding=binding,
                delegation=delegation,
                approval_binding=approval_binding,
                approval_id=approval_id,
                approval_nonce=approval_nonce,
                approved_by=approved_by,
                submission_id=submission_id,
                intent_digest=intent_digest,
            )

        return self._mapped(operation)

    def submit_attempt_request(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Parse one exact JSON request before entering the typed authority path."""

        fields = {
            "schema_version",
            "experiment_id",
            "binding",
            "delegation",
            "approval_binding",
            "approval_id",
            "approval_nonce",
            "approved_by",
            "submission_id",
            "intent_digest",
            "expected_revision",
            "expected_digest",
        }
        if (
            not isinstance(request, Mapping)
            or set(request) != fields
            or request.get("schema_version") != "bluefire.engine-attempt-submit.v1"
        ):
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The engine attempt request does not match the supported contract.",
            )
        try:
            binding = EngineAttemptBinding.from_mapping(request["binding"])
            delegation = EngineCapabilityDelegation.from_mapping(request["delegation"])
            approval = EngineExecutionApprovalBinding.from_mapping(request["approval_binding"])
        except (EngineDelegationError, TypeError, ValueError) as exc:
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The engine attempt request does not match the supported contract.",
            ) from exc
        if request.get("experiment_id") != binding.experiment_id:
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The engine attempt request belongs to another experiment.",
            )
        return self.submit_attempt(
            binding=binding,
            delegation=delegation,
            approval_binding=approval,
            approval_id=request["approval_id"],
            approval_nonce=request["approval_nonce"],
            approved_by=request["approved_by"],
            submission_id=request["submission_id"],
            intent_digest=request["intent_digest"],
            expected_revision=request["expected_revision"],
            expected_digest=request["expected_digest"],
        )

    def record_engine_attempt_observation(
        self,
        *,
        experiment_id: str,
        expected_revision: int,
        expected_digest: str,
        observation: IndependentObservationRecord,
    ) -> Mapping[str, Any]:
        """Persist one trusted target observation for a settled engine attempt.

        This is an internal controller seam, not an HTTP operation.  The
        controller-attested record is checked against the exact attempt and a
        finalized, byte-identical RunStore evidence record before the existing
        ProductStore performs the revision/digest compare-and-swap.  RunStore
        and ProductStore are separate durable stores, so the finalized-run
        check is an explicit immutable precondition rather than a false claim
        of one cross-filesystem transaction.
        """

        def operation() -> Mapping[str, Any]:
            if not isinstance(observation, IndependentObservationRecord):
                raise EngineExperimentError(
                    "engine observation requires controller-attested evidence"
                )
            observation.validate()
            if observation.attempt_id is None or observation.check_id is not None:
                raise EngineExperimentError(
                    "engine observation must belong to an external-engine attempt"
                )
            current = self._active(experiment_id)
            self._expect(
                current,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            matching = [
                entry
                for entry in current.attempts
                if entry.record.binding.attempt_id == observation.attempt_id
            ]
            if len(matching) != 1:
                raise EngineExperimentError("engine observation attempt is unavailable")
            binding = matching[0].record.binding
            if (
                binding.experiment_id != experiment_id
                or binding.run_id != observation.evidence.run_id
                or binding.target_snapshot_ref != observation.target_snapshot_ref
            ):
                raise EngineExperimentError(
                    "engine observation differs from its exact attempt binding"
                )
            existing = next(
                (
                    item
                    for item in current.independent_observations
                    if item.evidence_id == observation.evidence_id
                ),
                None,
            )
            if existing is not None:
                if existing.to_dict() != observation.to_dict():
                    raise EngineExperimentError(
                        "engine observation identity is already bound to different evidence"
                    )
                candidate = current
            else:
                candidate = current.record_independent_observation(
                    observation,
                    timestamp=self._now(),
                )
            verify_finalized_independent_observation(observation, self._run_source)
            if existing is None:
                self._presentation_source.assert_engine_experiment_presentation_transition_ready(
                    current,
                    candidate,
                )
            saved = self._history.compare_and_swap_engine_attempt_observation(
                experiment_id=current.experiment_id,
                observation=observation.to_dict(),
                expected_revision=current.revision,
                expected_experiment_digest=current.digest,
                timestamp=candidate.updated_at,
            )
            saved_experiment = EngineExperiment._from_controller_mapping(
                self._validate_document(saved)
            )
            if (
                saved_experiment.experiment_id != current.experiment_id
                or saved_experiment.digest != candidate.digest
                or saved_experiment.revision != candidate.revision
            ):
                raise EngineExperimentError(
                    "saved engine observation differs from its verified candidate"
                )
            record = self._history.get_engine_experiment(
                current.experiment_id,
                revision=saved_experiment.revision,
            )
            return self._workspace_from_record(record)

        return self._mapped(operation)

    def perform_controller_transition(
        self,
        *,
        experiment_id: str,
        expected_revision: int,
        expected_digest: str,
        action: EngineControllerAction,
        request_ref: str,
    ) -> Mapping[str, Any]:
        """Perform and persist exactly one trusted controller-owned transition."""

        def operation() -> Mapping[str, Any]:
            if not isinstance(action, EngineControllerAction):
                raise EngineExperimentError("controller action is unsupported")
            if not isinstance(request_ref, str) or _DIGEST.fullmatch(request_ref) is None:
                raise EngineExperimentError(
                    "controller request must be a protected digest reference"
                )
            controller = self._controller
            if controller is None:
                raise EngineControllerOperationError("trusted controller is unavailable")
            current = self._active(experiment_id)
            self._expect(
                current, expected_revision=expected_revision, expected_digest=expected_digest
            )
            successor = controller.perform(
                action=action,
                experiment=current,
                request_ref=request_ref,
            )
            self._validate_successor(current, successor)
            self._validate_action_successor(action, current, successor)
            self._presentation_source.assert_engine_experiment_presentation_transition_ready(
                current,
                successor,
            )
            record = self._history.save_engine_experiment(
                current.experiment_id,
                successor.to_dict(),
                expected_revision=current.revision,
                expected_digest=current.digest,
                validator=self._validate_document,
            )
            return self._workspace_from_record(record)

        return self._mapped(operation)

    def perform_controller_transition_request(
        self, experiment_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Parse a JSON transition request containing no evidence or executable input."""

        fields = {
            "schema_version",
            "expected_revision",
            "expected_digest",
            "action",
            "request_ref",
        }
        if (
            not isinstance(request, Mapping)
            or set(request) != fields
            or request.get("schema_version") != "bluefire.engine-controller-transition.v1"
        ):
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The controller transition request does not match the supported contract.",
            )
        try:
            action = EngineControllerAction(request["action"])
        except (TypeError, ValueError) as exc:
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The controller transition action is unsupported.",
            ) from exc
        return self.perform_controller_transition(
            experiment_id=experiment_id,
            expected_revision=request["expected_revision"],
            expected_digest=request["expected_digest"],
            action=action,
            request_ref=request["request_ref"],
        )

    def submit_controller_operation(
        self,
        *,
        experiment_id: str,
        expected_revision: int,
        expected_digest: str,
        action: EngineControllerJobAction,
        request_ref: str,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        """Submit a controller effect through an injected existing-job adapter."""

        def operation() -> Mapping[str, Any]:
            if not isinstance(action, EngineControllerJobAction):
                raise EngineExperimentError("controller job action is unsupported")
            if not isinstance(request_ref, str) or _DIGEST.fullmatch(request_ref) is None:
                raise EngineExperimentError(
                    "controller request must be a protected digest reference"
                )
            try:
                parsed_submission = uuid.UUID(str(submission_id))
            except ValueError as exc:
                raise EngineExperimentError(
                    "controller job submission identity is invalid"
                ) from exc
            if not isinstance(submission_id, str) or str(parsed_submission) != submission_id:
                raise EngineExperimentError("controller job submission identity is invalid")
            current = self._active(experiment_id)
            self._expect(
                current,
                expected_revision=expected_revision,
                expected_digest=expected_digest,
            )
            request = {
                "schema_version": "bluefire.engine-controller-job.v1",
                "experiment_id": current.experiment_id,
                "revision": current.revision,
                "experiment_digest": current.digest,
                "action": action.value,
                "request_ref": request_ref,
            }
            if not isinstance(intent_digest, str) or intent_digest != content_hash(request):
                raise EngineExperimentError("controller job submission intent changed")
            controller_jobs = self._controller_jobs
            if controller_jobs is None:
                raise EngineControllerOperationError("trusted controller jobs are unavailable")
            result = controller_jobs.submit(
                action=action,
                experiment=current,
                request_ref=request_ref,
                submission_id=submission_id,
                intent_digest=intent_digest,
            )
            return self._controller_job_receipt(
                result,
                experiment=current,
                action=action,
                submission_id=submission_id,
                intent_digest=intent_digest,
            )

        return self._mapped(operation)

    def submit_controller_operation_request(
        self, experiment_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Parse an effect request containing only protected references and job identity."""

        fields = {
            "schema_version",
            "expected_revision",
            "expected_digest",
            "action",
            "request_ref",
            "submission_id",
            "intent_digest",
        }
        if (
            not isinstance(request, Mapping)
            or set(request) != fields
            or request.get("schema_version") != "bluefire.engine-controller-job-submit.v1"
        ):
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The controller job request does not match the supported contract.",
            )
        try:
            action = EngineControllerJobAction(request["action"])
        except (TypeError, ValueError) as exc:
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "The controller job action is unsupported.",
            ) from exc
        return self.submit_controller_operation(
            experiment_id=experiment_id,
            expected_revision=request["expected_revision"],
            expected_digest=request["expected_digest"],
            action=action,
            request_ref=request["request_ref"],
            submission_id=request["submission_id"],
            intent_digest=request["intent_digest"],
        )

    def cancel_attempt(
        self,
        *,
        experiment_id: str,
        attempt_id: str,
        job_id: str,
    ) -> Mapping[str, Any]:
        """Cancel existing job custody, settling only proven undispatched work."""

        def operation() -> Mapping[str, Any]:
            experiment = self._active(experiment_id)
            _index, entry = experiment._attempt(attempt_id)
            if entry.job_id != job_id:
                raise EngineExperimentError("engine attempt belongs to another job")
            job = self._job_lifecycle.cancel(job_id)
            if not isinstance(job, Mapping) or job.get("job_id") != job_id:
                raise JobRuntimeError("job controller returned another job")
            state = job.get("state")
            if state not in {
                "queued",
                "planning",
                "running",
                "paused",
                "cancelling",
                "cancelled",
                "failed",
                "completed",
                "interrupted",
            }:
                raise JobRuntimeError("job controller returned an invalid state")
            if state == "cancelled":
                refreshed = self._active(experiment_id)
                _refreshed_index, refreshed_entry = refreshed._attempt(attempt_id)
                if (
                    refreshed_entry.record.state is AttemptState.QUEUED
                    and refreshed_entry.record.upstream_session_id is None
                    and refreshed_entry.settled_at is None
                ):
                    self._jobs.settle_undispatched_cancellation(
                        experiment_id=experiment_id,
                        attempt_id=attempt_id,
                        job_id=job_id,
                    )
            return {
                "schema_version": "bluefire.engine-attempt-cancellation.v1",
                "job": dict(json_clone(job)),
                "workspace": self._workspace_from_record(
                    self._history.get_engine_experiment(experiment_id)
                ),
            }

        return self._mapped(operation)

    def recover_attempt(self, *, experiment_id: str, attempt_id: str) -> Mapping[str, Any]:
        """Reconcile saved custody without relaunching or resubmitting an attempt."""

        def operation() -> Mapping[str, Any]:
            self._jobs.reconcile_interrupted_attempt(
                experiment_id=experiment_id,
                attempt_id=attempt_id,
            )
            return self._workspace_from_record(self._history.get_engine_experiment(experiment_id))

        return self._mapped(operation)

    def _assistance_presentation(
        self,
        experiment: EngineExperiment,
        *,
        selected_attempt_id: str | None,
        selected_check_id: str | None,
    ) -> Mapping[str, Any]:
        supplied = self._presentation_source.get_engine_experiment_presentation(
            experiment.experiment_id,
            revision=experiment.revision,
            experiment_digest=experiment.digest,
        )
        clone = json_clone(supplied)
        if not isinstance(clone, dict) or clone.get("selection") is not None:
            raise EngineExperimentWorkspaceError(
                "trusted presentation source cannot choose a workspace context"
            )
        if selected_attempt_id is not None:
            _index, entry = experiment._attempt(selected_attempt_id)
            binding = entry.record.binding
            clone["selection"] = {
                "kind": "engine_attempt",
                "id": binding.attempt_id,
                "role": binding.role.value,
                "job_id": entry.job_id,
                "run_id": binding.run_id,
            }
        elif selected_check_id is not None:
            matches = [check for check in experiment.checks if check.check_id == selected_check_id]
            if len(matches) != 1:
                raise EngineExperimentSelectionNotFound("selected controller check is unavailable")
            check = matches[0]
            clone["selection"] = {
                "kind": "controller_check",
                "id": check.check_id,
                "role": check.role.value,
                "job_id": check.job_id,
                "run_id": check.run_id,
            }
        return clone

    def _active(self, experiment_id: str) -> EngineExperiment:
        record = self._record(self._history.get_engine_experiment(experiment_id))
        if record["active"] is not True:
            raise ProductStoreError("engine experiment active head is invalid")
        return cast(EngineExperiment, record["experiment"])

    def _now(self) -> str:
        value = self._clock()
        try:
            parse_iso8601_datetime(value)
        except (TypeError, ValueError) as exc:
            raise EngineExperimentServiceError(
                "engine_clock_invalid",
                "The trusted service clock is unavailable.",
            ) from exc
        return value

    @staticmethod
    def _expect(
        experiment: EngineExperiment,
        *,
        expected_revision: int,
        expected_digest: str,
    ) -> None:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision != experiment.revision
            or not isinstance(expected_digest, str)
            or expected_digest != experiment.digest
        ):
            raise ResourceConflictError("engine experiment changed since it was reviewed")

    @staticmethod
    def _validate_successor(current: EngineExperiment, successor: Any) -> None:
        if not isinstance(successor, EngineExperiment):
            raise EngineControllerOperationError("trusted controller returned invalid state")
        successor.validate()
        if (
            successor.experiment_id != current.experiment_id
            or successor.objective_ref != current.objective_ref
            or successor.environment_ref != current.environment_ref
            or successor.scope_ref != current.scope_ref
            or successor.scope_version != current.scope_version
            or successor.initial_target_snapshot_ref != current.initial_target_snapshot_ref
            or successor.created_at != current.created_at
            or successor.revision != current.revision + 1
            or successor.previous_revision_digest != current.digest
        ):
            raise EngineControllerOperationError("trusted controller changed experiment identity")

    @staticmethod
    def _validate_action_successor(
        action: EngineControllerAction,
        current: EngineExperiment,
        successor: EngineExperiment,
    ) -> None:
        try:
            if action is EngineControllerAction.REVIEW_DEFENSE:
                if (
                    successor.defense_change is None
                    or successor.defense_change.state is not DefenseState.REVIEWED
                ):
                    raise EngineControllerOperationError("controller defense review is mismatched")
                expected = current.review_defense(
                    successor.defense_change,
                    timestamp=successor.updated_at,
                )
            else:
                if current.defense_change is None:
                    raise EngineControllerOperationError(
                        "controller defense retention lacks a change"
                    )
                expected = current.retain_defense(
                    current.defense_change.change_id,
                    retained_at=successor.updated_at,
                )
        except EngineExperimentError as exc:
            raise EngineControllerOperationError("controller defense state is mismatched") from exc
        if successor.to_dict() != expected.to_dict():
            raise EngineControllerOperationError(
                "trusted controller rewrote the reviewed experiment history"
            )

    @staticmethod
    def _controller_job_receipt(
        value: Mapping[str, Any],
        *,
        experiment: EngineExperiment,
        action: EngineControllerJobAction,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        fields = {
            "schema_version",
            "job_id",
            "kind",
            "experiment_id",
            "action",
            "submission_id",
            "intent_digest",
            "state",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != fields
            or value.get("schema_version") != "bluefire.engine-controller-job-submission.v1"
            or value.get("kind") != "engine-controller-operation"
            or value.get("experiment_id") != experiment.experiment_id
            or value.get("action") != action.value
            or value.get("submission_id") != submission_id
            or value.get("intent_digest") != intent_digest
            or value.get("state") not in _JOB_STATES
            or not isinstance(value.get("job_id"), str)
            or _JOB_ID.fullmatch(value["job_id"]) is None
        ):
            raise EngineControllerOperationError(
                "controller job adapter returned an unbound submission"
            )
        return dict(json_clone(value))

    @staticmethod
    def _validate_document(value: Mapping[str, Any]) -> Mapping[str, Any]:
        return EngineExperiment._from_controller_mapping(value).to_dict()

    def _read_from_record(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        record = self._record(value)
        experiment = record.pop("experiment")
        return {
            "schema_version": "bluefire.engine-experiment-read.v1",
            "record": record,
            "experiment": experiment.to_dict(),
        }

    def _workspace_from_record(
        self,
        value: Mapping[str, Any],
        *,
        selected_attempt_id: str | None = None,
        selected_check_id: str | None = None,
    ) -> Mapping[str, Any]:
        record = self._record(value)
        experiment = record.pop("experiment")
        if selected_attempt_id is not None and selected_check_id is not None:
            raise EngineExperimentServiceError(
                "engine_request_invalid",
                "Select one engine attempt or one controller check, not both.",
            )
        return present_engine_experiment_workspace(
            experiment,
            self._run_source,
            self._presentation_source,
            selected_attempt_id=selected_attempt_id,
            selected_check_id=selected_check_id,
        )

    @staticmethod
    def _record(value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != _RECORD_FIELDS:
            raise ProductStoreError("saved engine experiment record is invalid")
        if value.get("schema_version") != "bluefire.engine-experiment-record.v1":
            raise ProductStoreError("saved engine experiment record is unsupported")
        experiment_id = value.get("experiment_id")
        revision = value.get("revision")
        active_revision = value.get("active_revision")
        digest = value.get("digest")
        prior_digest = value.get("prior_digest")
        active = value.get("active")
        if (
            not isinstance(experiment_id, str)
            or _EXPERIMENT_ID.fullmatch(experiment_id) is None
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision <= 0
            or isinstance(active_revision, bool)
            or not isinstance(active_revision, int)
            or active_revision < revision
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            or (
                prior_digest is not None
                and (not isinstance(prior_digest, str) or _DIGEST.fullmatch(prior_digest) is None)
            )
            or not isinstance(active, bool)
            or active != (revision == active_revision)
        ):
            raise ProductStoreError("saved engine experiment record fields are invalid")
        created_at = value.get("created_at")
        if not isinstance(created_at, str):
            raise ProductStoreError("saved engine experiment record time is invalid")
        try:
            parse_iso8601_datetime(created_at)
        except (TypeError, ValueError) as exc:
            raise ProductStoreError("saved engine experiment record time is invalid") from exc
        experiment = EngineExperiment._from_controller_mapping(value.get("document"))
        if (
            experiment.experiment_id != experiment_id
            or experiment.revision != revision
            or experiment.previous_revision_digest != prior_digest
            or experiment.digest != digest
        ):
            raise ProductStoreError("saved engine experiment record integrity failed")
        return {
            "schema_version": "bluefire.engine-experiment-record.v1",
            "experiment_id": experiment_id,
            "revision": revision,
            "prior_digest": prior_digest,
            "digest": digest,
            "created_at": created_at,
            "active": active,
            "active_revision": active_revision,
            "experiment": experiment,
        }

    @staticmethod
    def _head(value: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(value, Mapping) or set(value) != _HEAD_FIELDS:
            raise ProductStoreError("saved engine experiment head is invalid")
        if value.get("schema_version") != "bluefire.engine-experiment-head.v1":
            raise ProductStoreError("saved engine experiment head is unsupported")
        experiment_id = value.get("experiment_id")
        revision = value.get("active_revision")
        digest = value.get("active_digest")
        if (
            not isinstance(experiment_id, str)
            or _EXPERIMENT_ID.fullmatch(experiment_id) is None
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision <= 0
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
        ):
            raise ProductStoreError("saved engine experiment head fields are invalid")
        created_at = value.get("created_at")
        updated_at = value.get("updated_at")
        if not isinstance(created_at, str) or not isinstance(updated_at, str):
            raise ProductStoreError("saved engine experiment head time is invalid")
        try:
            created = parse_iso8601_datetime(created_at)
            updated = parse_iso8601_datetime(updated_at)
        except (TypeError, ValueError) as exc:
            raise ProductStoreError("saved engine experiment head time is invalid") from exc
        if updated < created:
            raise ProductStoreError("saved engine experiment head time moved backward")
        return dict(json_clone(value))

    @staticmethod
    def _mapped(callback: Callable[[], _T]) -> _T:
        try:
            return callback()
        except EngineExperimentServiceError:
            raise
        except ResourceConflictError as exc:
            raise EngineExperimentServiceError(
                "engine_experiment_conflict",
                "The experiment changed after review. Refresh it before continuing.",
            ) from exc
        except EngineExperimentJobError as exc:
            raise EngineExperimentServiceError(
                "engine_execution_refused",
                "The saved engine attempt is unavailable, changed, or unsafe to execute.",
            ) from exc
        except EngineControllerOperationError as exc:
            raise EngineExperimentServiceError(
                "engine_controller_refused",
                "The trusted observation or defense operation could not be completed safely.",
            ) from exc
        except EngineDelegationError as exc:
            raise EngineExperimentServiceError(
                "engine_authority_refused",
                "The saved engine delegation or one-time approval is invalid or stale.",
            ) from exc
        except EngineExperimentError as exc:
            raise EngineExperimentServiceError(
                "engine_experiment_refused",
                "The saved experiment transition is invalid or out of sequence.",
            ) from exc
        except EngineExperimentSelectionNotFound as exc:
            raise EngineExperimentServiceError(
                "engine_selection_not_found",
                "The selected work is not in this saved experiment.",
            ) from exc
        except EngineExperimentAssistanceError as exc:
            raise EngineExperimentServiceError(
                "engine_assistance_context_unavailable",
                "The saved Assistant context is unavailable or changed.",
            ) from exc
        except EngineExperimentWorkspaceError as exc:
            raise EngineExperimentServiceError(
                "engine_workspace_unavailable",
                "The saved experiment workspace is unavailable or changed.",
            ) from exc
        except RunStoreError as exc:
            raise EngineExperimentServiceError(
                "engine_evidence_unavailable",
                "The saved run evidence is unavailable or failed integrity verification.",
            ) from exc
        except JobRuntimeError as exc:
            raise EngineExperimentServiceError(
                "engine_job_unavailable",
                "The retained engine job cannot be controlled from its current state.",
            ) from exc
        except ProductStoreError as exc:
            raise EngineExperimentServiceError(
                "engine_experiment_unavailable",
                "The saved engine experiment is unavailable or failed integrity verification.",
            ) from exc


__all__ = [
    "EngineControllerAction",
    "EngineControllerJobAction",
    "EngineControllerJobs",
    "EngineControllerOperationError",
    "EngineExperimentHistory",
    "EngineExperimentService",
    "EngineExperimentServiceError",
    "EngineJobLifecycle",
    "EngineExperimentPresentationSource",
    "TrustedEngineController",
]
