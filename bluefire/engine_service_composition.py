"""Service-owned engine assembly, binding, and construction rollback.

The optional inert factory receives the service's sole ProductStore. It closes
its own partial allocations if it raises; only a successfully claimed returned
composition transfers lifecycle ownership. Explicit adapter injection remains
externally owned, and unconfigured engine admission stays closed.
"""

from __future__ import annotations

import threading
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

from .application_errors import APIError
from .engine_action_preparation import EngineActionPreparationCoordinator
from .engine_action_submission import EngineActionSubmissionCoordinator
from .engine_artifact_store import EngineArtifactStore
from .engine_experiment_jobs import EngineAttemptRuntime, EngineExperimentJobs
from .engine_experiment_service import (
    EngineControllerJobs,
    EngineExperimentService,
    EngineExperimentServiceError,
    TrustedEngineController,
)
from .engine_experiment_workspace import EngineExperimentPresentationSource
from .engine_installed_composition import InstalledEngineCleanupUnresolved
from .job_runtime import RunJobController
from .product_store import ProductStore, ProductStoreError
from .run_store import RunStore

if TYPE_CHECKING:
    from .engine_installed_composition import InstalledEngineComposition

EngineControllerJobsFactory = Callable[
    [ProductStore, RunStore, RunJobController], EngineControllerJobs
]
EngineActionPreparationFactory = Callable[
    [ProductStore, EngineExperimentService], EngineActionPreparationCoordinator
]
EngineActionSubmissionFactory = Callable[
    [ProductStore, EngineExperimentService, EngineExperimentJobs, EngineControllerJobs | None],
    EngineActionSubmissionCoordinator,
]
EngineWorkflowCompositionFactory = Callable[[ProductStore], "InstalledEngineComposition"]


class EngineServiceComposition:
    """Validate and own one engine assembly without allocating service stores."""

    def __init__(
        self,
        *,
        runtime: EngineAttemptRuntime | None = None,
        controller: TrustedEngineController | None = None,
        controller_jobs: EngineControllerJobs | None = None,
        controller_jobs_factory: EngineControllerJobsFactory | None = None,
        preparation_factory: EngineActionPreparationFactory | None = None,
        submission_factory: EngineActionSubmissionFactory | None = None,
        artifact_store: EngineArtifactStore | None = None,
        composition: InstalledEngineComposition | None = None,
        composition_factory: EngineWorkflowCompositionFactory | None = None,
    ) -> None:
        if composition is not None and composition_factory is not None:
            raise ValueError(
                "Configure either an engine workflow composition or its service-owned factory."
            )
        if composition is not None or composition_factory is not None:
            if any(
                value is not None
                for value in (
                    runtime,
                    controller,
                    controller_jobs,
                    controller_jobs_factory,
                    preparation_factory,
                    submission_factory,
                    artifact_store,
                )
            ):
                raise ValueError(
                    "Configure either an engine workflow composition or explicit engine adapters."
                )
        if controller_jobs is not None and controller_jobs_factory is not None:
            raise ValueError(
                "Configure either engine controller jobs or its service-owned factory, not both."
            )
        self._composition: InstalledEngineComposition | None = None
        self._store: ProductStore | None = None
        self._composition_factory = composition_factory
        self._close_lock = threading.Lock()
        self._close_attempted = False
        self._runtime, self._controller = runtime, controller
        self._controller_jobs, self._controller_jobs_factory = (
            controller_jobs,
            controller_jobs_factory,
        )
        self._preparation_factory, self._submission_factory = (
            preparation_factory,
            submission_factory,
        )
        if artifact_store is not None and type(artifact_store) is not EngineArtifactStore:
            raise ValueError("The engine artifact reader must be a protected store.")
        self._artifact_store = artifact_store
        if composition is not None:
            self._claim(composition)

    def _claim(self, composition: InstalledEngineComposition) -> None:
        # Claim before adoption: a rejected owner may belong to another service.
        composition.claim_service()
        self._composition = composition

    def after_store(self, store: ProductStore) -> None:
        """Construct and claim the owner before binding any engine jobs."""
        if self._store is not None:
            if store is not self._store:
                raise ProductStoreError("Engine assembly belongs to another product store.")
            return
        if self._composition_factory is not None:
            self._claim(self._composition_factory(store))
        composition = self._composition
        if composition is not None:
            self._runtime, self._controller = composition.runtime, composition.controller
            self._artifact_store = composition.adapters.artifact_store
            self._controller_jobs_factory = composition.controller_jobs_factory
            self._preparation_factory = composition.action_preparation_factory
            self._submission_factory = composition.action_submission_factory
        self._store = store

    def bind(
        self,
        *,
        store: ProductStore,
        run_store: RunStore,
        jobs: RunJobController,
        presentation_source: EngineExperimentPresentationSource | None,
        clock: Callable[[], str],
    ) -> tuple[EngineExperimentJobs, EngineExperimentService]:
        """Wire only pure factories around the exact shared service owners."""
        if store is not self._store:
            raise ProductStoreError("Engine assembly belongs to another product store.")
        controller_jobs = (
            self._controller_jobs_factory(store, run_store, jobs)
            if self._controller_jobs_factory is not None
            else self._controller_jobs
        )
        composition = self._composition
        attempts = EngineExperimentJobs(
            controller=jobs,
            repository=store,
            runtime=self._runtime,
            clock=clock,
            reconciliation=(
                composition.reconciliation_coordinator if composition is not None else None
            ),
        )
        workspace = EngineExperimentService(
            history=store,
            run_source=run_store,
            jobs=attempts,
            job_lifecycle=jobs,
            controller=self._controller,
            clock=clock,
            presentation_source=presentation_source if presentation_source is not None else store,
            controller_jobs=controller_jobs,
            artifact_store=self._artifact_store,
        )
        if self._preparation_factory is not None:
            workspace._action_preparation = self._preparation_factory(store, workspace)
        if self._submission_factory is not None:
            workspace._action_submission = self._submission_factory(
                store, workspace, attempts, controller_jobs
            )
        return attempts, workspace

    def close(self, jobs: RunJobController | None) -> None:
        """Join workers before closing acquired resources, preserving retry rules."""
        composition = self._composition
        if composition is None:
            if jobs is not None:
                jobs.shutdown()
            return
        with self._close_lock:
            if self._close_attempted:
                return
            try:
                composition.shutdown_jobs(jobs)
            except Exception:
                raise ProductStoreError("The owned engine jobs could not be stopped.") from None
            try:
                composition.close()
            except InstalledEngineCleanupUnresolved:
                # A later close may advance only an effect-specific receipt.
                # Unknown generic handles remain unresolved without a retry.
                raise ProductStoreError("The owned engine resources could not be closed.") from None
            except Exception:
                self._close_attempted = True
                raise ProductStoreError("The owned engine resources could not be closed.") from None
            self._close_attempted = True


class InitializingEngineService(Protocol):
    def _close_engine_workflow(self) -> None: ...


def rollback_service_initialization(service: InitializingEngineService) -> None:
    """Release acquired owners in the service's established rollback order."""
    for attribute in ("_provider_access", "_provider_check_transport"):
        owner: Any = getattr(service, attribute, None)
        if owner is not None:
            try:
                owner.close()
            except Exception:
                pass
    try:
        service._close_engine_workflow()
    except Exception:
        # Preserve the initialization failure, including when cleanup fails.
        pass
    for attribute in ("receiver_defense", "composition"):
        owner = getattr(service, attribute, None)
        if owner is not None:
            try:
                owner.owners.close_all()
            except Exception:
                pass
    control = getattr(service, "_file_access", None)
    if control is not None:
        for owner in (control.windows, control.windows_correction):
            try:
                owner.close_all()
            except Exception:
                pass


def cancel_engine_job(
    *,
    store: ProductStore,
    workspace: EngineExperimentService,
    job_id: str,
    job: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Route engine cancellation through its exact saved attempt or check."""
    if job.get("kind") == EngineExperimentJobs.JOB_KIND:
        request = job.get("request")
        experiment_id = request.get("experiment_id") if isinstance(request, Mapping) else None
        attempt_id = request.get("attempt_id") if isinstance(request, Mapping) else None
        if not isinstance(experiment_id, str) or not isinstance(attempt_id, str):
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_signal_refused",
                "The engine job could not be bound to its saved attempt.",
            )
        try:
            cancellation = workspace.cancel_attempt(
                experiment_id=experiment_id,
                attempt_id=attempt_id,
                job_id=job_id,
            )
        except EngineExperimentServiceError as exc:
            try:
                durable_job = store.get_job(job_id)
            except ProductStoreError:
                durable_job = None
            if isinstance(durable_job, Mapping) and durable_job.get("state") in {
                "cancelling",
                "cancelled",
            }:
                return dict(durable_job)
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_signal_refused",
                "The engine job could not be cancelled from its current state.",
            ) from exc
        cancelled_job = cancellation.get("job")
        if not isinstance(cancelled_job, Mapping):
            raise APIError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "invalid_service_response",
                "The engine cancellation returned an invalid job response.",
            )
        return dict(cancelled_job)
    if job.get("kind") == "engine-controller-check":
        request = job.get("request")
        experiment_id = request.get("experiment_id") if isinstance(request, Mapping) else None
        check_id = request.get("check_id") if isinstance(request, Mapping) else None
        if not isinstance(experiment_id, str) or not isinstance(check_id, str):
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_signal_refused",
                "The controller-check job could not be bound to its saved check.",
            )
        try:
            cancellation = workspace.cancel_controller_check(
                experiment_id=experiment_id,
                check_id=check_id,
                job_id=job_id,
            )
        except EngineExperimentServiceError as exc:
            try:
                durable_job = store.get_job(job_id)
            except ProductStoreError:
                durable_job = None
            if isinstance(durable_job, Mapping) and durable_job.get("state") in {
                "cancelling",
                "cancelled",
            }:
                return dict(durable_job)
            raise APIError(
                HTTPStatus.CONFLICT,
                "job_signal_refused",
                "The controller-check job could not be cancelled from its current state.",
            ) from exc
        cancelled_job = cancellation.get("job")
        if not isinstance(cancelled_job, Mapping):
            raise APIError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "invalid_service_response",
                "The controller-check cancellation returned an invalid job response.",
            )
        return dict(cancelled_job)
    return None
