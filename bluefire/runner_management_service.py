"""Application service for explicit managed-runner lifecycle operations."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Mapping

from .application_errors import APIError
from .contracts import ExecutionMode
from .runner_bootstrap import RUNNER_ID
from .runner_lifecycle import RunnerLifecycleError

if TYPE_CHECKING:
    from .config import RunnerProfile
    from .runner_lifecycle import ManagedRunnerLifecycle


class RunnerManagementServiceMixin:
    """Expose runner lifecycle operations without owning the HTTP adapter."""

    if TYPE_CHECKING:
        runner_lifecycle: ManagedRunnerLifecycle

        def _runner_lifecycle_profile(self, profile_id: str | None) -> RunnerProfile | None: ...

        def _runner_profiles(self) -> tuple[RunnerProfile, ...]: ...

    def runner_status(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Return path-free managed-runner state without starting it."""

        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.status(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_lifecycle_unavailable",
                "Managed runner status could not be verified.",
                [str(exc)],
            ) from exc

    def bootstrap_runner(
        self,
        *,
        profile_id: str | None = None,
        allow_upgrade: bool = False,
    ) -> Mapping[str, Any]:
        """Explicitly install/verify the packaged runner and local enrollment."""

        if type(allow_upgrade) is not bool:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "runner_bootstrap_invalid",
                "Runner upgrade confirmation must be boolean.",
            )
        self._runner_lifecycle_profile(profile_id)
        profiles = tuple(
            profile for profile in self._runner_profiles() if profile.mode is ExecutionMode.EXECUTE
        )
        if not profiles:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_profile_unavailable",
                "No Execute runner profile is available for enrollment.",
            )
        try:
            return self.runner_lifecycle.bootstrap(
                allowed_profile_ids=tuple(profile.id for profile in profiles),
                allow_upgrade=allow_upgrade,
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_bootstrap_refused",
                "Managed runner bootstrap was refused.",
                [str(exc)],
            ) from exc

    def start_runner(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.start(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_start_refused",
                "Managed runner start was refused.",
                [str(exc)],
            ) from exc

    def stop_runner(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.stop(
                profile_id=selected.id if selected is not None else None
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_stop_refused",
                "Managed runner stop was refused.",
                [str(exc)],
            ) from exc

    def revoke_runner(self) -> Mapping[str, Any]:
        try:
            return self.runner_lifecycle.revoke()
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_revoke_refused",
                "Managed runner trust revocation was refused.",
                [str(exc)],
            ) from exc

    def remove_runner(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        if confirm_runner_id != RUNNER_ID:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "runner_remove_confirmation_invalid",
                "Runner removal requires the exact managed runner ID.",
            )
        try:
            return self.runner_lifecycle.remove(confirm_runner_id=confirm_runner_id)
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_remove_refused",
                "Managed runner removal was refused.",
                [str(exc)],
            ) from exc


__all__ = ["RunnerManagementServiceMixin"]
