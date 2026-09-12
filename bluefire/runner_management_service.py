"""Application service for explicit managed-runner lifecycle operations."""

from __future__ import annotations

import re
from contextlib import contextmanager
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Iterator, Mapping

from .application_errors import APIError
from .contracts import ExecutionMode
from .runner_bootstrap import RUNNER_ID
from .runner_lifecycle import RunnerLifecycleError
from .util import content_hash

if TYPE_CHECKING:
    from .config import RunnerProfile
    from .runner_lifecycle import ManagedRunnerLifecycle


class RunnerManagementServiceMixin:
    """Expose runner lifecycle operations without owning the HTTP adapter."""

    if TYPE_CHECKING:
        import threading

        from .job_runtime import RunJobController

        runner_lifecycle: ManagedRunnerLifecycle
        job_controller: RunJobController
        _runtime_configuration_lock: threading.RLock

        def _runner_lifecycle_profile(self, profile_id: str | None) -> RunnerProfile | None: ...

        def _runner_profiles(self) -> tuple[RunnerProfile, ...]: ...

    def runner_status(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Return path-free managed-runner state without starting it."""

        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.status(
                profile_id=selected.id if selected is not None else None,
                profile_budget_seconds=(
                    selected.budgets.max_seconds
                    if selected is not None
                    else self._managed_host_profile_budget()
                ),
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
        upgrade_review_digest: str | None = None,
    ) -> Mapping[str, Any]:
        """Explicitly install/verify the packaged runner and local enrollment."""

        if type(allow_upgrade) is not bool or (
            upgrade_review_digest is not None
            and (
                not allow_upgrade
                or not isinstance(upgrade_review_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", upgrade_review_digest) is None
            )
        ):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "runner_bootstrap_invalid",
                "Runner upgrade requires a boolean confirmation and an optional exact review digest.",
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
            if upgrade_review_digest is not None:
                with self._runner_upgrade_admission():
                    current_profiles = tuple(
                        profile
                        for profile in self._runner_profiles()
                        if profile.mode is ExecutionMode.EXECUTE
                    )
                    return self.runner_lifecycle.bootstrap(
                        allowed_profile_ids=tuple(profile.id for profile in current_profiles),
                        allow_upgrade=True,
                        upgrade_review_digest=upgrade_review_digest,
                        profile_binding=content_hash(
                            [profile.to_dict() for profile in current_profiles]
                        ),
                    )
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

    @contextmanager
    def _runner_upgrade_admission(self) -> Iterator[None]:
        """Keep profile edits and new jobs out of the exact reviewed transition."""
        from .job_runtime import JobRuntimeError

        try:
            with self._runtime_configuration_lock, self.job_controller.idle_guard():
                yield
        except JobRuntimeError:
            raise RunnerLifecycleError(
                "Runner upgrade requires all product jobs to be idle."
            ) from None

    def review_runner_upgrade(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Stage the packaged artifact and review a stopped history-preserving upgrade."""
        self._runner_lifecycle_profile(profile_id)
        try:
            with self._runner_upgrade_admission():
                profiles = tuple(
                    profile
                    for profile in self._runner_profiles()
                    if profile.mode is ExecutionMode.EXECUTE
                )
                if not profiles:
                    raise RunnerLifecycleError(
                        "No Execute runner profile is available for enrollment."
                    )
                return self.runner_lifecycle.review_upgrade(
                    allowed_profile_ids=tuple(profile.id for profile in profiles),
                    profile_binding=content_hash([profile.to_dict() for profile in profiles]),
                )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_upgrade_review_refused",
                "Managed runner upgrade review was refused.",
                [str(exc)],
            ) from exc

    def start_runner(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        selected = self._runner_lifecycle_profile(profile_id)
        try:
            return self.runner_lifecycle.start(
                profile_id=selected.id if selected is not None else None,
                profile_budget_seconds=self._managed_host_profile_budget(),
            )
        except RunnerLifecycleError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "runner_start_refused",
                "Managed runner start was refused.",
                [str(exc)],
            ) from exc

    def _managed_host_profile_budget(self) -> int | None:
        return max(
            (
                profile.budgets.max_seconds
                for profile in self._runner_profiles()
                if profile.mode is ExecutionMode.EXECUTE
            ),
            default=None,
        )

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
