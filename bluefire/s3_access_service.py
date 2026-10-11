"""Thin JSON service boundary for the saved S3 workspace."""

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .application_errors import APIError
from .job_runtime import JobRuntimeError
from .product_store_errors import ProductStoreError
from .run_store import RunStoreError
from .s3_access_contract import S3AccessError


class S3AccessServiceMixin:
    if TYPE_CHECKING:
        from .s3_access_jobs import S3AccessJobs

        s3_access: S3AccessJobs

    def _s3_call(self, callback: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]:
        try:
            return callback()
        except (
            S3AccessError,
            ProductStoreError,
            RunStoreError,
            JobRuntimeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "s3_access_refused",
                "The saved S3 request is unavailable, changed, or unsafe to repeat. Refresh its retained state and review before another operation.",
            ) from exc

    def s3_access_environments(self) -> Mapping[str, Any]:
        return self._s3_call(self.s3_access.environments)

    def s3_access_setup_profiles(self) -> Mapping[str, Any]:
        from .s3_access_onboarding import setup_profiles

        return setup_profiles(self)

    def check_s3_access_setup(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        from .s3_access_onboarding import check_setup

        return check_setup(self, request)

    def review_s3_access_setup_draft(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        from .s3_access_onboarding import review_draft

        return review_draft(self, request)

    def s3_access_saved_setup_draft(self, profile_id: str) -> Mapping[str, Any]:
        from .s3_access_setup_drafts import read_saved_draft

        return read_saved_draft(self, profile_id)

    def save_s3_access_setup_draft(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        from .s3_access_setup_drafts import save_draft

        return save_draft(self, request)

    def s3_access_exercises(self) -> Mapping[str, Any]:
        return self._s3_call(self.s3_access.list_exercises)

    def create_s3_access(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.create(request))

    def s3_access_exercise(self, identifier: str) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.read(identifier))

    def review_s3_access(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.review(identifier, request))

    def submit_s3_access(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.submit(identifier, request))

    def stop_s3_access(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.stop(identifier, request))

    def recover_s3_access(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._s3_call(lambda: self.s3_access.recover(identifier, request))

    def s3_audit_reviews(self, identifier: str) -> Mapping[str, Any]:
        from .s3_audit_reviews import list_reviews

        return self._s3_call(lambda: list_reviews(self.s3_access, identifier))

    def s3_audit_review(self, identifier: str, review_id: str) -> Mapping[str, Any]:
        from .s3_audit_reviews import read_review

        return self._s3_call(lambda: read_review(self.s3_access, identifier, review_id))

    def save_s3_audit_review(
        self, identifier: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        from .s3_audit_reviews import save_review

        return self._s3_call(lambda: save_review(self.s3_access, identifier, request))
