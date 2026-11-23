"""Thin JSON service boundary for retained AD share-access workflows."""

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .ad_smb_contract import AdSmbError, document, exact
from .application_errors import APIError
from .job_runtime import JobRuntimeError
from .product_store_errors import ProductStoreError
from .run_store import RunStoreError


class AdSmbServiceMixin:
    if TYPE_CHECKING:
        from .ad_smb_jobs import AdSmbJobs

        ad_smb: AdSmbJobs

    def _ad_smb_call(self, callback: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]:
        try:
            return callback()
        except (
            AdSmbError,
            ProductStoreError,
            RunStoreError,
            JobRuntimeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "ad_smb_refused",
                "The saved AD request is unavailable, changed, or unsafe to repeat. Refresh its retained state before another operation.",
            ) from exc

    def ad_smb_environments(self) -> Mapping[str, Any]:
        return self._ad_smb_call(self.ad_smb.environments)

    def ad_smb_workflows(self) -> Mapping[str, Any]:
        return self._ad_smb_call(self.ad_smb.list)

    def create_ad_smb(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._ad_smb_call(lambda: self.ad_smb.create(request))

    def ad_smb_workflow(self, identifier: str) -> Mapping[str, Any]:
        return self._ad_smb_call(lambda: self.ad_smb.read(identifier))

    def ad_smb_assistance_context(self, identifier: str) -> Mapping[str, Any]:
        from .assistance_ad_smb_context import context

        return self._ad_smb_call(lambda: context(self, workflow_job_id=identifier))

    def review_ad_smb(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        def review() -> Mapping[str, Any]:
            row = document(request)
            exact(row, {"phase"}, "AD stage review")
            return self.ad_smb.review(identifier, row["phase"])

        return self._ad_smb_call(review)

    def submit_ad_smb(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._ad_smb_call(lambda: self.ad_smb.submit(identifier, request))

    def stop_ad_smb(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        def stop() -> Mapping[str, Any]:
            exact(document(request), set(), "AD stop")
            return self.ad_smb.stop(identifier)

        return self._ad_smb_call(stop)

    def recover_ad_smb(self, identifier: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        def recover() -> Mapping[str, Any]:
            exact(document(request), set(), "AD original-result recovery")
            return self.ad_smb.recover(identifier)

        return self._ad_smb_call(recover)
