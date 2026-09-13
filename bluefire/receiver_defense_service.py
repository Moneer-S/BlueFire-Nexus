"""Public JSON boundary for explicit native receiver comparison operations."""

from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .application_errors import APIError
from .product_store_errors import ProductStoreError
from .receiver_session_contract import ReceiverSessionError


class ReceiverDefenseServiceMixin:
    if TYPE_CHECKING:
        from .receiver_defense_jobs import ReceiverDefenseJobs

        receiver_defense: ReceiverDefenseJobs

    def _receiver_call(self, callback: Callable[[], Mapping[str, Any]]) -> Mapping[str, Any]:
        try:
            return callback()
        except APIError:
            raise
        except (ProductStoreError, ReceiverSessionError, KeyError, TypeError, ValueError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "receiver_defense_refused",
                "The exact receiver comparison request is unavailable, changed, or unsafe to repeat.",
            ) from exc

    def receiver_defense_context(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.context(request))

    def submit_receiver_defense(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.submit(request))

    def receiver_defense_job(self, job_id: str) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.read(job_id))

    def receiver_defense_jobs(self, *, cursor: str | None = None) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.list(cursor=cursor))

    def prepare_receiver_defense(
        self, job_id: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.prepare(job_id, request))

    def review_receiver_defense(self, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._receiver_call(lambda: self.receiver_defense.review(job_id, request))
