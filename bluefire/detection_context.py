"""Independent application boundary for detector import and run evaluation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .detection_backends import ExternalDetectionValidator
from .detections import DetectionCandidate
from .product_store import ProductStore
from .run_store import RunStore


class DetectionContext(Protocol):
    """Services required by detector operations without a reverse facade import."""

    run_store: RunStore
    product_store: ProductStore
    validator: ExternalDetectionValidator

    @property
    def _lock(self) -> AbstractContextManager[Any]: ...

    @staticmethod
    def _fields(
        request: Mapping[str, Any], *, required: set[str], optional: set[str], context: str
    ) -> None: ...

    @staticmethod
    def _candidate_from_resource(resource: Mapping[str, Any]) -> DetectionCandidate: ...

    def _resource(self, candidate_id: str) -> Mapping[str, Any]: ...

    def upsert_hypothesis(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def clone(self, candidate_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
