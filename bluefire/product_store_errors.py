"""Stable error types shared by the durable product-store modules."""

from __future__ import annotations

from .domain_errors import ProductStoreError as ProductStoreError


class ResourceConflictError(ProductStoreError):
    """Raised when a resource changed after its expected snapshot was read."""


class ResearchSourceIntegrityError(ProductStoreError):
    """Raised when a persisted research-source identity would be rewritten."""


class DetectionRevisionIntegrityError(ProductStoreError):
    """Raised when an immutable detection revision identity conflicts."""


class DetectionRevisionLimitError(DetectionRevisionIntegrityError):
    """Raised when a detection lineage has reached its configured bound."""


class ActionPackageIntegrityError(ProductStoreError):
    """Raised when package bytes or persisted package identity fail verification."""


class ActionPackageConflictError(ActionPackageIntegrityError):
    """Raised when an immutable package or publisher identity would be rewritten."""


__all__ = [
    "ActionPackageConflictError",
    "ActionPackageIntegrityError",
    "DetectionRevisionIntegrityError",
    "DetectionRevisionLimitError",
    "ProductStoreError",
    "ResourceConflictError",
    "ResearchSourceIntegrityError",
]
