"""Independent context for the reviewed source-intake operation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol

from .action_catalog import ActionCatalogSnapshot
from .config import RunnerProfile
from .contracts import ExecutionMode
from .product_store import ProductStore
from .run_store import RunStore


class ReviewedSourceIntakeContext(Protocol):
    """Only services borrowed by intake; never import the composition facade."""

    store: RunStore
    product_store: ProductStore

    @property
    def _action_catalog_lock(self) -> AbstractContextManager[Any]: ...

    def _profile(self, value: Any, mode: ExecutionMode) -> RunnerProfile | None: ...

    def _action_catalog_boundary(
        self, expected: Mapping[str, Any] | None = None
    ) -> ActionCatalogSnapshot: ...

    def _load_action_catalog_snapshot(
        self, generation: int | None = None
    ) -> ActionCatalogSnapshot: ...

    def trust_action_package_publisher(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def install_action_package(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def activate_action_package(
        self, package_id: str, version: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...
