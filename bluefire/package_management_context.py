"""Explicit borrowed services for action-package management."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .action_catalog import ActionCatalogSnapshot
from .config import RunnerProfile
from .contracts import ExecutionMode
from .product_store import ProductStore
from .registry import BehaviorRegistry
from .runner_client import RunnerTransport


class ActionPackageContext(Protocol):
    """Borrow the existing catalog boundary without a reverse facade import."""

    product_store: ProductStore
    _built_in_registry: BehaviorRegistry
    runner_factory: Callable[[RunnerProfile], tuple[RunnerTransport, Path]]

    @property
    def _action_catalog_lock(self) -> AbstractContextManager[Any]: ...

    def _profile(self, value: Any, mode: ExecutionMode) -> RunnerProfile | None: ...

    def _runner_profiles(self) -> tuple[RunnerProfile, ...]: ...

    def _action_catalog_boundary(
        self, expected: Mapping[str, Any] | None = None
    ) -> ActionCatalogSnapshot: ...

    def _refresh_action_catalog(self) -> ActionCatalogSnapshot: ...
