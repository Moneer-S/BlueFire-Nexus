"""Narrow existing service seams borrowed by native run assistance."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .action_catalog import ActionCatalogSnapshot
from .ai_provider_access import AIProviderAccess
from .config import AIConfig, RunnerProfile
from .contracts import ExecutionMode
from .detection_lab import DetectionLabService
from .job_runtime import RunJobController
from .product_store import ProductStore
from .run_store import RunStore


class AssistanceRunService(Protocol):
    product_store: ProductStore
    store: RunStore
    job_controller: RunJobController
    detection_lab: DetectionLabService
    _provider_access: AIProviderAccess
    _runtime_configuration_lock: Any
    _action_catalog_lock: Any
    assistance_runs: Any

    def _runtime_ai(self) -> AIConfig: ...
    def _mode(self, request: Mapping[str, Any]) -> ExecutionMode: ...
    def _profile(self, value: Any, mode: ExecutionMode) -> RunnerProfile | None: ...
    def _action_catalog_boundary(self) -> ActionCatalogSnapshot: ...
    def _approval_review_expires_at(self) -> str: ...
    def graph_ai_job(self, job_id: str) -> Mapping[str, Any]: ...
    def scenario_version(self, scenario_id: str, *, version: int) -> Mapping[str, Any]: ...
    def preflight(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def job(self, job_id: str) -> Mapping[str, Any]: ...
    def submit_run(
        self, request: Mapping[str, Any], *, _assistance_run: Mapping[str, Any] | None = None
    ) -> Mapping[str, Any]: ...
