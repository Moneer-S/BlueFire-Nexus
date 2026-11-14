"""Late construction of tenant controller jobs for one installed service.

Binding makes no target calls. The executors reopen accepted requests from the
service ProductStore and publish checks to its RunStore.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Callable

from .engine_installed_composition import (
    InstalledControllerJobAdapters,
    InstalledEngineCompositionError,
)
from .tenant_record_experiment_controller import TenantRecordExperimentController
from .tenant_record_job_executors import (
    ProductStoreTenantRecordAuthoritySource,
    TenantControllerCheckRunPublisher,
    TenantRecordControllerCheckExecutor,
    TenantRecordDefenseExecutor,
)

if TYPE_CHECKING:
    from .job_runtime import RunJobController
    from .product_store import ProductStore
    from .run_store import RunStore


class ControllerOwnedTenantRecordJobAdapterFactory:
    """Bind tenant defense and check executors to exact live service owners."""

    def __init__(
        self,
        *,
        controller: TenantRecordExperimentController,
        clock: Callable[[], str],
    ) -> None:
        if not isinstance(controller, TenantRecordExperimentController) or not callable(clock):
            raise InstalledEngineCompositionError(
                "tenant controller and trusted clock are required"
            )
        self._controller = controller
        self._clock = clock
        self._lock = threading.RLock()
        self._owners: tuple[ProductStore, RunStore, RunJobController] | None = None
        self._binding: InstalledControllerJobAdapters | None = None

    def bind(
        self, *, store: ProductStore, run_store: RunStore, jobs: RunJobController
    ) -> InstalledControllerJobAdapters:
        if store is None or run_store is None or jobs is None:
            raise InstalledEngineCompositionError("shared service owners are required")
        with self._lock:
            if self._owners is not None:
                if (
                    store is not self._owners[0]
                    or run_store is not self._owners[1]
                    or jobs is not self._owners[2]
                ):
                    raise InstalledEngineCompositionError(
                        "tenant controller-job adapters belong to another service"
                    )
                if self._binding is None:
                    raise InstalledEngineCompositionError(
                        "tenant controller-job adapter binding is incomplete"
                    )
                return self._binding

            authority = ProductStoreTenantRecordAuthoritySource(store)
            publisher = TenantControllerCheckRunPublisher(run_store, clock=self._clock)
            binding = InstalledControllerJobAdapters(
                defense_executor=TenantRecordDefenseExecutor(
                    controller=self._controller,
                    authority=authority,
                    clock=self._clock,
                ),
                check_executor=TenantRecordControllerCheckExecutor(
                    controller=self._controller,
                    authority=authority,
                    publisher=publisher,
                    clock=self._clock,
                ),
            )
            self._owners = (store, run_store, jobs)
            self._binding = binding
            return binding
