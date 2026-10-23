"""Bounded, privacy-safe timing for product metadata seeded by test fixtures."""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from functools import wraps
from typing import Callable, Iterator

_PHASES = {"service-init", "seed-metadata"}
_OPERATIONS = {"scenario-save", "resource-save"}


class SeedTiming:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._started = clock()
        self._phase = "service-init"
        self._counts = {
            "scenario-save": [0, 0],
            "resource-save": [0, 0],
        }
        self._current: str | None = None
        self._current_started: float | None = None
        self._reported: set[float] = set()
        self.monitor_thread: threading.Thread | None = None
        self.monitor_stop_failed = False

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        if name not in _PHASES:
            raise ValueError("seed timing phase is not allowlisted")
        with self._lock:
            previous = self._phase
            self._phase = name
        try:
            yield
        finally:
            with self._lock:
                self._phase = previous

    @contextmanager
    def operation(self, name: str) -> Iterator[None]:
        if name not in _OPERATIONS:
            raise ValueError("seed timing operation is not allowlisted")
        started = self._clock()
        with self._lock:
            self._counts[name][0] += 1
            self._current = name
            self._current_started = started
        try:
            yield
        finally:
            with self._lock:
                self._counts[name][1] += 1
                self._current = None
                self._current_started = None

    def report_due(
        self,
        thresholds: tuple[float, ...],
        *,
        now: float | None = None,
        write: Callable[[str], None] | None = None,
    ) -> None:
        current_time = self._clock() if now is None else now
        output = write or _write_stderr
        for threshold in thresholds:
            with self._lock:
                if current_time - self._started < threshold or threshold in self._reported:
                    continue
                self._reported.add(threshold)
                phase = self._phase
                elapsed = current_time - self._started
                current = self._current or "none"
                age = (
                    current_time - self._current_started
                    if self._current_started is not None
                    else 0.0
                )
                scenario_started, scenario_completed = self._counts["scenario-save"]
                resource_started, resource_completed = self._counts["resource-save"]
            output(
                "bluefire_seed_timing "
                f"elapsed={elapsed:.1f}s phase={phase} "
                f"scenario_saves={scenario_completed}/{scenario_started} "
                f"resource_saves={resource_completed}/{resource_started} "
                f"current={current} operation_age={age:.1f}s\n"
            )


def _write_stderr(message: str) -> None:
    try:
        sys.stderr.write(message)
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


@contextmanager
def observe_service_seed(
    service_module,
    store_class,
    *,
    thresholds: tuple[float, ...] = (60.0, 120.0),
    interval: float = 1.0,
    clock: Callable[[], float] = time.monotonic,
    write: Callable[[str], None] | None = None,
    monitor: bool = True,
    join_timeout: float = 2.0,
    thread_factory=threading.Thread,
) -> Iterator[SeedTiming]:
    """Temporarily wrap only metadata seeding and its two store-save methods."""
    if interval <= 0 or join_timeout <= 0 or any(value <= 0 for value in thresholds):
        raise ValueError("timing thresholds, interval, and join bound must be positive")
    if tuple(sorted(set(thresholds))) != thresholds:
        raise ValueError("timing thresholds must be strictly increasing")

    timing = SeedTiming(clock=clock)
    original_seed = service_module.seed_product_metadata
    original_scenario_save = store_class.save_scenario
    original_resource_save = store_class.save_resource

    @wraps(original_seed)
    def timed_seed(*args, **kwargs):
        with timing.phase("seed-metadata"):
            return original_seed(*args, **kwargs)

    @wraps(original_scenario_save)
    def timed_scenario_save(self, *args, **kwargs):
        with timing.operation("scenario-save"):
            return original_scenario_save(self, *args, **kwargs)

    @wraps(original_resource_save)
    def timed_resource_save(self, *args, **kwargs):
        with timing.operation("resource-save"):
            return original_resource_save(self, *args, **kwargs)

    stop = threading.Event()
    worker: threading.Thread | None = None
    try:
        service_module.seed_product_metadata = timed_seed
        store_class.save_scenario = timed_scenario_save
        store_class.save_resource = timed_resource_save
        if monitor and thresholds:

            def report() -> None:
                while not stop.wait(interval):
                    timing.report_due(thresholds, write=write)

            worker = thread_factory(target=report, name="bluefire-seed-timing", daemon=True)
            timing.monitor_thread = worker
            worker.start()
        yield timing
    finally:
        active_exception = sys.exc_info()[0] is not None
        stop.set()
        try:
            if worker is not None:
                try:
                    if worker.ident is not None:
                        worker.join(timeout=join_timeout)
                    if worker.ident is not None and worker.is_alive():
                        timing.monitor_stop_failed = True
                except Exception:
                    timing.monitor_stop_failed = True
        finally:
            service_module.seed_product_metadata = original_seed
            store_class.save_scenario = original_scenario_save
            store_class.save_resource = original_resource_save
        if timing.monitor_stop_failed and not active_exception:
            raise RuntimeError("seed timing monitor did not stop within its bound")
