"""Telemetry bus that fans out events to configured sinks."""

from __future__ import annotations

import logging
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..models import TelemetryEvent
from .sinks import SinkResult, TelemetrySink, build_sinks

LOGGER = logging.getLogger(__name__)


class TelemetryBus:
    """Send telemetry events to configured sinks.

    ``step_id`` and ``run_id`` (PR #147) flow through ``emit_many`` /
    ``emit`` so the orchestrator can annotate every event with the
    scenario step + run identifiers without changing module code.
    Module-emitted events typically leave both fields empty; the bus
    fills them in on the way out so downstream sinks see self-describing
    JSONL rows. Events that already carry a non-empty ``step_id`` /
    ``run_id`` (e.g. emitted by an out-of-tree module that decided to
    set them itself) are NOT overwritten — the original identifier
    wins.
    """

    def __init__(self, config: Dict[str, Any], run_dir: Path) -> None:
        telemetry_cfg = config.get("telemetry", {})
        sink_cfgs = telemetry_cfg.get("sinks", [])
        self.sinks: List[TelemetrySink] = build_sinks(sink_cfgs, run_dir)

    def emit(
        self,
        event: TelemetryEvent,
        *,
        step_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> list[SinkResult]:
        annotated = self._annotate(event, step_id=step_id, run_id=run_id)
        payload = asdict(annotated)
        results: list[SinkResult] = []
        for sink in self.sinks:
            sink_result = sink.send(payload)
            results.append(sink_result)
            if not sink_result.success:
                # Fail closed per sink; never crash run due to telemetry delivery.
                LOGGER.warning(
                    "Telemetry sink '%s' failed: %s",
                    sink_result.sink,
                    sink_result.detail,
                )
        return results

    def emit_many(
        self,
        events: Iterable[TelemetryEvent],
        *,
        step_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> list[SinkResult]:
        results: list[SinkResult] = []
        for event in events:
            results.extend(self.emit(event, step_id=step_id, run_id=run_id))
        return results

    @staticmethod
    def _annotate(
        event: TelemetryEvent,
        *,
        step_id: Optional[str],
        run_id: Optional[str],
    ) -> TelemetryEvent:
        """Return a copy of ``event`` with ``step_id`` / ``run_id`` filled in.

        Empty/missing identifiers on the original event are filled
        with the supplied values; pre-set identifiers are preserved
        (out-of-tree modules that set their own context win). Returns
        the original event unchanged when no annotation is needed so
        the dataclass replace cost stays bounded.
        """
        new_step = step_id if (step_id and not event.step_id) else event.step_id
        new_run = run_id if (run_id and not event.run_id) else event.run_id
        if new_step == event.step_id and new_run == event.run_id:
            return event
        return replace(event, step_id=new_step, run_id=new_run)

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()
