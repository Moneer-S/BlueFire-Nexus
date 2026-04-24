"""Telemetry bus that fans out events to configured sinks."""

from __future__ import annotations

import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..models import TelemetryEvent
from .sinks import SinkResult, TelemetrySink, build_sinks

LOGGER = logging.getLogger(__name__)


class TelemetryBus:
    """Send telemetry events to configured sinks."""

    def __init__(self, config: Dict[str, Any], run_dir: Path) -> None:
        telemetry_cfg = config.get("telemetry", {})
        sink_cfgs = telemetry_cfg.get("sinks", [])
        self.sinks: List[TelemetrySink] = build_sinks(sink_cfgs, run_dir)

    def emit(self, event: TelemetryEvent) -> list[SinkResult]:
        payload = asdict(event)
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

    def emit_many(self, events: Iterable[TelemetryEvent]) -> list[SinkResult]:
        results: list[SinkResult] = []
        for event in events:
            results.extend(self.emit(event))
        return results

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()
