"""Telemetry bus that fans out events to configured sinks."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from ..models import TelemetryEvent
from .sinks import SinkResult, TelemetrySink, build_sinks


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
            results.append(sink.send(payload))
        return results

    def emit_many(self, events: Iterable[TelemetryEvent]) -> list[SinkResult]:
        results: list[SinkResult] = []
        for event in events:
            results.extend(self.emit(event))
        return results

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()
