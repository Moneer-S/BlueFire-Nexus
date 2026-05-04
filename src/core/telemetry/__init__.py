"""Telemetry package exports.

Baseline is local-first. Outbound SIEM exporters were removed during
stabilization; the package surface only exposes the local sink and the bus.
"""

from .bus import TelemetryBus
from .sinks import (
    JSONLSink,
    LocalTelemetrySink,
    SinkResult,
    TelemetrySink,
    build_sinks,
)

__all__ = [
    "TelemetryBus",
    "TelemetrySink",
    "SinkResult",
    "JSONLSink",
    "LocalTelemetrySink",
    "build_sinks",
]
