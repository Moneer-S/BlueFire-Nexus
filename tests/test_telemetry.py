"""Local-first telemetry tests.

Outbound SIEM exporters (Splunk/OpenSearch/Elasticsearch/NGSIEM) were removed
from the baseline. These tests confirm:

* JSONL is always the active sink, with a sane default path.
* Legacy remote-sink config entries are ignored with a deprecation warning,
  so old configs do not crash and do not silently regain network egress.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.core.models import TelemetryEvent
from src.core.telemetry import (
    JSONLSink,
    LocalTelemetrySink,
    TelemetryBus,
    build_sinks,
)


def test_jsonl_sink_writes_local_file(tmp_path: Path) -> None:
    target = tmp_path / "out" / "telemetry.jsonl"
    sink = JSONLSink(target)
    result = sink.send({"event_type": "test", "module": "test"})
    assert result.success is True
    assert target.exists()
    line = target.read_text(encoding="utf-8").strip()
    assert json.loads(line) == {"event_type": "test", "module": "test"}


def test_local_telemetry_sink_alias_is_jsonl() -> None:
    assert LocalTelemetrySink is JSONLSink


def test_telemetry_bus_defaults_to_local_jsonl_only(tmp_path: Path) -> None:
    bus = TelemetryBus({}, tmp_path)
    assert [sink.sink_type for sink in bus.sinks] == ["jsonl"]
    results = bus.emit(TelemetryEvent(event_type="test", module="test"))
    assert len(results) == 1
    assert results[0].success is True
    assert (tmp_path / "telemetry.jsonl").exists()


def test_legacy_remote_sink_configs_are_ignored_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = {
        "telemetry": {
            "sinks": [
                {"type": "splunk", "enabled": True, "endpoint": "https://splunk.example/hec"},
                {"type": "opensearch", "enabled": True, "endpoint": "https://opensearch.example"},
                {"type": "elasticsearch", "enabled": True, "endpoint": "https://es.example"},
                {"type": "ngsiem", "enabled": True, "endpoint": "https://ngsiem.example"},
                {"type": "http_bulk", "enabled": True, "endpoint": "https://collector.example"},
            ]
        }
    }
    with caplog.at_level(logging.WARNING, logger="src.core.telemetry.sinks"):
        bus = TelemetryBus(config, tmp_path)

    # Only the local JSONL sink survives, regardless of legacy config entries.
    assert [sink.sink_type for sink in bus.sinks] == ["jsonl"]

    warned_for = {
        record.args[0]
        for record in caplog.records
        if "no longer supported" in record.getMessage()
    }
    assert warned_for == {"splunk", "opensearch", "elasticsearch", "ngsiem", "http_bulk"}


def test_jsonl_sink_honours_explicit_path(tmp_path: Path) -> None:
    custom = tmp_path / "custom" / "events.jsonl"
    sinks = build_sinks(
        [{"type": "jsonl", "enabled": True, "file": str(custom)}],
        tmp_path,
    )
    assert len(sinks) == 1
    assert isinstance(sinks[0], JSONLSink)
    assert sinks[0].output_file == custom
