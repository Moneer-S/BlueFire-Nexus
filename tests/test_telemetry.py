from pathlib import Path

from src.core.models import TelemetryEvent
from src.core.telemetry import TelemetryBus


def test_telemetry_uses_priority_remote_plus_jsonl(tmp_path: Path):
    config = {
        "telemetry": {
            "sinks": [
                {"type": "splunk", "enabled": True, "endpoint": "https://splunk.example/hec"},
                {
                    "type": "opensearch",
                    "enabled": True,
                    "endpoint": "https://opensearch.example/_bulk",
                },
            ]
        }
    }
    bus = TelemetryBus(config, tmp_path)
    sink_types = [sink.sink_type for sink in bus.sinks]

    # opensearch has priority over splunk if both are enabled.
    assert sink_types[0] == "opensearch"
    # local jsonl sink is always present.
    assert sink_types[-1] == "jsonl"

    results = bus.emit(TelemetryEvent(event_type="test", module="test"))
    assert len(results) == 2
