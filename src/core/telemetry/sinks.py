"""Telemetry sink abstractions and implementations.

Baseline scope is local-first: only the JSONL sink is active. Outbound SIEM
exporters (Splunk HEC, OpenSearch, Elasticsearch, NGSIEM, generic HTTP bulk)
were removed during baseline stabilization — they re-introduced uncontrolled
egress before the safety/mode model was finalized.

Old config keys naming remote sink types are detected by ``build_sinks`` and
ignored with a one-time warning, so legacy configs do not crash but also do
not silently regain network egress.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

LOGGER = logging.getLogger(__name__)

REMOVED_REMOTE_SINK_TYPES = frozenset(
    {"opensearch", "elasticsearch", "ngsiem", "splunk", "splunk_hec", "http_bulk"}
)


@dataclass
class SinkResult:
    sink: str
    success: bool
    detail: str = ""


class TelemetrySink:
    sink_type = "base"

    def send(self, event: Dict[str, Any]) -> SinkResult:
        raise NotImplementedError

    def close(self) -> None:
        return


class JSONLSink(TelemetrySink):
    """Append-only local JSON Lines sink. Project-internal artifact only."""

    sink_type = "jsonl"

    def __init__(self, output_file: Path):
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

    def send(self, event: Dict[str, Any]) -> SinkResult:
        with self.output_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")
        return SinkResult(self.sink_type, True, f"wrote {self.output_file}")


# Stable alias for callers that prefer a name reflecting the local-only contract.
LocalTelemetrySink = JSONLSink


def build_sinks(
    sink_configs: Iterable[Dict[str, Any]],
    run_dir: Path,
) -> List[TelemetrySink]:
    """Build the active telemetry sinks for a run.

    Always returns at least the local JSONL sink. Any legacy remote-exporter
    sink configs (``splunk``, ``opensearch``, ``elasticsearch``, ``ngsiem``,
    ``http_bulk``) are skipped with a deprecation warning so old configs keep
    loading without restoring network egress.
    """
    run_dir = Path(run_dir)
    sinks: List[TelemetrySink] = []
    jsonl_configured = False

    for sink_cfg in sink_configs:
        sink_type = str(sink_cfg.get("type", "")).lower()
        if not sink_type:
            continue
        if sink_type in REMOVED_REMOTE_SINK_TYPES:
            LOGGER.warning(
                "Telemetry sink type '%s' is no longer supported in the baseline; "
                "config entry ignored. Remove it from your config to silence this warning.",
                sink_type,
            )
            continue
        if sink_type == "jsonl":
            if not sink_cfg.get("enabled", True):
                jsonl_configured = True
                continue
            output_file = sink_cfg.get("file") or sink_cfg.get("path")
            target = Path(output_file) if output_file else (run_dir / "telemetry.jsonl")
            sinks.append(JSONLSink(target))
            jsonl_configured = True
        else:
            LOGGER.warning("Unknown telemetry sink type '%s' ignored.", sink_type)

    # Guarantee a default local sink for the run when nothing was configured.
    if not jsonl_configured:
        sinks.append(JSONLSink(run_dir / "telemetry.jsonl"))

    return sinks
