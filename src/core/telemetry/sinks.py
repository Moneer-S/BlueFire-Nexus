"""Telemetry sink abstractions and implementations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import requests


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
    sink_type = "jsonl"

    def __init__(self, output_file: Path):
        self.output_file = output_file
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

    def send(self, event: Dict[str, Any]) -> SinkResult:
        with self.output_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")
        return SinkResult(self.sink_type, True, f"wrote {self.output_file}")


class HttpBulkSink(TelemetrySink):
    sink_type = "http_bulk"

    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def send(self, event: Dict[str, Any]) -> SinkResult:
        try:
            response = requests.post(
                self.endpoint,
                json=event,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            return SinkResult(self.sink_type, True, f"http {response.status_code}")
        except Exception as exc:  # fail closed
            return SinkResult(self.sink_type, False, str(exc))


class OpenSearchSink(HttpBulkSink):
    sink_type = "opensearch"


class ElasticsearchSink(HttpBulkSink):
    sink_type = "elasticsearch"


class NGSIEMSink(HttpBulkSink):
    sink_type = "ngsiem"


class SplunkHECSink(HttpBulkSink):
    sink_type = "splunk_hec"

    def send(self, event: Dict[str, Any]) -> SinkResult:
        payload = {"event": event}
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            return SinkResult(self.sink_type, True, f"http {response.status_code}")
        except Exception as exc:
            return SinkResult(self.sink_type, False, str(exc))


def build_sinks(
    sink_configs: Iterable[Dict[str, Any]],
    run_dir: Path,
) -> list[TelemetrySink]:
    configs_by_type: Dict[str, Dict[str, Any]] = {}
    for sink_cfg in sink_configs:
        sink_type = str(sink_cfg.get("type", "")).lower()
        if sink_type:
            configs_by_type[sink_type] = dict(sink_cfg)

    # Respect the required sink preference order.
    remote_priority = ("opensearch", "elasticsearch", "ngsiem", "splunk", "splunk_hec")
    sinks: list[TelemetrySink] = []
    for sink_type in remote_priority:
        sink_cfg = configs_by_type.get(sink_type)
        if not sink_cfg or not sink_cfg.get("enabled", False):
            continue
        endpoint = str(sink_cfg.get("endpoint", "")).strip()
        if not endpoint:
            continue
        headers = sink_cfg.get("headers") or {}
        timeout = int(sink_cfg.get("timeout_seconds", 10))
        verify_ssl = bool(sink_cfg.get("verify_ssl", True))
        if sink_type == "opensearch":
            sinks.append(OpenSearchSink(endpoint, headers, timeout, verify_ssl))
            break
        if sink_type == "elasticsearch":
            sinks.append(ElasticsearchSink(endpoint, headers, timeout, verify_ssl))
            break
        if sink_type == "ngsiem":
            sinks.append(NGSIEMSink(endpoint, headers, timeout, verify_ssl))
            break
        if sink_type in {"splunk", "splunk_hec"}:
            sinks.append(SplunkHECSink(endpoint, headers, timeout, verify_ssl))
            break

    # JSONL is always available and stays enabled as the default/local sink.
    sinks.append(JSONLSink(run_dir / "telemetry.jsonl"))
    return sinks
