"""Splunk SPL detection draft generator."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..models import ModuleResult


def _quote(value: str) -> str:
    return value.replace('"', '\\"')


def _legacy_fields(hints: Mapping[str, Any], artifacts: Mapping[str, Any]) -> dict[str, str]:
    legacy = artifacts.get("legacy")
    payload = legacy.get("payload", {}) if isinstance(legacy, Mapping) else {}
    fields: dict[str, str] = {}
    for key in (
        "protocol",
        "transport",
        "endpoint",
        "command",
        "target_process",
        "campaign_id",
        "actor",
        "tactic",
        "technique",
        "mode",
        "capability",
        "legacy_subtype",
        "dns_record_type",
        "chunk_size",
        "rotation_count",
        "udp_port",
        "rpc_method",
        "api_hash",
        "runtime_warning",
    ):
        value = payload.get(key) if isinstance(payload, Mapping) else None
        if value is None:
            value = hints.get(key)
        if value is not None:
            fields[key] = str(value)
    risk_score = hints.get("risk_score")
    if risk_score is not None:
        fields["risk_score"] = str(risk_score)
    risk_severity = hints.get("risk_severity")
    if risk_severity is not None:
        fields["risk_severity"] = str(risk_severity)
    return fields


def render_spl(
    result: ModuleResult,
    run_id: str,
    hint_override: Mapping[str, Any] | None = None,
) -> str:
    technique = result.techniques[0] if result.techniques else "T0000"
    module = result.module
    hints = hint_override or result.detection_hints or {}
    fields = _legacy_fields(hints, result.artifacts or {})
    eval_parts = [
        f'run_id="{_quote(run_id)}"',
        f'module="{_quote(module)}"',
        f'technique="{_quote(technique)}"',
    ]
    for key, value in fields.items():
        eval_parts.append(f'{key}="{_quote(value)}"')
    table_fields = ["run_id", "module", "technique", *fields.keys()]
    return (
        "| makeresults | eval "
        + ", ".join(eval_parts)
        + ' | where module!="" | table '
        + " ".join(table_fields)
    )


def write_spl(result: ModuleResult, output_dir: Path, run_id: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{result.module}.spl"
    target.write_text(render_spl(result, run_id), encoding="utf-8")
    return target
