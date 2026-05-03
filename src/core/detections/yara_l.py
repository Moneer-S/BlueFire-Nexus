"""Google SecOps YARA-L draft generator."""

from __future__ import annotations

from typing import Any, Dict


def build_yara_l_rule(run_id: str, module: str, hint: Dict[str, Any]) -> str:
    technique_id = hint.get("mitre_technique_id") or hint.get("mitre_technique") or "T0000"
    risk_score = int(hint.get("risk_score", 50))
    risk_score = max(0, min(100, risk_score))
    risk_severity = str(hint.get("risk_severity", "medium")).lower()
    if risk_severity not in {"low", "medium", "high", "critical"}:
        risk_severity = "medium"
    process_name = (
        hint.get("process_name")
        or hint.get("process_command_line")
        or hint.get("network_url")
        or hint.get("endpoint")
        or module
    )
    event_type = str(hint.get("event_type", "PROCESS_LAUNCH"))
    safe_name = f"{module}_{run_id}".replace("-", "_")
    return (
        f"rule bluefire_{safe_name}_{technique_id.replace('.', '_').replace('-', '_')} {{\n"
        "  meta:\n"
        f'    technique = "{technique_id}"\n'
        f'    run_id = "{run_id}"\n'
        '    generated_by = "BlueFire-Nexus"\n'
        f'    risk_score = "{risk_score}"\n'
        f'    risk_severity = "{risk_severity}"\n'
        "  events:\n"
        f'    $e.metadata.event_type = "{event_type}"\n'
        f'    $e.target.process.file.full_path contains "{process_name}"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )


def generate_yara_l(name: str, technique_id: str, metadata: Dict[str, Any]) -> str:
    """Backward-compatible helper used by the detection engine."""
    hint: Dict[str, Any] = dict(metadata or {})
    hint.setdefault("mitre_technique_id", technique_id or "T0000")
    return build_yara_l_rule("manual", name, hint)
