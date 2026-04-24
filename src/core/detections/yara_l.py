"""Google SecOps YARA-L draft generator."""

from __future__ import annotations

from typing import Any, Dict


def build_yara_l_rule(run_id: str, module: str, hint: Dict[str, Any]) -> str:
    technique_id = hint.get("mitre_technique_id", "T0000")
    process_name = hint.get("process_name", module)
    safe_name = f"{module}_{run_id}".replace("-", "_")
    return (
        f"rule bluefire_{safe_name}_{technique_id.replace('.', '_').replace('-', '_')} {{\n"
        "  meta:\n"
        f"    technique = \"{technique_id}\"\n"
        f"    run_id = \"{run_id}\"\n"
        "    generated_by = \"BlueFire-Nexus\"\n"
        "  events:\n"
        "    $e.metadata.event_type = \"PROCESS_LAUNCH\"\n"
        f"    $e.target.process.file.full_path contains \"{process_name}\"\n"
        "  condition:\n"
        "    $e\n"
        "}\n"
    )


def generate_yara_l(name: str, technique_id: str, metadata: Dict[str, Any]) -> str:
    """Backward-compatible helper used by the detection engine."""
    hint: Dict[str, Any] = dict(metadata or {})
    hint.setdefault("mitre_technique_id", technique_id or "T0000")
    return build_yara_l_rule("manual", name, hint)
