"""Run reporting helpers for BlueFire-Nexus (JSON/Markdown/purple summaries)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Mapping

from ..models import ModuleResult
from ..risk import score_module_result


def _mode_badge(result: ModuleResult) -> Dict[str, Any]:
    """Extract a per-module mode/safety summary for report rendering.

    Reads from `result.artifacts` and `result.detection_hints` because most
    standard and legacy modules already record mode-relevant fields there.
    Returns a small dict with the keys reports want to surface:

    * `mode`         — "emulate" / "simulate" / "dry-run" / "real-execution"
    * `pack`         — capability pack name when the result is from a legacy
                       adapter, else empty
    * `network_touch`— bool when the module honours the `network_touch`
                       contract, else None
    * `target_os`    — operator-resolved target OS when the module
                       honours `target_os`, else empty
    * `lab_acknowledged` — true when the result was produced under explicit
                           lab confirmation, else false
    * `destructive`  — true when the result represents a destructive
                       operation that received explicit acknowledgment
    """
    artifacts = result.artifacts if isinstance(result.artifacts, dict) else {}
    hints = result.detection_hints if isinstance(result.detection_hints, dict) else {}

    legacy = artifacts.get("legacy")
    pack = ""
    mode = ""
    lab_acknowledged = False
    if isinstance(legacy, dict):
        pack = str(legacy.get("pack") or "")
        mode = str(legacy.get("mode") or "")
        decision = legacy.get("decision")
        if isinstance(decision, dict):
            lab_acknowledged = bool(decision.get("acknowledged", False))

    if not mode:
        # Standard modules: infer simulate vs real-execution from artifacts.
        if "stdout" in artifacts and "return_code" in artifacts:
            output = str(artifacts.get("stdout") or "")
            mode = "dry-run" if output.startswith("[dry-run]") else "real-execution"
        else:
            mode = "simulate"

    network_touch_value: Any = artifacts.get("network_touch")
    if network_touch_value is None:
        network_touch_value = hints.get("network_touch")

    target_os = str(artifacts.get("target_os") or hints.get("target_os") or "")

    destructive = False
    if artifacts.get("destructive") and artifacts.get("i_understand_this_is_a_lab"):
        destructive = True

    return {
        "mode": mode,
        "pack": pack,
        "network_touch": (
            bool(network_touch_value) if isinstance(network_touch_value, bool) else None
        ),
        "target_os": target_os,
        "lab_acknowledged": lab_acknowledged,
        "destructive": destructive,
    }


def write_json_report(run_dir: Path, results: Dict[str, ModuleResult]) -> Path:
    """Write machine-readable run report."""
    output = run_dir / "report.json"
    payload = {name: asdict(result) for name, result in results.items()}
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output


def write_purple_report(
    output_dir: Path,
    run_id: str,
    module_name: str,
    result: ModuleResult,
    detection_paths: Mapping[str, str],
) -> Path:
    """Write a concise markdown report for a module or scenario run."""
    report_path = output_dir / "report.md"
    lines = [
        f"# BlueFire Purple Report ({run_id})",
        "",
        f"- Module: `{module_name}`",
        f"- Status: `{result.status}`",
        f"- Message: {result.message or 'n/a'}",
        f"- Techniques: {', '.join(result.techniques) if result.techniques else 'n/a'}",
        "",
        "## Detection Artifacts",
    ]
    if detection_paths:
        for key, value in detection_paths.items():
            lines.append(f"- {key}: `{value}`")
    else:
        lines.append("- none")
    lines.append("")
    if result.artifacts:
        lines.append("## Artifacts")
        for key, value in result.artifacts.items():
            lines.append(f"- {key}: `{value}`")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def write_markdown_report(
    run_dir: Path,
    scenario_name: str,
    results: Dict[str, ModuleResult],
    detections: Dict[str, Dict[str, str]],
) -> Path:
    """Write a human-readable purple-team report."""
    report_path = run_dir / "report.md"
    pack_stats = {
        "actor_pack": {"count": 0, "simulate": 0, "emulate": 0},
        "c2_pack": {"count": 0, "simulate": 0, "emulate": 0},
        "stealth_pack": {"count": 0, "simulate": 0, "emulate": 0},
    }
    attack_coverage: set[str] = set()
    detection_total = 0
    runtime_warning_count = 0
    risk_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    risk_scores: list[int] = []
    for outputs in detections.values():
        detection_total += len(outputs)

    lines = [
        f"# BlueFire Run Report: {scenario_name}",
        "",
        "## Legacy Capability Pack Summary",
        "",
    ]
    for result in results.values():
        if result.techniques:
            attack_coverage.update(result.techniques)
        risk = score_module_result(result)
        severity = str(risk.get("severity", "low")).lower()
        if severity not in risk_totals:
            severity = "low"
        risk_totals[severity] += 1
        risk_scores.append(int(risk.get("score", 0)))
        legacy = result.artifacts.get("legacy")
        if not isinstance(legacy, dict):
            continue
        pack_name = str(legacy.get("pack", ""))
        mode = str(legacy.get("mode", "simulate")).lower()
        payload = legacy.get("payload", {})
        if isinstance(payload, dict) and payload.get("runtime_warning"):
            runtime_warning_count += 1
        if pack_name not in pack_stats:
            continue
        pack_stats[pack_name]["count"] += 1
        if mode == "emulate":
            pack_stats[pack_name]["emulate"] += 1
        else:
            pack_stats[pack_name]["simulate"] += 1

    coverage_text = ", ".join(sorted(attack_coverage)) if attack_coverage else "n/a"
    # Build technique -> [module:step, ...] map so defenders can see which
    # step covers which technique without cross-referencing JSON output.
    technique_to_steps: Dict[str, list[str]] = {}
    for step_key, result in results.items():
        if not result.techniques:
            continue
        for tech in result.techniques:
            technique_to_steps.setdefault(tech, []).append(step_key)
    lines.extend(
        [
            f"- ATT&CK techniques covered: {coverage_text}",
            f"- Detection artifacts generated: {detection_total}",
            f"- Runtime warnings observed: {runtime_warning_count}",
            (
                "- Risk summary: "
                f"critical={risk_totals['critical']} high={risk_totals['high']} "
                f"medium={risk_totals['medium']} low={risk_totals['low']}"
            ),
            (
                f"- Average module risk score: "
                f"{(sum(risk_scores) / len(risk_scores)) if risk_scores else 0:.1f}"
            ),
            "",
            "### Pack Usage",
        ]
    )
    for pack_name, stats in pack_stats.items():
        lines.append(
            f"- {pack_name}: total={stats['count']} "
            f"simulate={stats['simulate']} emulate={stats['emulate']}"
        )
    if technique_to_steps:
        lines.extend(
            [
                "",
                "## ATT&CK Technique Coverage",
                "",
            ]
        )
        for tech in sorted(technique_to_steps):
            covering = ", ".join(f"`{step_key}`" for step_key in technique_to_steps[tech])
            lines.append(f"- {tech} — {covering}")
    lines.extend(
        [
            "",
            "## Module Results",
            "",
        ]
    )
    blocked_steps: list[str] = []
    for module_name, result in results.items():
        legacy = result.artifacts.get("legacy")
        safety_line = ""
        warning_line = ""
        risk = score_module_result(result)
        risk_line = (
            f"- Risk score: `{risk.get('score')}` "
            f"(severity: `{risk.get('severity')}`)"
        )
        if isinstance(legacy, dict):
            safety_line = (
                f"- Capability Pack: `{legacy.get('pack')}` / `{legacy.get('capability')}` "
                f"(mode: `{legacy.get('mode')}`)"
            )
            payload = legacy.get("payload", {})
            if isinstance(payload, dict) and payload.get("runtime_warning"):
                warning_line = f"- Runtime warning: {payload.get('runtime_warning')}"
        if result.status == "blocked":
            blocked_steps.append(module_name)
        badge = _mode_badge(result)
        mode_line = f"- Mode: `{badge['mode']}`"
        extras: list[str] = []
        if badge["network_touch"] is not None:
            extras.append(f"network_touch=`{badge['network_touch']}`")
        if badge["target_os"]:
            extras.append(f"target_os=`{badge['target_os']}`")
        if badge["lab_acknowledged"]:
            extras.append("lab_acknowledged=`true`")
        if badge["destructive"]:
            extras.append("destructive=`true (acknowledged)`")
        if extras:
            mode_line += " (" + ", ".join(extras) + ")"
        lines.extend(
            [
                f"### {module_name}",
                f"- Status: `{result.status}`",
                f"- Message: {result.message or 'n/a'}",
                f"- Techniques: {', '.join(result.techniques) if result.techniques else 'n/a'}",
                mode_line,
                risk_line,
                safety_line,
                warning_line,
                "",
            ]
        )

    if blocked_steps:
        lines.extend(
            [
                "## Blocked Steps",
                "",
                "The following steps did not run because a safety/lab gate was not satisfied:",
                "",
            ]
        )
        for module_name in blocked_steps:
            lines.append(f"- `{module_name}`")
        lines.append("")
    lines.append("## Detection Artifacts")
    lines.append("")
    for module_name, outputs in detections.items():
        lines.append(f"- **{module_name}**")
        for output_type, output_path in outputs.items():
            lines.append(f"  - {output_type}: `{output_path}`")
    lines.append("")
    report_path.write_text("\n".join(line for line in lines if line), encoding="utf-8")
    return report_path


def build_risk_summary(
    results: Dict[str, ModuleResult],
    *,
    scenario_name: str = "",
) -> Dict[str, Any]:
    """Build a machine-readable risk summary across module results."""
    modules: list[Dict[str, Any]] = []
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scores: list[int] = []
    blocked: list[str] = []
    for module_name, result in results.items():
        risk = score_module_result(result)
        severity = str(risk.get("severity", "low")).lower()
        if severity not in totals:
            severity = "low"
        totals[severity] += 1
        score = int(risk.get("score", 0))
        scores.append(score)
        if result.status == "blocked":
            blocked.append(module_name)
        badge = _mode_badge(result)
        modules.append(
            {
                "module": module_name,
                "module_runtime": result.module,
                "status": result.status,
                "score": score,
                "severity": severity,
                "mode": badge["mode"],
                "network_touch": badge["network_touch"],
                "target_os": badge["target_os"],
                "lab_acknowledged": badge["lab_acknowledged"],
                "destructive": badge["destructive"],
                "pack": risk.get("pack", ""),
                "capability": risk.get("capability", ""),
                "legacy_mode": risk.get("mode", ""),
                "runtime_warning": bool(risk.get("runtime_warning", False)),
                "rationale": list(risk.get("rationale", [])),
            }
        )
    average = (sum(scores) / len(scores)) if scores else 0.0
    summary: Dict[str, Any] = {
        "risk_summary": {
            "critical": totals["critical"],
            "high": totals["high"],
            "medium": totals["medium"],
            "low": totals["low"],
        },
        "average_score": round(average, 2),
        "max_score": max(scores) if scores else 0,
        "min_score": min(scores) if scores else 0,
        "module_count": len(modules),
        "blocked_steps": blocked,
        "modules": modules,
    }
    if scenario_name:
        summary["scenario"] = scenario_name
    return summary


def write_risk_summary(
    run_dir: Path,
    results: Dict[str, ModuleResult],
    *,
    scenario_name: str = "",
) -> Path:
    """Write a machine-readable risk summary report to disk."""
    target = run_dir / "risk_summary.json"
    summary = build_risk_summary(results, scenario_name=scenario_name)
    target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return target
