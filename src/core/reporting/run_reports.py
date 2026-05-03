"""Run reporting helpers for BlueFire-Nexus (JSON/Markdown/purple summaries)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Mapping

from ..models import ModuleResult
from ..risk import score_module_result


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
                "- Average module risk score: "
                f"{(sum(risk_scores) / len(risk_scores)) if risk_scores else 0:.1f}"
            ),
            "",
            "### Pack Usage",
        ]
    )
    for pack_name, stats in pack_stats.items():
        lines.append(
            f"- {pack_name}: total={stats['count']} simulate={stats['simulate']} "
            f"emulate={stats['emulate']}"
        )
    lines.extend(
        [
            "",
            "## Module Results",
            "",
        ]
    )
    for module_name, result in results.items():
        legacy = result.artifacts.get("legacy")
        safety_line = ""
        warning_line = ""
        risk = score_module_result(result)
        risk_line = f"- Risk score: `{risk.get('score')}` (severity: `{risk.get('severity')}`)"
        if isinstance(legacy, dict):
            safety_line = (
                f"- Capability Pack: `{legacy.get('pack')}` / `{legacy.get('capability')}` "
                f"(mode: `{legacy.get('mode')}`)"
            )
            payload = legacy.get("payload", {})
            if isinstance(payload, dict) and payload.get("runtime_warning"):
                warning_line = f"- Runtime warning: {payload.get('runtime_warning')}"
        lines.extend(
            [
                f"### {module_name}",
                f"- Status: `{result.status}`",
                f"- Message: {result.message or 'n/a'}",
                f"- Techniques: {', '.join(result.techniques) if result.techniques else 'n/a'}",
                risk_line,
                safety_line,
                warning_line,
                "",
            ]
        )
    lines.append("## Detection Artifacts")
    lines.append("")
    for module_name, outputs in detections.items():
        lines.append(f"- **{module_name}**")
        for output_type, output_path in outputs.items():
            lines.append(f"  - {output_type}: `{output_path}`")
    lines.append("")
    report_path.write_text("\n".join(line for line in lines if line), encoding="utf-8")
    return report_path


def build_risk_summary(results: Dict[str, ModuleResult]) -> Dict[str, Any]:
    """Build a machine-readable risk summary across module results."""
    modules: list[Dict[str, Any]] = []
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    scores: list[int] = []
    for module_name, result in results.items():
        risk = score_module_result(result)
        severity = str(risk.get("severity", "low")).lower()
        if severity not in totals:
            severity = "low"
        totals[severity] += 1
        score = int(risk.get("score", 0))
        scores.append(score)
        modules.append(
            {
                "module": module_name,
                "module_runtime": result.module,
                "status": result.status,
                "score": score,
                "severity": severity,
                "pack": risk.get("pack", ""),
                "capability": risk.get("capability", ""),
                "mode": risk.get("mode", ""),
                "runtime_warning": bool(risk.get("runtime_warning", False)),
                "rationale": list(risk.get("rationale", [])),
            }
        )
    average = (sum(scores) / len(scores)) if scores else 0.0
    return {
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
        "modules": modules,
    }


def write_risk_summary(run_dir: Path, results: Dict[str, ModuleResult]) -> Path:
    """Write a machine-readable risk summary report to disk."""
    target = run_dir / "risk_summary.json"
    summary = build_risk_summary(results)
    target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return target
