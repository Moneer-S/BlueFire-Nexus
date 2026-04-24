"""Run reporting helpers for BlueFire-Nexus."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Mapping

from .models import ModuleResult


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
            "",
            "### Pack Usage",
        ]
    )
    for pack_name, stats in pack_stats.items():
        lines.append(
            f"- {pack_name}: total={stats['count']} "
            f"simulate={stats['simulate']} emulate={stats['emulate']}"
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
