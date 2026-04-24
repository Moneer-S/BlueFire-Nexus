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
    lines = [
        f"# BlueFire Run Report: {scenario_name}",
        "",
        "## Module Results",
        "",
    ]
    for module_name, result in results.items():
        lines.extend(
            [
                f"### {module_name}",
                f"- Status: `{result.status}`",
                f"- Message: {result.message or 'n/a'}",
                f"- Techniques: {', '.join(result.techniques) if result.techniques else 'n/a'}",
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
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
