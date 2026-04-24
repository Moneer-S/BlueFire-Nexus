"""Detection generation orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

from ..models import ModuleResult
from .sigma import build_sigma_rule
from .spl import render_spl
from .yara_l import generate_yara_l


def write_detection_artifacts(
    output_dir: Path,
    run_id: str,
    module_results: Dict[str, ModuleResult],
) -> Dict[str, list[str]]:
    """Write Sigma, YARA-L and SPL detections for each successful module result."""
    detections_dir = output_dir / "detections"
    sigma_dir = detections_dir / "sigma"
    yaral_dir = detections_dir / "yara_l"
    spl_dir = detections_dir / "spl"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    yaral_dir.mkdir(parents=True, exist_ok=True)
    spl_dir.mkdir(parents=True, exist_ok=True)

    generated: Dict[str, list[str]] = {"sigma": [], "yara_l": [], "spl": []}
    for module_name, result in module_results.items():
        if result.status not in {"success", "partial_success"}:
            continue

        hint: Dict[str, Any] = dict(result.detection_hints or {})
        technique = (
            hint.get("mitre_technique")
            or hint.get("mitre_technique_id")
            or (result.techniques[0] if result.techniques else "T0000")
        )

        stem = f"{module_name}_{run_id}"

        sigma_rule = build_sigma_rule(run_id, module_name, hint)
        sigma_path = sigma_dir / f"{stem}.yml"
        sigma_path.write_text(yaml.safe_dump(sigma_rule, sort_keys=False), encoding="utf-8")
        generated["sigma"].append(str(sigma_path))

        yaral = generate_yara_l(module_name, technique, hint)
        yaral_path = yaral_dir / f"{stem}.yaral"
        yaral_path.write_text(yaral, encoding="utf-8")
        generated["yara_l"].append(str(yaral_path))

        spl_path = spl_dir / f"{stem}.spl"
        spl_path.write_text(render_spl(result, run_id), encoding="utf-8")
        generated["spl"].append(str(spl_path))

    return generated
