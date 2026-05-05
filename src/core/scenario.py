"""Scenario loading and execution helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass
class ScenarioStep:
    step_id: str
    name: str
    module: str
    params: Dict[str, Any]


@dataclass
class Scenario:
    id: str
    name: str
    objective: str
    attack_techniques: List[str]
    steps: List[ScenarioStep]
    expected_detections: List[str]
    blue_team_guidance: List[str]
    fail_fast: bool = True


def load_scenario(path: str | Path) -> Scenario:
    scenario_path = Path(path)
    with scenario_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    step_entries = raw.get("steps", [])
    steps: List[ScenarioStep] = []
    for index, step in enumerate(step_entries):
        if not isinstance(step, dict):
            continue
        step_id = str(step.get("id") or f"step-{index + 1}")
        steps.append(
            ScenarioStep(
                step_id=step_id,
                name=str(step.get("name") or step_id),
                module=str(step.get("module", "")),
                params=step.get("params") or step.get("operation") or {},
            )
        )
    return Scenario(
        id=str(raw.get("id", scenario_path.stem)),
        name=str(raw.get("name", scenario_path.stem)),
        objective=str(raw.get("objective", "")),
        attack_techniques=raw.get("attack_coverage", raw.get("mitre", [])),
        steps=steps,
        expected_detections=raw.get("expected_detections", []),
        blue_team_guidance=raw.get("blue_team_guidance", []),
        fail_fast=bool(raw.get("fail_fast", True)),
    )
