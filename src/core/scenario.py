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
    # Optional defender-facing description of the step's intent — what
    # this step is trying to achieve in the chain. Surfaces alongside
    # the existing scenario-level ``objective:`` paragraph in the
    # static dashboard timeline, ``report.md`` per-step section, the
    # offline copilot narrative, and the manifest. Empty string is the
    # backwards-compatible default for scenarios that don't declare
    # per-step objectives.
    objective: str = ""


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
        # Per-step ``objective:`` is schema-additive (PR #144) — older
        # scenarios that omit it keep the empty-string default. The
        # value is normalised to a string with leading/trailing
        # whitespace stripped so a YAML block scalar with trailing
        # newlines doesn't end up rendering with a stray blank line in
        # the dashboard / report.md.
        objective = str(step.get("objective") or "").strip()
        steps.append(
            ScenarioStep(
                step_id=step_id,
                name=str(step.get("name") or step_id),
                module=str(step.get("module", "")),
                params=step.get("params") or step.get("operation") or {},
                objective=objective,
            )
        )
    # Resolve declared techniques. Fall back to legacy keys ONLY when the
    # canonical `attack_coverage` key is absent — an explicit empty list
    # under `attack_coverage: []` must be preserved (e.g. an experimental
    # scenario that intentionally declares no coverage). Truthy/falsy
    # short-circuiting (`a or b`) silently swallowed empty lists, which
    # made `attack_coverage: []` indistinguishable from "missing key" and
    # caused declared coverage to drift to whichever fallback was first
    # populated.
    if "attack_coverage" in raw:
        declared_techniques = raw.get("attack_coverage") or []
    elif "mitre" in raw:
        declared_techniques = raw.get("mitre") or []
    elif "attack_techniques" in raw:
        declared_techniques = raw.get("attack_techniques") or []
    else:
        declared_techniques = []
    return Scenario(
        id=str(raw.get("id", scenario_path.stem)),
        name=str(raw.get("name", scenario_path.stem)),
        objective=str(raw.get("objective", "")),
        attack_techniques=list(declared_techniques),
        steps=steps,
        expected_detections=raw.get("expected_detections", []),
        blue_team_guidance=raw.get("blue_team_guidance", []),
        fail_fast=bool(raw.get("fail_fast", True)),
    )
