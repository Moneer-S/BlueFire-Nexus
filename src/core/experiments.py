"""Simple harness for scenario experiment runs."""

from __future__ import annotations

import copy
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .bluefire_nexus import BlueFireNexus
from .scenario import load_scenario


@dataclass
class ExperimentSummary:
    scenario: str
    runs: int
    successes: int
    failures: int
    detection_artifact_count: int
    step_success_rate: float
    detection_coverage_rate: float
    output_file: str


def _count_detection_artifacts(result: Dict[str, Any]) -> int:
    total = 0
    for step in result.get("steps", []):
        detections = step.get("detections", {})
        if isinstance(detections, dict):
            for value in detections.values():
                if isinstance(value, list):
                    total += len(value)
                elif value:
                    total += 1
    return total


def _mutate_run_params(base_result: Dict[str, Any], enable_jitter: bool) -> Dict[str, Any]:
    """Build deterministic, bounded parameter jitter for experiment reruns."""
    if not enable_jitter:
        return {}
    # Keep mutation intentionally low-risk: only adjust synthetic tunables.
    return {
        "mutation": {
            "intensity": random.choice(["low", "medium"]),
            "noise_ratio": round(random.uniform(0.05, 0.2), 2),
            "variant": random.choice(["baseline", "alt-path"]),
        },
        "previous_status": base_result.get("status", "unknown"),
    }


def _merge_step_mutation(
    steps: list[Dict[str, Any]],
    mutation_state: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    """Apply bounded experiment mutation into scenario step params."""
    if not steps:
        return steps
    mutation = mutation_state.get("mutation")
    if not isinstance(mutation, Mapping):
        return steps

    merged: list[Dict[str, Any]] = []
    for step in steps:
        step_copy = copy.deepcopy(step)
        params = step_copy.get("params")
        if not isinstance(params, dict):
            params = {}
        params["experiment_mutation"] = dict(mutation)
        params["mutation_applied"] = True
        params["mutation_variant"] = str(mutation.get("variant", "baseline"))
        params["mutation_intensity"] = str(mutation.get("intensity", "low"))
        step_copy["params"] = params
        merged.append(step_copy)
    return merged


def run_experiment(
    nexus: BlueFireNexus,
    scenario_path: str,
    runs: int = 5,
    seed: int | None = None,
    jitter: bool = False,
) -> ExperimentSummary:
    if seed is not None:
        random.seed(seed)

    scenario = load_scenario(Path(scenario_path))
    output_records: List[Dict[str, Any]] = []
    successes = 0
    failures = 0
    total_steps = 0
    successful_steps = 0
    detection_count = 0
    runs_with_detection = 0
    mutation_state: Dict[str, Any] = {}

    for index in range(runs):
        run_id = f"exp-{scenario.id}-{index+1:03d}"
        step_overrides: Dict[str, Dict[str, Any]] = {}
        if mutation_state:
            mutated_steps = _merge_step_mutation(
                [step.__dict__ for step in scenario.steps],
                mutation_state,
            )
            for step in mutated_steps:
                step_id = str(step.get("step_id") or step.get("id") or "")
                params = step.get("params")
                if step_id and isinstance(params, dict):
                    step_overrides[step_id] = params

        result = nexus.run_scenario_file(
            str(Path(scenario_path)),
            run_id=run_id,
            step_param_overrides=step_overrides or None,
        )
        if mutation_state:
            result.setdefault("experiment_context", {})
            result["experiment_context"]["mutation"] = copy.deepcopy(mutation_state)

        output_records.append(result)
        if result.get("status") in {"success", "partial_success"}:
            successes += 1
        else:
            failures += 1

        steps = result.get("steps", [])
        total_steps += len(steps)
        successful_steps += sum(1 for step in steps if step.get("status") == "success")

        run_detection_count = _count_detection_artifacts(result)
        detection_count += run_detection_count
        if run_detection_count > 0:
            runs_with_detection += 1

        mutation_state = _mutate_run_params(result, enable_jitter=jitter)

    out_dir = Path("output") / f"experiment-{scenario.id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "summary.json"
    target.write_text(json.dumps(output_records, indent=2), encoding="utf-8")

    step_success_rate = (successful_steps / total_steps) if total_steps else 0.0
    detection_coverage_rate = (runs_with_detection / runs) if runs else 0.0

    return ExperimentSummary(
        scenario=scenario.name,
        runs=runs,
        successes=successes,
        failures=failures,
        detection_artifact_count=detection_count,
        step_success_rate=round(step_success_rate, 4),
        detection_coverage_rate=round(detection_coverage_rate, 4),
        output_file=str(target),
    )


def run_experiment_series(
    scenario_path: str,
    iterations: int = 3,
    jitter: bool = False,
) -> Dict[str, Any]:
    """Compatibility wrapper returning dict summary for tests/CLI."""
    nexus = BlueFireNexus()
    summary = run_experiment(nexus, scenario_path, runs=iterations, jitter=jitter)
    payload = {
        "scenario": summary.scenario,
        "runs": summary.runs,
        "successes": summary.successes,
        "failures": summary.failures,
        "detection_artifact_count": summary.detection_artifact_count,
        "step_success_rate": summary.step_success_rate,
        "detection_coverage_rate": summary.detection_coverage_rate,
        "output_file": summary.output_file,
        "jitter_enabled": jitter,
        "detection_efficacy": {
            "artifact_count": summary.detection_artifact_count,
            "step_success_rate": summary.step_success_rate,
            "coverage_rate": summary.detection_coverage_rate,
        },
    }
    try:
        payload["results"] = json.loads(Path(summary.output_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload["results"] = []
    return payload

