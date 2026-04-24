"""Simple harness for scenario experiment runs."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from .bluefire_nexus import BlueFireNexus
from .scenario import load_scenario


@dataclass
class ExperimentSummary:
    scenario: str
    runs: int
    successes: int
    failures: int
    output_file: str


def run_experiment(
    nexus: BlueFireNexus,
    scenario_path: str,
    runs: int = 5,
    seed: int | None = None,
) -> ExperimentSummary:
    if seed is not None:
        random.seed(seed)

    scenario = load_scenario(Path(scenario_path))
    output_records: List[Dict[str, Any]] = []
    successes = 0
    failures = 0

    for index in range(runs):
        run_id = f"exp-{scenario.id}-{index+1:03d}"
        result = nexus.run_scenario_file(str(Path(scenario_path)), run_id=run_id)
        output_records.append(result)
        if result.get("status") in {"success", "partial_success"}:
            successes += 1
        else:
            failures += 1

    out_dir = Path("output") / f"experiment-{scenario.id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "summary.json"
    target.write_text(json.dumps(output_records, indent=2), encoding="utf-8")

    return ExperimentSummary(
        scenario=scenario.name,
        runs=runs,
        successes=successes,
        failures=failures,
        output_file=str(target),
    )


def run_experiment_series(
    scenario_path: str,
    iterations: int = 3,
    jitter: bool = False,
) -> Dict[str, Any]:
    """Compatibility wrapper returning dict summary for tests/CLI."""
    nexus = BlueFireNexus()
    summary = run_experiment(nexus, scenario_path, runs=iterations)
    payload = {
        "scenario": summary.scenario,
        "runs": summary.runs,
        "successes": summary.successes,
        "failures": summary.failures,
        "output_file": summary.output_file,
        "jitter_enabled": jitter,
    }
    return payload

