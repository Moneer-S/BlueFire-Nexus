from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.contracts import load_scenario
from bluefire.job_runtime import JobCancelled
from bluefire.orchestrator import Orchestrator, SimulationCancelled
from bluefire.registry import load_builtin_registry
from bluefire.run_store import RunStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("after_steps", [0, 1])
def test_checkpoint_cancellation_finalizes_only_the_known_partial_simulation(
    tmp_path: Path, after_steps: int
) -> None:
    store = RunStore(tmp_path / "runs")
    orchestrator = Orchestrator(load_builtin_registry(), store)
    seen: list[str] = []

    def checkpoint(progress: Mapping[str, Any]) -> None:
        if "run_id" in progress:
            seen.append(str(progress["run_id"]))
        if seen and progress.get("completed_steps", 0) >= after_steps:
            raise JobCancelled("test checkpoint cancellation")

    with pytest.raises(SimulationCancelled) as raised:
        orchestrator.run(
            load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml"),
            checkpoint=checkpoint,
        )
    run = store.get_run(raised.value.run_id)
    assert set(seen) == {run["run_id"]}
    assert run["status"] == "cancelled"
    assert len(run["steps"]) == after_steps
    assert bool(run["evidence"]["records"]) == bool(after_steps)
    assert store.validate_bundle(run["run_id"])["valid"]
    assert "objective_reached" not in run
    assert len(store.list_runs()) == 1


def test_planning_cancellation_does_not_invent_a_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs")

    def checkpoint(progress: Mapping[str, Any]) -> None:
        raise JobCancelled("cancelled before a run exists")

    with pytest.raises(JobCancelled):
        Orchestrator(load_builtin_registry(), store).run(
            load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml"),
            checkpoint=checkpoint,
        )
    assert store.list_runs() == []
