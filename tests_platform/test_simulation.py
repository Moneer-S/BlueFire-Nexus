from __future__ import annotations

from typing import Any, Mapping

from bluefire.contracts import SafetyTier, StepOutcome
from bluefire.planner import PlanStep
from bluefire.simulation import SimulationRegistry


def _step(
    action_id: str,
    simulation_id: str,
    parameters: Mapping[str, Any] | None = None,
) -> PlanStep:
    return PlanStep(
        step_id="step",
        behavior_id=action_id,
        action_id=action_id,
        simulation_id=simulation_id,
        parameters=dict(parameters or {}),
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=SafetyTier.SAFE,
        alternates=(),
    )


def test_new_discovery_and_archive_simulations_are_pure_and_typed() -> None:
    registry = SimulationRegistry()
    system = registry.execute(
        _step("endpoint.discovery.system.v1", "simulation.endpoint.discovery.system.v1"),
        bound_inputs={},
    )
    processes = registry.execute(
        _step(
            "endpoint.discovery.processes.v1",
            "simulation.endpoint.discovery.processes.v1",
            {"record_limit": 1},
        ),
        bound_inputs={},
    )
    recursive = registry.execute(
        _step(
            "sandbox.discovery.recursive.v1",
            "simulation.sandbox.discovery.recursive.v1",
        ),
        bound_inputs={
            "workspace": {
                "root": "synthetic/fixtures",
                "fixture_path": "synthetic/fixtures/input.txt",
            }
        },
    )
    archive = registry.execute(
        _step("sandbox.archive.tar.v1", "simulation.sandbox.archive.tar.v1"),
        bound_inputs={"records": recursive.artifacts["records"]},
    )

    assert all(
        result.outcome is StepOutcome.SUCCESS for result in (system, processes, recursive, archive)
    )
    assert system.artifacts["system"]["type"] == "artifact.endpoint.system-profile.v1"
    assert len(processes.artifacts["processes"]["entries"]) == 1
    assert recursive.artifacts["records"][0]["kind"] == "file"
    assert archive.artifacts["bundle"]["type"] == "artifact.sandbox.archive.v1"
    assert all(result.details["side_effects_started"] is False for result in (system, archive))


def test_restricted_canary_simulation_is_labeled_synthetic() -> None:
    result = SimulationRegistry().execute(
        _step(
            "sandbox.restricted.persistence-marker.v1",
            "simulation.sandbox.restricted.persistence-marker.v1",
            {"label": "persistence_detection_canary"},
        ),
        bound_inputs={},
    )

    assert result.outcome is StepOutcome.SUCCESS
    assert result.artifacts["marker"]["synthetic"] is True
    assert result.artifacts["workspace"]["root"] == "synthetic/restricted"
    assert result.details["side_effects_started"] is False
