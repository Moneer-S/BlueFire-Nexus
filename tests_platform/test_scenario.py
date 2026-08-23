from __future__ import annotations

import copy
from pathlib import Path

import pytest

from bluefire.contracts import ContractError, ScenarioDefinition, StepOutcome, load_scenario
from bluefire.registry import RegistryError, load_builtin_registry

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "scenarios" / "sandbox_research_chain.yaml"


def test_sandbox_scenario_is_typed_reachable_dag() -> None:
    registry = load_builtin_registry()
    scenario = load_scenario(SCENARIO_PATH)
    registry.validate_scenario(scenario)
    assert len(scenario.steps) == 7


def test_scenario_has_discovery_swap_blocked_fallback_and_cleanup() -> None:
    scenario = load_scenario(SCENARIO_PATH)
    discovery = scenario.step("discover_records")
    assert discovery.alternates == ("sandbox.discovery.metadata.v1",)
    assert any(
        edge.from_step == "try_loopback"
        and edge.outcome is StepOutcome.BLOCKED
        and edge.to_step == "export_locally"
        for edge in scenario.edges
    )
    assert scenario.step("cleanup_workspace").behavior_id == "sandbox.cleanup.v1"


def test_scenario_rejects_duplicate_steps() -> None:
    raw = load_scenario(SCENARIO_PATH).to_dict()
    raw["steps"].append(copy.deepcopy(raw["steps"][0]))
    with pytest.raises(ContractError, match="duplicate IDs"):
        ScenarioDefinition.from_mapping(raw)


def test_registry_rejects_cycles_and_unreachable_steps() -> None:
    registry = load_builtin_registry()
    raw = load_scenario(SCENARIO_PATH).to_dict()
    failed_export_edge = next(
        edge
        for edge in raw["edges"]
        if edge["from_step"] == "export_locally" and edge["outcome"] == "failed"
    )
    failed_export_edge["to_step"] = "transform_fixture"
    with pytest.raises(RegistryError, match="cycle"):
        registry.validate_scenario(ScenarioDefinition.from_mapping(raw))

    raw = load_scenario(SCENARIO_PATH).to_dict()
    raw["edges"] = [edge for edge in raw["edges"] if edge["to_step"] != "export_locally"]
    with pytest.raises(RegistryError, match="unreachable"):
        registry.validate_scenario(ScenarioDefinition.from_mapping(raw))


def test_registry_rejects_mismatched_artifact_binding() -> None:
    registry = load_builtin_registry()
    raw = load_scenario(SCENARIO_PATH).to_dict()
    discovery = next(step for step in raw["steps"] if step["id"] == "discover_records")
    discovery["inputs"]["fixture"] = {
        "from_step": "create_fixture",
        "artifact": "workspace",
    }
    with pytest.raises(RegistryError, match="type does not match"):
        registry.validate_scenario(ScenarioDefinition.from_mapping(raw))
