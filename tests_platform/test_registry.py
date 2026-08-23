from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.config import RunnerProfile, load_config
from bluefire.contracts import ExecutionState
from bluefire.registry import BehaviorRegistry, RegistryError, load_builtin_registry

EXPECTED_ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
}
ROOT = Path(__file__).resolve().parents[1]


def test_builtin_registry_has_only_reviewed_sandbox_actions() -> None:
    registry = load_builtin_registry()
    assert set(registry.action_ids) == EXPECTED_ACTION_IDS
    assert all(
        "command" not in action_id and "script" not in action_id
        for action_id in registry.action_ids
    )


def test_action_and_behavior_parameter_contracts_are_identical() -> None:
    registry = load_builtin_registry()
    for action_id in EXPECTED_ACTION_IDS:
        behavior = registry.get_behavior(action_id)
        action = registry.get_action(action_id)
        assert behavior.parameters == action.parameters


def test_discovery_behaviors_are_compatible_swaps() -> None:
    registry = load_builtin_registry()
    assert "sandbox.discovery.metadata.v1" in registry.compatible_behaviors(
        "sandbox.discovery.list.v1"
    )


def test_restricted_research_entries_are_metadata_only() -> None:
    registry = load_builtin_registry()
    restricted = {
        "research.credential.access.v1",
        "research.persistence.change.v1",
        "research.lateral.movement.v1",
        "research.defense.evasion.v1",
    }
    for behavior_id in restricted:
        behavior = registry.get_behavior(behavior_id)
        assert behavior.execution_state is ExecutionState.METADATA_ONLY
        assert behavior.action_ids == ()
        assert behavior.simulation_id is None


def test_registry_rejects_duplicate_behavior_ids() -> None:
    registry = load_builtin_registry()
    behavior = registry.get_behavior("sandbox.fixture.create.v1")
    with pytest.raises(RegistryError, match="duplicate behavior ID"):
        BehaviorRegistry([behavior, behavior], [])


def test_registry_validates_execute_profile_capabilities() -> None:
    registry = load_builtin_registry()
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    execute_profile = next(
        profile for profile in config.runner_profiles if profile.mode.value == "execute"
    )
    registry.validate_runner_profile(execute_profile)

    raw = execute_profile.to_dict()
    raw["capabilities"].remove("filesystem.write")
    incomplete = RunnerProfile.from_mapping(raw)
    with pytest.raises(RegistryError, match="lacks action capabilities"):
        registry.validate_runner_profile(incomplete)
