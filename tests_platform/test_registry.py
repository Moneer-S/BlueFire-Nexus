from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.config import RunnerProfile, load_config
from bluefire.contracts import ExecutionState
from bluefire.registry import BehaviorRegistry, RegistryError, load_builtin_registry
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS

REPRESENTATIVE_ACTION_IDS = {
    "sandbox.execution.native-canary.v1",
    "sandbox.identity-material.seed.v1",
    "sandbox.identity-material.inspect.v1",
    "sandbox.peer.handoff.v1",
    "sandbox.observability.variant.v1",
}

EXPECTED_ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "endpoint.discovery.system.v1",
    "endpoint.discovery.windows-version.v1",
    "endpoint.discovery.processes.v1",
    "sandbox.discovery.recursive.v1",
    "sandbox.archive.tar.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.restricted.persistence-marker.v1",
    "sandbox.cleanup.v1",
} | REPRESENTATIVE_ACTION_IDS
EXPECTED_EXECUTABLE_BEHAVIOR_IDS = (
    EXPECTED_ACTION_IDS - {"endpoint.discovery.windows-version.v1"}
) | {"sandbox.credential.peer-challenge.v1"}
ROOT = Path(__file__).resolve().parents[1]


def test_builtin_registry_has_only_reviewed_bounded_actions() -> None:
    registry = load_builtin_registry()
    assert set(registry.action_ids) == EXPECTED_ACTION_IDS
    assert {
        behavior.id
        for behavior in registry.behaviors
        if behavior.execution_state is ExecutionState.ACTION
    } == EXPECTED_EXECUTABLE_BEHAVIOR_IDS
    assert all(
        "command" not in action_id and "script" not in action_id
        for action_id in registry.action_ids
    )


def test_windows_version_action_is_latent_until_a_package_adds_its_behavior() -> None:
    registry = load_builtin_registry()
    action = registry.get_action("endpoint.discovery.windows-version.v1")

    assert action.platforms == ("windows",)
    assert action.capabilities == ("system.discovery",)
    assert action.outputs[0].name == "windows_version"
    assert action.outputs[0].type == "artifact.endpoint.windows-version.v1"
    assert "endpoint.discovery.windows-version.v1" not in registry.behavior_ids


def test_representative_actions_are_versioned_bounded_and_cross_platform() -> None:
    registry = load_builtin_registry()
    assert {
        action_id: BUILTIN_RUNNER_ACTION_VERSIONS[action_id]
        for action_id in REPRESENTATIVE_ACTION_IDS
    } == {
        action_id: "2.0.0" if action_id == "sandbox.peer.handoff.v1" else "1.0.0"
        for action_id in REPRESENTATIVE_ACTION_IDS
    }

    expected_contracts = {
        "sandbox.execution.native-canary.v1": {
            "tier": "safe",
            "capabilities": ("native.execution",),
            "mutates": False,
            "cleanup": None,
        },
        "sandbox.identity-material.seed.v1": {
            "tier": "safe",
            "capabilities": ("sandbox.identity-material.seed", "filesystem.write"),
            "mutates": True,
            "cleanup": "sandbox.cleanup.v1",
        },
        "sandbox.identity-material.inspect.v1": {
            "tier": "safe",
            "capabilities": ("sandbox.identity-material.inspect", "filesystem.read"),
            "mutates": False,
            "cleanup": None,
        },
        "sandbox.peer.handoff.v1": {
            "tier": "controlled",
            "capabilities": ("sandbox.peer", "filesystem.read", "network.loopback"),
            "mutates": False,
            "cleanup": None,
        },
        "sandbox.observability.variant.v1": {
            "tier": "safe",
            "capabilities": (
                "sandbox.observability.variant",
                "filesystem.read",
                "filesystem.write",
            ),
            "mutates": True,
            "cleanup": "sandbox.cleanup.v1",
        },
    }
    for action_id, expected in expected_contracts.items():
        action = registry.get_action(action_id)
        behavior = registry.get_behavior(action_id)
        assert action.platforms == ("windows", "linux", "macos")
        assert behavior.platforms == action.platforms
        assert behavior.execution_state is ExecutionState.ACTION
        assert action.safety_tier.value == expected["tier"]
        assert action.capabilities == expected["capabilities"]
        assert action.mutates is expected["mutates"]
        assert action.cleanup_action_id == expected["cleanup"]


def test_representative_logical_parameters_expose_no_path_host_or_command() -> None:
    registry = load_builtin_registry()
    assert tuple(
        parameter.name
        for parameter in registry.get_action("sandbox.execution.native-canary.v1").parameters
    ) == ("rounds",)
    assert registry.get_action("sandbox.identity-material.seed.v1").parameters == ()
    assert registry.get_action("sandbox.identity-material.inspect.v1").parameters == ()
    assert tuple(
        parameter.name for parameter in registry.get_action("sandbox.peer.handoff.v1").parameters
    ) == ("port",)
    assert tuple(
        parameter.name
        for parameter in registry.get_action("sandbox.observability.variant.v1").parameters
    ) == ("representation",)


def test_action_and_behavior_parameter_contracts_are_identical() -> None:
    registry = load_builtin_registry()
    for action_id in EXPECTED_ACTION_IDS - {"endpoint.discovery.windows-version.v1"}:
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


def test_restricted_canary_is_an_explicit_bounded_action() -> None:
    registry = load_builtin_registry()
    behavior = registry.get_behavior("sandbox.restricted.persistence-marker.v1")
    action = registry.get_action("sandbox.restricted.persistence-marker.v1")

    assert behavior.execution_state is ExecutionState.ACTION
    assert behavior.safety_tier.value == "restricted"
    assert behavior.action_ids == (action.id,)
    assert action.capabilities == ("sandbox.restricted", "filesystem.write")
    assert action.cleanup_action_id == "sandbox.cleanup.v1"


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
