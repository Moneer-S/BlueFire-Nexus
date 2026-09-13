from __future__ import annotations

import pytest

from bluefire.contracts import (
    BehaviorDefinition,
    ContractError,
    ExecutionState,
    ParameterSpec,
)
from bluefire.plugins import PluginManifest, PluginManifestError


def _behavior_mapping() -> dict:
    return {
        "schema_version": "bluefire.behavior.v1",
        "id": "sandbox.test.behavior.v1",
        "title": "Test behavior",
        "purpose": "Exercise contract validation.",
        "execution_state": "action",
        "safety_tier": "safe",
        "platforms": ["sandbox"],
        "techniques": [],
        "capabilities": ["sandbox.test"],
        "inputs": [],
        "outputs": [{"name": "result", "type": "artifact.sandbox.test.v1"}],
        "parameters": [
            {
                "name": "count",
                "type": "integer",
                "default": 2,
                "minimum": 1,
                "maximum": 4,
            }
        ],
        "simulation_id": "simulation.sandbox.test.v1",
        "action_ids": ["sandbox.test.action.v1"],
        "telemetry": ["sandbox.test.completed"],
        "detection_hints": [],
        "provenance": {
            "source": "test fixture",
            "reference": "tests_platform",
            "license": "MIT",
            "derived": False,
        },
        "limitations": ["Test metadata only."],
    }


def test_behavior_contract_rejects_unknown_fields() -> None:
    raw = _behavior_mapping()
    raw["unexpected"] = True
    with pytest.raises(ContractError, match="unknown fields"):
        BehaviorDefinition.from_mapping(raw)


def test_behavior_contract_rejects_unversioned_ids() -> None:
    raw = _behavior_mapping()
    raw["id"] = "sandbox.test.behavior"
    with pytest.raises(ContractError, match="versioned stable ID"):
        BehaviorDefinition.from_mapping(raw)


def test_parameter_contract_validates_type_range_and_unknown_values() -> None:
    spec = ParameterSpec.from_mapping(
        {"name": "count", "type": "integer", "minimum": 1, "maximum": 3}
    )
    spec.validate_value(2)
    with pytest.raises(ContractError, match="type integer"):
        spec.validate_value(True)
    with pytest.raises(ContractError, match="exceeds"):
        spec.validate_value(4)


@pytest.mark.parametrize(
    ("value", "message"),
    [(10**309, "exceeds the maximum"), (-(10**309), "below the minimum")],
)
def test_integer_parameter_range_validation_handles_values_larger_than_float(
    value: int,
    message: str,
) -> None:
    spec = ParameterSpec.from_mapping(
        {"name": "count", "type": "integer", "minimum": 1, "maximum": 100}
    )

    with pytest.raises(ContractError, match=message):
        spec.validate_value(value, "scenario.parameters.count")


def test_metadata_only_behavior_cannot_claim_execution_support() -> None:
    raw = _behavior_mapping()
    raw["execution_state"] = ExecutionState.METADATA_ONLY.value
    with pytest.raises(ContractError, match="cannot declare execution IDs"):
        BehaviorDefinition.from_mapping(raw)


def _plugin_mapping() -> dict:
    return {
        "schema_version": "bluefire.plugin.v1",
        "id": "plugin.fixture.catalog.v1",
        "name": "Fixture catalog",
        "version": "1.0.0",
        "enabled": False,
        "trust": "reviewed",
        "integrity": {"algorithm": "sha256", "digest": "a" * 64},
        "license": "MIT",
        "provenance": {
            "source": "test fixture",
            "reference": "tests_platform",
            "license": "MIT",
            "derived": False,
        },
        "permissions": ["catalog.read"],
        "capabilities": ["sandbox.fixture"],
        "behavior_ids": ["sandbox.fixture.create.v1"],
        "action_ids": [],
    }


def test_plugin_manifest_is_declarative_only() -> None:
    manifest = PluginManifest.from_mapping(_plugin_mapping())
    assert manifest.enabled is False
    assert manifest.integrity.algorithm == "sha256"
    assert PluginManifest.from_mapping(manifest.to_dict()) == manifest

    raw = _plugin_mapping()
    raw["python_entry_point"] = "untrusted.module:load"
    with pytest.raises(ContractError, match="unknown fields"):
        PluginManifest.from_mapping(raw)


def test_plugin_manifest_requires_real_integrity_digest() -> None:
    raw = _plugin_mapping()
    raw["integrity"]["digest"] = "not-a-digest"
    with pytest.raises(PluginManifestError, match="SHA-256"):
        PluginManifest.from_mapping(raw)
