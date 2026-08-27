from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.contracts import ActionDefinition
from bluefire.runner_contracts import (
    RunnerContractError,
    build_execution_manifest,
    build_runner_profile,
    current_platform,
    seal_manifest,
    seal_profile,
)
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
ACTION_ID = "independent.portable-probe.v1"
BEHAVIOR_ID = "independent.portable-provider.v1"


def _action() -> ActionDefinition:
    platform = current_platform()
    return ActionDefinition.from_mapping(
        {
            "schema_version": "bluefire.action.v1",
            "id": ACTION_ID,
            "title": "Portable provider probe",
            "purpose": "Execute an independently distributed pure provider.",
            "safety_tier": "safe",
            "capabilities": ["native.execution"],
            "platforms": [platform],
            "inputs": [],
            "outputs": [
                {
                    "name": "result",
                    "type": "artifact.provider.portable-probe.v1",
                    "required": True,
                    "multiple": False,
                    "description": "Typed provider result.",
                }
            ],
            "parameters": [
                {
                    "name": "label",
                    "type": "string",
                    "required": True,
                    "default": None,
                    "enum": ["release"],
                    "minimum": None,
                    "maximum": None,
                    "description": "Bound probe label.",
                }
            ],
            "mutates": False,
            "cleanup_action_id": None,
            "provenance": {
                "source": "BlueFire provider contract test",
                "reference": "urn:bluefire:test:provider",
                "license": "MIT",
                "derived": False,
                "notes": "Deterministic fictional test data.",
            },
        }
    )


def _binding() -> tuple[dict[str, object], dict[str, object]]:
    artifact = b"\x00asm\x01\x00\x00\x00"
    artifact_digest = "sha256:" + hashlib.sha256(artifact).hexdigest()
    action_digest = "sha256:" + "5" * 64
    program = {
        "schema_version": "bluefire.wasm-provider-program.v1",
        "provider_id": "independent.portable-provider.v1",
        "action_contract_digest": action_digest,
    }
    runtime_contract = {
        "schema_version": "bluefire.provider-runtime-action-contract.v1",
        "logical_action_id": ACTION_ID,
        "inputs": [],
        "outputs": [
            {
                "name": "result",
                "type": "artifact.provider.portable-probe.v1",
                "required": True,
                "multiple": False,
            }
        ],
        "parameters": [
            {
                "name": "label",
                "type": "string",
                "required": True,
                "default": None,
                "enum": ["release"],
                "minimum": None,
                "maximum": None,
            }
        ],
        "capabilities": ["native_execution"],
        "safety_tier": "safe",
        "platforms": [current_platform()],
        "mutates": False,
        "cleanup_action_id": None,
    }
    binding: dict[str, object] = {
        "schema_version": "bluefire.runner-provider-execution-binding.v1",
        "catalog_generation": 8,
        "catalog_digest": "sha256:" + "1" * 64,
        "logical_behavior_id": BEHAVIOR_ID,
        "logical_action_id": ACTION_ID,
        "package_id": "independent.portable-provider",
        "package_version": "1.0.0",
        "package_digest": "sha256:" + "2" * 64,
        "content_digest": "sha256:" + "3" * 64,
        "program_digest": content_hash(program),
        "provider_id": "independent.portable-provider.v1",
        "abi_version": "bluefire.provider-abi.v1",
        "artifact_sha256": artifact_digest,
        "artifact_size": len(artifact),
        "action_contract_digest": action_digest,
        "runtime_contract_digest": content_hash(runtime_contract),
        "provider_runtime_contract_digest": "sha256:" + "6" * 64,
        "inputs": runtime_contract["inputs"],
        "outputs": runtime_contract["outputs"],
        "parameters": runtime_contract["parameters"],
        "capabilities": runtime_contract["capabilities"],
        "safety_tier": runtime_contract["safety_tier"],
        "platforms": runtime_contract["platforms"],
        "mutates": False,
        "cleanup_action_id": None,
        "limits": {
            "max_module_bytes": 64 * 1024,
            "max_memory_bytes": 2 * 1024 * 1024,
            "max_input_bytes": 64 * 1024,
            "max_output_bytes": 64 * 1024,
            "fuel": 1_000_000,
        },
    }
    artifact_row: dict[str, object] = {
        "artifact_sha256": artifact_digest,
        "artifact_size": len(artifact),
        "artifact_hex": artifact.hex(),
    }
    return binding, artifact_row


def _profile(tmp_path: Path) -> tuple[dict[str, object], ActionDefinition, dict[str, object]]:
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    configured = next(item for item in config.runner_profiles if item.mode.value == "execute")
    configured = replace(configured, enabled_actions=configured.enabled_actions + (ACTION_ID,))
    binding, artifact = _binding()
    profile = build_runner_profile(
        configured,
        sandbox_root=tmp_path / "sandbox",
        platform=current_platform(),
        filesystem_scope=(),
        provider_bindings=(binding,),
        provider_artifacts=(artifact,),
    )
    return profile, _action(), binding


def test_provider_artifact_is_private_to_the_sealed_profile(tmp_path: Path) -> None:
    profile, action, binding = _profile(tmp_path)

    assert profile["provider_bindings"] == [binding]
    assert profile["provider_artifacts"][0]["artifact_hex"] == "0061736d01000000"
    assert profile["policy_digest"].startswith("sha256:")

    manifest = build_execution_manifest(
        run_id="run-provider-contract",
        step_id="step-provider-contract",
        behavior_id=BEHAVIOR_ID,
        action=action,
        runner_profile=profile,
        params={"label": "release"},
        filesystem_scope=(),
        approval_record=None,
        provider_binding=binding,
    )
    assert manifest["provider_binding"] == binding
    assert "execution_binding" not in manifest
    assert "artifact_hex" not in str(manifest)


@pytest.mark.parametrize("target", ["profile_digest", "artifact", "manifest_binding"])
def test_provider_contract_tampering_is_refused(tmp_path: Path, target: str) -> None:
    profile, action, binding = _profile(tmp_path)
    if target == "profile_digest":
        profile["provider_bindings"][0]["artifact_size"] = 9
        with pytest.raises(RunnerContractError):
            seal_profile(profile)
        return
    if target == "artifact":
        profile["provider_artifacts"][0]["artifact_hex"] = "0161736d01000000"
        profile["policy_digest"] = ""
        with pytest.raises(RunnerContractError):
            seal_profile(profile)
        return
    manifest = build_execution_manifest(
        run_id="run-provider-contract",
        step_id="step-provider-contract",
        behavior_id=BEHAVIOR_ID,
        action=action,
        runner_profile=profile,
        params={"label": "release"},
        filesystem_scope=(),
        approval_record=None,
        provider_binding=binding,
    )
    changed = copy.deepcopy(manifest)
    changed["provider_binding"]["runtime_contract_digest"] = "sha256:" + "7" * 64
    with pytest.raises(RunnerContractError):
        seal_manifest(changed)


def test_provider_binding_cannot_be_combined_with_legacy_alias(tmp_path: Path) -> None:
    profile, action, binding = _profile(tmp_path)
    with pytest.raises(RunnerContractError, match="two package execution models"):
        build_execution_manifest(
            run_id="run-provider-contract",
            step_id="step-provider-contract",
            behavior_id=BEHAVIOR_ID,
            action=action,
            runner_profile=profile,
            params={"label": "release"},
            filesystem_scope=(),
            approval_record=None,
            execution_binding={},
            provider_binding=binding,
        )
