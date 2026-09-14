"""Pure source-record tests: no runner, provider, socket or subprocess effects."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.approvals import execution_approval_binding, execution_approval_state
from bluefire.config import AutonomyLevel, RunnerProfile
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry
from bluefire.replay_checkpoint import (
    CheckpointError,
    build_checkpoint,
    build_restoration_plan,
    validate_checkpoint,
    validate_restoration_plan,
)
from bluefire.replay_checkpoint_binding import checkpoint_source_binding_hash
from bluefire.replay_checkpoint_parameters import build_parameter_resolution, reviewed_intent
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_replay_checkpoint import _checkpoint_kwargs, _rehash_checkpoint


def gzip_checkpoint_inputs():
    registry = load_builtin_registry()
    scenario = load_scenario(
        Path(__file__).resolve().parents[1] / "scenarios/atomic_gzip_collection.yaml"
    )
    kwargs = _checkpoint_kwargs()
    profile_doc = kwargs["source_authority"]["profile"]
    profile_doc["environment_type"] = "disposable"
    profile_doc["platforms"] = ["linux"]
    profile_doc["enabled_actions"] += [
        "sandbox.collection.atomic-gzip.v1",
        "sandbox.collection.records.v1",
        "sandbox.collection.archive.v1",
    ]
    profile_doc["capabilities"] = sorted(
        {
            capability
            for action_id in profile_doc["enabled_actions"]
            for capability in registry.get_action(action_id).capabilities
        }
    )
    kwargs["source_authority"]["runner_readiness"]["platform"] = "linux"
    profile = RunnerProfile.from_mapping(profile_doc)
    kwargs["source_authority"]["profile"] = profile.to_dict()
    plan = (
        DeterministicPlanner(registry)
        .compile(scenario, mode=ExecutionMode.EXECUTE, profile=profile)
        .to_dict()
    )
    binding_arguments = dict(
        registry=registry,
        scenario=scenario,
        plan=plan,
        profile=profile,
        target_scope=kwargs["source_authority"]["target_scope"],
        autonomy=AutonomyLevel.OFF,
        ai_provider=plan["ai_provider"],
        runner_readiness=kwargs["source_authority"]["runner_readiness"],
        catalog_authority=kwargs["source_authority"]["catalog_authority"],
    )
    binding = execution_approval_binding(**binding_arguments)
    intent = execution_approval_state(**binding_arguments)
    assert binding["state_digest"] == content_hash(intent)
    kwargs.update(
        scenario=scenario.to_dict(),
        plan=plan,
        checkpoint_before_step_id="select_records",
        source_binding_hash=checkpoint_source_binding_hash(
            source_run_id=kwargs["source_run_id"],
            scenario=scenario.to_dict(),
            plan=plan,
            approval_binding=binding,
        ),
        parameter_resolution=build_parameter_resolution(scenario.to_dict(), binding, intent),
    )
    return kwargs, registry


def restoration(checkpoint, kwargs, registry):
    return build_restoration_plan(
        checkpoint,
        target_scenario=kwargs["scenario"],
        target_plan=kwargs["plan"],
        target_profile=kwargs["source_authority"]["profile"],
        target_scope=kwargs["source_authority"]["target_scope"],
        target_catalog_authority=kwargs["source_authority"]["catalog_authority"],
        target_runner_readiness=kwargs["source_authority"]["runner_readiness"],
        variant_impact={
            "parameter_steps": [],
            "behavior_steps": [],
            "action_steps": [],
            "autonomy_changed": False,
            "profile_changed": False,
            "defense_change": None,
        },
        registry=registry,
    )


def test_gzip_omitted_default_checkpoint_and_exact_restoration_are_bound():
    kwargs, registry = gzip_checkpoint_inputs()
    original = copy.deepcopy(kwargs)
    assert kwargs["scenario"]["steps"][3]["parameters"] == {"stage_variant": "primary"}
    assert "max_collection_bytes" in kwargs["plan"]["steps"][3]["parameters"]
    checkpoint = build_checkpoint(**kwargs)
    assert checkpoint["schema_version"] == "bluefire.replay-checkpoint.v2"
    assert (
        checkpoint["source_scenario"]["steps"][3]["parameters_hash"]
        != checkpoint["source_plan"]["steps"][3]["parameters_hash"]
    )
    assert (
        validate_checkpoint(checkpoint, expected_source_binding_hash=kwargs["source_binding_hash"])
        == checkpoint
    )
    target = restoration(checkpoint, kwargs, registry)
    assert validate_restoration_plan(target, checkpoint) == target
    assert kwargs == original


def test_legacy_v1_exact_equality_stays_required():
    kwargs = _checkpoint_kwargs()
    checkpoint = build_checkpoint(**kwargs)
    assert checkpoint["schema_version"] == "bluefire.replay-checkpoint.v1"
    assert "parameter_resolution" not in checkpoint
    kwargs["plan"]["steps"][0]["parameters"]["unreviewed"] = 1
    with pytest.raises(CheckpointError):
        build_checkpoint(**kwargs)
    kwargs, _ = gzip_checkpoint_inputs()
    del kwargs["parameter_resolution"]
    with pytest.raises(CheckpointError):
        build_checkpoint(**kwargs)


@pytest.mark.parametrize(
    "mutation",
    ["default", "type", "bound", "catalog", "approval", "source", "authored", "schema", "resolved"],
)
def test_rehashed_parameter_proof_cannot_change_reviewed_authority(mutation):
    kwargs, _ = gzip_checkpoint_inputs()
    checkpoint = copy.deepcopy(build_checkpoint(**kwargs))
    proof = checkpoint["parameter_resolution"]
    intent = reviewed_intent(proof)
    envelope = intent["resolved_alternate_envelope"]
    option = envelope["steps"][3]["options"][0]
    parameter = next(
        row for row in option["contract"]["parameters"] if row["name"] == "max_collection_bytes"
    )
    if mutation in {"default", "type", "bound"}:
        parameter[{"default": "default", "type": "type", "bound": "maximum"}[mutation]] = {
            "default": 512,
            "type": "boolean",
            "bound": 1,
        }[mutation]
        option["contract_digest"] = content_hash(option["contract"])
        envelope["envelope_digest"] = content_hash(
            {key: value for key, value in envelope.items() if key != "envelope_digest"}
        )
    elif mutation == "catalog":
        intent["catalog_authority"]["generation"] += 1
    elif mutation == "approval":
        proof["approval_binding"]["state_digest"] = "sha256:" + "c" * 64
    elif mutation == "source":
        checkpoint["source_binding_hash"] = "sha256:" + "d" * 64
    elif mutation == "authored":
        proof["authored_parameters"]["stage_collection"]["max_collection_bytes"] = 512
    elif mutation == "schema":
        checkpoint["schema_version"] = "bluefire.replay-checkpoint.v1"
    else:
        option["resolved_parameters"]["max_collection_bytes"] = 512
    if mutation not in {"authored", "schema"}:
        checkpoint["parameter_resolution"] = build_parameter_resolution(
            kwargs["scenario"],
            proof["approval_binding"],
            intent,
        )
    _rehash_checkpoint(checkpoint)
    with pytest.raises(CheckpointError):
        validate_checkpoint(checkpoint, expected_source_binding_hash=kwargs["source_binding_hash"])


@pytest.mark.parametrize("invalid", [True, 0, -1, 1048577, "512", {"value": 512}])
def test_even_newly_hashed_invalid_default_or_resolved_value_is_refused(invalid):
    kwargs, _ = gzip_checkpoint_inputs()
    proof = kwargs["parameter_resolution"]
    intent = reviewed_intent(proof)
    envelope = intent["resolved_alternate_envelope"]
    option = envelope["steps"][3]["options"][0]
    option["resolved_parameters"]["max_collection_bytes"] = invalid
    kwargs["scenario"]["steps"][3]["parameters"]["max_collection_bytes"] = invalid
    intent["scenario_digest"] = content_hash(kwargs["scenario"])
    kwargs["plan"]["steps"][3]["parameters"]["max_collection_bytes"] = invalid
    envelope["envelope_digest"] = content_hash(
        {key: value for key, value in envelope.items() if key != "envelope_digest"}
    )
    binding = proof["approval_binding"]
    binding["state_digest"] = content_hash(intent)
    binding["plan_digest"] = content_hash(kwargs["plan"])
    kwargs["parameter_resolution"] = build_parameter_resolution(kwargs["scenario"], binding, intent)
    kwargs["source_binding_hash"] = checkpoint_source_binding_hash(
        source_run_id=kwargs["source_run_id"],
        scenario=kwargs["scenario"],
        plan=kwargs["plan"],
        approval_binding=binding,
    )
    with pytest.raises(CheckpointError, match="violate the reviewed behavior contract"):
        build_checkpoint(**kwargs)


def test_restoration_refuses_changed_catalog_definition_or_unbound_target_default():
    kwargs, registry = gzip_checkpoint_inputs()
    checkpoint = build_checkpoint(**kwargs)
    behavior = registry.get_behavior("sandbox.collection.atomic-gzip.v1")
    changed_behavior = replace(
        behavior,
        parameters=tuple(
            replace(spec, default=512) if spec.name == "max_collection_bytes" else spec
            for spec in behavior.parameters
        ),
    )
    changed_registry = type(registry)(
        [changed_behavior if item.id == behavior.id else item for item in registry.behaviors],
        [
            (
                replace(item, parameters=changed_behavior.parameters)
                if item.id == behavior.id
                else item
            )
            for item in registry.actions
        ],
    )
    with pytest.raises(CheckpointError):
        restoration(checkpoint, kwargs, changed_registry)
    kwargs["plan"]["steps"][3]["parameters"]["max_collection_bytes"] = 512
    with pytest.raises(CheckpointError):
        restoration(checkpoint, kwargs, registry)


def test_restoration_refuses_changed_action_with_unchanged_behavior():
    kwargs, registry = gzip_checkpoint_inputs()
    checkpoint = build_checkpoint(**kwargs)
    action = registry.get_action("sandbox.collection.atomic-gzip.v1")
    changed_registry = type(registry)(
        registry.behaviors,
        [
            replace(item, purpose="Changed execution contract") if item.id == action.id else item
            for item in registry.actions
        ],
    )
    assert changed_registry.get_behavior(action.id) == registry.get_behavior(action.id)
    with pytest.raises(CheckpointError):
        restoration(checkpoint, kwargs, changed_registry)


@pytest.mark.parametrize("limit", ["byte", "node"])
def test_compact_references_cannot_amplify_reconstructed_approval(limit):
    # The compact JSON fits the existing checkpoint limits. Reusing its one
    # contract must still charge every expanded occurrence before intent hashing.
    contract = {"description": "x" * 16_384} if limit == "byte" else {"rows": [0] * 1024}
    digest = content_hash(contract)
    option = {
        "contract": {"reviewed_contract_ref": digest},
        "contract_digest": digest,
        "actions": [],
    }
    proof = {
        "intent_template": {
            "resolved_alternate_envelope": {
                "steps": [{"options": [copy.deepcopy(option) for _ in range(256)]}]
            }
        },
        "contracts": {digest: contract},
    }
    from bluefire.replay_checkpoint import _json_copy

    assert _json_copy(proof, "bounded proof") == proof
    assert len(canonical_json_bytes(proof)) < 256 * 1024
    with pytest.raises(CheckpointError, match=f"expanded approval exceeds its {limit} bound"):
        reviewed_intent(proof)
