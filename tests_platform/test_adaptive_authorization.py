"""Offline contract tests; no runner, provider transport, or lab is launched."""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bluefire.adaptive_execution import (
    AdaptiveAuthorizationError,
    compile_adaptive_authorization,
    validate_adaptive_authorization,
    validate_selected_method,
)
from bluefire.approvals import ApprovalError, execution_approval_binding
from bluefire.config import AutonomyLevel, CleanupPolicy, load_config
from bluefire.contracts import ContractError, ExecutionMode, ScenarioDefinition, load_scenario
from bluefire.planner import DeterministicPlanner
from bluefire.registry import BehaviorRegistry, load_builtin_registry
from bluefire.util import content_hash

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)
SCOPE = {"scope_refs": ["sandbox.workspace", "network.loopback", "export.local"]}
POLICY = {
    "schema_version": "bluefire.adaptive-execution.v1",
    "steps": [
        {
            "step_id": "discover_records",
            "methods": [
                {
                    "behavior_id": "sandbox.discovery.list.v1",
                    "action_id": "sandbox.discovery.list.v1",
                },
                {
                    "behavior_id": "sandbox.discovery.metadata.v1",
                    "action_id": "sandbox.discovery.metadata.v1",
                },
            ],
        }
    ],
    "eligible_outcomes": ["blocked", "failed", "partial"],
    "max_retries": 1,
    "on_provider_failure": "stop",
}


def setup(*, policy=POLICY, scenario_name="sandbox_research_chain.yaml", platform="windows"):
    registry = load_builtin_registry()
    raw = load_scenario(ROOT / "scenarios" / scenario_name).to_dict()
    if policy is not None:
        raw["adaptive_execution"] = copy.deepcopy(policy)
    scenario = ScenarioDefinition.from_mapping(raw)
    profile = next(
        profile
        for profile in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if profile.id == "sandbox-execute.v1"
    )
    planner = DeterministicPlanner(registry)
    plan = planner.compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile, autonomy=AutonomyLevel.AUTO
    )
    arguments = {
        "registry": registry,
        "scenario": scenario,
        "plan": plan,
        "profile": profile,
        "target_scope": SCOPE,
        "platform": platform,
        "planner": planner,
    }
    return arguments, compile_adaptive_authorization(**arguments)


def binding(arguments, authorization=None):
    return execution_approval_binding(
        registry=arguments["registry"],
        scenario=arguments["scenario"],
        plan=arguments["plan"].to_dict(),
        profile=arguments["profile"],
        target_scope=SCOPE,
        autonomy=AutonomyLevel.AUTO,
        ai_provider={},
        adaptive_authorization=authorization,
    )


def selection_arguments(arguments, authorization):
    return {
        "authorization": authorization,
        "expected_authorization_digest": authorization["authorization_digest"],
        "step": authorization["steps"][0]["methods"][1]["plan_step"],
        "profile": arguments["profile"],
        "target_scope": SCOPE,
        "platform": "windows",
        "registry": arguments["registry"],
        "remaining_steps": 3,
        "remaining_seconds": 10.0,
        "retries_used": 0,
        "approval_expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "now": NOW,
        "is_retry": True,
    }


def test_saved_policy_roundtrips_and_resolves_only_explicit_exact_methods():
    arguments, authorization = setup()
    assert arguments["scenario"].to_dict()["adaptive_execution"] == POLICY
    assert ScenarioDefinition.from_mapping(arguments["scenario"].to_dict()) == arguments["scenario"]
    methods = authorization["steps"][0]["methods"]
    assert [row["plan_step"]["action_id"] for row in methods] == [
        "sandbox.discovery.list.v1",
        "sandbox.discovery.metadata.v1",
    ]
    assert len(authorization["steps"]) == 1
    for method in methods:
        assert method["plan_step"]["parameters"] == {}
        assert method["plan_step"]["inputs"] == {
            "fixture": {"from_step": "transform_fixture", "artifact": "fixture"}
        }
        assert method["plan_step_digest"] == content_hash(method["plan_step"])
    selected = validate_selected_method(**selection_arguments(arguments, authorization))
    assert selected == methods[1]
    assert (
        binding(arguments, authorization)["state_digest"]
        != binding(setup(policy=None)[0])["state_digest"]
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(max_retries=True),
        lambda p: p.update(max_retries=2),
        lambda p: p.update(eligible_outcomes=["success"]),
        lambda p: p.update(eligible_outcomes=[]),
        lambda p: p.update(eligible_outcomes=["failed", "failed"]),
        lambda p: p.update(on_provider_failure="continue"),
        lambda p: p.update(command="unreviewed"),
        lambda p: p["steps"][0].update(step_id="absent"),
        lambda p: p["steps"].append(copy.deepcopy(p["steps"][0])),
        lambda p: p["steps"][0]["methods"].pop(),
        lambda p: p["steps"][0]["methods"].append(copy.deepcopy(p["steps"][0]["methods"][0])),
        lambda p: p["steps"][0]["methods"][1].update(behavior_id="sandbox.fixture.create.v1"),
    ],
)
def test_policy_rejects_unbounded_or_unowned_authority(mutate):
    policy = copy.deepcopy(POLICY)
    mutate(policy)
    with pytest.raises(ContractError):
        setup(policy=policy)


def test_explicit_null_does_not_alias_absent_legacy_authority():
    raw = load_scenario(ROOT / "scenarios/sandbox_research_chain.yaml").to_dict()
    assert "adaptive_execution" not in raw
    raw["adaptive_execution"] = None
    with pytest.raises(ContractError):
        ScenarioDefinition.from_mapping(raw)


def test_legacy_authority_cannot_silently_upgrade_and_optin_requires_resolved_review():
    legacy, absent = setup(policy=None)
    arguments, authorization = setup()
    assert absent is None
    assert "adaptive_execution" not in legacy["scenario"].to_dict()
    assert binding(legacy) == execution_approval_binding(
        registry=legacy["registry"],
        scenario=legacy["scenario"],
        plan=legacy["plan"].to_dict(),
        profile=legacy["profile"],
        target_scope=SCOPE,
        autonomy=AutonomyLevel.AUTO,
        ai_provider={},
    )
    with pytest.raises(ApprovalError, match="requires its resolved"):
        binding(arguments)
    with pytest.raises(ApprovalError, match="legacy"):
        binding(legacy, authorization)


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_id", "sandbox.fixture.create.v1"),
        ("behavior_id", "sandbox.fixture.create.v1"),
        ("parameters", {"record_limit": 99}),
        ("inputs", {"fixture": {"from_step": "create_fixture", "artifact": "workspace"}}),
        ("required_capabilities", ["process.spawn"]),
        ("execution_binding", {"runner_opcode": "unreviewed"}),
    ],
)
def test_selected_operation_must_exactly_match_reviewed_method(field, value):
    arguments, authorization = setup()
    selected = selection_arguments(arguments, authorization)
    selected["step"] = {**selected["step"], field: value}
    with pytest.raises(AdaptiveAuthorizationError, match="were not reviewed"):
        validate_selected_method(**selected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_scope", {"scope_refs": ["sandbox.workspace"]}),
        ("platform", "linux"),
        ("catalog_authority", {"generation": 99}),
        ("remaining_steps", 0),
        ("remaining_steps", True),
        ("remaining_seconds", 0.0),
        ("remaining_seconds", float("nan")),
        ("retries_used", 1),
        ("retries_used", -1),
        ("approval_expires_at", NOW.isoformat()),
        ("approval_expires_at", "2026-09-12T00:00:00"),
    ],
)
def test_changed_target_environment_expiry_or_exhausted_budget_refuses(field, value):
    arguments, authorization = setup()
    selected = selection_arguments(arguments, authorization)
    selected[field] = value
    with pytest.raises(AdaptiveAuthorizationError):
        validate_selected_method(**selected)


def test_reserved_retry_can_be_rechecked_without_reserving_another():
    arguments, authorization = setup()
    selected = selection_arguments(arguments, authorization)
    selected.update(retries_used=1, is_retry=False)
    assert validate_selected_method(**selected)["plan_step"] == selected["step"]


def test_changed_profile_or_contract_invalidates_previously_reviewed_authority():
    arguments, authorization = setup()
    selected = selection_arguments(arguments, authorization)
    selected["profile"] = replace(
        arguments["profile"], blocked_actions=("sandbox.discovery.metadata.v1",)
    )
    with pytest.raises(AdaptiveAuthorizationError, match="profile changed"):
        validate_selected_method(**selected)
    registry = arguments["registry"]
    changed = replace(
        registry.get_action("sandbox.discovery.metadata.v1"), purpose="Changed method contract"
    )
    selected = selection_arguments(arguments, authorization)
    selected["registry"] = BehaviorRegistry(
        [registry.get_behavior(identity) for identity in registry.behavior_ids],
        [
            changed if identity == changed.id else registry.get_action(identity)
            for identity in registry.action_ids
        ],
    )
    with pytest.raises(AdaptiveAuthorizationError, match="contracts"):
        validate_selected_method(**selected)


def test_compile_refuses_disabled_incompatible_and_unowned_actions():
    arguments, _ = setup()
    for profile in (
        replace(arguments["profile"], blocked_actions=("sandbox.discovery.metadata.v1",)),
        replace(
            arguments["profile"],
            enabled_actions=tuple(
                action
                for action in arguments["profile"].enabled_actions
                if action != "sandbox.discovery.metadata.v1"
            ),
        ),
    ):
        with pytest.raises(ValueError, match="disabled|blocked"):
            compile_adaptive_authorization(**{**arguments, "profile": profile})
    with pytest.raises(AdaptiveAuthorizationError, match="platform"):
        compile_adaptive_authorization(**{**arguments, "platform": "unreviewed"})
    policy = copy.deepcopy(POLICY)
    policy["steps"][0]["methods"][1]["action_id"] = "sandbox.fixture.create.v1"
    with pytest.raises(ValueError, match="not registered"):
        setup(policy=policy)


def test_recomputed_untrusted_hash_cannot_change_the_reviewed_digest_or_parameters():
    arguments, authorization = setup()
    tampered = copy.deepcopy(authorization)
    method = tampered["steps"][0]["methods"][1]
    method["plan_step"]["parameters"]["record_limit"] = 99
    method["plan_step_digest"] = content_hash(method["plan_step"])
    tampered["authorization_digest"] = content_hash(
        {key: value for key, value in tampered.items() if key != "authorization_digest"}
    )
    with pytest.raises(AdaptiveAuthorizationError, match="digest changed"):
        validate_adaptive_authorization(
            tampered,
            expected_digest=authorization["authorization_digest"],
            registry=arguments["registry"],
            profile=arguments["profile"],
            target_scope=SCOPE,
            platform="windows",
        )
    with pytest.raises(ApprovalError, match="parameters"):
        binding(arguments, tampered)


def test_each_policy_change_requires_a_different_binding():
    arguments, authorization = setup()
    original = binding(arguments, authorization)
    for key, value in (("eligible_outcomes", ["failed"]), ("on_provider_failure", "deterministic")):
        policy = copy.deepcopy(POLICY)
        policy[key] = value
        changed_arguments, changed = setup(policy=policy)
        assert binding(changed_arguments, changed)["state_digest"] != original["state_digest"]


def test_real_collection_choices_pin_exact_values_cleanup_and_linux_compatibility():
    policy = copy.deepcopy(POLICY)
    policy["steps"] = [
        {
            "step_id": "stage_collection",
            "methods": [
                {
                    "behavior_id": "sandbox.collection.atomic-gzip.v1",
                    "action_id": "sandbox.collection.atomic-gzip.v1",
                },
                {
                    "behavior_id": "sandbox.collection.records.v1",
                    "action_id": "sandbox.collection.records.v1",
                },
                {
                    "behavior_id": "sandbox.collection.archive.v1",
                    "action_id": "sandbox.collection.archive.v1",
                },
            ],
        }
    ]
    arguments, authorization = setup(
        policy=policy, scenario_name="atomic_gzip_collection.yaml", platform="linux"
    )
    for method in authorization["steps"][0]["methods"]:
        assert method["plan_step"]["parameters"] == {
            "stage_variant": "primary",
            "max_collection_bytes": 1048576,
        }
        assert method["mutates"] is True
        assert method["cleanup_action_id"] == "sandbox.cleanup.v1"
    selected = selection_arguments(arguments, authorization)
    selected["platform"] = "linux"
    reviewed_parameters = selected["step"]["parameters"]
    for changed in ({"stage_variant": "heldout"}, {"max_collection_bytes": 2048}):
        selected["step"] = {**selected["step"], "parameters": {**reviewed_parameters, **changed}}
        with pytest.raises(AdaptiveAuthorizationError, match="were not reviewed"):
            validate_selected_method(**selected)
    with pytest.raises(AdaptiveAuthorizationError, match="always policy"):
        compile_adaptive_authorization(
            **{
                **arguments,
                "profile": replace(arguments["profile"], cleanup_policy=CleanupPolicy.MANUAL),
            }
        )
    with pytest.raises(AdaptiveAuthorizationError, match="cleanup is not enabled"):
        compile_adaptive_authorization(
            **{
                **arguments,
                "profile": replace(arguments["profile"], blocked_actions=("sandbox.cleanup.v1",)),
            }
        )
    with pytest.raises(AdaptiveAuthorizationError, match="platform"):
        compile_adaptive_authorization(**{**arguments, "platform": "windows"})
