"""Finite v2 authority and v1 compatibility; no provider or runner is started."""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from bluefire.adaptive_execution import (
    AdaptiveAuthorizationError,
    compile_adaptive_authorization,
    validate_adaptive_authorization,
    validate_selected_method,
)
from bluefire.adaptive_execution_contract import AdaptiveContractError, AdaptiveExecution
from bluefire.approvals import ApprovalError
from bluefire.config import AutonomyLevel, CleanupPolicy
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.util import content_hash
from tests_platform.test_adaptive_authorization import (
    NOW,
    POLICY,
    SCOPE,
    binding,
    selection_arguments,
    setup,
)


def budget_policy():
    return {
        **copy.deepcopy(POLICY),
        "schema_version": "bluefire.adaptive-execution.v2",
        "max_retries": 3,
        "steps": [
            {
                "step_id": "select_records",
                "max_retries": 1,
                "methods": [
                    {
                        "behavior_id": f"sandbox.discovery.{name}.v1",
                        "action_id": f"sandbox.discovery.{name}.v1",
                    }
                    for name in ("metadata", "list")
                ],
            },
            {
                "step_id": "stage_collection",
                "max_retries": 2,
                "methods": [
                    {
                        "behavior_id": f"sandbox.collection.{name}.v1",
                        "action_id": f"sandbox.collection.{name}.v1",
                    }
                    for name in ("atomic-gzip", "records", "archive")
                ],
            },
        ],
    }


def compiled(policy=None):
    arguments, _ = setup(policy=None, scenario_name="atomic_gzip_collection.yaml", platform="linux")
    raw = arguments["scenario"].to_dict()
    next(step for step in raw["steps"] if step["id"] == "select_records")["alternates"] = [
        "sandbox.discovery.list.v1"
    ]
    raw["adaptive_execution"] = budget_policy() if policy is None else copy.deepcopy(policy)
    scenario = ScenarioDefinition.from_mapping(raw)
    plan = arguments["planner"].compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=arguments["profile"],
        autonomy=AutonomyLevel.AUTO,
    )
    arguments.update(scenario=scenario, plan=plan)
    return arguments, compile_adaptive_authorization(**arguments)


def selection(arguments, authorization, step_index=1):
    values = selection_arguments(arguments, authorization)
    values.update(
        platform="linux",
        step=authorization["steps"][step_index]["methods"][1]["plan_step"],
        step_retries_used=0,
    )
    return values


def rehash(authorization):
    authorization["authorization_digest"] = content_hash(
        {key: value for key, value in authorization.items() if key != "authorization_digest"}
    )


def test_v1_policy_bytes_default_construction_and_one_retry_remain_unchanged():
    policy = AdaptiveExecution.from_mapping(POLICY)
    assert json.dumps(policy.to_dict(), separators=(",", ":")) == json.dumps(
        POLICY, separators=(",", ":")
    )
    assert (
        AdaptiveExecution(
            policy.steps, policy.eligible_outcomes, policy.max_retries, policy.on_provider_failure
        ).to_dict()
        == POLICY
    )
    assert policy.steps[0].max_retries is None
    arguments, authorization = setup()
    assert authorization["schema_version"] == "bluefire.adaptive-authorization.v1"
    assert authorization["policy"] == POLICY
    values = selection_arguments(arguments, authorization)
    assert validate_selected_method(**values)["plan_step"] == values["step"]
    values.update(retries_used=1, is_retry=False)
    assert validate_selected_method(**values)["plan_step"] == values["step"]
    with pytest.raises(AdaptiveAuthorizationError, match="retry budget"):
        validate_selected_method(**{**values, "is_retry": True})


def test_v2_roundtrips_explicit_caps_and_compiles_exact_approval_bound_choices():
    policy = budget_policy()
    assert AdaptiveExecution.from_mapping(policy).to_dict() == policy
    arguments, authorization = compiled(policy)
    assert authorization["schema_version"] == "bluefire.adaptive-authorization.v2"
    assert authorization["policy"] == policy
    assert authorization["limits"] == arguments["profile"].budgets.to_dict()
    assert [row["step_id"] for row in authorization["steps"]] == [
        "select_records",
        "stage_collection",
    ]
    assert len(authorization["steps"][0]["methods"]) == 2
    assert len(authorization["steps"][1]["methods"]) == 3
    assert binding(arguments, authorization)["state_digest"]
    with pytest.raises(ApprovalError, match="requires its resolved"):
        binding(arguments)


@pytest.mark.parametrize("value", [True, 1.0, "2", None, 0, 9, 4])
def test_v2_rejects_invalid_or_unattainable_lineage_caps(value):
    policy = budget_policy()
    policy["max_retries"] = value
    with pytest.raises(AdaptiveContractError, match="lineage retry cap"):
        AdaptiveExecution.from_mapping(policy)


@pytest.mark.parametrize("value", [True, 1.0, "1", None, 0, -1, 2, 4])
def test_v2_rejects_invalid_or_excess_step_caps(value):
    policy = budget_policy()
    policy["steps"][0]["max_retries"] = value
    with pytest.raises(AdaptiveContractError, match="step retry cap"):
        AdaptiveExecution.from_mapping(policy)


def test_v2_accepts_eight_total_retries_only_with_sufficient_distinct_method_caps():
    policy = budget_policy()
    policy["steps"] = [
        {
            "step_id": f"step_{index}",
            "max_retries": 3,
            "methods": [
                {
                    "behavior_id": f"fixture.method{method}.v1",
                    "action_id": f"fixture.method{method}.v1",
                }
                for method in range(4)
            ],
        }
        for index in range(3)
    ]
    policy["max_retries"] = 8
    assert AdaptiveExecution.from_mapping(policy).to_dict() == policy
    policy["max_retries"] = 9
    with pytest.raises(AdaptiveContractError):
        AdaptiveExecution.from_mapping(policy)


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(schema_version="bluefire.adaptive-execution.v3"),
        lambda value: value.update(extra_budget=1),
        lambda value: value["steps"][0].pop("max_retries"),
        lambda value: value["steps"][0].update(extra_budget=1),
        lambda value: value["steps"][0]["methods"][0].update(max_retries=1),
        lambda value: value.update(eligible_outcomes=["success"]),
        lambda value: value.update(on_provider_failure="retry"),
    ],
)
def test_v2_rejects_missing_unknown_or_expanded_contract_fields(change):
    policy = budget_policy()
    change(policy)
    with pytest.raises(AdaptiveContractError):
        AdaptiveExecution.from_mapping(policy)


def test_v1_cannot_gain_step_caps_or_a_second_retry_without_explicit_version_change():
    for policy in (
        {**copy.deepcopy(POLICY), "max_retries": 2},
        {**copy.deepcopy(POLICY), "steps": [{**POLICY["steps"][0], "max_retries": 1}]},
    ):
        with pytest.raises(AdaptiveContractError):
            AdaptiveExecution.from_mapping(policy)


@pytest.mark.parametrize("source_version", [1, 2])
def test_authorization_and_policy_versions_must_pair_even_with_a_recomputed_digest(source_version):
    arguments, authorization = setup() if source_version == 1 else compiled()
    authorization["schema_version"] = f"bluefire.adaptive-authorization.v{3 - source_version}"
    rehash(authorization)
    with pytest.raises(AdaptiveAuthorizationError, match="schema does not match"):
        validate_adaptive_authorization(
            authorization,
            expected_digest=authorization["authorization_digest"],
            registry=arguments["registry"],
            profile=arguments["profile"],
            target_scope=SCOPE,
            platform=arguments["platform"],
        )


@pytest.mark.parametrize("kind", ["lineage", "step"])
def test_cap_changes_require_new_approval_and_cannot_be_rehashed_into_existing_authority(kind):
    policy = budget_policy()
    policy["max_retries"] = 2
    arguments, authorization = compiled(policy)
    original_binding = binding(arguments, authorization)
    if kind == "lineage":
        policy["max_retries"] = 1
    else:
        policy["steps"][1]["max_retries"] = 1
    changed_arguments, changed = compiled(policy)
    assert changed["authorization_digest"] != authorization["authorization_digest"]
    assert binding(changed_arguments, changed)["state_digest"] != original_binding["state_digest"]
    values = selection(arguments, authorization)
    values["authorization"] = changed
    with pytest.raises(AdaptiveAuthorizationError, match="digest changed"):
        validate_selected_method(**values)
    with pytest.raises(ApprovalError, match="reviewed scenario and plan"):
        binding(arguments, changed)


def test_step_and_lineage_caps_are_independent_and_reserved_attempts_can_be_rechecked():
    arguments, authorization = compiled()
    collection = selection(arguments, authorization)
    collection.update(retries_used=2, step_retries_used=1)
    assert validate_selected_method(**collection)["plan_step"] == collection["step"]
    collection.update(retries_used=3, step_retries_used=2, is_retry=False)
    assert validate_selected_method(**collection)["plan_step"] == collection["step"]
    with pytest.raises(AdaptiveAuthorizationError, match="retry budget"):
        validate_selected_method(**{**collection, "is_retry": True})
    discovery = selection(arguments, authorization, step_index=0)
    discovery.update(retries_used=1, step_retries_used=1)
    with pytest.raises(AdaptiveAuthorizationError, match="per-step retry budget"):
        validate_selected_method(**discovery)
    assert validate_selected_method(**{**discovery, "is_retry": False})
    with pytest.raises(AdaptiveAuthorizationError, match="per-step retry budget"):
        validate_selected_method(
            **{**discovery, "retries_used": 2, "step_retries_used": 2, "is_retry": False}
        )


@pytest.mark.parametrize("value", [None, True, 1.0, "0", -1, 1])
def test_v2_requires_a_valid_step_count_consistent_with_lineage_usage(value):
    arguments, authorization = compiled()
    values = selection(arguments, authorization)
    values["step_retries_used"] = value
    with pytest.raises(AdaptiveAuthorizationError, match="per-step retry count"):
        validate_selected_method(**values)
    values.pop("step_retries_used")
    with pytest.raises(AdaptiveAuthorizationError, match="per-step retry count"):
        validate_selected_method(**values)


@pytest.mark.parametrize(
    "field,value",
    [
        ("remaining_steps", 0),
        ("remaining_steps", True),
        ("remaining_seconds", 0),
        ("remaining_seconds", float("nan")),
        ("retries_used", True),
        ("retries_used", 1.0),
        ("is_retry", 1),
        ("approval_expires_at", NOW.isoformat()),
        ("target_scope", {"scope_refs": ["sandbox.workspace"]}),
    ],
)
def test_v2_does_not_expand_existing_runtime_budget_expiry_or_scope(field, value):
    arguments, authorization = compiled()
    values = selection(arguments, authorization)
    values[field] = value
    with pytest.raises(AdaptiveAuthorizationError):
        validate_selected_method(**values)


def test_v2_preserves_exact_operation_and_cleanup_requirements():
    arguments, authorization = compiled()
    values = selection(arguments, authorization)
    values["step"] = {**values["step"], "parameters": {"stage_variant": "heldout"}}
    with pytest.raises(AdaptiveAuthorizationError, match="were not reviewed"):
        validate_selected_method(**values)
    with pytest.raises(AdaptiveAuthorizationError, match="always policy"):
        compile_adaptive_authorization(
            **{
                **arguments,
                "profile": replace(arguments["profile"], cleanup_policy=CleanupPolicy.MANUAL),
            }
        )
