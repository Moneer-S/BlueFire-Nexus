"""Authored budget/record boundaries only; no runner, provider network or lab effects."""

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.adaptive_observations import project_runtime_observations
from bluefire.adaptive_record_validation import (
    ADAPTIVE_DECISION_CONTRACT,
    ADAPTIVE_DECISION_CONTRACT_V5,
    validate_v4_attempt_record,
    validate_v5_attempt_record,
    validate_v5_proposal_record,
)
from bluefire.adaptive_runtime import propose_reviewed_method, reviewed_methods
from bluefire.ai import AIProviderError
from bluefire.ai_record_validation import DurableProposalRecordError
from bluefire.config import AutonomyLevel
from bluefire.util import content_hash
from tests_platform.test_adaptive_runtime import Provider
from tests_platform.test_adaptive_runtime import runtime as runtime


def identity(step):
    value = step.to_dict() if hasattr(step, "to_dict") else step
    return {field: value[field] for field in ("step_id", "behavior_id", "action_id")}


@pytest.fixture
def budget_runtime(runtime):
    kwargs, config = runtime
    kwargs = deepcopy(kwargs)
    first = kwargs["current_step"]
    methods = [
        *reviewed_methods(kwargs["authorization"], first.step_id),
        replace(first, action_id="sandbox.collection.records.v1"),
    ]
    # These exact authored PlanSteps are selector inputs, not claims that the
    # registry/compiler grants those combinations. Authorization has separate tests.
    groups = [
        {"step_id": step_id, "methods": [replace(step, step_id=step_id) for step in methods]}
        for step_id in (first.step_id, "other_step", "last_step")
    ]
    policy = {
        "schema_version": "bluefire.adaptive-execution.v2",
        "max_retries": 8,
        "on_provider_failure": "stop",
        "eligible_outcomes": ["blocked", "failed", "partial"],
        "steps": [
            {
                "step_id": group["step_id"],
                "max_retries": 3,
                "methods": [
                    {field: getattr(step, field) for field in ("behavior_id", "action_id")}
                    for step in group["methods"]
                ],
            }
            for group in groups
        ],
    }
    kwargs.update(
        policy=policy,
        authorization={
            "schema_version": "bluefire.adaptive-authorization.v2",
            "authorization_digest": content_hash("authored-reviewed-v2"),
            "policy": deepcopy(policy),
            "steps": [
                {
                    "step_id": group["step_id"],
                    "methods": [{"plan_step": step.to_dict()} for step in group["methods"]],
                }
                for group in groups
            ],
        },
        step_retries_used=0,
        attempted_methods=[identity(first)],
    )
    return kwargs, config


def record_with_hashes(record):
    projection = record["planner_state"]["observations"]
    projection["projection_digest"] = content_hash(
        {key: value for key, value in projection.items() if key != "projection_digest"}
    )
    record["planner_state_digest"] = content_hash(record["planner_state"])
    record["proposal_policy_digest"] = content_hash(record["proposal_policy"])
    return record


def test_v2_three_distinct_pivots_exclude_verified_lineage_and_do_not_reserve(budget_runtime):
    kwargs, config = budget_runtime
    all_methods = reviewed_methods(kwargs["authorization"], kwargs["current_step"].step_id)
    for used in range(3):
        # Only the newest attempt is in this continuation's local rows. Earlier
        # methods remain excluded by the caller's verified lineage projection.
        kwargs.update(
            current_step=all_methods[used],
            steps=[{**identity(all_methods[used]), "status": "failed", "evidence_ids": []}],
            retries_used=used,
            step_retries_used=used,
            attempted_methods=[identity(step) for step in all_methods[: used + 1]],
        )
        retained = deepcopy(kwargs["attempted_methods"])
        checked = []
        provider = Provider(config)
        result = propose_reviewed_method(
            **{**kwargs, "validate_choice": checked.append}, provider=provider
        )
        assert result.selected_step == all_methods[used + 1]
        assert checked == [all_methods[used + 1]]
        assert kwargs["attempted_methods"] == retained
        assert kwargs["retries_used"] == kwargs["step_retries_used"] == used
        record = result.record
        assert record["schema_version"] == "bluefire.ai-proposal-record.v5"
        policy = record["proposal_policy"]
        assert policy["schema_version"] == "bluefire.ai-proposal-policy.v3"
        assert policy["adaptive_policy_digest"] == content_hash(kwargs["policy"])
        assert (policy["maximum_adaptive_retries"], policy["adaptive_retries_used"]) == (8, used)
        assert (policy["maximum_step_retries"], policy["step_retries_used"]) == (3, used)
        assert policy["attempted_methods"] == retained
        state = validate_v5_proposal_record(record)
        assert state == provider.requests[0].context
        assert state["schema_version"] == "bluefire.planner-state.v3"
        assert state["decision_contract"] == ADAPTIVE_DECISION_CONTRACT_V5
        assert state["observations"]["schema_version"] == "bluefire.runtime-observations.v2"
        assert state["observations"]["remaining_budgets"] == {
            "steps": 4,
            "seconds": 30.0,
            "retries": 8 - used,
            "step_retries": 3 - used,
        }
        assert provider.requests[0].observation_summary.to_dict()["schema_version"] == (
            "bluefire.runtime-observation-summary.v1"
        )


@pytest.mark.parametrize("boundary", ["step", "lineage", "steps", "seconds", "rounded_seconds"])
def test_each_exhausted_budget_stops_without_provider_or_fallback(budget_runtime, boundary):
    kwargs, config = budget_runtime
    kwargs["policy"]["on_provider_failure"] = "deterministic"
    kwargs["authorization"]["policy"] = deepcopy(kwargs["policy"])
    if boundary == "step":
        kwargs.update(retries_used=3, step_retries_used=3)
        methods = reviewed_methods(kwargs["authorization"], kwargs["current_step"].step_id)
        kwargs["attempted_methods"] = [identity(step) for step in methods]
    elif boundary == "lineage":
        kwargs.update(retries_used=8, step_retries_used=2)
        kwargs["attempted_methods"] = [
            identity(step)
            for group in kwargs["authorization"]["steps"]
            for step in reviewed_methods(kwargs["authorization"], group["step_id"])[
                : 3 if group["step_id"] == kwargs["current_step"].step_id else 4
            ]
        ]
    elif boundary == "steps":
        kwargs["remaining_steps"] = 0
    else:
        kwargs["remaining_seconds"] = 0.0 if boundary == "seconds" else 0.0001
    provider = Provider(config)
    result = propose_reviewed_method(**kwargs, provider=provider)
    assert result.stop and result.selected_step is None and not provider.requests
    assert result.record["application_status"] == "stopped_budget_exhausted"
    assert result.record["decision_source"] == "none"
    assert result.record["provider_called"] is False
    validate_v5_attempt_record(result.record)
    with pytest.raises(DurableProposalRecordError, match="not a replayable proposal"):
        validate_v5_proposal_record(result.record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("step_retries_used", None),
        ("step_retries_used", True),
        ("step_retries_used", 0.0),
        ("step_retries_used", -1),
        ("step_retries_used", 1),
        ("retries_used", True),
        ("retries_used", 9),
        ("attempted_methods", None),
        ("attempted_methods", []),
    ],
)
def test_v2_requires_explicit_typed_lineage_inputs_before_provider(budget_runtime, field, value):
    kwargs, config = budget_runtime
    provider = Provider(config)
    with pytest.raises(ValueError):
        propose_reviewed_method(**{**kwargs, field: value}, provider=provider)
    assert not provider.requests


@pytest.mark.parametrize(
    "change", ["duplicate", "unknown", "omission", "refund_step", "refund_total"]
)
def test_lineage_methods_cannot_be_forgotten_repeated_or_refunded(budget_runtime, change):
    kwargs, config = budget_runtime
    methods = reviewed_methods(kwargs["authorization"], kwargs["current_step"].step_id)
    if change == "duplicate":
        kwargs["attempted_methods"] *= 2
    elif change == "unknown":
        kwargs["attempted_methods"][0]["action_id"] = "unreviewed.action.v1"
    elif change == "omission":
        kwargs["steps"].append({**identity(methods[1]), "status": "failed", "evidence_ids": []})
    elif change == "refund_step":
        kwargs["attempted_methods"].append(identity(methods[1]))
        kwargs["retries_used"] = 1
    else:
        other = reviewed_methods(kwargs["authorization"], "other_step")
        kwargs["attempted_methods"].extend(identity(step) for step in other[:2])
    provider = Provider(config)
    with pytest.raises(ValueError):
        propose_reviewed_method(**kwargs, provider=provider)
    assert not provider.requests


@pytest.mark.parametrize("disposition", ["review", "stop", "failure", "fallback", "no_inputs"])
def test_v5_retains_distinct_non_dispatch_dispositions(budget_runtime, disposition):
    kwargs, config = budget_runtime
    provider = Provider(config)
    if disposition == "review":
        kwargs["plan"] = replace(kwargs["plan"], autonomy=AutonomyLevel.ASSIST)
        expected = "awaiting_operator_approval"
    elif disposition == "stop":
        provider = Provider(config, proposal_type="stop")
        expected = "stopped_by_proposal"
    elif disposition == "no_inputs":
        for method in kwargs["authorization"]["steps"][0]["methods"][1:]:
            method["plan_step"]["inputs"] = {"data": {"from_step": "absent", "artifact": "data"}}
        expected = "stopped_no_permitted_choice"
    else:

        class Failure(Provider):
            def propose(self, request):
                raise AIProviderError("authored unavailable provider")

        provider = Failure(config)
        expected = "rejected_policy"
        if disposition == "fallback":
            kwargs["policy"]["on_provider_failure"] = "deterministic"
            kwargs["authorization"]["policy"] = deepcopy(kwargs["policy"])
            expected = "configured_fallback"
    result = propose_reviewed_method(**kwargs, provider=provider)
    assert result.selected_step is None
    assert result.stop is (disposition != "fallback")
    assert result.record["application_status"] == expected
    validate_v5_attempt_record(result.record)


@pytest.mark.parametrize(
    "change",
    [
        "missing_step_cap",
        "step_cap_bool",
        "refunded_remaining",
        "step_remaining_bool",
        "lineage_remaining",
        "repeated_option",
        "missing_guidance",
        "old_guidance",
        "invalid_policy_digest",
    ],
)
def test_v5_rehashed_records_cannot_widen_or_omit_budget_boundaries(budget_runtime, change):
    kwargs, config = budget_runtime
    record = deepcopy(propose_reviewed_method(**kwargs, provider=Provider(config)).record)
    policy = record["proposal_policy"]
    state = record["planner_state"]
    budgets = state["observations"]["remaining_budgets"]
    if change == "missing_step_cap":
        policy.pop("maximum_step_retries")
    elif change == "step_cap_bool":
        policy["maximum_step_retries"] = True
    elif change == "refunded_remaining":
        policy["step_retries_used"] = policy["adaptive_retries_used"] = 1
    elif change == "step_remaining_bool":
        budgets["step_retries"] = True
    elif change == "lineage_remaining":
        budgets["retries"] = 7
    elif change == "repeated_option":
        policy["attempted_methods"].append(identity(record["registered_options"][0]["plan_step"]))
        policy["step_retries_used"] = policy["adaptive_retries_used"] = 1
        budgets.update(retries=7, step_retries=2)
    elif change == "missing_guidance":
        state.pop("decision_contract")
    elif change == "old_guidance":
        state["decision_contract"] = deepcopy(ADAPTIVE_DECISION_CONTRACT)
    else:
        policy["adaptive_policy_digest"] = "not-a-policy-digest"
    with pytest.raises(DurableProposalRecordError):
        validate_v5_attempt_record(record_with_hashes(record))


def test_legacy_v4_guidance_and_budget_projection_stay_unchanged(runtime):
    kwargs, config = runtime
    record = propose_reviewed_method(**kwargs, provider=Provider(config)).record
    state = validate_v4_attempt_record(record)
    assert record["schema_version"] == "bluefire.ai-proposal-record.v4"
    assert record["proposal_policy"]["schema_version"] == "bluefire.ai-proposal-policy.v2"
    assert state["schema_version"] == "bluefire.planner-state.v2"
    assert state["decision_contract"]["selection_effect"] == (
        "Retry this step once using one exact untried registered option."
    )
    assert state["observations"]["schema_version"] == "bluefire.runtime-observations.v1"
    assert state["observations"]["remaining_budgets"] == {"steps": 4, "seconds": 30.0, "retries": 1}
    state.pop("decision_contract")
    record["planner_state_digest"] = content_hash(state)
    assert validate_v4_attempt_record(record) == state
    with pytest.raises(DurableProposalRecordError):
        validate_v5_attempt_record(record)


def test_v2_revalidation_failure_keeps_budget_and_never_selects_effects(budget_runtime):
    kwargs, config = budget_runtime
    before = deepcopy(kwargs["attempted_methods"])
    checked = []

    def expired(selected):
        checked.append(selected)
        raise ValueError("authored expiry after proposal latency")

    result = propose_reviewed_method(
        **{**kwargs, "validate_choice": expired}, provider=Provider(config)
    )
    assert len(checked) == 1
    assert result.stop and result.selected_step is None
    assert result.record["application_status"] == "rejected_policy"
    assert kwargs["attempted_methods"] == before
    assert kwargs["retries_used"] == kwargs["step_retries_used"] == 0
    validate_v5_attempt_record(result.record)


def test_v2_observation_extension_preserves_existing_facts_and_unknowns(runtime):
    kwargs, _ = runtime
    arguments = {
        "steps": kwargs["steps"],
        "records": [],
        "alternatives": reviewed_methods(kwargs["authorization"], kwargs["current_step"].step_id),
        "artifacts": {},
        "platform": "linux",
        "remaining_steps": 4,
        "remaining_seconds": 30.0,
        "retries_remaining": 1,
    }
    legacy = project_runtime_observations(**arguments)
    extended = project_runtime_observations(**arguments, step_retries_remaining=2)
    for field in ("attempts", "available_methods", "unknowns", "omitted_attempt_count", "platform"):
        assert extended[field] == legacy[field]
    assert extended["remaining_budgets"] == {**legacy["remaining_budgets"], "step_retries": 2}


@pytest.mark.parametrize("value", [True, -1, 4, 1.0])
def test_v2_observation_projection_refuses_invalid_step_allowance(value):
    with pytest.raises(ValueError, match="budgets"):
        project_runtime_observations(
            steps=[],
            records=[],
            alternatives=[],
            artifacts={},
            platform="linux",
            remaining_steps=1,
            remaining_seconds=2.0,
            retries_remaining=8,
            step_retries_remaining=value,
        )
