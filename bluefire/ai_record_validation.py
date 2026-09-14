"""Strict, type-safe validation for durable AI proposal-record envelopes."""

from __future__ import annotations

import re
from typing import Any, Mapping, cast

from .util import content_hash

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_STEP_ID = re.compile(r"^[a-z][a-z0-9_]*$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_DECISION_ID = re.compile(r"^decision-[0-9a-f]{20}$")
_OUTCOMES = frozenset({"success", "partial", "blocked", "failed"})
_DISPOSITIONS = frozenset({"simulate", "execute", "counterfactual", "stop"})
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "mode",
        "autonomy",
        "observed_outcome",
        "registered_options",
        "maximum_adaptive_retries",
        "adaptive_retries_used",
        "remaining_steps",
        "execute_mutations_require_fresh_approval",
        "runner_profile_id",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "current_step_id",
        "outcome",
        "autonomy",
        "state_digest",
        "plan_digest",
        "deterministic_decision_id",
        "allowed_step_ids",
        "allowed_behavior_ids",
        "allowed_action_ids",
        "allowed_edges",
        "allowed_parameter_schemas",
        "retryable_step_ids",
        "registered_options",
        "planner_state",
        "planner_state_digest",
        "proposal_policy",
        "proposal_policy_digest",
        "provider",
        "proposal",
        "proposal_digest",
        "application_status",
        "application_reason",
        "proposal_policy_evaluation",
    }
)
_PROVIDER_FIELDS = frozenset(
    {
        "requested_provider_id",
        "effective_provider_id",
        "model",
        "proposal_id",
        "response_id",
        "attempts",
        "used_fallback",
        "fallback_reason",
        "usage",
    }
)
_APPLIED_STATUSES = frozenset(
    {
        "applied_registered_alternate",
        "applied_typed_parameters",
        "applied_registered_action",
        "applied_registered_retry",
    }
)


class DurableProposalRecordError(ValueError):
    """Raised when a v3 durable proposal record is not self-consistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DurableProposalRecordError(message)


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    _require(
        isinstance(value, Mapping) and all(isinstance(key, str) for key in value),
        f"{context} is invalid",
    )
    return cast(Mapping[str, Any], value)


def _list(value: Any, context: str) -> list[Any]:
    _require(isinstance(value, list), f"{context} is invalid")
    return cast(list[Any], value)


def _validate_provider(record: Mapping[str, Any]) -> None:
    provider = _mapping(record.get("provider"), "persisted AI provider metadata")
    _require(set(provider) == _PROVIDER_FIELDS, "persisted AI provider fields are invalid")
    for field in (
        "requested_provider_id",
        "effective_provider_id",
        "model",
        "proposal_id",
        "response_id",
    ):
        value = provider.get(field)
        _require(
            isinstance(value, str) and 0 < len(value) <= 512,
            f"persisted AI provider {field} is invalid",
        )
    attempts = provider.get("attempts")
    fallback_reason = provider.get("fallback_reason")
    _require(
        not isinstance(attempts, bool) and isinstance(attempts, int) and 1 <= attempts <= 20,
        "persisted AI provider attempts are invalid",
    )
    _require(isinstance(provider.get("used_fallback"), bool), "fallback state is invalid")
    _require(
        fallback_reason is None
        or (isinstance(fallback_reason, str) and 0 < len(fallback_reason) <= 2_000),
        "fallback reason is invalid",
    )
    usage = _mapping(provider.get("usage"), "persisted AI provider usage")
    _require(
        set(usage).issubset({"input_tokens", "output_tokens", "total_tokens"})
        and all(
            not isinstance(value, bool) and isinstance(value, int) and value >= 0
            for value in usage.values()
        ),
        "persisted AI provider usage is invalid",
    )


def _validate_evaluation(record: Mapping[str, Any]) -> Mapping[str, Any]:
    evaluation = _mapping(
        record.get("proposal_policy_evaluation"), "persisted AI policy evaluation"
    )
    status = evaluation.get("status")
    expected = {
        "permitted": {"status", "policy_digest", "mutation", "execute_requires_fresh_approval"},
        "refused": {"status", "policy_digest", "reason"},
        "not_applicable": {"status", "policy_digest"},
    }.get(status if isinstance(status, str) else "")
    _require(expected is not None and set(evaluation) == expected, "policy evaluation is invalid")
    _require(
        evaluation.get("policy_digest") == record.get("proposal_policy_digest"),
        "policy evaluation digest is invalid",
    )
    if status == "permitted":
        _require(
            isinstance(evaluation.get("mutation"), bool)
            and isinstance(evaluation.get("execute_requires_fresh_approval"), bool),
            "permitted policy evaluation is invalid",
        )
    elif status == "refused":
        reason = evaluation.get("reason")
        _require(
            isinstance(reason, str) and 0 < len(reason) <= 2_000,
            "refused policy evaluation is invalid",
        )
    return evaluation


def _validate_policy(record: Mapping[str, Any]) -> Mapping[str, Any]:
    policy = _mapping(record.get("proposal_policy"), "persisted AI proposal policy")
    _require(set(policy) == _POLICY_FIELDS, "persisted AI proposal policy fields are invalid")
    mode = policy.get("mode")
    autonomy = policy.get("autonomy")
    outcome = policy.get("observed_outcome")
    retries = policy.get("adaptive_retries_used")
    remaining = policy.get("remaining_steps")
    profile_id = policy.get("runner_profile_id")
    _require(
        policy.get("schema_version") == "bluefire.ai-proposal-policy.v1"
        and mode in {"simulate", "execute"}
        and autonomy in {"off", "assist", "auto"}
        and autonomy == record.get("autonomy")
        and outcome in _OUTCOMES
        and outcome == record.get("outcome")
        and policy.get("registered_options") == record.get("registered_options")
        and policy.get("maximum_adaptive_retries") == 1
        and not isinstance(retries, bool)
        and isinstance(retries, int)
        and 0 <= retries <= 1
        and not isinstance(remaining, bool)
        and isinstance(remaining, int)
        and remaining >= 0
        and policy.get("execute_mutations_require_fresh_approval") is True,
        "persisted AI proposal policy boundary is invalid",
    )
    _list(policy.get("registered_options"), "persisted AI registered options")
    _require(
        (
            mode == "simulate"
            and (
                profile_id is None
                or (isinstance(profile_id, str) and _STABLE_ID.fullmatch(profile_id) is not None)
            )
        )
        or (
            mode == "execute"
            and isinstance(profile_id, str)
            and _STABLE_ID.fullmatch(profile_id) is not None
        ),
        "persisted AI runner profile policy is invalid",
    )
    _require(
        record.get("proposal_policy_digest") == content_hash(policy),
        "persisted AI proposal policy digest is mismatched",
    )
    return policy


def _validate_registered_options(record: Mapping[str, Any]) -> None:
    options = _list(record.get("registered_options"), "persisted AI registered options")
    _require(len(options) <= 2, "persisted AI registered options exceed the bound")
    roles: set[str] = set()
    allowed_steps = _list(record.get("allowed_step_ids"), "persisted AI allowed steps")
    allowed_behaviors = _list(record.get("allowed_behavior_ids"), "persisted AI allowed behaviors")
    allowed_actions = _list(record.get("allowed_action_ids"), "persisted AI allowed actions")
    allowed_edges = _list(record.get("allowed_edges"), "persisted AI allowed edges")
    retryable_steps = _list(record.get("retryable_step_ids"), "persisted AI retryable steps")
    parameter_schemas = _mapping(
        record.get("allowed_parameter_schemas"), "persisted AI parameter schemas"
    )
    projected_edges: list[Mapping[str, Any]] = []
    projected_actions: list[str] = []
    for raw_option in options:
        option = _mapping(raw_option, "persisted AI registered option")
        _require(
            set(option)
            == {
                "role",
                "step_id",
                "behavior_ids",
                "action_ids_by_behavior",
                "parameter_schemas",
                "edge",
            },
            "persisted AI registered option fields are invalid",
        )
        role = option.get("role")
        step_id = option.get("step_id")
        behaviors = _list(option.get("behavior_ids"), "registered option behaviors")
        actions_by_behavior = _mapping(
            option.get("action_ids_by_behavior"), "registered option actions"
        )
        schemas = _mapping(option.get("parameter_schemas"), "registered option schemas")
        _require(
            role in {"next", "retry"}
            and role not in roles
            and isinstance(step_id, str)
            and _STEP_ID.fullmatch(step_id) is not None
            and step_id in allowed_steps
            and 1 <= len(behaviors) <= 1_000
            and len(behaviors) == len(set(behaviors))
            and all(
                isinstance(behavior_id, str)
                and _STABLE_ID.fullmatch(behavior_id) is not None
                and behavior_id in allowed_behaviors
                for behavior_id in behaviors
            )
            and schemas == parameter_schemas.get(step_id, {}),
            "persisted AI registered option boundary is invalid",
        )
        roles.add(cast(str, role))
        for behavior_id, raw_actions in actions_by_behavior.items():
            actions = _list(raw_actions, f"registered actions for {behavior_id}")
            _require(
                len(actions) == len(set(actions))
                and all(
                    isinstance(action_id, str)
                    and _STABLE_ID.fullmatch(action_id) is not None
                    and action_id in allowed_actions
                    for action_id in actions
                ),
                "persisted AI registered action boundary is invalid",
            )
        edge = option.get("edge")
        if role == "next":
            edge_mapping = _mapping(edge, "persisted AI registered edge")
            _require(
                set(edge_mapping) == {"from_step", "outcome", "to_step"}
                and edge_mapping.get("from_step") == record.get("current_step_id")
                and edge_mapping.get("outcome") == record.get("outcome")
                and edge_mapping.get("to_step") == step_id
                and edge_mapping in allowed_edges,
                "persisted AI registered edge is invalid",
            )
            _require(
                set(actions_by_behavior) == set(behaviors),
                "registered successor action projection is invalid",
            )
            projected_edges.append(edge_mapping)
            for behavior_id in behaviors:
                projected_actions.extend(actions_by_behavior[behavior_id])
        else:
            _require(
                edge is None and not actions_by_behavior and step_id in retryable_steps,
                "persisted AI retry option is invalid",
            )
    _require(
        allowed_edges == projected_edges
        and allowed_actions == list(dict.fromkeys(projected_actions)),
        "persisted AI registered option projection is invalid",
    )


def _validate_planner_state(
    record: Mapping[str, Any], policy: Mapping[str, Any]
) -> Mapping[str, Any]:
    state = _mapping(record.get("planner_state"), "persisted AI planner state")
    _require(
        set(state)
        == {
            "schema_version",
            "source_state_digest",
            "mode",
            "current_step_id",
            "outcome",
            "completed_steps",
            "deterministic_decision",
            "registered_options",
            "remaining_budgets",
        },
        "persisted AI planner state fields are invalid",
    )
    _require(
        state.get("schema_version") == "bluefire.planner-state.v1"
        and state.get("source_state_digest") == record.get("state_digest")
        and state.get("mode") == policy.get("mode")
        and state.get("current_step_id") == record.get("current_step_id")
        and state.get("outcome") == record.get("outcome")
        and state.get("registered_options") == record.get("registered_options")
        and record.get("planner_state_digest") == content_hash(state),
        "persisted AI planner state boundary is mismatched",
    )
    completed = _list(state.get("completed_steps"), "persisted AI completed steps")
    _require(1 <= len(completed) <= 1_000, "persisted AI completed steps are invalid")
    for row in completed:
        item = _mapping(row, "persisted AI completed step")
        _require(
            set(item) == {"step_id", "behavior_id", "status"}
            and isinstance(item.get("step_id"), str)
            and _STEP_ID.fullmatch(item["step_id"]) is not None
            and isinstance(item.get("behavior_id"), str)
            and _STABLE_ID.fullmatch(item["behavior_id"]) is not None
            and item.get("status") in _OUTCOMES,
            "persisted AI completed step is invalid",
        )
    _require(
        completed[-1].get("step_id") == record.get("current_step_id")
        and completed[-1].get("status") == record.get("outcome"),
        "persisted AI completed prefix is invalid",
    )
    budgets = _mapping(state.get("remaining_budgets"), "persisted AI remaining budgets")
    maximum_retries = policy.get("maximum_adaptive_retries")
    retries_used = policy.get("adaptive_retries_used")
    remaining_steps = budgets.get("steps")
    remaining_retries = budgets.get("retries")
    _require(
        set(budgets) == {"steps", "retries"}
        and not isinstance(remaining_steps, bool)
        and isinstance(remaining_steps, int)
        and remaining_steps >= 0
        and not isinstance(remaining_retries, bool)
        and isinstance(remaining_retries, int)
        and remaining_retries >= 0
        and remaining_steps == policy.get("remaining_steps")
        and remaining_retries == max(cast(int, maximum_retries) - cast(int, retries_used), 0),
        "persisted AI planner budgets are invalid",
    )
    decision = _mapping(state.get("deterministic_decision"), "persisted planner decision")
    _require(
        set(decision)
        == {"decision_id", "selected_step_id", "selected_behavior_id", "execution_disposition"},
        "persisted planner decision fields are invalid",
    )
    step_id = decision.get("selected_step_id")
    behavior_id = decision.get("selected_behavior_id")
    disposition = decision.get("execution_disposition")
    decision_id = decision.get("decision_id")
    _require(
        isinstance(decision_id, str)
        and _DECISION_ID.fullmatch(decision_id) is not None
        and decision_id == record.get("deterministic_decision_id")
        and disposition in _DISPOSITIONS,
        "persisted planner decision identity is invalid",
    )
    if disposition == "stop":
        _require(step_id is None and behavior_id is None, "stop decision selected a graph object")
    else:
        _require(
            isinstance(step_id, str)
            and _STEP_ID.fullmatch(step_id) is not None
            and isinstance(behavior_id, str)
            and _STABLE_ID.fullmatch(behavior_id) is not None,
            "persisted planner selection is invalid",
        )
    if disposition in {"simulate", "execute"}:
        _require(disposition == policy.get("mode"), "planner disposition does not match mode")
        next_options = [
            option
            for option in _list(state.get("registered_options"), "registered options")
            if isinstance(option, Mapping) and option.get("role") == "next"
        ]
        _require(len(next_options) == 1, "planner successor is ambiguous")
        behaviors = _list(next_options[0].get("behavior_ids"), "registered behaviors")
        _require(
            bool(behaviors)
            and step_id == next_options[0].get("step_id")
            and behavior_id == behaviors[0],
            "planner decision did not select the deterministic registered successor",
        )
    expected_decision_id = (
        "decision-"
        + content_hash(
            {
                "run_id": record.get("run_id"),
                "current_step_id": record.get("current_step_id"),
                "outcome": record.get("outcome"),
                "state_digest": record.get("state_digest"),
                "selected_step_id": step_id,
                "disposition": disposition,
            }
        ).removeprefix("sha256:")[:20]
    )
    _require(decision_id == expected_decision_id, "persisted planner decision digest is invalid")
    return state


def validate_v3_proposal_record(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate the exact v3 envelope and return its authenticated planner state."""

    _require(isinstance(record, Mapping), "persisted AI proposal record is invalid")
    evaluation = _validate_evaluation(record)
    status = record.get("application_status")
    _require(
        isinstance(status, str) and 0 < len(status) <= 128,
        "persisted AI application status is invalid",
    )
    expected_fields = set(_RECORD_FIELDS)
    if status == "awaiting_operator_approval":
        expected_fields.add("registered_step")
    elif status in _APPLIED_STATUSES and evaluation.get("mutation") is True:
        expected_fields.update({"applied_step", "applied_next_step_id"})
    _require(set(record) == expected_fields, "persisted AI proposal record fields are invalid")
    _require(
        record.get("schema_version") == "bluefire.ai-proposal-record.v3"
        and isinstance(record.get("run_id"), str)
        and _RUN_ID.fullmatch(record["run_id"]) is not None
        and isinstance(record.get("current_step_id"), str)
        and _STEP_ID.fullmatch(record["current_step_id"]) is not None
        and record.get("outcome") in _OUTCOMES
        and record.get("autonomy") in {"off", "assist", "auto"}
        and all(
            isinstance(record.get(field), str) and _DIGEST.fullmatch(record[field]) is not None
            for field in (
                "state_digest",
                "plan_digest",
                "planner_state_digest",
                "proposal_policy_digest",
                "proposal_digest",
            )
        )
        and isinstance(record.get("deterministic_decision_id"), str)
        and _DECISION_ID.fullmatch(record["deterministic_decision_id"]) is not None
        and isinstance(record.get("application_reason"), str)
        and 0 < len(record["application_reason"]) <= 4_000,
        "persisted AI proposal record boundary is invalid",
    )
    for field in (
        "allowed_step_ids",
        "allowed_behavior_ids",
        "allowed_action_ids",
        "allowed_edges",
        "retryable_step_ids",
        "registered_options",
    ):
        _list(record.get(field), f"persisted AI {field}")
    _mapping(record.get("allowed_parameter_schemas"), "persisted AI parameter schemas")
    _mapping(record.get("proposal"), "persisted AI proposal")
    _validate_registered_options(record)
    if status == "awaiting_operator_approval":
        _mapping(record.get("registered_step"), "persisted AI registered step")
    if {"applied_step", "applied_next_step_id"}.issubset(record):
        _mapping(record.get("applied_step"), "persisted AI applied step")
        next_step_id = record.get("applied_next_step_id")
        _require(
            isinstance(next_step_id, str) and _STEP_ID.fullmatch(next_step_id) is not None,
            "persisted AI applied successor is invalid",
        )
    _validate_provider(record)
    policy = _validate_policy(record)
    return _validate_planner_state(record, policy)


__all__ = ["DurableProposalRecordError", "validate_v3_proposal_record"]
