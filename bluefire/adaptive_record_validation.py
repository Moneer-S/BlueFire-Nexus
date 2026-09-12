"""Versioned validation of finite Execute proposals; legacy v3 remains unchanged."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .ai_record_validation import DurableProposalRecordError, _validate_provider
from .util import content_hash

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE_FIELDS = frozenset(
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
        "authorization_digest",
        "proposal",
        "provider",
        "provider_attempt",
        "provider_called",
        "decision_source",
        "application_status",
        "application_reason",
        "stop_requested",
        "proposal_digest",
    }
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DurableProposalRecordError(message)


def validate_v4_proposal_record(
    record: Mapping[str, Any], *, require_proposal: bool = True
) -> Mapping[str, Any]:
    """Validate a reviewable record; authority must still bind to the source run.

    A record hash alone never authorizes a dispatch. Service review checks source
    approval binding; runtime execution uses its separately verified authorization.
    Failed calls with no valid proposal are retained evidence, not replay commands.
    """
    status = record.get("application_status")
    has_proposal = isinstance(record.get("proposal"), Mapping)
    _require(
        has_proposal or not require_proposal,
        "an unsuccessful planning attempt is not a replayable proposal",
    )
    optional = (
        {"registered_step"}
        if status == "awaiting_operator_approval"
        else (
            {"applied_step", "applied_next_step_id"}
            if status == "applied_reviewed_method"
            else (
                {"failure_class"} if status in {"rejected_policy", "configured_fallback"} else set()
            )
        )
    )
    expected_fields = (
        _BASE_FIELDS if has_proposal else _BASE_FIELDS - {"proposal_digest"}
    ) | optional
    _require(set(record) == expected_fields, "v4 proposal fields are invalid")
    _require(record.get("schema_version") == "bluefire.ai-proposal-record.v4", "v4 schema invalid")
    _require(
        status
        in {
            "awaiting_operator_approval",
            "applied_reviewed_method",
            "stopped_by_proposal",
            "rejected_policy",
            "configured_fallback",
            "stopped_no_permitted_choice",
            "stopped_budget_exhausted",
        },
        "v4 status invalid",
    )
    for field in (
        "state_digest",
        "plan_digest",
        "planner_state_digest",
        "proposal_policy_digest",
        "authorization_digest",
        *(("proposal_digest",) if has_proposal else ()),
    ):
        _require(
            isinstance(record.get(field), str) and bool(_DIGEST.fullmatch(record[field])),
            "v4 digest invalid",
        )
    _require(record.get("autonomy") in {"assist", "auto"}, "v4 autonomy invalid")
    _require(record.get("outcome") in {"blocked", "failed", "partial"}, "v4 outcome invalid")
    _require(isinstance(record.get("stop_requested"), bool), "v4 stop disposition invalid")
    _require(
        record.get("decision_source")
        in {
            "provider",
            "deterministic_provider",
            "configured_provider_fallback",
            "configured_deterministic_fallback",
            *(("none",) if not has_proposal else ()),
        },
        "v4 decision provenance invalid",
    )
    _require(
        isinstance(record.get("application_reason"), str)
        and 0 < len(record["application_reason"]) <= 4000,
        "v4 reason invalid",
    )
    policy = record.get("proposal_policy")
    _require(
        isinstance(policy, Mapping)
        and set(policy)
        == {
            "schema_version",
            "mode",
            "autonomy",
            "observed_outcome",
            "authorization_digest",
            "registered_options",
            "maximum_adaptive_retries",
            "adaptive_retries_used",
            "remaining_steps",
            "on_provider_failure",
        },
        "v4 policy fields invalid",
    )
    assert isinstance(policy, Mapping)
    _require(
        policy["schema_version"] == "bluefire.ai-proposal-policy.v2"
        and policy["mode"] == "execute"
        and policy["autonomy"] == record["autonomy"]
        and policy["observed_outcome"] == record["outcome"]
        and policy["authorization_digest"] == record["authorization_digest"]
        and type(policy["maximum_adaptive_retries"]) is int
        and policy["maximum_adaptive_retries"] == 1
        and type(policy["adaptive_retries_used"]) is int
        and 0 <= policy["adaptive_retries_used"] <= 1
        and type(policy["remaining_steps"]) is int
        and policy["remaining_steps"] >= 0
        and policy["on_provider_failure"] in {"stop", "deterministic"}
        and content_hash(policy) == record["proposal_policy_digest"],
        "v4 policy boundary invalid",
    )
    options = record.get("registered_options")
    _require(
        isinstance(options, list)
        and 0 <= len(options) <= 4
        and policy["registered_options"] == options,
        "v4 method choices invalid",
    )
    assert isinstance(options, list)
    pairs = set()
    for option in options:
        _require(
            isinstance(option, Mapping)
            and set(option)
            == {
                "role",
                "step_id",
                "behavior_id",
                "action_id",
                "plan_step",
                "plan_step_digest",
            },
            "v4 method fields invalid",
        )
        step = option["plan_step"]
        _require(
            isinstance(step, Mapping) and option["plan_step_digest"] == content_hash(step),
            "v4 method digest invalid",
        )
        _require(
            option["role"] == "retry"
            and option["step_id"] == record["current_step_id"]
            and all(
                option[field] == step.get(field)
                for field in ("step_id", "behavior_id", "action_id")
            ),
            "v4 method identity invalid",
        )
        pair = (option["behavior_id"], option["action_id"])
        _require(pair not in pairs, "v4 duplicate method")
        pairs.add(pair)
    _require(
        record["allowed_step_ids"] == ([record["current_step_id"]] if options else [])
        and record["retryable_step_ids"] == record["allowed_step_ids"]
        and record["allowed_behavior_ids"] == list(dict.fromkeys(o["behavior_id"] for o in options))
        and record["allowed_action_ids"] == list(dict.fromkeys(o["action_id"] for o in options))
        and record["allowed_edges"] == []
        and record["allowed_parameter_schemas"] == {},
        "v4 method allowlist projection invalid",
    )
    state = record.get("planner_state")
    _require(
        isinstance(state, Mapping)
        and set(state)
        == {
            "schema_version",
            "source_state_digest",
            "current_step_id",
            "outcome",
            "authorization_digest",
            "registered_options",
            "observations",
            "deterministic_decision",
        },
        "v4 planner state fields invalid",
    )
    assert isinstance(state, Mapping)
    _require(
        state["schema_version"] == "bluefire.planner-state.v2"
        and state["source_state_digest"] == record["state_digest"]
        and state["current_step_id"] == record["current_step_id"]
        and state["outcome"] == record["outcome"]
        and state["authorization_digest"] == record["authorization_digest"]
        and state["registered_options"] == options
        and content_hash(state) == record["planner_state_digest"],
        "v4 planner state binding invalid",
    )
    observations = state["observations"]
    _require(
        isinstance(observations, Mapping)
        and observations.get("schema_version") == "bluefire.runtime-observations.v1"
        and observations.get("projection_digest")
        == content_hash(
            {key: value for key, value in observations.items() if key != "projection_digest"}
        ),
        "v4 observation projection invalid",
    )
    deterministic = state["deterministic_decision"]
    _require(
        isinstance(deterministic, Mapping)
        and deterministic.get("decision_id") == record["deterministic_decision_id"]
        and deterministic.get("run_id") == record["run_id"]
        and deterministic.get("current_state_digest") == record["state_digest"],
        "v4 deterministic decision binding invalid",
    )
    configured = record["provider_attempt"]
    _require(
        isinstance(configured, Mapping)
        and set(configured) == {"provider_id", "kind", "model"}
        and all(
            isinstance(configured[field], str) and 0 < len(configured[field]) <= 512
            for field in configured
        )
        and configured["kind"] in {"deterministic", "openai_responses", "chat_completions"}
        and type(record["provider_called"]) is bool,
        "v4 provider attempt identity invalid",
    )
    if not has_proposal:
        _require(
            record["proposal"] is None and record["provider"] is None,
            "v4 absent response is ambiguous",
        )
        if status in {"stopped_no_permitted_choice", "stopped_budget_exhausted"}:
            _require(
                record["provider_called"] is False
                and record["decision_source"] == "none"
                and record["stop_requested"] is True,
                "v4 no-call disposition invalid",
            )
            if status == "stopped_no_permitted_choice":
                _require(not options, "v4 no-choice refusal contains available choices")
            else:
                budgets = observations.get("remaining_budgets", {})
                _require(
                    policy["remaining_steps"] == 0
                    or policy["adaptive_retries_used"] == 1
                    or budgets.get("seconds") == 0,
                    "v4 budget refusal has remaining budget",
                )
        else:
            _require(
                status in {"rejected_policy", "configured_fallback"}
                and record["provider_called"] is True,
                "v4 failed call disposition invalid",
            )
            _require(
                (
                    status == "rejected_policy"
                    and record["stop_requested"] is True
                    and record["decision_source"] == "none"
                )
                or (
                    status == "configured_fallback"
                    and record["stop_requested"] is False
                    and record["decision_source"] == "configured_deterministic_fallback"
                    and policy["on_provider_failure"] == "deterministic"
                    and record["autonomy"] == "auto"
                ),
                "v4 failed call fallback boundary invalid",
            )
        return state
    _require(record["provider_called"] is True, "v4 response has no provider call")
    _validate_provider(record)
    proposal = record.get("proposal")
    _require(
        isinstance(proposal, Mapping) and content_hash(proposal) == record["proposal_digest"],
        "v4 proposal digest invalid",
    )
    assert isinstance(proposal, Mapping)
    if status in {"awaiting_operator_approval", "applied_reviewed_method"}:
        _require(
            bool(options)
            and policy["remaining_steps"] > 0
            and policy["adaptive_retries_used"] == 0,
            "v4 applied/reviewed choice exceeds runtime budget",
        )
        selected = record[
            "registered_step" if status == "awaiting_operator_approval" else "applied_step"
        ]
        _require(
            proposal.get("proposal_type") == "select_registered_action"
            and selected in [option["plan_step"] for option in options]
            and all(
                selected.get(field) == proposal.get("selected_" + field)
                for field in ("step_id", "behavior_id", "action_id")
            ),
            "v4 applied choice was not an exact reviewed method",
        )
        if status == "applied_reviewed_method":
            _require(
                record["autonomy"] == "auto"
                and proposal.get("requires_operator_review") is False
                and record["stop_requested"] is False
                and record["applied_next_step_id"] == selected["step_id"],
                "v4 application gate invalid",
            )
        else:
            _require(record["stop_requested"] is True, "v4 review did not stop execution")
    elif status == "configured_fallback":
        _require(
            policy["on_provider_failure"] == "deterministic"
            and record["autonomy"] == "auto"
            and record["decision_source"] == "configured_deterministic_fallback"
            and record["stop_requested"] is False,
            "v4 fallback boundary invalid",
        )
    else:
        _require(record["stop_requested"] is True, "v4 refusal did not stop execution")
    return state


def validate_v4_attempt_record(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate retained failures/no-calls as evidence, never as replay commands."""
    return validate_v4_proposal_record(record, require_proposal=False)
