"""Bind a finite method review to its original consumed approval and fresh replay."""

from __future__ import annotations

from typing import Any, Mapping

from .adaptive_budget import reserve_method, validate_budget
from .approvals import execution_approval_binding
from .config import AutonomyLevel, RunnerProfile
from .contracts import ScenarioDefinition
from .registry import BehaviorRegistry
from .util import content_hash


def validate_review_source(
    *,
    source: Mapping[str, Any],
    record: Mapping[str, Any],
    registry: BehaviorRegistry,
    consumed_approval: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Validate a verified source; return its detached v2 budget for service reservation.

    This check neither mutates the source nor consumes an approval. The service
    reserves the selected method and binds that ledger to the fresh approval.
    """
    policy = source.get("policy")
    authority = policy.get("adaptive_authorization") if isinstance(policy, Mapping) else None
    if not isinstance(authority, Mapping) or record.get("authorization_digest") != authority.get(
        "authorization_digest"
    ):
        raise ValueError("adaptive proposal does not bind to its original reviewed authority")
    assert isinstance(policy, Mapping)
    scenario = ScenarioDefinition.from_mapping(source["scenario"])
    profile = RunnerProfile.from_mapping(source["profile"], "adaptive review profile")
    binding = execution_approval_binding(
        registry=registry,
        scenario=scenario,
        plan=source["plan"],
        profile=profile,
        target_scope=policy["authorized_target_scope"],
        autonomy=AutonomyLevel(source["autonomy"]),
        ai_provider=source["ai_provider"],
        context=policy["approval_context"],
        runner_readiness=policy.get("runner_readiness"),
        catalog_authority=policy.get("catalog_authority"),
        adaptive_authorization=authority,
    )
    if binding != policy.get("approval_binding") or any(
        consumed_approval.get(key) != value for key, value in binding.items()
    ):
        raise ValueError("adaptive proposal authority differs from the original consumed approval")
    if consumed_approval.get("status") != "claimed":
        raise ValueError("adaptive proposal source approval was not claimed")
    if record.get("registered_step") not in [
        method["plan_step"] for step in authority["steps"] for method in step["methods"]
    ]:
        raise ValueError("adaptive proposal review selected an unreviewed method")
    adaptive_policy = scenario.adaptive_execution
    if record.get("schema_version") == "bluefire.ai-proposal-record.v5":
        if (
            adaptive_policy is None
            or adaptive_policy.schema_version != "bluefire.adaptive-execution.v2"
            or source.get("mode") != "execute"
            or record.get("run_id") != source.get("run_id")
            or record.get("application_status") != "awaiting_operator_approval"
            or record.get("outcome") not in adaptive_policy.eligible_outcomes
        ):
            raise ValueError("adaptive v5 review does not bind to its v2 source policy")
        budget = validate_budget(source.get("adaptive_retry"), adaptive_policy)
        selected = record["registered_step"]
        if record.get("current_step_id") != selected["step_id"]:
            raise ValueError("adaptive review selected a different step")
        proposal_policy = record.get("proposal_policy")
        limit = budget["per_step"][selected["step_id"]]
        expected = {
            "schema_version": "bluefire.ai-proposal-policy.v3",
            "mode": "execute",
            "authorization_digest": authority["authorization_digest"],
            "adaptive_policy_digest": budget["policy_digest"],
            "maximum_adaptive_retries": budget["maximum"],
            "adaptive_retries_used": budget["used"],
            "maximum_step_retries": limit["maximum"],
            "step_retries_used": limit["used"],
            "attempted_methods": budget["attempted_methods"],
            "observed_outcome": record["outcome"],
            "on_provider_failure": adaptive_policy.on_provider_failure,
        }
        if (
            not isinstance(proposal_policy, Mapping)
            or content_hash(proposal_policy) != record.get("proposal_policy_digest")
            or any(
                content_hash(proposal_policy.get(key)) != content_hash(value)
                for key, value in expected.items()
            )
        ):
            raise ValueError("adaptive proposal policy does not match the retained source budget")
        # Prove availability without committing a reservation. The service owns
        # the actual reservation and its fresh approval context.
        reserve_method(budget, adaptive_policy, selected)
        return budget
    if (
        adaptive_policy is not None
        and adaptive_policy.schema_version != "bluefire.adaptive-execution.v1"
    ):
        raise ValueError("adaptive v2 source requires a v5 proposal review")
    retry = source.get("adaptive_retry")
    if not isinstance(retry, Mapping) or retry.get("used") != 0:
        raise ValueError("adaptive proposal review exceeds the one-retry lineage")
    return None
