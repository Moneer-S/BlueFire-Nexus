"""Bind a finite method review to its original consumed approval and fresh replay."""

from __future__ import annotations

from typing import Any, Mapping

from .approvals import execution_approval_binding
from .config import AutonomyLevel, RunnerProfile
from .contracts import ScenarioDefinition
from .registry import BehaviorRegistry


def validate_review_source(
    *,
    source: Mapping[str, Any],
    record: Mapping[str, Any],
    registry: BehaviorRegistry,
    consumed_approval: Mapping[str, Any],
) -> None:
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
    retry = source.get("adaptive_retry")
    if not isinstance(retry, Mapping) or retry.get("used") != 0:
        raise ValueError("adaptive proposal review exceeds the one-retry lineage")
