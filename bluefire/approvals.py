"""Typed approval bindings shared by the service and orchestration boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .config import AutonomyLevel, RunnerProfile
from .contracts import ScenarioDefinition
from .registry import BehaviorRegistry
from .util import content_hash


class ApprovalError(ValueError):
    """Raised when an Execute approval is absent, stale, or differently bound."""


class ApprovalStore(Protocol):
    """Minimal durable capability store required by Execute orchestration."""

    def claim_consumed_approval(
        self,
        approval_id: str,
        *,
        nonce: str,
        approved_by: str,
        expected_state_digest: str,
        expected_plan_digest: str,
        expected_target_scope_digest: str,
        expected_profile_id: str,
        expected_maximum_tier: str,
    ) -> Mapping[str, Any]: ...


def execution_approval_binding(
    *,
    registry: BehaviorRegistry,
    scenario: ScenarioDefinition,
    plan: Mapping[str, Any],
    profile: RunnerProfile,
    target_scope: Mapping[str, Any],
    autonomy: AutonomyLevel,
    ai_provider: Mapping[str, Any],
    context: Mapping[str, Any] | None = None,
    runner_readiness: Mapping[str, Any] | None = None,
) -> Mapping[str, str]:
    """Hash every operator-reviewed input that may affect an Execute plan."""

    raw_steps = plan.get("steps", [])
    action_implementations = {
        str(step["step_id"]): str(step["action_id"])
        for step in raw_steps
        if isinstance(step, Mapping)
        and isinstance(step.get("step_id"), str)
        and isinstance(step.get("action_id"), str)
    }
    state = {
        "schema_version": "bluefire.execution-intent.v1",
        "scenario_digest": content_hash(scenario.to_dict()),
        "mode": "execute",
        "profile": profile.to_dict(),
        "target_scope": dict(target_scope),
        "autonomy": autonomy.value,
        "ai_provider": dict(ai_provider),
        "context": dict(context or {}),
        "action_implementations": action_implementations,
        "resolved_alternate_envelope": execution_approval_envelope(
            registry=registry,
            scenario=scenario,
        ),
    }
    if runner_readiness is not None:
        state["runner_readiness"] = dict(runner_readiness)
    ranks = {"safe": 1, "controlled": 2, "restricted": 3}
    tiers: list[str] = []
    for step in scenario.steps:
        for behavior_id in (step.behavior_id, *step.alternates):
            behavior = registry.get_behavior(behavior_id)
            tiers.append(behavior.safety_tier.value)
            tiers.extend(
                registry.get_action(action_id).safety_tier.value
                for action_id in behavior.action_ids
            )
    maximum_tier = max(tiers, key=ranks.__getitem__) if tiers else "safe"
    return {
        "state_digest": content_hash(state),
        "plan_digest": content_hash(plan),
        "target_scope_digest": content_hash(target_scope),
        "profile_id": profile.id,
        "maximum_tier": maximum_tier,
    }


def execution_approval_envelope(
    *,
    registry: BehaviorRegistry,
    scenario: ScenarioDefinition,
) -> Mapping[str, Any]:
    """Resolve every primary/alternate contract that Auto may select later."""

    steps = []
    for step in scenario.steps:
        options = []
        for behavior_id in (step.behavior_id, *step.alternates):
            behavior = registry.get_behavior(behavior_id)
            behavior_document = behavior.to_dict()
            resolved_parameters = {
                spec.name: spec.default for spec in behavior.parameters if spec.default is not None
            }
            resolved_parameters.update(step.parameters)
            actions = []
            for action_id in behavior.action_ids:
                action_document = registry.get_action(action_id).to_dict()
                actions.append(
                    {
                        "action_id": action_id,
                        "contract_digest": content_hash(action_document),
                        "contract": action_document,
                    }
                )
            options.append(
                {
                    "behavior_id": behavior_id,
                    "is_primary": behavior_id == step.behavior_id,
                    "contract_digest": content_hash(behavior_document),
                    "contract": behavior_document,
                    "resolved_parameters": resolved_parameters,
                    "actions": actions,
                }
            )
        steps.append({"step_id": step.id, "options": options})
    body = {
        "schema_version": "bluefire.approval-envelope.v1",
        "scenario_id": scenario.id,
        "steps": steps,
    }
    return {**body, "envelope_digest": content_hash(body)}


def validate_claimed_approval(
    approval: Mapping[str, Any] | None,
    *,
    binding: Mapping[str, str],
    approved_by: str | None,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Validate a one-time approval capability without trusting caller assertions."""

    if approval is None:
        raise ApprovalError("Execute requires a consumed, plan-bound approval")
    required = {
        "approval_id",
        "state_digest",
        "plan_digest",
        "profile_id",
        "target_scope_digest",
        "maximum_tier",
        "status",
        "approved_at",
        "approved_by",
        "nonce",
        "consumed_at",
        "expires_at",
    }
    missing = sorted(required - set(approval))
    if missing:
        raise ApprovalError("approval record is incomplete: " + ", ".join(missing))
    if approval.get("status") != "claimed":
        raise ApprovalError("Execute approval has not been atomically claimed")
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise ApprovalError("Execute approval identity is missing")
    if approval.get("approved_by") != approved_by.strip():
        raise ApprovalError("Execute approval identity does not match the operator")
    if not isinstance(approval.get("approval_id"), str) or not str(
        approval["approval_id"]
    ).startswith("approval-"):
        raise ApprovalError("Execute approval identifier is invalid")
    if not isinstance(approval.get("nonce"), str) or not str(approval["nonce"]).strip():
        raise ApprovalError("Execute approval capability nonce is missing")
    for field in (
        "state_digest",
        "plan_digest",
        "profile_id",
        "target_scope_digest",
        "maximum_tier",
    ):
        if approval.get(field) != binding[field]:
            raise ApprovalError(f"Execute approval is not bound to the current {field}")

    approved_at = _timestamp(approval.get("approved_at"), "approved_at")
    consumed_at = _timestamp(approval.get("consumed_at"), "consumed_at")
    expires_at = _timestamp(approval.get("expires_at"), "expires_at")
    current = now or datetime.now(timezone.utc)
    if approved_at > consumed_at or consumed_at > current or expires_at <= current:
        raise ApprovalError("Execute approval is expired or has invalid timestamps")
    return dict(approval)


def public_approval_record(approval: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """Remove the consumed capability nonce before persisting or returning a run."""

    if approval is None:
        return None
    return {key: value for key, value in approval.items() if key != "nonce"}


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ApprovalError(f"Execute approval {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"Execute approval {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ApprovalError(f"Execute approval {field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "ApprovalError",
    "ApprovalStore",
    "execution_approval_binding",
    "execution_approval_envelope",
    "public_approval_record",
    "validate_claimed_approval",
]
