"""Runtime selection among exact reviewed methods, separate from effects and authority."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .adaptive_observations import project_runtime_observations
from .adaptive_record_validation import validate_v4_attempt_record
from .ai import AIProposalRequest, AIProviderCancelled, AIProviderError, ProposalType
from .config import AIProviderKind, AutonomyLevel
from .contracts import SafetyTier
from .evidence import EvidenceRecord
from .planner import ExecutionPlan, PlannerDecision, PlanStep
from .util import content_hash


@dataclass(frozen=True)
class AdaptiveRuntimeDecision:
    record: dict[str, Any]
    selected_step: PlanStep | None = None
    stop: bool = False

    def __post_init__(self) -> None:
        validate_v4_attempt_record(self.record)


def reviewed_plan_step(document: Mapping[str, Any]) -> PlanStep:
    """Rehydrate only a compiler-validated exact plan step, not model output."""
    return PlanStep(
        step_id=document["step_id"],
        behavior_id=document["behavior_id"],
        action_id=document["action_id"],
        simulation_id=document["simulation_id"],
        parameters=document["parameters"],
        inputs=document["inputs"],
        expected_outputs=tuple(document["expected_outputs"]),
        required_capabilities=tuple(document["required_capabilities"]),
        safety_tier=SafetyTier(document["safety_tier"]),
        alternates=tuple(document["alternates"]),
        execution_binding=document.get("execution_binding"),
    )


def reviewed_methods(authorization: Mapping[str, Any], step_id: str) -> tuple[PlanStep, ...]:
    return tuple(
        reviewed_plan_step(method["plan_step"])
        for group in authorization["steps"]
        if group["step_id"] == step_id
        for method in group["methods"]
    )


def propose_reviewed_method(
    *,
    run_id: str,
    plan: ExecutionPlan,
    current_step: PlanStep,
    outcome: str,
    decision: PlannerDecision,
    authorization: Mapping[str, Any],
    policy: Mapping[str, Any],
    provider: Any,
    steps: Sequence[Mapping[str, Any]],
    evidence: Sequence[EvidenceRecord],
    artifacts: Mapping[str, Any],
    platform: str,
    remaining_steps: int,
    remaining_seconds: float,
    retries_used: int,
    validate_choice: Callable[[PlanStep], Any],
    check_cancelled: Callable[[], None],
) -> AdaptiveRuntimeDecision:
    """Make one bounded proposal. This function never grants authority or dispatches.

    The caller checks policy eligibility and independently revalidates the complete
    selected operation immediately before its eventual effects. The callback here
    also checks expiry after provider latency, before recording an applicable choice.
    """
    deadline = time.monotonic() + remaining_seconds if remaining_seconds > 0 else None
    methods = reviewed_methods(authorization, current_step.step_id)
    projection = project_runtime_observations(
        steps=steps,
        records=evidence,
        alternatives=methods,
        artifacts=artifacts,
        platform=platform,
        remaining_steps=remaining_steps,
        remaining_seconds=remaining_seconds,
        retries_remaining=max(1 - retries_used, 0),
    )
    attempted = {
        (row.get("behavior_id"), row.get("action_id"))
        for row in steps
        if row.get("step_id") == current_step.step_id
    }
    compatible = {
        (item["behavior_id"], item["action_id"])
        for item in projection["available_methods"]
        if item["input_compatible"]
    }
    choices = tuple(
        step
        for step in methods
        if (step.behavior_id, step.action_id) in compatible
        and (step.behavior_id, step.action_id) not in attempted
    )
    options = [
        {
            "role": "retry",
            "step_id": step.step_id,
            "behavior_id": step.behavior_id,
            "action_id": step.action_id,
            "plan_step": step.to_dict(),
            "plan_step_digest": content_hash(step.to_dict()),
        }
        for step in choices
    ]
    proposal_policy = {
        "schema_version": "bluefire.ai-proposal-policy.v2",
        "mode": "execute",
        "autonomy": plan.autonomy.value,
        "observed_outcome": outcome,
        "authorization_digest": authorization["authorization_digest"],
        "registered_options": options,
        "maximum_adaptive_retries": 1,
        "adaptive_retries_used": retries_used,
        "remaining_steps": remaining_steps,
        "on_provider_failure": policy["on_provider_failure"],
    }
    planner_state = {
        "schema_version": "bluefire.planner-state.v2",
        "source_state_digest": decision.current_state_digest,
        "current_step_id": current_step.step_id,
        "outcome": outcome,
        "authorization_digest": authorization["authorization_digest"],
        "registered_options": options,
        "observations": projection,
        "deterministic_decision": decision.to_dict(),
    }
    request = AIProposalRequest(
        objective=plan.objective,
        current_state_digest=decision.current_state_digest,
        autonomy=plan.autonomy,
        allowed_step_ids=(current_step.step_id,) if choices else (),
        allowed_behavior_ids=tuple(dict.fromkeys(step.behavior_id for step in choices)),
        allowed_action_ids=tuple(dict.fromkeys(str(step.action_id) for step in choices)),
        retryable_step_ids=(current_step.step_id,) if choices else (),
        context=planner_state,
        deadline_monotonic=deadline,
    )
    record: dict[str, Any] = {
        "schema_version": "bluefire.ai-proposal-record.v4",
        "run_id": run_id,
        "current_step_id": current_step.step_id,
        "outcome": outcome,
        "autonomy": plan.autonomy.value,
        "state_digest": decision.current_state_digest,
        "plan_digest": content_hash(plan.to_dict()),
        "deterministic_decision_id": decision.decision_id,
        "allowed_step_ids": list(request.allowed_step_ids),
        "allowed_behavior_ids": list(request.allowed_behavior_ids),
        "allowed_action_ids": list(request.allowed_action_ids),
        "allowed_edges": [],
        "allowed_parameter_schemas": {},
        "retryable_step_ids": list(request.retryable_step_ids),
        "registered_options": options,
        "planner_state": planner_state,
        "planner_state_digest": content_hash(planner_state),
        "proposal_policy": proposal_policy,
        "proposal_policy_digest": content_hash(proposal_policy),
        "authorization_digest": authorization["authorization_digest"],
        "proposal": None,
        "provider": None,
        "provider_attempt": {
            "provider_id": provider.config.id,
            "kind": provider.config.kind.value,
            "model": provider.config.model,
        },
        "provider_called": False,
        "decision_source": "none",
        "application_status": "stopped_no_permitted_choice",
        "application_reason": "No compatible untried reviewed method remains.",
        "stop_requested": True,
    }
    check_cancelled()
    if remaining_steps < 1 or remaining_seconds <= 0 or retries_used >= 1:
        record.update(
            application_status="stopped_budget_exhausted",
            application_reason="No execution budget remains for a reviewed method; no provider was called.",
        )
        return AdaptiveRuntimeDecision(record, stop=True)
    if not choices:
        return AdaptiveRuntimeDecision(record, stop=True)
    try:
        record["provider_called"] = True
        result = provider.propose(request)
        check_cancelled()
        if result.requested_provider_id != provider.config.id or (
            plan.ai_provider.get("provider_id") is not None
            and result.requested_provider_id != plan.ai_provider["provider_id"]
        ):
            raise AIProviderError("provider identity does not match reviewed configuration")
        proposal = result.proposal
        record.update(
            provider=result.metadata(),
            proposal=proposal.to_dict(),
            proposal_digest=content_hash(proposal.to_dict()),
            decision_source=(
                "configured_provider_fallback"
                if result.used_fallback
                else (
                    "deterministic_provider"
                    if provider.config.kind is AIProviderKind.DETERMINISTIC
                    else "provider"
                )
            ),
        )
        request.validate_proposal(proposal)
        if proposal.proposal_type in {ProposalType.STOP, ProposalType.REQUEST_APPROVAL}:
            record.update(
                application_status="stopped_by_proposal",
                application_reason="The provider requested a stop or new operator decision.",
            )
            return AdaptiveRuntimeDecision(record, stop=True)
        if proposal.proposal_type is not ProposalType.SELECT_REGISTERED_ACTION:
            raise AIProviderError("A useful adaptive choice must select one exact reviewed method.")
        selected = next(
            (
                step
                for step in choices
                if (step.step_id, step.behavior_id, step.action_id)
                == (
                    proposal.selected_step_id,
                    proposal.selected_behavior_id,
                    proposal.selected_action_id,
                )
            ),
            None,
        )
        if selected is None:
            raise AIProviderError("The proposed method is outside the compatible reviewed set.")
        validate_choice(selected)
        if plan.autonomy is AutonomyLevel.ASSIST or proposal.requires_operator_review:
            record.update(
                application_status="awaiting_operator_approval",
                application_reason="Review this method change before a newly approved replay.",
                registered_step=selected.to_dict(),
            )
            return AdaptiveRuntimeDecision(record, stop=True)
        if plan.autonomy is not AutonomyLevel.AUTO:
            raise AIProviderError("Only Auto may apply a reviewed runtime method choice.")
        record.update(
            application_status="applied_reviewed_method",
            application_reason="Auto selected an untried method inside the reviewed authorization.",
            applied_step=selected.to_dict(),
            applied_next_step_id=selected.step_id,
            stop_requested=False,
        )
        return AdaptiveRuntimeDecision(record, selected_step=selected)
    except AIProviderCancelled:
        raise
    except (AIProviderError, ValueError) as exc:
        # Failure text may contain provider-controlled output; preserve a stable
        # classification here, never echo the exception body into model context.
        record.update(
            application_status="rejected_policy",
            failure_class=type(exc).__name__,
            application_reason="The provider returned no permitted useful choice.",
        )
        if policy["on_provider_failure"] == "deterministic" and plan.autonomy is AutonomyLevel.AUTO:
            record.update(
                decision_source="configured_deterministic_fallback",
                stop_requested=False,
                application_status="configured_fallback",
                application_reason="Configured fallback continues the deterministic graph; no adaptive method was applied.",
            )
            return AdaptiveRuntimeDecision(record)
        return AdaptiveRuntimeDecision(record, stop=True)
