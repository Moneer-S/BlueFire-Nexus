"""Registered runtime proposal policy; effects remain owned by the orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from .ai import AIProposalRequest, AIProvider, AIProviderError, ProposalType
from .ai_wire import AIProviderCancelled
from .config import AutonomyLevel, RunnerProfile
from .contracts import ExecutionMode, ScenarioDefinition, StepOutcome
from .planner import DeterministicPlanner, ExecutionPlan, PlannerDecision, PlannerError, PlanStep
from .registry import BehaviorRegistry, RegistryError
from .util import content_hash


class RuntimeProposalError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeProposals:
    registry: BehaviorRegistry
    planner: DeterministicPlanner
    proposal_provider: AIProvider | None
    _runner_opcode: Callable[[PlanStep], str | None]
    _plan_step: Callable[[ExecutionPlan, str], PlanStep]

    def propose(
        self,
        *,
        run_id: str,
        scenario: ScenarioDefinition,
        plan: ExecutionPlan,
        profile: RunnerProfile | None,
        mode: ExecutionMode,
        current_step_id: str,
        current_plan_step: PlanStep,
        outcome: StepOutcome,
        state: Mapping[str, Any],
        planner_decision: PlannerDecision,
        retries_used: int,
        remaining_steps: int,
    ) -> tuple[dict[str, Any] | None, PlanStep | None, str | None, bool]:
        if plan.autonomy is AutonomyLevel.OFF or self.proposal_provider is None:
            return None, None, None, False

        registered_edges = tuple(
            edge.to_dict()
            for edge in scenario.edges
            if edge.from_step == current_step_id and edge.outcome is outcome
        )
        next_step = scenario.step(str(registered_edges[0]["to_step"])) if registered_edges else None
        if next_step is not None and planner_decision.selected_step_id != next_step.id:
            raise RuntimeProposalError("deterministic next-node decision is inconsistent")
        retryable = bool(
            outcome in {StepOutcome.PARTIAL, StepOutcome.BLOCKED, StepOutcome.FAILED}
            and retries_used < 1
            and remaining_steps > 0
            and self._runner_opcode(current_plan_step) != "sandbox.cleanup.v1"
        )
        allowed_step_ids = tuple(
            dict.fromkeys(
                (
                    *((next_step.id,) if next_step is not None else ()),
                    *((current_step_id,) if retryable else ()),
                )
            )
        )
        behavior_ids: list[str] = []
        for step in (next_step, scenario.step(current_step_id) if retryable else None):
            if step is None:
                continue
            behavior_ids.extend((step.behavior_id, *step.alternates))
        if retryable and current_plan_step.behavior_id not in behavior_ids:
            behavior_ids.append(current_plan_step.behavior_id)
        allowed_behavior_ids = tuple(dict.fromkeys(behavior_ids))
        allowed_action_ids: tuple[str, ...] = ()
        if mode is ExecutionMode.EXECUTE and profile is not None and next_step is not None:
            action_ids: list[str] = []
            for behavior_id in (next_step.behavior_id, *next_step.alternates):
                behavior = self.registry.get_behavior(behavior_id)
                action_ids.extend(
                    action_id
                    for action_id in behavior.action_ids
                    if action_id in profile.enabled_actions
                    and action_id not in profile.blocked_actions
                )
            allowed_action_ids = tuple(dict.fromkeys(action_ids))
        allowed_parameter_schemas = (
            {next_step.id: self._primitive_parameter_schemas(next_step.behavior_id)}
            if next_step is not None
            else {}
        )
        retryable_step_ids = (current_step_id,) if retryable else ()
        registered_options: list[dict[str, Any]] = []
        if next_step is not None:
            registered_options.append(
                {
                    "role": "next",
                    "step_id": next_step.id,
                    "behavior_ids": [next_step.behavior_id, *next_step.alternates],
                    "action_ids_by_behavior": {
                        behavior_id: [
                            action_id
                            for action_id in self.registry.get_behavior(behavior_id).action_ids
                            if action_id in allowed_action_ids
                        ]
                        for behavior_id in (next_step.behavior_id, *next_step.alternates)
                    },
                    "parameter_schemas": allowed_parameter_schemas.get(next_step.id, {}),
                    "edge": dict(registered_edges[0]),
                }
            )
        if retryable:
            registered_options.append(
                {
                    "role": "retry",
                    "step_id": current_step_id,
                    "behavior_ids": [current_plan_step.behavior_id],
                    "action_ids_by_behavior": {},
                    "parameter_schemas": {},
                    "edge": None,
                }
            )
        proposal_policy = {
            "schema_version": "bluefire.ai-proposal-policy.v1",
            "mode": mode.value,
            "autonomy": plan.autonomy.value,
            "observed_outcome": outcome.value,
            "registered_options": registered_options,
            "maximum_adaptive_retries": 1,
            "adaptive_retries_used": retries_used,
            "remaining_steps": remaining_steps,
            "execute_mutations_require_fresh_approval": True,
            "runner_profile_id": profile.id if profile is not None else None,
        }
        planner_state = {
            "schema_version": "bluefire.planner-state.v1",
            "source_state_digest": planner_decision.current_state_digest,
            "mode": mode.value,
            "current_step_id": current_step_id,
            "outcome": outcome.value,
            "completed_steps": [
                {
                    "step_id": row.get("step_id"),
                    "behavior_id": row.get("behavior_id"),
                    "status": row.get("status"),
                }
                for row in state.get("steps", [])
                if isinstance(row, Mapping)
            ],
            "deterministic_decision": {
                "decision_id": planner_decision.decision_id,
                "selected_step_id": planner_decision.selected_step_id,
                "selected_behavior_id": planner_decision.selected_behavior_id,
                "execution_disposition": planner_decision.execution_disposition.value,
            },
            "registered_options": registered_options,
            "remaining_budgets": {
                "steps": remaining_steps,
                "retries": max(1 - retries_used, 0),
            },
        }
        planner_state_digest = content_hash(planner_state)
        request = AIProposalRequest(
            objective=plan.objective,
            current_state_digest=planner_decision.current_state_digest,
            autonomy=plan.autonomy,
            allowed_step_ids=allowed_step_ids,
            allowed_behavior_ids=allowed_behavior_ids,
            allowed_action_ids=allowed_action_ids,
            allowed_edges=registered_edges,
            allowed_parameter_schemas=allowed_parameter_schemas,
            retryable_step_ids=retryable_step_ids,
            context=planner_state,
        )
        base_record: dict[str, Any] = {
            "schema_version": "bluefire.ai-proposal-record.v3",
            "run_id": run_id,
            "current_step_id": current_step_id,
            "outcome": outcome.value,
            "autonomy": plan.autonomy.value,
            "state_digest": planner_decision.current_state_digest,
            "plan_digest": content_hash(plan.to_dict()),
            "deterministic_decision_id": planner_decision.decision_id,
            "allowed_step_ids": list(allowed_step_ids),
            "allowed_behavior_ids": list(allowed_behavior_ids),
            "allowed_action_ids": list(allowed_action_ids),
            "allowed_edges": [dict(edge) for edge in registered_edges],
            "allowed_parameter_schemas": allowed_parameter_schemas,
            "retryable_step_ids": list(retryable_step_ids),
            "registered_options": registered_options,
            "planner_state": planner_state,
            "planner_state_digest": planner_state_digest,
            "proposal_policy": proposal_policy,
            "proposal_policy_digest": content_hash(proposal_policy),
        }
        try:
            result = self.proposal_provider.propose(request)
            if result.requested_provider_id != self.proposal_provider.config.id:
                raise AIProviderError("provider result identity does not match the runtime")
            configured_provider_id = plan.ai_provider.get("provider_id")
            if (
                isinstance(configured_provider_id, str)
                and result.requested_provider_id != configured_provider_id
            ):
                raise AIProviderError("provider result identity does not match the plan")
            request.validate_proposal(result.proposal)
        except AIProviderCancelled:
            # Unwind through run() receipt cleanup without recording or applying
            # a proposal and without advancing the deterministic graph.
            raise
        except AIProviderError as exc:
            return (
                {
                    **base_record,
                    "provider": self.proposal_provider.config.runtime_metadata(),
                    "proposal": None,
                    "application_status": "rejected_invalid",
                    "application_reason": str(exc),
                },
                None,
                None,
                False,
            )

        proposal = result.proposal
        record = {
            **base_record,
            "provider": result.metadata(),
            "proposal": proposal.to_dict(),
            "proposal_digest": content_hash(proposal.to_dict()),
            "application_status": "recorded",
            "application_reason": "Proposal was recorded without changing the graph.",
            "proposal_policy_evaluation": {
                "status": "pending",
                "policy_digest": content_hash(proposal_policy),
            },
        }
        if proposal.proposal_type in {ProposalType.STOP, ProposalType.REQUEST_APPROVAL}:
            record["application_status"] = "stopped_by_proposal"
            record["application_reason"] = (
                "The provider requested a stop or a new operator decision."
            )
            record["proposal_policy_evaluation"] = {
                "status": "not_applicable",
                "policy_digest": content_hash(proposal_policy),
            }
            return record, None, None, False
        if proposal.proposal_type not in {
            ProposalType.SELECT_REGISTERED,
            ProposalType.SELECT_NEXT_NODE,
            ProposalType.CHANGE_PARAMETERS,
            ProposalType.SELECT_REGISTERED_ACTION,
            ProposalType.RETRY_REGISTERED,
        }:
            record["application_status"] = "not_applied_non_selection"
            record["application_reason"] = "The proposal requested no registered runtime mutation."
            record["proposal_policy_evaluation"] = {
                "status": "not_applicable",
                "policy_digest": content_hash(proposal_policy),
            }
            return record, None, None, False

        alternate_step: PlanStep | None = None
        adaptive_next_step_id: str | None = None
        retry_applied = False
        application_status = "accepted_registered_default"
        mutation = False
        try:
            assert proposal.selected_step_id is not None
            assert proposal.selected_behavior_id is not None
            proposed_scenario_step = scenario.step(proposal.selected_step_id)
            registered_behaviors = (
                proposed_scenario_step.behavior_id,
                *proposed_scenario_step.alternates,
            )
            if proposal.selected_behavior_id not in registered_behaviors:
                raise AIProviderError(
                    "proposal selected a behavior not owned by the registered node"
                )
            base_step = self._plan_step(plan, proposal.selected_step_id)
            if proposal.proposal_type is ProposalType.SELECT_REGISTERED:
                if next_step is None or proposal.selected_step_id != next_step.id:
                    raise AIProviderError(
                        "behavior selection is limited to the observed registered successor"
                    )
                adaptive_next_step_id = next_step.id
                if proposal.selected_behavior_id != base_step.behavior_id:
                    alternate_step = self.planner.compile_registered_alternate(
                        next_step,
                        behavior_id=proposal.selected_behavior_id,
                        mode=mode,
                        profile=profile,
                    )
                    mutation = True
                    application_status = "applied_registered_alternate"
            elif proposal.proposal_type is ProposalType.SELECT_NEXT_NODE:
                if (
                    next_step is None
                    or proposal.selected_step_id != next_step.id
                    or proposal.selected_behavior_id != base_step.behavior_id
                    or proposal.selected_edge not in registered_edges
                ):
                    raise AIProviderError(
                        "next-node selection is not the exact observed registered edge"
                    )
                adaptive_next_step_id = next_step.id
                application_status = "accepted_registered_next_node"
            elif proposal.proposal_type is ProposalType.CHANGE_PARAMETERS:
                if (
                    next_step is None
                    or proposal.selected_step_id != next_step.id
                    or proposal.selected_behavior_id != base_step.behavior_id
                ):
                    raise AIProviderError(
                        "parameter changes are limited to the observed registered successor"
                    )
                parameters = {
                    **dict(base_step.parameters),
                    **dict(proposal.parameter_change_map),
                }
                self.registry.get_behavior(base_step.behavior_id).validate_parameters(
                    parameters,
                    f"AI proposal parameters for {base_step.step_id}",
                )
                alternate_step = replace(base_step, parameters=parameters)
                adaptive_next_step_id = next_step.id
                mutation = parameters != dict(base_step.parameters)
                application_status = "applied_typed_parameters"
            elif proposal.proposal_type is ProposalType.SELECT_REGISTERED_ACTION:
                if (
                    mode is not ExecutionMode.EXECUTE
                    or profile is None
                    or next_step is None
                    or proposal.selected_step_id != next_step.id
                    or proposal.selected_behavior_id != base_step.behavior_id
                ):
                    raise AIProviderError(
                        "action selection requires the exact Execute successor and profile"
                    )
                action_id = proposal.selected_action_id
                behavior = self.registry.get_behavior(base_step.behavior_id)
                if (
                    action_id is None
                    or action_id not in behavior.action_ids
                    or action_id not in profile.enabled_actions
                    or action_id in profile.blocked_actions
                ):
                    raise AIProviderError(
                        "action is not owned by the behavior and enabled by the exact profile"
                    )
                self.registry.get_action(action_id)
                alternate_step = replace(base_step, action_id=action_id)
                adaptive_next_step_id = next_step.id
                mutation = action_id != base_step.action_id
                application_status = "applied_registered_action"
            else:
                if (
                    not retryable
                    or proposal.selected_step_id != current_step_id
                    or proposal.selected_behavior_id != current_plan_step.behavior_id
                ):
                    raise AIProviderError("retry selected a node outside the bounded retry policy")
                alternate_step = current_plan_step
                adaptive_next_step_id = current_step_id
                mutation = True
                retry_applied = True
                application_status = "applied_registered_retry"
        except (AIProviderError, KeyError, PlannerError, RegistryError, ValueError) as exc:
            record["application_status"] = "rejected_policy"
            record["application_reason"] = str(exc)
            record["proposal_policy_evaluation"] = {
                "status": "refused",
                "policy_digest": content_hash(proposal_policy),
                "reason": str(exc),
            }
            return record, None, None, False

        record["proposal_policy_evaluation"] = {
            "status": "permitted",
            "policy_digest": content_hash(proposal_policy),
            "mutation": mutation,
            "execute_requires_fresh_approval": mode is ExecutionMode.EXECUTE and mutation,
        }
        requires_gate = bool(
            (
                mutation
                and (
                    proposal.requires_operator_review
                    or plan.autonomy is AutonomyLevel.ASSIST
                    or mode is ExecutionMode.EXECUTE
                )
            )
            or (
                not mutation
                and proposal.requires_operator_review
                and plan.autonomy is AutonomyLevel.AUTO
            )
        )
        if requires_gate:
            record["application_status"] = "awaiting_operator_approval"
            record["application_reason"] = (
                "The registered proposal is paused for an operator decision. Acceptance "
                "will reconstruct it deterministically; Execute will require a fresh exact "
                "approval and a fresh-workspace replay from scenario start."
            )
            record["registered_step"] = (
                alternate_step.to_dict() if alternate_step is not None else base_step.to_dict()
            )
            return record, None, None, False
        if not mutation:
            record["application_status"] = (
                "recorded_for_review"
                if plan.autonomy is AutonomyLevel.ASSIST
                else application_status
            )
            record["application_reason"] = (
                "Assist recorded a default-preserving proposal without pausing."
                if plan.autonomy is AutonomyLevel.ASSIST
                else "The proposal preserved the deterministic registered plan."
            )
            return record, None, adaptive_next_step_id, False
        if mode is not ExecutionMode.SIMULATE or plan.autonomy is not AutonomyLevel.AUTO:
            record["application_status"] = "recorded_for_review"
            record["application_reason"] = "The mutation was recorded but not applied."
            return record, None, None, False
        record["application_status"] = application_status
        record["application_reason"] = (
            "Auto applied the policy-permitted registered Simulate mutation."
        )
        record["applied_step"] = (
            alternate_step.to_dict() if alternate_step is not None else base_step.to_dict()
        )
        record["applied_next_step_id"] = adaptive_next_step_id
        return record, alternate_step, adaptive_next_step_id, retry_applied

    def _primitive_parameter_schemas(
        self,
        behavior_id: str,
    ) -> dict[str, dict[str, Any]]:
        schemas: dict[str, dict[str, Any]] = {}
        for spec in self.registry.get_behavior(behavior_id).parameters:
            parameter_type = spec.type.value
            if parameter_type not in {"string", "integer", "number", "boolean"}:
                continue
            if parameter_type == "string" and not spec.enum:
                continue
            schemas[spec.name] = {
                "type": parameter_type,
                "enum": list(spec.enum),
                "minimum": spec.minimum,
                "maximum": spec.maximum,
            }
        return schemas


def adaptive_retry_count(replay: Mapping[str, Any] | None) -> int:
    if replay is None:
        return 0
    value = replay.get("adaptive_retry_count", 0)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1:
        raise RuntimeProposalError("adaptive retry lineage exceeds the one-retry bound")
    return int(value)


def approved_replay_transition(
    *,
    replay: Mapping[str, Any] | None,
    scenario: ScenarioDefinition,
    current_step_id: str,
    outcome: StepOutcome,
    planner_decision: PlannerDecision,
) -> tuple[bool, str | None]:
    if replay is None:
        return False, None
    resolution = replay.get("proposal_resolution")
    if (
        not isinstance(resolution, Mapping)
        or resolution.get("apply_after_step_id") != current_step_id
    ):
        return False, None
    proposal_type = resolution.get("proposal_type")
    selected_step_id = resolution.get("selected_step_id")
    if resolution.get("schema_version") == "bluefire.ai-proposal-resolution-lineage.v4":
        if (
            resolution.get("method_replay_from_start") is not True
            or proposal_type != ProposalType.SELECT_REGISTERED_ACTION.value
            or selected_step_id != current_step_id
            or replay.get("adaptive_retry_count") != 1
            or scenario.step(current_step_id).behavior_id != resolution.get("selected_behavior_id")
            or replay.get("action_implementations_to", {}).get(current_step_id)
            != resolution.get("selected_action_id")
        ):
            raise RuntimeProposalError(
                "reviewed method replay lineage does not match its fresh plan"
            )
        # A new exact approval reviewed this method as the saved primary in
        # a full replay. Observe its new outcome; do not recreate the prior
        # failure or dispatch the method a second time.
        return True, planner_decision.selected_step_id
    if resolution.get("schema_version") != "bluefire.ai-proposal-resolution-lineage.v3":
        raise RuntimeProposalError("approved proposal lineage version is invalid")
    if resolution.get("observed_outcome") != outcome.value:
        raise RuntimeProposalError("approved proposal lineage is stale for the replayed outcome")
    if proposal_type == ProposalType.RETRY_REGISTERED.value:
        if outcome not in {
            StepOutcome.PARTIAL,
            StepOutcome.BLOCKED,
            StepOutcome.FAILED,
        }:
            raise RuntimeProposalError(
                "approved retry lineage is not eligible for the replayed outcome"
            )
        if selected_step_id != current_step_id:
            raise RuntimeProposalError("approved retry lineage selected a different node")
        return True, current_step_id
    if not isinstance(selected_step_id, str):
        raise RuntimeProposalError("approved proposal lineage has no selected node")
    if proposal_type == ProposalType.SELECT_NEXT_NODE.value:
        selected_edge = resolution.get("selected_edge")
        exact_edges = [
            edge.to_dict()
            for edge in scenario.edges
            if edge.from_step == current_step_id and edge.outcome is outcome
        ]
        if (
            not isinstance(selected_edge, Mapping)
            or dict(selected_edge) not in exact_edges
            or selected_edge.get("to_step") != selected_step_id
        ):
            raise RuntimeProposalError(
                "approved next-node lineage is stale for the observed outcome"
            )
        return True, selected_step_id
    if planner_decision.selected_step_id != selected_step_id:
        raise RuntimeProposalError("approved proposal target is stale for the replayed outcome")
    return True, selected_step_id
