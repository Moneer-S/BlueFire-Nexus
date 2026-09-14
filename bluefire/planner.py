"""Deterministic planning and validation of optional AI proposals."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from .config import AutonomyLevel, RunnerProfile
from .contracts import (
    ExecutionMode,
    ExecutionState,
    SafetyTier,
    ScenarioDefinition,
    ScenarioStep,
    StepOutcome,
)
from .execution_contracts import ExecutionContractError, reject_forbidden_execution_keys
from .registry import BehaviorRegistry
from .util import content_hash


class PlannerError(ValueError):
    pass


def _resolve_autonomy(
    autonomy: AutonomyLevel | str | None,
    ai_enabled: bool | None,
) -> AutonomyLevel:
    if ai_enabled is not None and not isinstance(ai_enabled, bool):
        raise PlannerError("legacy ai_enabled must be a boolean")
    if autonomy is None:
        return AutonomyLevel.ASSIST if ai_enabled else AutonomyLevel.OFF
    try:
        resolved = autonomy if isinstance(autonomy, AutonomyLevel) else AutonomyLevel(autonomy)
    except ValueError as exc:
        raise PlannerError("autonomy must be off, assist, or auto") from exc
    if ai_enabled is not None and ai_enabled != (resolved is not AutonomyLevel.OFF):
        raise PlannerError("autonomy conflicts with legacy ai_enabled")
    return resolved


class ExecutionDisposition(str, Enum):
    SIMULATE = "simulate"
    EXECUTE = "execute"
    REQUEST_APPROVAL = "request_approval"
    COUNTERFACTUAL = "counterfactual"
    STOP = "stop"


@dataclass(frozen=True, slots=True)
class PlanStep:
    step_id: str
    behavior_id: str
    action_id: str | None
    simulation_id: str | None
    parameters: Mapping[str, Any]
    inputs: Mapping[str, Mapping[str, str]]
    expected_outputs: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    safety_tier: SafetyTier
    alternates: tuple[str, ...]
    execution_binding: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        document = {
            "step_id": self.step_id,
            "behavior_id": self.behavior_id,
            "action_id": self.action_id,
            "simulation_id": self.simulation_id,
            "parameters": dict(self.parameters),
            "inputs": {name: dict(binding) for name, binding in self.inputs.items()},
            "expected_outputs": list(self.expected_outputs),
            "required_capabilities": list(self.required_capabilities),
            "safety_tier": self.safety_tier.value,
            "alternates": list(self.alternates),
        }
        if self.execution_binding is not None:
            document["execution_binding"] = dict(self.execution_binding)
        return document


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    schema_version: str
    scenario_id: str
    objective: str
    mode: ExecutionMode
    autonomy: AutonomyLevel
    ai_provider: Mapping[str, Any]
    runner_profile_id: str | None
    scenario_digest: str
    steps: tuple[PlanStep, ...]
    edges: tuple[Mapping[str, str], ...]

    @property
    def ai_enabled(self) -> bool:
        return self.autonomy is not AutonomyLevel.OFF

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "objective": self.objective,
            "mode": self.mode.value,
            "ai_enabled": self.ai_enabled,
            "autonomy": self.autonomy.value,
            "ai_provider": dict(self.ai_provider),
            "runner_profile_id": self.runner_profile_id,
            "scenario_digest": self.scenario_digest,
            "steps": [step.to_dict() for step in self.steps],
            "edges": [dict(edge) for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class PlannerDecision:
    schema_version: str
    decision_id: str
    run_id: str
    objective: str
    current_state_digest: str
    selected_behavior_id: str | None
    selected_action_id: str | None
    selected_step_id: str | None
    selected_edge: Mapping[str, str] | None
    execution_disposition: ExecutionDisposition
    prerequisites_considered: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    reason: str
    alternatives_considered: tuple[str, ...]
    policy_evaluation: Mapping[str, Any]
    confidence: float
    approvals_required: tuple[str, ...]
    remaining_budgets: Mapping[str, int]
    proposed_by: str

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise PlannerError("planner confidence must be between zero and one")
        if self.selected_action_id and not self.selected_behavior_id:
            raise PlannerError("an action selection requires a behavior selection")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "run_id": self.run_id,
            "objective": self.objective,
            "current_state_digest": self.current_state_digest,
            "selected_behavior_id": self.selected_behavior_id,
            "selected_action_id": self.selected_action_id,
            "selected_step_id": self.selected_step_id,
            "selected_edge": dict(self.selected_edge) if self.selected_edge else None,
            "execution_disposition": self.execution_disposition.value,
            "prerequisites_considered": list(self.prerequisites_considered),
            "expected_outputs": list(self.expected_outputs),
            "reason": self.reason,
            "alternatives_considered": list(self.alternatives_considered),
            "policy_evaluation": dict(self.policy_evaluation),
            "confidence": self.confidence,
            "approvals_required": list(self.approvals_required),
            "remaining_budgets": dict(self.remaining_budgets),
            "proposed_by": self.proposed_by,
        }


class DeterministicPlanner:
    def __init__(
        self,
        registry: BehaviorRegistry,
        *,
        action_bindings: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
    ) -> None:
        self.registry = registry
        self.action_bindings = {
            (str(behavior_id), str(action_id)): dict(binding)
            for (behavior_id, action_id), binding in (action_bindings or {}).items()
        }
        unknown = sorted(
            (behavior_id, action_id)
            for behavior_id, action_id in self.action_bindings
            if behavior_id not in registry.behavior_ids or action_id not in registry.action_ids
        )
        if unknown:
            raise PlannerError(
                "execution bindings reference unregistered behavior/action pairs: "
                + ", ".join(f"{behavior}/{action}" for behavior, action in unknown)
            )

    def compile(
        self,
        scenario: ScenarioDefinition,
        *,
        mode: ExecutionMode = ExecutionMode.SIMULATE,
        profile: RunnerProfile | None = None,
        autonomy: AutonomyLevel | str | None = None,
        ai_provider: Mapping[str, Any] | None = None,
        ai_enabled: bool | None = None,
        action_implementations: Mapping[str, str] | None = None,
    ) -> ExecutionPlan:
        resolved_autonomy = _resolve_autonomy(autonomy, ai_enabled)
        self.registry.validate_scenario(scenario)
        if mode is ExecutionMode.EXECUTE and profile is None:
            raise PlannerError("Execute requires an explicit runner profile")
        if profile is not None and profile.mode is not mode:
            raise PlannerError("runner profile mode does not match the requested mode")
        selections = dict(action_implementations or {})
        if mode is ExecutionMode.SIMULATE and selections:
            raise PlannerError("Simulate does not accept action implementation selections")
        unknown_steps = sorted(set(selections) - {step.id for step in scenario.steps})
        if unknown_steps:
            raise PlannerError("unknown action implementation step: " + ", ".join(unknown_steps))
        steps = [
            self._compile_step(
                scenario_step,
                behavior_id=scenario_step.behavior_id,
                mode=mode,
                profile=profile,
                action_id=selections.get(scenario_step.id),
            )
            for scenario_step in scenario.steps
        ]
        scenario_snapshot = scenario.to_dict()
        return ExecutionPlan(
            schema_version="bluefire.plan.v1",
            scenario_id=scenario.id,
            objective=scenario.purpose,
            mode=mode,
            autonomy=resolved_autonomy,
            ai_provider=dict(ai_provider or {}),
            runner_profile_id=profile.id if profile else None,
            scenario_digest=content_hash(scenario_snapshot),
            steps=tuple(steps),
            edges=tuple(edge.to_dict() for edge in scenario.edges),
        )

    def compile_registered_alternate(
        self,
        scenario_step: ScenarioStep,
        *,
        behavior_id: str,
        mode: ExecutionMode,
        profile: RunnerProfile | None,
    ) -> PlanStep:
        """Compile one graph-registered alternate through normal action selection."""

        if behavior_id not in scenario_step.alternates:
            raise PlannerError("AI behavior selection is not a registered alternate")
        baseline = self.registry.get_behavior(scenario_step.behavior_id)
        alternate = self.registry.get_behavior(behavior_id)
        if alternate.io_signature() != baseline.io_signature():
            raise PlannerError("AI behavior selection is not contract-compatible")
        alternate.validate_parameters(
            scenario_step.parameters,
            f"step {scenario_step.id} alternate {behavior_id}.parameters",
        )
        return self._compile_step(
            scenario_step,
            behavior_id=behavior_id,
            mode=mode,
            profile=profile,
        )

    def decide_next(
        self,
        *,
        run_id: str,
        scenario: ScenarioDefinition,
        plan: ExecutionPlan,
        current_step_id: str,
        outcome: StepOutcome,
        state: Mapping[str, Any],
        completed_steps: int,
        retries_used: int = 0,
        allow_counterfactual: bool = True,
    ) -> PlannerDecision:
        matching_edges = [
            edge
            for edge in scenario.edges
            if edge.from_step == current_step_id and edge.outcome is outcome
        ]
        disposition = ExecutionDisposition.STOP
        selected_step: ScenarioStep | None = None
        selected_edge: Mapping[str, str] | None = None
        reason = f"No {outcome.value} branch is registered; stop."
        if matching_edges:
            edge = matching_edges[0]
            selected_step = scenario.step(edge.to_step)
            selected_edge = edge.to_dict()
            disposition = (
                ExecutionDisposition.EXECUTE
                if plan.mode is ExecutionMode.EXECUTE
                else ExecutionDisposition.SIMULATE
            )
            reason = f"Follow the registered {outcome.value} branch."
        elif outcome in {StepOutcome.BLOCKED, StepOutcome.FAILED} and allow_counterfactual:
            success_edges = [
                edge
                for edge in scenario.edges
                if edge.from_step == current_step_id and edge.outcome is StepOutcome.SUCCESS
            ]
            if success_edges:
                edge = success_edges[0]
                selected_step = scenario.step(edge.to_step)
                selected_edge = edge.to_dict()
                disposition = ExecutionDisposition.COUNTERFACTUAL
                reason = "No real alternate is registered; continue with labeled counterfactual evidence."

        behavior = self.registry.get_behavior(selected_step.behavior_id) if selected_step else None
        plan_step = (
            next((item for item in plan.steps if item.step_id == selected_step.id), None)
            if selected_step
            else None
        )
        decision_body = {
            "run_id": run_id,
            "current_step_id": current_step_id,
            "outcome": outcome.value,
            "state_digest": content_hash(state),
            "selected_step_id": selected_step.id if selected_step else None,
            "disposition": disposition.value,
        }
        return PlannerDecision(
            schema_version="bluefire.planner-decision.v1",
            decision_id="decision-" + content_hash(decision_body).removeprefix("sha256:")[:20],
            run_id=run_id,
            objective=plan.objective,
            current_state_digest=content_hash(state),
            selected_behavior_id=behavior.id if behavior else None,
            selected_action_id=plan_step.action_id if plan_step else None,
            selected_step_id=selected_step.id if selected_step else None,
            selected_edge=selected_edge,
            execution_disposition=disposition,
            prerequisites_considered=("typed_inputs", "registered_edge", "remaining_budget"),
            expected_outputs=plan_step.expected_outputs if plan_step else (),
            reason=reason,
            alternatives_considered=selected_step.alternates if selected_step else (),
            policy_evaluation={"status": "pending" if selected_step else "not_applicable"},
            confidence=1.0,
            approvals_required=(),
            remaining_budgets={
                "steps": max(len(plan.steps) - completed_steps, 0),
                "retries": max(1 - retries_used, 0),
            },
            proposed_by="deterministic-planner.v1",
        )

    @staticmethod
    def _select_action(action_ids: Iterable[str], profile: RunnerProfile | None) -> str:
        if profile is None:
            raise PlannerError("Execute requires a runner profile")
        for action_id in action_ids:
            if action_id in profile.enabled_actions:
                return action_id
        raise PlannerError("no behavior action is enabled by the selected runner profile")

    def _compile_step(
        self,
        scenario_step: ScenarioStep,
        *,
        behavior_id: str,
        mode: ExecutionMode,
        profile: RunnerProfile | None,
        action_id: str | None = None,
    ) -> PlanStep:
        behavior = self.registry.get_behavior(behavior_id)
        selected_action_id: str | None = None
        if mode is ExecutionMode.EXECUTE:
            if behavior.execution_state is not ExecutionState.ACTION:
                raise PlannerError(f"behavior {behavior.id} is not available for Execute")
            if action_id is not None:
                if action_id not in behavior.action_ids:
                    raise PlannerError(
                        f"action {action_id} is not registered to behavior {behavior.id}"
                    )
                self.registry.get_action(action_id)
                if profile is None or action_id not in profile.enabled_actions:
                    raise PlannerError(
                        f"action {action_id} is disabled by the selected runner profile"
                    )
                selected_action_id = action_id
            else:
                selected_action_id = self._select_action(behavior.action_ids, profile)
        elif behavior.simulation_id is None:
            raise PlannerError(f"behavior {behavior.id} has no simulation adapter")
        return PlanStep(
            step_id=scenario_step.id,
            behavior_id=behavior.id,
            action_id=selected_action_id,
            simulation_id=behavior.simulation_id,
            parameters=self._parameters_with_defaults(scenario_step, behavior.parameters),
            inputs={name: binding.to_dict() for name, binding in scenario_step.inputs.items()},
            expected_outputs=tuple(spec.name for spec in behavior.outputs),
            required_capabilities=behavior.capabilities,
            safety_tier=behavior.safety_tier,
            alternates=scenario_step.alternates,
            execution_binding=(
                dict(self.action_bindings[(behavior.id, selected_action_id)])
                if selected_action_id is not None
                and (behavior.id, selected_action_id) in self.action_bindings
                else None
            ),
        )

    @staticmethod
    def _parameters_with_defaults(step: ScenarioStep, specs: Iterable[Any]) -> dict[str, Any]:
        result = {spec.name: spec.default for spec in specs if spec.default is not None}
        result.update(step.parameters)
        return result


class AIProposalValidator:
    """Treat an AI decision as untrusted data and validate it against state."""

    _FIELDS = frozenset(
        {
            "schema_version",
            "decision_id",
            "run_id",
            "objective",
            "current_state_digest",
            "selected_behavior_id",
            "selected_action_id",
            "selected_step_id",
            "selected_edge",
            "execution_disposition",
            "prerequisites_considered",
            "expected_outputs",
            "reason",
            "alternatives_considered",
            "policy_evaluation",
            "confidence",
            "approvals_required",
            "remaining_budgets",
        }
    )

    def __init__(self, registry: BehaviorRegistry) -> None:
        self.registry = registry

    def validate(
        self,
        payload: Mapping[str, Any],
        *,
        scenario: ScenarioDefinition,
        plan: ExecutionPlan,
        profile: RunnerProfile | None,
        expected_run_id: str,
        expected_state_digest: str,
    ) -> PlannerDecision:
        try:
            reject_forbidden_execution_keys(payload)
        except ExecutionContractError as exc:
            raise PlannerError("AI decision contains forbidden executable fields") from exc
        unknown = set(payload) - self._FIELDS
        missing = self._FIELDS - set(payload)
        if unknown or missing:
            raise PlannerError(
                f"AI decision fields mismatch; unknown={sorted(unknown)}, missing={sorted(missing)}"
            )
        if payload["schema_version"] != "bluefire.planner-decision.v1":
            raise PlannerError("AI decision schema version is unsupported")
        if payload["run_id"] != expected_run_id:
            raise PlannerError("AI decision run_id does not match current run")
        if payload["current_state_digest"] != expected_state_digest:
            raise PlannerError("AI decision was made from stale state")
        behavior_id = payload["selected_behavior_id"]
        action_id = payload["selected_action_id"]
        step_id = payload["selected_step_id"]
        if step_id is not None:
            step = scenario.step(str(step_id))
            if behavior_id not in (step.behavior_id, *step.alternates):
                raise PlannerError("AI selected a behavior not registered for this graph node")
        behavior = self.registry.get_behavior(str(behavior_id)) if behavior_id else None
        if action_id is not None:
            if behavior is None or action_id not in behavior.action_ids:
                raise PlannerError("AI selected an action not registered to the behavior")
            self.registry.get_action(str(action_id))
            if profile is None or action_id not in profile.enabled_actions:
                raise PlannerError("AI selected an action disabled by the runner profile")
        selected_edge = payload["selected_edge"]
        if selected_edge is not None:
            if selected_edge not in [edge.to_dict() for edge in scenario.edges]:
                raise PlannerError("AI selected an edge not present in the scenario graph")
        try:
            disposition = ExecutionDisposition(payload["execution_disposition"])
        except ValueError as exc:
            raise PlannerError("AI selected an invalid execution disposition") from exc
        confidence = payload["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise PlannerError("AI confidence must be numeric")
        decision = PlannerDecision(
            schema_version="bluefire.planner-decision.v1",
            decision_id=str(payload["decision_id"]),
            run_id=str(payload["run_id"]),
            objective=str(payload["objective"]),
            current_state_digest=str(payload["current_state_digest"]),
            selected_behavior_id=str(behavior_id) if behavior_id else None,
            selected_action_id=str(action_id) if action_id else None,
            selected_step_id=str(step_id) if step_id else None,
            selected_edge=dict(selected_edge) if selected_edge else None,
            execution_disposition=disposition,
            prerequisites_considered=tuple(map(str, payload["prerequisites_considered"])),
            expected_outputs=tuple(map(str, payload["expected_outputs"])),
            reason=str(payload["reason"]),
            alternatives_considered=tuple(map(str, payload["alternatives_considered"])),
            policy_evaluation=dict(payload["policy_evaluation"]),
            confidence=float(confidence),
            approvals_required=tuple(map(str, payload["approvals_required"])),
            remaining_budgets={
                str(key): int(value) for key, value in payload["remaining_budgets"].items()
            },
            proposed_by="ai-planner",
        )
        plan_step = next(
            (item for item in plan.steps if item.step_id == decision.selected_step_id), None
        )
        if plan_step and decision.expected_outputs != plan_step.expected_outputs:
            raise PlannerError("AI expected outputs do not match the registered behavior contract")
        return decision


__all__ = [
    "AIProposalValidator",
    "DeterministicPlanner",
    "ExecutionDisposition",
    "ExecutionPlan",
    "PlanStep",
    "PlannerDecision",
    "PlannerError",
]
