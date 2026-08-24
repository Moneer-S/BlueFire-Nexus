"""Deterministic graph orchestration across Simulate and Execute modes."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .ai import AIProposalRequest, AIProvider, AIProviderError, ProposalType
from .approvals import (
    ApprovalError,
    ApprovalStore,
    execution_approval_binding,
    public_approval_record,
    validate_claimed_approval,
)
from .config import AutonomyLevel, CleanupPolicy, RunnerProfile
from .contracts import ExecutionMode, ScenarioDefinition, StepOutcome
from .detections import DetectionCandidate, DetectionPipeline
from .evidence import (
    EvidenceError,
    EvidenceGraph,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)
from .planner import (
    DeterministicPlanner,
    ExecutionDisposition,
    ExecutionPlan,
    PlannerDecision,
    PlannerError,
    PlanStep,
)
from .policy import ApprovalState, PolicyDecision, PolicyEngine, PolicyStatus
from .registry import BehaviorRegistry, RegistryError
from .run_store import RunHandle, RunStore
from .runner_adapter import AdaptedAction, RunnerActionAdapter, RunnerAdapterError
from .runner_client import RunnerTransport, RunnerTransportError
from .runner_contracts import build_execution_manifest, build_runner_profile, current_platform
from .simulation import SimulationError, SimulationRegistry
from .util import content_hash


class OrchestrationError(ValueError):
    """Raised when a requested run cannot be safely prepared."""


@dataclass(frozen=True, slots=True)
class PreflightReport:
    status: str
    mode: ExecutionMode
    scenario_id: str
    runner_profile_id: str | None
    ai_enabled: bool
    autonomy: AutonomyLevel
    ai_provider: Mapping[str, Any]
    actions: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    approval_required: bool
    problems: tuple[str, ...]
    plan: Mapping[str, Any]

    @property
    def ready(self) -> bool:
        return self.status == "ready"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.preflight.v1",
            "status": self.status,
            "ready": self.ready,
            "mode": self.mode.value,
            "scenario_id": self.scenario_id,
            "runner_profile_id": self.runner_profile_id,
            "ai_enabled": self.ai_enabled,
            "autonomy": self.autonomy.value,
            "ai_provider": dict(self.ai_provider),
            "actions": list(self.actions),
            "required_capabilities": list(self.required_capabilities),
            "approval_required": self.approval_required,
            "problems": list(self.problems),
            "plan": dict(self.plan),
        }


class Orchestrator:
    """Own graph transitions while delegating effects exclusively to Rust."""

    def __init__(
        self,
        registry: BehaviorRegistry,
        store: RunStore,
        *,
        runner: RunnerTransport | None = None,
        proposal_provider: AIProvider | None = None,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        self.runner = runner
        self.proposal_provider = proposal_provider
        self.approval_store = approval_store
        self.planner = DeterministicPlanner(registry)
        self.policy = PolicyEngine()
        self.simulations = SimulationRegistry()
        self.adapter = RunnerActionAdapter()

    def preflight(
        self,
        scenario: ScenarioDefinition,
        *,
        mode: ExecutionMode = ExecutionMode.SIMULATE,
        profile: RunnerProfile | None = None,
        autonomy: AutonomyLevel | str | None = None,
        ai_provider: Mapping[str, Any] | None = None,
        ai_enabled: bool | None = None,
        approval_present: bool = False,
        action_implementations: Mapping[str, str] | None = None,
    ) -> PreflightReport:
        problems: list[str] = []
        try:
            plan = self.planner.compile(
                scenario,
                mode=mode,
                profile=profile,
                autonomy=autonomy,
                ai_provider=ai_provider,
                ai_enabled=ai_enabled,
                action_implementations=action_implementations,
            )
        except Exception as exc:
            raise OrchestrationError(str(exc)) from exc

        if mode is ExecutionMode.EXECUTE:
            if profile is None:
                problems.append("Execute requires an explicit runner profile.")
            else:
                try:
                    self.registry.validate_runner_profile(profile)
                except Exception as exc:
                    problems.append(str(exc))
                problems.extend(self._cleanup_preflight_problems(plan, profile))
            if self.runner is None:
                problems.append("Execute requires an available Rust runner transport.")
            if profile is not None and profile.approval_required and not approval_present:
                problems.append("Explicit operator approval is required.")
        actions = tuple(step.action_id for step in plan.steps if step.action_id is not None)
        capabilities = tuple(
            sorted({capability for step in plan.steps for capability in step.required_capabilities})
        )
        approval_required = bool(
            mode is ExecutionMode.EXECUTE and profile is not None and profile.approval_required
        )
        status = "ready"
        if problems:
            status = (
                "approval_required"
                if problems == ["Explicit operator approval is required."]
                else "refused"
            )
        return PreflightReport(
            status=status,
            mode=mode,
            scenario_id=scenario.id,
            runner_profile_id=profile.id if profile else None,
            ai_enabled=plan.ai_enabled,
            autonomy=plan.autonomy,
            ai_provider=plan.ai_provider,
            actions=actions,
            required_capabilities=capabilities,
            approval_required=approval_required,
            problems=tuple(problems),
            plan=plan.to_dict(),
        )

    def run(
        self,
        scenario: ScenarioDefinition,
        *,
        mode: ExecutionMode = ExecutionMode.SIMULATE,
        profile: RunnerProfile | None = None,
        sandbox_root: str | Path | None = None,
        target_scope: Mapping[str, Any] | None = None,
        approved_by: str | None = None,
        approval_record: Mapping[str, Any] | None = None,
        autonomy: AutonomyLevel | str | None = None,
        ai_provider: Mapping[str, Any] | None = None,
        ai_enabled: bool | None = None,
        replay: Mapping[str, Any] | None = None,
        resume_from_step_id: str | None = None,
        seed_artifacts: Mapping[str, Any] | None = None,
        checkpoint: Callable[[Mapping[str, Any]], None] | None = None,
        action_implementations: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        execution_started = time.monotonic()
        if checkpoint is not None:
            checkpoint({"phase": "planning", "completed_steps": 0})
        preflight = self.preflight(
            scenario,
            mode=mode,
            profile=profile,
            autonomy=autonomy,
            ai_provider=ai_provider,
            ai_enabled=ai_enabled,
            approval_present=approval_record is not None,
            action_implementations=action_implementations,
        )
        if not preflight.ready:
            raise OrchestrationError("; ".join(preflight.problems))

        plan = self.planner.compile(
            scenario,
            mode=mode,
            profile=profile,
            autonomy=autonomy,
            ai_provider=ai_provider,
            ai_enabled=ai_enabled,
            action_implementations=action_implementations,
        )
        runner_profile_doc: Mapping[str, Any] | None = None
        observer: SandboxObserver | None = None
        authorized_target_scope: Mapping[str, Any] = {"scope_refs": []}
        validated_approval: Mapping[str, Any] | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None or sandbox_root is None or self.runner is None:
                raise OrchestrationError(
                    "Execute requires an explicit profile, sandbox root, and Rust runner"
                )
            authorized_target_scope = self._validated_target_scope(target_scope, profile)
            approval_context = (
                {
                    "replay": dict(replay or {}),
                    "resume_from_step_id": resume_from_step_id,
                }
                if replay is not None or resume_from_step_id is not None
                else None
            )
            binding = execution_approval_binding(
                registry=self.registry,
                scenario=scenario,
                plan=plan.to_dict(),
                profile=profile,
                target_scope=authorized_target_scope,
                autonomy=plan.autonomy,
                ai_provider=plan.ai_provider,
                context=approval_context,
            )
            if self.approval_store is None:
                raise OrchestrationError("Execute requires a durable approval verifier")
            approval_id = approval_record.get("approval_id") if approval_record else None
            nonce = approval_record.get("nonce") if approval_record else None
            if not isinstance(approval_id, str) or not isinstance(nonce, str):
                raise OrchestrationError("Execute approval capability is incomplete")
            try:
                claimed_approval = self.approval_store.claim_consumed_approval(
                    approval_id,
                    nonce=nonce,
                    approved_by=approved_by or "",
                    expected_state_digest=binding["state_digest"],
                    expected_plan_digest=binding["plan_digest"],
                    expected_target_scope_digest=binding["target_scope_digest"],
                    expected_profile_id=binding["profile_id"],
                    expected_maximum_tier=binding["maximum_tier"],
                )
                validated_approval = validate_claimed_approval(
                    claimed_approval,
                    binding=binding,
                    approved_by=approved_by,
                )
            except (ApprovalError, ValueError) as exc:
                raise OrchestrationError(str(exc)) from exc
            network_destinations = self._network_destinations(plan)
            runner_profile_doc = build_runner_profile(
                profile,
                sandbox_root=sandbox_root,
                filesystem_scope=self._filesystem_scope(plan),
                network_destinations=network_destinations,
            )
            observer = SandboxObserver(sandbox_root)
            self._validate_inventory(plan, self.runner.inventory())
        elif approval_record is not None:
            raise OrchestrationError("Simulate does not accept an Execute approval capability")

        persisted_approval = public_approval_record(validated_approval)

        handle = self.store.create_run(
            scenario=scenario.to_dict(),
            plan=plan.to_dict(),
            policy={
                "schema_version": "bluefire.run-policy.v1",
                "preflight": preflight.to_dict(),
                "authorized_target_scope": dict(authorized_target_scope),
                "autonomy": plan.autonomy.value,
                "ai_provider": dict(plan.ai_provider),
                "approval": dict(persisted_approval) if persisted_approval else None,
            },
            profile=profile.to_dict() if profile else None,
            replay=replay,
        )
        if checkpoint is not None:
            checkpoint(
                {
                    "phase": "running",
                    "run_id": handle.run_id,
                    "completed_steps": 0,
                }
            )
        receipt_ids: list[str] = []
        try:
            return self._run_prepared(
                scenario=scenario,
                mode=mode,
                profile=profile,
                runner_profile=runner_profile_doc,
                observer=observer,
                approved_by=approved_by,
                approval_record=validated_approval,
                authorized_target_scope=authorized_target_scope,
                replay=replay,
                resume_from_step_id=resume_from_step_id,
                seed_artifacts=seed_artifacts,
                preflight=preflight,
                plan=plan,
                handle=handle,
                receipt_ids=receipt_ids,
                execution_started=execution_started,
                checkpoint=checkpoint,
            )
        except BaseException:
            if (
                mode is ExecutionMode.EXECUTE
                and profile is not None
                and runner_profile_doc is not None
                and observer is not None
                and receipt_ids
            ):
                self._attempt_emergency_cleanup(
                    run_id=handle.run_id,
                    plan=plan,
                    profile=profile,
                    runner_profile=runner_profile_doc,
                    observer=observer,
                    approved_by=approved_by,
                    approval_record=validated_approval,
                    authorized_target_scope=authorized_target_scope,
                    receipt_ids=receipt_ids,
                )
            raise

    def _run_prepared(
        self,
        *,
        scenario: ScenarioDefinition,
        mode: ExecutionMode,
        profile: RunnerProfile | None,
        runner_profile: Mapping[str, Any] | None,
        observer: SandboxObserver | None,
        approved_by: str | None,
        approval_record: Mapping[str, Any] | None,
        authorized_target_scope: Mapping[str, Any],
        replay: Mapping[str, Any] | None,
        resume_from_step_id: str | None,
        seed_artifacts: Mapping[str, Any] | None,
        preflight: PreflightReport,
        plan: ExecutionPlan,
        handle: RunHandle,
        receipt_ids: list[str],
        execution_started: float,
        checkpoint: Callable[[Mapping[str, Any]], None] | None,
    ) -> Mapping[str, Any]:
        evidence = EvidenceGraph()
        artifacts: dict[str, Any] = dict(seed_artifacts or {})
        step_rows: list[dict[str, Any]] = []
        policy_rows: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        ai_proposals: list[dict[str, Any]] = []
        step_overrides: dict[str, PlanStep] = {}
        visited: set[str] = set()
        retries_used = self._adaptive_retry_count(replay)
        current_step_id: str | None = resume_from_step_id or scenario.start
        forced_cleanup = False
        cleanup_forced = False
        counterfactual_step: str | None = None
        cleanup_attempted = False
        approval_pause: dict[str, Any] | None = None
        max_steps = profile.budgets.max_steps if profile else max(len(plan.steps) * 2, 1)
        total_seconds = float(profile.budgets.max_seconds) if profile else None
        deadline = execution_started + total_seconds if total_seconds is not None else None
        cleanup_reserve = (
            min(5.0, max(0.25, total_seconds * 0.1), total_seconds / 2.0)
            if total_seconds is not None
            else 0.0
        )
        budget_exhausted = False

        while current_step_id and len(step_rows) < max_steps:
            if checkpoint is not None:
                checkpoint(
                    {
                        "phase": "running",
                        "current_step_id": current_step_id,
                        "completed_steps": len(step_rows),
                        "total_steps": max_steps,
                    }
                )
            if current_step_id in visited and not forced_cleanup:
                raise OrchestrationError("scenario traversal attempted to revisit a step")
            visited.add(current_step_id)
            scenario_step = scenario.step(current_step_id)
            plan_step = step_overrides.get(current_step_id) or self._plan_step(
                plan, current_step_id
            )

            if counterfactual_step == current_step_id:
                counterfactual_parents = tuple(
                    step_rows[-1].get("evidence_ids", []) if step_rows else []
                )
                row, record = self._counterfactual_row(
                    run_id=handle.run_id,
                    step=plan_step,
                    parent_ids=counterfactual_parents,
                )
                evidence.add(record)
                step_rows.append(row)
                self.store.append_event(handle.run_id, "step.counterfactual", row)
                current_step_id = None
                counterfactual_step = None
                if mode is ExecutionMode.EXECUTE and receipt_ids and not cleanup_attempted:
                    cleanup_step = next(
                        (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
                        None,
                    )
                    if cleanup_step is not None:
                        current_step_id = cleanup_step.step_id
                        forced_cleanup = True
                        cleanup_forced = True
                continue

            bound_inputs: Mapping[str, Any]
            parent_ids: tuple[str, ...]
            if forced_cleanup and plan_step.action_id == "sandbox.cleanup.v1":
                bound_inputs = {}
                parent_ids = tuple(step_rows[-1].get("evidence_ids", []) if step_rows else [])
            else:
                bound_inputs, parent_ids = self._bind_inputs(
                    scenario_step.inputs,
                    artifacts,
                    evidence,
                )

            if mode is ExecutionMode.SIMULATE:
                row, records = self._simulate_step(
                    run_id=handle.run_id,
                    step=plan_step,
                    bound_inputs=bound_inputs,
                    parent_ids=parent_ids,
                )
            else:
                assert profile is not None
                assert runner_profile is not None
                assert observer is not None
                action = self.registry.get_action(str(plan_step.action_id))
                is_cleanup = action.id == "sandbox.cleanup.v1"
                remaining = max((deadline or time.monotonic()) - time.monotonic(), 0.0)
                available = remaining if is_cleanup else max(remaining - cleanup_reserve, 0.0)
                action_timeout_ms = int(available * 1000)
                step_budget_exhausted = action_timeout_ms < 1
                budget_exhausted = budget_exhausted or step_budget_exhausted
                row, records, decision, _returned_receipts = self._execute_step(
                    run_id=handle.run_id,
                    step=plan_step,
                    bound_inputs=bound_inputs,
                    parent_ids=parent_ids,
                    profile=profile,
                    runner_profile=runner_profile,
                    observer=observer,
                    approved_by=approved_by,
                    approval_record=approval_record,
                    authorized_target_scope=authorized_target_scope,
                    receipt_ids=receipt_ids,
                    action_timeout_ms=action_timeout_ms,
                )
                policy_rows.append(decision.to_dict())
                if plan_step.action_id == "sandbox.cleanup.v1":
                    cleanup_attempted = True
                    if row["status"] == StepOutcome.SUCCESS.value:
                        receipt_ids.clear()

            evidence.extend(records)
            artifacts[current_step_id] = row.get("artifacts", {})
            step_rows.append(row)
            self.store.append_event(handle.run_id, "step.completed", row)

            if checkpoint is not None:
                checkpoint(
                    {
                        "phase": "running",
                        "current_step_id": current_step_id,
                        "completed_steps": len(step_rows),
                        "total_steps": max_steps,
                    }
                )

            if approval_pause is not None and plan_step.action_id == "sandbox.cleanup.v1":
                current_step_id = None
                continue

            if mode is ExecutionMode.EXECUTE and step_budget_exhausted:
                current_step_id = None
                forced_cleanup = False
                if mode is ExecutionMode.EXECUTE and receipt_ids:
                    cleanup_step = next(
                        (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
                        None,
                    )
                    if cleanup_step is not None and not cleanup_attempted:
                        current_step_id = cleanup_step.step_id
                        forced_cleanup = True
                        cleanup_forced = True
                continue

            outcome = StepOutcome(row["status"])
            state = {"artifacts": artifacts, "steps": step_rows}
            planner_decision = self.planner.decide_next(
                run_id=handle.run_id,
                scenario=scenario,
                plan=plan,
                current_step_id=current_step_id,
                outcome=outcome,
                state=state,
                completed_steps=len(step_rows),
                retries_used=retries_used,
            )
            decisions.append(planner_decision.to_dict())
            row["planner_decision_id"] = planner_decision.decision_id
            self.store.append_event(
                handle.run_id,
                "planner.decision",
                planner_decision.to_dict(),
            )
            replay_transition_applied, replay_transition = self._approved_replay_transition(
                replay=replay,
                scenario=scenario,
                current_step_id=current_step_id,
                outcome=outcome,
                planner_decision=planner_decision,
            )
            proposal_record: dict[str, Any] | None = None
            alternate_step: PlanStep | None = None
            adaptive_next_step_id: str | None = None
            retry_applied = False
            if replay_transition_applied:
                adaptive_next_step_id = replay_transition
                self.store.append_event(
                    handle.run_id,
                    "ai.proposal.resumed",
                    {
                        "schema_version": "bluefire.ai-proposal-resume.v1",
                        "source_run_id": replay.get("source_run_id") if replay else None,
                        "current_step_id": current_step_id,
                        "selected_step_id": replay_transition,
                    },
                )
            else:
                (
                    proposal_record,
                    alternate_step,
                    adaptive_next_step_id,
                    retry_applied,
                ) = self._propose_next_step(
                    run_id=handle.run_id,
                    scenario=scenario,
                    plan=plan,
                    profile=profile,
                    mode=mode,
                    current_step_id=current_step_id,
                    current_plan_step=plan_step,
                    outcome=outcome,
                    state=state,
                    planner_decision=planner_decision,
                    retries_used=retries_used,
                    remaining_steps=max_steps - len(step_rows),
                )
            if proposal_record is not None:
                ai_proposals.append(proposal_record)
                self.store.append_event(handle.run_id, "ai.proposal", proposal_record)
                if proposal_record.get("application_status") == "awaiting_operator_approval":
                    pending_proposal = proposal_record.get("proposal")
                    approval_pause = {
                        "schema_version": "bluefire.ai-approval-pause.v1",
                        "requested_after_step_id": current_step_id,
                        "proposed_step_id": (
                            pending_proposal.get("selected_step_id")
                            if isinstance(pending_proposal, Mapping)
                            else None
                        ),
                        "state_digest": planner_decision.current_state_digest,
                        "plan_digest": proposal_record.get("plan_digest"),
                        "proposal_digest": proposal_record.get("proposal_digest"),
                        "proposal_id": (
                            pending_proposal.get("proposal_id")
                            if isinstance(pending_proposal, Mapping)
                            else None
                        ),
                        "proposal": pending_proposal,
                        "resume_requires_replan": True,
                    }
                    self.store.append_event(
                        handle.run_id,
                        "run.awaiting_approval",
                        approval_pause,
                    )
            if alternate_step is not None:
                step_overrides[alternate_step.step_id] = alternate_step
            if retry_applied:
                retries_used += 1
                visited.discard(current_step_id)
            current_step_id = (
                None
                if approval_pause is not None
                else (adaptive_next_step_id or planner_decision.selected_step_id)
            )
            forced_cleanup = False
            if (
                adaptive_next_step_id is None
                and planner_decision.execution_disposition is ExecutionDisposition.COUNTERFACTUAL
            ):
                counterfactual_step = current_step_id

            if current_step_id is None and mode is ExecutionMode.EXECUTE and receipt_ids:
                cleanup_step = next(
                    (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
                    None,
                )
                if cleanup_step is not None and not cleanup_attempted:
                    current_step_id = cleanup_step.step_id
                    forced_cleanup = True
                    cleanup_forced = True
                    counterfactual_step = None

        if current_step_id is not None:
            raise OrchestrationError("run exceeded its step budget")

        detections = self._build_detections(evidence.records())
        cleanup_success = any(
            row.get("behavior_id") == "sandbox.cleanup.v1"
            and row.get("status") == StepOutcome.SUCCESS.value
            for row in step_rows
        )
        cleanup_required = mode is ExecutionMode.EXECUTE and any(
            step.action_id is not None
            and self.registry.get_action(step.action_id).cleanup_action_id is not None
            for step in plan.steps
        )
        business_rows = [row for row in step_rows if row.get("behavior_id") != "sandbox.cleanup.v1"]
        terminal_business = business_rows[-1] if business_rows else None
        terminal_satisfied = bool(
            terminal_business
            and terminal_business.get("status")
            in {StepOutcome.SUCCESS.value, StepOutcome.PARTIAL.value}
            and terminal_business.get("execution_disposition") != "counterfactual"
        )
        objective_reached = (
            terminal_satisfied
            and not cleanup_forced
            and (cleanup_success if cleanup_required else True)
        )
        result = {
            "schema_version": "bluefire.run-result.v1",
            "run_id": handle.run_id,
            "created_at": handle.created_at,
            "status": (
                "awaiting_approval"
                if approval_pause is not None
                else ("completed" if objective_reached else "incomplete")
            ),
            "mode": mode.value,
            "ai_enabled": plan.ai_enabled,
            "autonomy": plan.autonomy.value,
            "ai_provider": dict(plan.ai_provider),
            "runner_profile_id": profile.id if profile else None,
            "approval": public_approval_record(approval_record),
            "authorized_target_scope": dict(authorized_target_scope),
            "scenario_id": scenario.id,
            "objective": scenario.purpose,
            "objective_reached": objective_reached,
            "approval_pause": approval_pause,
            "objective_evaluation": {
                "terminal_step_id": (
                    terminal_business.get("step_id") if terminal_business else None
                ),
                "terminal_status": (terminal_business.get("status") if terminal_business else None),
                "cleanup_required": cleanup_required,
                "cleanup_forced": cleanup_forced,
                "cleanup_satisfied": cleanup_success if cleanup_required else None,
            },
            "steps": step_rows,
            "planner_decisions": decisions,
            "ai_proposals": ai_proposals,
            "cleanup": {
                "attempted": cleanup_attempted if mode is ExecutionMode.EXECUTE else False,
                "success": cleanup_success if mode is ExecutionMode.EXECUTE else None,
                "outstanding_receipt_count": len(receipt_ids),
            },
            "replay": dict(replay) if replay else None,
            "limitations": list(scenario.limitations),
            "runtime_budget": {
                "configured_seconds": total_seconds,
                "cleanup_reserve_seconds": cleanup_reserve,
                "elapsed_seconds": round(time.monotonic() - execution_started, 3),
                "exhausted": budget_exhausted,
            },
            "adaptive_retry": {
                "maximum": 1,
                "used": retries_used,
                "remaining": max(1 - retries_used, 0),
            },
        }
        self.store.write_json(
            handle.run_id,
            "policy.json",
            {
                "schema_version": "bluefire.run-policy.v1",
                "preflight": preflight.to_dict(),
                "decisions": policy_rows,
                "ai_proposals": ai_proposals,
                "authorized_target_scope": dict(authorized_target_scope),
                "autonomy": plan.autonomy.value,
                "ai_provider": dict(plan.ai_provider),
                "approval": public_approval_record(approval_record),
            },
        )
        self.store.finalize(
            handle.run_id,
            result=result,
            evidence=(record.to_dict() for record in evidence.records()),
            detections=(candidate.to_dict() for candidate in detections),
        )
        return self.store.get_run(handle.run_id)

    def recover_cleanup(
        self,
        scenario: ScenarioDefinition,
        *,
        run_id: str,
        profile: RunnerProfile,
        sandbox_root: str | Path,
        target_scope: Mapping[str, Any],
        approval_record: Mapping[str, Any],
        receipt_ids: Sequence[str],
        autonomy: AutonomyLevel,
        ai_provider: Mapping[str, Any],
        approval_context: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Reconcile only runner-owned receipts from one interrupted Execute run."""

        if self.runner is None:
            raise OrchestrationError("cleanup recovery requires the configured Rust runner")
        plan = self.planner.compile(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            autonomy=autonomy,
            ai_provider=ai_provider,
        )
        authorized_scope = self._validated_target_scope(target_scope, profile)
        binding = execution_approval_binding(
            registry=self.registry,
            scenario=scenario,
            plan=plan.to_dict(),
            profile=profile,
            target_scope=authorized_scope,
            autonomy=plan.autonomy,
            ai_provider=plan.ai_provider,
            context=approval_context,
        )
        approved_by = approval_record.get("approved_by")
        validate_claimed_approval(
            approval_record,
            binding=binding,
            approved_by=str(approved_by) if approved_by is not None else None,
        )
        clean_receipts = list(self._validated_receipt_ids(list(receipt_ids)))
        cleanup_step = next(
            (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
            None,
        )
        if cleanup_step is None:
            raise OrchestrationError("interrupted plan has no registered cleanup action")
        runner_profile = build_runner_profile(
            profile,
            sandbox_root=sandbox_root,
            filesystem_scope=self._filesystem_scope(plan),
            network_destinations=self._network_destinations(plan),
        )
        self._validate_cleanup_inventory(self.runner.inventory())
        row, records, decision, _returned = self._execute_step(
            run_id=run_id,
            step=cleanup_step,
            bound_inputs={},
            parent_ids=(),
            profile=profile,
            runner_profile=runner_profile,
            observer=SandboxObserver(sandbox_root),
            approved_by=str(approved_by),
            approval_record=approval_record,
            authorized_target_scope=authorized_scope,
            receipt_ids=clean_receipts,
            action_timeout_ms=min(profile.budgets.max_seconds * 1000, 5 * 60 * 1000),
        )
        if row.get("status") != StepOutcome.SUCCESS.value:
            raise OrchestrationError("runner receipt recovery cleanup did not complete")
        return {
            "schema_version": "bluefire.cleanup-recovery.v1",
            "run_id": run_id,
            "status": "completed",
            "receipt_ids": clean_receipts,
            "step": row,
            "policy": decision.to_dict(),
            "evidence": [record.to_dict() for record in records],
        }

    def _propose_next_step(
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
            raise OrchestrationError("deterministic next-node decision is inconsistent")
        retryable = bool(
            outcome in {StepOutcome.PARTIAL, StepOutcome.BLOCKED, StepOutcome.FAILED}
            and retries_used < 1
            and remaining_steps > 0
            and current_plan_step.behavior_id != "sandbox.cleanup.v1"
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
            context={
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
            },
        )
        base_record: dict[str, Any] = {
            "schema_version": "bluefire.ai-proposal-record.v2",
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

    @staticmethod
    def _adaptive_retry_count(replay: Mapping[str, Any] | None) -> int:
        if replay is None:
            return 0
        value = replay.get("adaptive_retry_count", 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1:
            raise OrchestrationError("adaptive retry lineage exceeds the one-retry bound")
        return int(value)

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

    def _approved_replay_transition(
        self,
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
        if proposal_type == ProposalType.RETRY_REGISTERED.value:
            if selected_step_id != current_step_id:
                raise OrchestrationError("approved retry lineage selected a different node")
            return True, planner_decision.selected_step_id
        if not isinstance(selected_step_id, str):
            raise OrchestrationError("approved proposal lineage has no selected node")
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
                raise OrchestrationError(
                    "approved next-node lineage is stale for the observed outcome"
                )
            return True, selected_step_id
        if planner_decision.selected_step_id != selected_step_id:
            raise OrchestrationError("approved proposal target is stale for the replayed outcome")
        return True, selected_step_id

    def _attempt_emergency_cleanup(
        self,
        *,
        run_id: str,
        plan: ExecutionPlan,
        profile: RunnerProfile,
        runner_profile: Mapping[str, Any],
        observer: SandboxObserver,
        approved_by: str | None,
        approval_record: Mapping[str, Any] | None,
        authorized_target_scope: Mapping[str, Any],
        receipt_ids: list[str],
    ) -> None:
        cleanup_step = next(
            (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
            None,
        )
        if cleanup_step is None or not receipt_ids:
            return
        status = "failed"
        try:
            row, _records, _decision, _returned_receipts = self._execute_step(
                run_id=run_id,
                step=cleanup_step,
                bound_inputs={},
                parent_ids=(),
                profile=profile,
                runner_profile=runner_profile,
                observer=observer,
                approved_by=approved_by,
                approval_record=approval_record,
                authorized_target_scope=authorized_target_scope,
                receipt_ids=receipt_ids,
            )
            status = str(row["status"])
            if status == StepOutcome.SUCCESS.value:
                receipt_ids.clear()
        except BaseException:
            status = "failed"
        try:
            self.store.append_event(
                run_id,
                "cleanup.emergency",
                {
                    "schema_version": "bluefire.cleanup-event.v1",
                    "status": status,
                    "outstanding_receipt_count": len(receipt_ids),
                },
            )
        except BaseException:
            pass

    def _cleanup_preflight_problems(
        self,
        plan: ExecutionPlan,
        profile: RunnerProfile,
    ) -> tuple[str, ...]:
        requires_cleanup = any(
            self.registry.get_action(str(step.action_id)).cleanup_action_id is not None
            for step in plan.steps
            if step.action_id is not None
        )
        if not requires_cleanup:
            return ()
        cleanup_id = "sandbox.cleanup.v1"
        problems: list[str] = []
        if profile.cleanup_policy is not CleanupPolicy.ALWAYS:
            problems.append("Mutating Execute actions require cleanup_policy: always.")
        if cleanup_id not in profile.enabled_actions:
            problems.append("Mutating Execute actions require the registered cleanup action.")
        if cleanup_id in profile.blocked_actions:
            problems.append("The runner profile control-blocks its required cleanup action.")
        if not any(step.action_id == cleanup_id for step in plan.steps):
            problems.append("The Execute plan has no registered cleanup step.")
        return tuple(problems)

    @staticmethod
    def _plan_step(plan: ExecutionPlan, step_id: str) -> PlanStep:
        for step in plan.steps:
            if step.step_id == step_id:
                return step
        raise OrchestrationError(f"plan has no step: {step_id}")

    @staticmethod
    def _bind_inputs(
        bindings: Mapping[str, Any],
        artifacts: Mapping[str, Any],
        evidence: EvidenceGraph,
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        bound: dict[str, Any] = {}
        parents: list[str] = []
        for port, binding in bindings.items():
            source = artifacts.get(binding.from_step)
            if not isinstance(source, Mapping) or binding.artifact not in source:
                raise OrchestrationError(
                    f"required artifact is unavailable: {binding.from_step}.{binding.artifact}"
                )
            bound[port] = source[binding.artifact]
            parents.extend(record.evidence_id for record in evidence.by_step(binding.from_step))
        return bound, tuple(dict.fromkeys(parents))

    def _simulate_step(
        self,
        *,
        run_id: str,
        step: PlanStep,
        bound_inputs: Mapping[str, Any],
        parent_ids: Sequence[str],
    ) -> tuple[dict[str, Any], tuple[EvidenceRecord, ...]]:
        try:
            simulation = self.simulations.execute(step, bound_inputs=bound_inputs)
        except SimulationError as exc:
            record = EvidenceRecord.create(
                run_id=run_id,
                step_id=step.step_id,
                behavior_id=step.behavior_id,
                action_id=None,
                provenance=EvidenceProvenance.UNKNOWN,
                producer="simulation-registry.v1",
                content={"error": str(exc), "side_effects_started": False},
                target_scope_ref="simulate:none",
                parent_evidence_ids=parent_ids,
                confidence=0.0,
            )
            return (
                self._row(
                    step,
                    StepOutcome.FAILED,
                    artifacts={},
                    telemetry=(),
                    evidence_ids=(record.evidence_id,),
                    execution_disposition="simulate",
                    error={"code": "simulation_failed", "message": str(exc)},
                ),
                (record,),
            )
        record = EvidenceRecord.create(
            run_id=run_id,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=None,
            provenance=EvidenceProvenance.SYNTHETIC,
            producer="simulation-registry.v1",
            content=dict(simulation.details, artifacts=dict(simulation.artifacts)),
            target_scope_ref="simulate:none",
            parent_evidence_ids=parent_ids,
            confidence=1.0,
            limitations=simulation.limitations,
        )
        return (
            self._row(
                step,
                simulation.outcome,
                artifacts=simulation.artifacts,
                telemetry=simulation.telemetry,
                evidence_ids=(record.evidence_id,),
                execution_disposition="simulate",
            ),
            (record,),
        )

    def _execute_step(
        self,
        *,
        run_id: str,
        step: PlanStep,
        bound_inputs: Mapping[str, Any],
        parent_ids: Sequence[str],
        profile: RunnerProfile,
        runner_profile: Mapping[str, Any],
        observer: SandboxObserver,
        approved_by: str | None,
        approval_record: Mapping[str, Any] | None,
        authorized_target_scope: Mapping[str, Any],
        receipt_ids: list[str],
        action_timeout_ms: int | None = None,
    ) -> tuple[dict[str, Any], tuple[EvidenceRecord, ...], PolicyDecision, tuple[str, ...]]:
        action = self.registry.get_action(str(step.action_id))
        if action_timeout_ms is not None and action_timeout_ms < 1:
            decision = self._budget_refusal(step, profile)
            record = self._control_record(run_id, step, decision, parent_ids)
            row = self._row(
                step,
                StepOutcome.BLOCKED,
                artifacts={},
                telemetry=("policy.runtime_budget_refused",),
                evidence_ids=(record.evidence_id,),
                execution_disposition="execute",
                policy=decision.to_dict(),
                error={
                    "code": "runtime_budget_exhausted",
                    "message": decision.reasons[0],
                },
            )
            return row, (record,), decision, ()
        try:
            adapted = self.adapter.adapt(
                step,
                bound_inputs=bound_inputs,
                receipt_ids=receipt_ids,
            )
        except RunnerAdapterError as exc:
            decision = self._adapter_refusal(step, profile, str(exc))
            record = self._control_record(run_id, step, decision, parent_ids)
            row = self._row(
                step,
                StepOutcome.BLOCKED,
                artifacts={},
                telemetry=("runner.adapter_refused",),
                evidence_ids=(record.evidence_id,),
                execution_disposition="execute",
                policy=decision.to_dict(),
                error={"code": "adapter_refused", "message": str(exc)},
            )
            return row, (record,), decision, ()

        required_target_scope = self._logical_scope(adapted)
        authorized_refs = set(authorized_target_scope.get("scope_refs", ()))
        required_refs = set(required_target_scope["scope_refs"])
        missing_scope = sorted(required_refs - authorized_refs)
        if missing_scope:
            decision = self._scope_refusal(
                step,
                profile,
                authorized_target_scope=authorized_target_scope,
                required_target_scope=required_target_scope,
                missing_scope=missing_scope,
            )
            record = self._control_record(run_id, step, decision, parent_ids)
            row = self._row(
                step,
                StepOutcome.BLOCKED,
                artifacts={},
                telemetry=("policy.target_scope_refused",),
                evidence_ids=(record.evidence_id,),
                execution_disposition="execute",
                policy=decision.to_dict(),
                error={
                    "code": "target_scope_refused",
                    "message": "; ".join(decision.reasons),
                },
            )
            return row, (record,), decision, ()

        manifest = build_execution_manifest(
            run_id=run_id,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action=action,
            runner_profile=runner_profile,
            params=adapted.params,
            filesystem_scope=adapted.filesystem_scope,
            network_destinations=adapted.network_destinations,
            evidence_refs=parent_ids,
            approval_record=approval_record,
            timeout_ms=action_timeout_ms,
        )
        approval = self._approval_state(
            manifest,
            action_id=action.id,
            profile_id=profile.id,
            target_scope=required_target_scope,
            approval_record=approval_record,
        )
        decision = self.policy.evaluate(
            step=step,
            action=action,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            platform=current_platform(),
            target_scope=required_target_scope,
            request_hash=str(manifest["request_hash"]),
            approval=approval,
        )
        if not decision.allowed:
            record = self._control_record(run_id, step, decision, parent_ids)
            row = self._row(
                step,
                StepOutcome.BLOCKED,
                artifacts={},
                telemetry=("policy.control_blocked",),
                evidence_ids=(record.evidence_id,),
                execution_disposition="execute",
                policy=decision.to_dict(),
                error={"code": decision.status.value, "message": "; ".join(decision.reasons)},
            )
            return row, (record,), decision, ()

        assert self.runner is not None
        try:
            runner_result = self.runner.execute(manifest, runner_profile)
            self._validate_runner_result(manifest, runner_profile, runner_result)
            returned_receipts = self._validated_receipt_ids(runner_result.get("receipt_ids", []))
            self._validate_cleanup_result(manifest, runner_result)
        except RunnerTransportError as exc:
            discovered_receipts = self._discover_runner_receipts(
                observer.root,
                expected_profile_id=profile.id,
            )
            for receipt_id in discovered_receipts:
                if receipt_id not in receipt_ids:
                    receipt_ids.append(receipt_id)
            record = EvidenceRecord.create(
                run_id=run_id,
                step_id=step.step_id,
                behavior_id=step.behavior_id,
                action_id=step.action_id,
                provenance=EvidenceProvenance.UNKNOWN,
                producer="runner-transport.v1",
                runner_profile_id=profile.id,
                environment={"environment_type": profile.environment_type.value},
                parent_evidence_ids=parent_ids,
                content={"error": str(exc), "execution_status": "unknown"},
                confidence=0.0,
                limitations=("Runner transport failed; execution evidence is unavailable.",),
                target_scope_ref=f"runner-profile:{profile.id}",
            )
            row = self._row(
                step,
                StepOutcome.FAILED,
                artifacts={},
                telemetry=("runner.transport_failed",),
                evidence_ids=(record.evidence_id,),
                execution_disposition="execute",
                policy=decision.to_dict(),
                receipts=discovered_receipts,
                error={"code": "runner_transport_failed", "message": str(exc)},
            )
            return row, (record,), decision, discovered_receipts
        except BaseException:
            for receipt_id in self._discover_runner_receipts(
                observer.root,
                expected_profile_id=profile.id,
            ):
                if receipt_id not in receipt_ids:
                    receipt_ids.append(receipt_id)
            raise

        for receipt_id in returned_receipts:
            if receipt_id not in receipt_ids:
                receipt_ids.append(receipt_id)
        discovered_receipts = self._discover_runner_receipts(
            observer.root,
            expected_profile_id=profile.id,
        )
        for receipt_id in discovered_receipts:
            if receipt_id not in receipt_ids:
                receipt_ids.append(receipt_id)
        effective_receipts = tuple(dict.fromkeys((*returned_receipts, *discovered_receipts)))

        runner_status = str(runner_result.get("status"))
        outcome = self._runner_outcome(runner_status)
        provenance = (
            EvidenceProvenance.CONTROL_BLOCKED
            if runner_status in {"refused", "control_blocked"}
            else EvidenceProvenance.EXECUTED
        )
        record = EvidenceRecord.create(
            run_id=run_id,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            provenance=provenance,
            producer="bluefire-rust-runner",
            runner_profile_id=profile.id,
            environment={
                "environment_type": profile.environment_type.value,
                "platform": runner_result.get("platform"),
            },
            parent_evidence_ids=parent_ids,
            content={
                "request_hash": manifest["request_hash"],
                "policy_digest": runner_profile["policy_digest"],
                "runner_status": runner_status,
                "runner_evidence": runner_result.get("evidence", []),
                "output": runner_result.get("output"),
                "stdout": runner_result.get("stdout", {}),
                "stderr": runner_result.get("stderr", {}),
                "error": runner_result.get("error"),
            },
            confidence=1.0,
            limitations=tuple(str(item) for item in runner_result.get("limitations", [])),
            target_scope_ref=f"runner-profile:{profile.id}",
        )
        records: list[EvidenceRecord] = [record]
        logical_outputs: Mapping[str, Any] = {}
        if outcome in {StepOutcome.SUCCESS, StepOutcome.PARTIAL}:
            try:
                logical_outputs = self.adapter.logical_outputs(
                    step,
                    bound_inputs=bound_inputs,
                    runner_output=runner_result.get("output"),
                    receipt_ids=effective_receipts,
                )
            except RunnerAdapterError:
                outcome = StepOutcome.PARTIAL
                logical_outputs = {}
        if provenance is EvidenceProvenance.EXECUTED:
            for path in adapted.observable_paths:
                try:
                    observed = observer.observe_file(
                        relative_path=path,
                        run_id=run_id,
                        step_id=step.step_id,
                        behavior_id=step.behavior_id,
                        action_id=str(step.action_id),
                        runner_profile_id=profile.id,
                        parent_evidence_ids=(record.evidence_id,),
                    )
                except (EvidenceError, OSError) as exc:
                    reason = (
                        str(exc)[:300]
                        if isinstance(exc, EvidenceError)
                        else "observer could not read the requested artifact"
                    )
                    records.append(
                        EvidenceRecord.create(
                            run_id=run_id,
                            step_id=step.step_id,
                            behavior_id=step.behavior_id,
                            action_id=str(step.action_id),
                            provenance=EvidenceProvenance.UNKNOWN,
                            producer="sandbox-observer.v1",
                            runner_profile_id=profile.id,
                            environment={"environment_type": profile.environment_type.value},
                            parent_evidence_ids=(record.evidence_id,),
                            content={
                                "artifact_type": "evidence_gap",
                                "requested_artifact": path,
                                "reason": reason,
                            },
                            confidence=0.0,
                            limitations=(
                                "Runner execution was reported, but the declared artifact "
                                "was not independently observed.",
                            ),
                            target_scope_ref=f"runner-profile:{profile.id}",
                        )
                    )
                    continue
                records.append(observed)

        telemetry = (
            tuple(self.registry.get_behavior(step.behavior_id).telemetry)
            if outcome in {StepOutcome.SUCCESS, StepOutcome.PARTIAL}
            else (f"runner.{runner_status}",)
        )
        row = self._row(
            step,
            outcome,
            artifacts=logical_outputs,
            telemetry=telemetry,
            evidence_ids=tuple(item.evidence_id for item in records),
            execution_disposition="execute",
            policy=decision.to_dict(),
            runner_status=runner_status,
            request_hash=str(manifest["request_hash"]),
            receipts=effective_receipts,
            cleanup=runner_result.get("cleanup"),
            error=runner_result.get("error"),
        )
        return row, tuple(records), decision, effective_receipts

    @staticmethod
    def _row(
        step: PlanStep,
        outcome: StepOutcome,
        *,
        artifacts: Mapping[str, Any],
        telemetry: Sequence[str],
        evidence_ids: Sequence[str],
        execution_disposition: str,
        **extra: Any,
    ) -> dict[str, Any]:
        row = {
            "schema_version": "bluefire.step-result.v1",
            "step_id": step.step_id,
            "behavior_id": step.behavior_id,
            "action_id": step.action_id,
            "simulation_id": step.simulation_id,
            "status": outcome.value,
            "execution_disposition": execution_disposition,
            "artifacts": dict(artifacts),
            "telemetry": list(telemetry),
            "evidence_ids": list(evidence_ids),
        }
        row.update(extra)
        return row

    @staticmethod
    def _runner_outcome(status: str) -> StepOutcome:
        if status == "success":
            return StepOutcome.SUCCESS
        if status == "partial":
            return StepOutcome.PARTIAL
        if status in {"refused", "control_blocked"}:
            return StepOutcome.BLOCKED
        return StepOutcome.FAILED

    @staticmethod
    def _logical_scope(adapted: AdaptedAction) -> dict[str, Any]:
        refs = ["sandbox.workspace"]
        if adapted.network_destinations:
            refs.append("network.loopback")
        if adapted.params.get("destination") == "exports/bundle.bin":
            refs.append("export.local")
        result: dict[str, Any] = {"scope_refs": refs}
        if adapted.network_destinations:
            destination = adapted.network_destinations[0]
            result["network_destination"] = f"{destination['host']}:{destination['port']}"
        return result

    @staticmethod
    def _validated_target_scope(
        value: Mapping[str, Any] | None,
        profile: RunnerProfile,
    ) -> dict[str, Any]:
        if value is None:
            raise OrchestrationError("Execute requires an explicit target scope")
        if not isinstance(value, Mapping) or set(value) != {"scope_refs"}:
            raise OrchestrationError("target scope must contain only scope_refs")
        raw_refs = value.get("scope_refs")
        if (
            not isinstance(raw_refs, list)
            or not raw_refs
            or not all(isinstance(item, str) and item for item in raw_refs)
        ):
            raise OrchestrationError("target scope refs must be a non-empty string list")
        if len(raw_refs) != len(set(raw_refs)):
            raise OrchestrationError("target scope refs cannot contain duplicates")
        extra = sorted(set(raw_refs) - set(profile.scope))
        if extra:
            raise OrchestrationError(
                "target scope expands beyond the selected profile: " + ", ".join(extra)
            )
        return {"scope_refs": list(raw_refs)}

    @staticmethod
    def _scope_refusal(
        step: PlanStep,
        profile: RunnerProfile,
        *,
        authorized_target_scope: Mapping[str, Any],
        required_target_scope: Mapping[str, Any],
        missing_scope: Sequence[str],
    ) -> PolicyDecision:
        reason = "operator target scope does not authorize: " + ", ".join(missing_scope)
        scope_digest = content_hash(authorized_target_scope)
        body = {
            "status": PolicyStatus.REFUSED.value,
            "step_id": step.step_id,
            "reason": reason,
            "authorized_target_scope": dict(authorized_target_scope),
            "required_target_scope": dict(required_target_scope),
        }
        return PolicyDecision(
            schema_version="bluefire.policy-decision.v1",
            status=PolicyStatus.REFUSED,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            runner_profile_id=profile.id,
            reasons=(reason,),
            required_approvals=(),
            evaluated_capabilities=step.required_capabilities,
            target_scope_digest=scope_digest,
            policy_digest=content_hash(body),
        )

    @staticmethod
    def _approval_state(
        manifest: Mapping[str, Any],
        *,
        action_id: str,
        profile_id: str,
        target_scope: Mapping[str, Any],
        approval_record: Mapping[str, Any] | None = None,
    ) -> ApprovalState | None:
        approval = manifest.get("approval")
        if not isinstance(approval, Mapping) or approval_record is None:
            return None
        nonce = (
            "bound-"
            + content_hash(
                {
                    "approval_id": approval_record["approval_id"],
                    "capability_nonce": approval_record["nonce"],
                    "request_hash": manifest["request_hash"],
                }
            )[7:]
        )
        return ApprovalState(
            schema_version="bluefire.approval.v1",
            approved_by=str(approval["approved_by"]),
            issued_at=str(approval["approved_at"]),
            expires_at=str(approval["expires_at"]),
            request_hash=str(manifest["request_hash"]),
            action_id=action_id,
            runner_profile_id=profile_id,
            target_scope_digest=content_hash(target_scope),
            nonce=nonce,
        )

    @staticmethod
    def _adapter_refusal(
        step: PlanStep,
        profile: RunnerProfile,
        reason: str,
    ) -> PolicyDecision:
        body = {
            "status": PolicyStatus.REFUSED.value,
            "step_id": step.step_id,
            "reason": reason,
        }
        return PolicyDecision(
            schema_version="bluefire.policy-decision.v1",
            status=PolicyStatus.REFUSED,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            runner_profile_id=profile.id,
            reasons=(reason,),
            required_approvals=(),
            evaluated_capabilities=step.required_capabilities,
            target_scope_digest=content_hash({}),
            policy_digest=content_hash(body),
        )

    @staticmethod
    def _budget_refusal(step: PlanStep, profile: RunnerProfile) -> PolicyDecision:
        reason = "overall run time budget was exhausted before action dispatch"
        body = {
            "status": PolicyStatus.REFUSED.value,
            "step_id": step.step_id,
            "reason": reason,
            "max_seconds": profile.budgets.max_seconds,
        }
        return PolicyDecision(
            schema_version="bluefire.policy-decision.v1",
            status=PolicyStatus.REFUSED,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            runner_profile_id=profile.id,
            reasons=(reason,),
            required_approvals=(),
            evaluated_capabilities=step.required_capabilities,
            target_scope_digest=content_hash({}),
            policy_digest=content_hash(body),
        )

    @staticmethod
    def _control_record(
        run_id: str,
        step: PlanStep,
        decision: PolicyDecision,
        parent_ids: Sequence[str],
    ) -> EvidenceRecord:
        return EvidenceRecord.create(
            run_id=run_id,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            provenance=EvidenceProvenance.CONTROL_BLOCKED,
            producer="policy-engine.v1",
            runner_profile_id=decision.runner_profile_id,
            environment={},
            parent_evidence_ids=parent_ids,
            content={"policy": decision.to_dict(), "side_effects_started": False},
            confidence=1.0,
            limitations=("Control decision only; the action was not dispatched.",),
            target_scope_ref=f"runner-profile:{decision.runner_profile_id}",
        )

    @staticmethod
    def _counterfactual_row(
        *,
        run_id: str,
        step: PlanStep,
        parent_ids: Sequence[str],
    ) -> tuple[dict[str, Any], EvidenceRecord]:
        record = EvidenceRecord.create(
            run_id=run_id,
            step_id=step.step_id,
            behavior_id=step.behavior_id,
            action_id=step.action_id,
            provenance=EvidenceProvenance.COUNTERFACTUAL,
            producer="deterministic-planner.v1",
            parent_evidence_ids=parent_ids,
            content={
                "reason": "No registered real outcome branch; continuation was not executed.",
                "side_effects_started": False,
            },
            confidence=1.0,
            limitations=("Counterfactual only; it is not execution evidence.",),
            target_scope_ref="counterfactual:none",
        )
        row = Orchestrator._row(
            step,
            StepOutcome.BLOCKED,
            artifacts={},
            telemetry=(),
            evidence_ids=(record.evidence_id,),
            execution_disposition="counterfactual",
        )
        return row, record

    @staticmethod
    def _filesystem_scope(plan: ExecutionPlan) -> tuple[str, ...]:
        """Compile the fixed runner roots needed by this exact reviewed plan."""

        roots_by_action = {
            "sandbox.fixture.create.v1": ("fixtures",),
            "sandbox.fixture.transform.v1": ("fixtures",),
            "sandbox.discovery.list.v1": ("fixtures",),
            "sandbox.discovery.metadata.v1": ("fixtures",),
            "sandbox.discovery.recursive.v1": ("fixtures",),
            "sandbox.archive.tar.v1": ("fixtures", "staged"),
            "sandbox.collection.stage.v1": ("fixtures", "staged"),
            "sandbox.network.loopback.v1": ("staged",),
            "sandbox.export.local.v1": ("staged", "exports"),
            "sandbox.restricted.persistence-marker.v1": ("restricted",),
        }
        selected: list[str] = []
        for step in plan.steps:
            for root in roots_by_action.get(step.action_id or "", ()):
                if root not in selected:
                    selected.append(root)
        return tuple(selected)

    @staticmethod
    def _network_destinations(plan: ExecutionPlan) -> tuple[Mapping[str, Any], ...]:
        rows: list[Mapping[str, Any]] = []
        for step in plan.steps:
            if step.action_id != "sandbox.network.loopback.v1":
                continue
            port = step.parameters.get("port", 4317)
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise OrchestrationError("loopback scenario port is invalid")
            rows.append({"host": "127.0.0.1", "port": port})
        unique = {(str(row["host"]), int(row["port"])): row for row in rows}
        return tuple(unique[key] for key in sorted(unique))

    @staticmethod
    def _validate_inventory(plan: ExecutionPlan, inventory: Mapping[str, Any]) -> None:
        if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
            raise OrchestrationError("Rust runner inventory schema is unsupported")
        raw_actions = inventory.get("actions")
        if not isinstance(raw_actions, list):
            raise OrchestrationError("Rust runner inventory has no action list")
        available = {
            str(row.get("action_id"))
            for row in raw_actions
            if isinstance(row, Mapping) and isinstance(row.get("action_id"), str)
        }
        requested = {str(step.action_id) for step in plan.steps if step.action_id}
        missing = sorted(requested - available)
        if missing:
            raise OrchestrationError("Rust runner lacks planned actions: " + ", ".join(missing))

    @staticmethod
    def _validate_cleanup_inventory(inventory: Mapping[str, Any]) -> None:
        """Require only the registered cleanup contract during crash recovery."""

        if inventory.get("schema_version") != "bluefire.runner-inventory.v1":
            raise OrchestrationError("Rust runner inventory schema is unsupported")
        raw_actions = inventory.get("actions")
        if not isinstance(raw_actions, list):
            raise OrchestrationError("Rust runner inventory has no action list")
        cleanup = next(
            (
                row
                for row in raw_actions
                if isinstance(row, Mapping) and row.get("action_id") == "sandbox.cleanup.v1"
            ),
            None,
        )
        if cleanup is None or cleanup.get("readiness") == "unavailable":
            raise OrchestrationError("Rust runner lacks an available cleanup action")

    @staticmethod
    def _validate_runner_result(
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        expected = {
            "schema_version": "bluefire.runner-result.v1",
            "run_id": manifest["run_id"],
            "step_id": manifest["step_id"],
            "behavior_id": manifest["behavior_id"],
            "action_id": manifest["action_id"],
            "request_hash": manifest["request_hash"],
            "policy_digest": profile["policy_digest"],
        }
        for field, value in expected.items():
            if result.get(field) != value:
                raise RunnerTransportError(f"runner result {field} does not match its request")

    @staticmethod
    def _validated_receipt_ids(value: Any) -> tuple[str, ...]:
        if not isinstance(value, list):
            raise RunnerTransportError("runner result receipt_ids must be a list")
        result: list[str] = []
        for receipt_id in value:
            if (
                not isinstance(receipt_id, str)
                or len(receipt_id) != 64
                or any(character not in "0123456789abcdef" for character in receipt_id)
            ):
                raise RunnerTransportError("runner returned an invalid receipt ID")
            if receipt_id in result:
                raise RunnerTransportError("runner returned duplicate receipt IDs")
            result.append(receipt_id)
        return tuple(result)

    @staticmethod
    def _discover_runner_receipts(
        sandbox_root: Path,
        *,
        expected_profile_id: str | None = None,
    ) -> tuple[str, ...]:
        receipt_root = sandbox_root / ".bluefire" / "receipts"
        if not receipt_root.exists():
            return ()
        if receipt_root.is_symlink() or not receipt_root.is_dir():
            raise RunnerTransportError("runner receipt directory is unsafe")
        resolved = receipt_root.resolve(strict=True)
        if resolved.parent.parent != sandbox_root.resolve(strict=True):
            raise RunnerTransportError("runner receipt directory escaped the sandbox")
        receipt_rows: list[tuple[datetime, str]] = []
        for entry in receipt_root.iterdir():
            receipt_id = entry.stem
            if (
                entry.is_symlink()
                or entry.suffix != ".json"
                or len(receipt_id) != 64
                or any(character not in "0123456789abcdef" for character in receipt_id)
            ):
                raise RunnerTransportError("runner receipt entry is unsafe")
            receipt_bytes: bytes | None = None
            receipt_size: int | None = None
            for attempt in range(5):
                try:
                    if not entry.is_file():
                        raise OSError("receipt metadata is not yet readable")
                    receipt_size = entry.stat().st_size
                    receipt_bytes = entry.read_bytes()
                    break
                except OSError:
                    if attempt == 4:
                        raise RunnerTransportError(
                            "runner receipt could not be read after a bounded retry"
                        ) from None
                    time.sleep(0.01)
            assert receipt_size is not None and receipt_bytes is not None
            if receipt_size > 256 * 1024 or len(receipt_bytes) > 256 * 1024:
                raise RunnerTransportError("runner receipt exceeds its storage bound")
            try:
                payload = json.loads(receipt_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RunnerTransportError("runner receipt could not be decoded") from exc
            if (
                not isinstance(payload, Mapping)
                or payload.get("schema_version") != "bluefire.receipt/v1"
                or payload.get("receipt_id") != receipt_id
                or not isinstance(payload.get("action_id"), str)
                or not isinstance(payload.get("runner_profile_id"), str)
                or not isinstance(payload.get("paths"), list)
            ):
                raise RunnerTransportError("runner receipt record is invalid")
            if (
                expected_profile_id is not None
                and payload.get("runner_profile_id") != expected_profile_id
            ):
                raise RunnerTransportError("runner receipt belongs to another profile")
            created_at = payload.get("created_at")
            if not isinstance(created_at, str):
                raise RunnerTransportError("runner receipt timestamp is invalid")
            try:
                parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise RunnerTransportError("runner receipt timestamp is invalid") from exc
            if parsed.tzinfo is None:
                raise RunnerTransportError("runner receipt timestamp is not timezone-aware")
            receipt_rows.append((parsed.astimezone(timezone.utc), receipt_id))
        receipt_rows.sort()
        return tuple(receipt_id for _created_at, receipt_id in receipt_rows)

    @staticmethod
    def _validate_cleanup_result(
        manifest: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> None:
        if manifest.get("action_id") != "sandbox.cleanup.v1":
            return
        cleanup = result.get("cleanup")
        if not isinstance(cleanup, Mapping):
            raise RunnerTransportError("cleanup result is missing its cleanup report")
        params = manifest.get("params")
        requested = params.get("receipt_ids") if isinstance(params, Mapping) else None
        if not isinstance(requested, list):
            raise RunnerTransportError("cleanup manifest has no receipt list")
        if result.get("status") != "success":
            return
        if cleanup.get("requested_receipts") != len(requested):
            raise RunnerTransportError("cleanup report does not cover every requested receipt")
        if cleanup.get("errors") != [] or cleanup.get("retained_paths") != []:
            raise RunnerTransportError("cleanup reported success with retained artifacts")

    @staticmethod
    def _build_detections(records: Sequence[EvidenceRecord]) -> tuple[DetectionCandidate, ...]:
        candidate = DetectionCandidate.hypothesis(
            behavior_id="sandbox.collection.stage.v1",
            title="Runner-owned sandbox staging file",
            target_language="internal",
            logsource={"category": "sandbox_observation", "product": "bluefire"},
            selection={"artifact_type": "file_observation", "path|startswith": "staged/"},
            provenance={"source": "canonical sandbox evidence model", "license": "MIT"},
            known_misses=("Does not inspect host or external telemetry.",),
        )
        pipeline = DetectionPipeline()
        candidate = pipeline.parse(candidate)
        candidate = pipeline.exercise_fixtures(
            candidate,
            [
                {
                    "fixture_id": "fixture-staging-positive.v1",
                    "artifact_type": "file_observation",
                    "path": "staged/000-fixture.txt",
                }
            ],
        )
        candidate = pipeline.exercise_observed(candidate, records)
        candidate = pipeline.evaluate_benign(
            candidate,
            [
                {
                    "fixture_id": "fixture-benign-source.v1",
                    "artifact_type": "file_observation",
                    "path": "fixtures/input.txt",
                }
            ],
            notes=("Benign source fixture should not match the staging-path candidate.",),
        )
        return (candidate,)


__all__ = ["OrchestrationError", "Orchestrator", "PreflightReport"]
