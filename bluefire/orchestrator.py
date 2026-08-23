"""Deterministic graph orchestration across Simulate and Execute modes."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .config import CleanupPolicy, RunnerProfile
from .contracts import ExecutionMode, ScenarioDefinition, StepOutcome
from .detections import DetectionCandidate, DetectionPipeline
from .evidence import (
    EvidenceError,
    EvidenceGraph,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)
from .planner import DeterministicPlanner, ExecutionDisposition, ExecutionPlan, PlanStep
from .policy import ApprovalState, PolicyDecision, PolicyEngine, PolicyStatus
from .registry import BehaviorRegistry
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
    ) -> None:
        self.registry = registry
        self.store = store
        self.runner = runner
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
        ai_enabled: bool = False,
        approval_present: bool = False,
    ) -> PreflightReport:
        problems: list[str] = []
        try:
            plan = self.planner.compile(
                scenario,
                mode=mode,
                profile=profile,
                ai_enabled=ai_enabled,
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
            ai_enabled=ai_enabled,
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
        approved_by: str | None = None,
        ai_enabled: bool = False,
        replay: Mapping[str, Any] | None = None,
        resume_from_step_id: str | None = None,
        seed_artifacts: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        preflight = self.preflight(
            scenario,
            mode=mode,
            profile=profile,
            ai_enabled=ai_enabled,
            approval_present=bool(approved_by and approved_by.strip()),
        )
        if not preflight.ready:
            raise OrchestrationError("; ".join(preflight.problems))

        plan = self.planner.compile(
            scenario,
            mode=mode,
            profile=profile,
            ai_enabled=ai_enabled,
        )
        runner_profile_doc: Mapping[str, Any] | None = None
        observer: SandboxObserver | None = None
        if mode is ExecutionMode.EXECUTE:
            if profile is None or sandbox_root is None or self.runner is None:
                raise OrchestrationError(
                    "Execute requires an explicit profile, sandbox root, and Rust runner"
                )
            network_destinations = self._network_destinations(plan)
            runner_profile_doc = build_runner_profile(
                profile,
                sandbox_root=sandbox_root,
                network_destinations=network_destinations,
            )
            observer = SandboxObserver(sandbox_root)
            self._validate_inventory(plan, self.runner.inventory())

        handle = self.store.create_run(
            scenario=scenario.to_dict(),
            plan=plan.to_dict(),
            policy={"schema_version": "bluefire.run-policy.v1", "preflight": preflight.to_dict()},
            profile=profile.to_dict() if profile else None,
            replay=replay,
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
                ai_enabled=ai_enabled,
                replay=replay,
                resume_from_step_id=resume_from_step_id,
                seed_artifacts=seed_artifacts,
                preflight=preflight,
                plan=plan,
                handle=handle,
                receipt_ids=receipt_ids,
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
        ai_enabled: bool,
        replay: Mapping[str, Any] | None,
        resume_from_step_id: str | None,
        seed_artifacts: Mapping[str, Any] | None,
        preflight: PreflightReport,
        plan: ExecutionPlan,
        handle: RunHandle,
        receipt_ids: list[str],
    ) -> Mapping[str, Any]:
        evidence = EvidenceGraph()
        artifacts: dict[str, Any] = dict(seed_artifacts or {})
        step_rows: list[dict[str, Any]] = []
        policy_rows: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        visited: set[str] = set()
        current_step_id: str | None = resume_from_step_id or scenario.start
        forced_cleanup = False
        counterfactual_step: str | None = None
        cleanup_attempted = False
        max_steps = profile.budgets.max_steps if profile else max(len(plan.steps) * 2, 1)

        while current_step_id and len(step_rows) < max_steps:
            if current_step_id in visited and not forced_cleanup:
                raise OrchestrationError("scenario traversal attempted to revisit a step")
            visited.add(current_step_id)
            scenario_step = scenario.step(current_step_id)
            plan_step = self._plan_step(plan, current_step_id)

            if counterfactual_step == current_step_id:
                parent_ids = tuple(step_rows[-1].get("evidence_ids", []) if step_rows else [])
                row, record = self._counterfactual_row(
                    run_id=handle.run_id,
                    step=plan_step,
                    parent_ids=parent_ids,
                )
                evidence.add(record)
                step_rows.append(row)
                self.store.append_event(handle.run_id, "step.counterfactual", row)
                current_step_id = None
                counterfactual_step = None
                continue

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
                row, records, decision, _returned_receipts = self._execute_step(
                    run_id=handle.run_id,
                    step=plan_step,
                    bound_inputs=bound_inputs,
                    parent_ids=parent_ids,
                    profile=profile,
                    runner_profile=runner_profile,
                    observer=observer,
                    approved_by=approved_by,
                    receipt_ids=receipt_ids,
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
            )
            decisions.append(planner_decision.to_dict())
            row["planner_decision_id"] = planner_decision.decision_id
            self.store.append_event(
                handle.run_id,
                "planner.decision",
                planner_decision.to_dict(),
            )
            current_step_id = planner_decision.selected_step_id
            forced_cleanup = False
            if planner_decision.execution_disposition is ExecutionDisposition.COUNTERFACTUAL:
                counterfactual_step = current_step_id

            if current_step_id is None and mode is ExecutionMode.EXECUTE and receipt_ids:
                cleanup_step = next(
                    (item for item in plan.steps if item.action_id == "sandbox.cleanup.v1"),
                    None,
                )
                if cleanup_step is not None and not cleanup_attempted:
                    current_step_id = cleanup_step.step_id
                    forced_cleanup = True
                    counterfactual_step = None

        if current_step_id is not None:
            raise OrchestrationError("run exceeded its step budget")

        detections = self._build_detections(evidence.records())
        cleanup_success = any(
            row.get("behavior_id") == "sandbox.cleanup.v1"
            and row.get("status") == StepOutcome.SUCCESS.value
            for row in step_rows
        )
        stage_success = any(
            row.get("behavior_id") == "sandbox.collection.stage.v1"
            and row.get("status") in {StepOutcome.SUCCESS.value, StepOutcome.PARTIAL.value}
            for row in step_rows
        )
        objective_reached = stage_success and (
            cleanup_success if mode is ExecutionMode.EXECUTE else True
        )
        result = {
            "schema_version": "bluefire.run-result.v1",
            "run_id": handle.run_id,
            "created_at": handle.created_at,
            "status": "completed" if objective_reached else "incomplete",
            "mode": mode.value,
            "ai_enabled": ai_enabled,
            "runner_profile_id": profile.id if profile else None,
            "scenario_id": scenario.id,
            "objective": scenario.purpose,
            "objective_reached": objective_reached,
            "steps": step_rows,
            "planner_decisions": decisions,
            "cleanup": {
                "attempted": cleanup_attempted if mode is ExecutionMode.EXECUTE else False,
                "success": cleanup_success if mode is ExecutionMode.EXECUTE else None,
                "outstanding_receipt_count": len(receipt_ids),
            },
            "replay": dict(replay) if replay else None,
            "limitations": list(scenario.limitations),
        }
        self.store.write_json(
            handle.run_id,
            "policy.json",
            {
                "schema_version": "bluefire.run-policy.v1",
                "preflight": preflight.to_dict(),
                "decisions": policy_rows,
            },
        )
        self.store.finalize(
            handle.run_id,
            result=result,
            evidence=(record.to_dict() for record in evidence.records()),
            detections=(candidate.to_dict() for candidate in detections),
        )
        return self.store.get_run(handle.run_id)

    def _attempt_emergency_cleanup(
        self,
        *,
        run_id: str,
        plan: ExecutionPlan,
        profile: RunnerProfile,
        runner_profile: Mapping[str, Any],
        observer: SandboxObserver,
        approved_by: str | None,
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
        receipt_ids: list[str],
    ) -> tuple[dict[str, Any], tuple[EvidenceRecord, ...], PolicyDecision, tuple[str, ...]]:
        action = self.registry.get_action(str(step.action_id))
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
            approved_by=approved_by,
        )
        target_scope = self._logical_scope(profile, adapted)
        approval = self._approval_state(
            manifest,
            action_id=action.id,
            profile_id=profile.id,
            target_scope=target_scope,
        )
        decision = self.policy.evaluate(
            step=step,
            action=action,
            mode=ExecutionMode.EXECUTE,
            profile=profile,
            platform=current_platform(),
            target_scope=target_scope,
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
                error={"code": "runner_transport_failed", "message": str(exc)},
            )
            return row, (record,), decision, ()

        for receipt_id in returned_receipts:
            if receipt_id not in receipt_ids:
                receipt_ids.append(receipt_id)

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
                    receipt_ids=returned_receipts,
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
                except (EvidenceError, OSError):
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
            receipts=returned_receipts,
            cleanup=runner_result.get("cleanup"),
            error=runner_result.get("error"),
        )
        return row, tuple(records), decision, returned_receipts

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
    def _logical_scope(profile: RunnerProfile, adapted: AdaptedAction) -> dict[str, Any]:
        refs = ["sandbox.workspace"]
        if adapted.network_destinations:
            refs.append("network.loopback")
        if adapted.params.get("destination") == "exports/bundle.bin":
            refs.append("export.local")
        references = [item for item in refs if item in profile.scope]
        result: dict[str, Any] = {"scope_refs": references}
        if adapted.network_destinations:
            destination = adapted.network_destinations[0]
            result["network_destination"] = f"{destination['host']}:{destination['port']}"
        return result

    @staticmethod
    def _approval_state(
        manifest: Mapping[str, Any],
        *,
        action_id: str,
        profile_id: str,
        target_scope: Mapping[str, Any],
    ) -> ApprovalState | None:
        approval = manifest.get("approval")
        if not isinstance(approval, Mapping):
            return None
        return ApprovalState(
            schema_version="bluefire.approval.v1",
            approved_by=str(approval["approved_by"]),
            issued_at=str(approval["approved_at"]),
            expires_at=str(approval["expires_at"]),
            request_hash=str(manifest["request_hash"]),
            action_id=action_id,
            runner_profile_id=profile_id,
            target_scope_digest=content_hash(target_scope),
            nonce="approval-" + uuid.uuid4().hex,
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
