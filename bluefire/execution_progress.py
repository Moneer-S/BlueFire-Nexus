"""Durable partial Execute observations and bounded compensating cleanup."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from .contracts import StepOutcome
from .evidence import EvidenceProvenance, EvidenceRecord
from .planner import ExecutionPlan, PlanStep
from .run_store import RunStore
from .runner_transport_errors import RunnerTaskCancelled


def persist_progress(
    store: RunStore,
    run_id: str,
    *,
    steps: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    proposals: Sequence[Mapping[str, Any]],
    evidence: Sequence[EvidenceRecord],
    retries_used: int,
) -> None:
    """Retain completed observations before the next cancellable boundary.

    Keep the existing unfinished status: this is neither a final verdict nor a
    replay checkpoint. Evidence is persisted first so a step never points to an
    observation that existed only in the orchestrator's memory.
    """
    store.write_json(
        run_id,
        "evidence.json",
        {"schema_version": "1.0", "records": [record.to_dict() for record in evidence]},
    )
    result = dict(store.read_json(run_id, "result.json"))
    result.update(
        steps=list(steps),
        planner_decisions=list(decisions),
        ai_proposals=list(proposals),
        adaptive_retry={"used": retries_used, "maximum": 1},
        objective_evaluation={"status": "not_evaluated", "reason": "execution_incomplete"},
    )
    store.write_json(run_id, "result.json", result)


def record_interrupted_dispatch(
    *,
    store: RunStore,
    run_id: str,
    step: PlanStep,
    manifest: Mapping[str, Any],
    runner_task_id: str | None,
    parent_ids: Sequence[str],
    dispatch_requested: bool,
    cancellation: RunnerTaskCancelled,
    row_factory: Callable[..., dict[str, Any]],
) -> None:
    """Record transport cancellation without inventing a runner result or effect."""
    interruption = {
        "schema_version": "bluefire.execution-interruption.v1",
        "dispatch_requested": dispatch_requested,
        "effect_outcome": "unknown",
        "runner_result_received": False,
        "process_tree_stopped": True,
        "cooperative_requested": cancellation.cooperative_requested,
        "cooperative_acknowledged": cancellation.cooperative_acknowledged,
        "forced_tree_termination": cancellation.forced_tree_termination,
        "control_cleanup_verified": cancellation.control_cleanup_verified,
    }
    identity = {"request_hash": manifest["request_hash"]}
    if runner_task_id is not None:
        identity["runner_task_id"] = runner_task_id
    record = EvidenceRecord.create(
        run_id=run_id,
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action_id=step.action_id,
        provenance=EvidenceProvenance.UNKNOWN,
        producer="orchestrator.v1",
        parent_evidence_ids=parent_ids,
        runner_profile_id=str(manifest["runner_profile_id"]),
        content={"artifact_type": "execution_interruption", **identity, **interruption},
        confidence=0.0,
        limitations=("Cancellation returned no validated runner effect result.",),
        target_scope_ref=f"runner-profile:{manifest['runner_profile_id']}",
    )
    current = store.read_json(run_id, "evidence.json")
    store.write_json(
        run_id,
        "evidence.json",
        {
            **current,
            "records": [*current.get("records", []), record.to_dict()],
        },
    )
    row = row_factory(
        step,
        StepOutcome.FAILED,
        artifacts={},
        telemetry=(),
        evidence_ids=(record.evidence_id,),
        execution_disposition="execute",
        interruption=interruption,
        **identity,
        error={
            "code": "execution_interrupted",
            "message": "Dispatch interrupted; effects unknown.",
        },
    )
    result = dict(store.read_json(run_id, "result.json"))
    result["steps"] = [*result.get("steps", []), row]
    result["objective_evaluation"] = {"status": "not_evaluated", "reason": "execution_interrupted"}
    store.write_json(run_id, "result.json", result)
    store.append_event(run_id, "step.interrupted", row)


def emergency_cleanup(
    *,
    store: RunStore,
    run_id: str,
    plan: ExecutionPlan,
    runner_opcode: Callable[[PlanStep], str | None],
    execute_step: Callable[..., Any],
    receipt_ids: list[str],
    execution_arguments: Mapping[str, Any],
) -> None:
    """Attempt the plan's cleanup without masking the original interruption."""
    cleanup_step = next(
        (item for item in plan.steps if runner_opcode(item) == "sandbox.cleanup.v1"), None
    )
    if cleanup_step is None or not receipt_ids:
        return
    status = "failed"
    try:
        row, records, _decision, _returned = execute_step(
            run_id=run_id,
            step=cleanup_step,
            bound_inputs={},
            parent_ids=(),
            receipt_ids=receipt_ids,
            **execution_arguments,
        )
        status = str(row["status"])
        if status == "success":
            receipt_ids.clear()
        # Preserve the actual cleanup result, even if later settlement must
        # independently reconcile receipts before it can finalize the run.
        current = store.read_json(run_id, "evidence.json")
        store.write_json(
            run_id,
            "evidence.json",
            {
                **current,
                "records": [*current.get("records", []), *(item.to_dict() for item in records)],
            },
        )
        store.append_event(run_id, "cleanup.emergency.result", row)
    except BaseException:
        status = "failed"
    try:
        store.append_event(
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
