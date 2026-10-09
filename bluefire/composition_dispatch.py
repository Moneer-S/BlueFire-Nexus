"""Grant hooks on the existing orchestrator, without a separate execution loop."""

from collections.abc import Mapping
from typing import Any

from .contracts import StepOutcome
from .evidence import EvidenceRecord
from .policy import GrantPolicyState, PolicyDecision
from .runner_client import RunnerTransportError
from .util import content_hash


def step_authority(
    engine, *, action, runner_profile, adapted, observer, profile, run_id, step, parent_ids
) -> tuple[
    dict[str, Any],
    tuple[dict[str, Any], tuple[EvidenceRecord, ...], PolicyDecision, tuple[str, ...]] | None,
]:
    execution = engine.grant_execution
    if execution is None:
        return {}, None
    if action.id != "sandbox.cleanup.v1":
        execution.check()
        return {"grant_attempt": execution.authority}, None
    receipts: dict[str, dict[str, Any]] = {}
    engine._discover_runner_receipts(
        observer.root, expected_profile_id=profile.id, _documents=receipts
    )
    authority = execution.cleanup_authority(runner_profile, adapted.params, receipts)
    if authority is not None:
        return {"grant_cleanup": authority}, None
    decision = engine._adapter_refusal(
        step, profile, "No owned native effects require a cleanup task."
    )
    record = engine._control_record(run_id, step, decision, parent_ids)
    row = engine._row(
        step,
        StepOutcome.BLOCKED,
        artifacts={},
        telemetry=("cleanup.not_required",),
        evidence_ids=(record.evidence_id,),
        execution_disposition="not_dispatched",
        policy=decision.to_dict(),
    )
    return {}, (row, (record,), decision, ())


def policy_state(
    execution, manifest, action_id, profile_id, target_scope, *, error_type=ValueError
):
    if execution is None:
        return None
    key = "grant_cleanup" if "grant_cleanup" in manifest else "grant_attempt"
    document = manifest.get(key)
    if not isinstance(document, Mapping):
        raise error_type("Grant-owned manifest lost its delegated authority")
    return GrantPolicyState(
        authority_kind="capability_" + key,
        issued_at=document["issued_at"],
        expires_at=document["expires_at"],
        request_hash=manifest["request_hash"],
        action_id=action_id,
        runner_profile_id=profile_id,
        target_scope_digest=content_hash(target_scope),
    )


def before_task(execution, step, inputs, manifest, task_id, cancel_event):
    if execution is None:
        return
    execution.before_task(step, inputs, manifest, task_id)
    if cancel_event is not None and cancel_event.is_set():
        raise RunnerTransportError("Grant-owned execution was cancelled before dispatch.")


def after_result(execution, step, manifest, task_id, result, receipts):
    if execution is not None:
        execution.after_task(step, manifest, task_id, result, observed_receipt_ids=tuple(receipts))


def after_cancellation(execution, step, manifest, task_id, cancellation):
    if execution is not None and cancellation.control_cleanup_verified:
        execution.after_task(
            step,
            manifest,
            task_id,
            {
                "schema_version": "bluefire.authenticated-task-cancelled.v1",
                "task_id": task_id,
                "request_hash": manifest["request_hash"],
                "cooperative_acknowledged": cancellation.cooperative_acknowledged,
                "forced_tree_termination": cancellation.forced_tree_termination,
                "control_cleanup_verified": True,
            },
        )


def after_unsent(execution, step, manifest, task_id, *, dispatch_requested, runner_task_id):
    if execution is not None and not dispatch_requested and runner_task_id is not None:
        execution.after_task(
            step,
            manifest,
            task_id,
            {
                "schema_version": "bluefire.task-not-sent.v1",
                "task_id": task_id,
                "request_hash": manifest["request_hash"],
            },
        )
