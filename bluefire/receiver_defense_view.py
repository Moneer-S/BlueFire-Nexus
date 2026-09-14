"""Read-only receiver comparison status without process adoption or renewal."""

from __future__ import annotations

from . import product_store_receiver_defense as records
from .application_errors import APIError
from .product_store_errors import ProductStoreError
from .receiver_defense_context import LIMITATIONS, PHASES, POLICIES
from .receiver_defense_result import verified_result
from .util import content_hash


def visible_job(coordinator, identifier):
    try:
        return coordinator.service.job(identifier)
    except APIError as exc:
        if exc.status == 404:
            return None
        raise


def attempt(coordinator, phase, reservation):
    view = {
        "phase": phase,
        "policy_id": POLICIES[PHASES.index(phase)],
        "status": "not_started",
        "receiver_job": None,
        "preparation": None,
        "decision": None,
        "execution_job": None,
        "result": None,
        "cleanup": {"receiver": "not_started", "run": "not_started"},
        "problem": None,
    }
    if reservation is None:
        return view
    try:
        child = visible_job(coordinator, reservation["receiver_job_id"])
        if child is None:
            raise ProductStoreError("Receiver publication is absent.")
    except ProductStoreError:
        view.update(
            status="interrupted",
            problem={
                "code": "receiver_publication_uncertain",
                "message": "The exact reserved preparation is not attached. Retry only its original submission.",
            },
        )
        return view
    prepared = records.preparation(child)
    progress = child["progress"]
    view.update(
        receiver_job=child,
        preparation=prepared,
        decision=progress.get("decision"),
        result=verified_result(coordinator, child),
        problem=progress.get("problem"),
    )
    execution_id = progress.get("execution_job_id")
    if execution_id:
        try:
            execution = visible_job(coordinator, execution_id)
        except (ProductStoreError, KeyError):
            execution = None
        view["execution_job"] = execution
    result = view["result"]
    if result is not None:
        child = {
            **child,
            "progress": {**progress, "result": result, "result_digest": content_hash(result)},
        }
        view["receiver_job"] = child
    view["cleanup"] = (
        result["cleanup"]
        if result
        else {
            "receiver": (
                "verified_closed"
                if progress.get("receiver_closed")
                else (
                    "active"
                    if prepared
                    and coordinator.owners.reviewable(child["job_id"], prepared["session"])
                    else "uncertain" if progress.get("prepare_started") else "not_started"
                )
            ),
            "run": "pending" if progress.get("execution_started") else "not_started",
        }
    )
    execution = view["execution_job"]
    if result:
        view["status"] = "completed" if records.phase_verified(child, phase) else "failed"
        if view["status"] == "failed" and view["problem"] is None:
            view["problem"] = {
                "code": "receiver_result_insufficient",
                "message": "This phase did not establish the expected authenticated policy decision and complete cleanup. Review the actual run and receiver evidence.",
            }
    elif execution:
        view["status"] = {
            "queued": "running",
            "planning": "running",
            "awaiting_approval": "awaiting_approval",
            "running": "running",
            "paused": "running",
            "cancelling": "stopping",
            "cancelled": "stopped",
            "completed": "interrupted",
            "failed": "failed",
            "interrupted": "interrupted",
        }.get(execution["state"], "interrupted")
    elif progress.get("decision", {}).get("decision") == "reject":
        view["status"] = "declined"
    elif prepared and child["state"] in {"completed", "interrupted"}:
        view["status"] = "review_ready"
    else:
        view["status"] = {
            "queued": "preparing",
            "planning": "preparing",
            "running": "preparing",
            "cancelling": "stopping",
            "cancelled": "stopped",
            "failed": "failed",
            "interrupted": "interrupted",
        }.get(child["state"], "interrupted")
    if (
        prepared
        and not execution
        and not progress.get("receiver_closed")
        and not coordinator.owners.reviewable(child["job_id"], prepared["session"])
    ):
        view["status"] = "interrupted"
        view["problem"] = {
            "code": "receiver_session_unavailable",
            "message": "The receiver expired or its live ownership was lost. Explicit preparation requires verified cleanup and a fresh approval; execution will not be repeated.",
        }
    return view


def read(coordinator, parent):
    phases = []
    stopped = parent["progress"].get("stopped") is True
    admission = parent["progress"]["admission"]
    admitted = parent["state"] == "completed" and admission == {"accepted": True, "problem": None}
    preceding = True
    for phase in PHASES:
        current = attempt(coordinator, phase, parent["progress"].get("phases", {}).get(phase))
        current["attempts"] = [
            attempt(coordinator, phase, old)
            for old in parent["progress"].get("attempt_history", [])
            if old["phase"] == phase
        ]
        child = current["receiver_job"]
        progress = child["progress"] if child else {}
        untouched = not progress.get("execution_started") and not progress.get("task_binding")
        current["prepare_allowed"] = (
            admitted
            and not stopped
            and preceding
            and (
                child is None
                or (
                    untouched
                    and current["status"] in {"failed", "interrupted", "stopped"}
                    and current["cleanup"]["receiver"] != "uncertain"
                )
            )
        )
        current["review_ready"] = bool(
            not stopped
            and current["status"] == "review_ready"
            and child
            and current["decision"] is None
            and coordinator.owners.reviewable(child["job_id"], current["preparation"]["session"])
        )
        phases.append(current)
        preceding = preceding and child is not None and records.phase_verified(child, phase)
    phases_completed = all(item["status"] == "completed" for item in phases)
    owners_settled = all(
        item["cleanup"]["receiver"] in {"not_started", "verified_closed"}
        and item["cleanup"]["run"] in {"not_started", "complete"}
        and item["status"] not in {"running", "preparing", "awaiting_approval", "stopping"}
        and (
            item["execution_job"] is None
            or item["execution_job"]["state"] in {"completed", "failed", "cancelled", "interrupted"}
        )
        for phase in phases
        for item in [phase, *phase["attempts"]]
    )
    completed = phases_completed and owners_settled
    status = (
        "completed"
        if completed
        else "stopped" if stopped and owners_settled else "stopping" if stopped else "active"
    )
    if not admitted and parent["state"] in {"failed", "cancelled", "interrupted"} and not stopped:
        status = "blocked"
    next_action = {
        "kind": "completed" if completed else "stopped" if stopped and owners_settled else "wait",
        "phase": None,
        "native_path": None,
    }
    if not stopped and not completed:
        for phase in phases:
            if phase["status"] == "completed":
                continue
            next_action["phase"] = phase["phase"]
            if phase["prepare_allowed"]:
                next_action["kind"] = "prepare_receiver"
            elif phase["review_ready"]:
                next_action["kind"] = "review_replay"
            elif phase["status"] == "awaiting_approval":
                next_action.update(
                    kind="approve_execute",
                    native_path="/runs?job=" + phase["execution_job"]["job_id"],
                )
            elif phase["status"] in {"failed", "interrupted", "declined", "stopped"}:
                status = "blocked"
                next_action["kind"] = "cleanup_required"
            break
    return {
        "schema_version": "bluefire.receiver-defense.v1",
        "job": coordinator.service.job(parent["job_id"]),
        "context": parent["request"]["context"],
        "phases": phases,
        "status": status,
        "admission": admission,
        "next_action": next_action,
        "can_start_new_test": owners_settled and (completed or stopped or status == "blocked"),
        "limitations": LIMITATIONS,
    }
