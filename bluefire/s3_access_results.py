"""Finite saved S3 stages and safe projections, not native execution authority."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from .s3_access_contract import S3AccessError, S3AccessScope, digest, exact, timestamp
from .s3_access_policy import plan_hardening
from .util import content_hash

OWNER_KIND = "s3.access"
OPERATION_KIND = "s3.access.operation"
PHASES = {
    "inspect": ("inspect_policy",),
    "baseline": ("probe_read", "legitimate_read"),
    "apply": ("apply_policy",),
    "retest": ("probe_read", "legitimate_read"),
    "reconcile": ("reconcile_policy",),
    "rollback": ("rollback_policy",),
}
SEND_LIMITS = {
    "inspect_policy": 2,
    "probe_read": 4,
    "legitimate_read": 5,
    "apply_policy": 4,
    "rollback_policy": 4,
    "reconcile_policy": 2,
}
TERMINAL = {"completed", "failed", "cancelled", "interrupted"}
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_JOB = re.compile(r"job-[0-9a-f]{32}", re.ASCII)


def job_id(value: Any) -> str:
    if not isinstance(value, str) or _JOB.fullmatch(value) is None:
        raise S3AccessError("Select an exact saved S3 exercise.")
    return value


def submission(value: Any) -> str:
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError:
        raise S3AccessError("A canonical submission identity is required.") from None
    return value


def reviewer(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.strip()) <= 100
        or any(ord(char) < 32 for char in value)
    ):
        raise S3AccessError("An explicit bounded reviewer identity is required.")
    return value.strip()


def environment(value: Any) -> dict[str, Any]:
    row = exact(
        value,
        {"environment_id", "display_name", "scope", "baseline_policy", "exclusive_writer_digest"},
        "S3 environment",
    )
    if (
        not isinstance(row["environment_id"], str)
        or _REFERENCE.fullmatch(row["environment_id"]) is None
    ):
        raise S3AccessError("The enrolled environment reference is invalid.")
    if (
        not isinstance(row["display_name"], str)
        or not 1 <= len(row["display_name"].strip()) <= 100
        or any(ord(char) < 32 for char in row["display_name"])
    ):
        raise S3AccessError("The enrolled environment name is invalid.")
    scope = S3AccessScope.from_mapping(row["scope"])
    change = plan_hardening(scope, row["baseline_policy"])
    if row["exclusive_writer_digest"] is not None:
        digest(row["exclusive_writer_digest"])
    return {**row, "scope": scope.to_dict(), "baseline_policy": change.to_dict()["before"]}


def phase_budget(phase: str) -> dict[str, int]:
    if phase not in PHASES:
        raise S3AccessError("Select a supported S3 stage.")
    reads = phase in {"baseline", "retest"}
    return {
        "api_calls": sum(SEND_LIMITS[item] for item in PHASES[phase]),
        "business_attempts": 3 if reads else 0,
        "sessions": 2 if reads else 0,
        "policy_changes": int(phase == "apply"),
        "rollbacks": int(phase == "rollback"),
    }


def remaining(owner: Mapping[str, Any]) -> dict[str, int]:
    limits = owner["request"]["environment"]["scope"]["limits"]
    used = owner["progress"].get("reserved", {})
    return {name: max(0, limits[name] - used.get(name, 0)) for name in phase_budget("inspect")}


def required_remaining(owner: Mapping[str, Any], phase: str) -> dict[str, int]:
    required = phase_budget(phase)
    future: tuple[str, ...]
    if phase == "apply":
        future = ("retest", "reconcile", "rollback", "reconcile")
    elif phase == "rollback":
        future = ("reconcile",)
    elif phase in {"retest", "reconcile"} and remaining(owner)["rollbacks"]:
        future = ("rollback", "reconcile")
        if phase == "reconcile" and latest(owner, "retest") is None:
            future = ("retest", *future)
    else:
        future = ()
    for recovery in future:
        allowance = phase_budget(recovery)
        required = {name: amount + allowance[name] for name, amount in required.items()}
    return required


def stage_affordable(owner: Mapping[str, Any], phase: str) -> bool:
    required = required_remaining(owner, phase)
    available = remaining(owner)
    return all(available[name] >= amount for name, amount in required.items())


def latest(owner: Mapping[str, Any], phase: str) -> Mapping[str, Any] | None:
    rows = [row for row in owner["progress"].get("operations", []) if row["phase"] == phase]
    return rows[-1] if rows else None


def allowed_phases(owner: Mapping[str, Any]) -> list[str]:
    progress = owner["progress"]
    if progress.get("pending_operation"):
        return []
    history = progress.get("operations", [])
    if history and history[-1]["outcome"]["cleanup"] != "verified":
        return []
    uncertain = bool(
        history and history[-1]["outcome"]["state"] in {"uncertain", "drift", "failed"}
    )
    applied = latest(owner, "apply")
    rolled_back = latest(owner, "rollback")
    reconciliation = latest(owner, "reconcile")
    policy = progress.get("policy_state", "baseline")
    if rolled_back and rolled_back["outcome"]["state"] == "observed":
        return []
    if not applied and not reconciliation and not progress.get("stopped"):
        inspected = latest(owner, "inspect")
        baseline = latest(owner, "baseline")
        if inspected is None or inspected["outcome"]["state"] != "observed":
            choices = ["inspect"]
        elif baseline is None or baseline["outcome"]["state"] != "observed":
            choices = ["baseline"]
        else:
            choices = ["apply"]
    elif uncertain:
        choices = ["reconcile"] if applied else []
    elif policy == "hardened":
        choices = ["rollback", "reconcile"]
        if latest(owner, "retest") is None and not progress.get("stopped"):
            choices.insert(0, "retest")
    elif progress.get("stopped") or applied or reconciliation:
        choices = ["reconcile"] if applied else []
    else:
        choices = []
    return [phase for phase in choices if stage_affordable(owner, phase)]


def assert_phase_current(scope: S3AccessScope, phase: str, now: datetime) -> None:
    scope.assert_current(clock=lambda: now)
    row = scope.to_dict()
    if phase not in {"reconcile", "rollback"} and now >= timestamp(row["created_at"]) + timedelta(
        seconds=row["limits"]["business_seconds"]
    ):
        raise S3AccessError("The business window ended; only scoped recovery remains available.")


def outcome(phase: str, executions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Project already contract-validated runner results without independent claims."""
    complete = len(executions) == len(PHASES[phase])
    cleanup = (
        "verified"
        if executions and all(row["cleanup"] == "verified" for row in executions)
        else "unknown"
    )
    observed = complete and all(
        row["admission"]["accepted"]
        and row["result"] is not None
        and row["result"]["outcome"] == "observed"
        for row in executions
    )
    facts: list[dict[str, Any]] = []
    for execution in executions:
        result = execution["result"]
        if result and result["outcome"] == "observed" and "objects" in result["data"]:
            facts.extend(
                {"reader": result["data"]["reader"], **item} for item in result["data"]["objects"]
            )
    state = "observed" if observed else "failed"
    if cleanup != "verified" or any(
        row["dispatch"] == "unknown"
        or (row["result"] and row["result"]["outcome"] == "reconcile_required")
        for row in executions
    ):
        state = "uncertain"
    if phase == "baseline" and observed and any(row["result"] != "read" for row in facts):
        state = "baseline_failed"
    if phase == "retest" and observed:
        state = (
            "denied_with_legitimate_reads"
            if facts
            == [
                {"reader": "probe", "purpose": "primary", "result": "service_denied"},
                *[
                    row
                    for row in facts[1:]
                    if row["reader"] == "legitimate" and row["result"] == "read"
                ],
            ]
            and len(facts) == 3
            else "defense_not_confirmed"
        )
    policy = None
    if phase == "reconcile" and observed:
        policy = executions[0]["result"]["data"]["structural_review"]
        if policy == "drift":
            state = "drift"
    return {
        "state": state,
        "cleanup": cleanup,
        "facts": facts,
        "policy_observation": policy,
        "complete": complete,
        "provenance": (
            "synthetic"
            if any(row["provenance"] == "synthetic" for row in executions)
            else "runner_reported"
        ),
        "independent_observations": 0,
        "audit": "not_collected",
        "resource_disposition": "retained",
    }


def review_document(owner: Mapping[str, Any], phase: str) -> dict[str, Any]:
    selected = owner["request"]["environment"]
    scope = S3AccessScope.from_mapping(selected["scope"])
    change = plan_hardening(scope, selected["baseline_policy"])
    value = {
        "schema_version": "bluefire.s3-stage-review.v1",
        "workflow_job_id": owner["job_id"],
        "phase": phase,
        "revision": owner["progress"].get("revision", 0),
        "environment_id": selected["environment_id"],
        "scope_digest": scope.digest,
        "runtime": owner["request"]["runtime"],
        "remaining": remaining(owner),
        "reserved": phase_budget(phase),
        "required_remaining": required_remaining(owner, phase),
        "policy_change": change.to_dict() if phase in {"apply", "rollback", "reconcile"} else None,
        "prior_run_ids": [
            run for row in owner["progress"].get("operations", []) for run in row["run_ids"]
        ],
    }
    return {**value, "review_digest": content_hash(value)}


def now() -> datetime:
    return datetime.now(timezone.utc)
