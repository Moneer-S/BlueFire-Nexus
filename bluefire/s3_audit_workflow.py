"""Pure saved-workflow audit slots, prospective holds and minimized projections."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Mapping

from . import s3_audit_collection_contract as contract
from .s3_access_contract import S3AccessError, S3AccessScope, exact, timestamp
from .util import content_hash, json_clone

PHASES = {"audit_baseline": ("collect_audit",), "audit_retest": ("collect_audit",)}
# Root releases this only after connected application/native/UI acceptance.
DISPATCH_RELEASED = False


def enrolled(owner: Mapping[str, Any]) -> bool:
    return "audit_source" in owner["request"]["environment"]


def commitment(owner: Mapping[str, Any]) -> dict[str, Any]:
    selected = owner["request"]["environment"]
    return contract.build_workflow(
        S3AccessScope.from_mapping(selected["scope"]),
        selected["audit_source"],
        workflow_job_id=owner["job_id"],
        environment_id=selected["environment_id"],
    )


def initial(owner: Mapping[str, Any]) -> dict[str, Any]:
    return {"audit_workflow": commitment(owner), "audit_read_slots": {}, "audit_slots": {}}


def retained(owner: Mapping[str, Any]) -> bool:
    """Legacy saved work never acquires new audit authority implicitly."""
    if not enrolled(owner):
        return False
    progress = owner["progress"]
    if "audit_workflow" not in progress:
        return False
    if progress["audit_workflow"] != commitment(owner):
        raise S3AccessError("The saved audit commitment changed.")
    for name in ("audit_read_slots", "audit_slots"):
        slots = progress.get(name)
        if not isinstance(slots, dict) or set(slots) - {"baseline", "retest"}:
            raise S3AccessError("The saved audit slots are invalid.")
        identifiers = []
        for row in slots.values():
            fields = {"operation_job_id"}
            if name == "audit_slots":
                fields |= {"review_digest", "pair_digest", "source_digest"}
            exact(row, fields, "saved audit slot")
            contract.text(row["operation_job_id"], contract._JOB, "audit operation identity")
            identifiers.append(row["operation_job_id"])
            for field in fields - {"operation_job_id"}:
                contract.digest(row[field])
        if len(identifiers) != len(set(identifiers)):
            raise S3AccessError("Audit phase slots cannot share an operation.")
    return True


def extra_holds(owner, phase: str, covered: set[str]) -> dict[str, int]:
    result = {"api_calls": 0, "business_attempts": 0, "sessions": 0}
    if not enrolled(owner):
        return result
    if not retained(owner):
        return result
    reads = owner["progress"]["audit_read_slots"]
    slots = owner["progress"]["audit_slots"]
    for original in ("baseline", "retest"):
        if original not in reads and original not in covered:
            result["api_calls"] += 9
            result["business_attempts"] += 3
            result["sessions"] += 2
        stage = "audit_" + original
        if original not in slots and stage != phase:
            result["api_calls"] += 9
            result["sessions"] += 1
    return result


def pair_available(owner, phase: str) -> bool:
    if not retained(owner):
        return False
    claim = owner["progress"]["audit_read_slots"].get(phase)
    if claim is None:
        return False
    rows = [
        row
        for row in owner["progress"]["operations"]
        if row["operation_job_id"] == claim["operation_job_id"] and row["phase"] == phase
    ]
    return bool(
        len(rows) == 1
        and len(rows[0]["run_ids"]) == 2
        and len(rows[0]["executions"]) == 2
        and all(
            row["cleanup"] == "verified"
            and row["result"] is not None
            and row["provenance"] == "runner_reported"
            and row["reservation_digest"] is not None
            for row in rows[0]["executions"]
        )
    )


def eligible(owner, stage: str) -> bool:
    if stage not in PHASES or not DISPATCH_RELEASED or not retained(owner):
        return False
    progress = owner["progress"]
    if progress.get("pending_operation") or progress.get("stopped"):
        return False
    if any(row["outcome"]["cleanup"] != "verified" for row in progress["operations"]):
        return False
    phase = stage.removeprefix("audit_")
    return phase not in progress["audit_slots"] and pair_available(owner, phase)


def absolute_expiry(owner, pair) -> str:
    bound = owner["request"]["environment"]["scope"]
    starts = [
        max(
            timestamp(bound["created_at"]),
            timestamp(row["request"]["deadline"])
            - timedelta(seconds=bound["limits"]["request_seconds"]),
        )
        for row in pair["reads"]
    ]
    end = min(
        timestamp(commitment(owner)["source"]["expires_at"]),
        min(starts) + timedelta(seconds=bound["limits"]["audit_seconds"]),
    )
    return end.isoformat().replace("+00:00", "Z")


def stage_review(owner, stage: str, pair, listing_date: str) -> dict[str, Any]:
    if stage not in PHASES or not retained(owner):
        raise S3AccessError("Select an explicitly enrolled audit stage.")
    scope = S3AccessScope.from_mapping(owner["request"]["environment"]["scope"])
    pair = contract.original_pair(scope, pair)
    source = commitment(owner)["source"]
    if not isinstance(listing_date, str) or len(listing_date) != 10:
        raise S3AccessError("The reviewed UTC listing date is invalid.")
    instant = timestamp(listing_date + "T00:00:00Z")
    if instant.date().isoformat() != listing_date:
        raise S3AccessError("The reviewed UTC listing date is invalid.")
    expiry = absolute_expiry(owner, pair)
    if pair["phase"] != stage.removeprefix("audit_") or instant >= timestamp(expiry):
        raise S3AccessError("The original paired audit interval is unavailable.")
    listed_at = instant.isoformat().replace("+00:00", "Z")
    return {
        "schema_version": "bluefire.s3-audit-stage-review.v1",
        "source": source,
        "source_digest": content_hash(source),
        "original_pair": pair,
        "pair_digest": content_hash(pair),
        "listing_date": listing_date,
        "collection_expires_at": expiry,
        "list_parameters": contract._listed(
            scope, {"source": source, "original_pair": pair, "issued_at": listed_at}
        ),
    }


def request_fields(owner, stage, review, operation_id, launch_id, request_id, issued_at):
    from .s3_audit_wire import REQUEST_SCHEMA

    checked = stage_review(owner, stage, review["original_pair"], review["listing_date"])
    if checked != review:
        raise S3AccessError("The original paired audit review changed.")
    scope = S3AccessScope.from_mapping(owner["request"]["environment"]["scope"])
    limits = commitment(owner)["budget"]["per_batch"]
    instant = timestamp(issued_at)
    deadline = min(
        instant + timedelta(seconds=limits["seconds"]), timestamp(review["collection_expires_at"])
    )
    value = contract.collection(
        scope,
        {
            "schema_version": contract.COLLECTION_SCHEMA,
            "launch_id": launch_id,
            "request_id": request_id,
            "source": review["source"],
            "workflow_job_id": owner["job_id"],
            "operation_job_id": operation_id,
            "issued_at": issued_at,
            "deadline": deadline.isoformat().replace("+00:00", "Z"),
            "original_pair": review["original_pair"],
        },
    )
    if contract.list_parameters(scope, value) != review["list_parameters"]:
        raise S3AccessError("The dated listing window needs a new review.")
    return {
        "schema_version": REQUEST_SCHEMA,
        "deadline": value["deadline"],
        "audit_authority_digest": content_hash(value["source"]),
        "audit": value,
    }


def projection(owner, pairs, problem):
    value = commitment(owner)
    active = retained(owner)
    claims = owner["progress"].get("audit_slots", {}) if active else {}
    used = len(claims)
    budget = value["budget"]
    reserved = {key: amount * used // 2 for key, amount in budget["workflow"].items()}
    held = {key: amount - reserved[key] for key, amount in budget["workflow"].items()}
    slots = []
    for phase in ("baseline", "retest"):
        claim = claims.get(phase)
        row = next(
            (
                row
                for row in owner["progress"]["operations"]
                if claim and row["operation_job_id"] == claim["operation_job_id"]
            ),
            None,
        )
        pair = pairs.get(phase)
        reason = problem.get(phase)
        if not active:
            reason = "historical_authority_absent"
        elif claim:
            reason = "phase_consumed"
        elif owner["progress"].get("stopped"):
            reason = "stopped"
        elif owner["progress"].get("pending_operation"):
            reason = "operation_pending"
        elif any(
            row["outcome"]["cleanup"] != "verified" for row in owner["progress"]["operations"]
        ):
            reason = "cleanup_unknown"
        elif pair is None:
            reason = "original_pair_unavailable"
        elif reason is None and not DISPATCH_RELEASED:
            reason = "collection_not_enabled"
        state = "ready" if reason is None else "unavailable"
        if claim:
            state = (
                "reserved"
                if row is None
                else ("completed" if row["outcome"]["state"] == "observed" else "failed")
            )
        slots.append(
            {
                "phase": phase,
                "stage": "audit_" + phase,
                "state": state,
                "problem": reason,
                "operation_job_id": claim["operation_job_id"] if claim else None,
                "review_id": claim["operation_job_id"] if state == "completed" else None,
                "original_pair": pair,
            }
        )
    return json_clone(
        {
            "schema_version": "bluefire.s3-audit-workspace.v1",
            "source": value["source"],
            "source_digest": content_hash(value["source"]),
            "workflow_digest": content_hash(value),
            "budget": budget,
            "reserved": reserved,
            "held": held,
            "slots": slots,
        }
    )
