"""Saved fixture receipts and review projections, never execution authority."""

from __future__ import annotations

from typing import Any, Mapping, cast

from . import s3_fixture_contract as contract
from .s3_access_contract import S3AccessError, S3AccessScope

PHASES = {
    "prepare": ("prepare_fixture", "prepare_fixture"),
    "reconcile_fixtures": ("reconcile_fixture", "reconcile_fixture"),
    "cleanup": ("cleanup_fixture", "cleanup_fixture"),
}
RECOVERY_PHASES = {"reconcile", "rollback", "reconcile_fixtures", "cleanup"}


def enabled(owner: Mapping[str, Any]) -> bool:
    return "fixture_lifecycle" in owner["request"]["environment"]


def receipts(owner: Mapping[str, Any]) -> list[dict[str, Any]]:
    selected = owner["request"]["environment"]
    intent = owner["request"]["fixture_intent_id"]
    rows = [
        {
            **obj,
            "state": "not_prepared",
            "etag": None,
            "intent_id": intent,
            "request_ids": [],
            "provenance": "not_observed",
        }
        for obj in selected["scope"]["objects"]
    ]
    for stage in owner["progress"].get("operations", []):
        if stage["phase"] not in PHASES:
            continue
        for index, execution in enumerate(stage["executions"]):
            row, result = rows[index], execution["result"]
            calls = result["calls"] if result else []
            if result and result["outcome"] == "observed":
                row.update(
                    state=result["data"]["state"],
                    etag=result["data"]["etag"],
                    request_ids=[call["request_id"] for call in calls],
                    provenance=execution["provenance"],
                )
            elif (
                stage["phase"] == "prepare"
                or (stage["phase"] == "cleanup" and row["state"] == "owned")
            ) and (execution["dispatch"] == "unknown" or execution["send_debits"] >= 5):
                row.update(
                    state="uncertain",
                    etag=None,
                    request_ids=[call["request_id"] for call in calls],
                    provenance=execution["provenance"],
                )
            # A failed read does not replace the last exact observation. It
            # remains in history and still requires another explicit review.
    return rows


def aggregate(rows: list[dict[str, Any]]) -> str:
    states = {row["state"] for row in rows}
    for unresolved in ("uncertain", "drift"):
        if unresolved in states:
            return unresolved
    if len(states) == 1:
        return cast(str, next(iter(states)))
    return "partial"


def projection(owner: Mapping[str, Any]) -> dict[str, Any]:
    rows = receipts(owner)
    state = aggregate(rows)
    disposition = (
        "not_prepared"
        if state == "not_prepared"
        else (
            "removed"
            if state == "absent"
            else "retained" if state == "owned" else "cleanup_required"
        )
    )
    return {
        "schema_version": "bluefire.s3-exercise.v2",
        "fixture_state": state,
        "fixtures": rows,
        "policy_retention": owner["progress"].get("policy_retention"),
        "resource_disposition": disposition,
    }


def choices(owner: Mapping[str, Any], ordinary: list[str]) -> list[str]:
    history = owner["progress"].get("operations", [])
    if owner["progress"].get("policy_state") not in {"baseline", "hardened"}:
        return [phase for phase in ordinary if phase == "reconcile"]
    prepared = any(row["phase"] == "prepare" for row in history)
    cleanups = sum(1 for row in history if row["phase"] == "cleanup")
    state = aggregate(receipts(owner))
    if not prepared:
        return ["prepare"] if not owner["progress"].get("stopped") else []
    if cleanups:
        if state == "absent":
            return []
        owned = {row["purpose"] for row in receipts(owner) if row["state"] == "owned"}
        if cleanups < 2 and state == "partial" and owned and not owned & deletion_attempts(owner):
            return ["cleanup", "reconcile_fixtures"]
        return ["reconcile_fixtures"]
    if state in {"uncertain", "drift"}:
        return ["reconcile_fixtures"]
    if state == "not_prepared":
        return ["reconcile_fixtures"]
    if state in {"partial", "absent"}:
        return ["cleanup", "reconcile_fixtures"]
    return [*ordinary, "cleanup", "reconcile_fixtures"]


def recovery_floor(owner: Mapping[str, Any], phase: str) -> int:
    """Reserved sends are never refunded; protect one bounded cleanup recovery."""
    cleanups = sum(
        1 for row in owner["progress"].get("operations", []) if row["phase"] == "cleanup"
    )
    remaining = max(0, 2 - cleanups)
    if phase == "prepare":
        return 58
    if phase == "cleanup":
        return 10 + max(0, remaining - 1) * 24
    return remaining * 24


def deletion_attempts(owner: Mapping[str, Any]) -> set[str]:
    attempted: set[str] = set()
    history = owner["progress"].get("operations", [])
    for position, stage in enumerate(history):
        if stage["phase"] != "cleanup":
            continue
        before = {**owner, "progress": {**owner["progress"], "operations": history[:position]}}
        previous = receipts(before)
        for index, execution in enumerate(stage["executions"]):
            if previous[index]["state"] == "owned" and (
                (execution["admission"]["accepted"] and execution["reservation_digest"] is not None)
                or execution["dispatch"] == "unknown"
            ):
                attempted.add(previous[index]["purpose"])
    return attempted


def review(owner: Mapping[str, Any], phase: str) -> dict[str, Any] | None:
    if phase not in PHASES:
        return None
    selected = owner["request"]["environment"]
    scope = S3AccessScope.from_mapping(selected["scope"])
    rows = receipts(owner)
    return {
        "authority_digest": contract.authority_digest(scope, selected["fixture_lifecycle"]),
        "intent_id": owner["request"]["fixture_intent_id"],
        "objects": [
            {
                "purpose": row["purpose"],
                "key": row["key"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "payload_preview": contract.payload(
                    scope.to_dict()["scope_id"], row["purpose"]
                ).decode("ascii"),
                "expected_etag": row["etag"] if phase != "prepare" else None,
            }
            for row in rows
        ],
        "policy_disposition": "retain_current",
        "policy_state": owner["progress"]["policy_state"],
    }


def request_fields(
    owner: Mapping[str, Any], phase: str, index: int, retained_review=None
) -> dict[str, Any]:
    if phase not in PHASES:
        return {"schema_version": "bluefire.s3-worker-request.v1"}
    value = (
        review(owner, phase) if retained_review is None else retained_review["fixture_lifecycle"]
    )
    if not isinstance(value, dict):
        raise S3AccessError("The fixture request lacks its exact saved review.")
    selected = owner["request"]["environment"]
    scope = S3AccessScope.from_mapping(selected["scope"])
    if (
        value["authority_digest"] != contract.authority_digest(scope, selected["fixture_lifecycle"])
        or value["intent_id"] != owner["request"]["fixture_intent_id"]
        or value["objects"][index]["purpose"] != contract.PURPOSES[index]
    ):
        raise S3AccessError("The fixture request differs from its saved enrollment and intent.")
    return {
        "schema_version": contract.REQUEST_SCHEMA,
        "fixture_authority_digest": value["authority_digest"],
        "fixture": {
            "schema_version": contract.OPERATION_SCHEMA,
            "intent_id": value["intent_id"],
            "purpose": contract.PURPOSES[index],
            "expected_etag": value["objects"][index]["expected_etag"],
        },
    }


def completion(owner: Mapping[str, Any], phase: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if phase != "cleanup":
        return {}
    return {
        "policy_retention": {
            "policy_state": owner["progress"]["policy_state"],
            "review_digest": value["review_digest"],
            "operation_job_id": value["operation_job_id"],
        }
    }
