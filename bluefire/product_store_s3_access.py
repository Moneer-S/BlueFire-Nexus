"""S3 phase reservations and immutable results in the existing jobs transaction."""

from __future__ import annotations

import hashlib
import re
import uuid
from contextlib import contextmanager
from typing import Any, Mapping

from .product_store_assistance import job_at, patch
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .s3_access_contract import S3AccessScope
from .s3_access_execution_contract import validate_execution
from .s3_access_policy import plan_hardening
from .s3_access_recovery import validate_recovery_context
from .s3_access_results import (
    OPERATION_KIND,
    OWNER_KIND,
    PHASES,
    SEND_LIMITS,
    allowed_phases,
    job_id,
    outcome,
    phase_budget,
    review_document,
)
from .s3_access_wire import S3WorkerRequest
from .util import content_hash


def owner_at(store, connection, identifier: str) -> Mapping[str, Any]:
    owner = job_at(store, connection, identifier)
    if owner["kind"] != OWNER_KIND:
        raise ProductStoreError("Select a saved S3 exercise.")
    return owner


def create_owner(store, document, *, submission_id: str, intent_digest: str):
    identifier, binding = store._job_submission_binding(submission_id, intent_digest)
    safe = safe_document({**document, "_submission": binding}, context="S3 saved exercise")
    with store._connection(write=True) as connection:
        old = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
        if old is not None:
            return store._matching_job_submission(old, OWNER_KIND, binding)
        progress = {
            "revision": 0,
            "operations": [],
            "reserved": {},
            "pending_operation": None,
            "policy_state": "baseline",
            "stopped": False,
        }
        now = utc_now()
        connection.execute(
            "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,?,'completed',?,?,?,?)",
            (identifier, OWNER_KIND, canonical_json(safe), canonical_json(progress), now, now),
        )
        return job_at(store, connection, identifier)


def publication_guard(store, connection, kind: str, document: Mapping[str, Any]) -> None:
    if kind != OPERATION_KIND:
        raise ProductStoreError("S3 stages require their exact job kind.")
    marker = document["s3_access"]
    owner = owner_at(store, connection, marker["workflow_job_id"])
    phase = marker["phase"]
    submitted = document["submitted_request"]
    validate_requests(owner, document)
    expected = review_document(owner, phase)
    if (
        phase not in allowed_phases(owner)
        or marker["review"] != expected
        or submitted["review_digest"] != expected["review_digest"]
        or marker["expected_revision"] != owner["progress"]["revision"]
    ):
        raise ProductStoreError("The S3 stage changed, is unsettled, or needs a new review.")
    # Reserve the UI phase and the child in the caller's one jobs transaction.
    # Native admission independently owns send authority and durable debits.
    resource = owner["request"]["environment"]["scope"]
    peers = connection.execute(
        "SELECT * FROM jobs WHERE kind = ? AND job_id != ?", (OWNER_KIND, owner["job_id"])
    ).fetchall()
    for row in peers:
        peer = store._job_from_row(row)
        scope = peer["request"]["environment"]["scope"]
        history = peer["progress"].get("operations", [])
        unsettled = (
            peer["progress"].get("pending_operation")
            or peer["progress"].get("policy_state") in {"hardened", "uncertain", "drift"}
            or bool(history and history[-1]["outcome"]["cleanup"] != "verified")
        )
        if (scope["account_id"], scope["region"], scope["bucket"]) == (
            resource["account_id"],
            resource["region"],
            resource["bucket"],
        ) and unsettled:
            raise ProductStoreError("Another saved S3 operation has this bucket reserved.")
    budget = phase_budget(phase)
    used = owner["progress"].get("reserved", {})
    patch(
        connection,
        owner,
        {
            "revision": owner["progress"]["revision"] + 1,
            "pending_operation": marker["operation_job_id"],
            "reserved": {key: used.get(key, 0) + value for key, value in budget.items()},
        },
    )


def validate_requests(owner, document) -> list[S3WorkerRequest]:
    marker, submitted = document["s3_access"], document["submitted_request"]
    phase = marker["phase"]
    operation_id = "job-" + uuid.UUID(submitted["submission_id"]).hex
    if marker["operation_job_id"] != operation_id or submitted["phase"] != phase:
        raise ProductStoreError("The saved S3 stage identity differs from its submission.")
    requests = [S3WorkerRequest.from_mapping(row) for row in document["worker_requests"]]
    selected = owner["request"]["environment"]
    runtime = owner["request"]["runtime"]
    scope = S3AccessScope.from_mapping(selected["scope"])
    change = plan_hardening(scope, selected["baseline_policy"]).to_dict()
    if len(requests) != len(PHASES[phase]) or len(
        {row.to_dict()["launch_id"] for row in requests}
    ) != len(requests):
        raise ProductStoreError("The saved S3 stage request sequence is invalid.")
    for index, (request, operation) in enumerate(zip(requests, PHASES[phase], strict=True)):
        row = request.to_dict()
        expected = {
            "scope": scope.to_dict(),
            "scope_digest": scope.digest,
            "operation": operation,
            "max_sends": SEND_LIMITS[operation],
            "request_id": hashlib.sha256(f"{operation_id}:{index}".encode()).hexdigest(),
            "worker_generation": runtime["worker_generation"],
            "runtime_digest": runtime["runtime_digest"],
            "policy_change": change if phase in {"apply", "rollback", "reconcile"} else None,
            "exclusive_writer_digest": (
                selected["exclusive_writer_digest"] if phase in {"apply", "rollback"} else None
            ),
        }
        if any(row[key] != value for key, value in expected.items()):
            raise ProductStoreError(
                "The S3 request differs from its saved scope or reviewed stage."
            )
    return requests


def guard_execution(store, operation_id: str) -> Mapping[str, Any]:
    with store._connection() as connection:
        child = job_at(store, connection, operation_id)
        marker = child["request"]["s3_access"]
        owner = owner_at(store, connection, marker["workflow_job_id"])
        if (
            child["kind"] != OPERATION_KIND
            or marker["operation_job_id"] != operation_id
            or owner["progress"].get("pending_operation") != operation_id
            or (
                owner["progress"].get("stopped")
                and marker["phase"] not in {"reconcile", "rollback"}
            )
        ):
            raise ProductStoreError("This S3 operation is no longer the active saved stage.")
        return owner


def workflow_approval(owner, operation_id, document, request) -> dict[str, Any]:
    marker, payload = document["s3_access"], request.to_dict()
    return {
        "schema_version": "bluefire.s3-workflow-approval.v1",
        "workflow_job_id": owner["job_id"],
        "operation_job_id": operation_id,
        "environment_id": owner["request"]["environment"]["environment_id"],
        "scope_digest": payload["scope_digest"],
        "request_digest": request.digest,
        "phase": marker["phase"],
        "reviewed_by": document["submitted_request"]["reviewed_by"],
        "review_digest": marker["review"]["review_digest"],
        "expected_workflow_revision": marker["expected_revision"],
        "prior_run_ids": marker["review"]["prior_run_ids"],
        "policy_change_digest": (
            content_hash(payload["policy_change"]) if payload["policy_change"] else None
        ),
    }


def validate_run_request(owner, child, run_id, request) -> None:
    requests = validate_requests(owner, child["request"])
    run_ids = child["progress"].get("run_ids", [])
    if (
        child["kind"] != OPERATION_KIND
        or child["request"]["s3_access"]["workflow_job_id"] != owner["job_id"]
        or child["request"]["s3_access"]["operation_job_id"] != child["job_id"]
        or not isinstance(run_ids, list)
        or len(run_ids) > len(requests)
        or any(not isinstance(value, str) for value in run_ids)
        or len(set(run_ids)) != len(run_ids)
        or run_id not in run_ids
        or requests[run_ids.index(run_id)].digest != request.digest
    ):
        raise ProductStoreError("The original S3 task differs from its saved run sequence.")


def original_task_context(owner, child, run_id, request, value) -> dict[str, Any]:
    validate_run_request(owner, child, run_id, request)
    checked = validate_recovery_context(request, value)
    if (
        checked["manifest"]["params"]["workflow_approval"]
        != workflow_approval(owner, child["job_id"], child["request"], request)
        or checked["profile"]["profile_id"] != owner["request"]["runtime"]["runner_profile_id"]
    ):
        raise ProductStoreError("The original S3 task differs from its saved approval or host.")
    return checked


def retain_original_task(store, operation_id, run_id, request, value) -> None:
    with store._connection(write=True) as connection:
        child = job_at(store, connection, operation_id)
        marker = child["request"]["s3_access"]
        owner = owner_at(store, connection, marker["workflow_job_id"])
        if (
            child["state"] != "running"
            or owner["progress"].get("pending_operation") != operation_id
            or (
                owner["progress"].get("stopped")
                and marker["phase"] not in {"rollback", "reconcile"}
            )
        ):
            raise ProductStoreError("The original S3 task no longer has an active reservation.")
        checked = original_task_context(owner, child, run_id, request, value)
        retained = child["progress"].get("original_tasks", {})
        if not isinstance(retained, dict) or set(retained) - set(child["progress"]["run_ids"]):
            raise ProductStoreError("The original S3 task checkpoint is invalid.")
        old = retained.get(run_id)
        if old is not None:
            if old != checked:
                raise ProductStoreError("This S3 run already has a different original task.")
            return
        patch(connection, child, {"original_tasks": {**retained, run_id: checked}})


@contextmanager
def result_publication(store, operation_id, run_id, request, execution):
    """Serialize only local run publication; callers must not perform host I/O here."""
    with store._connection(write=True) as connection:
        child = job_at(store, connection, operation_id)
        owner = owner_at(store, connection, child["request"]["s3_access"]["workflow_job_id"])
        validate_run_request(owner, child, run_id, request)
        if owner["progress"].get("pending_operation") != operation_id:
            raise ProductStoreError("The original S3 result no longer owns its reservation.")
        if execution["provenance"] != "synthetic" and execution["dispatch"] != "not_started":
            retained = child["progress"].get("original_tasks", {})
            if not isinstance(retained, dict) or run_id not in retained:
                raise ProductStoreError("The original S3 result has no retained task identity.")
            original_task_context(owner, child, run_id, request, retained[run_id])
        yield owner, child


def finish(
    store, operation_id: str, executions, run_ids, *, failure: bool = False
) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        child = job_at(store, connection, operation_id)
        marker = child["request"]["s3_access"]
        owner = owner_at(store, connection, marker["workflow_job_id"])
        phase = marker["phase"]
        requests = validate_requests(owner, child["request"])
        if child["kind"] != OPERATION_KIND or marker["operation_job_id"] != operation_id:
            raise ProductStoreError("The S3 result belongs to another operation.")
        if (
            len(executions) > len(PHASES[phase])
            or len(executions) != len(run_ids)
            or len(set(run_ids)) != len(run_ids)
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", item) is None
                for item in run_ids
            )
        ):
            raise ProductStoreError("The S3 result sequence is incomplete.")
        checked = [
            validate_execution(request, result)
            for request, result in zip(requests, executions, strict=False)
        ]
        if len(checked) != len(executions):
            raise ProductStoreError("The S3 result sequence exceeds its saved request.")
        summary = outcome(phase, checked)
        started_runs = child["progress"].get("run_ids", [])
        if (
            not isinstance(started_runs, list)
            or len(started_runs) > len(requests)
            or len(set(started_runs)) != len(started_runs)
            or started_runs[: len(run_ids)] != list(run_ids)
        ):
            raise ProductStoreError("The S3 results differ from the original dispatch sequence.")
        if len(started_runs) > len(run_ids):
            # Keep the original reservation until every started run has sealed proof.
            raise ProductStoreError("The original S3 operation still has an unsealed result.")
        if not checked and failure and not child["progress"].get("execution_started"):
            summary = {**summary, "state": "failed", "cleanup": "verified"}
        value: dict[str, Any] = safe_document(
            {
                "phase": phase,
                "operation_job_id": operation_id,
                "review_digest": marker["review"]["review_digest"],
                "run_ids": list(run_ids),
                "executions": checked,
                "outcome": summary,
            },
            context="S3 stage outcome",
        )
        value["outcome_digest"] = content_hash(value)
        old: Mapping[str, Any] | None = next(
            (
                row
                for row in owner["progress"]["operations"]
                if row["operation_job_id"] == operation_id
            ),
            None,
        )
        if old is not None:
            if old != value:
                raise ProductStoreError(
                    "The S3 operation already has a different immutable outcome."
                )
            return old
        if owner["progress"].get("pending_operation") != operation_id:
            raise ProductStoreError("The S3 reservation belongs to another operation.")
        policy = owner["progress"]["policy_state"]
        if summary["cleanup"] == "verified" and summary["state"] == "observed":
            if phase == "apply" or summary["policy_observation"] == "matched_after":
                policy = "hardened"
            elif phase == "rollback" or summary["policy_observation"] == "matched_before":
                policy = "baseline"
        elif phase in {"apply", "rollback"} and (
            checked or child["progress"].get("execution_started")
        ):
            policy = "uncertain"
        if summary["state"] == "drift":
            policy = "drift"
        patch(
            connection,
            owner,
            {
                "operations": [*owner["progress"]["operations"], value],
                "pending_operation": None,
                "policy_state": policy,
                "revision": owner["progress"]["revision"] + 1,
            },
        )
        return value


def stop(store, owner_id: str) -> str | None:
    with store._connection(write=True) as connection:
        owner = owner_at(store, connection, owner_id)
        patch(connection, owner, {"stopped": True, "revision": owner["progress"]["revision"] + 1})
        pending = owner["progress"].get("pending_operation")
        return job_id(pending) if pending is not None else None


def list_owners(store) -> list[Mapping[str, Any]]:
    with store._connection() as connection:
        rows = connection.execute(
            "SELECT * FROM jobs WHERE kind = ? ORDER BY updated_at DESC,job_id DESC LIMIT 101",
            (OWNER_KIND,),
        ).fetchall()
        return [store._job_from_row(row) for row in rows]
