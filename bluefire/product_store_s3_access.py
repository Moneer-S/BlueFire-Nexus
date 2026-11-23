"""S3 phase reservations and immutable results in the existing jobs transaction."""

from __future__ import annotations

import hashlib
import re
import uuid
from contextlib import contextmanager
from typing import Any, Mapping

from . import s3_audit_collection_contract as audit
from . import s3_audit_workflow as audit_workflow
from . import s3_fixture_results as fixtures
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
        if "audit_source" in safe["environment"]:
            progress.update(
                audit_workflow.initial(
                    {"job_id": identifier, "request": safe, "progress": progress}
                )
            )
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
    pair, host_digest = (None, None)
    if phase in audit_workflow.PHASES:
        pair, host_digest = _collection_pair(store, connection, owner, phase.removeprefix("audit_"))
        if marker.get("audit_original_host_digest") != host_digest:
            raise ProductStoreError("The collection differs from its original authenticated host.")
    expected = review_document(
        owner,
        phase,
        pair=pair,
        listing_date=(
            marker["review"]["audit_collection"]["listing_date"] if pair is not None else None
        ),
    )
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
            or (
                fixtures.enabled(peer)
                and fixtures.projection(peer)["fixture_state"] not in {"not_prepared", "absent"}
            )
        )
        if (scope["account_id"], scope["region"], scope["bucket"]) == (
            resource["account_id"],
            resource["region"],
            resource["bucket"],
        ) and unsettled:
            raise ProductStoreError("Another saved S3 operation has this bucket reserved.")
    budget = phase_budget(phase)
    used = owner["progress"].get("reserved", {})
    claims = {}
    if audit_workflow.enrolled(owner):
        retained = audit_workflow.retained(owner)
        if not retained and phase not in fixtures.RECOVERY_PHASES:
            raise ProductStoreError("Historical work cannot adopt audit authority.")
        if retained and phase in {"baseline", "retest"}:
            slots = owner["progress"]["audit_read_slots"]
            if phase in slots:
                raise ProductStoreError("An original audited read stage cannot be replaced.")
            claims["audit_read_slots"] = {
                **slots,
                phase: {"operation_job_id": marker["operation_job_id"]},
            }
        elif retained and phase in audit_workflow.PHASES:
            original = phase.removeprefix("audit_")
            slots = owner["progress"]["audit_slots"]
            if original in slots:
                raise ProductStoreError("This paired audit slot is already reserved.")
            claims["audit_slots"] = {
                **slots,
                original: {
                    "operation_job_id": marker["operation_job_id"],
                    "review_digest": expected["review_digest"],
                    "pair_digest": content_hash(pair),
                    "source_digest": expected["audit_collection"]["source_digest"],
                },
            }
    patch(
        connection,
        owner,
        {
            "revision": owner["progress"]["revision"] + 1,
            "pending_operation": marker["operation_job_id"],
            "reserved": {key: used.get(key, 0) + value for key, value in budget.items()},
            **claims,
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
            **(
                audit_workflow.request_fields(
                    owner,
                    phase,
                    marker["review"]["audit_collection"],
                    operation_id,
                    row["launch_id"],
                    row["request_id"],
                    row["audit"]["issued_at"],
                )
                if phase in audit_workflow.PHASES
                else fixtures.request_fields(owner, phase, index, marker["review"])
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
                owner["progress"].get("stopped") and marker["phase"] not in fixtures.RECOVERY_PHASES
            )
        ):
            raise ProductStoreError("This S3 operation is no longer the active saved stage.")
        if marker["phase"] in audit_workflow.PHASES:
            _check_collection_document(store, connection, owner, child["request"])
        return owner


def workflow_approval(owner, operation_id, document, request) -> dict[str, Any]:
    marker, payload = document["s3_access"], request.to_dict()
    value = {
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
    if marker["phase"] in fixtures.PHASES:
        value.update(
            schema_version="bluefire.s3-workflow-approval.v2",
            fixture_authority_digest=payload["fixture_authority_digest"],
            fixture_intent_id=payload["fixture"]["intent_id"],
        )
    selected = owner["request"]["environment"]
    if "audit_source" in selected:
        commitment = audit.build_workflow(
            S3AccessScope.from_mapping(selected["scope"]),
            selected["audit_source"],
            workflow_job_id=owner["job_id"],
            environment_id=selected["environment_id"],
        )
        value.update(
            schema_version=audit.APPROVAL_SCHEMA,
            audit_workflow_digest=content_hash(commitment),
        )
    return value


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
    if (
        checked["schema_version"] == "bluefire.s3-original-task.v2"
        and checked["manifest"]["run_id"] != run_id
    ):
        raise ProductStoreError("The original task differs from its immutable run identity.")
    if request.to_dict()["operation"] == "collect_audit" and (
        checked["schema_version"] != "bluefire.s3-original-task.v2"
        or content_hash({name: checked[name] for name in ("profile", "transport_identity")})
        != child["request"]["s3_access"].get("audit_original_host_digest")
    ):
        raise ProductStoreError("Collection cannot adopt a replacement original host.")
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
                owner["progress"].get("stopped") and marker["phase"] not in fixtures.RECOVERY_PHASES
            )
        ):
            raise ProductStoreError("The original S3 task no longer has an active reservation.")
        checked = original_task_context(owner, child, run_id, request, value)
        if (
            audit_workflow.enrolled(owner)
            and checked["schema_version"] != "bluefire.s3-original-task.v2"
        ):
            raise ProductStoreError("New audited tasks require their exact immutable run identity.")
        if marker["phase"] in audit_workflow.PHASES:
            _check_collection_document(store, connection, owner, child["request"])
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
        if child["request"]["s3_access"]["phase"] in audit_workflow.PHASES:
            _check_collection_document(store, connection, owner, child["request"])
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
        if phase in audit_workflow.PHASES:
            _check_collection_document(store, connection, owner, child["request"])
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
        if (
            phase in audit_workflow.PHASES
            and summary["state"] == "observed"
            and summary["cleanup"] == "verified"
        ):
            review = collected_review_document(store, connection, owner, child, value)
            prior = child["progress"].get("collected_review")
            if prior is not None and prior != review:
                raise ProductStoreError("The collection already has different immutable evidence.")
            patch(connection, child, {"collected_review": review})
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
        if summary["state"] == "drift" and phase not in fixtures.PHASES:
            policy = "drift"
        patch(
            connection,
            owner,
            {
                "operations": [*owner["progress"]["operations"], value],
                "pending_operation": None,
                "policy_state": policy,
                "revision": owner["progress"]["revision"] + 1,
                **(fixtures.completion(owner, phase, value) if fixtures.enabled(owner) else {}),
            },
        )
        return value


def _collection_pair(store, connection, owner, phase):
    if phase not in {"baseline", "retest"} or not audit_workflow.pair_available(owner, phase):
        raise ProductStoreError("Both clean original read results are required.")
    identifier = owner["progress"]["audit_read_slots"][phase]["operation_job_id"]
    matches = [
        row for row in owner["progress"]["operations"] if row["operation_job_id"] == identifier
    ]
    if len(matches) != 1:
        raise ProductStoreError("The original paired operation is ambiguous.")
    outcome = matches[0]
    if outcome["outcome_digest"] != content_hash(
        {key: value for key, value in outcome.items() if key != "outcome_digest"}
    ):
        raise ProductStoreError("The original paired outcome changed.")
    child = job_at(store, connection, identifier)
    marker = child["request"]["s3_access"]
    if (
        child["state"] not in {"completed", "failed", "cancelled", "interrupted"}
        or marker["phase"] != phase
    ):
        raise ProductStoreError("The original paired operation has not settled.")
    requests = validate_requests(owner, child["request"])
    contexts = child["progress"].get("original_tasks", {})
    reads, hosts = [], []
    for reader, run_id, request, execution in zip(
        ("probe", "legitimate"), outcome["run_ids"], requests, outcome["executions"], strict=True
    ):
        context = original_task_context(owner, child, run_id, request, contexts.get(run_id))
        if context["schema_version"] != "bluefire.s3-original-task.v2":
            raise ProductStoreError(
                "Historical task identities cannot become a new collection pair."
            )
        hosts.append(
            content_hash({name: context[name] for name in ("profile", "transport_identity")})
        )
        reads.append(
            {
                "reader": reader,
                "run_id": run_id,
                "manifest_digest": content_hash(context["manifest"]),
                "request_digest": request.digest,
                "worker_result_digest": content_hash(execution["result"]),
                "reservation_digest": execution["reservation_digest"],
                "cleanup": execution["cleanup"],
                "request": request.to_dict(),
                "result": execution["result"],
            }
        )
    if len(set(hosts)) != 1 or outcome["review_digest"] != marker["review"]["review_digest"]:
        raise ProductStoreError("The paired reads do not share their original host and review.")
    pair = audit.original_pair(
        S3AccessScope.from_mapping(owner["request"]["environment"]["scope"]),
        {
            "schema_version": audit.PAIR_SCHEMA,
            "workflow_job_id": owner["job_id"],
            "operation_job_id": identifier,
            "phase": phase,
            "outcome_digest": outcome["outcome_digest"],
            "review_digest": outcome["review_digest"],
            "reads": reads,
        },
    )
    return pair, hosts[0]


def collection_pair(store, owner_id: str, phase: str):
    with store._connection() as connection:
        return _collection_pair(store, connection, owner_at(store, connection, owner_id), phase)


def _check_collection_document(store, connection, owner, document):
    marker = document["s3_access"]
    phase = marker["phase"].removeprefix("audit_")
    pair, host = _collection_pair(store, connection, owner, phase)
    review = marker["review"]
    expected_slot = {
        "operation_job_id": marker["operation_job_id"],
        "review_digest": review["review_digest"],
        "pair_digest": content_hash(pair),
        "source_digest": content_hash(audit_workflow.commitment(owner)["source"]),
    }
    if (
        marker.get("audit_original_host_digest") != host
        or review["audit_collection"]["original_pair"] != pair
        or owner["progress"]["audit_slots"].get(phase) != expected_slot
        or review["review_digest"]
        != content_hash({key: value for key, value in review.items() if key != "review_digest"})
    ):
        raise ProductStoreError("The retained collection no longer joins its exact original pair.")
    return pair


def collected_review_document(store, connection, owner, child, outcome):
    pair = _check_collection_document(store, connection, owner, child["request"])
    requests = validate_requests(owner, child["request"])
    if len(requests) != 1 or len(outcome["run_ids"]) != 1 or len(outcome["executions"]) != 1:
        raise ProductStoreError("The original collection result is incomplete.")
    request, run_id = requests[0], outcome["run_ids"][0]
    if (
        outcome["operation_job_id"] != child["job_id"]
        or outcome["phase"] != child["request"]["s3_access"]["phase"]
        or outcome["review_digest"] != child["request"]["s3_access"]["review"]["review_digest"]
        or outcome["outcome_digest"]
        != content_hash({key: value for key, value in outcome.items() if key != "outcome_digest"})
    ):
        raise ProductStoreError("The collected review differs from its original outcome.")
    execution = validate_execution(request, outcome["executions"][0])
    result = execution["result"]
    context = original_task_context(
        owner, child, run_id, request, child["progress"].get("original_tasks", {}).get(run_id)
    )
    if (
        execution["provenance"] != "runner_reported"
        or execution["cleanup"] != "verified"
        or execution["dispatch"] != "permit_issued"
        or result is None
        or result["outcome"] != "observed"
        or result["data"]["reservation_digest"] != execution["reservation_digest"]
        or result["data"]["pair_digest"] != content_hash(pair)
    ):
        raise ProductStoreError("The collection lacks its exact authenticated retrieval receipt.")
    value = {
        "schema_version": "bluefire.s3-audit-collected-review.v1",
        "workflow_job_id": owner["job_id"],
        "operation_job_id": child["job_id"],
        "phase": pair["phase"],
        "collection_run_id": run_id,
        "manifest_digest": content_hash(context["manifest"]),
        "request_digest": request.digest,
        "worker_result_digest": content_hash(result),
        "reservation_digest": execution["reservation_digest"],
        "outcome_digest": outcome["outcome_digest"],
        "source": request.to_dict()["audit"]["source"],
        "original_pair": pair,
        "receipt": execution,
        "collection_provenance": "authenticated_source_retrieval",
        "raw_bytes_retained": False,
        "log_integrity_proven": False,
        "effective_access_claim": False,
    }
    return {**value, "review_digest": content_hash(value)}


def checked_collected_review(store, owner_id, operation_id):
    with store._connection() as connection:
        owner = owner_at(store, connection, owner_id)
        child = job_at(store, connection, job_id(operation_id))
        rows = [
            row
            for row in owner["progress"]["operations"]
            if row["operation_job_id"] == operation_id
        ]
        if len(rows) != 1 or rows[0]["phase"] not in audit_workflow.PHASES:
            raise ProductStoreError("Select one finalized collected review.")
        expected = collected_review_document(store, connection, owner, child, rows[0])
        if child["progress"].get("collected_review") != expected:
            raise ProductStoreError("The immutable collected review changed.")
        return {"review_id": child["job_id"], "created_at": child["created_at"], **expected}


def finalized_collection_recheck(store, owner_id, operation_id):
    """Retain exact query identity, never adopt a different finalized execution."""
    with store._connection() as connection:
        owner = owner_at(store, connection, owner_id)
        child = job_at(store, connection, job_id(operation_id))
        rows = [
            row
            for row in owner["progress"]["operations"]
            if row["operation_job_id"] == operation_id
        ]
        if (
            not audit_workflow.retained(owner)
            or len(rows) != 1
            or rows[0]["phase"] not in audit_workflow.PHASES
            or child["state"] not in {"completed", "failed", "cancelled", "interrupted"}
            or rows[0]["outcome"]["cleanup"] != "unknown"
        ):
            raise ProductStoreError("Select a finalized collection with unresolved cleanup.")
        row = rows[0]
        _check_collection_document(store, connection, owner, child["request"])
        requests = validate_requests(owner, child["request"])
        if (
            len(requests) != 1
            or len(row["run_ids"]) != 1
            or len(row["executions"]) != 1
            or row["phase"] != child["request"]["s3_access"]["phase"]
            or row["review_digest"] != child["request"]["s3_access"]["review"]["review_digest"]
            or row["outcome_digest"]
            != content_hash({key: value for key, value in row.items() if key != "outcome_digest"})
        ):
            raise ProductStoreError("The finalized collection has incomplete original lineage.")
        request, run_id = requests[0], row["run_ids"][0]
        execution = validate_execution(request, row["executions"][0])
        if (
            request.to_dict()["operation"] != "collect_audit"
            or execution["cleanup"] != "unknown"
            or execution["provenance"] != "runner_reported"
            or execution["reservation_digest"] is None
        ):
            return None
        contexts = child["progress"].get("original_tasks", {})
        if not isinstance(contexts, dict):
            raise ProductStoreError("The original collection task checkpoint is invalid.")
        if run_id not in contexts:
            return None
        context = original_task_context(owner, child, run_id, request, contexts[run_id])
        return {
            "operation_job_id": operation_id,
            "run_id": run_id,
            "outcome_digest": row["outcome_digest"],
            "request": request.to_dict(),
            "execution": execution,
            "context": context,
        }


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
