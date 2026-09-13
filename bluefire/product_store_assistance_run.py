"""Atomic native preparation decisions and nested run/inspection publication guards."""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any, Mapping

from .product_store_assistance import AssistanceStore, job_at, patch, require_active
from .product_store_errors import ProductStoreError
from .util import content_hash

KIND = "run.assistance.prepare"
INSPECT_KIND = "run.evidence.inspect"


def operation_at(
    store: AssistanceStore, connection: sqlite3.Connection, job_id: str
) -> Mapping[str, Any]:
    job = job_at(store, connection, job_id)
    if job["kind"] != KIND:
        raise ProductStoreError("The selected job is not a native run preparation.")
    return job


def preparation(job: Mapping[str, Any]) -> Mapping[str, Any] | None:
    prepared = job["progress"].get("preparation")
    if prepared is None:
        return None
    if (
        prepared["context_digest"] != job["request"]["context_digest"]
        or prepared["selection"] != job["request"]["submitted_request"]["selection"]
        or prepared["preparation_digest"]
        != content_hash(
            {key: value for key, value in prepared.items() if key != "preparation_digest"}
        )
        or prepared["run_request"]
        != {"scenario": prepared["scenario"], **prepared["selection"]["run_intent"]}
        or prepared.get("approval_created") is not False
        or prepared.get("effects_started") is not False
    ):
        raise ProductStoreError("The retained run preparation failed integrity validation.")
    return dict(prepared)


def run_identifier(job: Mapping[str, Any]) -> str:
    return str(
        uuid.uuid5(uuid.UUID(job["request"]["_submission"]["submission_id"]), "scenario-run")
    )


def decide(store: AssistanceStore, job_id: str, decision: Mapping[str, Any]) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = operation_at(store, connection, job_id)
        previous = job["progress"].get("decision")
        if previous is not None:
            if previous != decision:
                raise ProductStoreError("This preparation already has another native decision.")
            return job
        prepared = preparation(job)
        if prepared is None or decision["preparation_digest"] != prepared["preparation_digest"]:
            raise ProductStoreError("Native decision refers to another retained preparation.")
        if decision["decision"] not in {"accept", "reject", "policy"}:
            raise ProductStoreError("Native run decision is invalid.")
        if (
            decision["decision"] == "policy"
            and job["request"]["submitted_request"]["autonomy"] != "auto"
        ):
            raise ProductStoreError("Policy acceptance requires explicit retained Auto intent.")
        settled = job["state"] in {"completed", "interrupted"} or (
            decision["decision"] == "policy" and job["state"] == "running"
        )
        if job["progress"].get("stopped") or not settled:
            raise ProductStoreError("The native preparation is not settled and reviewable.")
        require_active(store, connection, job)
        values: dict[str, Any] = {"decision": dict(decision)}
        if decision["decision"] != "reject":
            submission = run_identifier(job)
            values.update(
                run_submission_id=submission, run_job_id="job-" + uuid.UUID(submission).hex
            )
        patch(connection, job, values)
        return operation_at(store, connection, job_id)


def publication_guard(
    store: AssistanceStore, connection: sqlite3.Connection, kind: str, document: Mapping[str, Any]
) -> None:
    binding = document["assistance_run"]
    if not isinstance(binding, Mapping) or set(binding) != {
        "operation_job_id",
        "preparation_digest",
    }:
        raise ProductStoreError("Native run publication binding is invalid.")
    job = operation_at(store, connection, binding["operation_job_id"])
    require_active(store, connection, job)
    prepared = preparation(job)
    if (
        job["progress"].get("stopped")
        or prepared is None
        or binding["preparation_digest"] != prepared["preparation_digest"]
        or job["progress"].get("decision", {}).get("decision") not in {"accept", "policy"}
    ):
        raise ProductStoreError("The native run preparation is stopped or was not accepted.")
    if kind == "scenario.run":
        submission = run_identifier(job)
        if (
            document.get("_run_submission_request") != prepared["run_request"]
            or {key: document.get(key) for key in prepared["run_request"]}
            != prepared["run_request"]
            or document["_submission"]["submission_id"] != submission
            or document["_submission"]["intent_digest"]
            != content_hash({"request": prepared["run_request"], "assistance_run": binding})
            or job["progress"].get("run_job_id") != "job-" + uuid.UUID(submission).hex
        ):
            raise ProductStoreError("Run publication differs from the accepted frozen request.")
        current = document.get("_run_submission_preflight", {})
        expected = prepared["preflight"]
        if any(
            current.get(key) != expected.get(key)
            for key in ("plan", "approval_binding", "runner_readiness", "catalog_authority")
        ):
            raise ProductStoreError("Run authority changed after native preparation review.")
    elif kind == INSPECT_KIND:
        if (
            document.get("run_id") != job["progress"].get("run_id")
            or document.get("run_digest") != job["progress"].get("run_digest")
            or document.get("provider_id") != job["request"]["submitted_request"]["provider_id"]
            or document.get("provider_binding_digest") != job["request"]["provider_binding_digest"]
            or document.get("message") != job["request"]["submitted_request"]["message"]
            or "job-" + uuid.UUID(document["_submission"]["submission_id"]).hex
            != job["progress"].get("inspection_job_id")
        ):
            raise ProductStoreError(
                "Inspection does not match the retained run and reserved attempt."
            )
    else:
        raise ProductStoreError("Unsupported native run child operation.")


def bind_result(
    store: AssistanceStore,
    job_id: str,
    run_job_id: str,
    run_id: str,
    run_digest: str,
    *,
    expected_result_ref: str | None,
) -> None:
    with store._connection(write=True) as connection:
        job = operation_at(store, connection, job_id)
        if job["progress"].get("run_job_id") != run_job_id:
            raise ProductStoreError("Finalized run is not this operation's reserved job.")
        for key, value in (("run_id", run_id), ("run_digest", run_digest)):
            if job["progress"].get(key) not in (None, value):
                raise ProductStoreError("Native operation already retains a different run result.")
        native = job_at(store, connection, run_job_id)
        if native.get("result_ref") != expected_result_ref:
            raise ProductStoreError("Native result linkage changed during finalization.")
        connection.execute("UPDATE jobs SET result_ref=? WHERE job_id=?", (run_id, run_job_id))
        patch(connection, native, {"run_id": run_id})
        # Preserve the actual committed result even if Stop raced with finalization.
        patch(connection, job, {"run_id": run_id, "run_digest": run_digest})


def reserve_inspection(store: AssistanceStore, job_id: str, *, retry: bool) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = operation_at(store, connection, job_id)
        require_active(store, connection, job)
        if job["progress"].get("stopped") or not job["progress"].get("run_id"):
            raise ProductStoreError("No active finalized run is available for inspection.")
        previous = job["progress"].get("inspection_job_id")
        attempt = int(job["progress"].get("inspection_attempt", 0))
        if previous is not None:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (previous,)).fetchone()
            if row is not None:
                nested_binding(job, store._job_from_row(row), INSPECT_KIND)
            if row is None or not retry or row["state"] not in {"failed", "interrupted"}:
                return job
        if attempt >= 3:
            raise ProductStoreError(
                "This operation exhausted its three bounded inspection attempts."
            )
        submission = str(
            uuid.uuid5(
                uuid.UUID(job["request"]["_submission"]["submission_id"]),
                f"inspection:{attempt + 1}",
            )
        )
        patch(
            connection,
            job,
            {
                "inspection_job_id": "job-" + uuid.UUID(submission).hex,
                "inspection_submission_id": submission,
                "inspection_attempt": attempt + 1,
            },
        )
        return operation_at(store, connection, job_id)


def stop(store: AssistanceStore, job_id: str) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = operation_at(store, connection, job_id)
        patch(connection, job, {"stopped": True})
        return operation_at(store, connection, job_id)


def nested_binding(operation: Mapping[str, Any], child: Mapping[str, Any], kind: str) -> None:
    prepared = preparation(operation)
    if prepared is None:
        raise ProductStoreError("Native child has no retained preparation.")
    request = child["request"]
    binding = {
        "operation_job_id": operation["job_id"],
        "preparation_digest": prepared["preparation_digest"],
    }
    submission = request.get("_submission", {})
    identifier = operation["progress"].get(
        "run_submission_id" if kind == "scenario.run" else "inspection_submission_id"
    )
    original = (
        prepared["run_request"]
        if kind == "scenario.run"
        else {key: value for key, value in request.items() if key != "_submission"}
    )
    intent = (
        content_hash({"request": original, "assistance_run": binding})
        if kind == "scenario.run"
        else content_hash(original)
    )
    if (
        not isinstance(identifier, str)
        or child["job_id"] != "job-" + uuid.UUID(identifier).hex
        or child["kind"] != kind
        or request.get("assistance_run") != binding
        or submission
        != {
            "schema_version": "bluefire.job-submission.v1",
            "submission_id": identifier,
            "intent_digest": intent,
        }
    ):
        raise ProductStoreError("Native child differs from its reserved submission and operation.")
    if kind == "scenario.run":
        if request.get("_run_submission_request") != original:
            raise ProductStoreError("Native run differs from its accepted request.")
    elif (
        request.get("run_id") != operation["progress"].get("run_id")
        or request.get("run_digest") != operation["progress"].get("run_digest")
        or request.get("provider_id") != operation["request"]["submitted_request"]["provider_id"]
        or request.get("provider_binding_digest") != operation["request"]["provider_binding_digest"]
        or request.get("message") != operation["request"]["submitted_request"]["message"]
    ):
        raise ProductStoreError("Inspection differs from its finalized run and provider binding.")
