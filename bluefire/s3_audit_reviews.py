"""Saved local correlation of imported audit files, never cloud collection authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import zlib
from typing import Any, Mapping

from . import product_store_s3_access as records
from . import s3_audit_workflow as audit_workflow
from .product_store_assistance import job_at
from .product_store_contracts import safe_document
from .product_store_s3_access import owner_at
from .product_store_serialization import canonical_json, utc_now
from .s3_access_audit import correlate_reads
from .s3_access_contract import S3AccessError, digest, exact
from .s3_access_results import OPERATION_KIND, job_id, submission
from .util import canonical_json_bytes, content_hash

KIND = "s3.audit.review"
SCHEMA = "bluefire.s3-audit-review.v1"
MAX_REVIEWS = 32
MAX_INPUT_BYTES = 512 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024
MAX_REVIEW_BYTES = 2 * 1024 * 1024


def _sources(jobs, owner_id: str) -> list[dict[str, Any]]:
    _owner, operations = jobs.retained_operations(owner_id)
    sources = []
    for row, requests in operations:
        for run_id, execution, request in zip(
            row["run_ids"], row["executions"], requests, strict=False
        ):
            operation = request.to_dict()["operation"]
            result = execution["result"]
            if operation not in {"probe_read", "legitimate_read"} or result is None:
                continue
            sources.append(
                {
                    "source": {
                        "run_id": run_id,
                        "operation_job_id": row["operation_job_id"],
                        "phase": row["phase"],
                        "reader": "probe" if operation == "probe_read" else "legitimate",
                        "request_digest": request.digest,
                        "worker_result_digest": content_hash(result),
                        "outcome_digest": row["outcome_digest"],
                        "provenance": execution["provenance"],
                        "cleanup": execution["cleanup"],
                    },
                    "request": request,
                    "result": result,
                }
            )
    if len({row["source"]["run_id"] for row in sources}) != len(sources):
        raise S3AccessError("Saved audit source identity is ambiguous.")
    return sources


def _selected(sources: list[dict[str, Any]], run_id: Any) -> dict[str, Any]:
    if not isinstance(run_id, str):
        raise S3AccessError("Select one finalized saved read attempt.")
    matches = [row for row in sources if row["source"]["run_id"] == run_id]
    if len(matches) != 1:
        raise S3AccessError("Select one finalized saved read attempt.")
    return matches[0]


def _checked_record(record, owner_id: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
    request = record["request"]
    exact(request, {"workflow_job_id", "review", "_submission"}, "saved audit review")
    review = request["review"]
    exact(
        review,
        {
            "schema_version",
            "workflow_job_id",
            "source",
            "correlation",
            "imports",
            "collection_provenance",
            "independent_collection_proven",
            "effective_access_claim",
            "raw_bytes_retained",
            "review_digest",
            "input_digest",
        },
        "audit review",
    )
    selected = _selected(sources, review["source"]["run_id"])
    digest(review["input_digest"])
    if (
        record["kind"] != KIND
        or record["state"] != "completed"
        or request["workflow_job_id"] != owner_id
        or review["workflow_job_id"] != owner_id
        or review["schema_version"] != SCHEMA
        or review["source"] != selected["source"]
        or review["review_digest"]
        != content_hash({key: value for key, value in review.items() if key != "review_digest"})
        or request["_submission"]["intent_digest"] != review["review_digest"]
        or job_id(record["job_id"])
        != "job-" + submission(request["_submission"]["submission_id"]).replace("-", "")
        or review["collection_provenance"] != "operator_import"
        or review["independent_collection_proven"] is not False
        or review["effective_access_claim"] is not False
        or review["raw_bytes_retained"] is not False
        or review["correlation"]["request_digest"] != selected["source"]["request_digest"]
        or review["correlation"]["worker_result_digest"]
        != selected["source"]["worker_result_digest"]
        or review["correlation"]["independent_collection_proven"] is not False
        or review["correlation"]["effective_access_claim"] is not False
    ):
        raise S3AccessError("Saved audit review identity or provenance is unavailable.")
    return {"review_id": record["job_id"], "created_at": record["created_at"], **review}


def read_review(jobs, owner_id: str, review_id: str) -> Mapping[str, Any]:
    sources = _sources(jobs, owner_id)
    record = jobs.store.get_job(job_id(review_id))
    if record["kind"] == OPERATION_KIND:
        collected = records.checked_collected_review(jobs.store, owner_id, review_id)
        if not isinstance(collected, Mapping):
            raise S3AccessError("Saved collected review is unavailable.")
        return collected
    return _checked_record(record, owner_id, sources)


def list_reviews(jobs, owner_id: str) -> Mapping[str, Any]:
    sources = _sources(jobs, owner_id)
    with jobs.store._connection() as connection:
        rows = connection.execute(
            "SELECT * FROM jobs WHERE kind = ? AND json_extract(request_json, '$.workflow_job_id') = ? ORDER BY created_at DESC, job_id DESC LIMIT ?",
            (KIND, owner_id, MAX_REVIEWS + 1),
        ).fetchall()
    if len(rows) > MAX_REVIEWS:
        raise S3AccessError("Saved audit review history exceeds its bound.")
    reviews = []
    for row in rows:
        value = _checked_record(jobs.store._job_from_row(row), owner_id, sources)
        reads = value["correlation"]["reads"]
        reviews.append(
            {
                "review_id": value["review_id"],
                "created_at": value["created_at"],
                "review_digest": value["review_digest"],
                "source": value["source"],
                "reported_delivery_state": value["correlation"]["audit"]["reported_delivery_state"],
                "statuses": [read["status"] for read in reads],
            }
        )
    value = {
        "schema_version": "bluefire.s3-audit-reviews.v1",
        "workflow_job_id": owner_id,
        "reads": [row["source"] for row in sources],
        "reviews": reviews,
        "maximum_reviews": MAX_REVIEWS,
        "maximum_input_bytes": MAX_INPUT_BYTES,
        "maximum_expanded_bytes": MAX_EXPANDED_BYTES,
        "collection_provenance": "operator_import",
        "independent_collection_proven": False,
    }
    owner = jobs._owner(owner_id)
    if audit_workflow.enrolled(owner):
        collections = []
        for operation in owner["progress"]["operations"]:
            if operation["phase"] not in audit_workflow.PHASES:
                continue
            child = jobs.store.get_job(operation["operation_job_id"])
            if child["progress"].get("collected_review") is None:
                continue
            review = records.checked_collected_review(jobs.store, owner_id, child["job_id"])
            data = review["receipt"]["result"]["data"]
            collections.append(
                {
                    "review_id": review["review_id"],
                    "created_at": review["created_at"],
                    "review_digest": review["review_digest"],
                    "phase": review["phase"],
                    "collection_run_id": review["collection_run_id"],
                    "original_run_ids": [row["run_id"] for row in review["original_pair"]["reads"]],
                    "reported_delivery_state": data["delivery_state"],
                    "statuses": [
                        row["status"]
                        for reader in ("probe", "legitimate")
                        for row in data["correlations"][reader]["reads"]
                    ],
                    "collection_provenance": "authenticated_source_retrieval",
                }
            )
        if len(collections) > 2 or len({row["phase"] for row in collections}) != len(collections):
            raise S3AccessError("The collected phase history exceeds its immutable slots.")
        value.update(
            schema_version="bluefire.s3-audit-reviews.v2",
            collections=collections,
            maximum_collections=2,
        )
        del value["collection_provenance"]
        del value["independent_collection_proven"]
    return value


def save_review(jobs, owner_id: str, value: Mapping[str, Any]) -> Mapping[str, Any]:
    exact(value, {"submission_id", "run_id", "delivery_state", "logs"}, "audit import")
    submitted = submission(value["submission_id"])
    logs = value["logs"]
    if not isinstance(logs, list) or not 1 <= len(logs) <= 4:
        raise S3AccessError("Select one to four bounded JSON audit files.")
    raw_logs, imports = [], []
    total, expanded = 0, 0
    for item in logs:
        exact(item, {"encoding", "data"}, "audit source file")
        raw, encoding = item["data"], item["encoding"]
        if (
            not isinstance(encoding, str)
            or encoding not in {"json", "gzip"}
            or not isinstance(raw, str)
            or not raw
            or len(raw) > 4 * ((MAX_INPUT_BYTES + 2) // 3)
        ):
            raise S3AccessError("Audit import exceeds its encoded file bound.")
        try:
            packed = base64.b64decode(raw, validate=True)
        except (ValueError, binascii.Error):
            raise S3AccessError("Audit import has invalid file encoding.") from None
        total += len(packed)
        if total > MAX_INPUT_BYTES:
            raise S3AccessError("Audit import exceeds its aggregate byte bound.")
        data = packed
        if encoding == "gzip":
            try:
                decoder = zlib.decompressobj(wbits=31)
                data = decoder.decompress(packed, MAX_EXPANDED_BYTES - expanded + 1)
                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise S3AccessError("Audit gzip is incomplete, concatenated or oversized.")
            except zlib.error:
                raise S3AccessError("Audit gzip is invalid.") from None
        expanded += len(data)
        if expanded > MAX_EXPANDED_BYTES:
            raise S3AccessError("Audit import exceeds its expanded byte bound.")
        raw_logs.append(data)
        imports.append(
            {
                "encoding": encoding,
                "sha256": "sha256:" + hashlib.sha256(packed).hexdigest(),
                "size_bytes": len(packed),
                "expanded_bytes": len(data),
            }
        )
    sources = _sources(jobs, owner_id)
    selected = _selected(sources, value["run_id"])
    correlation = correlate_reads(
        selected["request"],
        selected["result"],
        raw_logs,
        delivery_state=value["delivery_state"],
    )
    review: dict[str, Any] = {
        "schema_version": SCHEMA,
        "workflow_job_id": owner_id,
        "source": selected["source"],
        "correlation": correlation,
        "imports": imports,
        "collection_provenance": "operator_import",
        "independent_collection_proven": False,
        "effective_access_claim": False,
        "raw_bytes_retained": False,
        "input_digest": content_hash(value),
    }
    review["review_digest"] = content_hash(review)
    if len(canonical_json_bytes(review)) > MAX_REVIEW_BYTES:
        raise S3AccessError("Audit projection exceeds its saved byte bound.")
    store = jobs.store
    identifier, binding = store._job_submission_binding(submitted, review["review_digest"])
    document = safe_document(
        {"workflow_job_id": owner_id, "review": review, "_submission": binding},
        context="S3 imported audit review",
    )
    # One transaction publishes a complete immutable analysis, never an execution job.
    with store._connection(write=True) as connection:
        owner = owner_at(store, connection, owner_id)
        if not any(
            row["operation_job_id"] == selected["source"]["operation_job_id"]
            and row["outcome_digest"] == selected["source"]["outcome_digest"]
            and selected["source"]["run_id"] in row["run_ids"]
            for row in owner["progress"]["operations"]
        ):
            raise S3AccessError("The original saved read changed before review publication.")
        old = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
        if old is not None:
            record = store._matching_job_submission(old, KIND, binding)
        else:
            count = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE kind = ? AND json_extract(request_json, '$.workflow_job_id') = ?",
                (KIND, owner_id),
            ).fetchone()[0]
            if count >= MAX_REVIEWS:
                raise S3AccessError("The saved audit review limit has been reached.")
            now = utc_now()
            connection.execute(
                "INSERT INTO jobs(job_id,kind,state,request_json,progress_json,created_at,updated_at) VALUES(?,?,'completed',?,'{}',?,?)",
                (identifier, KIND, canonical_json(document), now, now),
            )
            record = job_at(store, connection, identifier)
    return _checked_record(record, owner_id, sources)
