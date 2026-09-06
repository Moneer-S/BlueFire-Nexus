"""Atomic review and child/report receipts inside the existing jobs database."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable, Mapping

from .ai_detection_revision import PROPOSAL_SCHEMA, validate_output
from .detections import DetectionCandidate, DetectionError
from .product_store import ProductStore, _safe_document
from .product_store_detection_evaluations import _read_row, save_report
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

PROPOSE_KIND = "detection.ai.propose"
APPLY_KIND = "detection.ai.apply"
APPLICATION_SCHEMA = "bluefire.detection-ai-application.v1"
DECISION_SCHEMA = "bluefire.detection-ai-decision.v1"


def proposal_from_job(job: Mapping[str, Any]) -> Mapping[str, Any]:
    if job.get("kind") != PROPOSE_KIND or job.get("state") != "completed":
        raise ProductStoreError("A completed detection proposal job is required.")
    proposal = job.get("progress", {}).get("proposal")
    request = job.get("request", {})
    if (
        not isinstance(proposal, dict)
        or proposal.get("schema_version") != PROPOSAL_SCHEMA
        or proposal.get("proposal_digest")
        != content_hash({k: v for k, v in proposal.items() if k != "proposal_digest"})
        or proposal.get("parent") != request.get("parent")
        or proposal.get("source_run") != request.get("source_run")
        or proposal.get("provider_binding_digest") != request.get("provider_binding_digest")
        or not isinstance(proposal.get("provider"), dict)
        or proposal["provider"].get("provider_id") != request.get("provider_id")
    ):
        raise ProductStoreError("The saved detection proposal binding is invalid.")
    try:
        validate_output(
            {
                key: proposal.get(key)
                for key in ("source", "reason", "evidence_refs", "limitations")
            },
            original_source=request["parent"]["source"],
            evidence_ids=request["observed_ids"],
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise ProductStoreError("The saved detection proposal is invalid.") from exc
    return proposal


def _job(store: ProductStore, connection: sqlite3.Connection, job_id: str) -> Mapping[str, Any]:
    row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if row is None:
        raise ProductStoreError("Detection job was not found.")
    return store._job_from_row(row)


def _progress(
    connection: sqlite3.Connection,
    job: Mapping[str, Any],
    patch: Mapping[str, Any],
    *,
    result_ref: str | None = None,
) -> None:
    progress = _safe_document({**job["progress"], **patch}, context="detection AI job progress")
    connection.execute(
        "UPDATE jobs SET progress_json = ?, result_ref = COALESCE(?, result_ref), updated_at = ? WHERE job_id = ?",
        (canonical_json(progress), result_ref, utc_now(), job["job_id"]),
    )


def decide(store: ProductStore, job_id: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
    with store._connection(write=True) as connection:
        job = _job(store, connection, job_id)
        proposal = proposal_from_job(job)
        if (
            request["proposal_digest"] != proposal["proposal_digest"]
            or request["parent_resource_digest"] != proposal["parent"]["resource_digest"]
        ):
            raise ProductStoreError("The reviewed proposal or parent digest does not match.")
        decision = {"schema_version": DECISION_SCHEMA, **request}
        existing = job["progress"].get("decision")
        if existing is not None:
            if {k: v for k, v in existing.items() if k != "reviewed_at"} != decision:
                raise ProductStoreError("This proposal already has a different recorded decision.")
            return job
        parent = connection.execute(
            "SELECT digest FROM resources WHERE kind = 'detection' AND resource_id = ?",
            (proposal["parent"]["candidate_id"],),
        ).fetchone()
        if request["decision"] == "accept" and (
            parent is None or parent["digest"] != request["parent_resource_digest"]
        ):
            raise ProductStoreError("The parent changed after this proposal was prepared.")
        decision["reviewed_at"] = utc_now()
        _progress(connection, job, {"decision": decision})
        return _job(store, connection, job_id)


def apply_revision(
    store: ProductStore,
    *,
    proposal_job_id: str,
    application_job_id: str,
    revision_root_id: str,
    build_document: Callable[[int], Mapping[str, Any]],
    max_revisions: int,
    build_report: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    check_cancelled: Callable[[], None],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """Commit child, report and both job links together, or none of them."""
    with store._connection(write=True) as connection:
        proposal_job = _job(store, connection, proposal_job_id)
        proposal = proposal_from_job(proposal_job)
        decision = proposal_job["progress"].get("decision")
        application_job = _job(store, connection, application_job_id)
        if (
            not isinstance(decision, Mapping)
            or decision.get("decision") != "accept"
            or decision.get("proposal_digest") != proposal["proposal_digest"]
            or decision.get("parent_resource_digest") != proposal["parent"]["resource_digest"]
            or application_job.get("kind") != APPLY_KIND
            or application_job["request"].get("proposal_job_id") != proposal_job_id
            or application_job["request"].get("proposal_digest") != proposal["proposal_digest"]
            or application_job["state"] not in {"running", "cancelling"}
        ):
            raise ProductStoreError("Detection application has no matching accepted proposal.")
        receipt = proposal_job["progress"].get("application")
        if receipt is not None:
            if (
                not isinstance(receipt, dict)
                or receipt.get("schema_version") != APPLICATION_SCHEMA
                or receipt.get("proposal_job_id") != proposal_job_id
                or receipt.get("proposal_digest") != proposal["proposal_digest"]
                or receipt.get("development_case") is not True
                or receipt.get("run_id") != proposal["source_run"]["run_id"]
            ):
                raise ProductStoreError("The committed detection receipt is invalid.")
            row = connection.execute(
                "SELECT * FROM resources WHERE kind = 'detection' AND resource_id = ?",
                (receipt.get("candidate_id"),),
            ).fetchone()
            report_row = connection.execute(
                "SELECT * FROM detection_run_evaluations WHERE evaluation_id = ?",
                (receipt.get("evaluation_id"),),
            ).fetchone()
            if row is None or report_row is None:
                raise ProductStoreError("The committed detection receipt has missing artifacts.")
            resource, report = store._resource_row(row), _read_row(report_row)
            try:
                candidate = DetectionCandidate.from_mapping(resource["document"])
            except (DetectionError, TypeError, ValueError) as exc:
                raise ProductStoreError("The committed detection definition is invalid.") from exc
            if (
                content_hash(resource["document"]) != resource["digest"]
                or candidate.rule_source != proposal["source"]
            ):
                raise ProductStoreError(
                    "The committed detection source does not match its proposal."
                )
            if (
                report.get("development_case") is not True
                or report["candidate"]["candidate_id"] != resource["id"]
                or report["candidate"]["definition_digest"]
                != resource["document"].get("definition_digest")
                or report["source"] != proposal["source_run"]
                or resource["document"].get("parent_candidate_id")
                != proposal["parent"]["candidate_id"]
            ):
                raise ProductStoreError(
                    "The committed detection artifacts do not match their receipt."
                )
            _progress(
                connection,
                application_job,
                {"application": receipt},
                result_ref=str(resource["id"]),
            )
            return resource, report, receipt
        check_cancelled()
        if application_job["state"] != "running":
            raise ProductStoreError("Detection application is no longer running.")
        row = connection.execute(
            "SELECT * FROM resources WHERE kind = 'detection' AND resource_id = ?",
            (proposal["parent"]["candidate_id"],),
        ).fetchone()
        if (
            row is None
            or row["digest"] != proposal["parent"]["resource_digest"]
            or content_hash(json.loads(row["document_json"])) != row["digest"]
        ):
            raise ProductStoreError("The parent changed after review; no child was created.")
        resource = store._save_detection_revision_in_transaction(
            connection, revision_root_id, build_document, max_revisions=max_revisions
        )
        report = save_report(
            connection,
            _safe_document(build_report(resource), context="detection AI development evaluation"),
        )
        if report["source"] != proposal["source_run"]:
            raise ProductStoreError("The immutable source changed before application.")
        receipt = {
            "schema_version": APPLICATION_SCHEMA,
            "proposal_job_id": proposal_job_id,
            "proposal_digest": proposal["proposal_digest"],
            "candidate_id": resource["id"],
            "evaluation_id": report["evaluation_id"],
            "run_id": proposal["source_run"]["run_id"],
            "development_case": True,
            "applied_at": utc_now(),
        }
        _progress(connection, proposal_job, {"application": receipt})
        _progress(
            connection, application_job, {"application": receipt}, result_ref=str(resource["id"])
        )
        check_cancelled()
        return resource, report, receipt
