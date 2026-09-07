"""Atomic initial-rule/report receipts in the existing product store."""

from __future__ import annotations

import sqlite3
from typing import Any, Callable, Mapping

from .ai_detection_create import APPLY_KIND, KIND, PROPOSAL_SCHEMA, validate_output
from .detections import DetectionCandidate
from .product_store import ProductStore, _safe_document
from .product_store_assistance import job_at, patch, require_active
from .product_store_detection_evaluations import _read_row, save_report
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

APPLICATION_SCHEMA = "bluefire.detection-source-creation-application.v1"


class CreationRefused(ProductStoreError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def safe_patch(
    connection: sqlite3.Connection, job: Mapping[str, Any], values: Mapping[str, Any]
) -> None:
    """Keep the ordinary product-store content boundary on direct writer updates."""
    try:
        progress = _safe_document(
            {**job["progress"], **values}, context="initial detection progress"
        )
    except ProductStoreError as exc:
        raise CreationRefused(
            "detection_creation_content_refused",
            "The proposed or reviewed content cannot be retained under the product data policy. Remove sensitive values and review the source again.",
        ) from exc
    patch(connection, job, progress)


def proposal(job: Mapping[str, Any]) -> Mapping[str, Any]:
    value = job["progress"].get("proposal")
    request = job["request"]
    if (
        job["kind"] != KIND
        or not isinstance(value, dict)
        or value.get("schema_version") != PROPOSAL_SCHEMA
        or value.get("proposal_digest")
        != content_hash({k: v for k, v in value.items() if k != "proposal_digest"})
        or value.get("selected") != request["context"]["selected"]
        or value.get("source_run") != request["context"]["source"]["source_run"]
        or value.get("provider_binding_digest") != request["provider_binding_digest"]
        or value.get("provider", {}).get("provider_id")
        != request["submitted_request"]["provider_id"]
    ):
        raise ProductStoreError("The retained initial source proposal binding is invalid.")
    validate_output(
        {
            key: value.get(key)
            for key in ("title", "source", "reason", "evidence_refs", "limitations")
        },
        evidence_ids=request["observed_ids"],
    )
    return value


def committed(
    store: ProductStore, connection: sqlite3.Connection, job: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    receipt = job["progress"].get("application")
    if receipt is None:
        return None
    value = proposal(job)
    decision = job["progress"].get("decision", {})
    row = connection.execute(
        "SELECT * FROM resources WHERE kind='detection' AND resource_id=?",
        (receipt.get("candidate_id"),),
    ).fetchone()
    evaluation_row = connection.execute(
        "SELECT * FROM detection_run_evaluations WHERE evaluation_id=?",
        (receipt.get("evaluation_id"),),
    ).fetchone()
    if row is None or evaluation_row is None:
        raise ProductStoreError("The initial detector receipt has missing artifacts.")
    resource, evaluation = store._resource_row(row), _read_row(evaluation_row)
    current_candidate = DetectionCandidate.from_mapping(resource["document"])
    app = job_at(store, connection, receipt["application_job_id"])
    snapshot = app["progress"].get("candidate_document")
    if not isinstance(snapshot, dict):
        raise ProductStoreError("The initial detector receipt has no immutable candidate snapshot.")
    candidate = DetectionCandidate.from_mapping(snapshot)
    if (
        current_candidate.candidate_id != candidate.candidate_id
        or current_candidate.definition_digest != candidate.definition_digest
        or current_candidate.rule_source != candidate.rule_source
        or current_candidate.revision_kind != "origin"
        or current_candidate.revision != 1
    ):
        raise ProductStoreError("The current rule no longer matches the initial source identity.")
    if (
        receipt.get("schema_version") != APPLICATION_SCHEMA
        or receipt.get("proposal_job_id") != job["job_id"]
        or receipt.get("proposal_digest") != value["proposal_digest"]
        or receipt.get("reviewed_digest") != decision.get("reviewed_digest")
        or decision.get("decision") != "accept"
        or app["kind"] != APPLY_KIND
        or app["request"].get("proposal_job_id") != job["job_id"]
        or app["request"].get("decision") != decision
        or app["request"].get("assistance_turn") != job["request"].get("assistance_turn")
        or app["progress"].get("application") != receipt
        or receipt.get("resource_digest") != content_hash(snapshot)
        or resource["digest"] != content_hash(resource["document"])
        or candidate.title != decision.get("title")
        or candidate.rule_source != decision.get("source")
        or candidate.revision != 1
        or receipt.get("definition_digest") != candidate.definition_digest
        or receipt.get("actual_source_digest") != content_hash(candidate.rule_source)
        or receipt.get("run_id") != value["selected"]["run_id"]
        or receipt.get("source_binding_digest") != value["selected"]["source_binding_digest"]
        or receipt.get("development_case") is not True
        or evaluation.get("development_case") is not True
        or evaluation["source"] != value["source_run"]
        or evaluation["candidate"]["candidate_id"] != candidate.candidate_id
        or evaluation["candidate"]["definition_digest"] != candidate.definition_digest
        or evaluation["candidate"]["resource_digest_at_evaluation"] != content_hash(snapshot)
        or receipt.get("operator_modified")
        != any(decision[key] != value[key] for key in ("title", "source"))
    ):
        raise ProductStoreError(
            "The saved detector, evaluation and accepted source do not match their receipt."
        )
    return receipt, evaluation


def apply(
    store: ProductStore,
    *,
    proposal_job_id: str,
    application_job_id: str,
    candidate: DetectionCandidate,
    report: Mapping[str, Any],
    check: Callable[[Mapping[str, Any]], None],
) -> Mapping[str, Any]:
    """Insert candidate, revision index, report and both job links, or none."""
    document = _safe_document(candidate.to_dict(), context="initial detection source")
    DetectionCandidate.from_mapping(document)
    digest = content_hash(document)
    with store._connection(write=True) as connection:
        job = job_at(store, connection, proposal_job_id)
        existing = committed(store, connection, job)
        if existing is not None:
            return existing[0]
        value = proposal(job)
        decision = job["progress"].get("decision", {})
        app = job_at(store, connection, application_job_id)
        require_active(store, connection, job)
        check(job)
        if (
            job["progress"].get("stopped")
            or app["state"] != "running"
            or app["kind"] != APPLY_KIND
            or app["request"].get("proposal_job_id") != proposal_job_id
            or app["request"].get("decision") != decision
            or decision.get("decision") != "accept"
            or candidate.rule_source != decision.get("source")
            or candidate.title != decision.get("title")
        ):
            raise ProductStoreError(
                "Initial detector application is stopped or has no exact reviewed decision."
            )
        if (
            connection.execute(
                "SELECT 1 FROM resources WHERE kind='detection' AND resource_id=?",
                (candidate.candidate_id,),
            ).fetchone()
            is not None
        ):
            raise CreationRefused(
                "detection_creation_identity_exists",
                "A rule with this executable-content identity already exists. Open that saved rule and use its native revision workflow; no existing source was overwritten.",
            )
        if (
            candidate.revision != 1
            or candidate.revision_kind != "origin"
            or report["source"] != value["source_run"]
            or report["candidate"]["resource_digest_at_evaluation"] != digest
            or report["candidate"]["candidate_id"] != candidate.candidate_id
            or report.get("development_case") is not True
        ):
            raise ProductStoreError(
                "Initial detector application artifacts are not bound to the reviewed source."
            )
        now = utc_now()
        connection.execute(
            "INSERT INTO resources(kind,resource_id,status,digest,document_json,created_at,updated_at) VALUES('detection',?,?,?,?,?,?)",
            (
                candidate.candidate_id,
                candidate.state.value,
                digest,
                canonical_json(document),
                now,
                now,
            ),
        )
        store._register_detection_revision(
            connection,
            candidate_id=candidate.candidate_id,
            revision=1,
            revision_root_id=candidate.candidate_id,
            created_at=now,
        )
        evaluation = save_report(connection, report)
        receipt = {
            "schema_version": APPLICATION_SCHEMA,
            "proposal_job_id": proposal_job_id,
            "application_job_id": application_job_id,
            "proposal_digest": value["proposal_digest"],
            "reviewed_digest": decision["reviewed_digest"],
            "candidate_id": candidate.candidate_id,
            "resource_digest": digest,
            "definition_digest": candidate.definition_digest,
            "actual_source_digest": content_hash(candidate.rule_source),
            "evaluation_id": evaluation["evaluation_id"],
            "run_id": value["selected"]["run_id"],
            "source_binding_digest": value["selected"]["source_binding_digest"],
            "operator_modified": any(decision[key] != value[key] for key in ("title", "source")),
            "development_case": True,
        }
        patch(connection, job, {"application": receipt})
        patch(connection, app, {"application": receipt, "candidate_document": document})
        connection.execute(
            "UPDATE jobs SET result_ref=? WHERE job_id=?",
            (candidate.candidate_id, application_job_id),
        )
        check(job)
        return receipt
