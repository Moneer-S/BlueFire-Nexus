"""Read-only, minimized saved-audit context with no dispatch capabilities."""

from typing import Any, Mapping

from .product_store_errors import ProductStoreError
from .s3_access_contract import S3AccessError, digest, exact
from .s3_access_results import job_id
from .s3_audit_reviews import read_review
from .util import content_hash

KIND = "s3_audit_review"
LIMITATIONS = [
    "This is an explanation of one immutable operator-imported audit review, not an execution plan.",
    "Imported records do not independently prove collection, completeness, effective access, prevention or full object bytes.",
    "Synthetic runner evidence remains synthetic; a matched request is not a successful defensive change.",
    "Missing, delayed, truncated and conflicting observations remain distinct. No cloud call, policy change, new grant or detector deployment is available from this context.",
]
COLLECTED_SUMMARY_SCHEMA = "bluefire.s3-collected-audit-summary.v1"
COLLECTED_LIMITATIONS = [
    "This is an explanation of one immutable authenticated-source retrieval review, not an execution plan.",
    "Authenticated retrieval does not prove CloudTrail signature-chain integrity, complete delivery, full object bytes, effective access or prevention.",
    "The paired read summaries preserve runner reports and correlated observations; a matched request is not a successful defensive change.",
    "Missing, delayed, truncated and conflicting observations remain distinct. No cloud call, policy change, new grant or detector deployment is available from this context.",
]
_STATUSES = {
    "matched",
    "conflict",
    "worker_unreported",
    "truncated",
    "unknown",
    "awaiting_delivery",
    "missing",
}
_OUTCOMES = {
    "unreported",
    "service_success",
    "service_denied",
    "object_missing",
    "bucket_missing",
    "credential_error",
    "other_service_error",
}


def _collected_summary(review):
    data = review["receipt"]["result"]["data"]
    reads = [
        {
            "purpose": row["purpose"],
            "reader": row["reader"],
            "status": row["status"],
            "worker_outcome": row["worker_outcome"],
            "matched_event_count": len(row["audit_event_ids"]),
            "full_object_bytes_proven": False,
        }
        for reader in ("probe", "legitimate")
        for row in data["correlations"][reader]["reads"]
    ]
    summary = {
        "schema_version": COLLECTED_SUMMARY_SCHEMA,
        "phase": review["phase"],
        "runner_source": review["receipt"]["provenance"],
        "cleanup": review["receipt"]["cleanup"],
        "collection_provenance": "authenticated_source_retrieval",
        "reported_delivery_state": data["delivery_state"],
        "source_event_count": data["usage"]["events"],
        "collected_file_count": data["usage"]["files"],
        "discovery_truncated": data["discovery"]["truncated"],
        "reads": reads,
        "raw_bytes_retained": False,
        "log_integrity_proven": False,
        "independent_collection_proven": False,
        "effective_access_claim": False,
    }
    if (
        summary["phase"] not in {"baseline", "retest"}
        or summary["runner_source"] != "runner_reported"
        or summary["cleanup"] != "verified"
        or summary["reported_delivery_state"] not in {"incomplete", "truncated", "unknown"}
        or type(summary["source_event_count"]) is not int
        or not 0 <= summary["source_event_count"] <= 500
        or type(summary["collected_file_count"]) is not int
        or not 0 <= summary["collected_file_count"] <= 4
        or type(summary["discovery_truncated"]) is not bool
        or (summary["discovery_truncated"] and summary["reported_delivery_state"] != "truncated")
        or [(row["reader"], row["purpose"]) for row in reads]
        != [("probe", "primary"), ("legitimate", "primary"), ("legitimate", "health")]
        or any(
            row["status"] not in _STATUSES
            or row["worker_outcome"] not in _OUTCOMES
            or type(row["matched_event_count"]) is not int
            or not 0 <= row["matched_event_count"] <= summary["source_event_count"]
            for row in reads
        )
    ):
        raise S3AccessError("The collected audit summary is invalid.")
    return summary


def _document(chosen, summary, limitations) -> Mapping[str, Any]:
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": chosen,
        "analysis_only": True,
        "capabilities": [],
        "reference_summary": summary,
        "limitations": limitations,
    }
    return {**document, "context_digest": content_hash(document)}


def selection(value):
    try:
        row = exact(
            value,
            {"kind", "workflow_job_id", "review_id", "review_digest"},
            "saved audit selection",
        )
        if row["kind"] != KIND:
            raise S3AccessError("Select a saved audit review.")
        job_id(row["workflow_job_id"])
        job_id(row["review_id"])
        digest(row["review_digest"])
        return dict(row)
    except (S3AccessError, TypeError, ValueError) as exc:
        raise ProductStoreError("Select one exact saved audit review.") from exc


def context(service, value) -> Mapping[str, Any]:
    chosen = selection(value)
    try:
        review = read_review(service.s3_access, chosen["workflow_job_id"], chosen["review_id"])
        if review["review_digest"] != chosen["review_digest"]:
            raise S3AccessError("The selected audit review changed.")
        if review["schema_version"] == "bluefire.s3-audit-collected-review.v1":
            return _document(chosen, _collected_summary(review), COLLECTED_LIMITATIONS)
        correlation = review["correlation"]
        audit = correlation["audit"]
        source = review["source"]
        summary = {
            "phase": source["phase"],
            "runner_source": source["provenance"],
            "cleanup": source["cleanup"],
            "collection_provenance": "operator_import",
            "reported_delivery_state": audit["reported_delivery_state"],
            "source_event_count": audit["source_event_count"],
            "counts": dict(audit["counts"]),
            "reads": [
                {
                    "purpose": row["purpose"],
                    "reader": row["reader"],
                    "status": row["status"],
                    "worker_outcome": row["worker_outcome"],
                    "matched_event_count": len(row["audit_event_ids"]),
                    "full_object_bytes_proven": False,
                }
                for row in correlation["reads"]
            ],
            "independent_collection_proven": False,
            "effective_access_claim": False,
        }
        if (
            summary["phase"] not in {"baseline", "retest"}
            or summary["runner_source"] not in {"synthetic", "runner_reported"}
            or summary["cleanup"] not in {"verified", "unknown"}
            or summary["reported_delivery_state"]
            not in {"unknown", "incomplete", "truncated", "complete"}
            or set(summary["counts"]) != {"excluded", "unknown", "duplicates"}
            or any(
                type(n) is not int or not 0 <= n <= 1000
                for n in [summary["source_event_count"], *summary["counts"].values()]
            )
            or not 1 <= len(summary["reads"]) <= 2
        ):
            raise S3AccessError("Saved audit summary is invalid.")
        for row in summary["reads"]:
            if (
                row["purpose"] not in {"primary", "health"}
                or row["reader"] not in {"probe", "legitimate"}
                or row["status"]
                not in {
                    "matched",
                    "conflict",
                    "worker_unreported",
                    "truncated",
                    "unknown",
                    "awaiting_delivery",
                    "missing",
                }
                or row["worker_outcome"]
                not in {
                    "unreported",
                    "service_success",
                    "service_denied",
                    "object_missing",
                    "bucket_missing",
                    "credential_error",
                    "other_service_error",
                }
                or not 0 <= row["matched_event_count"] <= 1000
            ):
                raise S3AccessError("Saved audit read summary is invalid.")
    except (S3AccessError, KeyError, TypeError, ValueError) as exc:
        raise ProductStoreError("The saved audit source is unavailable or changed.") from exc
    return _document(chosen, summary, LIMITATIONS)
