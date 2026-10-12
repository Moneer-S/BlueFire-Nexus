"""Read-only, minimized saved-audit context with no dispatch capabilities."""

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


def context(service, value):
    chosen = selection(value)
    try:
        review = read_review(service.s3_access, chosen["workflow_job_id"], chosen["review_id"])
        if review["review_digest"] != chosen["review_digest"]:
            raise S3AccessError("The selected audit review changed.")
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
    document = {
        "schema_version": "bluefire.assistance-context.v1",
        "selected": chosen,
        "analysis_only": True,
        "capabilities": [],
        "reference_summary": summary,
        "limitations": LIMITATIONS,
    }
    return {**document, "context_digest": content_hash(document)}
