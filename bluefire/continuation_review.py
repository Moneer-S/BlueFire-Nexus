"""Public canonical review for an accepted, still-pending Execute continuation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .util import content_hash, parse_iso8601_datetime

_BINDING_FIELDS = (
    "state_digest",
    "plan_digest",
    "target_scope_digest",
    "profile_id",
    "maximum_tier",
)


def continuation_approval_review(
    job: Mapping[str, Any],
    review: Mapping[str, Any],
    prepared: Mapping[str, Any],
    pending: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Expose reconstructed review data only for the exact fresh pending request.

    This returns no capability and makes no decision. The approval endpoint still
    reconstructs and atomically consumes its own independently checked binding.
    """
    progress, request = job.get("progress"), job.get("request")
    resolution = review.get("resolution")
    report, audit = prepared.get("approval_preflight"), prepared.get("audit")
    binding = prepared.get("approval_binding")
    if not all(
        isinstance(value, Mapping)
        for value in (progress, request, resolution, report, audit, binding)
    ):
        raise ValueError("continuation canonical review is unavailable")
    assert isinstance(progress, Mapping) and isinstance(request, Mapping)
    assert isinstance(resolution, Mapping) and isinstance(report, Mapping)
    assert isinstance(audit, Mapping) and isinstance(binding, Mapping)
    approval_id = pending.get("approval_id")
    if (
        job.get("state") != "awaiting_approval"
        or progress.get("approval_kind") != "ai_proposal_execute"
        or review.get("status") != "accepted"
        or review.get("job_id") != job.get("job_id")
        or progress.get("proposal_record_id") != review.get("proposal_record_id")
        or not isinstance(approval_id, str)
        or not approval_id
        or approval_id == request.get("approval_request_id")
        or pending.get("status") != "pending"
        or not isinstance(pending.get("expires_at"), str)
        or parse_iso8601_datetime(pending["expires_at"]) <= datetime.now(timezone.utc)
        or progress.get("approval_request_id") != approval_id
        or resolution.get("approval_request_id") != approval_id
        or resolution.get("continuation") != audit
        or audit.get("execute_approval_binding_digest") != content_hash(binding)
        or report.get("approval_binding") != binding
        or not isinstance(report.get("plan"), Mapping)
        or content_hash(report["plan"]) != binding.get("plan_digest")
        or content_hash(report.get("scope")) != binding.get("target_scope_digest")
        or not isinstance(report.get("approval_envelope"), Mapping)
        or any(
            not isinstance(binding.get(field), str)
            or not binding[field]
            or pending.get(field) != binding[field]
            for field in _BINDING_FIELDS
        )
    ):
        raise ValueError("continuation canonical review does not match the pending approval")
    return {
        "schema_version": "bluefire.continuation-approval-review.v1",
        "job_id": job["job_id"],
        "proposal_record_id": review["proposal_record_id"],
        "approval_request_id": approval_id,
        "preflight": dict(report),
    }
