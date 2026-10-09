"""Pure CloudTrail projections, not authenticated collection or access proof.

AWS documents eventTime as service-side request completion, and requestID as
optional. Omitted fields cannot establish a denial. Sources:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html
"""

from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from typing import Any, Sequence

from .s3_access_contract import S3AccessError, S3AccessScope, document, timestamp
from .s3_access_wire import SAFE_ERROR_CODES, SAFE_REQUEST_ID, S3WorkerRequest, validate_result
from .util import content_hash

_EVENT_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", re.ASCII)
_VERSION = re.compile(r"1\.([1-9][0-9]?)", re.ASCII)
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", re.ASCII)
_SESSION = re.compile(r"bf-[0-9a-f]{32}-(?:probe|legitimate)", re.ASCII)
_DELIVERY = {"complete", "incomplete", "truncated", "unknown"}
_ERROR_OUTCOMES = {
    "AccessDenied": "service_denied",
    "NoSuchKey": "object_missing",
    "NoSuchBucket": "bucket_missing",
    "ExpiredToken": "credential_error",
    "InvalidToken": "credential_error",
    "InvalidAccessKeyId": "credential_error",
    "SignatureDoesNotMatch": "credential_error",
    "RequestExpired": "credential_error",
    "AuthorizationHeaderMalformed": "credential_error",
}


def _utc(value: Any) -> str:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise S3AccessError("audit event time must be bounded UTC")
    return timestamp(value).isoformat()


def _project(scope: dict[str, Any], event: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Drop unknown text; accept only exact generated-object read context."""
    required = ("eventSource", "eventName", "eventType", "eventCategory", "awsRegion")
    if any(key not in event for key in required):
        return "unknown", None
    if tuple(event[key] for key in required) != (
        "s3.amazonaws.com",
        "GetObject",
        "AwsApiCall",
        "Data",
        scope["region"],
    ):
        return "excluded", None
    version = event.get("eventVersion")
    parsed_version = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if parsed_version is None or int(parsed_version[1]) < 7:
        return "unknown", None
    if ("managementEvent" in event and event["managementEvent"] is not False) or (
        "readOnly" in event and event["readOnly"] is not True
    ):
        return "excluded", None
    identity = event.get("userIdentity")
    params = event.get("requestParameters")
    if not isinstance(identity, dict) or not isinstance(params, dict):
        return "unknown", None
    context = identity.get("sessionContext")
    issuer = context.get("sessionIssuer") if isinstance(context, dict) else None
    if not isinstance(issuer, dict):
        return "unknown", None
    required_values = (
        event.get("recipientAccountId"),
        identity.get("accountId"),
        issuer.get("accountId"),
        identity.get("type"),
        issuer.get("type"),
        issuer.get("arn"),
        identity.get("arn"),
        params.get("bucketName"),
        params.get("key"),
    )
    if any(value is None for value in required_values):
        return "unknown", None
    if (
        required_values[:3] != (scope["account_id"],) * 3
        or identity["type"] != "AssumedRole"
        or issuer["type"] != "Role"
        or params["bucketName"] != scope["bucket"]
    ):
        return "excluded", None
    reader = next(
        (name for name in ("probe", "legitimate") if issuer["arn"] == scope["roles"][name]), None
    )
    obj = next((row for row in scope["objects"] if row["key"] == params["key"]), None)
    if reader is None or obj is None or (reader == "probe" and obj["purpose"] != "primary"):
        return "excluded", None
    if "resources" in event:
        resources = event["resources"]
        allowed = {
            "AWS::S3::Bucket": "arn:aws:s3:::" + scope["bucket"],
            "AWS::S3::Object": "arn:aws:s3:::" + scope["bucket"] + "/" + obj["key"],
        }
        if not isinstance(resources, list) or not resources:
            return "unknown", None
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("type"), str):
                return "unknown", None
            if (
                resource["type"] not in allowed
                or resource.get("ARN") != allowed[resource["type"]]
                or ("accountId" in resource and resource["accountId"] != scope["account_id"])
            ):
                return "excluded", None
    prefix = f"arn:aws:sts::{scope['account_id']}:assumed-role/"
    prefix += scope["roles"][reader].rsplit("/", 1)[1] + "/"
    arn = identity["arn"]
    if not isinstance(arn, str) or not arn.startswith(prefix):
        return "excluded", None
    session = arn[len(prefix) :]
    if _SESSION.fullmatch(session) is None or not session.endswith("-" + reader):
        return "excluded", None
    request_id = event.get("requestID")
    if not isinstance(request_id, str) or SAFE_REQUEST_ID.fullmatch(request_id) is None:
        return "unknown", None
    try:
        completed_at = _utc(event.get("eventTime"))
    except S3AccessError:
        return "unknown", None
    if (
        not timestamp(scope["created_at"])
        <= timestamp(completed_at)
        <= timestamp(scope["expires_at"])
    ):
        return "excluded", None
    # Updated records may change prior evidence. They require a collector-level
    # reconciliation contract, not implicit replacement of a previous event.
    addendum = event.get("addendum")
    delayed = False
    if addendum is not None:
        if not isinstance(addendum, dict) or addendum.get("reason") != "DELIVERY_DELAY":
            return "unknown", None
        delayed = True
    error = event.get("errorCode")
    if "errorCode" not in event:
        response = event.get("responseElements")
        if (
            "responseElements" not in event
            or event.get("errorMessage") is not None
            or response is not None
        ):
            return "unknown", None
        outcome = "service_success"
    elif not isinstance(error, str) or not error:
        return "unknown", None
    else:
        outcome = _ERROR_OUTCOMES.get(error, "other_service_error")
    return "accepted", {
        "event_id": event["eventID"],
        "completed_at": completed_at,
        "request_id": request_id,
        "reader": reader,
        "purpose": obj["purpose"],
        "session_arn": arn,
        "outcome": outcome,
        "service_error_code": (
            None
            if "errorCode" not in event
            else error if error in SAFE_ERROR_CODES else "OtherServiceError"
        ),
        "delivery_delayed": delayed,
    }


def normalize_audit(
    scope: S3AccessScope, raw_logs: Sequence[bytes], *, delivery_state: str = "unknown"
) -> dict[str, Any]:
    """Normalize bounded uncompressed log objects; collection state is caller-reported."""
    scope = S3AccessScope.from_mapping(scope.to_dict())
    row = scope.to_dict()
    if not isinstance(delivery_state, str) or delivery_state not in _DELIVERY:
        raise S3AccessError("audit delivery state is invalid")
    if not isinstance(raw_logs, (list, tuple)) or len(raw_logs) > row["limits"]["audit_events"]:
        raise S3AccessError("audit source count exceeds its bound")
    total = 0
    event_count = 0
    sources = []
    events: list[dict[str, Any]] = []
    seen: dict[str, tuple[str, dict[str, Any] | None]] = {}
    counts = {"excluded": 0, "unknown": 0, "duplicates": 0}
    for source_index, raw in enumerate(raw_logs):
        if type(raw) is not bytes:
            raise S3AccessError("audit sources must be uncompressed bytes")
        total += len(raw)
        if total > row["limits"]["audit_bytes"]:
            raise S3AccessError("audit sources exceed their aggregate byte bound")
        source_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        payload = document(raw, limit=row["limits"]["audit_bytes"])
        if set(payload) != {"Records"} or not isinstance(payload["Records"], list):
            raise S3AccessError("audit log must contain only a Records array")
        event_count += len(payload["Records"])
        if event_count > row["limits"]["audit_events"]:
            raise S3AccessError("audit events exceed their aggregate bound")
        sources.append(
            {
                "sha256": source_digest,
                "size_bytes": len(raw),
                "event_count": len(payload["Records"]),
            }
        )
        for record_index, event in enumerate(payload["Records"]):
            if not isinstance(event, dict):
                counts["unknown"] += 1
                continue
            identifier = event.get("eventID")
            if not isinstance(identifier, str) or _EVENT_ID.fullmatch(identifier) is None:
                counts["unknown"] += 1
                continue
            event_digest = content_hash(event)
            occurrence = {"source_index": source_index, "record_index": record_index}
            if identifier.lower() in seen:
                original_digest, original = seen[identifier.lower()]
                if event_digest != original_digest:
                    raise S3AccessError("audit event identifier has conflicting records")
                counts["duplicates"] += 1
                if original is not None:
                    original["occurrences"].append(occurrence)
                continue
            disposition, projected = _project(row, event)
            if projected is not None:
                projected.update({"event_digest": event_digest, "occurrences": [occurrence]})
                events.append(projected)
            else:
                counts[disposition] += 1
            seen[identifier.lower()] = (event_digest, projected)
    return {
        "schema_version": "bluefire.s3-audit-projection.v1",
        "scope_digest": scope.digest,
        "reported_delivery_state": delivery_state,
        "source_bytes": total,
        "source_event_count": event_count,
        "sources": sources,
        "events": events,
        "counts": counts,
        "independent_collection_proven": False,
        "effective_access_claim": False,
    }


def correlate_reads(
    request: S3WorkerRequest,
    worker_result: Any,
    raw_logs: Sequence[bytes],
    *,
    delivery_state: str = "unknown",
) -> dict[str, Any]:
    """Correlate exact IDs and authorized time, never infer missing access or bytes."""
    request = S3WorkerRequest.from_mapping(request.to_dict())
    source = request.to_dict()
    if source["operation"] not in {"probe_read", "legitimate_read"}:
        raise S3AccessError("audit correlation requires a scoped read request")
    result = validate_result(request, worker_result)
    read_ids = [call["request_id"] for call in result["calls"][3:]]
    if len(set(read_ids)) != len(read_ids) or (
        read_ids and any("error_code" in call for call in result["calls"][:3])
    ):
        raise S3AccessError("worker read identity or unique request mapping is invalid")
    scope = S3AccessScope.from_mapping(source["scope"])
    audit = normalize_audit(scope, raw_logs, delivery_state=delivery_state)
    reader = "probe" if source["operation"] == "probe_read" else "legitimate"
    session = "bf-" + source["request_id"][:32] + "-" + reader
    expected_arn = f"arn:aws:sts::{source['scope']['account_id']}:assumed-role/"
    expected_arn += source["scope"]["roles"][reader].rsplit("/", 1)[1] + "/" + session
    end = timestamp(source["deadline"])
    start = max(
        timestamp(source["scope"]["created_at"]),
        end - timedelta(seconds=source["scope"]["limits"]["request_seconds"]),
    )
    rows = []
    for index, obj in enumerate(source["scope"]["objects"][: 1 if reader == "probe" else 2]):
        call = result["calls"][index + 3] if len(result["calls"]) > index + 3 else None
        matching = (
            []
            if call is None
            else [
                event
                for event in audit["events"]
                if event["reader"] == reader
                and event["purpose"] == obj["purpose"]
                and event["session_arn"] == expected_arn
                and event["request_id"] == call["request_id"]
                and start <= timestamp(event["completed_at"]) <= end
            ]
        )
        worker_outcome = (
            "unreported"
            if call is None
            else (
                _ERROR_OUTCOMES.get(call["error_code"], "other_service_error")
                if "error_code" in call
                else "service_success"
            )
        )
        if matching:
            assert call is not None
            outcomes = {event["outcome"] for event in matching}
            errors = {event["service_error_code"] for event in matching}
            status = (
                "matched"
                if outcomes == {worker_outcome} and errors == {call.get("error_code")}
                else "conflict"
            )
        elif call is None:
            status = "worker_unreported"
        elif delivery_state == "truncated":
            status = "truncated"
        elif audit["counts"]["unknown"] or delivery_state == "unknown":
            status = "unknown"
        elif delivery_state == "incomplete":
            status = "awaiting_delivery"
        else:
            status = "missing"
        rows.append(
            {
                "purpose": obj["purpose"],
                "reader": reader,
                "status": status,
                "worker_outcome": worker_outcome,
                "worker_request_id": call["request_id"] if call else None,
                "audit_event_ids": [event["event_id"] for event in matching],
                "audit_outcomes": sorted({event["outcome"] for event in matching}),
                "full_object_bytes_proven": False,
            }
        )
    return {
        "schema_version": "bluefire.s3-audit-correlation.v1",
        "request_digest": request.digest,
        "worker_result_digest": content_hash(result),
        "audit": audit,
        "reads": rows,
        "authorized_request_window": {"from": start.isoformat(), "through": end.isoformat()},
        "independent_collection_proven": False,
        "effective_access_claim": False,
    }
