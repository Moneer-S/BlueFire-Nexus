"""Pure v1/v2 worker request and result contracts; no audit dispatch."""

from __future__ import annotations

import re
from typing import Any, Mapping

from . import s3_fixture_contract as fixtures
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .s3_access_policy import S3PolicyChange
from .util import content_hash

REQUEST_SCHEMA = "bluefire.s3-worker-request.v1"
MAX_FRAME_BYTES = 80 * 1024
OPERATIONS = {
    "inspect_policy",
    "reconcile_policy",
    "apply_policy",
    "rollback_policy",
    "probe_read",
    "legitimate_read",
}
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9+/=_:.-]{0,127}", re.ASCII)
SAFE_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "NoSuchKey",
        "NoSuchBucket",
        "ExpiredToken",
        "InvalidToken",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "RequestExpired",
        "AuthorizationHeaderMalformed",
        "PermanentRedirect",
        "SlowDown",
        "ServiceUnavailable",
        "InternalError",
        "PreconditionFailed",
        "OtherServiceError",
    }
)


def _hex(value: Any) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise S3AccessError("worker identity is invalid")
    return value


def request(value: Any) -> dict[str, Any]:
    """Validate only the unchanged v1/v2 worker request schemas."""
    row = document(value, limit=MAX_FRAME_BYTES)
    fixture_request = row.get("schema_version") == fixtures.REQUEST_SCHEMA
    exact(
        row,
        {
            "schema_version",
            "launch_id",
            "request_id",
            "worker_generation",
            "runtime_digest",
            "scope",
            "scope_digest",
            "operation",
            "policy_change",
            "deadline",
            "max_sends",
            "exclusive_writer_digest",
        }
        | ({"fixture", "fixture_authority_digest"} if fixture_request else set()),
        "worker request",
    )
    if (
        row["schema_version"] not in (REQUEST_SCHEMA, fixtures.REQUEST_SCHEMA)
        or not isinstance(row["operation"], str)
        or row["operation"] not in (fixtures.OPERATIONS if fixture_request else OPERATIONS)
    ):
        raise S3AccessError("worker operation or schema is unsupported")
    _hex(row["launch_id"])
    _hex(row["request_id"])
    digest(row["worker_generation"])
    digest(row["runtime_digest"])
    scope = S3AccessScope.from_mapping(row["scope"])
    if row["scope_digest"] != scope.digest:
        raise S3AccessError("worker scope digest differs from its exact document")
    row["scope"] = scope.to_dict()
    maximum = {
        "inspect_policy": 2,
        "reconcile_policy": 2,
        "apply_policy": 4,
        "rollback_policy": 4,
        "probe_read": 4,
        "legitimate_read": 5,
        **fixtures.SEND_LIMITS,
    }[row["operation"]]
    if type(row["max_sends"]) is not int or not 1 <= row["max_sends"] <= min(
        maximum, row["scope"]["limits"]["api_calls"]
    ):
        raise S3AccessError("worker send allowance is invalid")
    deadline = timestamp(row["deadline"])
    if (
        not timestamp(row["scope"]["created_at"])
        < deadline
        <= timestamp(row["scope"]["expires_at"])
    ):
        raise S3AccessError("worker deadline is outside the scope lifetime")
    row["deadline"] = deadline.isoformat().replace("+00:00", "Z")
    if row["operation"] in {"apply_policy", "rollback_policy", "reconcile_policy"}:
        change = S3PolicyChange.from_mapping(scope, row["policy_change"])
        row["policy_change"] = change.to_dict()
        if row["operation"] == "reconcile_policy":
            if row["exclusive_writer_digest"] is not None:
                raise S3AccessError("reconciliation cannot carry mutation authority")
        else:
            digest(row["exclusive_writer_digest"])
    elif row["policy_change"] is not None or row["exclusive_writer_digest"] is not None:
        raise S3AccessError("operation cannot carry policy mutation authority")
    if fixture_request:
        digest(row["fixture_authority_digest"])
        row["fixture"] = fixtures.operation(scope, row["operation"], row["fixture"])
    return row


def operation_plan(row: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    if row["schema_version"] == fixtures.REQUEST_SCHEMA:
        return fixtures.operation_plan(row)
    selected = row["operation"]
    plan = [("sts", "GetCallerIdentity", "controller")]
    if selected in {"probe_read", "legitimate_read"}:
        reader = "probe" if selected == "probe_read" else "legitimate"
        plan += [("sts", "AssumeRole", "controller"), ("sts", "GetCallerIdentity", reader)]
        plan += [("s3", "GetObject", reader)] * (1 if reader == "probe" else 2)
    else:
        plan += [("s3", "GetBucketPolicy", "controller")]
        if selected not in {"inspect_policy", "reconcile_policy"}:
            plan += [
                ("s3", "PutBucketPolicy", "controller"),
                ("s3", "GetBucketPolicy", "controller"),
            ]
    return plan


def validate_result(source: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """Validate ordinary worker data without the v3 dispatch facade."""
    source = request(source)
    row = document(value, limit=16 * 1024)
    exact(
        row,
        {
            "schema_version",
            "request_digest",
            "outcome",
            "data",
            "problem",
            "send_permits_consumed",
            "calls",
            "runtime_isolation_proven",
        },
        "worker result",
    )
    if (
        row["schema_version"]
        != (
            fixtures.RESULT_SCHEMA
            if source["schema_version"] == fixtures.REQUEST_SCHEMA
            else "bluefire.s3-worker-result.v1"
        )
        or row["request_digest"] != content_hash(source)
        or row["runtime_isolation_proven"] is not False
    ):
        raise S3AccessError("worker result binding or provenance is invalid")
    if row["outcome"] not in ("observed", "failed", "reconcile_required"):
        raise S3AccessError("worker result outcome is invalid")
    consumed = row["send_permits_consumed"]
    calls = row["calls"]
    plan = operation_plan(source)
    if (
        type(consumed) is not int
        or not 0 <= consumed <= min(source["max_sends"], len(plan))
        or not isinstance(calls, list)
        or len(calls) > consumed
    ):
        raise S3AccessError("worker result accounting is invalid")
    for call, (_, operation, role) in zip(calls, plan, strict=False):
        if not isinstance(call, Mapping):
            raise S3AccessError("worker response projection must be an object")
        fields = {"operation", "role", "request_id", "http_status"}
        exact(
            call,
            fields | ({"error_code"} if "error_code" in call else set()),
            "worker response projection",
        )
        identifier, status = call["request_id"], call["http_status"]
        if (
            call["operation"] != operation
            or call["role"] != role
            or not isinstance(identifier, str)
            or SAFE_REQUEST_ID.fullmatch(identifier) is None
            or type(status) is not int
        ):
            raise S3AccessError("worker response projection is invalid")
        if "error_code" in call:
            if (
                not isinstance(call["error_code"], str)
                or call["error_code"]
                not in (
                    SAFE_ERROR_CODES
                    | (
                        fixtures.ERROR_CODES
                        if source["schema_version"] == fixtures.REQUEST_SCHEMA
                        else set()
                    )
                )
                or not 400 <= status <= 599
            ):
                raise S3AccessError("worker error projection is invalid")
        elif status not in (
            {204}
            if operation == "DeleteObject"
            else {200, 204} if operation == "PutBucketPolicy" else {200}
        ):
            raise S3AccessError("worker response status is invalid")
    if row["outcome"] != "observed":
        expected = (
            "write_outcome_unsettled"
            if row["outcome"] == "reconcile_required"
            else "scoped_operation_failed"
        )
        if row["data"] is not None or row["problem"] != expected:
            raise S3AccessError("failed worker result cannot claim observations")
        if row["outcome"] == "reconcile_required" and (
            (
                source["operation"]
                not in {"apply_policy", "rollback_policy", "prepare_fixture", "cleanup_fixture"}
            )
            or consumed < (5 if source["operation"] in fixtures.OPERATIONS else 3)
            or (
                source["operation"] == "cleanup_fixture"
                and source["fixture"]["expected_etag"] is None
            )
        ):
            raise S3AccessError("worker reconciliation result has no write debit")
        return row
    if row["problem"] is not None or len(calls) != len(plan) or consumed != len(plan):
        raise S3AccessError("worker observations lack complete operation accounting")
    data = row["data"]
    if source["schema_version"] == fixtures.REQUEST_SCHEMA:
        fixtures.validate_observation(source, data, calls)
        return row
    if source["operation"] in {"probe_read", "legitimate_read"}:
        exact(data, {"reader", "objects", "effective_access_claim"}, "worker read observations")
        reader = "probe" if source["operation"] == "probe_read" else "legitimate"
        expected_objects = source["scope"]["objects"][: 1 if reader == "probe" else 2]
        if (
            data["reader"] != reader
            or data["effective_access_claim"] is not False
            or not isinstance(data["objects"], list)
            or len(data["objects"]) != len(expected_objects)
        ):
            raise S3AccessError("worker read provenance or object count is invalid")
        for observed, expected_object, call in zip(
            data["objects"], expected_objects, calls[3:], strict=True
        ):
            if not isinstance(observed, Mapping) or (
                observed.get("result") == "read" and type(observed.get("size_bytes")) is not int
            ):
                raise S3AccessError("worker object observation has an invalid shape")
            if call.get("error_code") == "AccessDenied" and call["http_status"] == 403:
                if observed != {"purpose": expected_object["purpose"], "result": "service_denied"}:
                    raise S3AccessError("worker denial does not match its service response")
            elif "error_code" in call or observed != {
                "result": "read",
                **{name: expected_object[name] for name in ("purpose", "sha256", "size_bytes")},
            }:
                raise S3AccessError(
                    "worker object observation differs from the exact generated bytes"
                )
        if any("error_code" in call for call in calls[:3]):
            raise S3AccessError("worker reader identity was not confirmed")
    else:
        exact(data, {"policy_digest", "structural_review"}, "worker policy observation")
        if source["operation"] == "reconcile_policy":
            current = digest(data["policy_digest"])
            change = source["policy_change"]
            review = (
                "matched_before"
                if current == change["before_digest"]
                else "matched_after" if current == change["after_digest"] else "drift"
            )
            if data["structural_review"] != review or any("error_code" in call for call in calls):
                raise S3AccessError("reconciliation differs from its exact policy observation")
            return row
        expected_digest = source["scope"]["policy"]["baseline_digest"]
        if source["operation"] == "apply_policy":
            expected_digest = source["policy_change"]["after_digest"]
        review = (
            "supported_baseline" if source["operation"] == "inspect_policy" else "exact_readback"
        )
        if data != {"policy_digest": expected_digest, "structural_review": review} or any(
            "error_code" in call for call in calls
        ):
            raise S3AccessError("worker policy observation differs from its exact review")
    return row
