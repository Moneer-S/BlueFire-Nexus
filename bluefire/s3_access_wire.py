"""Strict worker messages. Frame matching does not prove native containment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, cast

from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .s3_access_policy import S3PolicyChange
from .util import canonical_json_bytes, content_hash

REQUEST_SCHEMA = "bluefire.s3-worker-request.v1"
MAX_FRAME_BYTES = 80 * 1024
MAX_SECRET_FRAME_BYTES = 16 * 1024
OPERATIONS = {
    "inspect_policy",
    "reconcile_policy",
    "apply_policy",
    "rollback_policy",
    "probe_read",
    "legitimate_read",
}
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SECRET_TEXT = re.compile(r"[\x21-\x7e]+", re.ASCII)
Clock = Callable[[], datetime]
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


def decode_frame(payload: bytes, *, maximum: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    if type(payload) is not bytes or not payload.endswith(b"\n") or b"\n" in payload[:-1]:
        raise S3AccessError("worker frame must be one bounded JSON line")
    return document(payload, limit=maximum)


def encode_frame(value: Mapping[str, Any]) -> bytes:
    payload = canonical_json_bytes(document(value, limit=MAX_FRAME_BYTES - 1)) + b"\n"
    if len(payload) > MAX_FRAME_BYTES:
        raise S3AccessError("worker frame exceeds its byte bound")
    return payload


def _hex(value: Any) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise S3AccessError("worker identity is invalid")
    return value


def aware_now(clock: Clock) -> datetime:
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise S3AccessError("worker clock must supply an aware instant")
    return now.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class S3WorkerRequest:
    _canonical: bytes

    @classmethod
    def from_mapping(cls, value: Any) -> S3WorkerRequest:
        row = document(value, limit=MAX_FRAME_BYTES)
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
            },
            "worker request",
        )
        if (
            row["schema_version"] != REQUEST_SCHEMA
            or not isinstance(row["operation"], str)
            or row["operation"] not in OPERATIONS
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
            raise S3AccessError("read operation cannot carry mutation authority")
        return cls(canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def assert_current(self, clock: Clock) -> None:
        checked = S3WorkerRequest.from_mapping(self.to_dict()).to_dict()
        now = aware_now(clock)
        scope = S3AccessScope.from_mapping(checked["scope"])
        scope.assert_current(clock=lambda: now)
        remaining = (timestamp(checked["deadline"]) - now).total_seconds()
        if not 0 < remaining <= checked["scope"]["limits"]["request_seconds"]:
            raise S3AccessError("worker request deadline is unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class S3Credentials:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: datetime

    @classmethod
    def from_mapping(cls, value: Any, *, clock: Clock, deadline: datetime) -> S3Credentials:
        row = exact(
            value,
            {"access_key", "secret_key", "token", "expires_at"},
            "temporary credential material",
        )
        for name, lower, upper in (
            ("access_key", 16, 128),
            ("secret_key", 16, 128),
            ("token", 16, 12 * 1024),
        ):
            raw = row[name]
            if (
                not isinstance(raw, str)
                or not lower <= len(raw) <= upper
                or _SECRET_TEXT.fullmatch(raw) is None
            ):
                raise S3AccessError("temporary credential material is unsupported")
        expires = timestamp(row["expires_at"])
        now = aware_now(clock)
        if not now < deadline <= expires or not 0 < (expires - now).total_seconds() <= 900:
            raise S3AccessError("temporary credential lifetime is unsupported")
        return cls(row["access_key"], row["secret_key"], row["token"], expires)

    def client_arguments(self) -> dict[str, str]:
        return {
            "aws_access_key_id": self.access_key,
            "aws_secret_access_key": self.secret_key,
            "aws_session_token": self.token,
        }


class S3WorkerHandshake:
    """A protocol state machine; only the future native channel can authenticate ACKs."""

    def __init__(
        self, request: S3WorkerRequest, *, process_id: int, creation_identity: str, nonce: str
    ):
        self.request = S3WorkerRequest.from_mapping(request.to_dict())
        if (
            type(process_id) is not int
            or process_id <= 1
            or not isinstance(creation_identity, str)
            or re.fullmatch(r"[1-9][0-9]{0,31}", creation_identity) is None
        ):
            raise S3AccessError("worker process identity is invalid")
        self._ready = {
            "kind": "ready",
            "request_digest": self.request.digest,
            "process_id": process_id,
            "creation_identity": creation_identity,
            "nonce": _hex(nonce),
        }
        self._state = "ready"

    def ready(self) -> dict[str, Any]:
        return dict(self._ready)

    def accept_containment_ack(self, value: Any) -> None:
        expected = {**self._ready, "kind": "contained"}
        previous, self._state = self._state, "closed"
        if previous != "ready":
            raise S3AccessError("worker containment acknowledgement does not match")
        row = document(value)
        if type(row.get("process_id")) is not int or row != expected:
            raise S3AccessError("worker containment acknowledgement does not match")
        self._state = "contained"

    def accept_credentials(self, payload: bytes, *, clock: Clock) -> S3Credentials:
        if self._state != "contained":
            raise S3AccessError("worker is not ready for private credential material")
        self._state = "closed"
        self.request.assert_current(clock)
        frame = decode_frame(payload, maximum=MAX_SECRET_FRAME_BYTES)
        exact(frame, {"kind", "request_digest", "nonce", "credentials"}, "private credential frame")
        if (
            frame["kind"] != "credentials"
            or frame["request_digest"] != self.request.digest
            or frame["nonce"] != self._ready["nonce"]
        ):
            raise S3AccessError("private credential frame belongs to another worker request")
        return S3Credentials.from_mapping(
            frame["credentials"],
            clock=clock,
            deadline=timestamp(self.request.to_dict()["deadline"]),
        )


def permit_request(
    request: S3WorkerRequest, sequence: int, send: Mapping[str, Any]
) -> dict[str, Any]:
    row = request.to_dict()
    if type(sequence) is not int or not 1 <= sequence <= row["max_sends"]:
        raise S3AccessError("worker send allowance is exhausted")
    preview = {
        "kind": "send",
        "request_digest": request.digest,
        "sequence": sequence,
        "send": dict(send),
    }
    return {**preview, "send_digest": content_hash(preview)}


def validate_permit(value: Any, requested: Mapping[str, Any]) -> None:
    expected = {
        "kind": "permit",
        "request_digest": requested["request_digest"],
        "sequence": requested["sequence"],
        "send_digest": requested["send_digest"],
    }
    row = document(value, limit=2048)
    if type(row.get("sequence")) is not int or row != expected:
        raise S3AccessError("native send permit does not match the exact one-use request")


def operation_plan(request: S3WorkerRequest) -> list[tuple[str, str, str]]:
    selected = request.to_dict()["operation"]
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


def validate_result(request: S3WorkerRequest, value: Any) -> dict[str, Any]:
    """Validate worker-reported data, never elevate it to independent evidence."""
    request = S3WorkerRequest.from_mapping(request.to_dict())
    source = request.to_dict()
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
        row["schema_version"] != "bluefire.s3-worker-result.v1"
        or row["request_digest"] != request.digest
        or row["runtime_isolation_proven"] is not False
    ):
        raise S3AccessError("worker result binding or provenance is invalid")
    if row["outcome"] not in ("observed", "failed", "reconcile_required"):
        raise S3AccessError("worker result outcome is invalid")
    consumed = row["send_permits_consumed"]
    calls = row["calls"]
    plan = operation_plan(request)
    if (
        type(consumed) is not int
        or not 0 <= consumed <= source["max_sends"]
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
                or call["error_code"] not in SAFE_ERROR_CODES
                or not 400 <= status <= 599
            ):
                raise S3AccessError("worker error projection is invalid")
        elif status not in ({200, 204} if operation == "PutBucketPolicy" else {200}):
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
            source["operation"] not in {"apply_policy", "rollback_policy"} or consumed < 3
        ):
            raise S3AccessError("worker reconciliation result has no write debit")
        return row
    if row["problem"] is not None or len(calls) != len(plan) or consumed != len(plan):
        raise S3AccessError("worker observations lack complete operation accounting")
    data = row["data"]
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
