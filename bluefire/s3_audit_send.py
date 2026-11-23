"""Exact audit SDK preparation and response accounting, not send authority."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote, urlsplit

from . import s3_audit_collection_contract as audit
from . import s3_audit_wire as wire
from .s3_access_contract import S3AccessError, S3AccessScope, document
from .s3_access_sdk_transport import BoundedSdkBody
from .util import canonical_json_bytes


def target(value: Mapping[str, Any], service: str) -> tuple[str, str]:
    row = wire.request(value)
    if service not in {"sts", "s3"}:
        raise S3AccessError("audit SDK service is unsupported")
    region = (
        row["audit"]["source"]["audit_bucket_region"] if service == "s3" else row["scope"]["region"]
    )
    return region, f"{service}.{region}.amazonaws.com"


def parameters(send: Mapping[str, Any]) -> dict[str, Any]:
    operation, resource = send["operation"], send["resource"]
    if operation == "GetCallerIdentity":
        return {}
    if operation == "AssumeRole":
        return {
            "RoleArn": resource["role_arn"],
            "RoleSessionName": resource["session_name"],
            "DurationSeconds": 900,
        }
    if operation == "ListObjectsV2":
        return dict(resource)
    return {key: resource[key] for key in ("Bucket", "ExpectedBucketOwner", "Key", "IfMatch")}


def prepared_send(
    row: Mapping[str, Any],
    active: Mapping[str, Any],
    prepared: Any,
    *,
    sequence: int,
    committed_discovery: Mapping[str, Any] | None,
) -> dict[str, Any]:
    expected = wire.planned_send(row, sequence, committed_discovery=committed_discovery)
    if (active["service"], active["operation"], active["role"]) != (
        expected["service"],
        expected["operation"],
        expected["role"],
    ) or canonical_json_bytes(active["parameters"]) != canonical_json_bytes(parameters(expected)):
        raise S3AccessError("audit SDK parameters differ from the exact send")
    url = urlsplit(prepared.url)
    if (
        url.scheme != "https"
        or url.hostname != expected["host"]
        or url.port not in (None, 443)
        or url.username is not None
        or url.password is not None
        or url.fragment
        or prepared.method != expected["method"]
    ):
        raise S3AccessError("audit SDK endpoint differs from its exact target")
    body = prepared.body or b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    if type(body) is not bytes or len(body) > 20 * 1024:
        raise S3AccessError("audit SDK request body is unsupported")
    if "sha256:" + hashlib.sha256(body).hexdigest() != expected["payload_digest"]:
        raise S3AccessError("audit SDK body differs from its exact send")
    if expected["service"] == "sts":
        if url.path != "/" or url.query:
            raise S3AccessError("audit STS path differs from its fixed operation")
        return expected

    headers = {}
    for key, value in prepared.headers.items():
        name = str(key).lower()
        if name in headers:
            raise S3AccessError("audit SDK headers contain duplicate names")
        headers[name] = value.decode("ascii") if isinstance(value, bytes) else value
    params = parameters(expected)
    if headers.get("x-amz-expected-bucket-owner") != params["ExpectedBucketOwner"]:
        raise S3AccessError("audit SDK expected owner differs")
    forbidden = {
        "range",
        "x-amz-request-payer",
        "x-amz-server-side-encryption-customer-key",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    }
    if any(name in headers for name in forbidden):
        raise S3AccessError("audit SDK optional access parameters are unsupported")
    path = "/" + params["Bucket"]
    if expected["operation"] == "ListObjectsV2":
        if "if-match" in headers:
            raise S3AccessError("audit listing cannot carry an object condition")
        query = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6)
        # Pinned Botocore adds this encoding-only field before serializing ListObjectsV2.
        expected_query = {
            "list-type": "2",
            "prefix": params["Prefix"],
            "start-after": params["StartAfter"],
            "max-keys": "16",
            "encoding-type": "url",
        }
        if len(query) != len(dict(query)) or dict(query) != expected_query:
            raise S3AccessError("audit listing query differs from its dated prefix")
    else:
        path += "/" + quote(params["Key"], safe="/")
        if url.query or headers.get("if-match") != params["IfMatch"]:
            raise S3AccessError("audit object lacks its exact conditional identity")
    if url.path != path:
        raise S3AccessError("audit SDK path differs from its exact resource")
    return expected


class AuditSendState:
    """Worker-local accounting bound to the existing guard's current send."""

    def __init__(self, value: Mapping[str, Any]):
        self.row = wire.request(value)
        self.limits = audit.budget(
            S3AccessScope.from_mapping(self.row["scope"]), self.row["audit"]["source"]
        )["per_batch"]
        self._discovery: dict[str, Any] | None = None
        self._discovery_attempted = False
        self._receipts: dict[int, dict[str, Any]] = {}
        self.sdk_body_bytes = 0
        self.compressed_bytes = 0
        self.current: dict[str, Any] | None = None

    @property
    def discovery(self) -> dict[str, Any] | None:
        return (
            document(self._discovery, limit=audit.MAX_DURABLE_BYTES)
            if self._discovery is not None
            else None
        )

    def begin(self, sequence: int, active: Mapping[str, Any]) -> None:
        if self.current is not None and not self.current["reported"]:
            raise S3AccessError("audit response must finish before another send")
        expected = wire.planned_send(self.row, sequence, committed_discovery=self.discovery)
        if (active["service"], active["operation"], active["role"]) != (
            expected["service"],
            expected["operation"],
            expected["role"],
        ) or canonical_json_bytes(active["parameters"]) != canonical_json_bytes(
            parameters(expected)
        ):
            raise S3AccessError("audit SDK call differs from its fixed operation sequence")
        self.current = {
            "sequence": sequence,
            "operation": expected["operation"],
            "body": None,
            "policy": None,
            "bytes": 0,
            "reported": False,
        }

    def response_policy(self) -> tuple[int, Callable[[int], None]]:
        token = self.current
        if token is None or token["policy"] is not None:
            raise S3AccessError("audit response has no unused send policy")
        remaining = self.limits["sdk_body_bytes"] - self.sdk_body_bytes
        limit = min(audit.MAX_RESPONSE_BYTES, remaining)
        if token["operation"] == "GetObject":
            limit = min(limit, self.limits["compressed_bytes"] - self.compressed_bytes)
        if limit <= 0:
            raise S3AccessError("audit response byte budget is exhausted")

        def account(amount: int) -> None:
            if (
                token is not self.current
                or token["body"] is None
                or type(amount) is not int
                or amount <= 0
            ):
                raise S3AccessError("audit response byte accounting differs from its send")
            token["bytes"] += amount
            self.sdk_body_bytes += amount
            if token["operation"] == "GetObject":
                self.compressed_bytes += amount
            if (
                token["bytes"] > limit
                or self.sdk_body_bytes > self.limits["sdk_body_bytes"]
                or self.compressed_bytes > self.limits["compressed_bytes"]
            ):
                raise S3AccessError("audit cumulative response budget is exhausted")

        token["policy"] = (limit, account)
        return limit, account

    def capture_response(self, body: BoundedSdkBody) -> None:
        token = self.current
        if (
            token is None
            or token["body"] is not None
            or token["policy"] is None
            or type(body) is not BoundedSdkBody
            or body.total != 0
            or body.closed
            or body.complete
            or body.limit != token["policy"][0]
            or body.account_bytes is not token["policy"][1]
        ):
            raise S3AccessError("audit response body differs from its original send")
        token["body"] = body

    def response_receipt(self) -> dict[str, Any]:
        token = self.current
        if token is None:
            raise S3AccessError("audit response lacks an original send")
        body = token["body"]
        if body is None or not body.complete or not body.closed or body.total != token["bytes"]:
            raise S3AccessError("audit response lacks a complete original body")
        token["reported"] = True
        receipt = {"body_sha256": "sha256:" + body.body_sha256, "sdk_body_bytes": body.total}
        self._receipts[token["sequence"]] = receipt
        return dict(receipt)

    def accept_discovery(
        self,
        frame: Mapping[str, Any],
        ack: Mapping[str, Any],
        *,
        reservation_digest: str,
        sequence: int,
    ) -> dict[str, Any]:
        lists = audit.list_parameters(
            S3AccessScope.from_mapping(self.row["scope"]), self.row["audit"]
        )
        if (
            self._discovery_attempted
            or sequence != 3 + len(lists)
            or self.current is None
            or not self.current["reported"]
        ):
            raise S3AccessError("audit discovery is not at its original one-shot boundary")
        self._discovery_attempted = True
        durable = wire.discovery(self.row, frame, reservation_digest=reservation_digest)
        if any(
            item["body_sha256"] != self._receipts[4 + index]["body_sha256"]
            for index, item in enumerate(durable["listings"])
        ):
            raise S3AccessError("audit discovery differs from its original listing bodies")
        wire.validate_discovery_ack(self.row, durable, ack)
        self._discovery = durable
        return document(durable, limit=audit.MAX_DURABLE_BYTES)
