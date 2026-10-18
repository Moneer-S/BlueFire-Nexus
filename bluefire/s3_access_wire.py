"""Strict worker messages. Frame matching does not prove native containment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, cast

from . import s3_access_wire_contract as ordinary
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .s3_access_wire_contract import (
    MAX_FRAME_BYTES as MAX_FRAME_BYTES,
)
from .s3_access_wire_contract import (
    OPERATIONS as OPERATIONS,
)
from .s3_access_wire_contract import (
    REQUEST_SCHEMA as REQUEST_SCHEMA,
)
from .s3_access_wire_contract import (
    SAFE_ERROR_CODES as SAFE_ERROR_CODES,
)
from .s3_access_wire_contract import (
    SAFE_REQUEST_ID as SAFE_REQUEST_ID,
)
from .s3_access_wire_contract import (
    _hex as _hex,
)
from .util import canonical_json_bytes, content_hash

MAX_SECRET_FRAME_BYTES = 16 * 1024
_SECRET_TEXT = re.compile(r"[\x21-\x7e]+", re.ASCII)
Clock = Callable[[], datetime]


def decode_frame(payload: bytes, *, maximum: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    if type(payload) is not bytes or not payload.endswith(b"\n") or b"\n" in payload[:-1]:
        raise S3AccessError("worker frame must be one bounded JSON line")
    return document(payload, limit=maximum)


def encode_frame(value: Mapping[str, Any]) -> bytes:
    payload = canonical_json_bytes(document(value, limit=MAX_FRAME_BYTES - 1)) + b"\n"
    if len(payload) > MAX_FRAME_BYTES:
        raise S3AccessError("worker frame exceeds its byte bound")
    return payload


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
        if row.get("schema_version") == "bluefire.s3-worker-request.v3":
            from . import s3_audit_wire as audit_wire

            return cls(canonical_json_bytes(audit_wire.request(row)))
        return cls(canonical_json_bytes(ordinary.request(row)))

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
        if checked["schema_version"] == "bluefire.s3-worker-request.v3":
            from . import s3_audit_collection_contract as audit

            seconds = audit.budget(scope, checked["audit"]["source"])["per_batch"]["seconds"]
            if now < timestamp(checked["audit"]["issued_at"]) or remaining > seconds:
                raise S3AccessError("audit request is outside its original collection interval")


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
        self.reservation_digest: str | None = None

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
        audit_request = self.request.to_dict()["schema_version"] == "bluefire.s3-worker-request.v3"
        exact(
            frame,
            {"kind", "request_digest", "nonce", "credentials"}
            | ({"reservation_digest"} if audit_request else set()),
            "private credential frame",
        )
        if (
            frame["kind"] != "credentials"
            or frame["request_digest"] != self.request.digest
            or frame["nonce"] != self._ready["nonce"]
        ):
            raise S3AccessError("private credential frame belongs to another worker request")
        reservation = digest(frame["reservation_digest"]) if audit_request else None
        credentials = S3Credentials.from_mapping(
            frame["credentials"],
            clock=clock,
            deadline=timestamp(self.request.to_dict()["deadline"]),
        )
        self.reservation_digest = reservation
        return credentials


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
    row = request.to_dict()
    if row["schema_version"] == "bluefire.s3-worker-request.v3":
        from . import s3_audit_wire as audit_wire

        return audit_wire.operation_plan(row)
    return ordinary.operation_plan(row)


def validate_result(request: S3WorkerRequest, value: Any) -> dict[str, Any]:
    """Validate worker-reported data, never elevate it to independent evidence."""
    request = S3WorkerRequest.from_mapping(request.to_dict())
    source = request.to_dict()
    if source["schema_version"] == "bluefire.s3-worker-request.v3":
        from . import s3_audit_wire as audit_wire

        return audit_wire.validate_result(source, value)
    return ordinary.validate_result(source, value)
