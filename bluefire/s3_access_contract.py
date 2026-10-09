"""Finite S3 experiment scope; validation is neither enrollment nor authority."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, cast

from .util import canonical_json_bytes, content_hash

SCOPE_SCHEMA = "bluefire.s3-access-scope.v1"
MAX_DOCUMENT_BYTES = 32 * 1024
MAX_POLICY_BYTES = 20 * 1024
_SCOPE = re.compile(r"s3-[0-9a-f]{32}", re.ASCII)
_ACCOUNT = re.compile(r"[0-9]{12}", re.ASCII)
_REGION = re.compile(
    r"(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]?",
    re.ASCII,
)
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_-]{1,64})", re.ASCII)
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
LIMIT_CEILINGS = {
    "api_calls": 300,
    "business_attempts": 6,
    "sessions": 6,
    "session_seconds": 900,
    "object_bytes": 64 * 1024,
    "audit_bytes": 20 * 1024 * 1024,
    "audit_events": 1000,
    "business_seconds": 1800,
    "convergence_seconds": 300,
    "audit_seconds": 1800,
    "cleanup_seconds": 900,
    "request_seconds": 30,
    "policy_changes": 1,
    "rollbacks": 1,
}


class S3AccessError(ValueError):
    """A bounded structural refusal without echoing untrusted input."""


def exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise S3AccessError(f"{label} fields are unsupported")
    return value


def text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise S3AccessError(f"{label} is invalid")
    return value


def digest(value: Any) -> str:
    return text(value, _DIGEST, "digest")


def role_arn(value: Any, account_id: str) -> str:
    role = text(value, _ROLE, "same-account role")
    match = _ROLE.fullmatch(role)
    if match is None or match.group(1) != account_id:
        raise S3AccessError("role belongs to another account")
    return role


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise S3AccessError("document contains duplicate JSON keys")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise S3AccessError("document contains a non-finite JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise S3AccessError("document contains a non-finite JSON number")
    return result


def document(value: Any, *, limit: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    """Clone strict JSON without interpreting its fields or establishing trust."""
    try:
        if isinstance(value, (bytes, str)):
            payload = value.encode("utf-8") if isinstance(value, str) else value
        elif isinstance(value, Mapping):
            # JSON round-tripping must not silently coerce non-string map keys.
            def keys(item: Any) -> None:
                if isinstance(item, Mapping):
                    if any(not isinstance(key, str) for key in item):
                        raise S3AccessError("document keys must be strings")
                    for child in item.values():
                        keys(child)
                elif isinstance(item, list):
                    for child in item:
                        keys(child)
                elif item is not None and type(item) not in (str, int, float, bool):
                    raise S3AccessError("document contains a non-JSON value")

            keys(value)
            payload = canonical_json_bytes(value)
        else:
            raise S3AccessError("document must be a JSON object")
        if len(payload) > limit:
            raise S3AccessError("document exceeds its byte bound")
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_finite_float,
        )
        if not isinstance(parsed, dict):
            raise S3AccessError("document must be a JSON object")
        return parsed
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, S3AccessError):
            raise
        raise S3AccessError("document is not strict bounded JSON") from None


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise S3AccessError("scope timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise S3AccessError("scope timestamp must have a valid timezone") from None


@dataclass(frozen=True, slots=True)
class S3AccessScope:
    """Immutable structural scope, not a verified resource or execution grant."""

    _canonical: bytes

    @classmethod
    def from_mapping(cls, value: Any) -> S3AccessScope:
        row = document(value)
        exact(
            row,
            {
                "schema_version",
                "scope_id",
                "account_id",
                "region",
                "roles",
                "bucket",
                "prefix",
                "objects",
                "policy",
                "ownership_receipt_digest",
                "created_at",
                "expires_at",
                "limits",
            },
            "S3 scope",
        )
        if row["schema_version"] != SCOPE_SCHEMA:
            raise S3AccessError("S3 scope schema is unsupported")
        identity = text(row["scope_id"], _SCOPE, "scope identity")
        account = text(row["account_id"], _ACCOUNT, "account identity")
        text(row["region"], _REGION, "commercial region")
        roles = exact(row["roles"], {"controller", "probe", "legitimate"}, "roles")
        bound_roles = [role_arn(value, account) for value in roles.values()]
        if len(set(bound_roles)) != 3:
            raise S3AccessError("controller and reader roles must be distinct")
        bucket = text(row["bucket"], _BUCKET, "general-purpose bucket")
        if bucket.startswith(("xn--", "sthree-", "amzn-s3-demo-")) or bucket.endswith(
            ("-s3alias", "--ol-s3", "--x-s3", "--table-s3")
        ):
            raise S3AccessError("bucket naming family is unsupported")
        prefix = f"bluefire/{identity}/"
        if row["prefix"] != prefix:
            raise S3AccessError("generated prefix differs from its scope identity")
        limits = exact(row["limits"], set(LIMIT_CEILINGS), "limits")
        for key, maximum in LIMIT_CEILINGS.items():
            if type(limits[key]) is not int or not 1 <= limits[key] <= maximum:
                raise S3AccessError("scope limit is outside the supported ceiling")
        if (
            limits["session_seconds"] != 900
            or limits["convergence_seconds"] > limits["business_seconds"]
        ):
            raise S3AccessError("session or convergence limit is unsupported")
        objects = row["objects"]
        if not isinstance(objects, list) or len(objects) != 2:
            raise S3AccessError("scope requires exactly two generated objects")
        total = 0
        for obj, purpose, name in zip(
            objects, ("primary", "health"), ("records.jsonl", "health.jsonl"), strict=True
        ):
            exact(obj, {"purpose", "key", "sha256", "size_bytes"}, "generated object")
            if obj["purpose"] != purpose or obj["key"] != prefix + name:
                raise S3AccessError("generated object identity is unsupported")
            digest(obj["sha256"])
            if (
                type(obj["size_bytes"]) is not int
                or not 1 <= obj["size_bytes"] <= limits["object_bytes"]
            ):
                raise S3AccessError("generated object size is outside the scope")
            total += obj["size_bytes"]
        if total > limits["object_bytes"]:
            raise S3AccessError("combined generated objects exceed the byte allowance")
        policy = exact(
            row["policy"], {"probe_sid", "legitimate_sid", "baseline_digest"}, "policy binding"
        )
        suffix = identity[3:]
        if (
            policy["probe_sid"] != "BlueFireProbe" + suffix
            or policy["legitimate_sid"] != "BlueFireLegitimate" + suffix
        ):
            raise S3AccessError("owned policy statement identities differ from the scope")
        digest(policy["baseline_digest"])
        digest(row["ownership_receipt_digest"])
        created, expires = timestamp(row["created_at"]), timestamp(row["expires_at"])
        duration = (expires - created).total_seconds()
        if (
            not 0
            < duration
            <= sum(limits[key] for key in ("business_seconds", "audit_seconds", "cleanup_seconds"))
        ):
            raise S3AccessError("scope lifetime is outside its total time allowance")
        row["created_at"] = created.isoformat().replace("+00:00", "Z")
        row["expires_at"] = expires.isoformat().replace("+00:00", "Z")
        return cls(canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def assert_current(self, *, clock: Callable[[], datetime]) -> None:
        now = clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise S3AccessError("scope clock must supply a timezone-aware instant")
        row = self.to_dict()
        if (
            not timestamp(row["created_at"])
            <= now.astimezone(timezone.utc)
            < timestamp(row["expires_at"])
        ):
            raise S3AccessError("scope is not current")

    @property
    def object_arns(self) -> tuple[str, str]:
        row = self.to_dict()
        return cast(
            tuple[str, str],
            tuple(f"arn:aws:s3:::{row['bucket']}/{obj['key']}" for obj in row["objects"]),
        )

    @property
    def service_hosts(self) -> Mapping[str, str]:
        """Candidate commercial hosts, not a service-availability or DNS receipt."""
        region = self.to_dict()["region"]
        return {
            "s3": f"s3.{region}.amazonaws.com",
            "sts": f"sts.{region}.amazonaws.com",
            "iam": "iam.amazonaws.com",
        }
