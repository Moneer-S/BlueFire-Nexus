"""Immutable provider enrollment and bounded secret-free inference channel frames.

Only trusted composition may enroll a channel. This module creates no network or
process and does not attest that a future channel implements namespace isolation.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import time
from dataclasses import dataclass, replace
from typing import Any, Mapping
from urllib.parse import urlsplit

from .ai_wire import AIProviderTransportError, structured_request
from .config import AIProviderConfig, AIProviderKind
from .util import canonical_json_bytes, content_hash

MAX_BODY_BYTES = 1_048_576
_ID = re.compile(r"[0-9a-f]{64}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_PURPOSES = {
    "bluefire_connection_check",
    "bluefire_ai_proposal",
    "bluefire_ai_graph_draft",
    "bluefire_detection_source_revision",
    "bluefire_detection_source_creation",
    "bluefire_method_comparison",
    "bluefire_experiment_assistance",
    "bluefire_run_evidence_inspection",
}
ERROR_CODES = frozenset(
    {
        "broker_unavailable",
        "broker_binding_required",
        "broker_schema_unavailable",
        "broker_session_expired",
        "credential_unavailable",
        "request_cancelled",
        "request_timed_out",
        "transport_failed",
        "authentication_failed",
        "rate_limited",
        "endpoint_rejected",
        "response_content_type",
        "response_too_large",
        "request_too_large",
    }
)


def refusal(code: str = "broker_binding_required") -> AIProviderTransportError:
    return AIProviderTransportError(
        "Enrolled provider broker refused the request", retryable=False, code=code
    )


def body_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise ValueError("nonfinite value")


def strict_object(payload: bytes) -> Mapping[str, Any]:
    try:
        if type(payload) is not bytes or not 1 <= len(payload) <= MAX_BODY_BYTES:
            raise ValueError
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite
        )
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise refusal() from None


def schema_identity(body: bytes, kind: AIProviderKind) -> tuple[str, str]:
    value = strict_object(body)
    try:
        spec = (
            value["text"]["format"]
            if kind is AIProviderKind.OPENAI_RESPONSES
            else value["response_format"]["json_schema"]
        )
        name = spec["name"]
        if name not in _PURPOSES or not isinstance(spec["schema"], dict):
            raise ValueError
        return name, content_hash(spec["schema"])
    except (ValueError, TypeError, KeyError):
        raise refusal("broker_schema_unavailable") from None


@dataclass(frozen=True)
class BrokerEnrollment:
    configuration: bytes
    session_id: str
    expires_at_ms: int
    schemas: tuple[tuple[str, str], ...]
    destination_policy: str

    def __post_init__(self) -> None:
        config = self.config
        if (
            config.kind is AIProviderKind.DETERMINISTIC
            or not isinstance(self.session_id, str)
            or _ID.fullmatch(self.session_id) is None
            or type(self.expires_at_ms) is not int
            or self.expires_at_ms <= 0
            or type(self.schemas) is not tuple
            or not 1 <= len(self.schemas) <= 16
            or any(
                type(item) is not tuple
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
                for item in self.schemas
            )
            or len(set(self.schemas)) != len(self.schemas)
            or any(
                name not in _PURPOSES or _HASH.fullmatch(digest) is None
                for name, digest in self.schemas
            )
            or not isinstance(self.destination_policy, str)
            or self.destination_policy not in {"public_https", "explicit_endpoint"}
        ):
            raise refusal()
        if self.destination_policy == "public_https":
            parsed = urlsplit(str(config.endpoint))
            if parsed.scheme != "https" or parsed.hostname == "localhost":
                raise refusal()
            try:
                literal = ipaddress.ip_address(str(parsed.hostname))
            except ValueError:
                literal = None
            if literal is not None and not literal.is_global:
                raise refusal()
        if canonical_json_bytes(config.to_dict()) != self.configuration:
            raise refusal()

    @classmethod
    def create(
        cls,
        config: AIProviderConfig,
        *,
        session_id: str,
        expires_at_ms: int,
        schemas: tuple[tuple[str, str], ...],
        destination_policy: str = "public_https",
    ) -> BrokerEnrollment:
        now = time.time_ns() // 1_000_000
        if type(expires_at_ms) is not int or not now < expires_at_ms <= now + 900_000:
            raise refusal("broker_session_expired")
        enrolled = cls(
            canonical_json_bytes(config.to_dict()),
            session_id,
            expires_at_ms,
            schemas,
            destination_policy,
        )
        return replace(enrolled, schemas=tuple(sorted(enrolled.schemas)))

    @property
    def config(self) -> AIProviderConfig:
        return AIProviderConfig.from_mapping(strict_object(self.configuration))

    @property
    def digest(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.ai-broker-enrollment.v1",
                "configuration_digest": content_hash(self.config.to_dict()),
                "session_id": self.session_id,
                "expires_at_ms": self.expires_at_ms,
                "schemas": [list(item) for item in self.schemas],
                "destination_policy": self.destination_policy,
            }
        )

    def require_current(self, config: AIProviderConfig) -> None:
        if canonical_json_bytes(config.to_dict()) != self.configuration:
            raise refusal()
        if time.time_ns() // 1_000_000 >= self.expires_at_ms:
            raise refusal("broker_session_expired")

    def validate_body(self, body: bytes) -> tuple[str, str]:
        config = self.config
        identity = schema_identity(body, config.kind)
        if identity not in self.schemas:
            raise refusal("broker_schema_unavailable")
        value = strict_object(body)
        try:
            if config.kind is AIProviderKind.OPENAI_RESPONSES:
                instructions, input_text = value["instructions"], value["input"]
                schema = value["text"]["format"]["schema"]
                tokens = value["max_output_tokens"]
            else:
                instructions, input_text = (
                    value["messages"][0]["content"],
                    value["messages"][1]["content"],
                )
                schema = value["response_format"]["json_schema"]["schema"]
                tokens = value["max_completion_tokens"]
            if (
                not isinstance(instructions, str)
                or not isinstance(input_text, str)
                or type(tokens) is not int
                or not 1 <= tokens <= config.max_output_tokens
            ):
                raise ValueError
            expected = structured_request(
                replace(config, max_output_tokens=tokens),
                instructions=instructions,
                input_text=input_text,
                name=identity[0],
                schema=schema,
            )
            if canonical_json_bytes(value) != canonical_json_bytes(expected):
                raise ValueError
        except (ValueError, TypeError, KeyError, IndexError):
            raise refusal() from None
        return identity


def validate_broker_request(
    enrollment: BrokerEnrollment, request: Mapping[str, Any]
) -> bytes | None:
    """Shared client/server validator; a channel server must also reject reused IDs."""
    common = {"kind", "session_id", "binding_digest", "request_id", "timeout_seconds"}
    fields = common if request.get("kind") == "readiness" else common | {"body", "body_digest"}
    try:
        enrollment.require_current(enrollment.config)
        if (
            set(request) != fields
            or request["kind"] not in {"readiness", "post"}
            or request["session_id"] != enrollment.session_id
            or request["binding_digest"] != enrollment.digest
            or not isinstance(request["request_id"], str)
            or _ID.fullmatch(request["request_id"]) is None
        ):
            raise ValueError
        timeout = request["timeout_seconds"]
        if (
            type(timeout) not in {int, float}
            or not math.isfinite(timeout)
            or not 0 < timeout <= enrollment.config.timeout_seconds
        ):
            raise ValueError
        if request["kind"] == "readiness":
            if timeout > 1:
                raise ValueError
            return None
        encoded = request["body"]
        if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY_BYTES:
            raise ValueError
        body = base64.b64decode(encoded, validate=True)
        if body_digest(body) != request["body_digest"]:
            raise ValueError
        enrollment.validate_body(body)
        return body
    except AIProviderTransportError:
        raise
    except (ValueError, TypeError, KeyError):
        raise refusal() from None
