"""Strict controller-owned relay cores for the generated Strix tenant lab.

This module intentionally contains no listener, DNS, socket, subprocess, or
container code.  A trusted controller supplies protected forwarder
capabilities.  The relays accept only fixed, typed operations and therefore
never receive an upstream URL or a durable target/provider credential.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .engine_network_policy import EngineNetworkPlan
from .tenant_record_service import TenantResponse
from .util import canonical_json_bytes, content_hash, parse_iso8601_datetime

_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_TARGET_REQUEST_ID = re.compile(r"^relay-request-[0-9a-f]{32}$")
_MODEL_REQUEST_ID = re.compile(r"^gateway-request-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LAB_ID = re.compile(r"^[a-z][a-z0-9-]{7,63}$")
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}$")
_HEADER_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_TARGET_ROUTES = frozenset({"health", "metadata", "record_lookup", "bounded_export"})
_TARGET_REQUEST_HEADERS = frozenset({"accept", "user-agent", "x-bluefire-lab-tenant"})
_MODEL_REQUEST_HEADERS = frozenset({"accept", "content-type", "user-agent"})
_TARGET_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-length",
        "content-type",
        "x-bluefire-lab-request",
        "x-content-type-options",
    }
)
_MODEL_RESPONSE_HEADERS = frozenset(
    {"cache-control", "content-length", "content-type", "x-bluefire-provider"}
)
_FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "cookie",
        "forwarded",
        "host",
        "keep-alive",
        "location",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-bluefire-lab-source-token",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
    }
)
_MAX_HEADER_VALUE = 8_192
_MAX_JSON_DEPTH = 64
_CONTROLLED_PROVIDER_LABEL = "Test provider"
_CONTROLLED_SYSTEM_FINGERPRINT = "bluefire-test-provider-fixture-estimate"
_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
_SSE_RESPONSE_ID = re.compile(r"^chatcmpl-[0-9a-f]{12}-[0-9]{4}$")
_SSE_CALL_ID = re.compile(r"^call_[0-9]{4}_[0-9a-f]{16}$")
_JSON_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_CONTROLLED_STREAM_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "tools",
        "stream",
        "parallel_tool_calls",
        "tool_choice",
        "stream_options",
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "seed",
    }
)


class EngineRelayError(RuntimeError):
    """A fail-closed relay refusal with a bounded stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProtectedUpstreamUnknown(RuntimeError):
    """Protected forwarder signal that provider acceptance cannot be established."""

    def __init__(self, outcome_ref: str) -> None:
        self.outcome_ref = _require_digest(outcome_ref, "protected upstream outcome")
        super().__init__("protected model provider outcome is unknown")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _secret_in_bytes(secret: str, payload: bytes) -> bool:
    raw = secret.encode("ascii")
    escaped = json.dumps(secret, ensure_ascii=True)[1:-1].encode("ascii")
    return raw in payload or escaped in payload


def _json_contains_secret(value: Any, secret: str) -> bool:
    if isinstance(value, str):
        decoded = value
        for _ in range(_MAX_JSON_DEPTH):
            if secret in decoded:
                return True
            expanded = _JSON_UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), decoded)
            if expanded == decoded:
                return False
            decoded = expanded
        # Continued semantic expansion at the JSON-depth limit is ambiguous;
        # fail closed instead of forwarding a potentially concealed bearer.
        return True
    if isinstance(value, Mapping):
        return any(
            _json_contains_secret(key, secret) or _json_contains_secret(item, secret)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_json_contains_secret(item, secret) for item in value)
    return False


def model_gateway_authorization_ref(attempt_id: str, authorization_digest: str) -> str:
    if _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise ValueError("model gateway attempt ID is invalid")
    _require_digest(authorization_digest, "model gateway authorization digest")
    return content_hash(
        {
            "schema_version": "bluefire.model-gateway-authorization-ref.v1",
            "attempt_id": attempt_id,
            "authorization_digest": authorization_digest,
        }
    )


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _require_int(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside its reviewed bound")
    return value


def _require_text(value: object, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _require_window(created_at: str, expires_at: str, *, maximum: timedelta) -> None:
    try:
        created = parse_iso8601_datetime(created_at)
        expires = parse_iso8601_datetime(expires_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("relay authority time is invalid") from exc
    if not created_at.endswith("Z") or not expires_at.endswith("Z"):
        raise ValueError("relay authority time must use canonical UTC")
    if expires <= created or expires - created > maximum:
        raise ValueError("relay authority lifetime is outside its reviewed bound")


def _require_timestamp(value: str, label: str) -> None:
    try:
        parse_iso8601_datetime(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not value.endswith("Z"):
        raise ValueError(f"{label} must use canonical UTC")


def _now_utc(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise EngineRelayError("clock_invalid", "relay clock is not UTC") from None
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EngineRelayError("clock_invalid", "relay clock is not UTC")
    return value.astimezone(timezone.utc)


def _audit_recorded_at(clock: Callable[[], datetime], fallback: str) -> str:
    try:
        return _now_utc(clock).isoformat().replace("+00:00", "Z")
    except EngineRelayError:
        _require_timestamp(fallback, "relay audit fallback timestamp")
        return fallback


def _not_expired(expires_at: str, clock: Callable[[], datetime]) -> datetime:
    now = _now_utc(clock)
    if now >= parse_iso8601_datetime(expires_at):
        raise EngineRelayError("expired", "relay authority has expired")
    return now


def _strict_json(value: bytes, *, label: str) -> Mapping[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = item
        return result

    def nonfinite(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        decoded = value.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise EngineRelayError("invalid_json", f"{label} must be strict UTF-8 JSON") from None
    if not isinstance(parsed, Mapping):
        raise EngineRelayError("invalid_json", f"{label} must be a JSON object")
    _json_depth(parsed, 0)
    return parsed


def _json_depth(value: Any, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise EngineRelayError("invalid_json", "JSON nesting exceeds its reviewed bound")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EngineRelayError("invalid_json", "JSON member is invalid")
            _json_depth(item, depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _json_depth(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise EngineRelayError("invalid_json", "JSON number is outside its reviewed bound")


def _controlled_stream_tool_names(request: Mapping[str, Any]) -> frozenset[str]:
    stream_options = request.get("stream_options")
    if (
        set(request) - _CONTROLLED_STREAM_REQUEST_FIELDS
        or not {"model", "messages", "tools", "stream", "stream_options"} <= set(request)
        or request.get("stream") is not True
        or request.get("parallel_tool_calls", False) is not False
        or not isinstance(stream_options, Mapping)
        or set(stream_options) != {"include_usage"}
        or stream_options.get("include_usage") is not True
        or not isinstance(request.get("messages"), list)
        or not request["messages"]
    ):
        raise EngineRelayError("invalid_request", "controlled streaming request is invalid")
    tools = request.get("tools")
    if not isinstance(tools, list) or not 1 <= len(tools) <= 128:
        raise EngineRelayError("invalid_request", "controlled streaming tools are invalid")
    names: set[str] = set()
    for tool in tools:
        if not isinstance(tool, Mapping) or set(tool) != {"type", "function"}:
            raise EngineRelayError("invalid_request", "controlled streaming tools are invalid")
        function = tool.get("function")
        if (
            tool.get("type") != "function"
            or not isinstance(function, Mapping)
            or set(function) - {"name", "description", "parameters", "strict"}
            or not {"name", "parameters"} <= set(function)
            or not isinstance(function.get("name"), str)
            or _TOOL_NAME.fullmatch(function["name"]) is None
            or function["name"] in names
            or not isinstance(function.get("parameters"), Mapping)
            or ("description" in function and not isinstance(function.get("description"), str))
            or ("strict" in function and not isinstance(function.get("strict"), bool))
        ):
            raise EngineRelayError("invalid_request", "controlled streaming tools are invalid")
        names.add(function["name"])
    choice = request.get("tool_choice")
    if choice is None or (isinstance(choice, str) and choice in {"auto", "required"}):
        return frozenset(names)
    if (
        not isinstance(choice, Mapping)
        or set(choice) != {"type", "function"}
        or choice.get("type") != "function"
        or not isinstance(choice.get("function"), Mapping)
        or set(choice["function"]) != {"name"}
        or choice["function"].get("name") not in names
    ):
        raise EngineRelayError("invalid_request", "controlled streaming tool choice is invalid")
    return frozenset({choice["function"]["name"]})


def _exact_mapping(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EngineRelayError("invalid_upstream", f"{label} is invalid")
    return value


def _controlled_sse_base(
    value: Mapping[str, Any], *, attempt_id: str, model_id: str
) -> tuple[str, int, str, str, str]:
    response_id = value.get("id")
    created = value.get("created")
    if (
        not isinstance(response_id, str)
        or _SSE_RESPONSE_ID.fullmatch(response_id) is None
        or not response_id.startswith(f"chatcmpl-{attempt_id[-12:]}-")
        or isinstance(created, bool)
        or not isinstance(created, int)
        or not 0 <= created <= 4_294_967_295
        or value.get("object") != "chat.completion.chunk"
        or value.get("model") != model_id
        or value.get("system_fingerprint") != _CONTROLLED_SYSTEM_FINGERPRINT
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream identity is invalid")
    return (
        response_id,
        created,
        value["object"],
        value["model"],
        value["system_fingerprint"],
    )


@dataclass(frozen=True, slots=True)
class _ControlledSSE:
    documents: tuple[Mapping[str, Any], ...]
    arguments: Mapping[str, Any]
    input_tokens: int
    output_tokens: int


def _parse_controlled_sse(
    body: bytes,
    *,
    attempt_id: str,
    model_id: str,
    tool_names: frozenset[str],
    bearer: str,
    max_input_tokens: int,
    max_output_tokens: int,
) -> _ControlledSSE:
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        raise EngineRelayError("invalid_upstream", "controlled stream is not UTF-8") from None
    if (
        not decoded
        or "\r" in decoded
        or decoded.startswith("\ufeff")
        or not decoded.endswith("\n\n")
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream framing is invalid")
    events = decoded.split("\n\n")
    if len(events) != 5 or events[-1] != "":
        raise EngineRelayError("invalid_upstream", "controlled stream event count is invalid")
    payloads: list[str] = []
    for event in events[:-1]:
        if "\n" in event or not event.startswith("data: ") or len(event) <= len("data: "):
            raise EngineRelayError("invalid_upstream", "controlled stream event is invalid")
        payloads.append(event.removeprefix("data: "))
    if payloads[-1] != "[DONE]" or any(payload == "[DONE]" for payload in payloads[:-1]):
        raise EngineRelayError("invalid_upstream", "controlled stream terminator is invalid")
    documents = tuple(
        _strict_json(payload.encode("utf-8"), label="controlled stream event")
        for payload in payloads[:-1]
    )
    if _json_contains_secret(documents, bearer):
        raise EngineRelayError("secret_leak", "controlled stream contains gateway authority")
    tool_document = _exact_mapping(
        documents[0],
        {"id", "object", "created", "model", "system_fingerprint", "choices"},
        "controlled stream tool frame",
    )
    finish_document = _exact_mapping(
        documents[1],
        {"id", "object", "created", "model", "system_fingerprint", "choices"},
        "controlled stream finish frame",
    )
    usage_document = _exact_mapping(
        documents[2],
        {"id", "object", "created", "model", "system_fingerprint", "choices", "usage"},
        "controlled stream usage frame",
    )
    identity = _controlled_sse_base(tool_document, attempt_id=attempt_id, model_id=model_id)
    if any(
        _controlled_sse_base(document, attempt_id=attempt_id, model_id=model_id) != identity
        for document in (finish_document, usage_document)
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream identity drifted")

    choices = tool_document.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise EngineRelayError("invalid_upstream", "controlled stream tool choice is invalid")
    choice = _exact_mapping(
        choices[0], {"index", "delta", "finish_reason"}, "controlled stream tool choice"
    )
    delta = _exact_mapping(
        choice.get("delta"), {"role", "tool_calls"}, "controlled stream tool delta"
    )
    calls = delta.get("tool_calls")
    if (
        isinstance(choice.get("index"), bool)
        or choice.get("index") != 0
        or choice.get("finish_reason") is not None
        or delta.get("role") != "assistant"
        or not isinstance(calls, list)
        or len(calls) != 1
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream tool delta is invalid")
    call = _exact_mapping(
        calls[0], {"index", "id", "type", "function"}, "controlled stream tool call"
    )
    function = _exact_mapping(
        call.get("function"), {"name", "arguments"}, "controlled stream function"
    )
    call_id = call.get("id")
    tool_name = function.get("name")
    arguments_text = function.get("arguments")
    if (
        isinstance(call.get("index"), bool)
        or call.get("index") != 0
        or not isinstance(call_id, str)
        or _SSE_CALL_ID.fullmatch(call_id) is None
        or call_id[5:9] != identity[0][-4:]
        or call.get("type") != "function"
        or not isinstance(tool_name, str)
        or tool_name not in tool_names
        or not isinstance(arguments_text, str)
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream function is invalid")
    try:
        arguments = _strict_json(
            arguments_text.encode("utf-8"), label="controlled stream function arguments"
        )
    except UnicodeEncodeError:
        raise EngineRelayError(
            "invalid_upstream", "controlled stream function is invalid"
        ) from None
    if _json_contains_secret(arguments, bearer):
        raise EngineRelayError("secret_leak", "controlled stream contains gateway authority")
    if arguments_text != json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ):
        raise EngineRelayError(
            "invalid_upstream", "controlled stream function arguments are not canonical"
        )

    finish_choices = finish_document.get("choices")
    if not isinstance(finish_choices, list) or len(finish_choices) != 1:
        raise EngineRelayError("invalid_upstream", "controlled stream finish choice is invalid")
    finish = _exact_mapping(
        finish_choices[0],
        {"index", "delta", "finish_reason"},
        "controlled stream finish choice",
    )
    if (
        isinstance(finish.get("index"), bool)
        or finish.get("index") != 0
        or finish.get("delta") != {}
        or finish.get("finish_reason") != "tool_calls"
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream finish choice is invalid")

    if usage_document.get("choices") != []:
        raise EngineRelayError("invalid_upstream", "controlled stream usage choices are invalid")
    usage = _exact_mapping(
        usage_document.get("usage"),
        {"prompt_tokens", "completion_tokens", "total_tokens"},
        "controlled stream usage",
    )
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")
    if (
        isinstance(input_tokens, bool)
        or not isinstance(input_tokens, int)
        or not 1 <= input_tokens <= max_input_tokens
        or isinstance(output_tokens, bool)
        or not isinstance(output_tokens, int)
        or not 1 <= output_tokens <= max_output_tokens
        or isinstance(total_tokens, bool)
        or not isinstance(total_tokens, int)
        or total_tokens != input_tokens + output_tokens
    ):
        raise EngineRelayError("invalid_upstream", "controlled stream usage is invalid")
    return _ControlledSSE(
        documents=documents,
        arguments=arguments,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )


def _validate_controlled_provider_error(value: Mapping[str, Any]) -> None:
    outer = _exact_mapping(value, {"error"}, "controlled provider refusal")
    error = _exact_mapping(
        outer.get("error"), {"message", "type", "code"}, "controlled provider refusal"
    )
    message = error.get("message")
    code = error.get("code")
    if (
        error.get("type") != "invalid_request_error"
        or not isinstance(message, str)
        or not message.isascii()
        or not 1 <= len(message) <= 512
        or any(ord(character) < 32 or ord(character) == 127 for character in message)
        or not isinstance(code, str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None
    ):
        raise EngineRelayError("invalid_upstream", "controlled provider refusal is invalid")


def _normalized_headers(
    value: Sequence[tuple[str, str]],
    *,
    allowed: frozenset[str],
    label: str,
) -> tuple[tuple[str, str], ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or len(value) > 32
    ):
        raise EngineRelayError("invalid_headers", f"{label} headers are invalid")
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for row in value:
        if not isinstance(row, tuple) or len(row) != 2:
            raise EngineRelayError("invalid_headers", f"{label} headers are invalid")
        name, raw = row
        if (
            not isinstance(name, str)
            or name != name.lower()
            or _HEADER_NAME.fullmatch(name) is None
            or name in seen
            or name in _FORBIDDEN_HEADERS
            or name not in allowed
            or not isinstance(raw, str)
            or len(raw) > _MAX_HEADER_VALUE
            or not raw.isascii()
            or raw != raw.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in raw)
        ):
            raise EngineRelayError("invalid_headers", f"{label} headers are invalid")
        seen.add(name)
        result.append((name, raw))
    return tuple(sorted(result))


def _response_headers(
    value: Mapping[str, str],
    *,
    allowed: frozenset[str],
    body_size: int,
    label: str,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not dict or len(value) > 32:
        raise EngineRelayError("invalid_upstream", f"{label} headers are invalid")
    normalized = _normalized_headers(tuple(value.items()), allowed=allowed, label=label)
    declared = dict(normalized).get("content-length")
    if declared is not None and (
        not declared.isascii() or not declared.isdigit() or int(declared) != body_size
    ):
        raise EngineRelayError("invalid_upstream", f"{label} content length is invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class TargetRelayPolicy:
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    objective_ref: str
    environment_ref: str
    target_snapshot_digest: str
    protected_target_ref: str
    relay_identity_ref: str
    network_policy_digest: str
    relay_authority: str
    admitted_routes: tuple[str, ...]
    admitted_record_ids: tuple[str, ...]
    admitted_tenant_ids: tuple[str, ...]
    created_at: str
    expires_at: str
    max_requests: int = 256
    max_response_bytes: int = 256 * 1024
    max_total_response_bytes: int = 4 * 1024 * 1024
    request_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise ValueError("target relay attempt ID is invalid")
        for value, label in (
            (self.binding_digest, "target relay binding"),
            (self.delegation_digest, "target relay delegation"),
            (self.objective_ref, "target relay objective"),
            (self.environment_ref, "target relay environment"),
            (self.target_snapshot_digest, "target relay snapshot"),
            (self.protected_target_ref, "target relay protected target"),
            (self.relay_identity_ref, "target relay identity"),
            (self.network_policy_digest, "target relay network policy"),
        ):
            _require_digest(value, label)
        expected_authority = f"bf-target-{self.attempt_id[-12:]}:8080"
        if self.relay_authority != expected_authority:
            raise ValueError("target relay authority is not bound to the attempt")
        if (
            not self.admitted_routes
            or tuple(sorted(set(self.admitted_routes))) != self.admitted_routes
            or not set(self.admitted_routes).issubset(_TARGET_ROUTES)
        ):
            raise ValueError("target relay routes are invalid")
        for values, label in (
            (self.admitted_record_ids, "target relay record IDs"),
            (self.admitted_tenant_ids, "target relay tenant IDs"),
        ):
            if (
                not values
                or len(values) > 64
                or tuple(sorted(set(values))) != values
                or any(_LAB_ID.fullmatch(item) is None for item in values)
            ):
                raise ValueError(f"{label} are invalid")
        _require_window(self.created_at, self.expires_at, maximum=timedelta(hours=2))
        _require_int(self.max_requests, "target relay request count", minimum=1, maximum=2_048)
        _require_int(
            self.max_response_bytes,
            "target relay response bytes",
            minimum=1_024,
            maximum=4 * 1024 * 1024,
        )
        _require_int(
            self.max_total_response_bytes,
            "target relay total response bytes",
            minimum=self.max_response_bytes,
            maximum=64 * 1024 * 1024,
        )
        _require_int(self.request_timeout_ms, "target relay timeout", minimum=100, maximum=30_000)

    @classmethod
    def from_network_plan(
        cls,
        plan: EngineNetworkPlan,
        **values: Any,
    ) -> "TargetRelayPolicy":
        return cls(
            attempt_id=plan.attempt_id,
            network_policy_digest=plan.policy_digest,
            relay_authority=f"{plan.target.service_name}:{plan.target.port}",
            admitted_routes=tuple(sorted(values.pop("admitted_routes"))),
            admitted_record_ids=tuple(sorted(values.pop("admitted_record_ids"))),
            admitted_tenant_ids=tuple(sorted(values.pop("admitted_tenant_ids"))),
            **values,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.target-relay-policy.v1",
            "attempt_id": self.attempt_id,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "objective_ref": self.objective_ref,
            "environment_ref": self.environment_ref,
            "target_snapshot_digest": self.target_snapshot_digest,
            "protected_target_ref": self.protected_target_ref,
            "relay_identity_ref": self.relay_identity_ref,
            "network_policy_digest": self.network_policy_digest,
            "relay_authority": self.relay_authority,
            "admitted_routes": list(self.admitted_routes),
            "admitted_record_ids": list(self.admitted_record_ids),
            "admitted_tenant_ids": list(self.admitted_tenant_ids),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "max_requests": self.max_requests,
            "max_response_bytes": self.max_response_bytes,
            "max_total_response_bytes": self.max_total_response_bytes,
            "request_timeout_ms": self.request_timeout_ms,
            "redirect_policy": "refuse_all",
            "source_identity": "engine_worker",
        }

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ModelGatewayPolicy:
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    objective_ref: str
    environment_ref: str
    provider_ref: str
    model_id: str
    data_destination_ref: str
    relay_identity_ref: str
    network_policy_digest: str
    gateway_authority: str
    authorization_ref: str
    authorization_digest: str
    created_at: str
    expires_at: str
    max_requests: int
    max_request_bytes: int
    max_response_bytes: int
    max_total_request_bytes: int
    max_total_response_bytes: int
    max_input_tokens_per_request: int
    max_output_tokens_per_request: int
    max_total_tokens: int
    max_cost_microunits_per_request: int
    max_total_cost_microunits: int
    request_timeout_ms: int
    allow_controlled_test_sse: bool = False

    def __post_init__(self) -> None:
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise ValueError("model gateway attempt ID is invalid")
        for value, label in (
            (self.binding_digest, "model gateway binding"),
            (self.delegation_digest, "model gateway delegation"),
            (self.objective_ref, "model gateway objective"),
            (self.environment_ref, "model gateway environment"),
            (self.provider_ref, "model gateway provider"),
            (self.data_destination_ref, "model gateway data destination"),
            (self.relay_identity_ref, "model gateway relay identity"),
            (self.network_policy_digest, "model gateway network policy"),
            (self.authorization_ref, "model gateway authorization ref"),
            (self.authorization_digest, "model gateway authorization digest"),
        ):
            _require_digest(value, label)
        if _MODEL_ID.fullmatch(self.model_id) is None:
            raise ValueError("model gateway model identity is invalid")
        expected_authority = f"bf-model-{self.attempt_id[-12:]}:8081"
        if self.gateway_authority != expected_authority:
            raise ValueError("model gateway authority is not bound to the attempt")
        expected_authorization_ref = model_gateway_authorization_ref(
            self.attempt_id, self.authorization_digest
        )
        if self.authorization_ref != expected_authorization_ref:
            raise ValueError("model gateway authorization ref is not canonical")
        _require_window(self.created_at, self.expires_at, maximum=timedelta(hours=2))
        _require_int(self.max_requests, "model gateway request count", minimum=1, maximum=256)
        _require_int(
            self.max_request_bytes, "model gateway request bytes", minimum=1_024, maximum=1_048_576
        )
        _require_int(
            self.max_response_bytes,
            "model gateway response bytes",
            minimum=1_024,
            maximum=1_048_576,
        )
        _require_int(
            self.max_total_request_bytes,
            "model gateway total request bytes",
            minimum=self.max_request_bytes,
            maximum=16 * 1024 * 1024,
        )
        _require_int(
            self.max_total_response_bytes,
            "model gateway total response bytes",
            minimum=self.max_response_bytes,
            maximum=32 * 1024 * 1024,
        )
        _require_int(
            self.max_input_tokens_per_request,
            "model gateway input tokens",
            minimum=1,
            maximum=131_072,
        )
        _require_int(
            self.max_output_tokens_per_request,
            "model gateway output tokens",
            minimum=1,
            maximum=131_072,
        )
        per_request_tokens = self.max_input_tokens_per_request + self.max_output_tokens_per_request
        _require_int(
            self.max_total_tokens,
            "model gateway total tokens",
            minimum=per_request_tokens,
            maximum=1_048_576,
        )
        _require_int(
            self.max_cost_microunits_per_request,
            "model gateway request cost",
            minimum=1,
            maximum=100_000_000,
        )
        _require_int(
            self.max_total_cost_microunits,
            "model gateway total cost",
            minimum=self.max_cost_microunits_per_request,
            maximum=100_000_000,
        )
        _require_int(self.request_timeout_ms, "model gateway timeout", minimum=100, maximum=120_000)
        if not isinstance(self.allow_controlled_test_sse, bool):
            raise ValueError("model gateway controlled SSE policy is invalid")

    @classmethod
    def from_network_plan(cls, plan: EngineNetworkPlan, **values: Any) -> "ModelGatewayPolicy":
        return cls(
            attempt_id=plan.attempt_id,
            network_policy_digest=plan.policy_digest,
            gateway_authority=f"{plan.model_gateway.service_name}:{plan.model_gateway.port}",
            **values,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.model-gateway-policy.v2",
            "attempt_id": self.attempt_id,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "objective_ref": self.objective_ref,
            "environment_ref": self.environment_ref,
            "provider_ref": self.provider_ref,
            "model_id": self.model_id,
            "data_destination_ref": self.data_destination_ref,
            "relay_identity_ref": self.relay_identity_ref,
            "network_policy_digest": self.network_policy_digest,
            "gateway_authority": self.gateway_authority,
            "authorization_ref": self.authorization_ref,
            "authorization_digest": self.authorization_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "max_requests": self.max_requests,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "max_total_request_bytes": self.max_total_request_bytes,
            "max_total_response_bytes": self.max_total_response_bytes,
            "max_input_tokens_per_request": self.max_input_tokens_per_request,
            "max_output_tokens_per_request": self.max_output_tokens_per_request,
            "max_total_tokens": self.max_total_tokens,
            "max_cost_microunits_per_request": self.max_cost_microunits_per_request,
            "max_total_cost_microunits": self.max_total_cost_microunits,
            "request_timeout_ms": self.request_timeout_ms,
            "allow_controlled_test_sse": self.allow_controlled_test_sse,
            "path": "/v1/chat/completions",
            "redirect_policy": "refuse_all",
        }

    @property
    def policy_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class TargetRelayRequest:
    request_id: str
    attempt_id: str
    authority: str
    method: str
    target: str
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, slots=True)
class TargetOperation:
    request_id: str
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    network_policy_digest: str
    relay_identity_ref: str
    protected_target_ref: str
    route_id: str
    record_id: str | None
    tenant_id: str | None
    tenant_assertion: str | None
    source_identity: str
    max_response_bytes: int
    deadline_ns: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.target-relay-operation.v1",
            "request_id": self.request_id,
            "attempt_id": self.attempt_id,
            "binding_digest": self.binding_digest,
            "delegation_digest": self.delegation_digest,
            "network_policy_digest": self.network_policy_digest,
            "relay_identity_ref": self.relay_identity_ref,
            "protected_target_ref": self.protected_target_ref,
            "route_id": self.route_id,
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "tenant_assertion": self.tenant_assertion,
            "source_identity": self.source_identity,
            "max_response_bytes": self.max_response_bytes,
            "deadline_ns": self.deadline_ns,
        }


@dataclass(frozen=True, slots=True)
class ProtectedTargetResult:
    response: TenantResponse = field(repr=False)
    target_observation_ref: str
    protected_secret_absent: bool


class ProtectedTargetForwarder(Protocol):
    """Inject target admission and enforce the typed deadline and read cap."""

    def forward(self, operation: TargetOperation) -> ProtectedTargetResult: ...

    def revoke(self, attempt_id: str, relay_identity_ref: str) -> "ProtectedRevocationResult": ...


@dataclass(frozen=True, slots=True)
class ModelGatewayRequest:
    request_id: str
    attempt_id: str
    objective_ref: str
    provider_ref: str
    authority: str
    authorization: str = field(repr=False)
    method: str = "POST"
    target: str = "/v1/chat/completions"
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, slots=True)
class ModelForwardRequest:
    request_id: str
    attempt_id: str
    binding_digest: str
    delegation_digest: str
    network_policy_digest: str
    relay_identity_ref: str
    objective_ref: str
    environment_ref: str
    provider_ref: str
    model_id: str
    data_destination_ref: str
    authorization_ref: str
    max_input_tokens: int
    max_output_tokens: int
    max_response_bytes: int
    max_cost_microunits: int
    deadline_ns: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProtectedModelResult:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_microunits: int = 0
    provider_request_ref: str = ""
    protected_secret_absent: bool = False
    fixture_usage_estimate: bool = False
    live_model_proof: bool = False


@dataclass(frozen=True, slots=True)
class ProtectedRevocationResult:
    verified: bool
    receipt_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.verified, bool):
            raise ValueError("protected revocation state is invalid")
        _require_digest(self.receipt_ref, "protected revocation receipt")


def _safe_protected_revocation(
    callback: Callable[[], object], failure_document: Mapping[str, Any]
) -> ProtectedRevocationResult:
    try:
        result = callback()
        if not isinstance(result, ProtectedRevocationResult):
            raise ValueError("protected revocation result is invalid")
        return result
    except Exception:
        return ProtectedRevocationResult(
            verified=False,
            receipt_ref=content_hash(failure_document),
        )


class ProtectedModelForwarder(Protocol):
    """Inject provider authority and enforce typed deadline, byte, token, and cost caps.

    Post-dispatch transport ambiguity must use ``ProtectedUpstreamUnknown``;
    other exceptions assert that no publishable provider result was obtained.
    """

    def forward(self, request: ModelForwardRequest) -> ProtectedModelResult: ...

    def revoke(self, attempt_id: str, authorization_ref: str) -> ProtectedRevocationResult: ...


@dataclass(frozen=True, slots=True)
class RelayAuditRecord:
    relay_kind: str
    attempt_id: str
    objective_ref: str
    sequence: int
    request_id: str
    operation: str
    request_digest: str
    request_bytes: int
    response_digest: str | None
    response_bytes: int
    status: str
    result_status: int | None
    input_tokens: int
    output_tokens: int
    cost_microunits: int
    elapsed_ms: int
    recorded_at: str
    policy_digest: str
    evidence_ref: str | None
    fixture_usage_estimate: bool = False
    live_model_proof: bool = False

    def __post_init__(self) -> None:
        if self.relay_kind not in {"target", "model_gateway"}:
            raise ValueError("relay audit kind is invalid")
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise ValueError("relay audit attempt ID is invalid")
        _require_digest(self.objective_ref, "relay audit objective")
        _require_int(self.sequence, "relay audit sequence", minimum=1, maximum=1_000_000)
        request_pattern = _TARGET_REQUEST_ID if self.relay_kind == "target" else _MODEL_REQUEST_ID
        if request_pattern.fullmatch(self.request_id) is None:
            raise ValueError("relay audit request ID is invalid")
        allowed_operations = _TARGET_ROUTES if self.relay_kind == "target" else {"chat_completions"}
        if self.operation not in allowed_operations:
            raise ValueError("relay audit operation is invalid")
        _require_digest(self.request_digest, "relay audit request")
        if self.response_digest is not None:
            _require_digest(self.response_digest, "relay audit response")
        for value, label, maximum in (
            (self.request_bytes, "relay audit request bytes", 16 * 1024 * 1024),
            (self.response_bytes, "relay audit response bytes", 64 * 1024 * 1024),
            (self.input_tokens, "relay audit input tokens", 1_048_576),
            (self.output_tokens, "relay audit output tokens", 1_048_576),
            (self.cost_microunits, "relay audit cost", 100_000_000),
            (self.elapsed_ms, "relay audit elapsed time", 24 * 60 * 60 * 1_000),
        ):
            _require_int(value, label, minimum=0, maximum=maximum)
        if self.status not in {
            "succeeded",
            "upstream_failed",
            "deadline_exceeded",
            "revoked",
            "invalid_upstream",
            "secret_leak",
            "expired",
            "clock_invalid",
            "upstream_unknown",
        }:
            raise ValueError("relay audit status is invalid")
        if self.relay_kind == "target" and self.status == "upstream_unknown":
            raise ValueError("target relay cannot claim model-provider ambiguity")
        if self.result_status is not None and (
            isinstance(self.result_status, bool)
            or not isinstance(self.result_status, int)
            or not 200 <= self.result_status <= 599
            or 300 <= self.result_status <= 399
        ):
            raise ValueError("relay audit result status is invalid")
        if self.status == "succeeded":
            if (
                self.response_digest is None
                or self.result_status is None
                or self.evidence_ref is None
            ):
                raise ValueError("successful relay audit evidence is incomplete")
        elif (
            self.response_digest is not None
            or self.result_status is not None
            or self.response_bytes != 0
            or self.input_tokens != 0
            or self.output_tokens != 0
            or self.cost_microunits != 0
        ):
            raise ValueError("failed relay audit cannot claim a response")
        _require_timestamp(self.recorded_at, "relay audit timestamp")
        _require_digest(self.policy_digest, "relay audit policy")
        if self.evidence_ref is not None:
            _require_digest(self.evidence_ref, "relay audit evidence")
        if not isinstance(self.fixture_usage_estimate, bool) or not isinstance(
            self.live_model_proof, bool
        ):
            raise ValueError("relay audit model-proof state is invalid")
        if self.fixture_usage_estimate and self.live_model_proof:
            raise ValueError("relay audit model-proof state conflicts")
        if self.status != "succeeded" and (self.fixture_usage_estimate or self.live_model_proof):
            raise ValueError("failed relay audit cannot claim model proof")
        if self.relay_kind == "target" and (self.fixture_usage_estimate or self.live_model_proof):
            raise ValueError("target relay audit cannot claim model proof")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-relay-audit.v2",
            "relay_kind": self.relay_kind,
            "attempt_id": self.attempt_id,
            "objective_ref": self.objective_ref,
            "sequence": self.sequence,
            "request_id": self.request_id,
            "operation": self.operation,
            "request_digest": self.request_digest,
            "request_bytes": self.request_bytes,
            "response_digest": self.response_digest,
            "response_bytes": self.response_bytes,
            "status": self.status,
            "result_status": self.result_status,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_microunits": self.cost_microunits,
            "elapsed_ms": self.elapsed_ms,
            "recorded_at": self.recorded_at,
            "policy_digest": self.policy_digest,
            "evidence_ref": self.evidence_ref,
            "fixture_usage_estimate": self.fixture_usage_estimate,
            "live_model_proof": self.live_model_proof,
        }

    @property
    def record_digest(self) -> str:
        return content_hash(self.to_dict())


class RelayAuditSink(Protocol):
    """Controller-owned, bounded, non-reentrant append-only audit sink."""

    def append(self, record: RelayAuditRecord) -> None: ...


class BoundedRelayAudit:
    """Thread-safe hash-only audit sink for one controller-owned attempt."""

    def __init__(self, *, max_records: int = 512, max_total_bytes: int = 512 * 1024) -> None:
        self._max_records = _require_int(
            max_records, "relay audit record count", minimum=1, maximum=4_096
        )
        self._max_total_bytes = _require_int(
            max_total_bytes,
            "relay audit bytes",
            minimum=4_096,
            maximum=8 * 1024 * 1024,
        )
        self._lock = threading.Lock()
        self._records: list[RelayAuditRecord] = []
        self._bytes = 0

    def append(self, record: RelayAuditRecord) -> None:
        payload = canonical_json_bytes(record.to_dict())
        if len(payload) > 32 * 1024:
            raise EngineRelayError("audit_unavailable", "relay audit record exceeds its limit")
        with self._lock:
            if (
                len(self._records) >= self._max_records
                or self._bytes + len(payload) > self._max_total_bytes
            ):
                raise EngineRelayError("audit_unavailable", "relay audit capacity is exhausted")
            self._records.append(record)
            self._bytes += len(payload)

    def records(self) -> tuple[RelayAuditRecord, ...]:
        with self._lock:
            return tuple(self._records)


@dataclass(frozen=True, slots=True)
class RelayReceipt:
    relay_kind: str
    attempt_id: str
    sequence: int
    request_id: str
    operation: str
    request_digest: str
    response_digest: str
    response_status: int
    request_bytes: int
    response_bytes: int
    input_tokens: int
    output_tokens: int
    cost_microunits: int
    policy_digest: str
    audit_record_digest: str
    fixture_usage_estimate: bool = False
    live_model_proof: bool = False

    def __post_init__(self) -> None:
        if self.relay_kind not in {"target", "model_gateway"}:
            raise ValueError("relay receipt kind is invalid")
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise ValueError("relay receipt attempt ID is invalid")
        _require_int(self.sequence, "relay receipt sequence", minimum=1, maximum=1_000_000)
        request_pattern = _TARGET_REQUEST_ID if self.relay_kind == "target" else _MODEL_REQUEST_ID
        if request_pattern.fullmatch(self.request_id) is None:
            raise ValueError("relay receipt request ID is invalid")
        allowed_operations = _TARGET_ROUTES if self.relay_kind == "target" else {"chat_completions"}
        if self.operation not in allowed_operations:
            raise ValueError("relay receipt operation is invalid")
        for digest_value, label in (
            (self.request_digest, "relay receipt request"),
            (self.response_digest, "relay receipt response"),
            (self.policy_digest, "relay receipt policy"),
            (self.audit_record_digest, "relay receipt audit"),
        ):
            _require_digest(digest_value, label)
        if (
            isinstance(self.response_status, bool)
            or not isinstance(self.response_status, int)
            or not 200 <= self.response_status <= 599
            or 300 <= self.response_status <= 399
        ):
            raise ValueError("relay receipt response status is invalid")
        for numeric_value, label, maximum in (
            (self.request_bytes, "relay receipt request bytes", 16 * 1024 * 1024),
            (self.response_bytes, "relay receipt response bytes", 64 * 1024 * 1024),
            (self.input_tokens, "relay receipt input tokens", 1_048_576),
            (self.output_tokens, "relay receipt output tokens", 1_048_576),
            (self.cost_microunits, "relay receipt cost", 100_000_000),
        ):
            _require_int(numeric_value, label, minimum=0, maximum=maximum)
        if not isinstance(self.fixture_usage_estimate, bool) or not isinstance(
            self.live_model_proof, bool
        ):
            raise ValueError("relay receipt model-proof state is invalid")
        if self.fixture_usage_estimate and self.live_model_proof:
            raise ValueError("relay receipt model-proof state conflicts")
        if self.relay_kind == "target" and (self.fixture_usage_estimate or self.live_model_proof):
            raise ValueError("target relay receipt cannot claim model proof")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-relay-receipt.v2",
            "relay_kind": self.relay_kind,
            "attempt_id": self.attempt_id,
            "sequence": self.sequence,
            "request_id": self.request_id,
            "operation": self.operation,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "response_status": self.response_status,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_microunits": self.cost_microunits,
            "policy_digest": self.policy_digest,
            "audit_record_digest": self.audit_record_digest,
            "fixture_usage_estimate": self.fixture_usage_estimate,
            "live_model_proof": self.live_model_proof,
        }

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class RelayResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    receipt: RelayReceipt
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class GatewayRevocationReceipt:
    attempt_id: str
    authorization_ref: str
    policy_digest: str
    accepted_requests: int
    inflight_request: bool
    consumed_request_bytes: int
    reserved_response_bytes: int
    reserved_tokens: int
    reserved_cost_microunits: int
    protected_revocation_verified: bool
    protected_revocation_ref: str | None

    def __post_init__(self) -> None:
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise ValueError("gateway revocation attempt ID is invalid")
        _require_digest(self.authorization_ref, "gateway revocation authorization")
        _require_digest(self.policy_digest, "gateway revocation policy")
        for value, label, maximum in (
            (self.accepted_requests, "gateway accepted request count", 1_000_000),
            (self.consumed_request_bytes, "gateway consumed request bytes", 16 * 1024 * 1024),
            (self.reserved_response_bytes, "gateway reserved response bytes", 32 * 1024 * 1024),
            (self.reserved_tokens, "gateway reserved tokens", 1_048_576),
            (self.reserved_cost_microunits, "gateway reserved cost", 100_000_000),
        ):
            _require_int(value, label, minimum=0, maximum=maximum)
        if not isinstance(self.inflight_request, bool) or not isinstance(
            self.protected_revocation_verified, bool
        ):
            raise ValueError("gateway revocation state is invalid")
        if self.protected_revocation_ref is not None:
            _require_digest(self.protected_revocation_ref, "protected revocation")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.model-gateway-revocation.v1",
            "attempt_id": self.attempt_id,
            "authorization_ref": self.authorization_ref,
            "policy_digest": self.policy_digest,
            "accepted_requests": self.accepted_requests,
            "inflight_request": self.inflight_request,
            "consumed_request_bytes": self.consumed_request_bytes,
            "reserved_response_bytes": self.reserved_response_bytes,
            "reserved_tokens": self.reserved_tokens,
            "reserved_cost_microunits": self.reserved_cost_microunits,
            "protected_revocation_verified": self.protected_revocation_verified,
            "protected_revocation_ref": self.protected_revocation_ref,
        }

    @property
    def receipt_digest(self) -> str:
        return content_hash(self.to_dict())


def _target_operation(
    policy: TargetRelayPolicy,
    request: TargetRelayRequest,
    *,
    deadline_ns: int,
) -> TargetOperation:
    if request.attempt_id != policy.attempt_id:
        raise EngineRelayError("scope_refused", "target relay attempt is not admitted")
    if request.authority != policy.relay_authority:
        raise EngineRelayError("route_refused", "target relay authority is not admitted")
    if request.method != "GET" or not isinstance(request.body, bytes) or request.body:
        raise EngineRelayError("method_refused", "target relay admits only bodyless GET requests")
    if (
        not isinstance(request.target, str)
        or not request.target.startswith("/")
        or len(request.target) > 768
        or not request.target.isascii()
        or any(character in request.target for character in ("%", "\\", "#", "\x00"))
        or "//" in request.target
        or any(segment in {".", ".."} for segment in request.target.split("?", 1)[0].split("/"))
    ):
        raise EngineRelayError("route_refused", "target relay request target is not canonical")
    headers = dict(
        _normalized_headers(
            request.headers, allowed=_TARGET_REQUEST_HEADERS, label="target request"
        )
    )
    tenant_assertion = headers.get("x-bluefire-lab-tenant")
    if tenant_assertion is not None and tenant_assertion not in policy.admitted_tenant_ids:
        raise EngineRelayError("scope_refused", "target tenant assertion is not admitted")
    route_id: str
    record_id: str | None = None
    tenant_id: str | None = None
    if request.target == "/health":
        route_id = "health"
    elif request.target == "/openapi.json":
        route_id = "metadata"
    elif request.target.startswith("/records/") and "?" not in request.target:
        route_id = "record_lookup"
        record_id = request.target.removeprefix("/records/")
        if record_id not in policy.admitted_record_ids or "/" in record_id:
            raise EngineRelayError("scope_refused", "target record is not admitted")
    elif request.target.startswith("/exports?tenant="):
        route_id = "bounded_export"
        tenant_id = request.target.removeprefix("/exports?tenant=")
        if tenant_id not in policy.admitted_tenant_ids or "&" in tenant_id or "=" in tenant_id:
            raise EngineRelayError("scope_refused", "target export tenant is not admitted")
    else:
        raise EngineRelayError("route_refused", "target route is not admitted")
    if route_id not in policy.admitted_routes:
        raise EngineRelayError("route_refused", "target route is not admitted")
    return TargetOperation(
        request_id=request.request_id,
        attempt_id=request.attempt_id,
        binding_digest=policy.binding_digest,
        delegation_digest=policy.delegation_digest,
        network_policy_digest=policy.network_policy_digest,
        relay_identity_ref=policy.relay_identity_ref,
        protected_target_ref=policy.protected_target_ref,
        route_id=route_id,
        record_id=record_id,
        tenant_id=tenant_id,
        tenant_assertion=tenant_assertion,
        source_identity="engine_worker",
        max_response_bytes=policy.max_response_bytes,
        deadline_ns=deadline_ns,
    )


class FixedTargetRelay:
    """One-at-a-time fixed operation relay for the generated tenant target."""

    def __init__(
        self,
        policy: TargetRelayPolicy,
        forwarder: ProtectedTargetForwarder,
        audit: RelayAuditSink,
        *,
        clock: Callable[[], datetime],
        monotonic_ns: Callable[[], int],
    ) -> None:
        self.policy = policy
        self._forwarder = forwarder
        self._audit = audit
        self._clock = clock
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._sequence = 0
        self._reserved_response_bytes = 0
        self._inflight: object | None = None
        self._revoked = False
        self._last_revocation: ProtectedRevocationResult | None = None
        self._revocation_in_progress = False
        self._revocation_condition = threading.Condition(self._lock)

    def revoke(self) -> ProtectedRevocationResult:
        with self._revocation_condition:
            if self._last_revocation is not None:
                return self._last_revocation
            while self._revocation_in_progress:
                self._revocation_condition.wait()
                if self._last_revocation is not None:
                    return self._last_revocation
            self._revocation_in_progress = True
            self._revoked = True
        result = _safe_protected_revocation(
            lambda: self._forwarder.revoke(self.policy.attempt_id, self.policy.relay_identity_ref),
            {
                "schema_version": "bluefire.target-relay-revocation-failure.v1",
                "attempt_id": self.policy.attempt_id,
                "relay_identity_ref": self.policy.relay_identity_ref,
            },
        )
        with self._revocation_condition:
            if self._last_revocation is None:
                self._last_revocation = result
            self._revocation_in_progress = False
            self._revocation_condition.notify_all()
            return self._last_revocation

    def handle(self, request: TargetRelayRequest) -> RelayResponse:
        owner = object()
        try:
            return self._handle(request, owner)
        finally:
            with self._lock:
                if self._inflight is owner:
                    self._inflight = None

    def _handle(self, request: TargetRelayRequest, owner: object) -> RelayResponse:
        if _TARGET_REQUEST_ID.fullmatch(request.request_id) is None:
            raise EngineRelayError("invalid_request", "target relay request ID is invalid")
        _not_expired(self.policy.expires_at, self._clock)
        started = self._monotonic_ns()
        deadline = started + self.policy.request_timeout_ms * 1_000_000
        operation = _target_operation(self.policy, request, deadline_ns=deadline)
        request_digest = content_hash(
            {
                **operation.to_dict(),
                "request_headers_digest": content_hash(
                    list(
                        _normalized_headers(
                            request.headers,
                            allowed=_TARGET_REQUEST_HEADERS,
                            label="target request",
                        )
                    )
                ),
                "request_body_digest": _digest_bytes(request.body),
            }
        )
        with self._lock:
            if self._revoked:
                raise EngineRelayError("revoked", "target relay is revoked")
            if self._inflight is not None:
                raise EngineRelayError("busy", "target relay already has an in-flight request")
            if request.request_id in self._seen:
                raise EngineRelayError(
                    "replay_refused", "target relay request was already consumed"
                )
            if self._sequence >= self.policy.max_requests:
                raise EngineRelayError(
                    "budget_exhausted", "target relay request budget is exhausted"
                )
            if (
                self._reserved_response_bytes + self.policy.max_response_bytes
                > self.policy.max_total_response_bytes
            ):
                raise EngineRelayError(
                    "budget_exhausted", "target relay response budget is exhausted"
                )
            self._seen.add(request.request_id)
            self._sequence += 1
            sequence = self._sequence
            self._reserved_response_bytes += self.policy.max_response_bytes
            self._inflight = owner
        try:
            result = self._forwarder.forward(operation)
        except Exception:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "upstream_failed"
            )
            raise EngineRelayError("upstream_failed", "target relay forwarder failed") from None
        ended = self._monotonic_ns()
        with self._lock:
            revoked = self._revoked
        if ended > deadline:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "target relay deadline elapsed")
        if revoked:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "revoked"
            )
            raise EngineRelayError("revoked", "target relay was revoked during forwarding")
        try:
            _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, exc.code
            )
            raise
        try:
            response, headers = self._validate_result(result)
        except Exception:
            self._finish_target_failure(
                sequence,
                request,
                operation.route_id,
                request_digest,
                started,
                "invalid_upstream",
            )
            raise EngineRelayError("invalid_upstream", "target response is invalid") from None
        ended = self._monotonic_ns()
        if ended > deadline:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "target relay deadline elapsed")
        try:
            recorded_at = _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, exc.code
            )
            raise
        elapsed_ms = max(0, (ended - started) // 1_000_000)
        audit = RelayAuditRecord(
            relay_kind="target",
            attempt_id=self.policy.attempt_id,
            objective_ref=self.policy.objective_ref,
            sequence=sequence,
            request_id=request.request_id,
            operation=operation.route_id,
            request_digest=request_digest,
            request_bytes=0,
            response_digest=_digest_bytes(response.body),
            response_bytes=len(response.body),
            status="succeeded",
            result_status=response.status,
            input_tokens=0,
            output_tokens=0,
            cost_microunits=0,
            elapsed_ms=elapsed_ms,
            recorded_at=recorded_at.isoformat().replace("+00:00", "Z"),
            policy_digest=self.policy.policy_digest,
            evidence_ref=result.target_observation_ref,
        )
        receipt = RelayReceipt(
            relay_kind="target",
            attempt_id=self.policy.attempt_id,
            sequence=sequence,
            request_id=request.request_id,
            operation=operation.route_id,
            request_digest=request_digest,
            response_digest=_digest_bytes(response.body),
            response_status=response.status,
            request_bytes=0,
            response_bytes=len(response.body),
            input_tokens=0,
            output_tokens=0,
            cost_microunits=0,
            policy_digest=self.policy.policy_digest,
            audit_record_digest=audit.record_digest,
        )
        relay_response = RelayResponse(
            status=response.status,
            headers=headers,
            body=response.body,
            receipt=receipt,
        )
        try:
            _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, exc.code
            )
            raise
        with self._lock:
            deadline_elapsed = self._monotonic_ns() > deadline
            revoked = self._revoked
        if deadline_elapsed:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "target relay deadline elapsed")
        if revoked:
            self._finish_target_failure(
                sequence, request, operation.route_id, request_digest, started, "revoked"
            )
            raise EngineRelayError("revoked", "target relay was revoked before publication")
        # The final state check is the publication linearization point.  A later
        # revocation applies to future or not-yet-committed requests.  The
        # bounded audit append remains outside the state lock and must succeed
        # before the response is released.
        self._append_audit(audit)
        return relay_response

    def _validate_result(
        self, result: ProtectedTargetResult
    ) -> tuple[TenantResponse, tuple[tuple[str, str], ...]]:
        if not isinstance(result, ProtectedTargetResult):
            raise EngineRelayError("invalid_upstream", "target response is invalid")
        if result.protected_secret_absent is not True:
            raise EngineRelayError("invalid_upstream", "target secret scan is incomplete")
        try:
            _require_digest(result.target_observation_ref, "target observation")
        except ValueError:
            raise EngineRelayError("invalid_upstream", "target observation is invalid") from None
        response = result.response
        if not isinstance(response, TenantResponse):
            raise EngineRelayError("invalid_upstream", "target response is invalid")
        if (
            isinstance(response.status, bool)
            or not isinstance(response.status, int)
            or not 200 <= response.status <= 599
            or 300 <= response.status <= 399
        ):
            raise EngineRelayError("invalid_upstream", "target response status is invalid")
        if (
            not isinstance(response.body, bytes)
            or len(response.body) > self.policy.max_response_bytes
        ):
            raise EngineRelayError("invalid_upstream", "target response exceeds its limit")
        headers = _response_headers(
            response.headers,
            allowed=_TARGET_RESPONSE_HEADERS,
            body_size=len(response.body),
            label="target response",
        )
        if dict(headers).get("content-type") != "application/json; charset=utf-8":
            raise EngineRelayError("invalid_upstream", "target response content type is invalid")
        _strict_json(response.body, label="target response")
        return response, headers

    def _append_target_failure(
        self,
        sequence: int,
        request: TargetRelayRequest,
        operation: str,
        request_digest: str,
        started: int,
        status: str,
    ) -> None:
        record = RelayAuditRecord(
            relay_kind="target",
            attempt_id=self.policy.attempt_id,
            objective_ref=self.policy.objective_ref,
            sequence=sequence,
            request_id=request.request_id,
            operation=operation,
            request_digest=request_digest,
            request_bytes=len(request.body),
            response_digest=None,
            response_bytes=0,
            status=status,
            result_status=None,
            input_tokens=0,
            output_tokens=0,
            cost_microunits=0,
            elapsed_ms=max(0, (self._monotonic_ns() - started) // 1_000_000),
            recorded_at=_audit_recorded_at(self._clock, self.policy.created_at),
            policy_digest=self.policy.policy_digest,
            evidence_ref=None,
        )
        self._append_audit(record)

    def _finish_target_failure(
        self,
        sequence: int,
        request: TargetRelayRequest,
        operation: str,
        request_digest: str,
        started: int,
        status: str,
    ) -> None:
        self._append_target_failure(sequence, request, operation, request_digest, started, status)

    def _append_audit(self, record: RelayAuditRecord) -> None:
        try:
            self._audit.append(record)
        except Exception:
            raise EngineRelayError(
                "audit_unavailable", "target relay audit is unavailable"
            ) from None


class ControlledModelGateway:
    """Single-flight, budgeted model gateway backed by a protected forwarder."""

    def __init__(
        self,
        policy: ModelGatewayPolicy,
        bearer_token: str,
        forwarder: ProtectedModelForwarder,
        audit: RelayAuditSink,
        *,
        clock: Callable[[], datetime],
        monotonic_ns: Callable[[], int],
    ) -> None:
        token = _require_text(bearer_token, "model gateway bearer", maximum=512)
        if not token.isascii() or len(token) < 32:
            raise ValueError("model gateway bearer is invalid")
        if _digest_bytes(token.encode("ascii")) != policy.authorization_digest:
            raise ValueError("model gateway bearer does not match its authority")
        self.policy = policy
        self._bearer = token
        self._forwarder = forwarder
        self._audit = audit
        self._clock = clock
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._sequence = 0
        self._request_bytes = 0
        self._reserved_response_bytes = 0
        self._reserved_tokens = 0
        self._reserved_cost = 0
        self._inflight: object | None = None
        self._revoked = False
        self._last_revocation: GatewayRevocationReceipt | None = None
        self._revocation_in_progress = False
        self._revocation_condition = threading.Condition(self._lock)

    @property
    def authorization_ref(self) -> str:
        return self.policy.authorization_ref

    def lease(self) -> "ControlledModelGatewayLease":
        return ControlledModelGatewayLease(self)

    def secret_value(self) -> str:
        with self._lock:
            if self._revoked:
                raise EngineRelayError("revoked", "model gateway lease is revoked")
            _not_expired(self.policy.expires_at, self._clock)
            return self._bearer

    def revoke(self) -> GatewayRevocationReceipt:
        with self._revocation_condition:
            if self._last_revocation is not None:
                return self._last_revocation
            while self._revocation_in_progress:
                self._revocation_condition.wait()
                if self._last_revocation is not None:
                    return self._last_revocation
            self._revocation_in_progress = True
            self._revoked = True
            accepted_requests = self._sequence
            inflight_request = self._inflight is not None
            consumed_request_bytes = self._request_bytes
            reserved_response_bytes = self._reserved_response_bytes
            reserved_tokens = self._reserved_tokens
            reserved_cost_microunits = self._reserved_cost
        protected = _safe_protected_revocation(
            lambda: self._forwarder.revoke(self.policy.attempt_id, self.policy.authorization_ref),
            {
                "schema_version": "bluefire.model-forwarder-revocation-failure.v1",
                "attempt_id": self.policy.attempt_id,
                "authorization_ref": self.policy.authorization_ref,
            },
        )
        receipt = GatewayRevocationReceipt(
            attempt_id=self.policy.attempt_id,
            authorization_ref=self.policy.authorization_ref,
            policy_digest=self.policy.policy_digest,
            accepted_requests=accepted_requests,
            inflight_request=inflight_request,
            consumed_request_bytes=consumed_request_bytes,
            reserved_response_bytes=reserved_response_bytes,
            reserved_tokens=reserved_tokens,
            reserved_cost_microunits=reserved_cost_microunits,
            protected_revocation_verified=protected.verified,
            protected_revocation_ref=protected.receipt_ref,
        )
        with self._revocation_condition:
            if self._last_revocation is None:
                self._last_revocation = receipt
            self._revocation_in_progress = False
            self._revocation_condition.notify_all()
            return self._last_revocation

    def handle(self, request: ModelGatewayRequest) -> RelayResponse:
        owner = object()
        try:
            return self._handle(request, owner)
        finally:
            with self._lock:
                if self._inflight is owner:
                    self._inflight = None

    def _handle(self, request: ModelGatewayRequest, owner: object) -> RelayResponse:
        parsed, headers = self._validate_request(request)
        request_digest = content_hash(
            {
                "request_id": request.request_id,
                "attempt_id": request.attempt_id,
                "objective_ref": request.objective_ref,
                "provider_ref": request.provider_ref,
                "headers_digest": content_hash(list(headers)),
                "body_digest": _digest_bytes(request.body),
                "model_id": parsed["model"],
            }
        )
        with self._lock:
            if self._revoked:
                raise EngineRelayError("revoked", "model gateway is revoked")
            _not_expired(self.policy.expires_at, self._clock)
            if self._inflight is not None:
                raise EngineRelayError("busy", "model gateway already has an in-flight request")
            if request.request_id in self._seen:
                raise EngineRelayError("replay_refused", "model request was already consumed")
            if self._sequence >= self.policy.max_requests:
                raise EngineRelayError("budget_exhausted", "model request budget is exhausted")
            if self._request_bytes + len(request.body) > self.policy.max_total_request_bytes:
                raise EngineRelayError("budget_exhausted", "model request byte budget is exhausted")
            if (
                self._reserved_response_bytes + self.policy.max_response_bytes
                > self.policy.max_total_response_bytes
            ):
                raise EngineRelayError(
                    "budget_exhausted", "model response byte budget is exhausted"
                )
            reservation_tokens = (
                self.policy.max_input_tokens_per_request + self.policy.max_output_tokens_per_request
            )
            if self._reserved_tokens + reservation_tokens > self.policy.max_total_tokens:
                raise EngineRelayError("budget_exhausted", "model token budget is exhausted")
            if (
                self._reserved_cost + self.policy.max_cost_microunits_per_request
                > self.policy.max_total_cost_microunits
            ):
                raise EngineRelayError("budget_exhausted", "model cost budget is exhausted")
            self._seen.add(request.request_id)
            self._sequence += 1
            sequence = self._sequence
            self._request_bytes += len(request.body)
            self._reserved_response_bytes += self.policy.max_response_bytes
            self._reserved_tokens += reservation_tokens
            self._reserved_cost += self.policy.max_cost_microunits_per_request
            self._inflight = owner
        started = self._monotonic_ns()
        deadline = started + self.policy.request_timeout_ms * 1_000_000
        forwarded = ModelForwardRequest(
            request_id=request.request_id,
            attempt_id=request.attempt_id,
            binding_digest=self.policy.binding_digest,
            delegation_digest=self.policy.delegation_digest,
            network_policy_digest=self.policy.network_policy_digest,
            relay_identity_ref=self.policy.relay_identity_ref,
            objective_ref=request.objective_ref,
            environment_ref=self.policy.environment_ref,
            provider_ref=request.provider_ref,
            model_id=self.policy.model_id,
            data_destination_ref=self.policy.data_destination_ref,
            authorization_ref=self.policy.authorization_ref,
            max_input_tokens=self.policy.max_input_tokens_per_request,
            max_output_tokens=self.policy.max_output_tokens_per_request,
            max_response_bytes=self.policy.max_response_bytes,
            max_cost_microunits=self.policy.max_cost_microunits_per_request,
            deadline_ns=deadline,
            headers=headers,
            body=bytes(request.body),
        )
        try:
            result = self._forwarder.forward(forwarded)
        except ProtectedUpstreamUnknown as exc:
            try:
                outcome_ref = _require_digest(exc.outcome_ref, "protected upstream outcome")
            except Exception:
                outcome_ref = None
            self._finish_model_failure(
                sequence,
                request,
                request_digest,
                started,
                "upstream_unknown",
                evidence_ref=outcome_ref,
            )
            raise EngineRelayError(
                "upstream_unknown", "model provider outcome is unknown"
            ) from None
        except Exception:
            self._finish_model_failure(
                sequence, request, request_digest, started, "upstream_failed"
            )
            raise EngineRelayError("upstream_failed", "model forwarder failed") from None
        ended = self._monotonic_ns()
        with self._lock:
            revoked = self._revoked
        if ended > deadline:
            self._finish_model_failure(
                sequence, request, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "model gateway deadline elapsed")
        if revoked:
            self._finish_model_failure(sequence, request, request_digest, started, "revoked")
            raise EngineRelayError("revoked", "model gateway was revoked during forwarding")
        try:
            _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_model_failure(sequence, request, request_digest, started, exc.code)
            raise
        try:
            result, response_headers, response_document = self._validate_result(result, parsed)
        except EngineRelayError as exc:
            failure_status = "secret_leak" if exc.code == "secret_leak" else "invalid_upstream"
            self._finish_model_failure(sequence, request, request_digest, started, failure_status)
            raise EngineRelayError("invalid_upstream", "model response is invalid") from None
        except Exception:
            self._finish_model_failure(
                sequence, request, request_digest, started, "invalid_upstream"
            )
            raise EngineRelayError("invalid_upstream", "model response is invalid") from None
        if _secret_in_bytes(self._bearer, result.body) or _json_contains_secret(
            response_document, self._bearer
        ):
            self._finish_model_failure(sequence, request, request_digest, started, "secret_leak")
            raise EngineRelayError("invalid_upstream", "model response failed secret scanning")
        ended = self._monotonic_ns()
        if ended > deadline:
            self._finish_model_failure(
                sequence, request, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "model gateway deadline elapsed")
        try:
            recorded_at = _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_model_failure(sequence, request, request_digest, started, exc.code)
            raise
        elapsed_ms = max(0, (ended - started) // 1_000_000)
        audit = RelayAuditRecord(
            relay_kind="model_gateway",
            attempt_id=self.policy.attempt_id,
            objective_ref=self.policy.objective_ref,
            sequence=sequence,
            request_id=request.request_id,
            operation="chat_completions",
            request_digest=request_digest,
            request_bytes=len(request.body),
            response_digest=_digest_bytes(result.body),
            response_bytes=len(result.body),
            status="succeeded",
            result_status=result.status,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_microunits=result.cost_microunits,
            elapsed_ms=elapsed_ms,
            recorded_at=recorded_at.isoformat().replace("+00:00", "Z"),
            policy_digest=self.policy.policy_digest,
            evidence_ref=result.provider_request_ref,
            fixture_usage_estimate=result.fixture_usage_estimate,
            live_model_proof=result.live_model_proof,
        )
        receipt = RelayReceipt(
            relay_kind="model_gateway",
            attempt_id=self.policy.attempt_id,
            sequence=sequence,
            request_id=request.request_id,
            operation="chat_completions",
            request_digest=request_digest,
            response_digest=_digest_bytes(result.body),
            response_status=result.status,
            request_bytes=len(request.body),
            response_bytes=len(result.body),
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            cost_microunits=result.cost_microunits,
            policy_digest=self.policy.policy_digest,
            audit_record_digest=audit.record_digest,
            fixture_usage_estimate=result.fixture_usage_estimate,
            live_model_proof=result.live_model_proof,
        )
        relay_response = RelayResponse(
            status=result.status,
            headers=response_headers,
            body=result.body,
            receipt=receipt,
        )
        try:
            _not_expired(self.policy.expires_at, self._clock)
        except EngineRelayError as exc:
            self._finish_model_failure(sequence, request, request_digest, started, exc.code)
            raise
        with self._lock:
            deadline_elapsed = self._monotonic_ns() > deadline
            revoked = self._revoked
        if deadline_elapsed:
            self._finish_model_failure(
                sequence, request, request_digest, started, "deadline_exceeded"
            )
            raise EngineRelayError("deadline_exceeded", "model gateway deadline elapsed")
        if revoked:
            self._finish_model_failure(sequence, request, request_digest, started, "revoked")
            raise EngineRelayError("revoked", "model gateway was revoked before publication")
        # This final state check commits publication before the bounded audit
        # append.  A later revocation applies to future or uncommitted work.
        self._append_audit(audit)
        return relay_response

    def _validate_request(
        self, request: ModelGatewayRequest
    ) -> tuple[Mapping[str, Any], tuple[tuple[str, str], ...]]:
        if _MODEL_REQUEST_ID.fullmatch(request.request_id) is None:
            raise EngineRelayError("invalid_request", "model request ID is invalid")
        if (
            request.attempt_id != self.policy.attempt_id
            or request.objective_ref != self.policy.objective_ref
            or request.provider_ref != self.policy.provider_ref
        ):
            raise EngineRelayError("scope_refused", "model request binding is not admitted")
        expected = f"Bearer {self._bearer}"
        if (
            not isinstance(request.authorization, str)
            or len(request.authorization) != len(expected)
            or not request.authorization.isascii()
            or not hmac.compare_digest(
                request.authorization.encode("ascii"), expected.encode("ascii")
            )
        ):
            raise EngineRelayError("invalid_authorization", "model authorization failed")
        if (
            request.authority != self.policy.gateway_authority
            or request.method != "POST"
            or request.target != "/v1/chat/completions"
        ):
            raise EngineRelayError("route_refused", "model gateway route is not admitted")
        if not isinstance(request.body, bytes) or len(request.body) > self.policy.max_request_bytes:
            raise EngineRelayError("request_too_large", "model request exceeds its limit")
        if _secret_in_bytes(self._bearer, request.body):
            raise EngineRelayError("invalid_request", "model request contains gateway authority")
        headers = _normalized_headers(
            request.headers, allowed=_MODEL_REQUEST_HEADERS, label="model request"
        )
        if any(self._bearer in value for _, value in headers):
            raise EngineRelayError(
                "invalid_request", "model request headers contain gateway authority"
            )
        rows = dict(headers)
        if rows.get("content-type") != "application/json":
            raise EngineRelayError("invalid_headers", "model request content type is invalid")
        parsed = _strict_json(request.body, label="model request")
        if _json_contains_secret(parsed, self._bearer):
            raise EngineRelayError("invalid_request", "model request contains gateway authority")
        if parsed.get("model") != self.policy.model_id:
            raise EngineRelayError("scope_refused", "model identity is not admitted")
        stream = parsed.get("stream")
        if stream is True:
            if not self.policy.allow_controlled_test_sse:
                raise EngineRelayError(
                    "scope_refused", "controlled streaming model responses are not admitted"
                )
            _controlled_stream_tool_names(parsed)
        elif stream is None or stream is False:
            if "stream_options" in parsed:
                raise EngineRelayError(
                    "invalid_request", "stream options require an admitted streaming request"
                )
        else:
            raise EngineRelayError("invalid_request", "model stream selection is invalid")
        if "max_tokens" in parsed and "max_completion_tokens" in parsed:
            raise EngineRelayError("invalid_request", "model request has conflicting token limits")
        declared = parsed.get("max_completion_tokens", parsed.get("max_tokens"))
        if declared is not None and (
            isinstance(declared, bool)
            or not isinstance(declared, int)
            or not 1 <= declared <= self.policy.max_output_tokens_per_request
        ):
            raise EngineRelayError("budget_refused", "model output-token limit is not admitted")
        _not_expired(self.policy.expires_at, self._clock)
        return parsed, headers

    def _validate_result(
        self, result: ProtectedModelResult, request_document: Mapping[str, Any]
    ) -> tuple[ProtectedModelResult, tuple[tuple[str, str], ...], Any]:
        if not isinstance(result, ProtectedModelResult):
            raise EngineRelayError("invalid_upstream", "model response is invalid")
        if (
            isinstance(result.status, bool)
            or not isinstance(result.status, int)
            or not 200 <= result.status <= 599
            or 300 <= result.status <= 399
        ):
            raise EngineRelayError("invalid_upstream", "model response status is invalid")
        if not isinstance(result.body, bytes) or len(result.body) > self.policy.max_response_bytes:
            raise EngineRelayError("invalid_upstream", "model response exceeds its limit")
        if _secret_in_bytes(self._bearer, result.body):
            raise EngineRelayError("secret_leak", "model response failed secret scanning")
        headers = _response_headers(
            result.headers,
            allowed=_MODEL_RESPONSE_HEADERS,
            body_size=len(result.body),
            label="model response",
        )
        rows = dict(headers)
        if any(self._bearer in value for _, value in headers):
            raise EngineRelayError("secret_leak", "model response failed secret scanning")
        try:
            _require_int(
                result.input_tokens,
                "model input tokens",
                minimum=0,
                maximum=self.policy.max_input_tokens_per_request,
            )
            _require_int(
                result.output_tokens,
                "model output tokens",
                minimum=0,
                maximum=self.policy.max_output_tokens_per_request,
            )
            _require_int(
                result.cost_microunits,
                "model cost",
                minimum=0,
                maximum=self.policy.max_cost_microunits_per_request,
            )
            _require_digest(result.provider_request_ref, "provider request")
        except ValueError:
            raise EngineRelayError("invalid_upstream", "model usage receipt is invalid") from None
        if result.protected_secret_absent is not True:
            raise EngineRelayError("invalid_upstream", "model secret scan is incomplete")
        if not isinstance(result.fixture_usage_estimate, bool) or not isinstance(
            result.live_model_proof, bool
        ):
            raise EngineRelayError("invalid_upstream", "model proof state is invalid")
        if result.fixture_usage_estimate and result.live_model_proof:
            raise EngineRelayError("invalid_upstream", "model proof state conflicts")

        stream_requested = request_document.get("stream") is True
        content_type = rows.get("content-type")
        if content_type == "text/event-stream":
            if (
                not stream_requested
                or not self.policy.allow_controlled_test_sse
                or result.status != 200
                or set(rows)
                != {
                    "cache-control",
                    "content-length",
                    "content-type",
                    "x-bluefire-provider",
                }
                or rows.get("cache-control") != "no-store"
                or rows.get("content-length") != str(len(result.body))
                or rows.get("x-bluefire-provider") != _CONTROLLED_PROVIDER_LABEL
                or result.fixture_usage_estimate is not True
                or result.live_model_proof is not False
                or result.cost_microunits != 0
            ):
                raise EngineRelayError("invalid_upstream", "controlled stream proof is invalid")
            parsed_sse = _parse_controlled_sse(
                result.body,
                attempt_id=self.policy.attempt_id,
                model_id=self.policy.model_id,
                tool_names=_controlled_stream_tool_names(request_document),
                bearer=self._bearer,
                max_input_tokens=self.policy.max_input_tokens_per_request,
                max_output_tokens=self.policy.max_output_tokens_per_request,
            )
            if (
                parsed_sse.input_tokens != result.input_tokens
                or parsed_sse.output_tokens != result.output_tokens
            ):
                raise EngineRelayError("invalid_upstream", "controlled stream usage drifted")
            return result, headers, (*parsed_sse.documents, parsed_sse.arguments)

        if content_type != "application/json" or "x-bluefire-provider" in rows:
            raise EngineRelayError("invalid_upstream", "model response content type is invalid")
        parsed = _strict_json(result.body, label="model response")
        if _json_contains_secret(parsed, self._bearer):
            raise EngineRelayError("secret_leak", "model response failed secret scanning")
        if stream_requested:
            if (
                result.status < 400
                or set(rows) != {"cache-control", "content-length", "content-type"}
                or rows.get("cache-control") != "no-store"
                or rows.get("content-length") != str(len(result.body))
                or result.input_tokens != 0
                or result.output_tokens != 0
                or result.cost_microunits != 0
                or result.fixture_usage_estimate is not False
                or result.live_model_proof is not False
            ):
                raise EngineRelayError("invalid_upstream", "controlled provider refusal is invalid")
            _validate_controlled_provider_error(parsed)
        return result, headers, parsed

    def _append_model_failure(
        self,
        sequence: int,
        request: ModelGatewayRequest,
        request_digest: str,
        started: int,
        status: str,
        *,
        evidence_ref: str | None = None,
    ) -> None:
        self._append_audit(
            RelayAuditRecord(
                relay_kind="model_gateway",
                attempt_id=self.policy.attempt_id,
                objective_ref=self.policy.objective_ref,
                sequence=sequence,
                request_id=request.request_id,
                operation="chat_completions",
                request_digest=request_digest,
                request_bytes=len(request.body),
                response_digest=None,
                response_bytes=0,
                status=status,
                result_status=None,
                input_tokens=0,
                output_tokens=0,
                cost_microunits=0,
                elapsed_ms=max(0, (self._monotonic_ns() - started) // 1_000_000),
                recorded_at=_audit_recorded_at(self._clock, self.policy.created_at),
                policy_digest=self.policy.policy_digest,
                evidence_ref=evidence_ref,
            )
        )

    def _finish_model_failure(
        self,
        sequence: int,
        request: ModelGatewayRequest,
        request_digest: str,
        started: int,
        status: str,
        *,
        evidence_ref: str | None = None,
    ) -> None:
        self._append_model_failure(
            sequence,
            request,
            request_digest,
            started,
            status,
            evidence_ref=evidence_ref,
        )

    def _append_audit(self, record: RelayAuditRecord) -> None:
        try:
            self._audit.append(record)
        except Exception:
            raise EngineRelayError(
                "audit_unavailable", "model gateway audit is unavailable"
            ) from None


class ControlledModelGatewayLease:
    """Attempt-scoped lease compatible with ``StrixEngineRuntime``."""

    __slots__ = ("_gateway",)

    def __init__(self, gateway: ControlledModelGateway) -> None:
        self._gateway = gateway

    @property
    def authorization_ref(self) -> str:
        return self._gateway.authorization_ref

    def secret_value(self) -> str:
        return self._gateway.secret_value()

    def revoke(self) -> str:
        receipt = self._gateway.revoke()
        if not receipt.protected_revocation_verified:
            raise EngineRelayError(
                "revocation_unverified", "model gateway protected revocation is unverified"
            )
        return receipt.receipt_digest
