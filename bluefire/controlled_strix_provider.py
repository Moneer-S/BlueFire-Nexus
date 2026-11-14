"""Attempt-local OpenAI-compatible provider for Strix mechanics tests.

This fixture is deliberately not a model. It emits a finite sequence of tool
calls from a controller-owned manifest, validates each call against the exact
tool schema supplied by the client, and records only bounded metadata. It must
not be exposed as a configurable production provider or used as evidence of
live-model decision quality.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .strix_tool_conformance import (
    MODEL_ID,
    PROVIDER_ID,
    OfflineRootToolProfile,
    ToolConformanceError,
    validate_finish_arguments,
    validate_phase_parameters,
)

PROVIDER_LABEL = "Test provider"
MANIFEST_SCHEMA = "bluefire.controlled-strix-mechanics.v2"
DEFAULT_MODEL_ID = MODEL_ID
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
_ALLOWED_REQUEST_FIELDS = frozenset(
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
_ALLOWED_SCHEMA_KEYWORDS = frozenset(
    {
        "$schema",
        "additionalProperties",
        "const",
        "default",
        "description",
        "enum",
        "examples",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "nullable",
        "properties",
        "required",
        "title",
        "type",
    }
)


class ControlledProviderError(ValueError):
    """Bounded protocol failure that is safe to return to the test client."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.safe_message = message


def _reject_nonfinite(value: str) -> None:
    raise ControlledProviderError(400, "invalid_json", f"non-finite JSON value {value} is invalid")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ControlledProviderError(400, "invalid_json", "duplicate JSON field is invalid")
        value[name] = item
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write")
        remaining = remaining[written:]


def _bounded_text(value: Any, label: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is invalid")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ControlledProviderError(422, "invalid_manifest", f"{label} is outside its bound")
    return int(value)


def _schema_depth(value: Any, *, limit: int, depth: int = 0) -> int:
    if depth > limit:
        raise ControlledProviderError(422, "schema_too_deep", "tool schema is too deep")
    if isinstance(value, Mapping):
        return max(
            [depth] + [_schema_depth(item, limit=limit, depth=depth + 1) for item in value.values()]
        )
    if isinstance(value, list):
        return max([depth] + [_schema_depth(item, limit=limit, depth=depth + 1) for item in value])
    return depth


def _validate_schema_value(value: Any, schema: Any, *, depth: int, limit: int) -> None:
    if depth > limit or not isinstance(schema, Mapping):
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")
    unknown = set(schema) - _ALLOWED_SCHEMA_KEYWORDS
    if unknown:
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")

    if "const" in schema and value != schema["const"]:
        raise ControlledProviderError(422, "invalid_tool_arguments", "tool arguments are invalid")
    if "enum" in schema:
        options = schema["enum"]
        if not isinstance(options, list) or value not in options:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )

    declared = schema.get("type")
    if schema.get("nullable") is True and value is None:
        return
    if isinstance(declared, list):
        allowed = set(declared)
        if not allowed or not allowed <= {
            "array",
            "boolean",
            "integer",
            "null",
            "number",
            "object",
            "string",
        }:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        if value is None and "null" in allowed:
            return
        matches = [kind for kind in allowed if kind != "null" and _matches_type(value, kind)]
        if not matches:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        declared = matches[0]
    elif declared is None:
        if "properties" in schema or "required" in schema:
            declared = "object"
        else:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
    elif not isinstance(declared, str) or declared not in {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }:
        raise ControlledProviderError(422, "unsupported_tool_schema", "tool schema is unsupported")

    if not _matches_type(value, declared):
        raise ControlledProviderError(422, "invalid_tool_arguments", "tool arguments are invalid")

    if declared == "object":
        assert isinstance(value, Mapping)
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if (
            not isinstance(properties, Mapping)
            or not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
        ):
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        missing = set(required) - set(value)
        if missing:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        extras = set(value) - set(properties)
        additional = schema.get("additionalProperties", True)
        if extras and additional is False:
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        if extras and additional is not True:
            if not isinstance(additional, Mapping):
                raise ControlledProviderError(
                    422, "unsupported_tool_schema", "tool schema is unsupported"
                )
            for name in extras:
                _validate_schema_value(value[name], additional, depth=depth + 1, limit=limit)
        for name, item in value.items():
            if name in properties:
                _validate_schema_value(item, properties[name], depth=depth + 1, limit=limit)
    elif declared == "array":
        assert isinstance(value, list)
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", 1_024)
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or not minimum <= len(value) <= maximum
        ):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        items = schema.get("items")
        if items is None:
            raise ControlledProviderError(
                422, "unsupported_tool_schema", "tool schema is unsupported"
            )
        for item in value:
            _validate_schema_value(item, items, depth=depth + 1, limit=limit)
    elif declared == "string":
        assert isinstance(value, str)
        minimum = schema.get("minLength", 0)
        maximum = schema.get("maxLength", 1_000_000)
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or not minimum <= len(value) <= maximum
        ):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
    elif declared in {"integer", "number"}:
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and (not isinstance(minimum, (int, float)) or value < minimum):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )
        if maximum is not None and (not isinstance(maximum, (int, float)) or value > maximum):
            raise ControlledProviderError(
                422, "invalid_tool_arguments", "tool arguments are invalid"
            )


def _matches_type(value: Any, kind: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, Mapping),
        "string": isinstance(value, str),
    }[kind]


@dataclass(frozen=True, slots=True)
class MechanicsPhase:
    phase_id: str
    tool_name: str
    tool_schema_digest: str
    arguments_json: str

    @property
    def arguments(self) -> Any:
        return json.loads(self.arguments_json)


@dataclass(frozen=True, slots=True)
class ControlledProviderManifest:
    attempt_id: str
    model_id: str
    profile: OfflineRootToolProfile
    max_requests: int
    max_request_bytes: int
    max_response_bytes: int
    max_messages: int
    max_tools: int
    max_schema_depth: int
    max_input_tokens: int
    max_output_tokens: int
    max_total_tokens: int
    phases: tuple[MechanicsPhase, ...]
    digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ControlledProviderManifest":
        expected = {
            "schema_version",
            "attempt_id",
            "model_id",
            "profile",
            "max_requests",
            "max_request_bytes",
            "max_response_bytes",
            "max_messages",
            "max_tools",
            "max_schema_depth",
            "max_input_tokens",
            "max_output_tokens",
            "max_total_tokens",
            "phases",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema_version") != MANIFEST_SCHEMA
        ):
            raise ControlledProviderError(422, "invalid_manifest", "manifest fields are invalid")
        attempt_id = _bounded_text(value["attempt_id"], "attempt ID", maximum=47)
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise ControlledProviderError(422, "invalid_manifest", "attempt ID is invalid")
        model_id = _bounded_text(value["model_id"], "model ID", maximum=160)
        if model_id != DEFAULT_MODEL_ID:
            raise ControlledProviderError(422, "invalid_manifest", "Test-provider model changed")
        try:
            profile = OfflineRootToolProfile.from_mapping(value["profile"])
        except ToolConformanceError as exc:
            raise ControlledProviderError(422, "invalid_profile", str(exc)) from exc
        raw_phases = value["phases"]
        if not isinstance(raw_phases, list) or len(raw_phases) != 2:
            raise ControlledProviderError(422, "invalid_manifest", "manifest phases are invalid")
        phases: list[MechanicsPhase] = []
        phase_ids: set[str] = set()
        for raw_phase in raw_phases:
            if not isinstance(raw_phase, Mapping) or set(raw_phase) != {
                "phase_id",
                "tool_name",
                "tool_schema_digest",
                "parameters_schema",
                "arguments",
            }:
                raise ControlledProviderError(422, "invalid_manifest", "manifest phase is invalid")
            phase_id = _bounded_text(raw_phase["phase_id"], "phase ID", maximum=48)
            tool_name = _bounded_text(raw_phase["tool_name"], "tool name", maximum=128)
            digest = _bounded_text(
                raw_phase["tool_schema_digest"], "tool schema digest", maximum=71
            )
            if (
                phase_id in phase_ids
                or _TOOL_NAME.fullmatch(tool_name) is None
                or _DIGEST.fullmatch(digest) is None
            ):
                raise ControlledProviderError(422, "invalid_manifest", "manifest phase is invalid")
            try:
                validate_phase_parameters(tool_name, raw_phase["parameters_schema"])
                schema_digest = _sha256(_canonical(raw_phase["parameters_schema"]))
            except ToolConformanceError as exc:
                raise ControlledProviderError(422, "invalid_manifest", str(exc)) from exc
            except (RecursionError, TypeError, ValueError) as exc:
                raise ControlledProviderError(
                    422, "invalid_manifest", "phase schema is invalid"
                ) from exc
            if schema_digest != digest:
                raise ControlledProviderError(
                    422, "invalid_manifest", "phase schema digest changed"
                )
            try:
                arguments_json = _canonical(raw_phase["arguments"]).decode("ascii")
            except (RecursionError, TypeError, ValueError) as exc:
                raise ControlledProviderError(
                    422, "invalid_manifest", "tool arguments are invalid"
                ) from exc
            if len(arguments_json) > 32_768:
                raise ControlledProviderError(
                    422, "invalid_manifest", "tool arguments are too large"
                )
            phase_ids.add(phase_id)
            phases.append(
                MechanicsPhase(
                    phase_id=phase_id,
                    tool_name=tool_name,
                    tool_schema_digest=digest,
                    arguments_json=arguments_json,
                )
            )
        if tuple((phase.phase_id, phase.tool_name) for phase in phases) != (
            ("inspect_graph", "view_agent_graph"),
            ("finish", "finish_scan"),
        ):
            raise ControlledProviderError(
                422, "invalid_manifest", "manifest phase plan differs from pinned root mechanics"
            )
        if phases[0].arguments != {}:
            raise ControlledProviderError(
                422, "invalid_manifest", "graph inspection arguments changed"
            )
        try:
            validate_finish_arguments(phases[-1].arguments)
        except ToolConformanceError as exc:
            raise ControlledProviderError(422, "invalid_manifest", str(exc)) from exc
        phase_bindings = {binding.name: binding for binding in profile.tool_bindings}
        if any(
            phase.tool_schema_digest != phase_bindings[phase.tool_name].parameters_digest
            for phase in phases
        ):
            raise ControlledProviderError(
                422, "invalid_manifest", "phase schema differs from profile"
            )
        try:
            canonical = _canonical(value)
        except (RecursionError, TypeError, ValueError) as exc:
            raise ControlledProviderError(422, "invalid_manifest", "manifest is invalid") from exc
        return cls(
            attempt_id=attempt_id,
            model_id=model_id,
            profile=profile,
            max_requests=_bounded_int(value["max_requests"], "request limit", 2, 2),
            max_request_bytes=_bounded_int(
                value["max_request_bytes"], "request byte limit", 1_024, 131_072
            ),
            max_response_bytes=_bounded_int(
                value["max_response_bytes"], "response byte limit", 1_024, 65_536
            ),
            max_messages=_bounded_int(value["max_messages"], "message limit", 3, 64),
            max_tools=_bounded_int(
                value["max_tools"],
                "tool limit",
                len(profile.tool_bindings),
                len(profile.tool_bindings),
            ),
            max_schema_depth=_bounded_int(value["max_schema_depth"], "schema depth", 1, 32),
            max_input_tokens=_bounded_int(
                value["max_input_tokens"], "input token limit", 1, 32_768
            ),
            max_output_tokens=_bounded_int(
                value["max_output_tokens"], "output token limit", 1, 8_192
            ),
            max_total_tokens=_bounded_int(
                value["max_total_tokens"], "total token limit", 2, 40_960
            ),
            phases=tuple(phases),
            digest=_sha256(canonical),
        )


class ControlledProviderState:
    """Thread-safe state for one immutable mechanics attempt."""

    def __init__(
        self,
        manifest: ControlledProviderManifest,
        bearer_token: str,
        *,
        audit_path: Path | None = None,
    ) -> None:
        if not isinstance(manifest, ControlledProviderManifest):
            raise ValueError("provider manifest is invalid")
        # Attempt-local input cannot approve its own captured wire schemas.
        # No digest is enrolled until the exact installed SDK/Strix request is
        # independently captured and reviewed, so deployed serving fails here.
        try:
            manifest.profile.require_enrolled()
        except ToolConformanceError as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(bearer_token, str) or not 32 <= len(bearer_token) <= 512:
            raise ValueError("bearer token is invalid")
        if bearer_token != bearer_token.strip() or any(
            ord(character) < 33 or ord(character) > 126 for character in bearer_token
        ):
            raise ValueError("bearer token is invalid")
        self.manifest = manifest
        self._bearer_token = bearer_token
        self._audit_path = audit_path
        self._lock = threading.Lock()
        self._request_count = 0
        self._phase_index = 0
        self._pending_call_id: str | None = None
        self._pending_phase_id: str | None = None
        self._completed_call_ids: tuple[str, ...] = ()
        self._cancelled = False
        self._gateway_digest = _sha256(Path(__file__).read_bytes())

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    @property
    def pending_call_id(self) -> str | None:
        with self._lock:
            return self._pending_call_id

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    def authorize(self, authorization: str | None) -> None:
        expected = f"Bearer {self._bearer_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise ControlledProviderError(401, "invalid_authorization", "authorization failed")

    def respond(self, body: bytes) -> bytes:
        with self._lock:
            if self._cancelled:
                raise ControlledProviderError(409, "attempt_cancelled", "attempt is cancelled")
            if len(body) > self.manifest.max_request_bytes:
                raise ControlledProviderError(413, "request_too_large", "request exceeds its limit")
            if self._request_count >= self.manifest.max_requests:
                raise ControlledProviderError(429, "request_limit", "request limit reached")
            self._request_count += 1
            sequence = self._request_count
            try:
                request = json.loads(
                    body,
                    parse_constant=_reject_nonfinite,
                    object_pairs_hook=_strict_object,
                )
            except ControlledProviderError as exc:
                self._audit_error(sequence, body, exc.code)
                raise
            except (RecursionError, UnicodeDecodeError, ValueError) as exc:
                self._audit_error(sequence, body, "invalid_json")
                raise ControlledProviderError(
                    400, "invalid_json", "request body is invalid"
                ) from exc
            try:
                _schema_depth(request, limit=128)
            except ControlledProviderError as exc:
                self._audit_error(sequence, body, exc.code)
                raise
            try:
                response, audit, next_phase_index, call_id, phase_id, completed_ids = (
                    self._build_response(sequence, body, request)
                )
            except ControlledProviderError as exc:
                self._audit_error(sequence, body, exc.code)
                raise
            if len(response) > self.manifest.max_response_bytes:
                self._audit_error(sequence, body, "response_too_large")
                raise ControlledProviderError(
                    413, "response_too_large", "response exceeds its limit"
                )
            audit["response_byte_hash"] = _sha256(response)
            audit["response_byte_size"] = len(response)
            self._append_audit(audit)
            self._phase_index = next_phase_index
            self._pending_call_id = call_id
            self._pending_phase_id = phase_id
            self._completed_call_ids = completed_ids
            return response

    def _build_response(
        self, sequence: int, raw_body: bytes, request: Any
    ) -> tuple[bytes, dict[str, Any], int, str, str, tuple[str, ...]]:
        if not isinstance(request, Mapping) or set(request) - _ALLOWED_REQUEST_FIELDS:
            raise ControlledProviderError(
                400, "unsupported_request", "request shape is unsupported"
            )
        if not {"model", "messages", "tools", "stream"} <= set(request):
            raise ControlledProviderError(
                400, "unsupported_request", "request shape is unsupported"
            )
        if request["model"] != self.manifest.model_id:
            raise ControlledProviderError(422, "wrong_model", "model does not match the attempt")
        if request["stream"] is not True:
            raise ControlledProviderError(422, "stream_required", "streaming is required")
        if request.get("parallel_tool_calls") is not False:
            raise ControlledProviderError(
                422, "parallel_tools_unsupported", "parallel tool calls are unsupported"
            )
        self._validate_tuning(request)
        messages = request["messages"]
        if not isinstance(messages, list) or not 1 <= len(messages) <= self.manifest.max_messages:
            raise ControlledProviderError(422, "invalid_messages", "message history is invalid")
        self._validate_messages(messages)
        tools = self._tool_roster(request["tools"])

        next_phase_index = self._phase_index
        completed_ids = self._completed_call_ids
        tool_messages = [
            message
            for message in messages
            if isinstance(message, Mapping) and message.get("role") == "tool"
        ]
        result_ids = [message.get("tool_call_id") for message in tool_messages]
        expected_result_ids = list(completed_ids)
        if self._pending_call_id is not None:
            expected_result_ids.append(self._pending_call_id)
        if result_ids != expected_result_ids:
            raise ControlledProviderError(
                409, "unexpected_history", "tool result history is invalid"
            )

        if self._pending_call_id is not None:
            matches = [
                message
                for message in messages
                if isinstance(message, Mapping)
                and message.get("role") == "tool"
                and message.get("tool_call_id") == self._pending_call_id
            ]
            if len(matches) != 1 or messages[-1] is not matches[0]:
                raise ControlledProviderError(
                    409, "unexpected_history", "expected tool result is missing or duplicated"
                )
            if len(messages) < 2 or not self._matches_pending_assistant_call(messages[-2]):
                raise ControlledProviderError(
                    409, "unexpected_history", "tool result is not paired to its assistant call"
                )
            next_phase_index += 1
            completed_ids = (*completed_ids, self._pending_call_id)

        if next_phase_index >= len(self.manifest.phases):
            raise ControlledProviderError(409, "attempt_complete", "attempt is already complete")
        phase = self.manifest.phases[next_phase_index]
        tool = tools.get(phase.tool_name)
        if tool is None:
            raise ControlledProviderError(
                422, "missing_required_tool", "required tool is unavailable"
            )
        schema = tool["parameters"]
        if _sha256(_canonical(schema)) != phase.tool_schema_digest:
            raise ControlledProviderError(422, "tool_schema_drift", "required tool schema changed")
        _schema_depth(schema, limit=self.manifest.max_schema_depth)
        arguments = phase.arguments
        _validate_schema_value(arguments, schema, depth=0, limit=self.manifest.max_schema_depth)
        self._validate_tool_choice(request.get("tool_choice"), phase.tool_name)

        call_id = f"call_{sequence:04d}_{hashlib.sha256((self.manifest.attempt_id + phase.phase_id).encode()).hexdigest()[:16]}"
        arguments_text = phase.arguments_json
        response = self._sse_response(
            sequence=sequence,
            call_id=call_id,
            tool_name=phase.tool_name,
            arguments=arguments_text,
            include_usage=self._include_usage(request.get("stream_options")),
            prompt_bytes=len(raw_body),
        )
        audit = self._base_audit(sequence, raw_body, request, tools)
        audit.update(
            {
                "status": "tool_call",
                "phase_id": phase.phase_id,
                "emitted_call_id": call_id,
                "tool_name": phase.tool_name,
                "arguments_digest": _sha256(arguments_text.encode("ascii")),
                "fixture_usage_estimate": True,
            }
        )
        return response, audit, next_phase_index, call_id, phase.phase_id, completed_ids

    def _validate_messages(self, messages: Sequence[Any]) -> None:
        allowed_roles = {"assistant", "developer", "system", "tool", "user"}
        total_bytes = 0
        for message in messages:
            if not isinstance(message, Mapping) or message.get("role") not in allowed_roles:
                raise ControlledProviderError(422, "invalid_messages", "message history is invalid")
            total_bytes += len(_canonical(message))
        if total_bytes > self.manifest.max_request_bytes:
            raise ControlledProviderError(413, "request_too_large", "request exceeds its limit")

    def _matches_pending_assistant_call(self, message: Any) -> bool:
        if not isinstance(message, Mapping) or message.get("role") != "assistant":
            return False
        calls = message.get("tool_calls")
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], Mapping):
            return False
        call = calls[0]
        function = call.get("function")
        if (
            set(call) != {"id", "type", "function"}
            or not isinstance(function, Mapping)
            or set(function) != {"name", "arguments"}
        ):
            return False
        phase = self.manifest.phases[self._phase_index]
        return (
            call.get("id") == self._pending_call_id
            and call.get("type") == "function"
            and function.get("name") == phase.tool_name
            and function.get("arguments") == phase.arguments_json
        )

    def _validate_tuning(self, request: Mapping[str, Any]) -> None:
        for name, minimum, maximum in (("temperature", 0.0, 2.0), ("top_p", 0.0, 1.0)):
            value = request.get(name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not minimum <= float(value) <= maximum
            ):
                raise ControlledProviderError(
                    400, "unsupported_request", "request tuning is unsupported"
                )
        for name in ("max_tokens", "max_completion_tokens"):
            value = request.get(name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= self.manifest.max_output_tokens
            ):
                raise ControlledProviderError(
                    400, "unsupported_request", "request tuning is unsupported"
                )
        seed = request.get("seed")
        if seed is not None and (
            isinstance(seed, bool) or not isinstance(seed, int) or not -(2**31) <= seed < 2**31
        ):
            raise ControlledProviderError(
                400, "unsupported_request", "request tuning is unsupported"
            )
        stop = request.get("stop")
        if stop is None:
            return
        if isinstance(stop, str):
            valid = 1 <= len(stop) <= 200
        else:
            valid = (
                isinstance(stop, list)
                and 1 <= len(stop) <= 4
                and all(isinstance(item, str) and 1 <= len(item) <= 200 for item in stop)
                and len(stop) == len(set(stop))
            )
        if not valid:
            raise ControlledProviderError(
                400, "unsupported_request", "request tuning is unsupported"
            )

    def _tool_roster(self, value: Any) -> Mapping[str, Mapping[str, Any]]:
        try:
            roster = self.manifest.profile.check_request_roster(value)
        except ToolConformanceError as exc:
            raise ControlledProviderError(422, "tool_roster_drift", str(exc)) from exc
        for function in roster.values():
            _schema_depth(function["parameters"], limit=self.manifest.max_schema_depth)
        return MappingProxyType(
            {name: MappingProxyType(dict(tool)) for name, tool in roster.items()}
        )

    @staticmethod
    def _validate_tool_choice(value: Any, selected: str) -> None:
        if value is None or (isinstance(value, str) and value in {"auto", "required"}):
            return
        if value == "none":
            raise ControlledProviderError(
                422, "tool_choice_conflict", "tool choice is incompatible"
            )
        if (
            not isinstance(value, Mapping)
            or set(value) != {"type", "function"}
            or value.get("type") != "function"
            or not isinstance(value.get("function"), Mapping)
            or set(value["function"]) != {"name"}
            or value["function"].get("name") != selected
        ):
            raise ControlledProviderError(
                422, "tool_choice_conflict", "tool choice is incompatible"
            )

    @staticmethod
    def _include_usage(value: Any) -> bool:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"include_usage"}
            or value["include_usage"] is not True
        ):
            raise ControlledProviderError(
                400, "unsupported_request", "stream options are unsupported"
            )
        return True

    def _sse_response(
        self,
        *,
        sequence: int,
        call_id: str,
        tool_name: str,
        arguments: str,
        include_usage: bool,
        prompt_bytes: int,
    ) -> bytes:
        response_id = f"chatcmpl-{self.manifest.attempt_id[-12:]}-{sequence:04d}"
        base = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": self.manifest.model_id,
            "system_fingerprint": "bluefire-test-provider-fixture-estimate",
        }
        chunks: list[dict[str, Any]] = [
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": call_id,
                                    "type": "function",
                                    "function": {"name": tool_name, "arguments": arguments},
                                }
                            ],
                        },
                        "finish_reason": None,
                    }
                ],
            },
            {
                **base,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
            },
        ]
        if include_usage:
            prompt_tokens = max(1, (prompt_bytes + 3) // 4)
            completion_tokens = max(1, (len(arguments) + len(tool_name) + 3) // 4)
            if (
                prompt_tokens > self.manifest.max_input_tokens
                or completion_tokens > self.manifest.max_output_tokens
                or prompt_tokens + completion_tokens > self.manifest.max_total_tokens
            ):
                raise ControlledProviderError(
                    422, "usage_limit", "estimated usage exceeds its bound"
                )
            chunks.append(
                {
                    **base,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": prompt_tokens + completion_tokens,
                    },
                }
            )
        lines = [f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks]
        lines.append("data: [DONE]\n\n")
        return "".join(lines).encode("utf-8")

    def _base_audit(
        self,
        sequence: int,
        body: bytes,
        request: Mapping[str, Any],
        tools: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        roles = [message.get("role") for message in request["messages"]]
        return {
            "schema_version": "bluefire.controlled-provider-audit.v1",
            "provider_id": PROVIDER_ID,
            "provider_label": PROVIDER_LABEL,
            "attempt_id": self.manifest.attempt_id,
            "sequence": sequence,
            "wall_time_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            "gateway_build_digest": self._gateway_digest,
            "manifest_digest": self.manifest.digest,
            "request_byte_hash": _sha256(body),
            "request_byte_size": len(body),
            "model_id": request["model"],
            "message_count": len(request["messages"]),
            "message_roles": roles,
            "tool_schema_digests": {
                name: _sha256(_canonical(tool["parameters"]))
                for name, tool in sorted(tools.items())
            },
            "tool_choice": request.get("tool_choice"),
            "stream": True,
        }

    def _audit_error(self, sequence: int, body: bytes, code: str) -> None:
        self._append_audit(
            {
                "schema_version": "bluefire.controlled-provider-audit.v1",
                "provider_id": PROVIDER_ID,
                "provider_label": PROVIDER_LABEL,
                "attempt_id": self.manifest.attempt_id,
                "sequence": sequence,
                "wall_time_ns": time.time_ns(),
                "monotonic_ns": time.monotonic_ns(),
                "gateway_build_digest": self._gateway_digest,
                "manifest_digest": self.manifest.digest,
                "request_byte_hash": _sha256(body),
                "request_byte_size": len(body),
                "status": "error",
                "error_code": code,
            }
        )

    def _append_audit(self, value: Mapping[str, Any]) -> None:
        if self._audit_path is None:
            return
        payload = _canonical(value) + b"\n"
        if len(payload) > 64 * 1024:
            raise ControlledProviderError(413, "audit_too_large", "audit record exceeds its limit")
        descriptor: int | None = None
        try:
            self._audit_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self._audit_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0),
                0o600,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        except OSError as exc:
            raise ControlledProviderError(
                409, "audit_unavailable", "provider audit is unavailable"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


def build_handler(state: ControlledProviderState) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to exactly one attempt state."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "BlueFireControlledProvider/1"
        sys_version = ""
        request_deadline_seconds = 5.0

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(self.request_deadline_seconds)

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/chat/completions":
                self._error(404, "not_found", "endpoint is unavailable")
                return
            try:
                state.authorize(self.headers.get("Authorization"))
                content_type = self.headers.get_content_type()
                if content_type != "application/json":
                    raise ControlledProviderError(
                        400, "invalid_content_type", "content type must be application/json"
                    )
                length_text = self.headers.get("Content-Length")
                if length_text is None:
                    raise ControlledProviderError(
                        400, "missing_content_length", "content length is required"
                    )
                try:
                    length = int(length_text)
                except ValueError as exc:
                    raise ControlledProviderError(
                        400, "invalid_content_length", "content length is invalid"
                    ) from exc
                if length < 0 or length > state.manifest.max_request_bytes:
                    raise ControlledProviderError(
                        413, "request_too_large", "request exceeds its limit"
                    )
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ControlledProviderError(
                        400, "incomplete_request", "request is incomplete"
                    )
                payload = state.respond(body)
            except ControlledProviderError as exc:
                self._error(exc.status, exc.code, exc.safe_message)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-BlueFire-Provider", PROVIDER_LABEL)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _error(self, status: int, code: str, message: str) -> None:
            payload = _canonical(
                {
                    "error": {
                        "message": message,
                        "type": "invalid_request_error",
                        "code": code,
                    }
                }
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return Handler


def _load_manifest(path: Path) -> ControlledProviderManifest:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=_reject_nonfinite,
        object_pairs_hook=_strict_object,
    )
    if not isinstance(value, Mapping):
        raise ControlledProviderError(422, "invalid_manifest", "manifest is invalid")
    return ControlledProviderManifest.from_mapping(value)


def _load_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").rstrip("\r\n")
    if (
        "\n" in token
        or "\r" in token
        or not 32 <= len(token) <= 512
        or token != token.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise ValueError("token file is invalid")
    return token


def _write_private_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if os.name == "nt":
            # Windows rename is atomic and fails when the destination exists.
            os.rename(temporary, path)
        else:
            # POSIX rename replaces an existing path, so publish with an
            # exclusive hard link instead.
            os.link(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the BlueFire controlled Strix test provider")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1",))
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65_535:
        parser.error("--port must be between 0 and 65535")

    state = ControlledProviderState(
        _load_manifest(args.manifest),
        _load_token(args.token_file),
        audit_path=args.audit,
    )
    server = ThreadingHTTPServer((args.host, args.port), build_handler(state))
    server.daemon_threads = True
    shutdown_started = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        state.cancel()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    ready = {
        "schema_version": "bluefire.controlled-provider-ready.v1",
        "provider_id": PROVIDER_ID,
        "provider_label": PROVIDER_LABEL,
        "attempt_id": state.manifest.attempt_id,
        "model_id": state.manifest.model_id,
        "host": args.host,
        "port": int(server.server_address[1]),
        "manifest_digest": state.manifest.digest,
        "live_model_proof": False,
    }
    _write_private_exclusive(args.ready_file, _canonical(ready) + b"\n")
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        state.cancel()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
