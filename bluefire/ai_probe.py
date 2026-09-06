"""Opt-in, single-request provider capability check, never a fallback success."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Mapping

from .ai import AIJSONTransport, UrllibAIJSONTransport, _strict_json_object
from .ai_wire import (
    AIProviderError,
    AIProviderTransportError,
    AIWireError,
    credential_value,
    request_headers,
    response_usage,
    structured_output,
    structured_request,
)
from .config import AIProviderConfig, AIProviderKind
from .util import canonical_json_bytes, content_hash

_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean", "enum": [True]}},
    "required": ["ok"],
    "additionalProperties": False,
}


def check_provider(
    config: AIProviderConfig,
    *,
    connect: bool,
    environ: Mapping[str, str] | None = None,
    transport: AIJSONTransport | None = None,
) -> Mapping[str, Any]:
    """Resolve only this explicit reference; send a tiny synthetic request if asked.

    The token ceiling includes reasoning. A model unable to answer within this
    probe budget reports incomplete; we do not silently increase the budget.
    """
    key = credential_value(config, os.environ if environ is None else environ)
    ready = config.api_key is None or bool(key)
    result: dict[str, Any] = {
        "schema_version": "bluefire.ai-provider-check.v1",
        "provider_id": config.id,
        "configuration_digest": content_hash(config.to_dict()),
        "api_style": config.kind.value,
        "model": config.model,
        "credential_state": (
            "not_required" if config.api_key is None else "ready" if ready else "unavailable"
        ),
        "connectivity": "not_tested",
        "structured_output": "not_tested",
        "attempts": 0,
        "used_fallback": False,
        "code": "configuration_ready" if ready else "credential_unavailable",
        "message": (
            "Configuration checked; no network request was made."
            if ready
            else "The referenced server environment variable is unset or invalid. No network request was made."
        ),
    }
    if not connect or not ready:
        return result
    if config.kind is AIProviderKind.DETERMINISTIC:
        result.update(
            code="deterministic_no_network",
            message="Deterministic mode has no external connection to test.",
        )
        return result
    bounded = replace(
        config,
        timeout_seconds=min(config.timeout_seconds, 10),
        max_retries=0,
        max_output_tokens=min(config.max_output_tokens, 256),
    )
    result.update(
        attempts=1,
        timeout_seconds=bounded.timeout_seconds,
        max_output_tokens=bounded.max_output_tokens,
    )
    body = canonical_json_bytes(
        structured_request(
            bounded,
            instructions='Return exactly {"ok":true} using the supplied schema.',
            input_text="Synthetic connection test. No scenario or evidence is supplied.",
            name="bluefire_connection_check",
            schema=_SCHEMA,
        )
    )
    try:
        payload = (transport or UrllibAIJSONTransport()).post(
            str(bounded.endpoint),
            headers=request_headers(key),
            body=body,
            timeout_seconds=float(bounded.timeout_seconds),
        )
        if len(payload) > 1_048_576:
            raise AIWireError("response_invalid", "Probe response exceeded the byte limit.")
        result["connectivity"] = "passed"
        response = _strict_json_object(payload, "Provider check")
        for field in ("id", "model"):
            value = response.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise AIWireError("response_invalid", "Provider response identity is invalid.")
        text = structured_output(response, bounded.kind)
        response_usage(response.get("usage"), bounded.max_output_tokens, bounded.kind)
        output = _strict_json_object(text.encode("utf-8"), "Provider check output")
        if set(output) != {"ok"} or output["ok"] is not True:
            raise AIWireError("response_invalid", "Provider did not return the check schema.")
    except AIProviderTransportError as exc:
        messages = {
            "authentication_failed": "The endpoint rejected authentication. Check the referenced credential and account access.",
            "rate_limited": "The endpoint rate-limited this request. No retry was sent.",
            "endpoint_rejected": "The endpoint rejected the request. Check API style, endpoint path, model and strict schema support.",
        }
        result.update(
            connectivity="failed",
            code=exc.code,
            message=messages.get(
                exc.code, "The provider request failed or timed out. No retry or fallback was used."
            ),
        )
    except AIProviderError as exc:
        result.update(
            structured_output="failed",
            code=exc.code if isinstance(exc, AIWireError) else "response_invalid",
            message="The endpoint responded, but the bounded structured-output check failed. Check API style, model support, and token budget.",
        )
    else:
        result.update(
            structured_output="passed",
            response_model=response["model"],
            code="probe_passed",
            message="One live synthetic request completed with the required strict output. This does not certify proposal quality or every model capability.",
        )
    return result
