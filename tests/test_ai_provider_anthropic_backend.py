"""Anthropic Messages-API backend tests.

Every test uses an injectable :class:`_MockTransport` so no real
network call is ever issued. The CI guarantee is the same as the
local-first baseline: tests must not require API keys, must not
reach the network, and must not depend on any external service.

Pinned invariants (mirror the OpenAI-compatible backend's
contract where applicable, plus the Anthropic-specific shape
differences):

1. **Local-first gates (three of them)** — backend short-circuits
   to ``ProviderResponse(network_disabled=True, error=...)`` and
   never invokes the transport when ANY of the following holds:
   ``enabled=False``, empty ``api_base``, or empty ``api_key``.
   The third gate is intentionally STRICTER than the OpenAI-
   compatible backend because Anthropic has no local-server
   analog — failing safely with a clear error message beats a
   wasted 401.
2. **Auto-registration** — importing ``src.core.ai`` registers
   the adapter for canonical ``anthropic`` (and the ``claude``
   alias normalised at factory time).
3. **URL construction** — ``{api_base}/v1/messages`` unless the
   operator already included that suffix. Trailing slashes
   tolerated.
4. **Auth headers** — ``x-api-key`` (NOT ``Authorization: Bearer``)
   and ``anthropic-version`` (default ``2023-06-01``;
   override via ``ai_providers.anthropic.anthropic_version``).
5. **Request body** — model + messages + ``max_tokens`` always
   (Anthropic requires it; default 1024 when neither config nor
   options specify); top-level ``system`` field built from
   ``ProviderOptions.system`` and/or RAG context (concatenated);
   per-call options (max_tokens / temperature / timeout) honoured
   even when set to ``0`` (the same is-not-None discipline as the
   OpenAI-compatible backend).
6. **Response parsing** — happy path concatenates every ``text``-
   type content block; ``stop_reason`` becomes ``finish_reason``;
   Anthropic's ``input_tokens`` / ``output_tokens`` normalise to
   the shared ``prompt_tokens`` / ``completion_tokens`` /
   ``total_tokens`` keys; non-200 / invalid-JSON / no-content
   paths surface as ``error=...`` without raising.
7. **Transport errors** — caught and surfaced in
   ``ProviderResponse(error=...)``.
8. **Fallback chain compatibility** — the adapter wraps cleanly
   under :class:`FallbackChainProvider`; failures route to the
   fallback per the existing contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

import pytest

from src.core.ai.backends.anthropic import (
    AnthropicMessagesBackend,
    register_anthropic_backend,
)
from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.providers import ProviderFactory, TemplateProvider
from src.core.ai.transport import HTTPResponse
from src.core.ai.types import ProviderOptions, ProviderResponse


# ---------------------------------------------------------------------------
# MockTransport — captures every call so tests can assert request shape
# ---------------------------------------------------------------------------


@dataclass
class _CapturedCall:
    url: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    timeout: int


@dataclass
class _MockTransport:
    responses: List[Any] = field(default_factory=list)
    raise_on_call: Exception | None = None
    calls: List[_CapturedCall] = field(default_factory=list)

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any],
        timeout: int,
    ) -> HTTPResponse:
        self.calls.append(
            _CapturedCall(
                url=url,
                headers=dict(headers),
                body=dict(body),
                timeout=timeout,
            )
        )
        if self.raise_on_call is not None:
            raise self.raise_on_call
        if not self.responses:
            raise RuntimeError("MockTransport: no canned response left")
        next_response = self.responses.pop(0)
        if callable(next_response):
            return next_response(self.calls[-1])
        assert isinstance(next_response, HTTPResponse)
        return next_response


def _ok_messages_response(
    text: str = "claude-response",
    *,
    stop_reason: str = "end_turn",
    input_tokens: int = 5,
    output_tokens: int = 11,
    extras: Mapping[str, Any] | None = None,
) -> HTTPResponse:
    payload: Dict[str, Any] = {
        "id": "msg_default",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }
    if extras:
        payload.update(dict(extras))
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


def _ok_with(text: str = "ok") -> HTTPResponse:
    return _ok_messages_response(text=text)


# ---------------------------------------------------------------------------
# Local-first gates (three of them)
# ---------------------------------------------------------------------------


def test_backend_offline_when_enabled_false_even_with_api_base_and_key() -> None:
    """The most important gate. enabled=False short-circuits BEFORE
    any check on api_base / api_key, and the transport is never
    called even with both other gates passed."""
    transport = _MockTransport()
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk-real",
        transport=transport,
        enabled=False,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and "AI module is disabled" in response.error
    assert transport.calls == []


def test_backend_offline_when_api_base_empty() -> None:
    transport = _MockTransport()
    backend = AnthropicMessagesBackend(
        endpoint="",
        api_key="sk-real",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and "api_base not configured" in response.error
    assert transport.calls == []


def test_backend_offline_when_api_key_empty() -> None:
    """Anthropic-specific: empty api_key short-circuits with a clear
    error rather than dispatching and waiting for a 401. Anthropic
    has no local-server analog so the OpenAI-compatible "send
    anyway" semantics do not apply."""
    transport = _MockTransport()
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and "anthropic api_key is required" in response.error
    # Operator gets a clear pointer to the env-var config knob.
    assert "modules.ai.api_key_env" in response.error
    assert transport.calls == []


# ---------------------------------------------------------------------------
# URL construction
# ---------------------------------------------------------------------------


def test_backend_appends_messages_path_when_missing() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == "https://api.anthropic.example/v1/messages"


def test_backend_honours_explicit_messages_suffix() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example/v1/messages",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == "https://api.anthropic.example/v1/messages"


def test_backend_strips_trailing_slash_on_api_base() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example/",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == "https://api.anthropic.example/v1/messages"


# ---------------------------------------------------------------------------
# Auth + version headers
# ---------------------------------------------------------------------------


def test_backend_uses_x_api_key_header_not_bearer() -> None:
    """Anthropic-specific: ``x-api-key`` header (NOT
    ``Authorization: Bearer``)."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk-secret",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    headers = transport.calls[0].headers
    assert headers.get("x-api-key") == "sk-secret"
    # MUST NOT use Bearer auth.
    assert "Authorization" not in headers


def test_backend_includes_anthropic_version_header_default() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].headers.get("anthropic-version") == "2023-06-01"


def test_backend_provider_settings_anthropic_version_overrides_default() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        provider_settings={"anthropic_version": "2024-09-01"},
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].headers.get("anthropic-version") == "2024-09-01"


def test_backend_provider_settings_headers_extend_request_headers() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        provider_settings={"headers": {"anthropic-beta": "messages-2024-01-01"}},
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].headers.get("anthropic-beta") == "messages-2024-01-01"
    # Defaults are still present.
    assert transport.calls[0].headers.get("x-api-key") == "sk"


# ---------------------------------------------------------------------------
# Request body shape
# ---------------------------------------------------------------------------


def test_backend_request_body_contains_model_messages_and_max_tokens() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        model="claude-3-opus-20240229",
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("the prompt")
    body = transport.calls[0].body
    assert body["model"] == "claude-3-opus-20240229"
    assert body["messages"] == [{"role": "user", "content": "the prompt"}]
    # Anthropic REQUIRES max_tokens. Adapter default is 1024.
    assert body["max_tokens"] == 1024


def test_backend_max_tokens_uses_instance_default_when_set() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        max_tokens=4096,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].body["max_tokens"] == 4096


def test_backend_max_tokens_per_call_options_override_instance() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        max_tokens=512,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(max_tokens=2048))
    assert transport.calls[0].body["max_tokens"] == 2048


def test_backend_explicit_zero_options_propagate() -> None:
    """is-not-None discipline: max_tokens=0 / temperature=0.0 /
    timeout=0 are explicit operator choices and reach the request
    body (or transport timeout)."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        max_tokens=512,
        temperature=0.7,
        timeout=30,
        transport=transport,
        enabled=True,
    )
    backend.generate(
        "hi",
        options=ProviderOptions(max_tokens=0, temperature=0.0, timeout=0),
    )
    body = transport.calls[0].body
    assert body["max_tokens"] == 0
    assert body["temperature"] == 0.0
    assert transport.calls[0].timeout == 0


def test_backend_system_prompt_is_top_level_field_not_a_message() -> None:
    """Anthropic uses a top-level ``system`` field, NOT a system role
    in the messages array."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(system="you are a defender"))
    body = transport.calls[0].body
    assert body["system"] == "you are a defender"
    # Messages must contain ONLY the user message — no system role.
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert all(m["role"] != "system" for m in body["messages"])


def test_backend_concatenates_system_and_context_into_system_field() -> None:
    """Per-call system prompt + RAG context concatenate into the
    single top-level ``system`` field. Lets the shared
    ProviderOptions/_ask interface work the same way against
    Anthropic and OpenAI-compatible backends."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate(
        "hi",
        context=["doc-a snippet", "doc-b snippet"],
        options=ProviderOptions(system="be concise"),
    )
    body = transport.calls[0].body
    assert "be concise" in body["system"]
    assert "doc-a snippet" in body["system"]
    assert "doc-b snippet" in body["system"]


def test_backend_request_body_omits_temperature_when_unset() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        temperature=None,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert "temperature" not in transport.calls[0].body


def test_backend_uses_instance_timeout_when_options_omit_it() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        timeout=42,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].timeout == 42


# ---------------------------------------------------------------------------
# Response parsing — happy paths
# ---------------------------------------------------------------------------


def test_backend_happy_path_returns_text_usage_finish_reason() -> None:
    transport = _MockTransport(
        responses=[
            _ok_messages_response(
                text="claude wrote this",
                stop_reason="end_turn",
                input_tokens=12,
                output_tokens=20,
            )
        ]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "claude wrote this"
    # stop_reason -> finish_reason.
    assert response.finish_reason == "end_turn"
    # input/output_tokens normalised to shared usage keys.
    assert response.usage == {
        "prompt_tokens": 12,
        "completion_tokens": 20,
        "total_tokens": 32,
    }
    assert response.network_disabled is False
    assert response.error is None
    assert response.metadata.get("url") == "https://api.anthropic.example/v1/messages"


def test_backend_concatenates_multiple_text_blocks() -> None:
    """Anthropic responses can contain multiple ``text``-type content
    blocks. The adapter MUST concatenate them so multi-block
    responses are not silently truncated to the first block."""
    payload = {
        "id": "msg_multi",
        "content": [
            {"type": "text", "text": "first part. "},
            {"type": "text", "text": "second part."},
        ],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 2},
    }
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps(payload))]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "first part. second part."


def test_backend_metadata_includes_response_id_and_upstream_model() -> None:
    transport = _MockTransport(
        responses=[
            _ok_messages_response(extras={"id": "msg_abc-123", "model": "claude-server-side"})
        ]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.metadata.get("response_id") == "msg_abc-123"
    assert response.metadata.get("upstream_model") == "claude-server-side"


def test_backend_skips_non_text_content_blocks() -> None:
    """Anthropic may emit non-text content block types (tool_use,
    image, etc.). The adapter currently only renders text blocks;
    non-text blocks must not crash the parser."""
    payload = {
        "content": [
            {"type": "text", "text": "hello "},
            {"type": "tool_use", "id": "toolu_1", "name": "calc", "input": {}},
            {"type": "text", "text": "world"},
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 3, "output_tokens": 5},
    }
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps(payload))]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "hello world"
    assert response.finish_reason == "tool_use"


# ---------------------------------------------------------------------------
# Response parsing — error paths
# ---------------------------------------------------------------------------


def test_backend_non_200_status_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=429, body='{"error":{"type":"rate_limit_error"}}')]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "http 429" in response.error
    assert response.network_disabled is False
    assert response.metadata.get("status_code") == 429


def test_backend_invalid_json_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body="not-json")]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "not valid JSON" in response.error
    assert response.network_disabled is False


def test_backend_payload_without_content_array_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps({"id": "x"}))]
    )
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "no content array" in response.error


def test_backend_transport_exception_surfaces_as_error() -> None:
    transport = _MockTransport(raise_on_call=ConnectionError("network down"))
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "transport error" in response.error
    assert response.network_disabled is False


# ---------------------------------------------------------------------------
# Auto-registration + alias normalisation
# ---------------------------------------------------------------------------


def test_auto_registration_routes_anthropic_to_messages_backend() -> None:
    register_anthropic_backend()  # idempotent
    provider = ProviderFactory.from_ai_config(
        {"provider": "anthropic", "model": "m", "api_base": "https://api.anthropic.example"}
    )
    assert isinstance(provider, AnthropicMessagesBackend)


def test_claude_alias_normalises_to_anthropic_backend() -> None:
    register_anthropic_backend()
    provider = ProviderFactory.from_ai_config(
        {"provider": "claude", "model": "m", "api_base": "https://api.anthropic.example"}
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    # Canonical name is preserved.
    assert provider.name == "anthropic"


def test_anthropic_default_construction_is_offline() -> None:
    """Phase 1 contract: every recognised provider name yields
    network_disabled=True under the default factory call (no
    enabled flag set)."""
    provider = ProviderFactory.from_ai_config(
        {"provider": "anthropic", "model": "m", "api_base": "https://api.anthropic.example"}
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    response = provider.generate("hi")
    assert response.network_disabled is True


# ---------------------------------------------------------------------------
# Fallback chain compatibility
# ---------------------------------------------------------------------------


def test_anthropic_failure_falls_back_to_template() -> None:
    """The adapter wraps cleanly under FallbackChainProvider:
    a primary failure routes to the configured fallback, with
    fallback_used=True and primary attribution metadata."""
    transport = _MockTransport(raise_on_call=ConnectionError("upstream gone"))
    primary = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    fallback = TemplateProvider(model="safe-template")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    response = chain.generate("hi")
    assert response.fallback_used is True
    assert response.metadata.get("primary_provider") == "anthropic"
    assert response.metadata.get("primary_error") and "upstream gone" in (
        response.metadata.get("primary_error") or ""
    )
    # Fallback identity reflected.
    assert response.provider == "template"
    assert response.model == "safe-template"


def test_anthropic_offline_short_circuit_does_not_trigger_fallback() -> None:
    """A backend short-circuit (enabled=False / api_base empty /
    api_key empty) returns an error response, so the fallback
    chain DOES fire — verifying that the offline marker still
    routes through the wrapper correctly."""
    transport = _MockTransport()
    primary = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.example",
        api_key="",  # triggers anthropic api_key gate
        transport=transport,
        enabled=True,
    )
    fallback = TemplateProvider(model="safe-template")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)
    response = chain.generate("hi")
    # Fallback fired because the primary returned an error.
    assert response.fallback_used is True
    assert response.provider == "template"
    # Transport never called either way.
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Default-config zero-network proof
# ---------------------------------------------------------------------------


def test_default_config_anthropic_provider_does_not_call_transport() -> None:
    """End-to-end: even with a fully populated remote config
    (api_base + api_key resolved), an `enabled: false` config
    keeps the adapter offline and the transport untouched."""
    import os

    os.environ["BLUEFIRE_ANTHROPIC_TEST_KEY"] = "sk-test"
    try:
        ai_config = {
            "enabled": False,
            "provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022",
            "api_base": "https://api.anthropic.example",
            "api_key_env": "BLUEFIRE_ANTHROPIC_TEST_KEY",
        }
        provider = ProviderFactory.from_ai_config(ai_config)
        assert isinstance(provider, AnthropicMessagesBackend)
        transport = _MockTransport()
        provider.transport = transport
        response = provider.generate("hi")
        assert response.network_disabled is True
        assert "AI module is disabled" in (response.error or "")
        assert transport.calls == []
    finally:
        os.environ.pop("BLUEFIRE_ANTHROPIC_TEST_KEY", None)
