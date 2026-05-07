"""Gemini GenerateContent-API backend tests.

Every test uses an injectable :class:`_MockTransport` so no real
network call is ever issued. Same CI guarantee as the other
provider tests: no API keys, no network, no external service.

Pinned invariants (mirror the Anthropic backend's contract where
applicable, plus the Gemini-specific shape differences):

1. **Three local-first gates** (enabled / api_base / api_key);
   any one short-circuits to ``network_disabled=True``.
2. **Auto-registration** for canonical ``gemini`` and the
   ``google`` / ``google_gemini`` aliases.
3. **URL construction** — ``{api_base}/{api_version}/models/
   {model}:generateContent``. Honours an explicit
   ``:generateContent`` (or ``:streamGenerateContent``) suffix.
   ``api_version`` defaults to ``v1beta`` and is overridable via
   ``ai_providers.gemini.api_version``.
4. **Auth header** — ``x-goog-api-key`` (NOT Bearer, NOT
   x-api-key). Never appended as a query-string parameter.
5. **Request body** — ``contents`` array with role+parts shape
   (NOT ``messages`` of role+content); top-level
   ``systemInstruction`` field with parts shape; ``generationConfig``
   block holds ``maxOutputTokens`` / ``temperature`` (NOT top-
   level fields). is-not-None discipline so explicit zero values
   reach the request.
6. **Response parsing** — concatenates every ``text`` part from
   ``candidates[0].content.parts``; ``finishReason`` becomes
   ``finish_reason``; Gemini's ``promptTokenCount`` /
   ``candidatesTokenCount`` / ``totalTokenCount`` normalise to
   ``prompt_tokens`` / ``completion_tokens`` / ``total_tokens``;
   safety ratings + upstream model surface in metadata; non-200 /
   invalid JSON / no candidates / blocked-prompt all surface as
   ``error=...`` without raising.
7. **Transport errors** caught and surfaced.
8. **Fallback chain compatibility** — wraps cleanly under
   :class:`FallbackChainProvider`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

import pytest

from src.core.ai.backends.gemini import (
    GeminiGenerateContentBackend,
    register_gemini_backend,
)
from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.providers import ProviderFactory, TemplateProvider
from src.core.ai.transport import HTTPResponse
from src.core.ai.types import ProviderOptions, ProviderResponse


# ---------------------------------------------------------------------------
# MockTransport
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


def _ok_generate_response(
    text: str = "gemini-response",
    *,
    finish_reason: str = "STOP",
    prompt_tokens: int = 4,
    completion_tokens: int = 9,
    total_tokens: int | None = None,
    extras: Mapping[str, Any] | None = None,
) -> HTTPResponse:
    payload: Dict[str, Any] = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": text}],
                },
                "finishReason": finish_reason,
                "safetyRatings": [
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "NEGLIGIBLE"},
                ],
            }
        ],
        "usageMetadata": {
            "promptTokenCount": prompt_tokens,
            "candidatesTokenCount": completion_tokens,
        },
        "modelVersion": "gemini-1.5-flash-001",
    }
    if total_tokens is not None:
        payload["usageMetadata"]["totalTokenCount"] = total_tokens
    if extras:
        payload.update(dict(extras))
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


def _ok_with(text: str = "ok") -> HTTPResponse:
    return _ok_generate_response(text=text)


# ---------------------------------------------------------------------------
# Local-first gates
# ---------------------------------------------------------------------------


def test_backend_offline_when_enabled_false() -> None:
    transport = _MockTransport()
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
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
    backend = GeminiGenerateContentBackend(
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
    transport = _MockTransport()
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and "gemini api_key is required" in response.error
    assert "modules.ai.api_key_env" in response.error
    assert transport.calls == []


# ---------------------------------------------------------------------------
# URL construction
# ---------------------------------------------------------------------------


def test_backend_appends_default_v1beta_models_path_with_model() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        model="gemini-1.5-pro",
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-pro:generateContent"
    )


def test_backend_strips_trailing_slash_on_api_base() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        model="gemini-2.0-flash",
        endpoint="https://generativelanguage.googleapis.com/",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:generateContent"
    )


def test_backend_honours_explicit_generate_content_suffix() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    # Suffix not duplicated; operator's URL passes through as-is.
    assert transport.calls[0].url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-pro:generateContent"
    )


def test_backend_provider_settings_api_version_overrides_default() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        model="gemini-pro",
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        provider_settings={"api_version": "v1"},
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == (
        "https://generativelanguage.googleapis.com/v1/models/"
        "gemini-pro:generateContent"
    )


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------


def test_backend_uses_x_goog_api_key_header_not_bearer_or_query_param() -> None:
    """Gemini auth must use the ``x-goog-api-key`` header. Bearer is
    not accepted; the query-string variant is intentionally avoided
    because it leaks the key in server access logs."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk-secret",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    headers = transport.calls[0].headers
    assert headers.get("x-goog-api-key") == "sk-secret"
    assert "Authorization" not in headers
    assert "x-api-key" not in headers
    # Key must NOT appear in the URL (no ?key=... query-string variant).
    assert "key=" not in transport.calls[0].url


def test_backend_provider_settings_headers_extend_request_headers() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        provider_settings={"headers": {"X-Goog-User-Project": "lab-project"}},
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    headers = transport.calls[0].headers
    assert headers.get("X-Goog-User-Project") == "lab-project"
    assert headers.get("x-goog-api-key") == "sk"


# ---------------------------------------------------------------------------
# Request body shape
# ---------------------------------------------------------------------------


def test_backend_request_body_contains_user_content_with_parts() -> None:
    """Gemini uses the ``contents`` shape (NOT ``messages``)."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("the prompt")
    body = transport.calls[0].body
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "the prompt"}]},
    ]
    # MUST NOT use the messages shape.
    assert "messages" not in body


def test_backend_system_prompt_uses_system_instruction_top_level() -> None:
    """Gemini uses a top-level ``systemInstruction`` field with
    parts shape (NOT a system role in the contents array)."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(system="be defensive"))
    body = transport.calls[0].body
    assert body["systemInstruction"] == {"parts": [{"text": "be defensive"}]}
    # No system entry in contents.
    assert all(c["role"] != "system" for c in body["contents"])


def test_backend_concatenates_system_and_context_into_system_instruction() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate(
        "hi",
        context=["doc-a snippet", "doc-b snippet"],
        options=ProviderOptions(system="be brief"),
    )
    blob = transport.calls[0].body["systemInstruction"]["parts"][0]["text"]
    assert "be brief" in blob
    assert "doc-a snippet" in blob
    assert "doc-b snippet" in blob


def test_backend_generation_config_holds_max_tokens_and_temperature() -> None:
    """Gemini wraps generation knobs in ``generationConfig`` rather
    than top-level fields."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        max_tokens=2048,
        temperature=0.5,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    body = transport.calls[0].body
    assert body["generationConfig"] == {
        "maxOutputTokens": 2048,
        "temperature": 0.5,
    }
    assert "max_tokens" not in body
    assert "temperature" not in body


def test_backend_request_body_omits_generation_config_when_unset() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        max_tokens=None,
        temperature=None,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    body = transport.calls[0].body
    assert "generationConfig" not in body


def test_backend_explicit_zero_options_propagate() -> None:
    """is-not-None discipline: max_tokens=0 / temperature=0.0 /
    timeout=0 reach the request body and transport timeout."""
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
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
    gen_config = transport.calls[0].body["generationConfig"]
    assert gen_config["maxOutputTokens"] == 0
    assert gen_config["temperature"] == 0.0
    assert transport.calls[0].timeout == 0


def test_backend_uses_instance_timeout_when_options_omit_it() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        timeout=42,
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].timeout == 42


# ---------------------------------------------------------------------------
# Response parsing — happy path
# ---------------------------------------------------------------------------


def test_backend_happy_path_returns_text_usage_finish_reason() -> None:
    transport = _MockTransport(
        responses=[
            _ok_generate_response(
                text="gemini wrote this",
                finish_reason="STOP",
                prompt_tokens=8,
                completion_tokens=15,
                total_tokens=23,
            )
        ]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "gemini wrote this"
    assert response.finish_reason == "STOP"
    # promptTokenCount / candidatesTokenCount normalise into the
    # shared keys.
    assert response.usage == {
        "prompt_tokens": 8,
        "completion_tokens": 15,
        "total_tokens": 23,
    }
    assert response.network_disabled is False
    assert response.error is None


def test_backend_derives_total_tokens_when_omitted_by_vendor() -> None:
    """Vendor sometimes omits ``totalTokenCount``; the adapter
    derives it from the parts that are present so downstream
    consumers can rely on the key being there."""
    transport = _MockTransport(
        responses=[
            _ok_generate_response(
                prompt_tokens=4, completion_tokens=6, total_tokens=None,
            )
        ]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.usage == {
        "prompt_tokens": 4,
        "completion_tokens": 6,
        "total_tokens": 10,  # derived
    }


def test_backend_concatenates_multiple_text_parts() -> None:
    payload = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "first part. "},
                        {"text": "second part."},
                    ],
                },
                "finishReason": "STOP",
            }
        ]
    }
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps(payload))]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "first part. second part."


def test_backend_metadata_includes_upstream_model_and_safety_categories() -> None:
    transport = _MockTransport(responses=[_ok_with()])
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.metadata.get("upstream_model") == "gemini-1.5-flash-001"
    cats = response.metadata.get("safety_categories")
    assert cats is not None
    assert "HARM_CATEGORY_HATE_SPEECH" in cats
    assert "HARM_CATEGORY_DANGEROUS_CONTENT" in cats


# ---------------------------------------------------------------------------
# Response parsing — error paths
# ---------------------------------------------------------------------------


def test_backend_non_200_status_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=429, body='{"error":{"status":"RESOURCE_EXHAUSTED"}}')]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "http 429" in response.error
    assert response.network_disabled is False
    assert response.metadata.get("status_code") == 429


def test_backend_invalid_json_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body="not-json")]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "not valid JSON" in response.error


def test_backend_payload_without_candidates_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps({"otherKey": 1}))]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "no candidates" in response.error


def test_backend_blocked_prompt_surfaces_as_clear_error() -> None:
    """Gemini may block the whole prompt (no candidates) and report
    a ``promptFeedback.blockReason``. The adapter surfaces this as
    a clear error rather than the generic "no candidates" message."""
    payload = {
        "promptFeedback": {"blockReason": "SAFETY"},
        "candidates": [],
    }
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps(payload))]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error and "prompt blocked: SAFETY" in response.error
    assert response.metadata.get("block_reason") == "SAFETY"


def test_backend_transport_exception_surfaces_as_error() -> None:
    transport = _MockTransport(raise_on_call=ConnectionError("network down"))
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
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


def test_auto_registration_routes_gemini_to_generate_content_backend() -> None:
    register_gemini_backend()  # idempotent
    provider = ProviderFactory.from_ai_config(
        {"provider": "gemini", "model": "m", "api_base": "https://generativelanguage.googleapis.com"}
    )
    assert isinstance(provider, GeminiGenerateContentBackend)


@pytest.mark.parametrize("alias", ["google", "google_gemini"])
def test_alias_normalises_to_gemini_backend(alias: str) -> None:
    register_gemini_backend()
    provider = ProviderFactory.from_ai_config(
        {"provider": alias, "model": "m", "api_base": "https://generativelanguage.googleapis.com"}
    )
    assert isinstance(provider, GeminiGenerateContentBackend)
    assert provider.name == "gemini"


def test_gemini_default_construction_is_offline() -> None:
    """Phase 1 contract: default factory call yields
    network_disabled=True (enabled defaults to False)."""
    provider = ProviderFactory.from_ai_config(
        {"provider": "gemini", "model": "m", "api_base": "https://generativelanguage.googleapis.com"}
    )
    assert isinstance(provider, GeminiGenerateContentBackend)
    response = provider.generate("hi")
    assert response.network_disabled is True


# ---------------------------------------------------------------------------
# Fallback chain compatibility
# ---------------------------------------------------------------------------


def test_gemini_failure_falls_back_to_template() -> None:
    transport = _MockTransport(raise_on_call=ConnectionError("upstream gone"))
    primary = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    fallback = TemplateProvider(model="safe-template")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    response = chain.generate("hi")
    assert response.fallback_used is True
    assert response.metadata.get("primary_provider") == "gemini"
    assert response.provider == "template"


def test_gemini_offline_short_circuit_routes_through_fallback() -> None:
    """The api_key gate produces a structured error; the fallback
    chain wrapper picks that up and routes to the fallback,
    transport is never called."""
    transport = _MockTransport()
    primary = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com",
        api_key="",  # triggers the api_key gate
        transport=transport,
        enabled=True,
    )
    fallback = TemplateProvider(model="safe-template")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)
    response = chain.generate("hi")
    assert response.fallback_used is True
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Default-config zero-network proof
# ---------------------------------------------------------------------------


def test_default_config_gemini_provider_does_not_call_transport() -> None:
    import os

    os.environ["BLUEFIRE_GEMINI_TEST_KEY"] = "sk-test"
    try:
        ai_config = {
            "enabled": False,
            "provider": "gemini",
            "model": "gemini-1.5-flash",
            "api_base": "https://generativelanguage.googleapis.com",
            "api_key_env": "BLUEFIRE_GEMINI_TEST_KEY",
        }
        provider = ProviderFactory.from_ai_config(ai_config)
        assert isinstance(provider, GeminiGenerateContentBackend)
        transport = _MockTransport()
        provider.transport = transport
        response = provider.generate("hi")
        assert response.network_disabled is True
        assert "AI module is disabled" in (response.error or "")
        assert transport.calls == []
    finally:
        os.environ.pop("BLUEFIRE_GEMINI_TEST_KEY", None)
