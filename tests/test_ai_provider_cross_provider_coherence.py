"""Cross-provider coherence tests for the AI layer.

Earlier files prove each backend's own contract end-to-end
(``test_ai_provider_http_backend.py``,
``test_ai_provider_anthropic_backend.py``,
``test_ai_provider_gemini_backend.py``). This file asserts the
*cross-provider* invariants that nobody else asserts directly:

1. Local-first short-circuit fires for every canonical-name backend
   (template / OpenAI-compatible / Anthropic / Gemini) under the
   same documented preconditions: ``enabled=False``, empty
   ``api_base``, and (for the vendor-specific adapters) empty
   ``api_key``. No transport call regardless of the family.
2. Default config — built straight from ``ConfigManager`` — yields
   the ``TemplateProvider`` for every documented canonical name +
   alias. No vendor is privileged as the default.
3. Alias normalisation round-trips end-to-end: each alias yields
   the same backend class as its canonical name (and shares its
   resolved attributes).
4. ``ProviderOptions`` propagation parity across HTTP-backed
   adapters: ``system`` / ``temperature`` / ``max_tokens`` /
   ``timeout`` reach the wire in each backend's vendor-specific
   request shape, including the explicit-zero edge case (``0`` is
   not "use default" — it is an explicit operator choice).
5. Usage-key normalisation parity: every backend that reports usage
   surfaces the shared ``prompt_tokens`` / ``completion_tokens`` /
   ``total_tokens`` keys, regardless of the upstream vendor's
   keys.
6. Error-path uniformity across provider families: transport
   errors, non-200 responses, and parse errors all surface in
   ``ProviderResponse(error=..., text="")`` with
   ``network_disabled=False`` (the call DID hit the wire but the
   response was rejected) — never as a raised exception.
7. Fallback chain works identically across provider families:
   pairing each HTTP-backed primary with the offline template
   provider produces a clean degraded run with the documented
   ``fallback_used=True`` + ``primary_provider`` /
   ``primary_error`` markers.
8. Provider metadata is written consistently: every error response
   includes ``endpoint`` (or its empty-string equivalent) so report
   renderers can attribute attempts even on failure paths.

Every test uses an injectable mock transport — no real network
call ever. CI guarantees the same baseline: tests must not require
API keys, must not reach the network, and must not depend on any
external service.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

import pytest

from src.core.ai.backends.anthropic import AnthropicMessagesBackend
from src.core.ai.backends.gemini import GeminiGenerateContentBackend
from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend
from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.providers import ProviderFactory, TemplateProvider
from src.core.ai.transport import HTTPResponse
from src.core.ai.types import ProviderOptions, ProviderResponse
from src.core.config import ConfigManager
from src.core.configuration import get_ai_config


# ---------------------------------------------------------------------------
# Shared mock transport — captures every call so tests can assert request shape
# ---------------------------------------------------------------------------


@dataclass
class _CapturedCall:
    url: str
    headers: Dict[str, str]
    body: Dict[str, Any]
    timeout: int


@dataclass
class _MockTransport:
    """Shared mock transport used across every HTTP-backed family.

    Tests inject this into each backend so the same assertions can
    run against the OpenAI-compatible / Anthropic / Gemini adapters
    without duplicating call-capture machinery in three places.
    """

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


def _ok_openai(text: str = "ok", *, usage: Mapping[str, int] | None = None) -> HTTPResponse:
    """OpenAI chat-completions happy-path body."""
    payload: Dict[str, Any] = {
        "choices": [
            {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"},
        ],
        "usage": dict(
            usage or {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}
        ),
    }
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


def _ok_anthropic(text: str = "ok", *, usage: Mapping[str, int] | None = None) -> HTTPResponse:
    """Anthropic Messages-API happy-path body."""
    payload: Dict[str, Any] = {
        "id": "msg-test-1",
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": text}],
        "usage": dict(
            usage
            or {"input_tokens": 5, "output_tokens": 7}  # vendor keys
        ),
    }
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


def _ok_gemini(text: str = "ok", *, usage: Mapping[str, int] | None = None) -> HTTPResponse:
    """Gemini GenerateContent happy-path body."""
    payload: Dict[str, Any] = {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": text}]},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": dict(
            usage
            or {
                "promptTokenCount": 5,  # vendor keys
                "candidatesTokenCount": 7,
                "totalTokenCount": 12,
            }
        ),
    }
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


# ---------------------------------------------------------------------------
# 1. Local-first short-circuit applies uniformly across every backend
# ---------------------------------------------------------------------------


def _backend_factories():
    """Yield (label, build_backend) pairs for every HTTP-backed family.

    Each ``build_backend(transport, *, enabled, endpoint, api_key)``
    returns a backend instance configured with the given gates so
    one parametrised test can assert the same invariants against
    every family.
    """

    def _openai(transport, *, enabled: bool, endpoint: str, api_key: str):
        return OpenAICompatibleHTTPBackend(
            name="openai_compatible",
            model="m",
            endpoint=endpoint,
            api_key=api_key,
            transport=transport,
            enabled=enabled,
        )

    def _anthropic(transport, *, enabled: bool, endpoint: str, api_key: str):
        return AnthropicMessagesBackend(
            name="anthropic",
            model="m",
            endpoint=endpoint,
            api_key=api_key,
            transport=transport,
            enabled=enabled,
        )

    def _gemini(transport, *, enabled: bool, endpoint: str, api_key: str):
        return GeminiGenerateContentBackend(
            name="gemini",
            model="m",
            endpoint=endpoint,
            api_key=api_key,
            transport=transport,
            enabled=enabled,
        )

    yield ("openai_compatible", _openai)
    yield ("anthropic", _anthropic)
    yield ("gemini", _gemini)


@pytest.mark.parametrize("label,build", list(_backend_factories()))
def test_disabled_backend_never_calls_transport(label: str, build) -> None:
    """``enabled=False`` short-circuits to offline regardless of family.

    The call MUST NOT reach the transport — even with a fully
    configured endpoint and resolved key. This is the single most
    important local-first invariant: a misconfigured config that
    set ``provider`` + ``api_base`` + ``api_key_env`` but left
    ``enabled: false`` cannot leak prompts to the network.
    """
    transport = _MockTransport()
    backend = build(
        transport,
        enabled=False,
        endpoint="http://lab.example/v1",
        api_key="sk-test",
    )
    response = backend.generate("hello")
    assert isinstance(response, ProviderResponse)
    assert response.network_disabled is True
    assert response.error and "disabled" in response.error
    assert response.text == ""
    assert transport.calls == []  # transport never touched


@pytest.mark.parametrize("label,build", list(_backend_factories()))
def test_empty_api_base_never_calls_transport(label: str, build) -> None:
    """``api_base=""`` short-circuits to offline regardless of family.

    Even when the operator opted in via ``enabled=True``, an empty
    endpoint means the backend has nothing to dispatch against.
    """
    transport = _MockTransport()
    backend = build(
        transport,
        enabled=True,
        endpoint="",
        api_key="sk-test",
    )
    response = backend.generate("hello")
    assert response.network_disabled is True
    assert response.error and "api_base not configured" in response.error
    assert transport.calls == []


@pytest.mark.parametrize(
    "label,build",
    [
        # The OpenAI-compatible backend permits empty keys (Ollama,
        # llama.cpp, LM Studio run without auth) so it is intentionally
        # absent here — its empty-key behaviour is verified separately
        # in test_ai_provider_http_backend.py.
        ("anthropic", list(_backend_factories())[1][1]),
        ("gemini", list(_backend_factories())[2][1]),
    ],
)
def test_vendor_specific_backend_with_empty_key_short_circuits(label: str, build) -> None:
    """Anthropic and Gemini require an API key; missing key stays offline.

    Both vendors have no local-server analog, so dispatching with no
    key would just produce a wasted 401/403 round-trip. The adapter
    surfaces a clear, operator-actionable error instead.
    """
    transport = _MockTransport()
    backend = build(
        transport,
        enabled=True,
        endpoint="http://lab.example/v1",
        api_key="",
    )
    response = backend.generate("hello")
    assert response.network_disabled is True
    assert response.error and "api_key is required" in response.error
    # The error message must point operators at the env-var contract.
    assert "api_key_env" in response.error
    assert transport.calls == []


def test_openai_compatible_with_empty_key_dispatches_for_local_servers() -> None:
    """OpenAI-compatible backend dispatches even with empty ``api_key``.

    Confirms the documented difference between the OpenAI-compatible
    family (permits no auth — local servers like Ollama / llama.cpp
    run without an Authorization header) and the vendor-specific
    families (require a key). Pairs with the cross-family test
    above so the contrast is captured in the cross-provider suite.
    """
    transport = _MockTransport(responses=[_ok_openai("hi")])
    backend = OpenAICompatibleHTTPBackend(
        name="ollama",
        model="m",
        endpoint="http://localhost:11434/v1",
        api_key="",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hello")
    assert response.text == "hi"
    assert response.network_disabled is False
    assert len(transport.calls) == 1
    # No Authorization header — local server contract.
    assert "Authorization" not in transport.calls[0].headers


# ---------------------------------------------------------------------------
# 2. Default config and unknown names always yield TemplateProvider
# ---------------------------------------------------------------------------


def test_default_config_yields_template_provider_no_vendor_privilege() -> None:
    """Vanilla ``ConfigManager().to_dict()`` resolves to the offline template.

    Pinned guarantee that no vendor is privileged as the default —
    even when running the full configuration loader chain.
    """
    config = ConfigManager().to_dict()
    ai_cfg = get_ai_config(config)
    provider = ProviderFactory.from_ai_config(ai_cfg)
    assert isinstance(provider, TemplateProvider)
    assert ai_cfg["provider"] == "template"
    assert ai_cfg["enabled"] is False


@pytest.mark.parametrize(
    "garbage_name",
    [
        "definitely-not-a-provider",
        "openai-2",  # plausible-looking typo
        "gpt",       # very plausible typo
        "claude.ai", # alias-shaped typo
    ],
)
def test_unknown_provider_name_falls_back_to_template_via_from_ai_config(
    garbage_name: str,
) -> None:
    """Garbage / typo provider names route to the template, not to a vendor.

    Defends against silent privilege escalation: a typo in
    ``modules.ai.provider`` must never end up dispatching against
    the wrong vendor. The keyless template is the only safe
    fallback because it never makes a network call.
    """
    provider = ProviderFactory.from_ai_config(
        {"provider": garbage_name, "model": "m", "api_base": "http://lab.example"}
    )
    assert isinstance(provider, TemplateProvider)


# ---------------------------------------------------------------------------
# 3. Alias normalisation round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alias,canonical,expected_class",
    [
        ("claude", "anthropic", AnthropicMessagesBackend),
        ("google", "gemini", GeminiGenerateContentBackend),
        ("google_gemini", "gemini", GeminiGenerateContentBackend),
        ("xai", "grok", OpenAICompatibleHTTPBackend),
        ("x.ai", "grok", OpenAICompatibleHTTPBackend),
    ],
)
def test_alias_round_trips_to_canonical_backend(
    alias: str, canonical: str, expected_class: type
) -> None:
    """Operator-friendly aliases route to their canonical's backend.

    Both halves of the pair must produce the same backend class
    AND end up with the same canonical ``name`` attribute on the
    instance. Anything else means the alias map / factory dispatch
    is silently divergent between docs and runtime.
    """
    via_alias = ProviderFactory.from_ai_config(
        {"provider": alias, "model": "m", "api_base": "http://lab.example"}
    )
    via_canonical = ProviderFactory.from_ai_config(
        {"provider": canonical, "model": "m", "api_base": "http://lab.example"}
    )
    assert isinstance(via_alias, expected_class)
    assert isinstance(via_canonical, expected_class)
    assert via_alias.name == via_canonical.name == canonical


def test_alias_carries_provider_settings_into_canonical_backend() -> None:
    """``provider_settings`` flow-through survives alias normalisation.

    The alias path resolves through the same
    ``get_ai_config`` -> ``from_ai_config`` chain as the canonical
    path; the provider-settings block under ``ai_providers.<canonical>``
    must be picked up regardless of which name the operator put in
    ``modules.ai.provider``.
    """
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "claude",  # alias
                "model": "claude-3-5-sonnet-20241022",
                "api_base": "https://api.anthropic.com",
                "api_key_env": "BLUEFIRE_TEST_ANTHROPIC_KEY",
            }
        },
        "ai_providers": {
            # Settings filed under the canonical name.
            "anthropic": {
                "anthropic_version": "2024-09-01",
                "headers": {"X-Title": "lab"},
            },
        },
    }
    resolved = get_ai_config(config)
    provider = ProviderFactory.from_ai_config(resolved)
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.provider_settings.get("anthropic_version") == "2024-09-01"


# ---------------------------------------------------------------------------
# 4. ProviderOptions propagation parity
# ---------------------------------------------------------------------------


def test_options_temperature_zero_reaches_every_backend_request() -> None:
    """Explicit ``temperature=0.0`` is not silently dropped.

    ``ProviderOptions`` documents ``None`` as the "use default"
    sentinel; ``0.0`` is an explicit operator choice. Each adapter
    must place it in its vendor-specific request shape:

    - OpenAI-compatible: top-level ``temperature``
    - Anthropic: top-level ``temperature``
    - Gemini: ``generationConfig.temperature``
    """
    # OpenAI-compatible
    transport_openai = _MockTransport(responses=[_ok_openai("ok")])
    OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1",
        transport=transport_openai, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(temperature=0.0))
    assert transport_openai.calls[0].body.get("temperature") == 0.0

    # Anthropic
    transport_anthropic = _MockTransport(responses=[_ok_anthropic("ok")])
    AnthropicMessagesBackend(
        name="anthropic", model="m", endpoint="http://lab.example",
        transport=transport_anthropic, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(temperature=0.0))
    assert transport_anthropic.calls[0].body.get("temperature") == 0.0

    # Gemini
    transport_gemini = _MockTransport(responses=[_ok_gemini("ok")])
    GeminiGenerateContentBackend(
        name="gemini", model="m", endpoint="http://lab.example",
        transport=transport_gemini, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(temperature=0.0))
    gen_config = transport_gemini.calls[0].body.get("generationConfig", {})
    assert gen_config.get("temperature") == 0.0


def test_options_max_tokens_zero_reaches_every_backend_request() -> None:
    """Explicit ``max_tokens=0`` reaches each backend in its native shape.

    Edge case: ``0`` is a legitimate explicit value (some vendors
    use it as a "structured output only" or "no completion" hint),
    so the is-not-None discipline established in the per-backend
    test files must hold uniformly.
    """
    transport_openai = _MockTransport(responses=[_ok_openai("ok")])
    OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1",
        transport=transport_openai, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(max_tokens=0))
    assert transport_openai.calls[0].body.get("max_tokens") == 0

    transport_anthropic = _MockTransport(responses=[_ok_anthropic("ok")])
    AnthropicMessagesBackend(
        name="anthropic", model="m", endpoint="http://lab.example",
        transport=transport_anthropic, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(max_tokens=0))
    # Anthropic puts max_tokens at top-level.
    assert transport_anthropic.calls[0].body.get("max_tokens") == 0

    transport_gemini = _MockTransport(responses=[_ok_gemini("ok")])
    GeminiGenerateContentBackend(
        name="gemini", model="m", endpoint="http://lab.example",
        transport=transport_gemini, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(max_tokens=0))
    gen_config = transport_gemini.calls[0].body.get("generationConfig", {})
    assert gen_config.get("maxOutputTokens") == 0


def test_options_timeout_zero_reaches_every_backend_transport() -> None:
    """``timeout=0`` reaches the transport (does not silently fall back).

    Tests the per-backend ``_resolve_timeout`` discipline together
    so a regression in any one family is visible at the cross-
    provider level.
    """
    for backend, transport, response_factory in [
        (
            OpenAICompatibleHTTPBackend(
                name="openai", model="m", endpoint="http://lab.example/v1",
                api_key="sk",
                transport=_MockTransport(responses=[_ok_openai("ok")]),
                enabled=True, timeout=99,
            ),
            None,
            _ok_openai,
        ),
        (
            AnthropicMessagesBackend(
                name="anthropic", model="m", endpoint="http://lab.example",
                api_key="sk",
                transport=_MockTransport(responses=[_ok_anthropic("ok")]),
                enabled=True, timeout=99,
            ),
            None,
            _ok_anthropic,
        ),
        (
            GeminiGenerateContentBackend(
                name="gemini", model="m", endpoint="http://lab.example",
                api_key="sk",
                transport=_MockTransport(responses=[_ok_gemini("ok")]),
                enabled=True, timeout=99,
            ),
            None,
            _ok_gemini,
        ),
    ]:
        backend.generate("hi", options=ProviderOptions(timeout=0))
        # Transport timeout is the option value, not the instance default.
        assert backend.transport.calls[0].timeout == 0


def test_options_system_prompt_reaches_every_backend_in_native_shape() -> None:
    """``ProviderOptions.system`` reaches each backend's vendor shape.

    OpenAI-compatible: a leading ``role: system`` message in
    ``messages``. Anthropic: top-level ``system`` field. Gemini:
    top-level ``systemInstruction`` with a parts array.
    """
    system_text = "You are a defender; be concise."

    transport_openai = _MockTransport(responses=[_ok_openai("ok")])
    OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1",
        transport=transport_openai, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(system=system_text))
    messages = transport_openai.calls[0].body["messages"]
    assert messages[0] == {"role": "system", "content": system_text}

    transport_anthropic = _MockTransport(responses=[_ok_anthropic("ok")])
    AnthropicMessagesBackend(
        name="anthropic", model="m", endpoint="http://lab.example",
        transport=transport_anthropic, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(system=system_text))
    assert transport_anthropic.calls[0].body.get("system") == system_text

    transport_gemini = _MockTransport(responses=[_ok_gemini("ok")])
    GeminiGenerateContentBackend(
        name="gemini", model="m", endpoint="http://lab.example",
        transport=transport_gemini, enabled=True, api_key="sk",
    ).generate("hi", options=ProviderOptions(system=system_text))
    sys_inst = transport_gemini.calls[0].body.get("systemInstruction", {})
    parts = sys_inst.get("parts", [])
    assert any(p.get("text") == system_text for p in parts)


# ---------------------------------------------------------------------------
# 5. Usage-key normalisation parity
# ---------------------------------------------------------------------------


def test_usage_keys_are_uniform_across_every_backend_response() -> None:
    """Every backend that reports usage normalises into the shared keys.

    The Anthropic and Gemini upstream bodies use vendor-specific
    keys (``input_tokens`` / ``output_tokens`` for Anthropic;
    ``promptTokenCount`` / ``candidatesTokenCount`` /
    ``totalTokenCount`` for Gemini); after the adapter parse step,
    each ``ProviderResponse.usage`` mapping must carry the shared
    OpenAI-style keys so report renderers and operators see one
    consistent shape.
    """
    # OpenAI-compatible passes through usage as-is.
    backend_openai = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1",
        transport=_MockTransport(
            responses=[
                _ok_openai(
                    "ok",
                    usage={"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33},
                )
            ]
        ),
        enabled=True, api_key="sk",
    )
    response_openai = backend_openai.generate("hi")
    assert response_openai.usage == {
        "prompt_tokens": 11,
        "completion_tokens": 22,
        "total_tokens": 33,
    }

    # Anthropic vendor keys -> shared keys.
    backend_anthropic = AnthropicMessagesBackend(
        name="anthropic", model="m", endpoint="http://lab.example",
        transport=_MockTransport(
            responses=[
                _ok_anthropic("ok", usage={"input_tokens": 11, "output_tokens": 22})
            ]
        ),
        enabled=True, api_key="sk",
    )
    response_anthropic = backend_anthropic.generate("hi")
    assert response_anthropic.usage["prompt_tokens"] == 11
    assert response_anthropic.usage["completion_tokens"] == 22
    assert response_anthropic.usage["total_tokens"] == 33  # sum

    # Gemini vendor keys -> shared keys.
    backend_gemini = GeminiGenerateContentBackend(
        name="gemini", model="m", endpoint="http://lab.example",
        transport=_MockTransport(
            responses=[
                _ok_gemini(
                    "ok",
                    usage={
                        "promptTokenCount": 11,
                        "candidatesTokenCount": 22,
                        "totalTokenCount": 33,
                    },
                )
            ]
        ),
        enabled=True, api_key="sk",
    )
    response_gemini = backend_gemini.generate("hi")
    assert response_gemini.usage["prompt_tokens"] == 11
    assert response_gemini.usage["completion_tokens"] == 22
    assert response_gemini.usage["total_tokens"] == 33


# ---------------------------------------------------------------------------
# 6. Error-path uniformity
# ---------------------------------------------------------------------------


def _build_for_error_test(family: str, transport: _MockTransport):
    if family == "openai_compatible":
        return OpenAICompatibleHTTPBackend(
            name="openai", model="m", endpoint="http://lab.example/v1",
            transport=transport, enabled=True, api_key="sk",
        )
    if family == "anthropic":
        return AnthropicMessagesBackend(
            name="anthropic", model="m", endpoint="http://lab.example",
            transport=transport, enabled=True, api_key="sk",
        )
    if family == "gemini":
        return GeminiGenerateContentBackend(
            name="gemini", model="m", endpoint="http://lab.example",
            transport=transport, enabled=True, api_key="sk",
        )
    raise ValueError(family)


@pytest.mark.parametrize("family", ["openai_compatible", "anthropic", "gemini"])
def test_transport_exception_surfaces_uniformly(family: str) -> None:
    """Transport exceptions surface as ``error="transport error: ..."``.

    The wrapper-style error format (``"transport error: <exc>"``)
    is shared across every backend so operators can grep for one
    pattern and so the ``FallbackChainProvider`` triggers
    identically regardless of the family. Critically, the call
    DID hit the wire — ``network_disabled`` stays ``False``.
    """
    transport = _MockTransport(raise_on_call=ConnectionError("net is down"))
    backend = _build_for_error_test(family, transport)
    response = backend.generate("hi")
    assert isinstance(response, ProviderResponse)
    assert response.text == ""
    assert response.error and response.error.startswith("transport error:")
    assert response.network_disabled is False
    # endpoint always present so report renderers can attribute attempts.
    assert "endpoint" in response.metadata


@pytest.mark.parametrize("family", ["openai_compatible", "anthropic", "gemini"])
def test_non_200_status_surfaces_uniformly(family: str) -> None:
    """Non-200 responses surface as ``error="http <code>: <body>"``.

    Body is truncated to 200 chars so an absurd vendor-side error
    page does not blow out the response. Status code lands in the
    metadata mapping so call-site code can react to it without
    parsing the error string.
    """
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=429, body='{"error":"rate limit"}')]
    )
    backend = _build_for_error_test(family, transport)
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and response.error.startswith("http 429")
    assert response.network_disabled is False
    assert response.metadata.get("status_code") == 429


@pytest.mark.parametrize("family", ["openai_compatible", "anthropic", "gemini"])
def test_invalid_json_surfaces_uniformly(family: str) -> None:
    """Invalid JSON 200 body surfaces as a parse-error response.

    No raised exception ever reaches the caller — the call site
    receives a structured ``ProviderResponse(error=..., text="")``.
    """
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body="this-is-not-json")]
    )
    backend = _build_for_error_test(family, transport)
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error  # any reasonable parse error
    assert response.network_disabled is False


# ---------------------------------------------------------------------------
# 7. Fallback chain works identically across families
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family", ["openai_compatible", "anthropic", "gemini"])
def test_fallback_chain_degrades_gracefully_for_every_family(family: str) -> None:
    """Each HTTP-backed primary degrades to template on transport error.

    Same input chain (primary returns transport error -> fallback
    fires -> returned response carries fallback markers) regardless
    of which family the primary belongs to. This is the integration
    invariant operators rely on: ``fallback_provider: template``
    means the same thing under any primary.
    """
    transport = _MockTransport(raise_on_call=ConnectionError("net is down"))
    primary = _build_for_error_test(family, transport)
    fallback = TemplateProvider(model="fallback-template")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    response = chain.generate("hello")

    assert response.fallback_used is True
    # Template is the offline path.
    assert response.network_disabled is True
    # Body comes from the fallback.
    assert "TemplateProvider response" in response.text
    # Fallback marker carries the primary attribution.
    assert response.metadata.get("primary_provider") == primary.name
    assert response.metadata.get("primary_error", "").startswith("transport error:")


@pytest.mark.parametrize("family", ["openai_compatible", "anthropic", "gemini"])
def test_fallback_not_invoked_when_primary_succeeds(family: str) -> None:
    """Per-family success keeps the fallback dormant.

    Pairs with the failure test so each family is verified on both
    sides of the fallback contract.
    """
    if family == "openai_compatible":
        ok_response = _ok_openai("primary works")
    elif family == "anthropic":
        ok_response = _ok_anthropic("primary works")
    else:
        ok_response = _ok_gemini("primary works")
    transport = _MockTransport(responses=[ok_response])
    primary = _build_for_error_test(family, transport)

    # Use an in-test recording fallback so we can assert it was not called.
    fallback_calls: List[Any] = []

    @dataclass
    class _SpyFallback:
        name: str = "spy-fallback"
        model: str = "spy"

        def complete(self, prompt: str, context=None) -> str:
            return self.generate(prompt, context=context).text

        def generate(self, prompt, *, context=None, options=None):
            fallback_calls.append(prompt)
            return ProviderResponse(text="should-never-fire", provider="spy", model="m")

    chain = FallbackChainProvider(primary=primary, fallback=_SpyFallback())
    response = chain.generate("hello")

    assert response.fallback_used is False
    assert response.text == "primary works"
    assert fallback_calls == []
