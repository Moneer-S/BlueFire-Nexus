"""Phase 2 OpenAI-compatible HTTP backend tests.

Every test here uses an injectable :class:`_MockTransport` so no
real network call is ever issued. The CI guarantee is the same as
the local-first baseline: tests must not require API keys, must
not reach the network, and must not depend on any external
service.

Pinned invariants:

1. **Local-first short-circuit** — when ``api_base`` is empty, the
   backend returns ``ProviderResponse(network_disabled=True,
   error="api_base not configured...")`` and the transport is
   never called. The Phase 1 contract holds.
2. **Auto-registration** — importing ``src.core.ai`` registers the
   HTTP backend for the protocol-compatible canonical names
   (``openai_compatible``, ``openai``, ``grok``, ``ollama``,
   ``llama.cpp``, ``lm-studio``). Anthropic / gemini are NOT
   registered and resolve to the keyless stub.
3. **URL construction** — ``{api_base}/chat/completions`` unless
   the operator already included that suffix.
4. **Authorization header** — present iff ``api_key`` is non-empty;
   absent otherwise (so local Ollama / llama.cpp work without a
   key).
5. **Request body** — model / messages always; max_tokens and
   temperature only when configured (instance default OR per-call
   options); per-call options take precedence over instance
   defaults.
6. **Response parsing** — happy path produces text, usage, finish
   reason; non-200 / invalid-JSON / no-choices paths surface as
   ``error=...`` without raising.
7. **Transport errors** — network exceptions are caught and
   surfaced in ``error=...``; the call site never sees an
   uncaught exception.
8. **No-key path** — when no key is resolved, the backend either
   issues the call without an Authorization header (so local
   no-auth servers work) or short-circuits per the api_base rule
   above. Tests cover both.
9. **UrllibTransport** rejects non-HTTP(S) URL schemes before
   issuing any request (``file://`` / ``ftp://`` / unknown).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping

import pytest

from src.core.ai.backends.openai_compatible import (
    OpenAICompatibleHTTPBackend,
    register_default_backends,
)
from src.core.ai.providers import ProviderFactory
from src.core.ai.transport import HTTPResponse, UrllibTransport
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
    """Test transport that returns a canned response per call.

    ``responses`` is a list of either ``HTTPResponse`` instances or
    callables ``(call) -> HTTPResponse`` so each test can shape the
    response based on the request. ``raise_on_call`` can be set to
    an exception instance to simulate a transport failure.
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


def _ok_chat_response(
    text: str = "hello back",
    *,
    finish_reason: str = "stop",
    usage: Mapping[str, int] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> HTTPResponse:
    payload: Dict[str, Any] = {
        "choices": [
            {"message": {"role": "assistant", "content": text}, "finish_reason": finish_reason},
        ],
        "usage": dict(usage or {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}),
    }
    if extras:
        payload.update(dict(extras))
    return HTTPResponse(status_code=200, body=json.dumps(payload), headers={})


# ---------------------------------------------------------------------------
# Local-first short-circuit
# ---------------------------------------------------------------------------


def test_backend_offline_short_circuit_when_api_base_empty() -> None:
    """Tests the api_base gate. Operator opted in (`enabled=True`)
    but did not supply an endpoint — backend stays offline."""
    transport = _MockTransport()
    backend = OpenAICompatibleHTTPBackend(
        name="openai_compatible",
        model="m",
        endpoint="",  # nothing configured
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hello")
    assert isinstance(response, ProviderResponse)
    assert response.network_disabled is True
    assert response.error and "api_base not configured" in response.error
    assert response.text == ""
    # The transport must NOT have been called.
    assert transport.calls == []


def test_backend_offline_short_circuit_keeps_complete_callable() -> None:
    backend = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="", enabled=True,
    )
    # complete() routes through generate(); should NOT raise even
    # without a transport (no transport call happens anyway).
    text = backend.complete("hi")
    assert text == ""  # offline short-circuit returns empty text


# ---------------------------------------------------------------------------
# URL construction + auth header
# ---------------------------------------------------------------------------


def test_backend_appends_chat_completions_path_when_missing() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        api_key="sk-test",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert len(transport.calls) == 1
    assert transport.calls[0].url == "http://lab.example/v1/chat/completions"


def test_backend_honours_explicit_chat_completions_suffix() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1/chat/completions",
        api_key="sk-test",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    # Suffix not duplicated.
    assert transport.calls[0].url == "http://lab.example/v1/chat/completions"


def test_backend_strips_trailing_slash_on_api_base() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1/",  # trailing slash
        api_key="sk-test",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].url == "http://lab.example/v1/chat/completions"


def test_backend_includes_bearer_when_api_key_set() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        api_key="sk-secret",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0].headers.get("Authorization") == "Bearer sk-secret"


def test_backend_omits_authorization_when_api_key_empty() -> None:
    """Local servers (Ollama, llama.cpp) often need NO auth header."""
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="ollama",
        model="m",
        endpoint="http://localhost:11434/v1",
        api_key="",  # explicitly empty
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert "Authorization" not in transport.calls[0].headers


def test_backend_provider_settings_headers_extend_request_headers() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai_compatible",
        model="m",
        endpoint="http://lab.example/v1",
        api_key="k",
        provider_settings={"headers": {"X-Title": "lab", "X-Trace": "t-1"}},
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    headers = transport.calls[0].headers
    assert headers.get("X-Title") == "lab"
    assert headers.get("X-Trace") == "t-1"
    assert headers.get("Content-Type") == "application/json"


# ---------------------------------------------------------------------------
# Request body shape
# ---------------------------------------------------------------------------


def test_backend_request_body_contains_user_prompt() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="gpt-x",
        endpoint="http://lab.example/v1",
        transport=transport,
        enabled=True,
    )
    backend.generate("the prompt")
    body = transport.calls[0].body
    assert body["model"] == "gpt-x"
    assert {"role": "user", "content": "the prompt"} in body["messages"]


def test_backend_request_body_includes_system_when_options_set() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi", options=ProviderOptions(system="you are a defender"))
    messages = transport.calls[0].body["messages"]
    assert messages[0] == {"role": "system", "content": "you are a defender"}
    assert messages[-1] == {"role": "user", "content": "hi"}


def test_backend_request_body_includes_context_as_system_message() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        enabled=True,
    )
    backend.generate("question", context=["doc-a snippet", "doc-b snippet"])
    messages = transport.calls[0].body["messages"]
    # Context is concatenated into a single system message that
    # precedes the user prompt.
    assert any(
        m["role"] == "system" and "doc-a snippet" in m["content"] and "doc-b snippet" in m["content"]
        for m in messages
    )


def test_backend_request_body_omits_max_tokens_temperature_when_unset() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        max_tokens=None,
        temperature=None,
        enabled=True,
    )
    backend.generate("hi")
    body = transport.calls[0].body
    assert "max_tokens" not in body
    assert "temperature" not in body


def test_backend_options_override_instance_defaults() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        max_tokens=128,
        temperature=0.0,
        enabled=True,
    )
    backend.generate(
        "hi",
        options=ProviderOptions(max_tokens=512, temperature=0.7, timeout=99),
    )
    body = transport.calls[0].body
    assert body["max_tokens"] == 512
    assert body["temperature"] == 0.7
    # timeout from options also wins.
    assert transport.calls[0].timeout == 99


def test_backend_uses_instance_timeout_when_options_omit_it() -> None:
    transport = _MockTransport(responses=[_ok_chat_response()])
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
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
            _ok_chat_response(
                text="answer body",
                finish_reason="stop",
                usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            )
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == "answer body"
    assert response.finish_reason == "stop"
    assert response.usage == {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    assert response.network_disabled is False
    assert response.error is None
    assert response.metadata.get("url") == "http://lab.example/v1/chat/completions"


def test_backend_metadata_includes_response_id_when_present() -> None:
    transport = _MockTransport(
        responses=[
            _ok_chat_response(extras={"id": "resp-abc-123", "system_fingerprint": "fp-1"})
        ]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai",
        model="m",
        endpoint="http://lab.example/v1",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.metadata.get("response_id") == "resp-abc-123"
    assert response.metadata.get("system_fingerprint") == "fp-1"


# ---------------------------------------------------------------------------
# Response parsing — error paths (no exception, structured error)
# ---------------------------------------------------------------------------


def test_backend_non_200_status_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=429, body='{"error":"rate limit"}')]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1", transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "http 429" in response.error
    assert response.network_disabled is False
    assert response.metadata.get("status_code") == 429


def test_backend_invalid_json_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body="this-is-not-json")]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1", transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "not valid JSON" in response.error
    assert response.network_disabled is False


def test_backend_payload_without_choices_surfaces_as_error() -> None:
    transport = _MockTransport(
        responses=[HTTPResponse(status_code=200, body=json.dumps({"choices": []}))]
    )
    backend = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1", transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "no choices" in response.error
    assert response.network_disabled is False


def test_backend_transport_exception_surfaces_as_error() -> None:
    transport = _MockTransport(raise_on_call=ConnectionError("network is down"))
    backend = OpenAICompatibleHTTPBackend(
        name="openai", model="m", endpoint="http://lab.example/v1", transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.text == ""
    assert response.error and "transport error" in response.error
    assert response.network_disabled is False


# ---------------------------------------------------------------------------
# Auto-registration: from_ai_config returns the HTTP backend for
# protocol-compatible names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["openai_compatible", "openai", "grok", "ollama", "llama.cpp", "lm-studio"],
)
def test_auto_registration_routes_protocol_compatible_to_http_backend(name: str) -> None:
    """``register_default_backends()`` is called at import time of
    ``src.core.ai``; ``from_ai_config`` must therefore route every
    protocol-compatible canonical name through the HTTP backend."""
    register_default_backends()  # idempotent
    provider = ProviderFactory.from_ai_config(
        {"provider": name, "model": "m", "api_base": "http://lab.example/v1"}
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.name == name


def test_auto_registration_does_not_route_anthropic_to_http_backend() -> None:
    """Anthropic uses a different request shape (Messages API) and
    MUST NOT be silently bound to the OpenAI-compatible backend.
    It now routes to the dedicated AnthropicMessagesBackend."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    provider = ProviderFactory.from_ai_config(
        {"provider": "anthropic", "model": "m", "api_base": "http://lab.example/v1"}
    )
    assert not isinstance(provider, OpenAICompatibleHTTPBackend)
    assert isinstance(provider, AnthropicMessagesBackend)


def test_auto_registration_does_not_route_gemini_to_http_backend() -> None:
    """Gemini uses Google's GenerateContent shape; same reasoning."""
    from src.core.ai.providers import OpenAICompatibleProvider

    provider = ProviderFactory.from_ai_config(
        {"provider": "gemini", "model": "m", "api_base": "http://lab.example/v1"}
    )
    assert not isinstance(provider, OpenAICompatibleHTTPBackend)
    assert isinstance(provider, OpenAICompatibleProvider)


# ---------------------------------------------------------------------------
# UrllibTransport: scheme guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "ftp://lab.example/path",
        "gopher://lab.example",
        "javascript:alert(1)",
        "",
    ],
)
def test_urllib_transport_rejects_non_http_schemes(bad_url: str) -> None:
    transport = UrllibTransport()
    with pytest.raises(ValueError, match="non-HTTP"):
        transport.post_json(
            bad_url,
            headers={},
            body={"x": 1},
            timeout=1,
        )


def test_urllib_transport_accepts_http_and_https_schemes() -> None:
    """Sanity: scheme check is permissive for http(s). Does NOT
    actually issue the call (we never reach a real server in
    tests) — rejected by urllib because nothing answers."""
    transport = UrllibTransport()
    # Calling against a port unlikely to be open just confirms the
    # scheme check passed and execution proceeded into urllib.
    with pytest.raises(Exception) as excinfo:
        transport.post_json(
            "http://127.0.0.1:1/__bluefire_unit_test__",
            headers={},
            body={"x": 1},
            timeout=1,
        )
    # Any exception other than the scheme-check ValueError is fine —
    # we just need to confirm scheme didn't reject http://.
    assert "non-HTTP" not in str(excinfo.value)
