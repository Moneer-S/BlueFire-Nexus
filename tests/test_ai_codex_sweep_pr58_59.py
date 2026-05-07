"""Regression tests for Codex/Bugbot findings on PRs #58 + #59.

Each test references the originating PR comment. Pinned invariants:

1. **PR #58 P2 (Codex) — Anthropic /v1 suffix normalisation**:
   ``api_base: https://api.anthropic.com/v1`` (a natural copy-paste
   from OpenAI-style configs) must NOT produce
   ``.../v1/v1/messages``. The adapter normalises bare hosts,
   /v1-suffixed bases, and full ``/v1/messages`` URLs into the
   single canonical ``.../v1/messages`` shape.

2. **PR #58 Low (Cursor Bugbot) — test name accuracy**:
   ``test_anthropic_offline_short_circuit_does_not_trigger_fallback``
   was renamed to
   ``test_anthropic_offline_short_circuit_routes_through_fallback_chain``
   to match what the test actually verifies. No regression test
   needed beyond the rename — the test body is unchanged.

3. **PR #59 P2 (Codex) — Gemini stream-endpoint rejection**:
   The Gemini adapter only parses non-streaming responses, so an
   ``api_base`` ending in ``:streamGenerateContent`` MUST be
   rejected at the gate with a clear configuration error rather
   than dispatched to a path that returns parse/no-candidates
   errors against valid credentials. The transport must NEVER be
   invoked when the stream endpoint is configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

import pytest

from src.core.ai.backends.anthropic import AnthropicMessagesBackend
from src.core.ai.backends.gemini import GeminiGenerateContentBackend
from src.core.ai.transport import HTTPResponse


# ---------------------------------------------------------------------------
# Mock transport (shared)
# ---------------------------------------------------------------------------


@dataclass
class _MockTransport:
    responses: List[HTTPResponse] = field(default_factory=list)
    raise_on_call: Exception | None = None
    calls: list[dict] = field(default_factory=list)

    def post_json(self, url, *, headers, body, timeout):  # type: ignore[no-untyped-def]
        self.calls.append({"url": url, "headers": dict(headers), "body": dict(body), "timeout": timeout})
        if self.raise_on_call is not None:
            raise self.raise_on_call
        if not self.responses:
            return HTTPResponse(
                status_code=200,
                body='{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",'
                     '"usage":{"input_tokens":1,"output_tokens":1}}',
            )
        return self.responses.pop(0)


def _ok_anthropic_response() -> HTTPResponse:
    return HTTPResponse(
        status_code=200,
        body=(
            '{"id":"msg_x","content":[{"type":"text","text":"ok"}],'
            '"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}'
        ),
    )


# ---------------------------------------------------------------------------
# Finding #1 (PR #58 P2 Codex): Anthropic /v1 normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "api_base,expected_url",
    [
        # Bare host -> append /v1/messages.
        (
            "https://api.anthropic.com",
            "https://api.anthropic.com/v1/messages",
        ),
        # Bare host with trailing slash -> still append /v1/messages.
        (
            "https://api.anthropic.com/",
            "https://api.anthropic.com/v1/messages",
        ),
        # /v1-suffixed -> append only /messages (NOT /v1/messages).
        (
            "https://api.anthropic.com/v1",
            "https://api.anthropic.com/v1/messages",
        ),
        # /v1/ with trailing slash -> same.
        (
            "https://api.anthropic.com/v1/",
            "https://api.anthropic.com/v1/messages",
        ),
        # Already a full Messages URL -> use as-is.
        (
            "https://api.anthropic.com/v1/messages",
            "https://api.anthropic.com/v1/messages",
        ),
        # Trailing slash on a full Messages URL.
        (
            "https://api.anthropic.com/v1/messages/",
            "https://api.anthropic.com/v1/messages",
        ),
    ],
)
def test_codex_pr58_p2_anthropic_url_handles_v1_suffix(
    api_base: str, expected_url: str
) -> None:
    """Three input shapes (bare host / /v1 / full Messages URL) all
    canonicalise to the single correct URL. Closes the Codex P2
    where ``api_base: .../v1`` produced ``.../v1/v1/messages``."""
    transport = _MockTransport(responses=[_ok_anthropic_response()])
    backend = AnthropicMessagesBackend(
        endpoint=api_base,
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert transport.calls[0]["url"] == expected_url


def test_codex_pr58_p2_anthropic_v1_suffix_does_not_double_version() -> None:
    """Targeted regression: the original failure mode was
    ``https://api.anthropic.com/v1/v1/messages``. Verify that
    string never appears in the URL even when the operator
    explicitly ends api_base with ``/v1``."""
    transport = _MockTransport(responses=[_ok_anthropic_response()])
    backend = AnthropicMessagesBackend(
        endpoint="https://api.anthropic.com/v1",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    backend.generate("hi")
    assert "/v1/v1/" not in transport.calls[0]["url"]


# ---------------------------------------------------------------------------
# Finding #3 (PR #59 P2 Codex): Gemini reject :streamGenerateContent
# ---------------------------------------------------------------------------


def test_codex_pr59_p2_gemini_rejects_stream_endpoint_at_gate() -> None:
    """An ``api_base`` ending in ``:streamGenerateContent`` MUST
    short-circuit to offline with a clear config error. The
    transport is never invoked."""
    transport = _MockTransport()
    backend = GeminiGenerateContentBackend(
        endpoint=(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-1.5-flash:streamGenerateContent"
        ),
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.network_disabled is True
    assert response.error and ":streamGenerateContent" in response.error
    assert "non-streaming" in response.error
    # Operator-friendly hint.
    assert "non-streaming endpoint" in response.error
    # The transport MUST NOT have been called.
    assert transport.calls == []


def test_codex_pr59_p2_gemini_stream_rejection_is_orthogonal_to_other_gates() -> None:
    """Even when other gates (enabled / api_base / api_key) would
    let the call through, the streaming-endpoint rejection still
    fires. Sanity-check ordering: the stream rejection must appear
    AFTER enabled/api_base/api_key checks (which give clearer
    errors when those are the actual issue) but BEFORE any URL
    construction or transport dispatch."""
    transport = _MockTransport()
    # Disabled -> should produce the disabled error, not the stream
    # error, even though the URL would also be a stream URL.
    backend_disabled = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com/v1beta/models/m:streamGenerateContent",
        api_key="sk",
        transport=transport,
        enabled=False,
    )
    r1 = backend_disabled.generate("hi")
    assert "AI module is disabled" in (r1.error or "")
    # Empty key -> api_key error.
    backend_no_key = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com/v1beta/models/m:streamGenerateContent",
        api_key="",
        transport=transport,
        enabled=True,
    )
    r2 = backend_no_key.generate("hi")
    assert "gemini api_key is required" in (r2.error or "")
    assert transport.calls == []


def test_codex_pr59_p2_gemini_non_streaming_endpoint_still_dispatches() -> None:
    """Sanity: the explicit non-streaming endpoint (which the
    adapter parses) is NOT rejected by the new gate."""
    transport = _MockTransport(
        responses=[
            HTTPResponse(
                status_code=200,
                body=(
                    '{"candidates":[{"content":{"role":"model",'
                    '"parts":[{"text":"ok"}]},"finishReason":"STOP"}],'
                    '"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}'
                ),
            )
        ]
    )
    backend = GeminiGenerateContentBackend(
        endpoint="https://generativelanguage.googleapis.com/v1beta/models/m:generateContent",
        api_key="sk",
        transport=transport,
        enabled=True,
    )
    response = backend.generate("hi")
    assert response.error is None
    assert response.text == "ok"
    assert len(transport.calls) == 1
