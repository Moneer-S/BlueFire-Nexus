"""Phase 3 fallback-chain wrapper tests.

Pinned invariants:

1. **Success pass-through**: when the primary returns ``error=None``,
   the wrapper returns the primary response untouched. No fallback
   call. ``fallback_used`` stays ``False``.
2. **Failure with no fallback**: when the primary returns
   ``error=...`` and no fallback was configured, the wrapper
   returns the primary error response unchanged. The wrapper does
   NOT invent or hide errors.
3. **Failure with fallback**: when the primary returns ``error=...``
   and a fallback is configured, the wrapper invokes the fallback,
   marks the response with ``fallback_used=True``, and records
   ``primary_provider`` + ``primary_error`` in metadata so report
   renderers can attribute the degraded path.
4. **No fallback when primary succeeds**: even if a fallback is
   configured, a primary success must not invoke the fallback.
5. **Fallback receives identical inputs**: the prompt / context /
   options passed to the wrapper reach the fallback unchanged.
6. **complete() routes through generate()**: the legacy text-only
   entry point uses the wrapped logic without bypassing fallback.
7. **The wrapper itself never raises** — every failure surface
   comes through ``ProviderResponse.error``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List

import pytest

from src.core.ai.fallback import FallbackChainProvider
from src.core.ai.types import ProviderOptions, ProviderResponse


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class _RecordingProvider:
    """Minimal LLMProvider stand-in that records every call."""

    name: str = "test-primary"
    model: str = "test-model"
    response: ProviderResponse | None = None
    raise_on_call: Exception | None = None
    calls: List[Any] = field(default_factory=list)

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        self.calls.append(
            {"prompt": prompt, "context": list(context or []), "options": options}
        )
        if self.raise_on_call is not None:
            raise self.raise_on_call
        if self.response is None:
            return ProviderResponse(
                text=f"{self.name}-default-response",
                provider=self.name,
                model=self.model,
            )
        return self.response


def _ok(text: str = "ok", *, provider: str = "primary", model: str = "m1") -> ProviderResponse:
    return ProviderResponse(text=text, provider=provider, model=model, network_disabled=False)


def _failed(
    *,
    provider: str = "primary",
    model: str = "m1",
    error: str = "transport error",
) -> ProviderResponse:
    return ProviderResponse(
        text="",
        provider=provider,
        model=model,
        network_disabled=False,
        error=error,
    )


# ---------------------------------------------------------------------------
# Pass-through on primary success
# ---------------------------------------------------------------------------


def test_primary_success_returns_primary_response_unchanged() -> None:
    primary = _RecordingProvider(name="p1", response=_ok("primary works", provider="p1"))
    fallback = _RecordingProvider(name="f1")
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    result = chain.generate("hello")

    assert result.text == "primary works"
    assert result.provider == "p1"
    assert result.fallback_used is False
    assert result.error is None
    # Fallback must NOT have been called.
    assert fallback.calls == []


def test_primary_success_with_no_fallback_configured() -> None:
    primary = _RecordingProvider(name="p1", response=_ok("hi", provider="p1"))
    chain = FallbackChainProvider(primary=primary, fallback=None)
    result = chain.generate("ping")
    assert result.text == "hi"
    assert result.fallback_used is False


# ---------------------------------------------------------------------------
# Failure with no fallback
# ---------------------------------------------------------------------------


def test_primary_failure_with_no_fallback_returns_error_unchanged() -> None:
    primary = _RecordingProvider(
        name="p1", response=_failed(provider="p1", error="HTTP 500"),
    )
    chain = FallbackChainProvider(primary=primary, fallback=None)

    result = chain.generate("ping")

    assert result.error == "HTTP 500"
    assert result.fallback_used is False
    assert result.provider == "p1"


# ---------------------------------------------------------------------------
# Failure with fallback fires the fallback
# ---------------------------------------------------------------------------


def test_primary_failure_with_fallback_invokes_fallback() -> None:
    primary = _RecordingProvider(
        name="p1", response=_failed(provider="p1", error="HTTP 429"),
    )
    fallback = _RecordingProvider(
        name="template", response=_ok("safe template", provider="template"),
    )
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    result = chain.generate("the prompt")

    # Fallback fired.
    assert len(fallback.calls) == 1
    # Result reflects the fallback's response.
    assert result.text == "safe template"
    assert result.provider == "template"
    # Fallback marker.
    assert result.fallback_used is True
    # Attribution of original failure preserved in metadata.
    assert result.metadata.get("primary_provider") == "p1"
    assert result.metadata.get("primary_error") == "HTTP 429"


def test_fallback_receives_same_prompt_context_and_options() -> None:
    primary = _RecordingProvider(
        name="p1", response=_failed(provider="p1", error="boom"),
    )
    fallback = _RecordingProvider(
        name="f1", response=_ok("fallback-content", provider="f1"),
    )
    chain = FallbackChainProvider(primary=primary, fallback=fallback)

    options = ProviderOptions(system="system prompt", temperature=0.5, max_tokens=128)
    chain.generate("user prompt", context=["doc-a"], options=options)

    fb_call = fallback.calls[0]
    assert fb_call["prompt"] == "user prompt"
    assert fb_call["context"] == ["doc-a"]
    assert fb_call["options"] is options


def test_fallback_used_is_false_when_primary_succeeds_even_if_fallback_set() -> None:
    primary = _RecordingProvider(name="p1", response=_ok("happy"))
    fallback = _RecordingProvider(name="f1", response=_ok("never called"))
    chain = FallbackChainProvider(primary=primary, fallback=fallback)
    result = chain.generate("hi")
    assert result.text == "happy"
    assert result.fallback_used is False
    assert fallback.calls == []


def test_complete_routes_through_fallback_logic() -> None:
    """``complete()`` (legacy text-only entry point) must use the
    wrapped logic, not bypass fallback by reaching the primary
    directly."""
    primary = _RecordingProvider(
        name="p1", response=_failed(provider="p1", error="primary down"),
    )
    fallback = _RecordingProvider(
        name="template", response=_ok("safe", provider="template"),
    )
    chain = FallbackChainProvider(primary=primary, fallback=fallback)
    text = chain.complete("hi")
    assert text == "safe"
    # Fallback was invoked through the complete path too.
    assert len(fallback.calls) == 1


def test_chain_preserves_provider_name_and_model_attributes() -> None:
    """The wrapper exposes the primary's ``name`` and ``model`` so
    callers that inspect those attributes (e.g. for telemetry) see
    the configured primary, not 'unknown'."""
    primary = _RecordingProvider(name="p1", model="model-v")
    chain = FallbackChainProvider(primary=primary, fallback=None)
    assert chain.name == "p1"
    assert chain.model == "model-v"


def test_fallback_failure_still_returns_response_marked_as_fallback_used() -> None:
    """Edge case: fallback also fails. Caller still gets a structured
    response with ``fallback_used=True`` and the fallback's error
    surfaced; primary's error retained in metadata."""
    primary = _RecordingProvider(
        name="p1", response=_failed(provider="p1", error="primary boom"),
    )
    fallback = _RecordingProvider(
        name="template",
        response=_failed(provider="template", error="fallback boom"),
    )
    chain = FallbackChainProvider(primary=primary, fallback=fallback)
    result = chain.generate("hi")
    assert result.fallback_used is True
    assert result.error == "fallback boom"
    assert result.metadata.get("primary_error") == "primary boom"
    assert result.metadata.get("primary_provider") == "p1"
