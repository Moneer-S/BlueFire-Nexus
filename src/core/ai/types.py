"""Shared types for the provider-agnostic AI layer.

Two small frozen dataclasses define the on-the-wire shape between
callers and providers, independent of any specific backend
(template / OpenAI / Anthropic / Gemini / Grok / Ollama / generic
OpenAI-compatible). Phase 1 adds these alongside the existing
``LLMProvider.complete()`` text-only path so callers can opt into
the richer response without breaking back-compat.

No vendor-specific shapes. No SDK imports. No network code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderOptions:
    """Per-call options for ``LLMProvider.generate()``.

    Every field defaults to ``None`` (or empty mapping) meaning "use
    the resolved AI-config value or the provider's own default" so
    callers only need to set what they want to override on a single
    call. The runtime never injects a default temperature or
    max_tokens here — those come from ``get_ai_config(...)``.

    Frozen because options are passed across module boundaries; a
    mutable options object would make accidental cross-call state
    leakage easy.
    """

    system: str | None = None
    """Optional system / instruction prompt. Treated as a pre-prompt
    by providers that distinguish system from user turns; providers
    that do not (e.g. the offline ``TemplateProvider``) may ignore
    or concatenate it."""

    temperature: float | None = None
    """Sampling temperature. ``None`` means "use the provider's
    default" (which is itself driven by ``modules.ai.temperature``
    when set in config)."""

    max_tokens: int | None = None
    """Per-call cap on completion tokens. ``None`` means use the
    config-level ``modules.ai.max_tokens``."""

    timeout: int | None = None
    """Per-call request timeout in seconds. ``None`` means use the
    config-level ``modules.ai.timeout``."""

    metadata: Mapping[str, Any] = field(default_factory=dict)
    """Free-form per-call metadata passed through to the response's
    own ``metadata`` for caller-side correlation. Providers must
    not mutate it."""


@dataclass(frozen=True)
class ProviderResponse:
    """Structured result from ``LLMProvider.generate()``.

    Always carries enough metadata for callers (copilot artifact
    writers, report renderers, telemetry) to attribute the output
    to a specific provider/model and tell whether the call hit the
    network or the deterministic offline path. Fields default to
    safe values so a provider that has nothing useful to report can
    still construct a valid response without populating every key.
    """

    text: str
    """The completion text. Empty string when ``error`` is set."""

    provider: str
    """Canonical provider name (``"template"``, ``"openai"``,
    ``"anthropic"``, ``"gemini"``, ``"grok"``, ``"ollama"``,
    ``"openai_compatible"``, ...). Always set."""

    model: str
    """Specific model identifier the provider used. Always set."""

    usage: Mapping[str, int] = field(default_factory=dict)
    """Token-usage counters when the provider reports them. Common
    keys: ``prompt_tokens``, ``completion_tokens``, ``total_tokens``.
    Empty when usage is not reported (template / stub paths)."""

    finish_reason: str | None = None
    """Provider-reported termination reason (``"stop"``, ``"length"``,
    ``"error"``, ...). ``None`` when not applicable."""

    fallback_used: bool = False
    """``True`` when this response came from a configured
    ``modules.ai.fallback_provider`` because the primary provider
    failed. Surfaces in artifact metadata so reports can flag
    degraded runs."""

    network_disabled: bool = True
    """``True`` for the deterministic offline path (template /
    keyless stub). ``False`` for backends that actually issued an
    outbound request. Default is ``True`` because the local-first
    baseline never makes network calls."""

    error: str | None = None
    """Non-``None`` when the provider call failed. Usually paired
    with ``fallback_used=True`` if a fallback produced ``text``;
    otherwise the caller can decide whether to surface or retry."""

    metadata: Mapping[str, Any] = field(default_factory=dict)
    """Free-form provider-specific extras (request id, latency,
    safety filter outcome, etc.). Callers should treat unknown
    keys as informational only."""


__all__ = ["ProviderOptions", "ProviderResponse"]
