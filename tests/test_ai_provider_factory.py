"""Provider selection contract for the AI layer.

Defends two important invariants of the local-first baseline:

1. Unknown / empty / `none` provider names always fall back to the
   keyless deterministic TemplateProvider — never to a remote stub.
2. Recognized remote provider names instantiate
   ``OpenAICompatibleProvider`` but the default `complete()` path makes
   no outbound calls and works without an API key.
"""

from __future__ import annotations

import pytest

from src.core.ai.providers import (
    OpenAICompatibleProvider,
    ProviderFactory,
    TemplateProvider,
)


@pytest.mark.parametrize("name", ["", "none", "template"])
def test_template_fallback_for_offline_names(name: str) -> None:
    provider = ProviderFactory.build(name, "test-model", {})
    assert isinstance(provider, TemplateProvider)


def test_unknown_provider_name_falls_back_to_template() -> None:
    """Unknown names must NOT silently become a remote stub."""
    provider = ProviderFactory.build("definitely-not-a-provider", "x", {})
    assert isinstance(provider, TemplateProvider)


@pytest.mark.parametrize(
    "name",
    [
        "openai",
        "anthropic",
        "google",
        "ollama",
        "llama.cpp",
        "lm-studio",
        "openai_compatible",
    ],
)
def test_recognized_remote_name_returns_keyless_stub(name: str) -> None:
    provider = ProviderFactory.build(name, "default", {"api_key": ""})
    assert isinstance(provider, OpenAICompatibleProvider)
    response = provider.complete("hello world")
    # The default OpenAICompatible.complete must NOT make outbound calls
    # and must not require an API key — assert the response is the
    # documented stub format.
    assert "Network completion is intentionally disabled by default" in response


def test_template_provider_completion_is_deterministic() -> None:
    """Template provider must produce identical output for identical input."""
    provider = TemplateProvider(model="t1")
    a = provider.complete("repeat-me")
    b = provider.complete("repeat-me")
    assert a == b


def test_template_provider_redacts_explicit_redacted_marker() -> None:
    provider = TemplateProvider()
    response = provider.complete("contains [REDACTED] secret")
    assert "[REDACTED]" not in response
    assert "***" in response
