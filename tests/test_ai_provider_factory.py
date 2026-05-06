"""Provider selection contract for the AI layer.

Defends two important invariants of the local-first baseline:

1. Unknown / empty / `none` provider names always fall back to the
   keyless deterministic TemplateProvider — never to a remote stub.
2. Recognized remote provider names instantiate
   ``OpenAICompatibleProvider`` but the default `complete()` path makes
   no outbound calls and works without an API key.

Plus the `from_ai_config` contract:

3. ``ProviderFactory.from_ai_config`` consumes the resolved
   ``get_ai_config`` output (provider / model / api_base /
   api_key_env / provider_settings).
4. ``api_key_env`` resolves the named env var lazily — empty / unset
   means an empty ``api_key`` rather than an exception.
5. ``provider_settings`` (from ``ai_providers.<name>``) flows through
   to the keyless stub.
6. Garbage / non-mapping AI config falls back to TemplateProvider.
"""

from __future__ import annotations

import pytest

from src.core.ai.providers import (
    OpenAICompatibleProvider,
    ProviderFactory,
    TemplateProvider,
)
from src.core.configuration import get_ai_config


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


# ---------------------------------------------------------------------------
# ProviderFactory.from_ai_config — resolved-config contract
# ---------------------------------------------------------------------------


def test_from_ai_config_default_is_template_provider() -> None:
    """Default resolved AI config must yield the offline template provider."""
    provider = ProviderFactory.from_ai_config(get_ai_config(None))
    assert isinstance(provider, TemplateProvider)


def test_from_ai_config_garbage_input_falls_back_to_template() -> None:
    assert isinstance(ProviderFactory.from_ai_config(None), TemplateProvider)  # type: ignore[arg-type]
    assert isinstance(ProviderFactory.from_ai_config("not a mapping"), TemplateProvider)  # type: ignore[arg-type]


def test_from_ai_config_unknown_provider_falls_back_to_template() -> None:
    """Unknown provider names must NOT silently become a remote stub."""
    provider = ProviderFactory.from_ai_config(
        {"provider": "definitely-not-a-provider", "model": "x"}
    )
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
def test_from_ai_config_remote_provider_returns_keyless_stub(name: str) -> None:
    """Each known remote name returns the keyless stub with no outbound call."""
    provider = ProviderFactory.from_ai_config(
        {
            "provider": name,
            "model": "model-x",
            "api_base": "http://lab.example/v1",
        }
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == name
    assert provider.model == "model-x"
    assert provider.endpoint == "http://lab.example/v1"
    assert provider.api_key == ""  # no api_key_env set -> empty key, never raised
    response = provider.complete("hello")
    assert "Network completion is intentionally disabled by default" in response


def test_from_ai_config_resolves_api_key_env(monkeypatch) -> None:
    """When `api_key_env` is set, the named env var is read into `api_key`."""
    monkeypatch.setenv("BLUEFIRE_TEST_AI_KEY", "sk-test-resolved")
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "openai_compatible",
            "model": "m",
            "api_key_env": "BLUEFIRE_TEST_AI_KEY",
        }
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.api_key == "sk-test-resolved"


def test_from_ai_config_missing_env_var_yields_empty_api_key(monkeypatch) -> None:
    """Pointing at a missing env var becomes an empty api_key, not an error."""
    monkeypatch.delenv("BLUEFIRE_DEFINITELY_UNSET_KEY", raising=False)
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "openai_compatible",
            "model": "m",
            "api_key_env": "BLUEFIRE_DEFINITELY_UNSET_KEY",
        }
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.api_key == ""


def test_from_ai_config_does_not_read_env_when_api_key_env_is_empty(monkeypatch) -> None:
    """Empty `api_key_env` MUST yield an empty api_key without env reads.

    Asserted indirectly by setting a sentinel env var with a name that
    is *not* referenced — it must not leak into the provider — and by
    verifying the empty-string `api_key_env` short-circuit.
    """
    monkeypatch.setenv("BLUEFIRE_AMBIENT_KEY_THAT_SHOULD_NOT_LEAK", "leaked")
    provider = ProviderFactory.from_ai_config(
        {"provider": "openai_compatible", "model": "m", "api_key_env": ""}
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.api_key == ""


def test_from_ai_config_forwards_provider_settings() -> None:
    """`provider_settings` (from `ai_providers.<name>`) flows to the stub."""
    settings = {"organization": "org-123", "region": "us-east"}
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "openai_compatible",
            "model": "m",
            "provider_settings": settings,
        }
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.provider_settings == settings
    # Defensive copy: mutating the returned dict must not affect the source.
    provider.provider_settings["organization"] = "mutated"
    assert settings["organization"] == "org-123"


def test_from_ai_config_full_resolved_config_round_trip(monkeypatch) -> None:
    """End-to-end: get_ai_config(...) -> from_ai_config(...) yields the
    expected stub with env-resolved key + provider_settings flow-through.
    """
    monkeypatch.setenv("BLUEFIRE_VENDOR_KEY", "sk-vendor-9")
    config = {
        "modules": {
            "ai": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "vendor-model",
                "api_base": "http://vendor.lab/v1",
                "api_key_env": "BLUEFIRE_VENDOR_KEY",
            }
        },
        "ai_providers": {
            "openai_compatible": {
                "organization": "org-abc",
                "api_base": "http://vendor.lab/v1",
            }
        },
    }
    resolved = get_ai_config(config)
    provider = ProviderFactory.from_ai_config(resolved)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.name == "openai_compatible"
    assert provider.model == "vendor-model"
    assert provider.endpoint == "http://vendor.lab/v1"
    assert provider.api_key == "sk-vendor-9"
    assert provider.provider_settings.get("organization") == "org-abc"
    # Still no outbound network call by default.
    assert (
        "Network completion is intentionally disabled by default"
        in provider.complete("ping")
    )


def test_from_ai_config_template_provider_when_explicitly_offline() -> None:
    provider = ProviderFactory.from_ai_config(
        {"provider": "template", "model": "explicit-template"}
    )
    assert isinstance(provider, TemplateProvider)
    assert provider.model == "explicit-template"
