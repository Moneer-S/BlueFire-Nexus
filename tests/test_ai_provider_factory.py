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


def test_no_canonical_remote_name_routes_to_keyless_stub_after_phase_2() -> None:
    """After the Anthropic and Gemini adapters land, every canonical
    remote name has a real backend. The ``OpenAICompatibleProvider``
    keyless stub is no longer reachable via ``from_ai_config`` for
    any documented canonical name — verifying this invariant
    catches a future regression where a new canonical name is added
    without a corresponding registered backend."""
    for canonical in ProviderFactory._CANONICAL_REMOTE_NAMES:
        provider = ProviderFactory.from_ai_config(
            {"provider": canonical, "model": "m", "api_base": "http://lab.example/v1"}
        )
        assert not isinstance(provider, OpenAICompatibleProvider), (
            f"canonical name {canonical!r} routed to the keyless stub — "
            "every documented canonical name must have a registered backend"
        )


@pytest.mark.parametrize(
    "name",
    [
        "openai",
        "grok",
        "ollama",
        "llama.cpp",
        "lm-studio",
        "openai_compatible",
    ],
)
def test_from_ai_config_protocol_compatible_returns_http_backend(name: str) -> None:
    """OpenAI-compatible-protocol canonical names route through the
    Phase 2 HTTP backend. The backend itself stays offline when
    ``api_base`` is set but the operator has not enabled network use
    via a real key + endpoint combination — the local-first
    invariant is verified by ``test_phase_1_default_is_offline_for_every_provider_name``
    in the contract file."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    provider = ProviderFactory.from_ai_config(
        {
            "provider": name,
            "model": "model-x",
            "api_base": "http://lab.example/v1",
        }
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.name == name
    assert provider.model == "model-x"
    assert provider.endpoint == "http://lab.example/v1"
    assert provider.api_key == ""


def test_from_ai_config_normalises_claude_alias_to_anthropic_adapter() -> None:
    """``claude`` alias routes to the Anthropic Messages-API adapter
    (not the keyless stub) since Phase 1 of provider-specific
    adapters."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    provider = ProviderFactory.from_ai_config(
        {"provider": "claude", "model": "model-x"}
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.name == "anthropic"


@pytest.mark.parametrize(
    "alias",
    [
        "google",
        "google_gemini",
    ],
)
def test_from_ai_config_normalises_google_aliases_to_gemini_adapter(
    alias: str,
) -> None:
    """``google`` / ``google_gemini`` aliases route to the Gemini
    GenerateContent adapter since Phase 2 of provider-specific
    adapters."""
    from src.core.ai.backends.gemini import GeminiGenerateContentBackend

    provider = ProviderFactory.from_ai_config(
        {"provider": alias, "model": "model-x"}
    )
    assert isinstance(provider, GeminiGenerateContentBackend)
    assert provider.name == "gemini"


@pytest.mark.parametrize(
    "alias,canonical",
    [
        ("xai", "grok"),
        ("x.ai", "grok"),
    ],
)
def test_from_ai_config_normalises_alias_to_canonical_http_backend(
    alias: str, canonical: str
) -> None:
    """Alias resolution for canonical names backed by the Phase 2
    HTTP backend (grok). The alias is normalised before dispatch
    so the registered backend fires."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    provider = ProviderFactory.from_ai_config(
        {"provider": alias, "model": "model-x"}
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.name == canonical


def test_from_ai_config_normalises_case_and_whitespace() -> None:
    """Provider name resolution lower-cases and strips whitespace.
    ``openai`` is HTTP-backed so the result is the HTTP backend."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    provider = ProviderFactory.from_ai_config(
        {"provider": "  OpenAI ", "model": "model-x"}
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.name == "openai"


def test_from_ai_config_resolves_api_key_env(monkeypatch) -> None:
    """When `api_key_env` is set, the named env var is read into `api_key`.

    The env-resolution behaviour is shared across every backend path,
    so this test uses ``anthropic`` (which has a registered adapter)
    and asserts on the resolved ``api_key`` field rather than a
    specific backend class."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.setenv("BLUEFIRE_TEST_AI_KEY", "sk-test-resolved")
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "anthropic",
            "model": "m",
            "api_key_env": "BLUEFIRE_TEST_AI_KEY",
        }
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.api_key == "sk-test-resolved"


def test_from_ai_config_missing_env_var_yields_empty_api_key(monkeypatch) -> None:
    """Pointing at a missing env var becomes an empty api_key, not an error."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.delenv("BLUEFIRE_DEFINITELY_UNSET_KEY", raising=False)
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "anthropic",
            "model": "m",
            "api_key_env": "BLUEFIRE_DEFINITELY_UNSET_KEY",
        }
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.api_key == ""


def test_from_ai_config_does_not_read_env_when_api_key_env_is_empty(monkeypatch) -> None:
    """Empty `api_key_env` MUST yield an empty api_key without env reads."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    monkeypatch.setenv("BLUEFIRE_AMBIENT_KEY_THAT_SHOULD_NOT_LEAK", "leaked")
    provider = ProviderFactory.from_ai_config(
        {"provider": "anthropic", "model": "m", "api_key_env": ""}
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.api_key == ""


def test_from_ai_config_resolves_api_key_env_for_http_backend(monkeypatch) -> None:
    """Same env-key resolution path works for HTTP-backed names too."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    monkeypatch.setenv("BLUEFIRE_HTTP_BACKEND_KEY", "sk-http-resolved")
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "openai_compatible",
            "model": "m",
            "api_key_env": "BLUEFIRE_HTTP_BACKEND_KEY",
            "api_base": "http://lab.example/v1",
        }
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.api_key == "sk-http-resolved"


def test_from_ai_config_forwards_provider_settings_to_anthropic_adapter() -> None:
    """`provider_settings` (from `ai_providers.<name>`) flows to the
    registered backend. After Phase 1/2 of the provider-specific
    adapters, ``anthropic`` is one of the two backends with vendor-
    specific settings (anthropic_version, headers); this test pins
    the flow-through against that backend."""
    from src.core.ai.backends.anthropic import AnthropicMessagesBackend

    settings = {"anthropic_version": "2024-09-01", "headers": {"X-Title": "lab"}}
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "anthropic",
            "model": "m",
            "provider_settings": settings,
        }
    )
    assert isinstance(provider, AnthropicMessagesBackend)
    assert provider.provider_settings["anthropic_version"] == "2024-09-01"
    # Defensive copy: mutating the returned dict must not affect the source.
    provider.provider_settings["anthropic_version"] = "mutated"
    assert settings["anthropic_version"] == "2024-09-01"


def test_from_ai_config_forwards_provider_settings_to_http_backend() -> None:
    """Same flow-through for HTTP-backed names: provider_settings
    populates the backend so vendor-specific keys (organization,
    headers) can be passed through to outbound requests."""
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

    settings = {"organization": "org-456", "headers": {"X-Title": "lab"}}
    provider = ProviderFactory.from_ai_config(
        {
            "provider": "openai_compatible",
            "model": "m",
            "provider_settings": settings,
        }
    )
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.provider_settings["organization"] == "org-456"
    # Defensive copy: mutating the returned dict must not affect the source.
    provider.provider_settings["organization"] = "mutated"
    assert settings["organization"] == "org-456"


def test_from_ai_config_full_resolved_config_round_trip(monkeypatch) -> None:
    """End-to-end: get_ai_config(...) -> from_ai_config(...) yields the
    HTTP backend (Phase 2) configured with env-resolved key + provider
    settings + endpoint. The backend short-circuits to offline when
    no api_base is given; here api_base IS set so this test verifies
    the full configuration plumbing.
    """
    from src.core.ai.backends.openai_compatible import OpenAICompatibleHTTPBackend

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
    assert isinstance(provider, OpenAICompatibleHTTPBackend)
    assert provider.name == "openai_compatible"
    assert provider.model == "vendor-model"
    assert provider.endpoint == "http://vendor.lab/v1"
    assert provider.api_key == "sk-vendor-9"
    assert provider.provider_settings.get("organization") == "org-abc"


def test_from_ai_config_template_provider_when_explicitly_offline() -> None:
    provider = ProviderFactory.from_ai_config(
        {"provider": "template", "model": "explicit-template"}
    )
    assert isinstance(provider, TemplateProvider)
    assert provider.model == "explicit-template"
