"""Phase 1 provider contract: rich generate() + ProviderResponse + registry.

Pinned invariants:

1. Every provider exposes a ``generate(prompt, *, context, options)``
   method that returns a :class:`ProviderResponse` carrying
   provider/model/finish_reason/network_disabled.
2. The legacy ``complete(prompt, context) -> str`` path remains and
   matches ``generate(prompt, context=context).text`` byte-for-byte
   so existing callers see no behaviour change.
3. ``ProviderResponse`` defaults are local-first: ``network_disabled``
   is True, ``fallback_used`` is False, ``error`` is None, ``usage``
   is empty.
4. ``ProviderOptions`` is frozen (defensive against accidental
   cross-call state leakage) and every field defaults to None /
   empty so callers only set what they want to override.
5. ``ProviderOptions.metadata`` flows through into
   ``ProviderResponse.metadata`` so callers can correlate request /
   response pairs via opaque keys.
6. ``ProviderFactory.register_provider`` overrides the default
   keyless-stub for a canonical name; the registered factory
   receives the documented kwargs from
   ``ProviderFactory.from_ai_config``.
7. ``register_provider`` rejects unknown canonical names with a
   clear ``ValueError``.
8. Every Phase 1 provider construction path is offline / no-network
   regardless of provider name — a real backend has to opt in via
   ``register_provider``.
"""

from __future__ import annotations

import pytest

from src.core.ai.providers import (
    OpenAICompatibleProvider,
    ProviderFactory,
    TemplateProvider,
)
from src.core.ai.types import ProviderOptions, ProviderResponse


# ---------------------------------------------------------------------------
# ProviderResponse + ProviderOptions shape
# ---------------------------------------------------------------------------


def test_provider_response_defaults_are_local_first() -> None:
    response = ProviderResponse(text="hi", provider="template", model="t")
    assert response.network_disabled is True
    assert response.fallback_used is False
    assert response.error is None
    assert response.usage == {}
    assert response.metadata == {}
    assert response.finish_reason is None


def test_provider_response_is_frozen() -> None:
    response = ProviderResponse(text="hi", provider="t", model="m")
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        response.text = "mutated"  # type: ignore[misc]


def test_provider_options_defaults_are_all_none() -> None:
    opts = ProviderOptions()
    assert opts.system is None
    assert opts.temperature is None
    assert opts.max_tokens is None
    assert opts.timeout is None
    assert opts.metadata == {}


def test_provider_options_is_frozen() -> None:
    opts = ProviderOptions(temperature=0.7)
    with pytest.raises(Exception):
        opts.temperature = 0.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Template provider: generate() shape + complete() back-compat
# ---------------------------------------------------------------------------


def test_template_provider_generate_returns_provider_response() -> None:
    provider = TemplateProvider(model="unit")
    response = provider.generate("hello world")
    assert isinstance(response, ProviderResponse)
    assert response.provider == "template"
    assert response.model == "unit"
    assert response.network_disabled is True
    assert response.fallback_used is False
    assert response.error is None
    assert response.finish_reason == "stop"
    assert "TemplateProvider response" in response.text


def test_template_provider_complete_matches_generate_text() -> None:
    """``complete()`` is the back-compat shim and must produce
    byte-identical text to ``generate(...).text``."""
    provider = TemplateProvider(model="back-compat")
    direct = provider.complete("repeat-me", context=["ctx-a", "ctx-b"])
    rich = provider.generate("repeat-me", context=["ctx-a", "ctx-b"]).text
    assert direct == rich


def test_template_provider_passes_options_metadata_through() -> None:
    provider = TemplateProvider()
    opts = ProviderOptions(metadata={"trace_id": "abc-123"})
    response = provider.generate("ping", options=opts)
    assert response.metadata.get("trace_id") == "abc-123"


def test_template_provider_ignores_options_temperature_and_max_tokens() -> None:
    """Temperature / max_tokens have no meaning for the offline provider;
    they must be accepted (no exception) and ignored."""
    provider = TemplateProvider()
    opts = ProviderOptions(temperature=0.0, max_tokens=64, timeout=5)
    response = provider.generate("ping", options=opts)
    assert isinstance(response, ProviderResponse)
    assert response.network_disabled is True


# ---------------------------------------------------------------------------
# OpenAICompatibleProvider (the keyless stub) generate() shape
# ---------------------------------------------------------------------------


def test_keyless_stub_generate_returns_provider_response() -> None:
    provider = OpenAICompatibleProvider(
        name="openai",
        model="gpt-x",
        endpoint="http://lab.example/v1",
    )
    response = provider.generate("hello")
    assert isinstance(response, ProviderResponse)
    assert response.provider == "openai"
    assert response.model == "gpt-x"
    assert response.network_disabled is True
    assert response.fallback_used is False
    assert response.error is None
    assert "Network completion is intentionally disabled by default" in response.text
    # endpoint surfaces in metadata so callers can attribute the stub.
    assert response.metadata.get("endpoint") == "http://lab.example/v1"


def test_keyless_stub_metadata_includes_provider_settings_keys() -> None:
    provider = OpenAICompatibleProvider(
        name="openai_compatible",
        model="m",
        provider_settings={"organization": "org-1", "region": "us-east"},
    )
    response = provider.generate("hi")
    assert response.metadata.get("provider_settings_keys") == ["organization", "region"]


def test_keyless_stub_complete_matches_generate_text() -> None:
    provider = OpenAICompatibleProvider(name="grok", model="g-1")
    assert provider.complete("hello") == provider.generate("hello").text


# ---------------------------------------------------------------------------
# ProviderFactory: register_provider (Phase 2 hook)
# ---------------------------------------------------------------------------


def _save_registry() -> dict:
    """Snapshot the registry so each test can restore it on teardown."""
    return dict(ProviderFactory._REGISTRY)


def _restore_registry(snapshot: dict) -> None:
    ProviderFactory._REGISTRY.clear()
    ProviderFactory._REGISTRY.update(snapshot)


def test_register_provider_overrides_default_keyless_stub() -> None:
    """A registered factory replaces the keyless stub for that
    canonical name. Phase 2 backends plug in via this hook."""
    snapshot = _save_registry()
    try:
        captured: dict = {}

        class _RegisteredBackend:
            name = "openai_compatible"
            model = "registered"

            def __init__(self, **kwargs):
                captured.update(kwargs)

            def complete(self, prompt: str, context=None) -> str:
                return self.generate(prompt, context=context).text

            def generate(self, prompt, *, context=None, options=None):
                return ProviderResponse(
                    text=f"registered:{prompt[:20]}",
                    provider="openai_compatible",
                    model="registered",
                    network_disabled=False,  # pretend we hit the network
                )

        def _factory(**kwargs):
            return _RegisteredBackend(**kwargs)

        ProviderFactory.register_provider("openai_compatible", _factory)

        provider = ProviderFactory.from_ai_config(
            {
                "provider": "openai_compatible",
                "model": "vendor-m",
                "api_base": "http://lab.example/v1",
                "api_key_env": "",
                "provider_settings": {"x": 1},
            }
        )
        # Registered factory was used.
        assert isinstance(provider, _RegisteredBackend)
        # Documented kwargs were passed through.
        assert captured["provider"] == "openai_compatible"
        assert captured["model"] == "vendor-m"
        assert captured["api_base"] == "http://lab.example/v1"
        assert captured["api_key"] == ""
        assert captured["provider_settings"] == {"x": 1}
        # The full resolved AI config is also passed for forward-compat.
        assert captured["ai_config"]["provider"] == "openai_compatible"
        # generate() returns the registered backend's response.
        response = provider.generate("ping")
        assert response.text.startswith("registered:")
        assert response.network_disabled is False
    finally:
        _restore_registry(snapshot)


def test_register_provider_rejects_unknown_canonical_name() -> None:
    """Typos / unknown names must fail loudly so Phase 2 wiring
    can't silently miss the registry."""
    with pytest.raises(ValueError, match="not a known canonical name"):
        ProviderFactory.register_provider("definitely-not-a-provider", lambda **k: None)


def test_register_provider_accepts_template_and_known_remotes() -> None:
    """Sanity: every known canonical name is acceptable."""
    snapshot = _save_registry()
    try:
        for canonical in ProviderFactory.known_canonical_names():
            ProviderFactory.register_provider(canonical, lambda **k: None)
    finally:
        _restore_registry(snapshot)


# ---------------------------------------------------------------------------
# Phase 1 baseline: every default construction path is offline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "openai",
        "anthropic",
        "gemini",
        "grok",
        "ollama",
        "openai_compatible",
        "llama.cpp",
        "lm-studio",
        "google",  # alias
        "xai",     # alias
        "claude",  # alias
    ],
)
def test_phase_1_default_is_offline_for_every_provider_name(name: str) -> None:
    """Without any registered backend, every recognised provider name
    yields an offline-by-default provider (template or keyless stub).
    """
    snapshot = _save_registry()
    try:
        provider = ProviderFactory.from_ai_config({"provider": name, "model": "m"})
        response = provider.generate("ping")
        assert response.network_disabled is True
    finally:
        _restore_registry(snapshot)


def test_known_canonical_names_includes_phase_1_remotes() -> None:
    canonical = set(ProviderFactory.known_canonical_names())
    assert {"openai", "anthropic", "gemini", "grok", "ollama", "openai_compatible"} <= canonical
    assert "template" in canonical
