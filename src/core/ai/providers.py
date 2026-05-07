"""AI provider abstractions with deterministic offline fallback.

Phase 1 contract:

- :class:`LLMProvider` Protocol exposes both the legacy
  ``complete(prompt, context) -> str`` text-only path AND the new
  rich ``generate(prompt, *, context, options) -> ProviderResponse``
  path. ``complete()`` is the back-compat shim — every concrete
  provider implements ``generate()`` and the default ``complete()``
  returns ``self.generate(...).text``.
- :class:`ProviderFactory` is the single dispatch point. It honours
  alias normalisation (``google -> gemini``, ``xai -> grok``,
  ``claude -> anthropic``) so docs and config files can use the
  vendor-friendly name and still hit the canonical registry entry.
- :func:`ProviderFactory.register_provider` is the Phase 2 hook —
  real backends (HTTP transport, SDK wrappers) plug in by
  registering a factory function for a canonical name. Phase 1
  ships only the keyless stub for every known remote name; nothing
  in this module makes network calls.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Protocol

from .types import ProviderOptions, ProviderResponse


class LLMProvider(Protocol):
    """Common provider contract for copilot use."""

    name: str
    model: str

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        """Legacy text-only entry point.

        Concrete providers may implement this directly or as a thin
        wrapper around :meth:`generate` returning ``.text``.
        """
        ...

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        """Rich entry point with structured response and per-call options."""
        ...


@dataclass
class TemplateProvider:
    """Deterministic fallback provider for offline and CI."""

    model: str = "template-default"
    name: str = "template"

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        # The template provider intentionally ignores options:
        # temperature / max_tokens / timeout have no meaning for the
        # deterministic fallback, but the option is accepted so
        # callers can pass a single ``options=...`` to any provider.
        scrubbed = prompt.replace("[REDACTED]", "***").replace("\n", " ").strip()
        context_preview = " | ".join((context or [])[:2])[:220]
        text = (
            "TemplateProvider response\n"
            f"- model: {self.model}\n"
            f"- prompt_summary: {scrubbed[:220]}\n"
            f"- context_preview: {context_preview or 'none'}\n"
            "- recommendation: refine scenario steps, review detection coverage,"
            " validate telemetry\n"
        )
        metadata: Dict[str, Any] = {}
        if options is not None and options.metadata:
            metadata.update(options.metadata)
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=self.model,
            finish_reason="stop",
            network_disabled=True,
            metadata=metadata,
        )


@dataclass
class OpenAICompatibleProvider:
    """Vendor-neutral keyless stub for any recognised remote provider name.

    Despite the legacy class name, this is **not** an OpenAI-specific
    implementation — it is the placeholder used for every supported
    remote provider name (openai, anthropic, gemini, grok, ollama,
    llama.cpp, lm-studio, openai_compatible) until Phase 2 wires real
    backends in via :meth:`ProviderFactory.register_provider`. Its
    ``generate()`` (and therefore ``complete()``) method intentionally
    makes no outbound calls and works without an API key, so the
    local-first baseline stays offline even when an operator selects
    a remote provider.

    ``provider_settings`` carries the raw ``ai_providers.<name>`` sub-
    block (see ``core.configuration.get_ai_config``) so a future
    backend can opt into vendor-specific keys (organisation IDs,
    region pins, request-headers) without changing the factory
    contract.
    """

    name: str
    model: str
    endpoint: str = ""
    api_key: str = ""
    provider_settings: Dict[str, Any] = field(default_factory=dict)

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        # Security-first default: avoid outbound calls unless an
        # explicit code path is added later (see Phase 2 HTTP backend
        # registration via ProviderFactory.register_provider).
        _ = context
        text = (
            f"{self.name} provider configured with model={self.model}. "
            "Network completion is intentionally disabled by default.\n"
            f"prompt_summary: {prompt[:220]}"
        )
        metadata: Dict[str, Any] = {"endpoint": self.endpoint}
        if self.provider_settings:
            metadata["provider_settings_keys"] = sorted(self.provider_settings)
        if options is not None and options.metadata:
            metadata.update(dict(options.metadata))
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=self.model,
            finish_reason="stop",
            network_disabled=True,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Provider registry + factory
# ---------------------------------------------------------------------------


# Type of a registered provider factory. Receives the resolved
# AI-config dict (output of ``core.configuration.get_ai_config``)
# plus the already-normalised canonical provider name + model + the
# resolved API key (env-resolved by the factory) and returns an
# ``LLMProvider``-compatible instance.
ProviderFactoryFn = Callable[..., "LLMProvider"]


class ProviderFactory:
    """Build a provider from config while preserving user choice.

    Phase 2 backends register themselves via :meth:`register_provider`,
    which overrides the default keyless-stub behaviour for a
    canonical name. Phase 1 ships only the stub.
    """

    OFFLINE_NAMES = {"none", "template", ""}

    # Canonical remote-provider names. Aliases below resolve to one
    # of these. Adding a new canonical name means adding it here AND
    # (if it has a real backend) registering a factory via
    # ``register_provider``.
    _CANONICAL_REMOTE_NAMES = (
        "openai",
        "anthropic",
        "gemini",
        "grok",
        "ollama",
        "openai_compatible",
        "llama.cpp",
        "lm-studio",
    )

    # Operator-friendly alias -> canonical mapping. Keep this small;
    # only add aliases that are commonly used in the wild.
    _ALIASES = {
        "google": "gemini",
        "google_gemini": "gemini",
        "xai": "grok",
        "x.ai": "grok",
        "claude": "anthropic",
    }

    # Set of recognised remote names (canonical + aliases). Kept as
    # a public attribute for back-compat with tests that probe the
    # set directly.
    SUPPORTED_REMOTE = set(_CANONICAL_REMOTE_NAMES) | set(_ALIASES.keys())

    # Mapping of canonical name -> factory. Phase 1 leaves every
    # remote slot bound to the keyless stub; Phase 2 overrides
    # specific entries via ``register_provider``.
    _REGISTRY: Dict[str, ProviderFactoryFn] = {}

    @classmethod
    def normalise_name(cls, provider_name: str | None) -> str:
        """Return the canonical provider name for ``provider_name``.

        Lower-cases, strips whitespace, and applies alias resolution.
        Unknown names pass through unchanged so the caller can decide
        whether to fall back to the template provider.
        """
        canonical = (provider_name or "template").lower().strip()
        return cls._ALIASES.get(canonical, canonical)

    @classmethod
    def known_canonical_names(cls) -> tuple[str, ...]:
        """Canonical (non-alias) provider names recognised by the factory."""
        return ("template",) + cls._CANONICAL_REMOTE_NAMES

    @classmethod
    def register_provider(
        cls,
        canonical_name: str,
        factory: ProviderFactoryFn,
    ) -> None:
        """Register a real backend factory for a canonical provider name.

        Phase 2 entry point. The registered factory replaces the
        default keyless-stub behaviour for this canonical name. The
        factory is called with keyword arguments matching what
        :meth:`from_ai_config` resolves: ``provider``, ``model``,
        ``api_base``, ``api_key``, ``provider_settings`` (and any
        future fields). Implementations should accept ``**kwargs`` for
        forward-compat.

        Raises ``ValueError`` for unknown canonical names so typos in
        Phase 2 wiring fail loudly.
        """
        canonical = canonical_name.lower().strip()
        if canonical not in cls._CANONICAL_REMOTE_NAMES and canonical != "template":
            allowed = ", ".join(cls.known_canonical_names())
            raise ValueError(
                f"register_provider: {canonical_name!r} is not a known canonical "
                f"name. Expected one of: {allowed}"
            )
        cls._REGISTRY[canonical] = factory

    @staticmethod
    def build(provider_name: str, model: str, cfg: Mapping[str, Any]) -> LLMProvider:
        provider_key = ProviderFactory.normalise_name(provider_name)
        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")
        if provider_key in ProviderFactory._CANONICAL_REMOTE_NAMES:
            return OpenAICompatibleProvider(
                name=provider_key,
                model=model or "default",
                endpoint=str(cfg.get("api_base", "") or cfg.get("endpoint", "")),
                api_key=str(cfg.get("api_key", "")),
            )
        return TemplateProvider(model="template-default")

    @staticmethod
    def from_ai_config(ai_config: Mapping[str, Any]) -> LLMProvider:
        """Build a provider from the resolved ``get_ai_config`` output.

        Consumes the documented AI-config shape (provider, model,
        api_base, api_key_env, provider_settings) so callers no longer
        need to hand-marshal raw ``modules.ai`` dict reads. Honours the
        same provider/offline-fallback rules as :meth:`build`, plus:

        - ``api_key_env``: when set, the matching environment variable
          is read at construction time and passed as ``api_key``. The
          env var lookup is the *only* effect — a missing env var
          becomes an empty ``api_key`` rather than raising. No
          environment is touched when ``api_key_env`` is empty.
        - ``provider_settings``: forwarded to
          :class:`OpenAICompatibleProvider` (or to a Phase 2 backend
          registered via :meth:`register_provider`) so vendor-
          specific config can flow through without re-plumbing the
          factory.
        - Alias names (``google``, ``xai``, ``claude``) are normalised
          to their canonical equivalents (``gemini``, ``grok``,
          ``anthropic``) before dispatch.
        - Garbage / non-mapping input falls back to
          :class:`TemplateProvider` rather than raising.

        No network calls. No SDK imports. Safe to call when the
        runtime is in offline / template mode.
        """
        if not isinstance(ai_config, Mapping):
            return TemplateProvider(model="template-default")

        provider_key = ProviderFactory.normalise_name(ai_config.get("provider"))
        model = str(ai_config.get("model") or "default")

        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")

        if provider_key not in ProviderFactory._CANONICAL_REMOTE_NAMES:
            return TemplateProvider(model="template-default")

        api_key_env = str(ai_config.get("api_key_env") or "").strip()
        api_key = os.environ.get(api_key_env, "") if api_key_env else ""

        provider_settings_raw = ai_config.get("provider_settings")
        provider_settings: Dict[str, Any] = (
            dict(provider_settings_raw)
            if isinstance(provider_settings_raw, Mapping)
            else {}
        )
        api_base = str(ai_config.get("api_base") or "")

        # Phase 2 hook: a registered factory replaces the default
        # keyless stub for this canonical name. The registered
        # factory MUST accept the documented kwargs and may accept
        # **kwargs for forward-compat.
        registered = ProviderFactory._REGISTRY.get(provider_key)
        if registered is not None:
            return registered(
                provider=provider_key,
                model=model,
                api_base=api_base,
                api_key=api_key,
                provider_settings=provider_settings,
                ai_config=dict(ai_config),
            )

        return OpenAICompatibleProvider(
            name=provider_key,
            model=model,
            endpoint=api_base,
            api_key=api_key,
            provider_settings=provider_settings,
        )
