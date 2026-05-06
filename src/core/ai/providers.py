"""AI provider abstractions with deterministic offline fallback."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, Protocol


class LLMProvider(Protocol):
    """Common provider contract for copilot use."""

    name: str
    model: str

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        ...


@dataclass
class TemplateProvider:
    """Deterministic fallback provider for offline and CI."""

    model: str = "template-default"
    name: str = "template"

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        scrubbed = prompt.replace("[REDACTED]", "***").replace("\n", " ").strip()
        context_preview = " | ".join((context or [])[:2])[:220]
        return (
            "TemplateProvider response\n"
            f"- model: {self.model}\n"
            f"- prompt_summary: {scrubbed[:220]}\n"
            f"- context_preview: {context_preview or 'none'}\n"
            "- recommendation: refine scenario steps, review detection coverage,"
            " validate telemetry\n"
        )


@dataclass
class OpenAICompatibleProvider:
    """Vendor-neutral keyless stub for any recognised remote provider name.

    Despite the legacy class name, this is **not** an OpenAI-specific
    implementation — it is the placeholder used for every supported
    remote provider name (openai, anthropic, google, ollama, llama.cpp,
    lm-studio, openai_compatible). Its ``complete()`` method
    intentionally makes no outbound calls and works without an API
    key, so the local-first baseline stays offline even when an
    operator selects a remote provider.

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
        # Security-first default: avoid outbound calls unless explicit code path is added later.
        _ = context
        return (
            f"{self.name} provider configured with model={self.model}. "
            "Network completion is intentionally disabled by default.\n"
            f"prompt_summary: {prompt[:220]}"
        )


class ProviderFactory:
    """Build a provider from config while preserving user choice."""

    SUPPORTED_REMOTE = {
        "openai",
        "anthropic",
        "google",
        "ollama",
        "llama.cpp",
        "lm-studio",
        "openai_compatible",
    }

    OFFLINE_NAMES = {"none", "template", ""}

    @staticmethod
    def build(provider_name: str, model: str, cfg: Mapping[str, Any]) -> LLMProvider:
        provider_key = (provider_name or "template").lower()
        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")
        if provider_key in ProviderFactory.SUPPORTED_REMOTE:
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
          :class:`OpenAICompatibleProvider` so future backends can opt
          into vendor-specific config without re-plumbing the factory.
        - Garbage / non-mapping input falls back to
          :class:`TemplateProvider` rather than raising.

        No network calls. No SDK imports. Safe to call when the
        runtime is in offline / template mode.
        """
        if not isinstance(ai_config, Mapping):
            return TemplateProvider(model="template-default")

        provider_key = str(ai_config.get("provider") or "template").lower().strip()
        model = str(ai_config.get("model") or "default")

        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")

        if provider_key not in ProviderFactory.SUPPORTED_REMOTE:
            return TemplateProvider(model="template-default")

        api_key_env = str(ai_config.get("api_key_env") or "").strip()
        api_key = os.environ.get(api_key_env, "") if api_key_env else ""

        provider_settings_raw = ai_config.get("provider_settings")
        provider_settings: Dict[str, Any] = (
            dict(provider_settings_raw)
            if isinstance(provider_settings_raw, Mapping)
            else {}
        )

        return OpenAICompatibleProvider(
            name=provider_key,
            model=model,
            endpoint=str(ai_config.get("api_base") or ""),
            api_key=api_key,
            provider_settings=provider_settings,
        )
