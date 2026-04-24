"""AI provider abstractions with deterministic offline fallback."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


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
    """Thin provider wrapper without requiring live API calls by default."""

    name: str
    model: str
    endpoint: str = ""
    api_key: str = ""

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

    @staticmethod
    def build(provider_name: str, model: str, cfg: Mapping[str, Any]) -> LLMProvider:
        provider_key = (provider_name or "template").lower()
        if provider_key in {"none", "template"}:
            return TemplateProvider(model=model or "template-default")
        if provider_key in ProviderFactory.SUPPORTED_REMOTE:
            return OpenAICompatibleProvider(
                name=provider_key,
                model=model or "default",
                endpoint=str(cfg.get("api_base", "") or cfg.get("endpoint", "")),
                api_key=str(cfg.get("api_key", "")),
            )
        return TemplateProvider(model="template-default")
