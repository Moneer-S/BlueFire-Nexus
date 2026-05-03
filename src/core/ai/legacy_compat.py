"""Compatibility aliases for older AI provider APIs."""

from __future__ import annotations

from typing import Any, Dict

from .providers import LLMProvider as AIProvider
from .providers import ProviderFactory


def build_provider(config: Dict[str, Any]) -> AIProvider:
    """Legacy helper to build a provider from old config shape."""
    provider_name = str(config.get("provider", "template"))
    model = str(config.get("model", "default"))
    return ProviderFactory.build(provider_name, model, config)


__all__ = ["AIProvider", "build_provider"]
