"""AI package exports."""

from .backends.anthropic import AnthropicMessagesBackend, register_anthropic_backend
from .backends.gemini import GeminiGenerateContentBackend, register_gemini_backend
from .backends.openai_compatible import (
    OpenAICompatibleHTTPBackend,
    register_default_backends,
)
from .copilot import AICopilot
from .fallback import FallbackChainProvider
from .legacy_compat import AIProvider, build_provider
from .mutation import mutate_technique
from .providers import LLMProvider, OpenAICompatibleProvider, ProviderFactory, TemplateProvider
from .transport import HTTPResponse, HTTPTransport, UrllibTransport
from .types import ProviderOptions, ProviderResponse

# Register the OpenAI-compatible HTTP backend for protocol-compatible
# canonical names at import time. Idempotent. The backend short-
# circuits to network_disabled=True when no api_base is configured,
# so the Phase 1 local-first guarantee is preserved.
register_default_backends()

# Register the Anthropic Messages-API adapter for the `anthropic`
# canonical name. Idempotent. Defaults to ``enabled=False`` on the
# backend itself, so no network call happens unless an operator
# explicitly opts in via ``modules.ai.enabled: true`` plus a valid
# ``api_base`` and resolved API key.
register_anthropic_backend()

# Register the Gemini GenerateContent adapter for the `gemini`
# canonical name. Idempotent. Same default-False / opt-in contract
# as the Anthropic adapter.
register_gemini_backend()

__all__ = [
    "AICopilot",
    "AIProvider",
    "AnthropicMessagesBackend",
    "FallbackChainProvider",
    "GeminiGenerateContentBackend",
    "HTTPResponse",
    "HTTPTransport",
    "LLMProvider",
    "OpenAICompatibleHTTPBackend",
    "OpenAICompatibleProvider",
    "ProviderFactory",
    "ProviderOptions",
    "ProviderResponse",
    "TemplateProvider",
    "UrllibTransport",
    "build_provider",
    "mutate_technique",
    "register_anthropic_backend",
    "register_default_backends",
    "register_gemini_backend",
]
