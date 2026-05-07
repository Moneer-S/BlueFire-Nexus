"""AI package exports."""

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

__all__ = [
    "AICopilot",
    "AIProvider",
    "FallbackChainProvider",
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
    "register_default_backends",
]
