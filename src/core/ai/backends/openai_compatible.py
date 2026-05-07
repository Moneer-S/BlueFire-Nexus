"""HTTP backend for the OpenAI-compatible chat-completions protocol.

This is a *protocol* backend, not a vendor backend. The OpenAI
chat-completions request/response shape is implemented by many
vendors and local servers — operators select it via the
``provider`` config key and supply an ``api_base`` pointing at
their preferred endpoint.

Vendors / runtimes that speak this protocol out of the box:
- ``openai_compatible`` — the generic catch-all name.
- ``openai`` — canonical OpenAI API.
- ``grok`` — xAI's API exposes the OpenAI shape.
- ``ollama`` — when run with the OpenAI-compatible ``/v1`` mount.
- ``llama.cpp`` — when started in OpenAI-compatible server mode.
- ``lm-studio`` — local OpenAI-compatible server.

Vendors that DO NOT speak this protocol (and therefore stay on the
keyless stub until a provider-specific adapter lands):
- ``anthropic`` — uses the Messages API with a different shape.
- ``gemini`` — uses Google's GenerateContent API.

Default behaviour rules (defends the local-first baseline):
- Empty ``api_base`` -> no network call. Returns a structured
  ``ProviderResponse(network_disabled=True, error=...)`` so callers
  see "not configured" without the runtime ever issuing a request.
- Non-empty ``api_base`` -> the backend trusts the operator's
  explicit opt-in and issues the call via the injected transport.
- Transport / parse errors are caught and surfaced in
  ``ProviderResponse(error=..., text="")`` rather than propagating
  exceptions; the caller (Phase 3) decides whether to fall back.

API keys are NEVER read from disk here. They flow in via
``ProviderFactory.from_ai_config`` which resolves
``modules.ai.api_key_env`` against ``os.environ`` at construction
time. Tests inject a mock transport — no real network call.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..providers import ProviderFactory
from ..transport import HTTPTransport, UrllibTransport
from ..types import ProviderOptions, ProviderResponse


# Canonical names for which the OpenAI-compatible HTTP backend is
# the default. Vendors with different request shapes (anthropic,
# gemini) are intentionally absent.
_PROTOCOL_COMPATIBLE_NAMES: tuple[str, ...] = (
    "openai_compatible",
    "openai",
    "grok",
    "ollama",
    "llama.cpp",
    "lm-studio",
)


@dataclass
class OpenAICompatibleHTTPBackend:
    """HTTP-backed provider implementing the OpenAI chat-completions shape.

    Attributes carry the resolved AI-config values so the backend is
    self-contained: callers do not need to keep the config around.
    The ``transport`` is injectable so tests can verify request
    shape without touching the network.
    """

    name: str
    model: str
    endpoint: str = ""
    api_key: str = ""
    provider_settings: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    enabled: bool = False
    """Mirrors ``modules.ai.enabled``. When ``False``, the backend
    short-circuits to an offline response BEFORE issuing any HTTP
    call. The factory passes the resolved value at construction
    time, so a config with ``enabled: false`` but ``provider:
    openai`` + ``api_base`` set never triggers outbound traffic.
    Default is ``False`` to match the local-first baseline; any
    caller that builds the backend by hand for a real outbound call
    must opt in explicitly."""
    transport: HTTPTransport = field(default_factory=UrllibTransport)

    # ------------------------------------------------------------------
    # LLMProvider Protocol surface
    # ------------------------------------------------------------------

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        # Local-first gate #1: when the AI module is disabled at the
        # config layer (`modules.ai.enabled: false`), the backend
        # MUST NOT issue any outbound request even if `api_base` is
        # configured. Closes the Codex P1 from PR #54: the prior
        # version only checked `api_base`, so a config that intended
        # to keep AI off but had api_base set as a placeholder would
        # silently leak prompts to the network on any caller that
        # bypassed the copilot's enabled check.
        if not self.enabled:
            return self._offline_response(
                error=(
                    "AI module is disabled (modules.ai.enabled=false); "
                    "backend stays offline"
                ),
            )
        # Local-first gate #2: an empty `api_base` means the operator
        # selected this backend's name but did not supply an endpoint —
        # treat as "not configured" and stay offline.
        if not self.endpoint:
            return self._offline_response(
                error="api_base not configured; backend stays offline",
            )

        url = self._chat_completions_url()
        headers = self._build_headers()
        body = self._build_request_body(prompt, context=context, options=options)
        timeout = self._resolve_timeout(options)

        try:
            response = self.transport.post_json(
                url,
                headers=headers,
                body=body,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 — surface every transport error
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error=f"transport error: {exc}",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        if response.status_code != 200:
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error=f"http {response.status_code}: {response.body[:200]}",
                metadata={
                    "endpoint": self.endpoint,
                    "url": url,
                    "status_code": response.status_code,
                },
            )

        try:
            payload = response.json()
        except ValueError as exc:
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error=str(exc),
                metadata={"endpoint": self.endpoint, "url": url},
            )

        return self._parse_chat_completion(payload, url=url)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _chat_completions_url(self) -> str:
        base = self.endpoint.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        # Allow provider_settings.headers to add or override headers
        # for vendor-specific tags (organization id, X-Title, etc.).
        # Operators set these explicitly in `ai_providers.<name>.headers`.
        extra = self.provider_settings.get("headers")
        if isinstance(extra, Mapping):
            for k, v in extra.items():
                headers[str(k)] = str(v)
        return headers

    def _build_request_body(
        self,
        prompt: str,
        *,
        context: list[str] | None,
        options: ProviderOptions | None,
    ) -> Dict[str, Any]:
        messages: list[Dict[str, str]] = []
        system = options.system if options is not None else None
        if system:
            messages.append({"role": "system", "content": system})
        if context:
            ctx_blob = "\n\n".join(str(c) for c in context if c)
            if ctx_blob:
                messages.append({"role": "system", "content": ctx_blob})
        messages.append({"role": "user", "content": prompt})

        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }

        # Per-call options take precedence over instance defaults.
        # Closes Codex P2 from PR #54: ``ProviderOptions`` documents
        # ``None`` as the "use default" sentinel, so an explicit
        # ``max_tokens=0`` (or any non-None value) MUST be honoured —
        # not dropped via a truthy check.
        max_tokens = (
            options.max_tokens
            if options is not None and options.max_tokens is not None
            else self.max_tokens
        )
        if max_tokens is not None:
            body["max_tokens"] = int(max_tokens)

        temperature = (
            options.temperature
            if options is not None and options.temperature is not None
            else self.temperature
        )
        if temperature is not None:
            body["temperature"] = float(temperature)

        return body

    def _resolve_timeout(self, options: ProviderOptions | None) -> int:
        # Same is-not-None discipline as max_tokens / temperature so an
        # explicit per-call ``timeout=0`` (the legitimate "no timeout"
        # / "very short" sentinel) reaches the transport instead of
        # silently falling back to the instance default.
        if options is not None and options.timeout is not None:
            return int(options.timeout)
        return int(self.timeout)

    def _parse_chat_completion(self, payload: Any, *, url: str) -> ProviderResponse:
        if not isinstance(payload, Mapping):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response payload is not an object",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response has no choices",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        choice = choices[0] if isinstance(choices[0], Mapping) else {}
        message = choice.get("message") if isinstance(choice.get("message"), Mapping) else {}
        text = str(message.get("content") or "")
        finish_reason = choice.get("finish_reason")
        finish_str = str(finish_reason) if finish_reason is not None else None

        usage_raw = payload.get("usage") if isinstance(payload.get("usage"), Mapping) else {}
        usage: Dict[str, int] = {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage_raw.get(key)
            if isinstance(value, (int, float)):
                usage[key] = int(value)

        metadata: Dict[str, Any] = {"endpoint": self.endpoint, "url": url}
        # Surface useful provider-reported fields without exposing
        # the entire payload (which may contain prompt echoes).
        if "id" in payload:
            metadata["response_id"] = str(payload["id"])
        if "system_fingerprint" in payload:
            metadata["system_fingerprint"] = str(payload["system_fingerprint"])

        return ProviderResponse(
            text=text,
            provider=self.name,
            model=self.model,
            usage=usage,
            finish_reason=finish_str,
            network_disabled=False,
            metadata=metadata,
        )

    def _offline_response(self, *, error: str) -> ProviderResponse:
        return ProviderResponse(
            text="",
            provider=self.name,
            model=self.model,
            network_disabled=True,
            error=error,
            metadata={"endpoint": self.endpoint},
        )


# ---------------------------------------------------------------------------
# Factory function used at registration time
# ---------------------------------------------------------------------------


def _backend_factory(
    *,
    provider: str,
    model: str,
    api_base: str,
    api_key: str,
    provider_settings: Mapping[str, Any],
    ai_config: Mapping[str, Any],
    **_extra: Any,
) -> OpenAICompatibleHTTPBackend:
    """Construct a backend from the kwargs passed by ``ProviderFactory.from_ai_config``."""
    raw_max_tokens = ai_config.get("max_tokens")
    max_tokens: Optional[int]
    try:
        max_tokens = int(raw_max_tokens) if raw_max_tokens is not None else None
    except (TypeError, ValueError):
        max_tokens = None

    raw_temperature = ai_config.get("temperature")
    temperature: Optional[float]
    try:
        temperature = float(raw_temperature) if raw_temperature is not None else None
    except (TypeError, ValueError):
        temperature = None

    raw_timeout = ai_config.get("timeout", 30)
    try:
        timeout = int(raw_timeout)
    except (TypeError, ValueError):
        timeout = 30

    return OpenAICompatibleHTTPBackend(
        name=provider,
        model=model,
        endpoint=api_base,
        api_key=api_key,
        provider_settings=dict(provider_settings),
        timeout=timeout,
        max_tokens=max_tokens,
        temperature=temperature,
        enabled=bool(ai_config.get("enabled", False)),
    )


def register_default_backends() -> None:
    """Register the OpenAI-compatible HTTP backend for protocol-compatible names.

    Idempotent. Called from ``src/core/ai/__init__.py`` at import time
    so the backend is available out of the box. Default Phase 1
    contract still holds because the backend short-circuits to
    ``network_disabled=True`` when ``api_base`` is empty — only
    operators who explicitly set ``api_base`` can trigger network
    calls, and even then only when the chosen provider is enabled
    (``modules.ai.enabled: true``).

    Adding a new protocol-compatible canonical name only requires
    extending ``_PROTOCOL_COMPATIBLE_NAMES``.
    """
    for canonical in _PROTOCOL_COMPATIBLE_NAMES:
        ProviderFactory.register_provider(canonical, _backend_factory)


__all__ = [
    "OpenAICompatibleHTTPBackend",
    "register_default_backends",
]
