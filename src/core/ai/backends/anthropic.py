"""HTTP backend for Anthropic's Messages API.

This is a *vendor-specific* backend. The Anthropic Messages
request/response shape differs from the OpenAI chat-completions
shape in several ways, so it cannot share the same adapter:

- Endpoint suffix: ``/v1/messages`` (vs ``/chat/completions``).
- Auth header: ``x-api-key`` (vs ``Authorization: Bearer``).
- Required version header: ``anthropic-version`` (default
  ``2023-06-01``; override via ``ai_providers.anthropic
  .anthropic_version``).
- ``max_tokens`` is REQUIRED on every request (the adapter
  defaults to 1024 when neither the resolved config nor the
  per-call options specify a value).
- The system prompt is a top-level ``system`` field on the
  request body, not a message in the ``messages`` array.
- Response text comes from ``content[0].text`` (an array of
  content blocks), not ``choices[0].message.content``.
- Stop reason is ``stop_reason``, not ``finish_reason``.
- Usage keys are ``input_tokens`` / ``output_tokens``, not
  ``prompt_tokens`` / ``completion_tokens``. The adapter
  normalises these into the shared ``usage`` mapping so callers
  see consistent keys regardless of provider.

Default behaviour rules (defends the local-first baseline):

- ``enabled=False`` -> short-circuit to offline. The auto-
  registered factory passes ``modules.ai.enabled`` through.
- Empty ``api_base`` -> short-circuit to offline. The operator
  must supply an endpoint explicitly.
- Empty ``api_key`` -> short-circuit to offline with a clear
  ``error`` message. Anthropic has no local-server analog, so
  attempting the call with no key would just produce a wasted
  network round-trip and a 401. This differs from the OpenAI-
  compatible backend's "send anyway and let the server 401"
  behaviour, which exists specifically so local servers
  (Ollama, llama.cpp) can run without auth.
- Transport / parse errors are caught and surfaced in
  ``ProviderResponse(error=..., text="")`` rather than
  propagating exceptions.

API keys are NEVER read from disk here. They flow in via
``ProviderFactory.from_ai_config`` which resolves
``modules.ai.api_key_env`` (or ``ai_providers.anthropic
.api_key_env``) against ``os.environ`` at construction time.
Tests inject a mock transport — no real network call.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..providers import ProviderFactory
from ..transport import HTTPTransport, UrllibTransport
from ..types import ProviderOptions, ProviderResponse


_DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
"""Stable Messages-API version pinned by the adapter. Operators
who need a different version set
``ai_providers.anthropic.anthropic_version`` in config; the
adapter forwards it as the ``anthropic-version`` header."""

_DEFAULT_MAX_TOKENS = 1024
"""Anthropic's Messages API requires ``max_tokens`` on every
request. The adapter falls back to this value when neither the
resolved config nor the per-call ``ProviderOptions`` provides
one. Mirrors the documented default for `modules.ai.max_tokens`."""


@dataclass
class AnthropicMessagesBackend:
    """Vendor-specific Anthropic Messages-API provider.

    Attributes carry the resolved AI-config values so the backend
    is self-contained: callers do not need to keep the config
    around. The ``transport`` is injectable so tests can verify
    request shape without touching the network.
    """

    name: str = "anthropic"
    model: str = "claude-3-5-sonnet-20241022"
    endpoint: str = ""
    api_key: str = ""
    provider_settings: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    anthropic_version: str = _DEFAULT_ANTHROPIC_VERSION
    enabled: bool = False
    """Mirrors ``modules.ai.enabled``. When ``False`` the backend
    short-circuits to offline BEFORE issuing any HTTP call. Same
    contract as the OpenAI-compatible HTTP backend."""
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
        # Local-first gate #1: AI module disabled at config layer.
        if not self.enabled:
            return self._offline_response(
                error=(
                    "AI module is disabled (modules.ai.enabled=false); "
                    "backend stays offline"
                ),
            )
        # Local-first gate #2: no endpoint configured.
        if not self.endpoint:
            return self._offline_response(
                error="api_base not configured; backend stays offline",
            )
        # Local-first gate #3: Anthropic requires an API key. Failing
        # safely here gives the operator a clearer signal than a 401
        # and avoids wasted network round-trips. Differs intentionally
        # from the OpenAI-compatible backend, which permits empty keys
        # for local-server use.
        if not self.api_key:
            return self._offline_response(
                error=(
                    "anthropic api_key is required; set "
                    "modules.ai.api_key_env (or "
                    "ai_providers.anthropic.api_key_env) to the env "
                    "var holding the key"
                ),
            )

        url = self._messages_url()
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

        return self._parse_messages_response(payload, url=url)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _messages_url(self) -> str:
        base = self.endpoint.rstrip("/")
        if base.endswith("/v1/messages"):
            return base
        return f"{base}/v1/messages"

    def _build_headers(self) -> Dict[str, str]:
        version = str(
            self.provider_settings.get("anthropic_version") or self.anthropic_version
        )
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": version,
        }
        # Allow provider_settings.headers to add or override headers
        # for vendor-specific tags (organisation id, beta flags, etc.).
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
        # max_tokens precedence: per-call options -> instance default ->
        # adapter default. Anthropic REQUIRES this field.
        if options is not None and options.max_tokens is not None:
            resolved_max_tokens = int(options.max_tokens)
        elif self.max_tokens is not None:
            resolved_max_tokens = int(self.max_tokens)
        else:
            resolved_max_tokens = _DEFAULT_MAX_TOKENS

        body: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": resolved_max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        # Anthropic uses a top-level `system` field, not a system role
        # in the messages array. Concatenate the per-call system prompt
        # with the RAG context (if any) so callers can pass either or
        # both via the shared ProviderOptions/_ask interface.
        system_parts: list[str] = []
        if options is not None and options.system:
            system_parts.append(str(options.system))
        if context:
            ctx_blob = "\n\n".join(str(c) for c in context if c)
            if ctx_blob:
                system_parts.append(ctx_blob)
        if system_parts:
            body["system"] = "\n\n".join(system_parts)

        # temperature is optional. is-not-None for explicit-zero
        # propagation (closes the same Codex P2 the OpenAI-compatible
        # backend dealt with).
        if options is not None and options.temperature is not None:
            body["temperature"] = float(options.temperature)
        elif self.temperature is not None:
            body["temperature"] = float(self.temperature)

        return body

    def _resolve_timeout(self, options: ProviderOptions | None) -> int:
        # is-not-None so an explicit timeout=0 reaches the transport.
        if options is not None and options.timeout is not None:
            return int(options.timeout)
        return int(self.timeout)

    def _parse_messages_response(self, payload: Any, *, url: str) -> ProviderResponse:
        if not isinstance(payload, Mapping):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response payload is not an object",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        # Anthropic returns ``content`` as an array of content blocks
        # (each with a ``type`` and a per-type field). Concatenate every
        # ``text``-type block so multi-block responses are not silently
        # truncated to the first block.
        content_blocks = payload.get("content")
        if not isinstance(content_blocks, list):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response has no content array",
                metadata={"endpoint": self.endpoint, "url": url},
            )
        text_parts: list[str] = []
        for block in content_blocks:
            if not isinstance(block, Mapping):
                continue
            if str(block.get("type", "")).lower() == "text":
                value = block.get("text")
                if value:
                    text_parts.append(str(value))
        text = "".join(text_parts)

        stop_reason = payload.get("stop_reason")
        finish_str = str(stop_reason) if stop_reason is not None else None

        # Normalise usage into the shared ``prompt_tokens`` /
        # ``completion_tokens`` / ``total_tokens`` keys so report
        # renderers and operators see consistent shapes regardless
        # of which provider produced the response.
        usage_raw = payload.get("usage") if isinstance(payload.get("usage"), Mapping) else {}
        usage: Dict[str, int] = {}
        input_tokens = usage_raw.get("input_tokens")
        output_tokens = usage_raw.get("output_tokens")
        if isinstance(input_tokens, (int, float)):
            usage["prompt_tokens"] = int(input_tokens)
        if isinstance(output_tokens, (int, float)):
            usage["completion_tokens"] = int(output_tokens)
        if usage:
            usage["total_tokens"] = sum(usage.values())

        metadata: Dict[str, Any] = {"endpoint": self.endpoint, "url": url}
        if "id" in payload:
            metadata["response_id"] = str(payload["id"])
        if "model" in payload:
            # Anthropic echoes the model used; surface it for
            # attribution even when the operator pinned a model alias.
            metadata["upstream_model"] = str(payload["model"])
        # Surface the model server returns on the response too — useful
        # when alias names differ from the resolved model id.

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
) -> AnthropicMessagesBackend:
    """Construct the adapter from kwargs passed by ``ProviderFactory.from_ai_config``."""
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

    anthropic_version = str(
        provider_settings.get("anthropic_version") or _DEFAULT_ANTHROPIC_VERSION
    )

    return AnthropicMessagesBackend(
        name=provider,
        # Honour the operator's explicit model when set; otherwise use
        # the adapter's stable default.
        model=model if model and model != "default" else "claude-3-5-sonnet-20241022",
        endpoint=api_base,
        api_key=api_key,
        provider_settings=dict(provider_settings),
        timeout=timeout,
        max_tokens=max_tokens,
        temperature=temperature,
        anthropic_version=anthropic_version,
        enabled=bool(ai_config.get("enabled", False)),
    )


def register_anthropic_backend() -> None:
    """Register the Anthropic Messages-API backend for the canonical
    ``anthropic`` provider name. Idempotent. Called from
    ``src/core/ai/__init__.py`` at import time so the adapter is
    available out of the box.

    Default Phase 1 contract still holds because ``enabled`` defaults
    to ``False`` on the backend instance: a config that has not opted
    in via ``modules.ai.enabled: true`` (and a non-empty ``api_base``
    and ``api_key``) cannot trigger a network call.

    The ``claude`` alias is normalised to ``anthropic`` by
    :meth:`ProviderFactory.normalise_name`, so the registered factory
    automatically serves both names. No additional alias wiring needed.
    """
    ProviderFactory.register_provider("anthropic", _backend_factory)


__all__ = [
    "AnthropicMessagesBackend",
    "register_anthropic_backend",
]
