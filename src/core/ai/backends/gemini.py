"""HTTP backend for Google's Gemini GenerateContent API.

This is a *vendor-specific* backend. Google's GenerateContent
shape differs from both the OpenAI chat-completions shape and
the Anthropic Messages shape, so it gets its own adapter:

- URL pattern includes the model in the path:
  ``{api_base}/v1beta/models/{model}:generateContent``.
- Auth header: ``x-goog-api-key`` (Google's preferred style; the
  ``?key=...`` query-string variant is supported by the API but
  exposes the key in server logs and is therefore avoided).
- Request body shape:
  ``contents: [{role, parts: [{text}]}]`` (NOT ``messages`` of
  ``{role, content}``); top-level ``systemInstruction`` field
  with the same parts shape; ``generationConfig`` block holds
  ``temperature`` and ``maxOutputTokens`` (NOT a top-level
  ``temperature`` / ``max_tokens``).
- Response: text comes from
  ``candidates[0].content.parts[].text`` (an array of parts);
  finish reason is ``finishReason`` (camelCase); usage is
  ``usageMetadata.{promptTokenCount, candidatesTokenCount,
  totalTokenCount}``. The adapter normalises usage into the
  shared ``prompt_tokens`` / ``completion_tokens`` /
  ``total_tokens`` keys for caller-side consistency.

Default behaviour rules (defends the local-first baseline):

- ``enabled=False`` -> short-circuit to offline.
- Empty ``api_base`` -> short-circuit to offline.
- Empty ``api_key`` -> short-circuit to offline with a clear
  error. Same reasoning as the Anthropic adapter: Gemini has
  no local-server analog and dispatch without a key would just
  return 401/403.
- Transport / parse errors are caught and surfaced in
  ``ProviderResponse(error=..., text="")`` rather than
  propagating exceptions.

API keys are NEVER read from disk here. They flow in via
``ProviderFactory.from_ai_config`` which resolves
``modules.ai.api_key_env`` (or
``ai_providers.gemini.api_key_env``) against ``os.environ`` at
construction time. Tests inject a mock transport — no real
network call.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..providers import ProviderFactory
from ..transport import HTTPTransport, UrllibTransport
from ..types import ProviderOptions, ProviderResponse


_DEFAULT_API_VERSION = "v1beta"
"""The Gemini REST API segment to use in the URL path. Operators
who need a different version set
``ai_providers.gemini.api_version`` in config; the adapter slots
it into ``{api_base}/{api_version}/models/...``."""


@dataclass
class GeminiGenerateContentBackend:
    """Vendor-specific Google Gemini GenerateContent provider.

    Attributes carry the resolved AI-config values so the backend
    is self-contained: callers do not need to keep the config
    around. The ``transport`` is injectable so tests can verify
    request shape without touching the network.
    """

    name: str = "gemini"
    model: str = "gemini-1.5-flash"
    endpoint: str = ""
    api_key: str = ""
    provider_settings: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    api_version: str = _DEFAULT_API_VERSION
    enabled: bool = False
    """Mirrors ``modules.ai.enabled``. When ``False`` the backend
    short-circuits to offline BEFORE issuing any HTTP call. Same
    contract as the Anthropic and OpenAI-compatible backends."""
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
        # Local-first gate #3: Gemini requires an API key. Same
        # reasoning as the Anthropic adapter: failing safely with a
        # clear error beats a wasted 401/403.
        if not self.api_key:
            return self._offline_response(
                error=(
                    "gemini api_key is required; set "
                    "modules.ai.api_key_env (or "
                    "ai_providers.gemini.api_key_env) to the env "
                    "var holding the key"
                ),
            )

        url = self._generate_content_url()
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

        return self._parse_generate_content_response(payload, url=url)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _generate_content_url(self) -> str:
        base = self.endpoint.rstrip("/")
        # Honour an explicitly-built URL (operator already included
        # the model + ``:generateContent`` suffix) so advanced setups
        # can pin a different model variant per call site.
        if base.endswith(":generateContent") or base.endswith(":streamGenerateContent"):
            return base
        version = str(
            self.provider_settings.get("api_version") or self.api_version
        )
        return f"{base}/{version}/models/{self.model}:generateContent"

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-goog-api-key": self.api_key,
        }
        # Allow provider_settings.headers to add or override headers
        # for vendor-specific tags (project id, request labels, etc.).
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
        body: Dict[str, Any] = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
        }

        # Gemini's `systemInstruction` is a separate top-level field
        # with the same parts shape. Concatenate the per-call system
        # prompt and the RAG context so the shared
        # ProviderOptions/_ask interface works against Gemini
        # identically to the other adapters.
        system_parts: list[str] = []
        if options is not None and options.system:
            system_parts.append(str(options.system))
        if context:
            ctx_blob = "\n\n".join(str(c) for c in context if c)
            if ctx_blob:
                system_parts.append(ctx_blob)
        if system_parts:
            body["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}]
            }

        # Gemini wraps generation knobs in a `generationConfig` block
        # rather than top-level `temperature` / `max_tokens`. is-not-
        # None checks so explicit zero values reach the request.
        gen_config: Dict[str, Any] = {}
        if options is not None and options.max_tokens is not None:
            gen_config["maxOutputTokens"] = int(options.max_tokens)
        elif self.max_tokens is not None:
            gen_config["maxOutputTokens"] = int(self.max_tokens)

        if options is not None and options.temperature is not None:
            gen_config["temperature"] = float(options.temperature)
        elif self.temperature is not None:
            gen_config["temperature"] = float(self.temperature)

        if gen_config:
            body["generationConfig"] = gen_config

        return body

    def _resolve_timeout(self, options: ProviderOptions | None) -> int:
        # is-not-None so explicit timeout=0 reaches the transport.
        if options is not None and options.timeout is not None:
            return int(options.timeout)
        return int(self.timeout)

    def _parse_generate_content_response(
        self, payload: Any, *, url: str
    ) -> ProviderResponse:
        if not isinstance(payload, Mapping):
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response payload is not an object",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        # Look for prompt-level blocking before parsing candidates so
        # the operator gets a clear signal when Gemini blocked the
        # whole request rather than producing a candidate.
        prompt_feedback = payload.get("promptFeedback")
        if isinstance(prompt_feedback, Mapping):
            block_reason = prompt_feedback.get("blockReason")
            if block_reason:
                return ProviderResponse(
                    text="",
                    provider=self.name,
                    model=self.model,
                    network_disabled=False,
                    error=f"prompt blocked: {block_reason}",
                    metadata={
                        "endpoint": self.endpoint,
                        "url": url,
                        "block_reason": str(block_reason),
                    },
                )

        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            return ProviderResponse(
                text="",
                provider=self.name,
                model=self.model,
                network_disabled=False,
                error="response has no candidates",
                metadata={"endpoint": self.endpoint, "url": url},
            )

        candidate = candidates[0] if isinstance(candidates[0], Mapping) else {}
        content = candidate.get("content") if isinstance(candidate.get("content"), Mapping) else {}
        parts = content.get("parts") if isinstance(content.get("parts"), list) else []
        # Concatenate every part that carries a ``text`` field so a
        # multi-part response is not silently truncated.
        text_parts: list[str] = []
        for part in parts:
            if isinstance(part, Mapping):
                value = part.get("text")
                if value:
                    text_parts.append(str(value))
        text = "".join(text_parts)

        finish_reason = candidate.get("finishReason")
        finish_str = str(finish_reason) if finish_reason is not None else None

        # Normalise usage into the shared keys used by the other
        # adapters. Gemini reports `promptTokenCount` /
        # `candidatesTokenCount` / `totalTokenCount`.
        usage_raw = (
            payload.get("usageMetadata")
            if isinstance(payload.get("usageMetadata"), Mapping)
            else {}
        )
        usage: Dict[str, int] = {}
        prompt_tokens = usage_raw.get("promptTokenCount")
        completion_tokens = usage_raw.get("candidatesTokenCount")
        total_tokens = usage_raw.get("totalTokenCount")
        if isinstance(prompt_tokens, (int, float)):
            usage["prompt_tokens"] = int(prompt_tokens)
        if isinstance(completion_tokens, (int, float)):
            usage["completion_tokens"] = int(completion_tokens)
        if isinstance(total_tokens, (int, float)):
            usage["total_tokens"] = int(total_tokens)
        elif usage:
            # Vendor sometimes omits totalTokenCount; derive it from
            # the parts that are present so downstream consumers can
            # rely on the key being there.
            usage["total_tokens"] = sum(usage.values())

        metadata: Dict[str, Any] = {"endpoint": self.endpoint, "url": url}
        if "modelVersion" in payload:
            metadata["upstream_model"] = str(payload["modelVersion"])
        # Surface safety ratings (if any) so operators can see when a
        # candidate was attenuated. Single string per category for
        # report renderability; the full ratings array is intentionally
        # not echoed back to avoid duplicating prompt content in
        # metadata.
        safety_ratings = candidate.get("safetyRatings")
        if isinstance(safety_ratings, list) and safety_ratings:
            categories: list[str] = []
            for rating in safety_ratings:
                if isinstance(rating, Mapping):
                    category = rating.get("category")
                    if category:
                        categories.append(str(category))
            if categories:
                metadata["safety_categories"] = sorted(set(categories))

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
) -> GeminiGenerateContentBackend:
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

    api_version = str(provider_settings.get("api_version") or _DEFAULT_API_VERSION)

    return GeminiGenerateContentBackend(
        name=provider,
        # Honour the operator's explicit model when set; otherwise fall
        # back to the adapter's stable default. Gemini's URL contains
        # the model name so a non-empty value is required.
        model=model if model and model != "default" else "gemini-1.5-flash",
        endpoint=api_base,
        api_key=api_key,
        provider_settings=dict(provider_settings),
        timeout=timeout,
        max_tokens=max_tokens,
        temperature=temperature,
        api_version=api_version,
        enabled=bool(ai_config.get("enabled", False)),
    )


def register_gemini_backend() -> None:
    """Register the Gemini GenerateContent adapter for the canonical
    ``gemini`` provider name. Idempotent. Called from
    ``src/core/ai/__init__.py`` at import time so the adapter is
    available out of the box.

    Default Phase 1 contract still holds because ``enabled`` defaults
    to ``False`` on the backend instance: a config that has not opted
    in via ``modules.ai.enabled: true`` (and a non-empty ``api_base``
    and ``api_key``) cannot trigger a network call.

    The ``google`` and ``google_gemini`` aliases are normalised to
    ``gemini`` by :meth:`ProviderFactory.normalise_name`, so the
    registered factory automatically serves all three names.
    """
    ProviderFactory.register_provider("gemini", _backend_factory)


__all__ = [
    "GeminiGenerateContentBackend",
    "register_gemini_backend",
]
