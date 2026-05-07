"""Fallback-chain wrapper for AI providers.

When ``modules.ai.fallback_provider`` is set, the copilot wraps the
configured primary provider in a :class:`FallbackChainProvider` so
a primary failure (transport error, non-2xx, malformed payload)
silently retries via the named fallback provider. The most useful
fallback in practice is ``"template"`` — it never fails and never
makes network calls, so any primary outage degrades gracefully to
the deterministic offline path.

The wrapper preserves the :class:`LLMProvider` Protocol so callers
do not need to know whether they are talking to a single provider
or a chain. When the fallback fires, the returned
:class:`ProviderResponse` has ``fallback_used=True`` and carries
``primary_provider`` / ``primary_error`` keys in ``metadata`` so
artifact writers and report renderers can flag degraded runs.

Phase 3 introduces this wrapper; Phase 1 already shipped the
``fallback_provider`` config field. No new behaviour is enabled
unless an operator opts in by setting both
``modules.ai.fallback_provider`` AND a non-template
``modules.ai.provider``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .types import ProviderOptions, ProviderResponse


@dataclass
class FallbackChainProvider:
    """Wraps a primary provider with an optional fallback on error.

    A primary response with ``error is None`` (success path) is
    returned untouched. A primary response with a non-empty
    ``error`` is treated as a failure: if a fallback provider was
    configured, the wrapper invokes it and returns the fallback's
    response with ``fallback_used=True`` plus ``primary_provider``
    / ``primary_error`` recorded in ``metadata``. If no fallback was
    configured the primary error response is returned unchanged.

    The wrapper itself never raises — every failure surface comes
    through the existing :class:`ProviderResponse.error` channel.
    """

    primary: object
    fallback: Optional[object] = None

    @property
    def name(self) -> str:
        return getattr(self.primary, "name", "unknown")

    @property
    def model(self) -> str:
        return getattr(self.primary, "model", "unknown")

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        primary_response: ProviderResponse = self.primary.generate(  # type: ignore[attr-defined]
            prompt, context=context, options=options
        )
        # Success path: primary handled it. Pass through unchanged so
        # downstream callers see the actual primary metadata (no
        # fallback marker, no rewriting).
        if not primary_response.error:
            return primary_response
        # Failure path with no fallback: caller sees the error
        # surfaced by the primary. The wrapper does not invent one.
        if self.fallback is None:
            return primary_response

        fallback_response: ProviderResponse = self.fallback.generate(  # type: ignore[attr-defined]
            prompt, context=context, options=options
        )

        # Annotate the fallback response so artifact writers can
        # show "fallback used because <primary> reported <error>".
        annotated_metadata = dict(fallback_response.metadata)
        annotated_metadata["primary_provider"] = primary_response.provider
        if primary_response.error:
            annotated_metadata["primary_error"] = primary_response.error

        return ProviderResponse(
            text=fallback_response.text,
            provider=fallback_response.provider,
            model=fallback_response.model,
            usage=fallback_response.usage,
            finish_reason=fallback_response.finish_reason,
            fallback_used=True,
            network_disabled=fallback_response.network_disabled,
            error=fallback_response.error,
            metadata=annotated_metadata,
        )


__all__ = ["FallbackChainProvider"]
