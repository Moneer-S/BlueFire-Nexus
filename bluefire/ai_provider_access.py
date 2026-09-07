"""Explicit credential ownership for direct and enrolled broker provider calls."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

from .ai_transport import CancellationSignal, ManagedAIJSONTransport, UrllibAIJSONTransport
from .ai_wire import (
    AIProviderCancelled,
    AIProviderTransportError,
    credential_value,
    request_headers,
)
from .config import AIProviderConfig


@runtime_checkable
class AIJSONTransport(Protocol):
    def post(
        self, url: str, *, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> bytes: ...


@dataclass(frozen=True)
class ProviderReadiness:
    available: bool
    credential_state: str
    code: str
    message: str
    source: str = "direct"
    binding_digest: str | None = None
    lab_session_expires_at_ms: int | None = None


class AIProviderAccess(Protocol):
    def readiness(self, config: AIProviderConfig) -> ProviderReadiness: ...

    def post(
        self,
        config: AIProviderConfig,
        *,
        body: bytes,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> bytes: ...

    def close(self) -> None: ...


class DirectAIProviderAccess:
    """Retain direct-install endpoint/key semantics behind the shared interface."""

    def __init__(
        self, *, transport: AIJSONTransport | None = None, environ: Mapping[str, str] | None = None
    ) -> None:
        self.transport = transport
        self.environ = os.environ if environ is None else environ

    def readiness(self, config: AIProviderConfig) -> ProviderReadiness:
        available = config.api_key is None or bool(credential_value(config, self.environ))
        return ProviderReadiness(
            available=available,
            credential_state=(
                "not_required"
                if config.api_key is None
                else "ready" if available else "unavailable"
            ),
            code="configuration_ready" if available else "credential_unavailable",
            message=(
                "Configuration checked; no network request was made."
                if available
                else "The referenced server environment variable is unset or invalid. No network request was made."
            ),
        )

    def post(
        self,
        config: AIProviderConfig,
        *,
        body: bytes,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> bytes:
        if cancel_event is not None and cancel_event.is_set():
            raise AIProviderCancelled()
        key = credential_value(config, self.environ)
        if config.api_key is not None and not key:
            raise AIProviderTransportError(
                "Provider credential is unavailable", retryable=False, code="credential_unavailable"
            )
        transport: AIJSONTransport = self.transport or UrllibAIJSONTransport(
            cancel_event=cancel_event
        )
        if isinstance(transport, ManagedAIJSONTransport):
            transport = transport.bind(cancel_event)
        result = transport.post(
            str(config.endpoint),
            headers=request_headers(key),
            body=body,
            timeout_seconds=timeout_seconds,
        )
        if cancel_event is not None and cancel_event.is_set():
            raise AIProviderCancelled()
        return result

    def close(self) -> None:
        if isinstance(self.transport, ManagedAIJSONTransport):
            self.transport.close()
