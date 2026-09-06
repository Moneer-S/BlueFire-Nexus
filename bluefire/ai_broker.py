"""Service-owned enrolled broker access over an injected private channel.

There is no lab auto-discovery or public descriptor enrollment. Prepared-lab
startup supplies the fixed protected socket implementation explicitly; portable
tests do not by themselves establish the Linux isolation boundary.
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
from typing import Any, Mapping, Protocol

from .ai_broker_contract import (
    ERROR_CODES,
    MAX_BODY_BYTES,
    BrokerEnrollment,
    body_digest,
    refusal,
    validate_broker_request,
)
from .ai_provider_access import ProviderReadiness
from .ai_transport import CancellationSignal, RequestCancellation
from .ai_wire import AIProviderCancelled, AIProviderTransportError
from .config import AIProviderConfig
from .util import content_hash


class BrokerChannel(Protocol):
    """Trusted composition injects one exact enrolled, bounded channel owner."""

    def exchange(
        self,
        request: Mapping[str, Any],
        *,
        cancellation: CancellationSignal,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


class BrokeredAIProviderAccess:
    def __init__(self, enrollment: BrokerEnrollment, channel: BrokerChannel) -> None:
        self._enrollment = enrollment
        self._channel = channel
        self._cancel = threading.Event()
        self._condition = threading.Condition()
        self._active = 0

    @property
    def enrollment(self) -> BrokerEnrollment:
        return self._enrollment

    def _exchange(
        self,
        config: AIProviderConfig,
        *,
        body: bytes | None,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> Mapping[str, Any]:
        self.enrollment.require_current(config)
        cancellation = RequestCancellation(self._cancel, cancel_event)
        request: dict[str, Any] = {
            "kind": "readiness" if body is None else "post",
            "session_id": self.enrollment.session_id,
            "binding_digest": self.enrollment.digest,
            "request_id": secrets.token_hex(32),
            "timeout_seconds": timeout_seconds,
        }
        if body is not None:
            if type(body) is not bytes or not 1 <= len(body) <= MAX_BODY_BYTES:
                raise refusal()
            request.update(
                body=base64.b64encode(body).decode("ascii"),
                body_digest=body_digest(body),
            )
        validate_broker_request(self.enrollment, request)
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            if cancellation.is_set():
                raise AIProviderCancelled()
            self._active += 1
        try:
            response = self._channel.exchange(
                request, cancellation=cancellation, timeout_seconds=timeout_seconds
            )
            if cancellation.is_set():
                raise AIProviderCancelled()
            if time.monotonic() >= deadline:
                raise AIProviderTransportError(
                    "Enrolled broker request timed out", retryable=True, code="request_timed_out"
                )
            self.enrollment.require_current(config)
            if not isinstance(response, Mapping) or any(
                response.get(key) != value
                for key, value in {
                    "session_id": self.enrollment.session_id,
                    "binding_digest": self.enrollment.digest,
                    "request_id": request["request_id"],
                    "request_digest": content_hash(request),
                }.items()
            ):
                raise refusal("broker_unavailable")
            common = {"kind", "session_id", "binding_digest", "request_id", "request_digest"}
            kind = response.get("kind")
            if kind == "error":
                if (
                    set(response) != common | {"code", "retryable"}
                    or response["code"] not in ERROR_CODES
                    or type(response["retryable"]) is not bool
                ):
                    raise refusal("broker_unavailable")
                if response["code"] == "request_cancelled":
                    raise AIProviderCancelled()
                raise AIProviderTransportError(
                    "Enrolled broker request failed",
                    retryable=response["retryable"],
                    code=response["code"],
                )
            expected = common | ({"credential_state"} if body is None else {"body"})
            if set(response) != expected or kind != ("readiness" if body is None else "result"):
                raise refusal("broker_unavailable")
            return dict(response)
        except AIProviderTransportError as exc:
            if exc.code == "request_cancelled":
                raise AIProviderCancelled() from None
            if not isinstance(exc.code, str) or exc.code not in ERROR_CODES:
                raise refusal("broker_unavailable") from None
            raise AIProviderTransportError(
                "Enrolled broker request failed", retryable=exc.retryable is True, code=exc.code
            ) from None
        except Exception:
            raise refusal("broker_unavailable") from None
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def readiness(self, config: AIProviderConfig) -> ProviderReadiness:
        try:
            response = self._exchange(config, body=None, timeout_seconds=1.0)
            state = response["credential_state"]
            allowed = {"not_required"} if config.api_key is None else {"ready", "unavailable"}
            if not isinstance(state, str) or state not in allowed:
                raise refusal("broker_unavailable")
            available = state != "unavailable"
            return ProviderReadiness(
                available,
                state,
                "configuration_ready" if available else "credential_unavailable",
                "Enrolled broker credential ownership checked; provider connectivity is untested.",
                "broker",
                self.enrollment.digest,
            )
        except AIProviderTransportError as exc:
            return ProviderReadiness(
                False,
                "unavailable",
                exc.code,
                "The exact enrolled broker binding is unavailable; no provider request was made.",
                "broker",
                self.enrollment.digest,
            )

    def post(
        self,
        config: AIProviderConfig,
        *,
        body: bytes,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> bytes:
        response = self._exchange(
            config, body=body, timeout_seconds=timeout_seconds, cancel_event=cancel_event
        )
        try:
            encoded = response["body"]
            if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY_BYTES:
                raise ValueError
            payload = base64.b64decode(encoded, validate=True)
            if not 1 <= len(payload) <= MAX_BODY_BYTES:
                raise ValueError
            return payload
        except (ValueError, TypeError, KeyError):
            raise refusal("broker_unavailable") from None

    def close(self) -> None:
        self._cancel.set()
        try:
            self._channel.close()
        finally:
            with self._condition:
                if not self._condition.wait_for(lambda: self._active == 0, timeout=5):
                    raise refusal("broker_unavailable")
