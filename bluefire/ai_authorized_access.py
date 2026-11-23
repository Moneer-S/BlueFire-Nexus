"""Service-owned consent boundary shared by ordinary direct and prepared-lab calls."""

from __future__ import annotations

import math
import threading
import uuid
from typing import Any, Mapping

from . import product_store_ai_authorizations as persistence
from .ai_live_authorization import create_authorization, now_ms, refused, request_reservation
from .ai_provider_access import AIProviderAccess, ProviderReadiness
from .ai_transport import CancellationSignal, RequestCancellation
from .ai_wire import AIProviderCancelled, AIProviderTransportError
from .config import AIProviderConfig, AIProviderKind
from .util import content_hash


class AuthorizedAIProviderAccess:
    def __init__(self, access: AIProviderAccess, store: persistence.AuthorizationStore) -> None:
        self.access, self.store = access, store
        self._lock = threading.RLock()
        self._closed = False
        self._active: dict[str, set[threading.Event]] = {}
        persistence.invalidate_prior_session(store)
        enrollment = getattr(access, "enrollment", None)
        self.context: dict[str, Any] = (
            {
                "kind": "broker",
                "binding_digest": enrollment.digest,
                "expires_at_ms": enrollment.expires_at_ms,
                "provider": enrollment.config.to_dict(),
            }
            if enrollment is not None
            else {
                "kind": "direct",
                "binding_digest": content_hash({"service_session": uuid.uuid4().hex}),
                "expires_at_ms": None,
                "provider": None,
            }
        )

    def list(self) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.ai-live-authorizations.v1",
            "context": dict(self.context),
            "authorizations": persistence.list_authorizations(
                self.store, self.context["binding_digest"]
            ),
        }

    def authorize(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._lock:
            if self._closed:
                raise refused("live_context_unavailable")
            grant = create_authorization(request, self.context)
            for row in persistence.list_authorizations(self.store, self.context["binding_digest"]):
                if row["provider"]["id"] == grant["provider"]["id"]:
                    for event in self._active.get(row["authorization_id"], ()):
                        event.set()
            # Persist first. A broker refusal revokes this decision; it never silently becomes direct.
            saved = persistence.save_authorization(self.store, grant)
            try:
                if self.context["kind"] == "broker":
                    self.access.authorize_live(grant)  # type: ignore[attr-defined]
            except BaseException:
                persistence.revoke_authorization(
                    self.store, grant["authorization_id"], self.context["binding_digest"]
                )
                self._closed = True
                self.access.close()
                raise
            return {"authorization": saved}

    def revoke(self, authorization_id: str) -> Mapping[str, Any]:
        with self._lock:
            record = persistence.revoke_authorization(
                self.store, authorization_id, self.context["binding_digest"]
            )
            for event in self._active.get(authorization_id, ()):
                event.set()
            if self.context["kind"] == "broker":
                try:
                    self.access.revoke_live(authorization_id)  # type: ignore[attr-defined]
                except BaseException:
                    self._closed = True
                    self.access.close()
                    raise
            return {"authorization": record}

    def readiness(self, config: AIProviderConfig) -> ProviderReadiness:
        readiness = self.access.readiness(config)
        if config.kind is AIProviderKind.DETERMINISTIC or not readiness.available:
            return readiness
        try:
            if self._closed:
                raise refused("live_context_unavailable")
            persistence.current_authorization(
                self.store, content_hash(config.to_dict()), self.context["binding_digest"]
            )
        except AIProviderTransportError as exc:
            return ProviderReadiness(
                False,
                readiness.credential_state,
                exc.code,
                "Configuration is available; authorize the reviewed model data and usage before sending requests.",
                readiness.source,
                readiness.binding_digest,
                readiness.lab_session_expires_at_ms,
            )
        return readiness

    def post(
        self,
        config: AIProviderConfig,
        *,
        body: bytes,
        timeout_seconds: float,
        cancel_event: CancellationSignal | None = None,
    ) -> bytes:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= config.timeout_seconds
        ):
            raise refused("live_request_out_of_scope")
        with self._lock:
            if self._closed or (cancel_event is not None and cancel_event.is_set()):
                raise AIProviderCancelled()
            row = persistence.current_authorization(
                self.store, content_hash(config.to_dict()), self.context["binding_digest"]
            )
            grant = {key: value for key, value in row.items() if key not in {"status", "usage"}}
            reservation = request_reservation(config, body, grant)
            persistence.reserve(
                self.store, grant["authorization_id"], self.context["binding_digest"], reservation
            )
            cancelled = threading.Event()
            self._active.setdefault(grant["authorization_id"], set()).add(cancelled)
            remaining = (grant["expires_at_ms"] - now_ms()) / 1000
            timer = threading.Timer(max(0, remaining), cancelled.set)
            timer.daemon = True
            timer.start()
            # No refund: timeout, invalid responses and cancellation may still have incurred work.
        try:
            cancellation = RequestCancellation(cancelled, cancel_event)
            if cancellation.is_set() or remaining <= 0:
                raise AIProviderCancelled()
            result = self.access.post(
                config,
                body=body,
                timeout_seconds=min(timeout_seconds, remaining),
                cancel_event=cancellation,
            )
            if cancellation.is_set():
                raise AIProviderCancelled()
            return result
        finally:
            timer.cancel()
            with self._lock:
                self._active[grant["authorization_id"]].discard(cancelled)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for events in self._active.values():
                for event in events:
                    event.set()
        self.access.close()
