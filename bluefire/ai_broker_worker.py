"""Fixed enrolled provider service; no caller URL, headers or credential imports."""

from __future__ import annotations

import base64
import threading
import time
from typing import Any, Mapping

from .ai_broker_channel import FramedSocket, cancel_frame, response_binding
from .ai_broker_contract import ERROR_CODES, BrokerEnrollment, refusal, validate_broker_request
from .ai_provider_access import DirectAIProviderAccess
from .ai_transport import ManagedAIJSONTransport
from .ai_wire import AIProviderTransportError, credential_value


def serve_broker(
    stream: FramedSocket,
    enrollment: BrokerEnrollment,
    credential: str | None,
    *,
    transport: ManagedAIJSONTransport,
    stop: threading.Event,
) -> None:
    """The bootstrap owner supplies enrollment and credential once, before serving."""
    config = enrollment.config
    environment = {config.api_key.env: credential} if config.api_key and credential else {}
    if credential is not None and (
        config.api_key is None or credential_value(config, environment) != credential
    ):
        raise refusal("credential_unavailable")
    access = DirectAIProviderAccess(transport=transport, environ=environment)
    active: Mapping[str, Any] | None = None
    previous: Mapping[str, Any] | None = None
    completed: list[Mapping[str, Any]] = []
    cancelled = threading.Event()
    finished = threading.Event()
    thread: threading.Thread | None = None
    seen: set[str] = set()
    partial_started: float | None = None

    def perform(request: Mapping[str, Any], body: bytes) -> None:
        result = response_binding(request)
        try:
            payload = access.post(
                config,
                body=body,
                timeout_seconds=float(request["timeout_seconds"]),
                cancel_event=cancelled,
            )
            result.update(kind="result", body=base64.b64encode(payload).decode("ascii"))
        except AIProviderTransportError as exc:
            code = (
                exc.code
                if isinstance(exc.code, str) and exc.code in ERROR_CODES
                else "broker_unavailable"
            )
            result.update(kind="error", code=code, retryable=exc.retryable is True)
        except Exception:
            result.update(kind="error", code="broker_unavailable", retryable=False)
        finally:
            completed.append(result)
            finished.set()

    try:
        while not stop.is_set():
            enrollment.require_current(config)
            session_remaining = (enrollment.expires_at_ms - time.time_ns() // 1_000_000) / 1000
            if active is not None and finished.is_set():
                if thread is None:
                    raise refusal("broker_unavailable")
                thread.join(timeout=1.0)
                if thread.is_alive() or len(completed) != 1:
                    raise refusal("broker_unavailable")
                stream.send(
                    completed.pop(), deadline=time.monotonic() + min(1.0, session_remaining)
                )
                previous, active, thread = active, None, None
            try:
                frame = stream.receive(deadline=time.monotonic() + min(0.05, session_remaining))
                partial_started = None
            except AIProviderTransportError as exc:
                if exc.code != "request_timed_out":
                    raise
                if stream.pending or stream.expected is not None:
                    partial_started = partial_started or time.monotonic()
                    if time.monotonic() - partial_started >= 5.0:
                        raise refusal("broker_unavailable") from None
                continue
            if frame.get("kind") == "cancel":
                if active is not None and dict(frame) == cancel_frame(active):
                    cancelled.set()
                elif previous is None or dict(frame) != cancel_frame(previous):
                    raise refusal()
                continue
            body = validate_broker_request(enrollment, frame)
            request_id = str(frame["request_id"])
            if active is not None or request_id in seen or len(seen) >= 4096:
                raise refusal()
            seen.add(request_id)
            if body is None:
                state = access.readiness(config)
                stream.send(
                    {
                        "kind": "readiness",
                        **response_binding(frame),
                        "credential_state": state.credential_state,
                    },
                    deadline=time.monotonic() + min(1.0, session_remaining),
                )
                previous = frame
                continue
            cancelled = threading.Event()
            finished = threading.Event()
            active = frame
            thread = threading.Thread(
                target=perform, args=(frame, body), name="bluefire-broker-request"
            )
            thread.start()
    except EOFError:
        pass
    finally:
        cancelled.set()
        try:
            access.close()
        finally:
            try:
                if thread is not None:
                    thread.join(timeout=5.0)
                    if thread.is_alive():
                        raise refusal("broker_unavailable")
            finally:
                stream.close()
