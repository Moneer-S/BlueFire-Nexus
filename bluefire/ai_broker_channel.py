"""Bounded inference frames over one explicitly supplied private socket."""

from __future__ import annotations

import json
import select
import socket
import struct
import threading
import time
from typing import Any, Mapping

from .ai_broker_contract import MAX_BODY_BYTES, _nonfinite, _pairs, refusal
from .ai_transport import CancellationSignal
from .ai_wire import AIProviderCancelled, AIProviderTransportError
from .util import canonical_json_bytes, content_hash

FRAME_LIMIT = 2 * MAX_BODY_BYTES + 4096


class FramedSocket:
    """Retain partial reads across cancellation; never consume the following frame."""

    def __init__(self, endpoint: socket.socket) -> None:
        self.endpoint = endpoint
        self.endpoint.setblocking(False)
        self.endpoint.set_inheritable(False)
        self.pending = bytearray()
        self.expected: int | None = None

    def _wait(
        self, writing: bool, deadline: float, cancellation: CancellationSignal | None
    ) -> None:
        while True:
            if cancellation is not None and cancellation.is_set():
                raise AIProviderCancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise refusal("request_timed_out")
            readable, writable, _ = select.select(
                [] if writing else [self.endpoint],
                [self.endpoint] if writing else [],
                [],
                min(remaining, 0.025),
            )
            if readable or writable:
                return

    def send(
        self,
        value: Mapping[str, Any],
        *,
        deadline: float,
        cancellation: CancellationSignal | None = None,
    ) -> None:
        body = canonical_json_bytes(value)
        if not 1 <= len(body) <= FRAME_LIMIT:
            raise refusal("request_too_large")
        remaining = memoryview(struct.pack("!I", len(body)) + body)
        while remaining:
            self._wait(True, deadline, cancellation)
            try:
                count = self.endpoint.send(remaining)
            except BlockingIOError:
                continue
            if count <= 0:
                raise refusal("broker_unavailable")
            remaining = remaining[count:]

    def receive(
        self, *, deadline: float, cancellation: CancellationSignal | None = None
    ) -> Mapping[str, Any]:
        while True:
            target = 4 if self.expected is None else self.expected
            if len(self.pending) == target:
                if self.expected is None:
                    self.expected = struct.unpack("!I", self.pending)[0]
                    self.pending.clear()
                    if not 1 <= self.expected <= FRAME_LIMIT:
                        raise refusal("response_too_large")
                    continue
                encoded = bytes(self.pending)
                self.pending.clear()
                self.expected = None
                try:
                    value = json.loads(
                        encoded.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite
                    )
                    if not isinstance(value, dict):
                        raise ValueError
                    return value
                except (ValueError, UnicodeError, RecursionError):
                    raise refusal("broker_unavailable") from None
            self._wait(False, deadline, cancellation)
            try:
                block = self.endpoint.recv(min(65536, target - len(self.pending)))
            except BlockingIOError:
                continue
            if not block:
                raise EOFError("Private inference channel closed")
            self.pending.extend(block)

    def close(self) -> None:
        try:
            self.endpoint.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.endpoint.close()


def cancel_frame(request: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "kind": "cancel",
        "session_id": request["session_id"],
        "binding_digest": request["binding_digest"],
        "request_id": request["request_id"],
        "request_digest": content_hash(request),
    }


def response_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "session_id": request["session_id"],
        "binding_digest": request["binding_digest"],
        "request_id": request["request_id"],
        "request_digest": content_hash(request),
    }


class SocketBrokerChannel:
    """One framed request at a time; no endpoint lookup, FD discovery or reconnect."""

    def __init__(self, endpoint: socket.socket) -> None:
        self.stream = FramedSocket(endpoint)
        self.guard = threading.Lock()
        self.closed = threading.Event()

    def exchange(
        self,
        request: Mapping[str, Any],
        *,
        cancellation: CancellationSignal,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            if self.closed.is_set() or cancellation.is_set():
                raise AIProviderCancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise refusal("request_timed_out")
            if self.guard.acquire(timeout=min(remaining, 0.025)):
                break
        try:
            if self.closed.is_set() or cancellation.is_set():
                raise AIProviderCancelled()
            try:
                self.stream.send(request, deadline=deadline, cancellation=cancellation)
            except AIProviderCancelled:
                # A cancelled partial request has no safe next frame boundary.
                self.close()
                raise
            try:
                return self.stream.receive(deadline=deadline, cancellation=cancellation)
            except AIProviderCancelled:
                # Finish this exact exchange before the next request may enter.
                cleanup_deadline = time.monotonic() + 5.0
                self.stream.send(cancel_frame(request), deadline=cleanup_deadline)
                result = self.stream.receive(deadline=cleanup_deadline)
                if any(
                    result.get(key) != value for key, value in response_binding(request).items()
                ):
                    raise refusal("broker_unavailable") from None
                raise
        except AIProviderCancelled:
            raise
        except AIProviderTransportError:
            self.close()
            if cancellation.is_set():
                raise AIProviderCancelled() from None
            raise
        except Exception:
            # Partial writes, EOF and malformed frames cannot be safely resumed.
            self.close()
            if cancellation.is_set():
                raise AIProviderCancelled() from None
            raise refusal("broker_unavailable") from None
        finally:
            self.guard.release()

    def close(self) -> None:
        self.closed.set()
        self.stream.close()
