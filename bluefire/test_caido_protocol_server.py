"""Prebound-listener server for the deterministic Test Caido wire provider.

The controller supplies the only socket this module can use.  This module
never creates, binds, connects, listens on, or discovers a socket endpoint.
"""

from __future__ import annotations

import os
import re
import select
import socket
import sys
import threading
import time
from dataclasses import dataclass, field

from .test_caido_protocol_provider import (
    DRAIN_SCHEMA,
    LISTENER_HOST,
    LISTENER_PORT,
    LIVE_CAIDO_PROOF,
    MAX_BODY_BYTES,
    MAX_CONNECTIONS,
    MAX_HEADER_BYTES,
    SO_NETNS_COOKIE,
    TEST_PROVIDER,
    RuntimeState,
    TestCaidoProtocolRuntime,
    TestCaidoProviderError,
    _http_response,
)

REQUEST_DEADLINE_SECONDS = 5.0


class _PartialRequestError(TestCaidoProviderError):
    """Stable refusal retaining only the number of admitted bytes."""

    def __init__(self, code: str, byte_count: int) -> None:
        super().__init__(code)
        self.byte_count = byte_count


@dataclass(frozen=True, slots=True)
class TestCaidoDrainReceipt:
    attempt_id: str
    provider_identity_ref: str
    listener_absent: bool
    bearer_absent: bool
    project_state_absent: bool
    state: RuntimeState
    schema_version: str = DRAIN_SCHEMA
    test_provider: bool = TEST_PROVIDER
    live_caido_proof: bool = LIVE_CAIDO_PROOF
    target_cleanup_verified: bool = field(default=False, init=False)


class TestCaidoProtocolServer:
    """Adopt and serve one prebound numeric loopback listener."""

    def __init__(
        self,
        runtime: TestCaidoProtocolRuntime,
        listener: socket.socket,
    ) -> None:
        if type(runtime) is not TestCaidoProtocolRuntime or not isinstance(listener, socket.socket):
            raise TestCaidoProviderError("server_binding_invalid")
        self.runtime = runtime
        self._listener: socket.socket | None = listener
        self._binding = runtime.manifest.binding
        self._cancelled = threading.Event()
        self._serving = threading.Event()
        self._active: set[socket.socket] = set()
        self._lock = threading.RLock()
        self._closed = False
        self._verify_listener()

    def _verify_listener(self) -> None:
        listener = self._listener
        if listener is None or sys.platform != "linux":
            raise TestCaidoProviderError("listener_custody_invalid")
        try:
            info = os.fstat(listener.fileno())
            local = listener.getsockname()
            accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            cookie_bytes = listener.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8)
            listener.set_inheritable(False)
            listener.settimeout(0.05)
        except OSError:
            raise TestCaidoProviderError("listener_custody_invalid") from None
        if (
            listener.family != socket.AF_INET
            or listener.type != socket.SOCK_STREAM
            or tuple(local[:2]) != (LISTENER_HOST, LISTENER_PORT)
            or accepting != 1
            or info.st_dev != self._binding.listener_device
            or info.st_ino != self._binding.listener_inode
            or len(cookie_bytes) != 8
            or int.from_bytes(cookie_bytes, sys.byteorder) != self._binding.netns_cookie
            or listener.get_inheritable()
        ):
            raise TestCaidoProviderError("listener_custody_invalid")

    def serve_forever(self, stop: threading.Event | None = None) -> None:
        """Serve until cancelled or the controller's signal event is set."""

        with self._lock:
            if self._closed or self._serving.is_set():
                raise TestCaidoProviderError("server_state_refused")
            self._serving.set()
        try:
            while (
                not self._cancelled.is_set()
                and (stop is None or not stop.is_set())
                and self.runtime.state is RuntimeState.ACTIVE
            ):
                listener = self._listener
                if listener is None:
                    break
                try:
                    connection, peer = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if not self._cancelled.is_set():
                        self._retain_refusal("listener_unknown", 0)
                    break
                if peer[0] != LISTENER_HOST:
                    connection.close()
                    self._retain_refusal("peer_refused", 0)
                    continue
                with self._lock:
                    if len(self._active) >= MAX_CONNECTIONS:
                        connection.close()
                        self._retain_refusal("connection_bound", 0)
                        continue
                    try:
                        connection.set_inheritable(False)
                        connection.settimeout(0.25)
                    except OSError:
                        try:
                            connection.close()
                        except OSError:
                            pass
                        self._retain_refusal("connection_setup_unknown", 0)
                        continue
                    self._active.add(connection)
                try:
                    raw = self._read_request(connection, stop)
                    try:
                        response = self.runtime.handle(raw)
                    except TestCaidoProviderError as error:
                        response = _http_response(
                            400,
                            "Bad Request",
                            {
                                "error": {"code": error.code},
                                "test_provider": True,
                                "live_caido_proof": False,
                            },
                        )
                    connection.sendall(response)
                except (OSError, TestCaidoProviderError) as error:
                    if isinstance(error, TestCaidoProviderError):
                        self._retain_refusal(error.code, getattr(error, "byte_count", 0))
                finally:
                    with self._lock:
                        self._active.discard(connection)
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        connection.close()
                    except OSError:
                        pass
        finally:
            try:
                if self.runtime.state is RuntimeState.ACTIVE:
                    self.runtime.cancel()
            finally:
                try:
                    self._close_transport()
                finally:
                    self._serving.clear()

    def _retain_refusal(self, code: str, byte_count: int) -> None:
        try:
            self.runtime.record_refusal(code, byte_count)
        except TestCaidoProviderError:
            pass

    def _read_request(self, connection: socket.socket, stop: threading.Event | None) -> bytes:
        deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            if self._cancelled.is_set() or (stop is not None and stop.is_set()):
                raise _PartialRequestError("state_refused", len(head))
            if time.monotonic() >= deadline:
                raise _PartialRequestError("request_deadline", len(head))
            if len(head) >= MAX_HEADER_BYTES + 4:
                raise _PartialRequestError("message_bound", len(head))
            try:
                block = connection.recv(1)
            except TimeoutError:
                continue
            if not block:
                raise _PartialRequestError("framing_invalid", len(head))
            head.extend(block)
        lengths: list[bytes] = []
        for line in bytes(head[:-4]).split(b"\r\n")[1:]:
            name, delimiter, value = line.partition(b":")
            if delimiter and name.lower() == b"content-length":
                lengths.append(value.strip())
        if len(lengths) > 1 or (lengths and not re.fullmatch(rb"0|[1-9][0-9]{0,4}", lengths[0])):
            raise _PartialRequestError("length_invalid", len(head))
        length = 0 if not lengths else int(lengths[0])
        if length > MAX_BODY_BYTES:
            raise _PartialRequestError("message_bound", len(head))
        body = bytearray()
        while len(body) < length:
            if self._cancelled.is_set() or (stop is not None and stop.is_set()):
                raise _PartialRequestError("state_refused", len(head) + len(body))
            if time.monotonic() >= deadline:
                raise _PartialRequestError("request_deadline", len(head) + len(body))
            try:
                block = connection.recv(min(8192, length - len(body)))
            except TimeoutError:
                continue
            if not block:
                raise _PartialRequestError("framing_invalid", len(head) + len(body))
            body.extend(block)
        readable, _, _ = select.select([connection], [], [], 0)
        if readable and connection.recv(1, socket.MSG_PEEK):
            raise _PartialRequestError("pipelining_refused", len(head) + len(body))
        return bytes(head + body)

    def _close_transport(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cancelled.set()
            listener, self._listener = self._listener, None
            if listener is not None:
                try:
                    listener.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    listener.close()
                except OSError:
                    pass
            for connection in tuple(self._active):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass
            self._active.clear()

    def cancel(self) -> None:
        try:
            self.runtime.cancel()
        finally:
            self._close_transport()

    def drain(self) -> TestCaidoDrainReceipt:
        self.cancel()
        if self._serving.is_set() or self._active:
            raise TestCaidoProviderError("drain_pending")
        self.runtime.drain()
        return TestCaidoDrainReceipt(
            self._binding.attempt_id,
            self.runtime.provider_identity_ref,
            listener_absent=self._listener is None,
            bearer_absent=True,
            project_state_absent=True,
            state=self.runtime.state,
        )
