"""Focused lifecycle tests for the prebound Test Caido server."""

from __future__ import annotations

import threading

import pytest

from bluefire import test_caido_protocol_server as server_module
from bluefire.test_caido_protocol_provider import RuntimeState
from bluefire.test_caido_protocol_provider import TestCaidoProviderError as ProviderError


class _Listener:
    def __init__(self) -> None:
        self.closed = False

    def shutdown(self, _how: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FailCloseListener(_Listener):
    def close(self) -> None:
        self.closed = True
        raise OSError("bounded close failure")


class _Runtime:
    def __init__(self, state: RuntimeState = RuntimeState.ACTIVE) -> None:
        self.state = state
        self.cancel_calls = 0
        self.drain_calls = 0
        self.cancel_error: ProviderError | None = None

    def cancel(self) -> None:
        self.cancel_calls += 1
        if self.cancel_error is not None:
            raise self.cancel_error
        self.state = RuntimeState.REVOKED

    def drain(self) -> None:
        self.drain_calls += 1
        self.state = RuntimeState.DRAINED


class _StalledConnection:
    def __init__(self, prefix: bytes = b"") -> None:
        self._prefix = bytearray(prefix)

    def recv(self, _size: int, _flags: int = 0) -> bytes:
        if self._prefix:
            value = bytes(self._prefix[:1])
            del self._prefix[:1]
            return value
        raise TimeoutError


def _server(runtime: _Runtime, listener: _Listener | None = None):
    server = object.__new__(server_module.TestCaidoProtocolServer)
    server.runtime = runtime
    server._listener = listener or _Listener()
    server._cancelled = threading.Event()
    server._serving = threading.Event()
    server._active = set()
    server._lock = threading.RLock()
    server._closed = False
    return server


def test_partial_request_has_absolute_deadline_and_retains_only_byte_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _server(_Runtime())
    monkeypatch.setattr(server_module, "REQUEST_DEADLINE_SECONDS", 0.001)

    with pytest.raises(ProviderError, match="request_deadline") as failure:
        server._read_request(_StalledConnection(b"GET"), None)

    assert failure.value.code == "request_deadline"
    assert failure.value.byte_count == 3
    assert "GET" not in str(failure.value)


def test_cancel_closes_transport_even_when_runtime_audit_fails() -> None:
    runtime = _Runtime()
    runtime.cancel_error = ProviderError("audit_write_unknown")
    listener = _Listener()
    connection = _Listener()
    server = _server(runtime, listener)
    server._active.add(connection)

    with pytest.raises(ProviderError, match="audit_write_unknown"):
        server.cancel()

    assert server._closed is True
    assert server._listener is None
    assert listener.closed is True
    assert connection.closed is True
    assert not server._active


def test_one_close_error_does_not_leave_other_connections_active() -> None:
    runtime = _Runtime()
    listener = _FailCloseListener()
    connection = _Listener()
    server = _server(runtime, listener)
    server._active.add(connection)

    server.cancel()

    assert listener.closed is True
    assert connection.closed is True
    assert not server._active
    assert server._listener is None


def test_drain_refuses_while_serve_loop_is_still_active() -> None:
    runtime = _Runtime()
    server = _server(runtime)
    server._serving.set()

    with pytest.raises(ProviderError, match="drain_pending"):
        server.drain()

    assert runtime.cancel_calls == 1
    assert runtime.drain_calls == 0


def test_nonactive_runtime_closes_admission_without_accepting() -> None:
    runtime = _Runtime(RuntimeState.REVOKED)
    listener = _Listener()
    server = _server(runtime, listener)

    server.serve_forever()

    assert runtime.cancel_calls == 0
    assert server._closed is True
    assert listener.closed is True
    assert not server._serving.is_set()
