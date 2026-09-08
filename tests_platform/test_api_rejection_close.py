from __future__ import annotations

import io
import json
import socket
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.api as api_module
from tests_platform.test_api import running_server


@pytest.mark.parametrize(
    ("duplicate", "status", "code"),
    [
        ("Origin", 403, "origin_rejected"),
        ("Content-Length", 400, "invalid_length"),
        ("Content-Type", 415, "content_type_required"),
    ],
)
def test_rejection_reaches_client_before_delayed_body_and_closes_without_dispatch(
    duplicate: str, status: int, code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    receive_or_close = threading.Event()
    body_sent = threading.Event()
    original_finish = api_module.BlueFireRequestHandler._finish_rejected_request

    def finish_after_client_observes_response(handler: Any) -> None:
        connection = handler.connection

        class ScheduledPeer:
            def __getattr__(self, name: str) -> Any:
                return getattr(connection, name)

            def recv(self, size: int) -> bytes:
                # Coordinate the late send without relying on a 200 ms scheduler
                # window. Reads and half-close still use the real TCP connection.
                receive_or_close.set()
                if not body_sent.wait(3):
                    raise TimeoutError("test client did not release the late body")
                return connection.recv(size)

        handler.connection = ScheduledPeer()
        try:
            original_finish(handler)
        finally:
            handler.connection = connection

    monkeypatch.setattr(
        api_module.BlueFireRequestHandler,
        "_finish_rejected_request",
        finish_after_client_observes_response,
    )
    with running_server() as (server, service):
        with socket.create_connection(server.server_address, timeout=3) as client:
            closed = threading.Event()
            peer = client.getsockname()
            original_shutdown = server.shutdown_request

            def shutdown_request(request: Any) -> None:
                selected = request.getpeername() == peer
                original_shutdown(request)
                if selected:
                    closed.set()
                    receive_or_close.set()

            monkeypatch.setattr(server, "shutdown_request", shutdown_request)
            authority = f"127.0.0.1:{server.server_address[1]}"
            headers = {
                "Host": authority,
                "Origin": f"http://{authority}",
                "Cookie": server._test_browser_cookie,
                "Content-Length": "2",
                "Content-Type": "application/json",
            }
            lines = ["POST /api/v1/scenarios/validate HTTP/1.1"]
            for name, value in headers.items():
                lines.append(f"{name}: {value}")
                if name == duplicate:
                    lines.append(f"{name}: {value}")
            client.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            with client.makefile("rb") as response:
                assert response.readline().split()[1] == str(status).encode("ascii")
                response_headers = {}
                while (line := response.readline()) != b"\r\n":
                    assert line
                    name, value = line.decode("ascii").split(":", 1)
                    response_headers[name.lower()] = value.strip()
                body = response.read(int(response_headers["content-length"]))
                assert json.loads(body)["error"]["code"] == code
                assert response_headers["connection"] == "close"
                # The response is complete without waiting for the declared body.
                # The receive side stays open briefly for a separately sent body.
                assert receive_or_close.wait(1)
                assert not closed.is_set()
                client.sendall(
                    b"{}GET /api/v1/catalog HTTP/1.1\r\nHost: "
                    + authority.encode("ascii")
                    + b"\r\nCookie: "
                    + server._test_browser_cookie.encode("ascii")
                    + b"\r\n\r\n"
                )
                client.shutdown(socket.SHUT_WR)
                body_sent.set()
                assert response.read() == b""
                assert closed.wait(1)
        assert service.calls == []


def test_rejected_peer_cannot_hold_connection_open_by_withholding_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with running_server(authenticate=False) as (server, service):
        closed = threading.Event()
        original_shutdown = server.shutdown_request

        def shutdown_request(request: Any) -> None:
            original_shutdown(request)
            closed.set()

        monkeypatch.setattr(server, "shutdown_request", shutdown_request)
        with socket.create_connection(server.server_address, timeout=3) as client:
            authority = f"127.0.0.1:{server.server_address[1]}"
            client.sendall(
                (
                    "POST /api/v1/scenarios/validate HTTP/1.1\r\n"
                    f"Host: {authority}\r\nOrigin: http://{authority}\r\n"
                    f"Origin: http://{authority}\r\nContent-Length: 999999999\r\n\r\n"
                ).encode("ascii")
            )
            with client.makefile("rb") as response:
                reply = response.read()
            assert reply.startswith(b"HTTP/1.1 403 ")
            assert b'"code":"origin_rejected"' in reply
            assert closed.wait(1)
        assert service.calls == []


@pytest.mark.parametrize("limit", ["bytes", "deadline", "disconnect"])
def test_rejection_cleanup_has_absolute_limits_without_trusting_body_framing(
    limit: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [10.0]
    received = [0]
    timeouts = []
    half_closed = []

    class Peer:
        def shutdown(self, how: int) -> None:
            assert how == socket.SHUT_WR
            half_closed.append(True)

        def settimeout(self, timeout: float) -> None:
            assert 0 < timeout <= api_module._REJECTION_CLOSE_SECONDS
            timeouts.append(timeout)

        def recv(self, size: int) -> bytes:
            assert half_closed
            if limit == "disconnect":
                raise ConnectionResetError("peer gone")
            received[0] += size
            if limit == "deadline":
                clock[0] += 0.051
            return b"x" * size

    monkeypatch.setattr(api_module.time, "monotonic", lambda: clock[0])
    handler = SimpleNamespace(connection=Peer(), wfile=io.BytesIO())
    api_module.BlueFireRequestHandler._finish_rejected_request(handler)
    assert half_closed == [True]
    if limit == "bytes":
        assert received[0] == api_module._REJECTION_DISCARD_BYTES
    elif limit == "deadline":
        assert received[0] < api_module._REJECTION_DISCARD_BYTES
        assert len(timeouts) == 4
        assert timeouts[-1] < timeouts[0]
    else:
        assert received[0] == 0
