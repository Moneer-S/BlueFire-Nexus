"""Destination resolution and TLS assertions without DNS, sockets or provider calls."""

from __future__ import annotations

import socket
import ssl
import urllib.request

import pytest

from bluefire import _ai_transport_worker as worker
from bluefire.ai_transport import ManagedAIJSONTransport
from bluefire.ai_wire import AIProviderTransportError


def address(value, *, protocol=socket.IPPROTO_TCP):
    family = socket.AF_INET6 if ":" in value else socket.AF_INET
    return (
        family,
        socket.SOCK_STREAM,
        protocol,
        "",
        (value, 443, 0, 0) if family == socket.AF_INET6 else (value, 443),
    )


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "ff02::1",
        "fc00::1",
        "::ffff:127.0.0.1",
    ],
)
def test_public_policy_refuses_any_nonpublic_answer_before_connect(monkeypatch, ip):
    monkeypatch.setattr(
        worker.socket, "getaddrinfo", lambda *_a, **_k: [address("8.8.8.8"), address(ip)]
    )
    monkeypatch.setattr(
        worker.socket,
        "socket",
        lambda *_a: pytest.fail("no connection before complete destination validation"),
    )
    with pytest.raises(ValueError, match="destination resolution refused"):
        worker._pinned_opener("https://provider.example/v1/response", "public_https")


def test_tls_connects_only_resolved_address_and_keeps_original_hostname_verification(monkeypatch):
    resolutions, connections, tls = [], [], []

    def resolve(host, port, **kwargs):
        resolutions.append((host, port, kwargs))
        return [address("8.8.8.8")]

    class Socket:
        def settimeout(self, timeout):
            assert 0 < timeout <= 2

        def connect(self, destination):
            connections.append(destination)

        def close(self):
            pass

    monkeypatch.setattr(worker.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(worker.socket, "socket", lambda *_a: Socket())

    def do_open(_handler, connection_class, request, **kwargs):
        connection = connection_class(request.host, timeout=2, **kwargs)
        context = connection._context
        assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED

        class CheckedContext:
            def wrap_socket(self, endpoint, *, server_hostname):
                tls.append(server_hostname)
                return endpoint

        connection._context = CheckedContext()
        connection.connect()
        return connection

    monkeypatch.setattr(urllib.request.HTTPSHandler, "do_open", do_open)
    opener = worker._pinned_opener("https://provider.example/v1/response", "public_https")
    handler = next(
        item for item in opener.handlers if isinstance(item, urllib.request.HTTPSHandler)
    )
    handler.https_open(urllib.request.Request("https://provider.example/v1/response"))
    assert len(resolutions) == 1 and resolutions[0][:2] == ("provider.example", 443)
    assert connections == [("8.8.8.8", 443)] and tls == ["provider.example"]


def test_explicit_endpoint_allows_enrolled_local_tls_but_not_url_credentials(monkeypatch):
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_a, **_k: [address("127.0.0.1")])
    assert worker._pinned_opener("https://local-provider.example/v1/response", "explicit_endpoint")
    with pytest.raises(ValueError):
        worker._pinned_opener(
            "https://injected:credential@local-provider.example/v1/response", "explicit_endpoint"
        )


def test_managed_transport_refuses_changed_endpoint_before_spawning(monkeypatch):
    monkeypatch.setattr(
        "bluefire.ai_transport.subprocess.Popen",
        lambda *_a, **_k: pytest.fail("must refuse before process creation"),
    )
    transport = ManagedAIJSONTransport(
        enrolled_endpoint="http://127.0.0.1:8080/v1/fixed", destination_policy="explicit_endpoint"
    )
    try:
        with pytest.raises(AIProviderTransportError, match="not enrolled"):
            transport.post(
                "http://127.0.0.1:9999/v1/other", headers={}, body=b"{}", timeout_seconds=1
            )
    finally:
        transport.close()
