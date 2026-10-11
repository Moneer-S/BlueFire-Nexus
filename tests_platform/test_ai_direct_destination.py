"""Direct requests use the same DNS boundary as enrolled broker requests."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import _ai_transport_worker as worker
from bluefire.ai_transport import UrllibAIJSONTransport
from bluefire.config import AIProviderKind
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from tests_platform.test_ai_broker_destination import address
from tests_platform.test_ai_live_authorization import request as authorization_request
from tests_platform.test_ai_wire_runtime import _provider_config


def document(url="https://provider.example/v1/response"):
    return {"url": url, "headers": {}, "body": "e30=", "timeout_seconds": 2}


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "fec0::1",
        "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ],
)
@pytest.mark.parametrize("mixed", [False, True])
def test_default_direct_request_refuses_nonpublic_dns_before_socket(monkeypatch, ip, mixed):
    answers = ([address("8.8.8.8")] if mixed else []) + [address(ip)]
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_a, **_k: answers)
    monkeypatch.setattr(
        worker.socket, "socket", lambda *_a, **_k: pytest.fail("no socket for refused DNS")
    )
    assert worker.perform_request(document()) == {
        "ok": False,
        "code": "transport_failed",
        "retryable": False,
    }


def test_default_direct_request_resolves_once_and_preserves_tls_identity(monkeypatch):
    resolutions, connected, names = [], [], []

    def resolve(host, port, **kwargs):
        resolutions.append((host, port))
        assert len(resolutions) == 1
        return [address("8.8.8.8")]

    class Socket:
        def settimeout(self, timeout):
            assert 0 < timeout <= 2

        def connect(self, destination):
            connected.append(destination)

        def close(self):
            pass

    class Response:
        status = 200
        code = 200
        msg = "OK"
        headers = SimpleNamespace(get_content_type=lambda: "application/json")

        def info(self):
            return self.headers

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            assert limit == worker.MAX_BYTES + 1
            return b"{}"

    def do_open(_handler, connection_class, request, **kwargs):
        connection = connection_class(request.host, timeout=2, **kwargs)
        assert connection._context.check_hostname is True
        assert connection._context.verify_mode == ssl.CERT_REQUIRED

        def wrap_socket(endpoint, *, server_hostname):
            names.append(server_hostname)
            return endpoint

        connection._context = SimpleNamespace(wrap_socket=wrap_socket)
        connection.connect()
        return Response()

    monkeypatch.setattr(worker.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(worker.socket, "socket", lambda *_a, **_k: Socket())
    monkeypatch.setattr(urllib.request.HTTPSHandler, "do_open", do_open)
    assert worker.perform_request(document()) == {"ok": True, "body": "e30="}
    assert resolutions == [("provider.example", 443)]
    assert connected == [("8.8.8.8", 443)]
    assert names == ["provider.example"]


@pytest.mark.parametrize("policy", [None, "explicit_endpoint"])
def test_localhost_cannot_resolve_outside_loopback(monkeypatch, policy):
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_a, **_k: [address("10.1.2.3")])
    monkeypatch.setattr(
        worker.socket, "socket", lambda *_a, **_k: pytest.fail("no socket outside loopback")
    )
    payload = document("https://localhost/v1/response")
    if policy is not None:
        payload["destination_policy"] = policy
    assert worker.perform_request(payload)["ok"] is False


def test_authorized_service_direct_route_rejects_private_dns(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv("TEST_PROVIDER_KEY", uuid.uuid4().hex)

    def post(transport, url, *, headers, body, timeout_seconds):
        payload = dict(document(url), headers=dict(headers), body=base64.b64encode(body).decode())
        if transport.destination_policy is not None:
            payload["destination_policy"] = transport.destination_policy
        calls.append(payload)
        return transport._decode_result(json.dumps(worker.perform_request(payload)).encode())

    monkeypatch.setattr(UrllibAIJSONTransport, "post", post)
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_a, **_k: [address("127.0.0.1")])
    monkeypatch.setattr(
        worker.socket, "socket", lambda *_a, **_k: pytest.fail("service must not connect")
    )
    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
    )
    provider = replace(
        _provider_config(AIProviderKind.OPENAI_RESPONSES, authenticated=True),
        endpoint="https://provider.example/v1/response",
        max_retries=0,
    )
    try:
        service.authorize_ai(authorization_request(provider, local_endpoint_authorized=False))
        result = service.check_ai_provider({"provider": provider.to_dict(), "connect": True})
        assert result["connectivity"] == "failed"
        assert result["code"] == "transport_failed"
        assert len(calls) == 1
    finally:
        service.close()
