from __future__ import annotations

import ipaddress
import json
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from bluefire import ai_transport
from bluefire.ai_probe import check_provider
from bluefire.ai_transport import UrllibAIJSONTransport
from bluefire.ai_wire import AIProviderTransportError
from bluefire.config import AIProviderKind
from tests_platform.test_ai_wire_runtime import _envelope, _provider_config


@pytest.fixture
def workers(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[subprocess.Popen[bytes]]]:
    processes: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def capture(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        assert args[0][0] == getattr(sys, "_base_executable", sys.executable)
        assert "test-only-value" not in repr(args)
        assert "test-only-value" not in repr(kwargs.get("env"))
        assert kwargs["shell"] is False
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setenv("UNRELATED_TEST_SECRET", "test-only-value")
    monkeypatch.setattr(ai_transport.subprocess, "Popen", capture)
    yield processes
    for process in processes:
        assert process.poll() is not None, "HTTP worker survived request completion"
        reader = getattr(process, "stdout_thread", None) or getattr(process, "_stdout_thread", None)
        if reader is not None:
            assert not reader.is_alive(), "HTTP pipe reader survived request completion"
        assert process.stdout is None or process.stdout.closed
    assert not any(thread.name == "bluefire-ai-request-writer" for thread in threading.enumerate())


@pytest.fixture
def endpoint() -> Iterator[tuple[str, threading.Event, list[str]]]:
    stopped = threading.Event()
    entered = threading.Event()
    paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            self.connection.settimeout(2)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            paths.append(self.path)
            entered.set()
            try:
                if self.path == "/slow-headers":
                    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
                    for byte in response:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        if stopped.wait(0.04):
                            return
                    return
                status = (
                    302
                    if self.path == "/redirect"
                    else int(self.path[1:]) if self.path in {"/401", "/403"} else 200
                )
                self.send_response(status)
                self.send_header(
                    "Content-Type", "text/plain" if self.path == "/text" else "application/json"
                )
                if status == 302:
                    self.send_header("Location", "/target")
                body = (
                    b"x" * (1_048_576 + 1)
                    if self.path == "/oversized"
                    else (
                        b"private remote error body"
                        if status in {401, 403}
                        else json.dumps(
                            _envelope(AIProviderKind.OPENAI_RESPONSES, {"ok": True})
                        ).encode()
                    )
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.path == "/slow-body":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        if stopped.wait(0.04):
                            return
                else:
                    self.wfile.write(body)
            except (OSError, TimeoutError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    server.block_on_close = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", entered, paths
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _post(
    url: str, *, timeout: float = 3, cancel: threading.Event | None = None, body: bytes = b"{}"
) -> bytes:
    return UrllibAIJSONTransport(cancel_event=cancel).post(
        url,
        headers={"Authorization": "Bearer test-only-value"},
        body=body,
        timeout_seconds=timeout,
    )


@pytest.mark.parametrize("route", ["slow-headers", "slow-body"])
def test_deadline_covers_drip_headers_and_body(
    route: str,
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
) -> None:
    url, entered, paths = endpoint
    started = time.monotonic()
    with pytest.raises(AIProviderTransportError) as caught:
        _post(f"{url}/{route}", timeout=0.8)
    assert caught.value.code == "request_timed_out"
    assert time.monotonic() - started < 1.6
    assert entered.is_set()
    assert paths == [f"/{route}"]
    assert len(workers) == 1


def test_startup_deadline_releases_a_blocked_stdin_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workers: list[subprocess.Popen[bytes]]
) -> None:
    worker = tmp_path / "slow_startup.py"
    worker.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    monkeypatch.setattr(ai_transport, "_WORKER", worker)
    started = time.monotonic()
    with pytest.raises(AIProviderTransportError) as caught:
        _post("http://127.0.0.1:1/unused", timeout=0.4, body=b"x" * 524_288)
    assert caught.value.code == "request_timed_out"
    assert time.monotonic() - started < 1.3
    assert len(workers) == 1


def test_explicit_transport_cancellation_reaps_the_worker(
    endpoint: tuple[str, threading.Event, list[str]], workers: list[subprocess.Popen[bytes]]
) -> None:
    url, entered, _ = endpoint
    cancel = threading.Event()
    signal = threading.Thread(target=lambda: (entered.wait(2), cancel.set()))
    signal.start()
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            _post(f"{url}/slow-body", cancel=cancel)
        assert caught.value.code == "request_cancelled"
        assert not caught.value.retryable
    finally:
        signal.join(timeout=3)
    assert len(workers) == 1


def test_base_exception_also_reaps_worker_and_pipes(
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, entered, _ = endpoint
    original = UrllibAIJSONTransport._check_deadline

    def interrupt(self: UrllibAIJSONTransport, deadline: float) -> None:
        if entered.is_set():
            raise KeyboardInterrupt
        original(self, deadline)

    monkeypatch.setattr(UrllibAIJSONTransport, "_check_deadline", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _post(f"{url}/slow-body")
    assert len(workers) == 1


@pytest.mark.parametrize(
    "route,code",
    [
        ("redirect", "endpoint_rejected"),
        ("401", "authentication_failed"),
        ("403", "authentication_failed"),
        ("text", "response_content_type"),
        ("oversized", "response_too_large"),
    ],
)
def test_endpoint_guards_survive_worker_boundary(
    route: str,
    code: str,
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
) -> None:
    url, _, paths = endpoint
    with pytest.raises(AIProviderTransportError) as caught:
        _post(f"{url}/{route}")
    assert caught.value.code == code
    assert "private remote error body" not in str(caught.value)
    assert "test-only-value" not in str(caught.value)
    assert paths == [f"/{route}"]
    assert len(workers) == 1


def test_probe_uses_real_worker_and_keeps_one_attempt_on_deadline(
    endpoint: tuple[str, threading.Event, list[str]], workers: list[subprocess.Popen[bytes]]
) -> None:
    url, _, paths = endpoint
    config = replace(
        _provider_config(AIProviderKind.OPENAI_RESPONSES),
        endpoint=f"{url}/slow-body",
        timeout_seconds=1,
    )
    started = time.monotonic()
    result = check_provider(config, connect=True, environ={})
    assert result["code"] == "request_timed_out"
    assert result["connectivity"] == "failed"
    assert result["attempts"] == 1
    assert result["used_fallback"] is False
    assert time.monotonic() - started < 1.8
    assert len(workers) == 1
    assert paths == ["/slow-body"]


def test_probe_success_uses_exact_endpoint_without_ambient_proxy(
    endpoint: tuple[str, threading.Event, list[str]],
    workers: list[subprocess.Popen[bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, _, paths = endpoint
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    config = replace(_provider_config(AIProviderKind.OPENAI_RESPONSES), endpoint=f"{url}/success")
    result = check_provider(config, connect=True, environ={})
    assert result["code"] == "probe_passed"
    assert result["attempts"] == 1
    assert result["used_fallback"] is False
    assert len(workers) == 1
    assert paths == ["/success"]


def test_untrusted_tls_certificate_is_rejected(
    tmp_path: Path,
    workers: list[subprocess.Popen[bytes]],
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    identity = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(identity)
        .issuer_name(identity)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "test-cert.pem", tmp_path / "test-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    server.daemon_threads = False
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        with pytest.raises(AIProviderTransportError) as caught:
            _post(f"https://127.0.0.1:{server.server_port}/untrusted")
        assert caught.value.code == "transport_failed"
        assert len(workers) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
