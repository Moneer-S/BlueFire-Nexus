"""Real local Unix sockets exercise framing; no Docker daemon is contacted."""

from __future__ import annotations

import errno
import hashlib
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from bluefire.engine_docker_transport import (
    DockerDaemonTransportError,
    LinuxDockerDaemonEndpoint,
    LinuxUnixDockerDaemonTransport,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix-socket transport")

REQUEST = b"GET /v1.47/info HTTP/1.1\r\nHost: docker\r\n\r\n"
DAEMON_DIGEST = "sha256:" + "d" * 64
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}"
EXEC_ID = "e" * 64
EXEC_START_BODY = b'{"Detach":false,"Tty":false}'
EXEC_START_REQUEST = (
    f"POST /v1.47/exec/{EXEC_ID}/start HTTP/1.1\r\n".encode()
    + b"Host: docker\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
    + b"User-Agent: docker-sdk-python/7.1.0\r\n"
    + b"Connection: Upgrade\r\nUpgrade: tcp\r\n"
    + b"Content-Type: application/json\r\nContent-Length: "
    + str(len(EXEC_START_BODY)).encode()
    + b"\r\n\r\n"
    + EXEC_START_BODY
)


class Cancellation:
    def __init__(self) -> None:
        self.event = threading.Event()

    def is_cancelled(self) -> bool:
        return self.event.is_set()


class OwnedDaemon:
    def __init__(self, path: Path, script: Callable[[socket.socket, "OwnedDaemon"], None]) -> None:
        self.path = path
        self.request = b""
        self.accept_count = 0
        self.received = threading.Event()
        self.release = threading.Event()
        self.stop = threading.Event()
        self.errors: list[Exception] = []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(1)
        self.listener.settimeout(0.05)
        self.script = script
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                self.accept_count += 1
                with connection:
                    connection.settimeout(2)
                    while len(self.request) < len(self.expected_request):
                        piece = connection.recv(len(self.expected_request) - len(self.request))
                        if not piece:
                            return
                        self.request += piece
                    self.received.set()
                    self.script(connection, self)
                return
        except (BrokenPipeError, ConnectionResetError):
            pass  # A bounded refusing client closes while the fake is writing.
        except Exception as exc:
            self.errors.append(exc)

    @property
    def endpoint(self) -> LinuxDockerDaemonEndpoint:
        identity = self.path.stat()
        return LinuxDockerDaemonEndpoint(
            socket_path=str(self.path),
            daemon_instance_digest=DAEMON_DIGEST,
            socket_device=identity.st_dev,
            socket_inode=identity.st_ino,
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
            peer_pid=os.getpid(),
        )

    def close(self) -> None:
        self.release.set()
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "owned fake socket did not shut down"
        assert not self.errors

    expected_request = REQUEST


@contextmanager
def daemon(
    script: Callable[[socket.socket, OwnedDaemon], None], *, expected_request: bytes = REQUEST
) -> Iterator[OwnedDaemon]:
    # pytest's workspace-based tmp_path may exceed Linux's 108-byte sun_path bound.
    with tempfile.TemporaryDirectory(prefix="bf-docker-") as directory:
        server = OwnedDaemon(Path(directory) / "daemon.sock", script)
        server.expected_request = expected_request
        try:
            yield server
        finally:
            server.close()


def exchange(
    server: OwnedDaemon,
    *,
    raw_request: bytes = REQUEST,
    cancellation: Cancellation | None = None,
    timeout_seconds: float = 2,
    **limits: int,
):
    request_limit = limits.get("response_byte_limit", 32 * 1024**2)
    transport = LinuxUnixDockerDaemonTransport(server.endpoint, **limits)
    return transport.exchange(
        raw_request,
        deadline_monotonic_ns=time.monotonic_ns() + int(timeout_seconds * 1_000_000_000),
        response_byte_limit=request_limit,
        cancellation=cancellation or Cancellation(),
    )


def test_exact_request_and_response_bytes_no_dns_or_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_request = (
        b"POST /v1.47/containers/create HTTP/1.1\r\nHost: docker\r\n"
        b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
    )

    def no_dns(*args: object, **kwargs: object) -> None:
        pytest.fail("Unix transport must not resolve network names")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setenv("HTTP_PROXY", "http://invalid.example:1234")
    monkeypatch.setenv("HTTPS_PROXY", "http://invalid.example:1234")
    monkeypatch.setenv("DOCKER_HOST", "tcp://invalid.example:2375")
    with daemon(
        lambda connection, _: connection.sendall(RESPONSE), expected_request=raw_request
    ) as s:
        result = exchange(s, raw_request=raw_request)
        assert s.request == raw_request
        assert s.accept_count == 1
        assert result.raw_response == RESPONSE
        assert result.request_digest == "sha256:" + hashlib.sha256(raw_request).hexdigest()
        assert result.daemon_instance_digest == DAEMON_DIGEST


def test_chunked_transfer_is_bounded_and_normalized() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"
    )
    with daemon(lambda connection, _: connection.sendall(raw)) as s:
        result = exchange(s, response_byte_limit=2)
    head, body = result.raw_response.split(b"\r\n\r\n", 1)
    assert b"transfer-encoding" not in head.lower()
    assert b"content-length: 2" in head.lower()
    assert body == b"{}"


@pytest.mark.parametrize(
    "status,connection",
    [
        (b"101 UPGRADED", b"Connection: Upgrade\r\nUpgrade: tcp\r\n"),
        (b"200 OK", b"Connection: close\r\n"),
        (b"200 OK", b"Connection: Upgrade\r\nUpgrade: tcp\r\n"),
    ],
)
def test_exec_start_accepts_bounded_hijack_variants_and_normalizes_frames(
    status: bytes, connection: bytes
) -> None:
    frames = struct.pack(">BxxxI", 1, 3) + b"out" + struct.pack(">BxxxI", 2, 3) + b"err"
    head = (
        b"HTTP/1.1 "
        + status
        + b"\r\nApi-Version: 1.47\r\nDocker-Experimental: false\r\n"
        + b"OSType: linux\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n"
        + connection
        + b"\r\n"
    )

    def fragmented(connection_socket: socket.socket, _server: OwnedDaemon) -> None:
        for piece in (head[:17], head[17:], frames[:2], frames[2:9], frames[9:]):
            connection_socket.sendall(piece)

    with daemon(fragmented, expected_request=EXEC_START_REQUEST) as s:
        result = exchange(
            s,
            raw_request=EXEC_START_REQUEST,
            response_byte_limit=6,
        )
    normalized_head, normalized_body = result.raw_response.split(b"\r\n\r\n", 1)
    assert normalized_head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"connection:" not in normalized_head.lower()
    assert b"upgrade:" not in normalized_head.lower()
    assert b"content-length: 22" in normalized_head.lower()
    assert normalized_body == frames


def test_exec_start_rejects_missing_request_upgrade_before_send() -> None:
    plain = EXEC_START_REQUEST.replace(b"Connection: Upgrade\r\nUpgrade: tcp\r\n", b"")
    with daemon(lambda connection, _: connection.sendall(RESPONSE), expected_request=plain) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, raw_request=plain, response_byte_limit=64)
    assert caught.value.code == "attach_request_upgrade_required"
    assert not caught.value.request_may_have_been_sent
    assert s.request == b""


def test_exec_start_payload_limit_counts_decoded_bytes_not_frame_headers() -> None:
    frames = struct.pack(">BxxxI", 1, 5) + b"12345"
    response = (
        b"HTTP/1.1 101 UPGRADED\r\nApi-Version: 1.47\r\n"
        b"Docker-Experimental: false\r\nOSType: linux\r\n"
        b"Content-Type: application/vnd.docker.multiplexed-stream\r\n"
        b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n" + frames
    )
    with daemon(
        lambda connection, _: connection.sendall(response),
        expected_request=EXEC_START_REQUEST,
    ) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, raw_request=EXEC_START_REQUEST, response_byte_limit=4)
    assert caught.value.code == "payload_limit"
    assert caught.value.request_may_have_been_sent


def test_exec_start_cancellation_and_truncated_frame_are_uncertain() -> None:
    token = Cancellation()

    def partial(connection: socket.socket, server: OwnedDaemon) -> None:
        connection.sendall(
            b"HTTP/1.1 101 UPGRADED\r\nApi-Version: 1.47\r\n"
            b"Docker-Experimental: false\r\nOSType: linux\r\n"
            b"Content-Type: application/vnd.docker.multiplexed-stream\r\n"
            b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n" + struct.pack(">BxxxI", 1, 5) + b"12"
        )
        token.event.set()
        server.release.wait(timeout=2)

    with daemon(partial, expected_request=EXEC_START_REQUEST) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(
                s,
                raw_request=EXEC_START_REQUEST,
                response_byte_limit=16,
                cancellation=token,
            )
    assert caught.value.code == "cancelled"
    assert caught.value.request_may_have_been_sent


def test_exec_start_partial_frame_eof_is_uncertain_without_cancellation() -> None:
    response = (
        b"HTTP/1.1 101 UPGRADED\r\nApi-Version: 1.47\r\n"
        b"Docker-Experimental: false\r\nOSType: linux\r\n"
        b"Content-Type: application/vnd.docker.multiplexed-stream\r\n"
        b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n" + struct.pack(">BxxxI", 1, 5) + b"12"
    )
    with daemon(
        lambda connection, _: connection.sendall(response),
        expected_request=EXEC_START_REQUEST,
    ) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, raw_request=EXEC_START_REQUEST, response_byte_limit=16)
    assert caught.value.code == "attach_frame_truncated"
    assert caught.value.request_may_have_been_sent
    assert caught.value.response_started


def test_exec_start_socket_enforces_separate_frame_overhead_bound() -> None:
    frames = struct.pack(">BxxxI", 1, 0) + struct.pack(">BxxxI", 2, 0)
    response = (
        b"HTTP/1.1 101 UPGRADED\r\nApi-Version: 1.47\r\n"
        b"Docker-Experimental: false\r\nOSType: linux\r\n"
        b"Content-Type: application/vnd.docker.multiplexed-stream\r\n"
        b"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n" + frames
    )
    with daemon(
        lambda connection, _: connection.sendall(response),
        expected_request=EXEC_START_REQUEST,
    ) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(
                s,
                raw_request=EXEC_START_REQUEST,
                response_byte_limit=1,
                stream_overhead_byte_limit=8,
            )
    assert caught.value.code == "overhead_limit"
    assert caught.value.request_may_have_been_sent


def test_dispatch_gate_wraps_only_request_write() -> None:
    events: list[str] = []

    class Gate:
        request_digest = "sha256:" + hashlib.sha256(REQUEST).hexdigest()
        entered = False
        sent = False

        @contextmanager
        def before_send(self):
            self.entered = True
            events.append("enter")
            yield
            self.sent = True
            events.append("sent")

    gate = Gate()

    def respond(connection: socket.socket, _server: OwnedDaemon) -> None:
        events.append("read")
        connection.sendall(RESPONSE)

    with daemon(respond) as s:
        transport = LinuxUnixDockerDaemonTransport(s.endpoint)
        result = transport.exchange(
            REQUEST,
            deadline_monotonic_ns=time.monotonic_ns() + 2_000_000_000,
            response_byte_limit=2,
            cancellation=Cancellation(),
            dispatch_gate=gate,
        )
    assert result.raw_response == RESPONSE
    assert gate.entered and gate.sent
    assert events[0] == "enter"
    assert events.count("sent") == 1 and events.count("read") == 1


def test_dispatch_gate_must_bind_exact_request_before_socket_send() -> None:
    class WrongGate:
        request_digest = "sha256:" + "0" * 64
        entered = False
        sent = False

        @contextmanager
        def before_send(self):
            pytest.fail("a substituted request must never enter the live fence")
            yield

    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        transport = LinuxUnixDockerDaemonTransport(s.endpoint)
        with pytest.raises(DockerDaemonTransportError) as caught:
            transport.exchange(
                REQUEST,
                deadline_monotonic_ns=time.monotonic_ns() + 2_000_000_000,
                response_byte_limit=2,
                cancellation=Cancellation(),
                dispatch_gate=WrongGate(),
            )
    assert caught.value.code == "dispatch_gate_binding"
    assert not caught.value.request_may_have_been_sent
    assert s.request == b""


def test_head_representation_length_does_not_require_a_body() -> None:
    request = b"HEAD /v1.47/info HTTP/1.1\r\nHost: docker\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
    with daemon(lambda connection, _: connection.sendall(response), expected_request=request) as s:
        result = exchange(s, raw_request=request, response_byte_limit=2)
    assert result.raw_response == response


def test_no_content_response_may_omit_length() -> None:
    response = b"HTTP/1.1 204 No Content\r\n\r\n"
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        result = exchange(s)
    assert result.raw_response == response


def test_cancelled_before_send_has_no_ambiguous_effect() -> None:
    token = Cancellation()
    token.event.set()
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, cancellation=token)
        assert not s.received.is_set()
        assert s.request == b""
    assert caught.value.code == "cancelled"
    assert not caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == 0
    assert not caught.value.response_started


def test_deadline_before_send_has_no_ambiguous_effect() -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, timeout_seconds=-1)
        assert s.request == b""
    assert caught.value.code == "deadline_exceeded"
    assert not caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == 0


def test_disconnect_after_exact_send_is_uncertain_and_never_retried() -> None:
    with daemon(lambda _connection, _server: None) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s)
        assert s.request == REQUEST
        assert s.accept_count == 1
    assert caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == len(REQUEST)
    assert not caught.value.response_started


def test_cancel_during_receive_is_uncertain() -> None:
    token = Cancellation()

    def cancel_after_send(connection: socket.socket, server: OwnedDaemon) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx")
        token.event.set()
        server.release.wait(timeout=2)

    with daemon(cancel_after_send) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, cancellation=token)
        assert s.request == REQUEST
    assert caught.value.code == "cancelled"
    assert caught.value.request_may_have_been_sent


def test_absolute_deadline_bounds_a_stalled_response() -> None:
    def stall(_connection: socket.socket, server: OwnedDaemon) -> None:
        server.release.wait(timeout=2)

    started = time.monotonic()
    with daemon(stall) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, timeout_seconds=0.15)
        assert s.request == REQUEST
    assert time.monotonic() - started < 1.5
    assert caught.value.code == "deadline_exceeded"
    assert caught.value.request_may_have_been_sent


def test_progress_does_not_extend_absolute_deadline() -> None:
    def trickle(connection: socket.socket, server: OwnedDaemon) -> None:
        for byte in RESPONSE:
            connection.sendall(bytes([byte]))
            if server.release.wait(timeout=0.03):
                break

    started = time.monotonic()
    with daemon(trickle) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, timeout_seconds=0.15)
    assert time.monotonic() - started < 1.5
    assert caught.value.code == "deadline_exceeded"
    assert caught.value.request_may_have_been_sent
    assert caught.value.response_started


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n",
    ],
)
def test_response_body_bound_is_enforced_before_unbounded_read(response: bytes) -> None:
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, response_byte_limit=2)
    assert caught.value.request_may_have_been_sent
    assert caught.value.response_started


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 02\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}trailing",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\ng\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxXX0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Authority: injected\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ignored=x\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n{}",
        b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
        b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://invalid.example\r\n\r\n",
    ],
)
def test_ambiguous_response_framing_is_refused(response: bytes) -> None:
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s)
        assert s.accept_count == 1
    assert caught.value.request_may_have_been_sent
    assert caught.value.response_started


def test_headers_are_bounded() -> None:
    response = b"HTTP/1.1 200 OK\r\nX-Padding: " + b"x" * 512 + b"\r\nContent-Length: 0\r\n\r\n"
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        with pytest.raises(DockerDaemonTransportError):
            exchange(s, header_byte_limit=128)


def test_chunk_count_is_bounded_even_when_body_fits() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"1\r\nx\r\n" * 8192
        + b"0\r\n\r\n"
    )
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, response_byte_limit=8192)
    assert caught.value.request_may_have_been_sent


def test_total_wire_bound_includes_chunk_framing() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1\r\nx\r\n" * 6 + b"0\r\n\r\n"
    )
    with daemon(lambda connection, _: connection.sendall(response)) as s:
        with pytest.raises(DockerDaemonTransportError):
            exchange(s, response_byte_limit=6, wire_byte_limit=80)


@pytest.mark.parametrize(
    "invalid_raw_request",
    [
        b"GET /v1.47/info HTTP/1.1\r\nHost: docker\r\nContent-Length: 2\r\n\r\nx",
        b"GET /v1.47/info HTTP/1.1\r\nHost: docker\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        REQUEST + REQUEST,
    ],
)
def test_invalid_complete_request_is_refused_before_send(invalid_raw_request: bytes) -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s, raw_request=invalid_raw_request)
        assert s.request == b""
    assert not caught.value.request_may_have_been_sent


def test_truncated_content_length_response_is_uncertain() -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE[:-1])) as s:
        with pytest.raises(DockerDaemonTransportError) as caught:
            exchange(s)
    assert caught.value.request_may_have_been_sent
    assert caught.value.response_started


def test_socket_path_replacement_is_refused_before_send() -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        transport = LinuxUnixDockerDaemonTransport(s.endpoint)
        s.path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
            replacement.bind(str(s.path))
            replacement.listen(1)
            with pytest.raises(DockerDaemonTransportError) as caught:
                transport.exchange(
                    REQUEST,
                    deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
                    cancellation=Cancellation(),
                )
        assert s.request == b""
    assert not caught.value.request_may_have_been_sent


def test_wrong_peer_credentials_refused_before_send() -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        identity = s.endpoint
        wrong_peer = LinuxDockerDaemonEndpoint(
            socket_path=identity.socket_path,
            daemon_instance_digest=identity.daemon_instance_digest,
            socket_device=identity.socket_device,
            socket_inode=identity.socket_inode,
            peer_uid=os.getuid() + 1,
            peer_gid=os.getgid(),
            peer_pid=os.getpid(),
        )
        transport = LinuxUnixDockerDaemonTransport(wrong_peer)
        with pytest.raises(DockerDaemonTransportError) as caught:
            transport.exchange(
                REQUEST,
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
                cancellation=Cancellation(),
            )
    assert not caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == 0


def test_wrong_peer_pid_refused_before_send() -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        identity = s.endpoint
        wrong_peer = LinuxDockerDaemonEndpoint(
            socket_path=identity.socket_path,
            daemon_instance_digest=identity.daemon_instance_digest,
            socket_device=identity.socket_device,
            socket_inode=identity.socket_inode,
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
            peer_pid=os.getpid() + 1,
        )
        transport = LinuxUnixDockerDaemonTransport(wrong_peer)
        with pytest.raises(DockerDaemonTransportError) as caught:
            transport.exchange(
                REQUEST,
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
                cancellation=Cancellation(),
            )
    assert not caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == 0


def test_socket_creation_failure_is_classified_before_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        transport = LinuxUnixDockerDaemonTransport(s.endpoint)

        def fail_creation(*args: object, **kwargs: object) -> None:
            raise OSError(errno.EMFILE, "owned test exhausted file descriptors")

        monkeypatch.setattr(socket, "socket", fail_creation)
        with pytest.raises(DockerDaemonTransportError) as caught:
            transport.exchange(
                REQUEST,
                deadline_monotonic_ns=time.monotonic_ns() + 1_000_000_000,
                cancellation=Cancellation(),
            )
    assert not caught.value.request_may_have_been_sent
    assert caught.value.request_bytes_sent == 0


def test_socket_above_select_fd_limit_still_exchanges_exact_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fcntl
    import resource

    if resource.getrlimit(resource.RLIMIT_NOFILE)[0] <= 2048:
        pytest.skip("test needs one descriptor above Linux select FD_SETSIZE")
    original_socket = socket.socket

    def high_descriptor_socket(*args, **kwargs):
        created = original_socket(*args, **kwargs)
        if args and args[0] == socket.AF_UNIX and kwargs.get("fileno") is None:
            descriptor = fcntl.fcntl(created.fileno(), fcntl.F_DUPFD_CLOEXEC, 2048)
            created.close()
            return original_socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=descriptor)
        return created

    with daemon(lambda connection, _: connection.sendall(RESPONSE)) as s:
        monkeypatch.setattr(socket, "socket", high_descriptor_socket)
        result = exchange(s)
        assert s.request == REQUEST
    assert result.raw_response == RESPONSE
