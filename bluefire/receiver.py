"""Bounded loopback-only HTTP receiver for the reviewed network action.

The receiver treats every request body as opaque bytes.  It never interprets,
executes, redirects, or forwards content.  Received bytes stay in memory unless
an operator explicitly configures a receiver-owned storage directory.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, TextIO, cast

ARTIFACT_PATH = "/bluefire/v1/artifact"
DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_CONFIGURED_BODY_BYTES = 64 * 1024 * 1024
_MAX_REQUEST_LINE_BYTES = 1024
_MAX_HEADER_LINE_BYTES = 4096
_MAX_HEADER_BYTES = 16 * 1024
_MAX_HEADER_COUNT = 32
_OWNER_MARKER = ".bluefire-receiver-owner"
_OWNER_MARKER_CONTENT = "bluefire.loopback-receiver-storage.v1\n"
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReceiverConfig:
    """Validated bounds and bind settings for one receiver session."""

    host: str = "127.0.0.1"
    port: int = 4317
    max_requests: int = 1
    max_connections: int = 16
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    request_timeout_seconds: float = 5.0
    idle_timeout_seconds: float = 60.0
    storage_dir: Path | None = None

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("receiver host must be a literal loopback IP address") from exc
        if not address.is_loopback:
            raise ValueError("receiver host must be a literal loopback IP address")
        if not 0 <= self.port <= 65535:
            raise ValueError("receiver port must be between 0 and 65535")
        if not 1 <= self.max_requests <= 10_000:
            raise ValueError("receiver max_requests must be between 1 and 10000")
        if not self.max_requests <= self.max_connections <= 10_000:
            raise ValueError("receiver max_connections must be between max_requests and 10000")
        if not 0 <= self.max_body_bytes <= MAX_CONFIGURED_BODY_BYTES:
            raise ValueError(
                f"receiver max_body_bytes must be between 0 and {MAX_CONFIGURED_BODY_BYTES}"
            )
        if not 0 < self.request_timeout_seconds <= 3600:
            raise ValueError("receiver request timeout must be between 0 and 3600 seconds")
        if not 0 < self.idle_timeout_seconds <= 3600:
            raise ValueError("receiver idle timeout must be between 0 and 3600 seconds")


class _ProtocolRefusal(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class _ReceiverStorage:
    """Content-addressed storage rooted in a marked receiver-owned directory."""

    def __init__(self, configured_dir: Path) -> None:
        configured_dir = configured_dir.absolute()
        if configured_dir.exists():
            if configured_dir.is_symlink() or not configured_dir.is_dir():
                raise ValueError("receiver storage must be a non-symlink directory")
        else:
            configured_dir.mkdir(parents=True, mode=0o700)

        root = configured_dir.resolve(strict=True)
        marker = root / _OWNER_MARKER
        if marker.exists():
            if marker.is_symlink() or not marker.is_file():
                raise ValueError("receiver storage ownership marker is invalid")
            if marker.stat().st_size != len(_OWNER_MARKER_CONTENT.encode("ascii")):
                raise ValueError("receiver storage ownership marker is invalid")
            try:
                marker_content = marker.read_text(encoding="ascii")
            except (OSError, UnicodeError) as exc:
                raise ValueError("receiver storage ownership marker is unreadable") from exc
            if marker_content != _OWNER_MARKER_CONTENT:
                raise ValueError("receiver storage is not owned by this receiver protocol")
        else:
            if any(root.iterdir()):
                raise ValueError("unmarked receiver storage must be empty")
            try:
                with marker.open("x", encoding="ascii", newline="\n") as stream:
                    stream.write(_OWNER_MARKER_CONTENT)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError as exc:
                raise ValueError("receiver storage ownership marker changed during setup") from exc
        self._root = root

    def store(self, body: bytes, digest: str) -> bool:
        target = self._root / f"sha256-{digest}.bin"
        if not target.parent.resolve(strict=True) == self._root:
            raise OSError("receiver storage containment check failed")
        if target.exists():
            raise OSError("receiver storage entry already exists")

        created = False
        try:
            with target.open("xb") as stream:
                created = True
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            raise OSError("receiver storage entry changed during write") from None
        except OSError:
            if created:
                try:
                    target.unlink()
                except OSError:
                    pass
            raise
        return True


class _LoopbackTCPServer(socketserver.TCPServer):
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[socketserver.BaseRequestHandler],
        *,
        config: ReceiverConfig,
        storage: _ReceiverStorage | None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.connections_handled = 0
        self.requests_accepted = 0
        self.requests_refused = 0
        super().__init__(server_address, handler_class)

    def handle_error(self, request: object, client_address: object) -> None:
        # The default implementation prints tracebacks and local paths.  This
        # receiver reports only bounded protocol responses and aggregate counts.
        self.requests_refused += 1


class _LoopbackTCPServerV6(_LoopbackTCPServer):
    address_family = socket.AF_INET6


class _ReceiverHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_LoopbackTCPServer, self.server)
        connection = cast(socket.socket, self.request)
        server.connections_handled += 1
        try:
            connection.settimeout(server.config.request_timeout_seconds)
            peer = ipaddress.ip_address(connection.getpeername()[0])
            if not peer.is_loopback:
                raise _ProtocolRefusal(403, "peer_not_loopback")
            with connection.makefile("rb") as stream:
                response = _receive_request(server, stream)
            server.requests_accepted += 1
        except _ProtocolRefusal as exc:
            response = _json_response(exc.status, {"accepted": False, "error": exc.code})
            server.requests_refused += 1
        except (OSError, TimeoutError, ValueError):
            response = _json_response(400, {"accepted": False, "error": "request_failed"})
            server.requests_refused += 1
        try:
            connection.sendall(response)
        except OSError:
            pass


def _receive_request(server: _LoopbackTCPServer, stream: BinaryIO) -> bytes:
    request_line = _read_crlf_line(
        stream,
        limit=_MAX_REQUEST_LINE_BYTES,
        overflow_status=414,
        overflow_code="request_line_too_large",
    )
    try:
        request_text = request_line.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _ProtocolRefusal(400, "invalid_request_line") from exc
    parts = request_text.split(" ")
    if len(parts) != 3 or not all(parts):
        raise _ProtocolRefusal(400, "invalid_request_line")
    method, target, version = parts
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise _ProtocolRefusal(505, "unsupported_http_version")

    headers = _read_headers(stream)
    if method != "POST":
        raise _ProtocolRefusal(405, "method_not_allowed")
    if target != ARTIFACT_PATH:
        raise _ProtocolRefusal(404, "path_not_found")
    if "transfer-encoding" in headers:
        raise _ProtocolRefusal(400, "transfer_encoding_not_supported")
    if "content-encoding" in headers:
        raise _ProtocolRefusal(415, "content_encoding_not_supported")
    if headers.get("content-type") != "application/octet-stream":
        raise _ProtocolRefusal(415, "content_type_not_supported")

    length_text = headers.get("content-length")
    if length_text is None or not length_text.isascii() or not length_text.isdecimal():
        raise _ProtocolRefusal(411, "content_length_required")
    content_length = int(length_text)
    if content_length > server.config.max_body_bytes:
        raise _ProtocolRefusal(413, "body_too_large")

    expected_digest = headers.get("x-bluefire-sha256", "")
    if _SHA256.fullmatch(expected_digest) is None:
        raise _ProtocolRefusal(400, "invalid_sha256_header")
    body = _read_exact(stream, content_length)
    actual_digest = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise _ProtocolRefusal(422, "sha256_mismatch")

    stored = False
    if server.storage is not None:
        try:
            stored = server.storage.store(body, actual_digest)
        except OSError as exc:
            raise _ProtocolRefusal(500, "storage_failed") from exc
    status = 201 if stored else 200
    return _json_response(
        status,
        {
            "schema_version": "bluefire.loopback-receiver-result.v1",
            "accepted": True,
            "bytes_received": len(body),
            "sha256": actual_digest,
            "stored": stored,
        },
    )


def _read_headers(stream: BinaryIO) -> dict[str, str]:
    headers: dict[str, str] = {}
    total = 0
    for _ in range(_MAX_HEADER_COUNT + 1):
        line = _read_crlf_line(
            stream,
            limit=_MAX_HEADER_LINE_BYTES,
            overflow_status=431,
            overflow_code="headers_too_large",
        )
        total += len(line) + 2
        if total > _MAX_HEADER_BYTES:
            raise _ProtocolRefusal(431, "headers_too_large")
        if not line:
            return headers
        if len(headers) >= _MAX_HEADER_COUNT:
            raise _ProtocolRefusal(431, "too_many_headers")
        if line[:1] in {b" ", b"\t"} or b":" not in line:
            raise _ProtocolRefusal(400, "invalid_header")
        raw_name, raw_value = line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise _ProtocolRefusal(400, "invalid_header") from exc
        if _HEADER_NAME.fullmatch(name) is None or name in headers:
            raise _ProtocolRefusal(400, "invalid_header")
        headers[name] = value
    raise _ProtocolRefusal(431, "too_many_headers")


def _read_crlf_line(
    stream: BinaryIO,
    *,
    limit: int,
    overflow_status: int,
    overflow_code: str,
) -> bytes:
    line = stream.readline(limit + 1)
    if len(line) > limit:
        raise _ProtocolRefusal(overflow_status, overflow_code)
    if not line.endswith(b"\r\n"):
        raise _ProtocolRefusal(400, "incomplete_request")
    return line[:-2]


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    body = bytearray()
    while len(body) < length:
        chunk = stream.read(min(64 * 1024, length - len(body)))
        if not chunk:
            raise _ProtocolRefusal(400, "content_length_mismatch")
        body.extend(chunk)
    return bytes(body)


def _json_response(status: int, payload: Mapping[str, object]) -> bytes:
    reason = {
        200: "OK",
        201: "Created",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        411: "Length Required",
        413: "Content Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        422: "Unprocessable Content",
        431: "Request Header Fields Too Large",
        500: "Internal Server Error",
        505: "HTTP Version Not Supported",
    }.get(status, "Error")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "Connection: close",
    ]
    if status == 405:
        headers.append("Allow: POST")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


class LoopbackArtifactReceiver:
    """Own one bounded receiver socket and serve it synchronously."""

    def __init__(self, config: ReceiverConfig) -> None:
        address = ipaddress.ip_address(config.host)
        storage = _ReceiverStorage(config.storage_dir) if config.storage_dir else None
        server_type = _LoopbackTCPServerV6 if address.version == 6 else _LoopbackTCPServer
        self._server = server_type(
            (config.host, config.port),
            _ReceiverHandler,
            config=config,
            storage=storage,
        )
        self._config = config
        self._stopping = threading.Event()
        self._closed = False

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def serve(self) -> Mapping[str, object]:
        reason = "explicit_stop"
        idle_deadline = time.monotonic() + self._config.idle_timeout_seconds
        try:
            while (
                not self._stopping.is_set()
                and self._server.requests_accepted < self._config.max_requests
                and self._server.connections_handled < self._config.max_connections
            ):
                remaining = idle_deadline - time.monotonic()
                if remaining <= 0:
                    reason = "idle_timeout"
                    break
                self._server.timeout = min(0.25, remaining)
                before = self._server.connections_handled
                self._server.handle_request()
                if self._server.connections_handled > before:
                    idle_deadline = time.monotonic() + self._config.idle_timeout_seconds
            else:
                if self._server.requests_accepted >= self._config.max_requests:
                    reason = "max_requests"
                elif self._server.connections_handled >= self._config.max_connections:
                    reason = "max_connections"
        finally:
            self.close()
        return {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": reason,
            "connections_handled": self._server.connections_handled,
            "requests_accepted": self._server.requests_accepted,
            "requests_refused": self._server.requests_refused,
        }

    def stop(self) -> None:
        """Request a bounded, polling-loop shutdown without closing an active socket."""

        self._stopping.set()

    def close(self) -> None:
        self.stop()
        if not self._closed:
            self._server.server_close()
            self._closed = True

    def __enter__(self) -> LoopbackArtifactReceiver:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def run_loopback_receiver(
    config: ReceiverConfig,
    *,
    ready_stream: TextIO | None = sys.stderr,
) -> Mapping[str, object]:
    """Run a receiver session and optionally emit a path-free readiness record."""

    with LoopbackArtifactReceiver(config) as receiver:
        if ready_stream is not None:
            ready = {
                "schema_version": "bluefire.loopback-receiver-ready.v1",
                "host": receiver.host,
                "port": receiver.port,
                "max_requests": config.max_requests,
                "max_connections": config.max_connections,
                "max_body_bytes": config.max_body_bytes,
                "storage": "receiver_owned" if config.storage_dir else "memory_only",
            }
            print(json.dumps(ready, separators=(",", ":"), sort_keys=True), file=ready_stream)
            ready_stream.flush()
        return receiver.serve()


__all__ = [
    "ARTIFACT_PATH",
    "DEFAULT_MAX_BODY_BYTES",
    "LoopbackArtifactReceiver",
    "ReceiverConfig",
    "run_loopback_receiver",
]
