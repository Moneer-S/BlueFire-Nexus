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
import secrets
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, TextIO, cast

from .receiver_auth import (
    RESULT_SCHEMA_VERSION,
    ReceiverAuthenticationError,
    challenge_authentication,
    challenge_document,
    derive_receiver_task_key,
    disposable_peer_challenge_document,
    disposable_peer_result_document,
    request_authentication,
    request_document,
    response_authentication,
    validate_receiver_task_id,
    verify_authentication,
)
from .runner_client import RunnerTransportError, _PinnedPrivateDirectory
from .util import canonical_json_bytes

ARTIFACT_PATH = "/bluefire/v1/artifact"
CHALLENGE_PATH = "/bluefire/v1/challenge"
DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
DEFAULT_IDLE_TIMEOUT_SECONDS = 300.0
DISPOSABLE_PEER_IDLE_TIMEOUT_SECONDS = 240.0
DISPOSABLE_PEER_LIFETIME_TIMEOUT_SECONDS = 240.0
DISPOSABLE_PEER_MAX_CONNECTIONS = 8
DISPOSABLE_PEER_REQUEST_TIMEOUT_SECONDS = 5.0
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

    authentication_key: bytes = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 4317
    max_requests: int = 1
    max_connections: int = 16
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    request_timeout_seconds: float = 5.0
    idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS
    storage_dir: Path | None = None
    disposable_peer: bool = False

    def __post_init__(self) -> None:
        if type(self.authentication_key) is not bytes or len(self.authentication_key) != 32:
            raise ValueError("receiver authentication key must be exactly 32 bytes")
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
        if not 2 * self.max_requests <= self.max_connections <= 20_000:
            raise ValueError(
                "receiver max_connections must be between twice max_requests and 20000"
            )
        if not 0 <= self.max_body_bytes <= MAX_CONFIGURED_BODY_BYTES:
            raise ValueError(
                f"receiver max_body_bytes must be between 0 and {MAX_CONFIGURED_BODY_BYTES}"
            )
        if not 0 < self.request_timeout_seconds <= 3600:
            raise ValueError("receiver request timeout must be between 0 and 3600 seconds")
        if not 0 < self.idle_timeout_seconds <= 3600:
            raise ValueError("receiver idle timeout must be between 0 and 3600 seconds")
        if type(self.disposable_peer) is not bool:
            raise ValueError("receiver disposable peer mode must be a boolean")
        if self.disposable_peer:
            if self.host != "127.0.0.1":
                raise ValueError("disposable peer receiver host must be exactly 127.0.0.1")
            if self.max_requests != 1:
                raise ValueError("disposable peer receiver must accept exactly one artifact")
            if self.max_connections != DISPOSABLE_PEER_MAX_CONNECTIONS:
                raise ValueError("disposable peer receiver connection budget must be exactly 8")
            if self.storage_dir is not None:
                raise ValueError("disposable peer receiver must use memory-only storage")
            if self.request_timeout_seconds > DISPOSABLE_PEER_REQUEST_TIMEOUT_SECONDS:
                raise ValueError(
                    "disposable peer receiver request timeout must not exceed 5 seconds"
                )
            if self.idle_timeout_seconds > DISPOSABLE_PEER_IDLE_TIMEOUT_SECONDS:
                raise ValueError(
                    "disposable peer receiver idle timeout must not exceed 240 seconds"
                )


class _ProtocolRefusal(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class _Challenge:
    task_id: str
    sha256: str
    content_length: int
    expires_at: float


@dataclass(frozen=True, slots=True)
class _RequestResult:
    response: bytes
    accepted_artifact: bool = False
    issued_challenge: bool = False
    accepted_artifact_binding: Mapping[str, object] | None = None


class _DeadlineReader:
    """Read one request without allowing byte trickling to reset its deadline."""

    def __init__(self, connection: socket.socket, deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline
        self._buffer = bytearray()

    def _receive(self, maximum: int) -> bytes:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _ProtocolRefusal(408, "request_timeout")
        self._connection.settimeout(remaining)
        try:
            return self._connection.recv(maximum)
        except (TimeoutError, socket.timeout) as exc:
            raise _ProtocolRefusal(408, "request_timeout") from exc

    def readline(self, limit: int) -> bytes:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                end = newline + 1
                line = bytes(self._buffer[:end])
                del self._buffer[:end]
                return line
            if len(self._buffer) >= limit:
                line = bytes(self._buffer[:limit])
                del self._buffer[:limit]
                return line
            chunk = self._receive(min(4096, limit - len(self._buffer)))
            if not chunk:
                line = bytes(self._buffer)
                self._buffer.clear()
                return line
            self._buffer.extend(chunk)

    def read(self, maximum: int) -> bytes:
        if maximum <= 0:
            return b""
        if self._buffer:
            length = min(maximum, len(self._buffer))
            chunk = bytes(self._buffer[:length])
            del self._buffer[:length]
            return chunk
        return self._receive(maximum)


class _ReceiverStorage:
    """Content-addressed storage rooted in a marked receiver-owned directory."""

    def __init__(self, configured_dir: Path) -> None:
        configured_dir = configured_dir.absolute()
        try:
            if configured_dir.exists():
                if configured_dir.is_symlink() or not configured_dir.is_dir():
                    raise ValueError("receiver storage must be a non-symlink directory")
            else:
                configured_dir.mkdir(parents=True, mode=0o700)
        except OSError:
            raise ValueError("receiver storage is unavailable or unsafe") from None

        marker_content = _OWNER_MARKER_CONTENT.encode("ascii")
        directory = _PinnedPrivateDirectory(configured_dir)
        try:
            directory.__enter__()
            if directory.has_name(_OWNER_MARKER):
                try:
                    observed = directory.read(_OWNER_MARKER, maximum=len(marker_content))
                except OSError:
                    raise ValueError("receiver storage ownership marker is invalid") from None
                if observed != marker_content:
                    raise ValueError("receiver storage is not owned by this receiver protocol")
            else:
                names = directory.names(maximum=1)
                if names:
                    raise ValueError("unmarked receiver storage must be empty")
                try:
                    directory.create(
                        _OWNER_MARKER,
                        marker_content,
                        maximum=len(marker_content),
                    )
                except OSError:
                    raise ValueError(
                        "receiver storage ownership marker changed during setup"
                    ) from None
                if directory.names(maximum=1) != (_OWNER_MARKER,):
                    raise ValueError("receiver storage changed during setup")
        except ValueError:
            directory.close()
            raise
        except (OSError, RunnerTransportError):
            directory.close()
            raise ValueError("receiver storage is unavailable or unsafe") from None
        self._directory = directory

    def store(self, body: bytes, digest: str) -> bool:
        if _SHA256.fullmatch(digest) is None or hashlib.sha256(body).hexdigest() != digest:
            raise OSError("receiver storage digest binding is invalid")
        self._directory.create(
            f"sha256-{digest}.bin",
            body,
            maximum=MAX_CONFIGURED_BODY_BYTES,
        )
        return True

    def close(self) -> None:
        self._directory.close()


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
        self.challenges_issued = 0
        self.accepted_artifact_bindings: list[dict[str, object]] = []
        self.receiver_process_id = os.getpid()
        self.lifecycle_deadline = (
            time.monotonic() + DISPOSABLE_PEER_LIFETIME_TIMEOUT_SECONDS
            if config.disposable_peer
            else None
        )
        self.session_id = secrets.token_hex(32)
        self.challenges: dict[str, _Challenge] = {}
        super().__init__(server_address, handler_class)

    def handle_error(self, request: object, client_address: object) -> None:
        # The default implementation prints tracebacks and local paths.  This
        # receiver reports only bounded protocol responses and aggregate counts.
        self.requests_refused += 1

    def server_close(self) -> None:
        try:
            self.challenges.clear()
            super().server_close()
        finally:
            storage = self.storage
            self.storage = None
            if storage is not None:
                storage.close()


class _LoopbackTCPServerV6(_LoopbackTCPServer):
    address_family = socket.AF_INET6


class _ReceiverHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_LoopbackTCPServer, self.server)
        connection = cast(socket.socket, self.request)
        server.connections_handled += 1
        try:
            deadline = time.monotonic() + server.config.request_timeout_seconds
            if server.lifecycle_deadline is not None:
                deadline = min(deadline, server.lifecycle_deadline)
            peer = ipaddress.ip_address(connection.getpeername()[0])
            if not peer.is_loopback:
                raise _ProtocolRefusal(403, "peer_not_loopback")
            result = _receive_request(server, _DeadlineReader(connection, deadline))
            response = result.response
            if result.accepted_artifact:
                server.requests_accepted += 1
                binding = result.accepted_artifact_binding
                if binding is None:
                    raise _ProtocolRefusal(500, "accepted_binding_unavailable")
                server.accepted_artifact_bindings.append(dict(binding))
            if result.issued_challenge:
                server.challenges_issued += 1
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


def _receive_request(server: _LoopbackTCPServer, stream: _DeadlineReader) -> _RequestResult:
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
    if target == CHALLENGE_PATH:
        if method != "GET":
            raise _ProtocolRefusal(405, "method_not_allowed")
        return _issue_challenge(server, headers)
    if target != ARTIFACT_PATH:
        raise _ProtocolRefusal(404, "path_not_found")
    if method != "POST":
        raise _ProtocolRefusal(405, "method_not_allowed")
    return _receive_artifact(server, stream, headers)


def _issue_challenge(
    server: _LoopbackTCPServer,
    headers: Mapping[str, str],
) -> _RequestResult:
    _validate_host_header(server, headers)
    _validate_header_names(
        headers,
        required={
            "host",
            "x-bluefire-task-id",
            "x-bluefire-sha256",
            "x-bluefire-content-length",
        },
        allowed={
            "host",
            "x-bluefire-task-id",
            "x-bluefire-sha256",
            "x-bluefire-content-length",
            "accept",
            "connection",
            "content-length",
        },
    )
    if headers.get("content-length") not in {None, "0"}:
        raise _ProtocolRefusal(400, "challenge_body_not_allowed")
    task_id = headers.get("x-bluefire-task-id", "")
    sha256 = headers.get("x-bluefire-sha256", "")
    content_length_text = headers.get("x-bluefire-content-length", "")
    try:
        task_id = validate_receiver_task_id(task_id)
        task_key = derive_receiver_task_key(server.config.authentication_key, task_id)
        if (
            _SHA256.fullmatch(sha256) is None
            or not content_length_text.isascii()
            or not content_length_text.isdecimal()
            or (len(content_length_text) > 1 and content_length_text.startswith("0"))
        ):
            raise ReceiverAuthenticationError("receiver artifact binding is invalid")
        content_length = int(content_length_text)
        if content_length > MAX_CONFIGURED_BODY_BYTES:
            raise ReceiverAuthenticationError("receiver artifact binding is invalid")
    except ReceiverAuthenticationError as exc:
        raise _ProtocolRefusal(401, "receiver_authentication_failed") from exc
    if content_length > server.config.max_body_bytes:
        raise _ProtocolRefusal(413, "body_too_large")

    now = time.monotonic()
    for nonce, challenge in tuple(server.challenges.items()):
        if challenge.expires_at <= now:
            del server.challenges[nonce]
    nonce = secrets.token_hex(32)
    server.challenges[nonce] = _Challenge(
        task_id=task_id,
        sha256=sha256,
        content_length=content_length,
        expires_at=now + min(max(server.config.request_timeout_seconds * 2, 2.0), 30.0),
    )
    document_arguments = {
        "task_id": task_id,
        "session_id": server.session_id,
        "nonce": nonce,
        "host": str(server.server_address[0]),
        "port": int(server.server_address[1]),
        "sha256": sha256,
        "content_length": content_length,
    }
    if server.config.disposable_peer:
        document = disposable_peer_challenge_document(
            **document_arguments,
            receiver_process_id=server.receiver_process_id,
        )
    else:
        document = challenge_document(**document_arguments)
    body = canonical_json_bytes(document)
    authentication = challenge_authentication(task_key, document)
    return _RequestResult(
        _json_response(
            200,
            document,
            body=body,
            extra_headers={"X-BlueFire-Authentication": authentication},
        ),
        issued_challenge=True,
    )


def _receive_artifact(
    server: _LoopbackTCPServer,
    stream: _DeadlineReader,
    headers: Mapping[str, str],
) -> _RequestResult:
    _validate_host_header(server, headers)
    _validate_header_names(
        headers,
        required={
            "host",
            "content-type",
            "content-length",
            "x-bluefire-sha256",
            "x-bluefire-task-id",
            "x-bluefire-session-id",
            "x-bluefire-nonce",
            "x-bluefire-authentication",
        },
        allowed={
            "host",
            "content-type",
            "content-length",
            "connection",
            "x-bluefire-sha256",
            "x-bluefire-task-id",
            "x-bluefire-session-id",
            "x-bluefire-nonce",
            "x-bluefire-authentication",
        },
    )
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

    task_id = headers.get("x-bluefire-task-id", "")
    session_id = headers.get("x-bluefire-session-id", "")
    nonce = headers.get("x-bluefire-nonce", "")
    supplied_authentication = headers.get("x-bluefire-authentication", "")
    try:
        task_key = derive_receiver_task_key(server.config.authentication_key, task_id)
        request = request_document(
            task_id=task_id,
            session_id=session_id,
            nonce=nonce,
            host=str(server.server_address[0]),
            port=int(server.server_address[1]),
            sha256=expected_digest,
            content_length=content_length,
        )
        expected_authentication = request_authentication(task_key, request)
    except ReceiverAuthenticationError as exc:
        raise _ProtocolRefusal(401, "receiver_authentication_failed") from exc
    challenge = server.challenges.get(nonce)
    if (
        session_id != server.session_id
        or challenge is None
        or challenge.task_id != task_id
        or challenge.sha256 != expected_digest
        or challenge.content_length != content_length
        or challenge.expires_at <= time.monotonic()
        or not verify_authentication(supplied_authentication, expected_authentication)
    ):
        raise _ProtocolRefusal(401, "receiver_authentication_failed")
    # A challenge is one-time even when the subsequent body is malformed.
    del server.challenges[nonce]

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
    if server.config.disposable_peer:
        result = disposable_peer_result_document(
            task_id=task_id,
            session_id=session_id,
            bytes_received=len(body),
            sha256=actual_digest,
            receiver_process_id=server.receiver_process_id,
        )
    else:
        result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "accepted": True,
            "task_id": task_id,
            "session_id": session_id,
            "bytes_received": len(body),
            "sha256": actual_digest,
            "stored": stored,
        }
    response_body = canonical_json_bytes(result)
    authentication = response_authentication(
        task_key,
        supplied_authentication,
        response_body,
    )
    return _RequestResult(
        _json_response(
            status,
            result,
            body=response_body,
            extra_headers={"X-BlueFire-Authentication": authentication},
        ),
        accepted_artifact=True,
        accepted_artifact_binding={
            "task_id": task_id,
            "sha256": actual_digest,
            "bytes_received": len(body),
        },
    )


def _validate_host_header(server: _LoopbackTCPServer, headers: Mapping[str, str]) -> None:
    if headers.get("host") != _host_authority(server):
        raise _ProtocolRefusal(421, "host_mismatch")


def _host_authority(server: _LoopbackTCPServer) -> str:
    host = str(server.server_address[0])
    rendered = f"[{host}]" if ":" in host else host
    return f"{rendered}:{int(server.server_address[1])}"


def _validate_header_names(
    headers: Mapping[str, str],
    *,
    required: set[str],
    allowed: set[str],
) -> None:
    names = set(headers)
    if not required.issubset(names) or not names.issubset(allowed):
        raise _ProtocolRefusal(400, "invalid_header_set")


def _read_headers(stream: _DeadlineReader) -> dict[str, str]:
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
            value = raw_value.decode("ascii").strip(" ")
        except UnicodeDecodeError as exc:
            raise _ProtocolRefusal(400, "invalid_header") from exc
        if (
            _HEADER_NAME.fullmatch(name) is None
            or name in headers
            or not value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise _ProtocolRefusal(400, "invalid_header")
        headers[name] = value
    raise _ProtocolRefusal(431, "too_many_headers")


def _read_crlf_line(
    stream: _DeadlineReader,
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


def _read_exact(stream: _DeadlineReader, length: int) -> bytes:
    body = bytearray()
    while len(body) < length:
        chunk = stream.read(min(64 * 1024, length - len(body)))
        if not chunk:
            raise _ProtocolRefusal(400, "content_length_mismatch")
        body.extend(chunk)
    return bytes(body)


def _json_response(
    status: int,
    payload: Mapping[str, object],
    *,
    body: bytes | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> bytes:
    reason = {
        200: "OK",
        201: "Created",
        400: "Bad Request",
        401: "Unauthorized",
        421: "Misdirected Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        411: "Length Required",
        413: "Content Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        422: "Unprocessable Content",
        431: "Request Header Fields Too Large",
        500: "Internal Server Error",
        505: "HTTP Version Not Supported",
    }.get(status, "Error")
    body = body if body is not None else canonical_json_bytes(dict(payload))
    headers = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "Connection: close",
    ]
    if status == 405:
        headers.append("Allow: GET, POST")
    for name, value in (extra_headers or {}).items():
        headers.append(f"{name}: {value}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body


class LoopbackArtifactReceiver:
    """Own one bounded receiver socket and serve it synchronously."""

    def __init__(self, config: ReceiverConfig) -> None:
        address = ipaddress.ip_address(config.host)
        storage = _ReceiverStorage(config.storage_dir) if config.storage_dir else None
        server_type = _LoopbackTCPServerV6 if address.version == 6 else _LoopbackTCPServer
        try:
            self._server = server_type(
                (config.host, config.port),
                _ReceiverHandler,
                config=config,
                storage=storage,
            )
        except BaseException:
            if storage is not None:
                storage.close()
            raise
        self._config = config
        self._stopping = threading.Event()
        self._closed = False

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def process_id(self) -> int:
        return self._server.receiver_process_id

    @property
    def accepted_artifact_bindings(self) -> tuple[Mapping[str, object], ...]:
        """Return path-free identities observed by this receiver instance."""

        return tuple(dict(binding) for binding in self._server.accepted_artifact_bindings)

    def serve(self) -> Mapping[str, object]:
        reason = "explicit_stop"
        idle_deadline = time.monotonic() + self._config.idle_timeout_seconds
        lifetime_deadline = self._server.lifecycle_deadline
        try:
            while (
                not self._stopping.is_set()
                and self._server.requests_accepted < self._config.max_requests
                and self._server.connections_handled < self._config.max_connections
            ):
                now = time.monotonic()
                remaining = idle_deadline - now
                if lifetime_deadline is not None:
                    lifetime_remaining = lifetime_deadline - now
                    if lifetime_remaining <= 0:
                        reason = "lifecycle_timeout"
                        break
                    remaining = min(remaining, lifetime_remaining)
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
            "challenges_issued": self._server.challenges_issued,
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
            if config.disposable_peer:
                ready = {
                    "schema_version": "bluefire.loopback-receiver-ready.v2",
                    "mode": "disposable_peer",
                    "process_id": receiver.process_id,
                    "host": receiver.host,
                    "port": receiver.port,
                    "max_requests": 1,
                    "max_connections": DISPOSABLE_PEER_MAX_CONNECTIONS,
                    "storage": "memory_only",
                }
            else:
                ready = {
                    "schema_version": "bluefire.loopback-receiver-ready.v1",
                    "host": receiver.host,
                    "port": receiver.port,
                    "max_requests": config.max_requests,
                    "max_connections": config.max_connections,
                    "max_body_bytes": config.max_body_bytes,
                    "storage": "receiver_owned" if config.storage_dir else "memory_only",
                    "authentication": "managed_task_hmac_sha256",
                }
            print(json.dumps(ready, separators=(",", ":"), sort_keys=True), file=ready_stream)
            ready_stream.flush()
        return receiver.serve()


__all__ = [
    "ARTIFACT_PATH",
    "CHALLENGE_PATH",
    "DEFAULT_IDLE_TIMEOUT_SECONDS",
    "DEFAULT_MAX_BODY_BYTES",
    "DISPOSABLE_PEER_IDLE_TIMEOUT_SECONDS",
    "DISPOSABLE_PEER_LIFETIME_TIMEOUT_SECONDS",
    "DISPOSABLE_PEER_MAX_CONNECTIONS",
    "DISPOSABLE_PEER_REQUEST_TIMEOUT_SECONDS",
    "LoopbackArtifactReceiver",
    "ReceiverConfig",
    "run_loopback_receiver",
]
