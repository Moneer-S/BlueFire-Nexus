"""Controller-only, single-exchange Linux Docker Unix-socket HTTP transport.

The endpoint is an admission input, never a worker input. Its digest is a
controller binding, not a daemon identity discovered or granted by this module.
The socket inode and Linux peer credentials are checked before sending bytes.
No environment proxy, name lookup, TCP connection, redirect, or retry is used.
Chunked transfer framing is validated and replaced with Content-Length for the
existing proxy response validator; content and semantic headers are unchanged.
"""

from __future__ import annotations

import errno
import hashlib
import math
import os
import re
import select
import socket
import stat
import struct
import sys
import time
from contextlib import nullcontext
from dataclasses import dataclass

from .engine_docker_attached_stream import (
    MAX_DOCKER_STREAM_OVERHEAD_BYTES,
    DockerAttachedOutput,
    DockerAttachedStreamError,
    DockerMultiplexAccumulator,
)
from .engine_docker_proxy import (
    DockerDaemonExchange,
    DockerExecDispatchGate,
    DockerProxyCancellation,
    EngineDockerProxyError,
    parse_docker_http_request,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_STATUS = re.compile(rb"HTTP/1\.1 ([1-5][0-9]{2})(?: [\x20-\x7e]{0,64})?")
_MAX_BODY = 32 * 1024**2
_MAX_HEADER = 32 * 1024
_MAX_WIRE = 64 * 1024**2
_EXEC_START = re.compile(r"/v1\.[0-9]+/exec/[0-9a-f]{64}/start")


@dataclass(frozen=True, slots=True)
class LinuxDockerDaemonEndpoint:
    """Already admitted controller endpoint; contains no worker-facing data."""

    socket_path: str
    daemon_instance_digest: str
    socket_device: int
    socket_inode: int
    peer_uid: int
    peer_gid: int
    peer_pid: int

    def __post_init__(self) -> None:
        path = self.socket_path
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or any(part in {"", ".", ".."} for part in path[1:].split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise EngineDockerProxyError("Docker controller endpoint path is invalid")
        try:
            encoded = path.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise EngineDockerProxyError("Docker controller endpoint path is invalid") from exc
        if len(encoded) > 107:
            raise EngineDockerProxyError("Docker controller endpoint path exceeds its bound")
        if (
            not isinstance(self.daemon_instance_digest, str)
            or _DIGEST.fullmatch(self.daemon_instance_digest) is None
        ):
            raise EngineDockerProxyError("Docker controller daemon binding is invalid")
        for value in (self.socket_device, self.socket_inode, self.peer_uid, self.peer_gid):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EngineDockerProxyError("Docker controller endpoint identity is invalid")
        if (
            isinstance(self.peer_pid, bool)
            or not isinstance(self.peer_pid, int)
            or self.peer_pid < 1
        ):
            raise EngineDockerProxyError("Docker controller peer process identity is invalid")


class DockerDaemonTransportError(EngineDockerProxyError):
    """No raw response or endpoint path escapes in transport diagnostics.

    Once a send is attempted, failure is conservatively ambiguous even when the
    syscall reports no transferred bytes. A successful response is still subject
    to the proxy's independent ownership, policy, audit, and publication checks.
    """

    def __init__(
        self,
        code: str,
        *,
        request_may_have_been_sent: bool = False,
        request_bytes_sent: int = 0,
        response_started: bool = False,
    ) -> None:
        super().__init__(f"Docker controller transport {code}")
        self.code = code
        self.request_may_have_been_sent = request_may_have_been_sent
        self.request_bytes_sent = request_bytes_sent
        self.response_started = response_started


class _ExchangeIO:
    def __init__(
        self,
        sock: socket.socket,
        deadline: int,
        cancellation: DockerProxyCancellation,
        poll: float,
        wire_limit: int,
    ) -> None:
        self.sock = sock
        self.deadline = deadline
        self.cancellation = cancellation
        self.poll = poll
        self.wire_limit = wire_limit
        self.send_attempted = False
        self.sent = 0
        self.received = 0
        self.buffer = bytearray()

    def fail(self, code: str) -> DockerDaemonTransportError:
        return DockerDaemonTransportError(
            code,
            request_may_have_been_sent=self.send_attempted,
            request_bytes_sent=self.sent,
            response_started=self.received > 0,
        )

    def check(self) -> None:
        if self.cancellation.is_cancelled():
            raise self.fail("cancelled")
        if time.monotonic_ns() >= self.deadline:
            raise self.fail("deadline_exceeded")

    def ready(self, *, write: bool = False, eof_ok: bool = False) -> None:
        poller = select.poll()
        expected = select.POLLOUT if write else select.POLLIN
        poller.register(self.sock, expected | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        while True:
            self.check()
            remaining = (self.deadline - time.monotonic_ns()) / 1_000_000_000
            try:
                events = poller.poll(max(0, math.ceil(min(self.poll, remaining) * 1000)))
            except InterruptedError:
                continue
            self.check()
            if any(flags & expected for _, flags in events):
                return
            if eof_ok and any(flags & select.POLLHUP for _, flags in events):
                return
            if events:
                raise self.fail("socket_failed")

    def receive(self, maximum: int) -> None:
        while True:
            self.ready()
            try:
                block = self.sock.recv(min(maximum, 16384, self.wire_limit - self.received + 1))
            except (BlockingIOError, InterruptedError):
                continue
            if not block:
                raise self.fail("response_incomplete")
            self.received += len(block)
            if self.received > self.wire_limit:
                raise self.fail("response_limit")
            self.buffer.extend(block)
            return

    def receive_or_eof(self, maximum: int) -> bool:
        """Receive one bounded block; EOF is valid for a hijacked stream."""

        while True:
            self.ready(eof_ok=True)
            try:
                block = self.sock.recv(min(maximum, 16384, self.wire_limit - self.received + 1))
            except (BlockingIOError, InterruptedError):
                continue
            if not block:
                return False
            self.received += len(block)
            if self.received > self.wire_limit:
                raise self.fail("response_limit")
            self.buffer.extend(block)
            return True

    def take(self, length: int) -> bytes:
        while len(self.buffer) < length:
            self.receive(length - len(self.buffer))
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def line(self, maximum: int) -> bytes:
        while True:
            position = self.buffer.find(b"\r\n")
            if position >= 0:
                if position + 2 > maximum:
                    raise self.fail("response_limit")
                return self.take(position + 2)
            if len(self.buffer) >= maximum:
                raise self.fail("response_limit")
            self.receive(min(4096, maximum - len(self.buffer)))

    def finish(self) -> None:
        self.check()
        if self.buffer:
            raise self.fail("response_trailing_bytes")
        # A fresh connection is always closed after this exchange. Never read
        # past a complete frame to EOF (Docker may keep the connection open).
        try:
            extra = self.sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError):
            return
        if extra:
            raise self.fail("response_trailing_bytes")


def _response_head(
    stream: _ExchangeIO, header_limit: int, *, allow_switching_protocols: bool = False
) -> tuple[bytes, list[bytes], dict[bytes, bytes], int]:
    lines: list[bytes] = []
    size = 0
    while True:
        line = stream.line(header_limit - size)
        size += len(line)
        if line == b"\r\n":
            break
        lines.append(line[:-2])
    if not lines or _STATUS.fullmatch(lines[0]) is None:
        raise stream.fail("response_framing")
    status = int(lines[0].split(b" ", 2)[1])
    if (status < 200 and not (allow_switching_protocols and status == 101)) or (
        300 <= status < 400
    ):
        raise stream.fail("response_status_refused")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise stream.fail("response_framing")
        name, value = line.split(b":", 1)
        if _HEADER_NAME.fullmatch(name) is None:
            raise stream.fail("response_framing")
        name = name.lower()
        value = value.strip(b" \t")
        if name in headers or not value or any(c < 32 or c >= 127 for c in value):
            raise stream.fail("response_framing")
        headers[name] = value
    if b"trailer" in headers or (b"upgrade" in headers and not allow_switching_protocols):
        raise stream.fail("response_framing")
    return b"\r\n".join(lines) + b"\r\n\r\n", lines, headers, status


def _response(stream: _ExchangeIO, *, body_limit: int, header_limit: int, head: bool) -> bytes:
    raw_head, lines, headers, status = _response_head(stream, header_limit)
    length_text = headers.get(b"content-length")
    transfer = headers.get(b"transfer-encoding")
    if transfer is not None and (length_text is not None or transfer.lower() != b"chunked"):
        raise stream.fail("response_framing")
    if head or status == 204:
        if transfer is not None:
            raise stream.fail("response_framing")
        if length_text is None and status == 204:
            length_text = b"0"
        length = _content_length(stream, length_text, body_limit)
        if status == 204 and length != 0:
            raise stream.fail("response_framing")
        stream.finish()
        return raw_head
    if transfer is None:
        length = _content_length(stream, length_text, body_limit)
        body = stream.take(length)
        stream.finish()
        return raw_head + body
    body = bytearray()
    for _ in range(8192):
        chunk_line = stream.line(128)[:-2]
        if re.fullmatch(rb"[0-9A-Fa-f]{1,16}", chunk_line) is None:
            raise stream.fail("response_framing")
        length = int(chunk_line, 16)
        if length > body_limit - len(body):
            raise stream.fail("response_limit")
        if length == 0:
            if stream.line(2) != b"\r\n":
                raise stream.fail("response_framing")
            stream.finish()
            normalized = [
                line for line in lines if line.split(b":", 1)[0].lower() != b"transfer-encoding"
            ]
            normalized.append(b"Content-Length: " + str(len(body)).encode("ascii"))
            normalized_head = b"\r\n".join(normalized) + b"\r\n\r\n"
            if len(normalized_head) > header_limit:
                raise stream.fail("response_limit")
            return normalized_head + bytes(body)
        body.extend(stream.take(length))
        if stream.take(2) != b"\r\n":
            raise stream.fail("response_framing")
    raise stream.fail("response_limit")


def _attached_head(
    stream: _ExchangeIO, header_limit: int
) -> tuple[list[bytes], dict[bytes, bytes]]:
    _raw_head, lines, headers, status = _response_head(
        stream, header_limit, allow_switching_protocols=True
    )
    allowed = {
        b"api-version",
        b"connection",
        b"content-type",
        b"date",
        b"docker-experimental",
        b"ostype",
        b"server",
        b"upgrade",
    }
    if set(headers) - allowed:
        raise stream.fail("attach_response_headers")
    if headers.get(b"content-type") != b"application/vnd.docker.multiplexed-stream":
        raise stream.fail("attach_content_type")
    connection = headers.get(b"connection", b"").lower()
    upgrade = headers.get(b"upgrade", b"").lower()
    if status == 101:
        if connection != b"upgrade" or upgrade != b"tcp":
            raise stream.fail("attach_upgrade_invalid")
    elif status == 200:
        if connection not in {b"", b"close", b"upgrade"}:
            raise stream.fail("attach_connection_invalid")
        if (connection == b"upgrade") != (upgrade == b"tcp") or (
            connection != b"upgrade" and upgrade
        ):
            raise stream.fail("attach_upgrade_invalid")
    else:
        raise stream.fail("attach_status_refused")
    return lines, headers


def _attached_response(
    stream: _ExchangeIO,
    *,
    decoded_limit: int,
    overhead_limit: int,
    header_limit: int,
) -> tuple[bytes, DockerAttachedOutput]:
    lines, _headers = _attached_head(stream, header_limit)
    state = DockerMultiplexAccumulator(decoded_limit=decoded_limit, overhead_limit=overhead_limit)
    while True:
        while len(stream.buffer) < 8:
            if not stream.receive_or_eof(8 - len(stream.buffer)):
                if stream.buffer:
                    raise stream.fail("attach_frame_truncated")
                output = state.finish()
                preserved = [
                    line
                    for line in lines[1:]
                    if line.split(b":", 1)[0].lower()
                    not in {b"connection", b"upgrade", b"content-length"}
                ]
                normalized = [b"HTTP/1.1 200 OK", *preserved]
                normalized.append(
                    b"Content-Length: " + str(len(output.multiplexed)).encode("ascii")
                )
                rendered = b"\r\n".join(normalized) + b"\r\n\r\n" + output.multiplexed
                if len(rendered) > header_limit + decoded_limit + overhead_limit:
                    raise stream.fail("attach_response_limit")
                return rendered, output
        header = stream.take(8)
        try:
            size = state.admit_header(header)
        except DockerAttachedStreamError as exc:
            raise stream.fail(exc.code) from None
        while len(stream.buffer) < size:
            if not stream.receive_or_eof(size - len(stream.buffer)):
                raise stream.fail("attach_frame_truncated")
        payload = stream.take(size)
        try:
            state.admit_payload(header, payload)
        except DockerAttachedStreamError as exc:
            raise stream.fail(exc.code) from None


def _content_length(stream: _ExchangeIO, text: bytes | None, maximum: int) -> int:
    if (
        text is None
        or len(text) > 20
        or not text.isdigit()
        or str(int(text)).encode("ascii") != text
    ):
        raise stream.fail("response_framing")
    value = int(text)
    if value > maximum:
        raise stream.fail("response_limit")
    return value


class LinuxUnixDockerDaemonTransport:
    """One bounded exchange per pinned local connection, with no replay."""

    def __init__(
        self,
        endpoint: LinuxDockerDaemonEndpoint,
        *,
        response_byte_limit: int = _MAX_BODY,
        header_byte_limit: int = _MAX_HEADER,
        wire_byte_limit: int = _MAX_WIRE,
        stream_overhead_byte_limit: int = MAX_DOCKER_STREAM_OVERHEAD_BYTES,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise EngineDockerProxyError("Docker controller transport requires Linux")
        if not isinstance(endpoint, LinuxDockerDaemonEndpoint):
            raise EngineDockerProxyError("Docker controller endpoint is invalid")
        for value, maximum in (
            (response_byte_limit, _MAX_BODY),
            (header_byte_limit, _MAX_HEADER),
            (wire_byte_limit, _MAX_WIRE),
            (stream_overhead_byte_limit, MAX_DOCKER_STREAM_OVERHEAD_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise EngineDockerProxyError("Docker controller transport bound is invalid")
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not math.isfinite(poll_interval_seconds)
            or not 0 < poll_interval_seconds <= 0.1
        ):
            raise EngineDockerProxyError("Docker controller polling bound is invalid")
        self._endpoint = endpoint
        self._body_limit = response_byte_limit
        self._header_limit = header_byte_limit
        self._wire_limit = wire_byte_limit
        self._stream_overhead_limit = stream_overhead_byte_limit
        self._poll = poll_interval_seconds

    def _identity(self, stream: _ExchangeIO) -> None:
        info = os.lstat(self._endpoint.socket_path)
        if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != (
            self._endpoint.socket_device,
            self._endpoint.socket_inode,
        ):
            raise stream.fail("endpoint_identity_changed")

    def exchange(
        self,
        raw_request: bytes,
        *,
        deadline_monotonic_ns: int,
        cancellation: DockerProxyCancellation,
        response_byte_limit: int | None = None,
        dispatch_gate: DockerExecDispatchGate | None = None,
    ) -> DockerDaemonExchange:
        if response_byte_limit is None:
            response_byte_limit = self._body_limit
        if (
            isinstance(deadline_monotonic_ns, bool)
            or not isinstance(deadline_monotonic_ns, int)
            or deadline_monotonic_ns < 0
        ):
            raise DockerDaemonTransportError("deadline_invalid")
        if cancellation.is_cancelled():
            raise DockerDaemonTransportError("cancelled")
        if time.monotonic_ns() >= deadline_monotonic_ns:
            raise DockerDaemonTransportError("deadline_exceeded")
        if (
            isinstance(response_byte_limit, bool)
            or not isinstance(response_byte_limit, int)
            or not 1 <= response_byte_limit <= self._body_limit
        ):
            raise DockerDaemonTransportError("response_limit_invalid")
        # Recheck complete framing at the effect boundary, without changing bytes.
        try:
            request = parse_docker_http_request(raw_request)
        except EngineDockerProxyError:
            raise DockerDaemonTransportError("request_framing") from None
        is_exec_start = request.method == "POST" and _EXEC_START.fullmatch(request.target)
        if is_exec_start:
            values = dict(request.headers)
            if (
                values.get("connection", "").lower() != "upgrade"
                or values.get("upgrade", "").lower() != "tcp"
            ):
                raise DockerDaemonTransportError("attach_request_upgrade_required")
        request_digest = "sha256:" + hashlib.sha256(raw_request).hexdigest()
        if dispatch_gate is not None and (
            dispatch_gate.request_digest != request_digest
            or dispatch_gate.entered
            or dispatch_gate.sent
        ):
            raise DockerDaemonTransportError("dispatch_gate_binding")
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError:
            raise DockerDaemonTransportError("socket_failed") from None
        with sock:
            stream = _ExchangeIO(
                sock, deadline_monotonic_ns, cancellation, self._poll, self._wire_limit
            )
            try:
                sock.setblocking(False)
                stream.check()
                self._identity(stream)
                stream.check()
                connected = sock.connect_ex(self._endpoint.socket_path)
                if connected not in (0, errno.EISCONN):
                    if connected not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                        raise stream.fail("connect_failed")
                    stream.ready(write=True)
                    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                        raise stream.fail("connect_failed")
                self._identity(stream)
                pid, uid, gid = struct.unpack(
                    "3i",
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
                )
                if (pid, uid, gid) != (
                    self._endpoint.peer_pid,
                    self._endpoint.peer_uid,
                    self._endpoint.peer_gid,
                ):
                    raise stream.fail("peer_identity_changed")
                view = memoryview(raw_request)
                gate_context = (
                    dispatch_gate.before_send() if dispatch_gate is not None else nullcontext()
                )
                with gate_context:
                    while stream.sent < len(view):
                        stream.ready(write=True)
                        stream.check()
                        stream.send_attempted = True
                        try:
                            sent = sock.send(view[stream.sent :])
                        except (BlockingIOError, InterruptedError):
                            continue
                        if sent == 0:
                            raise stream.fail("send_incomplete")
                        stream.sent += sent
                if dispatch_gate is not None and (
                    not dispatch_gate.entered or not dispatch_gate.sent
                ):
                    raise stream.fail("dispatch_gate_unsettled")
                if is_exec_start:
                    response, _output = _attached_response(
                        stream,
                        decoded_limit=response_byte_limit,
                        overhead_limit=self._stream_overhead_limit,
                        header_limit=self._header_limit,
                    )
                else:
                    response = _response(
                        stream,
                        body_limit=min(self._body_limit, response_byte_limit),
                        header_limit=self._header_limit,
                        head=request.method == "HEAD",
                    )
                stream.check()
                return DockerDaemonExchange(
                    request_digest=request_digest,
                    daemon_instance_digest=self._endpoint.daemon_instance_digest,
                    raw_response=response,
                )
            except DockerDaemonTransportError:
                raise
            except OSError:
                raise stream.fail("socket_failed") from None


__all__ = [
    "DockerDaemonTransportError",
    "DockerExecDispatchGate",
    "LinuxDockerDaemonEndpoint",
    "LinuxUnixDockerDaemonTransport",
]
