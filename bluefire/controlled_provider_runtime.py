"""Controller-owned local Test-provider runtime; never a live-provider adapter.

Two attempt-local numeric-loopback listeners isolate the worker gateway bearer
from the private fixture bearer. All serving is deterministic; schemas captured
from an installed candidate still need an independently reviewed code enrollment.
No environment credentials, URL, DNS, proxy, redirect, or retry are consulted.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .controlled_provider_forwarder import (
    ControlledProviderAuditReceipt,
    ControlledProviderBinding,
    ControlledProviderDispatch,
    ControllerOwnedControlledProviderForwarder,
)
from .controlled_provider_preflight import (
    preflight_response,
    validate_preflight_request,
    validate_preflight_response,
)
from .controlled_strix_provider import (
    PROVIDER_LABEL,
    ControlledProviderManifest,
    ControlledProviderState,
    TargetInspectionSeed,
)
from .engine_relay import (
    BoundedRelayAudit,
    ControlledModelGateway,
    ModelGatewayPolicy,
    ModelGatewayRequest,
    ProtectedModelResult,
    _controlled_stream_tool_names,
    _digest_bytes,
    _json_contains_secret,
    _parse_controlled_sse,
    _secret_in_bytes,
    _strict_json,
)
from .strix_tool_conformance import MODEL_ID, canonical_json
from .util import content_hash

_REQUEST_ID = re.compile(r"gateway-request-[0-9a-f]{32}\Z")
_HEAD_CAP = 16_384


class ProtectedControlledProviderAudit:
    """Bounded private dispatch journal; only exact immutable receipts leave it."""

    def __init__(self, *, max_records: int) -> None:
        if type(max_records) is not int or not 1 <= max_records <= 32:
            raise ValueError("controlled audit capacity is invalid")
        self._max_records = max_records
        self._lock = threading.Lock()
        self._receipts: dict[str, ControlledProviderAuditReceipt] = {}

    def record(self, receipt: ControlledProviderAuditReceipt) -> None:
        if not isinstance(receipt, ControlledProviderAuditReceipt):
            raise ValueError("controlled audit row is invalid")
        with self._lock:
            if (
                len(self._receipts) >= self._max_records
                or receipt.request_id in self._receipts
                or any(row.sequence == receipt.sequence for row in self._receipts.values())
            ):
                raise ValueError("controlled audit row is duplicate or over budget")
            self._receipts[receipt.request_id] = receipt

    def correlate(
        self, binding: ControlledProviderBinding, request_id: str
    ) -> tuple[ControlledProviderAuditReceipt, ...]:
        with self._lock:
            receipt = self._receipts.get(request_id)
            if receipt is None or receipt.binding_ref != binding.binding_ref:
                return ()
            # Revalidation also prevents unchecked mutable/untyped source rows.
            return (ControlledProviderAuditReceipt(**vars_from_receipt(receipt)),)


def vars_from_receipt(receipt: ControlledProviderAuditReceipt) -> dict[str, Any]:
    return {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}


class NumericLoopbackControlledProviderTransport:
    """One AF_INET dispatch with absolute deadline, strict framing and secret scan."""

    def __init__(
        self,
        binding: ControlledProviderBinding,
        bearer: str,
        audit: ProtectedControlledProviderAudit,
        *,
        monotonic_ns: Callable[[], int],
    ) -> None:
        if _digest_bytes(bearer.encode("ascii")) != binding.material_ref:
            raise ValueError("controlled material differs from binding")
        self._binding = binding
        self._bearer = bearer
        self._audit = audit
        self._monotonic_ns = monotonic_ns

    def __repr__(self) -> str:
        return f"{type(self).__name__}(binding_ref={self._binding.binding_ref!r})"

    def _remaining(self, request: ControlledProviderDispatch) -> float:
        remaining = (request.deadline_ns - self._monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise ValueError("controlled dispatch deadline elapsed")
        return remaining

    def post_chat_completions(self, request: ControlledProviderDispatch) -> ProtectedModelResult:
        failed = False
        try:
            return self._dispatch(request)
        except Exception:
            failed = True
        # Never retain protected exception text or exception context.
        assert failed
        raise ValueError("controlled dispatch failed")

    def _dispatch(self, request: ControlledProviderDispatch) -> ProtectedModelResult:
        policy = self._binding.policy
        if (
            not isinstance(request, ControlledProviderDispatch)
            or request.binding_ref != self._binding.binding_ref
            or request.port != self._binding.port
            or request.host != "127.0.0.1"
            or request.method != "POST"
            or request.path != "/v1/chat/completions"
            or request.content_type != "application/json"
            or request.allow_dns
            or request.allow_proxy
            or request.allow_redirects
            or _REQUEST_ID.fullmatch(request.request_id) is None
            or not isinstance(request.body, bytes)
            or not 0 < len(request.body) <= policy.max_request_bytes
            or request.max_response_bytes != policy.max_response_bytes
            or type(request.deadline_ns) is not int
            or request.deadline_ns > self._monotonic_ns() + policy.request_timeout_ms * 1_000_000
        ):
            raise ValueError("controlled dispatch scope differs")
        # Raw sockets avoid HTTPConnection's getaddrinfo, environment proxies,
        # redirect handlers, automatic reconnect and SDK retry behavior.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
            channel.settimeout(self._remaining(request))
            channel.connect(("127.0.0.1", request.port))
            headers = (
                "POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{request.port}\r\n"
                f"Authorization: Bearer {self._bearer}\r\n"
                f"X-BlueFire-Request: {request.request_id}\r\n"
                f"X-BlueFire-Binding: {request.binding_ref}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(request.body)}\r\n\r\n"
            ).encode("ascii")
            channel.settimeout(self._remaining(request))
            channel.sendall(headers + request.body)
            received = bytearray()
            while b"\r\n\r\n" not in received:
                channel.settimeout(self._remaining(request))
                block = channel.recv(1)
                if not block or len(received) >= _HEAD_CAP:
                    raise ValueError("controlled response headers exceed limit")
                received.extend(block)
            raw_headers = bytes(received)
            if _secret_in_bytes(self._bearer, raw_headers):
                raise ValueError("controlled response contains material")
            lines = raw_headers[:-4].decode("ascii").split("\r\n")
            if lines[0] != "HTTP/1.1 200 OK":
                raise ValueError("controlled response status differs")
            rows: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, value = line.partition(": ")
                name = name.lower()
                if (
                    not separator
                    or name in rows
                    or name
                    not in {
                        "content-type",
                        "content-length",
                        "cache-control",
                        "x-bluefire-provider",
                    }
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)
                ):
                    raise ValueError("controlled response headers differ")
                rows[name] = value
            if _json_contains_secret(rows, self._bearer):
                raise ValueError("controlled headers contain encoded material")
            length = rows.get("content-length", "")
            if not length.isascii() or not length.isdecimal() or str(int(length)) != length:
                raise ValueError("controlled response framing differs")
            count = int(length)
            if not 0 < count <= request.max_response_bytes:
                raise ValueError("controlled response exceeds byte cap")
            body = bytearray()
            while len(body) < count:
                channel.settimeout(self._remaining(request))
                block = channel.recv(min(4096, count - len(body)))
                if not block:
                    raise ValueError("controlled response is incomplete")
                body.extend(block)
            self._remaining(request)
        payload = bytes(body)
        if _secret_in_bytes(self._bearer, payload):
            raise ValueError("controlled response contains material")
        document = _strict_json(request.body, label="controlled dispatch request")
        if document.get("stream") is True:
            stream = _parse_controlled_sse(
                payload,
                attempt_id=policy.attempt_id,
                model_id=policy.model_id,
                tool_names=_controlled_stream_tool_names(document),
                bearer=self._bearer,
                max_input_tokens=policy.max_input_tokens_per_request,
                max_output_tokens=policy.max_output_tokens_per_request,
            )
            usage = (stream.input_tokens, stream.output_tokens)
            response_id = stream.documents[0]["id"]
        else:
            response = _strict_json(payload, label="controlled preflight response")
            if _json_contains_secret(response, self._bearer):
                raise ValueError("controlled response contains encoded material")
            response_id = response.get("id")
            if (
                not isinstance(response_id, str)
                or re.fullmatch(rf"chatcmpl-{policy.attempt_id[-12:]}-[0-9]{{4}}", response_id)
                is None
            ):
                raise ValueError("controlled response identity differs")
            usage = validate_preflight_response(
                response,
                attempt_id=policy.attempt_id,
                sequence=int(response_id[-4:]),
                max_input_tokens=policy.max_input_tokens_per_request,
                max_output_tokens=policy.max_output_tokens_per_request,
            )
        receipts = self._audit.correlate(self._binding, request.request_id)
        if len(receipts) != 1:
            raise ValueError("controlled response audit is missing")
        receipt = receipts[0]
        if (
            receipt.request_digest != _digest_bytes(request.body)
            or receipt.request_bytes != len(request.body)
            or receipt.response_digest != _digest_bytes(payload)
            or receipt.response_bytes != len(payload)
            or (receipt.input_tokens, receipt.output_tokens) != usage
            or response_id != f"chatcmpl-{policy.attempt_id[-12:]}-{receipt.sequence:04d}"
        ):
            raise ValueError("controlled response audit differs")
        return ProtectedModelResult(
            status=200,
            headers=rows,
            body=payload,
            input_tokens=usage[0],
            output_tokens=usage[1],
            cost_microunits=0,
            provider_request_ref=receipt.provider_request_ref,
            protected_secret_absent=True,
            fixture_usage_estimate=True,
            live_model_proof=False,
        )


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    request_queue_size = 4

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._slots = threading.BoundedSemaphore(4)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # HTTP parse failures must not publish request content in process logs.
        pass

    def server_bind(self) -> None:
        # HTTPServer.server_bind performs reverse DNS for server_name. Bypass it.
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


class _DeadlineInput:
    """Unbuffered bounded input so slow headers/body cannot renew the deadline."""

    def __init__(self, channel: socket.socket, maximum: int) -> None:
        self._channel = channel
        self._deadline = time.monotonic() + 5
        self._remaining_bytes = maximum
        self._header_bytes = 0

    def read(self, size: int) -> bytes:
        if not 0 <= size <= self._remaining_bytes:
            raise ValueError("controlled listener read exceeds cap")
        data = bytearray()
        while len(data) < size:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("controlled listener read elapsed")
            self._channel.settimeout(remaining)
            block = self._channel.recv(min(4096, size - len(data)))
            if not block:
                break
            data.extend(block)
        self._remaining_bytes -= len(data)
        return bytes(data)

    def readline(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < min(size, _HEAD_CAP):
            block = self.read(1)
            if not block:
                break
            data.extend(block)
            if block == b"\n":
                self._header_bytes += len(data)
                if self._header_bytes > _HEAD_CAP:
                    raise ValueError("controlled listener headers exceed cap")
                return bytes(data)
        if data and not data.endswith(b"\n"):
            raise ValueError("controlled listener line exceeds cap")
        return bytes(data)

    def close(self) -> None:
        pass


def _handler(
    max_request_bytes: int,
    callback: Callable[[Mapping[str, str], bytes], tuple[int, Mapping[str, str], bytes]],
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def setup(self) -> None:
            super().setup()
            self.rfile.close()
            self.rfile = _DeadlineInput(self.connection, max_request_bytes + _HEAD_CAP)  # type: ignore[assignment]

        def do_POST(self) -> None:  # noqa: N802
            try:
                if self.path != "/v1/chat/completions":
                    raise ValueError("route refused")
                allowed = {
                    "host",
                    "authorization",
                    "content-type",
                    "content-length",
                    "accept",
                    "user-agent",
                    "x-bluefire-request",
                    "x-bluefire-binding",
                    "accept-encoding",
                    "connection",
                    "x-stainless-lang",
                    "x-stainless-package-version",
                    "x-stainless-os",
                    "x-stainless-arch",
                    "x-stainless-runtime",
                    "x-stainless-runtime-version",
                    "x-stainless-async",
                    "x-stainless-retry-count",
                    "x-stainless-read-timeout",
                }
                rows: dict[str, str] = {}
                for key, value in self.headers.items():
                    name = key.lower()
                    if name in rows or name not in allowed or len(value) > 8192:
                        raise ValueError("headers refused")
                    rows[name] = value
                length = rows.get("content-length", "")
                if (
                    rows.get("content-type") != "application/json"
                    or not length.isascii()
                    or not length.isdecimal()
                    or str(int(length)) != length
                    or not 0 < int(length) <= max_request_bytes
                ):
                    raise ValueError("framing refused")
                body = self.rfile.read(int(length))
                if len(body) != int(length):
                    raise ValueError("body incomplete")
                status, headers, payload = callback(rows, body)
            except Exception:
                status, headers, payload = (
                    400,
                    {"content-type": "application/json", "cache-control": "no-store"},
                    b'{"error":{"message":"Test provider request refused","type":"invalid_request_error","code":"request_refused"}}',
                )
            self.close_connection = True
            self.send_response_only(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def handle_expect_100(self) -> bool:
            return False

    return Handler


class ControllerOwnedTestProviderRuntime:
    """Own one immutable attempt, fixture generation, gateway and listeners.

    The optional manifest remains an offline candidate until code enrollment.
    Without it, only one exact no-tools CLI preflight can be served. Closing
    revokes and drains gateway work before releasing either listener. Revoking
    the gateway itself leaves the generated target lab untouched.
    """

    def __init__(
        self,
        policy: ModelGatewayPolicy,
        gateway_bearer: str,
        *,
        manifest: ControlledProviderManifest | None = None,
        target_seed_verifier: Callable[[TargetInspectionSeed], bool] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not isinstance(policy, ModelGatewayPolicy) or (
            manifest is not None and not isinstance(manifest, ControlledProviderManifest)
        ):
            raise ValueError("controlled runtime policy or manifest is invalid")
        if (
            policy.model_id != MODEL_ID
            or not policy.allow_controlled_test_sse
            or not isinstance(gateway_bearer, str)
            or not gateway_bearer.isascii()
            or not 32 <= len(gateway_bearer) <= 512
            or any(ord(char) < 33 or ord(char) > 126 for char in gateway_bearer)
            or _digest_bytes(gateway_bearer.encode("ascii")) != policy.authorization_digest
            or policy.max_requests > 3
            or (
                manifest is not None
                and (
                    manifest.attempt_id != policy.attempt_id
                    or manifest.model_id != policy.model_id
                    or policy.max_request_bytes != manifest.max_request_bytes
                    or policy.max_response_bytes != manifest.max_response_bytes
                    or policy.max_input_tokens_per_request != manifest.max_input_tokens
                    or policy.max_output_tokens_per_request != manifest.max_output_tokens
                    or policy.max_requests != manifest.max_requests + 1
                )
            )
        ):
            raise ValueError("controlled runtime policy differs from fixture")
        self._lock = threading.RLock()
        self._serve_lock = threading.Lock()
        self._clock = clock
        self._monotonic_ns = monotonic_ns
        self._pid = os.getpid()
        self._closed = False
        self._sequence = 0
        self._preflight_done = False
        self._manifest = manifest
        self._target_seed_verifier = target_seed_verifier
        self._state: ControlledProviderState | None = None
        self._provider_bearer = secrets.token_urlsafe(48)
        if hmac.compare_digest(gateway_bearer, self._provider_bearer):
            raise ValueError("controlled runtime bearers overlap")
        self.audit = ProtectedControlledProviderAudit(max_records=policy.max_requests)
        self.relay_audit = BoundedRelayAudit(max_records=policy.max_requests + 4)
        self._provider = _LoopbackServer(
            ("127.0.0.1", 0), _handler(policy.max_request_bytes, self._fixture)
        )
        self._provider_thread = threading.Thread(target=self._provider.serve_forever, daemon=True)
        generation = content_hash({"generation_nonce": secrets.token_hex(32), "pid": self._pid})
        self.binding = ControlledProviderBinding(
            policy=policy,
            generation_ref=generation,
            manifest_ref=manifest.digest
            if manifest is not None
            else content_hash({"preflight_only": True}),
            material_ref=_digest_bytes(self._provider_bearer.encode("ascii")),
            readiness_ref=content_hash(
                {"generation": generation, "socket": self._provider.server_address}
            ),
            custody_ref=content_hash(
                {"generation": generation, "pid": self._pid, "fd": self._provider.fileno()}
            ),
            port=self._provider.server_port,
        )
        self.transport = NumericLoopbackControlledProviderTransport(
            self.binding,
            self._provider_bearer,
            self.audit,
            monotonic_ns=monotonic_ns,
        )
        self.forwarder = ControllerOwnedControlledProviderForwarder(
            self.binding,
            self,
            self.transport,
            self.audit,
            monotonic_ns=monotonic_ns,
            clock=clock,
        )
        self.gateway = ControlledModelGateway(
            policy,
            gateway_bearer,
            self.forwarder,
            self.relay_audit,
            clock=clock,
            monotonic_ns=monotonic_ns,
        )
        try:
            self._gateway_server = _LoopbackServer(
                ("127.0.0.1", 0), _handler(policy.max_request_bytes, self._gateway_request)
            )
        except Exception:
            self._provider.server_close()
            raise
        self._gateway_thread = threading.Thread(
            target=self._gateway_server.serve_forever, daemon=True
        )
        self._provider_thread.start()
        self._gateway_thread.start()

    @property
    def gateway_port(self) -> int:
        return self._gateway_server.server_port

    def __repr__(self) -> str:
        return f"{type(self).__name__}(binding_ref={self.binding.binding_ref!r})"

    @contextmanager
    def session(
        self, expected: ControlledProviderBinding
    ) -> Iterator[ControllerOwnedTestProviderRuntime]:
        with self._lock:
            if expected != self.binding:
                raise ValueError("controlled generation scope differs")
            self.checked_binding()
            yield self

    def checked_binding(self) -> ControlledProviderBinding:
        with self._lock:
            if (
                self._closed
                or os.getpid() != self._pid
                or not self._provider_thread.is_alive()
                or not self._gateway_thread.is_alive()
                or self._provider.socket.getsockname() != ("127.0.0.1", self.binding.port)
                or _digest_bytes(self._provider_bearer.encode("ascii")) != self.binding.material_ref
                or self.binding.custody_ref
                != content_hash(
                    {
                        "generation": self.binding.generation_ref,
                        "pid": self._pid,
                        "fd": self._provider.fileno(),
                    }
                )
                or self.binding.readiness_ref
                != content_hash(
                    {
                        "generation": self.binding.generation_ref,
                        "socket": self._provider.server_address,
                    }
                )
                or self.binding.manifest_ref
                != (
                    self._manifest.digest
                    if self._manifest is not None
                    else content_hash({"preflight_only": True})
                )
            ):
                raise ValueError("controlled generation custody is unavailable")
            self._verify_target_seed()
            return self.binding

    def _verify_target_seed(self) -> None:
        if self._manifest is not None and self._manifest.target_inspection_seed is not None:
            if (
                self._target_seed_verifier is None
                or self._target_seed_verifier(self._manifest.target_inspection_seed) is not True
            ):
                raise ValueError("controlled target seed is not independently verified")

    def _fixture(
        self, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        with self._serve_lock:
            policy = self.binding.policy
            request_id = headers.get("x-bluefire-request", "")
            if (
                self._closed
                or _REQUEST_ID.fullmatch(request_id) is None
                or headers.get("host") != f"127.0.0.1:{self.binding.port}"
                or headers.get("x-bluefire-binding") != self.binding.binding_ref
                or not hmac.compare_digest(
                    headers.get("authorization", ""), f"Bearer {self._provider_bearer}"
                )
                or self._sequence >= policy.max_requests
            ):
                raise ValueError("controlled fixture authority differs")
            self._sequence += 1
            sequence = self._sequence
            request = _strict_json(body, label="controlled fixture request")
            if request.get("stream") is True:
                if not self._preflight_done or self._manifest is None:
                    raise ValueError(
                        "controlled tools require completed preflight and enrolled manifest"
                    )
                if self._state is None:
                    self._state = ControlledProviderState(
                        self._manifest,
                        self._provider_bearer,
                        sequence_offset=1,
                        target_seed_verifier=self._target_seed_verifier,
                    )
                payload = self._state.respond(body)
                stream = _parse_controlled_sse(
                    payload,
                    attempt_id=policy.attempt_id,
                    model_id=policy.model_id,
                    tool_names=_controlled_stream_tool_names(request),
                    bearer=self._provider_bearer,
                    max_input_tokens=policy.max_input_tokens_per_request,
                    max_output_tokens=policy.max_output_tokens_per_request,
                )
                usage = (stream.input_tokens, stream.output_tokens)
                response_headers = {
                    "content-type": "text/event-stream",
                    "cache-control": "no-store",
                    "x-bluefire-provider": PROVIDER_LABEL,
                }
            else:
                if self._preflight_done or sequence != 1:
                    raise ValueError("controlled preflight already consumed")
                validate_preflight_request(
                    request, max_output_tokens=policy.max_output_tokens_per_request
                )
                usage = (max(1, (len(body) + 3) // 4), 1)
                if usage[0] > policy.max_input_tokens_per_request:
                    raise ValueError("controlled preflight usage exceeds bound")
                payload = canonical_json(
                    preflight_response(
                        attempt_id=policy.attempt_id,
                        sequence=sequence,
                        created=int(self._clock().timestamp()),
                        input_tokens=usage[0],
                    )
                )
                response_headers = {"content-type": "application/json", "cache-control": "no-store"}
                self._preflight_done = True
            if len(payload) > policy.max_response_bytes:
                raise ValueError("controlled fixture response exceeds cap")
            self.audit.record(
                ControlledProviderAuditReceipt(
                    binding_ref=self.binding.binding_ref,
                    request_id=request_id,
                    sequence=sequence,
                    request_digest=_digest_bytes(body),
                    request_bytes=len(body),
                    response_digest=_digest_bytes(payload),
                    response_bytes=len(payload),
                    status=200,
                    input_tokens=usage[0],
                    output_tokens=usage[1],
                    provider_request_ref=content_hash(
                        {
                            "binding_ref": self.binding.binding_ref,
                            "request_id": request_id,
                            "sequence": sequence,
                            "request_digest": _digest_bytes(body),
                            "response_digest": _digest_bytes(payload),
                        }
                    ),
                )
            )
            return 200, response_headers, payload

    def _gateway_request(
        self, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        if set(headers) & {"x-bluefire-request", "x-bluefire-binding"}:
            raise ValueError("worker cannot select protected dispatch identity")
        # The pinned OpenAI client numbers its initial attempt as zero.  The
        # controlled listener never delegates retry policy to that client: a
        # non-zero, missing, or non-canonical value would make an SDK retry
        # indistinguishable from a fresh controller-owned dispatch after the
        # Stainless metadata is removed below.
        if headers.get("x-stainless-retry-count") != "0":
            raise ValueError("worker retry count is not the initial request")
        policy = self.binding.policy
        result = self.gateway.handle(
            ModelGatewayRequest(
                request_id=f"gateway-request-{secrets.token_hex(16)}",
                attempt_id=policy.attempt_id,
                objective_ref=policy.objective_ref,
                provider_ref=policy.provider_ref,
                authority=headers.get("host", ""),
                authorization=headers.get("authorization", ""),
                body=body,
                headers=tuple(
                    (name, value)
                    for name, value in headers.items()
                    if name in {"content-type", "accept", "user-agent"}
                ),
            )
        )
        return result.status, dict(result.headers), result.body

    def close(self) -> None:
        self.gateway.revoke()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._state is not None:
                self._state.cancel()
            for server in (self._gateway_server, self._provider):
                server.shutdown()
                server.server_close()
            self._gateway_thread.join(timeout=5)
            self._provider_thread.join(timeout=5)
            self._provider_bearer = ""

    def __enter__(self) -> ControllerOwnedTestProviderRuntime:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
