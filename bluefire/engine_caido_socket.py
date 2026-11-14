"""Controller-owned bounded Caido HTTP listener and private connector.

Construction requires protected worker peer custody and already-owned stream
capabilities. Numeric loopback alone is not authentication. There is no default
peer verifier, endpoint discovery, host dial, DNS, proxy, reconnect or redirect.
The connector peer alone may open the exact owned container's loopback 48080.
Caido remains control-plane data; target/model calls retain their separate
controlled relays and the container retains its restrictive network profile.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import select
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from .engine_caido_channel import (
    MAX_HEADER_BYTES,
    MAX_JSON_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESOLUTIONS,
    MAX_RESPONSE_BYTES,
    CaidoEndpointObservation,
    CaidoPendingExchange,
    CaidoPresence,
    EngineCaidoChannel,
    EngineCaidoError,
    EngineCaidoPlan,
    _bootstrap_request_ref,
    _request,
    _response,
)
from .engine_caido_wire import (
    HEADER_BYTES,
    MAC_BYTES,
    CaidoConnectorCredentials,
    authenticate_frame,
    encode_frame,
    inspect_header,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class CaidoSocketLimits:
    max_connections: int = 4
    max_exchanges: int = MAX_RESOLUTIONS
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if (
            type(self.max_connections) is not int
            or not 1 <= self.max_connections <= 8
            or type(self.max_exchanges) is not int
            or not 1 <= self.max_exchanges <= MAX_RESOLUTIONS
            or type(self.timeout_seconds) not in (int, float)
            or not 0 < self.timeout_seconds <= 30
        ):
            raise EngineCaidoError("socket_limits_invalid")


_DEFAULT_LIMITS = CaidoSocketLimits()


@dataclass(frozen=True, slots=True)
class CaidoSocketAudit:
    sequence: int
    plan_digest: str
    outcome: str


@dataclass(frozen=True, slots=True)
class WorkerPeerCustody:
    """Trusted verifier result binding the accepted socket to protected worker custody."""

    plan_digest: str
    attempt_id: str
    worker_ref: str
    peer_host: str
    peer_port: int


class ProtectedWorkerPeerVerifier(Protocol):
    def verify_exact(self, plan: EngineCaidoPlan, connection: socket.socket) -> WorkerPeerCustody:
        """Prove process/network-namespace custody, not merely loopback origin.

        Must be bounded and may not reenter the channel. Production factories
        must supply a platform-backed proof; no permissive implementation is
        provided by this module.
        """
        ...


@dataclass(frozen=True, slots=True)
class OwnedCaidoSocket:
    """Socket supplied by a trusted capability, never an engine-chosen address."""

    plan_digest: str
    attempt_id: str
    container_ref: str
    endpoint_ref: str
    connection: socket.socket = field(repr=False, compare=False)
    container_host: str = "127.0.0.1"
    container_port: int = 48080

    def validate(self, plan: EngineCaidoPlan, endpoint_ref: str) -> None:
        if (
            self.plan_digest != plan.digest
            or self.attempt_id != plan.attempt_id
            or self.container_ref != plan.container_ref
            or self.endpoint_ref != endpoint_ref
            or self.container_host != "127.0.0.1"
            or type(self.container_port) is not int
            or self.container_port != 48080
            or not isinstance(self.connection, socket.socket)
            or self.connection.family not in (socket.AF_INET, getattr(socket, "AF_UNIX", -1))
            or self.connection.type != socket.SOCK_STREAM
            or self.connection.fileno() < 0
        ):
            raise EngineCaidoError("owned_socket_binding_invalid")
        if self.connection.family == socket.AF_INET:
            try:
                local, peer = self.connection.getsockname(), self.connection.getpeername()
            except OSError:
                raise EngineCaidoError("owned_socket_binding_invalid") from None
            if (
                local[0] != "127.0.0.1"
                or peer[0] != "127.0.0.1"
                or (
                    endpoint_ref == plan.upstream_ref
                    and (type(peer[1]) is not int or peer[1] != plan.container_port)
                )
            ):
                raise EngineCaidoError("owned_socket_binding_invalid")


class OwnedCaidoStreamProvider(Protocol):
    def open_exact(self, plan: EngineCaidoPlan) -> OwnedCaidoSocket:
        """Synchronously admit an already-connected owned private stream.

        Must not block, discover addresses or defer stream creation. Controller
        connector streams bind endpoint_ref=plan.connector_ref; connector-peer
        Caido streams bind endpoint_ref=plan.upstream_ref and can reach only
        the owned container's fixed loopback 48080 in its network namespace.
        """
        ...

    def revoke_exact(self, plan: EngineCaidoPlan) -> None:
        """Cancel the owned remote peer/endpoint capability for this attempt.

        Must close outstanding remote streams and stop new admission before
        returning. Absence is separately observed; no resource cleanup claim.
        """
        ...

    def observe_exact(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        """Report exact capability absence, including remote owned streams."""
        ...


def _close(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


def _prepare(connection: socket.socket) -> None:
    connection.set_inheritable(False)
    connection.setblocking(False)


def _wait(
    connection: socket.socket, writing: bool, deadline: float, cancelled: threading.Event
) -> None:
    while True:
        if cancelled.is_set():
            raise EngineCaidoError("socket_revoked")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EngineCaidoError("socket_deadline")
        readable, writable, _ = select.select(
            [] if writing else [connection],
            [connection] if writing else [],
            [],
            min(0.025, remaining),
        )
        if readable or writable:
            return


def _send(
    connection: socket.socket, raw: bytes, deadline: float, cancelled: threading.Event
) -> None:
    pending = memoryview(raw)
    while pending:
        _wait(connection, True, deadline, cancelled)
        try:
            count = connection.send(pending)
        except BlockingIOError:
            continue
        if count <= 0:
            raise EngineCaidoError("socket_disconnected")
        pending = pending[count:]


def _receive(
    connection: socket.socket, size: int, deadline: float, cancelled: threading.Event
) -> bytes:
    result = bytearray()
    while len(result) < size:
        _wait(connection, False, deadline, cancelled)
        try:
            block = connection.recv(min(8192, size - len(result)))
        except BlockingIOError:
            continue
        if not block:
            raise EngineCaidoError("socket_disconnected")
        result.extend(block)
    return bytes(result)


def _http(
    connection: socket.socket, deadline: float, cancelled: threading.Event, *, response: bool
) -> bytes:
    """Read one finite Content-Length message; never consume a second request."""
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        if len(head) >= MAX_HEADER_BYTES + 4:
            raise EngineCaidoError("message_bound")
        head.extend(_receive(connection, 1, deadline, cancelled))
    lengths: list[bytes] = []
    for line in bytes(head[:-4]).split(b"\r\n")[1:]:
        name, _, value = line.partition(b": ")
        if name.lower() == b"content-length":
            lengths.append(value)
    if len(lengths) > 1:
        raise EngineCaidoError("length_invalid")
    length = lengths[0] if lengths else b"0"
    if not re.fullmatch(rb"0|[1-9][0-9]{0,4}", length) or int(length) > MAX_JSON_BYTES:
        raise EngineCaidoError("length_invalid")
    raw = bytes(head) + _receive(connection, int(length), deadline, cancelled)
    maximum = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if len(raw) > maximum:
        raise EngineCaidoError("message_bound")
    # An already-buffered second message is refused, never pipelined upstream.
    ready, _, _ = select.select([connection], [], [], 0)
    if ready and connection.recv(1, socket.MSG_PEEK):
        raise EngineCaidoError("framing_invalid")
    return raw


def _receive_frame(
    connection: socket.socket,
    plan: EngineCaidoPlan,
    credentials: CaidoConnectorCredentials,
    deadline: float,
    cancelled: threading.Event,
    *,
    response: bool,
) -> tuple[bytes, bytes, bytes]:
    header = _receive(connection, HEADER_BYTES, deadline, cancelled)
    _, _, length = inspect_header(plan, header, response=response)
    mac = _receive(connection, MAC_BYTES, deadline, cancelled)
    payload = _receive(connection, length, deadline, cancelled)
    ready, _, _ = select.select([connection], [], [], 0)
    if ready and connection.recv(1, socket.MSG_PEEK):
        raise EngineCaidoError("connector_frame_invalid")
    nonce, request_digest = authenticate_frame(
        plan, credentials, header, mac, payload, response=response
    )
    return nonce, request_digest, payload


class _Lifecycle:
    def __init__(self, plan: EngineCaidoPlan, limits: CaidoSocketLimits) -> None:
        plan.validate()
        self._plan = plan
        self._digest = plan.digest
        self._limits = limits
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._active = False
        self._used = False
        self._accepted = 0
        self._sockets: set[socket.socket] = set()
        self._audits: deque[CaidoSocketAudit] = deque(maxlen=512)
        self._sequence = 0

    @property
    def audits(self) -> tuple[CaidoSocketAudit, ...]:
        with self._lock:
            return tuple(self._audits)

    def _audit(self, outcome: str) -> None:
        self._sequence += 1
        self._audits.append(CaidoSocketAudit(self._sequence, self._digest, outcome))

    def _identity(self, plan: EngineCaidoPlan) -> None:
        if type(plan) is not EngineCaidoPlan or plan != self._plan or plan.digest != self._digest:
            raise EngineCaidoError("socket_identity_invalid")

    def _activate(self, plan: EngineCaidoPlan) -> None:
        self._identity(plan)
        if self._used or self._cancelled.is_set():
            raise EngineCaidoError("socket_reopen_refused")
        self._active = self._used = True
        self._audit("activated")

    def _reserve_connection(self) -> None:
        if not self._active or self._cancelled.is_set():
            raise EngineCaidoError("socket_revoked")
        if len(self._sockets) >= self._limits.max_connections:
            raise EngineCaidoError("connection_bound")

    def _consume_exchange(self) -> None:
        if not self._active or self._cancelled.is_set():
            raise EngineCaidoError("socket_revoked")
        if self._accepted >= self._limits.max_exchanges:
            raise EngineCaidoError("exchange_bound")
        self._accepted += 1

    def _admit(self) -> None:
        self._reserve_connection()
        self._consume_exchange()

    def _release(self, connection: socket.socket) -> None:
        _close(connection)
        with self._lock:
            self._sockets.discard(connection)

    def revoke(self, plan: EngineCaidoPlan) -> None:
        with self._lock:
            self._identity(plan)
            self._active = False
            self._cancelled.set()
            for connection in tuple(self._sockets):
                _close(connection)
            self._audit("revoked")

    def observe(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        with self._lock:
            self._identity(plan)
            presence = CaidoPresence.PRESENT if self._active else CaidoPresence.ABSENT
            if not self._active and self._sockets:
                presence = CaidoPresence.UNKNOWN
            return CaidoEndpointObservation(plan, presence)


class _Pending:
    def __init__(
        self,
        connector: CaidoSocketConnector,
        connection: socket.socket,
        frame: bytes,
        sent: int,
        nonce: bytes,
        digest: bytes,
        deadline: float,
    ) -> None:
        self._connector, self._connection = connector, connection
        self._frame, self._sent, self._nonce, self._digest = frame, sent, nonce, digest
        self._deadline = deadline
        self._finished = False

    def finish(self) -> bytes | None:
        with self._connector._lock:
            if self._finished:
                raise EngineCaidoError("connector_replay_refused")
            self._finished = True
        owner = self._connector
        try:
            _send(self._connection, self._frame[self._sent :], self._deadline, owner._cancelled)
            nonce, digest, payload = _receive_frame(
                self._connection,
                owner._plan,
                owner._credentials,
                self._deadline,
                owner._cancelled,
                response=True,
            )
            if nonce != self._nonce or digest != self._digest:
                raise EngineCaidoError("connector_response_binding_invalid")
            _response(payload)
            with owner._lock:
                if not owner._active:
                    raise EngineCaidoError("socket_revoked")
                owner._audit("resolved")
            return payload
        except Exception:
            owner.revoke(owner._plan)
            with owner._lock:
                owner._audit("exchange_unknown")
            raise EngineCaidoError("exchange_unknown") from None
        finally:
            owner._release(self._connection)


class CaidoSocketConnector(_Lifecycle):
    """One authenticated exchange per pre-owned private stream, without replay."""

    def __init__(
        self,
        plan: EngineCaidoPlan,
        credentials: CaidoConnectorCredentials,
        streams: OwnedCaidoStreamProvider,
        limits: CaidoSocketLimits = _DEFAULT_LIMITS,
    ) -> None:
        super().__init__(plan, limits)
        credentials.validate(plan)
        if any(
            not callable(getattr(streams, name, None))
            for name in ("open_exact", "revoke_exact", "observe_exact")
        ):
            raise EngineCaidoError("owned_stream_capability_required")
        self._credentials, self._streams = credentials, streams

    def revoke(self, plan: EngineCaidoPlan) -> None:
        super().revoke(plan)
        self._streams.revoke_exact(plan)

    def observe(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        local = super().observe(plan)
        if local.presence is CaidoPresence.ABSENT:
            remote = self._streams.observe_exact(plan)
            if (
                type(remote) is not CaidoEndpointObservation
                or type(remote.plan) is not EngineCaidoPlan
                or remote.plan != plan
                or remote.plan.digest != self._digest
                or remote.presence is not CaidoPresence.ABSENT
            ):
                return CaidoEndpointObservation(plan, CaidoPresence.UNKNOWN)
        return local

    def activate(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        with self._lock:
            self._activate(plan)
            return self.observe(plan)

    def start_exchange(self, plan: EngineCaidoPlan, request: bytes) -> CaidoPendingExchange:
        with self._lock:
            self._identity(plan)
            _request(request, plan)
            self._admit()
            connection: socket.socket | None = None
            deadline = time.monotonic() + self._limits.timeout_seconds
            try:
                owned = self._streams.open_exact(plan)
                if type(owned) is not OwnedCaidoSocket:
                    raise EngineCaidoError("owned_socket_binding_invalid")
                connection = owned.connection
                owned.validate(plan, plan.connector_ref)
                _prepare(connection)
                self._sockets.add(connection)
                nonce, digest = secrets.token_bytes(32), hashlib.sha256(request).digest()
                frame = encode_frame(
                    plan,
                    self._credentials,
                    request,
                    response=False,
                    nonce=nonce,
                    request_digest=digest,
                )
                # Dispatch is synchronous and nonblocking under the lifecycle
                # lock. finish only completes an already-started exchange.
                if self._cancelled.is_set() or time.monotonic() >= deadline:
                    raise EngineCaidoError("socket_deadline")
                sent = connection.send(frame)
                if sent <= 0:
                    raise EngineCaidoError("socket_disconnected")
                self._audit("dispatched")
                return _Pending(self, connection, frame, sent, nonce, digest, deadline)
            except Exception:
                if connection is not None:
                    self._release(connection)
                self.revoke(plan)
                self._audit("dispatch_unknown")
                raise EngineCaidoError("exchange_unknown") from None


class CaidoOwnedConnectorPeer(_Lifecycle):
    """Private authenticated bridge into the exact owned container endpoint.

    The controller's platform adapter owns and supplies each private connection
    and endpoint capability. This class does not listen or dial an address.
    """

    def __init__(
        self,
        plan: EngineCaidoPlan,
        credentials: CaidoConnectorCredentials,
        endpoints: OwnedCaidoStreamProvider,
        limits: CaidoSocketLimits = _DEFAULT_LIMITS,
    ) -> None:
        super().__init__(plan, limits)
        credentials.validate(plan)
        if any(
            not callable(getattr(endpoints, name, None))
            for name in ("open_exact", "revoke_exact", "observe_exact")
        ):
            raise EngineCaidoError("owned_endpoint_capability_required")
        self._credentials, self._endpoints = credentials, endpoints
        self._seen: set[bytes] = set()
        self._peer_inflight = 0
        self._activate(plan)

    def revoke(self, plan: EngineCaidoPlan) -> None:
        super().revoke(plan)
        self._endpoints.revoke_exact(plan)

    def observe(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        local = super().observe(plan)
        with self._lock:
            if not self._active and self._peer_inflight:
                return CaidoEndpointObservation(plan, CaidoPresence.UNKNOWN)
        if local.presence is CaidoPresence.ABSENT:
            remote = self._endpoints.observe_exact(plan)
            if (
                type(remote) is not CaidoEndpointObservation
                or type(remote.plan) is not EngineCaidoPlan
                or remote.plan != plan
                or remote.plan.digest != self._digest
                or remote.presence is not CaidoPresence.ABSENT
            ):
                return CaidoEndpointObservation(plan, CaidoPresence.UNKNOWN)
        return local

    def serve_once(self, owned: OwnedCaidoSocket) -> None:
        connection = owned.connection
        upstream: socket.socket | None = None
        admitted = False
        deadline = time.monotonic() + self._limits.timeout_seconds
        try:
            with self._lock:
                owned.validate(self._plan, self._plan.connector_ref)
                # Each admitted exchange reserves its private and upstream
                # sockets before either authenticated operation can proceed.
                if (self._peer_inflight + 1) * 2 > self._limits.max_connections:
                    raise EngineCaidoError("connection_bound")
                self._admit()
                self._peer_inflight += 1
                admitted = True
                _prepare(connection)
                self._sockets.add(connection)
            nonce, digest, request = _receive_frame(
                connection, self._plan, self._credentials, deadline, self._cancelled, response=False
            )
            _request(request, self._plan)
            with self._lock:
                if not self._active or nonce in self._seen:
                    raise EngineCaidoError("connector_replay_refused")
                if self._cancelled.is_set() or time.monotonic() >= deadline:
                    raise EngineCaidoError("socket_deadline")
                self._seen.add(nonce)
                endpoint = self._endpoints.open_exact(self._plan)
                upstream = endpoint.connection
                endpoint.validate(self._plan, self._plan.upstream_ref)
                _prepare(upstream)
                self._sockets.add(upstream)
                self._audit("authenticated")
            # Header names may use any case accepted by the core.
            rewritten = re.sub(
                rb"(?im)^host: 127\.0\.0\.1:[0-9]+\r$",
                b"Host: 127.0.0.1:48080\r",
                request,
                count=1,
            )
            _send(upstream, rewritten, deadline, self._cancelled)
            response = _http(upstream, deadline, self._cancelled, response=True)
            _response(response)
            frame = encode_frame(
                self._plan,
                self._credentials,
                response,
                response=True,
                nonce=nonce,
                request_digest=digest,
            )
            _send(connection, frame, deadline, self._cancelled)
            with self._lock:
                self._audit("resolved")
        except Exception:
            with self._lock:
                self._audit("exchange_refused")
            # A failed authenticated operation might have reached Caido. The
            # attempt cannot silently acquire a new stream and replay it.
            self.revoke(self._plan)
            raise EngineCaidoError("exchange_unknown") from None
        finally:
            if upstream is not None:
                self._release(upstream)
            self._release(connection)
            if admitted:
                with self._lock:
                    self._peer_inflight -= 1


class CaidoLoopbackListener(_Lifecycle):
    """Transparent strict HTTP; every connection needs protected worker custody."""

    def __init__(
        self,
        plan: EngineCaidoPlan,
        peer_verifier: ProtectedWorkerPeerVerifier,
        worker_ref: str,
        limits: CaidoSocketLimits = _DEFAULT_LIMITS,
    ) -> None:
        super().__init__(plan, limits)
        if (
            not callable(getattr(peer_verifier, "verify_exact", None))
            or type(worker_ref) is not str
            or _DIGEST.fullmatch(worker_ref) is None
        ):
            raise EngineCaidoError("protected_worker_custody_required")
        self._verifier, self._worker_ref = peer_verifier, worker_ref
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self._channel: EngineCaidoChannel | None = None

    def attach(self, channel: EngineCaidoChannel) -> None:
        with self._lock:
            if self._used or self._channel is not None or type(channel) is not EngineCaidoChannel:
                raise EngineCaidoError("listener_attachment_refused")
            self._channel = channel

    def activate(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        with self._lock:
            self._identity(plan)
            if self._channel is None:
                raise EngineCaidoError("listener_attachment_required")
            self._activate(plan)
            listener: socket.socket | None = None
            try:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Exclusive binding; no SO_REUSEADDR/SO_REUSEPORT sharing.
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                listener.set_inheritable(False)
                listener.bind(("127.0.0.1", plan.listener_port))
                listener.listen(self._limits.max_connections)
                listener.settimeout(0.025)
                self._listener = listener
                self._thread = threading.Thread(target=self._accept, daemon=True)
                self._thread.start()
            except Exception:
                if listener is not None:
                    _close(listener)
                self._active = False
                self._cancelled.set()
                raise EngineCaidoError("listener_activation_unknown") from None
            return self.observe(plan)

    def _accept(self) -> None:
        while not self._cancelled.is_set():
            try:
                listener = self._listener
                if listener is None:
                    return
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._cancelled.is_set():
                    self.revoke(self._plan)
                return
            with self._lock:
                try:
                    # A raw loopback connection consumes only a concurrent
                    # socket slot. The finite exchange budget is charged only
                    # after the protected worker verifier succeeds.
                    self._reserve_connection()
                except EngineCaidoError:
                    _close(connection)
                    self._audit("connection_refused")
                    continue
                worker = None
                try:
                    _prepare(connection)
                    self._sockets.add(connection)
                    worker = threading.Thread(target=self._serve, args=(connection,), daemon=True)
                    self._workers.add(worker)
                    worker.start()
                except Exception:
                    self._release(connection)
                    if worker is not None:
                        self._workers.discard(worker)
                    self._audit("worker_start_unknown")
                    self.revoke(self._plan)
                    return

    def _serve(self, connection: socket.socket) -> None:
        custody_verified = False
        response_resolved = False
        try:
            deadline = time.monotonic() + self._limits.timeout_seconds
            peer = connection.getpeername()
            custody = self._verifier.verify_exact(self._plan, connection)
            if (
                type(custody) is not WorkerPeerCustody
                or custody.plan_digest != self._digest
                or custody.attempt_id != self._plan.attempt_id
                or custody.worker_ref != self._worker_ref
                or custody.peer_host != "127.0.0.1"
                or type(custody.peer_port) is not int
                or (custody.peer_host, custody.peer_port) != peer
            ):
                raise EngineCaidoError("worker_peer_refused")
            custody_verified = True
            with self._lock:
                self._consume_exchange()
            request = _http(connection, deadline, self._cancelled, response=False)
            channel = self._channel
            if channel is None:
                raise EngineCaidoError("listener_attachment_required")
            if self._cancelled.is_set() or time.monotonic() >= deadline:
                raise EngineCaidoError("socket_deadline")
            request_ref = _bootstrap_request_ref(self._plan, request)
            if request_ref is None:
                request_ref = "sha256:" + secrets.token_hex(32)
            response = channel.resolve(request_ref, request).response
            response_resolved = True
            try:
                _send(connection, response, deadline, self._cancelled)
            except Exception:
                # The upstream operation may already have mutated Caido. A
                # fresh connection would receive a new request identity, so a
                # lost response is ambiguous and revokes the whole channel
                # rather than permitting an unsafe replay.
                channel.revoke()
                with self._lock:
                    self._audit("response_delivery_unknown")
                raise
            with self._lock:
                self._audit("resolved")
        except Exception as error:
            if (
                custody_verified
                and not response_resolved
                and isinstance(error, EngineCaidoError)
                and error.code == "exchange_bound"
            ):
                channel = self._channel
                if channel is not None:
                    channel.revoke()
            with self._lock:
                self._audit("request_refused")
        finally:
            self._release(connection)
            with self._lock:
                self._workers.discard(threading.current_thread())

    def revoke(self, plan: EngineCaidoPlan) -> None:
        with self._lock:
            super().revoke(plan)
            listener, self._listener = self._listener, None
            if listener is not None:
                _close(listener)

    def observe(self, plan: EngineCaidoPlan) -> CaidoEndpointObservation:
        with self._lock:
            observation = super().observe(plan)
            if not self._active and (
                self._workers or (self._thread is not None and self._thread.is_alive())
            ):
                return CaidoEndpointObservation(plan, CaidoPresence.UNKNOWN)
            return observation


@dataclass(frozen=True, slots=True)
class ControllerCaidoSocketChannel:
    channel: EngineCaidoChannel
    listener: CaidoLoopbackListener
    connector: CaidoSocketConnector


def create_controller_caido_socket_channel(
    plan: EngineCaidoPlan,
    *,
    credentials: CaidoConnectorCredentials,
    worker_ref: str,
    peer_verifier: ProtectedWorkerPeerVerifier,
    streams: OwnedCaidoStreamProvider,
    limits: CaidoSocketLimits = _DEFAULT_LIMITS,
) -> ControllerCaidoSocketChannel:
    """Closed-by-default factory; opens no socket until channel.activate().

    The integrating platform must supply authenticated owned streams and a
    protected worker process/network-namespace custody verifier. A permissive
    loopback/port check does not satisfy this seam. Fresh attempts need a fresh
    plan, credentials and capability instances; revoked instances never reopen.
    """
    listener = CaidoLoopbackListener(plan, peer_verifier, worker_ref, limits)
    connector = CaidoSocketConnector(plan, credentials, streams, limits)
    channel = EngineCaidoChannel(plan, listener, connector)
    listener.attach(channel)
    return ControllerCaidoSocketChannel(channel, listener, connector)
