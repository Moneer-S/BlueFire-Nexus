"""Only owned local sockets: no Docker, Strix, network discovery or target egress."""

from __future__ import annotations

import hashlib
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import replace

import pytest

from bluefire import engine_caido_channel as core
from bluefire import engine_caido_socket as transport
from bluefire.engine_caido_wire import CaidoConnectorCredentials, encode_frame

RESPONSE = (
    b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}'
)


def digest(character: str = "a") -> str:
    return "sha256:" + character * 64


def plan() -> core.EngineCaidoPlan:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    return core.EngineCaidoPlan(
        "engine-attempt-" + "a" * 32,
        *(digest(character) for character in "123456789"),
        port,
    )


def request(identity: core.EngineCaidoPlan) -> bytes:
    return (
        f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{identity.listener_port}\r\n"
        "Accept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
        "User-Agent: Python/3.12 aiohttp/3.14.5\r\n\r\n"
    ).encode()


def bootstrap_request(identity: core.EngineCaidoPlan) -> bytes:
    body = core.CAIDO_GUEST_BOOTSTRAP_BODY
    return (
        f"POST /graphql HTTP/1.1\r\nHost: 127.0.0.1:{identity.listener_port}\r\n"
        "User-Agent: curl/8.14.1\r\nAccept: */*\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body


def bound(
    identity: core.EngineCaidoPlan, connection: socket.socket, endpoint_ref: str
) -> transport.OwnedCaidoSocket:
    return transport.OwnedCaidoSocket(
        identity.digest, identity.attempt_id, identity.container_ref, endpoint_ref, connection
    )


class OwnedFakeCaido:
    """Exact pre-owned local fake endpoint, never production endpoint resolution."""

    def __init__(self, identity: core.EngineCaidoPlan) -> None:
        self.plan = identity
        self.response: bytes | None = RESPONSE
        self.release = threading.Event()
        self.entered = threading.Event()
        self.block = False
        self.requests: list[bytes] = []
        self.errors: list[Exception] = []
        self.sockets: set[socket.socket] = set()
        self.workers: list[threading.Thread] = []
        self.revoked = False
        self.calls = 0
        self.listener: socket.socket | None = None
        if not hasattr(socket, "AF_UNIX"):
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.bind(("127.0.0.1", identity.container_port))
            self.listener.listen(8)

    def open_exact(self, identity: core.EngineCaidoPlan) -> transport.OwnedCaidoSocket:
        assert identity == self.plan and not self.revoked
        self.calls += 1
        if self.listener is None:
            controller, endpoint = socket.socketpair()
        else:
            controller = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            controller.connect(("127.0.0.1", identity.container_port))
            endpoint, _ = self.listener.accept()
        self.sockets.update((controller, endpoint))

        def serve() -> None:
            try:
                transport._prepare(endpoint)
                raw = transport._http(
                    endpoint, time.monotonic() + 2, threading.Event(), response=False
                )
                self.requests.append(raw)
                self.entered.set()
                if self.block:
                    assert self.release.wait(3)
                if self.response is not None:
                    endpoint.settimeout(2)
                    endpoint.sendall(self.response)
            except (OSError, core.EngineCaidoError) as error:
                self.errors.append(error)
            finally:
                transport._close(endpoint)
                self.sockets.discard(endpoint)

        worker = threading.Thread(target=serve)
        self.workers.append(worker)
        worker.start()
        return bound(identity, controller, identity.upstream_ref)

    def revoke_exact(self, identity: core.EngineCaidoPlan) -> None:
        assert identity == self.plan
        self.revoked = True
        self.release.set()
        for connection in tuple(self.sockets):
            transport._close(connection)
        self.sockets.clear()
        if self.listener is not None:
            transport._close(self.listener)
            self.listener = None

    def observe_exact(self, identity: core.EngineCaidoPlan) -> core.CaidoEndpointObservation:
        return core.CaidoEndpointObservation(
            identity,
            core.CaidoPresence.ABSENT
            if self.revoked and not self.sockets
            else core.CaidoPresence.PRESENT,
        )


class OwnedPrivateStreams:
    def __init__(
        self, identity: core.EngineCaidoPlan, peer: transport.CaidoOwnedConnectorPeer
    ) -> None:
        self.plan, self.peer = identity, peer
        self.calls = 0
        self.errors: list[str] = []
        self.workers: list[threading.Thread] = []
        self.wrong_binding = False
        self.remote_unknown = False

    def open_exact(self, identity: core.EngineCaidoPlan) -> transport.OwnedCaidoSocket:
        assert identity == self.plan
        self.calls += 1
        controller, peer = socket.socketpair()

        def serve() -> None:
            try:
                self.peer.serve_once(bound(identity, peer, identity.connector_ref))
            except core.EngineCaidoError as error:
                self.errors.append(error.code)

        worker = threading.Thread(target=serve)
        self.workers.append(worker)
        worker.start()
        result = bound(identity, controller, identity.connector_ref)
        return replace(result, container_ref=digest("b")) if self.wrong_binding else result

    def revoke_exact(self, identity: core.EngineCaidoPlan) -> None:
        self.peer.revoke(identity)

    def observe_exact(self, identity: core.EngineCaidoPlan) -> core.CaidoEndpointObservation:
        return (
            core.CaidoEndpointObservation(identity, core.CaidoPresence.UNKNOWN)
            if self.remote_unknown
            else self.peer.observe(identity)
        )


class ExplicitOwnedTestWorker:
    """Test-only capability: accepts only client sockets explicitly registered by this test."""

    def __init__(self) -> None:
        self.peers: set[tuple[str, int]] = set()
        self.wrong_identity = False

    def verify_exact(
        self, identity: core.EngineCaidoPlan, connection: socket.socket
    ) -> transport.WorkerPeerCustody:
        peer = connection.getpeername()
        if peer not in self.peers:
            raise core.EngineCaidoError("unowned_test_peer")
        return transport.WorkerPeerCustody(
            identity.digest,
            identity.attempt_id,
            digest("b") if self.wrong_identity else digest(),
            peer[0],
            peer[1],
        )


class Harness:
    def __init__(
        self, *, wrong_key: bool = False, limits: transport.CaidoSocketLimits | None = None
    ) -> None:
        self.plan = plan()
        self.credentials = CaidoConnectorCredentials(self.plan.digest, b"k" * 32)
        self.endpoint = OwnedFakeCaido(self.plan)
        peer_credentials = (
            replace(self.credentials, key=b"z" * 32) if wrong_key else self.credentials
        )
        selected = limits or transport.CaidoSocketLimits(timeout_seconds=1)
        self.peer = transport.CaidoOwnedConnectorPeer(
            self.plan, peer_credentials, self.endpoint, selected
        )
        self.streams = OwnedPrivateStreams(self.plan, self.peer)
        self.verifier = ExplicitOwnedTestWorker()
        self.bundle = transport.create_controller_caido_socket_channel(
            self.plan,
            credentials=self.credentials,
            worker_ref=digest(),
            peer_verifier=self.verifier,
            streams=self.streams,
            limits=selected,
        )
        self.bundle.channel.activate()

    def client(self, *, owned: bool = True) -> socket.socket:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.bind(("127.0.0.1", 0))
        if owned:
            self.verifier.peers.add(client.getsockname())
        client.settimeout(2)
        client.connect(("127.0.0.1", self.plan.listener_port))
        return client

    def exchange(self, raw: bytes | None = None, *, owned: bool = True) -> bytes:
        with self.client(owned=owned) as client:
            try:
                client.sendall(request(self.plan) if raw is None else raw)
                chunks = []
                while chunk := client.recv(8192):
                    chunks.append(chunk)
                return b"".join(chunks)
            except (ConnectionResetError, ConnectionAbortedError):
                return b""

    def close(self) -> core.CaidoDrainReceipt:
        self.bundle.channel.cancel()
        self.endpoint.release.set()
        for worker in self.streams.workers + self.endpoint.workers:
            worker.join(3)
            assert not worker.is_alive()
        deadline = time.monotonic() + 2
        while True:
            try:
                receipt = self.bundle.channel.drain()
                if receipt.state is core.CaidoState.DRAINED:
                    return receipt
            except core.EngineCaidoError as error:
                assert error.code == "drain_pending"
            assert time.monotonic() < deadline
            time.sleep(0.005)


@pytest.fixture
def harness() -> Iterator[Harness]:
    result = Harness()
    yield result
    result.close()


def test_authenticated_handshake_and_transparent_bounded_http(harness: Harness) -> None:
    assert harness.exchange() == RESPONSE
    assert harness.endpoint.requests == [
        request(harness.plan).replace(str(harness.plan.listener_port).encode(), b"48080")
    ]
    assert harness.streams.calls == harness.endpoint.calls == 1
    assert "authenticated" in [audit.outcome for audit in harness.peer.audits]
    assert b"k" * 32 not in repr(harness.credentials).encode()


def test_graphql_forwards_one_validated_message(harness: Harness) -> None:
    body = b'{"query":"{viewer{id}}"}'
    raw = (
        f"POST /graphql HTTP/1.1\r\nHost: 127.0.0.1:{harness.plan.listener_port}\r\n"
        "Accept: */*\r\nAccept-Encoding: gzip, deflate\r\n"
        "User-Agent: Python/3.12 aiohttp/3.14.5\r\n"
        "Authorization: Bearer guest-token\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    assert harness.exchange(raw) == RESPONSE
    assert harness.endpoint.requests == [
        raw.replace(str(harness.plan.listener_port).encode(), b"48080", 1)
    ]


def test_sealed_strix_guest_bootstrap_forwards_exactly(harness: Harness) -> None:
    raw = bootstrap_request(harness.plan)
    assert harness.exchange(raw) == RESPONSE
    # The fake 2xx is deliberately not a usable guest-token payload. A Strix
    # retry receives the attempt-local retained response without replaying the
    # login mutation upstream.
    assert harness.exchange(raw) == RESPONSE
    assert harness.endpoint.requests == [
        raw.replace(str(harness.plan.listener_port).encode(), b"48080", 1)
    ]


@pytest.mark.parametrize("owned,wrong_identity", [(False, False), (True, True)])
def test_wrong_worker_peer_never_opens_private_stream(
    harness: Harness, owned: bool, wrong_identity: bool
) -> None:
    harness.verifier.wrong_identity = wrong_identity
    assert harness.exchange(owned=owned) == b""
    assert harness.streams.calls == harness.endpoint.calls == 0


def test_unverified_loopback_peers_do_not_consume_exchange_budget() -> None:
    harness = Harness(
        limits=transport.CaidoSocketLimits(max_connections=2, max_exchanges=1, timeout_seconds=1)
    )
    try:
        for _ in range(3):
            assert harness.exchange(owned=False) == b""
        assert harness.streams.calls == harness.endpoint.calls == 0
        assert harness.bundle.channel.state is core.CaidoState.ACTIVE
        assert harness.exchange() == RESPONSE
        assert harness.endpoint.calls == 1
    finally:
        harness.close()


def test_owned_upstream_socket_checks_real_peer_port_not_claimed_metadata() -> None:
    identity = plan()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    while listener.getsockname()[1] == identity.container_port:
        transport._close(listener)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accepted: socket.socket | None = None
    try:
        listener.listen(1)
        client.connect(listener.getsockname())
        accepted, _ = listener.accept()
        owned = bound(identity, client, identity.upstream_ref)
        assert client.getpeername()[1] != identity.container_port
        with pytest.raises(core.EngineCaidoError, match="owned_socket_binding_invalid"):
            owned.validate(identity, identity.upstream_ref)
        replace(owned, endpoint_ref=identity.connector_ref).validate(
            identity, identity.connector_ref
        )
    finally:
        if accepted is not None:
            transport._close(accepted)
        transport._close(client)
        transport._close(listener)


def test_wrong_token_and_wrong_bound_container_do_not_reach_caido() -> None:
    for wrong_key in (True, False):
        harness = Harness(wrong_key=wrong_key)
        harness.streams.wrong_binding = not wrong_key
        try:
            assert harness.exchange() == b""
            assert harness.endpoint.calls == 0
            assert harness.bundle.channel.state is core.CaidoState.UNKNOWN
            assert harness.exchange() == b""
            assert harness.streams.calls == 1
        finally:
            harness.close()


@pytest.mark.parametrize("malformation", ["route", "pipeline", "oversize", "chunked", "proxy"])
def test_request_bounds_before_upstream_effect(harness: Harness, malformation: str) -> None:
    raw = request(harness.plan)
    raw = {
        "route": raw.replace(b"/health", b"http://example.test/health"),
        "pipeline": raw + raw,
        "oversize": raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 99999\r\n\r\n"),
        "chunked": raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
        "proxy": raw.replace(b"\r\n\r\n", b"\r\nProxy-Authorization: SECRET\r\n\r\n"),
    }[malformation]
    assert harness.exchange(raw) == b""
    assert harness.endpoint.calls == 0
    assert "SECRET" not in repr(harness.bundle.listener.audits)


@pytest.mark.parametrize(
    "response", [None, RESPONSE.replace(b"200 OK", b"302 Found"), RESPONSE + RESPONSE]
)
def test_disconnect_or_redirect_is_ambiguous_and_never_replayed(
    harness: Harness, response: bytes | None
) -> None:
    harness.endpoint.response = response
    bootstrap = bootstrap_request(harness.plan)
    assert harness.exchange(bootstrap) == b""
    assert harness.bundle.channel.state is core.CaidoState.UNKNOWN
    assert harness.exchange() == b""
    assert harness.endpoint.calls == 1


def test_lost_response_delivery_revokes_resolved_mutation_before_retry(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_send = transport._send

    def fail_worker_delivery(
        connection: socket.socket,
        raw: bytes,
        deadline: float,
        cancelled: threading.Event,
    ) -> None:
        if raw == RESPONSE:
            original_send(connection, raw, deadline, cancelled)
            raise core.EngineCaidoError("injected_post_send_reset")
        original_send(connection, raw, deadline, cancelled)

    monkeypatch.setattr(transport, "_send", fail_worker_delivery)
    bootstrap = bootstrap_request(harness.plan)
    assert harness.exchange(bootstrap) in {b"", RESPONSE}
    assert harness.endpoint.calls == 1
    assert harness.bundle.channel.state in {core.CaidoState.REVOKED, core.CaidoState.UNKNOWN}
    with pytest.raises(core.EngineCaidoError, match="state_refused"):
        harness.bundle.channel.resolve(digest("f"), bootstrap)
    assert harness.endpoint.calls == 1
    assert "response_delivery_unknown" in [
        audit.outcome for audit in harness.bundle.listener.audits
    ]


def test_cancel_closes_inflight_remote_streams_discards_result_and_releases_port(
    harness: Harness,
) -> None:
    harness.endpoint.block = True
    results: list[bytes] = []
    worker = threading.Thread(target=lambda: results.append(harness.exchange()))
    worker.start()
    assert harness.endpoint.entered.wait(2)
    receipt = harness.close()
    worker.join(2)
    assert not worker.is_alive() and results == [b""]
    assert receipt.resource_cleanup_verified is False
    assert receipt.listener_absent and receipt.connector_absent
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fresh:
        fresh.bind(("127.0.0.1", harness.plan.listener_port))
    with pytest.raises(core.EngineCaidoError, match="state_refused"):
        harness.bundle.channel.activate()
    with pytest.raises(core.EngineCaidoError, match="reopen_refused"):
        harness.bundle.listener.activate(harness.plan)


def test_remote_absence_is_required_for_drain(harness: Harness) -> None:
    harness.close()
    harness.streams.remote_unknown = True
    receipt = harness.bundle.channel.drain()
    assert receipt.listener_absent and not receipt.connector_absent
    assert receipt.state is core.CaidoState.UNKNOWN
    harness.streams.remote_unknown = False


def test_frame_replay_refused_before_second_upstream_operation(harness: Harness) -> None:
    raw = request(harness.plan)
    frame = encode_frame(
        harness.plan,
        harness.credentials,
        raw,
        response=False,
        nonce=b"n" * 32,
        request_digest=hashlib.sha256(raw).digest(),
    )
    for index in range(2):
        controller, peer = socket.socketpair()
        errors: list[str] = []

        def serve(endpoint_socket: socket.socket = peer, caught: list[str] = errors) -> None:
            try:
                harness.peer.serve_once(
                    bound(harness.plan, endpoint_socket, harness.plan.connector_ref)
                )
            except core.EngineCaidoError as error:
                caught.append(error.code)

        worker = threading.Thread(target=serve)
        worker.start()
        controller.settimeout(2)
        controller.sendall(frame)
        try:
            while controller.recv(8192):
                pass
        except ConnectionResetError:
            pass
        controller.close()
        worker.join(2)
        assert not worker.is_alive()
        assert bool(errors) is bool(index)
    assert harness.endpoint.calls == 1


def test_factory_requires_protected_custody_and_owned_stream_capabilities() -> None:
    identity = plan()
    with pytest.raises(core.EngineCaidoError, match="custody_required"):
        transport.CaidoLoopbackListener(identity, None, digest())  # type: ignore[arg-type]
    with pytest.raises(core.EngineCaidoError, match="capability_required"):
        transport.CaidoSocketConnector(
            identity, CaidoConnectorCredentials(identity.digest, b"k" * 32), None
        )  # type: ignore[arg-type]


def test_connection_budget_is_finite_and_no_reopen() -> None:
    harness = Harness(
        limits=transport.CaidoSocketLimits(max_connections=2, max_exchanges=1, timeout_seconds=1)
    )
    try:
        assert harness.exchange() == RESPONSE
        assert harness.exchange() == b""
        assert harness.endpoint.calls == 1
    finally:
        harness.close()


def test_peer_reserves_both_private_and_upstream_socket_slots() -> None:
    harness = Harness(limits=transport.CaidoSocketLimits(max_connections=1, timeout_seconds=1))
    try:
        assert harness.exchange() == b""
        assert harness.endpoint.calls == 0
    finally:
        harness.close()


def test_incomplete_request_and_upstream_stall_have_absolute_deadlines() -> None:
    harness = Harness(limits=transport.CaidoSocketLimits(timeout_seconds=0.15))
    try:
        started = time.monotonic()
        assert harness.exchange(request(harness.plan)[:-2]) == b""
        assert time.monotonic() - started < 1.5
        assert harness.endpoint.calls == 0
        harness.endpoint.block = True
        started = time.monotonic()
        assert harness.exchange() == b""
        assert time.monotonic() - started < 1.5
        assert harness.bundle.channel.state is core.CaidoState.UNKNOWN
    finally:
        harness.close()


@pytest.mark.parametrize("offset", [0, 8, 9, 41, 73, 120, 152, 184, 188, None])
def test_framed_identity_auth_and_length_tampering_precedes_caido_open(offset: int | None) -> None:
    harness = Harness()
    try:
        raw = request(harness.plan)
        frame = bytearray(
            encode_frame(
                harness.plan,
                harness.credentials,
                raw,
                response=False,
                nonce=b"n" * 32,
                request_digest=hashlib.sha256(raw).digest(),
            )
        )
        if offset is None:
            frame *= 2
        else:
            frame[offset] ^= 128
        controller, peer = socket.socketpair()
        errors: list[str] = []

        def serve() -> None:
            try:
                harness.peer.serve_once(bound(harness.plan, peer, harness.plan.connector_ref))
            except core.EngineCaidoError as error:
                errors.append(error.code)

        worker = threading.Thread(target=serve)
        worker.start()
        controller.settimeout(2)
        controller.sendall(frame)
        try:
            assert controller.recv(8192) == b""
        except ConnectionResetError:
            pass
        finally:
            controller.close()
        worker.join(2)
        assert not worker.is_alive()
        assert errors == ["exchange_unknown"]
        assert harness.endpoint.calls == 0
    finally:
        harness.close()


def test_partial_activation_revokes_listener_port_and_remote_capabilities() -> None:
    identity = plan()
    credentials = CaidoConnectorCredentials(identity.digest, b"k" * 32)
    endpoint = OwnedFakeCaido(identity)
    peer = transport.CaidoOwnedConnectorPeer(identity, credentials, endpoint)
    streams = OwnedPrivateStreams(identity, peer)
    bundle = transport.create_controller_caido_socket_channel(
        identity,
        credentials=credentials,
        worker_ref=digest(),
        peer_verifier=ExplicitOwnedTestWorker(),
        streams=streams,
    )
    bundle.connector.revoke(identity)
    with pytest.raises(core.EngineCaidoError, match="activation_unknown"):
        bundle.channel.activate()
    deadline = time.monotonic() + 2
    while bundle.channel.drain().state is not core.CaidoState.DRAINED:
        assert time.monotonic() < deadline
        time.sleep(0.005)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fresh:
        fresh.bind(("127.0.0.1", identity.listener_port))


def test_worker_start_failure_closes_accepted_socket_and_listener(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_start(self: threading.Thread) -> None:
        raise RuntimeError("SECRET worker failure")

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    assert harness.exchange() == b""
    assert harness.endpoint.calls == 0
    assert "SECRET" not in repr(harness.bundle.listener.audits)
    deadline = time.monotonic() + 2
    while harness.bundle.listener.observe(harness.plan).presence is not core.CaidoPresence.ABSENT:
        assert time.monotonic() < deadline
        time.sleep(0.005)


def test_expired_stream_admission_never_dispatches_authenticated_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(limits=transport.CaidoSocketLimits(timeout_seconds=0.05))
    original_open = harness.streams.open_exact

    def delayed_open(identity: core.EngineCaidoPlan) -> transport.OwnedCaidoSocket:
        owned = original_open(identity)
        # Simulate a provider violating its nonblocking contract, or a process
        # descheduled across the absolute deadline before initial dispatch.
        time.sleep(0.1)
        return owned

    monkeypatch.setattr(harness.streams, "open_exact", delayed_open)
    try:
        assert harness.exchange() == b""
        assert harness.endpoint.calls == 0
        assert harness.bundle.channel.state is core.CaidoState.UNKNOWN
    finally:
        harness.close()
