"""No platform dependencies: all Caido channel capabilities are injected fakes."""

from __future__ import annotations

import inspect
import threading
from dataclasses import FrozenInstanceError, replace

import pytest

from bluefire import engine_caido_channel as caido


def digest(character: str = "a") -> str:
    return "sha256:" + character * 64


def plan() -> caido.EngineCaidoPlan:
    return caido.EngineCaidoPlan(
        attempt_id="engine-attempt-" + "a" * 32,
        authorization_digest=digest("1"),
        build_identity_digest=digest("2"),
        daemon_ref=digest("3"),
        network_ref=digest("4"),
        container_ref=digest("5"),
        upstream_ref=digest("6"),
        listener_ref=digest("7"),
        connector_ref=digest("8"),
        channel_ref=digest("9"),
        listener_port=48100,
    )


def request(
    line: bytes = b"POST /graphql HTTP/1.1",
    body: bytes = b'{"query":"{ viewer { id } }"}',
    headers: bytes = b"",
) -> bytes:
    return (
        line
        + b"\r\nHost: 127.0.0.1:48100\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n"
        + headers
        + b"\r\n"
        + body
    )


HEALTH = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:48100\r\n\r\n"
RESPONSE = (
    b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}'
)


class Endpoint:
    def __init__(self) -> None:
        self.presence = caido.CaidoPresence.ABSENT
        self.revoke_calls = 0
        self.observation_plan: caido.EngineCaidoPlan | None = None
        self.fail_revoke = False

    def activate(self, identity: caido.EngineCaidoPlan) -> caido.CaidoEndpointObservation:
        self.presence = caido.CaidoPresence.PRESENT
        return self.observe(identity)

    def revoke(self, identity: caido.EngineCaidoPlan) -> None:
        self.revoke_calls += 1
        if self.fail_revoke:
            raise RuntimeError("SECRET provider error")
        self.presence = caido.CaidoPresence.ABSENT

    def observe(self, identity: caido.EngineCaidoPlan) -> caido.CaidoEndpointObservation:
        return caido.CaidoEndpointObservation(self.observation_plan or identity, self.presence)


class Transport(Endpoint):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[caido.EngineCaidoPlan, bytes]] = []
        self.response: bytes | None = RESPONSE
        self.error = False
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None

    def start_exchange(
        self, identity: caido.EngineCaidoPlan, raw: bytes
    ) -> caido.CaidoPendingExchange:
        self.calls.append((identity, raw))
        return self

    def finish(self) -> bytes | None:
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(5)
        if self.error:
            raise RuntimeError("SECRET untrusted upstream payload")
        return self.response


def channel() -> tuple[caido.EngineCaidoChannel, Endpoint, Transport]:
    listener, transport = Endpoint(), Transport()
    core = caido.EngineCaidoChannel(plan(), listener, transport)
    core.activate()
    return core, listener, transport


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("listener_host", "localhost"),
        ("listener_host", "127.0.0.2"),
        ("listener_host", "0.0.0.0"),
        ("listener_host", "::1"),
        ("container_host", "host.docker.internal"),
        ("container_host", "172.17.0.1"),
        ("container_host", "::ffff:127.0.0.1"),
        ("container_port", 48081),
        ("container_port", True),
        ("listener_port", True),
        ("listener_port", 0),
        ("listener_port", 65536),
        ("tls", True),
        ("tls", 0),
        ("attempt_id", "engine-attempt-bad"),
        ("authorization_digest", "SECRET"),
        ("build_identity_digest", "sha256:" + "A" * 64),
    ],
)
def test_fixed_protected_plan(field: str, value: object) -> None:
    with pytest.raises(caido.EngineCaidoError):
        replace(plan(), **{field: value})  # type: ignore[arg-type]


def test_plan_and_exchange_receipts_are_immutable() -> None:
    core, _, transport = channel()
    receipt = core.resolve(digest(), request())
    assert transport.calls == [(plan(), request())]
    assert receipt.route is caido.CaidoRoute.GRAPHQL
    assert receipt.response == RESPONSE
    assert "viewer" not in repr(receipt)
    with pytest.raises(FrozenInstanceError):
        receipt.status = 500  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        plan().tls = True  # type: ignore[misc]


def test_bodyless_health_and_exact_idempotence() -> None:
    core, _, transport = channel()
    first = core.resolve(digest(), HEALTH)
    assert core.resolve(digest(), HEALTH) is first
    assert len(transport.calls) == 1
    with pytest.raises(caido.EngineCaidoError, match="resolution_conflict"):
        core.resolve(digest(), request())
    core.revoke()
    with pytest.raises(caido.EngineCaidoError, match="state_refused"):
        core.resolve(digest(), HEALTH)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "line",
    [
        b"CONNECT 127.0.0.1:48080 HTTP/1.1",
        b"GET http://127.0.0.1:48080/health HTTP/1.1",
        b"GET //127.0.0.1/health HTTP/1.1",
        b"GET 127.0.0.1:48080 HTTP/1.1",
        b"POST /graphql?upstream=http://evil HTTP/1.1",
        b"POST /graphql#fragment HTTP/1.1",
        b"POST /%67raphql HTTP/1.1",
        b"POST /other HTTP/1.1",
        b"GET /graphql HTTP/1.1",
        b"POST /health HTTP/1.1",
        b"POST /graphql HTTP/1.0",
        b"POST  /graphql HTTP/1.1",
        b"POST /graphql\tHTTP/1.1",
    ],
)
def test_only_literal_origin_form_routes(line: bytes) -> None:
    core, _, transport = channel()
    with pytest.raises(caido.EngineCaidoError):
        core.resolve(digest(), request(line))
    assert not transport.calls


@pytest.mark.parametrize(
    "header",
    [
        b"Transfer-Encoding: chunked\r\n",
        b"transfer-encoding: identity\r\n",
        b"Content-Length: 27\r\n",
        b"content-length: 27\r\n",
        b"Host: evil\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: Upgrade\r\n",
        b"Proxy-Authorization: SECRET\r\n",
        b"Authorization: SECRET\r\n",
        b"Forwarded: host=evil\r\n",
        b"Trailer: Content-Length\r\n",
        b"TE: trailers\r\n",
        b" Cookie: SECRET\r\n",
        b"Accept: application/json\r\n\tfolded\r\n",
        b"Accept:\tapplication/json\r\n",
        b"Accept: application/json \r\n",
        b"Accept: */*\r\n",
    ],
)
def test_header_and_smuggling_refusals(header: bytes) -> None:
    core, _, transport = channel()
    with pytest.raises(caido.EngineCaidoError):
        core.resolve(digest(), request(headers=header))
    assert not transport.calls


@pytest.mark.parametrize(
    "raw",
    [
        HEALTH + HEALTH,
        HEALTH.replace(b"\r\n", b"\n"),
        HEALTH.replace(b"127.0.0.1", b"localhost"),
        HEALTH.replace(b"48100", b"48080"),
        HEALTH.replace(b"\r\n\r\n", b"\r\nContent-Length: 1\r\n\r\nx"),
        request().replace(b"Content-Length: 29", b"Content-Length: 029"),
        request().replace(b"Content-Length: 29", b"Content-Length: +29"),
        request().replace(b"Content-Length: 29\r\n", b""),
        b"x" * (caido.MAX_REQUEST_BYTES + 1),
        request(headers=b"Accept: " + b"x" * caido.MAX_HEADER_BYTES + b"\r\n"),
        bytearray(HEALTH),
    ],
    ids=lambda raw: f"framing-{len(raw)}",
)
def test_framing_and_byte_bounds(raw: bytes) -> None:
    core, _, transport = channel()
    with pytest.raises(caido.EngineCaidoError):
        core.resolve(digest(), raw)
    assert not transport.calls


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"null",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e9999}',
        b'{"x":"\\ud800"}',
        b"\xef\xbb\xbf{}",
        b'{"x":"\xff"}',
        b'{"x":' + b"[" * 50 + b"0" + b"]" * 50 + b"}",
        b'{"x":[' + b"0," * 4096 + b"0]}",
        b'{"x":"' + b"x" * caido.MAX_JSON_BYTES + b'"}',
    ],
    ids=lambda body: f"json-{len(body)}",
)
def test_bounded_strict_json(body: bytes) -> None:
    core, _, transport = channel()
    with pytest.raises(caido.EngineCaidoError):
        core.resolve(digest(), request(body=body))
    assert not transport.calls


@pytest.mark.parametrize(
    "raw",
    [
        RESPONSE.replace(b"200 OK", b"302 Found"),
        RESPONSE.replace(b"200 OK", b"204 No Content"),
        RESPONSE.replace(b"200 OK", b"205 Reset Content"),
        RESPONSE.replace(b"200 OK", b"101 Switching Protocols"),
        RESPONSE.replace(b"\r\n\r\n", b"\r\nLocation: http://evil\r\n\r\n"),
        RESPONSE.replace(b"\r\n\r\n", b"\r\nUpgrade: websocket\r\n\r\n"),
        RESPONSE.replace(b"Content-Length: 11", b"Transfer-Encoding: chunked"),
        RESPONSE + RESPONSE,
        RESPONSE.replace(b'{"ok":true}', b'{"ok":NaN}'),
        b"x" * (caido.MAX_RESPONSE_BYTES + 1),
        None,
    ],
    ids=lambda raw: f"response-{len(raw) if raw is not None else 'unknown'}",
)
def test_unverified_response_is_unknown_and_never_replayed(raw: bytes | None) -> None:
    core, _, transport = channel()
    transport.response = raw
    with pytest.raises(caido.EngineCaidoError, match="exchange_unknown"):
        core.resolve(digest(), request())
    assert core.state is caido.CaidoState.UNKNOWN
    with pytest.raises(caido.EngineCaidoError, match="state_refused"):
        core.resolve(digest(), request())
    assert len(transport.calls) == 1


def test_unknown_exception_and_audits_never_contain_payload_or_secret() -> None:
    core, _, transport = channel()
    transport.error = True
    with pytest.raises(caido.EngineCaidoError) as error:
        core.resolve(digest(), request(body=b'{"query":"SECRET"}'))
    text = str(error.value) + repr(core.audits)
    assert "SECRET" not in text
    assert "query" not in text
    assert "viewer" not in text


@pytest.mark.parametrize(
    "field",
    [
        "authorization_digest",
        "build_identity_digest",
        "daemon_ref",
        "network_ref",
        "container_ref",
        "upstream_ref",
        "listener_ref",
        "connector_ref",
        "channel_ref",
    ],
)
def test_every_protected_binding_is_exact(field: str) -> None:
    listener, transport = Endpoint(), Transport()
    transport.observation_plan = replace(plan(), **{field: digest("b")})  # type: ignore[arg-type]
    core = caido.EngineCaidoChannel(plan(), listener, transport)
    with pytest.raises(caido.EngineCaidoError, match="activation_unknown"):
        core.activate()
    assert core.state is caido.CaidoState.UNKNOWN
    with pytest.raises(caido.EngineCaidoError):
        core.resolve(digest(), HEALTH)


def test_verified_drain_requires_listener_and_connector_absence() -> None:
    core, listener, transport = channel()
    with pytest.raises(caido.EngineCaidoError, match="state_refused"):
        core.drain()
    core.cancel()
    transport.presence = caido.CaidoPresence.PRESENT
    receipt = core.drain()
    assert receipt.listener_absent and not receipt.connector_absent
    assert receipt.state is caido.CaidoState.UNKNOWN
    assert receipt.resource_cleanup_verified is False
    transport.presence = caido.CaidoPresence.UNKNOWN
    assert core.drain().state is caido.CaidoState.UNKNOWN
    transport.presence = caido.CaidoPresence.ABSENT
    transport.observation_plan = replace(plan(), upstream_ref=digest("b"))
    assert core.drain().state is caido.CaidoState.UNKNOWN
    transport.observation_plan = None
    drained = core.drain()
    assert drained.state is caido.CaidoState.DRAINED
    assert drained.listener_absent and drained.connector_absent
    assert core.drain() == drained
    assert listener.revoke_calls == transport.revoke_calls == 1


def test_revoke_failure_still_attempts_both_endpoints() -> None:
    core, listener, transport = channel()
    listener.fail_revoke = True
    core.revoke()
    assert listener.revoke_calls == transport.revoke_calls == 1
    assert core.state is caido.CaidoState.UNKNOWN
    assert core.drain().state is caido.CaidoState.UNKNOWN
    listener.fail_revoke = False
    core.revoke()
    assert core.drain().state is caido.CaidoState.DRAINED


def test_cancel_discards_inflight_and_drain_waits_for_return() -> None:
    core, _, transport = channel()
    transport.entered, transport.release = threading.Event(), threading.Event()
    errors: list[str] = []

    def resolve() -> None:
        try:
            core.resolve(digest(), request())
        except caido.EngineCaidoError as error:
            errors.append(error.code)

    worker = threading.Thread(target=resolve)
    worker.start()
    try:
        assert transport.entered.wait(5)
        with pytest.raises(caido.EngineCaidoError, match="resolution_pending"):
            core.resolve(digest(), request())
        with pytest.raises(caido.EngineCaidoError, match="resolution_conflict"):
            core.resolve(digest(), HEALTH)
        core.cancel()
        with pytest.raises(caido.EngineCaidoError, match="drain_pending"):
            core.drain()
    finally:
        transport.release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert errors == ["state_refused"]
    assert core.drain().state is caido.CaidoState.DRAINED
    assert len(transport.calls) == 1


def test_resolution_storage_and_audit_storage_are_bounded() -> None:
    core, _, transport = channel()
    for index in range(caido.MAX_RESOLUTIONS):
        core.resolve("sha256:" + f"{index:064x}", HEALTH)
    with pytest.raises(caido.EngineCaidoError, match="resolution_bound"):
        core.resolve(digest(), HEALTH)
    assert len(transport.calls) == caido.MAX_RESOLUTIONS
    for _ in range(600):
        with pytest.raises(caido.EngineCaidoError):
            core.resolve(digest(), request(b"GET /forbidden HTTP/1.1"))
    assert len(core.audits) == 512


def test_reentrant_activation_cancellation_never_resurrects_channel() -> None:
    class CancellingListener(Endpoint):
        def activate(self, identity: caido.EngineCaidoPlan) -> caido.CaidoEndpointObservation:
            observation = super().activate(identity)
            core.cancel()
            return observation

    listener, transport = CancellingListener(), Transport()
    core = caido.EngineCaidoChannel(plan(), listener, transport)
    with pytest.raises(caido.EngineCaidoError, match="activation_unknown"):
        core.activate()
    assert core.state is caido.CaidoState.UNKNOWN
    assert transport.presence is caido.CaidoPresence.ABSENT
    assert core.drain().state is caido.CaidoState.DRAINED


def test_send_admission_is_atomic_with_cancellation() -> None:
    admitted = threading.Event()
    release_admission = threading.Event()
    cancelled = threading.Event()
    errors: list[str] = []

    class PausedAdmission(Transport):
        def start_exchange(
            self, identity: caido.EngineCaidoPlan, raw: bytes
        ) -> caido.CaidoPendingExchange:
            admitted.set()
            assert release_admission.wait(5)
            assert not cancelled.is_set()
            return super().start_exchange(identity, raw)

    transport = PausedAdmission()
    transport.entered, transport.release = threading.Event(), threading.Event()
    core = caido.EngineCaidoChannel(plan(), Endpoint(), transport)
    core.activate()

    def resolve() -> None:
        try:
            core.resolve(digest(), HEALTH)
        except caido.EngineCaidoError as error:
            errors.append(error.code)

    def cancel() -> None:
        core.cancel()
        cancelled.set()

    worker = threading.Thread(target=resolve)
    canceller = threading.Thread(target=cancel)
    worker.start()
    try:
        assert admitted.wait(5)
        canceller.start()
        assert not cancelled.is_set()
        release_admission.set()
        assert transport.entered.wait(5)
        assert cancelled.wait(5)
        assert len(transport.calls) == 1
    finally:
        release_admission.set()
        transport.release.set()
        worker.join(5)
        canceller.join(5)
    assert not worker.is_alive() and not canceller.is_alive()
    assert errors == ["state_refused"]
    assert core.drain().state is caido.CaidoState.DRAINED


def test_core_imports_no_platform_effect_capabilities() -> None:
    source = inspect.getsource(caido)
    for forbidden in ("import socket", "import subprocess", "import docker", "import requests"):
        assert forbidden not in source
