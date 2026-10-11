"""Synthetic channel admission/transport tests: no sockets or host enrollment."""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_channel as contract
from bluefire import ad_smb_channel_transport as transport
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.runner_client import SubprocessRustRunner
from bluefire.runner_transport import (
    TRANSPORT_SCHEMA_VERSION,
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    _enrollment_binding,
    _port,
    _RequestRefusal,
)
from bluefire.runner_transport_errors import (
    AuthenticatedRunnerTransportError,
    RunnerAuthenticationError,
)
from bluefire.runner_transport_security import sign_request, sign_response
from bluefire.runner_trust import RunnerEnrollment
from bluefire.util import content_hash
from tests_platform.test_ad_smb_contract import NOW, pin, scope_row


def channel_row(role="member"):
    scope = AdSmbScope.from_mapping(scope_row())
    host = scope.to_dict()["hosts"][role]
    return {
        "schema_version": contract.SCHEMA,
        "scope_digest": scope.digest,
        "role": role,
        "host_id": host["host_id"],
        "host_ipv4": host["ipv4"],
        "controller_ipv4": "10.44.0.10",
        "port": 8843,
        "runner_id": "ad-" + role,
        "client_id": "ad-controller",
        "profile_id": "profile-" + role,
        "profile_digest": pin("4"),
        "runner_binary_digest": pin("5"),
        "inventory_digest": pin("6"),
        "ca_fingerprint": pin("7"),
        "server_fingerprint": pin("8"),
        "client_fingerprint": pin("9"),
        "created_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T02:00:00Z",
        "policy_receipt_digest": pin("a"),
    }


@pytest.fixture
def channel(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(minutes=1)

    monkeypatch.setattr(contract, "datetime", Clock)
    return contract.AdSmbHostChannel.from_mapping(
        AdSmbScope.from_mapping(scope_row()), channel_row()
    )


def enrollment(channel):
    row = channel.to_dict()
    return SimpleNamespace(
        runner_id=row["runner_id"],
        client_id=row["client_id"],
        allowed_profile_ids=(row["profile_id"],),
        metadata=row,
        hmac_key=lambda: bytes(range(32)),
        transport_identity_scope=lambda: {"ad_smb_channel_digest": channel.digest},
    )


def bare_client(channel):
    client = object.__new__(transport.EnrolledAdSmbClient)
    client.channel = channel
    row = channel.to_dict()
    client.profile_id = row["profile_id"]
    client.host, client.port = row["host_ipv4"], row["port"]
    client.socket_timeout_seconds = 10.0
    client._enrollments = SimpleNamespace(active=lambda: enrollment(channel))
    return client


def request(channel, operation="health", payload=None):
    row, payload = channel.to_dict(), payload or {}
    unsigned = {
        "schema_version": TRANSPORT_SCHEMA_VERSION,
        "kind": "request",
        "operation": operation,
        "runner_id": row["runner_id"],
        "client_id": row["client_id"],
        "profile_id": row["profile_id"],
        "task_id": "test-task",
        "nonce": "a" * 64,
        "request_hash": content_hash(payload),
        "payload": payload,
    }
    return sign_request(enrollment(channel), unsigned)


def test_roundtrip_detached_expiry_and_role(channel):
    value = channel.to_dict()
    value["host_ipv4"] = "10.44.0.99"
    assert channel.to_dict()["host_ipv4"] == "10.44.0.2"
    channel.assert_current(NOW)
    with pytest.raises(AdSmbError):
        channel.assert_current(NOW + timedelta(hours=2))
    with pytest.raises(AdSmbError):
        channel.assert_current(NOW - timedelta(seconds=1))
    client = contract.AdSmbHostChannel.from_mapping(
        AdSmbScope.from_mapping(scope_row()), channel_row("client")
    )
    assert client.digest != channel.digest


@pytest.mark.parametrize("field", list(channel_row()))
def test_all_channel_fields_required(field):
    row = channel_row()
    del row[field]
    with pytest.raises(AdSmbError):
        contract.AdSmbHostChannel.from_mapping(AdSmbScope.from_mapping(scope_row()), row)


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_ipv4", "127.0.0.1"),
        ("controller_ipv4", "0.0.0.0"),
        ("controller_ipv4", "10.44.0.1"),
        ("controller_ipv4", "example.com"),
        ("controller_ipv4", "::1"),
        ("controller_ipv4", "8.8.8.8"),
        ("controller_ipv4", "010.44.0.10"),
        ("controller_ipv4", 123),
        ("role", "dc"),
        ("port", True),
        ("port", 445),
        ("port", 65536),
        ("scope_digest", pin("f")),
        ("host_id", pin("f")),
        ("profile_digest", "token-secret"),
        ("runner_id", "ad-controller"),
        ("client_id", "bad\nidentity"),
        ("ca_fingerprint", pin("8")),
        ("expires_at", "2026-10-11T00:00:00Z"),
        ("expires_at", "2026-10-09T00:00:00Z"),
        ("created_at", "2026-10-09T00:00:00+00:00"),
        ("created_at", "2026-02-30T00:00:00Z"),
        ("extra", "secret"),
    ],
)
def test_bad_channel_refused(field, value):
    row = channel_row()
    row[field] = value
    with pytest.raises(AdSmbError):
        contract.AdSmbHostChannel.from_mapping(AdSmbScope.from_mapping(scope_row()), row)


def test_local_addresses_and_identity_generation_unchanged(channel):
    for cls in (AuthenticatedRunnerClient, AuthenticatedRunnerServer):
        assert cls._checked_host("127.0.0.1") == "127.0.0.1"
        assert cls._checked_host("::1") == "::1"
        assert cls._transport_kind == "mutual-tls-loopback"
        with pytest.raises(AuthenticatedRunnerTransportError):
            cls._checked_host("10.44.0.2")
    assert RunnerEnrollment.transport_identity_scope(object()) == {}
    local = enrollment(channel)
    local.transport_identity_scope = lambda: {}
    identity = {
        key: local.metadata[key]
        for key in (
            "runner_id",
            "client_id",
            "ca_fingerprint",
            "server_fingerprint",
            "client_fingerprint",
        )
    }
    assert _enrollment_binding(local, pin("9"))["enrollment_generation"] == content_hash(identity)
    assert _enrollment_binding(enrollment(channel), pin("9"))[
        "enrollment_generation"
    ] != content_hash(identity)


@pytest.mark.parametrize("dedicated", [False, True])
def test_extracted_identity_validator_retains_exact_transport_kind(channel, monkeypatch, dedicated):
    client = bare_client(channel) if dedicated else object.__new__(AuthenticatedRunnerClient)
    enrolled = enrollment(channel)
    if not dedicated:
        enrolled.transport_identity_scope = lambda: {}
    row = channel.to_dict()
    health = {
        "runner_id": enrolled.runner_id,
        "client_id": enrolled.client_id,
        "transport": client._transport_kind,
        "tls": "TLSv1.3",
        "server_fingerprint": row["server_fingerprint"],
        "client_fingerprint": row["client_fingerprint"],
        "authenticated_peer_fingerprint": row["client_fingerprint"],
        "enrollment_generation": _enrollment_binding(enrolled, row["client_fingerprint"])[
            "enrollment_generation"
        ],
        "runner_binary_digest": row["runner_binary_digest"],
        "inventory_digest": row["inventory_digest"],
    }
    monkeypatch.setattr(client, "_active_enrollment", lambda: enrolled)
    monkeypatch.setattr(client, "health", lambda: dict(health))
    identity = client.transport_identity()
    assert identity["transport"] == client._transport_kind
    assert identity["enrollment_generation"] == health["enrollment_generation"]
    if dedicated:
        assert identity["channel_digest"] == channel.digest
        assert identity["ad_smb_execution_available"] is False
    other = AuthenticatedRunnerClient if dedicated else transport.EnrolledAdSmbClient
    health["transport"] = other._transport_kind
    with pytest.raises(RunnerAuthenticationError, match="transport identity"):
        client.transport_identity()


@pytest.mark.parametrize("value", [True, False, -1, 65536, 1.0, "10", None])
def test_legacy_port_rejects_same_noncanonical_values(value):
    with pytest.raises(AuthenticatedRunnerTransportError):
        _port(value, allow_zero=False)
    with pytest.raises(AuthenticatedRunnerTransportError):
        _port(value, allow_zero=True)


def test_legacy_port_exact_bounds():
    assert _port(0, allow_zero=True) == 0
    assert _port(1, allow_zero=False) == 1
    assert _port(65535, allow_zero=False) == 65535
    with pytest.raises(AuthenticatedRunnerTransportError):
        _port(0, allow_zero=False)


def test_changed_channel_policy_cannot_reuse_original_ledger_generation(channel):
    changed = channel.to_dict()
    changed["policy_receipt_digest"] = pin("f")
    other = contract.AdSmbHostChannel.from_mapping(AdSmbScope.from_mapping(scope_row()), changed)
    assert (
        _enrollment_binding(enrollment(other), pin("9"))["enrollment_generation"]
        != _enrollment_binding(enrollment(channel), pin("9"))["enrollment_generation"]
    )


def test_client_constructor_uses_exact_role_without_socket(channel, monkeypatch):
    calls = []

    def loader(root, **kwargs):
        calls.append((root, kwargs))
        return enrollment(channel)

    monkeypatch.setattr(transport, "load_channel_enrollment", loader)
    monkeypatch.setattr(
        transport.socket, "socket", lambda *args: pytest.fail("constructor must not connect")
    )
    client = transport.EnrolledAdSmbClient(
        "synthetic-role", scope=AdSmbScope.from_mapping(scope_row()), channel=channel
    )
    assert client.host == "10.44.0.2"
    assert client.port == 8843
    assert calls[0][1]["side"] == "client"
    assert client.recovery_attempts == 3
    assert client.socket_timeout_seconds == 10.0


@pytest.mark.parametrize("timeout", [None, True, 0, -1, 61, float("nan"), float("inf")])
def test_server_refuses_unbounded_native_supervisor_before_listener(channel, monkeypatch, timeout):
    runner = object.__new__(SubprocessRustRunner)
    runner.timeout_seconds = timeout
    monkeypatch.setattr(
        AuthenticatedRunnerServer,
        "__init__",
        lambda *args, **kwargs: pytest.fail("no base effects"),
    )
    with pytest.raises(RunnerAuthenticationError):
        transport.EnrolledAdSmbServer(
            "synthetic-role",
            runner,
            state_path="synthetic-ledger",
            scope=AdSmbScope.from_mapping(scope_row()),
            channel=channel,
        )


def test_server_constructor_fixed_bounds_and_no_callback(channel, monkeypatch):
    calls = []
    runner = object.__new__(SubprocessRustRunner)
    runner.timeout_seconds = 35.0
    monkeypatch.setattr(
        AuthenticatedRunnerServer, "__init__", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    server = transport.EnrolledAdSmbServer(
        "synthetic-role",
        runner,
        state_path="synthetic-ledger",
        scope=AdSmbScope.from_mapping(scope_row()),
        channel=channel,
    )
    assert calls[0][1]["host"] == "10.44.0.2"
    assert calls[0][1]["port"] == 8843
    assert calls[0][1]["max_workers"] == 4
    assert calls[0][1]["control_worker_reserve"] == 2
    assert server._enrollment_cache(calls[0][0][1], None).side == "server"
    assert not server.ad_smb_execution_available


class FakeSocket:
    def __init__(self, channel):
        self.row = channel.to_dict()
        self.calls = []
        self.closed = False

    def settimeout(self, value):
        self.calls.append(("timeout", value))

    def bind(self, value):
        self.calls.append(("bind", value))

    def connect(self, value):
        self.calls.append(("connect", value))

    def getpeername(self):
        return self.row["host_ipv4"], self.row["port"]

    def getsockname(self):
        return self.row["controller_ipv4"], 50100

    def close(self):
        self.closed = True


def test_client_fixed_ip_source_bind_and_no_resolver(channel, monkeypatch):
    fake = FakeSocket(channel)
    families = []
    monkeypatch.setattr(transport.socket, "socket", lambda *args: families.append(args) or fake)
    monkeypatch.setattr(
        transport.socket, "getaddrinfo", lambda *args: pytest.fail("DNS is forbidden")
    )
    client = bare_client(channel)
    assert client._connect_socket() is fake
    assert families == [(transport.socket.AF_INET, transport.socket.SOCK_STREAM)]
    assert fake.calls == [
        ("timeout", 10.0),
        ("bind", ("10.44.0.10", 0)),
        ("connect", ("10.44.0.2", 8843)),
    ]
    assert not fake.closed


@pytest.mark.parametrize("failure", ["connect", "peer", "source"])
def test_failed_client_socket_owned_cleanup(channel, monkeypatch, failure):
    fake = FakeSocket(channel)
    if failure == "connect":
        fake.connect = lambda value: (_ for _ in ()).throw(OSError("synthetic"))
    elif failure == "peer":
        fake.getpeername = lambda: ("10.44.0.9", 8843)
    else:
        fake.getsockname = lambda: ("10.44.0.9", 50100)
    monkeypatch.setattr(transport.socket, "socket", lambda *args: fake)
    with pytest.raises((OSError, RunnerAuthenticationError)):
        bare_client(channel)._connect_socket()
    assert fake.closed


def test_changed_destination_refused_before_socket(channel, monkeypatch):
    client = bare_client(channel)
    client.port += 1
    monkeypatch.setattr(transport.socket, "socket", lambda *args: pytest.fail("no socket"))
    with pytest.raises(RunnerAuthenticationError):
        client._connect_socket()


@pytest.mark.parametrize(
    "source,destination,port",
    [
        ("10.44.0.9", "10.44.0.2", 8843),
        ("10.44.0.10", "0.0.0.0", 8843),
        ("10.44.0.10", "10.44.0.2", 8844),
    ],
)
def test_server_rejects_non_enrolled_socket_before_tls(channel, source, destination, port):
    server = object.__new__(transport.EnrolledAdSmbServer)
    server.channel = channel
    fake = SimpleNamespace(
        getpeername=lambda: (source, 50100), getsockname=lambda: (destination, port)
    )
    with pytest.raises(RunnerAuthenticationError):
        server._validate_raw_peer(fake)


@pytest.mark.parametrize(
    "operation", ["execute", "shutdown", "native_tool_inspect", "s3_access_environments", "other"]
)
def test_no_general_dispatch_or_shutdown_in_channel(channel, operation, monkeypatch):
    client = bare_client(channel)
    monkeypatch.setattr(client, "_exchange", lambda *args, **kwargs: pytest.fail("no exchange"))
    with pytest.raises(RunnerAuthenticationError):
        client._call(operation, {}, task_id="task")


@pytest.mark.parametrize("forbidden", ["shutdown", "s3_access_environments"])
def test_server_request_reuses_hmac_profile_validation_and_fixed_controls(channel, forbidden):
    server = object.__new__(transport.EnrolledAdSmbServer)
    server.channel = channel
    valid = request(channel)
    assert server._validated_request(valid, enrollment(channel)) == valid
    with pytest.raises(_RequestRefusal):
        server._validated_request(request(channel, forbidden), enrollment(channel))
    invalid = {**valid, "authentication": pin("0")}
    with pytest.raises(_RequestRefusal):
        server._validated_request(invalid, enrollment(channel))
    assert transport.EnrolledAdSmbServer._dispatch is AuthenticatedRunnerServer._dispatch
    assert transport.EnrolledAdSmbServer._begin_request is AuthenticatedRunnerServer._begin_request


def test_original_recovery_uses_authenticated_protocol_without_execute(channel, monkeypatch):
    client = bare_client(channel)
    captured = []

    def exchange(raw, enrolled, **kwargs):
        captured.append(raw)
        response = {
            **{key: value for key, value in raw.items() if key != "authentication"},
            "kind": "response",
            "payload": {"state": "unknown"},
            "response_hash": content_hash({"state": "unknown"}),
            "ok": True,
            "status": "completed",
            "error_code": None,
        }
        return sign_response(enrolled, response)

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.recover("original-task", pin("b")) == {"state": "unknown"}
    assert len(captured) == 1
    assert captured[0]["operation"] == "recover"
    assert captured[0]["payload"] == {
        "original_task_id": "original-task",
        "original_request_hash": pin("b"),
    }
    assert captured[0]["profile_id"] == "profile-member"
    assert not client.ad_smb_execution_available
