from __future__ import annotations

import json
import os
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

import pytest

import bluefire.tenant_record_target_child as child
from bluefire.tenant_record_lab import baseline_defense_config, generate_tenant_record_fixture
from bluefire.tenant_record_observer import BoundedTenantAuditLog
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.util import canonical_json_bytes

RUN_ID = "engine-lab-" + "1" * 32
ATTEMPT_ID = "engine-attempt-" + "2" * 32
CREATED_AT = "2026-11-04T12:00:00Z"
NOW = datetime(2026, 11, 4, 12, 0, 5, tzinfo=timezone.utc)
SEED = b"f" * 32
SIGNING_KEY = b"s" * 32
ADMISSIONS = {
    "engine_worker": b"e" * 32,
    "ordinary_user": b"o" * 32,
    "controller_probe": b"c" * 32,
}


def packet(*, hardened: bool = False, max_requests: int = 8) -> child.TenantTargetPacket:
    return child.TenantTargetPacket.create(
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        fixture_seed=SEED,
        held_out=True,
        defense_mode="signed_session" if hardened else "client_asserted",
        admissions=ADMISSIONS,
        created_at=CREATED_AT,
        max_runtime_seconds=60,
        signing_key=SIGNING_KEY if hardened else None,
        key_id="session-key-alpha" if hardened else None,
        application_nonce="application-nonce-alpha" if hardened else None,
        max_requests=max_requests,
        max_audit_events=max(max_requests, 8),
        max_audit_bytes=64 * 1024,
    )


def arguments(root: Path, *, host: str = "127.0.0.1", port: int = 0) -> child.FixedTargetArguments:
    return child.FixedTargetArguments(
        packet=root / "packet.json",
        audit=root / "audit.jsonl",
        ready_file=root / "ready.json",
        host=host,
        port=port,
    )


def admitted_headers(
    identity: str = "engine_worker", *, extra: Mapping[str, str] | None = None
) -> list[tuple[str, str]]:
    token = child.SourceAdmission.create(identity, ADMISSIONS[identity]).to_mapping()["token_b64"]
    return [
        ("Host", "127.0.0.1"),
        (child.SOURCE_HEADER, token),
        *((extra or {}).items()),
    ]


def service(
    root: Path, *, maximum: int = 8, numeric_host: str = "127.0.0.1"
) -> tuple[child.TargetChildService, Path, child.AuditFileSink]:
    fixture = generate_tenant_record_fixture(SEED, held_out=True)
    config = baseline_defense_config(fixture)
    log = BoundedTenantAuditLog(max_events=maximum)
    audit_path = root / "audit.jsonl"
    sink = child.AuditFileSink(audit_path, maximum_bytes=64 * 1024)
    request_numbers = iter(range(1, maximum + 2))

    def request_id() -> str:
        return f"request-{next(request_numbers):024x}"

    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=log,
        allowed_hosts=(numeric_host, child.TARGET_LOGICAL_AUTHORITY),
        clock=lambda: NOW,
        request_id_factory=request_id,
    )
    target = child.TargetChildService(
        application=application,
        audit_log=log,
        audit_sink=sink,
        admissions=packet(max_requests=maximum).admissions,
        budget=child.RequestBudget(maximum),
        numeric_authority=numeric_host,
    )
    return target, audit_path, sink


def test_packet_round_trip_is_canonical_deterministic_and_secret_safe() -> None:
    expected = packet(hardened=True)
    parsed = child.TenantTargetPacket.from_bytes(expected.to_bytes())

    assert parsed == expected
    assert parsed.digest == expected.digest
    assert parsed.materialize() == expected.materialize()
    rendered = repr(parsed)
    assert SEED.hex() not in rendered
    assert SIGNING_KEY.decode("ascii") not in rendered
    assert all(token.decode("ascii") not in rendered for token in ADMISSIONS.values())


def test_packet_rejects_noncanonical_tampered_and_reused_admission_material() -> None:
    expected = packet()
    pretty = json.dumps(expected.to_mapping(), indent=2).encode() + b"\n"
    with pytest.raises(child.TenantTargetChildError, match="not canonical"):
        child.TenantTargetPacket.from_bytes(pretty)

    tampered = expected.to_mapping()
    tampered["expected_fixture_digest"] = "sha256:" + "0" * 64
    with pytest.raises(child.TenantTargetChildError, match="does not match"):
        child.TenantTargetPacket.from_bytes(canonical_json_bytes(tampered) + b"\n")

    repeated = dict(ADMISSIONS)
    repeated["ordinary_user"] = repeated["engine_worker"]
    with pytest.raises(child.TenantTargetChildError, match="reuse a token"):
        child.TenantTargetPacket.create(
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            fixture_seed=SEED,
            held_out=False,
            defense_mode="client_asserted",
            admissions=repeated,
            created_at=CREATED_AT,
            max_runtime_seconds=60,
        )


@pytest.mark.parametrize("size", [31, 65])
def test_packet_rejects_out_of_bound_signing_keys(size: int) -> None:
    with pytest.raises((child.TenantTargetChildError, ValueError)):
        child.TenantTargetPacket.create(
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            fixture_seed=SEED,
            held_out=False,
            defense_mode="signed_session",
            admissions=ADMISSIONS,
            created_at=CREATED_AT,
            max_runtime_seconds=60,
            signing_key=b"k" * size,
            key_id="session-key-alpha",
            application_nonce="application-nonce-alpha",
        )


def test_fixed_argv_accepts_only_exact_derived_loopback_shape(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "target"
    values = [
        "--fixed-target",
        "--packet",
        str(root / "packet.json"),
        "--audit",
        str(root / "audit.jsonl"),
        "--ready-file",
        str(root / "ready.json"),
        "--host",
        "127.0.0.1",
        "--port",
        "0",
    ]

    parsed = child.parse_fixed_target_arguments(values)
    assert parsed == arguments(root)

    for index, replacement in (
        (1, "--manifest"),
        (8, "localhost"),
        (10, "01"),
        (10, "65536"),
    ):
        invalid = list(values)
        invalid[index] = replacement
        with pytest.raises(child.TenantTargetChildError):
            child.parse_fixed_target_arguments(invalid)

    aliased = list(values)
    aliased[2] = str(root / "nested" / ".." / "packet.json")
    with pytest.raises(child.TenantTargetChildError, match="paths"):
        child.parse_fixed_target_arguments(aliased)


def test_ready_receipt_round_trip_binds_endpoint_packet_and_bounds() -> None:
    target_packet = packet()
    fixture, config = target_packet.materialize()
    expected = child.TargetReadyReceipt(
        pid=4312,
        host="127.0.0.1",
        port=43123,
        packet_digest=target_packet.digest,
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
        admission_digests=target_packet.admission_digests,
        max_audit_events=target_packet.max_audit_events,
        max_audit_bytes=target_packet.max_audit_bytes,
        max_requests=target_packet.max_requests,
        max_runtime_seconds=target_packet.max_runtime_seconds,
        started_at="2026-11-04T12:00:05Z",
    )

    parsed = child.TargetReadyReceipt.from_bytes(expected.to_bytes())
    assert parsed == expected
    assert parsed.to_mapping()["host"] == "127.0.0.1"
    assert parsed.to_mapping()["port"] == 43123
    assert "endpoint" not in parsed.to_mapping()
    assert parsed.ready_digest == expected.ready_digest

    changed = expected.to_mapping()
    changed["port"] = 43124
    with pytest.raises(child.TenantTargetChildError, match="digest changed"):
        child.TargetReadyReceipt.from_bytes(canonical_json_bytes(changed) + b"\n")


def test_service_derives_source_identity_and_persists_audit_before_response(
    tmp_path: Path,
) -> None:
    target, audit_path, sink = service(tmp_path)

    response = target.handle_get("/openapi.json", admitted_headers())
    sink.close()
    assert response.status == 200
    rows = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    assert len(rows) == 1
    assert rows[0]["source_identity"] == "engine_worker"
    persisted = audit_path.read_bytes()
    assert all(token not in persisted for token in ADMISSIONS.values())
    assert SIGNING_KEY not in persisted


@pytest.mark.parametrize(
    ("authority", "numeric_host"),
    [
        (child.TARGET_LOGICAL_AUTHORITY, "127.0.0.1"),
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.1:43123", "127.0.0.1"),
        (child.TARGET_LOGICAL_AUTHORITY, "[::1]"),
        ("[::1]", "[::1]"),
        ("[::1]:43123", "[::1]"),
    ],
)
def test_service_accepts_only_fixed_logical_or_numeric_loopback_authority(
    tmp_path: Path, authority: str, numeric_host: str
) -> None:
    target, audit_path, sink = service(tmp_path, numeric_host=numeric_host)
    headers = admitted_headers()
    headers[0] = ("Host", authority)

    response = target.handle_get("/health", headers)
    sink.close()

    assert response.status == 200
    rows = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    assert len(rows) == 1
    assert rows[0]["decision"] == "public_health"


@pytest.mark.parametrize(
    "authority",
    [
        "tenant-record.test.example",
        "tenant-record.test@127.0.0.1",
        "tenant-record.test:0",
        "tenant-record.test:43123",
        "tenant-record.test:65536",
        "tenant-record.test:not-a-port",
        "tenant-record.test evil",
        "tenant-record.\ttest",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:not-a-port",
        "localhost",
        "127.0.0.2",
        "[::2]",
    ],
)
def test_service_rejects_authority_lookalikes_and_alternates(
    tmp_path: Path, authority: str
) -> None:
    target, audit_path, sink = service(tmp_path)
    headers = admitted_headers()
    headers[0] = ("Host", authority)

    response = target.handle_get("/health", headers)
    sink.close()

    assert response.status == 400
    assert json.loads(response.body)["error"] == "invalid_host"
    rows = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    assert len(rows) == 1
    assert rows[0]["decision"] == "invalid_request"


def test_service_rejects_duplicate_or_ambiguous_host_authority(tmp_path: Path) -> None:
    target, audit_path, sink = service(tmp_path)
    response = target.handle_get(
        "/health",
        [
            *admitted_headers(),
            ("host", child.TARGET_LOGICAL_AUTHORITY),
        ],
    )
    sink.close()

    assert response.status == 400
    assert json.loads(response.body)["error"] == "invalid_request"
    rows = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    assert len(rows) == 1
    assert rows[0]["decision"] == "invalid_request"


def test_service_rejects_spoofed_or_missing_admission_without_application_audit(
    tmp_path: Path,
) -> None:
    target, audit_path, sink = service(tmp_path, maximum=3)

    spoofed = target.handle_get(
        "/health",
        admitted_headers(extra={"x-bluefire-lab-source-identity": "ordinary_user"}),
    )
    missing = target.handle_get("/health", [("Host", "127.0.0.1")])
    sink.close()
    assert (spoofed.status, missing.status) == (403, 403)
    assert audit_path.read_bytes() == b""
    assert not target.terminal


def test_standard_non_get_requests_are_budgeted_and_audited(tmp_path: Path) -> None:
    target, audit_path, sink = service(tmp_path, maximum=2)

    assert target.handle("POST", "/health", admitted_headers()).status == 405
    assert target.handle("OPTIONS", "/health", admitted_headers()).status == 405
    assert target.terminal
    assert target.handle_get("/health", admitted_headers()).status == 429
    sink.close()
    rows = [json.loads(line) for line in audit_path.read_bytes().splitlines()]
    assert [row["decision"] for row in rows] == ["invalid_request", "invalid_request"]


class BrokenSink:
    def append(self, _row: object) -> None:
        raise OSError("simulated protected audit failure")


def test_audit_persistence_failure_is_terminal_and_suppresses_success() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    config = baseline_defense_config(fixture)
    log = BoundedTenantAuditLog(max_events=2)
    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=log,
        allowed_hosts=("127.0.0.1",),
    )
    target = child.TargetChildService(
        application=application,
        audit_log=log,
        audit_sink=BrokenSink(),  # type: ignore[arg-type]
        admissions=packet().admissions,
        budget=child.RequestBudget(2),
        numeric_authority="127.0.0.1",
    )

    response = target.handle_get("/health", admitted_headers())
    assert response.status == 500
    assert target.terminal


class FakeServer:
    def __init__(self, endpoint: tuple[str, int]) -> None:
        self.server_address: tuple[object, ...] = (endpoint[0], 43123)
        self.timeout = 0.0
        self.handle_calls = 0
        self.closed = False

    def handle_request(self) -> None:
        self.handle_calls += 1

    def server_close(self) -> None:
        self.closed = True


def test_runner_uses_fake_server_publishes_canonical_ready_and_honors_stop(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve() / "target"
    root.mkdir()
    target_packet = packet(hardened=True)
    (root / "packet.json").write_bytes(target_packet.to_bytes())
    stopped = threading.Event()
    stopped.set()
    captured: list[FakeServer] = []

    def factory(endpoint, _handler):
        server = FakeServer(endpoint)
        captured.append(server)
        return server

    receipt = child.run_target_child(
        arguments(root),
        protection_check=lambda parent, source: parent == root and source == root / "packet.json",
        server_factory=factory,
        utc_now=lambda: NOW,
        monotonic=lambda: 100.0,
        stop_event=stopped,
    )

    assert captured[0].handle_calls == 0
    assert captured[0].closed
    assert child.TargetReadyReceipt.from_bytes((root / "ready.json").read_bytes()) == receipt
    assert (root / "audit.jsonl").read_bytes() == b""
    published = (root / "ready.json").read_bytes()
    assert SIGNING_KEY not in published
    assert all(token not in published for token in ADMISSIONS.values())


def test_runner_rejects_expired_packet_and_existing_output_without_server(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve() / "target"
    root.mkdir()
    target_packet = packet()
    (root / "packet.json").write_bytes(target_packet.to_bytes())

    def forbidden(*_args, **_kwargs):
        raise AssertionError("server must not be constructed")

    with pytest.raises(child.TenantTargetChildError, match="lifetime"):
        child.run_target_child(
            arguments(root),
            protection_check=lambda _parent, _source: True,
            server_factory=forbidden,
            utc_now=lambda: datetime(2026, 11, 4, 12, 2, tzinfo=timezone.utc),
        )

    (root / "ready.json").write_bytes(b"occupied")
    with pytest.raises(child.TenantTargetChildError, match="output already exists"):
        child.run_target_child(
            arguments(root),
            protection_check=lambda _parent, _source: True,
            server_factory=forbidden,
            utc_now=lambda: NOW,
        )


def test_packet_read_rejects_unprotected_or_multi_link_input(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "target"
    root.mkdir()
    source = root / "packet.json"
    source.write_bytes(packet().to_bytes())
    with pytest.raises(child.TenantTargetChildError, match="not protected"):
        child.run_target_child(
            arguments(root),
            protection_check=lambda _parent, _source: False,
            server_factory=lambda *_args: pytest.fail("server must not be constructed"),
            utc_now=lambda: NOW,
        )

    alias = tmp_path / "packet-alias.json"
    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this test filesystem")
    with pytest.raises(child.TenantTargetChildError, match="bounded owned file"):
        child.run_target_child(
            arguments(root),
            protection_check=lambda _parent, _source: True,
            server_factory=lambda *_args: pytest.fail("server must not be constructed"),
            utc_now=lambda: NOW,
        )


def test_remaining_packet_lifetime_caps_server_loop(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "target"
    root.mkdir()
    target_packet = packet()
    (root / "packet.json").write_bytes(target_packet.to_bytes())
    server = FakeServer(("127.0.0.1", 0))
    ticks = iter((100.0, 104.9, 105.0))

    child.run_target_child(
        arguments(root),
        protection_check=lambda _parent, _source: True,
        server_factory=lambda _endpoint, _handler: server,
        utc_now=lambda: datetime(2026, 11, 4, 12, 0, 55, tzinfo=timezone.utc),
        monotonic=lambda: next(ticks),
    )

    assert server.handle_calls == 1
    assert server.timeout == pytest.approx(0.1)
    assert server.closed


def test_frozen_ready_receipt_copies_admission_mapping() -> None:
    target_packet = packet()
    fixture, config = target_packet.materialize()
    mutable = dict(target_packet.admission_digests)
    receipt = child.TargetReadyReceipt(
        pid=1,
        host="::1",
        port=1,
        packet_digest=target_packet.digest,
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
        admission_digests=mutable,
        max_audit_events=8,
        max_audit_bytes=4096,
        max_requests=8,
        max_runtime_seconds=60,
        started_at="2026-11-04T12:00:05Z",
    )
    original = receipt.ready_digest
    mutable["engine_worker"] = "sha256:" + "0" * 64
    assert receipt.ready_digest == original
    with pytest.raises(TypeError):
        receipt.admission_digests["engine_worker"] = "sha256:" + "0" * 64  # type: ignore[index]


def test_packet_dataclass_rechecks_material_after_replace() -> None:
    expected = packet()
    with pytest.raises(child.TenantTargetChildError, match="does not match"):
        replace(expected, expected_config_digest="sha256:" + "0" * 64)
