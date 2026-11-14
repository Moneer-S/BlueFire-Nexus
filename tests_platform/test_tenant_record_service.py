from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer
from typing import Callable

import pytest

from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
)
from bluefire.tenant_record_observer import BoundedTenantAuditLog
from bluefire.tenant_record_service import TenantRecordApplication, tenant_record_handler

SEED = b"tenant-service-test-seed-00000000001"
KEY = b"tenant-service-signing-key-material-00000000000001"
NOW = datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc)


def _ids() -> Callable[[], str]:
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"request-{counter:024x}"

    return next_id


def _headers(**extra: str) -> dict[str, str]:
    return {"host": "tenant-record.test", **extra}


def test_baseline_client_assertion_reaches_both_protected_routes() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    audit = BoundedTenantAuditLog()
    application = TenantRecordApplication(
        fixture=fixture,
        config=baseline_defense_config(fixture),
        audit_log=audit,
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )
    protected = fixture.records_for(fixture.protected_tenant_id)[0]

    lookup = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        _headers(**{"x-bluefire-lab-tenant": fixture.protected_tenant_id}),
        source_identity="engine_worker",
    )
    exported = application.handle(
        "GET",
        f"/exports?tenant={fixture.protected_tenant_id}",
        _headers(**{"x-bluefire-lab-tenant": fixture.protected_tenant_id}),
        source_identity="engine_worker",
    )

    assert lookup.status == exported.status == 200
    assert protected.to_dict() in json.loads(lookup.body)["records"]
    assert len(json.loads(exported.body)["records"]) == 2
    assert [row.route for row in audit.snapshot()] == ["record_lookup", "bounded_export"]
    assert all(row.decision == "allowed_client_asserted" for row in audit.snapshot())


def test_hardening_blocks_exact_reproducer_and_preserves_legitimate_use() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    hardened = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-tenant-service",
        application_nonce="apply-tenant-service-0001",
        prior=baseline_defense_config(fixture),
    )
    audit = BoundedTenantAuditLog()
    application = TenantRecordApplication(
        fixture=fixture,
        config=hardened,
        signing_key=KEY,
        audit_log=audit,
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    original_headers = _headers(**{"x-bluefire-lab-tenant": fixture.protected_tenant_id})

    retest = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        original_headers,
        source_identity="engine_worker",
    )
    adaptive = application.handle(
        "GET",
        f"/exports?tenant={fixture.protected_tenant_id}",
        original_headers,
        source_identity="engine_worker",
    )
    token = mint_lab_session(
        fixture,
        hardened,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )
    legitimate = application.handle(
        "GET",
        f"/exports?tenant={fixture.protected_tenant_id}",
        _headers(authorization=f"BlueFireLab {token}"),
        source_identity="ordinary_user",
    )

    assert retest.status == adaptive.status == 401
    assert protected.generated_value.encode() not in retest.body + adaptive.body
    assert legitimate.status == 200
    assert protected.to_dict() in json.loads(legitimate.body)["records"]
    assert audit.snapshot()[-1].decision == "allowed_signed_session"


def test_metadata_supports_discovery_without_protected_contents() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    application = TenantRecordApplication(
        fixture=fixture,
        config=baseline_defense_config(fixture),
        audit_log=BoundedTenantAuditLog(),
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )

    response = application.handle(
        "GET", "/openapi.json", _headers(), source_identity="engine_worker"
    )
    payload = json.loads(response.body)

    assert response.status == 200
    assert [route["name"] for route in payload["routes"]] == list(fixture.route_order)
    assert fixture.protected_tenant_id in payload["known_tenants"]
    assert all(record.generated_value.encode() not in response.body for record in fixture.records)


def test_duplicate_sensitive_headers_and_malformed_host_port_are_rejected() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    application = TenantRecordApplication(
        fixture=fixture,
        config=baseline_defense_config(fixture),
        audit_log=BoundedTenantAuditLog(),
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )

    duplicate = application.handle(
        "GET",
        "/health",
        [("Host", "tenant-record.test"), ("host", "tenant-record.test")],
        source_identity="controller_probe",
    )
    malformed_port = application.handle(
        "GET",
        "/health",
        {"host": "tenant-record.test:not-a-port"},
        source_identity="controller_probe",
    )

    assert duplicate.status == malformed_port.status == 400
    assert json.loads(duplicate.body)["error"] == "invalid_request"
    assert json.loads(malformed_port.body)["error"] == "invalid_host"


def test_held_out_fixture_uses_same_attack_defense_and_legitimate_contract() -> None:
    fixture = generate_tenant_record_fixture(SEED, held_out=True)
    baseline = baseline_defense_config(fixture)
    baseline_app = TenantRecordApplication(
        fixture=fixture,
        config=baseline,
        audit_log=BoundedTenantAuditLog(),
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )
    target = f"/exports?tenant={fixture.protected_tenant_id}"
    original_headers = _headers(**{"x-bluefire-lab-tenant": fixture.protected_tenant_id})
    baseline_response = baseline_app.handle(
        "GET", target, original_headers, source_identity="engine_worker"
    )

    hardened = hardened_defense_config(
        fixture,
        signing_key=KEY,
        key_id="key-tenant-service",
        application_nonce="apply-held-out-0001",
        prior=baseline,
    )
    hardened_app = TenantRecordApplication(
        fixture=fixture,
        config=hardened,
        signing_key=KEY,
        audit_log=BoundedTenantAuditLog(),
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )
    retest = hardened_app.handle("GET", target, original_headers, source_identity="engine_worker")
    token = mint_lab_session(
        fixture,
        hardened,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )
    legitimate = hardened_app.handle(
        "GET",
        target,
        _headers(authorization=f"BlueFireLab {token}"),
        source_identity="ordinary_user",
    )

    assert fixture.route_order[0] == "bounded_export"
    assert baseline_response.status == legitimate.status == 200
    assert retest.status == 401
    assert json.loads(baseline_response.body) == json.loads(legitimate.body)


def test_handler_runs_on_caller_owned_loopback_server() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    application = TenantRecordApplication(
        fixture=fixture,
        config=baseline_defense_config(fixture),
        audit_log=BoundedTenantAuditLog(),
        allowed_hosts=("127.0.0.1",),
        clock=lambda: NOW,
        request_id_factory=_ids(),
    )
    server = HTTPServer(
        ("127.0.0.1", 0),
        tenant_record_handler(application, source_identity=lambda _address: "engine_worker"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/health", method="GET"
        )
        try:
            response_context = urllib.request.urlopen(  # noqa: S310 - owned loopback
                request, timeout=2
            )
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, PermissionError) and getattr(reason, "winerror", None) == 10013:
                pytest.skip("the current Windows sandbox blocks owned loopback connections")
            raise
        with response_context as response:
            body = response.read()
            assert response.status == 200
            assert json.loads(body)["status"] == "ready"
            assert response.headers["X-BlueFire-Lab-Request"].startswith("request-")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
