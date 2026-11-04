from __future__ import annotations

from datetime import datetime, timezone

import pytest

from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
)
from bluefire.tenant_record_observer import (
    BoundedTenantAuditLog,
    TenantRecordObservationError,
    checked_observation_content,
    observe_tenant_response,
)
from bluefire.tenant_record_service import TenantRecordApplication

SEED = b"tenant-observer-test-seed-0000000001"
KEY = b"tenant-observer-signing-key-material-0000000000001"
NOW = datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc)


def _application(*, hardened: bool = False):
    fixture = generate_tenant_record_fixture(SEED)
    baseline = baseline_defense_config(fixture)
    config = (
        hardened_defense_config(
            fixture,
            signing_key=KEY,
            key_id="key-tenant-observer",
            application_nonce="apply-tenant-observer-0001",
            prior=baseline,
        )
        if hardened
        else baseline
    )
    audit = BoundedTenantAuditLog()
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"request-{counter:024x}"

    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        signing_key=KEY if hardened else None,
        audit_log=audit,
        clock=lambda: NOW,
        request_id_factory=next_id,
    )
    return fixture, config, audit, application


def _observe(fixture, config, audit, response):
    return observe_tenant_response(
        fixture=fixture,
        config=config,
        audit_row=audit.row(response.headers["x-bluefire-lab-request"]),
        response_status=response.status,
        response_headers=response.headers,
        response_body=response.body,
        attempt_id="attempt-baseline-0001",
        run_id="run-20261104T150000Z-0123456789abcdef",
        step_id="tenant-boundary",
        target_scope_ref="sha256:" + "1" * 64,
    )


def test_observer_establishes_unauthorized_target_effect_without_engine_claim() -> None:
    fixture, config, audit, application = _application()
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    response = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        {"host": "tenant-record.test", "x-bluefire-lab-tenant": fixture.protected_tenant_id},
        source_identity="engine_worker",
    )

    content = checked_observation_content(_observe(fixture, config, audit, response))

    assert content["assessment"] == "unauthorized_disclosure"
    assert content["protected_record_ids"] == [protected.record_id]
    assert content["requested_tenant"] == fixture.protected_tenant_id
    assert content["authenticated_tenant"] == fixture.protected_tenant_id
    assert content["tenant_classification"] == "protected_authenticated"
    assert content["independent_observation"] is True
    assert content["engine_assertion"] is False


def test_observer_distinguishes_denial_and_legitimate_success() -> None:
    fixture, config, audit, application = _application(hardened=True)
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    denied = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        {"host": "tenant-record.test", "x-bluefire-lab-tenant": fixture.protected_tenant_id},
        source_identity="engine_worker",
    )
    denied_record = _observe(fixture, config, audit, denied)

    token = mint_lab_session(
        fixture,
        config,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )
    legitimate = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        {"host": "tenant-record.test", "authorization": f"BlueFireLab {token}"},
        source_identity="ordinary_user",
    )
    legitimate_record = _observe(fixture, config, audit, legitimate)

    denied_content = checked_observation_content(denied_record)
    assert denied_content["assessment"] == "authorization_denied"
    assert denied_content["requested_tenant"] == fixture.protected_tenant_id
    assert denied_content["authenticated_tenant"] is None
    assert denied_content["tenant_classification"] == "protected_requested_unauthenticated"
    assert (
        checked_observation_content(legitimate_record)["assessment"] == "legitimate_use_succeeded"
    )


def test_observer_rejects_client_target_mismatch() -> None:
    fixture, config, audit, application = _application()
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    response = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        {"host": "tenant-record.test", "x-bluefire-lab-tenant": fixture.protected_tenant_id},
        source_identity="engine_worker",
    )

    with pytest.raises(TenantRecordObservationError, match="bytes disagree"):
        observe_tenant_response(
            fixture=fixture,
            config=config,
            audit_row=audit.snapshot()[0],
            response_status=response.status,
            response_headers=response.headers,
            response_body=response.body + b"tampered",
            attempt_id="attempt-baseline-0001",
            run_id="run-20261104T150000Z-0123456789abcdef",
            step_id="tenant-boundary",
            target_scope_ref="sha256:" + "1" * 64,
        )

    tampered_headers = dict(response.headers)
    tampered_headers["cache-control"] = "public"
    with pytest.raises(TenantRecordObservationError, match="headers disagree"):
        observe_tenant_response(
            fixture=fixture,
            config=config,
            audit_row=audit.snapshot()[0],
            response_status=response.status,
            response_headers=tampered_headers,
            response_body=response.body,
            attempt_id="attempt-baseline-0001",
            run_id="run-20261104T150000Z-0123456789abcdef",
            step_id="tenant-boundary",
            target_scope_ref="sha256:" + "1" * 64,
        )


def test_observer_classifies_known_record_tenant_mismatch() -> None:
    fixture, config, audit, application = _application(hardened=True)
    probe_record = fixture.records_for(fixture.probe_tenant_id)[0]
    token = mint_lab_session(
        fixture,
        config,
        signing_key=KEY,
        subject_id=fixture.legitimate_subject_id,
        tenant_id=fixture.protected_tenant_id,
        issued_at=NOW,
        lifetime_seconds=60,
    )

    response = application.handle(
        "GET",
        f"/records/{probe_record.record_id}",
        {"host": "tenant-record.test", "authorization": f"BlueFireLab {token}"},
        source_identity="ordinary_user",
    )
    content = checked_observation_content(_observe(fixture, config, audit, response))

    assert response.status == 404
    assert content["requested_tenant"] == fixture.probe_tenant_id
    assert content["authenticated_tenant"] == fixture.protected_tenant_id
    assert content["tenant_classification"] == "cross_tenant_mismatch"
    assert content["assessment"] == "no_protected_effect"


def test_audit_log_is_bounded_and_unique() -> None:
    fixture = generate_tenant_record_fixture(SEED)
    audit = BoundedTenantAuditLog(max_events=1)
    application = TenantRecordApplication(
        fixture=fixture,
        config=baseline_defense_config(fixture),
        audit_log=audit,
        clock=lambda: NOW,
        request_id_factory=lambda: "request-000000000000000000000001",
    )
    application.handle(
        "GET", "/health", {"host": "tenant-record.test"}, source_identity="controller_probe"
    )

    with pytest.raises(TenantRecordObservationError, match="limit"):
        application.handle(
            "GET", "/health", {"host": "tenant-record.test"}, source_identity="controller_probe"
        )
