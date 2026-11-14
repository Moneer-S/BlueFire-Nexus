from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from bluefire.evidence import EvidenceRecord
from bluefire.tenant_http_observer import (
    HTTP_OBSERVATION_SCHEMA_V2,
    HTTP_OBSERVER_ID_V2,
    checked_tenant_http_observation_content_v2,
    observe_tenant_http_response_v2,
)
from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from bluefire.tenant_record_observer import (
    BoundedTenantAuditLog,
    TenantRecordObservationError,
    checked_observation_content,
    observe_tenant_response,
)
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.util import content_hash

KEY = b"http-v2-observer-signing-material-00000000001"


def _inputs(*, hardened=False, target=None, protected=False):
    fixture = generate_tenant_record_fixture(b"http-v2-observer-fixture-seed-0000000001")
    base = baseline_defense_config(fixture)
    config = (
        hardened_defense_config(
            fixture,
            prior=base,
            key_id="key-observer-http-00000001",
            application_nonce="hardening-observer-http-0000001",
            signing_key=KEY,
        )
        if hardened
        else base
    )
    audit = BoundedTenantAuditLog()
    app = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=audit,
        signing_key=KEY if hardened else None,
        clock=lambda: datetime(2026, 11, 5, 15, 0, 1, tzinfo=timezone.utc),
        request_id_factory=lambda: "request-" + "4" * 24,
    )
    tenant = fixture.protected_tenant_id if protected else fixture.probe_tenant_id
    headers = {"host": "tenant-record.test", "x-bluefire-lab-tenant": tenant}
    response = app.handle(
        "GET",
        target or f"/records/{fixture.records_for(tenant)[0].record_id}",
        headers,
        source_identity="engine_worker",
    )
    return {
        "fixture": fixture,
        "config": config,
        "audit_row": audit.snapshot()[0],
        "response_status": response.status,
        "response_headers": response.headers,
        "response_body": response.body,
        "attempt_id": "engine-attempt-" + "2" * 32,
        "run_id": "run-20261105T150000Z-" + "1" * 16,
        "step_id": "http_v2",
        "target_scope_ref": content_hash({"label": "scope"}),
    }


@pytest.mark.parametrize("hardened", [False, True])
def test_audited_unknown_tenant_denial_has_a_separate_v2_contract(hardened):
    inputs = _inputs(hardened=hardened, target="/exports?tenant=unknown-tenant")
    # The baseline identity is admitted, so this is a cross-tenant denial.
    # Hardened mode denies authentication before routing the unknown tenant.
    observed = observe_tenant_http_response_v2(**inputs)
    content = checked_tenant_http_observation_content_v2(observed)
    assert content["response_status"] == (401 if hardened else 403)
    assert content["requested_tenant"] == "unknown-tenant"
    assert content["tenant_classification"] == (
        "unknown_requested_unauthenticated" if hardened else "cross_tenant_mismatch"
    )
    assert content["assessment"] == "authorization_denied"
    assert observed.producer == HTTP_OBSERVER_ID_V2
    assert content["schema_version"] == HTTP_OBSERVATION_SCHEMA_V2
    with pytest.raises(TenantRecordObservationError):
        checked_observation_content(observed)
    if hardened:
        # The pre-existing v1 checker and its closed classifications are unchanged.
        with pytest.raises(TenantRecordObservationError):
            checked_observation_content(observe_tenant_response(**inputs))


@pytest.mark.parametrize(
    "settings,assessment",
    [
        ({}, "no_protected_effect"),
        ({"protected": True}, "unauthorized_disclosure"),
        ({"target": "/records/unknown-record"}, "no_protected_effect"),
    ],
)
def test_v2_preserves_independent_effect_assessments(settings, assessment):
    observed = observe_tenant_http_response_v2(**_inputs(**settings))
    content = checked_tenant_http_observation_content_v2(observed)
    assert content["assessment"] == assessment
    assert content["independent_observation"] is True
    assert content["engine_assertion"] is False


def test_v2_requires_the_exact_response_audit_correlation():
    inputs = _inputs()
    inputs["response_body"] += b" "
    with pytest.raises(TenantRecordObservationError):
        observe_tenant_http_response_v2(**inputs)


def _changed(record, content):
    return EvidenceRecord.create(
        run_id=record.run_id,
        step_id=record.step_id,
        behavior_id=record.behavior_id,
        provenance=record.provenance,
        producer=record.producer,
        content=content,
        target_scope_ref=record.target_scope_ref,
        environment=record.environment,
        timestamp=record.timestamp,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"authenticated_tenant": "invented-tenant"},
        {"requested_tenant": None},
        {"response_status": 200},
        {"assessment": "no_protected_effect"},
    ],
)
def test_unknown_tenant_label_cannot_hide_an_inconsistent_observation(change):
    observed = observe_tenant_http_response_v2(
        **_inputs(hardened=True, target="/exports?tenant=unknown-tenant")
    )
    with pytest.raises(TenantRecordObservationError):
        checked_tenant_http_observation_content_v2(
            _changed(observed, {**observed.content, **change})
        )


def test_mutated_evidence_hash_is_rejected_before_schema_conversion():
    observed = observe_tenant_http_response_v2(**_inputs())
    tampered = replace(observed, content={**observed.content, "response_status": 403})
    with pytest.raises(ValueError):
        checked_tenant_http_observation_content_v2(tampered)


def test_rehashed_assessment_cannot_invent_an_authentication_denial():
    observed = observe_tenant_http_response_v2(**_inputs())
    with pytest.raises(TenantRecordObservationError):
        checked_tenant_http_observation_content_v2(
            _changed(observed, {**observed.content, "assessment": "authorization_denied"})
        )
