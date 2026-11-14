from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from bluefire.tenant_record_controller_contract import tenant_target_snapshot_ref
from bluefire.tenant_record_experiment_fixture import (
    TenantRecordExperimentFixtureError,
    prepare_tenant_record_experiment_case,
    snapshot_tenant_record_engine_response,
    verify_tenant_record_experiment_bundle,
)
from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from bluefire.tenant_record_lab_launcher import LoopbackEndpoint
from bluefire.tenant_record_observer import BoundedTenantAuditLog
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.tenant_record_target_adapter import (
    TenantBoundAuditReceipt,
    TenantEngineTargetResult,
)

OBJECTIVE = "sha256:" + "1" * 64
ENVIRONMENT = "sha256:" + "2" * 64
SCOPE = "sha256:" + "3" * 64
BASELINE_ATTEMPT = "engine-attempt-" + "1" * 32
ADAPTIVE_ATTEMPT = "engine-attempt-" + "2" * 32
SIGNING_KEY = b"tenant-experiment-case-signing-key-0001"
RUN_ID = "run-20261104T150000Z-0123456789abcdef"


def _origin(attempt_id: str) -> str:
    return f"http://bf-target-{attempt_id.removeprefix('engine-attempt-')}:8080"


def _case(
    *,
    held_out: bool = False,
    attempt_id: str = BASELINE_ATTEMPT,
    attempt_role: str = "baseline",
):
    fixture = generate_tenant_record_fixture(
        b"tenant-experiment-case-seed-00000001", held_out=held_out
    )
    baseline = baseline_defense_config(fixture)
    config = (
        baseline
        if attempt_role == "baseline"
        else hardened_defense_config(
            fixture,
            signing_key=SIGNING_KEY,
            key_id="key-experiment-case",
            application_nonce="apply-experiment-case-0001",
            prior=baseline,
        )
    )
    case, criterion, urls = prepare_tenant_record_experiment_case(
        fixture,
        target_config=config,
        attempt_id=attempt_id,
        attempt_role=attempt_role,
        objective_ref=OBJECTIVE,
        environment_ref=ENVIRONMENT,
        scope_ref=SCOPE,
    )
    return fixture, config, case, criterion, urls


@pytest.mark.parametrize("held_out", [False, True])
def test_engine_brief_exposes_capability_boundary_without_held_solution(held_out):
    fixture, config, case, criterion, urls = _case(held_out=held_out)
    origin = _origin(case.attempt_id)

    brief = case.engine_brief()
    serialized = repr(brief)
    assert brief["case_ref"] == case.digest
    assert brief["experiment_ref"] == case.experiment_ref
    assert brief["attempt_id"] == case.attempt_id
    assert brief["attempt_role"] == "baseline"
    assert brief["asset_ref"] == fixture.digest
    assert brief["target_snapshot_ref"] == tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    assert brief["service_generation"] == config.service_generation
    assert brief["starting_identity"]["tenant_id"] == fixture.probe_tenant_id
    assert brief["target_origin"] == origin
    assert brief["authorized_url_set_ref"] == urls.digest
    assert brief["discovery"] == {
        "method": "GET",
        "target": origin + "/openapi.json",
    }
    assert brief["delegation"]["target_assets"] == [fixture.digest]
    assert brief["delegation"]["isolation"] == "owned_disposable_tenant_lab"
    assert fixture.protected_tenant_id not in serialized
    assert all(record.record_id not in serialized for record in fixture.records)
    assert all(record.generated_value not in serialized for record in fixture.records)
    assert all(route not in serialized for route in fixture.route_order)
    assert criterion.experiment_ref == case.experiment_ref
    evaluation = criterion.evaluation_contract()
    assert evaluation["baseline_effect"]["source_identity"] == "engine_worker"
    assert evaluation["original_operation_replay"]["request"] == (
        "exact_retained_failure_mechanism"
    )
    assert evaluation["fresh_adaptive_attempt"]["no_finding_is_security_proof"] is False
    assert evaluation["legitimate_use"]["authenticated_tenant"] == (fixture.protected_tenant_id)
    assert fixture.protected_tenant_id not in serialized


def test_primary_and_held_out_cases_change_conditions_without_changing_objective_shape():
    primary_fixture, _primary_config, primary, primary_criterion, primary_urls = _case()
    held_fixture, _held_config, held, held_criterion, held_urls = _case(held_out=True)
    origin = _origin(BASELINE_ATTEMPT)

    assert primary.objective_ref == held.objective_ref
    assert primary.environment_ref == held.environment_ref
    assert primary.scope_ref == held.scope_ref
    assert primary.condition_ref != held.condition_ref
    assert primary.asset_ref != held.asset_ref
    assert primary.starting_tenant_id != held.starting_tenant_id
    assert primary_fixture.route_order == tuple(reversed(held_fixture.route_order))
    assert primary_criterion.protected_record_bindings != (held_criterion.protected_record_bindings)
    assert primary_urls.digest != held_urls.digest
    assert all(url.startswith(origin + "/") for url in primary_urls.urls + held_urls.urls)


def test_fresh_attempts_share_experiment_but_not_attempt_authority():
    fixture, baseline_config, baseline, baseline_criterion, baseline_urls = _case()
    adaptive_config = hardened_defense_config(
        fixture,
        signing_key=SIGNING_KEY,
        key_id="key-experiment-case",
        application_nonce="apply-experiment-case-0001",
        prior=baseline_config,
    )
    adaptive, adaptive_criterion, adaptive_urls = prepare_tenant_record_experiment_case(
        fixture,
        target_config=adaptive_config,
        attempt_id=ADAPTIVE_ATTEMPT,
        attempt_role="adaptive_search",
        objective_ref=OBJECTIVE,
        environment_ref=ENVIRONMENT,
        scope_ref=SCOPE,
    )

    assert baseline.experiment_ref == adaptive.experiment_ref
    assert baseline_criterion == adaptive_criterion
    assert baseline.digest != adaptive.digest
    assert baseline.case_id != adaptive.case_id
    assert baseline.attempt_id != adaptive.attempt_id
    assert baseline.target_config_ref == baseline_config.digest
    assert adaptive.target_config_ref == adaptive_config.digest
    assert baseline.target_snapshot_ref != adaptive.target_snapshot_ref
    assert baseline.service_generation != adaptive.service_generation
    assert baseline.target_origin == _origin(BASELINE_ATTEMPT)
    assert adaptive.target_origin == _origin(ADAPTIVE_ATTEMPT)
    assert baseline.authorized_url_set_ref == baseline_urls.digest
    assert adaptive.authorized_url_set_ref == adaptive_urls.digest
    assert baseline_urls.digest != adaptive_urls.digest

    with pytest.raises(TenantRecordExperimentFixtureError, match="do not match"):
        verify_tenant_record_experiment_bundle(
            fixture, baseline_config, baseline, baseline_criterion, adaptive_urls
        )
    with pytest.raises(TenantRecordExperimentFixtureError, match="do not match"):
        verify_tenant_record_experiment_bundle(
            fixture, adaptive_config, baseline, baseline_criterion, baseline_urls
        )


def test_target_authority_binds_the_complete_attempt_identity():
    first = "engine-attempt-" + "1" * 20 + "a" * 12
    second = "engine-attempt-" + "2" * 20 + "a" * 12
    _fixture, _config, first_case, _criterion, first_urls = _case(attempt_id=first)
    _fixture, _config, second_case, _criterion, second_urls = _case(attempt_id=second)

    assert first_case.target_origin != second_case.target_origin
    assert first_urls.digest != second_urls.digest
    assert first_case.target_origin == _origin(first)
    assert second_case.target_origin == _origin(second)


def test_scope_and_target_asset_remain_distinct_bindings():
    fixture, _config, case, criterion, _urls = _case()

    assert case.scope_ref == SCOPE
    assert case.asset_ref == fixture.digest
    assert case.scope_ref != case.asset_ref
    with pytest.raises(TenantRecordExperimentFixtureError):
        replace(case, scope_ref="not-a-digest")
    foreign = replace(criterion, fixture_digest=case.scope_ref)
    assert foreign.fixture_digest != case.asset_ref


@pytest.mark.parametrize(
    "changes",
    (
        {"max_http_calls": 0},
        {"max_http_calls": 33},
        {"max_total_response_bytes": 0},
        {"max_total_response_bytes": 33 * 65536},
        {"max_runtime_seconds": 0},
        {"max_runtime_seconds": 901},
    ),
)
def test_case_budgets_remain_bounded(changes):
    _fixture, _config, case, _criterion, _urls = _case()
    with pytest.raises(TenantRecordExperimentFixtureError):
        replace(case, **changes)


def test_case_identity_binds_even_valid_budget_changes():
    _fixture, _config, case, _criterion, _urls = _case()
    with pytest.raises(TenantRecordExperimentFixtureError, match="identity"):
        replace(case, max_http_calls=17)


def test_criterion_rejects_duplicate_or_unbound_records():
    fixture, config, case, criterion, urls = _case()
    first = criterion.protected_record_bindings[0]
    with pytest.raises(TenantRecordExperimentFixtureError):
        replace(criterion, protected_record_bindings=(first, first))
    foreign = replace(criterion, experiment_ref="sha256:" + "f" * 64)
    assert foreign.experiment_ref != case.experiment_ref
    assert criterion.experiment_ref == case.experiment_ref
    with pytest.raises(TenantRecordExperimentFixtureError, match="do not match"):
        verify_tenant_record_experiment_bundle(fixture, config, case, foreign, urls)


@pytest.mark.parametrize(
    "origin",
    (
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://2130706433:8080",
        "http://0x7f000001:8080",
        "http://tenant-record.test:8080",
        "https://bf-target-111111111111:8080",
        "http://bf-target-111111111111:8080/path",
        "http://user@bf-target-111111111111:8080",
        "http://bf-target-111111111111:0",
    ),
)
def test_case_refuses_localhost_rewrite_and_unadmitted_origins(origin):
    _fixture, _config, case, _criterion, _urls = _case()
    with pytest.raises(TenantRecordExperimentFixtureError):
        replace(case, target_origin=origin)


def test_controller_url_set_is_exact_but_not_disclosed_to_engine():
    fixture, config, case, criterion, urls = _case()
    origin = _origin(case.attempt_id)
    brief = repr(case.engine_brief())
    assert origin + "/openapi.json" in urls.urls
    assert origin + "/health" in urls.urls
    assert {origin + f"/records/{record.record_id}" for record in fixture.records} < set(urls.urls)
    assert origin + f"/exports?tenant={fixture.protected_tenant_id}" in urls.urls
    assert fixture.protected_tenant_id not in brief
    assert all(record.record_id not in brief for record in fixture.records)

    changed = list(urls.urls)
    changed[2] = origin + "/records/record-00000000000000000000"
    substituted = replace(urls, urls=tuple(changed))
    with pytest.raises(TenantRecordExperimentFixtureError, match="do not match"):
        verify_tenant_record_experiment_bundle(fixture, config, case, criterion, substituted)


def _target_result_for(case, fixture, config, route):
    audit = BoundedTenantAuditLog()
    host = urlsplit(case.target_origin).hostname
    assert host is not None
    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=audit,
        signing_key=SIGNING_KEY if config.mode == "signed_session" else None,
        allowed_hosts=(host,),
        clock=lambda: datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc),
        request_id_factory=lambda: "request-" + "a" * 24,
    )
    response = application.handle(
        "GET",
        route,
        {"host": host, "x-bluefire-lab-tenant": fixture.protected_tenant_id},
        source_identity="engine_worker",
    )
    row = audit.row(response.headers["x-bluefire-lab-request"])
    token = "sha256:" + "b" * 64
    binding = TenantBoundAuditReceipt(
        request_id=row.request_id,
        audit_row_digest=row.digest,
        source_identity="engine_worker",
        source_admission_digest=token,
        plan_digest=token,
        lifecycle_digest=token,
        liveness_receipt_digest=token,
        run_id=RUN_ID,
        attempt_id=case.attempt_id,
        packet_digest=token,
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        endpoint=LoopbackEndpoint("127.0.0.1", 8080),
        ready_digest=token,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    return TenantEngineTargetResult(
        relay_request_id="relay-request-" + "c" * 32,
        operation_digest=token,
        target_request_id=row.request_id,
        response=response,
        generation_digest=token,
        audit_row=row,
        audit_binding=binding,
        audit_retention_ref=token,
        target_observation_ref=token,
        protected_secret_absent=True,
    )


@pytest.mark.parametrize("held_out", [False, True])
def test_target_snapshot_uses_audited_public_discovery_and_generation(held_out):
    fixture, config, case, _criterion, _urls = _case(held_out=held_out)
    result = _target_result_for(case, fixture, config, "/openapi.json")
    snapshot, evidence = snapshot_tenant_record_engine_response(
        fixture=fixture,
        target_config=config,
        case=case,
        target_result=result,
        run_id=RUN_ID,
        step_id="target-discovery",
    )

    assert snapshot.target_request_id == result.target_request_id
    assert snapshot.target_snapshot_ref == case.target_snapshot_ref
    assert snapshot.service_generation == config.service_generation
    assert snapshot.audit_row_ref == result.audit_row.digest
    assert snapshot.independent_evidence_ref == evidence.record_hash
    assert snapshot.public_routes == tuple(
        (name, "/records/{record_id}" if name == "record_lookup" else "/exports?tenant={tenant_id}")
        for name in fixture.route_order
    )
    assert snapshot.public_starting_tenant_id == fixture.probe_tenant_id
    assert snapshot.public_record_directory == tuple(record.record_id for record in fixture.records)
    assert evidence.content["independent_observation"] is True


def test_target_snapshot_keeps_defended_denial_and_old_event_distinct():
    fixture, config, case, _criterion, _urls = _case(
        attempt_id=ADAPTIVE_ATTEMPT,
        attempt_role="adaptive_search",
    )
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    result = _target_result_for(case, fixture, config, f"/records/{protected.record_id}")
    snapshot, evidence = snapshot_tenant_record_engine_response(
        fixture=fixture,
        target_config=config,
        case=case,
        target_result=result,
        run_id=RUN_ID,
        step_id="defended-attempt",
    )
    assert snapshot.status_code == 401
    assert snapshot.decision == "denied_missing_session"
    assert snapshot.returned_record_ids == ()
    assert evidence.content["assessment"] == "authorization_denied"

    baseline_config = baseline_defense_config(fixture)
    baseline, _held, _urls = prepare_tenant_record_experiment_case(
        fixture,
        target_config=baseline_config,
        attempt_id=BASELINE_ATTEMPT,
        attempt_role="baseline",
        objective_ref=OBJECTIVE,
        environment_ref=ENVIRONMENT,
        scope_ref=SCOPE,
    )
    with pytest.raises(TenantRecordExperimentFixtureError, match="observation differs"):
        snapshot_tenant_record_engine_response(
            fixture=fixture,
            target_config=baseline_config,
            case=baseline,
            target_result=result,
            run_id=RUN_ID,
            step_id="stale-attempt",
        )
