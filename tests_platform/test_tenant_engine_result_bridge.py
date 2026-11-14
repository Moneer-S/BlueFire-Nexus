from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

import pytest

from bluefire.engine_attempt_contract import (
    EngineAttemptBinding,
    EngineEvidenceItem,
    EvidenceCategory,
)
from bluefire.engine_relay import (
    BoundedRelayAudit,
    FixedTargetRelay,
    ProtectedRevocationResult,
    ProtectedTargetResult,
    TargetOperation,
    TargetRelayPolicy,
    TargetRelayRequest,
)
from bluefire.tenant_engine_result_bridge import (
    TenantEngineResultBridgeError,
    bridge_tenant_engine_result,
)
from bluefire.tenant_record_experiment_controller import tenant_target_snapshot_ref
from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from bluefire.tenant_record_lab_launcher import LoopbackEndpoint
from bluefire.tenant_record_observer import BoundedTenantAuditLog, checked_observation_content
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.tenant_record_target_adapter import (
    TenantBoundAuditReceipt,
    TenantEngineTargetRequest,
    TenantEngineTargetResult,
    TenantEngineTargetRoute,
    TenantGenerationExpectation,
)
from bluefire.util import content_hash

TIME = "2026-11-04T15:00:01Z"
KEY = b"result-bridge-signing-material-00000000001"


def _hash(label: str) -> str:
    return content_hash({"label": label})


class _Forwarder:
    def __init__(self, operation: TargetOperation, result: TenantEngineTargetResult) -> None:
        self.operation, self.result = operation, result

    def forward(self, operation: TargetOperation) -> ProtectedTargetResult:
        assert operation == self.operation
        return ProtectedTargetResult(self.result.response, self.result.target_observation_ref, True)

    def revoke(self, attempt_id: str, relay_identity_ref: str) -> ProtectedRevocationResult:
        raise AssertionError("pure test does not revoke resources")


def _proof(request, result, retained) -> str:
    return content_hash(
        {
            "schema_version": "bluefire.tenant-engine-target-observation.v1",
            "relay_request_id": request.relay_request_id,
            "operation_digest": request.operation_digest,
            "target_request_id": result.target_request_id,
            "generation_digest": request.expected_generation.digest,
            "target_snapshot_ref": request.target_snapshot_ref,
            "audit_row_digest": result.audit_row.digest,
            "audit_binding_digest": retained.digest,
            "audit_retention_ref": result.audit_retention_ref,
            "response_status": result.response.status,
            "response_sha256": "sha256:" + hashlib.sha256(result.response.body).hexdigest(),
            "response_headers_sha256": content_hash(dict(result.response.headers)),
        }
    )


def _case(
    *, hardened=False, protected=True, route="record_lookup", identity="1", record_index=0
) -> dict[str, Any]:
    fixture = generate_tenant_record_fixture(b"tenant-engine-result-bridge-seed-0000000001")
    config = (
        hardened_defense_config(
            fixture,
            prior=baseline_defense_config(fixture),
            key_id="key-result-bridge-00000001",
            application_nonce="hardening-bridge-00000001",
            signing_key=KEY,
        )
        if hardened
        else baseline_defense_config(fixture)
    )
    snapshot = tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": "experiment-" + "a" * 32,
            "attempt_id": "engine-attempt-" + identity * 32,
            "run_id": "run-20261104T150000Z-" + identity * 16,
            "role": "adaptive_search" if hardened else "baseline",
            "parent_attempt_id": "engine-attempt-" + "f" * 32 if hardened else None,
            "objective_ref": _hash("objective"),
            "environment_ref": _hash("environment"),
            "target_snapshot_ref": snapshot,
            "scope_ref": _hash("scope"),
            "scope_version": "owned-lab.v1",
            "engine_id": "strix",
            "engine_version": "1.7.0",
            "engine_revision": "a" * 40,
            "engine_package_digest": _hash("package"),
            "policy_overlay_digest": _hash("overlay"),
            "model_provider": "controlled-provider",
            "model_id": "controlled-model",
            "model_data_destination": "owned test gateway",
            "model_authorization_ref": _hash("model-authorization"),
            "wall_clock_seconds": 600,
            "action_limit": 24,
            "cost_limit_microunits": 0,
            "artifact_byte_limit": 1_048_576,
            "created_at": "2026-11-04T15:00:00Z",
        }
    )
    policy = TargetRelayPolicy(
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=_hash("delegation"),
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        target_snapshot_digest=snapshot,
        protected_target_ref=_hash("protected-target"),
        relay_identity_ref=_hash("relay"),
        network_policy_digest=_hash("network"),
        relay_authority=f"bf-target-{binding.attempt_id[-12:]}:8080",
        admitted_routes=("bounded_export", "health", "metadata", "record_lookup"),
        admitted_record_ids=tuple(sorted(record.record_id for record in fixture.records)),
        admitted_tenant_ids=tuple(sorted({record.tenant_id for record in fixture.records})),
        created_at=binding.created_at,
        expires_at="2026-11-04T15:10:00Z",
        max_response_bytes=65_536,
    )
    tenant = fixture.protected_tenant_id if protected else fixture.probe_tenant_id
    record = fixture.records_for(tenant)[record_index]
    operation = TargetOperation(
        request_id="relay-request-" + identity * 32,
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=policy.delegation_digest,
        network_policy_digest=policy.network_policy_digest,
        relay_identity_ref=policy.relay_identity_ref,
        protected_target_ref=policy.protected_target_ref,
        route_id=route,
        record_id=record.record_id if route == "record_lookup" else None,
        tenant_id=tenant if route == "bounded_export" else None,
        tenant_assertion=tenant if route in {"record_lookup", "bounded_export"} else None,
        source_identity="engine_worker",
        max_response_bytes=policy.max_response_bytes,
        deadline_ns=policy.request_timeout_ms * 1_000_000,
    )
    generation = TenantGenerationExpectation(
        plan_digest=_hash("plan"),
        lifecycle_digest=_hash("lifecycle"),
        ready_digest=_hash("ready"),
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    request = TenantEngineTargetRequest(
        relay_request_id=operation.request_id,
        operation_digest=content_hash(operation.to_dict()),
        expected_generation=generation,
        target_snapshot_ref=snapshot,
        route=TenantEngineTargetRoute(route),
        record_id=operation.record_id,
        tenant_id=operation.tenant_id,
        tenant_assertion=operation.tenant_assertion,
        max_response_bytes=operation.max_response_bytes,
        deadline_ns=operation.deadline_ns,
    )
    audit = BoundedTenantAuditLog()
    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        signing_key=KEY if hardened else None,
        audit_log=audit,
        clock=lambda: datetime(2026, 11, 4, 15, 0, 1, tzinfo=timezone.utc),
        request_id_factory=lambda: "request-" + identity * 24,
    )
    target = {
        "record_lookup": f"/records/{record.record_id}",
        "bounded_export": f"/exports?tenant={tenant}",
        "health": "/health",
        "metadata": "/openapi.json",
    }[route]
    headers = {"host": "tenant-record.test"}
    if operation.tenant_assertion:
        headers["x-bluefire-lab-tenant"] = operation.tenant_assertion
    response = application.handle("GET", target, headers, source_identity="engine_worker")
    row = audit.snapshot()[0]
    retained = TenantBoundAuditReceipt(
        request_id=row.request_id,
        audit_row_digest=row.digest,
        source_identity="engine_worker",
        source_admission_digest=_hash("source-admission"),
        plan_digest=generation.plan_digest,
        lifecycle_digest=generation.lifecycle_digest,
        liveness_receipt_digest=_hash("liveness"),
        run_id="engine-lab-" + identity * 32,
        attempt_id="engine-attempt-" + "d" * 32,
        packet_digest=_hash("packet"),
        fixture_digest=fixture.digest,
        config_digest=config.digest,
        endpoint=LoopbackEndpoint(host="127.0.0.1", port=31337),
        ready_digest=generation.ready_digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    result = TenantEngineTargetResult(
        relay_request_id=request.relay_request_id,
        operation_digest=request.operation_digest,
        target_request_id=row.request_id,
        response=response,
        generation_digest=generation.digest,
        audit_row=row,
        audit_binding=replace(retained),
        audit_retention_ref=_hash("audit-retention"),
        target_observation_ref=_hash("placeholder"),
        protected_secret_absent=True,
    )
    result = replace(result, target_observation_ref=_proof(request, result, retained))
    relay_request = TargetRelayRequest(
        request_id=operation.request_id,
        attempt_id=binding.attempt_id,
        authority=policy.relay_authority,
        method="GET",
        target=target,
        headers=(
            (("x-bluefire-lab-tenant", operation.tenant_assertion),)
            if operation.tenant_assertion is not None
            else ()
        ),
    )
    relay_audit = BoundedRelayAudit()
    relay = FixedTargetRelay(
        policy,
        _Forwarder(operation, result),
        relay_audit,
        clock=lambda: datetime(2026, 11, 4, 15, 0, 1, tzinfo=timezone.utc),
        monotonic_ns=lambda: 0,
    )
    relay.handle(relay_request)
    return {
        "binding": binding,
        "policy": policy,
        "fixture": fixture,
        "config": config,
        "operation": operation,
        "relay_request": relay_request,
        "request": request,
        "result": result,
        "retained_audit_binding": retained,
        "retained_audit_ref": result.audit_retention_ref,
        "retained_relay_audit": relay_audit.records()[0],
        "retained_relay_audit_ref": _hash("protected-relay-retention"),
    }


def _report(case, **changes) -> EngineEvidenceItem:
    content: dict[str, Any] = {
        "schema_version": "bluefire.strix-run-snapshot.v1",
        "upstream_run_id": "upstream-session",
        "engine_status": "completed",
        "attempt_state": "completed",
        "completeness": "complete",
        "exit_reason": None,
        "process_exit_code": 2,
        "process_classification": "findings_threshold",
        "engine_reported_findings": True,
        "security_outcome": "not_independently_established",
        "caveats": [],
        "run_record_sha256": _hash("run-artifact"),
        "coverage_sha256": None,
    }
    content.update(changes)
    return EngineEvidenceItem.create(
        attempt_id=case["binding"].attempt_id,
        run_id=case["binding"].run_id,
        category=EvidenceCategory.ENGINE_ASSERTION,
        producer="strix",
        observed_at=TIME,
        content=content,
        source_artifact_digest=_hash("run-artifact"),
    )


@pytest.mark.parametrize("route", ["record_lookup", "bounded_export"])
def test_exact_result_yields_existing_controller_observation_without_effects(route) -> None:
    case = _case(route=route)
    before = json.dumps(case["result"].audit_row.to_dict(), sort_keys=True)
    bridged = bridge_tenant_engine_result(**case, engine_evidence=_report(case))
    observation = bridged.observation
    assert observation.assessment == "unauthorized_disclosure"
    assert observation.failure_mechanism is not None
    independent = observation.independent_observation()
    independent.validate()
    assert independent.attempt_id == case["binding"].attempt_id
    assert independent.target_snapshot_ref == case["binding"].target_snapshot_ref
    assert independent.evidence == observation.evidence
    assert bridged.engine_report.reported_findings is True
    assert before == json.dumps(case["result"].audit_row.to_dict(), sort_keys=True)
    assert bridge_tenant_engine_result(**case, engine_evidence=_report(case)) == bridged


@pytest.mark.parametrize("report_state", ["failed", "unknown", "cancelled", None])
def test_refusal_unknown_and_missing_report_do_not_determine_target_outcome(report_state) -> None:
    case = _case(protected=False)
    report = (
        None
        if report_state is None
        else _report(case, attempt_state=report_state, exit_reason="Model refused the request.")
    )
    bridged = bridge_tenant_engine_result(**case, engine_evidence=report)
    assert bridged.observation.assessment == "no_protected_effect"
    assert bridged.observation.failure_mechanism is None
    public = bridged.to_dict()
    assert public["engine_report"]["security_outcome"] == "not_independently_established"
    assert "prevention" not in json.dumps(public)
    assert "objective_success" not in public


def test_findings_claim_cannot_override_independent_denial() -> None:
    case = _case(hardened=True)
    bridged = bridge_tenant_engine_result(**case, engine_evidence=_report(case))
    assert bridged.engine_report.reported_findings is True
    assert bridged.observation.assessment == "authorization_denied"
    assert (
        checked_observation_content(bridged.observation.evidence)["source_identity"]
        == "engine_worker"
    )


def test_public_projection_contains_no_engine_prose_paths_secrets_or_tool_trace() -> None:
    case = _case()
    sensitive = "C:/private/credentials/api-key-DO-NOT-EXPOSE"
    report = _report(
        case,
        upstream_run_id=sensitive,
        exit_reason="raw prompt and tool trace " + sensitive,
        caveats=[sensitive],
        engine_status=sensitive,
    )
    bridged = bridge_tenant_engine_result(**case, engine_evidence=report)
    public = json.dumps(bridged.to_dict())
    assert sensitive not in public
    assert "raw prompt" not in public
    assert "127.0.0.1" not in public
    assert "31337" not in public
    assert bridged.engine_report.evidence_ref == content_hash(report.to_dict())
    assert case["result"].response.body.decode() not in public


@pytest.mark.parametrize(
    ("part", "field", "replacement"),
    [
        ("operation", "attempt_id", "engine-attempt-" + "2" * 32),
        ("operation", "binding_digest", _hash("wrong-binding")),
        ("operation", "network_policy_digest", _hash("wrong-network")),
        ("operation", "delegation_digest", _hash("wrong-delegation")),
        ("operation", "relay_identity_ref", _hash("wrong-relay")),
        ("operation", "protected_target_ref", _hash("wrong-target")),
        ("operation", "source_identity", "ordinary_user"),
        ("operation", "request_id", "relay-request-" + "2" * 32),
        ("operation", "max_response_bytes", 1024),
        ("operation", "deadline_ns", 999_999),
        ("request", "operation_digest", _hash("wrong-operation")),
        ("request", "target_snapshot_ref", _hash("wrong-snapshot")),
        ("result", "operation_digest", _hash("wrong-operation")),
        ("result", "relay_request_id", "relay-request-" + "2" * 32),
        ("result", "generation_digest", _hash("wrong-generation")),
        ("result", "audit_retention_ref", _hash("wrong-retention")),
        ("result", "target_observation_ref", _hash("wrong-observation")),
        ("retained_audit_binding", "attempt_id", "engine-attempt-" + "2" * 32),
        ("retained_audit_binding", "run_id", "run-20261104T150000Z-" + "2" * 16),
        ("retained_audit_binding", "source_admission_digest", _hash("wrong-admission")),
        ("retained_audit_binding", "liveness_receipt_digest", _hash("wrong-liveness")),
        ("retained_audit_binding", "packet_digest", _hash("wrong-packet")),
        ("retained_audit_binding", "config_digest", _hash("wrong-config")),
        ("retained_audit_binding", "ready_digest", _hash("wrong-ready")),
        ("retained_relay_audit", "request_id", "relay-request-" + "2" * 32),
        ("retained_relay_audit", "attempt_id", "engine-attempt-" + "2" * 32),
        ("retained_relay_audit", "objective_ref", _hash("wrong-objective")),
        ("retained_relay_audit", "request_digest", _hash("wrong-request")),
        ("retained_relay_audit", "response_digest", _hash("wrong-response")),
        ("retained_relay_audit", "policy_digest", _hash("wrong-policy")),
        ("retained_relay_audit", "evidence_ref", _hash("wrong-action-proof")),
    ],
)
def test_cross_attempt_action_generation_and_proof_swaps_are_rejected(
    part, field, replacement
) -> None:
    case = _case()
    case[part] = replace(case[part], **{field: replacement})
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(**case)


@pytest.mark.parametrize("field", ["body", "status", "headers"])
def test_even_rehashed_observation_cannot_launder_altered_response(field) -> None:
    case = _case()
    response = case["result"].response
    replacement = {
        "body": b'{"records":[]}',
        "status": 403,
        "headers": {**response.headers, "content-length": "0"},
    }[field]
    result = replace(case["result"], response=replace(response, **{field: replacement}))
    case["result"] = replace(
        result,
        target_observation_ref=_proof(case["request"], result, case["retained_audit_binding"]),
    )
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(**case)


def test_fresh_attempt_cannot_reuse_previous_target_result_or_report() -> None:
    old, fresh = _case(identity="1"), _case(identity="2")
    assert fresh["binding"].attempt_id != old["binding"].attempt_id
    assert fresh["binding"].run_id != old["binding"].run_id
    assert fresh["request"].relay_request_id != old["request"].relay_request_id
    assert (
        bridge_tenant_engine_result(**fresh).observation.attempt_id == fresh["binding"].attempt_id
    )
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(**fresh, engine_evidence=_report(old))
    fresh["result"] = old["result"]
    fresh["retained_audit_binding"] = old["retained_audit_binding"]
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(**fresh)


def test_missing_target_telemetry_and_untrusted_mapping_never_mint_observations() -> None:
    case = _case()
    for result in (None, {}, {"status": "refused", "target_prevented": True}):
        case["result"] = result
        with pytest.raises(TenantEngineResultBridgeError, match="typed inputs"):
            bridge_tenant_engine_result(**case)


def test_forged_report_category_producer_and_security_claim_are_rejected() -> None:
    case = _case()
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(
            **case, engine_evidence=_report(case, security_outcome="success")
        )
    for producer, category in (
        ("fake-strix", EvidenceCategory.ENGINE_ASSERTION),
        ("strix", EvidenceCategory.TOOL_RESULT),
    ):
        original = _report(case)
        forged = EngineEvidenceItem.create(
            attempt_id=original.attempt_id,
            run_id=original.run_id,
            category=category,
            producer=producer,
            observed_at=TIME,
            content=original.content,
            source_artifact_digest=original.source_artifact_digest,
        )
        with pytest.raises(TenantEngineResultBridgeError):
            bridge_tenant_engine_result(**case, engine_evidence=forged)


def test_mutated_after_admission_report_is_rejected_without_echoing_payload() -> None:
    case = _case()
    report = _report(case)
    report.content["attempt_state"] = "secret prompt"  # type: ignore[index]
    with pytest.raises(TenantEngineResultBridgeError) as error:
        bridge_tenant_engine_result(**case, engine_evidence=report)
    assert "secret prompt" not in str(error.value)


def test_expired_audit_and_unadmitted_route_fail_closed() -> None:
    case = _case()
    case["policy"] = replace(case["policy"], expires_at="2026-11-04T15:00:01Z")
    with pytest.raises(TenantEngineResultBridgeError, match="lifetime"):
        bridge_tenant_engine_result(**case)
    case = _case()
    case["policy"] = replace(case["policy"], admitted_routes=("health",))
    with pytest.raises(TenantEngineResultBridgeError):
        bridge_tenant_engine_result(**case)


def test_launcher_generation_identity_is_distinct_from_active_engine_identity() -> None:
    case = _case()
    retained, binding = case["retained_audit_binding"], case["binding"]
    assert retained.run_id.startswith("engine-lab-")
    assert binding.run_id.startswith("run-")
    assert retained.attempt_id != binding.attempt_id
    bridged = bridge_tenant_engine_result(**case)
    assert bridged.observation.run_id == binding.run_id
    assert bridged.observation.attempt_id == binding.attempt_id
    assert bridged.audit_binding_ref == retained.digest


def test_rehashed_fresh_relay_request_id_cannot_relabel_an_existing_target_event() -> None:
    case = _case()
    relay_id = "relay-request-" + "2" * 32
    operation = replace(case["operation"], request_id=relay_id)
    request = replace(
        case["request"],
        relay_request_id=relay_id,
        operation_digest=content_hash(operation.to_dict()),
    )
    result = replace(
        case["result"],
        relay_request_id=relay_id,
        operation_digest=request.operation_digest,
    )
    case.update(
        operation=operation,
        request=request,
        relay_request=replace(case["relay_request"], request_id=relay_id),
        result=replace(
            result,
            target_observation_ref=_proof(request, result, case["retained_audit_binding"]),
        ),
    )
    with pytest.raises(TenantEngineResultBridgeError, match="successful relay audit"):
        bridge_tenant_engine_result(**case)


def test_same_attempt_substituted_record_result_requires_its_exact_retained_relay_audit() -> None:
    old, substituted = _case(), _case(record_index=1)
    assert old["operation"].record_id != substituted["operation"].record_id
    assert old["binding"] == substituted["binding"]
    assert (
        bridge_tenant_engine_result(**substituted).observation.assessment
        == "unauthorized_disclosure"
    )
    substituted["retained_relay_audit"] = old["retained_relay_audit"]
    with pytest.raises(TenantEngineResultBridgeError, match="successful relay audit"):
        bridge_tenant_engine_result(**substituted)


@pytest.mark.parametrize("relay_audit", [None, {}, {"status": "succeeded"}])
def test_missing_trusted_relay_audit_never_mints_independent_observation(relay_audit) -> None:
    case = _case()
    case["retained_relay_audit"] = relay_audit
    with pytest.raises(TenantEngineResultBridgeError, match="typed inputs"):
        bridge_tenant_engine_result(**case)


@pytest.mark.parametrize(
    "status", ["upstream_failed", "deadline_exceeded", "secret_leak", "revoked"]
)
def test_unsuccessful_relay_audit_never_establishes_target_effect_or_prevention(status) -> None:
    case = _case()
    case["retained_relay_audit"] = replace(
        case["retained_relay_audit"],
        status=status,
        response_digest=None,
        response_bytes=0,
        result_status=None,
        evidence_ref=None,
    )
    with pytest.raises(TenantEngineResultBridgeError, match="successful relay audit"):
        bridge_tenant_engine_result(**case)


def test_relay_retention_reference_is_mandatory_and_bounded() -> None:
    case = _case()
    case["retained_relay_audit_ref"] = "C:/private/not-a-proof"
    with pytest.raises(TenantEngineResultBridgeError, match="proof reference"):
        bridge_tenant_engine_result(**case)
