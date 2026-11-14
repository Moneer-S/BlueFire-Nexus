from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.engine_artifact_store import EngineArtifactPublicationBinding, EngineArtifactStore
from bluefire.engine_relay import BoundedRelayAudit, EngineRelayError, TargetRelayRequest
from bluefire.tenant_engine_run_trace import NO_DISCLOSURE_OUTCOME, verify_tenant_engine_run_trace
from bluefire.tenant_http_completion import ControllerOwnedTenantHttpCompletion
from bluefire.tenant_http_observer import checked_tenant_http_observation_content_v2
from bluefire.tenant_http_result_bridge import (
    TenantHttpResultBridgeError,
    bridge_tenant_http_result_v2,
)
from bluefire.tenant_http_run_trace import compile_tenant_http_run_trace_v2
from bluefire.tenant_http_target_adapter import (
    TenantHttpEngineTargetRequestV2,
    TenantRecordHttpTargetAdapterV2,
)
from bluefire.tenant_http_target_profile import (
    TenantHttpTargetProfileV2,
    admit_tenant_http_operation,
)
from bluefire.tenant_http_target_relay import ControlledTenantHttpRelayV2
from bluefire.tenant_record_controller_contract import tenant_target_snapshot_ref
from bluefire.tenant_record_lab_launcher import LoopbackEndpoint
from bluefire.tenant_record_target_adapter import TenantTargetAdapterError
from bluefire.util import content_hash
from tests_platform.test_engine_artifact_store import seal
from tests_platform.test_tenant_engine_result_bridge import _case as _binding_case
from tests_platform.test_tenant_record_target_adapter import (
    KEY,
    NOW,
    FakeSource,
    FakeTransport,
    _expectation,
    _fixture_and_configs,
    _generation,
    _protect,
)


def _hash(label: str) -> str:
    return content_hash({"v2-test": label})


def _setup(root: Path, *, hardened=False, clock_ns=None):
    fixture, before, after = _fixture_and_configs()
    config = after if hardened else before
    generation = _generation(root, fixture=fixture, config=config, marker="1a")
    generation = replace(
        generation, packet=replace(generation.packet, verified_at="2026-11-04T15:00:03Z")
    )
    source = FakeSource(generation, root)
    transport = FakeTransport(
        generation=generation, root=root, signing_key=KEY if hardened else None
    )
    expectation = _expectation(generation, root)
    binding = replace(
        _binding_case()["binding"],
        attempt_id=generation.lifecycle.plan.attempt_id,
        target_snapshot_ref=tenant_target_snapshot_ref(
            fixture_digest=fixture.digest,
            target_snapshot_id=config.target_snapshot_id,
            service_generation=config.service_generation,
        ),
    )
    profile = TenantHttpTargetProfileV2.from_running(
        generation=generation,
        expected_generation=expectation,
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=_hash("delegation"),
        objective_ref=binding.objective_ref,
        environment_ref=binding.environment_ref,
        scope_ref=binding.scope_ref,
        created_at="2026-11-04T15:00:03Z",
        expires_at="2026-11-04T15:00:33Z",
        child_request_reserve=4,
        max_http_calls=4,
        max_response_bytes=65536,
        max_total_response_bytes=4 * 65536,
        request_timeout_ms=5000,
        run_timeout_ms=30000,
    )
    monotonic = clock_ns or (lambda: 1_000_000_000)
    adapter = TenantRecordHttpTargetAdapterV2(
        scratch_root=root, source=source, transport=transport, monotonic_ns=monotonic
    )
    audit = BoundedRelayAudit()
    relay = ControlledTenantHttpRelayV2(
        profile, adapter, audit, clock=lambda: NOW, monotonic_ns=monotonic
    )
    return fixture, config, generation, source, transport, binding, profile, adapter, audit, relay


def _request(profile, target="/health", *, headers=(), number=1, **changes):
    return replace(
        TargetRelayRequest(
            f"relay-request-{number:032x}",
            profile.attempt_id,
            profile.authority,
            "GET",
            target,
            headers,
        ),
        **changes,
    )


def _completion(case, root: Path):
    binding, profile = case[5], case[6]
    source = root / "worker-source"
    source.mkdir()
    (source / "run.json").write_bytes(b'{"status":"completed"}')
    artifact_root = root / "worker-artifacts"
    artifact_root.mkdir()
    _protect(artifact_root, directory=True)
    artifacts = EngineArtifactStore(artifact_root)
    publication = EngineArtifactPublicationBinding(
        attempt_id=binding.attempt_id,
        binding_digest=binding.binding_digest,
        delegation_digest=profile.delegation_digest,
        launch_digest=_hash("launch"),
        runtime_resolution_ref=_hash("runtime-resolution"),
        execution_claim_ref=_hash("execution-claim"),
        worker_outcome_digest=_hash("worker-outcome"),
    )
    artifacts.import_or_reopen(
        attempt_id=binding.attempt_id,
        source_run_dir=source,
        source_seal=seal(source, attempt_id=binding.attempt_id),
        allowed_names=("run.json",),
        publication_binding=publication,
    )
    receipts = root / "completion-receipts"
    receipts.mkdir()
    _protect(receipts, directory=True)
    return ControllerOwnedTenantHttpCompletion(
        root=receipts,
        artifacts=artifacts,
        binding=binding,
        profile=profile,
        monotonic_ns=lambda: 1_000_000_000,
    )


def _bridge(case, request, forwarded):
    (
        fixture,
        config,
        _generation_value,
        source,
        _transport,
        binding,
        profile,
        _adapter_value,
        audit,
        _relay_value,
    ) = case
    # Reopen the retained controller records independently of the result envelope.
    retained = next(
        item
        for item in source.audit_bindings
        if item.request_id == forwarded.result.target_request_id
    )
    return bridge_tenant_http_result_v2(
        binding=binding,
        profile=profile,
        fixture=fixture,
        config=config,
        relay_request=request,
        forwarded=forwarded,
        retained_audit_binding=replace(retained),
        retained_audit_ref=content_hash({"retained_audit_binding": retained.digest}),
        retained_relay_audit=replace(audit.records()[-1]),
        retained_relay_audit_ref=_hash("retained-relay"),
    )


@pytest.mark.parametrize(
    "target",
    (
        "/records/unknown-record",
        "/records/abc",
        "/records/a_b",
        "/exports?tenant=unknown-tenant",
        "/health",
        "/openapi.json",
    ),
)
def test_v2_app_grammar_is_independent_of_known_ids(tmp_path, target):
    *_, profile, _adapter_value, _audit_value, _relay_value = _setup(tmp_path)
    operation = admit_tenant_http_operation(
        profile, _request(profile, target), deadline_ns=6_000_000_000
    )
    assert operation.target == target
    assert operation.source_identity == "engine_worker"
    assert operation.asset_ref == profile.asset_ref


@pytest.mark.parametrize(
    "target",
    (
        "http://127.0.0.1:1/health",
        "//evil/health",
        "/health?x=y",
        "/records/../health",
        "/records/a%2fb",
        "/records/a\\b",
        "/records/unknown-record?x=y",
        "/exports?tenant=abc&tenant=def",
        "/exports?tenant=abc&x=y",
        "/exports?tenant=",
        "/exports?tenant=abc#x",
        "/exports?tenant=a+b",
        "/exports?tenant=ABC",
        "/records/" + "a" * 65,
        "/unrelated-service",
    ),
)
def test_v2_rejects_alternate_or_noncanonical_targets_before_effect(tmp_path, target):
    *_, profile, _adapter_value, _audit_value, relay = _setup(tmp_path)
    with pytest.raises(EngineRelayError):
        relay.handle(_request(profile, target))
    trace = relay.controller_trace()
    assert trace["accepted_http_calls"] == 0
    assert trace["target_results"] == 0
    assert trace["controller_refusals"][0]["target_result"] is False


@pytest.mark.parametrize(
    "headers",
    (
        (("host", "evil"),),
        (("authorization", "Bearer nope"),),
        (("cookie", "x=y"),),
        (("x-bluefire-lab-source-token", "stolen"),),
        (("x-forwarded-host", "evil"),),
        (("content-length", "1"),),
        (("accept", "x"), ("accept", "y")),
        (("Accept", "x"),),
        (("user-agent", "x\r\ny"),),
        (("user-agent", "x" * 257),),
        (("x-bluefire-lab-tenant", "../tenant"),),
    ),
)
def test_v2_headers_cannot_inject_authority_or_framing(tmp_path, headers):
    *_, profile, _adapter_value, _audit_value, relay = _setup(tmp_path)
    with pytest.raises(EngineRelayError):
        relay.handle(_request(profile, headers=headers))
    assert relay.controller_trace()["accepted_http_calls"] == 0


@pytest.mark.parametrize(
    "changes",
    (
        {"authority": "localhost:41003"},
        {"authority": "127.0.0.1:41004"},
        {"method": "POST"},
        {"body": b"payload"},
        {"attempt_id": "engine-attempt-" + "f" * 32},
    ),
)
def test_v2_binds_exact_origin_method_body_and_attempt(tmp_path, changes):
    case = _setup(tmp_path)
    profile, relay = case[6], case[-1]
    with pytest.raises(EngineRelayError):
        relay.handle(_request(profile, **changes))
    assert not case[4].calls


@pytest.mark.parametrize(
    ("hardened", "target_kind", "status"),
    (
        (False, "unknown_record", 404),
        (False, "unknown_tenant", 403),
        (True, "unknown_record", 401),
        (True, "unknown_tenant", 401),
    ),
)
def test_v2_target_denials_are_correlated_observations(tmp_path, hardened, target_kind, status):
    case = _setup(tmp_path, hardened=hardened)
    (
        fixture,
        _config,
        _generation_value,
        _source_value,
        transport,
        _binding,
        profile,
        _adapter_value,
        audit,
        relay,
    ) = case
    target = (
        "/records/unknown-record"
        if target_kind == "unknown_record"
        else "/exports?tenant=unknown-tenant"
    )
    headers = (
        ("user-agent", "Strix controlled HTTP"),
        ("accept", "application/json"),
        ("x-bluefire-lab-tenant", fixture.probe_tenant_id),
    )
    request = _request(profile, target, headers=headers)
    result = relay.handle(request)
    observed = _bridge(case, request, result)
    content = checked_tenant_http_observation_content_v2(observed.observation)
    assert content["response_status"] == status
    assert content["assessment"] in {"authorization_denied", "no_protected_effect"}
    assert audit.records()[0].status == "succeeded"
    assert audit.records()[0].result_status == status
    assert not relay.controller_trace()["controller_refusals"]
    assert dict(transport.calls[0][2])["user-agent"] == "Strix controlled HTTP"
    assert dict(transport.calls[0][2])["accept"] == "application/json"
    assert observed.target_observation_ref == result.result.target_observation_ref


def test_v2_engine_selects_record_tenant_header_and_request_order(tmp_path):
    case = _setup(tmp_path)
    fixture, profile, relay = case[0], case[6], case[-1]
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    request = _request(
        profile,
        f"/records/{protected.record_id}",
        headers=(("x-bluefire-lab-tenant", fixture.protected_tenant_id),),
    )
    disclosure = _bridge(case, request, relay.handle(request))
    assert (
        checked_tenant_http_observation_content_v2(disclosure.observation)["assessment"]
        == "unauthorized_disclosure"
    )
    later = _request(profile, "/openapi.json", number=2)
    assert relay.handle(later).result.response.status == 200
    assert [event["kind"] for event in relay.controller_trace()["events"]] == [
        "dispatch",
        "target_result",
        "dispatch",
        "target_result",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_http_calls", 33),
        ("child_request_reserve", 32),
        ("max_response_bytes", 65537),
        ("max_total_response_bytes", 4 * 65536 + 1),
        ("request_timeout_ms", 5001),
        ("run_timeout_ms", 600001),
        ("child_max_audit_bytes", 4096),
        ("endpoint", LoopbackEndpoint("127.0.0.1", 0)),
    ),
)
def test_v2_budgets_stay_inside_child_and_audit_caps(tmp_path, field, value):
    profile = _setup(tmp_path)[6]
    with pytest.raises(ValueError):
        replace(profile, **{field: value})


def test_v2_separate_http_call_and_response_reservation_budgets(tmp_path):
    case = _setup(tmp_path)
    profile = replace(case[6], max_total_response_bytes=65536)
    # Bind a fresh adapter; an already bound adapter cannot be rebound.
    adapter = TenantRecordHttpTargetAdapterV2(
        scratch_root=tmp_path, source=case[3], transport=case[4], monotonic_ns=lambda: 1_000_000_000
    )
    relay = ControlledTenantHttpRelayV2(
        profile, adapter, BoundedRelayAudit(), clock=lambda: NOW, monotonic_ns=lambda: 1_000_000_000
    )
    relay.handle(_request(profile))
    with pytest.raises(EngineRelayError, match="response-byte"):
        relay.handle(_request(profile, number=2))
    assert relay.controller_trace()["accepted_http_calls"] == 1
    assert relay.controller_trace()["budget_exhausted"] is True
    assert relay.controller_trace()["controller_refusals"][0]["code"] == "budget_exhausted"


def test_v2_adapter_rechecks_direct_operations_and_replay(tmp_path):
    case = _setup(tmp_path)
    profile, adapter = case[6], case[7]
    operation = admit_tenant_http_operation(profile, _request(profile), deadline_ns=6_000_000_000)
    with pytest.raises(TenantTargetAdapterError):
        TenantHttpEngineTargetRequestV2(
            profile, replace(operation, source_identity="ordinary_user")
        )
    adapter.engine_http_request(TenantHttpEngineTargetRequestV2(profile, operation))
    with pytest.raises(EngineRelayError, match="consumed"):
        adapter.engine_http_request(TenantHttpEngineTargetRequestV2(profile, operation))


def test_v2_changed_generation_or_asset_stops_before_network(tmp_path):
    case = _setup(tmp_path)
    profile, source, transport = case[6], case[3], case[4]
    forged = replace(profile, asset_ref=_hash("other-asset"))
    adapter = TenantRecordHttpTargetAdapterV2(
        scratch_root=tmp_path, source=source, transport=transport
    )
    with pytest.raises((EngineRelayError, ValueError)):
        adapter.bind_http_profile(forged)
    assert not transport.calls
    source.fail_check = True
    with pytest.raises(EngineRelayError, match="unknown"):
        case[-1].handle(_request(profile))
    assert not transport.calls
    assert case[-1].controller_trace()["target_unknown"] == 1


def test_v2_deadline_revocation_and_audit_failure_never_yield_negative_result(tmp_path):
    now = [1_000_000_000]
    case = _setup(tmp_path, clock_ns=lambda: now[0])
    profile, relay = case[6], case[-1]
    now[0] += profile.run_timeout_ms * 1_000_000
    with pytest.raises(EngineRelayError, match="deadline"):
        relay.handle(_request(profile))
    assert relay.controller_trace()["budget_exhausted"] is True
    assert not case[4].calls


def test_v2_revocation_blocks_future_effects(tmp_path):
    case = _setup(tmp_path)
    profile, relay = case[6], case[-1]
    assert relay.revoke(_completion(case, tmp_path)).digest.startswith("sha256:")
    with pytest.raises(EngineRelayError, match="revoked"):
        relay.handle(_request(profile))
    assert not case[4].calls


def test_v2_target_secret_stays_private_and_bridge_rejects_relabeling(tmp_path):
    case = _setup(tmp_path)
    profile, relay = case[6], case[-1]
    request = _request(profile)
    forwarded = relay.handle(request)
    observed = _bridge(case, request, forwarded)
    token = case[2].admission("engine_worker").token
    assert base64.urlsafe_b64encode(token).decode("ascii").rstrip("=") not in repr(
        observed.to_dict()
    )
    with pytest.raises(TenantHttpResultBridgeError):
        _bridge(case, replace(request, target="/openapi.json"), forwarded)
    with pytest.raises(TenantHttpResultBridgeError):
        _bridge(
            case,
            request,
            replace(
                forwarded,
                result=replace(forwarded.result, audit_retention_ref=_hash("forged-retention")),
            ),
        )


@pytest.mark.parametrize(
    ("missing_result", "close_relay"), ((False, True), (True, True), (False, False))
)
def test_v2_complete_relay_trace_correlates_independent_results(
    tmp_path, missing_result, close_relay
):
    case = _setup(tmp_path)
    profile, relay, binding = case[6], case[-1], case[5]
    request = _request(profile)
    observed = _bridge(case, request, relay.handle(request))
    owner = _completion(case, tmp_path)
    if close_relay:
        relay.revoke(owner)
    bundle = compile_tenant_http_run_trace_v2(
        profile=profile,
        run_id=binding.run_id,
        retained_controller_trace=relay.controller_trace(),
        retained_bridged_results={} if missing_result else {request.request_id: observed},
        state="completed",
        completion_owner=owner,
        finished_ns=1_000_000_001,
    )
    assessment = verify_tenant_engine_run_trace(
        binding=bundle.binding,
        events=bundle.events,
        terminal=bundle.terminal,
        retained_results=bundle.results,
        retained_terminal_ref=bundle.terminal.digest,
        reopened_cessation=bundle.reopened_cessation,
    )
    assert assessment.outcome == (
        "unknown" if missing_result or not close_relay else NO_DISCLOSURE_OUTCOME
    )


def test_v2_refusals_stay_separate_in_complete_trace(tmp_path):
    case = _setup(tmp_path)
    profile, relay, binding = case[6], case[-1], case[5]
    with pytest.raises(EngineRelayError):
        relay.handle(_request(profile, target="https://example.invalid", number=2))
    request = _request(profile)
    observed = _bridge(case, request, relay.handle(request))
    owner = _completion(case, tmp_path)
    relay.revoke(owner)
    bundle = compile_tenant_http_run_trace_v2(
        profile=profile,
        run_id=binding.run_id,
        retained_controller_trace=relay.controller_trace(),
        retained_bridged_results={request.request_id: observed},
        state="completed",
        completion_owner=owner,
        finished_ns=1_000_000_001,
    )
    assessment = verify_tenant_engine_run_trace(
        binding=bundle.binding,
        events=bundle.events,
        terminal=bundle.terminal,
        retained_results=bundle.results,
        retained_terminal_ref=bundle.terminal.digest,
        reopened_cessation=bundle.reopened_cessation,
    )
    assert assessment.controller_refusals == 1
    assert assessment.target_results == 1
    assert assessment.outcome == NO_DISCLOSURE_OUTCOME


def test_v2_fresh_packet_verification_time_is_not_a_generation_change(tmp_path):
    case = _setup(tmp_path)
    source, profile, relay = case[3], case[6], case[-1]
    source.current = replace(
        source.current, packet=replace(source.current.packet, verified_at="2026-11-04T15:00:04Z")
    )
    assert relay.handle(_request(profile)).result.response.status == 200


def test_v2_direct_adapter_refuses_a_longer_per_request_deadline(tmp_path):
    case = _setup(tmp_path)
    profile, adapter = case[6], case[7]
    operation = admit_tenant_http_operation(profile, _request(profile), deadline_ns=7_000_000_000)
    with pytest.raises(TenantTargetAdapterError):
        adapter.engine_http_request(TenantHttpEngineTargetRequestV2(profile, operation))
    assert not case[4].calls


def test_v2_redirect_or_missing_target_audit_is_unknown(tmp_path):
    case = _setup(tmp_path)
    transport, profile, relay = case[4], case[6], case[-1]
    original = transport.request

    def redirect(endpoint, request):
        return replace(original(endpoint, request), status=302)

    transport.request = redirect
    with pytest.raises(EngineRelayError, match="unknown"):
        relay.handle(_request(profile))
    trace = relay.controller_trace()
    assert trace["target_results"] == 0
    assert trace["target_unknown"] == 1
    assert len(transport.calls) == 1
