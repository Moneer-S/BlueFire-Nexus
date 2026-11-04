from __future__ import annotations

import base64
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.engine_relay import EngineRelayError, TargetOperation, TargetRelayPolicy
from bluefire.tenant_record_experiment_controller import tenant_target_snapshot_ref
from bluefire.tenant_record_relay_forwarder import (
    ControllerOwnedTenantTargetForwarder,
    tenant_protected_target_ref,
)
from bluefire.tenant_record_target_adapter import TenantTargetAdapterError
from bluefire.util import content_hash
from tests_platform.test_tenant_record_target_adapter import (
    KEY,
    _adapter,
    _admissions,
    _expectation,
    _fixture_and_configs,
    _generation,
)


def _digest(label: str) -> str:
    return content_hash({"forwarder-test": label})


def _policy(generation, root: Path, fixture) -> TargetRelayPolicy:  # type: ignore[no-untyped-def]
    expectation = _expectation(generation, root)
    snapshot_ref = tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=expectation.target_snapshot_id,
        service_generation=expectation.service_generation,
    )
    attempt_id = generation.lifecycle.plan.attempt_id
    return TargetRelayPolicy(
        attempt_id=attempt_id,
        binding_digest=_digest("binding"),
        delegation_digest=_digest("delegation"),
        objective_ref=_digest("objective"),
        environment_ref=_digest("environment"),
        target_snapshot_digest=snapshot_ref,
        protected_target_ref=tenant_protected_target_ref(expectation, snapshot_ref),
        relay_identity_ref=_digest("relay-identity"),
        network_policy_digest=_digest("network-policy"),
        relay_authority=f"bf-target-{attempt_id[-12:]}:8080",
        admitted_routes=("bounded_export", "health", "metadata", "record_lookup"),
        admitted_record_ids=tuple(sorted(record.record_id for record in fixture.records)),
        admitted_tenant_ids=tuple(sorted((fixture.probe_tenant_id, fixture.protected_tenant_id))),
        created_at="2026-11-04T15:00:00Z",
        expires_at="2026-11-04T16:00:00Z",
        max_requests=16,
        max_response_bytes=64 * 1024,
        max_total_response_bytes=4 * 64 * 1024,
        request_timeout_ms=5_000,
    )


def _forwarder(policy, generation, root, adapter, **values):  # type: ignore[no-untyped-def]
    return ControllerOwnedTenantTargetForwarder(
        policy=policy,
        expected_generation=_expectation(generation, root),
        target_snapshot_ref=policy.target_snapshot_digest,
        adapter=adapter,
        monotonic_ns=lambda: 1_000_000_000,
        **values,
    )


def _operation(
    policy: TargetRelayPolicy,
    *,
    suffix: str = "1",
    route_id: str = "health",
    record_id: str | None = None,
    tenant_id: str | None = None,
    tenant_assertion: str | None = None,
) -> TargetOperation:
    return TargetOperation(
        request_id="relay-request-" + suffix * 32,
        attempt_id=policy.attempt_id,
        binding_digest=policy.binding_digest,
        delegation_digest=policy.delegation_digest,
        network_policy_digest=policy.network_policy_digest,
        relay_identity_ref=policy.relay_identity_ref,
        protected_target_ref=policy.protected_target_ref,
        route_id=route_id,
        record_id=record_id,
        tenant_id=tenant_id,
        tenant_assertion=tenant_assertion,
        source_identity="engine_worker",
        max_response_bytes=policy.max_response_bytes,
        deadline_ns=6_000_000_000,
    )


def test_forwarder_executes_fixed_route_and_retains_exact_audit(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="1a")
    adapter, source, transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(policy, generation, tmp_path, adapter)

    result = forwarder.forward(_operation(policy))

    assert result.response.status == 200
    assert result.protected_secret_absent is True
    assert result.target_observation_ref.startswith("sha256:")
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == "/health"
    assert len(source.audit_bindings) == 1
    assert source.audit_bindings[0].source_identity == "engine_worker"
    assert source.audit_bindings[0].request_id == result.response.headers["x-bluefire-lab-request"]
    admission = generation.admission("engine_worker").token
    public = repr(result) + repr(_operation(policy))
    assert admission.hex() not in public
    assert base64.urlsafe_b64encode(admission).decode("ascii").rstrip("=") not in public


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("attempt_id", "engine-attempt-" + "f" * 32),
        ("binding_digest", _digest("wrong-binding")),
        ("delegation_digest", _digest("wrong-delegation")),
        ("network_policy_digest", _digest("wrong-network")),
        ("relay_identity_ref", _digest("wrong-relay")),
        ("protected_target_ref", _digest("wrong-target")),
        ("source_identity", "controller_probe"),
    ),
)
def test_forwarder_rejects_every_immutable_identity_before_dispatch(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="2b")
    adapter, _source, transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(policy, generation, tmp_path, adapter)
    operation = replace(_operation(policy), **{field: value})

    with pytest.raises(EngineRelayError, match="scope"):
        forwarder.forward(operation)

    assert transport.calls == []


@pytest.mark.parametrize(
    "operation",
    (
        lambda policy: replace(_operation(policy), max_response_bytes=64 * 1024 - 1),
        lambda policy: replace(_operation(policy), deadline_ns=1_000_000_000),
        lambda policy: replace(_operation(policy), tenant_assertion="tenant-protected"),
        lambda policy: replace(
            _operation(policy, route_id="bounded_export"),
            tenant_id="tenant-protected",
            tenant_assertion="tenant-probe",
        ),
        lambda policy: replace(_operation(policy), route_id="arbitrary"),
    ),
)
def test_forwarder_rejects_cap_deadline_and_route_smuggling_before_dispatch(
    tmp_path: Path,
    operation,
) -> None:  # type: ignore[no-untyped-def]
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="3c")
    adapter, _source, transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(policy, generation, tmp_path, adapter)

    with pytest.raises(EngineRelayError):
        forwarder.forward(operation(policy))

    assert transport.calls == []


def test_old_generation_fails_after_defense_and_fresh_forwarder_observes_denial(
    tmp_path: Path,
) -> None:
    fixture, before, after = _fixture_and_configs()
    baseline = _generation(tmp_path, fixture=fixture, config=before, marker="4d")
    hardened = _generation(
        tmp_path,
        fixture=fixture,
        config=after,
        marker="5e",
        admissions=_admissions(b"h"),
    )
    old_adapter, old_source, old_transport = _adapter(tmp_path, baseline)
    old_policy = _policy(baseline, tmp_path, fixture)
    old_forwarder = _forwarder(old_policy, baseline, tmp_path, old_adapter)
    old_source.current = hardened

    with pytest.raises(TenantTargetAdapterError, match="generation"):
        old_forwarder.forward(_operation(old_policy, suffix="4"))

    assert old_transport.calls == []

    fresh_adapter, fresh_source, fresh_transport = _adapter(tmp_path, hardened, signing_key=KEY)
    fresh_policy = _policy(hardened, tmp_path, fixture)
    fresh_forwarder = _forwarder(fresh_policy, hardened, tmp_path, fresh_adapter)
    record = fixture.records_for(fixture.protected_tenant_id)[0]
    denied = fresh_forwarder.forward(
        _operation(
            fresh_policy,
            suffix="5",
            route_id="record_lookup",
            record_id=record.record_id,
            tenant_assertion=fixture.protected_tenant_id,
        )
    )

    assert denied.response.status == 401
    assert fresh_source.audit_bindings[-1].source_identity == "engine_worker"
    assert len(fresh_transport.calls) == 1
    assert "authorization" not in dict(fresh_transport.calls[0][2])


def test_revoke_waits_for_inflight_then_blocks_result_and_new_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="6f")
    adapter, source, transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(
        policy,
        generation,
        tmp_path,
        adapter,
        revocation_timeout_seconds=1.0,
    )
    original = adapter.engine_request
    started = threading.Event()
    release = threading.Event()

    def blocked(request):  # type: ignore[no-untyped-def]
        started.set()
        assert release.wait(1)
        return original(request)

    monkeypatch.setattr(adapter, "engine_request", blocked)
    failures: list[Exception] = []

    def invoke() -> None:
        try:
            forwarder.forward(_operation(policy, suffix="6"))
        except Exception as exc:  # expected revocation race
            failures.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert started.wait(1)
    timer = threading.Timer(0.05, release.set)
    timer.start()
    revoked = forwarder.revoke(policy.attempt_id, policy.relay_identity_ref)
    worker.join(1)
    timer.join(1)

    assert revoked.verified is True
    assert len(failures) == 1
    assert isinstance(failures[0], EngineRelayError)
    assert failures[0].code == "revoked"
    with pytest.raises(EngineRelayError, match="revoked"):
        forwarder.forward(_operation(policy, suffix="7"))
    assert len(transport.calls) == 1
    assert source.transition_intents == []
    assert source.cleanup_intents == []


def test_revocation_scope_mismatch_does_not_revoke(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="7a")
    adapter, _source, _transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(policy, generation, tmp_path, adapter)

    with pytest.raises(EngineRelayError, match="scope"):
        forwarder.revoke(policy.attempt_id, _digest("other-relay"))

    assert forwarder.forward(_operation(policy, suffix="8")).response.status == 200


def test_revocation_timeout_is_unverified_until_inflight_settles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="8b")
    adapter, source, _transport = _adapter(tmp_path, generation)
    policy = _policy(generation, tmp_path, fixture)
    forwarder = _forwarder(
        policy,
        generation,
        tmp_path,
        adapter,
        revocation_timeout_seconds=0.01,
    )
    original = adapter.engine_request
    started = threading.Event()
    release = threading.Event()

    def blocked(request):  # type: ignore[no-untyped-def]
        started.set()
        assert release.wait(1)
        return original(request)

    monkeypatch.setattr(adapter, "engine_request", blocked)
    failures: list[Exception] = []

    def invoke() -> None:
        try:
            forwarder.forward(_operation(policy, suffix="9"))
        except Exception as exc:  # expected revocation race
            failures.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    assert started.wait(1)

    first = forwarder.revoke(policy.attempt_id, policy.relay_identity_ref)
    assert first.verified is False
    release.set()
    worker.join(1)
    second = forwarder.revoke(policy.attempt_id, policy.relay_identity_ref)

    assert second.verified is True
    assert second.receipt_ref != first.receipt_ref
    assert len(failures) == 1
    assert isinstance(failures[0], EngineRelayError)
    assert source.transition_intents == []
    assert source.cleanup_intents == []


def test_forwarder_refuses_policy_above_native_response_cap(tmp_path: Path) -> None:
    fixture, before, _after = _fixture_and_configs()
    generation = _generation(tmp_path, fixture=fixture, config=before, marker="9c")
    adapter, _source, _transport = _adapter(tmp_path, generation)
    policy = replace(
        _policy(generation, tmp_path, fixture),
        max_response_bytes=64 * 1024 + 1,
        max_total_response_bytes=4 * 64 * 1024 + 4,
    )

    with pytest.raises(ValueError, match="response cap"):
        _forwarder(policy, generation, tmp_path, adapter)
