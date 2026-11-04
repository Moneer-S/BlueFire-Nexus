from __future__ import annotations

from dataclasses import replace
from typing import Sequence

import pytest

from bluefire.engine_network_policy import (
    EffectiveNetworkSnapshot,
    EndpointRole,
    EngineNetworkObserver,
    EngineNetworkPlan,
    EngineNetworkPolicyError,
    EngineNetworkVerification,
    NetworkFlow,
    NetworkProbeResult,
    ProbeOutcome,
    ResolutionBinding,
    VerificationState,
    observe_effective_network,
    required_probe_matrix,
    validate_model_gateway_url,
    validate_target_url,
    verify_effective_network,
)

ATTEMPT_ID = "engine-attempt-0123456789abcdef0123456789abcdef"
DIGEST = "sha256:" + "a" * 64
ENFORCER = "sha256:" + "b" * 64
NOW = "2026-11-04T12:00:00Z"


def _plan(*, ipv6: bool = False) -> EngineNetworkPlan:
    if ipv6:
        return EngineNetworkPlan.create(
            attempt_id=ATTEMPT_ID,
            network_identity_ref=DIGEST,
            subnet="fd12:3456:789a::/64",
            target_address="fd12:3456:789a::2",
            model_gateway_address="fd12:3456:789a::3",
            host_gateway_address="fd12:3456:789a::1",
            created_at=NOW,
        )
    return EngineNetworkPlan.create(
        attempt_id=ATTEMPT_ID,
        network_identity_ref=DIGEST,
        subnet="172.28.40.0/24",
        target_address="172.28.40.2",
        model_gateway_address="172.28.40.3",
        host_gateway_address="172.28.40.1",
        created_at=NOW,
    )


def _snapshot(plan: EngineNetworkPlan) -> EffectiveNetworkSnapshot:
    return EffectiveNetworkSnapshot(
        schema_version="bluefire.engine-network-snapshot.v1",
        attempt_id=plan.attempt_id,
        policy_digest=plan.policy_digest,
        network_identity_ref=plan.network_identity_ref,
        network_name=plan.network_name,
        subnet=plan.subnet,
        controller_address=plan.controller_address,
        daemon_address=plan.daemon_address,
        enforcer_ref=ENFORCER,
        captured_at=NOW,
        attached_network_identity_refs=(plan.network_identity_ref,),
        allowed_flows=(
            NetworkFlow(EndpointRole.TARGET, plan.target.address, plan.target.port),
            NetworkFlow(
                EndpointRole.MODEL_GATEWAY,
                plan.model_gateway.address,
                plan.model_gateway.port,
            ),
        ),
        resolution_bindings=(
            ResolutionBinding(
                EndpointRole.TARGET,
                plan.target.service_name,
                (plan.target.address,),
            ),
            ResolutionBinding(
                EndpointRole.MODEL_GATEWAY,
                plan.model_gateway.service_name,
                (plan.model_gateway.address,),
            ),
        ),
        blocked_classes=(
            "controller",
            "daemon",
            "host_gateway",
            "link_local",
            "metadata",
            "other_egress",
            "public_dns",
        ),
        default_egress_deny=True,
        public_dns_blocked=True,
        metadata_blocked=True,
        host_gateway_blocked=True,
        controller_blocked=True,
        daemon_tcp_disabled=True,
        management_socket_exposed=False,
        redirects_revalidated=True,
        single_network_attachment=True,
        host_network_disabled=True,
        overlapping_host_routes_absent=True,
        host_loopback_unreachable=True,
    )


def _probes(plan: EngineNetworkPlan) -> tuple[NetworkProbeResult, ...]:
    return tuple(
        NetworkProbeResult(name, address, port, expected)
        for name, address, port, expected in required_probe_matrix(plan)
    )


def test_plan_round_trips_and_derives_fixed_service_names() -> None:
    plan = _plan()

    assert plan.network_name == "bf-engine-456789abcdef"
    assert plan.target.service_name == "bf-target-456789abcdef"
    assert plan.model_gateway.service_name == "bf-model-456789abcdef"
    assert plan.target.port == 8080
    assert plan.model_gateway.port == 8081
    assert EngineNetworkPlan.from_mapping(plan.to_dict()) == plan
    assert plan.policy_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_address", "127.0.0.1", "outside"),
        ("target_address", "169.254.10.2", "outside"),
        ("target_address", "8.8.8.8", "outside"),
        ("target_address", "::ffff:172.28.40.2", "canonical"),
        ("model_gateway_address", "172.28.40.2", "distinct"),
        ("host_gateway_address", "172.28.40.255", "usable"),
    ],
)
def test_plan_rejects_unadmitted_or_colliding_addresses(
    field: str, value: str, message: str
) -> None:
    values = {
        "attempt_id": ATTEMPT_ID,
        "network_identity_ref": DIGEST,
        "subnet": "172.28.40.0/24",
        "target_address": "172.28.40.2",
        "model_gateway_address": "172.28.40.3",
        "host_gateway_address": "172.28.40.1",
        "created_at": NOW,
    }
    values[field] = value
    with pytest.raises(EngineNetworkPolicyError, match=message):
        EngineNetworkPlan.create(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "subnet",
    [
        "172.28.40.1/24",
        "172.28.40.0/31",
        "100.64.0.0/24",
        "203.0.113.0/24",
        "fd12:3456:789a::1/64",
        "fd00:ec2::/64",
        "2001:db8::/64",
        "fe80::/64",
    ],
)
def test_plan_rejects_noncanonical_or_nonprivate_subnets(subnet: str) -> None:
    with pytest.raises(EngineNetworkPolicyError, match="subnet"):
        EngineNetworkPlan.create(
            attempt_id=ATTEMPT_ID,
            network_identity_ref=DIGEST,
            subnet=subnet,
            target_address="172.28.40.2",
            model_gateway_address="172.28.40.3",
            host_gateway_address="172.28.40.1",
            created_at=NOW,
        )


def test_ipv6_ula_plan_and_probe_matrix_are_supported() -> None:
    plan = _plan(ipv6=True)

    assert plan.subnet == "fd12:3456:789a::/64"
    assert plan.target.address == "fd12:3456:789a::2"
    assert len(required_probe_matrix(plan)) == 11
    assert (
        verify_effective_network(plan, _snapshot(plan), _probes(plan), checked_at=NOW).state
        is VerificationState.VERIFIED
    )


def test_plan_mapping_refuses_derived_name_or_fixed_policy_tampering() -> None:
    plan = _plan()
    row = plan.to_dict()
    row["network_name"] = "bf-engine-deadbeef0000"
    with pytest.raises(EngineNetworkPolicyError, match="not canonical"):
        EngineNetworkPlan.from_mapping(row)

    row = plan.to_dict()
    row["default_egress"] = "allow"
    with pytest.raises(EngineNetworkPolicyError, match="not canonical"):
        EngineNetworkPlan.from_mapping(row)


def test_effective_snapshot_round_trips_strictly() -> None:
    snapshot = _snapshot(_plan())

    assert EffectiveNetworkSnapshot.from_mapping(snapshot.to_dict()) == snapshot

    row = snapshot.to_dict()
    row["extra"] = True
    with pytest.raises(EngineNetworkPolicyError, match="fields"):
        EffectiveNetworkSnapshot.from_mapping(row)

    row = snapshot.to_dict()
    row["resolution_bindings"][0]["addresses"].append("172.28.40.4")
    with pytest.raises(EngineNetworkPolicyError, match="one address"):
        EffectiveNetworkSnapshot.from_mapping(row)


def test_complete_external_snapshot_and_fixed_probes_verify() -> None:
    plan = _plan()

    result = verify_effective_network(plan, _snapshot(plan), _probes(plan), checked_at=NOW)

    assert result.state is VerificationState.VERIFIED
    assert result.limitations == ()
    assert result.policy_digest == plan.policy_digest
    assert result.snapshot_digest.startswith("sha256:")
    assert len(result.probes) == 11
    assert (
        EngineNetworkVerification.from_mapping(
            result.to_dict(), plan=plan, snapshot=_snapshot(plan)
        )
        == result
    )


def test_verification_rehydration_rejects_state_or_probe_tampering() -> None:
    plan = _plan()
    result = verify_effective_network(plan, _snapshot(plan), _probes(plan), checked_at=NOW)
    row = result.to_dict()
    row["state"] = "unknown"
    with pytest.raises(EngineNetworkPolicyError, match="contradicts"):
        EngineNetworkVerification.from_mapping(row, plan=plan, snapshot=_snapshot(plan))

    row = result.to_dict()
    row["probes"].append(row["probes"][0])
    with pytest.raises(EngineNetworkPolicyError, match="duplicate"):
        EngineNetworkVerification.from_mapping(row, plan=plan, snapshot=_snapshot(plan))

    row = result.to_dict()
    row["probes"] = []
    with pytest.raises(EngineNetworkPolicyError, match="does not match"):
        EngineNetworkVerification.from_mapping(row, plan=plan, snapshot=_snapshot(plan))

    row = result.to_dict()
    row["state"] = "unknown"
    row["limitations"] = ["arbitrary"]
    with pytest.raises(EngineNetworkPolicyError, match="does not match"):
        EngineNetworkVerification.from_mapping(row, plan=plan, snapshot=_snapshot(plan))

    mismatch_probes = list(_probes(plan))
    mismatch_probes[2] = replace(mismatch_probes[2], outcome=ProbeOutcome.UNEXPECTED_REACHABLE)
    mismatch = verify_effective_network(
        plan, _snapshot(plan), mismatch_probes, checked_at=NOW
    ).to_dict()
    mismatch["state"] = "unknown"
    with pytest.raises(EngineNetworkPolicyError, match="does not match"):
        EngineNetworkVerification.from_mapping(mismatch, plan=plan, snapshot=_snapshot(plan))


def test_direct_plan_construction_cannot_bypass_fixed_controls() -> None:
    plan = _plan()
    tampered = replace(plan, default_egress="allow")

    with pytest.raises(EngineNetworkPolicyError, match="not canonical"):
        verify_effective_network(tampered, _snapshot(plan), _probes(plan), checked_at=NOW)


@pytest.mark.parametrize(
    ("snapshot", "expected"),
    [
        (lambda value: replace(value, default_egress_deny=False), "effective_control"),
        (
            lambda value: replace(
                value,
                resolution_bindings=(
                    replace(value.resolution_bindings[0], addresses=("172.28.40.4",)),
                    value.resolution_bindings[1],
                ),
            ),
            "resolution_binding",
        ),
        (
            lambda value: replace(value, network_identity_ref="sha256:" + "c" * 64),
            "network_identity",
        ),
        (
            lambda value: replace(value, captured_at="2026-11-04T12:01:00Z"),
            "snapshot_time",
        ),
        (
            lambda value: replace(value, captured_at="2026-11-04T11:59:59Z"),
            "snapshot_time",
        ),
        (
            lambda value: replace(value, controller_address="172.28.40.4"),
            "management_location",
        ),
        (
            lambda value: replace(
                value,
                attached_network_identity_refs=(
                    value.network_identity_ref,
                    "sha256:" + "d" * 64,
                ),
            ),
            "network_attachment",
        ),
        (
            lambda value: replace(value, single_network_attachment=False),
            "effective_control",
        ),
    ],
)
def test_snapshot_mismatches_never_verify(snapshot: object, expected: str) -> None:
    plan = _plan()
    changed = snapshot(_snapshot(plan))  # type: ignore[operator]

    result = verify_effective_network(plan, changed, _probes(plan), checked_at=NOW)

    assert result.state is VerificationState.MISMATCH
    assert any(expected in item for item in result.limitations)


def test_missing_or_inconclusive_probe_is_unknown() -> None:
    plan = _plan()
    probes = list(_probes(plan))
    probes.pop()
    probes[2] = replace(probes[2], outcome=ProbeOutcome.INCONCLUSIVE)

    result = verify_effective_network(plan, _snapshot(plan), probes, checked_at=NOW)

    assert result.state is VerificationState.UNKNOWN
    assert "public_dns_v4_inconclusive" in result.limitations
    assert "rebound_target_missing" in result.limitations


def test_unexpected_reachability_is_a_mismatch() -> None:
    plan = _plan()
    probes = list(_probes(plan))
    probes[2] = replace(probes[2], outcome=ProbeOutcome.UNEXPECTED_REACHABLE)

    result = verify_effective_network(plan, _snapshot(plan), probes, checked_at=NOW)

    assert result.state is VerificationState.MISMATCH
    assert "public_dns_v4_unexpected" in result.limitations


def test_extra_duplicate_or_redirected_probe_is_refused() -> None:
    plan = _plan()
    probes = list(_probes(plan))
    with pytest.raises(EngineNetworkPolicyError, match="duplicated"):
        verify_effective_network(plan, _snapshot(plan), probes + [probes[0]], checked_at=NOW)

    bad = replace(probes[0], address="172.28.40.4")
    with pytest.raises(EngineNetworkPolicyError, match="destination"):
        verify_effective_network(plan, _snapshot(plan), [bad], checked_at=NOW)

    extra = NetworkProbeResult("arbitrary", "9.9.9.11", 443, ProbeOutcome.BLOCKED_BY_POLICY)
    with pytest.raises(EngineNetworkPolicyError, match="outside"):
        verify_effective_network(plan, _snapshot(plan), probes + [extra], checked_at=NOW)


class _Observer(EngineNetworkObserver):
    def __init__(self, plan: EngineNetworkPlan) -> None:
        self.plan = plan
        self.calls: list[str] = []

    def capture(self, plan: EngineNetworkPlan) -> EffectiveNetworkSnapshot:
        assert plan == self.plan
        self.calls.append("capture")
        return _snapshot(plan)

    def probe(self, plan: EngineNetworkPlan) -> Sequence[NetworkProbeResult]:
        assert plan == self.plan
        self.calls.append("probe")
        return _probes(plan)


def test_observer_is_injected_and_cannot_change_the_matrix() -> None:
    plan = _plan()
    observer = _Observer(plan)

    result = observe_effective_network(plan, observer, checked_at=NOW)

    assert result.state is VerificationState.VERIFIED
    assert observer.calls == ["capture", "probe"]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:8080/",
        "http://bf-target-456789abcdef:8081/",
        "https://bf-target-456789abcdef:8080/",
        "http://user@bf-target-456789abcdef:8080/",
        "http://bf-target-456789abcdef:8080/path#fragment",
        "http://bf-target-456789abcdef:8080\\@example.com/",
        "http://127.0.0.1:8080/",
        "http://9.9.9.9:8080/",
        "http://BF-TARGET-456789ABCDEF:8080/",
        "http://bf-target-456789abcdef:08080/",
    ],
)
def test_target_url_rejects_scope_expansion_redirects_and_ambiguous_forms(url: str) -> None:
    with pytest.raises(EngineNetworkPolicyError):
        validate_target_url(_plan(), url)


def test_target_url_accepts_only_bound_origin_with_arbitrary_target_path() -> None:
    plan = _plan()
    service_url = f"{plan.target.origin}/exports?tenant=generated"
    literal_url = f"http://{plan.target.address}:{plan.target.port}/records/generated"

    assert validate_target_url(plan, service_url) == service_url
    assert validate_target_url(plan, literal_url) == literal_url


def test_model_gateway_requires_the_exact_attempt_local_endpoint() -> None:
    plan = _plan()
    exact = f"{plan.model_gateway.origin}/v1/chat/completions"

    assert validate_model_gateway_url(plan, exact) == exact
    with pytest.raises(EngineNetworkPolicyError, match="exact path"):
        validate_model_gateway_url(plan, exact + "?debug=1")
    with pytest.raises(EngineNetworkPolicyError, match="exact path"):
        validate_model_gateway_url(plan, f"{plan.model_gateway.origin}/v1/models")
