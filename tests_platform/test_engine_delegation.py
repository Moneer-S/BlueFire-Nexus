from __future__ import annotations

from dataclasses import replace

import pytest

from bluefire.engine_attempt_contract import (
    AttemptRole,
    EngineAttemptBinding,
    EngineAttemptContractError,
)
from bluefire.engine_delegation import (
    EngineCapabilityDelegation,
    EngineDelegationError,
    EngineEffectClass,
    EngineExecutionApprovalBinding,
    EngineOperationClass,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _delegation() -> EngineCapabilityDelegation:
    return EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + "1" * 32,
        experiment_id="experiment-" + "2" * 32,
        attempt_id="engine-attempt-" + "3" * 32,
        role=AttemptRole.BASELINE,
        parent_attempt_id=None,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        target_snapshot_ref=_digest("3"),
        scope_ref=_digest("4"),
        scope_version="tenant-record-service.v1",
        engine_id="strix",
        engine_version="1.7.0",
        engine_revision="5" * 40,
        engine_package_digest=_digest("6"),
        policy_overlay_digest=_digest("7"),
        model_authorization_ref=_digest("8"),
        model_provider="controlled-test-provider",
        model_id="controlled-strix-mechanics-v1",
        model_data_destination="attempt-local-loopback-test-provider",
        network_policy_digest=_digest("9"),
        custody_plan_digest=_digest("a"),
        wall_clock_seconds=780,
        action_limit=32,
        cost_limit_microunits=50_000,
        artifact_byte_limit=4 * 1024 * 1024,
        created_at="2026-11-04T12:00:00Z",
        expires_at="2026-11-04T12:15:00Z",
    )


def _binding(delegation: EngineCapabilityDelegation) -> EngineAttemptBinding:
    return EngineAttemptBinding(
        schema_version="bluefire.engine-attempt-binding.v1",
        experiment_id=delegation.experiment_id,
        attempt_id=delegation.attempt_id,
        run_id="run-20261104T120001Z-" + "b" * 16,
        role=AttemptRole.BASELINE,
        objective_ref=delegation.objective_ref,
        environment_ref=delegation.environment_ref,
        target_snapshot_ref=delegation.target_snapshot_ref,
        scope_ref=delegation.scope_ref,
        scope_version=delegation.scope_version,
        engine_id=delegation.engine_id,
        engine_version=delegation.engine_version,
        engine_revision=delegation.engine_revision,
        engine_package_digest=delegation.engine_package_digest,
        policy_overlay_digest=delegation.policy_overlay_digest,
        model_provider=delegation.model_provider,
        model_id=delegation.model_id,
        model_data_destination=delegation.model_data_destination,
        model_authorization_ref=delegation.model_authorization_ref,
        wall_clock_seconds=delegation.wall_clock_seconds,
        action_limit=delegation.action_limit,
        cost_limit_microunits=delegation.cost_limit_microunits,
        artifact_byte_limit=delegation.artifact_byte_limit,
        created_at="2026-11-04T12:00:01Z",
        parent_attempt_id=None,
    )


def test_delegation_round_trip_is_canonical_and_digest_stable() -> None:
    delegation = _delegation()

    document = delegation.to_dict()
    parsed = EngineCapabilityDelegation.from_mapping(document)

    assert parsed == delegation
    assert parsed.to_dict() == document
    assert parsed.delegation_digest == delegation.delegation_digest
    assert document["operation_classes"] == [
        "service_surface_discovery",
        "http_authorization_assessment",
    ]
    assert document["effect_classes"] == [
        "bounded_http_requests",
        "read_generated_lab_records",
        "write_attempt_artifacts",
    ]
    assert not {
        "command",
        "script",
        "url",
        "mount",
        "credential",
        "tool_server",
        "defense_change",
    } & set(document)


def test_delegation_binds_attempt_and_existing_one_time_approval_fields() -> None:
    delegation = _delegation()
    binding = _binding(delegation)

    assert delegation.validate_attempt_binding(binding) == binding
    assert delegation.validate_attempt_binding(binding.to_dict()) == binding

    approval = delegation.approval_binding(binding)
    assert EngineExecutionApprovalBinding.from_mapping(approval.to_dict()) == approval
    assert approval.delegation_digest == delegation.delegation_digest
    assert approval.attempt_binding_digest == binding.binding_digest
    assert approval.plan_digest == delegation.delegation_digest
    assert approval.store_binding() == {
        "state_digest": approval.state_digest,
        "plan_digest": delegation.delegation_digest,
        "target_scope_digest": delegation.scope_ref,
        "profile_id": "engine-worker.strix.v1",
        "maximum_tier": "controlled",
    }
    assert approval.request_binding() == {
        "run_id": binding.run_id,
        **approval.store_binding(),
        "expires_at": delegation.expires_at,
    }
    assert delegation.validate_approval_binding(approval, binding) == approval
    assert approval.validate_approval_record(
        {"approval_id": "approval-" + "d" * 32, **approval.request_binding()}
    )["approval_id"].startswith("approval-")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("experiment_id", "experiment-" + "f" * 32),
        ("attempt_id", "engine-attempt-" + "f" * 32),
        ("objective_ref", _digest("b")),
        ("environment_ref", _digest("b")),
        ("target_snapshot_ref", _digest("b")),
        ("scope_ref", _digest("b")),
        ("scope_version", "tenant-record-service.v2"),
        ("engine_version", "1.7.1"),
        ("engine_revision", "b" * 40),
        ("engine_package_digest", _digest("b")),
        ("policy_overlay_digest", _digest("b")),
        ("model_authorization_ref", _digest("b")),
        ("model_provider", "different-provider"),
        ("model_id", "different-model"),
        ("model_data_destination", "different-destination"),
        ("wall_clock_seconds", 781),
        ("action_limit", 33),
        ("cost_limit_microunits", 50_001),
        ("artifact_byte_limit", 4 * 1024 * 1024 + 1),
    ],
)
def test_attempt_cannot_exceed_or_differ_from_delegation(field: str, replacement: object) -> None:
    delegation = _delegation()
    binding = replace(_binding(delegation), **{field: replacement})

    with pytest.raises(EngineDelegationError, match="exceeds or differs"):
        delegation.validate_attempt_binding(binding)


def test_attempt_must_be_created_during_delegation() -> None:
    delegation = _delegation()

    with pytest.raises(EngineDelegationError, match="not created during"):
        delegation.validate_attempt_binding(
            replace(_binding(delegation), created_at="2026-11-04T12:15:00Z")
        )


def test_attempt_constructor_and_delegation_reparse_fail_closed() -> None:
    delegation = _delegation()
    binding = _binding(delegation)

    with pytest.raises(EngineAttemptContractError, match="run ID is invalid"):
        replace(binding, run_id="not-a-run")

    invalid = binding.to_dict()
    invalid["run_id"] = "not-a-run"

    with pytest.raises(EngineDelegationError, match="binding is invalid"):
        delegation.validate_attempt_binding(invalid)


def test_role_and_parent_lineage_are_bound() -> None:
    baseline = _delegation()
    with pytest.raises(EngineDelegationError, match="baseline delegation"):
        replace(baseline, parent_attempt_id="engine-attempt-" + "f" * 32)

    adaptive = replace(
        baseline,
        role=AttemptRole.ADAPTIVE_SEARCH,
        parent_attempt_id="engine-attempt-" + "f" * 32,
    )
    adaptive_binding = replace(
        _binding(adaptive),
        role=AttemptRole.ADAPTIVE_SEARCH,
        parent_attempt_id=adaptive.parent_attempt_id,
    )
    assert adaptive.validate_attempt_binding(adaptive_binding) == adaptive_binding
    with pytest.raises(EngineDelegationError, match="exceeds or differs"):
        adaptive.validate_attempt_binding(
            replace(adaptive_binding, parent_attempt_id="engine-attempt-" + "e" * 32)
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("engine_id", "unreviewed-engine", "not admitted"),
        ("scope_version", "unversioned", "scope version"),
        ("expires_at", "2026-11-04T12:00:00Z", "expiry"),
        ("expires_at", "2026-11-04T12:23:01Z", "expiry"),
        ("wall_clock_seconds", True, "outside its bound"),
        ("action_limit", 0, "outside its bound"),
        ("artifact_byte_limit", 64 * 1024 * 1024 + 1, "outside its bound"),
    ],
)
def test_delegation_rejects_unsupported_identity_or_limits(
    field: str, value: object, match: str
) -> None:
    values = _delegation().to_dict()
    values[field] = value

    with pytest.raises(EngineDelegationError, match=match):
        EngineCapabilityDelegation.from_mapping(values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_classes", ["service_surface_discovery"]),
        (
            "operation_classes",
            ["http_authorization_assessment", "service_surface_discovery"],
        ),
        (
            "operation_classes",
            ["service_surface_discovery", "arbitrary_shell_execution"],
        ),
        ("effect_classes", ["bounded_http_requests"]),
        (
            "effect_classes",
            [
                "bounded_http_requests",
                "read_generated_lab_records",
                "apply_defensive_change",
            ],
        ),
    ],
)
def test_delegation_requires_exact_reviewed_v1_capability(field: str, value: list[str]) -> None:
    document = _delegation().to_dict()
    document[field] = value

    with pytest.raises(EngineDelegationError):
        EngineCapabilityDelegation.from_mapping(document)


@pytest.mark.parametrize(
    "field",
    ["command", "script", "url", "mount", "credential", "tool_server", "defense_change"],
)
def test_delegation_rejects_authority_expanding_fields(field: str) -> None:
    document = _delegation().to_dict()
    document[field] = "not-authorized"

    with pytest.raises(EngineDelegationError, match="fields do not match"):
        EngineCapabilityDelegation.from_mapping(document)


def test_direct_construction_cannot_bypass_capability_validation() -> None:
    delegation = _delegation()

    with pytest.raises(EngineDelegationError, match="operation classes"):
        replace(
            delegation,
            operation_classes=(EngineOperationClass.SERVICE_SURFACE_DISCOVERY,),
        )
    with pytest.raises(EngineDelegationError, match="effect classes"):
        replace(
            delegation,
            effect_classes=(EngineEffectClass.BOUNDED_HTTP_REQUESTS,),
        )


def test_approval_binding_rejects_tampering() -> None:
    approval = _delegation().approval_binding(_binding(_delegation())).to_dict()
    approval["plan_digest"] = _digest("f")

    with pytest.raises(EngineDelegationError, match="does not bind"):
        EngineExecutionApprovalBinding.from_mapping(approval)

    approval = _delegation().approval_binding(_binding(_delegation())).to_dict()
    approval["credential"] = "secret"
    with pytest.raises(EngineDelegationError, match="fields do not match"):
        EngineExecutionApprovalBinding.from_mapping(approval)


def test_approval_state_scope_run_and_expiry_are_exactly_bound() -> None:
    delegation = _delegation()
    binding = _binding(delegation)
    approval = delegation.approval_binding(binding)

    for field, value in (
        ("state_digest", _digest("f")),
        ("target_scope_digest", _digest("f")),
        ("run_id", "run-20261104T120001Z-" + "f" * 16),
        ("expires_at", "2026-11-04T12:14:59Z"),
    ):
        document = approval.to_dict()
        document[field] = value
        if field == "state_digest":
            with pytest.raises(EngineDelegationError, match="state does not bind"):
                EngineExecutionApprovalBinding.from_mapping(document)
        else:
            structurally_valid = EngineExecutionApprovalBinding.from_mapping(document)
            with pytest.raises(EngineDelegationError, match="does not match delegation"):
                delegation.validate_approval_binding(structurally_valid, binding)

    record = {"approval_id": "approval-" + "d" * 32, **approval.request_binding()}
    record["expires_at"] = "2026-11-04T12:16:00Z"
    with pytest.raises(EngineDelegationError, match="does not match the exact request"):
        approval.validate_approval_record(record)
