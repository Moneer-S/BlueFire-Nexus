"""Pure contract tests for owned user-service identity and cleanup evidence."""

from __future__ import annotations

from dataclasses import replace

import pytest

from bluefire.contracts import ContractError
from bluefire.evidence import EvidenceError, EvidenceProvenance, EvidenceRecord
from bluefire.tool_adapters.service_lifecycle import (
    IDENTITY_SCHEMA,
    OBSERVATION_SCHEMA,
    OBSERVER,
    OwnedUserService,
    assess_service_cleanup,
)
from bluefire.util import canonical_json_bytes

CREATED = "2026-01-01T00:00:00Z"
DUE = "2026-01-01T00:30:00Z"
STARTED = "2026-01-01T00:10:00Z"
EVALUATED = "2026-01-01T00:10:05Z"
OBSERVED = "2026-01-01T00:10:04Z"
OVERDUE_STARTED = "2026-01-01T00:31:00Z"
OVERDUE_EVALUATED = "2026-01-01T00:31:05Z"
OVERDUE_OBSERVED = "2026-01-01T00:31:04Z"


@pytest.fixture
def identity_data() -> dict[str, object]:
    return {
        "schema_version": IDENTITY_SCHEMA,
        "authorization_digest": "sha256:" + "a" * 64,
        "runner_profile_id": "runner.profile.v1",
        "workspace_id": "workspace-1",
        "target_scope_digest": "sha256:" + "b" * 64,
        "owner_uid": 1000,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "manager_id": "a" * 32,
        "unit_nonce": "b" * 32,
        "unit_content_digest": "sha256:" + "c" * 64,
        "created_at": CREATED,
        "cleanup_due_at": DUE,
    }


@pytest.fixture
def identity(identity_data: dict[str, object]) -> OwnedUserService:
    return OwnedUserService.from_mapping(identity_data)


def _facts(identity: OwnedUserService) -> dict[str, object]:
    row = identity.to_dict()
    return {
        "schema_version": OBSERVATION_SCHEMA,
        "identity_digest": identity.digest,
        "owner_uid": row["owner_uid"],
        "boot_id": row["boot_id"],
        "manager_id": row["manager_id"],
        "unit_name": identity.unit_name,
        "manager_state": "available",
        "unit_load_state": "absent",
        "unit_active_state": "inactive",
        "unit_file_state": "absent",
        "enable_links_state": "absent",
        "cgroup_state": "empty",
    }


def _evidence(
    identity: OwnedUserService,
    *,
    content: dict[str, object] | None = None,
    timestamp: str = OBSERVED,
    provenance: EvidenceProvenance = EvidenceProvenance.OBSERVED,
    producer: str = OBSERVER,
    action_id: str | None = "service.cleanup.v1",
) -> EvidenceRecord:
    row = identity.to_dict()
    return EvidenceRecord.create(
        run_id="run-service-contract",
        step_id="observe-cleanup",
        behavior_id="service.cleanup.observation.v1",
        provenance=provenance,
        producer=producer,
        action_id=action_id,
        runner_profile_id=row["runner_profile_id"],
        content=_facts(identity) if content is None else content,
        target_scope_ref=row["target_scope_digest"],
        timestamp=timestamp,
    )


def test_identity_is_canonical_immutable_and_derives_only_nonce_unit(identity_data, identity):
    reordered = dict(reversed(list(identity_data.items())))
    assert OwnedUserService.from_mapping(reordered).digest == identity.digest
    assert identity.unit_name == "bluefire-" + "b" * 32 + ".service"
    original = identity.to_dict()
    identity_data["workspace_id"] = "changed"
    exported = identity.to_dict()
    exported["workspace_id"] = "changed-again"
    assert identity.to_dict() == original
    assert OwnedUserService.from_mapping(identity_data).digest != identity.digest


@pytest.mark.parametrize("field", ["command", "script", "executable", "args", "path", "unit_path"])
def test_identity_rejects_unknown_injection_fields(identity_data, field):
    identity_data[field] = "unreviewed"
    with pytest.raises(ContractError):
        OwnedUserService.from_mapping(identity_data)


@pytest.mark.parametrize("uid", [0, True, False, -1, 2**32 - 1, "1000"])
def test_identity_rejects_root_and_non_numeric_owner_uids(identity_data, uid):
    identity_data["owner_uid"] = uid
    with pytest.raises(ContractError):
        OwnedUserService.from_mapping(identity_data)


@pytest.mark.parametrize(
    "created,due", [(CREATED, CREATED), (DUE, CREATED), (CREATED, "2026-01-01T01:00:01Z")]
)
def test_identity_lifetime_is_positive_and_at_most_one_hour(identity_data, created, due):
    identity_data["created_at"], identity_data["cleanup_due_at"] = created, due
    with pytest.raises(ContractError):
        OwnedUserService.from_mapping(identity_data)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update({"owner_uid": 0}),
        lambda row: row.update({"boot_id": "00000000-0000-0000-0000-000000000000"}),
        lambda row: row.update({"command": "sh"}),
        lambda row: row.update({"cleanup_due_at": "2026-01-01T01:00:01Z"}),
    ],
)
def test_direct_constructor_cannot_bypass_identity_validation(identity_data, mutation):
    mutation(identity_data)
    with pytest.raises(ContractError):
        OwnedUserService(canonical_json_bytes(identity_data))


def test_direct_constructor_rejects_noncanonical_or_mutable_bytes(identity):
    with pytest.raises(ContractError):
        OwnedUserService(bytearray(identity._canonical))
    with pytest.raises(ContractError):
        OwnedUserService(identity._canonical + b" ")
    with pytest.raises(ContractError):
        replace(identity, _canonical=identity._canonical + b" ")


def test_replace_cannot_bypass_root_extra_field_or_lifetime(identity, identity_data):
    for mutation in (
        lambda row: row.update({"owner_uid": 0}),
        lambda row: row.update({"command": "sh"}),
        lambda row: row.update({"cleanup_due_at": "2026-01-01T01:00:01Z"}),
    ):
        changed = dict(identity_data)
        mutation(changed)
        with pytest.raises(ContractError):
            replace(identity, _canonical=canonical_json_bytes(changed))


def test_direct_constructor_rejects_non_json_canonical_bytes(identity):
    with pytest.raises(ContractError):
        OwnedUserService(b"not-json")


def test_cleanup_requires_exact_observed_record_and_preserves_hashes(identity):
    record = _evidence(identity)
    restored = EvidenceRecord.from_mapping(record.to_dict())
    assessment = assess_service_cleanup(
        identity, restored, cleanup_started_at=STARTED, evaluated_at=EVALUATED
    )
    assert assessment.status == "verified_absent"
    assert assessment.evidence_id == record.evidence_id
    assert assessment.record_hash == record.record_hash
    tampered = record.to_dict()
    tampered["content"]["cgroup_state"] = "populated"
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_mapping(tampered)


@pytest.mark.parametrize(
    "provenance,producer",
    [(EvidenceProvenance.SYNTHETIC, OBSERVER), (EvidenceProvenance.OBSERVED, "observer.other.v1")],
)
def test_cleanup_requires_independent_observer(identity, provenance, producer):
    result = assess_service_cleanup(
        identity,
        _evidence(identity, provenance=provenance, producer=producer),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "unknown"
    assert result.reasons == ("independent_service_observer_required",)


@pytest.mark.parametrize(
    "timestamp", ["2026-01-01T00:09:59Z", "2026-01-01T00:10:06Z", "2026-01-01T00:10:00Z"]
)
def test_cleanup_requires_fresh_observation_inside_window(identity, timestamp):
    evaluated = "2026-01-01T00:10:10Z" if timestamp.endswith("00Z") else EVALUATED
    result = assess_service_cleanup(
        identity,
        _evidence(identity, timestamp=timestamp),
        cleanup_started_at=STARTED,
        evaluated_at=evaluated,
    )
    assert result.status == "unknown"
    assert result.reasons == ("observation_outside_cleanup_window",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("unit_load_state", "loaded"),
        ("unit_active_state", "active"),
        ("unit_file_state", "owned"),
        ("enable_links_state", "owned"),
        ("cgroup_state", "populated"),
    ],
)
def test_each_residue_gate_prevents_verified_absent(identity, field, value):
    facts = _facts(identity)
    facts[field] = value
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "residue"
    assert result.reasons == (field + "_remains",)


@pytest.mark.parametrize(
    "field",
    ["identity_digest", "owner_uid", "boot_id", "manager_id", "unit_name"],
)
def test_cleanup_requires_exact_identity_fields(identity, field):
    facts = _facts(identity)
    facts[field] = "mismatch" if field != "owner_uid" else 1001
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "identity_mismatch"
    assert result.reasons == (field + "_changed",)


@pytest.mark.parametrize("field", ["runner_profile_id", "target_scope_ref"])
def test_cleanup_requires_exact_profile_and_target(identity, field):
    kwargs = {field: "changed"}
    result = assess_service_cleanup(
        identity,
        EvidenceRecord.create(
            run_id="run-service-contract",
            step_id="observe-cleanup",
            behavior_id="service.cleanup.observation.v1",
            provenance=EvidenceProvenance.OBSERVED,
            producer=OBSERVER,
            runner_profile_id=kwargs.get("runner_profile_id", "runner.profile.v1"),
            content=_facts(identity),
            target_scope_ref=kwargs.get("target_scope_ref", "sha256:" + "b" * 64),
            timestamp=OBSERVED,
        ),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "identity_mismatch"
    expected = "runner_profile_changed" if field == "runner_profile_id" else "target_scope_changed"
    assert result.reasons == (expected,)


@pytest.mark.parametrize("field", ["unit_file_state", "enable_links_state"])
def test_changed_owned_resource_is_identity_mismatch(identity, field):
    facts = _facts(identity)
    facts[field] = "changed"
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "identity_mismatch"
    assert result.reasons == ("owned_resources_changed",)


def test_wrong_shape_parent_or_main_pid_and_action_success_cannot_prove_absence(identity):
    facts = _facts(identity)
    facts["parent_pid"] = 10
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "unknown"
    executed = assess_service_cleanup(
        identity,
        _evidence(
            identity, provenance=EvidenceProvenance.EXECUTED, action_id="service.stop.success"
        ),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert executed.status == "unknown"


def test_missing_or_unknown_observation_is_not_clean(identity):
    assert (
        assess_service_cleanup(
            identity, None, cleanup_started_at=STARTED, evaluated_at=EVALUATED
        ).status
        == "unknown"
    )
    facts = _facts(identity)
    facts["unit_active_state"] = "unknown"
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "unknown"
    facts = _facts(identity)
    facts["manager_state"] = "unavailable"
    result = assess_service_cleanup(
        identity,
        _evidence(identity, content=facts),
        cleanup_started_at=STARTED,
        evaluated_at=EVALUATED,
    )
    assert result.status == "unknown"


def test_cleanup_remains_reportable_after_due_time(identity):
    result = assess_service_cleanup(
        identity,
        _evidence(identity, timestamp=OVERDUE_OBSERVED),
        cleanup_started_at=OVERDUE_STARTED,
        evaluated_at=OVERDUE_EVALUATED,
    )
    assert result.status == "verified_absent"


def test_assessor_rejects_stale_mutated_record_hash(identity):
    record = _evidence(identity)
    object.__setattr__(record, "content", {**record.content, "cgroup_state": "populated"})
    result = assess_service_cleanup(
        identity, record, cleanup_started_at=STARTED, evaluated_at=EVALUATED
    )
    assert result.status == "unknown"
    assert result.reasons == ("observation_integrity_invalid",)


def test_assessor_rejects_oversized_observation(identity):
    record = EvidenceRecord.create(
        run_id="run-service-contract",
        step_id="observe-cleanup",
        behavior_id="service.cleanup.observation.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer=OBSERVER,
        runner_profile_id="runner.profile.v1",
        environment={"padding": "x" * 17_000},
        content=_facts(identity),
        target_scope_ref="sha256:" + "b" * 64,
        timestamp=OBSERVED,
    )
    assert len(canonical_json_bytes(record.to_dict())) > 16 * 1024
    result = assess_service_cleanup(
        identity, record, cleanup_started_at=STARTED, evaluated_at=EVALUATED
    )
    assert result.status == "unknown"
    assert result.reasons == ("observation_size_exceeded",)
