"""Pure file-read target review; no probe, socket, host, or Docker activity."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.engine_attempt_contract import AttemptRole, EngineAttemptBinding
from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION, EngineExperiment
from bluefire.engine_file_access_snapshot import (
    CURRENT_HARDENED,
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from bluefire.engine_file_access_target import (
    TARGET_POLICY_VERSION,
    EngineFileReadTargetError,
    EngineFileReadTargetPolicy,
)
from bluefire.file_access_contract import (
    MAX_BYTES,
    PROBE_ACTION,
    VerifiedFileAccessBinding,
    verify_file_access_binding,
)
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding

NOW_MS = 1_000_000
READ_JOB = "job-" + "1" * 32
HARDEN_JOB = "job-" + "2" * 32


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _current(
    *, hardened: bool = False
) -> tuple[FileAccessReadMechanism, FileAccessTargetSnapshot, VerifiedFileAccessBinding]:
    document = binding()
    baseline = {
        "baseline_digest": _digest("a"),
        "non_owner": "allowed",
        "owner": "allowed",
        "record_count": document["resource"]["record_count"],
        "sha256": document["resource"]["sha256"],
        "source_binding": {
            "operation_job_id": READ_JOB,
            "evidence_digest": _digest("a"),
        },
    }
    original = verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=NOW_MS
    )
    mechanism = FileAccessReadMechanism.from_verified_binding(original, baseline=baseline)
    if hardened:
        document["mode"] = "0600"
        document["control_revision"] = 2
    current = verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=NOW_MS
    )
    snapshot = FileAccessTargetSnapshot.from_verified_binding(
        current,
        mechanism=mechanism,
        control_owner_id=READ_JOB,
        control_digest=_digest("b" if hardened else "c"),
        prior_control_digest=_digest("c") if hardened else None,
        source_operation_job_id=HARDEN_JOB if hardened else READ_JOB,
        source_evidence_digest=_digest("d" if hardened else "a"),
        phase=CURRENT_HARDENED if hardened else HISTORICAL_BASELINE,
    )
    return mechanism, snapshot, current


def _attempt(
    mechanism: FileAccessReadMechanism, snapshot: FileAccessTargetSnapshot
) -> EngineAttemptBinding:
    return EngineAttemptBinding(
        schema_version="bluefire.engine-attempt-binding.v1",
        experiment_id="experiment-" + "1" * 32,
        attempt_id="engine-attempt-" + "2" * 32,
        run_id="run-19700101T001640Z-" + "3" * 16,
        role=AttemptRole.BASELINE,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        target_snapshot_ref=snapshot.target_snapshot_ref,
        scope_ref=mechanism.mechanism_ref,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        engine_id="strix",
        engine_version="1.7.0",
        engine_revision="4" * 40,
        engine_package_digest=_digest("5"),
        policy_overlay_digest=_digest("6"),
        model_provider="controlled-test-provider",
        model_id="controlled-file-read-v1",
        model_data_destination="attempt-local-loopback-test-provider",
        model_authorization_ref=_digest("7"),
        wall_clock_seconds=780,
        action_limit=8,
        cost_limit_microunits=50_000,
        artifact_byte_limit=MAX_BYTES,
        created_at="1970-01-01T00:16:40Z",
        parent_attempt_id=None,
    )


def _policy() -> tuple[EngineFileReadTargetPolicy, EngineAttemptBinding, VerifiedFileAccessBinding]:
    mechanism, snapshot, current = _current()
    attempt = _attempt(mechanism, snapshot)
    policy = EngineFileReadTargetPolicy.from_controller(
        attempt=attempt,
        mechanism=mechanism,
        historical_snapshot=snapshot,
        snapshot=snapshot,
        historical_binding=current,
        current_binding=current,
        now_ms=NOW_MS,
        request_budget=4,
        deadline_ms=NOW_MS + 30_000,
    )
    return policy, attempt, current


def _adaptive_policy() -> tuple[
    EngineFileReadTargetPolicy,
    EngineAttemptBinding,
    VerifiedFileAccessBinding,
    VerifiedFileAccessBinding,
]:
    mechanism, historical, historical_binding = _current()
    _, hardened, current_binding = _current(hardened=True)
    attempt = replace(
        _attempt(mechanism, hardened),
        role=AttemptRole.ADAPTIVE_SEARCH,
        parent_attempt_id="engine-attempt-" + "9" * 32,
    )
    policy = EngineFileReadTargetPolicy.from_controller(
        attempt=attempt,
        mechanism=mechanism,
        historical_snapshot=historical,
        snapshot=hardened,
        historical_binding=historical_binding,
        current_binding=current_binding,
        now_ms=NOW_MS,
        request_budget=4,
        deadline_ms=NOW_MS + 30_000,
    )
    return policy, attempt, historical_binding, current_binding


def test_policy_binds_one_fixed_read_and_round_trips_without_authority() -> None:
    policy, attempt, current = _policy()

    assert policy.read_action_id == PROBE_ACTION
    assert policy.max_read_bytes == MAX_BYTES
    assert policy.request_budget == 4
    assert policy.snapshot.target_snapshot_ref == attempt.target_snapshot_ref
    assert policy.historical_snapshot.to_dict() == policy.snapshot.to_dict()
    assert policy.mechanism.mechanism_ref == attempt.scope_ref
    assert policy.target_policy_version == TARGET_POLICY_VERSION
    assert attempt.scope_version == ENGINE_CAPABILITY_SCOPE_VERSION
    assert EngineFileReadTargetPolicy.from_mapping(policy.to_dict()).to_dict() == policy.to_dict()
    policy.require_current(
        expected_policy_digest=policy.policy_digest,
        attempt=attempt,
        current_mechanism=policy.mechanism,
        current_historical_snapshot=policy.historical_snapshot,
        current_snapshot=policy.snapshot,
        historical_binding=current,
        current_binding=current,
        now_ms=NOW_MS + 1,
    )
    assert not hasattr(policy, "execute")
    assert not hasattr(policy, "dispatch")


def test_policy_accepts_attempt_reserved_by_canonical_engine_experiment() -> None:
    mechanism, snapshot, current = _current()
    attempt = _attempt(mechanism, snapshot)
    experiment = EngineExperiment.create(
        experiment_id=attempt.experiment_id,
        objective_ref=attempt.objective_ref,
        environment_ref=attempt.environment_ref,
        scope_ref=mechanism.mechanism_ref,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=snapshot.target_snapshot_ref,
        created_at=attempt.created_at,
    )
    reserved = experiment.reserve_attempt(
        attempt,
        job_id="job-" + "a" * 32,
        delegation_digest=_digest("a"),
        execution_approval_digest=_digest("b"),
        execution_approval_id="approval-" + "a" * 32,
        timestamp=attempt.created_at,
    )
    reserved_attempt = reserved.attempts[0].record.binding

    policy = EngineFileReadTargetPolicy.from_controller(
        attempt=reserved_attempt,
        mechanism=mechanism,
        historical_snapshot=snapshot,
        snapshot=snapshot,
        historical_binding=current,
        current_binding=current,
        now_ms=NOW_MS,
        request_budget=4,
        deadline_ms=NOW_MS + 30_000,
    )

    assert reserved.scope_version == ENGINE_CAPABILITY_SCOPE_VERSION
    assert reserved_attempt.scope_version == ENGINE_CAPABILITY_SCOPE_VERSION
    assert policy.target_policy_version == TARGET_POLICY_VERSION
    assert EngineFileReadTargetPolicy.from_mapping(policy.to_dict()).policy_digest == (
        policy.policy_digest
    )
    policy.require_current(
        expected_policy_digest=policy.policy_digest,
        attempt=reserved_attempt,
        current_mechanism=mechanism,
        current_historical_snapshot=snapshot,
        current_snapshot=snapshot,
        historical_binding=current,
        current_binding=current,
        now_ms=NOW_MS + 1,
    )


@pytest.mark.parametrize(
    "substituted_version",
    [ENGINE_CAPABILITY_SCOPE_VERSION, "file-access.uid1002-write.v1", "tenant-record-service.v1"],
)
def test_target_policy_rejects_version_substitution(substituted_version: str) -> None:
    policy, attempt, current = _policy()
    substituted = policy.to_dict()
    substituted["target_policy_version"] = substituted_version

    assert content_hash(substituted) != policy.policy_digest
    with pytest.raises(EngineFileReadTargetError, match="policy version"):
        EngineFileReadTargetPolicy.from_mapping(substituted)
    with pytest.raises(EngineFileReadTargetError, match="protected policy"):
        policy.require_current(
            expected_policy_digest=content_hash(substituted),
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=current,
            current_binding=current,
            now_ms=NOW_MS,
        )


def test_target_policy_rejects_legacy_serialization_without_policy_version() -> None:
    policy, _, _ = _policy()
    legacy = policy.to_dict()
    legacy["schema_version"] = "bluefire.engine-file-read-target.v1"
    legacy.pop("target_policy_version")

    with pytest.raises(EngineFileReadTargetError, match="fields"):
        EngineFileReadTargetPolicy.from_mapping(legacy)

    substituted = policy.to_dict()
    substituted["scope_version"] = TARGET_POLICY_VERSION
    with pytest.raises(EngineFileReadTargetError, match="fields"):
        EngineFileReadTargetPolicy.from_mapping(substituted)


def test_adaptive_policy_requires_exact_original_and_hardened_pair() -> None:
    policy, attempt, historical_binding, current_binding = _adaptive_policy()

    assert policy.historical_snapshot.to_dict()["mode"] == "0640"
    assert policy.snapshot.to_dict()["mode"] == "0600"
    assert policy.historical_snapshot.target_snapshot_ref != policy.snapshot.target_snapshot_ref
    policy.require_current(
        expected_policy_digest=policy.policy_digest,
        attempt=attempt,
        current_mechanism=policy.mechanism,
        current_historical_snapshot=policy.historical_snapshot,
        current_snapshot=policy.snapshot,
        historical_binding=historical_binding,
        current_binding=current_binding,
        now_ms=NOW_MS + 1,
    )


def test_adaptive_policy_rejects_missing_or_unpaired_history() -> None:
    policy, _, _, _ = _adaptive_policy()
    missing = policy.to_dict()
    missing.pop("historical_snapshot")
    with pytest.raises(EngineFileReadTargetError, match="fields"):
        EngineFileReadTargetPolicy.from_mapping(missing)

    unpaired = policy.to_dict()
    unpaired["snapshot"]["control_owner_id"] = "job-" + "f" * 32
    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_mapping(unpaired)

    wrong_preimage = policy.to_dict()
    wrong_preimage["snapshot"]["prior_control_digest"] = _digest("f")
    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_mapping(wrong_preimage)


def test_baseline_current_snapshot_must_equal_historical_read() -> None:
    policy, _, _ = _policy()
    changed = policy.to_dict()
    changed["historical_snapshot"]["control_digest"] = _digest("f")

    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_mapping(changed)


def test_adaptive_policy_rejects_substituted_historical_snapshot_on_reopen() -> None:
    policy, attempt, historical_binding, current_binding = _adaptive_policy()
    substituted = policy.historical_snapshot.to_dict()
    substituted["binding_digest"] = _digest("f")
    changed = replace(
        policy, historical_snapshot=FileAccessTargetSnapshot.from_mapping(substituted)
    )

    with pytest.raises(EngineFileReadTargetError, match="changed"):
        changed.require_current(
            expected_policy_digest=changed.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=historical_binding,
            current_binding=current_binding,
            now_ms=NOW_MS + 1,
        )


def test_adaptive_policy_rejects_hardened_binding_as_historical() -> None:
    policy, attempt, _, current_binding = _adaptive_policy()

    with pytest.raises(EngineFileReadTargetError):
        policy.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=current_binding,
            current_binding=current_binding,
            now_ms=NOW_MS + 1,
        )


def test_coherent_forged_baseline_digest_fails_independent_reopen() -> None:
    policy, attempt, historical_binding, current_binding = _adaptive_policy()
    forged_mechanism = policy.mechanism.to_dict()
    forged_mechanism["original_read_evidence_digest"] = _digest("f")
    mechanism = FileAccessReadMechanism.from_mapping(forged_mechanism)
    forged_historical = policy.historical_snapshot.to_dict()
    forged_historical["mechanism_ref"] = mechanism.mechanism_ref
    forged_historical["baseline_evidence_digest"] = _digest("f")
    forged_historical["source"]["evidence_digest"] = _digest("f")
    historical = FileAccessTargetSnapshot.from_mapping(forged_historical)
    forged_current = policy.snapshot.to_dict()
    forged_current["mechanism_ref"] = mechanism.mechanism_ref
    forged_current["baseline_evidence_digest"] = _digest("f")
    current = FileAccessTargetSnapshot.from_mapping(forged_current)
    forged_attempt = replace(
        attempt,
        scope_ref=mechanism.mechanism_ref,
        target_snapshot_ref=current.target_snapshot_ref,
    )
    forged = EngineFileReadTargetPolicy.from_mapping(
        {
            **policy.to_dict(),
            "attempt_binding_digest": forged_attempt.binding_digest,
            "mechanism": mechanism.to_dict(),
            "historical_snapshot": historical.to_dict(),
            "snapshot": current.to_dict(),
        }
    )

    with pytest.raises(EngineFileReadTargetError):
        forged.require_current(
            expected_policy_digest=forged.policy_digest,
            attempt=forged_attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=historical_binding,
            current_binding=current_binding,
            now_ms=NOW_MS + 1,
        )


@pytest.mark.parametrize(("field", "increase"), [("request_budget", 1), ("deadline_ms", 60_000)])
def test_protected_policy_digest_rejects_serialized_budget_or_deadline_widening(
    field: str, increase: int
) -> None:
    policy, attempt, historical_binding = _policy()
    widened = policy.to_dict()
    widened[field] += increase
    parsed = EngineFileReadTargetPolicy.from_mapping(widened)

    with pytest.raises(EngineFileReadTargetError, match="protected policy"):
        parsed.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=historical_binding,
            current_binding=historical_binding,
            now_ms=NOW_MS + 1,
        )


@pytest.mark.parametrize(
    "field",
    [
        "path",
        "command",
        "credential",
        "mount",
        "chmod",
        "host_execution",
        "shell",
        "script",
        "executable",
        "model_parameters",
    ],
)
def test_policy_rejects_arbitrary_execution_fields(field: str) -> None:
    policy, _, _ = _policy()
    value = policy.to_dict()
    value[field] = "untrusted"

    with pytest.raises(EngineFileReadTargetError, match="fields"):
        EngineFileReadTargetPolicy.from_mapping(value)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("mechanism", "resource_path", "/etc/shadow"),
        ("mechanism", "probe_action_id", "generic.host.exec"),
        ("mechanism", "probe_uid", 1000),
        ("snapshot", "resource_path", "/etc/shadow"),
        ("snapshot", "mode", "0777"),
    ],
)
def test_policy_rejects_substituted_read_identity(section: str, field: str, value: object) -> None:
    policy, _, _ = _policy()
    changed = deepcopy(policy.to_dict())
    changed[section][field] = value

    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_mapping(changed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_budget", 0),
        ("request_budget", 65),
        ("request_budget", True),
        ("max_read_bytes", MAX_BYTES + 1),
        ("per_request_ms", 5_001),
        ("deadline_ms", NOW_MS),
        ("deadline_ms", NOW_MS + 900_001),
    ],
)
def test_policy_rejects_widened_or_nonfinite_limits(field: str, value: object) -> None:
    policy, _, _ = _policy()
    changed = policy.to_dict()
    changed[field] = value
    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_mapping(changed)


def test_controller_comparison_rejects_budget_deadline_and_scope_widening() -> None:
    policy, attempt, current = _policy()
    with pytest.raises(EngineFileReadTargetError):
        replace(policy, request_budget=9).require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=current,
            current_binding=current,
            now_ms=NOW_MS,
        )
    for changed_attempt in (
        replace(attempt, target_snapshot_ref=_digest("f")),
        replace(attempt, scope_ref=_digest("f")),
        replace(attempt, scope_version=TARGET_POLICY_VERSION),
        replace(attempt, scope_version="tenant-record-service.v1"),
    ):
        with pytest.raises(EngineFileReadTargetError):
            policy.require_current(
                expected_policy_digest=policy.policy_digest,
                attempt=changed_attempt,
                current_mechanism=policy.mechanism,
                current_historical_snapshot=policy.historical_snapshot,
                current_snapshot=policy.snapshot,
                historical_binding=current,
                current_binding=current,
                now_ms=NOW_MS,
            )
    with pytest.raises(EngineFileReadTargetError):
        policy.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=current,
            current_binding=current,
            now_ms=policy.deadline_ms,
        )


@pytest.mark.parametrize(
    ("wall_clock_seconds", "deadline_ms"),
    [
        (780, NOW_MS + 780_001),
        (900, 1_800_001),
    ],
)
def test_controller_rejects_deadline_after_attempt_or_enrollment(
    wall_clock_seconds: int, deadline_ms: int
) -> None:
    policy, attempt, current = _policy()
    changed_attempt = replace(attempt, wall_clock_seconds=wall_clock_seconds)

    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_controller(
            attempt=changed_attempt,
            mechanism=policy.mechanism,
            historical_snapshot=policy.historical_snapshot,
            snapshot=policy.snapshot,
            historical_binding=current,
            current_binding=current,
            now_ms=NOW_MS,
            request_budget=4,
            deadline_ms=deadline_ms,
        )


def test_baseline_role_cannot_target_hardened_snapshot() -> None:
    mechanism, snapshot, current = _current(hardened=True)
    _, historical, historical_binding = _current()
    attempt = _attempt(mechanism, snapshot)

    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_controller(
            attempt=attempt,
            mechanism=mechanism,
            historical_snapshot=historical,
            snapshot=snapshot,
            historical_binding=historical_binding,
            current_binding=current,
            now_ms=NOW_MS,
            request_budget=4,
            deadline_ms=NOW_MS + 30_000,
        )


def test_adaptive_role_cannot_reuse_historical_baseline_snapshot() -> None:
    policy, attempt, current = _policy()
    adaptive_attempt = replace(
        attempt,
        role=AttemptRole.ADAPTIVE_SEARCH,
        parent_attempt_id="engine-attempt-" + "9" * 32,
    )

    with pytest.raises(EngineFileReadTargetError):
        EngineFileReadTargetPolicy.from_controller(
            attempt=adaptive_attempt,
            mechanism=policy.mechanism,
            historical_snapshot=policy.historical_snapshot,
            snapshot=policy.snapshot,
            historical_binding=current,
            current_binding=current,
            now_ms=NOW_MS,
            request_budget=4,
            deadline_ms=NOW_MS + 30_000,
        )


def test_reopened_hardened_snapshot_cannot_satisfy_historical_policy() -> None:
    policy, attempt, historical_binding = _policy()
    hardened_mechanism, hardened_snapshot, hardened_binding = _current(hardened=True)

    with pytest.raises(EngineFileReadTargetError, match="changed"):
        policy.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=hardened_mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=hardened_snapshot,
            historical_binding=historical_binding,
            current_binding=hardened_binding,
            now_ms=NOW_MS + 1,
        )


def test_policy_rejects_historical_binding_after_current_resource_changes() -> None:
    policy, attempt, historical_binding = _policy()
    _, _, hardened_binding = _current(hardened=True)

    with pytest.raises(EngineFileReadTargetError):
        policy.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=historical_binding,
            current_binding=hardened_binding,
            now_ms=NOW_MS + 1,
        )


def test_policy_rejects_changed_enrolled_probe_identity() -> None:
    policy, attempt, historical_binding = _policy()
    changed = binding()
    changed["worker"]["pid"] += 1
    rebound = verify_file_access_binding(
        changed, expected_document_digest=content_hash(changed), now_ms=NOW_MS
    )

    with pytest.raises(EngineFileReadTargetError):
        policy.require_current(
            expected_policy_digest=policy.policy_digest,
            attempt=attempt,
            current_mechanism=policy.mechanism,
            current_historical_snapshot=policy.historical_snapshot,
            current_snapshot=policy.snapshot,
            historical_binding=historical_binding,
            current_binding=rebound,
            now_ms=NOW_MS + 1,
        )
