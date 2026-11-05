"""Durable file-read reservations; these tests never execute a native read."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire import product_store_capability_grants as capability_records
from bluefire import product_store_file_access_records as file_access_records
from bluefire.capability_dependency import endpoint_digest, usage_document
from bluefire.capability_packs import RECEIVER_PACK
from bluefire.engine_attempt_contract import (
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
)
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    CleanupState,
    EngineExperiment,
)
from bluefire.engine_file_access_snapshot import (
    HISTORICAL_BASELINE,
    FileAccessReadMechanism,
    FileAccessTargetSnapshot,
)
from bluefire.engine_file_access_target import EngineFileReadTargetPolicy
from bluefire.file_access_contract import MAX_BYTES, PROBE_ACTION, verify_file_access_binding
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform.file_access_fixtures import binding


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _timestamp(now_ms: int) -> str:
    return (
        datetime.fromtimestamp(now_ms / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _validate_experiment(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return EngineExperiment._from_controller_mapping(document).to_dict()


def _insert_file_access_operation(
    store: ProductStore,
    *,
    job_id: str,
    owner_id: str,
    enrollment_id: str,
    operation: str,
    outcome: Mapping[str, Any] | None,
    control: Mapping[str, Any] | None = None,
) -> None:
    """Persist relationally valid control history without dispatching an effect."""

    document = {"control_owner_id": owner_id, "operation": operation}
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                "file_access.operation",
                "completed" if outcome is not None else "running",
                "{}",
                "{}",
                None,
                None,
                "1970-01-01T00:16:40Z",
                "1970-01-01T00:16:40Z",
            ),
        )
        connection.execute(
            "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
            (
                job_id,
                owner_id,
                enrollment_id,
                operation,
                canonical_json(document),
                content_hash(document),
            ),
        )
        if outcome is not None:
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) "
                "VALUES(?,?,?)",
                (job_id, canonical_json(outcome), content_hash(outcome)),
            )
        if control is not None:
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                (
                    owner_id,
                    control["revision"],
                    job_id,
                    canonical_json(control),
                    content_hash(control),
                ),
            )


def _insert_unsettled_control_usage(store: ProductStore, owner_id: str) -> None:
    """Add an internally consistent capability lease with no settlement."""

    lineage_id = "lineage-engine-file-access-claim"
    grant_id = "grant-engine-file-access-claim"
    attempt_id = "attempt-engine-file-access-claim"
    environment = {
        "control_owner_id": owner_id,
        "control_digest": _digest("a"),
        "environment_id": "environment-engine-file-access-claim",
        "runner_id": "runner-test",
        "target_scope_digest": _digest("b"),
        "policy_digest": _digest("c"),
        "port": 1234,
    }
    objective = {"predicate": "test"}
    limits: dict[str, Any] = {}
    lineage_binding = {
        "control_owner_id": owner_id,
        "environment_id": environment["environment_id"],
        "runner_id": environment["runner_id"],
        "target_scope_digest": environment["target_scope_digest"],
        "predicate": objective["predicate"],
    }
    lineage = {"binding": lineage_binding, "limits": limits}
    grant_body = {
        "schema_version": "bluefire.capability-grant.v1",
        "grant_id": grant_id,
        "environment": environment,
        "objective": objective,
        "limits": limits,
        "snapshot": {"pack": RECEIVER_PACK},
        "created_at_ms": 1,
        "expires_at_ms": 2**62,
    }
    grant = {**grant_body, "grant_digest": content_hash(grant_body)}
    compiled_body = {"handoff": {"mode": "test"}}
    compiled = {**compiled_body, "compiled_digest": content_hash(compiled_body)}
    lease_body = {
        "attempt_id": attempt_id,
        "grant_id": grant_id,
        "grant_digest": grant["grant_digest"],
        "lineage_id": lineage_id,
        "control_owner_id": owner_id,
        "endpoint_digest": endpoint_digest(environment),
        "job_id": "job-" + "e" * 32,
        "run_id": "run-engine-file-access-claim",
        "compiled_digest": compiled["compiled_digest"],
    }
    lease = {**lease_body, "lease_digest": content_hash(lease_body)}
    usage = usage_document(grant, compiled, lease)
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO capability_lineages VALUES(?,?,?,?)",
            (
                lineage_id,
                content_hash(lineage_binding),
                canonical_json(lineage),
                content_hash(lineage),
            ),
        )
        connection.execute(
            "INSERT INTO capability_grants VALUES(?,?,?,?,?,?,?)",
            (
                grant_id,
                lineage_id,
                owner_id,
                canonical_json(grant),
                content_hash(grant),
                grant["created_at_ms"],
                grant["expires_at_ms"],
            ),
        )
        connection.execute(
            "INSERT INTO capability_grant_events(grant_id,status,at_ms) VALUES(?,?,?)",
            (grant_id, "active", 1),
        )
        connection.execute(
            "INSERT INTO capability_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attempt_id,
                grant_id,
                lineage_id,
                owner_id,
                lease["endpoint_digest"],
                lease["job_id"],
                lease["run_id"],
                canonical_json(lease),
                content_hash(lease),
                canonical_json(compiled),
                content_hash(compiled),
                1,
            ),
        )
        connection.execute(
            "INSERT INTO capability_control_usages VALUES(?,?,?,?)",
            (attempt_id, owner_id, canonical_json(usage), content_hash(usage)),
        )


def _saved_policy(
    store: ProductStore,
    *,
    marker: str = "1",
    now_ms: int | None = None,
    request_budget: int = 2,
) -> tuple[EngineExperiment, EngineAttemptBinding, EngineFileReadTargetPolicy]:
    """Save a real v2 experiment with one baseline attempt and bound policy."""

    instant = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    created_at = _timestamp(instant)
    document = binding()
    document["expires_at_ms"] = instant + 600_000
    control_owner_id = "job-" + "a" * 31 + marker
    baseline = {
        "baseline_digest": _digest("a"),
        "non_owner": "allowed",
        "owner": "allowed",
        "record_count": document["resource"]["record_count"],
        "sha256": document["resource"]["sha256"],
        "source_binding": {
            "operation_job_id": control_owner_id,
            "evidence_digest": _digest("a"),
        },
    }
    verified = verify_file_access_binding(
        document, expected_document_digest=content_hash(document), now_ms=instant
    )
    control = {
        "schema_version": "bluefire.retained-file-control.v1",
        "control_owner_id": control_owner_id,
        "enrollment_id": document["enrollment_id"],
        "revision": document["control_revision"],
        "status": "baseline_verified",
        "binding": document,
        "binding_digest": content_hash(document),
        "source": {"retained": "owned"},
        "baseline": baseline,
    }
    _insert_file_access_operation(
        store,
        job_id=control_owner_id,
        owner_id=control_owner_id,
        enrollment_id=document["enrollment_id"],
        operation="baseline",
        outcome={"state": "complete", "control_digest": content_hash(control)},
        control=control,
    )
    mechanism = FileAccessReadMechanism.from_verified_binding(verified, baseline=baseline)
    snapshot = FileAccessTargetSnapshot.from_verified_binding(
        verified,
        mechanism=mechanism,
        control_owner_id=control_owner_id,
        control_digest=content_hash(control),
        prior_control_digest=None,
        source_operation_job_id=control_owner_id,
        source_evidence_digest=_digest("a"),
        phase=HISTORICAL_BASELINE,
    )
    experiment_id = "experiment-" + marker * 32
    attempt_id = "engine-attempt-" + marker * 32
    run_time = datetime.fromtimestamp(instant / 1000, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    attempt = EngineAttemptBinding(
        schema_version="bluefire.engine-attempt-binding.v1",
        experiment_id=experiment_id,
        attempt_id=attempt_id,
        run_id=f"run-{run_time}-{marker * 16}",
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
        created_at=created_at,
        parent_attempt_id=None,
    )
    experiment = EngineExperiment.create(
        experiment_id=experiment_id,
        objective_ref=attempt.objective_ref,
        environment_ref=attempt.environment_ref,
        scope_ref=attempt.scope_ref,
        scope_version=attempt.scope_version,
        target_snapshot_ref=attempt.target_snapshot_ref,
        created_at=created_at,
    )
    initial = store.create_engine_experiment(
        experiment_id, experiment.to_dict(), validator=_validate_experiment
    )
    reserved = experiment.reserve_attempt(
        attempt,
        job_id="job-" + marker * 32,
        delegation_digest=_digest("8"),
        execution_approval_digest=_digest("9"),
        execution_approval_id="approval-" + marker * 32,
        timestamp=created_at,
    )
    store.save_engine_experiment(
        experiment_id,
        reserved.to_dict(),
        expected_revision=1,
        expected_digest=str(initial["digest"]),
        validator=_validate_experiment,
    )
    policy = EngineFileReadTargetPolicy.from_controller(
        attempt=reserved.attempts[0].record.binding,
        mechanism=mechanism,
        historical_snapshot=snapshot,
        snapshot=snapshot,
        historical_binding=verified,
        current_binding=verified,
        now_ms=instant,
        request_budget=request_budget,
        deadline_ms=instant + 300_000,
    )
    return reserved, attempt, policy


def _claim(store: ProductStore, attempt_id: str, ordinal: int, marker: str) -> Mapping[str, Any]:
    request_hash = _digest(marker)
    return store.claim_engine_file_access_request(
        attempt_id,
        ordinal=ordinal,
        task_id="execute-" + request_hash[7:],
        request_hash=request_hash,
        transport_request_hash=content_hash({"transport": marker}),
    )


def _sql_claim(path: Path, reservation: Mapping[str, Any], ordinal: int, marker: str) -> None:
    """Attempt a well formed direct insert without the store's transaction gate."""

    request_hash = _digest(marker)
    transport_request_hash = content_hash({"transport": marker})
    task_id = "execute-" + request_hash[7:]
    identity = {
        "schema_version": "bluefire.engine-file-access-request-claim.v1",
        "reservation_ref": reservation["reservation_ref"],
        "ordinal": ordinal,
        "task_id": task_id,
        "request_hash": request_hash,
        "transport_request_hash": transport_request_hash,
    }
    document = {
        **identity,
        "claim_ref": content_hash(identity),
        "policy_digest": reservation["policy_digest"],
        "attempt_id": reservation["attempt_id"],
        "claimed_at_ms": reservation["created_at_ms"],
    }
    with sqlite3.connect(path) as connection:
        connection.execute(
            """INSERT INTO engine_file_access_request_claims (
                attempt_id, ordinal, claim_ref, reservation_ref, policy_digest,
                task_id, request_hash, transport_request_hash, claimed_at_ms,
                document_json, record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                document["attempt_id"],
                ordinal,
                document["claim_ref"],
                document["reservation_ref"],
                document["policy_digest"],
                task_id,
                request_hash,
                transport_request_hash,
                document["claimed_at_ms"],
                canonical_json(document),
                content_hash(document),
            ),
        )


def _sql_reservation(
    path: Path, experiment: EngineExperiment, policy: EngineFileReadTargetPolicy
) -> None:
    """Insert canonical bytes directly, bypassing the store's policy check."""

    entry = experiment.attempts[0]
    attempt = entry.record.binding
    identity = {
        "schema_version": "bluefire.engine-file-access-target-reservation.v1",
        "experiment_id": experiment.experiment_id,
        "attempt_id": attempt.attempt_id,
        "policy_digest": policy.policy_digest,
    }
    document = {
        **identity,
        "reservation_ref": content_hash(identity),
        "job_id": entry.job_id,
        "run_id": attempt.run_id,
        "role": attempt.role.value,
        "action_id": PROBE_ACTION,
        "binding_digest": attempt.binding_digest,
        "mechanism_ref": policy.mechanism.mechanism_ref,
        "historical_snapshot_ref": policy.historical_snapshot.target_snapshot_ref,
        "target_snapshot_ref": policy.snapshot.target_snapshot_ref,
        "target_policy_version": policy.target_policy_version,
        "request_budget": policy.request_budget,
        "issued_at_ms": policy.issued_at_ms,
        "deadline_ms": policy.deadline_ms,
        "policy": policy.to_dict(),
        "created_at_ms": time.time_ns() // 1_000_000,
    }
    with sqlite3.connect(path) as connection:
        connection.execute(
            """INSERT INTO engine_file_access_target_reservations (
                attempt_id, experiment_id, job_id, run_id, role, action_id,
                binding_digest, mechanism_ref, historical_snapshot_ref,
                target_snapshot_ref, target_policy_version, policy_digest,
                reservation_ref, request_budget, issued_at_ms, deadline_ms,
                document_json, record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                document["attempt_id"],
                document["experiment_id"],
                document["job_id"],
                document["run_id"],
                document["role"],
                document["action_id"],
                document["binding_digest"],
                document["mechanism_ref"],
                document["historical_snapshot_ref"],
                document["target_snapshot_ref"],
                document["target_policy_version"],
                document["policy_digest"],
                document["reservation_ref"],
                document["request_budget"],
                document["issued_at_ms"],
                document["deadline_ms"],
                canonical_json(document),
                content_hash(document),
            ),
        )


def test_reservation_survives_reopen_and_exact_retries(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store)

    first = store.reserve_engine_file_access_target(
        experiment.experiment_id, attempt.attempt_id, policy
    )
    assert first["binding_digest"] == attempt.binding_digest
    assert first["policy_digest"] == policy.policy_digest
    assert first["policy"] == policy.to_dict()
    assert first["request_budget"] == policy.request_budget
    assert (
        store.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, policy
        )
        == first
    )
    assert store.get_engine_file_access_target_reservation(attempt.attempt_id) == first

    reopened = ProductStore(path)
    assert reopened.get_engine_file_access_target_reservation(attempt.attempt_id) == first
    assert (
        reopened.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, policy
        )
        == first
    )


def test_reservation_rejects_other_attempt_substitution_and_expiry(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    first_experiment, first_attempt, policy = _saved_policy(store)
    other_experiment, other_attempt, _ = _saved_policy(store, marker="2")

    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            other_experiment.experiment_id, other_attempt.attempt_id, policy
        )
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            first_experiment.experiment_id, other_attempt.attempt_id, policy
        )

    store.reserve_engine_file_access_target(
        first_experiment.experiment_id, first_attempt.attempt_id, policy
    )
    substituted = replace(policy, request_budget=1)
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            first_experiment.experiment_id, first_attempt.attempt_id, substituted
        )

    stale_experiment, stale_attempt, stale_policy = _saved_policy(
        store, marker="3", now_ms=time.time_ns() // 1_000_000 - 360_000
    )
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            stale_experiment.experiment_id, stale_attempt.attempt_id, stale_policy
        )


def test_reservation_requires_saved_experiment_and_attempt(tmp_path: Path) -> None:
    source = ProductStore(tmp_path / "source.db")
    _, attempt, policy = _saved_policy(source)
    destination = ProductStore(tmp_path / "destination.db")
    with pytest.raises(ProductStoreError):
        destination.reserve_engine_file_access_target(
            attempt.experiment_id, attempt.attempt_id, policy
        )

    caller_only = EngineExperiment.create(
        experiment_id=attempt.experiment_id,
        objective_ref=attempt.objective_ref,
        environment_ref=attempt.environment_ref,
        scope_ref=attempt.scope_ref,
        scope_version=attempt.scope_version,
        target_snapshot_ref=attempt.target_snapshot_ref,
        created_at=attempt.created_at,
    )
    destination.create_engine_experiment(
        caller_only.experiment_id,
        caller_only.to_dict(),
        validator=_validate_experiment,
    )
    with pytest.raises(ProductStoreError):
        destination.reserve_engine_file_access_target(
            attempt.experiment_id, attempt.attempt_id, policy
        )


def test_reservation_rejects_canonical_snapshot_and_mechanism_substitution(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    changed_snapshot = FileAccessTargetSnapshot.from_mapping(
        {**policy.snapshot.to_dict(), "control_digest": _digest("d")}
    )
    substituted_snapshot = EngineFileReadTargetPolicy.from_mapping(
        {
            **policy.to_dict(),
            "historical_snapshot": changed_snapshot.to_dict(),
            "snapshot": changed_snapshot.to_dict(),
        }
    )
    assert substituted_snapshot.policy_digest != policy.policy_digest
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, substituted_snapshot
        )

    changed_mechanism = FileAccessReadMechanism.from_mapping(
        {**policy.mechanism.to_dict(), "worker_identity_digest": _digest("d")}
    )
    changed_snapshot = FileAccessTargetSnapshot.from_mapping(
        {
            **policy.snapshot.to_dict(),
            "mechanism_ref": changed_mechanism.mechanism_ref,
        }
    )
    substituted_mechanism = EngineFileReadTargetPolicy.from_mapping(
        {
            **policy.to_dict(),
            "mechanism": changed_mechanism.to_dict(),
            "historical_snapshot": changed_snapshot.to_dict(),
            "snapshot": changed_snapshot.to_dict(),
        }
    )
    assert substituted_mechanism.policy_digest != policy.policy_digest
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, substituted_mechanism
        )


def test_claims_are_ordered_bounded_and_no_replay_across_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store, request_budget=2)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)

    with pytest.raises(ProductStoreError):
        _claim(store, attempt.attempt_id, 2, "b")
    first = _claim(store, attempt.attempt_id, 1, "a")
    assert first["policy_digest"] == policy.policy_digest
    assert first["request_hash"] == _digest("a")
    assert first["task_id"] == "execute-" + "a" * 64
    with pytest.raises(ProductStoreError):
        _claim(store, attempt.attempt_id, 1, "a")
    reopened = ProductStore(path)
    assert reopened.list_engine_file_access_request_claims(attempt.attempt_id) == [first]
    with pytest.raises(ProductStoreError):
        _claim(reopened, attempt.attempt_id, 1, "a")
    with pytest.raises(ProductStoreError):
        _claim(reopened, attempt.attempt_id, 1, "c")
    with pytest.raises(ProductStoreError):
        _claim(reopened, attempt.attempt_id, 2, "a")
    second = _claim(reopened, attempt.attempt_id, 2, "b")
    assert reopened.list_engine_file_access_request_claims(attempt.attempt_id) == [first, second]
    with pytest.raises(ProductStoreError):
        _claim(reopened, attempt.attempt_id, 3, "c")


def test_claim_rejects_expired_policy_and_wrong_task_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    with pytest.raises(ProductStoreError):
        store.claim_engine_file_access_request(
            attempt.attempt_id,
            ordinal=1,
            task_id="execute-" + "f" * 64,
            request_hash=_digest("a"),
            transport_request_hash=_digest("b"),
        )
    monkeypatch.setattr(time, "time_ns", lambda: policy.deadline_ms * 1_000_000)
    with pytest.raises(ProductStoreError):
        _claim(store, attempt.attempt_id, 1, "a")
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


def test_claim_api_has_no_command_path_or_uid_override(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    claim = store.claim_engine_file_access_request
    for field, value in (("command", "id"), ("path", "/tmp/other"), ("uid", 0)):
        with pytest.raises(TypeError):
            claim(
                attempt.attempt_id,
                ordinal=1,
                task_id="execute-" + "a" * 64,
                request_hash=_digest("a"),
                transport_request_hash=_digest("b"),
                **{field: value},
            )
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


def test_claim_rejects_attempt_settled_after_reservation(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    settled_at = _timestamp(time.time_ns() // 1_000_000)
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED, timestamp=settled_at
    )
    settled = experiment.settle_attempt(
        terminal,
        engine_evidence=(),
        artifact_manifest_ref=None,
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("e"),
        settled_at=settled_at,
    )
    store.save_engine_experiment(
        experiment.experiment_id,
        settled.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validate_experiment,
    )
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, policy
        )
    with pytest.raises(ProductStoreError):
        _claim(store, attempt.attempt_id, 1, "a")


@pytest.mark.parametrize("change", ["pending_operation", "unsettled_usage", "new_control"])
def test_claim_rechecks_saved_control_and_effects_without_consuming_ordinal(
    tmp_path: Path, change: str
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    snapshot = policy.snapshot.to_dict()
    owner_id = snapshot["control_owner_id"]

    if change == "pending_operation":
        _insert_file_access_operation(
            store,
            job_id="job-" + "d" * 32,
            owner_id=owner_id,
            enrollment_id=snapshot["enrollment_id"],
            operation="harden",
            outcome=None,
        )
    elif change == "unsettled_usage":
        _insert_unsettled_control_usage(store, owner_id)
    else:
        with store._connection() as connection:
            row = connection.execute(
                "SELECT document_json FROM file_access_revisions WHERE control_owner_id=? "
                "ORDER BY revision DESC LIMIT 1",
                (owner_id,),
            ).fetchone()
            assert row is not None
            changed_control = json.loads(row["document_json"])
        changed_control["revision"] += 1
        changed_control["status"] = "hardened"
        changed_control["binding"]["control_revision"] += 1
        changed_control["binding"]["mode"] = "0600"
        changed_control["binding_digest"] = content_hash(changed_control["binding"])
        _insert_file_access_operation(
            store,
            job_id="job-" + "f" * 32,
            owner_id=owner_id,
            enrollment_id=snapshot["enrollment_id"],
            operation="harden",
            outcome={"state": "complete", "control_digest": content_hash(changed_control)},
            control=changed_control,
        )

    with store._connection() as connection:
        latest = file_access_records._control_at(connection, owner_id)
        observed = (
            latest["document_digest"] == snapshot["control_digest"],
            file_access_records._pending(connection, owner_id),
            capability_records.control_usages_settled(store, connection, owner_id),
        )
        expected = {
            "pending_operation": (True, True, True),
            "unsettled_usage": (True, False, False),
            "new_control": (False, False, True),
        }
        assert observed == expected[change]
        if change == "unsettled_usage":
            capability_records._attempt_at(connection, "attempt-engine-file-access-claim")

    with pytest.raises(ProductStoreError):
        _claim(ProductStore(store.path), attempt.attempt_id, 1, "a")
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


def test_active_lifecycle_update_preserves_exact_policy_without_widening(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment, attempt, policy = _saved_policy(store)
    reservation = store.reserve_engine_file_access_target(
        experiment.experiment_id, attempt.attempt_id, policy
    )
    preflight = experiment.attempts[0].record.transition(AttemptState.PREFLIGHT)
    updated = experiment.update_attempt_record(
        preflight, timestamp=_timestamp(time.time_ns() // 1_000_000)
    )
    store.save_engine_experiment(
        experiment.experiment_id,
        updated.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validate_experiment,
    )

    assert (
        store.reserve_engine_file_access_target(
            experiment.experiment_id, attempt.attempt_id, policy
        )
        == reservation
    )
    with pytest.raises(ProductStoreError):
        store.reserve_engine_file_access_target(
            experiment.experiment_id,
            attempt.attempt_id,
            replace(policy, request_budget=policy.request_budget + 1),
        )
    assert _claim(store, attempt.attempt_id, 1, "a")["ordinal"] == 1


def test_concurrent_first_claim_has_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    contenders = [ProductStore(path), ProductStore(path)]
    barrier = threading.Barrier(2)
    successes: list[Mapping[str, Any]] = []
    errors: list[Exception] = []

    def compete(contender: ProductStore, marker: str) -> None:
        barrier.wait()
        try:
            successes.append(_claim(contender, attempt.attempt_id, 1, marker))
        except Exception as exc:  # Both results must be accounted for.
            errors.append(exc)

    threads = [
        threading.Thread(target=compete, args=(contenders[0], "a")),
        threading.Thread(target=compete, args=(contenders[1], "b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert len(successes) == 1
    assert len(errors) == 1 and isinstance(errors[0], ProductStoreError)
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == successes


def test_sql_reservation_and_claim_rows_are_immutable(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store)
    store.reserve_engine_file_access_target(experiment.experiment_id, attempt.attempt_id, policy)
    _claim(store, attempt.attempt_id, 1, "a")

    with sqlite3.connect(path) as connection:
        for table in (
            "engine_file_access_target_reservations",
            "engine_file_access_request_claims",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"UPDATE {table} SET rowid = rowid WHERE rowid = 1")
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"DELETE FROM {table} WHERE rowid = 1")


def test_sql_claim_insert_cannot_skip_ordinal_or_exceed_budget(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store)
    reservation = store.reserve_engine_file_access_target(
        experiment.experiment_id, attempt.attempt_id, policy
    )
    with pytest.raises(sqlite3.IntegrityError, match="ordinal is not next"):
        _sql_claim(path, reservation, 2, "c")
    first = _claim(store, attempt.attempt_id, 1, "a")
    second = _claim(store, attempt.attempt_id, 2, "b")
    with pytest.raises(sqlite3.IntegrityError, match="exceeds reservation"):
        _sql_claim(path, reservation, 3, "d")
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == [
        first,
        second,
    ]


@pytest.mark.parametrize("widening", ["budget", "deadline"])
def test_claim_rechecks_saved_attempt_limits_after_direct_sql_reservation(
    tmp_path: Path, widening: str
) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, attempt, policy = _saved_policy(store)
    forged = (
        replace(policy, request_budget=attempt.action_limit + 1)
        if widening == "budget"
        else replace(
            policy,
            deadline_ms=policy.issued_at_ms + attempt.wall_clock_seconds * 1000 + 1,
        )
    )
    _sql_reservation(path, experiment, forged)
    assert (
        store.get_engine_file_access_target_reservation(attempt.attempt_id)["policy_digest"]
        == forged.policy_digest
    )
    with pytest.raises(ProductStoreError, match="differs from saved attempt"):
        _claim(store, attempt.attempt_id, 1, "a")
    assert store.list_engine_file_access_request_claims(attempt.attempt_id) == []


def test_sql_reservation_rejects_settled_saved_attempt(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store = ProductStore(path)
    experiment, _attempt, policy = _saved_policy(store)
    settled_at = _timestamp(time.time_ns() // 1_000_000)
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED, timestamp=settled_at
    )
    settled = experiment.settle_attempt(
        terminal,
        engine_evidence=(),
        artifact_manifest_ref=None,
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("e"),
        settled_at=settled_at,
    )
    store.save_engine_experiment(
        experiment.experiment_id,
        settled.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validate_experiment,
    )
    with pytest.raises(sqlite3.IntegrityError, match="attempt is not saved"):
        _sql_reservation(path, experiment, policy)


def test_schema_upgrade_reopen_and_forward_version_refusal(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, '2026-11-04T00:00:00Z')",
            (SCHEMA_VERSION - 1,),
        )
    store = ProductStore(path)
    assert store.schema_version == SCHEMA_VERSION
    experiment, attempt, policy = _saved_policy(store)
    saved = store.reserve_engine_file_access_target(
        experiment.experiment_id, attempt.attempt_id, policy
    )
    assert ProductStore(path).get_engine_file_access_target_reservation(attempt.attempt_id) == saved

    forward = tmp_path / "forward.db"
    with sqlite3.connect(forward) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, '2026-11-04T00:00:00Z')",
            (SCHEMA_VERSION + 1,),
        )
    with pytest.raises(ProductStoreError, match="newer"):
        ProductStore(forward)
