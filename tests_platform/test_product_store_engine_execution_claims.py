from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.engine_action_preparation import EngineWorkspaceAction
from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
)
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import CleanupState, EngineExperiment
from bluefire.engine_experiment_jobs import (
    EngineExperimentJobError,
    EngineExperimentJobs,
    installed_execution_claim_policy,
)
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform.test_engine_action_submission_store import REVIEWER, _accept, _attempt
from tests_platform.test_product_store_engine_actions import (
    EXPERIMENT_ID,
    WORKSPACE_REF,
    _attempt_authority,
    _iso,
    _limits,
    _store,
    _times,
)
from tests_platform.test_product_store_engine_jobs import _attempt_observation

RESOLUTION_REF = "sha256:" + "d" * 64


def _attempt_v2(
    tmp_path: Path,
) -> tuple[ProductStore, Mapping[str, Any], dict[str, Any]]:
    store = _store(tmp_path)
    prepared_at, expires_at, _now = _times()
    binding, delegation, approval_binding = _attempt_authority(prepared_at, expires_at)
    history = store.get_engine_experiment(EXPERIMENT_ID)

    def factory(approval: Mapping[str, Any] | None, submission_id: str | None):
        assert approval is not None and submission_id is not None
        experiment = EngineExperiment._from_controller_mapping(history["document"])
        request = EngineExperimentJobs._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval_binding,
            approval_id=str(approval["approval_id"]),
            execution_claim_policy=installed_execution_claim_policy(),
        )
        document = {
            "binding": binding.to_dict(),
            "delegation": delegation.to_dict(),
            "approval_binding": approval_binding.to_dict(),
        }
        return request, {
            "schema_version": "bluefire.engine-action-authority.v1",
            "kind": "engine_attempt",
            "document": document,
            "document_digest": content_hash(document),
        }

    protected = store.create_engine_action_preparation(
        experiment_id=EXPERIMENT_ID,
        experiment_revision=history["revision"],
        experiment_digest=history["digest"],
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.START_BASELINE,
        limits=_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=factory,
        approval_request=approval_binding.request_binding(),
    )
    public = store.prepared_engine_action(protected["request_ref"])
    values = {
        "experiment_id": EXPERIMENT_ID,
        "preparation_id": public["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    return store, protected, values


def _authority(
    protected: Mapping[str, Any],
) -> tuple[EngineAttemptBinding, EngineCapabilityDelegation]:
    document = protected["protected_request"]["authority"]["document"]
    return (
        EngineAttemptBinding.from_mapping(document["binding"]),
        EngineCapabilityDelegation.from_mapping(document["delegation"]),
    )


def _ready(
    tmp_path: Path,
) -> tuple[
    ProductStore,
    Mapping[str, Any],
    Mapping[str, Any],
    EngineAttemptBinding,
    EngineCapabilityDelegation,
    str,
    str,
]:
    store, protected, values = _attempt_v2(tmp_path)
    job, created = _accept(store, values)
    assert created is True
    binding, delegation = _authority(protected)
    store.transition_job(job["job_id"], "planning")
    store.transition_job(job["job_id"], "running")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    preflight_at = _iso(datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1))
    preflight = experiment.attempts[0].record.transition(AttemptState.PREFLIGHT)
    store.compare_and_swap_engine_attempt_record(
        experiment_id=EXPERIMENT_ID,
        record=preflight.to_dict(),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
        timestamp=preflight_at,
    )
    claimed_at = _iso(datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=2))
    return store, protected, values, binding, delegation, job["job_id"], claimed_at


def _claim(
    store: ProductStore,
    *,
    job_id: str,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    claimed_at: str,
    resolution_ref: str = RESOLUTION_REF,
):
    return store.claim_accepted_engine_attempt_execution(
        job_id=job_id,
        binding=binding.to_dict(),
        delegation=delegation.to_dict(),
        runtime_resolution_ref=resolution_ref,
        reviewer=REVIEWER,
        claimed_at=claimed_at,
    )


def _settle_preflight_cancellation(
    tmp_path: Path,
) -> tuple[
    ProductStore,
    EngineAttemptBinding,
    EngineCapabilityDelegation,
    str,
    Mapping[str, Any],
    EngineExperiment,
]:
    store, _protected, _values, binding, delegation, job_id, checked_at = _ready(tmp_path)
    store.transition_job(job_id, "cancelling")
    precheck = store.inspect_accepted_engine_attempt_pre_dispatch_cancellation(
        job_id=job_id,
        binding=binding.to_dict(),
        delegation=delegation.to_dict(),
        reviewer=REVIEWER,
        checked_at=checked_at,
    )
    assert precheck is not None and precheck.pre_dispatch_ref is not None
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    settled_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=settled_at,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_execution_claim",
        limitations=("External-engine dispatch did not begin.",),
    )
    updated = EngineExperiment._from_controller_mapping(
        store.settle_engine_attempt_pre_dispatch(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=job_id,
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            record=terminal.to_dict(),
            exit_reason="controller_cancelled_before_execution_claim",
            adapter_pre_dispatch_ref=precheck.pre_dispatch_ref,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    with store._connection() as connection:
        row = connection.execute(
            "SELECT document_json FROM engine_attempt_pre_dispatch_settlements"
        ).fetchone()
    assert row is not None
    document = json.loads(str(row["document_json"]))
    assert isinstance(document, dict)
    return store, binding, delegation, job_id, document, updated


def test_claim_is_append_only_one_shot_and_lost_ack_never_reissues(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)

    first = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    replay = _claim(
        ProductStore(store.path),
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=3)),
    )

    assert first.created is True
    assert first.document is not None
    assert replay.created is False
    assert replay.document == first.document
    assert replay.pre_dispatch_ref is None
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_attempt_execution_claims").fetchone()[0]
            == 1
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE engine_attempt_execution_claims SET claimed_at=claimed_at")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM engine_attempt_execution_claims")
        with pytest.raises(sqlite3.IntegrityError, match="immutable|append-only|conflicts"):
            connection.execute("""INSERT OR REPLACE INTO engine_attempt_execution_claims
                SELECT * FROM engine_attempt_execution_claims""")

    serialized = json.dumps(first.document, sort_keys=True).lower()
    assert "password" not in serialized
    assert "secret" not in serialized
    assert "\\users\\" not in serialized
    assert "/".join(("", "home", "")) not in serialized


def test_concurrent_claim_has_exactly_one_authority_winner(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)

    def contender(_index: int):
        return _claim(
            ProductStore(store.path),
            job_id=job_id,
            binding=binding,
            delegation=delegation,
            claimed_at=claimed_at,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(contender, range(8)))

    assert sum(result.created for result in results) == 1
    assert len({result.document["claim_ref"] for result in results if result.document}) == 1


def test_claim_requires_running_exact_preflight_and_unexpired_authority(
    tmp_path: Path,
) -> None:
    store, protected, values = _attempt_v2(tmp_path)
    job, _created = _accept(store, values)
    binding, delegation = _authority(protected)
    store.transition_job(job["job_id"], "planning")
    store.transition_job(job["job_id"], "running")

    with pytest.raises(ResourceConflictError, match="exact preflight"):
        _claim(
            store,
            job_id=job["job_id"],
            binding=binding,
            delegation=delegation,
            claimed_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=2)),
        )
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    preflight = experiment.attempts[0].record.transition(AttemptState.PREFLIGHT)
    store.compare_and_swap_engine_attempt_record(
        experiment_id=EXPERIMENT_ID,
        record=preflight.to_dict(),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
        timestamp=_iso(datetime.now(timezone.utc) + timedelta(seconds=1)),
    )
    with pytest.raises(ResourceConflictError, match="outside its authority"):
        _claim(
            store,
            job_id=job["job_id"],
            binding=binding,
            delegation=delegation,
            claimed_at=delegation.expires_at,
        )


def test_v2_running_and_completed_mutations_require_a_durable_claim(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, _delegation, _job_id, _claimed_at = _ready(tmp_path)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    preflight = experiment.attempts[0].record
    started_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    ended_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=4))
    running = preflight.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-unclaimed",
        timestamp=started_at,
    )

    with pytest.raises(ResourceConflictError, match="durable execution claim"):
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=started_at,
        )

    completed_document = preflight.to_dict()
    completed_document.update(
        {
            "state": AttemptState.COMPLETED.value,
            "upstream_session_id": "strix-session-unclaimed",
            "started_at": started_at,
            "ended_at": ended_at,
            "exit_code": 0,
            "completeness": AttemptCompleteness.COMPLETE.value,
            "exit_reason": "completed",
            "limitations": [],
        }
    )
    completed = EngineAttemptRecord.from_mapping(completed_document)
    with pytest.raises(ResourceConflictError, match="durable execution claim"):
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=completed.to_dict(),
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.VERIFIED_ABSENT.value,
            cleanup_evidence_ref="sha256:" + "4" * 64,
            settled_at=ended_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    assert binding.attempt_id == preflight.binding.attempt_id


def test_claimed_preflight_cannot_start_after_its_job_became_terminal(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.created is True
    assert claimed.document is not None
    store.transition_job(job_id, "failed")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-terminal-job",
        timestamp=_iso(datetime.now(timezone.utc) + timedelta(seconds=3)),
    )

    with pytest.raises(ResourceConflictError, match="live bound job"):
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=str(running.started_at),
        )


def test_generic_v2_pre_dispatch_settlement_cannot_use_an_arbitrary_receipt(
    tmp_path: Path,
) -> None:
    store, _protected, _values, _binding, _delegation, _job_id, _claimed_at = _ready(tmp_path)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    settled_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    cancelled = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=settled_at,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_execution_claim",
        limitations=("External-engine dispatch did not begin.",),
    )

    with pytest.raises(ResourceConflictError, match="durable execution claim"):
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=cancelled.to_dict(),
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.VERIFIED_ABSENT.value,
            cleanup_evidence_ref="sha256:" + "5" * 64,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )


def test_unexpired_authority_cannot_be_settled_as_expired(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, settled_at = _ready(tmp_path)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=settled_at,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="authority_expired_before_dispatch",
        limitations=("External-engine dispatch did not begin.",),
    )

    with pytest.raises(ResourceConflictError, match="job or attempt state changed"):
        store.settle_engine_attempt_pre_dispatch(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=job_id,
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            record=terminal.to_dict(),
            exit_reason="authority_expired_before_dispatch",
            adapter_pre_dispatch_ref=None,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )


def test_legacy_v1_acceptance_cannot_gain_first_v22_launch_authority(tmp_path: Path) -> None:
    store, protected, values = _attempt(tmp_path)
    job, _created = _accept(store, values)
    binding, delegation = _authority(protected)
    store.transition_job(job["job_id"], "planning")
    store.transition_job(job["job_id"], "running")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    preflight = experiment.attempts[0].record.transition(AttemptState.PREFLIGHT)
    store.compare_and_swap_engine_attempt_record(
        experiment_id=EXPERIMENT_ID,
        record=preflight.to_dict(),
        expected_revision=experiment.revision,
        expected_experiment_digest=experiment.digest,
        timestamp=_iso(datetime.now(timezone.utc) + timedelta(seconds=1)),
    )

    with pytest.raises(ResourceConflictError, match="immutable installed policy"):
        _claim(
            store,
            job_id=job["job_id"],
            binding=binding,
            delegation=delegation,
            claimed_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=2)),
        )
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_attempt_execution_claims").fetchone()[0]
            == 0
        )


def test_v2_job_request_rejects_changed_execution_claim_policy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prepared_at, expires_at, _now = _times()
    binding, delegation, approval = _attempt_authority(prepared_at, expires_at)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    policy = {**installed_execution_claim_policy(), "accepted_jobs_adapter": "changed"}

    with pytest.raises(EngineExperimentJobError, match="claim policy changed"):
        EngineExperimentJobs._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval,
            approval_id="approval-" + "1" * 32,
            execution_claim_policy=policy,
        )


def test_pre_dispatch_cancellation_is_atomic_and_never_creates_claim(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, checked_at = _ready(tmp_path)
    store.transition_job(job_id, "cancelling")

    result = store.inspect_accepted_engine_attempt_pre_dispatch_cancellation(
        job_id=job_id,
        binding=binding.to_dict(),
        delegation=delegation.to_dict(),
        reviewer=REVIEWER,
        checked_at=checked_at,
    )
    assert result is not None
    assert result.document is None
    assert result.created is False
    assert result.job_state == "cancelling"
    assert result.pre_dispatch_ref is not None
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_attempt_execution_claims").fetchone()[0]
            == 0
        )


def test_exact_pre_dispatch_settlement_is_immutable_and_reopens_after_interruption(
    tmp_path: Path,
) -> None:
    store, binding, delegation, job_id, document, updated = _settle_preflight_cancellation(tmp_path)
    entry = updated.attempts[0]
    assert entry.record.state is AttemptState.CANCELLED
    assert entry.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert entry.cleanup_evidence_ref == document["settlement_ref"]
    assert document["adapter_pre_dispatch_ref"] is not None
    assert document["prior_attempt_state"] == "preflight"
    assert document["observed_job_state"] == "cancelling"

    with store._connection(write=True) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_attempt_pre_dispatch_settlements"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_attempt_execution_claims").fetchone()[0]
            == 0
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE engine_attempt_pre_dispatch_settlements SET settled_at=settled_at"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM engine_attempt_pre_dispatch_settlements")
        with pytest.raises(sqlite3.IntegrityError, match="immutable|append-only|conflicts"):
            connection.execute("""INSERT OR REPLACE INTO engine_attempt_pre_dispatch_settlements
                SELECT * FROM engine_attempt_pre_dispatch_settlements""")

    with pytest.raises(ResourceConflictError, match="exact preflight"):
        _claim(
            store,
            job_id=job_id,
            binding=binding,
            delegation=delegation,
            claimed_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=4)),
        )

    store.transition_job(job_id, "interrupted")
    recovery = ProductStore(store.path).get_accepted_engine_attempt_execution(
        binding=binding.to_dict(),
        delegation=delegation.to_dict(),
        reviewer=REVIEWER,
    )
    assert recovery.document is None
    assert recovery.pre_dispatch_document == document
    assert recovery.job_state == "interrupted"
    serialized = json.dumps(document, sort_keys=True).lower()
    assert "password" not in serialized
    assert "secret" not in serialized
    assert "\\users\\" not in serialized
    assert "/".join(("", "home", "")) not in serialized


def test_execution_claim_and_pre_dispatch_receipt_are_mutually_exclusive(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.created is True
    store.transition_job(job_id, "cancelling")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    settled_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=settled_at,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_execution_claim",
        limitations=("External-engine dispatch did not begin.",),
    )

    with pytest.raises(ResourceConflictError, match="execution custody"):
        store.settle_engine_attempt_pre_dispatch(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=job_id,
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            record=terminal.to_dict(),
            exit_reason="controller_cancelled_before_execution_claim",
            adapter_pre_dispatch_ref="sha256:" + "6" * 64,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_attempt_pre_dispatch_settlements"
            ).fetchone()[0]
            == 0
        )


def test_raw_pre_dispatch_receipt_without_terminal_state_is_not_trusted(
    tmp_path: Path,
) -> None:
    store, binding, delegation, job_id, document, _updated = _settle_preflight_cancellation(
        tmp_path
    )
    store.transition_job(job_id, "interrupted")
    with store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER engine_experiment_heads_valid_update")
        connection.execute(
            """UPDATE engine_experiment_heads
            SET active_revision=?,active_digest=? WHERE experiment_id=?""",
            (
                document["prior_revision"],
                document["prior_experiment_digest"],
                EXPERIMENT_ID,
            ),
        )

    with pytest.raises(ProductStoreError, match="terminal state changed"):
        store.get_accepted_engine_attempt_execution(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
        )


def test_queued_pre_dispatch_cancellation_receipt_binds_exact_prior_state(
    tmp_path: Path,
) -> None:
    store, protected, values = _attempt_v2(tmp_path)
    job, created = _accept(store, values)
    assert created is True
    binding, delegation = _authority(protected)
    store.transition_job(job["job_id"], "cancelled")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    assert experiment.attempts[0].record.state is AttemptState.QUEUED
    settled_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    terminal = experiment.attempts[0].record.transition(
        AttemptState.CANCELLED,
        timestamp=settled_at,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled_before_dispatch",
        limitations=("External-engine dispatch did not begin.",),
    )
    wrapper_receipt = content_hash(
        {
            "schema_version": "bluefire.engine-undispatched-cancellation-receipt.v1",
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": binding.attempt_id,
            "job_id": job["job_id"],
            "binding_digest": binding.binding_digest,
            "job_state": "cancelled",
            "custody_state": "never_dispatched",
            "recorded_at": settled_at,
        }
    )
    updated = EngineExperiment._from_controller_mapping(
        store.settle_undispatched_engine_attempt_cancellation(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            job_id=job["job_id"],
            record=terminal.to_dict(),
            cleanup_evidence_ref=wrapper_receipt,
            settled_at=settled_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    with store._connection() as connection:
        row = connection.execute(
            "SELECT document_json FROM engine_attempt_pre_dispatch_settlements"
        ).fetchone()
    assert row is not None
    document = json.loads(str(row["document_json"]))
    assert document["prior_attempt_state"] == "queued"
    assert document["observed_job_state"] == "cancelled"
    assert document["adapter_pre_dispatch_ref"] is None
    assert document["exit_reason"] == "controller_cancelled_before_dispatch"
    assert updated.attempts[0].cleanup_evidence_ref == document["settlement_ref"]


@pytest.mark.parametrize("preflight", [False, True], ids=["queued", "preflight"])
def test_unclaimed_recovery_is_unknown_and_lost_ack_retry_is_idempotent(
    tmp_path: Path,
    preflight: bool,
) -> None:
    if preflight:
        store, _protected, _values, binding, delegation, job_id, _claimed_at = _ready(tmp_path)
    else:
        store, protected, values = _attempt_v2(tmp_path)
        job, created = _accept(store, values)
        assert created is True
        binding, delegation = _authority(protected)
        job_id = str(job["job_id"])
    store.transition_job(job_id, "failed")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    timestamp = _iso(datetime.now(timezone.utc) + timedelta(seconds=3))
    receipt = content_hash(
        {
            "schema_version": "bluefire.engine-unclaimed-recovery.v1",
            "attempt_id": binding.attempt_id,
            "binding_digest": binding.binding_digest,
            "delegation_digest": delegation.delegation_digest,
            "job_id": job_id,
            "job_state": "failed",
            "recorded_at": timestamp,
        }
    )
    with store.engine_attempt_reconciliation_session() as capability:
        first = EngineExperiment._from_controller_mapping(
            store.settle_unclaimed_engine_attempt_recovery(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                job_id=job_id,
                job_state="failed",
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                cleanup_evidence_ref=receipt,
                timestamp=timestamp,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                reconciliation_capability=capability,
            )
        )
    other = ProductStore(store.path)
    with other.engine_attempt_reconciliation_session() as capability:
        retried = EngineExperiment._from_controller_mapping(
            other.settle_unclaimed_engine_attempt_recovery(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                job_id=job_id,
                job_state="failed",
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                cleanup_evidence_ref=receipt,
                timestamp=timestamp,
                expected_revision=first.revision,
                expected_experiment_digest=first.digest,
                reconciliation_capability=capability,
            )
        )

    assert retried.revision == first.revision
    assert retried.digest == first.digest
    assert retried.to_dict() == first.to_dict()
    entry = retried.attempts[0]
    assert entry.record.state is AttemptState.FAILED
    assert entry.record.exit_reason == "installed_execution_claim_unknown"
    assert entry.cleanup_state is CleanupState.UNKNOWN
    assert entry.cleanup_evidence_ref == receipt


def test_unclaimed_recovery_refuses_a_running_job(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, timestamp = _ready(tmp_path)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )

    with store.engine_attempt_reconciliation_session() as capability:
        with pytest.raises(ProductStoreError, match="job state is invalid"):
            store.settle_unclaimed_engine_attempt_recovery(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                job_id=job_id,
                job_state="running",
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                cleanup_evidence_ref="sha256:" + "7" * 64,
                timestamp=timestamp,
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                reconciliation_capability=capability,
            )


def test_reconciliation_is_terminal_only_and_missing_claim_stays_ambiguous(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, _claimed_at = _ready(tmp_path)
    with pytest.raises(ResourceConflictError, match="terminal job"):
        store.get_accepted_engine_attempt_execution(
            binding=binding.to_dict(), delegation=delegation.to_dict(), reviewer=REVIEWER
        )

    store.transition_job(job_id, "failed")
    recovery = store.get_accepted_engine_attempt_execution(
        binding=binding.to_dict(), delegation=delegation.to_dict(), reviewer=REVIEWER
    )
    assert recovery.document is None
    assert recovery.job_id == job_id
    assert recovery.job_state == "failed"


def test_completed_job_without_claim_is_inconsistent_not_absent(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, _claimed_at = _ready(tmp_path)
    store.transition_job(job_id, "completed")

    with pytest.raises(ResourceConflictError, match="completed engine job has no settled"):
        store.get_accepted_engine_attempt_execution(
            binding=binding.to_dict(), delegation=delegation.to_dict(), reviewer=REVIEWER
        )


def test_reconciliation_reopens_claim_but_never_issues_new_authority(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    store.transition_job(job_id, "failed")

    recovery = ProductStore(store.path).get_accepted_engine_attempt_execution(
        binding=binding.to_dict(), delegation=delegation.to_dict(), reviewer=REVIEWER
    )
    assert recovery.document == claimed.document
    assert recovery.job_state == "failed"
    with store._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM engine_attempt_execution_claims").fetchone()[0]
            == 1
        )


def test_reconciliation_intent_create_and_reopen_are_stable_across_stores(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.document is not None
    store.transition_job(job_id, "failed")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    created_at = _iso(datetime.now(timezone.utc) + timedelta(seconds=4))
    with store.engine_attempt_reconciliation_session() as capability:
        first = store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=created_at,
            saved_record=experiment.attempts[0].record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            reconciliation_capability=capability,
        )
    other = ProductStore(store.path)
    with other.engine_attempt_reconciliation_session() as capability:
        reopened = other.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=5)),
            saved_record=experiment.attempts[0].record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            reconciliation_capability=capability,
        )

    assert first.reconciliation_document is not None
    assert reopened.reconciliation_document == first.reconciliation_document
    assert first.reconciliation_document["job_state"] == "failed"
    assert reopened.job_state == first.job_state == "failed"
    assert (
        reopened.reconciliation_document["reconciliation_ref"]
        == first.reconciliation_document["reconciliation_ref"]
    )
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_attempt_reconciliation_intents"
            ).fetchone()[0]
            == 1
        )


def test_reconciliation_intent_job_state_tamper_is_rejected(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    store.transition_job(job_id, "failed")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    with store.engine_attempt_reconciliation_session() as capability:
        created = store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=4)),
            saved_record=experiment.attempts[0].record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            reconciliation_capability=capability,
        )
    assert created.reconciliation_document is not None
    changed = dict(created.reconciliation_document)
    changed["job_state"] = "interrupted"
    with store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER engine_attempt_reconciliation_intents_no_update")
        connection.execute(
            """UPDATE engine_attempt_reconciliation_intents
            SET job_state=?,document_json=?,record_digest=?""",
            (
                "interrupted",
                canonical_json(changed),
                content_hash(changed),
            ),
        )

    with store.engine_attempt_reconciliation_session() as capability:
        with pytest.raises(ProductStoreError, match="intent integrity changed"):
            store.begin_or_reopen_engine_attempt_reconciliation(
                binding=binding.to_dict(),
                delegation=delegation.to_dict(),
                reviewer=REVIEWER,
                created_at=_iso(datetime.now(timezone.utc) + timedelta(seconds=5)),
                saved_record=experiment.attempts[0].record.to_dict(),
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                reconciliation_capability=capability,
            )


def test_v2_product_store_lifecycle_loads_settles_observes_and_cleans_up(
    tmp_path: Path,
) -> None:
    store, protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.created is True
    assert claimed.document is not None
    loaded = store.load_engine_attempt_execution(EXPERIMENT_ID, binding.attempt_id)
    assert loaded["delegation"] == delegation.to_dict()
    assert loaded["experiment"]["attempts"][0]["record"]["state"] == "preflight"
    assert (
        protected["protected_request"]["job_request"]["execution_claim_policy"]
        == installed_execution_claim_policy()
    )

    experiment = EngineExperiment._from_controller_mapping(loaded["experiment"])
    preflight = experiment.attempts[0].record
    started = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=3)
    started_at = _iso(started)
    running = preflight.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-claim-lifecycle",
        timestamp=started_at,
    )
    experiment = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=started_at,
        )
    )
    observed_at = _iso(started + timedelta(seconds=1))
    ended_at = _iso(started + timedelta(seconds=2))
    observation = _attempt_observation(binding, timestamp=observed_at)
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp=ended_at,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    settled = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=completed.to_dict(),
            engine_evidence=(),
            independent_observations=(observation.to_dict(),),
            artifact_manifest_ref="sha256:" + "7" * 64,
            cleanup_state=CleanupState.UNKNOWN.value,
            cleanup_evidence_ref="sha256:" + "8" * 64,
            settled_at=ended_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    store.transition_job(job_id, "completed")
    with store.engine_attempt_reconciliation_session() as capability:
        reconciliation = store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=_iso(started + timedelta(seconds=3)),
            saved_record=settled.attempts[0].record.to_dict(),
            expected_revision=settled.revision,
            expected_experiment_digest=settled.digest,
            reconciliation_capability=capability,
        )
        assert reconciliation.reconciliation_document is not None
        reconciliation_ref = str(reconciliation.reconciliation_document["reconciliation_ref"])
        assert reconciliation.reconciliation_document["claim_ref"] == claimed.document["claim_ref"]
        assert reconciliation.reconciliation_document["job_state"] == "completed"
        cleanup_ref = "sha256:" + "9" * 64
        cleaned = EngineExperiment._from_controller_mapping(
            store.reconcile_engine_attempt_cleanup(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                cleanup_state=CleanupState.VERIFIED_ABSENT.value,
                cleanup_evidence_ref=cleanup_ref,
                timestamp=_iso(started + timedelta(seconds=4)),
                expected_revision=settled.revision,
                expected_experiment_digest=settled.digest,
                reconciliation_ref=reconciliation_ref,
                reconciliation_capability=capability,
            )
        )
    other = ProductStore(store.path)
    with other.engine_attempt_reconciliation_session() as capability:
        replay = EngineExperiment._from_controller_mapping(
            other.reconcile_engine_attempt_cleanup(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                cleanup_state=CleanupState.VERIFIED_ABSENT.value,
                cleanup_evidence_ref=cleanup_ref,
                timestamp=_iso(started + timedelta(seconds=5)),
                expected_revision=cleaned.revision,
                expected_experiment_digest=cleaned.digest,
                reconciliation_ref=reconciliation_ref,
                reconciliation_capability=capability,
            )
        )
    assert replay.revision == cleaned.revision
    assert replay.digest == cleaned.digest
    with store.engine_attempt_reconciliation_session() as capability:
        with pytest.raises(ResourceConflictError, match="cannot be replaced"):
            store.reconcile_engine_attempt_cleanup(
                experiment_id=EXPERIMENT_ID,
                attempt_id=binding.attempt_id,
                cleanup_state=CleanupState.VERIFIED_ABSENT.value,
                cleanup_evidence_ref="sha256:" + "a" * 64,
                timestamp=_iso(started + timedelta(seconds=6)),
                expected_revision=cleaned.revision,
                expected_experiment_digest=cleaned.digest,
                reconciliation_ref=reconciliation_ref,
                reconciliation_capability=capability,
            )
    assert cleaned.attempts[0].record.state is AttemptState.COMPLETED
    assert cleaned.attempts[0].cleanup_state is CleanupState.VERIFIED_ABSENT
    assert cleaned.independent_observations[-1].evidence.evidence_id == (
        observation.evidence.evidence_id
    )
    with store._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM engine_attempt_reconciliation_intents"
            ).fetchone()[0]
            == 1
        )


def test_claim_read_rejects_canonical_document_identity_tamper(tmp_path: Path) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.document is not None
    store.transition_job(job_id, "failed")
    changed = dict(claimed.document)
    changed["runtime_resolution_ref"] = "sha256:" + "e" * 64
    # Retaining the old claim_ref with a fully rehashed canonical row exercises
    # the independently recomputed identity rather than only record_digest.
    with store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER engine_attempt_execution_claims_no_update")
        with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
            connection.execute("UPDATE engine_attempt_execution_claims SET claimed_at=NULL")
        connection.execute(
            """UPDATE engine_attempt_execution_claims
            SET runtime_resolution_ref=?,document_json=?,record_digest=?""",
            (
                changed["runtime_resolution_ref"],
                canonical_json(changed),
                content_hash(changed),
            ),
        )

    with pytest.raises(ProductStoreError, match="integrity changed"):
        store.get_accepted_engine_attempt_execution(
            binding=binding.to_dict(), delegation=delegation.to_dict(), reviewer=REVIEWER
        )


def test_insert_trigger_rejects_missing_claim_document_fields(tmp_path: Path) -> None:
    store, protected, values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    with store._connection(write=True) as connection:
        preparation = connection.execute(
            "SELECT * FROM engine_action_preparations WHERE request_ref=?",
            (protected["request_ref"],),
        ).fetchone()
        acceptance = connection.execute(
            "SELECT * FROM engine_action_acceptances WHERE request_ref=?",
            (protected["request_ref"],),
        ).fetchone()
        assert preparation is not None and acceptance is not None
        with pytest.raises(sqlite3.IntegrityError, match="document changed"):
            connection.execute(
                """INSERT INTO engine_attempt_execution_claims(
                claim_ref,job_id,attempt_id,experiment_id,preparation_ref,preparation_id,
                preparation_record_digest,acceptance_record_digest,binding_digest,
                delegation_digest,submission_id,intent_digest,runtime_resolution_ref,
                job_request_digest,preflight_revision,preflight_experiment_digest,
                claimed_at,document_json,record_digest
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "sha256:" + "1" * 64,
                    job_id,
                    binding.attempt_id,
                    binding.experiment_id,
                    protected["request_ref"],
                    values["preparation_id"],
                    preparation["record_digest"],
                    acceptance["record_digest"],
                    binding.binding_digest,
                    delegation.delegation_digest,
                    protected["submission_id"],
                    protected["intent_digest"],
                    "sha256:" + "9" * 64,
                    content_hash(protected["protected_request"]["job_request"]),
                    experiment.revision,
                    experiment.digest,
                    claimed_at,
                    canonical_json(
                        {"schema_version": "bluefire.engine-attempt-execution-claim.v1"}
                    ),
                    "sha256:" + "c" * 64,
                ),
            )


def _race_claimed_interrupted(
    tmp_path: Path,
) -> tuple[
    ProductStore,
    EngineAttemptBinding,
    EngineCapabilityDelegation,
    str,
    EngineExperiment,
    str,
]:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.created is True and claimed.document is not None
    store.transition_job(job_id, "interrupted")
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    created_at = _iso(datetime.now(timezone.utc) + timedelta(minutes=1))
    return store, binding, delegation, job_id, experiment, created_at


def test_reconciliation_intent_freezes_terminal_engine_job_state(tmp_path: Path) -> None:
    store, binding, delegation, job_id, experiment, created_at = _race_claimed_interrupted(tmp_path)
    with store.engine_attempt_reconciliation_session() as capability:
        decision = store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=created_at,
            saved_record=experiment.attempts[0].record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            reconciliation_capability=capability,
        )
    assert decision.reconciliation_document is not None

    with pytest.raises(sqlite3.IntegrityError, match="freezes"):
        store.transition_job(job_id, "planning")
    assert store.get_job(job_id)["state"] == "interrupted"
    with store._connection() as connection:
        saved = connection.execute(
            "SELECT document_json FROM engine_attempt_reconciliation_intents"
        ).fetchone()
    assert saved is not None
    assert json.loads(str(saved["document_json"])) == decision.reconciliation_document


def test_reconciliation_intent_and_resume_have_exactly_one_winner(tmp_path: Path) -> None:
    import threading

    store, binding, delegation, job_id, experiment, created_at = _race_claimed_interrupted(tmp_path)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    failures: list[BaseException] = []

    def recover() -> None:
        candidate = ProductStore(store.path)
        barrier.wait(timeout=5)
        try:
            with candidate.engine_attempt_reconciliation_session() as capability:
                candidate.begin_or_reopen_engine_attempt_reconciliation(
                    binding=binding.to_dict(),
                    delegation=delegation.to_dict(),
                    reviewer=REVIEWER,
                    created_at=created_at,
                    saved_record=experiment.attempts[0].record.to_dict(),
                    expected_revision=experiment.revision,
                    expected_experiment_digest=experiment.digest,
                    reconciliation_capability=capability,
                )
            outcomes.append("intent")
        except BaseException as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    def resume() -> None:
        candidate = ProductStore(store.path)
        barrier.wait(timeout=5)
        try:
            candidate.transition_job(job_id, "planning")
            outcomes.append("resume")
        except BaseException as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=recover), threading.Thread(target=resume)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(outcomes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], (ProductStoreError, sqlite3.IntegrityError))
    with store._connection() as connection:
        intent_count = connection.execute(
            "SELECT COUNT(*) FROM engine_attempt_reconciliation_intents"
        ).fetchone()[0]
    if outcomes == ["intent"]:
        assert intent_count == 1
        assert store.get_job(job_id)["state"] == "interrupted"
    else:
        assert outcomes == ["resume"]
        assert intent_count == 0
        assert store.get_job(job_id)["state"] == "planning"


def test_reconciliation_capability_is_exact_live_thread_local_proof(tmp_path: Path) -> None:
    import threading

    store, binding, delegation, _job_id, experiment, created_at = _race_claimed_interrupted(
        tmp_path
    )
    other = ProductStore(store.path)
    with store.engine_attempt_reconciliation_session() as capability:
        with pytest.raises(ProductStoreError, match="already active"):
            with other.engine_attempt_reconciliation_session():
                pytest.fail("nested recovery session unexpectedly opened")

        with pytest.raises(ProductStoreError, match="not active"):
            store.begin_or_reopen_engine_attempt_reconciliation(
                binding=binding.to_dict(),
                delegation=delegation.to_dict(),
                reviewer=REVIEWER,
                created_at=created_at,
                saved_record=experiment.attempts[0].record.to_dict(),
                expected_revision=experiment.revision,
                expected_experiment_digest=experiment.digest,
                reconciliation_capability=object(),
            )

        cross_thread: list[BaseException] = []

        def use_on_other_thread() -> None:
            try:
                store.begin_or_reopen_engine_attempt_reconciliation(
                    binding=binding.to_dict(),
                    delegation=delegation.to_dict(),
                    reviewer=REVIEWER,
                    created_at=created_at,
                    saved_record=experiment.attempts[0].record.to_dict(),
                    expected_revision=experiment.revision,
                    expected_experiment_digest=experiment.digest,
                    reconciliation_capability=capability,
                )
            except BaseException as exc:  # pragma: no branch - asserted below
                cross_thread.append(exc)

        thread = threading.Thread(target=use_on_other_thread)
        thread.start()
        thread.join(timeout=10)
        assert len(cross_thread) == 1
        assert isinstance(cross_thread[0], ProductStoreError)
        assert "not active" in str(cross_thread[0])

    with pytest.raises(ProductStoreError, match="not active"):
        store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=created_at,
            saved_record=experiment.attempts[0].record.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            reconciliation_capability=capability,
        )


def test_recovery_cleanup_refuses_durable_intent_without_active_capability(
    tmp_path: Path,
) -> None:
    store, _protected, _values, binding, delegation, job_id, claimed_at = _ready(tmp_path)
    claimed = _claim(
        store,
        job_id=job_id,
        binding=binding,
        delegation=delegation,
        claimed_at=claimed_at,
    )
    assert claimed.document is not None
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    started = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=3)
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="strix-session-capability-race",
        timestamp=_iso(started),
    )
    experiment = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_record(
            experiment_id=EXPERIMENT_ID,
            record=running.to_dict(),
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
            timestamp=_iso(started),
        )
    )
    ended_at = _iso(started + timedelta(seconds=1))
    failed = running.transition(
        AttemptState.FAILED,
        timestamp=ended_at,
        exit_code=1,
        completeness=AttemptCompleteness.PARTIAL,
        exit_reason="failed",
    )
    settled = EngineExperiment._from_controller_mapping(
        store.compare_and_swap_engine_attempt_settlement(
            experiment_id=EXPERIMENT_ID,
            record=failed.to_dict(),
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.UNKNOWN.value,
            cleanup_evidence_ref="sha256:" + "7" * 64,
            settled_at=ended_at,
            expected_revision=experiment.revision,
            expected_experiment_digest=experiment.digest,
        )
    )
    store.transition_job(job_id, "interrupted")
    with store.engine_attempt_reconciliation_session() as capability:
        decision = store.begin_or_reopen_engine_attempt_reconciliation(
            binding=binding.to_dict(),
            delegation=delegation.to_dict(),
            reviewer=REVIEWER,
            created_at=_iso(started + timedelta(minutes=1)),
            saved_record=settled.attempts[0].record.to_dict(),
            expected_revision=settled.revision,
            expected_experiment_digest=settled.digest,
            reconciliation_capability=capability,
        )
    assert decision.reconciliation_document is not None
    reconciliation_ref = str(decision.reconciliation_document["reconciliation_ref"])

    with pytest.raises(ProductStoreError, match="not active"):
        store.reconcile_engine_attempt_cleanup(
            experiment_id=EXPERIMENT_ID,
            attempt_id=binding.attempt_id,
            cleanup_state=CleanupState.VERIFIED_ABSENT.value,
            cleanup_evidence_ref="sha256:" + "8" * 64,
            timestamp=_iso(started + timedelta(minutes=2)),
            expected_revision=settled.revision,
            expected_experiment_digest=settled.digest,
            reconciliation_ref=reconciliation_ref,
            reconciliation_capability=None,
        )
    assert store.get_engine_experiment_document(EXPERIMENT_ID) == settled.to_dict()


def test_same_marker_empty_draft_intent_table_is_rebuilt(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with store._connection(write=True) as connection:
        for trigger in (
            "engine_attempt_reconciliation_intents_freeze_job_state",
            "engine_attempt_reconciliation_intents_valid_insert",
            "engine_attempt_reconciliation_intents_no_update",
            "engine_attempt_reconciliation_intents_no_delete",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        connection.execute("DROP TABLE engine_attempt_reconciliation_intents")
        connection.execute("CREATE TABLE engine_attempt_reconciliation_intents (draft_ref TEXT)")

    reopened = ProductStore(store.path)
    with reopened._connection() as connection:
        columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(engine_attempt_reconciliation_intents)"
            ).fetchall()
        }
    assert "job_state" in columns
    assert "reconciliation_ref" in columns
    assert "draft_ref" not in columns


def test_same_marker_nonempty_draft_intent_table_fails_closed(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with store._connection(write=True) as connection:
        for trigger in (
            "engine_attempt_reconciliation_intents_freeze_job_state",
            "engine_attempt_reconciliation_intents_valid_insert",
            "engine_attempt_reconciliation_intents_no_update",
            "engine_attempt_reconciliation_intents_no_delete",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        connection.execute("DROP TABLE engine_attempt_reconciliation_intents")
        connection.execute("CREATE TABLE engine_attempt_reconciliation_intents (draft_ref TEXT)")
        connection.execute(
            "INSERT INTO engine_attempt_reconciliation_intents(draft_ref) VALUES ('retained')"
        )

    with pytest.raises(ProductStoreError, match="draft.*manual recovery"):
        ProductStore(store.path)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute(
            "SELECT draft_ref FROM engine_attempt_reconciliation_intents"
        ).fetchone() == ("retained",)


def test_same_marker_pre_dispatch_check_rebuild_preserves_receipt(tmp_path: Path) -> None:
    store, _binding, _delegation, _job_id, receipt, _updated = _settle_preflight_cancellation(
        tmp_path
    )
    with store._connection(write=True) as connection:
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='engine_attempt_pre_dispatch_settlements'"
        ).fetchone()
        assert schema is not None
        old_schema = str(schema["sql"]).replace(
            "('running','cancelling','cancelled')",
            "('running','cancelling')",
        )
        assert old_schema != schema["sql"]
        for trigger in (
            "engine_attempt_execution_claims_valid_insert",
            "engine_attempt_pre_dispatch_settlements_valid_insert",
            "engine_attempt_pre_dispatch_settlements_no_update",
            "engine_attempt_pre_dispatch_settlements_no_delete",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        connection.execute(
            "ALTER TABLE engine_attempt_pre_dispatch_settlements "
            "RENAME TO engine_attempt_pre_dispatch_settlements_current"
        )
        connection.execute(old_schema)
        connection.execute(
            "INSERT INTO engine_attempt_pre_dispatch_settlements "
            "SELECT * FROM engine_attempt_pre_dispatch_settlements_current"
        )
        connection.execute("DROP TABLE engine_attempt_pre_dispatch_settlements_current")

    reopened = ProductStore(store.path)
    with reopened._connection() as connection:
        row = connection.execute(
            "SELECT document_json FROM engine_attempt_pre_dispatch_settlements"
        ).fetchone()
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='engine_attempt_pre_dispatch_settlements'"
        ).fetchone()
    assert row is not None and json.loads(str(row["document_json"])) == receipt
    assert schema is not None
    assert "'cancelled'" in str(schema["sql"])


def test_reconciliation_capability_is_not_inherited_across_fork(tmp_path: Path) -> None:
    import multiprocessing

    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("fork-only recovery capability regression")
    store, binding, delegation, _job_id, experiment, created_at = _race_claimed_interrupted(
        tmp_path
    )
    context: Any = multiprocessing.get_context("fork")
    outcomes = context.Queue()

    with store.engine_attempt_reconciliation_session() as capability:

        def child() -> None:
            try:
                store.begin_or_reopen_engine_attempt_reconciliation(
                    binding=binding.to_dict(),
                    delegation=delegation.to_dict(),
                    reviewer=REVIEWER,
                    created_at=created_at,
                    saved_record=experiment.attempts[0].record.to_dict(),
                    expected_revision=experiment.revision,
                    expected_experiment_digest=experiment.digest,
                    reconciliation_capability=capability,
                )
            except BaseException as exc:  # pragma: no branch - child result below
                outcomes.put((type(exc).__name__, str(exc)))
            else:
                outcomes.put(("unexpected-success", ""))

        process = context.Process(target=child)
        process.start()
        process.join(timeout=10)
        assert process.exitcode == 0

    name, message = outcomes.get(timeout=2)
    assert name == "ProductStoreError"
    assert "not active" in message
