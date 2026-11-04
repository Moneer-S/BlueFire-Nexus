from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

import bluefire.product_store_engine_action_submissions as submissions
import bluefire.product_store_engine_actions as preparations
import bluefire.product_store_engine_jobs as engine_jobs
from bluefire.engine_action_preparation import EngineWorkspaceAction
from bluefire.engine_controller_jobs import DefenseOperation, EngineControllerJobs
from bluefire.engine_experiment import (
    ControllerCheckRole,
    DefenseState,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import build_completed_experiment
from tests_platform.test_product_store_engine_actions import (
    EXPERIMENT_ID,
    WORKSPACE_REF,
    _applied_tenant_mechanism_experiment,
    _controller_jobs,
    _controller_limits,
    _ControllerRepository,
    _create_attempt,
    _defense_plan,
    _failure_mechanism,
    _iso,
    _material_authority,
    _prepared_controller_check_material,
    _store,
    _store_experiment,
    _store_tenant_defense_history,
    _tenant_defense_states,
    _times,
    _validator,
)

REVIEWER = "bluefire.local-operator"


def _attempt(tmp_path: Path) -> tuple[ProductStore, Mapping[str, Any], dict[str, Any]]:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    protected = _create_attempt(store, prepared_at=prepared_at, expires_at=expires_at)
    public = store.prepared_engine_action(protected["request_ref"])
    values = {
        "experiment_id": EXPERIMENT_ID,
        "preparation_id": public["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    return store, protected, values


def _accept(store: ProductStore, values: Mapping[str, Any]):
    return store.accept_engine_action_preparation(**values, validate_workspace=lambda _record: None)


def _receipt(store: ProductStore, values: Mapping[str, Any]):
    return store.get_engine_action_acceptance(**values)


def _counts(store: ProductStore) -> tuple[int, int, int]:
    with store._connection() as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("jobs", "engine_action_acceptances", "engine_experiment_versions")
        )  # type: ignore[return-value]


def _approve(store: ProductStore, protected: Mapping[str, Any], *, consume: bool = False):
    approval_id = protected["approval_request_id"]
    approval = store.get_approval_request(approval_id)
    binding = {
        "expected_state_digest": approval["state_digest"],
        "expected_plan_digest": approval["plan_digest"],
        "expected_target_scope_digest": approval["target_scope_digest"],
    }
    approved = store.approve(approval_id, approved_by=REVIEWER, **binding)
    return (
        store.consume_approval(approval_id, nonce=approved["nonce"], **binding)
        if consume
        else approved
    )


@pytest.mark.parametrize("initial", ["pending", "approved", "consumed"])
def test_acceptance_resumes_approval_and_joins_fixed_job_receipt_and_head(
    tmp_path: Path, initial: str
) -> None:
    store, protected, values = _attempt(tmp_path)
    if initial != "pending":
        _approve(store, protected, consume=initial == "consumed")
    before_approval = store.get_approval_request(protected["approval_request_id"])
    assert _receipt(store, values) is None
    seen: list[Mapping[str, Any]] = []
    job, created = store.accept_engine_action_preparation(**values, validate_workspace=seen.append)
    assert created is True
    assert len(seen) == 1
    assert seen[0]["protected_request"] == protected["protected_request"]
    assert seen[0]["experiment_document"]["revision"] == 1
    approval = store.get_approval_request(protected["approval_request_id"])
    assert approval["status"] == "claimed"
    assert approval["approved_by"] == REVIEWER
    assert (
        approval["requested_at"]
        <= approval["approved_at"]
        <= approval["consumed_at"]
        <= approval["claimed_at"]
        < approval["expires_at"]
    )
    if initial != "pending":
        assert approval["nonce"] == before_approval["nonce"]
        assert approval["approved_at"] == before_approval["approved_at"]
    request = dict(job["request"])
    submission = request.pop("_submission")
    assert request == protected["protected_request"]["job_request"]
    assert submission["intent_digest"] == content_hash(request) == protected["intent_digest"]
    assert job["kind"] == "engine-attempt"
    receipt = _receipt(store, values)
    assert receipt["job"] == {"job_id": job["job_id"], "kind": "engine-attempt"}
    assert receipt["transition"] is None
    assert set(receipt) == {
        "schema_version",
        "receipt_id",
        "preparation_id",
        "protected_request_ref",
        "experiment_id",
        "action_kind",
        "accepted_at",
        "job",
        "transition",
    }
    serialized = json.dumps(receipt)
    for private in (
        "nonce",
        "approved_by",
        "reviewer",
        "authority",
        "delegation",
        "approval_binding",
        "_engine_execution",
        "execution_approval_id",
    ):
        assert private not in serialized
    assert _counts(store) == (1, 1, 2)
    repeated, created = _accept(store, values)
    assert repeated == job and created is False
    assert _receipt(store, values) == receipt


@pytest.mark.parametrize("separate_stores", [False, True])
def test_concurrent_identical_acceptance_has_one_job_receipt_and_reservation(
    tmp_path: Path, separate_stores: bool
) -> None:
    store, _protected, values = _attempt(tmp_path)
    stores = [ProductStore(store.path) if separate_stores else store for _ in range(6)]
    barrier = threading.Barrier(len(stores))

    def submit(instance: ProductStore):
        barrier.wait(timeout=10)
        return _accept(instance, values)

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        results = list(pool.map(submit, stores))
    assert sum(created for _job, created in results) == 1
    assert len({job["job_id"] for job, _created in results}) == 1
    assert _counts(store) == (1, 1, 2)


@pytest.mark.parametrize("boundary", ["approval", "job", "head", "receipt"])
def test_crash_boundaries_roll_back_approval_job_head_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    store, protected, values = _attempt(tmp_path)
    original = store.get_approval_request(protected["approval_request_id"])
    if boundary == "approval":

        def fail_reservation(*_args: Any, **_kwargs: Any):
            raise RuntimeError("crash after approval consumption")

        monkeypatch.setattr(engine_jobs, "reserve_engine_attempt_submission_at", fail_reservation)
    elif boundary == "head":
        append = engine_jobs._append_experiment_at

        def fail_append(*args: Any, **kwargs: Any):
            append(*args, **kwargs)
            raise RuntimeError("crash after experiment append")

        monkeypatch.setattr(engine_jobs, "_append_experiment_at", fail_append)
    else:
        table = "jobs" if boundary == "job" else "engine_action_acceptances"
        with sqlite3.connect(store.path) as connection:
            connection.execute(f"""CREATE TRIGGER synthetic_crash AFTER INSERT ON {table}
                BEGIN SELECT RAISE(ABORT, 'synthetic crash'); END""")
    with pytest.raises((RuntimeError, sqlite3.IntegrityError)):
        _accept(store, values)
    assert store.get_approval_request(protected["approval_request_id"]) == original
    assert _counts(store) == (0, 0, 1)
    assert _receipt(store, values) is None
    monkeypatch.undo()
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER IF EXISTS synthetic_crash")
    assert _accept(store, values)[1] is True
    assert _counts(store) == (1, 1, 2)


def test_accepted_restart_retry_precedes_expiry_head_and_workspace_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, protected, values = _attempt(tmp_path)
    job, _ = _accept(store, values)
    receipt = _receipt(store, values)
    current = store.get_engine_experiment(EXPERIMENT_ID)
    experiment = EngineExperiment._from_controller_mapping(current["document"])
    changed = replace(
        experiment,
        revision=experiment.revision + 1,
        previous_revision_digest=experiment.digest,
        updated_at=experiment.updated_at,
    )
    store.save_engine_experiment(
        EXPERIMENT_ID,
        changed.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validator,
    )
    expired = _iso(
        datetime.fromisoformat(protected["expires_at"].replace("Z", "+00:00")) + timedelta(days=1)
    )
    monkeypatch.setattr(submissions, "utc_now", lambda: expired)
    restarted = ProductStore(store.path)

    def unavailable(_record: Mapping[str, Any]) -> None:
        raise AssertionError("an accepted retry must not rebuild the workspace")

    assert restarted.accept_engine_action_preparation(**values, validate_workspace=unavailable) == (
        job,
        False,
    )
    assert _receipt(restarted, values) == receipt
    assert _counts(restarted) == (1, 1, 3)


def test_expired_unaccepted_action_and_stale_workspace_leave_pending_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, protected, values = _attempt(tmp_path)
    pending = store.get_approval_request(protected["approval_request_id"])

    def stale(_record: Mapping[str, Any]) -> None:
        raise ResourceConflictError("workspace drift")

    with pytest.raises(ResourceConflictError, match="workspace drift"):
        store.accept_engine_action_preparation(**values, validate_workspace=stale)
    monkeypatch.setattr(submissions, "utc_now", lambda: protected["expires_at"])
    with pytest.raises(ProductStoreError, match="expired"):
        _accept(store, values)
    assert store.get_approval_request(protected["approval_request_id"]) == pending
    assert _counts(store) == (0, 0, 1)


def test_claimed_exact_job_without_receipt_recovers_without_current_head_or_time_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, protected, values = _attempt(tmp_path)
    job, _ = _accept(store, values)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER engine_action_acceptances_no_delete")
        connection.execute("DELETE FROM engine_action_acceptances")
    monkeypatch.setattr(submissions, "utc_now", lambda: protected["expires_at"])

    def unavailable(_record: Mapping[str, Any]) -> None:
        raise AssertionError("legacy exact claim already has its reservation")

    assert store.accept_engine_action_preparation(**values, validate_workspace=unavailable) == (
        job,
        False,
    )
    assert _receipt(store, values)["job"]["job_id"] == job["job_id"]
    assert _counts(store) == (1, 1, 2)


def test_claimed_approval_without_exact_job_is_integrity_failure(tmp_path: Path) -> None:
    store, protected, values = _attempt(tmp_path)
    consumed = _approve(store, protected, consume=True)
    store.claim_consumed_approval(
        protected["approval_request_id"],
        nonce=consumed["nonce"],
        approved_by=REVIEWER,
        expected_state_digest=consumed["state_digest"],
        expected_plan_digest=consumed["plan_digest"],
        expected_target_scope_digest=consumed["target_scope_digest"],
        expected_profile_id=consumed["profile_id"],
        expected_maximum_tier=consumed["maximum_tier"],
    )
    with pytest.raises(ProductStoreError, match="no exact job"):
        _accept(store, values)
    assert _counts(store) == (0, 0, 1)


def test_recovery_repairs_only_proven_claim_and_returns_receipt_without_enqueue(
    tmp_path: Path,
) -> None:
    store, _protected, values = _attempt(tmp_path)
    assert store.recover_engine_action_acceptance(**values) is None
    job, _created = _accept(store, values)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER engine_action_acceptances_no_delete")
        connection.execute("DELETE FROM engine_action_acceptances")
    recovered = ProductStore(store.path).recover_engine_action_acceptance(**values)
    assert recovered is not None
    assert recovered == _receipt(store, values)
    assert recovered["job"] == {"job_id": job["job_id"], "kind": "engine-attempt"}
    assert _counts(store) == (1, 1, 2)


@pytest.mark.parametrize(
    ("tamper", "recovery"),
    [
        ("time", False),
        ("unrelated_record", False),
        ("unrelated_record", True),
    ],
)
def test_complete_reserved_successor_is_pinned_even_after_self_consistent_row_rewrite(
    tmp_path: Path, recovery: bool, tamper: str
) -> None:
    store, _protected, values = _attempt(tmp_path)
    _accept(store, values)
    reserved = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment(EXPERIMENT_ID)["document"]
    )
    if tamper == "time":
        changed_time = _iso(
            datetime.fromisoformat(reserved.updated_at.replace("Z", "+00:00"))
            - timedelta(microseconds=1)
        )
        changed = replace(reserved, updated_at=changed_time)
    else:
        entry = reserved.attempts[0]
        changed = replace(
            reserved,
            attempts=(
                replace(
                    entry,
                    record=replace(
                        entry.record, limitations=("Unrelated retained record was rewritten",)
                    ),
                ),
            ),
        )
    changed.validate()
    with sqlite3.connect(store.path) as connection:
        if recovery:
            connection.execute("DROP TRIGGER engine_action_acceptances_no_delete")
            connection.execute("DELETE FROM engine_action_acceptances")
        connection.execute("DROP TRIGGER engine_experiment_versions_no_update")
        connection.execute(
            "UPDATE engine_experiment_versions SET document_json = ?, digest = ? WHERE revision = 2",
            (canonical_json(changed.to_dict()), changed.digest),
        )
    with pytest.raises(ProductStoreError):
        if recovery:
            store.recover_engine_action_acceptance(**values)
        else:
            _receipt(store, values)
    assert _counts(store) == (1, 0 if recovery else 1, 2)


def test_future_claim_cannot_reconstruct_acceptance_even_with_matching_job_time(
    tmp_path: Path,
) -> None:
    store, protected, values = _attempt(tmp_path)
    job, _ = _accept(store, values)
    approval = store.get_approval_request(protected["approval_request_id"])
    future = _iso(
        datetime.fromisoformat(approval["claimed_at"].replace("Z", "+00:00"))
        + timedelta(seconds=30)
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER engine_action_acceptances_no_delete")
        connection.execute("DELETE FROM engine_action_acceptances")
        connection.execute(
            "UPDATE approval_requests SET claimed_at = ? WHERE approval_id = ?",
            (future, approval["approval_id"]),
        )
        connection.execute(
            "UPDATE jobs SET created_at = ? WHERE job_id = ?", (future, job["job_id"])
        )
    with pytest.raises(ProductStoreError, match="fixed job time"):
        store.recover_engine_action_acceptance(**values)
    assert _counts(store) == (1, 0, 2)


@pytest.mark.parametrize(
    "tamper", ["withdrawn", "reviewer", "nonce", "chronology", "binding", "expiry"]
)
def test_conflicting_approval_states_fail_closed_without_job(tmp_path: Path, tamper: str) -> None:
    store, protected, values = _attempt(tmp_path)
    approved = _approve(store, protected, consume=True)
    changes = {
        "withdrawn": ("status", "withdrawn"),
        "reviewer": ("approved_by", "untrusted-browser"),
        "nonce": ("nonce", ""),
        "chronology": ("consumed_at", "2026-01-01T00:00:00Z"),
        "binding": ("state_digest", "sha256:" + "0" * 64),
        "expiry": ("expires_at", _iso(datetime.now(timezone.utc) + timedelta(hours=1))),
    }
    field, value = changes[tamper]
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            f"UPDATE approval_requests SET {field} = ? WHERE approval_id = ?",
            (value, approved["approval_id"]),
        )
    with pytest.raises((ProductStoreError, ValueError)):
        _accept(store, values)
    assert _counts(store) == (0, 0, 1)


@pytest.mark.parametrize("tamper", ["job", "context", "preparation", "receipt", "approval"])
def test_accepted_retry_rechecks_retained_integrity(tmp_path: Path, tamper: str) -> None:
    store, protected, values = _attempt(tmp_path)
    job, _ = _accept(store, values)
    with sqlite3.connect(store.path) as connection:
        if tamper == "job":
            request = dict(job["request"])
            request["attempt_id"] = "engine-attempt-" + "b" * 32
            connection.execute(
                "UPDATE jobs SET request_json = ? WHERE job_id = ?",
                (canonical_json(request), job["job_id"]),
            )
        elif tamper == "context":
            progress = dict(job["progress"])
            progress["_engine_execution"] = {}
            connection.execute(
                "UPDATE jobs SET progress_json = ? WHERE job_id = ?",
                (canonical_json(progress), job["job_id"]),
            )
        elif tamper == "preparation":
            connection.execute("DROP TRIGGER engine_action_preparations_no_update")
            connection.execute(
                "UPDATE engine_action_preparations SET limits_digest = ?", ("sha256:" + "0" * 64,)
            )
        elif tamper == "receipt":
            connection.execute("DROP TRIGGER engine_action_acceptances_no_update")
            connection.execute("UPDATE engine_action_acceptances SET receipt_json = '{}' ")
        else:
            connection.execute("UPDATE approval_requests SET nonce = 'changed-after-acceptance'")
    with pytest.raises((ProductStoreError, ValueError)):
        _receipt(store, values)
    assert _counts(store) == (1, 1, 2)


def test_acceptance_rows_are_append_only(tmp_path: Path) -> None:
    store, _protected, values = _attempt(tmp_path)
    _accept(store, values)
    with sqlite3.connect(store.path) as connection:
        for statement in (
            "DELETE FROM engine_action_acceptances",
            "UPDATE engine_action_acceptances SET approval_digest = NULL",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
        row = connection.execute("SELECT * FROM engine_action_acceptances").fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT OR REPLACE INTO engine_action_acceptances VALUES (?, ?, ?, ?, ?, ?, ?)", row
            )


def test_review_transition_is_exact_idempotent_and_creates_no_job(tmp_path: Path) -> None:
    prepared_at, expires_at, _ = _times()
    plan = _defense_plan(prepared_at)
    experiment, reviewed, _unknown, _applied = _tenant_defense_states(plan)
    assert reviewed.defense_change is not None
    store = _store_experiment(tmp_path, experiment)
    authority = _material_authority(
        "tenant_defense_review",
        {
            "schema_version": "bluefire.tenant-defense-review-authority.v1",
            "plan": plan,
            "proposed_change": reviewed.defense_change.to_dict(),
        },
    )
    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REVIEW_DEFENSE,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda _approval, _submission: (None, authority),
    )
    values = {
        "experiment_id": experiment.experiment_id,
        "preparation_id": store.prepared_engine_action(protected["request_ref"])["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    receipt, created = _accept(store, values)
    assert created is True and receipt["job"] is None
    assert receipt["transition"] == {"revision": reviewed.revision, "digest": reviewed.digest}
    assert store.get_engine_experiment(experiment.experiment_id)["document"] == reviewed.to_dict()
    assert _accept(store, values) == (receipt, False)
    assert _receipt(store, values) == receipt
    assert _counts(store) == (0, 1, 2)


@pytest.mark.parametrize(
    ("action", "operation", "applied"),
    [
        (EngineWorkspaceAction.APPLY_DEFENSE, DefenseOperation.APPLY, False),
        (EngineWorkspaceAction.ROLLBACK_DEFENSE, DefenseOperation.ROLLBACK, True),
    ],
)
def test_defense_job_acceptance_preserves_exact_request_without_beginning_effect(
    tmp_path: Path, action: EngineWorkspaceAction, operation: DefenseOperation, applied: bool
) -> None:
    prepared_at, expires_at, _ = _times()
    reviewed_at, review_expires_at, _ = _times(offset=-10)
    plan = _defense_plan(reviewed_at)
    store, experiment = _store_tenant_defense_history(
        tmp_path, plan=plan, expires_at=review_expires_at, applied=applied
    )
    assert experiment.defense_change is not None
    request = _controller_jobs(_ControllerRepository(experiment)).prepare_defense_operation(
        experiment_id=experiment.experiment_id,
        change_id=experiment.defense_change.change_id,
        operation=operation,
    )
    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=action,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda _approval, _submission: (
            request,
            _material_authority("tenant_defense_plan", plan),
        ),
    )
    values = {
        "experiment_id": experiment.experiment_id,
        "preparation_id": store.prepared_engine_action(protected["request_ref"])["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    before = store.get_engine_experiment(experiment.experiment_id)
    job, created = _accept(store, values)
    assert created is True and job["kind"] == "engine-controller-operation"
    stored = dict(job["request"])
    stored.pop("_submission")
    assert stored == request
    assert store.get_engine_experiment(experiment.experiment_id) == before
    assert _receipt(store, values)["job"] == {"job_id": job["job_id"], "kind": job["kind"]}
    assert _accept(store, values) == (job, False)


def test_controller_check_acceptance_reserves_exact_typed_input_and_job(tmp_path: Path) -> None:
    experiment, mechanism = _applied_tenant_mechanism_experiment()
    store = _store_experiment(tmp_path, experiment)
    prepared_at, expires_at, _ = _times()
    request, authority = _prepared_controller_check_material(
        experiment, mechanism, reserved_at=prepared_at
    )
    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.REPEAT_MECHANISM,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda _approval, _submission: (request, authority),
    )
    values = {
        "experiment_id": experiment.experiment_id,
        "preparation_id": store.prepared_engine_action(protected["request_ref"])["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    job, created = _accept(store, values)
    assert created is True and job["kind"] == "engine-controller-check"
    current = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment(experiment.experiment_id)["document"]
    )
    assert current.checks[-1].job_id == job["job_id"]
    assert current.checks[-1].input_digest == request["input_digest"]
    assert _receipt(store, values)["job"] == {"job_id": job["job_id"], "kind": job["kind"]}
    assert _accept(store, values) == (job, False)


def test_legitimate_use_acceptance_preserves_exact_named_check(tmp_path: Path) -> None:
    completed = build_completed_experiment()
    assert completed.defense_change is not None
    mechanism = _failure_mechanism()
    mechanism_ref = content_hash(mechanism.to_dict())
    legitimate = completed.checks[-1]
    experiment = replace(
        completed,
        revision=1,
        previous_revision_digest=None,
        defense_change=replace(
            completed.defense_change,
            state=DefenseState.APPLIED,
            retained_at=None,
            mechanism_ref=mechanism_ref,
        ),
        checks=tuple(
            replace(check, mechanism_ref=mechanism_ref) for check in completed.checks[:-1]
        ),
        independent_observations=tuple(
            _controller_observation_record(
                target_snapshot_ref=observation.target_snapshot_ref,
                mechanism_ref=mechanism_ref,
                evidence=observation.evidence,
                attempt_id=observation.attempt_id,
                check_id=observation.check_id,
                check_input_digest=observation.check_input_digest,
            )
            for observation in completed.independent_observations
            if observation.check_id != legitimate.check_id
        ),
    )
    experiment.validate()
    store = _store_experiment(tmp_path, experiment)
    prepared_at, expires_at, _ = _times()
    builder = EngineControllerJobs(
        controller=cast(Any, None),
        repository=_ControllerRepository(experiment),
        defense_executor=None,
        check_executor=None,
        clock=lambda: prepared_at,
    )
    assert experiment.current_target_snapshot_ref is not None
    request = builder.prepare_controller_check(
        experiment_id=experiment.experiment_id,
        check_id="controller-check-" + "f" * 32,
        run_id="run-20261104T122000Z-" + "f" * 16,
        role=ControllerCheckRole.LEGITIMATE_USE,
        mechanism_ref=mechanism_ref,
        target_snapshot_ref=experiment.current_target_snapshot_ref,
        input_digest="sha256:" + "e" * 64,
        reserved_at=prepared_at,
    )
    authority = _material_authority(
        "tenant_controller_check",
        {
            "schema_version": "bluefire.tenant-controller-check-authority.v1",
            "mechanism": mechanism.to_dict(),
            **{
                field: request[field]
                for field in ("check_id", "run_id", "role", "input_digest", "reserved_at")
            },
        },
    )
    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.RUN_LEGITIMATE_USE,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at=expires_at,
        protected_factory=lambda _approval, _submission: (request, authority),
    )
    values = {
        "experiment_id": experiment.experiment_id,
        "preparation_id": store.prepared_engine_action(protected["request_ref"])["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    job, created = _accept(store, values)
    assert created is True and job["kind"] == "engine-controller-check"
    current = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment(experiment.experiment_id)["document"]
    )
    assert current.checks[-1].role is ControllerCheckRole.LEGITIMATE_USE
    assert current.checks[-1].input_digest == request["input_digest"]
    assert _accept(store, values) == (job, False)
    assert _receipt(store, values)["action_kind"] == "run_legitimate_use"


def test_retain_transition_uses_retained_plan_and_only_appends_pure_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_at = "2026-11-04T12:06:00Z"
    monkeypatch.setattr(preparations, "utc_now", lambda: reviewed_at)
    plan = _defense_plan(reviewed_at)
    store, applied = _store_tenant_defense_history(
        tmp_path, plan=plan, expires_at="2026-11-04T12:11:00Z", applied=True
    )
    completed = build_completed_experiment()
    assert applied.defense_change is not None
    after = applied.defense_change.after_target_snapshot_ref
    adaptive = completed.attempts[-1]
    rebound = replace(adaptive.record.binding, target_snapshot_ref=after)
    experiment = replace(
        completed,
        revision=applied.revision + 1,
        previous_revision_digest=applied.digest,
        initial_target_snapshot_ref=applied.initial_target_snapshot_ref,
        current_target_snapshot_ref=after,
        defense_change=applied.defense_change,
        attempts=(
            applied.attempts[0],
            replace(
                adaptive,
                record=replace(
                    adaptive.record, binding=rebound, binding_digest=rebound.binding_digest
                ),
            ),
        ),
        checks=tuple(replace(check, target_snapshot_ref=after) for check in completed.checks),
        independent_observations=(applied.independent_observations[0],)
        + tuple(
            _controller_observation_record(
                target_snapshot_ref=after,
                mechanism_ref=observation.mechanism_ref,
                evidence=observation.evidence,
                attempt_id=observation.attempt_id,
                check_id=observation.check_id,
                check_input_digest=observation.check_input_digest,
            )
            for observation in completed.independent_observations[1:]
        ),
    )
    experiment.validate()
    store.save_engine_experiment(
        experiment.experiment_id,
        experiment.to_dict(),
        expected_revision=applied.revision,
        expected_digest=applied.digest,
        validator=_validator,
    )
    prepared_at = "2026-11-04T12:20:00Z"
    monkeypatch.setattr(preparations, "utc_now", lambda: prepared_at)
    monkeypatch.setattr(submissions, "utc_now", lambda: prepared_at)
    protected = store.create_engine_action_preparation(
        experiment_id=experiment.experiment_id,
        experiment_revision=experiment.revision,
        experiment_digest=experiment.digest,
        workspace_digest=WORKSPACE_REF,
        action=EngineWorkspaceAction.RETAIN_DEFENSE,
        limits=_controller_limits(),
        prepared_at=prepared_at,
        expires_at="2026-11-04T12:25:00Z",
        protected_factory=lambda _approval, _submission: (
            None,
            _material_authority("tenant_defense_plan", plan),
        ),
    )
    values = {
        "experiment_id": experiment.experiment_id,
        "preparation_id": store.prepared_engine_action(protected["request_ref"])["preparation_id"],
        "request_ref": protected["request_ref"],
        "reviewer": REVIEWER,
    }
    expected = experiment.retain_defense(applied.defense_change.change_id, retained_at=prepared_at)
    before_counts = _counts(store)
    receipt, created = _accept(store, values)
    assert created is True and receipt["job"] is None
    assert receipt["transition"] == {"revision": expected.revision, "digest": expected.digest}
    assert store.get_engine_experiment(experiment.experiment_id)["document"] == expected.to_dict()
    assert _accept(store, values) == (receipt, False)
    assert _receipt(store, values) == receipt
    assert _counts(store) == (before_counts[0], 1, before_counts[2] + 1)


def test_schema16_upgrade_preserves_retained_preparation_and_enables_acceptance(
    tmp_path: Path,
) -> None:
    store, protected, values = _attempt(tmp_path)
    before = store.get_protected_engine_action_preparation(protected["request_ref"])
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE engine_action_acceptances")
        connection.execute("DELETE FROM schema_migrations WHERE version = 17")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations VALUES (16, '2026-11-04T00:00:00Z')"
        )
    upgraded = ProductStore(store.path)
    assert upgraded.schema_version == 17
    assert upgraded.get_protected_engine_action_preparation(protected["request_ref"]) == before
    assert _accept(upgraded, values)[1] is True


def test_schema_initialization_requires_existing_transaction() -> None:
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ProductStoreError, match="requires one transaction"):
            submissions.initialize_schema(connection)
