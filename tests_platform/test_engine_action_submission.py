from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, cast

import pytest

import bluefire.product_store_engine_action_submissions as submission_store
from bluefire.engine_action_submission import (
    EngineActionSubmissionCoordinator,
    EngineActionSubmissionServiceError,
)
from bluefire.engine_experiment import EngineExperiment
from bluefire.engine_experiment_jobs import EngineExperimentJobs
from bluefire.engine_experiment_service import (
    EngineExperimentService,
    EngineExperimentServiceError,
)
from bluefire.job_runtime import JobQueueFull, JobRuntimeClosed, RunJobController
from bluefire.product_store import ProductStore
from bluefire.util import content_hash, parse_iso8601_datetime
from tests_platform.test_product_store_engine_actions import (
    EXPERIMENT_ID,
    WORKSPACE_REF,
    _ActionStore,
    _create_attempt,
    _store,
    _times,
    _validator,
)

REVIEWER = "bluefire.local-operator"


class _Workspace:
    def __init__(self, store: ProductStore) -> None:
        record = store.get_engine_experiment(EXPERIMENT_ID)
        self.value: Mapping[str, Any] = {
            "schema_version": "bluefire.engine-experiment-workspace.v1",
            "experiment_id": EXPERIMENT_ID,
            "revision": record["revision"],
            "experiment_digest": record["digest"],
            "workspace_digest": WORKSPACE_REF,
            "actions": [{"kind": "start_baseline", "enabled": True}],
        }
        self.calls = 0
        self.failure: Exception | None = None

    def workspace(self, experiment_id: str) -> Mapping[str, Any]:
        assert experiment_id == EXPERIMENT_ID
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return self.value


class _Gate:
    """The JobController persistence gate, with no worker or effect callback."""

    def __init__(self, store: ProductStore) -> None:
        self.store = store
        self.calls: list[Mapping[str, Any]] = []
        self.failure: Exception | None = None
        self.factory_calls = 0

    def submit(
        self,
        kind: str,
        request: Mapping[str, Any],
        *,
        submission_id: str,
        intent_digest: str,
        submission_factory: Callable[[], tuple[Mapping[str, Any], bool]],
        **values: Any,
    ) -> Mapping[str, Any]:
        self.calls.append(
            {
                "kind": kind,
                "request": request,
                "submission_id": submission_id,
                "intent_digest": intent_digest,
                **values,
            }
        )
        if self.failure is not None:
            raise self.failure
        existing = self.store.get_job_submission(
            kind, submission_id=submission_id, intent_digest=intent_digest
        )
        if existing is not None:
            return existing
        self.factory_calls += 1
        result, _created = submission_factory()
        return result


def _prepared(tmp_path: Path) -> tuple[_ActionStore, Mapping[str, Any], Mapping[str, Any]]:
    store = _store(tmp_path)
    prepared_at, expires_at, _ = _times()
    protected = _create_attempt(store, prepared_at=prepared_at, expires_at=expires_at)
    public = store.prepared_engine_action(protected["request_ref"])
    request = {
        "schema_version": "bluefire.engine-action-submit.v1",
        "preparation_id": public["preparation_id"],
        "protected_request_ref": public["protected_request_ref"],
    }
    return store, protected, request


def _coordinator(
    store: ProductStore,
    *,
    gate: Any = None,
    workspace: _Workspace | None = None,
    runtime: Any = True,
    reviewer: str = REVIEWER,
) -> tuple[EngineActionSubmissionCoordinator, _Gate, _Workspace]:
    selected_gate = gate if gate is not None else _Gate(store)
    selected_workspace = workspace if workspace is not None else _Workspace(store)
    jobs = EngineExperimentJobs(
        controller=cast(Any, selected_gate),
        repository=store,
        runtime=cast(Any, object()) if runtime else None,
        clock=lambda: "2026-11-04T12:00:00Z",
    )
    coordinator = EngineActionSubmissionCoordinator(
        history=store,
        workspace_source=selected_workspace,
        jobs=jobs,
        controller_jobs=None,
        reviewer=reviewer,
    )
    return coordinator, selected_gate, selected_workspace


def _assert_pending(store: ProductStore, protected: Mapping[str, Any]) -> None:
    approval = store.get_approval_request(protected["approval_request_id"])
    assert approval["status"] == "pending"
    assert approval["nonce"] is None
    assert approval["approved_by"] is None
    assert store.list_jobs() == []
    assert store.get_engine_experiment(EXPERIMENT_ID)["revision"] == 1


def test_submit_derives_exact_inner_request_and_returns_only_safe_receipt(tmp_path: Path) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)

    result = coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)

    assert set(result) == {
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
    assert result["schema_version"] == "bluefire.engine-action-acceptance.v1"
    assert result["job"]["kind"] == "engine-attempt"
    assert result["transition"] is None
    assert workspace.calls == 1
    assert len(gate.calls) == gate.factory_calls == 1
    call = gate.calls[0]
    assert call["kind"] == "engine-attempt"
    assert call["request"] == protected["protected_request"]["job_request"]
    assert call["submission_id"] == protected["submission_id"]
    assert call["intent_digest"] == protected["intent_digest"] == content_hash(call["request"])
    assert call["intent_digest"] != content_hash(protected["protected_request"])
    approval = store.get_approval_request(protected["approval_request_id"])
    assert approval["status"] == "claimed"
    assert approval["approved_by"] == REVIEWER
    encoded = json.dumps(result)
    for private in ("authority", "approved_by", "nonce", "approval_id", "delegation", "binding"):
        assert private not in encoded
    assert approval["nonce"] not in encoded
    assert REVIEWER not in encoded


@pytest.mark.parametrize(
    "field",
    [
        "approved_by",
        "reviewer",
        "approval_id",
        "approval_nonce",
        "nonce",
        "token",
        "action",
        "expected_revision",
        "expected_digest",
        "workspace_digest",
        "limits",
        "submission_id",
        "intent_digest",
        "authority",
        "binding",
        "job_request",
    ],
)
def test_submit_rejects_every_extra_caller_authority_field(tmp_path: Path, field: str) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)
    with pytest.raises(EngineActionSubmissionServiceError) as failure:
        coordinator.submit(experiment_id=EXPERIMENT_ID, request={**request, field: "caller-value"})
    assert failure.value.code == "engine_request_invalid"
    assert gate.calls == []
    assert workspace.calls == 0
    _assert_pending(store, protected)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "bluefire.engine-action-submit.v2"),
        ("preparation_id", None),
        ("preparation_id", 1),
        ("preparation_id", "sha256:" + "A" * 64),
        ("protected_request_ref", " " + "sha256:" + "a" * 64),
        ("protected_request_ref", {"value": "sha256:" + "a" * 64}),
    ],
)
def test_submit_rejects_noncanonical_handles_without_admission(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)
    with pytest.raises(EngineActionSubmissionServiceError) as failure:
        coordinator.submit(experiment_id=EXPERIMENT_ID, request={**request, field: value})
    assert failure.value.code == "engine_request_invalid"
    assert gate.calls == []
    assert workspace.calls == 0
    _assert_pending(store, protected)


@pytest.mark.parametrize("failure", [JobQueueFull("full"), JobRuntimeClosed("closed")])
def test_queue_gate_refusal_never_advances_pending_approval(
    tmp_path: Path,
    failure: Exception,
) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)
    gate.failure = failure
    with pytest.raises(EngineActionSubmissionServiceError) as refused:
        coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
    assert refused.value.code == "engine_action_submission_refused"
    assert workspace.calls == 0
    assert gate.factory_calls == 0
    _assert_pending(store, protected)


def test_missing_runtime_refuses_before_gate_and_approval(tmp_path: Path) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store, runtime=False)
    with pytest.raises(EngineActionSubmissionServiceError) as failure:
        coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
    assert failure.value.code == "engine_action_submission_refused"
    assert gate.calls == []
    assert workspace.calls == 0
    _assert_pending(store, protected)


@pytest.mark.parametrize("change", ["digest", "action", "disabled"])
def test_workspace_is_rechecked_inside_admission_before_approval(
    tmp_path: Path,
    change: str,
) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)
    if change == "digest":
        workspace.value = {**workspace.value, "workspace_digest": "sha256:" + "f" * 64}
    else:
        workspace.value = {
            **workspace.value,
            "actions": [
                {
                    "kind": "start_adaptive_search" if change == "action" else "start_baseline",
                    "enabled": change != "disabled",
                }
            ],
        }
    with pytest.raises(EngineActionSubmissionServiceError):
        coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
    assert gate.factory_calls == workspace.calls == 1
    _assert_pending(store, protected)


def test_retry_after_restart_expiry_and_new_head_precedes_runtime_and_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, protected, request = _prepared(tmp_path)
    coordinator, gate, _workspace = _coordinator(store)
    accepted = coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
    current = store.get_engine_experiment(EXPERIMENT_ID)
    experiment = EngineExperiment._from_controller_mapping(current["document"])
    updated = replace(
        experiment,
        revision=experiment.revision + 1,
        previous_revision_digest=experiment.digest,
        updated_at=experiment.updated_at,
    )
    store.save_engine_experiment(
        EXPERIMENT_ID,
        updated.to_dict(),
        expected_revision=experiment.revision,
        expected_digest=experiment.digest,
        validator=_validator,
    )
    after_expiry = parse_iso8601_datetime(protected["expires_at"]) + timedelta(days=1)
    monkeypatch.setattr(
        submission_store, "utc_now", lambda: after_expiry.isoformat().replace("+00:00", "Z")
    )
    restarted = ProductStore(store.path)
    unavailable, retry_gate, retry_workspace = _coordinator(restarted, runtime=False)
    retry_workspace.failure = AssertionError("accepted retry must not project workspace")
    retry_gate.failure = AssertionError("accepted retry must not revisit queue")

    assert unavailable.submit(experiment_id=EXPERIMENT_ID, request=request) == accepted
    assert retry_gate.calls == []
    assert retry_workspace.calls == 0
    assert len(gate.calls) == 1
    assert len(store.list_jobs()) == 1


def test_claimed_exact_job_without_receipt_is_recovered_without_reenqueue(tmp_path: Path) -> None:
    store, _protected, request = _prepared(tmp_path)
    coordinator, gate, workspace = _coordinator(store)
    accepted = coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER engine_action_acceptances_no_delete")
        connection.execute("DELETE FROM engine_action_acceptances")
    workspace.failure = AssertionError("claimed recovery must use retained reservation")

    recovered = coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)

    assert recovered["job"] == accepted["job"]
    assert len(store.list_jobs()) == 1
    assert gate.factory_calls == 1


def test_scheduling_failure_retains_acceptance_and_retry_never_enqueues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, protected, request = _prepared(tmp_path)
    controller = RunJobController(store, max_workers=1, recover_on_start=False)
    coordinator, _gate, workspace = _coordinator(store, gate=controller)
    calls: list[bool] = []

    def refuse_schedule(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        calls.append(True)
        raise RuntimeError("executor scheduling unavailable")

    monkeypatch.setattr(controller._executor, "submit", refuse_schedule)
    try:
        with pytest.raises(EngineActionSubmissionServiceError) as failure:
            coordinator.submit(experiment_id=EXPERIMENT_ID, request=request)
        assert failure.value.code == "engine_action_submission_refused"
        assert store.list_jobs()[0]["state"] == "failed"
        accepted = store.get_engine_action_acceptance(
            experiment_id=EXPERIMENT_ID,
            preparation_id=request["preparation_id"],
            request_ref=request["protected_request_ref"],
            reviewer=REVIEWER,
        )
        assert accepted is not None
        workspace.failure = AssertionError("accepted retry must not project workspace")
        assert coordinator.submit(experiment_id=EXPERIMENT_ID, request=request) == accepted
        assert calls == [True]
        assert store.get_approval_request(protected["approval_request_id"])["status"] == "claimed"
    finally:
        controller.shutdown()


def test_service_delegates_exact_request_and_maps_safe_failure(tmp_path: Path) -> None:
    store, _protected, request = _prepared(tmp_path)
    coordinator, gate, _workspace = _coordinator(store)
    service = EngineExperimentService(
        history=store,
        run_source=cast(Any, object()),
        jobs=cast(Any, object()),
        job_lifecycle=cast(Any, object()),
        controller=None,
        clock=lambda: "unused",
        presentation_source=cast(Any, object()),
        action_submission=coordinator,
    )
    accepted = service.submit_prepared_action_request(EXPERIMENT_ID, request)
    assert accepted["job"]["job_id"] == store.list_jobs()[0]["job_id"]
    assert len(gate.calls) == 1
    with pytest.raises(EngineExperimentServiceError) as failure:
        service.submit_prepared_action_request(EXPERIMENT_ID, {**request, "reviewer": REVIEWER})
    assert failure.value.code == "engine_request_invalid"


def test_service_without_submission_coordinator_is_unavailable(tmp_path: Path) -> None:
    store, protected, request = _prepared(tmp_path)
    service = EngineExperimentService(
        history=store,
        run_source=cast(Any, object()),
        jobs=cast(Any, object()),
        job_lifecycle=cast(Any, object()),
        controller=None,
        clock=lambda: "unused",
        presentation_source=cast(Any, object()),
    )
    with pytest.raises(EngineExperimentServiceError) as failure:
        service.submit_prepared_action_request(EXPERIMENT_ID, request)
    assert failure.value.code == "engine_action_unavailable"
    _assert_pending(store, protected)


@pytest.mark.parametrize("reviewer", ["", " user", "user ", "user\nname", "x" * 201])
def test_local_operator_identity_must_be_canonical_at_injection(
    tmp_path: Path,
    reviewer: str,
) -> None:
    store, protected, _request = _prepared(tmp_path)
    with pytest.raises(ValueError, match="stable trusted local operator"):
        _coordinator(store, reviewer=reviewer)
    _assert_pending(store, protected)
