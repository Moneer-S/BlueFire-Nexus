from __future__ import annotations

from pathlib import Path

import pytest

import bluefire.service as service_module
from bluefire.application_errors import APIError
from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION, EngineExperiment
from bluefire.engine_experiment_service import EngineExperimentServiceError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import (
    ENVIRONMENT_REF,
    EXPERIMENT_ID,
    INITIAL_SNAPSHOT,
    OBJECTIVE_REF,
    SCOPE_REF,
)
from tests_platform.test_engine_experiment_jobs import SUBMISSION_ID, _authority
from tests_platform.test_engine_experiment_service import CREATED_AT
from tests_platform.test_product_store_engine_presentations import (
    _initial_target,
    _profile,
)


def _create_request() -> dict[str, object]:
    return {
        "schema_version": "bluefire.engine-experiment-create.v1",
        "experiment_id": EXPERIMENT_ID,
        "objective_ref": OBJECTIVE_REF,
        "environment_ref": ENVIRONMENT_REF,
        "scope_ref": SCOPE_REF,
        "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
        "target_snapshot_ref": INITIAL_SNAPSHOT,
    }


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BlueFireService:
    monkeypatch.setattr(service_module, "_engine_service_clock", lambda: CREATED_AT)
    return BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "state" / "bluefire.sqlite3",
    )


def test_default_service_refuses_unprovisioned_create_without_partial_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    try:
        with pytest.raises(EngineExperimentServiceError) as caught:
            service.engine_experiment_service.create_request(_create_request())

        assert caught.value.code == "engine_experiment_unavailable"
        assert service.product_store.list_engine_experiments() == []
    finally:
        service.close()


def test_default_product_store_presentation_supports_create_workspace_and_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    service.product_store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    try:
        created = service.engine_experiment_service.create_request(_create_request())
        reopened = service.engine_experiment_service.workspace(EXPERIMENT_ID)
    finally:
        service.close()

    assert created["schema_version"] == "bluefire.engine-experiment-workspace.v1"
    assert created["experiment_digest"] == reopened["experiment_digest"]
    assert created["actions"][0]["enabled"] is True

    restarted = _service(tmp_path, monkeypatch)
    try:
        after_restart = restarted.engine_experiment_service.workspace(EXPERIMENT_ID)
    finally:
        restarted.close()

    assert after_restart == reopened


def test_unconfigured_runtime_refuses_execution_without_faking_a_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    service.product_store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    try:
        workspace = service.engine_experiment_service.create_request(_create_request())
        binding, delegation, approval = _authority()
        saved = service.product_store.get_engine_experiment(EXPERIMENT_ID)
        experiment = EngineExperiment._from_controller_mapping(saved["document"])
        approval_id = "approval-" + "1" * 32
        intent = service.engine_attempt_jobs._request(
            experiment=experiment,
            binding=binding,
            delegation=delegation,
            approval=approval,
            approval_id=approval_id,
        )
        with pytest.raises(EngineExperimentServiceError) as caught:
            service.engine_experiment_service.submit_attempt_request(
                {
                    "schema_version": "bluefire.engine-attempt-submit.v1",
                    "experiment_id": EXPERIMENT_ID,
                    "binding": binding.to_dict(),
                    "delegation": delegation.to_dict(),
                    "approval_binding": approval.to_dict(),
                    "approval_id": approval_id,
                    "approval_nonce": "nonce",
                    "approved_by": "operator",
                    "submission_id": SUBMISSION_ID,
                    "intent_digest": content_hash(intent),
                    "expected_revision": workspace["revision"],
                    "expected_digest": workspace["experiment_digest"],
                }
            )

        assert caught.value.code == "engine_execution_refused"
        assert service.product_store.list_jobs() == []
    finally:
        service.close()


def test_default_product_service_captures_only_digest_bound_assistant_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    service.product_store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    try:
        workspace = service.engine_experiment_service.create_request(_create_request())
        selection = {
            "kind": "engine_experiment",
            "experiment_id": EXPERIMENT_ID,
            "workspace_digest": workspace["workspace_digest"],
            "attempt_id": None,
            "check_id": None,
        }
        context = service.engine_experiment_service.assistance_context_request(
            EXPERIMENT_ID,
            selection,
        )
        stale = dict(selection)
        stale["workspace_digest"] = "sha256:" + "f" * 64
        with pytest.raises(EngineExperimentServiceError) as caught:
            service.engine_experiment_service.assistance_context_request(
                EXPERIMENT_ID,
                stale,
            )
    finally:
        service.close()

    assert context["analysis_only"] is True
    assert context["capabilities"] == []
    assert context["selected"] == selection
    assert context["reference_summary"]["workspace_digest"] == workspace["workspace_digest"]
    assert caught.value.code == "engine_assistance_context_unavailable"


def test_generic_cancel_routes_engine_attempt_through_specialized_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "a" * 32
    attempt_id = "engine-attempt-" + "a" * 32
    stored = {
        "job_id": job_id,
        "kind": "engine-attempt",
        "request": {
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": attempt_id,
        },
    }
    calls: list[dict[str, str]] = []

    def cancel_attempt(**values):
        calls.append(values)
        return {"job": {"job_id": job_id, "state": "cancelled"}, "workspace": {}}

    monkeypatch.setattr(service.product_store, "get_job", lambda identifier: stored)
    monkeypatch.setattr(service._engine_experiment_service, "cancel_attempt", cancel_attempt)
    try:
        cancelled = service.cancel_job(job_id)
    finally:
        service.close()

    assert cancelled == {"job_id": job_id, "state": "cancelled"}
    assert calls == [
        {
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": attempt_id,
            "job_id": job_id,
        }
    ]


def test_generic_cancel_routes_controller_check_through_specialized_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "c" * 32
    check_id = "controller-check-" + "c" * 32
    stored = {
        "job_id": job_id,
        "kind": "engine-controller-check",
        "request": {
            "experiment_id": EXPERIMENT_ID,
            "check_id": check_id,
        },
    }
    calls: list[dict[str, str]] = []

    def cancel_controller_check(**values):
        calls.append(values)
        return {"job": {"job_id": job_id, "state": "cancelled"}, "workspace": {}}

    monkeypatch.setattr(service.product_store, "get_job", lambda identifier: stored)
    monkeypatch.setattr(
        service._engine_experiment_service,
        "cancel_controller_check",
        cancel_controller_check,
    )
    try:
        cancelled = service.cancel_job(job_id)
    finally:
        service.close()

    assert cancelled == {"job_id": job_id, "state": "cancelled"}
    assert calls == [
        {
            "experiment_id": EXPERIMENT_ID,
            "check_id": check_id,
            "job_id": job_id,
        }
    ]


def test_generic_controller_check_cancel_rejects_an_unbound_stored_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "d" * 32
    monkeypatch.setattr(
        service.product_store,
        "get_job",
        lambda identifier: {
            "job_id": identifier,
            "kind": "engine-controller-check",
            "request": {"experiment_id": EXPERIMENT_ID},
        },
    )
    try:
        with pytest.raises(APIError) as caught:
            service.cancel_job(job_id)
    finally:
        service.close()

    assert caught.value.status == 409
    assert caught.value.code == "job_signal_refused"


def test_generic_controller_check_cancel_returns_durable_terminal_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "e" * 32
    check_id = "controller-check-" + "e" * 32
    stored = {
        "job_id": job_id,
        "kind": "engine-controller-check",
        "request": {
            "experiment_id": EXPERIMENT_ID,
            "check_id": check_id,
        },
    }
    refreshed = {
        "job_id": job_id,
        "kind": "engine-controller-check",
        "state": "cancelled",
    }
    snapshots = iter((stored, refreshed))
    monkeypatch.setattr(service.product_store, "get_job", lambda _identifier: next(snapshots))

    def cancelled_without_workspace(**_values):
        raise EngineExperimentServiceError(
            "engine_workspace_unavailable",
            "post-cancellation rendering is unavailable",
        )

    monkeypatch.setattr(
        service._engine_experiment_service,
        "cancel_controller_check",
        cancelled_without_workspace,
    )
    try:
        cancelled = service.cancel_job(job_id)
    finally:
        service.close()

    assert cancelled == refreshed


def test_controller_job_factory_receives_the_service_owned_stores_and_controller(
    tmp_path: Path,
) -> None:
    class _ControllerJobs:
        def submit(self, **values):
            raise AssertionError(f"unexpected controller effect: {values}")

    adapter = _ControllerJobs()
    captured = []

    def factory(product_store, run_store, controller):
        captured.append((product_store, run_store, controller))
        return adapter

    service = BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "state" / "bluefire.sqlite3",
        engine_controller_jobs_factory=factory,
    )
    try:
        assert captured == [(service.product_store, service.store, service.job_controller)]
        assert service.engine_experiment_service._controller_jobs is adapter
    finally:
        service.close()


def test_generic_engine_cancel_rejects_an_unbound_stored_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "b" * 32
    monkeypatch.setattr(
        service.product_store,
        "get_job",
        lambda identifier: {
            "job_id": identifier,
            "kind": "engine-attempt",
            "request": {"experiment_id": EXPERIMENT_ID},
        },
    )
    try:
        with pytest.raises(APIError) as caught:
            service.cancel_job(job_id)
    finally:
        service.close()

    assert caught.value.status == 409
    assert caught.value.code == "job_signal_refused"


@pytest.mark.parametrize(
    "failure_code",
    ["engine_workspace_unavailable", "engine_execution_refused"],
)
def test_generic_engine_cancel_returns_fresh_job_after_durable_cancellation(
    failure_code: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    job_id = "job-" + "c" * 32
    attempt_id = "engine-attempt-" + "c" * 32
    stored = {
        "job_id": job_id,
        "kind": "engine-attempt",
        "request": {
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": attempt_id,
        },
    }
    refreshed = {"job_id": job_id, "kind": "engine-attempt", "state": "cancelled"}
    snapshots = iter((stored, refreshed))
    monkeypatch.setattr(service.product_store, "get_job", lambda _identifier: next(snapshots))

    def cancelled_without_workspace(**_values):
        raise EngineExperimentServiceError(
            failure_code,
            "post-cancellation settlement or rendering is unavailable",
        )

    monkeypatch.setattr(
        service._engine_experiment_service,
        "cancel_attempt",
        cancelled_without_workspace,
    )
    try:
        cancelled = service.cancel_job(job_id)
    finally:
        service.close()

    assert cancelled == refreshed


def test_controller_job_direct_and_factory_injection_are_mutually_exclusive(
    tmp_path: Path,
) -> None:
    adapter = object()

    with pytest.raises(ValueError, match="either engine controller jobs"):
        BlueFireService(
            project_root=Path(__file__).resolve().parents[1],
            runs_dir=tmp_path / "runs",
            product_db_path=tmp_path / "state" / "bluefire.sqlite3",
            engine_controller_jobs=adapter,  # type: ignore[arg-type]
            engine_controller_jobs_factory=lambda *_args: adapter,  # type: ignore[arg-type]
        )
