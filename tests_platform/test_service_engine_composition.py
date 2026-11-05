"""Service ownership of an explicitly supplied installed engine stays inert."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

import bluefire.service as service_module
from bluefire.engine_experiment_service import EngineExperimentServiceError
from bluefire.job_runtime import JobContext, RunJobController
from bluefire.product_store import ProductStoreError
from bluefire.service import BlueFireService
from tests_platform.test_engine_action_service_composition import PREPARE_REQUEST, SUBMIT_REQUEST
from tests_platform.test_engine_experiment import EXPERIMENT_ID
from tests_platform.test_engine_installed_composition import _configured, _Resource
from tests_platform.test_engine_product_service_splice import _create_request
from tests_platform.test_product_store_engine_presentations import _initial_target, _profile


def _service(tmp_path: Path, **values: Any) -> BlueFireService:
    return BlueFireService(
        project_root=Path(__file__).resolve().parents[1],
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        **values,
    )


def test_supplied_composition_wires_exact_shared_owners_and_inert_factories(tmp_path):
    configured = _configured()
    owner = configured.composition
    service = _service(tmp_path, engine_workflow_composition=owner)
    try:
        workspace = service.engine_experiment_service
        bound = owner.bind(service.product_store, workspace)
        assert service.engine_attempt_jobs._runtime is owner.runtime
        assert workspace._controller is owner.controller
        assert workspace._history is service.product_store
        assert workspace._run_source is service.store
        assert workspace._job_lifecycle is service.job_controller
        assert workspace._controller_jobs is owner._legacy_controller_jobs
        assert workspace._action_preparation is bound.preparation
        assert workspace._action_submission is bound.submission
        assert bound.submission._jobs is service.engine_attempt_jobs
        assert bound.submission._controller_jobs is owner._controller_jobs
        assert owner._job_controller is service.job_controller
        assert configured.events == []
        assert service.product_store.list_jobs() == []
    finally:
        service.close()


@pytest.mark.parametrize(
    "argument",
    [
        "engine_attempt_runtime",
        "engine_controller",
        "engine_controller_jobs",
        "engine_controller_jobs_factory",
        "engine_action_preparation_factory",
        "engine_action_submission_factory",
    ],
)
def test_composition_rejects_each_explicit_adapter_before_acquiring_ownership(tmp_path, argument):
    events = []
    configured = _configured(resources=(_Resource(events, "private owner"),))
    with pytest.raises(ValueError, match="either an engine workflow composition"):
        _service(
            tmp_path, engine_workflow_composition=configured.composition, **{argument: object()}
        )
    assert events == configured.events == []
    assert not (tmp_path / "product.sqlite3").exists()
    configured.composition.close()


def test_composition_workspace_reads_have_no_protected_effects(tmp_path):
    configured = _configured()
    service = _service(tmp_path, engine_workflow_composition=configured.composition)
    try:
        service.product_store.provision_engine_experiment_presentation(
            EXPERIMENT_ID,
            _profile(),
            _initial_target(),
        )
        service.engine_experiment_service.create_request(_create_request())
        before = service.product_store.get_engine_experiment(EXPERIMENT_ID)
        first = service.engine_experiment_service.workspace(EXPERIMENT_ID)
        assert service.engine_experiment_service.workspace(EXPERIMENT_ID) == first
        assert service.product_store.get_engine_experiment(EXPERIMENT_ID) == before
        assert service.product_store.list_jobs() == []
        assert configured.events == []
    finally:
        service.close()


def test_close_cancels_and_joins_workers_before_closing_composition_once(tmp_path, monkeypatch):
    events = []
    configured = _configured(resources=(_Resource(events, "protected transports"),))
    service = _service(tmp_path, engine_workflow_composition=configured.composition)
    original_shutdown = service.job_controller.shutdown
    started = threading.Event()

    def shutdown(*, cancel_active=True):
        events.append("shutdown")
        original_shutdown(cancel_active=cancel_active)
        events.append("joined")

    def worker(context: JobContext, _request):
        started.set()
        assert context.cancellation_event.wait(10)
        events.append("cancelled")
        context.checkpoint()
        raise AssertionError("cancelled worker must stop")

    monkeypatch.setattr(service.job_controller, "shutdown", shutdown)
    try:
        submitted = service.job_controller.submit("composition-owner-test", {}, callback=worker)
        assert started.wait(10)
    finally:
        service.close()
    service.close()
    assert events == ["shutdown", "cancelled", "joined", ("close", "protected transports")]
    assert service.product_store.get_job(submitted["job_id"])["state"] == "cancelled"


@pytest.mark.parametrize("phase", ["before_bind", "after_bind", "prepare", "submit", "late"])
def test_constructor_failure_closes_only_acquired_owners_once(tmp_path, monkeypatch, phase):
    events = []
    configured = _configured(resources=(_Resource(events, "protected transports"),))
    owner = configured.composition
    failure = RuntimeError("constructor failed")
    original_shutdown = RunJobController.shutdown
    original_factory = owner.controller_jobs_factory
    original_close = owner.close
    close_calls = []

    def shutdown(jobs, *, cancel_active=True):
        events.append("shutdown")
        original_shutdown(jobs, cancel_active=cancel_active)
        events.append("joined")

    def factory(*args):
        if phase != "before_bind":
            original_factory(*args)
        raise failure

    def fail(*_args):
        raise failure

    def close():
        close_calls.append(True)
        original_close()

    monkeypatch.setattr(RunJobController, "shutdown", shutdown)
    monkeypatch.setattr(owner, "close", close)
    if phase in {"before_bind", "after_bind"}:
        monkeypatch.setattr(owner, "controller_jobs_factory", factory)
    elif phase == "prepare":
        monkeypatch.setattr(owner, "action_preparation_factory", fail)
    elif phase == "submit":
        monkeypatch.setattr(owner, "action_submission_factory", fail)
    else:
        monkeypatch.setattr(BlueFireService, "_synchronize_run_index", fail)
    with pytest.raises(RuntimeError) as caught:
        _service(tmp_path, engine_workflow_composition=owner)
    assert caught.value is failure
    assert events == ["shutdown", "joined", ("close", "protected transports")]
    assert close_calls == [True]


def test_early_constructor_failure_does_not_close_unacquired_resources(tmp_path, monkeypatch):
    events = []
    configured = _configured(resources=(_Resource(events, "protected transports"),))
    monkeypatch.setattr(
        BlueFireService,
        "_load_default_config",
        lambda *_: (_ for _ in ()).throw(ValueError("bad config")),
    )
    monkeypatch.setattr(
        service_module, "ManagedAIJSONTransport", lambda: pytest.fail("transport not acquired")
    )
    monkeypatch.setattr(
        service_module, "RunJobController", lambda *_a, **_k: pytest.fail("jobs not acquired")
    )
    with pytest.raises(ValueError, match="bad config"):
        _service(tmp_path, engine_workflow_composition=configured.composition)
    assert events == [("close", "protected transports")]


def test_close_failure_is_sanitized_and_never_retries_composition_close(tmp_path, monkeypatch):
    configured = _configured()
    owner = configured.composition
    service = _service(tmp_path, engine_workflow_composition=owner)
    calls = []
    original = owner.close

    def close():
        calls.append(True)
        original()
        raise RuntimeError("private-token-path")

    monkeypatch.setattr(owner, "close", close)
    with pytest.raises(ProductStoreError, match="owned engine resources") as caught:
        service.close()
    assert "private-token-path" not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    service.close()
    assert calls == [True]


def test_constructor_error_survives_composition_cleanup_failure(tmp_path, monkeypatch):
    configured = _configured()
    failure = ValueError("initial failure")

    def fail(*_args):
        raise failure

    monkeypatch.setattr(configured.composition, "action_preparation_factory", fail)
    monkeypatch.setattr(
        configured.composition,
        "close",
        lambda: (_ for _ in ()).throw(RuntimeError("private-token")),
    )
    with pytest.raises(ValueError) as caught:
        _service(tmp_path, engine_workflow_composition=configured.composition)
    assert caught.value is failure


def test_default_service_keeps_engine_action_admission_fail_closed(tmp_path):
    service = _service(tmp_path)
    try:
        assert service.engine_attempt_jobs._runtime is None
        assert service.engine_experiment_service._controller is None
        for method, request in (
            (service.engine_experiment_service.prepare_action_request, PREPARE_REQUEST),
            (service.engine_experiment_service.submit_prepared_action_request, SUBMIT_REQUEST),
        ):
            with pytest.raises(EngineExperimentServiceError) as caught:
                method(EXPERIMENT_ID, request)
            assert caught.value.code == "engine_action_unavailable"
        assert service.product_store.list_jobs() == []
    finally:
        service.close()


def test_shutdown_failure_keeps_composition_resources_open_and_can_retry(tmp_path, monkeypatch):
    events = []
    configured = _configured(resources=(_Resource(events, "protected transports"),))
    owner = configured.composition
    service = _service(tmp_path, engine_workflow_composition=owner)
    shutdown = service.job_controller.shutdown
    shutdown_calls = []

    def fail(*, cancel_active=True):
        shutdown_calls.append("failed")
        raise RuntimeError("private shutdown token")

    def retry(*, cancel_active=True):
        shutdown_calls.append("joined")
        shutdown(cancel_active=cancel_active)

    monkeypatch.setattr(service.job_controller, "shutdown", fail)
    with pytest.raises(ProductStoreError, match="owned engine jobs") as caught:
        service.close()
    assert "private shutdown token" not in str(caught.value)
    assert events == []
    assert shutdown_calls == ["failed"]
    monkeypatch.setattr(service.job_controller, "shutdown", retry)
    service.close()
    service.close()
    assert events == [("close", "protected transports")]
    assert shutdown_calls == ["failed", "joined"]


def test_rollback_releases_created_provider_and_transport_once(tmp_path, monkeypatch):
    configured = _configured()
    events = []

    class ClosingOwner:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(self.name)

    monkeypatch.setattr(service_module, "ManagedAIJSONTransport", lambda: ClosingOwner("transport"))
    monkeypatch.setattr(
        service_module, "AuthorizedAIProviderAccess", lambda *_args: ClosingOwner("provider")
    )

    def fail(*_args):
        raise ValueError("prepare failed")

    monkeypatch.setattr(configured.composition, "action_preparation_factory", fail)
    with pytest.raises(ValueError, match="prepare failed"):
        _service(tmp_path, engine_workflow_composition=configured.composition)
    assert events == ["provider", "transport"]


def test_explicit_engine_adapters_keep_external_lifecycle_ownership(tmp_path):
    class ExternalOwner:
        def close(self):
            pytest.fail("explicit engine injection does not transfer lifecycle ownership")

    runtime = ExternalOwner()
    controller = ExternalOwner()
    service = _service(tmp_path, engine_attempt_runtime=runtime, engine_controller=controller)
    assert service.engine_attempt_jobs._runtime is runtime
    assert service.engine_experiment_service._controller is controller
    service.close()


@pytest.mark.parametrize("state", ["claimed", "bound", "closed"])
def test_composition_reuse_is_rejected_before_service_resource_allocation(
    tmp_path, monkeypatch, state
):
    from tests_platform.test_engine_installed_composition import _bind

    events = []
    configured = _configured(resources=(_Resource(events, "protected transports"),))
    owner = configured.composition
    if state == "claimed":
        owner.claim_service()
    elif state == "bound":
        _bind(configured)
    else:
        owner.close()
    previous_events = list(events)

    def forbidden(*_args, **_values):
        pytest.fail("rejected composition must not allocate service resources")

    for name in ("RunStore", "ProductStore", "ManagedAIJSONTransport", "RunJobController"):
        monkeypatch.setattr(service_module, name, forbidden)
    with pytest.raises(RuntimeError, match="another service|stopping"):
        _service(tmp_path, engine_workflow_composition=owner)
    assert events == previous_events
    assert configured.events == []
    owner.shutdown_jobs()
    owner.close()


def test_composition_generic_controller_submission_fails_closed_with_stable_error(tmp_path):
    from bluefire.engine_experiment_service import EngineControllerJobAction
    from bluefire.util import content_hash

    configured = _configured()
    service = _service(tmp_path, engine_workflow_composition=configured.composition)
    try:
        service.product_store.provision_engine_experiment_presentation(
            EXPERIMENT_ID,
            _profile(),
            _initial_target(),
        )
        workspace = service.engine_experiment_service.create_request(_create_request())
        request_ref = "sha256:" + "5" * 64
        request = {
            "schema_version": "bluefire.engine-controller-job.v1",
            "experiment_id": EXPERIMENT_ID,
            "revision": workspace["revision"],
            "experiment_digest": workspace["experiment_digest"],
            "action": EngineControllerJobAction.APPLY_DEFENSE.value,
            "request_ref": request_ref,
        }
        with pytest.raises(EngineExperimentServiceError) as caught:
            service.engine_experiment_service.submit_controller_operation(
                experiment_id=EXPERIMENT_ID,
                expected_revision=workspace["revision"],
                expected_digest=workspace["experiment_digest"],
                action=EngineControllerJobAction.APPLY_DEFENSE,
                request_ref=request_ref,
                submission_id="11111111-1111-4111-8111-111111111111",
                intent_digest=content_hash(request),
            )
        assert caught.value.code == "engine_controller_refused"
        assert service.product_store.list_jobs() == []
        assert configured.events == []
    finally:
        service.close()


def test_composition_preserves_concrete_prepared_work_and_legacy_cancellation(
    tmp_path, monkeypatch
):
    configured = _configured()
    owner = configured.composition
    service = _service(tmp_path, engine_workflow_composition=owner)
    try:
        concrete = owner._controller_jobs
        calls = []
        accepted = []
        receipt = {"job_id": "job-" + "a" * 32}

        def delegate(**values):
            calls.append(values)
            if "submission_factory" in values:
                values["submission_factory"]()
            return receipt

        monkeypatch.setattr(concrete, "submit_prepared", delegate)
        monkeypatch.setattr(concrete, "settle_undispatched_check_cancellation", delegate)
        protected = {
            "experiment_id": EXPERIMENT_ID,
            "action_kind": "apply_defense",
            "preparation_kind": "controller_job",
            "protected_request": {"job_request": {"protected": True}},
            "submission_id": "11111111-1111-4111-8111-111111111111",
            "intent_digest": "sha256:" + "c" * 64,
        }

        def accept(**_values):
            accepted.append(receipt)
            return receipt, True

        monkeypatch.setattr(
            service.product_store,
            "get_engine_action_acceptance",
            lambda **_values: accepted[0] if accepted else None,
        )
        monkeypatch.setattr(
            service.product_store, "recover_engine_action_acceptance", lambda **_values: None
        )
        monkeypatch.setattr(
            service.product_store, "get_protected_engine_action_preparation", lambda _ref: protected
        )
        monkeypatch.setattr(service.product_store, "accept_engine_action_preparation", accept)
        assert (
            service.engine_experiment_service.submit_prepared_action_request(
                EXPERIMENT_ID, SUBMIT_REQUEST
            )
            is receipt
        )
        assert calls[0]["request"] is protected["protected_request"]["job_request"]
        assert calls[0]["submission_id"] == protected["submission_id"]
        assert calls[0]["intent_digest"] == protected["intent_digest"]
        assert len(accepted) == 1
        cancel = {
            "experiment_id": EXPERIMENT_ID,
            "check_id": "exact-check",
            "job_id": receipt["job_id"],
        }
        assert (
            service.engine_experiment_service._controller_jobs.settle_undispatched_check_cancellation(
                **cancel
            )
            is receipt
        )
        assert len(calls) == 2
        assert calls[1] == cancel
        assert service.product_store.list_jobs() == []
    finally:
        service.close()
