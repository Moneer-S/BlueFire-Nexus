"""Post-store installed assembly shares service owners without starting effects."""

from __future__ import annotations

import threading

import pytest

import bluefire.service as service_module
from bluefire.ai_provider_access import DirectAIProviderAccess
from bluefire.job_runtime import JobContext, RunJobController
from bluefire.service import BlueFireService
from tests_platform.test_engine_installed_composition import _configured, _Resource
from tests_platform.test_service_engine_composition import _service


def test_factory_receives_the_only_store_before_provider_catalog_and_jobs(tmp_path, monkeypatch):
    configured = _configured()
    owner = configured.composition
    events = []
    stores = []
    original_store = service_module.ProductStore
    original_authorized = service_module.AuthorizedAIProviderAccess
    original_catalog = BlueFireService._load_action_catalog_snapshot
    original_jobs = service_module.RunJobController
    original_claim = owner.claim_service
    original_controller = owner.controller_jobs_factory

    def store(*args, **values):
        result = original_store(*args, **values)
        stores.append(result)
        events.append("store")
        return result

    def factory(product_store):
        assert stores == [product_store]
        assert product_store.list_jobs() == []
        events.append("factory")
        return owner

    def claim():
        events.append("claim")
        original_claim()

    def authorized(access, product_store):
        assert product_store is stores[0]
        events.append("provider")
        return original_authorized(access, product_store)

    def catalog(service, *args, **values):
        events.append("catalog")
        return original_catalog(service, *args, **values)

    def jobs(product_store, *args, **values):
        assert product_store is stores[0]
        events.append("jobs")
        return original_jobs(product_store, *args, **values)

    def controller(product_store, *args):
        assert product_store is stores[0]
        events.append("controller")
        return original_controller(product_store, *args)

    monkeypatch.setattr(service_module, "ProductStore", store)
    monkeypatch.setattr(service_module, "AuthorizedAIProviderAccess", authorized)
    monkeypatch.setattr(BlueFireService, "_load_action_catalog_snapshot", catalog)
    monkeypatch.setattr(service_module, "RunJobController", jobs)
    monkeypatch.setattr(owner, "claim_service", claim)
    monkeypatch.setattr(owner, "controller_jobs_factory", controller)
    service = _service(tmp_path, engine_workflow_composition_factory=factory)
    try:
        assert events == ["store", "factory", "claim", "provider", "catalog", "jobs", "controller"]
        assert stores == [service.product_store]
        workspace = service.engine_experiment_service
        binding = owner.bind(service.product_store, workspace)
        assert service.engine_attempt_jobs._runtime is owner.runtime
        assert service.engine_attempt_jobs._repository is service.product_store
        assert service.engine_attempt_jobs._reconciliation is owner.reconciliation_coordinator
        assert workspace._history is service.product_store
        assert workspace._run_source is service.store
        assert workspace._job_lifecycle is service.job_controller
        assert workspace._controller_jobs is owner._legacy_controller_jobs
        assert workspace._action_preparation is binding.preparation
        assert workspace._action_submission is binding.submission
        assert owner._job_controller is service.job_controller
        assert owner._store is service.product_store
        assert configured.events == []
        assert service.product_store.list_jobs() == []
    finally:
        service.close()


@pytest.mark.parametrize(
    "argument",
    [
        "engine_workflow_composition",
        "engine_attempt_runtime",
        "engine_controller",
        "engine_controller_jobs",
        "engine_controller_jobs_factory",
        "engine_action_preparation_factory",
        "engine_action_submission_factory",
    ],
)
def test_factory_conflicts_are_rejected_before_any_service_allocation(
    tmp_path, monkeypatch, argument
):
    configured = _configured()

    def forbidden(*_args, **_values):
        pytest.fail("conflicting composition configuration must not allocate owners")

    for name in ("RunStore", "ProductStore", "ManagedAIJSONTransport", "RunJobController"):
        monkeypatch.setattr(service_module, name, forbidden)
    value = configured.composition if argument == "engine_workflow_composition" else object()
    try:
        with pytest.raises(ValueError, match="either"):
            _service(
                tmp_path,
                engine_workflow_composition_factory=forbidden,
                **{argument: value},
            )
        assert configured.events == []
        assert configured.composition._service_claimed is False
        assert not (tmp_path / "product.sqlite3").exists()
    finally:
        configured.composition.close()


def test_factory_failure_cleans_factory_allocations_and_acquired_transport(tmp_path, monkeypatch):
    events = []
    failure = ValueError("protected assembly failed")
    monkeypatch.setattr(
        service_module,
        "ManagedAIJSONTransport",
        lambda: _Resource(events, "service transport"),
    )

    def forbidden(*_args, **_values):
        pytest.fail("failed assembly must not construct provider, catalog or jobs")

    monkeypatch.setattr(service_module, "AuthorizedAIProviderAccess", forbidden)
    monkeypatch.setattr(BlueFireService, "_load_action_catalog_snapshot", forbidden)
    monkeypatch.setattr(service_module, "RunJobController", forbidden)

    def factory(product_store):
        assert product_store.list_jobs() == []
        events.append("factory")
        partial = _Resource(events, "factory partial allocation")
        try:
            raise failure
        finally:
            # Until return the factory retains responsibility for partial owners.
            partial.close()

    with pytest.raises(ValueError) as caught:
        _service(tmp_path, engine_workflow_composition_factory=factory)
    assert caught.value is failure
    assert events == [
        "factory",
        ("close", "factory partial allocation"),
        ("close", "service transport"),
    ]


def test_factory_cannot_adopt_or_close_another_services_composition(tmp_path, monkeypatch):
    events = []
    configured = _configured(resources=(_Resource(events, "first service owner"),))
    owner = configured.composition
    first = _service(tmp_path / "first", engine_workflow_composition=owner)
    monkeypatch.setattr(
        service_module,
        "ManagedAIJSONTransport",
        lambda: _Resource(events, "second service transport"),
    )
    received = []

    def factory(product_store):
        received.append(product_store)
        assert product_store is not first.product_store
        return owner

    try:
        with pytest.raises(RuntimeError, match="another service"):
            _service(tmp_path / "second", engine_workflow_composition_factory=factory)
        assert len(received) == 1
        assert events == [("close", "second service transport")]
        assert owner._closed is False
        assert owner._stopping is False
        assert owner._job_controller is first.job_controller
        assert owner.bind(first.product_store, first.engine_experiment_service)
        assert configured.events == []
    finally:
        first.close()
    assert events == [
        ("close", "second service transport"),
        ("close", "first service owner"),
    ]


@pytest.mark.parametrize(
    "phase", ["provider", "before_controller", "after_controller", "prepare", "submit", "late"]
)
def test_factory_owner_is_released_on_each_downstream_constructor_failure(
    tmp_path, monkeypatch, phase
):
    events = []
    configured = _configured(resources=(_Resource(events, "protected resources"),))
    owner = configured.composition
    failure = RuntimeError("downstream initialization failed")
    original_controller = owner.controller_jobs_factory
    original_shutdown = RunJobController.shutdown
    original_close = owner.close
    close_calls = []

    def shutdown(jobs, *, cancel_active=True):
        events.append("shutdown")
        original_shutdown(jobs, cancel_active=cancel_active)
        events.append("joined")

    def controller(*args):
        if phase == "after_controller":
            original_controller(*args)
        raise failure

    def fail(*_args, **_values):
        raise failure

    def close():
        close_calls.append(True)
        original_close()

    monkeypatch.setattr(RunJobController, "shutdown", shutdown)
    monkeypatch.setattr(owner, "close", close)
    if phase == "provider":
        monkeypatch.setattr(service_module, "AuthorizedAIProviderAccess", fail)
    elif phase in {"before_controller", "after_controller"}:
        monkeypatch.setattr(owner, "controller_jobs_factory", controller)
    elif phase == "prepare":
        monkeypatch.setattr(owner, "action_preparation_factory", fail)
    elif phase == "submit":
        monkeypatch.setattr(owner, "action_submission_factory", fail)
    else:
        monkeypatch.setattr(BlueFireService, "_synchronize_run_index", fail)
    with pytest.raises(RuntimeError) as caught:
        _service(tmp_path, engine_workflow_composition_factory=lambda _store: owner)
    assert caught.value is failure
    expected = [] if phase == "provider" else ["shutdown", "joined"]
    assert events == expected + [("close", "protected resources")]
    assert close_calls == [True]


def test_factory_close_orders_provider_jobs_and_resources_and_closes_engine_once(
    tmp_path, monkeypatch
):
    events = []
    configured = _configured(
        resources=(_Resource(events, "first resource"), _Resource(events, "last resource"))
    )

    class Provider(DirectAIProviderAccess):
        def close(self):
            events.append("provider")

    monkeypatch.setattr(
        service_module, "ManagedAIJSONTransport", lambda: _Resource(events, "transport")
    )
    service = _service(
        tmp_path,
        ai_provider_access=Provider(),
        engine_workflow_composition_factory=lambda _store: configured.composition,
    )
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
        submitted = service.job_controller.submit("factory-lifecycle-test", {}, callback=worker)
        assert started.wait(10)
    finally:
        service.close()
    expected = [
        "provider",
        ("close", "transport"),
        "shutdown",
        "cancelled",
        "joined",
        ("close", "last resource"),
        ("close", "first resource"),
    ]
    assert events == expected
    service.close()
    assert events.count("shutdown") == 1
    assert events.count(("close", "last resource")) == 1
    assert events.count(("close", "first resource")) == 1
    assert service.product_store.get_job(submitted["job_id"])["state"] == "cancelled"
