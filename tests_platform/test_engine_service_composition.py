"""The service keeps its maintained engine assembly injection API after extraction."""

import pytest

import bluefire.engine_service_composition as composition_module
import bluefire.service as service_module
from bluefire.engine_service_composition import EngineServiceComposition
from bluefire.product_store import ProductStoreError
from tests_platform.test_engine_installed_composition import _configured, _Resource


@pytest.mark.parametrize(
    "name",
    [
        "EngineControllerJobsFactory",
        "EngineActionPreparationFactory",
        "EngineActionSubmissionFactory",
        "EngineWorkflowCompositionFactory",
    ],
)
def test_service_preserves_public_engine_factory_aliases(name):
    assert getattr(service_module, name) is getattr(composition_module, name)


def test_helper_claims_explicit_composition_before_store_and_closes_without_jobs():
    events = []
    configured = _configured(resources=(_Resource(events, "early owner"),))
    owner = configured.composition
    helper = EngineServiceComposition(composition=owner)
    assert owner._service_claimed is True
    assert owner._job_controller is None
    assert events == configured.events == []
    helper.close(None)
    helper.close(None)
    assert events == [("close", "early owner")]


@pytest.mark.parametrize(
    "argument",
    [
        "runtime",
        "controller",
        "controller_jobs",
        "controller_jobs_factory",
        "preparation_factory",
        "submission_factory",
        "composition_factory",
    ],
)
def test_helper_rejects_conflicts_without_claiming_composition(argument):
    events = []
    configured = _configured(resources=(_Resource(events, "unclaimed owner"),))
    owner = configured.composition
    try:
        with pytest.raises(ValueError, match="either"):
            EngineServiceComposition(composition=owner, **{argument: object()})
        assert owner._service_claimed is False
        assert events == configured.events == []
    finally:
        owner.close()


def test_helper_retains_the_first_store_and_calls_factory_only_once(monkeypatch):
    configured = _configured()
    owner = configured.composition
    first_store = object()
    other_store = object()
    calls = []

    def factory(store):
        calls.append(store)
        return owner

    def forbidden(*_args, **_values):
        pytest.fail("a changed store must be rejected before invoking controller factories")

    monkeypatch.setattr(owner, "controller_jobs_factory", forbidden)
    helper = EngineServiceComposition(composition_factory=factory)
    try:
        helper.after_store(first_store)
        helper.after_store(first_store)
        assert calls == [first_store]
        assert owner._service_claimed is True
        assert owner._job_controller is None
        with pytest.raises(ProductStoreError, match="another product store"):
            helper.after_store(other_store)
        with pytest.raises(ProductStoreError, match="another product store"):
            helper.bind(
                store=other_store,
                run_store=object(),
                jobs=object(),
                presentation_source=None,
                clock=lambda: "unused",
            )
        assert calls == [first_store]
        assert configured.events == []
    finally:
        helper.close(None)


def test_helper_does_not_adopt_or_close_a_rejected_factory_owner():
    events = []
    configured = _configured(resources=(_Resource(events, "first helper owner"),))
    owner = configured.composition
    first = EngineServiceComposition(composition=owner)
    second = EngineServiceComposition(composition_factory=lambda _store: owner)
    try:
        with pytest.raises(RuntimeError, match="another service"):
            second.after_store(object())
        second.close(None)
        assert owner._closed is False
        assert owner._stopping is False
        assert events == configured.events == []
    finally:
        first.close(None)
    assert events == [("close", "first helper owner")]
