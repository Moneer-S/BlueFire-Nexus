"""Installed wiring uses fake protected owners; no engine, lab or network starts."""

from __future__ import annotations

from dataclasses import fields, replace
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_experiment_jobs import EngineExperimentJobs
from bluefire.engine_experiment_service import EngineExperimentService
from bluefire.engine_installed_composition import (
    AcceptedPreparedEngineAttempt,
    InstalledAttemptComponents,
    InstalledEngineAdapters,
    InstalledEngineComposition,
    InstalledEngineCompositionError,
    InstalledEngineSources,
)
from tests_platform.test_engine_experiment import _new_experiment
from tests_platform.test_engine_experiment_jobs import _authority
from tests_platform.test_engine_experiment_service import _History, _PresentationSource, _RunSource

JOB = "job-" + "a" * 32
PREPARATION = "sha256:" + "b" * 64


class _Untouched:
    def __getattr__(self, name: str) -> Any:
        def forbidden(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError(f"unexpected protected operation: {name}")

        return forbidden


class _Resource:
    def __init__(self, events, name, *, fail=False):
        self.events, self.name, self.fail = events, name, fail

    def close(self):
        self.events.append(("close", self.name))
        if self.fail:
            raise RuntimeError("private credential must not appear in errors")


class _JobController(_Untouched):
    def __init__(self, events):
        self.events = events
        self.fail = False

    def shutdown(self, *, cancel_active):
        assert cancel_active is True
        self.events.append(("shutdown",))
        if self.fail:
            raise RuntimeError("shutdown did not join")


class _AcceptedJobs:
    def __init__(self, events):
        self.events = events
        self.accepted = False
        self.consumed = False
        self.changed = False

    def claim_for_execution(self, *, job_id, binding, delegation):
        self.events.append(("claim", job_id))
        if not self.accepted or self.consumed:
            return None
        self.consumed = True
        return AcceptedPreparedEngineAttempt(
            job_id="job-" + "c" * 32 if self.changed else job_id,
            preparation_ref=PREPARATION,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
        )


class _Runtime:
    def __init__(self, events):
        self.events = events
        self.result = object()

    def execute(self, context, binding, delegation, transition):
        self.events.append(("execute", context.job_id, binding, delegation, transition))
        return self.result

    def reconcile(self, binding, delegation, saved_record):
        self.events.append(("reconcile", binding, delegation, saved_record))
        return self.result


class _Attempts:
    def __init__(self, events):
        self.events = events
        self.runtime = _Runtime(events)
        self.resource = _Resource(events, "attempt relays")

    def for_execution(self, **values):
        self.events.append(("factory_execute", values))
        return InstalledAttemptComponents(self.runtime, (self.resource,))

    def for_reconciliation(self, **values):
        self.events.append(("factory_reconcile", values))
        return InstalledAttemptComponents(self.runtime, (self.resource,))


def _configured(*, accepted_jobs=None, resources=()):
    events = []
    untouched: Any = _Untouched()
    accepted = _AcceptedJobs(events) if accepted_jobs is None else accepted_jobs
    sources = InstalledEngineSources(
        **{field.name: untouched for field in fields(InstalledEngineSources)}
    )
    sources = replace(sources, accepted_jobs=accepted)
    attempts = _Attempts(events)
    adapters = InstalledEngineAdapters(
        **{field.name: untouched for field in fields(InstalledEngineAdapters)}
    )
    adapters = replace(adapters, attempts=attempts, resources=resources)
    composition = InstalledEngineComposition(
        sources=sources,
        adapters=adapters,
        installed_bluefire_revision="a" * 40,
        reviewer="local-reviewer",
        clock=untouched.clock,
    )
    return SimpleNamespace(
        composition=composition,
        events=events,
        accepted=accepted,
        attempts=attempts,
        store=untouched,
        runs=_Untouched(),
        jobs=_JobController(events),
    )


def _bind(config, *, presentation_source=None):
    owner = config.composition
    controller_jobs = owner.controller_jobs_factory(config.store, config.runs, config.jobs)
    attempts = EngineExperimentJobs(
        controller=config.jobs,
        repository=config.store,
        runtime=owner.runtime,
        clock=lambda: "unused",
    )
    workspace = EngineExperimentService(
        history=config.store,
        run_source=config.runs,
        jobs=attempts,
        job_lifecycle=config.jobs,
        controller=owner.controller,
        controller_jobs=controller_jobs,
        clock=lambda: "unused",
        presentation_source=config.store if presentation_source is None else presentation_source,
    )
    return workspace, attempts, controller_jobs


@pytest.mark.parametrize("group", ["sources", "adapters"])
def test_every_protected_dependency_is_required_without_effects(group):
    config = _configured()
    owner = config.composition
    selected = getattr(owner, group)
    for field in fields(selected):
        if field.name == "resources":
            continue
        values = {"sources": owner.sources, "adapters": owner.adapters}
        values[group] = replace(selected, **{field.name: None})
        with pytest.raises(InstalledEngineCompositionError, match=field.name):
            InstalledEngineComposition(
                **values,
                installed_bluefire_revision="a" * 40,
                reviewer="local-reviewer",
                clock=lambda: "unused",
            )
    assert config.events == []


def test_binding_is_two_phase_inert_and_shares_every_owner():
    config = _configured()
    owner = config.composition
    workspace, jobs, controller_jobs = _bind(config)
    preparation = owner.action_preparation_factory(config.store, workspace)
    submission = owner.action_submission_factory(config.store, workspace, jobs, controller_jobs)
    bound = owner.bind(config.store, workspace)
    assert owner.bind(config.store, workspace) is bound
    assert bound.preparation is preparation
    assert bound.submission is submission
    assert preparation._preparer is bound.preparer
    assert bound.preparer._materials is bound.material_source
    assert bound.preparer._issuer is bound.material_source
    assert bound.preparer._resolver is owner.resolver
    assert bound.preparer._jobs is controller_jobs
    assert bound.material_source._resolver is owner.resolver
    assert bound.material_source._authority is owner.sources.authority
    assert bound.material_source._generations is owner.sources.generations
    assert owner.issuer._registry is owner.sources.issuance_registry
    assert owner.controller_jobs_factory(config.store, config.runs, config.jobs) is controller_jobs
    assert submission._jobs is jobs
    assert submission._controller_jobs is controller_jobs
    assert owner.live_provider_proof is False
    assert config.events == []
    owner.shutdown_jobs()
    owner.close()


def test_actual_workspace_reads_never_admit_or_start_engine_work():
    config = _configured()
    owner = config.composition
    experiment = _new_experiment()
    retained = _History(experiment)

    class ReadOnlyHistory(_Untouched):
        def get_engine_experiment(self, experiment_id, *, revision=None):
            return retained.get_engine_experiment(experiment_id, revision=revision)

    config.store = ReadOnlyHistory()
    config.runs = _RunSource()
    presentation = _PresentationSource(retained)
    workspace, jobs, controller_jobs = _bind(config, presentation_source=presentation)
    workspace._action_preparation = owner.action_preparation_factory(config.store, workspace)
    workspace._action_submission = owner.action_submission_factory(
        config.store, workspace, jobs, controller_jobs
    )
    before = experiment.to_dict()
    first = workspace.workspace(experiment.experiment_id)
    second = workspace.workspace(experiment.experiment_id)
    assert first == second
    assert first["experiment_id"] == experiment.experiment_id
    assert first["engine_setup"]["model"]["test_provider"] is True
    assert retained.experiment.to_dict() == before
    assert presentation.create_preflights == presentation.transition_preflights == []
    assert owner.live_provider_proof is False
    assert config.events == []
    owner.shutdown_jobs()
    owner.close()


def test_unbound_close_has_no_job_effect_and_closes_owned_handles_once():
    events = []
    resource = _Resource(events, "protected transport")
    config = _configured(resources=(resource, resource))
    config.composition.close()
    config.composition.close()
    config.composition.shutdown_jobs()
    assert events == [("close", "protected transport")]
    assert config.events == []


def test_binding_rejects_other_service_and_mixed_jobs():
    config = _configured()
    owner = config.composition
    workspace, jobs, controller_jobs = _bind(config)
    with pytest.raises(InstalledEngineCompositionError):
        owner.bind(_Untouched(), workspace)
    with pytest.raises(InstalledEngineCompositionError):
        owner.controller_jobs_factory(config.store, _Untouched(), config.jobs)
    with pytest.raises(InstalledEngineCompositionError):
        owner.action_submission_factory(config.store, workspace, object(), controller_jobs)
    original = jobs._runtime
    jobs._runtime = None
    with pytest.raises(InstalledEngineCompositionError):
        owner.bind(config.store, workspace)
    jobs._runtime = original
    owner.bind(config.store, workspace)
    other, _, _ = _bind(config)
    with pytest.raises(InstalledEngineCompositionError):
        owner.bind(config.store, other)
    assert config.events == []
    owner.shutdown_jobs()
    owner.close()


@pytest.mark.parametrize("state", ["unbound", "unaccepted", "changed"])
def test_runtime_requires_exact_accepted_prepared_job_before_any_factory(state):
    config = _configured()
    owner = config.composition
    binding, delegation, _ = _authority()
    if state != "unbound":
        workspace, _, _ = _bind(config)
        owner.bind(config.store, workspace)
    config.accepted.accepted = state == "changed"
    config.accepted.changed = state == "changed"
    with pytest.raises(InstalledEngineCompositionError):
        owner.runtime.execute(SimpleNamespace(job_id=JOB), binding, delegation, lambda *_: None)
    assert all(event[0] == "claim" for event in config.events)
    owner.shutdown_jobs()
    owner.close()


def test_execution_factory_receives_exact_authority_once_and_restart_only_reopens():
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    config.accepted.accepted = True
    binding, delegation, _ = _authority()
    context = SimpleNamespace(job_id=JOB)

    def transition(*_):
        pass

    assert (
        owner.runtime.execute(context, binding, delegation, transition)
        is config.attempts.runtime.result
    )
    execution = config.events[1][1]
    assert execution["composition"] is owner
    assert execution["binding"] is binding
    assert execution["delegation"] is delegation
    assert execution["accepted"].preparation_ref == PREPARATION
    with pytest.raises(InstalledEngineCompositionError, match="already consumed"):
        owner.runtime.execute(context, binding, delegation, transition)
    assert [event[0] for event in config.events] == ["claim", "factory_execute", "execute"]
    owner.shutdown_jobs()
    owner.close()
    assert config.events[-2:] == [("shutdown",), ("close", "attempt relays")]

    restarted = _configured(accepted_jobs=config.accepted)
    workspace, _, _ = _bind(restarted)
    restarted.composition.bind(restarted.store, workspace)
    saved = EngineAttemptRecord.create(binding)
    assert (
        restarted.composition.runtime.reconcile(binding, delegation, saved)
        is restarted.attempts.runtime.result
    )
    assert [event[0] for event in restarted.events] == ["factory_reconcile", "reconcile"]
    with pytest.raises(InstalledEngineCompositionError, match="unavailable"):
        restarted.composition.runtime.execute(context, binding, delegation, transition)
    assert [event[0] for event in restarted.events] == ["factory_reconcile", "reconcile"]
    restarted.composition.shutdown_jobs()
    restarted.composition.close()


def test_shutdown_must_finish_before_reverse_order_exactly_once_close():
    events = []
    first = _Resource(events, "first")
    second = _Resource(events, "second", fail=True)
    config = _configured(resources=(first, second, first))
    owner = config.composition
    _bind(config)
    with pytest.raises(InstalledEngineCompositionError, match="shutdown_jobs"):
        owner.close()
    assert events == config.events == []
    config.jobs.fail = True
    with pytest.raises(RuntimeError, match="did not join"):
        owner.shutdown_jobs()
    with pytest.raises(InstalledEngineCompositionError, match="shutdown_jobs"):
        owner.close()
    assert events == []
    config.jobs.fail = False
    owner.shutdown_jobs()
    owner.shutdown_jobs()
    with pytest.raises(InstalledEngineCompositionError, match="resource close failed") as caught:
        owner.close()
    assert "credential" not in str(caught.value)
    assert events == [("close", "first"), ("close", "second")]
    assert config.events == [("shutdown",), ("shutdown",)]
    owner.close()
    assert len(events) == 2
    with pytest.raises(InstalledEngineCompositionError, match="stopping"):
        owner.controller_jobs_factory(config.store, config.runs, config.jobs)
