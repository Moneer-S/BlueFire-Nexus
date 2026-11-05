"""Installed wiring uses fake protected owners; no engine, lab or network starts."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields, replace
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire.engine_attempt_contract import EngineAttemptRecord
from bluefire.engine_experiment import CleanupState
from bluefire.engine_experiment_jobs import EngineExperimentJobs, EngineRuntimeSettlement
from bluefire.engine_experiment_service import EngineExperimentService
from bluefire.engine_installed_composition import (
    AcceptedPreparedEngineAttempt,
    InstalledAttemptComponents,
    InstalledEngineAdapters,
    InstalledEngineComposition,
    InstalledEngineCompositionError,
    InstalledEngineSources,
)
from bluefire.engine_reconciliation import (
    ClaimedEngineReconciliation,
    EngineReconciliationError,
)
from bluefire.product_store_accepted_engine_jobs import (
    AcceptedEngineJobError,
    AcceptedEnginePreDispatchCancelled,
    PreDispatchCancelledEngineAttempt,
)
from tests_platform.test_engine_experiment import _new_experiment
from tests_platform.test_engine_experiment_jobs import _authority
from tests_platform.test_engine_experiment_service import _History, _PresentationSource, _RunSource

JOB = "job-" + "a" * 32
PREPARATION = "sha256:" + "b" * 64
CLAIM = "sha256:" + "c" * 64
RESOLUTION = "sha256:" + "d" * 64
PREDISPATCH = "sha256:" + "e" * 64
NOW = "2026-11-04T12:04:00Z"


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
        self.cancelled = False
        self.current_error = False
        self.retained: AcceptedPreparedEngineAttempt | None = None

    def claim_for_execution(self, *, job_id, binding, delegation):
        self.events.append(("claim", job_id))
        if self.cancelled:
            return PreDispatchCancelledEngineAttempt(
                job_id=job_id,
                job_state="cancelling",
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                pre_dispatch_ref=PREDISPATCH,
            )
        if not self.accepted or self.consumed:
            return None
        self.consumed = True
        self.retained = AcceptedPreparedEngineAttempt(
            job_id="job-" + "c" * 32 if self.changed else job_id,
            preparation_ref=PREPARATION,
            binding_digest=binding.binding_digest,
            delegation_digest=delegation.delegation_digest,
            claim_ref=CLAIM,
            runtime_resolution_ref=RESOLUTION,
        )
        return self.retained

    def require_current(self, *, accepted, binding, delegation):
        self.events.append(("require_current", accepted.runtime_resolution_ref))
        if self.current_error:
            raise AcceptedEngineJobError("admission changed")
        accepted.validate(accepted.job_id, binding, delegation)

    def reopen_for_reconciliation(self, *, binding, delegation):
        self.events.append(("reopen", binding.attempt_id))
        if self.retained is None:
            self.retained = AcceptedPreparedEngineAttempt(
                job_id=JOB,
                preparation_ref=PREPARATION,
                binding_digest=binding.binding_digest,
                delegation_digest=delegation.delegation_digest,
                claim_ref=CLAIM,
                runtime_resolution_ref=RESOLUTION,
            )
        return self.retained


class _ReconciliationCoordinator:
    def __init__(self, events):
        self.events = events
        self.plan = None
        self.active = None
        self._capability = object()

    @property
    def reconciliation_capability(self):
        if self.active is None:
            raise EngineReconciliationError("synthetic reconciliation is not active")
        return self._capability

    @contextmanager
    def session(self, *, experiment_id, attempt_id):
        if self.active is not None:
            raise EngineReconciliationError("synthetic reconciliation is already active")
        self.events.append(("reconciliation_enter", experiment_id, attempt_id))
        self.active = self.plan
        try:
            yield self
        finally:
            self.active = None
            self.events.append(("reconciliation_exit", experiment_id, attempt_id))

    def require_active_claimed(self, *, binding, delegation, reconciliation_ref):
        self.events.append(("require_active_reconciliation", reconciliation_ref))
        if self.active is None:
            raise EngineReconciliationError("synthetic reconciliation is not active")
        self.active.validate(binding, delegation, EngineAttemptRecord.create(binding))
        if self.active.reconciliation_ref != reconciliation_ref:
            raise EngineReconciliationError("synthetic reconciliation changed")
        return self.active


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

    def reconcile_claimed(self, binding, delegation, saved_record, *, reconciliation_ref):
        self.events.append(
            (
                "reconcile_claimed",
                binding,
                delegation,
                saved_record,
                reconciliation_ref,
            )
        )
        return EngineRuntimeSettlement(
            record=saved_record,
            engine_evidence=(),
            artifact_manifest_ref=None,
            cleanup_state=CleanupState.UNKNOWN,
            cleanup_evidence_ref="sha256:" + "f" * 64,
            settled_at=NOW,
            reconciliation_ref=reconciliation_ref,
        )


class _Context:
    def __init__(self, events, job_id=JOB):
        self.events = events
        self.job_id = job_id

    def checkpoint(self, progress=None):
        self.events.append(("checkpoint", progress))


class _Attempts:
    def __init__(self, events):
        self.events = events
        self.runtime = _Runtime(events)
        self.resource = _Resource(events, "attempt relays")
        self.policy = {
            "schema_version": "bluefire.installed-attempt-reconciliation.v1",
            "effects": "exact-reference-idempotent-no-launch",
        }

    @property
    def reconciliation_policy(self):
        return dict(self.policy)

    def for_execution(self, **values):
        self.events.append(("factory_execute", values))
        return InstalledAttemptComponents(
            self.runtime,
            (self.resource,),
            values["accepted"].runtime_resolution_ref,
        )

    def for_reconciliation(self, **values):
        self.events.append(("factory_reconcile", values))
        return InstalledAttemptComponents(
            self.runtime,
            (self.resource,),
            values["accepted"].runtime_resolution_ref,
        )


def _configured(*, accepted_jobs=None, resources=()):
    events = []
    untouched: Any = _Untouched()
    accepted = _AcceptedJobs(events) if accepted_jobs is None else accepted_jobs
    accepted.events = events
    sources = InstalledEngineSources(
        **{field.name: untouched for field in fields(InstalledEngineSources)}
    )
    attempts = _Attempts(events)
    reconciliation = _ReconciliationCoordinator(events)
    adapters = InstalledEngineAdapters(
        **{field.name: untouched for field in fields(InstalledEngineAdapters)}
    )
    adapters = replace(adapters, attempts=attempts, resources=resources)
    composition = InstalledEngineComposition(
        sources=sources,
        adapters=adapters,
        installed_bluefire_revision="a" * 40,
        reviewer="local-reviewer",
        clock=lambda: NOW,
    )
    return SimpleNamespace(
        composition=composition,
        events=events,
        accepted=accepted,
        attempts=attempts,
        reconciliation=reconciliation,
        store=untouched,
        runs=_Untouched(),
        jobs=_JobController(events),
    )


def _bind(config, *, presentation_source=None):
    owner = config.composition
    controller_jobs = owner.controller_jobs_factory(config.store, config.runs, config.jobs)
    owner._product_store_reconciliation = config.reconciliation
    attempts = EngineExperimentJobs(
        controller=config.jobs,
        repository=config.store,
        runtime=owner.runtime,
        reconciliation=owner.reconciliation_coordinator,
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
    owner._accepted_jobs = config.accepted
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


def test_attempt_factory_must_declare_exact_idempotent_reconciliation_policy():
    config = _configured()
    adapters = replace(
        config.composition.adapters,
        attempts=SimpleNamespace(
            reconciliation_policy={
                "schema_version": "bluefire.installed-attempt-reconciliation.v1",
                "effects": "best-effort",
            }
        ),
    )
    with pytest.raises(InstalledEngineCompositionError, match="policy is unavailable"):
        InstalledEngineComposition(
            sources=config.composition.sources,
            adapters=adapters,
            installed_bluefire_revision="a" * 40,
            reviewer="local-reviewer",
            clock=lambda: NOW,
        )
    assert config.events == []
    config.composition.close()


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
    assert bound.preparer._jobs is owner._controller_jobs
    assert bound.material_source._resolver is owner.resolver
    assert bound.material_source._authority is owner.sources.authority
    assert bound.material_source._generations is owner.sources.generations
    assert owner.issuer._registry is owner.sources.issuance_registry
    assert owner.controller_jobs_factory(config.store, config.runs, config.jobs) is controller_jobs
    assert submission._jobs is jobs
    assert submission._controller_jobs is owner._controller_jobs
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


def test_execution_factory_receives_exact_authority_once_and_claimed_restart_only_reopens():
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    config.accepted.accepted = True
    binding, delegation, _ = _authority()
    context = _Context(config.events)

    def transition(*_):
        pass

    assert (
        owner.runtime.execute(context, binding, delegation, transition)
        is config.attempts.runtime.result
    )
    execution = config.events[3][1]
    assert execution["composition"] is owner
    assert execution["binding"] is binding
    assert execution["delegation"] is delegation
    assert execution["accepted"].preparation_ref == PREPARATION
    with pytest.raises(InstalledEngineCompositionError, match="already consumed"):
        owner.runtime.execute(context, binding, delegation, transition)
    assert [event[0] for event in config.events] == [
        "claim",
        "checkpoint",
        "require_current",
        "factory_execute",
        "execute",
    ]
    owner.shutdown_jobs()
    owner.close()
    assert config.events[-2:] == [("shutdown",), ("close", "attempt relays")]

    restarted = _configured(accepted_jobs=config.accepted)
    workspace, _, _ = _bind(restarted)
    restarted.composition.bind(restarted.store, workspace)
    saved = EngineAttemptRecord.create(binding)
    with pytest.raises(InstalledEngineCompositionError, match="active claimed session"):
        restarted.composition.runtime.reconcile(binding, delegation, saved)
    reconciliation_ref = "sha256:" + "9" * 64
    restarted.reconciliation.plan = ClaimedEngineReconciliation(
        job_id=JOB,
        job_state="interrupted",
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM,
        runtime_resolution_ref=RESOLUTION,
        reconciliation_ref=reconciliation_ref,
    )
    with restarted.composition.reconciliation_coordinator.session(
        experiment_id=binding.experiment_id,
        attempt_id=binding.attempt_id,
    ):
        settlement = restarted.composition.runtime.reconcile_claimed(
            binding,
            delegation,
            saved,
            reconciliation_ref=reconciliation_ref,
        )
    assert settlement.reconciliation_ref == reconciliation_ref
    assert [event[0] for event in restarted.events] == [
        "reconciliation_enter",
        "require_active_reconciliation",
        "reopen",
        "factory_reconcile",
        "reconcile_claimed",
        "reconciliation_exit",
    ]
    assert restarted.events[3][1]["reconciliation_ref"] == reconciliation_ref
    with pytest.raises(InstalledEngineCompositionError, match="unavailable"):
        restarted.composition.runtime.execute(context, binding, delegation, transition)
    assert [event[0] for event in restarted.events] == [
        "reconciliation_enter",
        "require_active_reconciliation",
        "reopen",
        "factory_reconcile",
        "reconcile_claimed",
        "reconciliation_exit",
        "claim",
    ]
    restarted.composition.shutdown_jobs()
    restarted.composition.close()


def test_pre_dispatch_cancellation_never_reaches_checkpoint_or_factory():
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    config.accepted.cancelled = True
    binding, delegation, _ = _authority()

    with pytest.raises(AcceptedEnginePreDispatchCancelled):
        owner.runtime.execute(_Context(config.events), binding, delegation, lambda *_: None)

    assert [event[0] for event in config.events] == ["claim"]
    owner.shutdown_jobs()
    owner.close()


def test_admission_change_after_checkpoint_never_reaches_factory():
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    config.accepted.accepted = True
    config.accepted.current_error = True
    binding, delegation, _ = _authority()

    with pytest.raises(InstalledEngineCompositionError, match="no longer current"):
        owner.runtime.execute(_Context(config.events), binding, delegation, lambda *_: None)

    assert [event[0] for event in config.events] == [
        "claim",
        "checkpoint",
        "require_current",
    ]
    owner.shutdown_jobs()
    owner.close()


def test_direct_installed_recovery_without_outer_session_fails_closed():
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    binding, delegation, _ = _authority()
    saved = EngineAttemptRecord.create(binding)

    with pytest.raises(InstalledEngineCompositionError, match="active claimed session"):
        owner.runtime.reconcile(binding, delegation, saved)
    with pytest.raises(InstalledEngineCompositionError, match="intent is unavailable"):
        owner.runtime.reconcile_claimed(
            binding,
            delegation,
            saved,
            reconciliation_ref="sha256:" + "9" * 64,
        )

    assert [event[0] for event in config.events] == ["require_active_reconciliation"]
    assert all(event[0] != "factory_reconcile" for event in config.events)
    owner.shutdown_jobs()
    owner.close()


@pytest.mark.parametrize("stage", ["factory", "runtime"])
def test_claimed_reconciliation_sanitizes_private_adapter_failures(stage):
    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    binding, delegation, _ = _authority()
    saved = EngineAttemptRecord.create(binding)
    reconciliation_ref = "sha256:" + "9" * 64
    config.reconciliation.plan = ClaimedEngineReconciliation(
        job_id=JOB,
        job_state="interrupted",
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM,
        runtime_resolution_ref=RESOLUTION,
        reconciliation_ref=reconciliation_ref,
    )
    secret = r"C:\private\credential-token.txt"

    def fail(*_args, **_values):
        raise RuntimeError(secret)

    if stage == "factory":
        config.attempts.for_reconciliation = fail
    else:
        config.attempts.runtime.reconcile_claimed = fail

    with pytest.raises(EngineReconciliationError) as caught:
        with owner.reconciliation_coordinator.session(
            experiment_id=binding.experiment_id,
            attempt_id=binding.attempt_id,
        ):
            owner.runtime.reconcile_claimed(
                binding,
                delegation,
                saved,
                reconciliation_ref=reconciliation_ref,
            )

    assert secret not in str(caught.value)
    owner.shutdown_jobs()
    owner.close()


def test_concurrent_recovery_session_is_rejected_before_any_factory():
    import threading

    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    binding, delegation, _ = _authority()
    entered = threading.Event()
    release = threading.Event()
    failures = []

    def recover():
        try:
            with owner.reconciliation_coordinator.session(
                experiment_id=binding.experiment_id,
                attempt_id=binding.attempt_id,
            ):
                entered.set()
                assert release.wait(timeout=5)
        except Exception as exc:  # pragma: no branch - surfaced below
            failures.append(exc)

    thread = threading.Thread(target=recover)
    thread.start()
    assert entered.wait(timeout=5)
    with pytest.raises(EngineReconciliationError, match="lifecycle is unavailable"):
        with owner.reconciliation_coordinator.session(
            experiment_id=binding.experiment_id,
            attempt_id=binding.attempt_id,
        ):
            raise AssertionError("duplicate recovery session must not enter")
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert failures == []
    assert [event[0] for event in config.events].count("factory_reconcile") == 0
    owner.shutdown_jobs()
    owner.close()


def test_shutdown_waits_for_outer_reconciliation_session_through_final_boundary():
    import threading

    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    binding, _delegation, _ = _authority()
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()

    def recover():
        with owner.reconciliation_coordinator.session(
            experiment_id=binding.experiment_id,
            attempt_id=binding.attempt_id,
        ):
            entered.set()
            assert release.wait(timeout=5)

    recovery = threading.Thread(target=recover)
    recovery.start()
    assert entered.wait(timeout=5)

    def stop():
        owner.shutdown_jobs()
        stopped.set()

    shutdown = threading.Thread(target=stop)
    shutdown.start()
    for _ in range(100):
        with owner._lock:
            if owner._stopping:
                break
        stopped.wait(0.01)
    with owner._lock:
        assert owner._stopping
    assert not stopped.is_set()
    release.set()
    recovery.join(timeout=5)
    shutdown.join(timeout=5)
    assert not recovery.is_alive()
    assert not shutdown.is_alive()
    assert stopped.is_set()
    owner.close()


def test_execution_factory_resources_are_closed_if_shutdown_wins_return_race():
    import threading

    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    config.accepted.accepted = True
    binding, delegation, _ = _authority()
    entered = threading.Event()
    release = threading.Event()
    original = config.attempts.for_execution
    failures = []

    def blocking_factory(**values):
        entered.set()
        assert release.wait(timeout=5)
        return original(**values)

    config.attempts.for_execution = blocking_factory

    def execute():
        try:
            owner.runtime.execute(_Context(config.events), binding, delegation, lambda *_: None)
        except Exception as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    worker = threading.Thread(target=execute)
    worker.start()
    assert entered.wait(timeout=5)
    owner.shutdown_jobs()
    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], InstalledEngineCompositionError)
    assert [event for event in config.events if event == ("close", "attempt relays")] == [
        ("close", "attempt relays")
    ]
    assert all(event[0] != "execute" for event in config.events)
    owner.close()


def test_reconciliation_factory_resources_are_closed_if_shutdown_wins_return_race():
    import threading

    config = _configured()
    owner = config.composition
    workspace, _, _ = _bind(config)
    owner.bind(config.store, workspace)
    binding, delegation, _ = _authority()
    saved = EngineAttemptRecord.create(binding)
    reconciliation_ref = "sha256:" + "9" * 64
    config.reconciliation.plan = ClaimedEngineReconciliation(
        job_id=JOB,
        job_state="interrupted",
        binding_digest=binding.binding_digest,
        delegation_digest=delegation.delegation_digest,
        claim_ref=CLAIM,
        runtime_resolution_ref=RESOLUTION,
        reconciliation_ref=reconciliation_ref,
    )
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()
    failures = []
    original = config.attempts.for_reconciliation

    def blocking_factory(**values):
        entered.set()
        assert release.wait(timeout=5)
        return original(**values)

    config.attempts.for_reconciliation = blocking_factory

    def recover():
        try:
            with owner.reconciliation_coordinator.session(
                experiment_id=binding.experiment_id,
                attempt_id=binding.attempt_id,
            ):
                owner.runtime.reconcile_claimed(
                    binding,
                    delegation,
                    saved,
                    reconciliation_ref=reconciliation_ref,
                )
        except Exception as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    recovery = threading.Thread(target=recover)
    recovery.start()
    assert entered.wait(timeout=5)

    def stop():
        owner.shutdown_jobs()
        stopped.set()

    shutdown = threading.Thread(target=stop)
    shutdown.start()
    for _ in range(100):
        with owner._lock:
            if owner._stopping:
                break
        stopped.wait(0.01)
    assert not stopped.is_set()
    release.set()
    recovery.join(timeout=5)
    shutdown.join(timeout=5)
    assert not recovery.is_alive()
    assert not shutdown.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], EngineReconciliationError)
    assert [event for event in config.events if event == ("close", "attempt relays")] == [
        ("close", "attempt relays")
    ]
    assert all(event[0] != "reconcile_claimed" for event in config.events)
    owner.close()


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


def test_shutdown_accepts_service_jobs_before_factory_binding_and_rejects_foreign_jobs():
    config = _configured()
    owner = config.composition
    owner.shutdown_jobs(config.jobs)
    owner.shutdown_jobs(config.jobs)
    with pytest.raises(InstalledEngineCompositionError, match="another service"):
        owner.shutdown_jobs(_JobController([]))
    owner.close()
    assert config.events == [("shutdown",)]


def test_bound_shutdown_rejects_foreign_jobs_without_stopping_owners():
    config = _configured()
    _bind(config)
    with pytest.raises(InstalledEngineCompositionError, match="another service"):
        config.composition.shutdown_jobs(_JobController([]))
    assert config.events == []
    config.composition.shutdown_jobs(config.jobs)
    config.composition.close()
    assert config.events == [("shutdown",)]


def test_composition_claim_is_atomic_and_does_not_touch_protected_sources():
    import threading

    config = _configured()
    claims = []
    gate = threading.Barrier(2)

    def claim():
        gate.wait(timeout=5)
        try:
            config.composition.claim_service()
        except InstalledEngineCompositionError:
            claims.append(False)
        else:
            claims.append(True)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert sorted(claims) == [False, True]
    assert config.events == []
    config.composition.close()
