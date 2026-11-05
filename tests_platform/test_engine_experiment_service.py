from __future__ import annotations

from typing import Any, Mapping

import pytest

from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
)
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    EngineExperiment,
    _controller_observation_record,
)
from bluefire.engine_experiment_service import (
    EngineControllerAction,
    EngineControllerJobAction,
    EngineExperimentService,
    EngineExperimentServiceError,
)
from bluefire.evidence import EvidenceRecord
from bluefire.job_runtime import JobNotManaged
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.run_store import RunStoreError
from bluefire.util import content_hash
from tests_platform.test_engine_controller_jobs import _applied_experiment
from tests_platform.test_engine_experiment import (
    AFTER_SNAPSHOT,
    MECHANISM_REF,
    REPRODUCER_CHECK,
    REPRODUCER_RUN,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


EXPERIMENT_ID = "experiment-" + "1" * 32
CREATED_AT = "2026-11-04T12:00:00Z"


class _History:
    def __init__(self, experiment: EngineExperiment | None = None) -> None:
        self.experiment = experiment
        self.versions = {} if experiment is None else {experiment.revision: experiment}
        self.created_at = CREATED_AT

    def create_engine_experiment(self, experiment_id, document, *, validator):
        candidate = EngineExperiment._from_controller_mapping(validator(document))
        if self.experiment is not None:
            if self.experiment.to_dict() != candidate.to_dict():
                raise ResourceConflictError("different history")
        else:
            self.experiment = candidate
            self.versions[candidate.revision] = candidate
        return self._record()

    def save_engine_experiment(
        self,
        experiment_id,
        document,
        *,
        expected_revision,
        expected_digest,
        validator,
    ):
        assert self.experiment is not None
        if (
            experiment_id != self.experiment.experiment_id
            or expected_revision != self.experiment.revision
            or expected_digest != self.experiment.digest
        ):
            raise ResourceConflictError("stale")
        candidate = EngineExperiment._from_controller_mapping(validator(document))
        self.experiment = candidate
        self.versions[candidate.revision] = candidate
        return self._record()

    def get_engine_experiment(self, experiment_id, *, revision=None):
        assert self.experiment is not None
        if experiment_id != self.experiment.experiment_id:
            raise AssertionError("unexpected experiment")
        selected = self.experiment if revision is None else self.versions[revision]
        return self._record(selected)

    def list_engine_experiments(self, *, limit=100):
        assert limit > 0
        if self.experiment is None:
            return []
        return [
            {
                "schema_version": "bluefire.engine-experiment-head.v1",
                "experiment_id": self.experiment.experiment_id,
                "active_revision": self.experiment.revision,
                "active_digest": self.experiment.digest,
                "created_at": self.created_at,
                "updated_at": self.experiment.updated_at,
            }
        ]

    def compare_and_swap_engine_attempt_observation(
        self,
        *,
        experiment_id,
        observation,
        expected_revision,
        expected_experiment_digest,
        timestamp,
    ):
        assert self.experiment is not None
        if (
            experiment_id != self.experiment.experiment_id
            or expected_revision != self.experiment.revision
            or expected_experiment_digest != self.experiment.digest
        ):
            raise ResourceConflictError("stale")
        admitted = _controller_observation_record(
            target_snapshot_ref=observation["target_snapshot_ref"],
            mechanism_ref=observation["mechanism_ref"],
            attempt_id=observation["attempt_id"],
            check_id=observation["check_id"],
            check_input_digest=observation["check_input_digest"],
            evidence=EvidenceRecord.from_mapping(observation["evidence"]),
        )
        existing = next(
            (
                item
                for item in self.experiment.independent_observations
                if item.evidence_id == admitted.evidence_id
            ),
            None,
        )
        if existing is not None:
            if existing.to_dict() != admitted.to_dict():
                raise ProductStoreError("different evidence")
            return self.experiment.to_dict()
        candidate = self.experiment.record_independent_observation(
            admitted,
            timestamp=timestamp,
        )
        self.experiment = candidate
        self.versions[candidate.revision] = candidate
        return candidate.to_dict()

    def _record(self, selected=None):
        assert self.experiment is not None
        candidate = self.experiment if selected is None else selected
        return {
            "schema_version": "bluefire.engine-experiment-record.v1",
            "experiment_id": candidate.experiment_id,
            "revision": candidate.revision,
            "prior_digest": candidate.previous_revision_digest,
            "digest": candidate.digest,
            "document": candidate.to_dict(),
            "created_at": self.created_at,
            "active": candidate.revision == self.experiment.revision,
            "active_revision": self.experiment.revision,
        }


class _RunSource:
    def get_run(self, run_id, *, require_finalized=False):
        del run_id, require_finalized
        raise RunStoreError("run is not finalized")


class _FinalizedRunSource:
    def __init__(self, run_id: str, records: list[Mapping[str, Any]]) -> None:
        self.run_id = run_id
        self.records = records
        self.requests: list[tuple[str, bool]] = []

    def get_run(self, run_id, *, require_finalized=False):
        self.requests.append((run_id, require_finalized))
        return {
            "run_id": self.run_id,
            "evidence": {"schema_version": "1.0", "records": self.records},
        }


class _Jobs:
    def __init__(self, history: _History) -> None:
        self.history = history
        self.submissions: list[Mapping[str, Any]] = []
        self.cancelled: list[tuple[str, str, str]] = []
        self.recovered: list[tuple[str, str]] = []

    def submit(self, **values):
        self.submissions.append(values)
        return {"job_id": "job-" + "f" * 32, "state": "queued"}

    def settle_undispatched_cancellation(self, *, experiment_id, attempt_id, job_id):
        self.cancelled.append((experiment_id, attempt_id, job_id))
        assert self.history.experiment is not None
        return self.history.experiment.to_dict()

    def reconcile_interrupted_attempt(self, *, experiment_id, attempt_id):
        self.recovered.append((experiment_id, attempt_id))
        assert self.history.experiment is not None
        return self.history.experiment.to_dict()


class _Lifecycle:
    def __init__(self, state: str = "cancelled") -> None:
        self.state = state
        self.calls: list[str] = []

    def cancel(self, job_id):
        self.calls.append(job_id)
        return {"job_id": job_id, "state": self.state}


class _PresentationSource:
    def __init__(self, history: _History) -> None:
        self.history = history
        self.create_preflights: list[EngineExperiment] = []
        self.transition_preflights: list[tuple[EngineExperiment, EngineExperiment]] = []

    def assert_engine_experiment_presentation_create_ready(self, experiment):
        self.create_preflights.append(experiment)

    def assert_engine_experiment_presentation_transition_ready(self, current, successor):
        self.transition_preflights.append((current, successor))

    def get_engine_experiment_presentation(self, experiment_id, *, revision, experiment_digest):
        experiment = self.history.versions[revision]
        assert experiment.experiment_id == experiment_id
        assert experiment.digest == experiment_digest
        return self.presentation_for(experiment)

    def presentation_for(self, experiment):
        if experiment.attempts:
            binding = experiment.attempts[0].record.binding
            engine = {
                "id": binding.engine_id,
                "display_name": "Strix",
                "version": binding.engine_version,
                "revision": binding.engine_revision,
                "package_digest": binding.engine_package_digest,
                "sandbox_image_digest": _digest("b"),
            }
            model = {
                "provider": binding.model_provider,
                "id": binding.model_id,
                "data_destination": binding.model_data_destination,
                "authorization_digest": binding.model_authorization_ref,
                "test_provider": True,
            }
            limits = {
                "wall_clock_seconds": binding.wall_clock_seconds,
                "action_limit": binding.action_limit,
                "artifact_byte_limit": binding.artifact_byte_limit,
                "cost_limit_microunits": binding.cost_limit_microunits,
            }
        else:
            engine = {
                "id": "strix",
                "display_name": "Strix",
                "version": "1.7.0",
                "revision": "7" * 40,
                "package_digest": _digest("7"),
                "sandbox_image_digest": _digest("b"),
            }
            model = {
                "provider": "provider.test",
                "id": "test-model",
                "data_destination": "https://model.test/v1",
                "authorization_digest": _digest("9"),
                "test_provider": True,
            }
            limits = {
                "wall_clock_seconds": 300,
                "action_limit": 20,
                "artifact_byte_limit": 4 * 1024 * 1024,
                "cost_limit_microunits": 1_000_000,
            }
        current_target = (
            None
            if experiment.current_target_snapshot_ref is None
            else {
                "snapshot_ref": experiment.current_target_snapshot_ref,
                "display_name": "Generated tenant-record target",
                "captured_at": experiment.updated_at,
            }
        )
        change = experiment.defense_change
        defensive_change = (
            None
            if change is None
            else {
                "change_id": change.change_id,
                "state": change.state.value,
                "kind": "identity",
                "summary": "Require a signed session for protected tenant reads.",
                "mechanism_ref": change.mechanism_ref,
                "before_target_snapshot_ref": change.before_target_snapshot_ref,
                "after_target_snapshot_ref": change.after_target_snapshot_ref,
                "rollback_digest": change.rollback_digest,
                "applied_at": change.applied_at,
            }
        )
        return {
            "schema_version": "bluefire.engine-experiment-presentation.v1",
            "experiment_id": experiment.experiment_id,
            "revision": experiment.revision,
            "experiment_digest": experiment.digest,
            "objective": {
                "objective_ref": experiment.objective_ref,
                "title": "Protect generated tenant records",
                "summary": "Test the original failure, apply a bounded defense, and retest it.",
            },
            "environment": {
                "environment_ref": experiment.environment_ref,
                "environment_id": "tenant-record-lab",
                "display_name": "Disposable tenant-record lab",
                "platform": "linux",
                "disposable": True,
            },
            "current_target": current_target,
            "engine_setup": {"engine": engine, "model": model},
            "authorization": {
                "scope_ref": experiment.scope_ref,
                "scope_version": experiment.scope_version,
                **limits,
            },
            "defensive_change": defensive_change,
            "selection": None,
            "limitations": ["Controlled test-provider responses only."],
        }


class _NoopController:
    def perform(self, *, action, experiment, request_ref):
        del action, request_ref
        return experiment._changed(timestamp=experiment.updated_at)


class _ControllerJobs:
    def __init__(self, history: _History | None = None) -> None:
        self.history = history
        self.requests: list[Mapping[str, Any]] = []
        self.cancelled_checks: list[tuple[str, str, str]] = []
        self.state = "queued"

    def submit(self, **values):
        self.requests.append(values)
        return {
            "schema_version": "bluefire.engine-controller-job-submission.v1",
            "job_id": "job-" + "e" * 32,
            "kind": "engine-controller-operation",
            "experiment_id": values["experiment"].experiment_id,
            "action": values["action"].value,
            "submission_id": values["submission_id"],
            "intent_digest": values["intent_digest"],
            "state": self.state,
        }

    def settle_undispatched_check_cancellation(
        self, *, experiment_id: str, check_id: str, job_id: str
    ):
        self.cancelled_checks.append((experiment_id, check_id, job_id))
        history = self.history
        assert history is not None and history.experiment is not None
        experiment = history.experiment
        _index, check = experiment._check(check_id)
        settled_at = "2026-11-04T12:09:00Z"
        terminal = check.settle(
            state=ControllerCheckState.UNKNOWN,
            result_digest=_digest("e"),
            independent_evidence_refs=(),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("d"),
            settled_at=settled_at,
        )
        history.experiment = experiment.settle_controller_check(terminal, timestamp=settled_at)
        history.versions[history.experiment.revision] = history.experiment
        return history.experiment.to_dict()


class _UnboundControllerJobs(_ControllerJobs):
    def submit(self, **values):
        result = dict(super().submit(**values))
        result["action"] = "rollback_defense"
        return result


def _new_experiment() -> EngineExperiment:
    return EngineExperiment.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        scope_ref=_digest("3"),
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=_digest("4"),
        created_at=CREATED_AT,
    )


def _reserve_baseline(experiment: EngineExperiment) -> EngineExperiment:
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": "engine-attempt-" + "a" * 32,
            "run_id": "run-20261104T120100Z-" + "a" * 16,
            "role": AttemptRole.BASELINE.value,
            "objective_ref": _digest("1"),
            "environment_ref": _digest("2"),
            "target_snapshot_ref": _digest("4"),
            "scope_ref": _digest("3"),
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "engine_id": "strix",
            "engine_version": "1.7.0",
            "engine_revision": "7" * 40,
            "engine_package_digest": _digest("7"),
            "policy_overlay_digest": _digest("8"),
            "model_provider": "provider.test",
            "model_id": "test-model",
            "model_data_destination": "https://model.test/v1",
            "model_authorization_ref": _digest("9"),
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": "2026-11-04T12:01:00Z",
            "parent_attempt_id": None,
        }
    )
    return experiment.reserve_attempt(
        binding,
        job_id="job-" + "a" * 32,
        delegation_digest=_digest("a"),
        execution_approval_digest=_digest("b"),
        execution_approval_id="approval-" + "a" * 32,
        timestamp="2026-11-04T12:01:00Z",
    )


def _settle_cancelled(experiment: EngineExperiment) -> EngineExperiment:
    queued = experiment.attempts[0].record
    preflight = queued.transition(AttemptState.PREFLIGHT, timestamp="2026-11-04T12:02:00Z")
    experiment = experiment.update_attempt_record(preflight, timestamp="2026-11-04T12:02:00Z")
    running = preflight.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-aabbccdd",
        timestamp="2026-11-04T12:02:10Z",
    )
    experiment = experiment.update_attempt_record(running, timestamp="2026-11-04T12:02:10Z")
    cancelled = running.transition(
        AttemptState.CANCELLED,
        timestamp="2026-11-04T12:02:20Z",
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="controller_cancelled",
    )
    return experiment.settle_attempt(
        cancelled,
        engine_evidence=(),
        artifact_manifest_ref=None,
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("d"),
        settled_at="2026-11-04T12:02:20Z",
    )


def _service(
    history: _History,
    *,
    controller=None,
    controller_jobs=None,
    clock=None,
    presentation_source=None,
    run_source=None,
    lifecycle=None,
) -> tuple[EngineExperimentService, _Jobs]:
    jobs = _Jobs(history)
    return (
        EngineExperimentService(
            history=history,
            run_source=run_source or _RunSource(),
            jobs=jobs,  # type: ignore[arg-type]
            job_lifecycle=lifecycle or _Lifecycle(),
            controller=controller,
            clock=(lambda: CREATED_AT) if clock is None else clock,
            presentation_source=presentation_source or _PresentationSource(history),
            controller_jobs=controller_jobs,
        ),
        jobs,
    )


def _reserved_reproducer_check() -> EngineExperiment:
    experiment = _applied_experiment()
    created_at = "2026-11-04T12:08:00Z"
    check = ControllerCheckRecord.reserve(
        check_id=REPRODUCER_CHECK,
        experiment_id=experiment.experiment_id,
        job_id="job-" + "e" * 32,
        run_id=REPRODUCER_RUN,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("c"),
        created_at=created_at,
    )
    return experiment.reserve_controller_check(check, timestamp=created_at)


def test_create_read_list_and_workspace_share_one_canonical_head() -> None:
    history = _History()
    service, _jobs = _service(history)

    workspace = service.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        scope_ref=_digest("3"),
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=_digest("4"),
    )

    assert workspace["schema_version"] == "bluefire.engine-experiment-workspace.v1"
    assert workspace["revision"] == 1
    assert workspace["projection"]["workflow_state"] == "ready_for_baseline"
    assert workspace["projection"]["experiment_digest"] == workspace["experiment_digest"]
    saved = service.get(EXPERIMENT_ID)
    assert saved["record"]["digest"] == workspace["experiment_digest"]
    assert service.workspace(EXPERIMENT_ID) == workspace
    assert service.list()["experiments"] == [
        {
            "schema_version": "bluefire.engine-experiment-head.v1",
            "experiment_id": EXPERIMENT_ID,
            "active_revision": 1,
            "active_digest": workspace["experiment_digest"],
            "created_at": CREATED_AT,
            "updated_at": CREATED_AT,
        }
    ]


def test_create_preflights_exact_presentation_before_persisting() -> None:
    history = _History()
    presentation = _PresentationSource(history)
    service, _jobs = _service(history, presentation_source=presentation)

    service.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref=_digest("1"),
        environment_ref=_digest("2"),
        scope_ref=_digest("3"),
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=_digest("4"),
    )

    assert len(presentation.create_preflights) == 1
    candidate = presentation.create_preflights[0]
    assert candidate.revision == 1
    assert candidate.created_at == CREATED_AT
    assert history.experiment == candidate


def test_unprovisioned_presentation_refuses_create_without_history() -> None:
    history = _History()

    class _Unprovisioned(_PresentationSource):
        def assert_engine_experiment_presentation_create_ready(self, experiment):
            del experiment
            raise ProductStoreError("presentation is not provisioned")

    service, _jobs = _service(
        history,
        presentation_source=_Unprovisioned(history),
    )

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.create(
            experiment_id=EXPERIMENT_ID,
            objective_ref=_digest("1"),
            environment_ref=_digest("2"),
            scope_ref=_digest("3"),
            scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
            target_snapshot_ref=_digest("4"),
        )

    assert caught.value.code == "engine_experiment_unavailable"
    assert history.experiment is None


def test_json_create_uses_trusted_clock_and_rejects_caller_time() -> None:
    history = _History()
    service, _jobs = _service(history)
    request = {
        "schema_version": "bluefire.engine-experiment-create.v1",
        "experiment_id": EXPERIMENT_ID,
        "objective_ref": _digest("1"),
        "environment_ref": _digest("2"),
        "scope_ref": _digest("3"),
        "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
        "target_snapshot_ref": _digest("4"),
    }

    workspace = service.create_request(request)
    assert workspace["revision"] == 1
    assert service.get(EXPERIMENT_ID)["experiment"]["created_at"] == CREATED_AT

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.create_request({**request, "created_at": "2099-01-01T00:00:00Z"})
    assert caught.value.code == "engine_request_invalid"


def test_create_retry_reopens_same_identity_when_trusted_clock_advances() -> None:
    history = _History()
    times = iter((CREATED_AT, "2026-11-04T12:00:05Z"))
    service, _jobs = _service(history, clock=lambda: next(times))
    values = {
        "experiment_id": EXPERIMENT_ID,
        "objective_ref": _digest("1"),
        "environment_ref": _digest("2"),
        "scope_ref": _digest("3"),
        "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
        "target_snapshot_ref": _digest("4"),
    }

    first = service.create(**values)
    replay = service.create(**values)

    assert replay == first
    assert service.get(EXPERIMENT_ID)["experiment"]["created_at"] == CREATED_AT


def test_record_integrity_and_stale_controller_transition_fail_closed() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history, controller=_NoopController())
    stale = _digest("f")

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.perform_controller_transition(
            experiment_id=EXPERIMENT_ID,
            expected_revision=1,
            expected_digest=stale,
            action=EngineControllerAction.REVIEW_DEFENSE,
            request_ref=_digest("5"),
        )
    assert caught.value.code == "engine_experiment_conflict"

    current = history.experiment
    assert current is not None
    with pytest.raises(EngineExperimentServiceError) as caught:
        service.perform_controller_transition(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            action=EngineControllerAction.REVIEW_DEFENSE,
            request_ref=_digest("5"),
        )
    assert caught.value.code == "engine_controller_refused"
    assert history.experiment == current

    record = dict(history._record())
    record["digest"] = _digest("e")
    history.get_engine_experiment = lambda *_args, **_kwargs: record  # type: ignore[method-assign]
    with pytest.raises(EngineExperimentServiceError) as caught:
        service.get(EXPERIMENT_ID)
    assert caught.value.code == "engine_experiment_unavailable"


def test_unprovisioned_successor_presentation_refuses_transition_without_history() -> None:
    from bluefire.engine_experiment import _controller_observation_record
    from tests_platform.test_engine_experiment import (
        BASELINE_ATTEMPT,
        BASELINE_RUN,
        INITIAL_SNAPSHOT,
        MECHANISM_REF,
        _defense,
        _settle_latest_attempt,
        _tenant_observation,
    )

    current = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:03:00Z",
            hardened=False,
        ),
    )
    current = current.record_independent_observation(
        observation,
        timestamp="2026-11-04T12:05:00Z",
    )
    successor = current.review_defense(
        _defense(),
        timestamp="2026-11-04T12:06:00Z",
    )
    history = _History(current)

    class _ReviewController:
        def perform(self, *, action, experiment, request_ref):
            del action, request_ref
            assert experiment == current
            return successor

    class _UnprovisionedSuccessor(_PresentationSource):
        def assert_engine_experiment_presentation_transition_ready(self, current, successor):
            del current, successor
            raise ProductStoreError("successor presentation is not provisioned")

    service, _jobs = _service(
        history,
        controller=_ReviewController(),
        presentation_source=_UnprovisionedSuccessor(history),
    )

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.perform_controller_transition(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            action=EngineControllerAction.REVIEW_DEFENSE,
            request_ref=_digest("5"),
        )

    assert caught.value.code == "engine_experiment_unavailable"
    assert history.experiment == current
    assert history.versions == {current.revision: current}


def test_json_transition_contract_rejects_extras_and_never_accepts_evidence() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history)
    current = history.experiment
    assert current is not None
    request = {
        "schema_version": "bluefire.engine-controller-transition.v1",
        "expected_revision": current.revision,
        "expected_digest": current.digest,
        "action": "review_defense",
        "request_ref": _digest("5"),
        "evidence": {"assessment": "unauthorized_disclosure"},
    }

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.perform_controller_transition_request(EXPERIMENT_ID, request)
    assert caught.value.code == "engine_request_invalid"

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.submit_attempt_request(
            {
                "schema_version": "bluefire.engine-attempt-submit.v1",
                "experiment_id": EXPERIMENT_ID,
            }
        )
    assert caught.value.code == "engine_request_invalid"


def test_internal_attempt_observation_requires_exact_finalized_run_and_is_idempotent() -> None:
    from tests_platform.test_engine_experiment import (
        BASELINE_ATTEMPT,
        BASELINE_RUN,
        INITIAL_SNAPSHOT,
        MECHANISM_REF,
        _settle_latest_attempt,
        _tenant_observation,
    )

    current = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:03:00Z",
            hardened=False,
        ),
    )
    history = _History(current)
    runs = _FinalizedRunSource(BASELINE_RUN, [observation.evidence.to_dict()])
    presentation = _PresentationSource(history)
    service, _jobs = _service(
        history,
        run_source=runs,
        presentation_source=presentation,
        clock=lambda: "2026-11-04T12:05:00Z",
    )

    workspace = service.record_engine_attempt_observation(
        experiment_id=EXPERIMENT_ID,
        expected_revision=current.revision,
        expected_digest=current.digest,
        observation=observation,
    )

    assert workspace["revision"] == current.revision + 1
    assert history.experiment is not None
    assert history.experiment.independent_observations == (observation,)
    assert runs.requests
    assert all(request == (BASELINE_RUN, True) for request in runs.requests)
    assert presentation.transition_preflights == [(current, history.experiment)]

    replay = service.record_engine_attempt_observation(
        experiment_id=EXPERIMENT_ID,
        expected_revision=history.experiment.revision,
        expected_digest=history.experiment.digest,
        observation=observation,
    )
    assert replay["revision"] == workspace["revision"]
    assert history.experiment.revision == workspace["revision"]
    assert presentation.transition_preflights == [(current, history.experiment)]

    unavailable_history = _History(current)
    unavailable, _jobs = _service(
        unavailable_history,
        clock=lambda: "2026-11-04T12:05:00Z",
    )
    with pytest.raises(EngineExperimentServiceError) as caught:
        unavailable.record_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            observation=observation,
        )
    assert caught.value.code == "engine_evidence_unavailable"
    assert unavailable_history.experiment == current

    absent_history = _History(current)
    absent, _jobs = _service(
        absent_history,
        run_source=_FinalizedRunSource(BASELINE_RUN, []),
        clock=lambda: "2026-11-04T12:05:00Z",
    )
    with pytest.raises(EngineExperimentServiceError) as caught:
        absent.record_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            observation=observation,
        )
    assert caught.value.code == "engine_experiment_refused"
    assert absent_history.experiment == current


def test_controller_effect_is_a_visible_job_and_does_not_mutate_inline() -> None:
    history = _History(_new_experiment())
    controller_jobs = _ControllerJobs()
    service, _jobs = _service(history, controller_jobs=controller_jobs)
    current = history.experiment
    assert current is not None
    request_ref = _digest("5")
    public_request = {
        "schema_version": "bluefire.engine-controller-job.v1",
        "experiment_id": EXPERIMENT_ID,
        "revision": current.revision,
        "experiment_digest": current.digest,
        "action": EngineControllerJobAction.APPLY_DEFENSE.value,
        "request_ref": request_ref,
    }

    job = service.submit_controller_operation_request(
        EXPERIMENT_ID,
        {
            "schema_version": "bluefire.engine-controller-job-submit.v1",
            "expected_revision": current.revision,
            "expected_digest": current.digest,
            "action": "apply_defense",
            "request_ref": request_ref,
            "submission_id": "11111111-1111-4111-8111-111111111111",
            "intent_digest": content_hash(public_request),
        },
    )

    assert job == {
        "schema_version": "bluefire.engine-controller-job-submission.v1",
        "job_id": "job-" + "e" * 32,
        "kind": "engine-controller-operation",
        "experiment_id": EXPERIMENT_ID,
        "action": "apply_defense",
        "submission_id": "11111111-1111-4111-8111-111111111111",
        "intent_digest": content_hash(public_request),
        "state": "queued",
    }
    assert history.experiment == current
    assert controller_jobs.requests[0]["action"] is EngineControllerJobAction.APPLY_DEFENSE

    controller_jobs.state = "completed"
    replay = service.submit_controller_operation_request(
        EXPERIMENT_ID,
        {
            "schema_version": "bluefire.engine-controller-job-submit.v1",
            "expected_revision": current.revision,
            "expected_digest": current.digest,
            "action": "apply_defense",
            "request_ref": request_ref,
            "submission_id": "11111111-1111-4111-8111-111111111111",
            "intent_digest": content_hash(public_request),
        },
    )
    assert replay["job_id"] == job["job_id"]
    assert replay["state"] == "completed"


def test_controller_job_rejects_noncanonical_submission_and_unbound_receipt() -> None:
    history = _History(_new_experiment())
    current = history.experiment
    assert current is not None
    request_ref = _digest("5")
    intent = content_hash(
        {
            "schema_version": "bluefire.engine-controller-job.v1",
            "experiment_id": EXPERIMENT_ID,
            "revision": current.revision,
            "experiment_digest": current.digest,
            "action": "apply_defense",
            "request_ref": request_ref,
        }
    )
    service, _jobs = _service(history, controller_jobs=_ControllerJobs())

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.submit_controller_operation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            action=EngineControllerJobAction.APPLY_DEFENSE,
            request_ref=request_ref,
            submission_id="NOT-A-CANONICAL-UUID",
            intent_digest=intent,
        )
    assert caught.value.code == "engine_experiment_refused"

    unbound, _jobs = _service(history, controller_jobs=_UnboundControllerJobs())
    with pytest.raises(EngineExperimentServiceError) as caught:
        unbound.submit_controller_operation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            action=EngineControllerJobAction.APPLY_DEFENSE,
            request_ref=request_ref,
            submission_id="11111111-1111-4111-8111-111111111111",
            intent_digest=intent,
        )
    assert caught.value.code == "engine_controller_refused"


def test_cancel_and_recover_delegate_without_resubmitting() -> None:
    experiment = _reserve_baseline(_new_experiment())
    history = _History(experiment)
    service, jobs = _service(history)
    attempt = experiment.attempts[0]

    cancelled = service.cancel_attempt(
        experiment_id=EXPERIMENT_ID,
        attempt_id=attempt.record.binding.attempt_id,
        job_id=attempt.job_id,
    )
    assert cancelled["job"]["state"] == "cancelled"
    assert jobs.cancelled == [(EXPERIMENT_ID, attempt.record.binding.attempt_id, attempt.job_id)]

    recovered = service.recover_attempt(
        experiment_id=EXPERIMENT_ID,
        attempt_id=attempt.record.binding.attempt_id,
    )
    assert recovered["projection"]["workflow_state"] == "baseline_active"
    assert jobs.recovered == [(EXPERIMENT_ID, attempt.record.binding.attempt_id)]


def test_cancel_does_not_reclassify_callback_settlement_as_undispatched() -> None:
    experiment = _settle_cancelled(_reserve_baseline(_new_experiment()))
    history = _History(experiment)
    service, jobs = _service(history)
    attempt = experiment.attempts[0]

    result = service.cancel_attempt(
        experiment_id=EXPERIMENT_ID,
        attempt_id=attempt.record.binding.attempt_id,
        job_id=attempt.job_id,
    )

    assert result["job"]["state"] == "cancelled"
    assert jobs.cancelled == []


def test_cancel_controller_check_settles_undispatched_state_once() -> None:
    experiment = _reserved_reproducer_check()
    history = _History(experiment)
    lifecycle = _Lifecycle()
    controller_jobs = _ControllerJobs(history)
    service, _jobs = _service(
        history,
        controller_jobs=controller_jobs,
        lifecycle=lifecycle,
    )
    check = experiment.checks[0]

    first = service.cancel_controller_check(
        experiment_id=EXPERIMENT_ID,
        check_id=check.check_id,
        job_id=check.job_id,
    )
    second = service.cancel_controller_check(
        experiment_id=EXPERIMENT_ID,
        check_id=check.check_id,
        job_id=check.job_id,
    )

    assert first["job"]["state"] == "cancelled"
    assert second["job"] == first["job"]
    assert controller_jobs.cancelled_checks == [(EXPERIMENT_ID, check.check_id, check.job_id)]
    assert lifecycle.calls == [check.job_id, check.job_id]
    assert history.experiment is not None
    settled = history.experiment.checks[0]
    assert settled.state is ControllerCheckState.UNKNOWN
    assert settled.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert second["workspace"]["experiment_digest"] == history.experiment.digest


@pytest.mark.parametrize("job_state", ["cancelling", "failed", "completed", "interrupted"])
def test_cancel_controller_check_does_not_reclassify_dispatched_or_terminal_work(
    job_state: str,
) -> None:
    experiment = _reserved_reproducer_check()
    history = _History(experiment)
    lifecycle = _Lifecycle(job_state)
    controller_jobs = _ControllerJobs(history)
    service, _jobs = _service(
        history,
        controller_jobs=controller_jobs,
        lifecycle=lifecycle,
    )
    check = experiment.checks[0]

    result = service.cancel_controller_check(
        experiment_id=EXPERIMENT_ID,
        check_id=check.check_id,
        job_id=check.job_id,
    )

    assert result["job"]["state"] == job_state
    assert controller_jobs.cancelled_checks == []
    assert history.experiment is not None
    assert history.experiment.checks[0].state is ControllerCheckState.RESERVED


def test_cancel_controller_check_refuses_before_job_control_without_adapter_or_binding() -> None:
    experiment = _reserved_reproducer_check()
    history = _History(experiment)
    lifecycle = _Lifecycle()
    service, _jobs = _service(history, lifecycle=lifecycle)
    check = experiment.checks[0]

    with pytest.raises(EngineExperimentServiceError) as unavailable:
        service.cancel_controller_check(
            experiment_id=EXPERIMENT_ID,
            check_id=check.check_id,
            job_id=check.job_id,
        )
    assert unavailable.value.code == "engine_controller_refused"

    controller_jobs = _ControllerJobs(history)
    bound, _jobs = _service(
        history,
        controller_jobs=controller_jobs,
        lifecycle=lifecycle,
    )
    with pytest.raises(EngineExperimentServiceError) as changed:
        bound.cancel_controller_check(
            experiment_id=EXPERIMENT_ID,
            check_id=check.check_id,
            job_id="job-" + "f" * 32,
        )
    assert changed.value.code == "engine_experiment_refused"
    assert lifecycle.calls == []
    assert controller_jobs.cancelled_checks == []


def test_cancel_controller_check_after_restart_requires_recovery_without_replay() -> None:
    class _RestartedLifecycle(_Lifecycle):
        def cancel(self, job_id):
            self.calls.append(job_id)
            raise JobNotManaged("callback owner ended")

    experiment = _reserved_reproducer_check()
    history = _History(experiment)
    lifecycle = _RestartedLifecycle()
    controller_jobs = _ControllerJobs(history)
    service, _jobs = _service(
        history,
        controller_jobs=controller_jobs,
        lifecycle=lifecycle,
    )
    check = experiment.checks[0]

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.cancel_controller_check(
            experiment_id=EXPERIMENT_ID,
            check_id=check.check_id,
            job_id=check.job_id,
        )

    assert caught.value.code == "engine_job_unavailable"
    assert lifecycle.calls == [check.job_id]
    assert controller_jobs.cancelled_checks == []
    assert history.experiment is not None
    assert history.experiment.checks[0].state is ControllerCheckState.RESERVED


def test_workspace_projection_is_digest_bound() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history)
    workspace = service.workspace(EXPERIMENT_ID)

    assert workspace["projection"]["experiment_digest"] == workspace["experiment_digest"]


def test_assistant_context_is_bound_to_the_exact_canonical_workspace() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history)
    workspace = service.workspace(EXPERIMENT_ID)
    selection = {
        "kind": "engine_experiment",
        "experiment_id": EXPERIMENT_ID,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": None,
        "check_id": None,
    }

    context = service.assistance_context_request(EXPERIMENT_ID, selection)

    assert context["schema_version"] == "bluefire.assistance-context.v1"
    assert context["selected"] == selection
    assert context["analysis_only"] is True
    assert context["capabilities"] == []
    assert context["reference_summary"]["workspace_digest"] == workspace["workspace_digest"]


def test_assistant_context_rebuilds_one_exact_selected_attempt() -> None:
    experiment = _reserve_baseline(_new_experiment())
    history = _History(experiment)
    service, _jobs = _service(history)
    attempt_id = experiment.attempts[0].record.binding.attempt_id
    workspace = service.workspace(EXPERIMENT_ID, selected_attempt_id=attempt_id)
    selection = {
        "kind": "engine_experiment",
        "experiment_id": EXPERIMENT_ID,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": attempt_id,
        "check_id": None,
    }

    context = service.assistance_context_request(EXPERIMENT_ID, selection)

    assert context["selected"] == selection
    assert context["reference_summary"]["selected_record"]["kind"] == "engine_attempt"
    assert context["reference_summary"]["selected_record"]["id"] == attempt_id


def test_assistant_context_refuses_stale_digest_without_provider_or_effect_work() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history)
    workspace = service.workspace(EXPERIMENT_ID)
    selection = {
        "kind": "engine_experiment",
        "experiment_id": EXPERIMENT_ID,
        "workspace_digest": _digest("f"),
        "attempt_id": None,
        "check_id": None,
    }
    assert selection["workspace_digest"] != workspace["workspace_digest"]

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.assistance_context_request(EXPERIMENT_ID, selection)

    assert caught.value.code == "engine_assistance_context_unavailable"


def test_assistant_context_refuses_path_and_selection_identity_drift() -> None:
    history = _History(_new_experiment())
    service, _jobs = _service(history)
    workspace = service.workspace(EXPERIMENT_ID)
    selection = {
        "kind": "engine_experiment",
        "experiment_id": "experiment-" + "2" * 32,
        "workspace_digest": workspace["workspace_digest"],
        "attempt_id": None,
        "check_id": None,
    }

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.assistance_context_request(EXPERIMENT_ID, selection)

    assert caught.value.code == "engine_request_invalid"


def test_workspace_deep_link_binds_exactly_one_saved_selection() -> None:
    experiment = _reserve_baseline(_new_experiment())
    history = _History(experiment)
    service, _jobs = _service(history)
    entry = experiment.attempts[0]

    workspace = service.workspace(
        EXPERIMENT_ID,
        selected_attempt_id=entry.record.binding.attempt_id,
    )
    selected = workspace["selected_context"]
    assert selected["kind"] == "engine_attempt"
    assert selected["attempt"]["attempt_id"] == entry.record.binding.attempt_id
    assert selected["attempt"]["job_id"] == entry.job_id
    assert selected["attempt"]["run_id"] == entry.record.binding.run_id
    assert selected["attempt"]["role"] == "baseline"

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.workspace(
            EXPERIMENT_ID,
            selected_attempt_id=entry.record.binding.attempt_id,
            selected_check_id="controller-check-" + "c" * 32,
        )
    assert caught.value.code == "engine_request_invalid"

    with pytest.raises(EngineExperimentServiceError) as caught:
        service.workspace(
            EXPERIMENT_ID,
            selected_attempt_id="engine-attempt-" + "f" * 32,
        )
    assert caught.value.code == "engine_selection_not_found"


def test_workspace_reopens_exact_historical_presentation_revision() -> None:
    first = _new_experiment()
    history = _History(first)
    second = first._changed(timestamp="2026-11-04T12:00:05Z")
    history.save_engine_experiment(
        EXPERIMENT_ID,
        second.to_dict(),
        expected_revision=first.revision,
        expected_digest=first.digest,
        validator=lambda value: EngineExperiment._from_controller_mapping(value).to_dict(),
    )
    service, _jobs = _service(history)

    current = service.workspace(EXPERIMENT_ID)
    historical = service.workspace(EXPERIMENT_ID, revision=1)

    assert current["revision"] == 2
    assert historical["revision"] == 1
    assert historical["experiment_digest"] == first.digest
    assert current["experiment_digest"] == second.digest
    assert historical["current_target"]["captured_at"] == CREATED_AT
    assert current["current_target"]["captured_at"] == "2026-11-04T12:00:05Z"
