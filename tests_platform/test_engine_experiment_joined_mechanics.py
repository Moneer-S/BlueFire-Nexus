"""Joined non-live product proof for the external-engine defense workflow.

This test deliberately uses deterministic in-process collaborators for the
external engine and disposable target.  Product identity, approval, job,
history, evidence, presentation, API, restart, and no-replay behavior use the
real BlueFire implementations.  It is not native Strix or live-model proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from bluefire.api_routes import APIRoutes
from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
)
from bluefire.engine_controller_jobs import (
    ControllerCheckRecovery,
    ControllerCheckSettlement,
    DefenseOperation,
    DefenseOperationSettlement,
)
from bluefire.engine_controller_jobs import (
    EngineControllerJobs as TrustedControllerJobs,
)
from bluefire.engine_delegation import EngineCapabilityDelegation
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    DefenseState,
    EngineDefenseChange,
    EngineExperiment,
    IndependentObservationRecord,
    _controller_observation_record,
)
from bluefire.engine_experiment_api import dispatch_engine_experiments
from bluefire.engine_experiment_jobs import EngineExperimentJobs, EngineRuntimeSettlement
from bluefire.engine_experiment_service import (
    EngineControllerAction,
    EngineControllerJobAction,
    EngineExperimentService,
)
from bluefire.job_runtime import JobState, RunJobController
from bluefire.product_store import ProductStore
from bluefire.run_store import RunStore
from bluefire.util import content_hash
from tests_platform.test_engine_experiment import _digest, _tenant_observation

EXPERIMENT_ID = "experiment-" + "1" * 32
OBJECTIVE_REF = _digest("1")
ENVIRONMENT_REF = _digest("2")
SCOPE_REF = _digest("3")
INITIAL_SNAPSHOT = _digest("4")
AFTER_SNAPSHOT = _digest("5")
MECHANISM_REF = _digest("6")
BASELINE_ATTEMPT = "engine-attempt-" + "a" * 32
ADAPTIVE_ATTEMPT = "engine-attempt-" + "b" * 32
REPRODUCER_CHECK = "controller-check-" + "c" * 32
LEGITIMATE_CHECK = "controller-check-" + "d" * 32
DEFENSE_CHANGE = "defense-change-" + "e" * 32
ROOT = "/api/v1/engine-experiments"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class _Timeline:
    def __init__(self) -> None:
        self.base = datetime.now(timezone.utc).replace(microsecond=0)
        self.offset = -1

    def __call__(self) -> str:
        self.offset += 1
        return _iso(self.base + timedelta(seconds=self.offset))


class _Handler:
    def __init__(self, service: EngineExperimentService, path: str) -> None:
        self.path = path
        self.platform_server = SimpleNamespace(
            service=SimpleNamespace(engine_experiment_service=service)
        )
        self.errors: list[tuple[int, str, str]] = []
        self.allowed: list[str] = []
        self.responses: list[Mapping[str, Any]] = []

    @property
    def _routes(self) -> APIRoutes:
        return APIRoutes(self)

    def _error(self, status: int, code: str, message: str) -> None:
        self.errors.append((status, code, message))

    def _method_not_allowed(self, allow: str) -> None:
        self.allowed.append(allow)

    def _dispatch(self, callback: Any) -> None:
        self.responses.append(callback())


def _dispatch(
    service: EngineExperimentService,
    path: str,
    body: Mapping[str, Any] | None = None,
    *,
    raw_path: str | None = None,
) -> Mapping[str, Any]:
    handler = _Handler(service, raw_path or path)
    assert dispatch_engine_experiments(handler, path, body)
    assert handler.errors == []
    assert handler.allowed == []
    assert len(handler.responses) == 1
    return handler.responses[0]


def _profile() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-presentation-profile.v1",
        "experiment_id": EXPERIMENT_ID,
        "objective": {
            "objective_ref": OBJECTIVE_REF,
            "title": "Protect generated tenant records",
            "summary": "Test the original route, apply signed sessions, and retest it.",
        },
        "environment": {
            "environment_ref": ENVIRONMENT_REF,
            "environment_id": "tenant-record-lab",
            "display_name": "Disposable tenant-record lab",
            "platform": "linux",
            "disposable": True,
        },
        "initial_target_snapshot_ref": INITIAL_SNAPSHOT,
        "engine_setup": {
            "engine": {
                "id": "strix",
                "display_name": "Strix",
                "version": "1.7.0",
                "revision": "7" * 40,
                "package_digest": _digest("7"),
                "sandbox_image_digest": _digest("8"),
            },
            "model": {
                "provider": "provider.test",
                "id": "controlled-provider",
                "data_destination": "https://model.test/v1",
                "authorization_digest": _digest("9"),
                "test_provider": True,
            },
        },
        "authorization": {
            "scope_ref": SCOPE_REF,
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "cost_limit_microunits": 1_000_000,
        },
        "limitations": [
            "Controlled test-provider mechanics only; live-model inference is not proven.",
            "In-process fake runtime does not prove native Strix execution or containment.",
            "Sandbox image and test-provider identities describe prepared setup; attempt records do not independently attest them.",
        ],
    }


def _target(snapshot_ref: str, captured_at: str, display_name: str) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-target-presentation.v1",
        "experiment_id": EXPERIMENT_ID,
        "snapshot_ref": snapshot_ref,
        "display_name": display_name,
        "captured_at": captured_at,
    }


def _defense_presentation() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-defense-presentation.v1",
        "experiment_id": EXPERIMENT_ID,
        "change_id": DEFENSE_CHANGE,
        "kind": "identity",
        "summary": "Required a target-bound signed session for protected tenant records.",
    }


def _run_handle(store: RunStore) -> str:
    return store.create_run(
        scenario={"schema_version": "bluefire.scenario.v1", "id": "tenant-record-test"},
        plan={"schema_version": "bluefire.plan.v1", "steps": []},
        policy={"schema_version": "bluefire.policy.v1", "allowed": True},
        profile=None,
    ).run_id


def _finalize_run(store: RunStore, run_id: str, evidence: list[Mapping[str, Any]]) -> None:
    created_at = store.get_run(run_id)["created_at"]
    store.finalize(
        run_id,
        result={
            "schema_version": "bluefire.run-result.v1",
            "status": "completed",
            "created_at": created_at,
        },
        evidence=evidence,
        detections=[],
    )


def _binding(
    *,
    role: AttemptRole,
    attempt_id: str,
    run_id: str,
    target_snapshot_ref: str,
    created_at: str,
    parent_attempt_id: str | None,
) -> EngineAttemptBinding:
    return EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": EXPERIMENT_ID,
            "attempt_id": attempt_id,
            "run_id": run_id,
            "role": role.value,
            "objective_ref": OBJECTIVE_REF,
            "environment_ref": ENVIRONMENT_REF,
            "target_snapshot_ref": target_snapshot_ref,
            "scope_ref": SCOPE_REF,
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "engine_id": "strix",
            "engine_version": "1.7.0",
            "engine_revision": "7" * 40,
            "engine_package_digest": _digest("7"),
            "policy_overlay_digest": _digest("a"),
            "model_provider": "provider.test",
            "model_id": "controlled-provider",
            "model_data_destination": "https://model.test/v1",
            "model_authorization_ref": _digest("9"),
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": created_at,
            "parent_attempt_id": parent_attempt_id,
        }
    )


def _delegation(binding: EngineAttemptBinding, timeline: _Timeline) -> EngineCapabilityDelegation:
    binding_time = datetime.fromisoformat(binding.created_at.removesuffix("Z") + "+00:00")
    return EngineCapabilityDelegation.create(
        delegation_id="engine-delegation-" + binding.attempt_id[-32:],
        experiment_id=EXPERIMENT_ID,
        attempt_id=binding.attempt_id,
        role=binding.role,
        parent_attempt_id=binding.parent_attempt_id,
        objective_ref=OBJECTIVE_REF,
        environment_ref=ENVIRONMENT_REF,
        target_snapshot_ref=binding.target_snapshot_ref,
        scope_ref=SCOPE_REF,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        engine_id=binding.engine_id,
        engine_version=binding.engine_version,
        engine_revision=binding.engine_revision,
        engine_package_digest=binding.engine_package_digest,
        policy_overlay_digest=binding.policy_overlay_digest,
        model_authorization_ref=binding.model_authorization_ref,
        model_provider=binding.model_provider,
        model_id=binding.model_id,
        model_data_destination=binding.model_data_destination,
        network_policy_digest=_digest("b"),
        custody_plan_digest=_digest("c"),
        wall_clock_seconds=binding.wall_clock_seconds,
        action_limit=binding.action_limit,
        cost_limit_microunits=binding.cost_limit_microunits,
        artifact_byte_limit=binding.artifact_byte_limit,
        created_at=_iso(binding_time - timedelta(seconds=1)),
        expires_at=_iso(timeline.base + timedelta(minutes=10)),
    )


@dataclass
class _PreparedAttempt:
    request: dict[str, Any]
    observation: IndependentObservationRecord | None = None


def _prepare_attempt(
    store: ProductStore,
    *,
    binding: EngineAttemptBinding,
    delegation: EngineCapabilityDelegation,
    submission_id: str,
) -> _PreparedAttempt:
    approval = delegation.approval_binding(binding)
    saved = store.create_approval_request(**approval.request_binding())
    approved = store.approve(
        str(saved["approval_id"]),
        approved_by="Joined test operator",
        expected_state_digest=approval.state_digest,
        expected_plan_digest=approval.plan_digest,
        expected_target_scope_digest=approval.target_scope_digest,
    )
    store.consume_approval(
        str(saved["approval_id"]),
        nonce=str(approved["nonce"]),
        expected_state_digest=approval.state_digest,
        expected_plan_digest=approval.plan_digest,
        expected_target_scope_digest=approval.target_scope_digest,
    )
    experiment = EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )
    job_request = EngineExperimentJobs._request(
        experiment=experiment,
        binding=binding,
        delegation=delegation,
        approval=approval,
        approval_id=str(saved["approval_id"]),
    )
    return _PreparedAttempt(
        request={
            "schema_version": "bluefire.engine-attempt-submit.v1",
            "experiment_id": EXPERIMENT_ID,
            "binding": binding.to_dict(),
            "delegation": delegation.to_dict(),
            "approval_binding": approval.to_dict(),
            "approval_id": str(saved["approval_id"]),
            "approval_nonce": str(approved["nonce"]),
            "approved_by": "Joined test operator",
            "submission_id": submission_id,
            "intent_digest": content_hash(job_request),
            "expected_revision": experiment.revision,
            "expected_digest": experiment.digest,
        }
    )


class _Runtime:
    def __init__(self, timeline: _Timeline) -> None:
        self.timeline = timeline
        self.execute_calls = 0
        self.reconcile_calls = 0

    def execute(
        self, context: Any, binding: EngineAttemptBinding, delegation: Any, transition: Any
    ) -> EngineRuntimeSettlement:
        self.execute_calls += 1
        assert delegation.validate_attempt_binding(binding) == binding
        started_at = self.timeline()
        preflight = EngineAttemptRecord.create(binding).transition(
            AttemptState.PREFLIGHT,
            timestamp=started_at,
        )
        running = preflight.transition(
            AttemptState.RUNNING,
            upstream_session_id="controlled-strix-" + binding.attempt_id[-8:],
            timestamp=started_at,
        )
        transition(running, started_at)
        context.checkpoint({"phase": "controlled-test-provider"})
        finished_at = self.timeline()
        completed = running.transition(
            AttemptState.COMPLETED,
            timestamp=finished_at,
            exit_code=0,
            completeness=AttemptCompleteness.COMPLETE,
            exit_reason="controlled_test_provider_completed",
        )
        return EngineRuntimeSettlement(
            record=completed,
            engine_evidence=(),
            artifact_manifest_ref=_digest("d"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("e"),
            settled_at=finished_at,
        )

    def reconcile(
        self, binding: EngineAttemptBinding, delegation: Any, saved_record: EngineAttemptRecord
    ) -> EngineRuntimeSettlement:
        self.reconcile_calls += 1
        assert delegation.validate_attempt_binding(binding) == binding
        return EngineRuntimeSettlement(
            record=saved_record,
            engine_evidence=(),
            artifact_manifest_ref=_digest("d"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("e"),
            settled_at=self.timeline(),
        )


class _IndependentObserver:
    """Controller-side target observation kept outside the engine runtime fake."""

    def __init__(self, runs: RunStore) -> None:
        self.runs = runs
        self.calls = 0

    def observe_attempt(
        self,
        binding: EngineAttemptBinding,
        *,
        observed_at: str,
        hardened: bool,
    ) -> IndependentObservationRecord:
        self.calls += 1
        evidence = _tenant_observation(
            owner_id=binding.attempt_id,
            run_id=binding.run_id,
            timestamp=observed_at,
            hardened=hardened,
        )
        observation = _controller_observation_record(
            target_snapshot_ref=binding.target_snapshot_ref,
            mechanism_ref=MECHANISM_REF,
            attempt_id=binding.attempt_id,
            evidence=evidence,
        )
        _finalize_run(self.runs, binding.run_id, [evidence.to_dict()])
        return observation


class _ReviewController:
    def __init__(self, store: ProductStore, timeline: _Timeline) -> None:
        self.store = store
        self.timeline = timeline

    def perform(
        self, *, action: EngineControllerAction, experiment: EngineExperiment, request_ref: str
    ) -> EngineExperiment:
        assert request_ref.startswith("sha256:")
        if action is EngineControllerAction.REVIEW_DEFENSE:
            reviewed_at = self.timeline()
            successor = experiment.review_defense(
                EngineDefenseChange.reviewed(
                    change_id=DEFENSE_CHANGE,
                    experiment_id=EXPERIMENT_ID,
                    mechanism_ref=MECHANISM_REF,
                    preimage_digest=_digest("f"),
                    approved_configuration_digest=_digest("0"),
                    before_target_snapshot_ref=INITIAL_SNAPSHOT,
                    after_target_snapshot_ref=AFTER_SNAPSHOT,
                    rollback_digest=_digest("1"),
                    reviewed_by="Joined test operator",
                    reviewed_at=reviewed_at,
                ),
                timestamp=reviewed_at,
            )
            self.store.provision_engine_experiment_transition_presentation(
                experiment,
                successor,
                defense_presentation=_defense_presentation(),
            )
            return successor
        assert action is EngineControllerAction.RETAIN_DEFENSE
        assert experiment.defense_change is not None
        return experiment.retain_defense(
            experiment.defense_change.change_id,
            retained_at=self.timeline(),
        )


class _DefenseExecutor:
    def __init__(self, store: ProductStore, timeline: _Timeline) -> None:
        self.store = store
        self.timeline = timeline
        self.calls = 0
        self.observed_unknown = False

    def execute(
        self, _context: Any, experiment: EngineExperiment, operation: DefenseOperation
    ) -> DefenseOperationSettlement:
        self.calls += 1
        assert operation is DefenseOperation.APPLY
        assert experiment.defense_change is not None
        assert experiment.defense_change.state is DefenseState.UNKNOWN
        assert experiment.current_target_snapshot_ref is None
        assert experiment.defense_change.application_receipt_digest is not None
        self.observed_unknown = True
        settled_at = self.timeline()
        settlement = DefenseOperationSettlement(
            operation=operation,
            change_id=experiment.defense_change.change_id,
            target_snapshot_ref=AFTER_SNAPSHOT,
            configuration_digest=experiment.defense_change.approved_configuration_digest,
            receipt_digest=_digest("2"),
            settled_at=settled_at,
        )
        successor = experiment.reconcile_defense_applied(
            settlement.change_id,
            applied_configuration_digest=str(settlement.configuration_digest),
            reconciliation_receipt_digest=settlement.receipt_digest,
            observed_target_snapshot_ref=settlement.target_snapshot_ref,
            reconciled_at=settlement.settled_at,
        )
        self.store.provision_engine_experiment_transition_presentation(
            experiment,
            successor,
            target_presentation=_target(
                AFTER_SNAPSHOT,
                settled_at,
                "Hardened tenant-record target",
            ),
        )
        return settlement


class _CheckExecutor:
    def __init__(self, runs: RunStore, timeline: _Timeline) -> None:
        self.runs = runs
        self.timeline = timeline

    def _settlement(self, check: ControllerCheckRecord) -> ControllerCheckSettlement:
        observed_at = self.timeline()
        evidence = _tenant_observation(
            owner_id=check.check_id,
            run_id=check.run_id,
            timestamp=observed_at,
            hardened=True,
            legitimate=check.role is ControllerCheckRole.LEGITIMATE_USE,
        )
        _finalize_run(self.runs, check.run_id, [evidence.to_dict()])
        return ControllerCheckSettlement(
            state=ControllerCheckState.COMPLETED,
            result_digest=_digest("3"),
            observations=(evidence,),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("4"),
            settled_at=self.timeline(),
        )

    def execute(self, _context: Any, check: ControllerCheckRecord) -> ControllerCheckSettlement:
        return self._settlement(check)

    def reconcile(self, check: ControllerCheckRecord) -> ControllerCheckRecovery:
        return ControllerCheckRecovery(
            settlement=self._settlement(check)
            if check.state is ControllerCheckState.RESERVED
            else None,
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("4"),
            reconciled_at=self.timeline(),
        )


@dataclass(frozen=True)
class _CheckSpec:
    check_id: str
    run_id: str
    role: ControllerCheckRole
    input_digest: str


class _ControllerJobAdapter:
    def __init__(self, jobs: TrustedControllerJobs, specs: Mapping[str, _CheckSpec]) -> None:
        self.jobs = jobs
        self.specs = specs

    def submit(
        self,
        *,
        action: EngineControllerJobAction,
        experiment: EngineExperiment,
        request_ref: str,
        submission_id: str,
        intent_digest: str,
    ) -> Mapping[str, Any]:
        if action is EngineControllerJobAction.APPLY_DEFENSE:
            assert experiment.defense_change is not None
            internal = self.jobs.prepare_defense_operation(
                experiment_id=experiment.experiment_id,
                change_id=experiment.defense_change.change_id,
                operation=DefenseOperation.APPLY,
            )
            job = self.jobs.submit_defense_operation(
                request=internal,
                submission_id=submission_id,
                intent_digest=content_hash(internal),
            )
        else:
            expected_role = {
                EngineControllerJobAction.RUN_RETAINED_REPRODUCER: ControllerCheckRole.RETAINED_REPRODUCER,
                EngineControllerJobAction.RUN_LEGITIMATE_USE: ControllerCheckRole.LEGITIMATE_USE,
            }[action]
            spec = self.specs[request_ref]
            assert spec.role is expected_role
            internal = self.jobs.prepare_controller_check(
                experiment_id=experiment.experiment_id,
                check_id=spec.check_id,
                run_id=spec.run_id,
                role=spec.role,
                mechanism_ref=MECHANISM_REF,
                target_snapshot_ref=AFTER_SNAPSHOT,
                input_digest=spec.input_digest,
                reserved_at=experiment.updated_at,
            )
            job = self.jobs.submit_controller_check(
                request=internal,
                submission_id=submission_id,
                intent_digest=content_hash(internal),
            )
        return {
            "schema_version": "bluefire.engine-controller-job-submission.v1",
            "job_id": job["job_id"],
            "kind": "engine-controller-operation",
            "experiment_id": experiment.experiment_id,
            "action": action.value,
            "submission_id": submission_id,
            "intent_digest": intent_digest,
            "state": job["state"],
        }


def _controller_request(
    experiment: EngineExperiment,
    *,
    action: EngineControllerJobAction,
    request_ref: str,
    submission_id: str,
) -> dict[str, Any]:
    protected = {
        "schema_version": "bluefire.engine-controller-job.v1",
        "experiment_id": EXPERIMENT_ID,
        "revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "action": action.value,
        "request_ref": request_ref,
    }
    return {
        "schema_version": "bluefire.engine-controller-job-submit.v1",
        "expected_revision": experiment.revision,
        "expected_digest": experiment.digest,
        "action": action.value,
        "request_ref": request_ref,
        "submission_id": submission_id,
        "intent_digest": content_hash(protected),
    }


def _transition_request(
    experiment: EngineExperiment, *, action: EngineControllerAction, request_ref: str
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-controller-transition.v1",
        "expected_revision": experiment.revision,
        "expected_digest": experiment.digest,
        "action": action.value,
        "request_ref": request_ref,
    }


def _experiment(store: ProductStore) -> EngineExperiment:
    return EngineExperiment._from_controller_mapping(
        store.get_engine_experiment_document(EXPERIMENT_ID)
    )


def _wait_completed(controller: RunJobController, receipt: Mapping[str, Any]) -> None:
    job = controller.wait(str(receipt["job_id"]), timeout=5)
    assert job["state"] == JobState.COMPLETED.value, job.get("error", job)


def test_joined_product_path_preserves_evidence_defense_retests_and_no_replay(
    tmp_path: Path,
) -> None:
    """Join the public product path without claiming native or live-model proof."""

    timeline = _Timeline()
    product_path = tmp_path / "product.sqlite3"
    run_path = tmp_path / "runs"
    store = ProductStore(product_path)
    runs = RunStore(run_path)

    baseline_run = _run_handle(runs)
    reproducer_run = _run_handle(runs)
    adaptive_run = _run_handle(runs)
    legitimate_run = _run_handle(runs)
    # Creation consumes the timeline's first tick, so the preprovisioned target
    # has the exact controller capture time required by revision one.
    initial_captured_at = _iso(timeline.base)
    store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _target(INITIAL_SNAPSHOT, initial_captured_at, "Generated tenant-record target"),
    )

    specs = {
        _digest("c"): _CheckSpec(
            check_id=REPRODUCER_CHECK,
            run_id=reproducer_run,
            role=ControllerCheckRole.RETAINED_REPRODUCER,
            input_digest=_digest("3"),
        ),
        _digest("d"): _CheckSpec(
            check_id=LEGITIMATE_CHECK,
            run_id=legitimate_run,
            role=ControllerCheckRole.LEGITIMATE_USE,
            input_digest=_digest("8"),
        ),
    }
    runtime = _Runtime(timeline)
    observer = _IndependentObserver(runs)
    defense_executor = _DefenseExecutor(store, timeline)
    lifecycle = RunJobController(
        store,
        max_workers=1,
        max_pending_jobs=4,
        recover_on_start=False,
        thread_name_prefix="joined-engine-test",
    )
    attempt_jobs = EngineExperimentJobs(
        controller=lifecycle,
        repository=store,
        runtime=runtime,
        clock=timeline,
    )
    trusted_controller_jobs = TrustedControllerJobs(
        controller=lifecycle,
        repository=store,
        defense_executor=defense_executor,
        check_executor=_CheckExecutor(runs, timeline),
        clock=timeline,
    )
    service = EngineExperimentService(
        history=store,
        run_source=runs,
        jobs=attempt_jobs,
        job_lifecycle=lifecycle,
        controller=_ReviewController(store, timeline),
        clock=timeline,
        presentation_source=store,
        controller_jobs=_ControllerJobAdapter(trusted_controller_jobs, specs),
    )

    try:
        created = _dispatch(
            service,
            ROOT,
            {
                "schema_version": "bluefire.engine-experiment-create.v1",
                "experiment_id": EXPERIMENT_ID,
                "objective_ref": OBJECTIVE_REF,
                "environment_ref": ENVIRONMENT_REF,
                "scope_ref": SCOPE_REF,
                "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
                "target_snapshot_ref": INITIAL_SNAPSHOT,
            },
        )
        assert created["projection"]["workflow_state"] == "ready_for_baseline"
        assert created["engine_setup"]["model"]["test_provider"] is True
        assert created["limitations"] == [
            "Controlled test-provider mechanics only; live-model inference is not proven.",
            "In-process fake runtime does not prove native Strix execution or containment.",
            "Sandbox image and test-provider identities describe prepared setup; attempt records do not independently attest them.",
            "Labeled test-provider responses do not establish live-model decision quality.",
        ]

        baseline_binding = _binding(
            role=AttemptRole.BASELINE,
            attempt_id=BASELINE_ATTEMPT,
            run_id=baseline_run,
            target_snapshot_ref=INITIAL_SNAPSHOT,
            created_at=timeline(),
            parent_attempt_id=None,
        )
        baseline = _prepare_attempt(
            store,
            binding=baseline_binding,
            delegation=_delegation(baseline_binding, timeline),
            submission_id="00000000-0000-4000-8000-000000000001",
        )
        baseline_receipt = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/attempts",
            baseline.request,
        )
        _wait_completed(lifecycle, baseline_receipt)

        current = _experiment(store)
        baseline_ended_at = current.attempts[0].record.ended_at
        assert baseline_ended_at is not None
        baseline_workspace = service.record_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            observation=observer.observe_attempt(
                baseline_binding,
                observed_at=baseline_ended_at,
                hardened=False,
            ),
        )
        assert baseline_workspace["projection"]["workflow_state"] == "review_defense"
        assert (
            baseline_workspace["projection"]["conclusion"]["original_mechanism"]["status"]
            == "established"
        )
        baseline_approval_id = str(baseline.request["approval_id"])
        assert store.get_approval_request(baseline_approval_id)["status"] == "claimed"

        current = _experiment(store)
        reviewed = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/defense/review",
            _transition_request(
                current,
                action=EngineControllerAction.REVIEW_DEFENSE,
                request_ref=_digest("e"),
            ),
        )
        assert reviewed["projection"]["workflow_state"] == "apply_defense"
        reviewed_change = reviewed["defensive_change"]
        assert reviewed_change["change_id"] == DEFENSE_CHANGE
        assert reviewed_change["state"] == "reviewed"
        assert reviewed_change["kind"] == "identity"
        assert reviewed_change["summary"] == (
            "Required a target-bound signed session for protected tenant records."
        )

        current = _experiment(store)
        apply_receipt = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/defense/apply",
            _controller_request(
                current,
                action=EngineControllerJobAction.APPLY_DEFENSE,
                request_ref=_digest("f"),
                submission_id="00000000-0000-4000-8000-000000000002",
            ),
        )
        _wait_completed(lifecycle, apply_receipt)
        assert defense_executor.calls == 1
        assert defense_executor.observed_unknown is True
        after_apply = _dispatch(service, f"{ROOT}/{EXPERIMENT_ID}/workspace")
        assert after_apply["projection"]["workflow_state"] == "run_retained_reproducer"
        assert after_apply["projection"]["conclusion"]["defense"]["state"] == "applied"
        assert after_apply["projection"]["conclusion"]["unknowns"] == [
            "The exact retained reproducer has no conclusive independent outcome.",
            "Fresh adaptive search has not produced a conclusive bounded result.",
            "Legitimate use has not been independently confirmed.",
        ]

        current = _experiment(store)
        reproducer_receipt = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/checks/retained-reproducer/run",
            _controller_request(
                current,
                action=EngineControllerJobAction.RUN_RETAINED_REPRODUCER,
                request_ref=_digest("c"),
                submission_id="00000000-0000-4000-8000-000000000003",
            ),
        )
        _wait_completed(lifecycle, reproducer_receipt)
        reproduced = _dispatch(service, f"{ROOT}/{EXPERIMENT_ID}/workspace")
        assert reproduced["projection"]["workflow_state"] == "run_adaptive_search"
        assert reproduced["projection"]["conclusion"]["retained_reproducer"]["status"] == "blocked"

        adaptive_binding = _binding(
            role=AttemptRole.ADAPTIVE_SEARCH,
            attempt_id=ADAPTIVE_ATTEMPT,
            run_id=adaptive_run,
            target_snapshot_ref=AFTER_SNAPSHOT,
            created_at=timeline(),
            parent_attempt_id=BASELINE_ATTEMPT,
        )
        adaptive = _prepare_attempt(
            store,
            binding=adaptive_binding,
            delegation=_delegation(adaptive_binding, timeline),
            submission_id="00000000-0000-4000-8000-000000000004",
        )
        adaptive_receipt = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/attempts",
            adaptive.request,
        )
        _wait_completed(lifecycle, adaptive_receipt)
        current = _experiment(store)
        adaptive_ended_at = current.attempts[-1].record.ended_at
        assert adaptive_ended_at is not None
        adaptive_workspace = service.record_engine_attempt_observation(
            experiment_id=EXPERIMENT_ID,
            expected_revision=current.revision,
            expected_digest=current.digest,
            observation=observer.observe_attempt(
                adaptive_binding,
                observed_at=adaptive_ended_at,
                hardened=True,
            ),
        )
        assert adaptive_workspace["projection"]["workflow_state"] == "run_legitimate_use"
        adaptive_result = adaptive_workspace["projection"]["conclusion"]["adaptive_search"]
        assert adaptive_result["status"] == "no_path_observed_within_limits"
        assert adaptive_result["limit_qualified"] is True

        current = _experiment(store)
        legitimate_receipt = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/checks/legitimate-use/run",
            _controller_request(
                current,
                action=EngineControllerJobAction.RUN_LEGITIMATE_USE,
                request_ref=_digest("d"),
                submission_id="00000000-0000-4000-8000-000000000005",
            ),
        )
        _wait_completed(lifecycle, legitimate_receipt)
        before_disposition = _dispatch(service, f"{ROOT}/{EXPERIMENT_ID}/workspace")
        assert before_disposition["projection"]["workflow_state"] == ("choose_defense_disposition")
        assert (
            before_disposition["projection"]["conclusion"]["legitimate_use"]["status"] == "passed"
        )

        current = _experiment(store)
        completed = _dispatch(
            service,
            f"{ROOT}/{EXPERIMENT_ID}/defense/retain",
            _transition_request(
                current,
                action=EngineControllerAction.RETAIN_DEFENSE,
                request_ref=_digest("0"),
            ),
        )
        conclusion = completed["projection"]["conclusion"]
        assert completed["projection"]["workflow_state"] == "complete"
        assert conclusion["headline"] == (
            "original_blocked_no_remaining_path_observed_within_limits"
        )
        assert conclusion["original_mechanism"]["status"] == "established"
        assert conclusion["retained_reproducer"]["status"] == "blocked"
        assert conclusion["adaptive_search"] == {
            "status": "no_path_observed_within_limits",
            "run_id": adaptive_run,
            "support_refs": conclusion["adaptive_search"]["support_refs"],
            "limit_qualified": True,
        }
        assert conclusion["legitimate_use"]["status"] == "passed"
        assert conclusion["telemetry_health"]["status"] == "complete"
        assert conclusion["cleanup"]["status"] == "verified_absent"
        assert conclusion["defense"]["state"] == "retained"
        assert conclusion["unknowns"] == []
        assert runtime.execute_calls == 2
        assert observer.calls == 2
        assert len(completed["projection"]["observations"]) == 4
        assert {row["state"] for row in completed["projection"]["run_integrity"]} == {"verified"}
        assert [row["execution_approval_id"] for row in completed["projection"]["attempts"]] == [
            baseline_approval_id,
            str(adaptive.request["approval_id"]),
        ]
        final_revision = int(completed["revision"])
        final_digest = str(completed["experiment_digest"])
    finally:
        lifecycle.shutdown(cancel_active=True)

    reopened_store = ProductStore(product_path)
    reopened_runs = RunStore(run_path)
    recovery_runtime = _Runtime(timeline)
    restarted_lifecycle = RunJobController(
        reopened_store,
        max_workers=1,
        max_pending_jobs=2,
        recover_on_start=True,
        thread_name_prefix="joined-engine-recovery-test",
    )
    restarted_jobs = EngineExperimentJobs(
        controller=restarted_lifecycle,
        repository=reopened_store,
        runtime=recovery_runtime,
        clock=timeline,
    )
    restarted = EngineExperimentService(
        history=reopened_store,
        run_source=reopened_runs,
        jobs=restarted_jobs,
        job_lifecycle=restarted_lifecycle,
        controller=_ReviewController(reopened_store, timeline),
        clock=timeline,
        presentation_source=reopened_store,
    )
    try:
        reopened = _dispatch(restarted, f"{ROOT}/{EXPERIMENT_ID}/workspace")
        historical = restarted.workspace(EXPERIMENT_ID, revision=1)
        recovered = _dispatch(
            restarted,
            f"{ROOT}/{EXPERIMENT_ID}/attempts/{BASELINE_ATTEMPT}/recover",
            {},
        )

        assert reopened["experiment_digest"] == final_digest
        assert reopened["projection"]["workflow_state"] == "complete"
        assert historical["revision"] == 1
        assert historical["projection"]["workflow_state"] == "ready_for_baseline"
        preserved_final = restarted.workspace(EXPERIMENT_ID, revision=final_revision)
        assert preserved_final["experiment_digest"] == final_digest
        assert recovered["projection"]["workflow_state"] == "complete"
        assert recovered["projection"]["conclusion"] == reopened["projection"]["conclusion"]
        assert recovery_runtime.execute_calls == 0
        assert recovery_runtime.reconcile_calls == 1
    finally:
        restarted_lifecycle.shutdown(cancel_active=True)
