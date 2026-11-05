from __future__ import annotations

import pytest

from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineEvidenceItem,
    EvidenceCategory,
)
from bluefire.engine_experiment import (
    ENGINE_CAPABILITY_SCOPE_VERSION,
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
    DefenseState,
    EngineDefenseChange,
    EngineExperiment,
    EngineExperimentError,
    IndependentObservationRecord,
    _controller_observation_record,
)
from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
    mint_lab_session,
)
from bluefire.tenant_record_observer import (
    BoundedTenantAuditLog,
    observe_tenant_response,
)
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.util import parse_iso8601_datetime


def _digest(character: str) -> str:
    return "sha256:" + character * 64


EXPERIMENT_ID = "experiment-" + "1" * 32
OBJECTIVE_REF = _digest("1")
ENVIRONMENT_REF = _digest("2")
SCOPE_REF = _digest("3")
INITIAL_SNAPSHOT = _digest("4")
AFTER_SNAPSHOT = _digest("5")
MECHANISM_REF = _digest("6")
BASELINE_ATTEMPT = "engine-attempt-" + "a" * 32
ADAPTIVE_ATTEMPT = "engine-attempt-" + "b" * 32
BASELINE_RUN = "run-20261104T120100Z-" + "a" * 16
REPRODUCER_RUN = "run-20261104T120800Z-" + "b" * 16
ADAPTIVE_RUN = "run-20261104T121100Z-" + "c" * 16
LEGITIMATE_RUN = "run-20261104T121600Z-" + "d" * 16
REPRODUCER_CHECK = "controller-check-" + "c" * 32
LEGITIMATE_CHECK = "controller-check-" + "d" * 32


def _binding(
    role: AttemptRole,
    *,
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
            "policy_overlay_digest": _digest("8"),
            "model_provider": "provider.test",
            "model_id": "test-model",
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


def _new_experiment() -> EngineExperiment:
    return EngineExperiment.create(
        experiment_id=EXPERIMENT_ID,
        objective_ref=OBJECTIVE_REF,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        scope_version=ENGINE_CAPABILITY_SCOPE_VERSION,
        target_snapshot_ref=INITIAL_SNAPSHOT,
        created_at="2026-11-04T12:00:00Z",
    )


def _reserve_baseline(experiment: EngineExperiment) -> EngineExperiment:
    return experiment.reserve_attempt(
        _binding(
            AttemptRole.BASELINE,
            attempt_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            target_snapshot_ref=INITIAL_SNAPSHOT,
            created_at="2026-11-04T12:01:00Z",
            parent_attempt_id=None,
        ),
        job_id="job-" + "a" * 32,
        delegation_digest=_digest("a"),
        execution_approval_digest=_digest("b"),
        execution_approval_id="approval-" + "a" * 32,
        timestamp="2026-11-04T12:01:00Z",
    )


def _settle_latest_attempt(
    experiment: EngineExperiment,
    *,
    started_at: str,
    ended_at: str,
    cleanup_state: CleanupState = CleanupState.VERIFIED_ABSENT,
) -> EngineExperiment:
    current = experiment.attempts[-1].record
    experiment = experiment.update_attempt_record(
        current.transition(AttemptState.PREFLIGHT), timestamp=started_at
    )
    current = experiment.attempts[-1].record
    running = current.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-" + current.binding.attempt_id[-8:],
        timestamp=started_at,
    )
    experiment = experiment.update_attempt_record(running, timestamp=started_at)
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp=ended_at,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    return experiment.settle_attempt(
        completed,
        engine_evidence=(),
        artifact_manifest_ref=_digest("c"),
        cleanup_state=cleanup_state,
        cleanup_evidence_ref=_digest("d"),
        settled_at=ended_at,
    )


def _tenant_observation(
    *,
    owner_id: str,
    run_id: str,
    timestamp: str,
    hardened: bool,
    legitimate: bool = False,
):
    seed = b"engine-experiment-fixture-seed-000001"
    key = b"engine-experiment-signing-key-000000000001"
    fixture = generate_tenant_record_fixture(seed)
    baseline = baseline_defense_config(fixture)
    config = (
        hardened_defense_config(
            fixture,
            signing_key=key,
            key_id="key-engine-experiment",
            application_nonce="apply-engine-experiment-0001",
            prior=baseline,
        )
        if hardened
        else baseline
    )
    audit = BoundedTenantAuditLog()
    now = parse_iso8601_datetime(timestamp)
    application = TenantRecordApplication(
        fixture=fixture,
        config=config,
        signing_key=key if hardened else None,
        audit_log=audit,
        clock=lambda: now,
        request_id_factory=lambda: "request-" + run_id[-16:] + "00000000",
    )
    protected = fixture.records_for(fixture.protected_tenant_id)[0]
    headers = {"host": "tenant-record.test"}
    source_identity = "engine_worker"
    if legitimate:
        token = mint_lab_session(
            fixture,
            config,
            signing_key=key,
            subject_id=fixture.legitimate_subject_id,
            tenant_id=fixture.protected_tenant_id,
            issued_at=now,
            lifetime_seconds=60,
        )
        headers["authorization"] = f"BlueFireLab {token}"
        source_identity = "ordinary_user"
    elif not hardened:
        headers["x-bluefire-lab-tenant"] = fixture.protected_tenant_id
    response = application.handle(
        "GET",
        f"/records/{protected.record_id}",
        headers,
        source_identity=source_identity,
    )
    return observe_tenant_response(
        fixture=fixture,
        config=config,
        audit_row=audit.snapshot()[0],
        response_status=response.status,
        response_headers=response.headers,
        response_body=response.body,
        attempt_id=owner_id,
        run_id=run_id,
        step_id="tenant-boundary",
        target_scope_ref=SCOPE_REF,
    )


def test_tenant_observation_fixture_preserves_single_digit_fraction_instant() -> None:
    evidence = _tenant_observation(
        owner_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        timestamp="2026-11-04T12:03:00.5Z",
        hardened=False,
    )

    assert parse_iso8601_datetime(evidence.timestamp) == parse_iso8601_datetime(
        "2026-11-04T12:03:00.5Z"
    )


def _defense() -> EngineDefenseChange:
    return EngineDefenseChange.reviewed(
        change_id="defense-change-" + "e" * 32,
        experiment_id=EXPERIMENT_ID,
        mechanism_ref=MECHANISM_REF,
        preimage_digest=_digest("e"),
        approved_configuration_digest=_digest("f"),
        before_target_snapshot_ref=INITIAL_SNAPSHOT,
        after_target_snapshot_ref=AFTER_SNAPSHOT,
        rollback_digest=_digest("0"),
        reviewed_by="operator",
        reviewed_at="2026-11-04T12:06:00Z",
    )


def build_completed_experiment() -> EngineExperiment:
    experiment = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    baseline_observation = _controller_observation_record(
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
    experiment = experiment.record_independent_observation(
        baseline_observation, timestamp="2026-11-04T12:05:00Z"
    )
    experiment = experiment.review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")
    experiment = experiment.begin_defense_application(
        "defense-change-" + "e" * 32,
        operation_receipt_digest=_digest("1"),
        started_at="2026-11-04T12:06:30Z",
    )
    experiment = experiment.apply_defense(
        "defense-change-" + "e" * 32,
        applied_configuration_digest=_digest("f"),
        reconciliation_receipt_digest=_digest("2"),
        observed_target_snapshot_ref=AFTER_SNAPSHOT,
        reconciled_at="2026-11-04T12:07:00Z",
    )

    reproducer = ControllerCheckRecord.reserve(
        check_id=REPRODUCER_CHECK,
        experiment_id=EXPERIMENT_ID,
        job_id="job-" + "c" * 32,
        run_id=REPRODUCER_RUN,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("3"),
        created_at="2026-11-04T12:08:00Z",
    )
    experiment = experiment.reserve_controller_check(reproducer, timestamp="2026-11-04T12:08:00Z")
    reproducer_observation = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        check_id=REPRODUCER_CHECK,
        check_input_digest=reproducer.input_digest,
        evidence=_tenant_observation(
            owner_id=REPRODUCER_CHECK,
            run_id=REPRODUCER_RUN,
            timestamp="2026-11-04T12:09:00Z",
            hardened=True,
        ),
    )
    experiment = experiment.record_independent_observation(
        reproducer_observation, timestamp="2026-11-04T12:09:00Z"
    )
    reproducer = reproducer.settle(
        state=ControllerCheckState.COMPLETED,
        result_digest=_digest("4"),
        independent_evidence_refs=(reproducer_observation.evidence_id,),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("5"),
        settled_at="2026-11-04T12:10:00Z",
    )
    experiment = experiment.settle_controller_check(reproducer, timestamp="2026-11-04T12:10:00Z")

    adaptive_binding = _binding(
        AttemptRole.ADAPTIVE_SEARCH,
        attempt_id=ADAPTIVE_ATTEMPT,
        run_id=ADAPTIVE_RUN,
        target_snapshot_ref=AFTER_SNAPSHOT,
        created_at="2026-11-04T12:11:00Z",
        parent_attempt_id=BASELINE_ATTEMPT,
    )
    experiment = experiment.reserve_attempt(
        adaptive_binding,
        job_id="job-" + "b" * 32,
        delegation_digest=_digest("6"),
        execution_approval_digest=_digest("7"),
        execution_approval_id="approval-" + "b" * 32,
        timestamp="2026-11-04T12:11:00Z",
    )
    experiment = _settle_latest_attempt(
        experiment,
        started_at="2026-11-04T12:12:00Z",
        ended_at="2026-11-04T12:14:00Z",
    )
    adaptive_observation = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=ADAPTIVE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=ADAPTIVE_ATTEMPT,
            run_id=ADAPTIVE_RUN,
            timestamp="2026-11-04T12:13:00Z",
            hardened=True,
        ),
    )
    experiment = experiment.record_independent_observation(
        adaptive_observation, timestamp="2026-11-04T12:15:00Z"
    )

    legitimate = ControllerCheckRecord.reserve(
        check_id=LEGITIMATE_CHECK,
        experiment_id=EXPERIMENT_ID,
        job_id="job-" + "d" * 32,
        run_id=LEGITIMATE_RUN,
        role=ControllerCheckRole.LEGITIMATE_USE,
        mechanism_ref=MECHANISM_REF,
        target_snapshot_ref=AFTER_SNAPSHOT,
        input_digest=_digest("8"),
        created_at="2026-11-04T12:16:00Z",
    )
    experiment = experiment.reserve_controller_check(legitimate, timestamp="2026-11-04T12:16:00Z")
    legitimate_observation = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        check_id=LEGITIMATE_CHECK,
        check_input_digest=legitimate.input_digest,
        evidence=_tenant_observation(
            owner_id=LEGITIMATE_CHECK,
            run_id=LEGITIMATE_RUN,
            timestamp="2026-11-04T12:17:00Z",
            hardened=True,
            legitimate=True,
        ),
    )
    experiment = experiment.record_independent_observation(
        legitimate_observation, timestamp="2026-11-04T12:17:00Z"
    )
    legitimate = legitimate.settle(
        state=ControllerCheckState.COMPLETED,
        result_digest=_digest("9"),
        independent_evidence_refs=(legitimate_observation.evidence_id,),
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("a"),
        settled_at="2026-11-04T12:18:00Z",
    )
    experiment = experiment.settle_controller_check(legitimate, timestamp="2026-11-04T12:18:00Z")
    return experiment.retain_defense(
        "defense-change-" + "e" * 32,
        retained_at="2026-11-04T12:19:00Z",
    )


def test_complete_workflow_separates_engine_attempts_and_controller_checks() -> None:
    experiment = build_completed_experiment()

    assert [entry.record.binding.role for entry in experiment.attempts] == [
        AttemptRole.BASELINE,
        AttemptRole.ADAPTIVE_SEARCH,
    ]
    assert [check.role for check in experiment.checks] == [
        ControllerCheckRole.RETAINED_REPRODUCER,
        ControllerCheckRole.LEGITIMATE_USE,
    ]
    assert all(not hasattr(check, "engine_id") for check in experiment.checks)
    assert experiment.defense_change is not None
    assert experiment.defense_change.state is DefenseState.RETAINED
    assert EngineExperiment._from_controller_mapping(experiment.to_dict()) == experiment
    assert experiment.previous_revision_digest is not None


def test_retained_disposition_rehydration_requires_complete_clean_workflow() -> None:
    incomplete = build_completed_experiment().to_dict()
    incomplete["checks"] = incomplete["checks"][:-1]
    incomplete["independent_observations"] = [
        row for row in incomplete["independent_observations"] if row["check_id"] != LEGITIMATE_CHECK
    ]

    with pytest.raises(EngineExperimentError, match="complete workflow"):
        EngineExperiment._from_controller_mapping(incomplete)

    residual = build_completed_experiment().to_dict()
    residual["checks"][-1]["cleanup_state"] = "residue"

    with pytest.raises(EngineExperimentError, match="not verified absent"):
        EngineExperiment._from_controller_mapping(residual)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda saved: saved["defense_change"].__setitem__(
                "reviewed_at", "2026-11-04T12:03:59Z"
            ),
            "review predates baseline settlement",
        ),
        (
            lambda saved: saved["checks"][0].__setitem__("created_at", "2026-11-04T12:06:59Z"),
            "predates verified defense application",
        ),
        (
            lambda saved: saved["checks"][1].__setitem__("created_at", "2026-11-04T12:13:59Z"),
            "predates adaptive settlement",
        ),
    ],
)
def test_rehydration_rejects_backdated_workflow_events(mutate, message: str) -> None:
    saved = build_completed_experiment().to_dict()
    mutate(saved)

    with pytest.raises(EngineExperimentError, match=message):
        EngineExperiment._from_controller_mapping(saved)


@pytest.mark.parametrize("disposition", ["retained", "rollback_unknown", "rolled_back"])
def test_rehydration_rejects_disposition_before_owned_work_settlement(
    disposition: str,
) -> None:
    saved = build_completed_experiment().to_dict()
    change = saved["defense_change"]
    if disposition == "retained":
        change["retained_at"] = "2026-11-04T12:07:30Z"
    else:
        change.update(
            {
                "state": "unknown" if disposition == "rollback_unknown" else "rolled_back",
                "rollback_operation_digest": _digest("1"),
                "rollback_started_at": "2026-11-04T12:07:30Z",
                "rollback_receipt_digest": (
                    None if disposition == "rollback_unknown" else _digest("2")
                ),
                "rolled_back_at": (
                    None if disposition == "rollback_unknown" else "2026-11-04T12:07:45Z"
                ),
                "retained_at": None,
            }
        )
        saved["current_target_snapshot_ref"] = (
            None if disposition == "rollback_unknown" else INITIAL_SNAPSHOT
        )

    with pytest.raises(EngineExperimentError, match="workflow settlement"):
        EngineExperiment._from_controller_mapping(saved)


@pytest.mark.parametrize(
    ("defense_state", "check_state"),
    [("unknown", "active"), ("rolled_back", "residue")],
)
def test_rollback_rehydration_requires_owned_work_verified_absent(
    defense_state: str,
    check_state: str,
) -> None:
    saved = build_completed_experiment().to_dict()
    change = saved["defense_change"]
    change.update(
        {
            "state": defense_state,
            "rollback_operation_digest": _digest("1"),
            "rollback_started_at": "2026-11-04T12:18:30Z",
            "rollback_receipt_digest": (None if defense_state == "unknown" else _digest("2")),
            "rolled_back_at": (None if defense_state == "unknown" else "2026-11-04T12:18:45Z"),
            "retained_at": None,
        }
    )
    saved["current_target_snapshot_ref"] = None if defense_state == "unknown" else INITIAL_SNAPSHOT
    check = saved["checks"][-1]
    if check_state == "active":
        check.update(
            {
                "state": "reserved",
                "result_digest": None,
                "independent_evidence_refs": [],
                "settled_at": None,
                "cleanup_state": "pending",
                "cleanup_evidence_ref": None,
            }
        )
    else:
        check["cleanup_state"] = "residue"

    with pytest.raises(EngineExperimentError, match="not verified absent"):
        EngineExperiment._from_controller_mapping(saved)


@pytest.mark.parametrize("terminal", [False, True])
def test_rehydration_rejects_attempt_lifecycle_after_saved_experiment(
    terminal: bool,
) -> None:
    experiment = _reserve_baseline(_new_experiment())
    queued = experiment.attempts[0].record
    experiment = experiment.update_attempt_record(
        queued.transition(AttemptState.PREFLIGHT),
        timestamp="2026-11-04T12:02:00Z",
    )
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-future-lifecycle",
        timestamp="2026-11-04T12:02:00Z",
    )
    experiment = experiment.update_attempt_record(
        running,
        timestamp="2026-11-04T12:02:00Z",
    )
    if terminal:
        completed = running.transition(
            AttemptState.COMPLETED,
            timestamp="2026-11-04T12:04:00Z",
            exit_code=0,
            completeness=AttemptCompleteness.COMPLETE,
            exit_reason="completed",
        )
        experiment = experiment.settle_attempt(
            completed,
            engine_evidence=(),
            artifact_manifest_ref=_digest("c"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("d"),
            settled_at="2026-11-04T12:04:00Z",
        )
        saved_at = "2026-11-04T12:03:00Z"
    else:
        saved_at = "2026-11-04T12:01:30Z"
    saved = experiment.to_dict()
    saved["updated_at"] = saved_at

    with pytest.raises(EngineExperimentError, match="outside the saved experiment"):
        EngineExperiment._from_controller_mapping(saved)


def test_rehydration_rejects_adaptive_search_before_reproducer_settlement() -> None:
    saved = build_completed_experiment().to_dict()
    record = saved["attempts"][1]["record"]
    binding_document = dict(record["binding"])
    binding_document["created_at"] = "2026-11-04T12:09:30Z"
    binding = EngineAttemptBinding.from_mapping(binding_document)
    record["binding"] = binding.to_dict()
    record["binding_digest"] = binding.binding_digest

    with pytest.raises(EngineExperimentError, match="predates retained reproducer"):
        EngineExperiment._from_controller_mapping(saved)


def test_rehydration_rejects_active_check_observation_after_saved_experiment() -> None:
    saved = build_completed_experiment().to_dict()
    saved["defense_change"].update({"state": "applied", "retained_at": None})
    saved["current_target_snapshot_ref"] = AFTER_SNAPSHOT
    saved["updated_at"] = "2026-11-04T12:16:30Z"
    saved["checks"][-1].update(
        {
            "state": "reserved",
            "result_digest": None,
            "independent_evidence_refs": [],
            "settled_at": None,
            "cleanup_state": "pending",
            "cleanup_evidence_ref": None,
        }
    )

    with pytest.raises(EngineExperimentError, match="postdates the saved experiment"):
        EngineExperiment._from_controller_mapping(saved)


def test_legacy_scope_and_lifecycle_replacement_fail_closed() -> None:
    with pytest.raises(EngineExperimentError, match="versioned capability delegation"):
        EngineExperiment.create(
            experiment_id=EXPERIMENT_ID,
            objective_ref=OBJECTIVE_REF,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
            scope_version="bluefire.exact-plan.v1",
            target_snapshot_ref=INITIAL_SNAPSHOT,
            created_at="2026-11-04T12:00:00Z",
        )

    experiment = _reserve_baseline(_new_experiment())
    queued = experiment.attempts[0].record
    running = queued.transition(AttemptState.PREFLIGHT).transition(
        AttemptState.RUNNING,
        upstream_session_id="session-original",
        timestamp="2026-11-04T12:02:00Z",
    )
    with pytest.raises(EngineExperimentError, match="transition"):
        experiment.update_attempt_record(running, timestamp="2026-11-04T12:02:00Z")


def test_unknown_defense_does_not_claim_target_and_reconciles_with_new_receipt() -> None:
    experiment = _settle_latest_attempt(
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
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    ).review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")
    experiment = experiment.mark_defense_application_unknown(
        "defense-change-" + "e" * 32,
        application_receipt_digest=_digest("b"),
        applied_at="2026-11-04T12:07:00Z",
    )

    assert experiment.current_target_snapshot_ref is None
    assert experiment.defense_change is not None
    original_receipt = experiment.defense_change.application_receipt_digest
    experiment = experiment.reconcile_defense_applied(
        "defense-change-" + "e" * 32,
        applied_configuration_digest=_digest("f"),
        reconciliation_receipt_digest=_digest("d"),
        observed_target_snapshot_ref=AFTER_SNAPSHOT,
        reconciled_at="2026-11-04T12:08:00Z",
    )
    assert experiment.current_target_snapshot_ref == AFTER_SNAPSHOT
    assert experiment.defense_change.application_receipt_digest == original_receipt
    assert experiment.defense_change.reconciliation_receipt_digest == _digest("d")


def test_cleanup_reconciliation_does_not_resubmit_and_allows_early_rollback() -> None:
    experiment = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
        cleanup_state=CleanupState.UNKNOWN,
    )
    attempt_count = len(experiment.attempts)
    experiment = experiment.reconcile_attempt_cleanup(
        BASELINE_ATTEMPT,
        cleanup_state=CleanupState.VERIFIED_ABSENT,
        cleanup_evidence_ref=_digest("e"),
        timestamp="2026-11-04T12:05:00Z",
    )
    assert len(experiment.attempts) == attempt_count
    assert experiment.attempts[0].cleanup_state is CleanupState.VERIFIED_ABSENT
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
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:06:00Z"
    )
    change = EngineDefenseChange.reviewed(
        change_id="defense-change-" + "e" * 32,
        experiment_id=EXPERIMENT_ID,
        mechanism_ref=MECHANISM_REF,
        preimage_digest=_digest("e"),
        approved_configuration_digest=_digest("f"),
        before_target_snapshot_ref=INITIAL_SNAPSHOT,
        after_target_snapshot_ref=AFTER_SNAPSHOT,
        rollback_digest=_digest("0"),
        reviewed_by="operator",
        reviewed_at="2026-11-04T12:07:00Z",
    )
    experiment = (
        experiment.review_defense(change, timestamp="2026-11-04T12:07:00Z")
        .begin_defense_application(
            change.change_id,
            operation_receipt_digest=_digest("1"),
            started_at="2026-11-04T12:07:30Z",
        )
        .apply_defense(
            change.change_id,
            applied_configuration_digest=_digest("f"),
            reconciliation_receipt_digest=_digest("2"),
            observed_target_snapshot_ref=AFTER_SNAPSHOT,
            reconciled_at="2026-11-04T12:08:00Z",
        )
    )
    experiment = experiment.begin_defense_rollback(
        change.change_id,
        rollback_operation_digest=_digest("4"),
        rollback_started_at="2026-11-04T12:08:30Z",
    )
    experiment = experiment.rollback_defense(
        change.change_id,
        rollback_receipt_digest=_digest("3"),
        observed_target_snapshot_ref=INITIAL_SNAPSHOT,
        rolled_back_at="2026-11-04T12:09:00Z",
    )
    assert experiment.defense_change is not None
    assert experiment.defense_change.state is DefenseState.ROLLED_BACK
    assert experiment.current_target_snapshot_ref == INITIAL_SNAPSHOT


def test_completed_workflow_rollback_preserves_historical_attempts_and_checks() -> None:
    experiment = build_completed_experiment()
    attempt_ids = tuple(entry.record.binding.attempt_id for entry in experiment.attempts)
    check_ids = tuple(check.check_id for check in experiment.checks)
    change_id = "defense-change-" + "e" * 32

    experiment = experiment.begin_defense_rollback(
        change_id,
        rollback_operation_digest=_digest("b"),
        rollback_started_at="2026-11-04T12:20:00Z",
    )

    assert experiment.defense_change is not None
    assert experiment.defense_change.state is DefenseState.UNKNOWN
    assert experiment.current_target_snapshot_ref is None
    assert tuple(entry.record.binding.attempt_id for entry in experiment.attempts) == attempt_ids
    assert tuple(check.check_id for check in experiment.checks) == check_ids

    experiment = experiment.reconcile_defense_rolled_back(
        change_id,
        rollback_receipt_digest=_digest("c"),
        observed_target_snapshot_ref=INITIAL_SNAPSHOT,
        rolled_back_at="2026-11-04T12:21:00Z",
    )

    assert experiment.defense_change.state is DefenseState.ROLLED_BACK
    assert experiment.current_target_snapshot_ref == INITIAL_SNAPSHOT
    assert tuple(entry.record.binding.attempt_id for entry in experiment.attempts) == attempt_ids
    assert tuple(check.check_id for check in experiment.checks) == check_ids


def test_check_owned_observation_cannot_relabel_the_checked_mechanism() -> None:
    experiment = build_completed_experiment()
    check = next(row for row in experiment.checks if row.check_id == LEGITIMATE_CHECK)
    relabelled = _controller_observation_record(
        target_snapshot_ref=AFTER_SNAPSHOT,
        mechanism_ref=_digest("0"),
        check_id=check.check_id,
        check_input_digest=check.input_digest,
        evidence=_tenant_observation(
            owner_id=check.check_id,
            run_id=check.run_id,
            timestamp="2026-11-04T12:17:30Z",
            hardened=True,
            legitimate=True,
        ),
    )

    with pytest.raises(EngineExperimentError, match="observation mechanism changed"):
        experiment.record_independent_observation(
            relabelled,
            timestamp="2026-11-04T12:20:00Z",
        )


@pytest.mark.parametrize("settled_rollback", [False, True])
def test_post_defense_history_requires_a_verified_applied_configuration(
    settled_rollback: bool,
) -> None:
    saved = build_completed_experiment().to_dict()
    forged = _defense().application_unknown(
        application_receipt_digest=_digest("1"),
        applied_at="2026-11-04T12:07:00Z",
    )
    forged = forged.begin_rollback(
        rollback_operation_digest=_digest("2"),
        rollback_started_at="2026-11-04T12:08:00Z",
    )
    if settled_rollback:
        forged = forged.rollback(
            rollback_receipt_digest=_digest("3"),
            rolled_back_at="2026-11-04T12:09:00Z",
        )
    saved["defense_change"] = forged.to_dict()
    saved["current_target_snapshot_ref"] = INITIAL_SNAPSHOT if settled_rollback else None

    with pytest.raises(EngineExperimentError, match="verified application"):
        EngineExperiment._from_controller_mapping(saved)


def test_independent_observation_requires_controller_attestation_and_exact_receipt() -> None:
    evidence = _tenant_observation(
        owner_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        timestamp="2026-11-04T12:05:00Z",
        hardened=False,
    )
    with pytest.raises(EngineExperimentError, match="trusted controller authority"):
        IndependentObservationRecord.create(
            target_snapshot_ref=INITIAL_SNAPSHOT,
            mechanism_ref=MECHANISM_REF,
            attempt_id=BASELINE_ATTEMPT,
            evidence=evidence,
        )

    completed = build_completed_experiment()
    with pytest.raises(EngineExperimentError, match="trusted controller authority"):
        EngineExperiment.from_mapping(completed.to_dict())

    tampered = completed.to_dict()
    tampered["independent_observations"][0]["mechanism_ref"] = _digest("0")
    with pytest.raises(EngineExperimentError, match="receipt changed"):
        EngineExperiment._from_controller_mapping(tampered)


def test_defense_requires_durable_operation_receipts_and_exact_reviewed_config() -> None:
    experiment = _settle_latest_attempt(
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
    experiment = experiment.record_independent_observation(
        observation, timestamp="2026-11-04T12:05:00Z"
    ).review_defense(_defense(), timestamp="2026-11-04T12:06:00Z")

    with pytest.raises(EngineExperimentError, match="durably begun"):
        experiment.apply_defense(
            "defense-change-" + "e" * 32,
            applied_configuration_digest=_digest("f"),
            reconciliation_receipt_digest=_digest("1"),
            observed_target_snapshot_ref=AFTER_SNAPSHOT,
            reconciled_at="2026-11-04T12:07:00Z",
        )

    experiment = experiment.begin_defense_application(
        "defense-change-" + "e" * 32,
        operation_receipt_digest=_digest("2"),
        started_at="2026-11-04T12:07:00Z",
    )
    with pytest.raises(EngineExperimentError, match="reviewed configuration"):
        experiment.reconcile_defense_applied(
            "defense-change-" + "e" * 32,
            applied_configuration_digest=_digest("3"),
            reconciliation_receipt_digest=_digest("4"),
            observed_target_snapshot_ref=AFTER_SNAPSHOT,
            reconciled_at="2026-11-04T12:08:00Z",
        )


def test_engine_and_check_evidence_must_fall_inside_owner_lifecycle() -> None:
    experiment = _reserve_baseline(_new_experiment())
    queued = experiment.attempts[0].record
    experiment = experiment.update_attempt_record(
        queued.transition(AttemptState.PREFLIGHT), timestamp="2026-11-04T12:02:00Z"
    )
    running = experiment.attempts[0].record.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-time-boundary",
        timestamp="2026-11-04T12:02:00Z",
    )
    experiment = experiment.update_attempt_record(running, timestamp="2026-11-04T12:02:00Z")
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:04:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    late_evidence = EngineEvidenceItem.create(
        attempt_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        category=EvidenceCategory.TOOL_RESULT,
        producer="strix",
        observed_at="2026-11-04T12:04:01Z",
        content={"result": "late"},
        source_artifact_digest=_digest("e"),
    )
    with pytest.raises(EngineExperimentError, match="outside its attempt lifecycle"):
        experiment.settle_attempt(
            completed,
            engine_evidence=(late_evidence,),
            artifact_manifest_ref=_digest("c"),
            cleanup_state=CleanupState.VERIFIED_ABSENT,
            cleanup_evidence_ref=_digest("d"),
            settled_at="2026-11-04T12:05:00Z",
        )

    settled = _settle_latest_attempt(
        _reserve_baseline(_new_experiment()),
        started_at="2026-11-04T12:02:00Z",
        ended_at="2026-11-04T12:04:00Z",
    )
    late_observation = _controller_observation_record(
        target_snapshot_ref=INITIAL_SNAPSHOT,
        mechanism_ref=MECHANISM_REF,
        attempt_id=BASELINE_ATTEMPT,
        evidence=_tenant_observation(
            owner_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            timestamp="2026-11-04T12:04:01Z",
            hardened=False,
        ),
    )
    with pytest.raises(EngineExperimentError, match="outside its attempt lifecycle"):
        settled.record_independent_observation(late_observation, timestamp="2026-11-04T12:05:00Z")

    tampered = build_completed_experiment().to_dict()
    tampered["checks"][0]["settled_at"] = "2026-11-04T12:20:00Z"
    with pytest.raises(EngineExperimentError, match="postdates the experiment"):
        EngineExperiment._from_controller_mapping(tampered)


def test_approval_identity_is_persisted_and_cannot_be_reused() -> None:
    experiment = _reserve_baseline(_new_experiment())
    assert experiment.attempts[0].execution_approval_id == "approval-" + "a" * 32
    saved = experiment.to_dict()
    saved["attempts"][0]["execution_approval_id"] = "approval-invalid"
    with pytest.raises(EngineExperimentError, match="approval identity"):
        EngineExperiment.from_mapping(saved)
