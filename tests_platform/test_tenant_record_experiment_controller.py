from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from bluefire.engine_attempt_contract import (
    AttemptCompleteness,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptRecord,
)
from bluefire.engine_experiment import CleanupState, EngineAttemptEntry
from bluefire.tenant_record_experiment_controller import (
    ControllerCheckRole,
    EngineAttemptRole,
    LabDisposition,
    MutationState,
    TenantDefensePlan,
    TenantFailureMechanism,
    TenantRecordControllerError,
    TenantRecordExperimentController,
    TenantTargetCleanup,
    TenantTargetOperationUnknown,
    TenantTargetReadback,
    generate_held_out_variation,
)
from bluefire.tenant_record_lab import (
    TenantDefenseConfig,
    TenantRecordFixture,
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from bluefire.tenant_record_observer import BoundedTenantAuditLog, TenantAuditRow
from bluefire.tenant_record_service import TenantRecordApplication, TenantResponse
from bluefire.util import content_hash

SEED = b"tenant-controller-test-seed-000000001"
KEY = b"tenant-controller-signing-key-material-00000000001"
NOW = datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc)
TIME = "2026-11-04T15:00:00Z"
SCOPE = "sha256:" + "1" * 64

BASELINE_ATTEMPT = "engine-attempt-" + "1" * 32
ADAPTIVE_ATTEMPT = "engine-attempt-" + "2" * 32
BASELINE_RUN = "run-20261104T150000Z-" + "1" * 16
ADAPTIVE_RUN = "run-20261104T150100Z-" + "2" * 16
REPRODUCER_CHECK = "controller-check-" + "3" * 32
LEGITIMATE_CHECK = "controller-check-" + "4" * 32
REPRODUCER_RUN = "run-20261104T150200Z-" + "3" * 16
LEGITIMATE_RUN = "run-20261104T150300Z-" + "4" * 16
DEFENSE_OPERATION = "tenant-defense-" + "5" * 32
ROLLBACK_OPERATION = "tenant-rollback-" + "6" * 32
CLEANUP_OPERATION = "tenant-cleanup-" + "7" * 32


class _Target:
    def __init__(self, fixture: TenantRecordFixture) -> None:
        self.fixture = fixture
        self.config = baseline_defense_config(fixture)
        self.audit = BoundedTenantAuditLog()
        self.cleaned = False
        self.apply_readback_unknown = False
        self.rollback_readback_unknown = False
        self.cleanup_verified = True
        self.current_unknown = False
        self.raise_apply_unknown = False
        self._counter = 0
        self._rebuild()

    def _next_id(self) -> str:
        self._counter += 1
        return f"request-{self._counter:024x}"

    def _rebuild(self) -> None:
        self.audit = BoundedTenantAuditLog()
        self.application = TenantRecordApplication(
            fixture=self.fixture,
            config=self.config,
            signing_key=KEY if self.config.mode == "signed_session" else None,
            audit_log=self.audit,
            clock=lambda: NOW,
            request_id_factory=self._next_id,
        )

    def current_config(self) -> TenantDefenseConfig | None:
        if self.cleaned:
            raise AssertionError("a cleaned target has no current configuration")
        return None if self.current_unknown else self.config

    def audit_row(self, request_id: str) -> TenantAuditRow:
        return self.audit.row(request_id)

    @staticmethod
    def _request(mechanism: TenantFailureMechanism) -> tuple[str, dict[str, str]]:
        target = (
            f"/records/{mechanism.record_id}"
            if mechanism.route.value == "record_lookup"
            else f"/exports?tenant={mechanism.protected_tenant_id}"
        )
        return target, {
            "host": "tenant-record.test",
            "x-bluefire-lab-tenant": mechanism.protected_tenant_id,
        }

    def engine_request(self, *, route: str) -> TenantResponse:
        protected = self.fixture.records_for(self.fixture.protected_tenant_id)[0]
        target = (
            f"/records/{protected.record_id}"
            if route == "record_lookup"
            else f"/exports?tenant={self.fixture.protected_tenant_id}"
        )
        return self.application.handle(
            "GET",
            target,
            {
                "host": "tenant-record.test",
                "x-bluefire-lab-tenant": self.fixture.protected_tenant_id,
            },
            source_identity="engine_worker",
        )

    def controller_request(
        self,
        mechanism: TenantFailureMechanism,
        *,
        source_identity: str,
        session_token: str | None,
    ) -> TenantResponse:
        target, headers = self._request(mechanism)
        if session_token is not None:
            headers.pop("x-bluefire-lab-tenant")
            headers["authorization"] = f"BlueFireLab {session_token}"
        return self.application.handle("GET", target, headers, source_identity=source_identity)

    def apply_defense(self, plan: TenantDefensePlan) -> TenantTargetReadback:
        assert plan.before == self.config
        self.config = plan.after
        self._rebuild()
        receipt = content_hash(
            {"operation": plan.operation_id, "direction": "apply", "config": self.config.digest}
        )
        if self.raise_apply_unknown:
            raise TenantTargetOperationUnknown("apply outcome interrupted", receipt_digest=receipt)
        return TenantTargetReadback(
            observed_config=None if self.apply_readback_unknown else self.config,
            receipt_digest=receipt,
        )

    def rollback_defense(
        self, plan: TenantDefensePlan, *, operation_id: str
    ) -> TenantTargetReadback:
        assert plan.after == self.config
        self.config = plan.before
        self._rebuild()
        return TenantTargetReadback(
            observed_config=None if self.rollback_readback_unknown else self.config,
            receipt_digest=content_hash(
                {"operation": operation_id, "direction": "rollback", "config": self.config.digest}
            ),
        )

    def cleanup_lab(
        self,
        fixture: TenantRecordFixture,
        *,
        expected_config_digest: str,
        operation_id: str,
    ) -> TenantTargetCleanup:
        assert fixture.digest == self.fixture.digest
        assert expected_config_digest == self.config.digest
        if self.cleanup_verified:
            self.cleaned = True
        return TenantTargetCleanup(
            verified_absent=self.cleanup_verified,
            receipt_digest=content_hash(
                {
                    "operation": operation_id,
                    "fixture": fixture.digest,
                    "verified_absent": self.cleanup_verified,
                }
            ),
        )


def _controller() -> tuple[TenantRecordFixture, _Target, TenantRecordExperimentController]:
    fixture = generate_tenant_record_fixture(SEED)
    target = _Target(fixture)
    return (
        fixture,
        target,
        TenantRecordExperimentController(fixture=fixture, target=target, signing_key=KEY),
    )


def _plan(controller: TenantRecordExperimentController) -> TenantDefensePlan:
    return controller.prepare_defense(
        operation_id=DEFENSE_OPERATION,
        key_id="key-tenant-controller",
        application_nonce="apply-tenant-controller-0001",
        responsible_actor="bluefire-controller",
        planned_at=TIME,
    )


def _baseline(target: _Target, controller: TenantRecordExperimentController):
    response = target.engine_request(route="record_lookup")
    return controller.observe_engine_response(
        role=EngineAttemptRole.BASELINE,
        attempt_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        response=response,
        step_id="tenant-boundary",
        target_scope_ref=SCOPE,
    )


def _checks(controller: TenantRecordExperimentController, mechanism: TenantFailureMechanism):
    reproducer = controller.run_exact_reproducer(
        mechanism,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
        target_scope_ref=SCOPE,
        performed_at=TIME,
    )
    legitimate = controller.run_legitimate_use(
        mechanism,
        check_id=LEGITIMATE_CHECK,
        run_id=LEGITIMATE_RUN,
        target_scope_ref=SCOPE,
        performed_at=TIME,
        issued_at=NOW,
        lifetime_seconds=60,
    )
    return reproducer, legitimate


def _adaptive(target: _Target, controller: TenantRecordExperimentController):
    response = target.engine_request(route="bounded_export")
    return controller.observe_engine_response(
        role=EngineAttemptRole.ADAPTIVE_SEARCH,
        attempt_id=ADAPTIVE_ATTEMPT,
        run_id=ADAPTIVE_RUN,
        response=response,
        step_id="adaptive-tenant-boundary",
        target_scope_ref=SCOPE,
    )


def _attempt_entry(
    role: EngineAttemptRole, *, attempt_id: str, run_id: str, cleanup: CleanupState
) -> EngineAttemptEntry:
    binding = EngineAttemptBinding.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-binding.v1",
            "experiment_id": "experiment-" + "9" * 32,
            "attempt_id": attempt_id,
            "run_id": run_id,
            "role": role.value,
            "objective_ref": "sha256:" + "1" * 64,
            "environment_ref": "sha256:" + "2" * 64,
            "target_snapshot_ref": "sha256:" + "3" * 64,
            "scope_ref": "sha256:" + "4" * 64,
            "scope_version": "bluefire.engine-capability-delegation.v1",
            "engine_id": "strix",
            "engine_version": "1.7.0",
            "engine_revision": "5" * 40,
            "engine_package_digest": "sha256:" + "6" * 64,
            "policy_overlay_digest": "sha256:" + "7" * 64,
            "model_provider": "provider.test",
            "model_id": "test-model",
            "model_data_destination": "https://model.test/v1",
            "model_authorization_ref": "sha256:" + "8" * 64,
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "cost_limit_microunits": 1_000_000,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "created_at": TIME,
            "parent_attempt_id": None if role is EngineAttemptRole.BASELINE else BASELINE_ATTEMPT,
        }
    )
    record = EngineAttemptRecord.create(binding).transition(AttemptState.PREFLIGHT)
    record = record.transition(
        AttemptState.RUNNING,
        upstream_session_id="session-" + attempt_id[-8:],
        timestamp=TIME,
    )
    record = record.transition(
        AttemptState.COMPLETED,
        timestamp=TIME,
        exit_code=0,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="completed",
    )
    return EngineAttemptEntry.from_mapping(
        {
            "schema_version": "bluefire.engine-attempt-entry.v2",
            "job_id": "job-" + ("a" if role is EngineAttemptRole.BASELINE else "b") * 32,
            "delegation_digest": "sha256:" + "9" * 64,
            "execution_approval_digest": "sha256:" + "a" * 64,
            "execution_approval_id": "approval-"
            + ("a" if role is EngineAttemptRole.BASELINE else "b") * 32,
            "record": record.to_dict(),
            "evidence": [],
            "artifact_manifest_ref": "sha256:" + "b" * 64,
            "cleanup_state": cleanup.value,
            "cleanup_evidence_ref": "sha256:"
            + ("c" if role is EngineAttemptRole.BASELINE else "d") * 64,
            "settled_at": TIME,
        }
    )


def _cleanup() -> tuple[EngineAttemptEntry, EngineAttemptEntry]:
    return (
        _attempt_entry(
            EngineAttemptRole.BASELINE,
            attempt_id=BASELINE_ATTEMPT,
            run_id=BASELINE_RUN,
            cleanup=CleanupState.VERIFIED_ABSENT,
        ),
        _attempt_entry(
            EngineAttemptRole.ADAPTIVE_SEARCH,
            attempt_id=ADAPTIVE_ATTEMPT,
            run_id=ADAPTIVE_RUN,
            cleanup=CleanupState.VERIFIED_ABSENT,
        ),
    )


def test_baseline_observation_captures_exact_fixed_failure_mechanism() -> None:
    fixture, target, controller = _controller()

    observation = _baseline(target, controller)

    assert observation.assessment == "unauthorized_disclosure"
    assert observation.failure_mechanism is not None
    mechanism = observation.failure_mechanism
    assert mechanism.fixture_digest == fixture.digest
    assert mechanism.record_id in {
        item.record_id for item in fixture.records_for(fixture.protected_tenant_id)
    }
    assert mechanism.to_dict()["method"] == "GET"
    assert set(mechanism.to_dict()) == {
        "schema_version",
        "method",
        "host",
        "fixture_digest",
        "original_target_snapshot_id",
        "route",
        "protected_tenant_id",
        "record_id",
        "identity_input",
        "request_digest",
    }


def test_defense_exact_reproducer_adaptive_observation_and_legitimate_use() -> None:
    _fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)

    applied = controller.apply_defense(plan, settled_at=TIME)
    reproducer, legitimate = _checks(controller, baseline.failure_mechanism)
    adaptive = _adaptive(target, controller)

    assert applied.state is MutationState.APPLIED
    assert applied.change_id is not None
    assert applied.change_receipt_digest is not None
    assert "change_receipt" not in plan.to_dict()
    assert reproducer.role is ControllerCheckRole.RETAINED_REPRODUCER
    assert reproducer.assessment == "authorization_denied"
    assert reproducer.passed is True
    assert adaptive.assessment == "authorization_denied"
    assert adaptive.failure_mechanism is None
    assert legitimate.role is ControllerCheckRole.LEGITIMATE_USE
    assert legitimate.assessment == "legitimate_use_succeeded"
    assert legitimate.passed is True
    serialized = str(plan.to_dict()) + str(reproducer.to_dict()) + str(legitimate.to_dict())
    assert KEY.decode() not in serialized


def test_interrupted_apply_and_rollback_remain_unknown_until_fresh_reconciliation() -> None:
    _fixture, target, controller = _controller()
    plan = _plan(controller)
    target.apply_readback_unknown = True

    apply = controller.apply_defense(plan, settled_at=TIME)
    target.current_unknown = True
    unknown_reconciliation = controller.reconcile_defense(
        plan,
        direction="apply",
        operation_id=DEFENSE_OPERATION,
        settled_at=TIME,
        observation_receipt_digest="sha256:" + "e" * 64,
    )
    target.current_unknown = False
    reconciled_apply = controller.reconcile_defense(
        plan,
        direction="apply",
        operation_id=DEFENSE_OPERATION,
        settled_at=TIME,
        observation_receipt_digest="sha256:" + "c" * 64,
    )
    target.rollback_readback_unknown = True
    rollback = controller.rollback_defense(plan, operation_id=ROLLBACK_OPERATION, settled_at=TIME)
    reconciled_rollback = controller.reconcile_defense(
        plan,
        direction="rollback",
        operation_id=ROLLBACK_OPERATION,
        settled_at=TIME,
        observation_receipt_digest="sha256:" + "d" * 64,
    )

    assert apply.state is MutationState.UNKNOWN
    assert apply.target_snapshot_id is None
    assert unknown_reconciliation.state is MutationState.UNKNOWN
    assert unknown_reconciliation.target_snapshot_id is None
    assert reconciled_apply.state is MutationState.APPLIED
    assert rollback.state is MutationState.UNKNOWN
    assert rollback.target_snapshot_id is None
    assert reconciled_rollback.state is MutationState.ROLLED_BACK


def test_retained_hardening_requires_both_controls_and_both_engine_cleanup_proofs() -> None:
    _fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)
    assert controller.apply_defense(plan, settled_at=TIME).state is MutationState.APPLIED
    reproducer, legitimate = _checks(controller, baseline.failure_mechanism)
    adaptive = _adaptive(target, controller)

    retained = controller.retain_hardening(
        plan,
        operation_id=CLEANUP_OPERATION,
        baseline=baseline,
        adaptive=adaptive,
        reproducer=reproducer,
        legitimate_use=legitimate,
        engine_cleanup=_cleanup(),
        recorded_at=TIME,
    )

    assert retained.disposition is LabDisposition.RETAINED_HARDENING
    assert retained.target_config_digest == plan.after.digest
    assert retained.target_cleanup_receipt_digest is None

    incomplete = (_cleanup()[0], _cleanup()[0])
    with pytest.raises(TenantRecordControllerError, match="both engine attempts"):
        controller.retain_hardening(
            plan,
            operation_id=CLEANUP_OPERATION,
            baseline=baseline,
            adaptive=adaptive,
            reproducer=reproducer,
            legitimate_use=legitimate,
            engine_cleanup=incomplete,
            recorded_at=TIME,
        )

    wrong_run = (
        _cleanup()[0],
        _attempt_entry(
            EngineAttemptRole.ADAPTIVE_SEARCH,
            attempt_id=ADAPTIVE_ATTEMPT,
            run_id="run-20261104T150100Z-" + "f" * 16,
            cleanup=CleanupState.VERIFIED_ABSENT,
        ),
    )
    with pytest.raises(TenantRecordControllerError, match="verified absent"):
        controller.retain_hardening(
            plan,
            operation_id=CLEANUP_OPERATION,
            baseline=baseline,
            adaptive=adaptive,
            reproducer=reproducer,
            legitimate_use=legitimate,
            engine_cleanup=wrong_run,
            recorded_at=TIME,
        )


def test_cleanup_preserves_unknown_instead_of_claiming_absence() -> None:
    _fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)
    controller.apply_defense(plan, settled_at=TIME)
    reproducer, legitimate = _checks(controller, baseline.failure_mechanism)
    adaptive = _adaptive(target, controller)
    target.cleanup_verified = False

    unknown = controller.cleanup_lab(
        plan,
        operation_id=CLEANUP_OPERATION,
        baseline=baseline,
        adaptive=adaptive,
        reproducer=reproducer,
        legitimate_use=legitimate,
        engine_cleanup=_cleanup(),
        recorded_at=TIME,
    )

    assert unknown.disposition is LabDisposition.UNKNOWN
    assert unknown.target_snapshot_id == plan.after.target_snapshot_id
    assert unknown.target_cleanup_receipt_digest is not None

    target.cleanup_verified = True
    cleaned = controller.cleanup_lab(
        plan,
        operation_id=CLEANUP_OPERATION,
        baseline=baseline,
        adaptive=adaptive,
        reproducer=reproducer,
        legitimate_use=legitimate,
        engine_cleanup=_cleanup(),
        recorded_at=TIME,
    )
    assert cleaned.disposition is LabDisposition.CLEANED
    assert cleaned.target_snapshot_id is None
    assert target.cleaned is True


def test_held_out_variation_reuses_contract_but_changes_ids_and_route_order() -> None:
    primary = generate_tenant_record_fixture(SEED)

    held_out = generate_held_out_variation(SEED, primary=primary)
    target = _Target(held_out)
    controller = TenantRecordExperimentController(fixture=held_out, target=target, signing_key=KEY)
    baseline = _baseline_for(
        target,
        controller,
        attempt_id=BASELINE_ATTEMPT,
        run_id=BASELINE_RUN,
        route=held_out.route_order[0],
    )

    assert held_out.fixture_id != primary.fixture_id
    assert held_out.protected_tenant_id != primary.protected_tenant_id
    assert held_out.route_order != primary.route_order
    assert baseline.assessment == "unauthorized_disclosure"
    assert baseline.failure_mechanism is not None
    assert baseline.failure_mechanism.route.value == held_out.route_order[0]


def _baseline_for(
    target: _Target,
    controller: TenantRecordExperimentController,
    *,
    attempt_id: str,
    run_id: str,
    route: str,
):
    response = target.engine_request(route=route)
    return controller.observe_engine_response(
        role=EngineAttemptRole.BASELINE,
        attempt_id=attempt_id,
        run_id=run_id,
        response=response,
        step_id="tenant-boundary",
        target_scope_ref=SCOPE,
    )


def test_mechanism_has_no_arbitrary_url_or_command_surface() -> None:
    fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None

    with pytest.raises(TenantRecordControllerError, match="digest"):
        TenantFailureMechanism(
            fixture_digest=fixture.digest,
            original_target_snapshot_id=fixture.target_snapshot_id,
            route=baseline.failure_mechanism.route,
            protected_tenant_id=fixture.protected_tenant_id,
            record_id=baseline.failure_mechanism.record_id,
            request_digest="https://not-allowed.example/path",
        )

    fields = set(baseline.failure_mechanism.to_dict())
    assert not fields & {"url", "command", "script", "path", "headers", "credential"}


def test_canonical_but_foreign_mechanism_is_rejected_before_target_request() -> None:
    fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)
    controller.apply_defense(plan, settled_at=TIME)
    binding = baseline.failure_mechanism.request_binding()
    binding["original_target_snapshot_id"] = "snapshot-" + "a" * 20
    binding["record_id"] = "record-" + "b" * 20
    forged = TenantFailureMechanism(
        fixture_digest=fixture.digest,
        original_target_snapshot_id=binding["original_target_snapshot_id"],
        route=baseline.failure_mechanism.route,
        protected_tenant_id=fixture.protected_tenant_id,
        record_id=binding["record_id"],
        request_digest=content_hash(binding),
    )

    with pytest.raises(TenantRecordControllerError, match="another fixture"):
        controller.run_exact_reproducer(
            forged,
            check_id=REPRODUCER_CHECK,
            run_id=REPRODUCER_RUN,
            target_scope_ref=SCOPE,
            performed_at=TIME,
        )

    alternate_record = next(
        record.record_id
        for record in fixture.records_for(fixture.protected_tenant_id)
        if record.record_id != baseline.failure_mechanism.record_id
    )
    alternate_binding = baseline.failure_mechanism.request_binding()
    alternate_binding["record_id"] = alternate_record
    alternate = TenantFailureMechanism(
        fixture_digest=fixture.digest,
        original_target_snapshot_id=baseline.failure_mechanism.original_target_snapshot_id,
        route=baseline.failure_mechanism.route,
        protected_tenant_id=fixture.protected_tenant_id,
        record_id=alternate_record,
        request_digest=content_hash(alternate_binding),
    )
    with pytest.raises(TenantRecordControllerError, match="observed request"):
        replace(baseline, failure_mechanism=alternate)


def test_defense_plan_is_bound_to_controller_key_and_exact_change_receipt() -> None:
    fixture, _target, controller = _controller()
    plan = _plan(controller)
    foreign_key = b"foreign-tenant-controller-signing-key-material-000001"
    foreign_after = hardened_defense_config(
        fixture,
        signing_key=foreign_key,
        key_id="key-tenant-controller",
        application_nonce="apply-tenant-controller-0001",
        prior=plan.before,
    )
    review = {
        "schema_version": "bluefire.tenant-record-defense-review.v1",
        "preimage_digest": plan.before.digest,
        "approved_configuration_digest": foreign_after.digest,
        "responsible_actor": plan.responsible_actor,
        "reviewed_at": plan.planned_at,
        "claims_application": False,
    }
    review_digest = content_hash(review)
    forged = TenantDefensePlan(
        operation_id=plan.operation_id,
        fixture_digest=plan.fixture_digest,
        before=plan.before,
        after=foreign_after,
        review_id="review-" + review_digest.removeprefix("sha256:")[:20],
        review_digest=review_digest,
        responsible_actor=plan.responsible_actor,
        planned_at=plan.planned_at,
    )

    with pytest.raises(TenantRecordControllerError, match="controller signing key"):
        controller.apply_defense(forged, settled_at=TIME)

    with pytest.raises(TenantRecordControllerError, match="review binding"):
        replace(plan, review_digest="sha256:" + "f" * 64)


def test_target_exception_after_mutation_is_recorded_unknown_then_reconciled() -> None:
    _fixture, target, controller = _controller()
    plan = _plan(controller)
    target.raise_apply_unknown = True

    unknown = controller.apply_defense(plan, settled_at=TIME)
    reconciled = controller.reconcile_defense(
        plan,
        direction="apply",
        operation_id=DEFENSE_OPERATION,
        settled_at=TIME,
        observation_receipt_digest="sha256:" + "e" * 64,
    )

    assert unknown.state is MutationState.UNKNOWN
    assert unknown.target_snapshot_id is None
    assert reconciled.state is MutationState.APPLIED


def test_check_time_must_equal_protected_audit_time() -> None:
    _fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)
    controller.apply_defense(plan, settled_at=TIME)
    reproducer, _legitimate = _checks(controller, baseline.failure_mechanism)

    with pytest.raises(TenantRecordControllerError, match="protected target event"):
        replace(reproducer, performed_at="2026-11-04T15:00:01Z")
