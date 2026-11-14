from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

from bluefire.engine_action_contract import EngineWorkspaceAction
from bluefire.engine_controller_job_contract import DefenseOperation
from bluefire.engine_experiment import (
    CleanupState,
    ControllerCheckRecord,
    ControllerCheckRole,
    ControllerCheckState,
)
from bluefire.engine_installed_composition import InstalledEngineCompositionError
from bluefire.run_store import RunStore
from bluefire.tenant_record_controller_contract import TenantTargetOperationUnknown
from bluefire.tenant_record_installed_adapters import ControllerOwnedTenantRecordJobAdapterFactory
from bluefire.tenant_record_job_executors import (
    ProductStoreTenantRecordAuthoritySource,
    TenantControllerCheckRunPublisher,
    TenantRecordControllerCheckExecutor,
    TenantRecordDefenseExecutor,
    TenantRecordJobExecutorError,
)
from bluefire.util import content_hash
from tests_platform.test_product_store_engine_actions import _tenant_defense_states
from tests_platform.test_tenant_record_experiment_controller import (
    LEGITIMATE_CHECK,
    LEGITIMATE_RUN,
    REPRODUCER_CHECK,
    REPRODUCER_RUN,
    SCOPE,
    TIME,
    _baseline,
    _controller,
    _plan,
)

EXPERIMENT_ID = "experiment-" + "9" * 32
JOB_ID = "job-" + "a" * 32
LATER = "2026-11-04T15:00:02Z"
WORKSPACE_REF = "sha256:" + "7" * 64
SUBMISSION_ID = "00000000-0000-0000-0000-000000000001"


class _AcceptedStore:
    def __init__(self, record: Mapping[str, Any]) -> None:
        self.record = record
        self.calls = 0

    def get_protected_engine_controller_action_for_job(self, job_id: str) -> Mapping[str, Any]:
        assert job_id == JOB_ID
        self.calls += 1
        return self.record


class _Context:
    def __init__(self, checkpoint: Any = None) -> None:
        self.job_id = JOB_ID
        self.progress: list[Mapping[str, Any]] = []
        self._checkpoint = checkpoint

    def checkpoint(self, progress: Mapping[str, Any]) -> None:
        self.progress.append(dict(progress))
        if self._checkpoint is not None:
            self._checkpoint()


def _authority(kind: str, document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-action-authority.v1",
        "kind": kind,
        "document": dict(document),
        "document_digest": content_hash(document),
    }


def _check(
    controller: Any,
    mechanism: Any,
    *,
    role: ControllerCheckRole,
    check_id: str,
    run_id: str,
) -> ControllerCheckRecord:
    target_ref = controller.current_target_snapshot_ref()
    return ControllerCheckRecord.reserve(
        check_id=check_id,
        experiment_id=EXPERIMENT_ID,
        job_id=JOB_ID,
        run_id=run_id,
        role=role,
        mechanism_ref=content_hash(mechanism.to_dict()),
        target_snapshot_ref=target_ref,
        input_digest="sha256:" + "8" * 64,
        created_at=TIME,
    )


def _check_record(
    check: ControllerCheckRecord,
    mechanism: Any,
    action: EngineWorkspaceAction,
) -> dict[str, Any]:
    experiment_document = {
        "experiment_id": check.experiment_id,
        "scope_ref": SCOPE,
    }
    request = {
        "experiment_id": check.experiment_id,
        "check_id": check.check_id,
        "run_id": check.run_id,
        "role": check.role.value,
        "performer": check.performer.value,
        "mechanism_ref": check.mechanism_ref,
        "target_snapshot_ref": check.target_snapshot_ref,
        "input_digest": check.input_digest,
        "reserved_at": check.created_at,
    }
    document = {
        "schema_version": "bluefire.tenant-controller-check-authority.v1",
        "mechanism": mechanism.to_dict(),
        "check_id": check.check_id,
        "run_id": check.run_id,
        "role": check.role.value,
        "input_digest": check.input_digest,
        "reserved_at": check.created_at,
    }
    experiment_digest = content_hash(experiment_document)
    protected_request = {
        "schema_version": "bluefire.protected-engine-action.v1",
        "experiment_id": check.experiment_id,
        "experiment_revision": 1,
        "experiment_digest": experiment_digest,
        "workspace_digest": WORKSPACE_REF,
        "action_kind": action.value,
        "preparation_kind": "controller_job",
        "approval_request_id": None,
        "submission_id": SUBMISSION_ID,
        "job_request": request,
        "authority": _authority("tenant_controller_check", document),
    }
    return {
        "experiment_id": check.experiment_id,
        "experiment_revision": 1,
        "experiment_digest": experiment_digest,
        "experiment_document": experiment_document,
        "workspace_digest": WORKSPACE_REF,
        "action_kind": action.value,
        "preparation_kind": "controller_job",
        "approval_request_id": None,
        "submission_id": SUBMISSION_ID,
        "protected_request": protected_request,
    }


def _hardened_controller():
    _fixture, target, controller = _controller()
    baseline = _baseline(target, controller)
    assert baseline.failure_mechanism is not None
    plan = _plan(controller)
    assert controller.apply_defense(plan, settled_at=TIME).state.value == "applied"
    return target, controller, baseline.failure_mechanism


def test_controller_check_executes_target_and_recovery_never_replays(tmp_path: Path) -> None:
    target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
    )
    accepted = _AcceptedStore(
        _check_record(check, mechanism, EngineWorkspaceAction.REPEAT_MECHANISM)
    )
    runs = RunStore(tmp_path / "runs")
    jobs = object()
    factory = ControllerOwnedTenantRecordJobAdapterFactory(
        controller=controller,
        clock=lambda: TIME,
    )
    binding = factory.bind(store=cast(Any, accepted), run_store=runs, jobs=cast(Any, jobs))
    assert factory.bind(store=cast(Any, accepted), run_store=runs, jobs=cast(Any, jobs)) is binding
    with pytest.raises(InstalledEngineCompositionError, match="another service"):
        factory.bind(store=cast(Any, accepted), run_store=runs, jobs=cast(Any, object()))
    executor = binding.check_executor
    context = _Context()
    before = target._counter  # noqa: SLF001 - target test double dispatch count

    settlement = executor.execute(cast(Any, context), check)

    assert target._counter == before + 1  # noqa: SLF001
    assert accepted.calls == 2
    assert context.progress[0]["phase"] == "tenant_controller_check_dispatch"
    settlement.validate(check)
    assert settlement.state is ControllerCheckState.COMPLETED
    assert settlement.cleanup_state is CleanupState.VERIFIED_ABSENT
    assert settlement.observations[0].target_scope_ref == SCOPE
    retained = runs.get_run(check.run_id, require_finalized=True)
    assert retained["failure_mechanism"] == mechanism.to_dict()
    assert retained["controller_check"]["assessment"] == "authorization_denied"
    assert retained["evidence"]["records"] == [settlement.observations[0].to_dict()]
    assert runs.validate_bundle(check.run_id)["valid"] is True

    reopened = RunStore(tmp_path / "runs")
    recovery_binding = ControllerOwnedTenantRecordJobAdapterFactory(
        controller=controller, clock=lambda: TIME
    ).bind(store=cast(Any, accepted), run_store=reopened, jobs=cast(Any, object()))
    recovered = recovery_binding.check_executor.reconcile(check)

    assert target._counter == before + 1  # noqa: SLF001
    assert recovered.settlement == settlement


def test_legitimate_token_is_not_retained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.LEGITIMATE_USE,
        check_id=LEGITIMATE_CHECK,
        run_id=LEGITIMATE_RUN,
    )
    accepted = _AcceptedStore(
        _check_record(check, mechanism, EngineWorkspaceAction.RUN_LEGITIMATE_USE)
    )
    runs = RunStore(tmp_path / "runs")
    executor = TenantRecordControllerCheckExecutor(
        controller=controller,
        authority=ProductStoreTenantRecordAuthoritySource(accepted),
        publisher=TenantControllerCheckRunPublisher(runs, clock=lambda: LATER),
        clock=lambda: TIME,
        legitimate_session_lifetime_seconds=30,
    )
    tokens: list[str | None] = []
    original = target.controller_request

    def capture(
        mechanism_value: Any,
        *,
        source_identity: str,
        session_token: str | None,
        expected_target_snapshot_ref: str,
    ):
        tokens.append(session_token)
        return original(
            mechanism_value,
            source_identity=source_identity,
            session_token=session_token,
            expected_target_snapshot_ref=expected_target_snapshot_ref,
        )

    monkeypatch.setattr(target, "controller_request", capture)

    settlement = executor.execute(cast(Any, _Context()), check)

    assert settlement.observations[0].to_dict()["content"]["assessment"] == (
        "legitimate_use_succeeded"
    )
    assert len(tokens) == 1 and tokens[0]
    retained_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (runs.root / check.run_id).iterdir()
        if path.is_file()
    )
    assert cast(str, tokens[0]) not in retained_text


def test_changed_snapshot_or_reservation_is_rejected_before_dispatch(tmp_path: Path) -> None:
    target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
    )
    record = _check_record(check, mechanism, EngineWorkspaceAction.REPEAT_MECHANISM)
    accepted = _AcceptedStore(record)
    authority = ProductStoreTenantRecordAuthoritySource(accepted)
    with pytest.raises(TenantRecordJobExecutorError, match="current custody"):
        authority.check(
            job_id=JOB_ID,
            check=replace(check, created_at="2026-11-04T15:00:01Z"),
        )

    def replace_generation() -> None:
        generation = target.config.service_generation
        target.config = replace(
            target.config,
            service_generation=generation[:-1] + ("0" if generation[-1] != "0" else "1"),
        )
        target._rebuild()  # noqa: SLF001 - intentional target generation change

    runs = RunStore(tmp_path / "runs")
    binding = ControllerOwnedTenantRecordJobAdapterFactory(
        controller=controller,
        clock=lambda: TIME,
    ).bind(store=cast(Any, accepted), run_store=runs, jobs=cast(Any, object()))
    executor = binding.check_executor
    before = target._counter  # noqa: SLF001

    with pytest.raises(TenantRecordJobExecutorError, match="target snapshot changed"):
        executor.execute(cast(Any, _Context(replace_generation)), check)

    assert target._counter == before  # noqa: SLF001
    assert not (tmp_path / "runs" / check.run_id).exists()


def test_snapshot_change_after_preflight_is_rejected_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
    )
    executor = TenantRecordControllerCheckExecutor(
        controller=controller,
        authority=ProductStoreTenantRecordAuthoritySource(
            _AcceptedStore(_check_record(check, mechanism, EngineWorkspaceAction.REPEAT_MECHANISM))
        ),
        publisher=TenantControllerCheckRunPublisher(
            RunStore(tmp_path / "runs"), clock=lambda: LATER
        ),
        clock=lambda: TIME,
    )
    original = target.controller_request

    def change_after_preflight(
        mechanism_value: Any,
        *,
        source_identity: str,
        session_token: str | None,
        expected_target_snapshot_ref: str,
    ):
        generation = target.config.service_generation
        target.config = replace(
            target.config,
            service_generation=generation[:-1] + ("0" if generation[-1] != "0" else "1"),
        )
        target._rebuild()  # noqa: SLF001 - intentional in-lock generation race
        return original(
            mechanism_value,
            source_identity=source_identity,
            session_token=session_token,
            expected_target_snapshot_ref=expected_target_snapshot_ref,
        )

    monkeypatch.setattr(target, "controller_request", change_after_preflight)
    before = target._counter  # noqa: SLF001

    with pytest.raises(TenantRecordJobExecutorError, match="controller check failed"):
        executor.execute(cast(Any, _Context()), check)

    assert target._counter == before  # noqa: SLF001
    assert not (tmp_path / "runs" / check.run_id).exists()


def test_unknown_target_receipt_is_published_and_recovered_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
    )
    accepted = _AcceptedStore(
        _check_record(check, mechanism, EngineWorkspaceAction.REPEAT_MECHANISM)
    )
    runs = RunStore(tmp_path / "runs")
    publisher = TenantControllerCheckRunPublisher(runs, clock=lambda: LATER)
    executor = TenantRecordControllerCheckExecutor(
        controller=controller,
        authority=ProductStoreTenantRecordAuthoritySource(accepted),
        publisher=publisher,
        clock=lambda: TIME,
    )
    receipt = content_hash(
        {
            "stage": "transport",
            "request": mechanism.request_digest,
            "generation": check.target_snapshot_ref,
        }
    )
    calls = 0

    def become_unknown(
        _mechanism_value: Any,
        *,
        source_identity: str,
        session_token: str | None,
        expected_target_snapshot_ref: str,
    ):
        nonlocal calls
        assert source_identity == "controller_probe"
        assert session_token is None
        assert expected_target_snapshot_ref == check.target_snapshot_ref
        calls += 1
        raise TenantTargetOperationUnknown(
            "target request outcome is unknown", receipt_digest=receipt
        )

    monkeypatch.setattr(target, "controller_request", become_unknown)

    settlement = executor.execute(cast(Any, _Context()), check)

    settlement.validate(check)
    assert calls == 1
    assert settlement.state is ControllerCheckState.UNKNOWN
    assert settlement.result_digest == receipt
    assert settlement.observations == ()
    assert settlement.cleanup_state is CleanupState.UNKNOWN
    assert settlement.cleanup_evidence_ref != receipt
    retained = runs.get_run(check.run_id, require_finalized=True)
    assert retained["status"] == "unknown"
    assert retained["result_digest"] == receipt
    assert retained["target_operation_receipt_digest"] == receipt
    assert retained["cleanup_evidence_ref"] == settlement.cleanup_evidence_ref
    assert retained["evidence"]["records"] == []
    assert "controller_check" not in retained
    assert "assessment" not in retained
    assert runs.validate_bundle(check.run_id)["valid"] is True

    assert (
        publisher.publish_unknown(
            check,
            mechanism,
            SCOPE,
            target_operation_receipt_digest=receipt,
            settled_at=TIME,
        )
        == settlement
    )
    with pytest.raises(TenantRecordJobExecutorError, match="published exactly"):
        publisher.publish_unknown(
            check,
            mechanism,
            SCOPE,
            target_operation_receipt_digest=content_hash({"different": receipt}),
            settled_at=TIME,
        )

    recovered = executor.reconcile(check)

    assert recovered.settlement == settlement
    assert recovered.cleanup_state is CleanupState.UNKNOWN
    assert recovered.cleanup_evidence_ref == settlement.cleanup_evidence_ref
    assert calls == 1


def test_conflicting_bundle_is_not_repaired_and_absent_recovery_is_unknown(
    tmp_path: Path,
) -> None:
    _target, controller, mechanism = _hardened_controller()
    check = _check(
        controller,
        mechanism,
        role=ControllerCheckRole.RETAINED_REPRODUCER,
        check_id=REPRODUCER_CHECK,
        run_id=REPRODUCER_RUN,
    )
    outcome = controller.run_exact_reproducer(
        mechanism,
        check_id=check.check_id,
        run_id=check.run_id,
        target_scope_ref=SCOPE,
        expected_target_snapshot_ref=check.target_snapshot_ref,
        performed_at=None,
    )
    runs = RunStore(tmp_path / "runs")
    publisher = TenantControllerCheckRunPublisher(runs, clock=lambda: LATER)
    foreign_scope = "sha256:" + "f" * 64
    wrong_scope_publisher = TenantControllerCheckRunPublisher(
        RunStore(tmp_path / "wrong-scope"), clock=lambda: LATER
    )
    with pytest.raises(TenantRecordJobExecutorError, match="result changed"):
        wrong_scope_publisher.publish(check, outcome, mechanism, foreign_scope)
    assert not (tmp_path / "wrong-scope" / check.run_id).exists()
    absent = publisher.recover(check, mechanism, SCOPE)
    assert absent.settlement is not None
    assert absent.settlement.state is ControllerCheckState.UNKNOWN
    assert absent.cleanup_state is CleanupState.UNKNOWN

    foreign_outcome = controller.run_exact_reproducer(
        mechanism,
        check_id=check.check_id,
        run_id=check.run_id,
        target_scope_ref=foreign_scope,
        expected_target_snapshot_ref=check.target_snapshot_ref,
        performed_at=None,
    )
    foreign_publisher = TenantControllerCheckRunPublisher(
        RunStore(tmp_path / "foreign-bundle"), clock=lambda: LATER
    )
    foreign_publisher.publish(check, foreign_outcome, mechanism, foreign_scope)
    rebound = foreign_publisher.recover(check, mechanism, SCOPE)
    assert rebound.settlement is not None
    assert rebound.settlement.state is ControllerCheckState.UNKNOWN
    assert rebound.settlement.result_digest != foreign_outcome.digest

    runs.publish_finalized_run(
        check.run_id,
        created_at=check.created_at,
        finalized_at=TIME,
        scenario={"schema_version": "test.unrelated.v1"},
        plan={"schema_version": "test.unrelated.v1"},
        policy={"schema_version": "test.unrelated.v1"},
        profile={},
        result={"schema_version": "test.unrelated.v1", "status": "completed"},
        evidence=(),
        detections=(),
    )
    before = runs.get_run(check.run_id, require_finalized=True)

    with pytest.raises(TenantRecordJobExecutorError, match="published exactly"):
        publisher.publish(check, outcome, mechanism, SCOPE)

    assert runs.get_run(check.run_id, require_finalized=True) == before
    assert runs.validate_bundle(check.run_id)["valid"] is True


def _defense_record(experiment: Any, plan: Any) -> dict[str, Any]:
    assert experiment.defense_change is not None
    request = {
        "experiment_id": experiment.experiment_id,
        "operation": DefenseOperation.APPLY.value,
        "change_id": experiment.defense_change.change_id,
    }
    authority = _authority("tenant_defense_plan", plan.to_dict())
    protected_request = {
        "schema_version": "bluefire.protected-engine-action.v1",
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "workspace_digest": WORKSPACE_REF,
        "action_kind": EngineWorkspaceAction.APPLY_DEFENSE.value,
        "preparation_kind": "controller_job",
        "approval_request_id": None,
        "submission_id": SUBMISSION_ID,
        "job_request": request,
        "authority": authority,
    }
    return {
        "experiment_id": experiment.experiment_id,
        "experiment_revision": experiment.revision,
        "experiment_digest": experiment.digest,
        "workspace_digest": WORKSPACE_REF,
        "action_kind": EngineWorkspaceAction.APPLY_DEFENSE.value,
        "preparation_kind": "controller_job",
        "approval_request_id": None,
        "submission_id": SUBMISSION_ID,
        "protected_request": protected_request,
    }


def test_defense_executor_applies_exact_plan_without_coercing_unknown() -> None:
    fixture, target, controller = _controller()
    plan = _plan(controller)
    _prereview, _reviewed, unknown, _applied = _tenant_defense_states(plan.to_dict())
    assert unknown.defense_change is not None
    executor = TenantRecordDefenseExecutor(
        controller=controller,
        authority=ProductStoreTenantRecordAuthoritySource(
            _AcceptedStore(_defense_record(unknown, plan))
        ),
        clock=lambda: LATER,
    )

    settlement = executor.execute(cast(Any, _Context()), unknown, DefenseOperation.APPLY)

    settlement.validate(unknown, expected_operation=DefenseOperation.APPLY)
    assert target.config == plan.after
    assert settlement.configuration_digest == plan.after.digest
    assert settlement.target_snapshot_ref == unknown.defense_change.after_target_snapshot_ref
    assert fixture.digest == plan.fixture_digest

    _fixture, uncertain_target, uncertain_controller = _controller()
    uncertain_plan = _plan(uncertain_controller)
    _pre, _review, uncertain, _done = _tenant_defense_states(uncertain_plan.to_dict())
    uncertain_target.apply_readback_unknown = True
    uncertain_executor = TenantRecordDefenseExecutor(
        controller=uncertain_controller,
        authority=ProductStoreTenantRecordAuthoritySource(
            _AcceptedStore(_defense_record(uncertain, uncertain_plan))
        ),
        clock=lambda: LATER,
    )

    with pytest.raises(TenantRecordJobExecutorError, match="settled as unknown"):
        uncertain_executor.execute(cast(Any, _Context()), uncertain, DefenseOperation.APPLY)

    assert uncertain_target.config == uncertain_plan.after
