from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

import bluefire.engine_exec_operation_supervisor as supervisor_module
from bluefire.engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2
from bluefire.engine_exec_operation_supervisor import (
    ControllerOwnedExecOperationCustodyV2,
    EngineExecOperationSupervisorError,
    ExecLifetimeOperationRequestV2,
    ExecLifetimeSupervisorActivationV2,
    ExecLifetimeSupervisorBindingV2,
    ExecLifetimeSupervisorRecoveryV2,
    ExecLifetimeTerminalReceiptV2,
)
from bluefire.util import content_hash


def _digest(label: str) -> str:
    return content_hash(label)


ATTEMPT = "engine-attempt-" + "1" * 32
OPERATION = "operation-" + "2" * 32
CONTAINER = "3" * 64
CLAIM = _digest("claim")
FENCE = _digest("fence")
CUSTODY = _digest("custody")
NETWORK = _digest("network")
CONTROLLER = _digest("controller")
SUPERVISOR = _digest("supervisor")
QUALIFICATION = _digest("qualification")
SESSION = _digest("supervisor session")
EPOCH = _digest("clock epoch")
DEADLINE = 30_000_000_000


def _binding() -> ExecLifetimeSupervisorBindingV2:
    return ExecLifetimeSupervisorBindingV2(
        attempt_id=ATTEMPT,
        claim_ref=CLAIM,
        controller_fence=FENCE,
        custody_plan_digest=CUSTODY,
        network_policy_digest=NETWORK,
        controller_instance_ref=CONTROLLER,
        supervisor_qualification_ref=QUALIFICATION,
    )


def _admission() -> object:
    return SimpleNamespace(
        admission_digest=_digest("admission"),
        container_id=CONTAINER,
        profile=SimpleNamespace(attempt_id=ATTEMPT),
        request=SimpleNamespace(operation_id=OPERATION),
    )


def _request() -> ExecLifetimeOperationRequestV2:
    admission = _admission()
    return ExecLifetimeOperationRequestV2(
        admission_digest=admission.admission_digest,
        attempt_id=ATTEMPT,
        operation_id=OPERATION,
        container_id=CONTAINER,
        claim_ref=CLAIM,
        controller_fence=FENCE,
        custody_plan_digest=CUSTODY,
        network_policy_digest=NETWORK,
        operation_deadline_monotonic_ns=DEADLINE,
        controller_instance_ref=CONTROLLER,
        supervisor_instance_ref=SUPERVISOR,
    )


def _proof(
    request: ExecLifetimeOperationRequestV2 | None = None,
    *,
    generation: int = 1,
    lease_ref: str | None = None,
) -> VerifiedExecLifetimeCustodyV2:
    row = _request() if request is None else request
    return VerifiedExecLifetimeCustodyV2(
        admission_digest=row.admission_digest,
        attempt_id=row.attempt_id,
        operation_id=row.operation_id,
        container_id=row.container_id,
        claim_ref=row.claim_ref,
        controller_fence=row.controller_fence,
        custody_plan_digest=row.custody_plan_digest,
        network_policy_digest=row.network_policy_digest,
        operation_deadline_monotonic_ns=row.operation_deadline_monotonic_ns,
        controller_instance_ref=row.controller_instance_ref,
        supervisor_instance_ref=row.supervisor_instance_ref,
        lease_ref=_digest("lease") if lease_ref is None else lease_ref,
        lease_generation=generation,
    )


def _terminal(
    request: ExecLifetimeOperationRequestV2,
    proof: VerifiedExecLifetimeCustodyV2,
    *,
    absent: bool,
    observed_monotonic_ns: int = 2,
) -> ExecLifetimeTerminalReceiptV2:
    return ExecLifetimeTerminalReceiptV2.create(
        request_ref=request.request_ref,
        lease_ref=proof.lease_ref,
        lease_generation=proof.lease_generation,
        outcome="verified_absent" if absent else "verified_complete",
        completion_qualification_ref=None if absent else _digest("completion qualification"),
        final_inventory_digest=_digest("final inventory") if absent else None,
        clock_epoch_ref=EPOCH,
        observed_monotonic_ns=observed_monotonic_ns,
        background_work_absent=True,
        container_absent=absent,
    )


class _Backend:
    def __init__(
        self,
        *,
        active: tuple[VerifiedExecLifetimeCustodyV2, ...] = (),
        terminals: tuple[ExecLifetimeTerminalReceiptV2, ...] = (),
        origin_activation_ref: str | None = None,
    ) -> None:
        self.active = {item.operation_id: item for item in active}
        self.terminals = terminals
        self.events: list[tuple[str, str]] = []
        self.uncertain = False
        self.fail_terminate = False
        self.fail_arm = False
        self.fail_detach = False
        self.arm_override: VerifiedExecLifetimeCustodyV2 | None = None
        self.live_override: VerifiedExecLifetimeCustodyV2 | None = None
        self.origin_activation_ref = origin_activation_ref

    @property
    def cleanup_uncertain(self) -> bool:
        return self.uncertain

    def _activation(
        self, binding: ExecLifetimeSupervisorBindingV2, action: str
    ) -> ExecLifetimeSupervisorActivationV2:
        self.events.append((action, binding.binding_ref))
        activation = ExecLifetimeSupervisorActivationV2.create(
            action=action,  # type: ignore[arg-type]
            binding_ref=binding.binding_ref,
            controller_instance_ref=CONTROLLER,
            supervisor_instance_ref=SUPERVISOR,
            supervisor_session_ref=SESSION,
            clock_epoch_ref=EPOCH,
            supervisor_qualification_ref=QUALIFICATION,
            origin_activation_ref=(
                self.origin_activation_ref if action == "reopened" else None
            ),
            active_leases=tuple(self.active.values()),
            terminal_receipts=self.terminals,
        )
        if action == "activated":
            self.origin_activation_ref = activation.activation_ref
        return activation

    def activate_new(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2:
        return self._activation(binding, "activated")

    def reopen_existing(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2:
        return self._activation(binding, "reopened")

    def arm(self, request: ExecLifetimeOperationRequestV2) -> VerifiedExecLifetimeCustodyV2:
        self.events.append(("arm", request.request_ref))
        if self.fail_arm:
            raise RuntimeError("arm response lost")
        proof = self.arm_override or _proof(request)
        self.active[request.operation_id] = proof
        return proof

    def require_live(
        self, request: ExecLifetimeOperationRequestV2
    ) -> VerifiedExecLifetimeCustodyV2:
        self.events.append(("require_live", request.request_ref))
        current = self.active[request.operation_id]
        proof = self.live_override or replace(current, lease_generation=current.lease_generation + 1)
        self.active[request.operation_id] = proof
        return proof

    def complete(
        self, request: ExecLifetimeOperationRequestV2
    ) -> ExecLifetimeTerminalReceiptV2:
        self.events.append(("complete", request.request_ref))
        return _terminal(request, self.active.pop(request.operation_id), absent=False)

    def terminate(
        self, request: ExecLifetimeOperationRequestV2, *, reason: str
    ) -> ExecLifetimeTerminalReceiptV2:
        self.events.append(("terminate:" + reason, request.request_ref))
        if self.fail_terminate:
            self.uncertain = True
            raise RuntimeError("absence unavailable")
        proof = self.active.pop(request.operation_id, _proof(request))
        return _terminal(request, proof, absent=True)

    def close(self) -> None:
        self.events.append(("close", "backend"))

    def detach(self) -> None:
        self.events.append(("detach", "backend"))
        if self.fail_detach:
            raise RuntimeError("detach unavailable")


def _open(backend: _Backend | None = None) -> tuple[ControllerOwnedExecOperationCustodyV2, _Backend]:
    selected = _Backend() if backend is None else backend
    return (
        ControllerOwnedExecOperationCustodyV2.open(
            binding=_binding(),
            supervisor=selected,
        ),
        selected,
    )


def _live(owner: ControllerOwnedExecOperationCustodyV2):
    return owner.require_live(
        admission=_admission(),  # type: ignore[arg-type]
        claim_ref=CLAIM,
        controller_fence=FENCE,
        custody_plan_digest=CUSTODY,
        network_policy_digest=NETWORK,
        operation_deadline_monotonic_ns=DEADLINE,
    )


def test_open_arms_once_then_reopens_same_lease_with_monotonic_generation(
    monkeypatch,
) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    first = _live(owner)
    second = _live(owner)
    assert first.lease_ref == second.lease_ref
    assert (first.lease_generation, second.lease_generation) == (1, 2)
    assert [event[0] for event in backend.events] == ["activated", "arm", "require_live"]


def test_completion_requires_background_absence_qualification(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    receipt = owner.settle_completed(
        _admission(),  # type: ignore[arg-type]
        claim_ref=CLAIM,
        controller_fence=FENCE,
        custody_plan_digest=CUSTODY,
        network_policy_digest=NETWORK,
        operation_deadline_monotonic_ns=DEADLINE,
    )
    assert receipt.outcome == "verified_complete"
    assert receipt.background_work_absent is True
    assert [event[0] for event in backend.events][-1] == "complete"
    owner.close()


def test_completion_after_deadline_forces_verified_absence(monkeypatch) -> None:
    values = iter((1, 1, DEADLINE))
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: next(values))
    owner, backend = _open()
    _live(owner)
    with pytest.raises(EngineExecOperationSupervisorError, match="deadline elapsed"):
        owner.settle_completed(
            _admission(),  # type: ignore[arg-type]
            claim_ref=CLAIM,
            controller_fence=FENCE,
            custody_plan_digest=CUSTODY,
            network_policy_digest=NETWORK,
            operation_deadline_monotonic_ns=DEADLINE,
        )
    assert [event[0] for event in backend.events][-1] == "terminate:deadline_elapsed"


def test_completion_crossing_deadline_cannot_publish_success(monkeypatch) -> None:
    values = iter((1, 1, 1, DEADLINE))
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: next(values))
    owner, backend = _open()
    _live(owner)
    with pytest.raises(EngineExecOperationSupervisorError, match="deadline elapsed"):
        owner.settle_completed(
            _admission(),  # type: ignore[arg-type]
            claim_ref=CLAIM,
            controller_fence=FENCE,
            custody_plan_digest=CUSTODY,
            network_policy_digest=NETWORK,
            operation_deadline_monotonic_ns=DEADLINE,
        )
    assert [event[0] for event in backend.events][-2:] == [
        "complete",
        "terminate:deadline_elapsed_after_completion",
    ]


def test_cancel_requires_verified_container_absence(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    receipt = owner.cancel(
        _admission(),  # type: ignore[arg-type]
        claim_ref=CLAIM,
        controller_fence=FENCE,
        custody_plan_digest=CUSTODY,
        network_policy_digest=NETWORK,
        operation_deadline_monotonic_ns=DEADLINE,
        reason="operator_cancelled",
    )
    assert receipt.outcome == "verified_absent" and receipt.container_absent
    assert [event[0] for event in backend.events][-1] == "terminate:operator_cancelled"


def test_reopen_restores_live_lease_without_rearming(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    origin = _digest("origin activation")
    backend = _Backend(active=(_proof(),), origin_activation_ref=origin)
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=SUPERVISOR,
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((_request().request_ref, OPERATION, _digest("lease"), 1, DEADLINE),),
    )
    owner = ControllerOwnedExecOperationCustodyV2.reopen(
        binding=_binding(), supervisor=backend, recovery=recovery
    )
    proof = _live(owner)
    assert proof.lease_generation == 2
    assert [event[0] for event in backend.events] == ["reopened", "require_live"]


def test_reopen_refuses_supervisor_or_clock_epoch_rotation_and_detaches() -> None:
    origin = _digest("origin activation")
    backend = _Backend(active=(_proof(),), origin_activation_ref=origin)
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=_digest("other supervisor"),
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((_request().request_ref, OPERATION, _digest("lease"), 1, DEADLINE),),
    )
    with pytest.raises(EngineExecOperationSupervisorError, match="recovery identity changed"):
        ControllerOwnedExecOperationCustodyV2.reopen(
            binding=_binding(), supervisor=backend, recovery=recovery
        )
    assert [event[0] for event in backend.events][-1] == "detach"


def test_reopen_binds_immutable_request_not_only_operation_and_lease() -> None:
    origin = _digest("origin activation")
    changed = replace(_proof(), admission_digest=_digest("changed admission"))
    backend = _Backend(active=(changed,), origin_activation_ref=origin)
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=SUPERVISOR,
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((_request().request_ref, OPERATION, _digest("lease"), 1, DEADLINE),),
    )
    with pytest.raises(EngineExecOperationSupervisorError, match="recovery identity changed"):
        ControllerOwnedExecOperationCustodyV2.reopen(
            binding=_binding(), supervisor=backend, recovery=recovery
        )
    assert [event[0] for event in backend.events][-1] == "detach"


def test_reopen_recovers_durable_terminal_receipt_instead_of_relaunching() -> None:
    origin = _digest("origin activation")
    request, proof = _request(), _proof()
    terminal = _terminal(request, proof, absent=True)
    backend = _Backend(terminals=(terminal,), origin_activation_ref=origin)
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=SUPERVISOR,
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((request.request_ref, OPERATION, proof.lease_ref, 1, DEADLINE),),
    )
    owner = ControllerOwnedExecOperationCustodyV2.reopen(
        binding=_binding(), supervisor=backend, recovery=recovery
    )
    assert owner.recovered_terminal_receipts == (terminal,)
    assert [event[0] for event in backend.events] == ["reopened"]


def test_reopen_rejects_same_request_as_both_live_and_terminal() -> None:
    origin = _digest("origin activation")
    request, proof = _request(), _proof()
    terminal = _terminal(request, proof, absent=True)
    backend = _Backend(
        active=(proof,), terminals=(terminal,), origin_activation_ref=origin
    )
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=SUPERVISOR,
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((request.request_ref, OPERATION, proof.lease_ref, 1, DEADLINE),),
    )
    with pytest.raises(EngineExecOperationSupervisorError, match="recovery identity changed"):
        ControllerOwnedExecOperationCustodyV2.reopen(
            binding=_binding(), supervisor=backend, recovery=recovery
        )
    assert [event[0] for event in backend.events][-1] == "detach"


def test_reopen_rejects_completion_observed_at_or_after_original_deadline() -> None:
    origin = _digest("origin activation")
    request, proof = _request(), _proof()
    terminal = _terminal(
        request, proof, absent=False, observed_monotonic_ns=DEADLINE
    )
    backend = _Backend(terminals=(terminal,), origin_activation_ref=origin)
    recovery = ExecLifetimeSupervisorRecoveryV2(
        activation_ref=origin,
        supervisor_instance_ref=SUPERVISOR,
        supervisor_session_ref=SESSION,
        clock_epoch_ref=EPOCH,
        operation_leases=((request.request_ref, OPERATION, proof.lease_ref, 1, DEADLINE),),
    )
    with pytest.raises(EngineExecOperationSupervisorError, match="recovery identity changed"):
        ControllerOwnedExecOperationCustodyV2.reopen(
            binding=_binding(), supervisor=backend, recovery=recovery
        )


def test_changed_authority_is_refused_before_backend_arm(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    with pytest.raises(EngineExecOperationSupervisorError, match="authority binding changed"):
        owner.require_live(
            admission=_admission(),  # type: ignore[arg-type]
            claim_ref=_digest("other claim"),
            controller_fence=FENCE,
            custody_plan_digest=CUSTODY,
            network_policy_digest=NETWORK,
            operation_deadline_monotonic_ns=DEADLINE,
        )
    assert [event[0] for event in backend.events] == ["activated"]


def test_invalid_arm_proof_triggers_idempotent_absence_settlement(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    backend = _Backend()
    backend.arm_override = replace(_proof(), claim_ref=_digest("other claim"))
    owner, _ = _open(backend)
    with pytest.raises(EngineExecOperationSupervisorError, match="live check failed"):
        _live(owner)
    assert [event[0] for event in backend.events][-1] == "terminate:live_check_failed"
    assert owner.cleanup_uncertain is False


def test_lost_arm_response_cannot_treat_an_unbound_absence_receipt_as_clean(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    backend = _Backend()
    backend.fail_arm = True
    owner, _ = _open(backend)
    with pytest.raises(EngineExecOperationSupervisorError, match="live check failed"):
        _live(owner)
    assert [event[0] for event in backend.events][-1] == "terminate:live_check_failed"
    assert owner.cleanup_uncertain is True


def test_lease_identity_change_or_generation_regression_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    backend.live_override = replace(_proof(), lease_ref=_digest("changed lease"))
    with pytest.raises(EngineExecOperationSupervisorError, match="live check failed"):
        _live(owner)
    assert [event[0] for event in backend.events][-1] == "terminate:live_check_failed"


def test_deadline_after_fresh_check_forces_absence_before_refusal(monkeypatch) -> None:
    values = iter((1, DEADLINE))
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: next(values))
    owner, backend = _open()
    with pytest.raises(EngineExecOperationSupervisorError, match="deadline elapsed"):
        _live(owner)
    assert [event[0] for event in backend.events][-1] == "terminate:deadline_elapsed"
    assert owner.cleanup_uncertain is False


def test_unverified_termination_retains_uncertain_owner_and_blocks_reuse(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    backend.fail_terminate = True
    with pytest.raises(EngineExecOperationSupervisorError, match="absence is unverified"):
        owner.cancel(
            _admission(),  # type: ignore[arg-type]
            claim_ref=CLAIM,
            controller_fence=FENCE,
            custody_plan_digest=CUSTODY,
            network_policy_digest=NETWORK,
            operation_deadline_monotonic_ns=DEADLINE,
            reason="operator_cancelled",
        )
    assert owner.cleanup_uncertain is True
    with pytest.raises(EngineExecOperationSupervisorError, match="unavailable"):
        _live(owner)


def test_close_stops_every_active_operation_before_backend_close(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    owner.close()
    receipts = owner.close_terminal_receipts
    assert len(receipts) == 1
    assert type(receipts[0]) is ExecLifetimeTerminalReceiptV2
    assert receipts[0].request_ref == _request().request_ref
    assert receipts[0].outcome == "verified_absent"
    assert receipts[0].container_absent is True
    assert owner.close_terminal_receipts == receipts
    assert [event[0] for event in backend.events][-2:] == [
        "terminate:controller_close",
        "close",
    ]
    with pytest.raises(EngineExecOperationSupervisorError, match="unavailable"):
        _live(owner)


def test_close_failure_is_sticky_and_never_publishes_clean_cleanup(monkeypatch) -> None:
    monkeypatch.setattr(supervisor_module.time, "monotonic_ns", lambda: 1)
    owner, backend = _open()
    _live(owner)
    backend.fail_terminate = True
    with pytest.raises(EngineExecOperationSupervisorError, match="cleanup is unverified"):
        owner.close()
    assert owner.close_terminal_receipts == ()
    assert [event[0] for event in backend.events][-1] == "detach"
    assert owner.cleanup_uncertain is True
    with pytest.raises(EngineExecOperationSupervisorError, match="remains uncertain"):
        owner.close()


def test_new_activation_cannot_smuggle_historical_live_leases() -> None:
    backend = _Backend(active=(_proof(),))
    with pytest.raises(EngineExecOperationSupervisorError, match="contains old leases"):
        ControllerOwnedExecOperationCustodyV2.open(
            binding=_binding(), supervisor=backend
        )
    assert [event[0] for event in backend.events][-1] == "detach"


def test_failed_activation_detach_failure_is_explicitly_uncertain() -> None:
    backend = _Backend(active=(_proof(),))
    backend.fail_detach = True
    with pytest.raises(EngineExecOperationSupervisorError, match="uncertain detached custody"):
        ControllerOwnedExecOperationCustodyV2.open(
            binding=_binding(), supervisor=backend
        )


def test_public_constructor_cannot_accept_a_self_hashed_activation_receipt() -> None:
    backend = _Backend()
    activation = backend.activate_new(_binding())
    with pytest.raises(EngineExecOperationSupervisorError, match="protected backend"):
        ControllerOwnedExecOperationCustodyV2(
            binding=_binding(),
            supervisor=backend,
            activation=activation,
            expected_action="activated",
            recovery=None,
            _token=object(),
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"background_work_absent": False}, "terminal proof is incomplete"),
        ({"container_absent": False}, "absence proof is incomplete"),
        ({"completion_qualification_ref": _digest("unexpected")}, "absence proof is incomplete"),
        ({"final_inventory_digest": None}, "absence proof is incomplete"),
    ),
)
def test_absence_receipt_cannot_omit_independent_settlement(changes, message) -> None:
    receipt = _terminal(_request(), _proof(), absent=True)
    with pytest.raises(EngineExecOperationSupervisorError, match=message):
        replace(receipt, **changes)
