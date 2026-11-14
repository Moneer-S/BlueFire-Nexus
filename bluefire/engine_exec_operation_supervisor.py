"""Controller owner for an externally supervised Docker exec lifetime.

The owner in this module is deliberately not the external watchdog.  It binds
one qualified, crash-surviving supervisor backend to the controller and makes
that backend's fresh authenticated checks usable by exec dispatch.  There is
no in-process timer, fixture backend, or permissive fallback here: production
composition must supply the protected backend and retain this owner for the
whole attempt.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from .engine_exec_operation_custody import VerifiedExecLifetimeCustodyV2
from .util import content_hash

if TYPE_CHECKING:
    from .engine_docker_exec_admission import DockerExecAdmissionV2


class EngineExecOperationSupervisorError(RuntimeError):
    """The protected supervisor lease or terminal settlement is unavailable."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_CONSTRUCTION_TOKEN = object()


def _match(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EngineExecOperationSupervisorError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    return _match(value, _DIGEST, label)


@dataclass(frozen=True, slots=True)
class ExecLifetimeSupervisorBindingV2:
    """Activation binding retained by a qualified external supervisor."""

    attempt_id: str
    claim_ref: str
    controller_fence: str
    custody_plan_digest: str
    network_policy_digest: str
    controller_instance_ref: str
    supervisor_qualification_ref: str

    def __post_init__(self) -> None:
        _match(self.attempt_id, _ATTEMPT, "exec supervisor attempt")
        for name in (
            "claim_ref",
            "controller_fence",
            "custody_plan_digest",
            "network_policy_digest",
            "controller_instance_ref",
            "supervisor_qualification_ref",
        ):
            _digest(getattr(self, name), f"exec supervisor {name}")

    @property
    def binding_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.exec-lifetime-supervisor-binding.v2",
                **asdict(self),
            }
        )


@dataclass(frozen=True, slots=True)
class ExecLifetimeSupervisorActivationV2:
    """Authenticated activation/reopen receipt from the external supervisor."""

    action: Literal["activated", "reopened"]
    binding_ref: str
    controller_instance_ref: str
    supervisor_instance_ref: str
    supervisor_session_ref: str
    clock_epoch_ref: str
    supervisor_qualification_ref: str
    origin_activation_ref: str | None
    active_leases: tuple[VerifiedExecLifetimeCustodyV2, ...]
    terminal_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...]
    deadline_stop_enforced: bool
    controller_loss_stop_enforced: bool
    activation_ref: str

    def __post_init__(self) -> None:
        if self.action not in {"activated", "reopened"}:
            raise EngineExecOperationSupervisorError("exec supervisor activation action is invalid")
        for name in (
            "binding_ref",
            "controller_instance_ref",
            "supervisor_instance_ref",
            "supervisor_session_ref",
            "clock_epoch_ref",
            "supervisor_qualification_ref",
            "activation_ref",
        ):
            _digest(getattr(self, name), f"exec supervisor activation {name}")
        if (
            type(self.active_leases) is not tuple
            or len(self.active_leases) > 128
            or any(type(item) is not VerifiedExecLifetimeCustodyV2 for item in self.active_leases)
            or type(self.terminal_receipts) is not tuple
            or len(self.terminal_receipts) > 128
            or any(
                type(item) is not ExecLifetimeTerminalReceiptV2
                for item in self.terminal_receipts
            )
            or len({item.request_ref for item in self.terminal_receipts})
            != len(self.terminal_receipts)
            or len({item.operation_id for item in self.active_leases}) != len(self.active_leases)
            or len({item.lease_ref for item in self.active_leases}) != len(self.active_leases)
            or self.deadline_stop_enforced is not True
            or self.controller_loss_stop_enforced is not True
        ):
            raise EngineExecOperationSupervisorError("exec supervisor activation is unenforced")
        if (self.action == "activated") != (self.origin_activation_ref is None):
            raise EngineExecOperationSupervisorError("exec supervisor activation lineage is invalid")
        if self.origin_activation_ref is not None:
            _digest(self.origin_activation_ref, "exec supervisor origin activation")
        if self.activation_ref != content_hash(self.document(include_ref=False)):
            raise EngineExecOperationSupervisorError("exec supervisor activation receipt changed")

    @classmethod
    def create(
        cls,
        *,
        action: Literal["activated", "reopened"],
        binding_ref: str,
        controller_instance_ref: str,
        supervisor_instance_ref: str,
        supervisor_session_ref: str,
        clock_epoch_ref: str,
        supervisor_qualification_ref: str,
        origin_activation_ref: str | None = None,
        active_leases: tuple[VerifiedExecLifetimeCustodyV2, ...] = (),
        terminal_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...] = (),
    ) -> ExecLifetimeSupervisorActivationV2:
        values = {
            "action": action,
            "binding_ref": binding_ref,
            "controller_instance_ref": controller_instance_ref,
            "supervisor_instance_ref": supervisor_instance_ref,
            "supervisor_session_ref": supervisor_session_ref,
            "clock_epoch_ref": clock_epoch_ref,
            "supervisor_qualification_ref": supervisor_qualification_ref,
            "origin_activation_ref": origin_activation_ref,
            "active_leases": active_leases,
            "terminal_receipts": terminal_receipts,
            "deadline_stop_enforced": True,
            "controller_loss_stop_enforced": True,
        }
        provisional = {
            **values,
            "active_leases": [item.proof_ref for item in active_leases],
            "terminal_receipts": [item.receipt_ref for item in terminal_receipts],
            "schema_version": "bluefire.exec-lifetime-supervisor-activation.v2",
        }
        return cls(**values, activation_ref=content_hash(provisional))

    def document(self, *, include_ref: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": "bluefire.exec-lifetime-supervisor-activation.v2",
            "action": self.action,
            "binding_ref": self.binding_ref,
            "controller_instance_ref": self.controller_instance_ref,
            "supervisor_instance_ref": self.supervisor_instance_ref,
            "supervisor_session_ref": self.supervisor_session_ref,
            "clock_epoch_ref": self.clock_epoch_ref,
            "supervisor_qualification_ref": self.supervisor_qualification_ref,
            "origin_activation_ref": self.origin_activation_ref,
            "active_leases": [item.proof_ref for item in self.active_leases],
            "terminal_receipts": [item.receipt_ref for item in self.terminal_receipts],
            "deadline_stop_enforced": self.deadline_stop_enforced,
            "controller_loss_stop_enforced": self.controller_loss_stop_enforced,
        }
        if include_ref:
            result["activation_ref"] = self.activation_ref
        return result


@dataclass(frozen=True, slots=True)
class ExecLifetimeSupervisorRecoveryV2:
    """Durable identity needed to reopen, never to activate a new supervisor."""

    activation_ref: str
    supervisor_instance_ref: str
    supervisor_session_ref: str
    clock_epoch_ref: str
    operation_leases: tuple[tuple[str, str, str, int, int], ...]

    def __post_init__(self) -> None:
        for name in (
            "activation_ref",
            "supervisor_instance_ref",
            "supervisor_session_ref",
            "clock_epoch_ref",
        ):
            _digest(getattr(self, name), f"exec supervisor recovery {name}")
        if type(self.operation_leases) is not tuple or len(self.operation_leases) > 128:
            raise EngineExecOperationSupervisorError("exec supervisor recovery leases are invalid")
        operations: set[str] = set()
        leases: set[str] = set()
        requests: set[str] = set()
        for row in self.operation_leases:
            if type(row) is not tuple or len(row) != 5:
                raise EngineExecOperationSupervisorError(
                    "exec supervisor recovery lease is invalid"
                )
            request_ref, operation_id, lease_ref, generation, deadline = row
            _digest(request_ref, "exec supervisor recovery request")
            _match(operation_id, _OPERATION, "exec supervisor recovery operation")
            _digest(lease_ref, "exec supervisor recovery lease")
            if type(generation) is not int or not 1 <= generation < 2**63:
                raise EngineExecOperationSupervisorError(
                    "exec supervisor recovery generation is invalid"
                )
            if type(deadline) is not int or deadline <= 0:
                raise EngineExecOperationSupervisorError(
                    "exec supervisor recovery deadline is invalid"
                )
            if operation_id in operations or lease_ref in leases or request_ref in requests:
                raise EngineExecOperationSupervisorError(
                    "exec supervisor recovery lease is duplicated"
                )
            operations.add(operation_id)
            leases.add(lease_ref)
            requests.add(request_ref)

    @property
    def recovery_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.exec-lifetime-supervisor-recovery.v2",
                "activation_ref": self.activation_ref,
                "supervisor_instance_ref": self.supervisor_instance_ref,
                "supervisor_session_ref": self.supervisor_session_ref,
                "clock_epoch_ref": self.clock_epoch_ref,
                "operation_leases": [
                    {
                        "request_ref": request_ref,
                        "operation_id": operation_id,
                        "lease_ref": lease_ref,
                        "lease_generation": generation,
                        "operation_deadline_monotonic_ns": deadline,
                    }
                    for request_ref, operation_id, lease_ref, generation, deadline in self.operation_leases
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class ExecLifetimeOperationRequestV2:
    admission_digest: str
    attempt_id: str
    operation_id: str
    container_id: str
    claim_ref: str
    controller_fence: str
    custody_plan_digest: str
    network_policy_digest: str
    operation_deadline_monotonic_ns: int
    controller_instance_ref: str
    supervisor_instance_ref: str

    def __post_init__(self) -> None:
        _digest(self.admission_digest, "exec supervisor admission")
        _match(self.attempt_id, _ATTEMPT, "exec supervisor attempt")
        _match(self.operation_id, _OPERATION, "exec supervisor operation")
        _match(self.container_id, _CONTAINER, "exec supervisor container")
        for name in (
            "claim_ref",
            "controller_fence",
            "custody_plan_digest",
            "network_policy_digest",
            "controller_instance_ref",
            "supervisor_instance_ref",
        ):
            _digest(getattr(self, name), f"exec supervisor operation {name}")
        if (
            type(self.operation_deadline_monotonic_ns) is not int
            or self.operation_deadline_monotonic_ns <= 0
        ):
            raise EngineExecOperationSupervisorError("exec supervisor deadline is invalid")

    @property
    def request_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.exec-lifetime-operation-request.v2",
                **asdict(self),
            }
        )


@dataclass(frozen=True, slots=True)
class ExecLifetimeTerminalReceiptV2:
    """Protected proof that an operation no longer has unowned background work."""

    request_ref: str
    lease_ref: str
    lease_generation: int
    outcome: Literal["verified_complete", "verified_absent"]
    completion_qualification_ref: str | None
    final_inventory_digest: str | None
    clock_epoch_ref: str
    observed_monotonic_ns: int
    background_work_absent: bool
    container_absent: bool
    receipt_ref: str

    def __post_init__(self) -> None:
        _digest(self.request_ref, "exec supervisor terminal request")
        _digest(self.lease_ref, "exec supervisor terminal lease")
        _digest(self.clock_epoch_ref, "exec supervisor terminal clock epoch")
        if type(self.lease_generation) is not int or not 1 <= self.lease_generation < 2**63:
            raise EngineExecOperationSupervisorError("exec supervisor terminal generation is invalid")
        if type(self.observed_monotonic_ns) is not int or self.observed_monotonic_ns <= 0:
            raise EngineExecOperationSupervisorError(
                "exec supervisor terminal observation time is invalid"
            )
        if self.outcome not in {"verified_complete", "verified_absent"}:
            raise EngineExecOperationSupervisorError("exec supervisor terminal outcome is invalid")
        if self.background_work_absent is not True or type(self.container_absent) is not bool:
            raise EngineExecOperationSupervisorError("exec supervisor terminal proof is incomplete")
        if self.outcome == "verified_absent":
            if (
                self.container_absent is not True
                or self.completion_qualification_ref is not None
                or self.final_inventory_digest is None
            ):
                raise EngineExecOperationSupervisorError(
                    "exec supervisor absence proof is incomplete"
                )
            _digest(self.final_inventory_digest, "exec supervisor final inventory")
        else:
            if self.container_absent or self.completion_qualification_ref is None:
                raise EngineExecOperationSupervisorError(
                    "exec supervisor completion proof is unqualified"
                )
            _digest(
                self.completion_qualification_ref,
                "exec supervisor completion qualification",
            )
            if self.final_inventory_digest is not None:
                _digest(self.final_inventory_digest, "exec supervisor final inventory")
        _digest(self.receipt_ref, "exec supervisor terminal receipt")
        if self.receipt_ref != content_hash(self.document(include_ref=False)):
            raise EngineExecOperationSupervisorError("exec supervisor terminal receipt changed")

    @classmethod
    def create(
        cls,
        *,
        request_ref: str,
        lease_ref: str,
        lease_generation: int,
        outcome: Literal["verified_complete", "verified_absent"],
        completion_qualification_ref: str | None,
        final_inventory_digest: str | None,
        clock_epoch_ref: str,
        observed_monotonic_ns: int,
        background_work_absent: bool,
        container_absent: bool,
    ) -> ExecLifetimeTerminalReceiptV2:
        values = {
            "request_ref": request_ref,
            "lease_ref": lease_ref,
            "lease_generation": lease_generation,
            "outcome": outcome,
            "completion_qualification_ref": completion_qualification_ref,
            "final_inventory_digest": final_inventory_digest,
            "clock_epoch_ref": clock_epoch_ref,
            "observed_monotonic_ns": observed_monotonic_ns,
            "background_work_absent": background_work_absent,
            "container_absent": container_absent,
        }
        document = {
            "schema_version": "bluefire.exec-lifetime-terminal-receipt.v2",
            **values,
        }
        return cls(**values, receipt_ref=content_hash(document))

    def document(self, *, include_ref: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": "bluefire.exec-lifetime-terminal-receipt.v2",
            "request_ref": self.request_ref,
            "lease_ref": self.lease_ref,
            "lease_generation": self.lease_generation,
            "outcome": self.outcome,
            "completion_qualification_ref": self.completion_qualification_ref,
            "final_inventory_digest": self.final_inventory_digest,
            "clock_epoch_ref": self.clock_epoch_ref,
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "background_work_absent": self.background_work_absent,
            "container_absent": self.container_absent,
        }
        if include_ref:
            result["receipt_ref"] = self.receipt_ref
        return result


class ProtectedExecLifetimeSupervisorV2(Protocol):
    """Qualified external service; implementations must survive controller loss."""

    @property
    def cleanup_uncertain(self) -> bool: ...

    def activate_new(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2: ...

    def reopen_existing(
        self, binding: ExecLifetimeSupervisorBindingV2
    ) -> ExecLifetimeSupervisorActivationV2: ...

    def arm(self, request: ExecLifetimeOperationRequestV2) -> VerifiedExecLifetimeCustodyV2: ...

    def require_live(
        self, request: ExecLifetimeOperationRequestV2
    ) -> VerifiedExecLifetimeCustodyV2: ...

    def complete(
        self, request: ExecLifetimeOperationRequestV2
    ) -> ExecLifetimeTerminalReceiptV2: ...

    def terminate(
        self, request: ExecLifetimeOperationRequestV2, *, reason: str
    ) -> ExecLifetimeTerminalReceiptV2: ...

    def detach(self) -> None:
        """Drop this controller connection without disarming live leases."""
        ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _ActiveOperation:
    request: ExecLifetimeOperationRequestV2
    proof: VerifiedExecLifetimeCustodyV2


class ControllerOwnedExecOperationCustodyV2:
    """Concrete retained owner over a required protected external supervisor."""

    def __init__(
        self,
        *,
        binding: ExecLifetimeSupervisorBindingV2,
        supervisor: ProtectedExecLifetimeSupervisorV2,
        activation: ExecLifetimeSupervisorActivationV2,
        expected_action: Literal["activated", "reopened"],
        recovery: ExecLifetimeSupervisorRecoveryV2 | None,
        _token: object,
    ) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise EngineExecOperationSupervisorError(
                "exec supervisor owner must be opened through its protected backend"
            )
        if type(binding) is not ExecLifetimeSupervisorBindingV2:
            raise EngineExecOperationSupervisorError("exec supervisor binding is invalid")
        for method in (
            "activate_new",
            "reopen_existing",
            "arm",
            "require_live",
            "complete",
            "terminate",
            "detach",
            "close",
        ):
            if not callable(getattr(supervisor, method, None)):
                raise EngineExecOperationSupervisorError(
                    "protected exec supervisor backend is incomplete"
                )
        self._binding = binding
        self._supervisor = supervisor
        self._activation = activation
        self._lock = threading.RLock()
        self._active: dict[str, _ActiveOperation] = {}
        self._recovered_terminal_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...] = ()
        self._close_terminal_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...] = ()
        self._closed = False
        self._cleanup_uncertain = False
        self._validate_activation(expected_action, recovery)

    @classmethod
    def open(
        cls,
        *,
        binding: ExecLifetimeSupervisorBindingV2,
        supervisor: ProtectedExecLifetimeSupervisorV2,
    ) -> ControllerOwnedExecOperationCustodyV2:
        try:
            activation = supervisor.activate_new(binding)
            return cls(
                binding=binding,
                supervisor=supervisor,
                activation=activation,
                expected_action="activated",
                recovery=None,
                _token=_CONSTRUCTION_TOKEN,
            )
        except Exception as exc:
            cls._detach_after_failed_activation(supervisor, exc)
            raise

    @classmethod
    def reopen(
        cls,
        *,
        binding: ExecLifetimeSupervisorBindingV2,
        supervisor: ProtectedExecLifetimeSupervisorV2,
        recovery: ExecLifetimeSupervisorRecoveryV2,
    ) -> ControllerOwnedExecOperationCustodyV2:
        if type(recovery) is not ExecLifetimeSupervisorRecoveryV2:
            raise EngineExecOperationSupervisorError("exec supervisor recovery is unavailable")
        try:
            activation = supervisor.reopen_existing(binding)
            return cls(
                binding=binding,
                supervisor=supervisor,
                activation=activation,
                expected_action="reopened",
                recovery=recovery,
                _token=_CONSTRUCTION_TOKEN,
            )
        except Exception as exc:
            cls._detach_after_failed_activation(supervisor, exc)
            raise

    @property
    def activation_ref(self) -> str:
        return self._activation.activation_ref

    @property
    def recovery(self) -> ExecLifetimeSupervisorRecoveryV2:
        with self._lock:
            return ExecLifetimeSupervisorRecoveryV2(
                activation_ref=(
                    self._activation.activation_ref
                    if self._activation.action == "activated"
                    else self._activation.origin_activation_ref
                ),
                supervisor_instance_ref=self._activation.supervisor_instance_ref,
                supervisor_session_ref=self._activation.supervisor_session_ref,
                clock_epoch_ref=self._activation.clock_epoch_ref,
                operation_leases=tuple(
                    sorted(
                        (
                            active.request.request_ref,
                            operation_id,
                            active.proof.lease_ref,
                            active.proof.lease_generation,
                            active.request.operation_deadline_monotonic_ns,
                        )
                        for operation_id, active in self._active.items()
                    )
                ),
            )

    @property
    def recovered_terminal_receipts(self) -> tuple[ExecLifetimeTerminalReceiptV2, ...]:
        """Durable no-launch outcomes recovered from the external supervisor."""
        with self._lock:
            return self._recovered_terminal_receipts

    @property
    def close_terminal_receipts(self) -> tuple[ExecLifetimeTerminalReceiptV2, ...]:
        """Verified absence receipts produced while closing active operations.

        A failed close may retain a verified subset. Callers must still treat
        ``cleanup_uncertain`` as authoritative for the remaining operations.
        """
        with self._lock:
            return self._close_terminal_receipts

    @property
    def cleanup_uncertain(self) -> bool:
        with self._lock:
            try:
                backend_uncertain = self._supervisor.cleanup_uncertain
            except Exception:
                return True
            return self._cleanup_uncertain or type(backend_uncertain) is not bool or backend_uncertain

    def _validate_activation(
        self,
        expected_action: str,
        recovery: ExecLifetimeSupervisorRecoveryV2 | None,
    ) -> None:
        activation = self._activation
        binding = self._binding
        if (
            type(activation) is not ExecLifetimeSupervisorActivationV2
            or activation.action != expected_action
            or activation.binding_ref != binding.binding_ref
            or activation.controller_instance_ref != binding.controller_instance_ref
            or activation.supervisor_qualification_ref
            != binding.supervisor_qualification_ref
        ):
            raise EngineExecOperationSupervisorError("exec supervisor activation changed")
        if expected_action == "activated" and activation.active_leases:
            raise EngineExecOperationSupervisorError("new exec supervisor contains old leases")
        if expected_action == "activated" and activation.terminal_receipts:
            raise EngineExecOperationSupervisorError(
                "new exec supervisor contains historical terminal receipts"
            )
        if expected_action == "activated" and recovery is not None:
            raise EngineExecOperationSupervisorError("new exec supervisor has recovery authority")
        if expected_action == "reopened":
            if recovery is None:
                raise EngineExecOperationSupervisorError("exec supervisor recovery is unavailable")
            expected_leases = {
                operation_id: (request_ref, lease_ref, generation, deadline)
                for request_ref, operation_id, lease_ref, generation, deadline in recovery.operation_leases
            }
            observed_leases = {item.operation_id: item for item in activation.active_leases}
            terminals = {item.request_ref: item for item in activation.terminal_receipts}
            expected_requests = {item[0] for item in expected_leases.values()}
            live_requests = {
                self._request_from_proof(item).request_ref
                for item in observed_leases.values()
            }
            if (
                activation.origin_activation_ref != recovery.activation_ref
                or activation.supervisor_instance_ref != recovery.supervisor_instance_ref
                or activation.supervisor_session_ref != recovery.supervisor_session_ref
                or activation.clock_epoch_ref != recovery.clock_epoch_ref
                or set(observed_leases) - set(expected_leases)
                or set(terminals) - expected_requests
                or live_requests & set(terminals)
                or live_requests | set(terminals) != expected_requests
                or len(live_requests) + len(terminals) != len(expected_requests)
                or any(
                    self._request_from_proof(proof).request_ref
                    != expected_leases[operation_id][0]
                    or proof.lease_ref != expected_leases[operation_id][1]
                    or proof.lease_generation < expected_leases[operation_id][2]
                    or proof.operation_deadline_monotonic_ns
                    != expected_leases[operation_id][3]
                    for operation_id, proof in observed_leases.items()
                )
                or any(
                    terminal.lease_ref
                    != next(
                        lease_ref
                        for request_ref, lease_ref, _generation, _deadline in expected_leases.values()
                        if request_ref == terminal.request_ref
                    )
                    or terminal.lease_generation
                    < next(
                        generation
                        for request_ref, _lease_ref, generation, _deadline in expected_leases.values()
                        if request_ref == terminal.request_ref
                    )
                    or terminal.clock_epoch_ref != recovery.clock_epoch_ref
                    or (
                        terminal.outcome == "verified_complete"
                        and terminal.observed_monotonic_ns
                        >= next(
                            deadline
                            for request_ref, _lease_ref, _generation, deadline in expected_leases.values()
                            if request_ref == terminal.request_ref
                        )
                    )
                    for terminal in activation.terminal_receipts
                )
            ):
                raise EngineExecOperationSupervisorError(
                    "exec supervisor recovery identity changed"
                )
            self._recovered_terminal_receipts = activation.terminal_receipts
        for proof in activation.active_leases:
            self._validate_base_proof(proof)
            request = self._request_from_proof(proof)
            self._active[proof.operation_id] = _ActiveOperation(request, proof)

    @staticmethod
    def _detach_after_failed_activation(
        supervisor: ProtectedExecLifetimeSupervisorV2, original: Exception
    ) -> None:
        try:
            supervisor.detach()
        except Exception as detach_error:
            raise EngineExecOperationSupervisorError(
                "exec supervisor activation failed with uncertain detached custody"
            ) from detach_error

    def require_live(
        self,
        *,
        admission: DockerExecAdmissionV2,
        claim_ref: str,
        controller_fence: str,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
    ) -> VerifiedExecLifetimeCustodyV2:
        request = self._operation_request(
            admission=admission,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline_monotonic_ns,
        )
        with self._lock:
            self._require_open()
            if time.monotonic_ns() >= request.operation_deadline_monotonic_ns:
                self._expire(request)
                raise EngineExecOperationSupervisorError("exec supervisor deadline elapsed")
            previous = self._active.get(request.operation_id)
            if previous is not None and previous.request != request:
                self._fail_closed(previous.request, "operation_binding_changed")
                raise EngineExecOperationSupervisorError("exec supervisor operation changed")
            proof: VerifiedExecLifetimeCustodyV2 | None = None
            try:
                proof = (
                    self._supervisor.arm(request)
                    if previous is None
                    else self._supervisor.require_live(request)
                )
                self._validate_proof(request, proof, previous)
            except Exception as exc:
                self._fail_closed(request, "live_check_failed", candidate=proof)
                raise EngineExecOperationSupervisorError(
                    "protected exec supervisor live check failed"
                ) from exc
            if time.monotonic_ns() >= request.operation_deadline_monotonic_ns:
                self._fail_closed(request, "deadline_elapsed", candidate=proof)
                raise EngineExecOperationSupervisorError("exec supervisor deadline elapsed")
            self._active[request.operation_id] = _ActiveOperation(request, proof)
            return proof

    def settle_completed(
        self,
        admission: DockerExecAdmissionV2,
        *,
        claim_ref: str,
        controller_fence: str,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
    ) -> ExecLifetimeTerminalReceiptV2:
        request = self._operation_request(
            admission=admission,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline_monotonic_ns,
        )
        with self._lock:
            self._require_open()
            active = self._require_active(request)
            if time.monotonic_ns() >= request.operation_deadline_monotonic_ns:
                try:
                    receipt = self._supervisor.terminate(
                        request, reason="deadline_elapsed"
                    )
                    self._validate_terminal(active, receipt, require_absent=True)
                    self._active.pop(request.operation_id, None)
                except Exception as exc:
                    self._cleanup_uncertain = True
                    raise EngineExecOperationSupervisorError(
                        "exec supervisor deadline absence is unverified"
                    ) from exc
                raise EngineExecOperationSupervisorError("exec supervisor deadline elapsed")
            try:
                receipt = self._supervisor.complete(request)
                self._validate_terminal(active, receipt, require_absent=False)
            except Exception as exc:
                self._fail_closed(request, "completion_unverified")
                raise EngineExecOperationSupervisorError(
                    "exec supervisor completion is unverified"
                ) from exc
            if (
                receipt.observed_monotonic_ns
                >= request.operation_deadline_monotonic_ns
                or time.monotonic_ns() >= request.operation_deadline_monotonic_ns
            ):
                try:
                    absent = self._supervisor.terminate(
                        request, reason="deadline_elapsed_after_completion"
                    )
                    self._validate_terminal(active, absent, require_absent=True)
                    if (
                        absent.lease_generation < receipt.lease_generation
                        or absent.observed_monotonic_ns < receipt.observed_monotonic_ns
                    ):
                        raise EngineExecOperationSupervisorError(
                            "exec supervisor deadline absence is stale"
                        )
                except Exception as exc:
                    self._cleanup_uncertain = True
                    raise EngineExecOperationSupervisorError(
                        "exec supervisor post-completion deadline absence is unverified"
                    ) from exc
                self._active.pop(request.operation_id, None)
                raise EngineExecOperationSupervisorError("exec supervisor deadline elapsed")
            self._active.pop(request.operation_id, None)
            return receipt

    def cancel(
        self,
        admission: DockerExecAdmissionV2,
        *,
        claim_ref: str,
        controller_fence: str,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
        reason: str,
    ) -> ExecLifetimeTerminalReceiptV2:
        _match(reason, _REASON, "exec supervisor cancellation reason")
        request = self._operation_request(
            admission=admission,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline_monotonic_ns,
        )
        with self._lock:
            self._require_open()
            active = self._require_active(request)
            try:
                receipt = self._supervisor.terminate(request, reason=reason)
                self._validate_terminal(active, receipt, require_absent=True)
            except Exception as exc:
                self._cleanup_uncertain = True
                raise EngineExecOperationSupervisorError(
                    "exec supervisor cancellation absence is unverified"
                ) from exc
            self._active.pop(request.operation_id, None)
            return receipt

    def close(self) -> None:
        failures: list[Exception] = []
        with self._lock:
            if self._closed:
                if self._cleanup_uncertain:
                    raise EngineExecOperationSupervisorError(
                        "exec supervisor cleanup remains uncertain"
                    )
                return
            self._closed = True
            for operation_id, active in tuple(self._active.items()):
                try:
                    receipt = self._supervisor.terminate(
                        active.request, reason="controller_close"
                    )
                    self._validate_terminal(active, receipt, require_absent=True)
                    self._close_terminal_receipts += (receipt,)
                    self._active.pop(operation_id, None)
                except Exception as exc:
                    failures.append(exc)
            if failures or self._active:
                try:
                    self._supervisor.detach()
                except Exception as exc:
                    failures.append(exc)
            else:
                try:
                    self._supervisor.close()
                except Exception as exc:
                    failures.append(exc)
            try:
                backend_uncertain = self._supervisor.cleanup_uncertain
                if type(backend_uncertain) is not bool or backend_uncertain:
                    failures.append(
                        EngineExecOperationSupervisorError(
                            "protected exec supervisor reports uncertain cleanup"
                        )
                    )
            except Exception as exc:
                failures.append(exc)
            if failures or self._active:
                self._cleanup_uncertain = True
                raise EngineExecOperationSupervisorError(
                    "exec supervisor cleanup is unverified"
                ) from failures[0] if failures else None

    def _require_open(self) -> None:
        if self._closed or self.cleanup_uncertain:
            raise EngineExecOperationSupervisorError("exec supervisor owner is unavailable")

    def _operation_request(
        self,
        *,
        admission: object,
        claim_ref: str,
        controller_fence: str,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
    ) -> ExecLifetimeOperationRequestV2:
        binding = self._binding
        try:
            admission_digest = admission.admission_digest
            container_id = admission.container_id
            attempt_id = admission.profile.attempt_id
            operation_id = admission.request.operation_id
        except Exception as exc:
            raise EngineExecOperationSupervisorError("exec admission identity is unavailable") from exc
        if (
            claim_ref != binding.claim_ref
            or controller_fence != binding.controller_fence
            or custody_plan_digest != binding.custody_plan_digest
            or network_policy_digest != binding.network_policy_digest
            or attempt_id != binding.attempt_id
        ):
            raise EngineExecOperationSupervisorError("exec supervisor authority binding changed")
        return ExecLifetimeOperationRequestV2(
            admission_digest=admission_digest,
            attempt_id=attempt_id,
            operation_id=operation_id,
            container_id=container_id,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline_monotonic_ns,
            controller_instance_ref=binding.controller_instance_ref,
            supervisor_instance_ref=self._activation.supervisor_instance_ref,
        )

    def _validate_base_proof(self, proof: VerifiedExecLifetimeCustodyV2) -> None:
        binding = self._binding
        activation = self._activation
        if (
            type(proof) is not VerifiedExecLifetimeCustodyV2
            or proof.attempt_id != binding.attempt_id
            or proof.claim_ref != binding.claim_ref
            or proof.controller_fence != binding.controller_fence
            or proof.custody_plan_digest != binding.custody_plan_digest
            or proof.network_policy_digest != binding.network_policy_digest
            or proof.controller_instance_ref != binding.controller_instance_ref
            or proof.supervisor_instance_ref != activation.supervisor_instance_ref
        ):
            raise EngineExecOperationSupervisorError("exec supervisor lease binding changed")

    def _validate_proof(
        self,
        request: ExecLifetimeOperationRequestV2,
        proof: VerifiedExecLifetimeCustodyV2,
        previous: _ActiveOperation | None,
    ) -> None:
        self._validate_base_proof(proof)
        for name in (
            "admission_digest",
            "attempt_id",
            "operation_id",
            "container_id",
            "claim_ref",
            "controller_fence",
            "custody_plan_digest",
            "network_policy_digest",
            "operation_deadline_monotonic_ns",
            "controller_instance_ref",
            "supervisor_instance_ref",
        ):
            if getattr(proof, name) != getattr(request, name):
                raise EngineExecOperationSupervisorError("exec supervisor live proof changed")
        if previous is not None and (
            proof.lease_ref != previous.proof.lease_ref
            or proof.lease_generation < previous.proof.lease_generation
        ):
            raise EngineExecOperationSupervisorError("exec supervisor lease regressed")

    def _request_from_proof(
        self, proof: VerifiedExecLifetimeCustodyV2
    ) -> ExecLifetimeOperationRequestV2:
        return ExecLifetimeOperationRequestV2(
            **{
                name: getattr(proof, name)
                for name in ExecLifetimeOperationRequestV2.__dataclass_fields__
            }
        )

    def _require_active(self, request: ExecLifetimeOperationRequestV2) -> _ActiveOperation:
        active = self._active.get(request.operation_id)
        if active is None or active.request != request:
            raise EngineExecOperationSupervisorError("exec supervisor operation is not active")
        return active

    def _validate_terminal(
        self,
        active: _ActiveOperation,
        receipt: ExecLifetimeTerminalReceiptV2,
        *,
        require_absent: bool,
    ) -> None:
        if (
            type(receipt) is not ExecLifetimeTerminalReceiptV2
            or receipt.request_ref != active.request.request_ref
            or receipt.lease_ref != active.proof.lease_ref
            or receipt.lease_generation < active.proof.lease_generation
            or receipt.clock_epoch_ref != self._activation.clock_epoch_ref
            or (require_absent and receipt.outcome != "verified_absent")
        ):
            raise EngineExecOperationSupervisorError("exec supervisor terminal proof changed")

    def _expire(self, request: ExecLifetimeOperationRequestV2) -> None:
        if request.operation_id in self._active:
            self._fail_closed(request, "deadline_elapsed")

    def _fail_closed(
        self,
        request: ExecLifetimeOperationRequestV2,
        reason: str,
        *,
        candidate: VerifiedExecLifetimeCustodyV2 | None = None,
    ) -> None:
        active = self._active.get(request.operation_id)
        if active is None:
            try:
                receipt = self._supervisor.terminate(request, reason=reason)
                if (
                    type(receipt) is not ExecLifetimeTerminalReceiptV2
                    or receipt.request_ref != request.request_ref
                    or receipt.outcome != "verified_absent"
                    or candidate is None
                    or receipt.lease_ref != candidate.lease_ref
                    or receipt.lease_generation < candidate.lease_generation
                ):
                    raise EngineExecOperationSupervisorError(
                        "exec supervisor absence proof changed"
                    )
            except Exception:
                self._cleanup_uncertain = True
            return
        try:
            receipt = self._supervisor.terminate(request, reason=reason)
            self._validate_terminal(active, receipt, require_absent=True)
            self._active.pop(request.operation_id, None)
        except Exception:
            self._cleanup_uncertain = True


__all__ = [
    "ControllerOwnedExecOperationCustodyV2",
    "EngineExecOperationSupervisorError",
    "ExecLifetimeOperationRequestV2",
    "ExecLifetimeSupervisorActivationV2",
    "ExecLifetimeSupervisorBindingV2",
    "ExecLifetimeSupervisorRecoveryV2",
    "ExecLifetimeTerminalReceiptV2",
    "ProtectedExecLifetimeSupervisorV2",
]
