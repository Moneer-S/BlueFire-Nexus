"""Send-time controller authority for a durably reserved V2 sandbox exec.

There is no default authority, fence, mapping or persistence. The transport must
enter ``gate.before_send()`` immediately around its first/only request write,
then release it before blocking on attached output. Closing attached I/O is not
process termination; cleanup has a separate non-launching authority scope.
"""

from __future__ import annotations

import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Generic, Iterator, Mapping, Protocol, TypeVar

from .engine_attempt_contract import EngineAttemptBinding
from .engine_delegation import EngineCapabilityDelegation
from .engine_docker_exec_admission import DockerExecAdmissionV2
from .engine_docker_exec_signals import read_cancelled, read_monotonic_ns
from .engine_exec_operation_custody import (
    ExecOperationCustodyOwnerV2,
    VerifiedExecLifetimeCustodyV2,
)
from .strix_controlled_backend import ControlledSandboxHandle
from .util import content_hash


class DockerExecDispatchError(RuntimeError):
    """One required live controller fact or durable reservation is unavailable."""


class DockerExecCustodyUnavailable(DockerExecDispatchError):
    """The continuous operation owner cannot establish exact live custody."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-f]{64}")


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DockerExecDispatchError("exec controller identity is invalid")
    return value


class ExecCancellation(Protocol):
    def is_cancelled(self) -> bool: ...


class AcceptedExecClaim(Protocol):
    @property
    def job_id(self) -> str: ...
    @property
    def preparation_ref(self) -> str: ...
    @property
    def binding_digest(self) -> str: ...
    @property
    def delegation_digest(self) -> str: ...
    @property
    def claim_ref(self) -> str: ...
    @property
    def runtime_resolution_ref(self) -> str: ...
    def validate(
        self, job_id: str, binding: EngineAttemptBinding, delegation: EngineCapabilityDelegation
    ) -> None: ...


_Claim = TypeVar("_Claim", bound=AcceptedExecClaim)
_ClaimContra = TypeVar("_ClaimContra", bound=AcceptedExecClaim, contravariant=True)


class CurrentAcceptedExecClaims(Protocol[_ClaimContra]):
    def require_current(
        self,
        *,
        accepted: _ClaimContra,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
    ) -> None: ...


class ControllerExecFence(Protocol):
    """Protected live job/fence authority shared with revocation and cancellation.

    Execution scope must hold the controller's current claim/fence and job
    authority across yield, including present-time expiry and job cancellation.
    Cleanup scope grants only owned-resource teardown, including after execution
    revocation. Neither scope may be reconstructed from worker-provided fields.
    """

    def hold_current(self, *, claim_ref: str, controller_fence: str) -> ContextManager[None]: ...
    def hold_cleanup(self, *, claim_ref: str, controller_fence: str) -> ContextManager[None]: ...


@dataclass(frozen=True, slots=True)
class ProtectedDockerExecHandleBindingV2:
    handle: ControlledSandboxHandle
    container_id: str
    policy_digest: str
    execution_identity_digest: str
    profile_digest: str
    claim_ref: str
    controller_fence: str

    def __post_init__(self) -> None:
        if (
            type(self.handle) is not ControlledSandboxHandle
            or _ID.fullmatch(self.container_id) is None
        ):
            raise DockerExecDispatchError("protected exec mapping is invalid")
        for value in (
            self.policy_digest,
            self.execution_identity_digest,
            self.profile_digest,
            self.claim_ref,
            self.controller_fence,
        ):
            _digest(value)

    def require(
        self, admission: DockerExecAdmissionV2, *, claim_ref: str, controller_fence: str
    ) -> None:
        candidate = admission.request.handle
        if (
            candidate != self.handle
            or candidate.opaque_ref is not self.handle.opaque_ref
            or admission.container_id != self.container_id
            or admission.policy_digest != self.policy_digest
            or admission.execution_identity_digest != self.execution_identity_digest
            or admission.profile.profile_digest != self.profile_digest
            or claim_ref != self.claim_ref
            or controller_fence != self.controller_fence
        ):
            raise DockerExecDispatchError("protected handle-to-container mapping differs")


class ProtectedDockerExecHandleMapV2:
    """Controller-retained original handles; revocation waits for a socket write."""

    def __init__(self, bindings: tuple[ProtectedDockerExecHandleBindingV2, ...]) -> None:
        if not isinstance(bindings, tuple) or any(
            type(item) is not ProtectedDockerExecHandleBindingV2 for item in bindings
        ):
            raise DockerExecDispatchError("protected exec mappings are unavailable")
        self._lock = threading.RLock()
        self._bindings = {
            (item.handle.attempt_id, item.handle.resource_id, item.handle.resource_digest): item
            for item in bindings
        }
        if len(self._bindings) != len(bindings):
            raise DockerExecDispatchError("protected exec mappings are not unique")
        self._execution_revoked: set[tuple[str, str, str]] = set()

    @contextmanager
    def hold_mapping(
        self,
        admission: DockerExecAdmissionV2,
        *,
        claim_ref: str,
        controller_fence: str,
        for_cleanup: bool = False,
    ) -> Iterator[None]:
        handle = admission.request.handle
        with self._lock:
            key = (handle.attempt_id, handle.resource_id, handle.resource_digest)
            retained = self._bindings.get(key)
            if retained is None:
                raise DockerExecDispatchError("protected exec handle was revoked")
            if not for_cleanup and key in self._execution_revoked:
                raise DockerExecDispatchError("protected exec handle was revoked")
            retained.require(admission, claim_ref=claim_ref, controller_fence=controller_fence)
            yield

    def revoke(self, handle: ControlledSandboxHandle) -> None:
        """Revoke execution while retaining exact teardown custody."""
        with self._lock:
            self._execution_revoked.add(
                (handle.attempt_id, handle.resource_id, handle.resource_digest)
            )


class ExecDispatchAuthorityV2(Protocol):
    @property
    def authority_ref(self) -> str: ...
    @property
    def claim_ref(self) -> str: ...
    @property
    def controller_fence(self) -> str: ...
    def execution_scope(self, admission: DockerExecAdmissionV2) -> ContextManager[None]: ...
    def cleanup_scope(self, admission: DockerExecAdmissionV2) -> ContextManager[None]: ...


class ControllerExecDispatchAuthorityV2(Generic[_Claim]):
    """Composition of existing accepted claim checks and protected live owners.

    Structural claim/currentness interfaces accept the existing application
    types without introducing an execution-to-application dependency. This class
    does not mint a fence or decide that a job is live; the mandatory protected
    fence provider must establish those facts for every socket write.
    """

    def __init__(
        self,
        *,
        accepted: _Claim,
        binding: EngineAttemptBinding,
        delegation: EngineCapabilityDelegation,
        accepted_jobs: CurrentAcceptedExecClaims[_Claim],
        controller_fence: str,
        fence: ControllerExecFence,
        protected_handles: ProtectedDockerExecHandleMapV2,
    ) -> None:
        if (
            accepted is None
            or accepted_jobs is None
            or fence is None
            or type(protected_handles) is not ProtectedDockerExecHandleMapV2
        ):
            raise DockerExecDispatchError("exec dispatch controller authority is unavailable")
        self._accepted = accepted
        self._binding = binding
        self._delegation = delegation
        self._accepted_jobs = accepted_jobs
        self._controller_fence = _digest(controller_fence)
        self._fence = fence
        self._handles = protected_handles
        self._validate_claim()
        self._authority_ref = self._identity_ref()

    def _identity_ref(self) -> str:
        accepted = self._accepted
        return content_hash(
            {
                "schema_version": "bluefire.engine-docker-exec-authority.v2",
                "job_id": accepted.job_id,
                "preparation_ref": accepted.preparation_ref,
                "binding_digest": accepted.binding_digest,
                "delegation_digest": accepted.delegation_digest,
                "claim_ref": accepted.claim_ref,
                "runtime_resolution_ref": accepted.runtime_resolution_ref,
                "controller_fence": self._controller_fence,
            }
        )

    def _validate_claim(self) -> None:
        checked = self._delegation.validate_attempt_binding(self._binding)
        self._accepted.validate(self._accepted.job_id, checked, self._delegation)
        _digest(self._accepted.claim_ref)
        if hasattr(self, "_authority_ref") and self._identity_ref() != self._authority_ref:
            raise DockerExecDispatchError("accepted exec claim identity changed")

    def _require_attempt(self, admission: DockerExecAdmissionV2) -> None:
        if (
            admission.profile.attempt_id != self._binding.attempt_id
            or self._binding.engine_id != "strix"
            or admission.profile.source_revision != self._binding.engine_revision
        ):
            raise DockerExecDispatchError("exec dispatch attempt differs from accepted claim")

    @property
    def authority_ref(self) -> str:
        return self._authority_ref

    @property
    def claim_ref(self) -> str:
        return self._accepted.claim_ref

    @property
    def controller_fence(self) -> str:
        return self._controller_fence

    @contextmanager
    def execution_scope(self, admission: DockerExecAdmissionV2) -> Iterator[None]:
        with self._fence.hold_current(
            claim_ref=self.claim_ref, controller_fence=self.controller_fence
        ):
            self._validate_claim()
            self._require_attempt(admission)
            self._accepted_jobs.require_current(
                accepted=self._accepted, binding=self._binding, delegation=self._delegation
            )
            with self._handles.hold_mapping(
                admission, claim_ref=self.claim_ref, controller_fence=self.controller_fence
            ):
                yield

    @contextmanager
    def target_activation_scope(
        self, *, attempt_id: str, target_scope_admission_ref: str
    ) -> Iterator[None]:
        """Pin the live accepted job for one owned target activation.

        The caller must also hold the ProductStore active execution lease and
        compare its observed activation target-scope ref with the admitted
        target policy before signaling the exact owned sidecar. This scope
        grants no general target request or Docker operation.
        """

        _digest(target_scope_admission_ref)
        with self._fence.hold_current(
            claim_ref=self.claim_ref, controller_fence=self.controller_fence
        ):
            self._validate_claim()
            if attempt_id != self._binding.attempt_id or self._binding.engine_id != "strix":
                raise DockerExecDispatchError(
                    "target activation attempt differs from accepted claim"
                )
            self._accepted_jobs.require_current(
                accepted=self._accepted,
                binding=self._binding,
                delegation=self._delegation,
            )
            yield

    @contextmanager
    def cleanup_scope(self, admission: DockerExecAdmissionV2) -> Iterator[None]:
        with self._fence.hold_cleanup(
            claim_ref=self.claim_ref, controller_fence=self.controller_fence
        ):
            self._validate_claim()
            self._require_attempt(admission)
            with self._handles.hold_mapping(
                admission,
                claim_ref=self.claim_ref,
                controller_fence=self.controller_fence,
                for_cleanup=True,
            ):
                yield


class ExecOperationJournalV2(Protocol):
    def claim_dispatch(
        self,
        *,
        admission: Mapping[str, Any],
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        authority_ref: str,
        exec_id: str | None = None,
    ) -> Mapping[str, Any]: ...
    def transition(
        self,
        *,
        admission: Mapping[str, Any],
        authority_ref: str,
        phase: str,
        exec_id: str | None = None,
    ) -> None: ...

    def hold_send(
        self,
        *,
        admission: Mapping[str, Any],
        operation: str,
        request_digest: str,
        authority_ref: str,
        reservation_ref: str,
    ) -> ContextManager[None]: ...


def _require_live_custody(
    owner: ExecOperationCustodyOwnerV2 | None,
    admission: DockerExecAdmissionV2,
    *,
    claim_ref: str,
    controller_fence: str,
    custody_plan_digest: str,
    network_policy_digest: str,
    operation_deadline_monotonic_ns: int,
    previous: VerifiedExecLifetimeCustodyV2 | None = None,
) -> VerifiedExecLifetimeCustodyV2:
    if owner is None:
        raise DockerExecCustodyUnavailable("continuous exec lifetime custody is unavailable")
    try:
        proof = owner.require_live(
            admission=admission,
            claim_ref=claim_ref,
            controller_fence=controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline_monotonic_ns,
        )
    except Exception as exc:
        raise DockerExecCustodyUnavailable(
            "continuous exec lifetime custody source is unavailable"
        ) from exc
    if type(proof) is not VerifiedExecLifetimeCustodyV2:
        raise DockerExecCustodyUnavailable("continuous exec lifetime custody proof is unavailable")
    # Shape validation cannot authenticate a supervisor. The explicitly wired
    # trusted owner authenticates fresh controller/supervisor/lease facts on
    # every call and retains the lease independently of these call scopes.
    text_fields = (
        "admission_digest",
        "attempt_id",
        "operation_id",
        "container_id",
        "claim_ref",
        "controller_fence",
        "custody_plan_digest",
        "network_policy_digest",
        "controller_instance_ref",
        "supervisor_instance_ref",
        "lease_ref",
    )
    try:
        values = {
            field: object.__getattribute__(proof, field)
            for field in (
                *text_fields,
                "operation_deadline_monotonic_ns",
                "lease_generation",
                "deadline_stop_enforced",
                "controller_loss_stop_enforced",
            )
        }
        if (
            any(type(values[field]) is not str for field in text_fields)
            or type(values["operation_deadline_monotonic_ns"]) is not int
            or type(values["lease_generation"]) is not int
            or values["deadline_stop_enforced"] is not True
            or values["controller_loss_stop_enforced"] is not True
        ):
            raise ValueError("invalid custody proof primitive types")
        proof = VerifiedExecLifetimeCustodyV2(**values)
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        raise DockerExecCustodyUnavailable(
            "continuous exec lifetime custody proof is invalid"
        ) from exc
    expected = {
        "admission_digest": admission.admission_digest,
        "attempt_id": admission.profile.attempt_id,
        "operation_id": admission.request.operation_id,
        "container_id": admission.container_id,
        "claim_ref": claim_ref,
        "controller_fence": controller_fence,
        "custody_plan_digest": custody_plan_digest,
        "network_policy_digest": network_policy_digest,
        "operation_deadline_monotonic_ns": operation_deadline_monotonic_ns,
    }
    if (
        any(getattr(proof, field) != value for field, value in expected.items())
        or proof.deadline_stop_enforced is not True
        or proof.controller_loss_stop_enforced is not True
    ):
        raise DockerExecCustodyUnavailable("continuous exec lifetime custody binding differs")
    if previous is not None and (
        proof.controller_instance_ref != previous.controller_instance_ref
        or proof.supervisor_instance_ref != previous.supervisor_instance_ref
        or proof.lease_ref != previous.lease_ref
        or proof.lease_generation < previous.lease_generation
    ):
        raise DockerExecCustodyUnavailable("continuous exec lifetime custody lease changed")
    return proof


class DockerExecSendGateV2:
    """A single-use write scope backed by an already committed reservation."""

    def __init__(
        self,
        *,
        admission: DockerExecAdmissionV2,
        authority: ExecDispatchAuthorityV2,
        journal: ExecOperationJournalV2,
        cancellation: ExecCancellation,
        monotonic_ns: Callable[[], int],
        deadline_ns: int,
        reservation_ref: str,
        request_digest: str,
        operation: str,
        continuous_custody: ExecOperationCustodyOwnerV2,
        custody_proof: VerifiedExecLifetimeCustodyV2,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
    ) -> None:
        self._admission, self._authority, self._journal = admission, authority, journal
        self._cancellation, self._clock, self._deadline = cancellation, monotonic_ns, deadline_ns
        self.reservation_ref = _digest(reservation_ref)
        self.request_digest = _digest(request_digest)
        self.operation = operation
        self.operation_id = admission.request.operation_id
        self.attempt_id = admission.profile.attempt_id
        self.container_id = admission.container_id
        self.policy_digest = admission.policy_digest
        self.claim_ref = authority.claim_ref
        self.controller_fence = authority.controller_fence
        self.admission_digest = admission.admission_digest
        self._continuous_custody = continuous_custody
        self._custody_proof = custody_proof
        self._custody_plan_digest = custody_plan_digest
        self._network_policy_digest = network_policy_digest
        self._operation_deadline = operation_deadline_monotonic_ns
        self.entered = False
        self.sent = False
        self._creator_pid = os.getpid()
        self._lock = threading.Lock()

    def _check(self) -> None:
        if read_cancelled(self._cancellation):
            raise DockerExecDispatchError("exec send was cancelled or cancellation is unavailable")
        now = read_monotonic_ns(self._clock)
        if now >= self._deadline:
            raise DockerExecDispatchError("exec send deadline expired or is unavailable")

    @contextmanager
    def before_send(self) -> Iterator[None]:
        # Inherited locks, SQLite handles and authority owners must never be
        # entered in a fork child, even to attempt an uncertainty transition.
        if os.getpid() != self._creator_pid:
            raise DockerExecDispatchError("exec send gate belongs to another process")
        with self._lock:
            if self.entered:
                raise DockerExecDispatchError("exec send reservation cannot be reused")
            self.entered = True
        try:
            with self._authority.execution_scope(self._admission):
                with self._journal.hold_send(
                    admission=self._admission.to_dict(),
                    operation=self.operation,
                    request_digest=self.request_digest,
                    authority_ref=self._authority.authority_ref,
                    reservation_ref=self.reservation_ref,
                ):
                    _require_live_custody(
                        self._continuous_custody,
                        self._admission,
                        claim_ref=self._authority.claim_ref,
                        controller_fence=self._authority.controller_fence,
                        custody_plan_digest=self._custody_plan_digest,
                        network_policy_digest=self._network_policy_digest,
                        operation_deadline_monotonic_ns=self._operation_deadline,
                        previous=self._custody_proof,
                    )
                    self._check()
                    yield
                    self._check()
            self.sent = True
        except BaseException:
            self._journal.transition(
                admission=self._admission.to_dict(),
                authority_ref=self._authority.authority_ref,
                phase="uncertain",
            )
            raise


class DockerExecDispatchRuntimeV2:
    def __init__(
        self,
        *,
        authority: ExecDispatchAuthorityV2,
        journal: ExecOperationJournalV2,
        monotonic_ns: Callable[[], int],
        continuous_custody: ExecOperationCustodyOwnerV2 | None = None,
    ) -> None:
        if authority is None or journal is None or not callable(monotonic_ns):
            raise DockerExecDispatchError("exec dispatch runtime is unavailable")
        _digest(authority.authority_ref)
        self._authority, self._journal, self._clock = authority, journal, monotonic_ns
        self._continuous_custody = continuous_custody

    @property
    def authority(self) -> ExecDispatchAuthorityV2:
        return self._authority

    @property
    def journal(self) -> ExecOperationJournalV2:
        return self._journal

    @property
    def continuous_custody(self) -> ExecOperationCustodyOwnerV2 | None:
        return self._continuous_custody

    def gate(
        self,
        admission: DockerExecAdmissionV2,
        *,
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        cancellation: ExecCancellation,
        custody_plan_digest: str,
        network_policy_digest: str,
        exec_id: str | None = None,
        operation_deadline_monotonic_ns: int | None = None,
    ) -> DockerExecSendGateV2:
        if self.continuous_custody is None:
            raise DockerExecCustodyUnavailable("continuous exec lifetime custody is unavailable")
        if type(admission) is not DockerExecAdmissionV2:
            raise DockerExecDispatchError("exec dispatch admission is unavailable")
        if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns <= 0:
            raise DockerExecDispatchError("exec dispatch route deadline is invalid")
        # Reserve before entering transport, including before connection setup.
        # If any later step is ambiguous, reconstruction sees a consumed record.
        operation_deadline = (
            deadline_monotonic_ns
            if operation_deadline_monotonic_ns is None
            else operation_deadline_monotonic_ns
        )
        _digest(custody_plan_digest)
        _digest(network_policy_digest)
        if type(operation_deadline) is not int or operation_deadline <= 0:
            raise DockerExecDispatchError("exec dispatch operation deadline is invalid")
        custody_proof = _require_live_custody(
            self.continuous_custody,
            admission,
            claim_ref=self.authority.claim_ref,
            controller_fence=self.authority.controller_fence,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline,
        )
        row = self.journal.claim_dispatch(
            admission=admission.to_dict(),
            operation=operation,
            request_digest=request_digest,
            deadline_monotonic_ns=operation_deadline,
            authority_ref=self.authority.authority_ref,
            exec_id=exec_id,
        )
        return DockerExecSendGateV2(
            admission=admission,
            authority=self.authority,
            journal=self.journal,
            cancellation=cancellation,
            monotonic_ns=self._clock,
            deadline_ns=min(deadline_monotonic_ns, operation_deadline),
            reservation_ref=row["reservation_ref"],
            request_digest=request_digest,
            operation=operation,
            continuous_custody=self.continuous_custody,
            custody_proof=custody_proof,
            custody_plan_digest=custody_plan_digest,
            network_policy_digest=network_policy_digest,
            operation_deadline_monotonic_ns=operation_deadline,
        )

    def _record(
        self, admission: DockerExecAdmissionV2, phase: str, exec_id: str | None = None
    ) -> None:
        self.journal.transition(
            admission=admission.to_dict(),
            authority_ref=self.authority.authority_ref,
            phase=phase,
            exec_id=exec_id,
        )

    def record_created(self, admission: DockerExecAdmissionV2, exec_id: str) -> None:
        self._record(admission, "created", exec_id)

    def record_started(self, admission: DockerExecAdmissionV2) -> None:
        self._record(admission, "started")

    def record_complete(self, admission: DockerExecAdmissionV2) -> None:
        self._record(admission, "complete")

    def mark_uncertain(self, admission: DockerExecAdmissionV2) -> None:
        self._record(admission, "uncertain")
