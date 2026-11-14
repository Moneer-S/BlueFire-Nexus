"""Protected whole-operation custody contract for controlled Docker exec.

An exec attach exchange ending is not proof that work inside the sandbox ended:
the admitted command can close its descriptors while leaving other work behind.
This contract therefore describes a lease owned by a qualified supervisor that
is independent of an individual Docker HTTP exchange.  The supervisor must be
armed before the first effect, remain responsible through final settlement, and
stop the attempt-owned container on deadline, cancellation, or controller loss.

The value below is evidence returned by a protected live check.  Possessing or
deserializing it does not mint authority.  Dispatch must call the retained
``ExecOperationCustodyOwnerV2`` immediately before every effect and the owner
must authenticate freshness through its protected supervisor backend.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Protocol

from .util import content_hash

if TYPE_CHECKING:
    from .engine_docker_exec_admission import DockerExecAdmissionV2


class EngineExecOperationCustodyError(ValueError):
    """Whole-operation custody proof or binding is invalid."""


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")


def _matches(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class VerifiedExecLifetimeCustodyV2:
    """Fresh authenticated proof for one already-retained supervisor lease.

    ``lease_ref`` identifies the same durable lease for the entire operation.
    A protected backend may advance ``lease_generation`` when it authenticates
    a fresh heartbeat, but it may never change the controller, supervisor, or
    lease identity.  The concrete owner, rather than a caller or this value,
    enforces that monotonic relationship.
    """

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
    lease_ref: str
    lease_generation: int
    deadline_stop_enforced: bool = True
    controller_loss_stop_enforced: bool = True

    def __post_init__(self) -> None:
        if (
            not _matches(self.admission_digest, _DIGEST)
            or not _matches(self.attempt_id, _ATTEMPT)
            or not _matches(self.operation_id, _OPERATION)
            or not _matches(self.container_id, _CONTAINER)
        ):
            raise EngineExecOperationCustodyError("exec lifetime custody identity is invalid")
        for value in (
            self.claim_ref,
            self.controller_fence,
            self.custody_plan_digest,
            self.network_policy_digest,
            self.controller_instance_ref,
            self.supervisor_instance_ref,
            self.lease_ref,
        ):
            if not _matches(value, _DIGEST):
                raise EngineExecOperationCustodyError(
                    "exec lifetime custody protected reference is invalid"
                )
        if (
            type(self.operation_deadline_monotonic_ns) is not int
            or self.operation_deadline_monotonic_ns <= 0
            or type(self.lease_generation) is not int
            or not 1 <= self.lease_generation < 2**63
            or self.deadline_stop_enforced is not True
            or self.controller_loss_stop_enforced is not True
        ):
            raise EngineExecOperationCustodyError("exec lifetime custody enforcement is invalid")

    @property
    def proof_ref(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.verified-exec-lifetime-custody.v2",
                **asdict(self),
            }
        )


class ExecOperationCustodyOwnerV2(Protocol):
    """Retained protected owner; no effectful or permissive default exists."""

    def require_live(
        self,
        *,
        admission: DockerExecAdmissionV2,
        claim_ref: str,
        controller_fence: str,
        custody_plan_digest: str,
        network_policy_digest: str,
        operation_deadline_monotonic_ns: int,
    ) -> VerifiedExecLifetimeCustodyV2: ...


__all__ = [
    "EngineExecOperationCustodyError",
    "ExecOperationCustodyOwnerV2",
    "VerifiedExecLifetimeCustodyV2",
]
