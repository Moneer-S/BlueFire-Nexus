"""Pure Docker proxy custody state, audit contracts, and V2 transitions."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Callable, ContextManager, Protocol

from .engine_docker_control import DockerApiDecision, DockerApiOperation, DockerOwnership
from .engine_docker_exec_admission import DockerExecAdmissionV2, DockerExecBindingV2
from .engine_docker_exec_cancellation import DockerExecCancellationWatchV2
from .engine_docker_exec_dispatch import DockerExecCustodyUnavailable, DockerExecDispatchError
from .engine_docker_exec_signals import (
    DockerExecSignalUnavailable,
    read_cancelled,
    read_monotonic_ns,
)
from .util import content_hash, json_clone

_RESOURCE_ID = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUDIT_TEXT_LIMIT = 96


class DockerExecDispatchGate(Protocol):
    entered: bool
    sent: bool
    request_digest: str

    def before_send(self) -> ContextManager[None]: ...


def strict_cancelled(signal: Any) -> bool:
    return read_cancelled(signal)


def proxy_failure_status(*, timeout: bool, busy: bool) -> int:
    return 504 if timeout else 409 if busy else 503


def exec_watch_outcome(watch: DockerExecCancellationWatchV2 | None) -> str | None:
    if watch is None:
        return None
    receipt = watch.receipt
    if receipt is None and not watch.triggered:
        return None
    if receipt is not None and receipt.reason in {
        "cancelled",
        "deadline_exceeded",
        "cancellation_probe_failed",
        "clock_probe_failed",
        "watcher_timeout",
    }:
        return receipt.reason
    return "exec_custody_triggered"


class DockerProxyRefusal(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def require_operation_live(signal: Any, clock: Callable[[], int], deadline: int) -> None:
    if strict_cancelled(signal):
        raise DockerProxyRefusal("cancelled")
    # Time must be observed after any potentially slow cancellation source.
    if read_monotonic_ns(clock) >= deadline:
        raise DockerProxyRefusal("deadline_exceeded")


def exec_failure_outcome(
    error: Exception,
    *,
    response_received: bool = False,
    transport_entered: bool = False,
    default: str | None = None,
) -> str:
    if isinstance(error, DockerExecCustodyUnavailable):
        return "exec_custody_unavailable"
    if isinstance(error, DockerExecSignalUnavailable):
        return "exec_signal_unavailable"
    if isinstance(error, DockerExecDispatchError):
        return "exec_dispatch_refused"
    return default or (
        "response_refused"
        if response_received
        else ("transport_failed" if transport_entered else "protocol_refused")
    )


class EngineDockerProxyError(RuntimeError):
    """Raised for a malformed or unpublishable proxy exchange."""


def _safe_text(value: Any, label: str, *, maximum: int = _AUDIT_TEXT_LIMIT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise EngineDockerProxyError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    text = _safe_text(value, label, maximum=71)
    if _DIGEST.fullmatch(text) is None:
        raise EngineDockerProxyError(f"{label} is invalid")
    return text


@dataclass(frozen=True, slots=True)
class DockerProxyAuditRecord:
    schema_version: str
    request_ref: str
    sequence: int
    phase: str
    outcome: str
    operation: str
    policy_digest: str
    request_digest: str
    response_digest: str | None
    state_before_digest: str
    state_after_digest: str
    started_monotonic_ns: int
    ended_monotonic_ns: int
    reconciliation_required: bool

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.engine-docker-proxy-audit.v1":
            raise EngineDockerProxyError("Docker proxy audit schema is unsupported")
        _digest(self.request_ref, "Docker proxy request reference")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise EngineDockerProxyError("Docker proxy audit sequence is invalid")
        if self.phase not in {"refused", "validated", "published", "suppressed"}:
            raise EngineDockerProxyError("Docker proxy audit phase is invalid")
        if self.outcome not in {
            "accepted",
            "audit_failed",
            "busy",
            "cancelled",
            "deadline_exceeded",
            "policy_refused",
            "protocol_refused",
            "reconciliation_required",
            "response_refused",
            "transport_failed",
            "image_inspect_required",
            "exec_operation_replayed_or_unsettled",
            "exec_deadline_unavailable",
            "exec_runtime_unavailable",
            "exec_reservation_failed",
            "exec_dispatch_refused",
            "exec_custody_unavailable",
            "exec_custody_triggered",
            "exec_signal_unavailable",
            "cancellation_probe_failed",
            "clock_probe_failed",
            "watcher_timeout",
        }:
            raise EngineDockerProxyError("Docker proxy audit outcome is invalid")
        _safe_text(self.operation, "Docker proxy operation", maximum=64)
        _digest(self.policy_digest, "Docker proxy policy digest")
        _digest(self.request_digest, "Docker proxy request digest")
        if self.response_digest is not None:
            _digest(self.response_digest, "Docker proxy response digest")
        _digest(self.state_before_digest, "Docker proxy prior state")
        _digest(self.state_after_digest, "Docker proxy next state")
        for value, label in (
            (self.started_monotonic_ns, "Docker proxy start"),
            (self.ended_monotonic_ns, "Docker proxy end"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EngineDockerProxyError(f"{label} is invalid")
        if self.ended_monotonic_ns < self.started_monotonic_ns:
            raise EngineDockerProxyError("Docker proxy audit chronology is invalid")

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "request_ref": self.request_ref,
                    "sequence": self.sequence,
                    "phase": self.phase,
                    "outcome": self.outcome,
                    "operation": self.operation,
                    "policy_digest": self.policy_digest,
                    "request_digest": self.request_digest,
                    "response_digest": self.response_digest,
                    "state_before_digest": self.state_before_digest,
                    "state_after_digest": self.state_after_digest,
                    "started_monotonic_ns": self.started_monotonic_ns,
                    "ended_monotonic_ns": self.ended_monotonic_ns,
                    "reconciliation_required": self.reconciliation_required,
                }
            )
        )


@dataclass(frozen=True, slots=True)
class DockerProxyState:
    ownership: DockerOwnership
    quarantined_container_ids: tuple[str, ...]
    quarantined_exec_bindings: tuple[tuple[str, str], ...]
    generation: int
    reconciliation_required: bool
    v2_exec_bindings: tuple[DockerExecBindingV2, ...] = ()
    v2_exec_operation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.ownership, DockerOwnership):
            raise EngineDockerProxyError("Docker proxy ownership is invalid")
        if (
            not isinstance(self.v2_exec_operation_ids, tuple)
            or tuple(sorted(set(self.v2_exec_operation_ids))) != self.v2_exec_operation_ids
            or len(self.v2_exec_operation_ids) > 1024
            or any(
                re.fullmatch(r"operation-[0-9a-f]{32}", item) is None
                for item in self.v2_exec_operation_ids
            )
        ):
            raise EngineDockerProxyError("Docker V2 exec operation history is invalid")
        if (
            not isinstance(self.v2_exec_bindings, tuple)
            or tuple(sorted(self.v2_exec_bindings, key=lambda item: item.exec_id))
            != self.v2_exec_bindings
            or len({item.exec_id for item in self.v2_exec_bindings}) != len(self.v2_exec_bindings)
            or len({item.admission.request.operation_id for item in self.v2_exec_bindings})
            != len(self.v2_exec_bindings)
            or any(
                type(item) is not DockerExecBindingV2
                or self.ownership.exec_container(item.exec_id) != item.admission.container_id
                for item in self.v2_exec_bindings
            )
        ):
            raise EngineDockerProxyError("Docker V2 exec custody bindings are invalid")
        for values, label in (
            (self.quarantined_container_ids, "Docker quarantined container"),
            (tuple(item[0] for item in self.quarantined_exec_bindings), "Docker quarantined exec"),
        ):
            if tuple(sorted(set(values))) != values or any(
                not isinstance(item, str) or _RESOURCE_ID.fullmatch(item) is None for item in values
            ):
                raise EngineDockerProxyError(f"{label} identity is invalid")
        if tuple(sorted(self.quarantined_exec_bindings)) != self.quarantined_exec_bindings:
            raise EngineDockerProxyError("Docker quarantined exec bindings are not canonical")
        for _exec_id, container_id in self.quarantined_exec_bindings:
            if _RESOURCE_ID.fullmatch(container_id) is None:
                raise EngineDockerProxyError("Docker quarantined exec owner is invalid")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 0
        ):
            raise EngineDockerProxyError("Docker proxy generation is invalid")

    @classmethod
    def create(cls, ownership: DockerOwnership) -> "DockerProxyState":
        return cls(
            ownership=ownership,
            quarantined_container_ids=(),
            quarantined_exec_bindings=(),
            generation=0,
            reconciliation_required=False,
        )

    def to_dict(self) -> dict[str, Any]:
        row = dict(
            json_clone(
                {
                    "daemon_instance_digest": self.ownership.daemon_instance_digest,
                    "pending_container_ids": list(self.ownership.pending_container_ids),
                    "container_ids": list(self.ownership.container_ids),
                    "exec_bindings": [list(item) for item in self.ownership.exec_bindings],
                    "quarantined_container_ids": list(self.quarantined_container_ids),
                    "quarantined_exec_bindings": [
                        list(item) for item in self.quarantined_exec_bindings
                    ],
                    "generation": self.generation,
                    "reconciliation_required": self.reconciliation_required,
                }
            )
        )
        if self.v2_exec_bindings:
            row["v2_exec_bindings"] = [item.to_dict() for item in self.v2_exec_bindings]
        if self.v2_exec_operation_ids:
            row["v2_exec_operation_ids"] = list(self.v2_exec_operation_ids)
        return row

    @property
    def state_digest(self) -> str:
        return content_hash(self.to_dict())


def _same_json_value_v2(actual: Any, expected: Any) -> bool:
    """Compare V2 inspect values recursively without Python's bool/int equality."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same_json_value_v2(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_json_value_v2(observed, value)
            for observed, value in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _ownership(
    state: DockerProxyState,
    *,
    pending: tuple[str, ...] | None = None,
    containers: tuple[str, ...] | None = None,
    exec_bindings: tuple[tuple[str, str], ...] | None = None,
) -> DockerOwnership:
    return DockerOwnership.create(
        daemon_instance_digest=state.ownership.daemon_instance_digest,
        pending_container_ids=(
            pending if pending is not None else state.ownership.pending_container_ids
        ),
        container_ids=containers if containers is not None else state.ownership.container_ids,
        exec_bindings=exec_bindings if exec_bindings is not None else state.ownership.exec_bindings,
    )


def quarantine_custody(
    before: DockerProxyState,
    *,
    discovered_container_id: str | None = None,
    discovered_exec: tuple[str, str] | None = None,
    decision: DockerApiDecision | None = None,
    known_binding: DockerExecBindingV2 | None = None,
    v2: bool = False,
) -> DockerProxyState:
    containers = set(before.quarantined_container_ids)
    execs = set(before.quarantined_exec_bindings)
    ownership = before.ownership
    if discovered_container_id is not None:
        containers.add(discovered_container_id)
        ownership = _ownership(
            before,
            pending=tuple(sorted({*ownership.pending_container_ids, discovered_container_id})),
        )
    if discovered_exec is not None:
        execs.add(discovered_exec)
    if known_binding is not None:
        containers.add(known_binding.admission.container_id)
        execs.add((known_binding.exec_id, known_binding.admission.container_id))
    if (
        v2
        and decision is not None
        and decision.operation
        in {
            DockerApiOperation.CONTAINER_EXEC_CREATE,
            DockerApiOperation.EXEC_START,
            DockerApiOperation.EXEC_INSPECT,
        }
        and decision.owner_container_id is not None
    ):
        containers.add(decision.owner_container_id)
        if (
            decision.operation is not DockerApiOperation.CONTAINER_EXEC_CREATE
            and decision.resource_id is not None
        ):
            execs.add((decision.resource_id, decision.owner_container_id))
    return replace(
        before,
        ownership=ownership,
        quarantined_container_ids=tuple(sorted(containers)),
        quarantined_exec_bindings=tuple(sorted(execs)),
        generation=before.generation + 1,
        reconciliation_required=True,
    )


def quarantine_admission(
    before: DockerProxyState, admission: DockerExecAdmissionV2
) -> DockerProxyState:
    if not before.ownership.owns_container(admission.container_id):
        raise EngineDockerProxyError("exec cancellation does not own this container")
    binding = next(
        (
            item
            for item in before.v2_exec_bindings
            if item.admission.admission_digest == admission.admission_digest
        ),
        None,
    )
    state = quarantine_custody(before, known_binding=binding, v2=True)
    return replace(
        state,
        quarantined_container_ids=tuple(
            sorted({*state.quarantined_container_ids, admission.container_id})
        ),
    )


def quarantine_exchange(
    before: DockerProxyState,
    validated: Any,
    candidate_container: str | None,
    candidate_exec: tuple[str, str] | None,
    decision: DockerApiDecision | None,
    known_binding: DockerExecBindingV2 | None,
    *,
    v2: bool,
) -> DockerProxyState:
    return quarantine_custody(
        before,
        discovered_container_id=(
            validated.discovered_container_id
            if validated is not None and validated.discovered_container_id is not None
            else candidate_container
        ),
        discovered_exec=(
            validated.discovered_exec
            if validated is not None and validated.discovered_exec is not None
            else candidate_exec
        ),
        decision=decision,
        known_binding=known_binding,
        v2=v2,
    )


def require_exec_custody(policy: Any, runtime: Any, lane: Any) -> None:
    if runtime is None or lane is None:
        raise EngineDockerProxyError("exec custody is unavailable")
    lane.require_binding(
        authority=runtime.authority,
        custody_plan_digest=policy.custody_plan_digest,
        network_policy_digest=policy.network_policy_digest,
        authority_ref=runtime.authority.authority_ref,
        claim_ref=runtime.authority.claim_ref,
        controller_fence=runtime.authority.controller_fence,
    )


def register_v2_exec(
    state: DockerProxyState, exec_id: str, admission: DockerExecAdmissionV2, deadline: int | None
) -> tuple[DockerExecBindingV2, ...]:
    return tuple(
        sorted(
            (
                *state.v2_exec_bindings,
                DockerExecBindingV2(exec_id, admission, deadline_monotonic_ns=deadline),
            ),
            key=lambda item: item.exec_id,
        )
    )


def start_v2_exec(state: DockerProxyState, exec_id: str | None) -> tuple[DockerExecBindingV2, ...]:
    return tuple(
        replace(item, phase="started") if item.exec_id == exec_id else item
        for item in state.v2_exec_bindings
    )


def transition_custody(
    before: DockerProxyState,
    ownership: DockerOwnership,
    bindings: tuple[DockerExecBindingV2, ...] | None,
    admission: DockerExecAdmissionV2 | None,
    operation: DockerApiOperation,
) -> DockerProxyState:
    operations = before.v2_exec_operation_ids
    if admission is not None and operation is DockerApiOperation.CONTAINER_EXEC_CREATE:
        operations = tuple(sorted((*operations, admission.request.operation_id)))
    return replace(
        before,
        ownership=ownership,
        v2_exec_bindings=bindings if bindings is not None else before.v2_exec_bindings,
        v2_exec_operation_ids=operations,
        generation=before.generation + 1,
        reconciliation_required=False,
    )


def complete_v2_exec(
    state: DockerProxyState,
    exec_id: str | None,
    admission: DockerExecAdmissionV2 | None,
    row: Any,
    user: str,
) -> tuple[DockerExecBindingV2, ...]:
    binding = next((item for item in state.v2_exec_bindings if item.exec_id == exec_id), None)
    if binding is None or admission is None or binding.phase != "started":
        raise EngineDockerProxyError("Docker V2 exec inspection lacks a started operation")
    expected = {
        "arguments": list(admission.request.argv[1:]),
        "entrypoint": admission.request.argv[0],
        "privileged": False,
        "tty": False,
        "user": user,
    }
    if (
        not _same_json_value_v2(row.get("ProcessConfig"), expected)
        or row.get("OpenStdin") is not False
        or row.get("OpenStdout") is not True
        or row.get("OpenStderr") is not True
        or row.get("Running") is not False
        or type(row.get("ExitCode")) is not int
        or not 0 <= row["ExitCode"] <= 255
    ):
        raise EngineDockerProxyError("Docker V2 exec inspection differs or is still running")
    return tuple(
        replace(item, phase="complete") if item.exec_id == exec_id else item
        for item in state.v2_exec_bindings
    )


def make_proxy_audit_record(
    *,
    policy_digest: str,
    request_ref: str,
    sequence: int,
    phase: str,
    outcome: str,
    operation: str,
    request_digest: str,
    response_digest: str | None,
    before: DockerProxyState,
    after: DockerProxyState,
    started: int,
    ended: int,
) -> DockerProxyAuditRecord:
    return DockerProxyAuditRecord(
        schema_version="bluefire.engine-docker-proxy-audit.v1",
        request_ref=request_ref,
        sequence=sequence,
        phase=phase,
        outcome=outcome,
        operation=operation,
        policy_digest=policy_digest,
        request_digest=request_digest,
        response_digest=response_digest,
        state_before_digest=before.state_digest,
        state_after_digest=after.state_digest,
        started_monotonic_ns=started,
        ended_monotonic_ns=ended,
        reconciliation_required=after.reconciliation_required,
    )
