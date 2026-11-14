"""Bounded custody cancellation independent of a blocked Docker exec stream."""

from __future__ import annotations

import math
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any, Callable, ContextManager, Iterator, Literal, Protocol

from .engine_docker_exec_admission import DockerExecAdmissionV2
from .engine_docker_exec_signals import read_cancelled, read_monotonic_ns
from .engine_worker_runtime import (
    EngineResourceCustody,
    ResourceCustodySnapshot,
    ResourceCustodyState,
)
from .util import content_hash

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REASON = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_POLL_SECONDS = 0.01


class DockerExecCleanupAuthorityV2(Protocol):
    @property
    def authority_ref(self) -> str: ...

    @property
    def claim_ref(self) -> str: ...

    @property
    def controller_fence(self) -> str: ...

    def cleanup_scope(self, admission: DockerExecAdmissionV2) -> ContextManager[Any]: ...


class DockerExecCancellationSignal(Protocol):
    def is_cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class DockerExecCancellationAuditRecordV2:
    admission_digest: str
    attempt_id: str
    container_id: str
    operation_id: str
    custody_plan_digest: str
    network_policy_digest: str
    authority_ref: str
    claim_ref: str
    controller_fence: str
    reason: str
    phase: Literal["requested", "absence_verified", "unknown"]
    monotonic_ns: int | None
    issue: str | None = None
    stop_snapshot_digest: str | None = None
    inspect_snapshot_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-docker-exec-cancellation-audit.v2",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }


class DockerExecCancellationAuditSink(Protocol):
    def append(self, record: DockerExecCancellationAuditRecordV2) -> str: ...


@dataclass(frozen=True, slots=True)
class DockerExecCancellationReceiptV2:
    admission_digest: str
    attempt_id: str
    container_id: str
    operation_id: str
    custody_plan_digest: str
    network_policy_digest: str
    authority_ref: str
    claim_ref: str
    controller_fence: str
    reason: str
    verified_absent: bool
    audited: bool
    issue: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.engine-docker-exec-cancellation-receipt.v2",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }


@dataclass(slots=True)
class _Cleanup:
    deadline: float
    opaque_ref: object = field(repr=False)
    done: threading.Event = field(default_factory=threading.Event)
    receipt: DockerExecCancellationReceiptV2 | None = None


class DockerExecCancellationWatchV2:
    """One daemon monitor; a receipt exists only after uncertainty is triggered."""

    def __init__(self) -> None:
        self._receipt: DockerExecCancellationReceiptV2 | None = None
        self._receipt_lock = threading.Lock()
        self._close = threading.Event()
        self._triggered = threading.Event()
        self._control_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def receipt(self) -> DockerExecCancellationReceiptV2 | None:
        with self._receipt_lock:
            return self._receipt

    @property
    def triggered(self) -> bool:
        return self._triggered.is_set()

    def _publish(self, receipt: DockerExecCancellationReceiptV2) -> None:
        with self._receipt_lock:
            if self._receipt is None:
                self._receipt = receipt


class DockerExecCancellationLaneV2:
    """Stop exact owned resources without acquiring the exec proxy's lock.

    The authority retains the accepted claim and validates the handle mapping.
    Custody uses its own endpoint; no exec-kill or attached-stream operation is
    used. Both custody calls and their independent absence evidence are required.
    Unknown receipts are cached and cannot later turn into successful settlement.
    """

    def __init__(
        self,
        *,
        custody: EngineResourceCustody,
        authority: DockerExecCleanupAuthorityV2,
        custody_plan_digest: str,
        network_policy_digest: str,
        audit: DockerExecCancellationAuditSink,
        monotonic_ns: Callable[[], int],
        cleanup_timeout_seconds: float = 10.0,
    ) -> None:
        if (
            not isinstance(custody_plan_digest, str)
            or _DIGEST.fullmatch(custody_plan_digest) is None
            or not isinstance(network_policy_digest, str)
            or _DIGEST.fullmatch(network_policy_digest) is None
            or isinstance(cleanup_timeout_seconds, bool)
            or not isinstance(cleanup_timeout_seconds, (int, float))
            or not math.isfinite(cleanup_timeout_seconds)
            or not 0 < cleanup_timeout_seconds <= 10
        ):
            raise ValueError("Docker exec cancellation bindings or timeout are invalid")
        self._custody = custody
        self._authority = authority
        self._authority_ref = authority.authority_ref
        self._claim_ref = authority.claim_ref
        self._controller_fence = authority.controller_fence
        if any(
            not isinstance(value, str) or _DIGEST.fullmatch(value) is None
            for value in (self._authority_ref, self._claim_ref, self._controller_fence)
        ):
            raise ValueError("Docker exec cancellation authority bindings are invalid")
        self._custody_plan_digest = custody_plan_digest
        self._network_policy_digest = network_policy_digest
        self._audit = audit
        self._clock = monotonic_ns
        self._timeout = float(cleanup_timeout_seconds)
        self._lock = threading.Lock()
        self._cleanups: dict[tuple[str, int], _Cleanup] = {}

    def require_binding(
        self,
        *,
        authority: DockerExecCleanupAuthorityV2,
        custody_plan_digest: str,
        network_policy_digest: str,
        authority_ref: str,
        claim_ref: str,
        controller_fence: str,
    ) -> None:
        if (
            authority is not self._authority
            or custody_plan_digest != self._custody_plan_digest
            or network_policy_digest != self._network_policy_digest
            or authority_ref != self._authority_ref
            or claim_ref != self._claim_ref
            or controller_fence != self._controller_fence
            or self._authority.authority_ref != self._authority_ref
            or self._authority.claim_ref != self._claim_ref
            or self._authority.controller_fence != self._controller_fence
        ):
            raise ValueError("Docker exec cancellation lane binds another cleanup authority")

    def _now(self) -> int:
        return read_monotonic_ns(self._clock)

    def _time_or_none(self) -> int | None:
        try:
            return self._now()
        except Exception:
            return None

    def _receipt(
        self,
        admission: DockerExecAdmissionV2,
        reason: str,
        *,
        verified_absent: bool = False,
        audited: bool = False,
        issue: str | None = None,
    ) -> DockerExecCancellationReceiptV2:
        return DockerExecCancellationReceiptV2(
            admission.admission_digest,
            admission.profile.attempt_id,
            admission.container_id,
            admission.request.operation_id,
            self._custody_plan_digest,
            self._network_policy_digest,
            self._authority_ref,
            self._claim_ref,
            self._controller_fence,
            reason,
            verified_absent,
            audited,
            issue,
        )

    def _record(
        self,
        receipt: DockerExecCancellationReceiptV2,
        phase: Literal["requested", "absence_verified", "unknown"],
        stop_digest: str | None = None,
        inspect_digest: str | None = None,
    ) -> bool:
        record = DockerExecCancellationAuditRecordV2(
            **{
                key: value
                for key, value in receipt.to_dict().items()
                if key not in {"schema_version", "verified_absent", "audited"}
            },
            phase=phase,
            monotonic_ns=self._time_or_none(),
            stop_snapshot_digest=stop_digest,
            inspect_snapshot_digest=inspect_digest,
        )
        try:
            return self._audit.append(record) == content_hash(record.to_dict()) and (
                phase == "unknown" or record.monotonic_ns is not None
            )
        except Exception:
            return False

    def _finish(self, cleanup: _Cleanup, receipt: DockerExecCancellationReceiptV2) -> None:
        with self._lock:
            if cleanup.receipt is None:
                cleanup.receipt = receipt
                cleanup.done.set()

    @staticmethod
    def _absent(snapshot: Any) -> bool:
        return (
            type(snapshot) is ResourceCustodySnapshot
            and snapshot.state is ResourceCustodyState.VERIFIED_ABSENT
            and snapshot.resource_ids == ()
            and snapshot.issue is None
        )

    @staticmethod
    def _snapshot_digest(snapshot: Any) -> str | None:
        if type(snapshot) is not ResourceCustodySnapshot:
            return None
        try:
            return content_hash(snapshot.to_dict())
        except Exception:
            return None

    def _cleanup(self, admission: DockerExecAdmissionV2, reason: str, cleanup: _Cleanup) -> None:
        receipt = self._receipt(admission, reason)
        requested_done = threading.Event()
        requested_audited = [False]
        clock_observed = threading.Event()
        observed_clock: list[int | None] = [None]

        def audit_requested() -> None:
            observed_clock[0] = self._time_or_none()
            clock_observed.set()
            requested_audited[0] = self._record(receipt, "requested")
            requested_done.set()

        # A blocked or failed audit must never prevent owned-resource teardown.
        threading.Thread(
            target=audit_requested, name="docker-exec-cancel-audit", daemon=True
        ).start()
        clock_observed.wait(min(self._timeout / 4, max(0.0, cleanup.deadline - time.monotonic())))
        started = observed_clock[0] if clock_observed.is_set() else None
        issue = "clock_unavailable" if started is None else None
        stopped: Any = None
        inspected: Any = None
        try:
            self.require_binding(
                authority=self._authority,
                custody_plan_digest=self._custody_plan_digest,
                network_policy_digest=self._network_policy_digest,
                authority_ref=self._authority_ref,
                claim_ref=self._claim_ref,
                controller_fence=self._controller_fence,
            )
            with self._authority.cleanup_scope(admission):
                for index, method in enumerate((self._custody.stop_owned, self._custody.inspect)):
                    remaining = cleanup.deadline - time.monotonic()
                    if remaining <= 0:
                        issue = issue or "cleanup_timeout"
                        break
                    try:
                        value = method(
                            admission.profile.attempt_id,
                            custody_identity_digest=self._custody_plan_digest,
                            network_policy_digest=self._network_policy_digest,
                            timeout_seconds=remaining,
                        )
                        if index == 0:
                            stopped = value
                        else:
                            inspected = value
                    except Exception:
                        issue = issue or "custody_failed"
        except Exception:
            issue = issue or "cleanup_scope_failed"
        ended = self._time_or_none()
        if ended is None or started is None or ended < started:
            issue = issue or "clock_unavailable"
        elif ended - started >= int(self._timeout * 1_000_000_000):
            issue = issue or "cleanup_timeout"
        if time.monotonic() >= cleanup.deadline:
            issue = issue or "cleanup_timeout"
        if not self._absent(stopped) or not self._absent(inspected):
            issue = issue or "absence_unverified"
        requested_done.wait(max(0.0, cleanup.deadline - time.monotonic()))
        if time.monotonic() >= cleanup.deadline:
            issue = issue or "cleanup_timeout"
        if not requested_done.is_set() or not requested_audited[0]:
            issue = issue or "audit_failed"
        receipt = replace(receipt, verified_absent=issue is None, issue=issue)
        phase: Literal["absence_verified", "unknown"] = (
            "absence_verified" if issue is None else "unknown"
        )
        stop_digest = self._snapshot_digest(stopped)
        inspect_digest = self._snapshot_digest(inspected)
        audited = self._record(receipt, phase, stop_digest, inspect_digest) and requested_audited[0]
        audited_at = self._time_or_none()
        late_issue: str | None = None
        if audited_at is None or started is None or audited_at < started:
            late_issue = "clock_unavailable"
        elif (
            audited_at - started >= int(self._timeout * 1_000_000_000)
            or time.monotonic() >= cleanup.deadline
        ):
            late_issue = "cleanup_timeout"
        if late_issue is not None and receipt.verified_absent:
            receipt = replace(receipt, verified_absent=False, issue=late_issue)
            audited = self._record(receipt, "unknown", stop_digest, inspect_digest) and audited
        if not audited:
            receipt = replace(receipt, verified_absent=False, issue=issue or "audit_failed")
            if phase != "unknown":
                self._record(receipt, "unknown", stop_digest, inspect_digest)
        self._finish(cleanup, replace(receipt, audited=audited))

    def cancel(
        self, admission: DockerExecAdmissionV2, reason: str
    ) -> DockerExecCancellationReceiptV2:
        if (
            type(admission) is not DockerExecAdmissionV2
            or not isinstance(reason, str)
            or _REASON.fullmatch(reason) is None
        ):
            raise ValueError("Docker exec cancellation admission or reason is invalid")
        opaque_ref = admission.request.handle.opaque_ref
        key = (admission.admission_digest, id(opaque_ref))
        with self._lock:
            cleanup = self._cleanups.get(key)
            first = cleanup is None
            if cleanup is None:
                cleanup = _Cleanup(time.monotonic() + self._timeout, opaque_ref)
                self._cleanups[key] = cleanup
        if first:
            threading.Thread(
                target=self._cleanup,
                args=(admission, reason, cleanup),
                name="docker-exec-custody-cleanup",
                daemon=True,
            ).start()
        if not cleanup.done.wait(max(0.0, cleanup.deadline - time.monotonic())):
            unknown = self._receipt(admission, reason, issue="cleanup_timeout")
            self._finish(cleanup, unknown)
            threading.Thread(
                target=self._record,
                args=(unknown, "unknown"),
                name="docker-exec-cancel-timeout-audit",
                daemon=True,
            ).start()
        with self._lock:
            assert cleanup.receipt is not None
            return cleanup.receipt

    @contextmanager
    def watch(
        self,
        admission: DockerExecAdmissionV2,
        cancellation: DockerExecCancellationSignal,
        deadline_monotonic_ns: int,
        on_uncertain: Callable[[], None],
    ) -> Iterator[DockerExecCancellationWatchV2]:
        if (
            type(admission) is not DockerExecAdmissionV2
            or type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns < 0
        ):
            raise ValueError("Docker exec watcher deadline is invalid")
        watcher = DockerExecCancellationWatchV2()

        def monitor() -> None:
            while not watcher._close.is_set():
                reason: str | None = None
                try:
                    if read_cancelled(cancellation):
                        reason = "cancelled"
                except Exception:
                    reason = "cancellation_probe_failed"
                try:
                    if self._now() >= deadline_monotonic_ns:
                        reason = reason or "deadline_exceeded"
                except Exception:
                    reason = reason or "clock_probe_failed"
                if reason is not None:
                    with watcher._control_lock:
                        if watcher._close.is_set():
                            return
                        watcher._triggered.set()
                    callback_done = threading.Event()
                    callback_failed = [False]

                    def mark_uncertain(
                        done: threading.Event = callback_done,
                        failed: list[bool] = callback_failed,
                    ) -> None:
                        try:
                            on_uncertain()
                        except Exception:
                            failed[0] = True
                        finally:
                            done.set()

                    # Invoke quarantine first, but never let its lock dependency
                    # suppress independent custody teardown of a blocked attach.
                    threading.Thread(
                        target=mark_uncertain, name="docker-exec-mark-uncertain", daemon=True
                    ).start()
                    callback_done.wait(min(0.25, self._timeout / 4))
                    callback_ok = callback_done.is_set() and not callback_failed[0]
                    receipt = self.cancel(admission, reason)
                    if not callback_ok:
                        receipt = replace(
                            receipt,
                            verified_absent=False,
                            audited=False,
                            issue="uncertainty_callback_failed",
                        )
                    watcher._publish(receipt)
                    return
                watcher._close.wait(_POLL_SECONDS)

        watcher._thread = threading.Thread(
            target=monitor, name="docker-exec-cancel-watch", daemon=True
        )
        watcher._thread.start()
        try:
            yield watcher
        finally:
            with watcher._control_lock:
                watcher._close.set()
            watcher._thread.join(self._timeout)
            if watcher._thread.is_alive():
                with watcher._control_lock:
                    watcher._triggered.set()
                watcher._publish(
                    self._receipt(admission, "watcher_timeout", issue="cleanup_timeout")
                )
