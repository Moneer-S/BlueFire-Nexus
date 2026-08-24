"""Bounded, durable background execution for BlueFire run jobs.

The controller intentionally knows nothing about scenario execution, shells, or
runner transports.  A caller supplies a Python callback and the callback uses
``JobContext`` checkpoints to cooperate with pause and cancellation requests.
Lifecycle state is persisted through the small ``JobStore`` protocol, which is
implemented by :class:`bluefire.product_store.ProductStore`.

Python cannot safely stop an arbitrary thread.  Execution callbacks therefore
must checkpoint around bounded units of work and use ``cooperative_wait`` in
place of uninterruptible waits.  The default shutdown path requests
cancellation and joins every worker thread.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import Any, Callable, Iterable, Mapping, Protocol, Type


class JobState(str, Enum):
    """Durable background-job lifecycle states."""

    QUEUED = "queued"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


TERMINAL_JOB_STATES = frozenset(
    {JobState.CANCELLED, JobState.COMPLETED, JobState.FAILED, JobState.INTERRUPTED}
)


class JobStore(Protocol):
    """Persistence contract required by :class:`RunJobController`."""

    def create_job(self, kind: str, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def transition_job(
        self,
        job_id: str,
        state: str,
        *,
        progress: Mapping[str, Any] | None = None,
        result_ref: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...

    def get_job(self, job_id: str) -> Mapping[str, Any]: ...

    def recover_interrupted_jobs(self) -> int: ...


class JobRuntimeError(RuntimeError):
    """Base error for invalid job-runtime operations."""


class JobRuntimeClosed(JobRuntimeError):
    """Raised when work is submitted after controller shutdown begins."""


class JobQueueFull(JobRuntimeError):
    """Raised when the bounded in-process job capacity is exhausted."""


class JobStateError(JobRuntimeError):
    """Raised when a cooperative signal is invalid for the current state."""


class JobNotManaged(JobRuntimeError):
    """Raised when a persisted job has no callback in this process."""


class JobWaitTimeout(JobRuntimeError):
    """Raised when a caller's bounded wait expires."""


class JobCancelled(Exception):
    """Cooperative cancellation signal raised at a callback checkpoint."""


@dataclass(frozen=True, slots=True)
class JobResult:
    """Small, persistence-safe result returned by an execution callback."""

    result_ref: str | None = None
    progress: Mapping[str, Any] | None = None
    awaiting_approval: bool = False


ExecutionResult = JobResult | str | None
ExecutionCallback = Callable[["JobContext", Mapping[str, Any]], ExecutionResult]


@dataclass(slots=True)
class _JobControl:
    job_id: str
    request: Mapping[str, Any]
    callback: ExecutionCallback
    requires_approval: bool
    approval_granted: bool = False
    approval_rejected: bool = False
    pause_requested: bool = False
    cancel_requested: bool = False
    future: Future[None] | None = None
    slot_released: bool = False


class JobContext:
    """Cooperative control surface passed to an execution callback.

    ``checkpoint`` both publishes progress and observes pause/cancel signals.
    Long operations should be split into bounded units with a checkpoint
    between units.  ``cooperative_wait`` is useful when waiting for an external
    event because controller signals wake it immediately.
    """

    def __init__(self, controller: "RunJobController", control: _JobControl) -> None:
        self._controller = controller
        self._control = control

    @property
    def job_id(self) -> str:
        return self._control.job_id

    @property
    def cancellation_requested(self) -> bool:
        with self._controller._condition:
            return self._control.cancel_requested

    @property
    def pause_requested(self) -> bool:
        with self._controller._condition:
            return self._control.pause_requested

    def progress_snapshot(self) -> Mapping[str, Any]:
        """Return the latest persisted progress document."""

        snapshot = self._controller.snapshot(self.job_id)
        progress = snapshot.get("progress", {})
        return dict(progress) if isinstance(progress, Mapping) else {}

    def checkpoint(
        self,
        progress: Mapping[str, Any] | None = None,
        *,
        replace_progress: bool = False,
    ) -> None:
        """Persist progress, honor pause, or raise ``JobCancelled``.

        Progress updates merge with the existing document by default so phase
        and approval metadata are not lost.  Values are validated by the
        injected durable store.
        """

        self._controller._checkpoint(
            self._control,
            progress=progress,
            replace_progress=replace_progress,
        )

    def report_progress(
        self,
        progress: Mapping[str, Any],
        *,
        replace: bool = False,
    ) -> None:
        """Publish a progress snapshot and act as a cooperative checkpoint."""

        self.checkpoint(progress, replace_progress=replace)

    def cooperative_wait(self, timeout: float) -> None:
        """Wait for at most ``timeout`` seconds while remaining controllable."""

        if timeout < 0:
            raise ValueError("cooperative wait timeout cannot be negative")
        self._controller._cooperative_wait(self._control, timeout)


class RunJobController:
    """Execute durable run jobs with a bounded set of worker threads."""

    def __init__(
        self,
        store: JobStore,
        execution_callback: ExecutionCallback | None = None,
        *,
        max_workers: int = 2,
        max_pending_jobs: int | None = None,
        recover_on_start: bool = True,
        thread_name_prefix: str = "bluefire-job",
    ) -> None:
        if isinstance(max_workers, bool) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        capacity = max_workers * 2 if max_pending_jobs is None else max_pending_jobs
        if isinstance(capacity, bool) or capacity < max_workers:
            raise ValueError("max_pending_jobs must be at least max_workers")
        if not isinstance(thread_name_prefix, str) or not thread_name_prefix.strip():
            raise ValueError("thread_name_prefix is required")

        self._store = store
        self._default_callback = execution_callback
        self._condition = threading.Condition(threading.RLock())
        self._capacity = threading.BoundedSemaphore(capacity)
        self._controls: dict[str, _JobControl] = {}
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=thread_name_prefix.strip(),
        )
        self.recovered_jobs = store.recover_interrupted_jobs() if recover_on_start else 0

    def __enter__(self) -> "RunJobController":
        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.shutdown()

    @property
    def active_job_ids(self) -> tuple[str, ...]:
        with self._condition:
            return tuple(sorted(self._controls))

    def submit(
        self,
        kind: str,
        request: Mapping[str, Any],
        *,
        requires_approval: bool = False,
        callback: ExecutionCallback | None = None,
    ) -> Mapping[str, Any]:
        """Persist and enqueue one callback without exceeding queue capacity."""

        selected_callback = callback or self._default_callback
        if selected_callback is None:
            raise JobRuntimeError("an execution callback is required")
        if not isinstance(requires_approval, bool):
            raise ValueError("requires_approval must be boolean")

        with self._condition:
            if self._closed:
                raise JobRuntimeClosed("job controller is shutting down")
            if not self._capacity.acquire(blocking=False):
                raise JobQueueFull("background job capacity is exhausted")
            control: _JobControl | None = None
            try:
                snapshot = self._store.create_job(kind, request)
                job_id = _job_id(snapshot)
                stored_request = snapshot.get("request", request)
                if not isinstance(stored_request, Mapping):
                    raise JobRuntimeError("job store returned an invalid request document")
                control = _JobControl(
                    job_id=job_id,
                    request=stored_request,
                    callback=selected_callback,
                    requires_approval=requires_approval,
                )
                self._controls[job_id] = control
                future = self._executor.submit(self._run_job, control)
                control.future = future
                future.add_done_callback(lambda _future: self._release_control(control))
            except BaseException:
                if control is not None:
                    self._controls.pop(control.job_id, None)
                self._capacity.release()
                raise
            self._condition.notify_all()
            return snapshot

    def snapshot(self, job_id: str) -> Mapping[str, Any]:
        """Read a durable lifecycle and progress snapshot."""

        with self._condition:
            return self._store.get_job(job_id)

    def approve(self, job_id: str, *, approval_ref: str | None = None) -> Mapping[str, Any]:
        """Release a pre-execution approval gate after external validation.

        The controller does not mint or validate approvals.  Callers should
        validate a bound one-time approval first and may persist its non-secret
        identifier as ``approval_ref`` for audit correlation.
        """

        with self._condition:
            control = self._managed_control(job_id)
            state = self._state(self._store.get_job(job_id))
            if state is not JobState.AWAITING_APPROVAL:
                raise JobStateError(f"job cannot be approved from {state.value}")
            update: dict[str, Any] = {"phase": JobState.RUNNING.value}
            if approval_ref is not None:
                if not isinstance(approval_ref, str) or not approval_ref.strip():
                    raise ValueError("approval_ref must be a non-empty string")
                update["approval_ref"] = approval_ref.strip()
            snapshot = self._transition(
                job_id,
                JobState.RUNNING,
                progress=update,
                merge_progress=True,
            )
            control.approval_granted = True
            control.approval_rejected = False
            self._condition.notify_all()
            return snapshot

    def reject_approval(
        self,
        job_id: str,
        *,
        decision_ref: str,
    ) -> Mapping[str, Any]:
        """Resolve a callback-created review gate without running a continuation."""

        if not isinstance(decision_ref, str) or not decision_ref.strip():
            raise ValueError("decision_ref must be a non-empty string")
        with self._condition:
            control = self._managed_control(job_id)
            state = self._state(self._store.get_job(job_id))
            if state is not JobState.AWAITING_APPROVAL:
                raise JobStateError(f"job cannot reject approval from {state.value}")
            control.approval_rejected = True
            control.approval_granted = False
            snapshot = self._transition(
                job_id,
                JobState.AWAITING_APPROVAL,
                progress={
                    "phase": JobState.AWAITING_APPROVAL.value,
                    "proposal_decision": "rejected",
                    "proposal_decision_ref": decision_ref.strip(),
                },
                merge_progress=True,
            )
            self._condition.notify_all()
            return snapshot

    def pause(self, job_id: str) -> Mapping[str, Any]:
        """Request a pause; the callback acknowledges it at its next checkpoint."""

        with self._condition:
            control = self._managed_control(job_id)
            state = self._state(self._store.get_job(job_id))
            if state is not JobState.RUNNING:
                raise JobStateError(f"job cannot be paused from {state.value}")
            control.pause_requested = True
            self._condition.notify_all()
            return self._store.get_job(job_id)

    def resume(self, job_id: str) -> Mapping[str, Any]:
        """Clear a pause request and release a cooperatively paused callback."""

        with self._condition:
            control = self._managed_control(job_id)
            state = self._state(self._store.get_job(job_id))
            if state is JobState.RUNNING and control.pause_requested:
                control.pause_requested = False
                self._condition.notify_all()
                return self._store.get_job(job_id)
            if state is not JobState.PAUSED:
                raise JobStateError(f"job cannot be resumed from {state.value}")
            control.pause_requested = False
            snapshot = self._transition(
                job_id,
                JobState.RUNNING,
                progress={"phase": JobState.RUNNING.value},
                merge_progress=True,
            )
            self._condition.notify_all()
            return snapshot

    def cancel(self, job_id: str) -> Mapping[str, Any]:
        """Request cancellation and persist the strongest valid transition."""

        with self._condition:
            snapshot = self._store.get_job(job_id)
            state = self._state(snapshot)
            if state in TERMINAL_JOB_STATES:
                return snapshot
            control = self._controls.get(job_id)
            if control is None:
                raise JobNotManaged(
                    "persisted job has no execution callback in this process; "
                    "restart recovery must resolve it"
                )
            control.cancel_requested = True
            control.pause_requested = False
            if state in {
                JobState.QUEUED,
                JobState.PLANNING,
                JobState.AWAITING_APPROVAL,
            }:
                snapshot = self._transition(
                    job_id,
                    JobState.CANCELLED,
                    progress={"phase": JobState.CANCELLED.value},
                    merge_progress=True,
                )
                if control.future is not None:
                    control.future.cancel()
            elif state in {JobState.RUNNING, JobState.PAUSED}:
                snapshot = self._transition(
                    job_id,
                    JobState.CANCELLING,
                    progress={"phase": JobState.CANCELLING.value},
                    merge_progress=True,
                )
            self._condition.notify_all()
            return snapshot

    def wait_for_state(
        self,
        job_id: str,
        states: Iterable[JobState | str],
        *,
        timeout: float | None = None,
    ) -> Mapping[str, Any]:
        """Wait until durable state reaches one of ``states``."""

        desired = {_coerce_state(item) for item in states}
        if not desired:
            raise ValueError("at least one target state is required")
        if timeout is not None and timeout < 0:
            raise ValueError("wait timeout cannot be negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while True:
                snapshot = self._store.get_job(job_id)
                if self._state(snapshot) in desired:
                    return snapshot
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    names = ", ".join(sorted(state.value for state in desired))
                    raise JobWaitTimeout(f"job did not reach {names} before timeout")
                self._condition.wait(remaining)

    def wait(self, job_id: str, *, timeout: float | None = None) -> Mapping[str, Any]:
        """Wait for a terminal persisted job state."""

        return self.wait_for_state(job_id, TERMINAL_JOB_STATES, timeout=timeout)

    def shutdown(self, *, cancel_active: bool = True) -> None:
        """Stop accepting work, cooperatively cancel active jobs, and join threads."""

        with self._condition:
            first_shutdown = not self._closed
            self._closed = True
            active_ids = tuple(self._controls) if first_shutdown and cancel_active else ()
        for job_id in active_ids:
            try:
                self.cancel(job_id)
            except (JobNotManaged, JobStateError):
                # A completion race made the signal unnecessary.
                pass
        self._executor.shutdown(wait=True, cancel_futures=cancel_active)
        with self._condition:
            self._condition.notify_all()

    def _run_job(self, control: _JobControl) -> None:
        try:
            with self._condition:
                state = self._state(self._store.get_job(control.job_id))
                if state is JobState.CANCELLED:
                    return
                self._transition(
                    control.job_id,
                    JobState.PLANNING,
                    progress={"phase": JobState.PLANNING.value},
                    merge_progress=True,
                )
                if control.cancel_requested:
                    self._finish_cancelled(control)
                    return
                if control.requires_approval:
                    self._transition(
                        control.job_id,
                        JobState.AWAITING_APPROVAL,
                        progress={"phase": JobState.AWAITING_APPROVAL.value},
                        merge_progress=True,
                    )
                    while not control.approval_granted and not control.cancel_requested:
                        self._condition.wait()
                    if control.cancel_requested:
                        self._finish_cancelled(control)
                        return
                    # ``approve`` persists awaiting_approval -> running.
                    control.approval_granted = False
                else:
                    self._transition(
                        control.job_id,
                        JobState.RUNNING,
                        progress={"phase": JobState.RUNNING.value},
                        merge_progress=True,
                    )
            context = JobContext(self, control)
            while True:
                result = control.callback(context, control.request)
                normalized = _normalise_result(result)
                # The callback-return boundary is also cooperative: a pause or
                # cancellation request that raced with return is honored before a
                # terminal state can be persisted.
                context.checkpoint(normalized.progress)
                with self._condition:
                    if control.cancel_requested:
                        self._finish_cancelled(control)
                        return
                    if not normalized.awaiting_approval:
                        self._transition(
                            control.job_id,
                            JobState.COMPLETED,
                            progress={"phase": JobState.COMPLETED.value},
                            merge_progress=True,
                            result_ref=normalized.result_ref,
                        )
                        return
                    control.approval_granted = False
                    control.approval_rejected = False
                    self._transition(
                        control.job_id,
                        JobState.AWAITING_APPROVAL,
                        progress={"phase": JobState.AWAITING_APPROVAL.value},
                        merge_progress=True,
                        result_ref=normalized.result_ref,
                    )
                    while not (
                        control.approval_granted
                        or control.approval_rejected
                        or control.cancel_requested
                    ):
                        self._condition.wait()
                    if control.cancel_requested:
                        self._finish_cancelled(control)
                        return
                    if control.approval_rejected:
                        self._transition(
                            control.job_id,
                            JobState.COMPLETED,
                            progress={"phase": JobState.COMPLETED.value},
                            merge_progress=True,
                            result_ref=normalized.result_ref,
                        )
                        return
                    # ``approve`` already persisted awaiting_approval -> running.
                    control.approval_granted = False
        except JobCancelled:
            with self._condition:
                self._finish_cancelled(control)
        except Exception as exc:
            with self._condition:
                self._finish_failed(control, exc)

    def _checkpoint(
        self,
        control: _JobControl,
        *,
        progress: Mapping[str, Any] | None,
        replace_progress: bool,
    ) -> None:
        with self._condition:
            if control.cancel_requested:
                raise JobCancelled("job cancellation requested")
            if progress is not None:
                state = self._state(self._store.get_job(control.job_id))
                self._transition(
                    control.job_id,
                    state,
                    progress=progress,
                    merge_progress=not replace_progress,
                )
            while control.pause_requested:
                if control.cancel_requested:
                    raise JobCancelled("job cancellation requested")
                state = self._state(self._store.get_job(control.job_id))
                if state is JobState.RUNNING:
                    self._transition(
                        control.job_id,
                        JobState.PAUSED,
                        progress={"phase": JobState.PAUSED.value},
                        merge_progress=True,
                    )
                self._condition.wait()
            if control.cancel_requested:
                raise JobCancelled("job cancellation requested")

    def _cooperative_wait(self, control: _JobControl, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                self._checkpoint(control, progress=None, replace_progress=False)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self._condition.wait(remaining)

    def _finish_cancelled(self, control: _JobControl) -> None:
        state = self._state(self._store.get_job(control.job_id))
        if state in TERMINAL_JOB_STATES:
            return
        if state in {JobState.RUNNING, JobState.PAUSED, JobState.INTERRUPTED}:
            self._transition(
                control.job_id,
                JobState.CANCELLING,
                progress={"phase": JobState.CANCELLING.value},
                merge_progress=True,
            )
            state = JobState.CANCELLING
        if state is JobState.CANCELLING:
            self._transition(
                control.job_id,
                JobState.CANCELLED,
                progress={"phase": JobState.CANCELLED.value},
                merge_progress=True,
            )
        elif state in {
            JobState.QUEUED,
            JobState.PLANNING,
            JobState.AWAITING_APPROVAL,
        }:
            self._transition(
                control.job_id,
                JobState.CANCELLED,
                progress={"phase": JobState.CANCELLED.value},
                merge_progress=True,
            )

    def _finish_failed(self, control: _JobControl, exc: Exception) -> None:
        state = self._state(self._store.get_job(control.job_id))
        if state in TERMINAL_JOB_STATES:
            return
        self._transition(
            control.job_id,
            JobState.FAILED,
            progress={"phase": JobState.FAILED.value},
            merge_progress=True,
            error={
                "code": "execution_callback_failed",
                "message": "execution callback failed",
                "exception_type": type(exc).__name__,
            },
        )

    def _transition(
        self,
        job_id: str,
        state: JobState,
        *,
        progress: Mapping[str, Any] | None = None,
        merge_progress: bool = False,
        result_ref: str | None = None,
        error: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        next_progress = progress
        if progress is not None and merge_progress:
            current = self._store.get_job(job_id).get("progress", {})
            merged = dict(current) if isinstance(current, Mapping) else {}
            merged.update(progress)
            next_progress = merged
        snapshot = self._store.transition_job(
            job_id,
            state.value,
            progress=next_progress,
            result_ref=result_ref,
            error=error,
        )
        self._condition.notify_all()
        return snapshot

    def _managed_control(self, job_id: str) -> _JobControl:
        control = self._controls.get(job_id)
        if control is None:
            raise JobNotManaged("job is not active in this controller")
        return control

    @staticmethod
    def _state(snapshot: Mapping[str, Any]) -> JobState:
        try:
            return JobState(str(snapshot["state"]))
        except (KeyError, ValueError) as exc:
            raise JobRuntimeError("job store returned an invalid lifecycle state") from exc

    def _release_control(self, control: _JobControl) -> None:
        with self._condition:
            if not control.slot_released:
                control.slot_released = True
                self._controls.pop(control.job_id, None)
                self._capacity.release()
            self._condition.notify_all()


def _job_id(snapshot: Mapping[str, Any]) -> str:
    value = snapshot.get("job_id")
    if not isinstance(value, str) or not value.strip():
        raise JobRuntimeError("job store returned an invalid job ID")
    return value


def _coerce_state(value: JobState | str) -> JobState:
    if isinstance(value, JobState):
        return value
    try:
        return JobState(value)
    except ValueError as exc:
        raise ValueError(f"unknown job state: {value}") from exc


def _normalise_result(value: ExecutionResult) -> JobResult:
    if value is None:
        return JobResult()
    if isinstance(value, JobResult):
        result = value
    elif isinstance(value, str):
        result = JobResult(result_ref=value)
    else:
        raise JobRuntimeError(
            "execution callback must return JobResult, a result reference, or None"
        )
    if result.result_ref is not None:
        if not result.result_ref.strip() or len(result.result_ref) > 2048:
            raise JobRuntimeError("result reference must be between 1 and 2048 characters")
        if any(character in result.result_ref for character in "\r\n\0"):
            raise JobRuntimeError("result reference contains an invalid control character")
    if not isinstance(result.awaiting_approval, bool):
        raise JobRuntimeError("awaiting_approval must be boolean")
    return result


__all__ = [
    "ExecutionCallback",
    "ExecutionResult",
    "JobCancelled",
    "JobContext",
    "JobNotManaged",
    "JobQueueFull",
    "JobResult",
    "JobRuntimeClosed",
    "JobRuntimeError",
    "JobState",
    "JobStateError",
    "JobStore",
    "JobWaitTimeout",
    "RunJobController",
    "TERMINAL_JOB_STATES",
]
