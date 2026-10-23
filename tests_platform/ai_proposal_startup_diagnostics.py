"""Best-effort cached evidence for proposal readiness and process-loss tests.

No process, store, transport or lock is queried while reporting. ``launched``
means only that the existing Popen wrapper returned, not that HTTP was reached.
The independent counters are a concurrent snapshot, not a causal trace.
Child phase records are bounded captured output, not a process liveness claim.
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from subprocess import TimeoutExpired
from typing import Any, Callable, Iterator

_STATES = frozenset(
    {
        "queued",
        "planning",
        "awaiting_approval",
        "running",
        "paused",
        "cancelling",
        "cancelled",
        "completed",
        "failed",
        "interrupted",
    }
)
_LAUNCH_STATES = frozenset({"absent", "attempting", "launched", "failed"})
_FAILURES = frozenset({"none", "os_error", "assertion_error", "other_exception"})
_COUNT_LIMIT = 32
_PROCESS_PREFIX = "BlueFire proposal phase: "
_PROCESS_PHASES = frozenset(
    {
        "child_started",
        "imports_complete",
        "service_initializing",
        "service_ready",
        "authorizing",
        "authorized",
        "context_preparing",
        "context_ready",
        "submitting",
        "submitted",
        "waiting_parent",
        "parent_terminal",
        "parent_wait_timeout",
        "waiting_child",
        "child_terminal",
        "child_wait_timeout",
        "proposal_entered",
        "proposal_published",
        "crash_marker_saved",
    }
)


def _choice(value: object, choices: frozenset[str] | set[str]) -> str:
    return value if type(value) is str and value in choices else "unknown"


def _count(value: object) -> int:
    return min(_COUNT_LIMIT, max(0, value)) if type(value) is int else 0


def _quiet(callback: Callable[..., Any], *args: Any) -> None:
    try:
        callback(*args)
    except BaseException:
        # Instrumentation must not replace an operation's result or exception.
        pass


class ProposalStartupRecorder:
    def __init__(self) -> None:
        self.launch_state = "absent"
        self.launch_attempts = 0
        self.launch_returns = 0
        self.launch_failures = 0
        self.launch_failure_category = "none"
        self.job_state = "unknown"
        self.job_phase = "unknown"

    def _launch_entered(self) -> None:
        self.launch_attempts = min(_COUNT_LIMIT, self.launch_attempts + 1)
        self.launch_state = "attempting"

    def _launch_returned(self) -> None:
        self.launch_returns = min(_COUNT_LIMIT, self.launch_returns + 1)
        self.launch_state = "launched"

    def _launch_failed(self, error: BaseException) -> None:
        self.launch_failures = min(_COUNT_LIMIT, self.launch_failures + 1)
        self.launch_state = "failed"
        self.launch_failure_category = (
            "os_error"
            if isinstance(error, OSError)
            else "assertion_error" if isinstance(error, AssertionError) else "other_exception"
        )

    def _transition_returned(self, result: object) -> None:
        # Only project the result already returned by the real operation. Do not
        # call arbitrary mapping getters or inspect request/error/progress data.
        if type(result) is not dict:
            return
        self.job_state = _choice(result.get("state"), _STATES)
        progress = result.get("progress")
        self.job_phase = (
            _choice(progress.get("phase"), _STATES) if type(progress) is dict else "unknown"
        )

    def wrap_popen(self, delegate: Callable[..., Any]) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            _quiet(self._launch_entered)
            try:
                result = delegate(*args, **kwargs)
            except BaseException as error:
                _quiet(self._launch_failed, error)
                raise
            _quiet(self._launch_returned)
            return result

        return call

    def wrap_transition(self, delegate: Callable[..., Any]) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            result = delegate(*args, **kwargs)
            _quiet(self._transition_returned, result)
            return result

        return call

    def snapshot(self) -> dict[str, str | int]:
        return {
            "schema_version": 1,
            "snapshot": "best_effort_cached",
            "launch_state": _choice(self.launch_state, _LAUNCH_STATES),
            "launch_attempts": _count(self.launch_attempts),
            "launch_returns": _count(self.launch_returns),
            "launch_failures": _count(self.launch_failures),
            "launch_failure_category": _choice(self.launch_failure_category, _FAILURES),
            "job_state": _choice(self.job_state, _STATES),
            "job_phase": _choice(self.job_phase, _STATES),
        }


@contextmanager
def proposal_startup_assertion(node: Any, recorder: ProposalStartupRecorder) -> Iterator[None]:
    try:
        yield
    except AssertionError:
        try:
            node.add_report_section(
                "call", "AI proposal startup", json.dumps(recorder.snapshot(), sort_keys=True)
            )
        except BaseException:
            # Even a broken recorder/report sink must leave the original
            # assertion and the caller's existing finally cleanup in control.
            pass
        raise


def proposal_process_phase(phase: object, snapshot: object = None) -> None:
    """Emit only a phase and already-returned job state, never reread the store."""
    try:
        recorder = ProposalStartupRecorder()
        recorder._transition_returned(snapshot)
        cached = recorder.snapshot()
        payload = {
            "phase": _choice(phase, _PROCESS_PHASES),
            "job_state": cached["job_state"],
            "job_phase": cached["job_phase"],
        }
        sys.stderr.write(_PROCESS_PREFIX + json.dumps(payload, sort_keys=True) + "\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _captured_records(output: object, prefix: str, line_limit: int) -> Iterator[dict[str, Any]]:
    if type(output) is bytes:
        text = output[-16384:].decode("utf-8", errors="replace")
    elif type(output) is str:
        text = output[-16384:]
    else:
        text = ""
    for line in text.splitlines()[-32:]:
        if not line.startswith(prefix) or len(line) > line_limit:
            continue
        try:
            value = json.loads(line[len(prefix) :])
        except (ValueError, RecursionError):
            continue
        if type(value) is dict:
            yield value


def _wait_projection(value: dict[str, Any]) -> dict[str, Any]:
    # This imports product types only while projecting a captured wait record,
    # never before the child's first startup phase or while querying a store.
    from tests_platform import job_wait_diagnostics as wait

    job = value.get("last_wait_job")
    projected_job: dict[str, Any] = {"available": False}
    if type(job) is dict and job.get("available") is True:
        projected_job = {
            "available": True,
            "state": _choice(job.get("state"), wait.STATES),
            "phase": _choice(
                job.get("phase"), wait.STATES | {"materializing_checkpoint", "finalizing"}
            ),
            "error_code": _choice(job.get("error_code"), wait.ERROR_CODES),
            "error_type": _choice(job.get("error_type"), wait.ERROR_TYPES),
        }
        for flag in (
            "has_error",
            "has_result_ref",
            "has_plan_field",
            "has_children_field",
            "has_proposal_review_field",
        ):
            projected_job[flag] = job.get(flag) is True
    frames = value.get("process_thread_functions")
    frames = frames if type(frames) is list else []
    bounded = [frame for frame in frames[:8] if type(frame) is list]
    return {
        "stage": _choice(value.get("stage"), wait.STAGES),
        "last_wait_job": projected_job,
        "process_thread_functions": [
            [_choice(function, wait.FUNCTIONS) for function in frame[:24]] for frame in bounded
        ],
        "process_threads_truncated": (
            value.get("process_threads_truncated") is True
            or len(frames) > 8
            or any(len(frame) > 24 for frame in bounded)
        ),
    }


def _process_output_snapshot(stdout: object, stderr: object) -> dict[str, Any]:
    events = [
        {
            "phase": _choice(value.get("phase"), _PROCESS_PHASES),
            "job_state": _choice(value.get("job_state"), _STATES),
            "job_phase": _choice(value.get("job_phase"), _STATES),
        }
        for value in _captured_records(stderr, _PROCESS_PREFIX, 512)
    ]
    waits = list(_captured_records(stdout, "Job wait diagnostic: ", 8192))[-2:]
    return {
        "schema_version": 1,
        "snapshot": "best_effort_captured_child_phases",
        "events": events[-16:],
        "last_phase": events[-1]["phase"] if events else "unknown",
        "job_waits": [_wait_projection(value) for value in waits],
    }


def _process_timeout_snapshot(error: TimeoutExpired) -> dict[str, Any]:
    return _process_output_snapshot(error.output, error.stderr)


def proposal_process_diagnostic(stdout: object, stderr: object) -> str:
    """Use the same safe projection for an unexpected child exit, without raw output."""
    try:
        return json.dumps(_process_output_snapshot(stdout, stderr), sort_keys=True)
    except BaseException:
        return '{"schema_version": 1, "snapshot": "unavailable"}'


@contextmanager
def proposal_process_timeout(node: Any) -> Iterator[None]:
    try:
        yield
    except TimeoutExpired as error:
        try:
            node.add_report_section(
                "call",
                "AI proposal process timeout",
                json.dumps(_process_timeout_snapshot(error), sort_keys=True),
            )
        except BaseException:
            pass
        raise
