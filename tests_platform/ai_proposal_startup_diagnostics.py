"""Best-effort cached evidence for the proposal test's existing readiness assertion.

No process, store, transport or lock is queried while reporting. ``launched``
means only that the existing Popen wrapper returned, not that HTTP was reached.
The independent counters are a concurrent snapshot, not a causal trace.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
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


def _choice(value: object, choices: frozenset[str]) -> str:
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
