"""Best-effort cached evidence for the broker-entry assertion in its test."""

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
_ERRORS = frozenset(
    {
        "none",
        "execution_callback_failed",
        "run_record_incomplete",
        "replay_record_incomplete",
        "run_cleanup_deferred",
        "replay_cleanup_deferred",
    }
)
_COUNT_LIMIT = 32


def _choice(value: object, allowed: frozenset[str]) -> str:
    return value if type(value) is str and value in allowed else "unknown"


def _count(value: object) -> int:
    return min(_COUNT_LIMIT, max(0, value)) if type(value) is int else 0


def _project(snapshot: object) -> tuple[str, str, str]:
    # Project only exact built-in dictionaries returned by the existing job
    # transition. Never inspect or retain request, result, or exception text.
    if type(snapshot) is not dict:
        return "unknown", "unknown", "unknown"
    state = _choice(snapshot.get("state"), _STATES)
    progress = snapshot.get("progress")
    phase = _choice(progress.get("phase"), _STATES) if type(progress) is dict else "unknown"
    if "error" not in snapshot:
        error_class = "unknown"
    else:
        error = snapshot.get("error")
        if error is None:
            error_class = "none"
        elif type(error) is dict:
            error_class = _choice(error.get("code"), _ERRORS)
        else:
            error_class = "unknown"
    return state, phase, error_class


def _quiet(callback: Callable[..., Any], *args: Any) -> None:
    try:
        callback(*args)
    except BaseException:
        # Diagnostic failures never replace application behavior.
        pass


class BrokerStartupRecorder:
    def __init__(self) -> None:
        self._submission_projection: tuple[str, str, str] | None = None
        self._transition_projection: tuple[str, str, str] | None = None
        self.transitions_seen = 0

    def _record_transition(self, result: object) -> None:
        projection = _project(result)
        self.transitions_seen = _count(self.transitions_seen + 1)
        # Assign a single immutable tuple, so a concurrent snapshot cannot mix
        # state, phase, and error classifications from different transitions.
        self._transition_projection = projection

    def _project_submission(self, result: object) -> tuple[str, str, str]:
        return _project(result)

    def _record_submission(self, result: object) -> None:
        self._submission_projection = self._project_submission(result)

    def record_submission(self, result: object) -> None:
        # Keep this separate from worker transitions: a late submit response
        # must not overwrite a transition that raced the caller.
        _quiet(self._record_submission, result)

    def wrap_transition(self, delegate: Callable[..., Any]) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            result = delegate(*args, **kwargs)
            _quiet(self._record_transition, result)
            return result

        return call

    def snapshot(self, broker_request_count: object) -> dict[str, str | int]:
        # Prefer one complete transition tuple if already observed. This is
        # explicitly best-effort across threads; no app/store lock is acquired.
        projection = self._transition_projection or self._submission_projection
        job_state, job_phase, error_class = projection or ("unknown", "unknown", "unknown")
        request_count = _count(broker_request_count)
        return {
            "schema_version": 1,
            "snapshot": "best_effort_cached",
            "job_state": _choice(job_state, _STATES),
            "job_phase": _choice(job_phase, _STATES),
            "error_class": _choice(error_class, _ERRORS),
            "transitions_seen": _count(self.transitions_seen),
            "broker_phase": "request_seen" if request_count else "no_request_seen",
            "broker_request_count": request_count,
        }


@contextmanager
def broker_startup_assertion(
    node: Any, recorder: BrokerStartupRecorder, channel: Any
) -> Iterator[None]:
    try:
        yield
    except AssertionError:
        try:
            # Read only the existing list length. Do not poll the job store,
            # inspect request data, or query the event (which takes its lock).
            report = recorder.snapshot(len(channel.requests))
            node.add_report_section(
                "call", "Broker job startup", json.dumps(report, sort_keys=True)
            )
        except BaseException:
            pass
        raise
