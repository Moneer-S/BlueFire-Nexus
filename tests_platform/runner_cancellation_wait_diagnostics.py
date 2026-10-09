"""Finite cached phases for the deadline fixture's cancellation Future wait.

Wrappers delegate original calls and retain no arguments, results or exceptions.
Snapshots are concurrent observations, not a trace or proof of remote cleanup.
The reporter performs no health, network, store, Future, thread or process read.
"""

from __future__ import annotations

import json
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from bluefire.runner_transport_errors import (
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
)

_PHASES = ("worker", "execute", "cancel", "recover")
_STATES = frozenset({"absent", "entered", "returned", "raised"})
_REMOTE_STATES = frozenset(
    {
        "queued",
        "running",
        "cancelling",
        "completed",
        "cancelled",
        "timed_out",
        "failed",
        "recovery_required",
    }
)
_ERRORS = frozenset(
    {
        "none",
        "cancelled",
        "runner_timeout",
        "authentication",
        "connection",
        "future_timeout",
        "os_error",
        "other_exception",
        "unknown",
    }
)
_COUNT_LIMIT = 32
# state, entered, returned, raised, error category, allowlisted response state
_EMPTY_ENTRY = ("absent", 0, 0, 0, "none", "unknown")


def _choice(value: object, allowed: frozenset[str]) -> str:
    return value if type(value) is str and value in allowed else "unknown"


def _count(value: object) -> int:
    return min(_COUNT_LIMIT, max(0, value)) if type(value) is int else 0


def _quiet(callback: Callable[..., Any], *args: Any) -> None:
    try:
        callback(*args)
    except BaseException:
        pass


def _error_category(error: BaseException) -> str:
    for kind, label in (
        (RunnerTaskCancelled, "cancelled"),
        (RunnerTaskTimedOut, "runner_timeout"),
        (RunnerAuthenticationError, "authentication"),
        (RunnerConnectionError, "connection"),
        (FutureTimeoutError, "future_timeout"),
        (TimeoutError, "future_timeout"),
        (OSError, "os_error"),
    ):
        if isinstance(error, kind):
            return label
    return "other_exception"


class CancellationWaitRecorder:
    def __init__(self) -> None:
        self._phases: dict[str, tuple[str, int, int, int, str, str]] = {
            phase: _EMPTY_ENTRY for phase in _PHASES
        }

    def _entry(self, phase: str) -> tuple[str, int, int, int, str, str]:
        state, entered, returned, raised, error, response_state = self._phases[phase]
        return state, entered, returned, raised, error, response_state

    def _entered(self, phase: str) -> None:
        _state, entered, returned, raised, _error, _response_state = self._entry(phase)
        self._phases[phase] = (
            "entered",
            _count(entered + 1),
            returned,
            raised,
            "none",
            "unknown",
        )

    def _returned(self, phase: str, result: object) -> None:
        state, entered, returned, raised, error, response_state = self._entry(phase)
        if phase in {"cancel", "recover"} and type(result) is dict:
            response_state = _choice(result.get("state"), _REMOTE_STATES)
        else:
            response_state = "unknown"
        self._phases[phase] = (
            "returned",
            entered,
            _count(returned + 1),
            raised,
            "none" if state == "entered" else error,
            response_state,
        )

    def _raised(self, phase: str, error: BaseException) -> None:
        _state, entered, returned, raised, _error, _response_state = self._entry(phase)
        self._phases[phase] = (
            "raised",
            entered,
            returned,
            _count(raised + 1),
            _error_category(error),
            "unknown",
        )

    def wrap(self, phase: str, delegate: Callable[..., Any]) -> Callable[..., Any]:
        if phase not in _PHASES:
            raise ValueError("Unsupported diagnostic phase")

        def call(*args: Any, **kwargs: Any) -> Any:
            _quiet(self._entered, phase)
            try:
                result = delegate(*args, **kwargs)
            except BaseException as error:
                _quiet(self._raised, phase, error)
                raise
            _quiet(self._returned, phase, result)
            return result

        return call

    def snapshot(self) -> dict[str, Any]:
        phase_map = self._phases if type(self._phases) is dict else {}
        projected: dict[str, dict[str, str | int]] = {}
        for phase in _PHASES:
            entry = phase_map.get(phase)
            entry = entry if type(entry) is tuple and len(entry) == 6 else _EMPTY_ENTRY
            state, entered, returned, raised, error, response_state = entry
            projected[phase] = {
                "state": _choice(state, _STATES),
                "entered": _count(entered),
                "returned": _count(returned),
                "raised": _count(raised),
                "error": _choice(error, _ERRORS),
                "response_state": _choice(response_state, _REMOTE_STATES),
            }
        return {
            "schema_version": 1,
            "boundary": "cancellation_future_result",
            "snapshot": "best_effort_cached",
            "timeout_origin": "unknown",
            "phases": projected,
        }


@contextmanager
def cancellation_future_wait(node: Any, recorder: CancellationWaitRecorder) -> Iterator[None]:
    try:
        yield
    except FutureTimeoutError:
        try:
            node.add_report_section(
                "call",
                "Runner cancellation wait",
                json.dumps(recorder.snapshot(), sort_keys=True),
            )
        except BaseException:
            # The pytest sink appends in memory. Diagnostic failures must not
            # replace the timeout or bypass the caller's existing cleanup.
            pass
        raise
