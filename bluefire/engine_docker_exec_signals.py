"""Bounded controller-only cancellation and monotonic-clock observations.

Prefer the sealed event token and the native monotonic clock. Generic sources
are activated only under a controller contract that they are read-only and
thread-safe: they execute on a daemon worker and may outlive the caller. A
timed-out observation never publishes a late result into controller state.
Hung callbacks retain their bounded worker slot until they actually return.
Clock sources must report the native monotonic-nanosecond epoch. Generic clock
comparisons use an upper estimate; budget creation uses a separate lower anchor.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Literal, final


class DockerExecSignalUnavailable(RuntimeError):
    """A controller observation did not complete with the exact required type."""


_MAX_PROBE_WORKERS = 32
_PROBE_TIMEOUT_SECONDS = 0.250
_PROBE_SLOTS = threading.BoundedSemaphore(_MAX_PROBE_WORKERS)
_Thread = threading.Thread
_Event = threading.Event
_EVENT_READ = threading.Event.is_set
_EVENT_CANCEL = threading.Event.set
_NATIVE_MONOTONIC_NS = time.monotonic_ns


def _after_fork_child() -> None:
    global _PROBE_SLOTS
    # No daemon observation survives fork, and no inherited semaphore lock is
    # safe to acquire in the child. The child gets its own bounded probe pool.
    _PROBE_SLOTS = threading.BoundedSemaphore(_MAX_PROBE_WORKERS)


_register_at_fork = getattr(os, "register_at_fork", None)
if callable(_register_at_fork):
    _register_at_fork(after_in_child=_after_fork_child)


@final
class ControllerExecCancellationV2:
    """Sealed controller-owned cancellation token with a nonblocking read."""

    __slots__ = ("__event",)

    def __init__(self) -> None:
        self.__event = _Event()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("controller exec cancellation token is sealed")

    def cancel(self) -> None:
        _EVENT_CANCEL(_token_event(self))

    def is_cancelled(self) -> bool:
        return _EVENT_READ(_token_event(self))


def _token_event(signal: ControllerExecCancellationV2) -> threading.Event:
    if type(signal) is not ControllerExecCancellationV2:
        raise DockerExecSignalUnavailable("controller cancellation token type differs")
    event = object.__getattribute__(signal, "_ControllerExecCancellationV2__event")
    if type(event) is not _Event:
        raise DockerExecSignalUnavailable("controller cancellation token was replaced")
    return event


def _probe(callback: Callable[[], Any], kind: Literal["cancel", "clock"]) -> bool | int:
    slots = _PROBE_SLOTS
    if not slots.acquire(blocking=False):
        raise DockerExecSignalUnavailable("controller signal probe capacity is exhausted")
    done = _Event()
    result: dict[str, bool | int] = {}

    def observe() -> None:
        try:
            value = callback()
            valid = type(value) is bool if kind == "cancel" else type(value) is int and value >= 0
            if valid:
                result["value"] = value
            # Wrong-type objects and their destructors stay on this worker.
            # Only exact bool/int values can ever reach the waiting caller.
            del value
        except BaseException:
            pass
        finally:
            done.set()
            slots.release()

    try:
        worker = _Thread(target=observe, name="bluefire-exec-signal", daemon=True)
    except BaseException as exc:
        slots.release()
        raise DockerExecSignalUnavailable("controller signal probe could not start") from exc
    try:
        worker.start()
    except BaseException as exc:
        # A start interrupted after native thread creation is ambiguous. Only
        # the worker may release this slot; a possibly running callback must
        # not silently make room for another unbounded worker.
        raise DockerExecSignalUnavailable("controller signal probe could not start") from exc
    if not done.wait(_PROBE_TIMEOUT_SECONDS):
        raise DockerExecSignalUnavailable("controller signal probe timed out")
    if "value" not in result:
        raise DockerExecSignalUnavailable(
            "controller signal probe failed or returned an invalid type"
        )
    return result["value"]


def read_cancelled(signal: Any) -> bool:
    """Read exact bool cancellation with a 250ms generic-source bound."""

    value: bool | int
    if type(signal) is ControllerExecCancellationV2:
        value = _EVENT_READ(_token_event(signal))
    else:
        # Resolve the method on the worker too: a descriptor can itself block.
        value = _probe(lambda: signal.is_cancelled(), "cancel")
    if type(value) is not bool:
        raise DockerExecSignalUnavailable("controller cancellation signal is not boolean")
    return value


def _native_monotonic_ns() -> int:
    native = _NATIVE_MONOTONIC_NS()
    if type(native) is not int or native < 0:
        raise DockerExecSignalUnavailable("controller monotonic signal is invalid")
    return native


def _generic_clock_sample(clock: Callable[[], Any]) -> tuple[int, int]:
    started = _native_monotonic_ns()
    value = _probe(clock, "clock")
    elapsed = _native_monotonic_ns() - started
    if type(value) is not int or value < 0:
        raise DockerExecSignalUnavailable("controller monotonic signal is invalid")
    if elapsed < 0:
        raise DockerExecSignalUnavailable("controller monotonic continuity is unavailable")
    return value, elapsed


def read_monotonic_ns(clock: Callable[[], Any]) -> int:
    """Read a bounded conservative upper estimate for deadline comparisons."""

    if clock is _NATIVE_MONOTONIC_NS:
        return _native_monotonic_ns()
    value, elapsed = _generic_clock_sample(clock)
    return value + elapsed


def read_monotonic_anchor_ns(clock: Callable[[], Any]) -> int:
    """Read a bounded lower anchor so observation latency cannot extend a budget."""

    if clock is _NATIVE_MONOTONIC_NS:
        return _native_monotonic_ns()
    value, elapsed = _generic_clock_sample(clock)
    return max(0, value - elapsed)
