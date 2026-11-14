"""No Docker: bounded read-only signal observations and gate uncertainty."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.engine_docker_exec_signals as signals
from bluefire.engine_docker_exec_dispatch import DockerExecDispatchError
from bluefire.engine_docker_exec_journal import DockerExecJournalError
from bluefire.engine_docker_exec_signals import (
    ControllerExecCancellationV2,
    DockerExecSignalUnavailable,
    read_cancelled,
    read_monotonic_anchor_ns,
    read_monotonic_ns,
)
from tests_platform.test_engine_docker_exec_dispatch import (
    CUSTODY_PLAN,
    NETWORK_POLICY,
    RAW,
    row,
    runtime,
)


def track_workers(monkeypatch: pytest.MonkeyPatch) -> list[threading.Thread]:
    workers: list[threading.Thread] = []
    original = signals._Thread

    def make_worker(**kwargs: Any) -> threading.Thread:
        worker = original(**kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(signals, "_Thread", make_worker)
    return workers


@pytest.mark.parametrize("value", [0, 1, None, "false", object()])
def test_cancellation_observation_requires_exact_boolean(value: Any) -> None:
    with pytest.raises(DockerExecSignalUnavailable, match="invalid type"):
        read_cancelled(SimpleNamespace(is_cancelled=lambda: value))


class IntSubclass(int):
    pass


@pytest.mark.parametrize("value", [-1, True, False, 1.0, "1", None, IntSubclass(1)])
def test_monotonic_observation_requires_exact_nonnegative_integer(value: Any) -> None:
    with pytest.raises(DockerExecSignalUnavailable, match="invalid type"):
        read_monotonic_ns(lambda: value)


def test_valid_generic_sources_run_on_daemon_worker_and_preserve_exact_types() -> None:
    observed: list[bool] = []

    def clock() -> int:
        observed.append(threading.current_thread().daemon)
        return 0

    before = time.monotonic_ns()
    observed_time = read_monotonic_ns(clock)
    assert 0 <= observed_time <= time.monotonic_ns() - before
    assert read_cancelled(SimpleNamespace(is_cancelled=lambda: True)) is True
    assert observed == [True]


def test_source_exception_is_sanitized_and_never_rethrown_to_controller() -> None:
    def clock() -> int:
        raise RuntimeError("private controller detail")

    with pytest.raises(DockerExecSignalUnavailable) as caught:
        read_monotonic_ns(clock)
    assert "private controller detail" not in str(caught.value)


@pytest.mark.parametrize("source_kind", ["clock", "cancellation_descriptor"])
def test_blocked_callback_or_descriptor_returns_within_probe_budget(
    monkeypatch: pytest.MonkeyPatch,
    source_kind: str,
) -> None:
    workers = track_workers(monkeypatch)
    release = threading.Event()

    def clock() -> int:
        release.wait()
        return 0

    class BlockingCancellation:
        @property
        def is_cancelled(self):
            release.wait()
            return lambda: False

    assert signals._PROBE_TIMEOUT_SECONDS == 0.250
    started = time.monotonic()
    try:
        with pytest.raises(DockerExecSignalUnavailable, match="timed out"):
            if source_kind == "clock":
                read_monotonic_ns(clock)
            else:
                read_cancelled(BlockingCancellation())
        assert time.monotonic() - started < 0.8
        assert len(workers) == 1 and workers[0].is_alive()
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive()


def test_saturated_pool_starts_no_additional_worker_until_hung_callbacks_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workers = track_workers(monkeypatch)
    monkeypatch.setattr(signals, "_PROBE_TIMEOUT_SECONDS", 0.005)
    release = threading.Event()

    def clock() -> int:
        release.wait()
        return 1

    assert signals._MAX_PROBE_WORKERS == 32
    try:
        for _ in range(signals._MAX_PROBE_WORKERS):
            with pytest.raises(DockerExecSignalUnavailable, match="timed out"):
                read_monotonic_ns(clock)
        assert len(workers) == 32
        started = time.monotonic()
        with pytest.raises(DockerExecSignalUnavailable, match="capacity is exhausted"):
            read_monotonic_ns(clock)
        assert time.monotonic() - started < 0.1
        assert len(workers) == 32 and all(worker.is_alive() for worker in workers)
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive()
    before = time.monotonic_ns()
    observed_time = read_monotonic_ns(lambda: 2)
    assert 2 <= observed_time <= 2 + time.monotonic_ns() - before


def test_concrete_event_and_native_clock_fastpaths_do_not_start_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("concrete signals must not enter the generic callback pool")

    monkeypatch.setattr(signals, "_probe", forbidden)
    cancel = ControllerExecCancellationV2()
    assert read_cancelled(cancel) is False and cancel.is_cancelled() is False
    cancel.cancel()
    assert read_cancelled(cancel) is True and cancel.is_cancelled() is True
    assert type(read_monotonic_ns(time.monotonic_ns)) is int
    with pytest.raises(AttributeError):
        object.__setattr__(cancel, "is_cancelled", lambda: False)
    with pytest.raises(TypeError, match="sealed"):
        type(
            "CancellationOverride",
            (ControllerExecCancellationV2,),
            {"is_cancelled": lambda self: False},
        )


def test_fastpath_rejects_replaced_event_subclass_without_calling_override() -> None:
    class EventOverride(threading.Event):
        def is_set(self) -> bool:
            pytest.fail("subclass callback must never enter the fastpath")

    cancel = ControllerExecCancellationV2()
    object.__setattr__(cancel, "_ControllerExecCancellationV2__event", EventOverride())
    with pytest.raises(DockerExecSignalUnavailable, match="was replaced"):
        read_cancelled(cancel)


def test_non_native_clock_wrapper_does_not_inherit_native_fastpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workers = track_workers(monkeypatch)
    assert type(read_monotonic_ns(lambda: time.monotonic_ns())) is int
    assert len(workers) == 1
    workers[0].join(timeout=1)


def test_gate_after_write_blocked_probe_is_bounded_uncertain_and_releases_cleanup_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workers = track_workers(monkeypatch)
    value, store, connection, admitted, _fence, _claims, _mapping, _clock, _cancel = runtime(
        tmp_path / "exec.sqlite"
    )
    release = threading.Event()

    class Cancellation:
        def __init__(self) -> None:
            self.calls = 0
            self.lock = threading.Lock()

        def is_cancelled(self) -> bool:
            with self.lock:
                self.calls += 1
                index = self.calls
            if index == 2:
                release.wait()
            return False

    cancellation = Cancellation()
    value._clock = time.monotonic_ns
    gate = value.gate(
        admitted,
        operation="container_exec_create",
        request_digest=RAW,
        deadline_monotonic_ns=time.monotonic_ns() + 5_000_000_000,
        cancellation=cancellation,
        custody_plan_digest=CUSTODY_PLAN,
        network_policy_digest=NETWORK_POLICY,
    )
    try:
        started = time.monotonic()
        with pytest.raises(DockerExecSignalUnavailable, match="timed out"):
            with gate.before_send():
                pass  # Simulated completed request write; no network or Docker.
        # This also includes the durable uncertainty commit. The independent
        # per-observation test verifies the 250ms callback wait itself.
        assert time.monotonic() - started < 1.5
        assert not gate.sent and row(store, admitted)["phase"] == "uncertain"
        completed = threading.Event()
        failures: list[BaseException] = []

        def cleanup_observer():
            try:
                with value.authority.cleanup_scope(admitted):
                    assert row(store, admitted)["phase"] == "uncertain"
            except BaseException as exc:
                failures.append(exc)
            finally:
                completed.set()

        cleanup = threading.Thread(target=cleanup_observer, daemon=True)
        cleanup.start()
        assert completed.wait(timeout=1)
        cleanup.join(timeout=1)
        assert not failures and not release.is_set()
        release.set()
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive()
        # Its late false result cannot reverse the already-published failure.
        assert not gate.sent and row(store, admitted)["phase"] == "uncertain"
        with pytest.raises(DockerExecJournalError, match="already reserved"):
            value.gate(
                admitted,
                operation="container_exec_create",
                request_digest=RAW,
                deadline_monotonic_ns=6_000_000_000,
                cancellation=cancellation,
                custody_plan_digest=CUSTODY_PLAN,
                network_policy_digest=NETWORK_POLICY,
            )
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=1)
        connection.close()


@pytest.mark.parametrize("slow_source", ["cancellation", "clock"])
def test_slow_signal_cannot_authorize_write_after_real_monotonic_deadline(
    tmp_path: Path,
    slow_source: str,
) -> None:
    value, store, connection, admitted, *_ = runtime(tmp_path / "exec.sqlite")

    def clock() -> int:
        sampled = time.monotonic_ns()
        if slow_source == "clock":
            time.sleep(0.2)
        return sampled

    class Cancellation:
        def is_cancelled(self) -> bool:
            if slow_source == "cancellation":
                time.sleep(0.2)
            return False

    value._clock = clock
    gate = value.gate(
        admitted,
        operation="container_exec_create",
        request_digest=RAW,
        deadline_monotonic_ns=time.monotonic_ns() + 50_000_000,
        cancellation=Cancellation(),
        custody_plan_digest=CUSTODY_PLAN,
        network_policy_digest=NETWORK_POLICY,
    )
    try:
        with pytest.raises((DockerExecDispatchError, DockerExecSignalUnavailable)):
            with gate.before_send():
                pytest.fail("slow observation must not authorize an expired write")
        assert not gate.sent and row(store, admitted)["phase"] == "uncertain"
    finally:
        connection.close()


def test_generic_clock_sample_is_aged_past_actual_callback_return_time() -> None:
    sampled_and_returned: list[int] = []

    def slow_clock() -> int:
        sampled = time.monotonic_ns()
        time.sleep(0.2)
        sampled_and_returned.extend((sampled, time.monotonic_ns()))
        return sampled

    observed = read_monotonic_ns(slow_clock)
    assert observed >= sampled_and_returned[1]
    assert observed - sampled_and_returned[0] >= 200_000_000


def test_generic_clock_budget_anchor_never_exceeds_native_probe_entrance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_native = signals._NATIVE_MONOTONIC_NS
    native_observations: list[int] = []

    def record_native() -> int:
        value = real_native()
        native_observations.append(value)
        return value

    def late_sampled_clock() -> int:
        time.sleep(0.2)
        return real_native()

    monkeypatch.setattr(signals, "_NATIVE_MONOTONIC_NS", record_native)
    anchor = read_monotonic_anchor_ns(late_sampled_clock)
    assert 0 <= anchor <= native_observations[0]
