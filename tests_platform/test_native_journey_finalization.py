from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

import bluefire.collector_journey as collector_journey
import bluefire.defense_frontier as defense_frontier
import bluefire.replay_journey as replay_journey
import bluefire.source_intake_journey as source_intake_journey

REPOSITORY = Path(__file__).resolve().parents[1]


class _Receiver:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def serve(self) -> dict[str, object]:
        return {}

    def stop(self) -> None:
        self._events.append("receiver-stop")

    def close(self) -> None:
        self._events.append("receiver-close")


class _Thread:
    def __init__(
        self,
        events: list[str],
        *,
        target: Callable[[], None],
        name: str,
        daemon: bool,
    ) -> None:
        del target, name, daemon
        self._events = events
        self._alive = False

    def start(self) -> None:
        self._events.append("thread-start")
        self._alive = True

    def is_alive(self) -> bool:
        return self._alive

    def join(self, *, timeout: float) -> None:
        del timeout
        self._events.append("thread-join")
        self._alive = False


def _receiver_and_thread_fakes(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    events: list[str],
) -> None:
    monkeypatch.setattr(module, "LoopbackArtifactReceiver", lambda _config: _Receiver(events))
    monkeypatch.setattr(
        module.threading,
        "Thread",
        lambda **kwargs: _Thread(events, **kwargs),
    )


def test_defense_frontier_finalizer_aggregates_every_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    events: list[str] = []
    primary_failure = OSError("bootstrap failed")
    cleanup_failure = OSError("runtime cleanup failed")
    journal_failure = OSError("journal cleanup failed")
    receiver_failure = OSError("receiver close failed")
    journal_guard = object()
    runtime_guard = object()

    class FailingReceiver(_Receiver):
        def close(self) -> None:
            super().close()
            raise receiver_failure

    monkeypatch.setattr(
        defense_frontier,
        "LoopbackArtifactReceiver",
        lambda _config: FailingReceiver(events),
    )
    monkeypatch.setattr(
        defense_frontier.threading,
        "Thread",
        lambda **kwargs: _Thread(events, **kwargs),
    )
    monkeypatch.setattr(
        defense_frontier,
        "_create_pinned_runner_journal",
        lambda _root: (events.append("journal-create"), journal_guard)[1],
    )
    monkeypatch.setattr(
        defense_frontier,
        "_create_pinned_runtime",
        lambda _prefix: (events.append("runtime-create"), (tmp_path / "runtime", runtime_guard))[1],
    )

    def fail_bootstrap(**_kwargs: object) -> None:
        events.append("bootstrap")
        raise primary_failure

    def fail_runtime_cleanup(*_args: object) -> None:
        events.append("runtime-cleanup")
        raise cleanup_failure

    def fail_journal_cleanup(_root: Path, guard: object) -> None:
        assert guard is journal_guard
        events.append("journal-cleanup")
        raise journal_failure

    monkeypatch.setattr(defense_frontier, "bootstrap_runner", fail_bootstrap)
    monkeypatch.setattr(defense_frontier, "_close_runtime_and_remove", fail_runtime_cleanup)
    monkeypatch.setattr(defense_frontier, "_remove_runner_journal", fail_journal_cleanup)

    with pytest.raises(defense_frontier._RuntimeCleanupError) as caught:
        defense_frontier.produce_defense_frontier_evidence(REPOSITORY, evidence)

    assert caught.value.failures == (
        primary_failure,
        cleanup_failure,
        journal_failure,
        receiver_failure,
    )
    assert events[-4:] == [
        "runtime-cleanup",
        "journal-cleanup",
        "receiver-close",
        "thread-join",
    ]


def test_collector_finalizer_continues_after_runtime_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    events: list[str] = []
    primary_failure = OSError("bootstrap failed")
    cleanup_failure = OSError("runtime cleanup failed")
    journal_guard = object()
    runtime_guard = object()
    child = SimpleNamespace(pid=4105)
    _receiver_and_thread_fakes(monkeypatch, collector_journey, events)
    monkeypatch.setattr(
        collector_journey,
        "_start_child",
        lambda: (events.append("child-start"), child)[1],
    )
    monkeypatch.setattr(
        collector_journey,
        "_stop_child",
        lambda stopped: events.append("child-stop") if stopped is child else None,
    )
    monkeypatch.setattr(
        collector_journey,
        "_create_pinned_runner_journal",
        lambda _root: (events.append("journal-create"), journal_guard)[1],
    )
    monkeypatch.setattr(
        collector_journey,
        "_create_pinned_runtime",
        lambda _prefix: (events.append("runtime-create"), (tmp_path / "runtime", runtime_guard))[1],
    )

    def fail_bootstrap(**_kwargs: object) -> None:
        events.append("bootstrap")
        raise primary_failure

    def fail_runtime_cleanup(*_args: object) -> None:
        events.append("runtime-cleanup")
        raise cleanup_failure

    monkeypatch.setattr(collector_journey, "bootstrap_runner", fail_bootstrap)
    monkeypatch.setattr(collector_journey, "_close_runtime_and_remove", fail_runtime_cleanup)
    monkeypatch.setattr(
        collector_journey,
        "_remove_runner_journal",
        lambda _root, guard: events.append("journal-cleanup") if guard is journal_guard else None,
    )

    with pytest.raises(defense_frontier._RuntimeCleanupError) as caught:
        collector_journey.produce_collector_evidence(REPOSITORY, evidence)

    assert caught.value.failures == (primary_failure, cleanup_failure)
    assert events[-5:] == [
        "journal-cleanup",
        "receiver-stop",
        "thread-join",
        "receiver-close",
        "child-stop",
    ]


def test_replay_finalizer_continues_after_runtime_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    events: list[str] = []
    primary_failure = OSError("bootstrap failed")
    cleanup_failure = OSError("runtime cleanup failed")
    journal_guard = object()
    runtime_guard = object()
    _receiver_and_thread_fakes(monkeypatch, replay_journey, events)
    monkeypatch.setattr(
        replay_journey,
        "_create_pinned_runner_journal",
        lambda _root: (events.append("journal-create"), journal_guard)[1],
    )
    monkeypatch.setattr(
        replay_journey,
        "_create_pinned_runtime",
        lambda _prefix: (events.append("runtime-create"), (tmp_path / "runtime", runtime_guard))[1],
    )

    def fail_bootstrap(**_kwargs: object) -> None:
        events.append("bootstrap")
        raise primary_failure

    def fail_runtime_cleanup(*_args: object) -> None:
        events.append("runtime-cleanup")
        raise cleanup_failure

    monkeypatch.setattr(replay_journey, "bootstrap_runner", fail_bootstrap)
    monkeypatch.setattr(replay_journey, "_close_runtime_and_remove", fail_runtime_cleanup)
    monkeypatch.setattr(
        replay_journey,
        "_remove_runner_journal",
        lambda _root, guard: events.append("journal-cleanup") if guard is journal_guard else None,
    )

    with pytest.raises(defense_frontier._RuntimeCleanupError) as caught:
        replay_journey.produce_replay_gate_evidence(REPOSITORY, evidence)

    assert caught.value.failures == (primary_failure, cleanup_failure)
    assert events[-4:] == [
        "journal-cleanup",
        "receiver-stop",
        "thread-join",
        "receiver-close",
    ]


def test_source_intake_finalizer_continues_after_runtime_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    events: list[str] = []
    primary_failure = OSError("safety checks failed")
    cleanup_failure = OSError("runtime cleanup failed")
    journal_guard = object()
    runtime_guard = object()
    monkeypatch.setattr(
        source_intake_journey,
        "_create_pinned_runner_journal",
        lambda _root: (events.append("journal-create"), journal_guard)[1],
    )
    monkeypatch.setattr(
        source_intake_journey,
        "_create_pinned_runtime",
        lambda _prefix: (events.append("runtime-create"), (tmp_path / "runtime", runtime_guard))[1],
    )

    def fail_safety(*_args: object) -> None:
        events.append("safety")
        raise primary_failure

    def fail_runtime_cleanup(*_args: object) -> None:
        events.append("runtime-cleanup")
        raise cleanup_failure

    monkeypatch.setattr(source_intake_journey, "_safety_evidence", fail_safety)
    monkeypatch.setattr(source_intake_journey, "_close_runtime_and_remove", fail_runtime_cleanup)
    monkeypatch.setattr(
        source_intake_journey,
        "_remove_runner_journal",
        lambda _root, guard: events.append("journal-cleanup") if guard is journal_guard else None,
    )

    with pytest.raises(defense_frontier._RuntimeCleanupError) as caught:
        source_intake_journey.produce_source_intake_gate_evidence(REPOSITORY, evidence)

    assert caught.value.failures == (primary_failure, cleanup_failure)
    assert events[-2:] == ["runtime-cleanup", "journal-cleanup"]
