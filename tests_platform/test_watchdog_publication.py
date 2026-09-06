"""File-only publication checks; these never launch a runner or watchdog."""

from __future__ import annotations

import errno
import json
import os
import subprocess  # nosec B404 - type annotation only
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import bluefire.runner_client as client
from bluefire.runner_private_files import _PinnedPrivateDirectory, _PrivateFileTwoLinksError
from bluefire.runner_transport_errors import RunnerTransportError

TASK = "task-publication-01"
PID = 4242
PAYLOAD = json.dumps(
    {
        "schema_version": "bluefire.runner-watchdog-ready.v1",
        "task_id": TASK,
        "watchdog_pid": PID,
    }
).encode()


def _reader(monkeypatch: pytest.MonkeyPatch) -> client.SubprocessRustRunner:
    # Construction is deliberately bypassed: only this non-spawning read method
    # is under test, and process liveness comes from a fixed test stub.
    runner = object.__new__(client.SubprocessRustRunner)
    monkeypatch.setattr(runner, "_process_exited_without_reap", lambda _process: False)
    return runner


def _poll(runner: client.SubprocessRustRunner, root: Path) -> None:
    runner._await_watchdog_readiness(
        cast(subprocess.Popen[bytes], SimpleNamespace(pid=PID)), root, TASK
    )


def _posix_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    elapsed = [0.0]

    def sleep(seconds: float) -> None:
        elapsed[0] += seconds

    # Replace only runner_client's module references, never the global os/time
    # modules used by pytest or real private-file validation on this host.
    monkeypatch.setattr(client, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: elapsed[0], sleep=sleep))
    monkeypatch.setattr(client, "_WATCHDOG_START_GRACE_SECONDS", 0.2)
    monkeypatch.setattr(client, "_PROCESS_POLL_SECONDS", 0.05)
    return elapsed


@pytest.mark.skipif(os.name == "nt", reason="Pauses the real POSIX link/unlink publication")
def test_paused_ready_publication_is_retried_until_strict_single_link_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    root.mkdir()
    linked, release = threading.Event(), threading.Event()
    failures: list[BaseException] = []
    original_link = os.link
    original_sleep = client.time.sleep
    retries: list[int] = []

    def paused_link(source, destination, **kwargs):
        original_link(source, destination, **kwargs)
        if destination == "ready.json":
            linked.set()
            if not release.wait(5):
                raise AssertionError("publication was not released")

    def publish() -> None:
        try:
            with _PinnedPrivateDirectory(root) as pinned:
                pinned.create("ready.json", PAYLOAD, maximum=4096)
        except BaseException as exc:
            failures.append(exc)

    def observe_retry(seconds: float) -> None:
        retries.append(1)
        assert (root / "ready.json").stat().st_nlink == 2
        release.set()
        publisher.join(5)
        assert not publisher.is_alive()
        original_sleep(seconds)

    monkeypatch.setattr(os, "link", paused_link)
    monkeypatch.setattr(
        client, "time", SimpleNamespace(monotonic=client.time.monotonic, sleep=observe_retry)
    )
    publisher = threading.Thread(target=publish)
    publisher.start()
    try:
        assert linked.wait(5)
        with _PinnedPrivateDirectory(root) as pinned:
            with pytest.raises(_PrivateFileTwoLinksError):
                pinned.read("ready.json", maximum=4096)
        _poll(_reader(monkeypatch), root)
        assert retries == [1]
        assert failures == []
        assert sorted(path.name for path in root.iterdir()) == ["ready.json"]
        with _PinnedPrivateDirectory(root) as pinned:
            assert pinned.read("ready.json", maximum=4096) == PAYLOAD
    finally:
        release.set()
        publisher.join(5)
        assert not publisher.is_alive()


def test_persistent_two_link_alias_is_never_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    root.mkdir()
    with _PinnedPrivateDirectory(root) as pinned:
        pinned.create("ready.json", PAYLOAD, maximum=4096)
        alias = root / ".t-0123456789ab"
        os.link(root / "ready.json", alias)
        with pytest.raises(_PrivateFileTwoLinksError):
            pinned.read("ready.json", maximum=4096)
        elapsed = _posix_clock(monkeypatch)
        with pytest.raises(RunnerTransportError, match="did not become ready"):
            _poll(_reader(monkeypatch), root)
        assert elapsed[0] == pytest.approx(0.2)
        assert alias.exists()
        assert (root / "ready.json").stat().st_nlink == 2
        with pytest.raises(_PrivateFileTwoLinksError):
            pinned.read("ready.json", maximum=4096)
        alias.unlink()
        assert pinned.read("ready.json", maximum=4096) == PAYLOAD
        _poll(_reader(monkeypatch), root)


def test_readiness_accepts_only_after_the_staging_link_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    root.mkdir()
    with _PinnedPrivateDirectory(root) as pinned:
        pinned.create("ready.json", PAYLOAD, maximum=4096)
    staging = root / ".t-0123456789ab"
    os.link(root / "ready.json", staging)
    elapsed = _posix_clock(monkeypatch)
    retries = []

    def finish_publication(seconds: float) -> None:
        with _PinnedPrivateDirectory(root) as pinned:
            with pytest.raises(_PrivateFileTwoLinksError):
                pinned.read("ready.json", maximum=4096)
        retries.append(1)
        staging.unlink()
        elapsed[0] += seconds

    monkeypatch.setattr(client.time, "sleep", finish_publication)
    _poll(_reader(monkeypatch), root)
    assert retries == [1]
    assert elapsed[0] == pytest.approx(0.05)
    with _PinnedPrivateDirectory(root) as pinned:
        assert pinned.read("ready.json", maximum=4096) == PAYLOAD


def test_other_link_counts_and_unrelated_io_errors_fail_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "control"
    root.mkdir()
    with _PinnedPrivateDirectory(root) as pinned:
        pinned.create("ready.json", PAYLOAD, maximum=4096)
    os.link(root / "ready.json", root / "alias-one")
    os.link(root / "ready.json", root / "alias-two")
    elapsed = _posix_clock(monkeypatch)
    runner = _reader(monkeypatch)
    with pytest.raises(RunnerTransportError, match="readiness is unavailable"):
        _poll(runner, root)
    assert elapsed[0] == 0
    attempts = []

    def broken_read(*_args, **_kwargs):
        attempts.append(1)
        raise OSError(errno.EIO, "synthetic unrelated I/O failure")

    monkeypatch.setattr(_PinnedPrivateDirectory, "read", broken_read)
    with pytest.raises(RunnerTransportError, match="readiness is unavailable"):
        _poll(runner, root)
    assert attempts == [1]
    assert elapsed[0] == 0
