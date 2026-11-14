"""Real local-process tests for the effect-free controlled worker fixture."""

from __future__ import annotations

import asyncio
import os
import selectors
import subprocess
import sys
import threading
import time
from typing import Any, Coroutine, TypeVar

import pytest

from bluefire import strix_controlled_worker_process as process_module
from tests_platform.test_strix_controlled_backend import _profile

_T = TypeVar("_T")
_DIGEST = "sha256:" + "a" * 64
_PLAN = "sha256:" + "b" * 64
_FENCE = "sha256:" + "c" * 64


def _run(coroutine: Coroutine[Any, Any, _T]) -> _T:
    # Windows' stock asyncio loop constructs a TCP socketpair, which the
    # hermetic test sandbox may forbid. This loop uses timers only.
    class TimerOnlySelector(selectors.SelectSelector):
        def select(self, timeout: float | None = None) -> list[Any]:
            if timeout is not None and timeout > 0:
                time.sleep(timeout)
            return []

    class LocalLoop(asyncio.SelectorEventLoop):
        def __init__(self) -> None:
            super().__init__(selector=TimerOnlySelector())

        def _make_self_pipe(self) -> None:
            self._ssock = None
            self._csock = None

        def _close_self_pipe(self) -> None:
            pass

    loop = LocalLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coroutine)
    finally:
        asyncio.set_event_loop(None)
        loop.close()


def _fixture(**options: Any) -> Any:
    profile = _profile()
    return process_module.run_controlled_worker_fixture(
        profile,
        claim_digest=_DIGEST,
        plan_digest=_PLAN,
        controller_fence=_FENCE,
        **options,
    )


def test_fixed_isolated_child_roundtrip_and_clean_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BLUEFIRE_REPO_TOKEN", "SENSITIVE_REPO_TOKEN")
    monkeypatch.setenv("PYTHONPATH", "SENSITIVE_IMPORT_PATH")
    monkeypatch.setenv("OPENAI_API_KEY", "SENSITIVE_KEY")
    launches: list[tuple[subprocess.Popen[bytes], dict[str, Any]]] = []
    original = process_module.subprocess.Popen

    def capture(argv: list[str], **options: Any) -> subprocess.Popen[bytes]:
        child = original(argv, **options)
        launches.append((child, {"argv": argv, **options}))
        return child

    monkeypatch.setattr(process_module.subprocess, "Popen", capture)
    outcome = _run(_fixture())
    assert outcome.methods == ("create_exact",)
    assert outcome.exit_code == 0
    child, options = launches[0]
    assert child.poll() == 0
    assert options["argv"][1:3] == ["-I", "-B"]
    assert options["argv"][3] == str(process_module._SCRIPT)
    assert options["shell"] is False and options["close_fds"] is True
    assert options["stdin"] == options["stdout"] == subprocess.PIPE
    assert options["stderr"] == subprocess.DEVNULL
    assert not {"BLUEFIRE_REPO_TOKEN", "PYTHONPATH", "OPENAI_API_KEY"} & options["env"].keys()
    assert not any("SENSITIVE" in str(value) for value in options["env"].values())


def test_only_bounded_darwin_runtime_environment_is_accepted() -> None:
    environment = {
        "LANG": "C.UTF-8",
        "__CFBundleIdentifier": "org.python.python",
        "__CF_USER_TEXT_ENCODING": "0x1F5:0x0:0x0",
        "VERSIONER_PYTHON_VERSION": "3.12.14",
        "VERSIONER_PYTHON_PREFER_32_BIT": "no",
        "LC_CTYPE": "UTF-8",
    }
    assert process_module._fixture_environment_is_valid(environment, "darwin")
    assert not process_module._fixture_environment_is_valid(environment, "linux")
    assert not process_module._fixture_environment_is_valid(environment, "win32")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("__CF_REPO_TOKEN", "bounded-but-unapproved"),
        ("VERSIONER_OPENAI_API_KEY", "bounded-but-unapproved"),
        ("__CFBundleIdentifier", "org.python.python\nOPENAI_API_KEY=secret"),
        ("__CF_USER_TEXT_ENCODING", "0x1F5:0x0:not-hex"),
        ("VERSIONER_PYTHON_VERSION", "3.12.release"),
        ("VERSIONER_PYTHON_PREFER_32_BIT", "sometimes"),
        ("LC_CTYPE", "en_US.UTF-8"),
        ("__CFBundleIdentifier", "a" * 256),
    ],
)
def test_darwin_environment_rejects_unapproved_or_unbounded_values(name: str, value: str) -> None:
    environment = {"LANG": "C.UTF-8", name: value}
    assert not process_module._fixture_environment_is_valid(environment, "darwin")


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_nonce",
        "wrong_fence",
        "wrong_sequence",
        "replay",
        "oversized_header",
        "partial_header",
        "partial_body",
        "exit",
        "stderr",
    ],
)
def test_bad_child_frames_or_death_are_sanitized_and_reaped(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    children: list[subprocess.Popen[bytes]] = []
    original = process_module.subprocess.Popen

    def capture(argv: list[str], **options: Any) -> subprocess.Popen[bytes]:
        child = original(argv, **options)
        children.append(child)
        return child

    monkeypatch.setattr(process_module.subprocess, "Popen", capture)
    with pytest.raises(process_module.ControlledWorkerProcessError) as failure:
        _run(_fixture(fixture_mode=mode, timeout_seconds=1.0))
    assert "SENSITIVE" not in str(failure.value)
    assert failure.value.__context__ is None
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0].stdin is not None and children[0].stdin.closed
    assert children[0].stdout is not None and children[0].stdout.closed


def test_timeout_and_late_cancellation_reap_blocked_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    children: list[subprocess.Popen[bytes]] = []
    original = process_module.subprocess.Popen

    def capture(argv: list[str], **options: Any) -> subprocess.Popen[bytes]:
        child = original(argv, **options)
        children.append(child)
        return child

    monkeypatch.setattr(process_module.subprocess, "Popen", capture)
    with pytest.raises(process_module.ControlledWorkerProcessError, match="timed out"):
        _run(_fixture(fixture_mode="hang", timeout_seconds=0.15))

    cancelled = threading.Event()
    timer = threading.Timer(0.1, cancelled.set)
    timer.start()
    try:
        with pytest.raises(process_module.ControlledWorkerProcessError, match="cancelled"):
            _run(_fixture(fixture_mode="hang", cancel_event=cancelled))
    finally:
        timer.cancel()
    assert len(children) == 2
    assert all(child.poll() is not None for child in children)


def test_pre_cancel_refuses_before_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    cancelled = threading.Event()
    cancelled.set()

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("spawned despite cancellation")

    monkeypatch.setattr(process_module.subprocess, "Popen", forbidden)
    with pytest.raises(process_module.ControlledWorkerProcessError, match="cancelled"):
        _run(_fixture(cancel_event=cancelled))


def test_uncertain_spawn_and_private_directory_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_spawn(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("SENSITIVE_SPAWN_DETAIL")

    monkeypatch.setattr(process_module.subprocess, "Popen", failed_spawn)
    with pytest.raises(
        process_module.ControlledWorkerProcessError, match="cleanup uncertain"
    ) as failure:
        _run(_fixture())
    assert "SENSITIVE" not in str(failure.value)
    assert failure.value.__context__ is None

    def failed_directory(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("SENSITIVE_PRIVATE_PATH")

    monkeypatch.setattr(process_module.tempfile, "TemporaryDirectory", failed_directory)
    with pytest.raises(
        process_module.ControlledWorkerProcessError, match="cleanup uncertain"
    ) as failure:
        _run(_fixture())
    assert "SENSITIVE" not in str(failure.value)
    assert failure.value.__context__ is None


def test_exec_and_cancel_are_both_received_while_exec_is_pending() -> None:
    outcome = _run(_fixture(fixture_mode="create_exec_cancel", timeout_seconds=5.0))
    assert outcome.methods == ("create_exact", "exec_exact", "cancel_exact")


def test_repeated_cancellation_waits_for_resistant_controller_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_event = asyncio.Event()
    settled_event = asyncio.Event()
    original_create = process_module._InertFixtureTransport.create_exact

    async def observed_create(self: Any, request: Any) -> Any:
        started_event.set()
        try:
            return await original_create(self, request)
        finally:
            settled_event.set()

    monkeypatch.setattr(process_module._InertFixtureTransport, "create_exact", observed_create)

    async def exercise() -> None:
        run = asyncio.create_task(_fixture(fixture_mode="resistant_create", timeout_seconds=5.0))
        await asyncio.wait_for(started_event.wait(), timeout=4.0)
        started = time.monotonic()
        run.cancel()
        asyncio.get_running_loop().call_later(0.05, run.cancel)
        with pytest.raises(process_module.ControlledWorkerProcessError, match="cancelled"):
            await run
        assert settled_event.is_set()
        assert time.monotonic() - started >= 0.25

    _run(exercise())


@pytest.mark.skipif(os.name != "nt", reason="Windows Job fallback")
def test_windows_job_finish_failure_retries_terminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bluefire import runner_windows_containment

    original = runner_windows_containment.WindowsJobContainment.terminate
    retried: list[int] = []

    def finish_fails(_self: Any, _child: Any) -> bool:
        return False

    def retry(self: Any, child: Any) -> bool:
        retried.append(child.pid)
        return original(self, child)

    monkeypatch.setattr(runner_windows_containment.WindowsJobContainment, "finish", finish_fails)
    monkeypatch.setattr(runner_windows_containment.WindowsJobContainment, "terminate", retry)
    outcome = _run(_fixture())
    assert outcome.methods == ("create_exact",)
    assert len(retried) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows Job fallback")
def test_windows_unconfirmed_job_drain_closes_owned_handle_and_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bluefire import runner_windows_containment

    releases: list[int] = []
    original_release = runner_windows_containment.WindowsJobContainment._release_job
    children: list[subprocess.Popen[bytes]] = []
    original_spawn = process_module.subprocess.Popen

    def capture(argv: list[str], **options: Any) -> subprocess.Popen[bytes]:
        child = original_spawn(argv, **options)
        children.append(child)
        return child

    def no_drain(_self: Any, _child: Any) -> bool:
        return False

    def release(self: Any, process_id: int) -> bool:
        releases.append(process_id)
        return original_release(self, process_id)

    monkeypatch.setattr(process_module.subprocess, "Popen", capture)
    monkeypatch.setattr(runner_windows_containment.WindowsJobContainment, "finish", no_drain)
    monkeypatch.setattr(runner_windows_containment.WindowsJobContainment, "terminate", no_drain)
    monkeypatch.setattr(runner_windows_containment.WindowsJobContainment, "_release_job", release)
    with pytest.raises(process_module.ControlledWorkerProcessError, match="cleanup uncertain"):
        _run(_fixture())
    assert len(children) == 1 and children[0].poll() is not None
    assert releases == [children[0].pid]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group regression")
def test_posix_owned_group_drains_descendant_holding_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    children: list[subprocess.Popen[bytes]] = []
    original = process_module.subprocess.Popen

    def capture(argv: list[str], **options: Any) -> subprocess.Popen[bytes]:
        child = original(argv, **options)
        children.append(child)
        assert options["start_new_session"] is True
        return child

    monkeypatch.setattr(process_module.subprocess, "Popen", capture)
    with pytest.raises(process_module.ControlledWorkerProcessError, match="timed out"):
        _run(_fixture(fixture_mode="descendant", timeout_seconds=1.0))
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0].stdout is not None and children[0].stdout.closed
