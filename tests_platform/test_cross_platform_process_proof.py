from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_process_proof as process_proof_module
from bluefire.cross_platform_process_proof import ProcessProofError
from bluefire.runner_client import (
    RunnerTaskCancelled,
    SubprocessRustRunner,
    execution_task_identity,
)
from bluefire.util import canonical_json_bytes, file_hash


class _WaitingCancellationRunner:
    def __init__(self) -> None:
        self.execute_thread_id: int | None = None
        self.cancel_event: threading.Event | None = None

    def execute_task(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: Path,
    ) -> Mapping[str, Any]:
        del task_id, durable_result_path
        self.execute_thread_id = threading.get_ident()
        self.cancel_event = cancel_event
        deadline = time.monotonic() + 2.0
        while not cancel_event.is_set():
            if time.monotonic() >= deadline:
                raise AssertionError("the cancellation readiness poll did not signal the runner")
            time.sleep(0.001)
        raise RunnerTaskCancelled(
            "the test runner confirmed cancellation",
            cooperative_requested=True,
            cooperative_acknowledged=True,
            forced_tree_termination=True,
            control_cleanup_verified=True,
        )


class _EarlyFailureRunner:
    def __init__(self) -> None:
        self.cancel_event: threading.Event | None = None

    def execute_task(
        self,
        _manifest: Mapping[str, Any],
        _profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: Path,
    ) -> Mapping[str, Any]:
        del task_id, durable_result_path
        self.cancel_event = cancel_event
        raise RuntimeError("synthetic execute failure")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessProofError(message)


def _ready_control(tmp_path: Path) -> Path:
    control = tmp_path / "control"
    control.mkdir()
    (control / "ready.json").write_bytes(b"{}\n")
    return control


def _install_ready_identity_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        process_proof_module,
        "_ready_record",
        lambda *_args, **_kwargs: {
            "parent_process_id": 101,
            "descendant_process_id": 202,
        },
    )
    monkeypatch.setattr(
        process_proof_module,
        "capture_process_identity",
        lambda process_id: {
            "process_id": process_id,
            "creation_time_100ns": process_id * 10,
        },
    )
    monkeypatch.setattr(process_proof_module, "process_identity_running", lambda _identity: True)


def _execute(
    runner: Any,
    control_root: Path,
    tmp_path: Path,
) -> tuple[RunnerTaskCancelled, Mapping[str, Any], Mapping[str, Any]]:
    manifest = {"request_hash": "sha256:" + "a" * 64}
    profile: dict[str, Any] = {}
    return process_proof_module._execute_cancellation_task(
        runner,
        manifest,
        profile,
        task_id=execution_task_identity(manifest, profile)[0],
        request_hash="sha256:" + "a" * 64,
        control_root=control_root,
        durable_result_path=tmp_path / "durable" / "result.json",
        require=_require,
    )


def test_cancellation_launcher_and_readiness_poll_stay_on_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    control = _ready_control(tmp_path)
    _install_ready_identity_stubs(monkeypatch)
    runner = _WaitingCancellationRunner()
    caller_thread_id = threading.get_ident()

    cancellation, parent, descendant = _execute(runner, control, tmp_path)

    assert runner.execute_thread_id == caller_thread_id
    assert cancellation.cooperative_acknowledged is True
    assert parent == {"process_id": 101, "creation_time_100ns": 1010}
    assert descendant == {"process_id": 202, "creation_time_100ns": 2020}
    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


@pytest.mark.parametrize("binding", ["native_id", "other_profile", "other_manifest"])
def test_cancellation_execution_rejects_mixed_identity_before_dispatch(
    tmp_path: Path, binding: str
) -> None:
    manifest = {"request_hash": "sha256:" + "a" * 64}
    profile: dict[str, Any] = {}
    task_id = execution_task_identity(manifest, profile)[0]
    if binding == "native_id":
        task_id = "execute-" + "a" * 64
    elif binding == "other_profile":
        profile = {"profile_id": "other"}
    else:
        manifest = {"request_hash": "sha256:" + "b" * 64}
    runner = _EarlyFailureRunner()
    with pytest.raises(ProcessProofError, match="execution identity is not request-bound"):
        process_proof_module._execute_cancellation_task(
            runner,
            manifest,
            profile,
            task_id=task_id,
            request_hash="sha256:" + "a" * 64,
            control_root=tmp_path / "absent",
            durable_result_path=tmp_path / "durable" / "result.json",
            require=_require,
        )
    assert runner.cancel_event is None


@pytest.mark.parametrize("ready_binding", ["native", "transport", "other_hash", "same_process"])
def test_real_proof_caller_keeps_transport_execution_and_native_readiness_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ready_binding: str
) -> None:
    """Exercise the real proof launcher with owned fixture records, never a native process."""
    from bluefire.config import load_config
    from bluefire.registry import load_builtin_registry

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    resources = tmp_path / "resources"
    resources.mkdir()
    binary = resources / "bluefire-runner.exe"
    binary.write_bytes(b"owned-test-runner-not-executed")
    service = SimpleNamespace(
        config=load_config(Path(__file__).resolve().parents[1] / "config/bluefire.example.yaml"),
        registry=load_builtin_registry(),
    )
    live = {101, 202}
    observed: list[tuple[str, str]] = []
    cleanup_tasks: list[str] = []
    original_pending = process_proof_module.runner_pending_result_path
    original_watchdog = process_proof_module.runner_watchdog_control_root

    class OwnedFixtureRunner:
        _decode_json = staticmethod(SubprocessRustRunner._decode_json)

        def __init__(self, runner_binary: Path, work_root: Path, **bounds: Any) -> None:
            assert runner_binary == binary.resolve()
            assert work_root == runtime / "cancellation/runner-work"
            assert bounds == {"timeout_seconds": 20.0, "output_limit_bytes": 64 * 1024}

        def execute_task(
            self,
            manifest: Mapping[str, Any],
            profile: Mapping[str, Any],
            *,
            task_id: str,
            cancel_event: threading.Event,
            durable_result_path: Path,
        ) -> Mapping[str, Any]:
            assert task_id == execution_task_identity(manifest, profile)[0]
            request_hash = str(manifest["request_hash"])
            native_id = "execute-" + request_hash.removeprefix("sha256:")
            assert task_id != native_id
            observed.append((task_id, native_id))
            durable_result_path.parent.mkdir()
            control = (
                Path(str(profile["sandbox_root"]))
                / process_proof_module.CONTROL_PARENT
                / request_hash[7:]
            )
            control.mkdir(parents=True)
            ready = {
                "schema_version": process_proof_module.READY_SCHEMA,
                "task_id": task_id if ready_binding == "transport" else native_id,
                "request_hash": (
                    "sha256:" + "b" * 64 if ready_binding == "other_hash" else request_hash
                ),
                "parent_process_id": 101,
                "descendant_process_id": 101 if ready_binding == "same_process" else 202,
            }
            payloads = {
                ".lease": b"lease:" + b"e" * 64 + b"\n",
                "ready.json": canonical_json_bytes(ready) + b"\n",
            }
            with process_proof_module._PinnedPrivateDirectory(control) as pinned:
                for name, payload in payloads.items():
                    pinned.create(name, payload, maximum=1024)
            try:
                assert cancel_event.is_set()
            finally:
                live.clear()
                with process_proof_module._PinnedPrivateDirectory(control, delete=True) as pinned:
                    for name, payload in payloads.items():
                        pinned.unlink(name, maximum=1024, expected=payload)
                    pinned.remove()
            raise RunnerTaskCancelled(
                "owned fixture cancellation",
                cooperative_requested=True,
                cooperative_acknowledged=True,
                forced_tree_termination=True,
                control_cleanup_verified=True,
            )

    def pending(path: Path, task_id: str) -> Path:
        cleanup_tasks.append(task_id)
        return original_pending(path, task_id)

    def watchdog(path: Path, task_id: str) -> Path:
        cleanup_tasks.append(task_id)
        return original_watchdog(path, task_id)

    monkeypatch.setattr(process_proof_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(process_proof_module, "SubprocessRustRunner", OwnedFixtureRunner)
    monkeypatch.setattr(
        process_proof_module,
        "capture_process_identity",
        lambda pid: {
            "process_id": pid,
            "creation_time_100ns": pid * 10,
        },
    )
    monkeypatch.setattr(
        process_proof_module, "process_identity_running", lambda value: value["process_id"] in live
    )
    monkeypatch.setattr(process_proof_module, "runner_pending_result_path", pending)
    monkeypatch.setattr(process_proof_module, "runner_watchdog_control_root", watchdog)
    if ready_binding != "native":
        with pytest.raises(ProcessProofError, match="readiness is not request-bound"):
            process_proof_module.process_tree_cancellation(
                runtime, resources, service, expected_runner_digest=file_hash(binary)
            )
        assert len(observed) == 1
        assert cleanup_tasks == []
    else:
        report = process_proof_module.process_tree_cancellation(
            runtime, resources, service, expected_runner_digest=file_hash(binary)
        )
        assert len(observed) == 1
        transport_id, native_id = observed[0]
        assert cleanup_tasks == [transport_id, transport_id]
        assert report["cancellation"]["task_id"] == native_id
        assert report["cancellation"]["request_hash"] == "sha256:" + native_id.removeprefix(
            "execute-"
        )
        assert report["cancellation"]["no_survivors"] is True


def test_early_execute_failure_signals_cancellation_without_a_worker(tmp_path: Path) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    runner = _EarlyFailureRunner()

    with pytest.raises(RuntimeError, match="synthetic execute failure"):
        _execute(runner, tmp_path / "absent-control", tmp_path)

    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


def test_readiness_poll_failure_cancels_runner_without_a_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    control = _ready_control(tmp_path)
    runner = _WaitingCancellationRunner()

    def fail_readiness(*_args: object, **_kwargs: object) -> Mapping[str, Any]:
        raise ProcessProofError("synthetic readiness failure")

    monkeypatch.setattr(process_proof_module, "_ready_record", fail_readiness)

    with pytest.raises(ProcessProofError, match="synthetic readiness failure"):
        _execute(runner, control, tmp_path)

    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before


def test_missing_readiness_is_bounded_on_the_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads_before = tuple(thread.ident for thread in threading.enumerate())
    runner = _WaitingCancellationRunner()
    monkeypatch.setattr(process_proof_module, "_CANCELLATION_READY_TIMEOUT_SECONDS", 0.05)
    started = time.monotonic()

    with pytest.raises(ProcessProofError, match="never started"):
        _execute(runner, tmp_path / "absent-control", tmp_path)

    assert time.monotonic() - started < 1.0
    assert runner.cancel_event is not None and runner.cancel_event.is_set()
    assert tuple(thread.ident for thread in threading.enumerate()) == threads_before
