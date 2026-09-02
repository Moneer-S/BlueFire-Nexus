from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import bluefire.runner_watchdog as watchdog_module
from bluefire.runner_client import RunnerTransportError, runner_watchdog_control_root
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.util import canonical_json_bytes, file_hash


def _write_config(
    tmp_path: Path,
    *,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    task_id = "task-watchdog-config-01"
    result_parent = tmp_path / "results"
    result_parent.mkdir()
    durable_result = result_parent / f"{task_id}.json"
    control_root = runner_watchdog_control_root(durable_result, task_id)
    control_root.mkdir()
    work_root = tmp_path / "work"
    work_root.mkdir()
    runner_binary = Path(sys.executable).resolve(strict=True)
    watchdog_script = Path(watchdog_module.__file__).resolve(strict=True)
    parent_death_script = watchdog_script.with_name("runner_parent_death.py")
    with _PinnedPrivateDirectory(result_parent) as pinned:
        parent_identity = pinned.directory_identity()
        parent_mount_identity = pinned.directory_mount_identity()
    value: dict[str, Any] = {
        "schema_version": "bluefire.runner-watchdog-config.v5",
        "task_id": task_id,
        "runner_binary": str(runner_binary),
        "runner_binary_digest": file_hash(runner_binary),
        "parent_death_script_digest": file_hash(parent_death_script),
        "watchdog_script_digest": file_hash(watchdog_script),
        "watchdog_interpreter": str(runner_binary),
        "watchdog_interpreter_digest": file_hash(runner_binary),
        "work_root": str(work_root),
        "timeout_seconds": 5.0,
        "output_limit_bytes": 4096,
        "durable_result_path": str(durable_result),
        "durable_result_parent_identity": list(parent_identity),
        "durable_result_parent_mount_identity": parent_mount_identity,
        "manifest": {},
        "profile": {},
        "cancellation_lease_token": None,
    }
    if mutate is not None:
        mutate(value)
    path = control_root / "config.json"
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    return path


def test_watchdog_config_v5_retains_exact_parent_lease(tmp_path: Path) -> None:
    config = watchdog_module._load_config(str(_write_config(tmp_path)))
    try:
        assert config.durable_result_parent.directory_identity() == (
            (tmp_path / "results").stat().st_dev,
            (tmp_path / "results").stat().st_ino,
        )
    finally:
        watchdog_module._close_config(config)


@pytest.mark.skipif(os.name != "nt", reason="Windows share-delete lease regression")
def test_watchdog_parent_lease_blocks_rebind_until_watchdog_close(tmp_path: Path) -> None:
    result_parent = tmp_path / "results"
    renamed_parent = tmp_path / "renamed-results"
    path = _write_config(tmp_path)
    host_guard = _PinnedPrivateDirectory(result_parent)
    host_guard.__enter__()
    try:
        config = watchdog_module._load_config(str(path))
        config.control.close()
    finally:
        host_guard.close()
    try:
        with pytest.raises(OSError):
            result_parent.rename(renamed_parent)
    finally:
        watchdog_module._close_config(config)

    result_parent.rename(renamed_parent)
    assert renamed_parent.is_dir()


def test_watchdog_config_rejects_platform_mount_identity_downgrade(tmp_path: Path) -> None:
    invalid_mount_identity = None if sys.platform.startswith("linux") else 1
    path = _write_config(
        tmp_path,
        mutate=lambda value: value.__setitem__(
            "durable_result_parent_mount_identity",
            invalid_mount_identity,
        ),
    )

    with pytest.raises(RunnerTransportError, match="configuration is invalid"):
        watchdog_module._load_config(str(path))


@pytest.mark.parametrize(
    "tampered",
    [None, 0, 1, "identity", [], [1], [True, 1], [0, 0], [1, -1]],
)
def test_watchdog_config_rejects_tampered_parent_lease_identity(
    tmp_path: Path,
    tampered: object,
) -> None:
    path = _write_config(
        tmp_path,
        mutate=lambda value: value.__setitem__("durable_result_parent_identity", tampered),
    )

    with pytest.raises(RunnerTransportError, match="configuration is invalid"):
        watchdog_module._load_config(str(path))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("durable_result_parent_identity"),
        lambda value: value.pop("durable_result_parent_mount_identity"),
        lambda value: value.pop("watchdog_interpreter"),
        lambda value: value.pop("watchdog_interpreter_digest"),
        lambda value: value.__setitem__(
            "watchdog_interpreter_digest",
            "sha256:" + "0" * 64,
        ),
        lambda value: value.__setitem__(
            "schema_version",
            "bluefire.runner-watchdog-config.v4",
        ),
    ],
    ids=[
        "missing-identity",
        "missing-mount-identity",
        "missing-watchdog-interpreter",
        "missing-watchdog-interpreter-digest",
        "changed-watchdog-interpreter",
        "legacy-schema",
    ],
)
def test_watchdog_config_refuses_unbound_or_legacy_lease_claims(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    path = _write_config(tmp_path, mutate=mutate)

    with pytest.raises(RunnerTransportError, match="configuration is invalid"):
        watchdog_module._load_config(str(path))


@pytest.mark.parametrize(
    "changed_field",
    [
        "runner_binary_digest",
        "_watchdog_interpreter_digest",
        "parent_death_script_digest",
        "watchdog_script_digest",
    ],
)
def test_watchdog_run_rejects_identity_change_across_constructor_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str,
) -> None:
    config = watchdog_module._load_config(str(_write_config(tmp_path)))
    executed = False

    class ChangedRunner:
        runner_binary_digest = config.runner_binary_digest
        _watchdog_interpreter_digest = config.watchdog_interpreter_digest
        parent_death_script_digest = config.parent_death_script_digest
        watchdog_script_digest = config.watchdog_script_digest

        def _execute_task_locally(self, *_args: Any, **_kwargs: Any) -> None:
            nonlocal executed
            executed = True

    setattr(ChangedRunner, changed_field, "sha256:" + "0" * 64)
    monkeypatch.setattr(
        watchdog_module,
        "SubprocessRustRunner",
        lambda *_args, **_kwargs: ChangedRunner(),
    )
    monkeypatch.setattr(watchdog_module, "_wait_for_start", lambda _config: "started")
    monkeypatch.setattr(watchdog_module, "_signal_exists", lambda *_args, **_kwargs: False)
    try:
        assert watchdog_module._run(config, receiver_environment={}) == (
            "failed",
            "runner_identity_changed",
            None,
        )
        assert executed is False
    finally:
        watchdog_module._close_config(config)


def test_watchdog_config_aggregates_all_failed_lease_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write_config(tmp_path)
    control_root = path.parent
    result_parent = tmp_path / "results"
    lease_failure = RunnerTransportError("durable lease failed")
    control_close_failure = OSError("control close failed")
    durable_close_failure = OSError("durable close failed")
    close_attempts: list[str] = []
    real_enter = _PinnedPrivateDirectory.__enter__
    real_close = _PinnedPrivateDirectory.close

    def enter_with_durable_failure(
        pinned: _PinnedPrivateDirectory,
    ) -> _PinnedPrivateDirectory:
        if pinned.path == result_parent:
            raise lease_failure
        return real_enter(pinned)

    def close_with_failures(pinned: _PinnedPrivateDirectory) -> None:
        if pinned.path == control_root and pinned.expected_identity is not None:
            close_attempts.append("control")
            real_close(pinned)
            raise control_close_failure
        if pinned.path == result_parent:
            close_attempts.append("durable")
            real_close(pinned)
            raise durable_close_failure
        real_close(pinned)

    monkeypatch.setattr(_PinnedPrivateDirectory, "__enter__", enter_with_durable_failure)
    monkeypatch.setattr(_PinnedPrivateDirectory, "close", close_with_failures)

    with pytest.raises(watchdog_module._WatchdogLeaseCleanupError) as raised:
        watchdog_module._load_config(str(path))

    assert raised.value.failures == (
        lease_failure,
        control_close_failure,
        durable_close_failure,
    )
    assert close_attempts == ["control", "durable"]
