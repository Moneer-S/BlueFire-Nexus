from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bluefire.defense_frontier as frontier_module
import bluefire.defense_frontier_gate as gate_module
import bluefire.defense_frontier_validation as validation_module
import bluefire.product_gates as product_gates
import bluefire.runner_private_files as private_files_module
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.defense_frontier import (
    PROVIDER_ID,
    REAL_PROVIDER_ID,
    SCENARIO_ID,
    STRUCTURAL_SCHEMA,
    DefenseFrontierError,
)
from bluefire.defense_frontier_validation import DefenseFrontierValidationError, load_report
from bluefire.orchestrator import Orchestrator
from bluefire.runner_bootstrap import RunnerBootstrapError
from bluefire.runner_transport_errors import RunnerTransportError
from bluefire.util import content_hash, file_hash

REPOSITORY = Path(__file__).resolve().parents[1]


def test_private_directory_close_attempts_both_descriptors_and_clears_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pinned = private_files_module._PinnedPrivateDirectory(tmp_path / "unused")
    first_descriptor = os.open(os.devnull, os.O_RDONLY)
    parent_descriptor = os.open(os.devnull, os.O_RDONLY)
    pinned._descriptor = first_descriptor
    pinned._parent_descriptor = parent_descriptor
    pinned._identity = (1, 2)
    pinned._mount_identity = 3
    first_failure = OSError("first descriptor close failed")
    real_close = os.close
    close_calls: list[int] = []

    def fail_first_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        if descriptor == first_descriptor:
            raise first_failure
        real_close(descriptor)

    monkeypatch.setattr(private_files_module.os, "close", fail_first_close)
    try:
        with pytest.raises(OSError) as caught:
            pinned.close()
        assert caught.value is first_failure
        assert close_calls == [first_descriptor, parent_descriptor]
        assert pinned._descriptor is None
        assert pinned._parent_descriptor is None
        assert pinned._identity is None
        assert pinned._mount_identity is None
        pinned.close()
        assert close_calls == [first_descriptor, parent_descriptor]
    finally:
        real_close(first_descriptor)


def test_private_directory_close_aggregates_both_descriptor_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pinned = private_files_module._PinnedPrivateDirectory(tmp_path / "unused")
    first_descriptor = os.open(os.devnull, os.O_RDONLY)
    parent_descriptor = os.open(os.devnull, os.O_RDONLY)
    pinned._descriptor = first_descriptor
    pinned._parent_descriptor = parent_descriptor
    pinned._identity = (1, 2)
    pinned._mount_identity = 3
    first_failure = OSError("first descriptor close failed")
    parent_failure = OSError("parent descriptor close failed")
    failures = {
        first_descriptor: first_failure,
        parent_descriptor: parent_failure,
    }
    real_close = os.close
    close_calls: list[int] = []
    closed: set[int] = set()

    def fail_every_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        real_close(descriptor)
        closed.add(descriptor)
        raise failures[descriptor]

    monkeypatch.setattr(private_files_module.os, "close", fail_every_close)
    try:
        with pytest.raises(private_files_module._PrivateFileCleanupError) as caught:
            pinned.close()
        assert caught.value.failures == (first_failure, parent_failure)
        assert close_calls == [first_descriptor, parent_descriptor]
        assert pinned._descriptor is None
        assert pinned._parent_descriptor is None
        assert pinned._identity is None
        assert pinned._mount_identity is None
        pinned.close()
        assert close_calls == [first_descriptor, parent_descriptor]
    finally:
        for descriptor in (first_descriptor, parent_descriptor):
            if descriptor not in closed:
                real_close(descriptor)


def test_private_directory_enter_retains_validation_and_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pinned = private_files_module._PinnedPrivateDirectory(tmp_path / "private")
    descriptor = os.open(os.devnull, os.O_RDONLY)
    pinned._descriptor = descriptor
    validation_failure = OSError("private directory validation failed")
    close_failure = OSError("private directory close failed")
    real_close = os.close
    closed = False

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise validation_failure

    def fail_close(open_descriptor: int) -> None:
        nonlocal closed
        real_close(open_descriptor)
        closed = True
        raise close_failure

    if os.name == "nt":
        monkeypatch.setattr(private_files_module, "_windows_open_descriptor", fail_open)
    else:
        monkeypatch.setattr(private_files_module.os, "open", fail_open)
    monkeypatch.setattr(private_files_module.os, "close", fail_close)
    try:
        with pytest.raises(private_files_module._PrivateFileCleanupError) as caught:
            pinned.__enter__()
        assert caught.value.failures == (validation_failure, close_failure)
        assert pinned._descriptor is None
        assert pinned._parent_descriptor is None
        assert pinned._identity is None
        assert pinned._mount_identity is None
    finally:
        if not closed:
            real_close(descriptor)


def test_private_directory_exit_retains_body_and_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pinned = private_files_module._PinnedPrivateDirectory(tmp_path / "unused")
    body_failure = ValueError("body failed")
    close_failure = OSError("close failed")

    def fail_close() -> None:
        raise close_failure

    monkeypatch.setattr(pinned, "close", fail_close)

    with pytest.raises(private_files_module._PrivateFileCleanupError) as caught:
        pinned.__exit__(ValueError, body_failure, None)

    assert caught.value.failures == (body_failure, close_failure)


def test_guarded_binary_file_close_aggregates_handle_and_directory_failures() -> None:
    handle_failure = OSError("file handle close failed")
    directory_failure = OSError("directory handle close failed")
    close_calls: list[str] = []

    def fail_handle_close() -> None:
        close_calls.append("handle")
        raise handle_failure

    def fail_directory_close() -> None:
        close_calls.append("directory")
        raise directory_failure

    guarded = private_files_module._GuardedBinaryFile(
        SimpleNamespace(close=fail_handle_close),  # type: ignore[arg-type]
        SimpleNamespace(close=fail_directory_close),  # type: ignore[arg-type]
        "private.json",
        1024,
    )

    with pytest.raises(private_files_module._PrivateFileCleanupError) as caught:
        guarded.close()

    assert caught.value.failures == (handle_failure, directory_failure)
    assert close_calls == ["handle", "directory"]


def test_token_known_folder_access_includes_query_and_impersonate() -> None:
    assert frontier_module._TOKEN_KNOWN_FOLDER_ACCESS == 0x000C


@pytest.mark.skipif(os.name != "nt", reason="Windows token-known-folder contract")
def test_runtime_temp_parent_ignores_isolated_environment_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = tmp_path / "environment-controlled-profile"
    local = poisoned / "AppData" / "Local"
    roaming = poisoned / "AppData" / "Roaming"
    local.mkdir(parents=True)
    roaming.mkdir(parents=True)
    for name, value in {
        "HOME": poisoned,
        "USERPROFILE": poisoned,
        "LOCALAPPDATA": local,
        "APPDATA": roaming,
        "TEMP": local,
        "TMP": local,
    }.items():
        monkeypatch.setenv(name, os.fspath(value))

    parent = frontier_module._runtime_temp_parent()

    assert parent.is_dir()
    assert parent != local.resolve()
    assert not parent.is_relative_to(poisoned.resolve())


def test_external_native_runtime_is_removed_when_bootstrap_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_parent = tmp_path / "token-temp"
    evidence = tmp_path / "evidence"
    runtime_parent.mkdir()
    evidence.mkdir()
    monkeypatch.setattr(
        frontier_module,
        "_runtime_temp_parent",
        lambda: runtime_parent,
    )

    def unavailable(**_kwargs: object) -> object:
        raise RunnerBootstrapError("unavailable")

    monkeypatch.setattr(frontier_module, "bootstrap_runner", unavailable)

    with pytest.raises(DefenseFrontierError, match="packaged native runner"):
        frontier_module.produce_defense_frontier_evidence(REPOSITORY, evidence)

    assert list(runtime_parent.iterdir()) == []


def test_runtime_removal_recovers_when_service_shutdown_failure_is_transient(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    (runtime / "private-state").write_bytes(b"sensitive")
    shutdown_failure = RuntimeError("shutdown failed")
    close_calls = 0

    def fail_shutdown() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise shutdown_failure

    frontier_module._close_runtime_and_remove(runtime, runtime_guard, fail_shutdown)

    assert close_calls == 2
    assert not runtime.exists()


def test_runtime_cleanup_recovers_transient_shutdown_and_removal_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    (runtime / "private-state").write_bytes(b"sensitive")
    shutdown_failure = RuntimeError("shutdown failed")
    removal_failure = OSError("removal failed")
    close_calls = 0
    removal_calls = 0
    real_unlink = private_files_module._PinnedPrivateDirectory.unlink

    def fail_shutdown() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise shutdown_failure

    def fail_removal(
        pinned: private_files_module._PinnedPrivateDirectory,
        name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal removal_calls
        if pinned.path == runtime and name == "private-state":
            removal_calls += 1
            if removal_calls == 1:
                raise removal_failure
        real_unlink(pinned, name, **kwargs)

    monkeypatch.setattr(private_files_module._PinnedPrivateDirectory, "unlink", fail_removal)
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    frontier_module._close_runtime_and_remove(runtime, runtime_guard, fail_shutdown)

    assert close_calls == 2
    assert removal_calls == 2
    assert not runtime.exists()


def test_runtime_cleanup_preserves_a_persistent_shutdown_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    shutdown_failure = RuntimeError("shutdown failed")
    close_calls = 0

    def fail_shutdown() -> None:
        nonlocal close_calls
        close_calls += 1
        raise shutdown_failure

    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)
    with pytest.raises(RuntimeError) as caught:
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, fail_shutdown)

    assert caught.value is shutdown_failure
    assert close_calls == frontier_module._CLEANUP_ATTEMPTS
    assert not runtime.exists()


def test_runtime_cleanup_rejects_a_noop_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    real_remove = private_files_module._PinnedPrivateDirectory.remove

    def noop_runtime_remove(pinned: private_files_module._PinnedPrivateDirectory) -> None:
        if pinned.path != runtime:
            real_remove(pinned)

    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "remove",
        noop_runtime_remove,
    )
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(DefenseFrontierError, match="runtime path was rebound"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)


def test_runtime_cleanup_refuses_rebound_directory_but_still_closes_service(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    displaced = tmp_path / "displaced-runtime"
    close_calls = 0

    def close_service() -> None:
        nonlocal close_calls
        close_calls += 1

    if os.name == "nt":
        with pytest.raises(OSError):
            runtime.rename(displaced)
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, close_service)
        assert not runtime.exists()
        assert not displaced.exists()
    else:
        runtime.rename(displaced)
        runtime.mkdir()
        sentinel = runtime / "replacement-sentinel.txt"
        sentinel.write_bytes(b"preserve replacement")
        with pytest.raises(DefenseFrontierError, match="identity changed"):
            frontier_module._close_runtime_and_remove(
                runtime,
                runtime_guard,
                close_service,
            )
        assert sentinel.read_bytes() == b"preserve replacement"
        assert displaced.is_dir()

    assert close_calls == 1


@pytest.mark.skipif(os.name == "nt", reason="the Windows root lease blocks rename-away")
def test_runtime_cleanup_does_not_treat_rename_away_as_disposal(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    displaced = tmp_path / "displaced-runtime"
    runtime.rename(displaced)

    with pytest.raises(DefenseFrontierError, match="identity changed"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert not runtime.exists()
    assert displaced.is_dir()


def test_runtime_cleanup_refuses_a_child_replacement_before_it_is_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    child = runtime / "managed"
    child.mkdir()
    (child / "owned-state").write_bytes(b"owned")
    displaced = tmp_path / "displaced-managed"
    race: list[str] = []
    real_enter = private_files_module._PinnedPrivateDirectory.__enter__

    def racing_enter(
        pinned: private_files_module._PinnedPrivateDirectory,
    ) -> private_files_module._PinnedPrivateDirectory:
        if pinned.path == child and not race:
            child.rename(displaced)
            child.mkdir()
            (child / "foreign-sentinel").write_bytes(b"preserve replacement")
            race.append("replaced")
        return real_enter(pinned)

    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "__enter__",
        racing_enter,
    )
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(DefenseFrontierError, match="before it could be pinned"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert race == ["replaced"]
    assert (child / "foreign-sentinel").read_bytes() == b"preserve replacement"
    assert (displaced / "owned-state").read_bytes() == b"owned"


def test_runtime_cleanup_preserves_child_enter_and_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    child_path = runtime / "child"
    child_path.mkdir(parents=True)
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    enter_failure = OSError("child enter failed")
    close_failure = OSError("child close failed")
    real_enter = private_files_module._PinnedPrivateDirectory.__enter__
    real_close = private_files_module._PinnedPrivateDirectory.close

    def fail_child_enter(
        pinned: private_files_module._PinnedPrivateDirectory,
    ) -> private_files_module._PinnedPrivateDirectory:
        if pinned.path == child_path:
            raise enter_failure
        return real_enter(pinned)

    def fail_child_close(pinned: private_files_module._PinnedPrivateDirectory) -> None:
        if pinned.path == child_path:
            raise close_failure
        real_close(pinned)

    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "__enter__",
        fail_child_enter,
    )
    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "close",
        fail_child_close,
    )

    with pytest.raises(frontier_module._RuntimeCleanupError) as caught:
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert caught.value.failures == (enter_failure, close_failure)
    assert child_path.is_dir()


def test_runtime_cleanup_removes_a_nested_pinned_tree(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    nested = runtime / "managed" / "transport" / "task"
    nested.mkdir(parents=True)
    (nested / "private-state.json").write_bytes(b"{}\n")

    frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert not runtime.exists()


def test_runtime_cleanup_fails_closed_after_bounded_persistent_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    private_state = runtime / "private-state"
    private_state.write_bytes(b"sensitive")
    attempts = 0
    real_unlink = private_files_module._PinnedPrivateDirectory.unlink

    def locked_unlink(
        pinned: private_files_module._PinnedPrivateDirectory,
        name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal attempts
        if pinned.path == runtime and name == private_state.name:
            attempts += 1
            raise PermissionError("persistent scanner lock")
        real_unlink(pinned, name, **kwargs)

    monkeypatch.setattr(private_files_module._PinnedPrivateDirectory, "unlink", locked_unlink)
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(DefenseFrontierError, match="could not be removed exactly"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert attempts == frontier_module._CLEANUP_ATTEMPTS
    assert private_state.read_bytes() == b"sensitive"


def test_runtime_cleanup_refuses_hardlinked_foreign_file(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    outside = tmp_path / "outside-sentinel"
    outside.write_bytes(b"must survive")
    os.link(outside, runtime / "linked-sentinel")

    with pytest.raises(DefenseFrontierError, match="unsafe file"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert outside.read_bytes() == b"must survive"
    assert (runtime / "linked-sentinel").read_bytes() == b"must survive"


def test_runtime_cleanup_bounds_its_final_emptiness_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    maxima: list[int | None] = []
    real_names = private_files_module._PinnedPrivateDirectory.names

    def recording_names(
        pinned: private_files_module._PinnedPrivateDirectory,
        *,
        maximum: int | None = None,
    ) -> tuple[str, ...]:
        if pinned is runtime_guard:
            maxima.append(maximum)
        return real_names(pinned, maximum=maximum)

    monkeypatch.setattr(private_files_module._PinnedPrivateDirectory, "names", recording_names)
    frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert maxima[-1] == 1


def test_runtime_cleanup_rejects_same_device_foreign_mount_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    entry = runtime / "mounted-file"
    entry.write_bytes(b"preserve")
    real_metadata = runtime_guard.entry_metadata_with_mount_identity

    def foreign_mount(name: str) -> tuple[os.stat_result, int | None]:
        details, mount_identity = real_metadata(name)
        return details, 1 if mount_identity != 1 else 2

    monkeypatch.setattr(runtime_guard, "entry_metadata_with_mount_identity", foreign_mount)

    with pytest.raises(DefenseFrontierError, match="unsafe entry"):
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert entry.read_bytes() == b"preserve"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mount-ID contract")
def test_runtime_cleanup_refuses_a_real_same_device_bind_mount(tmp_path: Path) -> None:
    if shutil.which("mount") is None or shutil.which("umount") is None:
        pytest.skip("mount utilities are unavailable")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    source = tmp_path / "source"
    source.mkdir()
    sentinel = source / "foreign-sentinel"
    sentinel.write_bytes(b"preserve")
    mountpoint = runtime / "mounted"
    mountpoint.mkdir()
    mounted = subprocess.run(  # noqa: S603 - fixed local mount command
        ["mount", "--bind", str(source), str(mountpoint)],
        check=False,
        capture_output=True,
        text=True,
    )
    if mounted.returncode != 0:
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)
        pytest.skip("the test environment cannot create a disposable bind mount")
    try:
        details, mount_identity = runtime_guard.entry_metadata_with_mount_identity(mountpoint.name)
        assert details.st_dev == runtime_guard.directory_identity()[0]
        assert mount_identity != runtime_guard.directory_mount_identity()
        with pytest.raises(DefenseFrontierError, match="unsafe entry"):
            frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)
        assert sentinel.read_bytes() == b"preserve"
    finally:
        subprocess.run(  # noqa: S603 - fixed local unmount command
            ["umount", str(mountpoint)],
            check=True,
            capture_output=True,
            text=True,
        )
        runtime_guard.close()


def test_runtime_create_and_pin_refuses_a_racing_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(frontier_module, "_runtime_temp_parent", lambda: tmp_path)
    real_enter = private_files_module._PinnedPrivateDirectory.__enter__
    raced_paths: list[tuple[Path, Path]] = []

    def racing_enter(
        pinned: private_files_module._PinnedPrivateDirectory,
    ) -> private_files_module._PinnedPrivateDirectory:
        if pinned.delete and pinned.path.name.startswith(".race-") and not raced_paths:
            displaced = tmp_path / "displaced-runtime"
            pinned.path.rename(displaced)
            pinned.path.mkdir()
            (pinned.path / "foreign-sentinel").write_bytes(b"preserve")
            raced_paths.append((pinned.path, displaced))
        return real_enter(pinned)

    monkeypatch.setattr(private_files_module._PinnedPrivateDirectory, "__enter__", racing_enter)
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(DefenseFrontierError, match="could not be pinned"):
        frontier_module._create_pinned_runtime(".race-")

    runtime, displaced = raced_paths[0]
    assert (runtime / "foreign-sentinel").read_bytes() == b"preserve"
    assert displaced.is_dir()


def test_runtime_cleanup_aggregates_removal_and_guard_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    removal_failure = OSError("remove failed")
    close_failure = OSError("close failed")
    real_close = runtime_guard.close

    def fail_remove(_guard: private_files_module._PinnedPrivateDirectory) -> None:
        raise removal_failure

    def fail_close() -> None:
        real_close()
        raise close_failure

    monkeypatch.setattr(frontier_module, "_remove_pinned_tree", fail_remove)
    monkeypatch.setattr(runtime_guard, "close", fail_close)

    with pytest.raises(frontier_module._RuntimeCleanupError) as caught:
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert caught.value.failures == (removal_failure, close_failure)


def test_runtime_cleanup_flattens_private_file_close_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime_guard = frontier_module._pin_runtime_directory(runtime)
    removal_failure = OSError("remove failed")
    descriptor_failure = OSError("directory descriptor close failed")
    parent_failure = OSError("parent descriptor close failed")
    real_close = runtime_guard.close

    def fail_remove(_guard: private_files_module._PinnedPrivateDirectory) -> None:
        raise removal_failure

    def fail_close() -> None:
        real_close()
        raise private_files_module._PrivateFileCleanupError((descriptor_failure, parent_failure))

    monkeypatch.setattr(frontier_module, "_remove_pinned_tree", fail_remove)
    monkeypatch.setattr(runtime_guard, "close", fail_close)

    with pytest.raises(frontier_module._RuntimeCleanupError) as caught:
        frontier_module._close_runtime_and_remove(runtime, runtime_guard, lambda: None)

    assert caught.value.failures == (
        removal_failure,
        descriptor_failure,
        parent_failure,
    )


def test_cleanup_retry_does_not_wrap_private_file_cleanup_failures() -> None:
    descriptor_failure = OSError("directory descriptor close failed")
    parent_failure = OSError("parent descriptor close failed")
    cleanup_failure = private_files_module._PrivateFileCleanupError(
        (descriptor_failure, parent_failure)
    )
    attempts = 0

    def fail_cleanup() -> None:
        nonlocal attempts
        attempts += 1
        raise cleanup_failure

    with pytest.raises(private_files_module._PrivateFileCleanupError) as caught:
        frontier_module._retry_cleanup(fail_cleanup, "cleanup failed")

    assert caught.value is cleanup_failure
    assert attempts == 1


def test_runner_journal_cleanup_retries_and_refuses_unexpected_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    journal_guard = frontier_module._create_pinned_runner_journal(runs)
    journal = journal_guard.path
    result = journal / ("execute-" + "a" * 64 + ".json")
    result.write_bytes(b"{}\n")
    journal_guard.authorize_cleanup_entry(result.name, maximum=1024)
    real_unlink = private_files_module._PinnedPrivateDirectory.unlink
    attempts = 0

    def intermittently_locked(
        pinned: private_files_module._PinnedPrivateDirectory,
        name: str,
        **kwargs: Any,
    ) -> None:
        nonlocal attempts
        if pinned.path == journal and name == result.name:
            attempts += 1
            if attempts < 3:
                raise PermissionError("simulated transient scanner lock")
        real_unlink(pinned, name, **kwargs)

    monkeypatch.setattr(
        private_files_module._PinnedPrivateDirectory,
        "unlink",
        intermittently_locked,
    )
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)
    frontier_module._remove_runner_journal(runs, journal_guard)
    assert attempts == 3
    assert not journal.exists()

    unexpected_guard = frontier_module._create_pinned_runner_journal(runs)
    unexpected_journal = unexpected_guard.path
    unexpected = unexpected_journal / "operator-owned.txt"
    unexpected.write_bytes(b"preserve")
    with pytest.raises(DefenseFrontierError, match="unexpected entry"):
        frontier_module._remove_runner_journal(runs, unexpected_guard)
    assert unexpected.read_bytes() == b"preserve"


def test_runner_journal_creation_is_descriptor_relative_or_rebind_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = tmp_path / "runs"
    displaced = tmp_path / "displaced-runs"
    runs.mkdir()
    real_mkdir = private_files_module.os.mkdir
    race: list[str] = []

    def race_before_relative_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if Path(os.fsdecode(path)).name == ".bluefire-runner-results" and not race:
            try:
                runs.rename(displaced)
            except OSError:
                race.append("blocked")
            else:
                race.append("replaced")
                real_mkdir(runs, 0o700)
        if dir_fd is None:
            real_mkdir(path, mode)
        else:
            real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(private_files_module.os, "mkdir", race_before_relative_mkdir)

    if os.name == "nt":
        guard = frontier_module._create_pinned_runner_journal(runs)
        assert race == ["blocked"]
        frontier_module._remove_runner_journal(runs, guard)
        assert not displaced.exists()
    else:
        with pytest.raises((DefenseFrontierError, RunnerTransportError)):
            frontier_module._create_pinned_runner_journal(runs)
        assert race == ["replaced"]
        assert list(runs.iterdir()) == []
        assert (displaced / ".bluefire-runner-results").is_dir()


def test_runner_journal_root_rename_race_is_blocked_or_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    journal_guard = frontier_module._create_pinned_runner_journal(runs)
    journal = journal_guard.path
    result = journal / ("execute-" + "b" * 64 + ".json")
    result.write_bytes(b"{}\n")
    journal_guard.authorize_cleanup_entry(result.name, maximum=1024)
    displaced = runs / "displaced-journal"
    race: list[str] = []
    real_names = private_files_module._PinnedPrivateDirectory.names

    def racing_names(
        pinned: private_files_module._PinnedPrivateDirectory,
        *,
        maximum: int | None = None,
    ) -> tuple[str, ...]:
        if pinned.path == journal and not race:
            try:
                journal.rename(displaced)
            except OSError:
                race.append("blocked")
            else:
                race.append("replaced")
                journal.mkdir()
                (journal / "foreign-sentinel").write_bytes(b"preserve replacement")
        return real_names(pinned, maximum=maximum)

    monkeypatch.setattr(private_files_module._PinnedPrivateDirectory, "names", racing_names)
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    if os.name == "nt":
        frontier_module._remove_runner_journal(runs, journal_guard)
        assert race == ["blocked"]
        assert not journal.exists()
        assert not displaced.exists()
    else:
        with pytest.raises(DefenseFrontierError, match="enumerated safely"):
            frontier_module._remove_runner_journal(runs, journal_guard)
        assert race == ["replaced"]
        assert (journal / "foreign-sentinel").read_bytes() == b"preserve replacement"
        assert (displaced / result.name).read_bytes() == b"{}\n"


def test_runner_journal_preserves_unregistered_valid_result_name(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    journal_guard = frontier_module._create_pinned_runner_journal(runs)
    unowned = journal_guard.path / ("execute-" + "d" * 64 + ".json")
    unowned.write_bytes(b"operator-owned-result")

    with pytest.raises(DefenseFrontierError, match="unowned"):
        frontier_module._remove_runner_journal(runs, journal_guard)

    assert unowned.read_bytes() == b"operator-owned-result"


def test_runner_journal_file_rebind_before_final_unlink_is_blocked_or_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    journal_guard = frontier_module._create_pinned_runner_journal(runs)
    journal = journal_guard.path
    result = journal / ("execute-" + "c" * 64 + ".json")
    result.write_bytes(b"owned-result")
    journal_guard.authorize_cleanup_entry(result.name, maximum=1024)
    victim = tmp_path / "foreign-victim.json"
    victim.write_bytes(b"foreign-must-survive")
    replacement = tmp_path / "foreign-replacement.json"
    os.link(victim, replacement)
    victim_identity = victim.stat().st_dev, victim.stat().st_ino
    race: list[str] = []
    monkeypatch.setattr(frontier_module.time, "sleep", lambda _seconds: None)

    if os.name == "nt":
        real_mark_delete = private_files_module._windows_mark_delete_descriptor

        def racing_mark_delete(descriptor: int) -> None:
            details = os.fstat(descriptor)
            if stat.S_ISREG(details.st_mode) and not race:
                try:
                    os.replace(replacement, result)
                except OSError:
                    race.append("blocked")
                else:  # pragma: no cover - a broken Windows file pin reaches this branch
                    race.append("replaced")
            real_mark_delete(descriptor)

        monkeypatch.setattr(
            private_files_module,
            "_windows_mark_delete_descriptor",
            racing_mark_delete,
        )
        frontier_module._remove_runner_journal(runs, journal_guard)
        assert race == ["blocked"]
        assert not journal.exists()
        assert replacement.exists()
    else:
        real_fchmod = os.fchmod

        def racing_fchmod(descriptor: int, mode: int) -> None:
            details = os.fstat(descriptor)
            if stat.S_ISREG(details.st_mode) and not race:
                os.replace(replacement, result)
                race.append("replaced")
            real_fchmod(descriptor, mode)

        monkeypatch.setattr(private_files_module.os, "fchmod", racing_fchmod)
        with pytest.raises(DefenseFrontierError, match="could not be removed exactly"):
            frontier_module._remove_runner_journal(runs, journal_guard)
        assert race == ["replaced"]
        assert result.read_bytes() == b"foreign-must-survive"

    assert victim.read_bytes() == b"foreign-must-survive"
    assert (victim.stat().st_dev, victim.stat().st_ino) == victim_identity


def test_builtin_detections_match_filesystem_collector_observations(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    staged_path = sandbox / "staged" / "bundle.jsonl"
    export_path = sandbox / "exports" / "ephemeral" / "bundle.bin"
    staged_path.parent.mkdir(parents=True)
    export_path.parent.mkdir(parents=True)
    staged_path.write_bytes(b"staged\n")
    export_path.write_bytes(b"export\n")
    collected = FilesystemCollector(sandbox).collect(
        CollectionRequest(
            run_id="run-detection-contract",
            step_id="observe",
            behavior_id="collection.independent-observation.v1",
            action_id="collector.filesystem.observe.v1",
            runner_profile_id="sandbox-execute.v1",
            target_scope_ref="runner-profile:sandbox-execute.v1",
            settings={"paths": ["staged/bundle.jsonl", "exports/ephemeral/bundle.bin"]},
        )
    )
    by_path = {str(record.content["path"]): record for record in collected.records}

    staging_candidate, export_candidate = Orchestrator._build_detections(collected.records)
    assert staging_candidate.observed_evidence_ids == (by_path["staged/bundle.jsonl"].evidence_id,)
    assert export_candidate.observed_evidence_ids == (
        by_path["exports/ephemeral/bundle.bin"].evidence_id,
    )


def _structural_report() -> dict[str, Any]:
    source = REPOSITORY / "scenarios" / "ai_adaptive_safe_chain.yaml"
    packaged = REPOSITORY / "bluefire" / "data" / source.name
    return {
        "schema_version": STRUCTURAL_SCHEMA,
        "passed": True,
        "scenario_contract": {
            "scenario_id": SCENARIO_ID,
            "source_sha256": file_hash(source),
            "packaged_sha256": file_hash(packaged),
        },
        "real_provider_contract": {
            "provider_id": REAL_PROVIDER_ID,
            "kind": "openai_responses",
            "endpoint_scheme": "https",
            "credential_reference": "OPENAI_API_KEY",
            "fallback_provider_id": PROVIDER_ID,
            "manual_key_required_for_release": False,
            "proposal_only": True,
        },
    }


@pytest.mark.parametrize(
    ("section", "field", "replacement", "message"),
    [
        (
            "scenario_contract",
            "source_sha256",
            "sha256:" + "0" * 64,
            "scenario packaging contract",
        ),
        (
            "real_provider_contract",
            "endpoint_scheme",
            "http",
            "provider contract",
        ),
    ],
)
def test_structural_validation_rejects_material_contract_tampering(
    section: str,
    field: str,
    replacement: str,
    message: str,
) -> None:
    report = _structural_report()
    validation_module._validate_structural(report, REPOSITORY)

    report[section][field] = replacement

    with pytest.raises(DefenseFrontierValidationError, match=message):
        validation_module._validate_structural(report, REPOSITORY)


def test_load_report_accepts_only_a_bounded_json_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"passed":true}\n', encoding="utf-8")
    assert load_report(report_path) == {"passed": True}

    monkeypatch.setattr(validation_module, "_REPORT_LIMIT", report_path.stat().st_size - 1)
    with pytest.raises(DefenseFrontierValidationError, match="exceeded its byte bound"):
        load_report(report_path)


class _SymlinkReportPath:
    def is_file(self) -> bool:
        return True

    def is_symlink(self) -> bool:
        return True

    def stat(self) -> None:
        raise AssertionError("a symlink must be rejected before metadata is read")

    def read_text(self, *, encoding: str) -> str:
        raise AssertionError("a symlink must be rejected before content is read")


def test_load_report_rejects_symlink_before_reading_it() -> None:
    with pytest.raises(DefenseFrontierValidationError, match="report is unavailable"):
        load_report(_SymlinkReportPath())  # type: ignore[arg-type]


@pytest.mark.parametrize("mutation", ["extra_step", "action_swap"])
def test_locked_native_path_rejects_unapproved_rows(mutation: str) -> None:
    steps = [
        {
            "step_id": step_id,
            "behavior_id": behavior_id,
            "action_id": action_id,
            "status": status,
        }
        for step_id, behavior_id, action_id, status in validation_module._CANONICAL_PATH
    ]
    if mutation == "extra_step":
        steps.insert(
            -1,
            {
                "step_id": "unapproved_effect",
                "behavior_id": "sandbox.export.local.v1",
                "action_id": "sandbox.export.local.v1",
                "status": "success",
            },
        )
    else:
        steps[0]["action_id"] = "sandbox.export.local.v1"

    with pytest.raises(DefenseFrontierValidationError, match="locked scenario path"):
        validation_module._validate_locked_execution_path(
            {"steps": steps}, validation_module._CANONICAL_PATH
        )


def test_gate_helper_environment_passes_only_explicit_acceptance_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in gate_module._ACCEPTANCE_ENVIRONMENT:
        monkeypatch.setenv(name, f"value-for-{name.lower()}")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross-the-gate")
    monkeypatch.setenv("BLUEFIRE_PRIVATE_VALUE", "must-not-cross-the-gate")

    environment = gate_module._isolated_python_environment(
        tmp_path,
        passthrough=gate_module._ACCEPTANCE_ENVIRONMENT,
    )

    assert {name: environment[name] for name in gate_module._ACCEPTANCE_ENVIRONMENT} == {
        name: f"value-for-{name.lower()}" for name in gate_module._ACCEPTANCE_ENVIRONMENT
    }
    assert "OPENAI_API_KEY" not in environment
    assert "BLUEFIRE_PRIVATE_VALUE" not in environment
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert {environment[name] for name in ("TEMP", "TMP", "TMPDIR")} == {str(tmp_path.resolve())}
    if gate_module.os.name == "nt":
        assert Path(environment["PATH"]).name.casefold() == "system32"


def _approval_run(binding: dict[str, str]) -> dict[str, Any]:
    intent_id = "intent-" + content_hash(binding).removeprefix("sha256:")[:32]
    approval = {
        "schema_version": "bluefire.approval-request.v1",
        "approval_id": "approval-" + "a" * 32,
        "run_id": intent_id,
        **binding,
        "status": "claimed",
        "requested_at": "2026-08-28T00:00:00Z",
        "expires_at": "2026-08-28T00:10:00Z",
        "approved_at": "2026-08-28T00:01:00Z",
        "approved_by": "gate-04-reviewer",
        "consumed_at": "2026-08-28T00:02:00Z",
        "claimed_at": "2026-08-28T00:03:00Z",
    }
    target_scope = {"kind": "disposable-fixture"}
    provider = {"provider_id": PROVIDER_ID}
    return {
        "approval": approval,
        "policy": {
            "approval": dict(approval),
            "approval_binding": dict(binding),
            "approval_context": {},
            "runner_readiness": None,
            "catalog_authority": None,
            "authorized_target_scope": target_scope,
            "autonomy": "auto",
            "ai_provider": provider,
        },
        "scenario": {},
        "plan": {},
        "profile": {},
        "authorized_target_scope": target_scope,
        "autonomy": "auto",
        "ai_provider": provider,
        "created_at": "2026-08-28T00:04:00Z",
        "finalized_at": "2026-08-28T00:05:00Z",
    }


@pytest.mark.parametrize("mutation", ["intent_id", "scope_duplicate"])
def test_approval_validation_binds_derived_intent_and_policy_duplicates(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = {
        "state_digest": "sha256:" + "1" * 64,
        "plan_digest": "sha256:" + "2" * 64,
        "profile_id": "sandbox-blocked-network.v1",
        "target_scope_digest": "sha256:" + "3" * 64,
        "maximum_tier": "controlled",
    }
    monkeypatch.setattr(
        validation_module,
        "execution_approval_binding",
        lambda **_kwargs: dict(binding),
    )
    monkeypatch.setattr(
        validation_module.ScenarioDefinition,
        "from_mapping",
        staticmethod(lambda _value: object()),
    )
    monkeypatch.setattr(
        validation_module.RunnerProfile,
        "from_mapping",
        staticmethod(lambda _value: object()),
    )
    run = _approval_run(binding)
    assert validation_module._approval_id(run) == "approval-" + "a" * 32

    if mutation == "intent_id":
        run["approval"]["run_id"] = "intent-" + "0" * 32
        run["policy"]["approval"] = dict(run["approval"])
    else:
        run["policy"]["authorized_target_scope"] = {"kind": "different"}

    with pytest.raises(DefenseFrontierValidationError, match="freshly claimed"):
        validation_module._approval_id(run)


def _planner_frontier() -> dict[str, Any]:
    run_id = "run-20260828T000001Z-1111111111111111"
    decision_id = "decision-" + "a" * 20
    plan = {"schema_version": "bluefire.plan.v1", "steps": []}
    steps = [
        {
            "step_id": "stage_evidence",
            "behavior_id": "sandbox.collection.stage.v1",
            "action_id": "sandbox.collection.stage.v1",
            "status": "success",
            "artifacts": {"staged": True},
        },
        {
            "step_id": "try_internal_transport",
            "behavior_id": "sandbox.network.loopback.v1",
            "action_id": "sandbox.network.loopback.v1",
            "status": "blocked",
            "artifacts": {},
            "planner_decision_id": decision_id,
        },
    ]
    digest_rows = [dict(row) for row in steps]
    digest_rows[-1].pop("planner_decision_id")
    state_digest = content_hash(
        {
            "artifacts": {row["step_id"]: row["artifacts"] for row in digest_rows},
            "steps": digest_rows,
        }
    )
    completed = [
        {
            "step_id": row["step_id"],
            "behavior_id": row["behavior_id"],
            "status": row["status"],
        }
        for row in digest_rows
    ]
    planner_state = {
        "schema_version": "bluefire.planner-state.v1",
        "source_state_digest": state_digest,
        "mode": "execute",
        "current_step_id": "try_internal_transport",
        "outcome": "blocked",
        "completed_steps": completed,
        "deterministic_decision": {
            "decision_id": decision_id,
            "selected_step_id": "preserve_approved_copy",
            "selected_behavior_id": "sandbox.export.local.v1",
            "execution_disposition": "execute",
        },
        "registered_options": [],
        "remaining_budgets": {"steps": 1, "retries": 1},
    }
    record = {
        "schema_version": "bluefire.ai-proposal-record.v3",
        "run_id": run_id,
        "plan_digest": content_hash(plan),
        "current_step_id": "try_internal_transport",
        "outcome": "blocked",
        "state_digest": state_digest,
        "deterministic_decision_id": decision_id,
        "planner_state": planner_state,
        "planner_state_digest": content_hash(planner_state),
        "proposal": {
            "proposal_type": "select_registered",
            "selected_step_id": "preserve_approved_copy",
            "selected_behavior_id": "sandbox.export.local.v1",
        },
        "provider": {"effective_provider_id": PROVIDER_ID, "used_fallback": False},
        "proposal_policy_evaluation": {
            "status": "permitted",
            "mutation": False,
            "execute_requires_fresh_approval": False,
        },
        "application_status": "accepted_registered_default",
    }
    return {
        "run_id": run_id,
        "plan": plan,
        "steps": steps,
        "ai_proposals": [record],
        "planner_decisions": [
            {
                "decision_id": decision_id,
                "run_id": run_id,
                "current_state_digest": state_digest,
                "selected_step_id": "preserve_approved_copy",
                "selected_behavior_id": "sandbox.export.local.v1",
                "execution_disposition": "execute",
            }
        ],
    }


@pytest.mark.parametrize("mutation", ["run_id", "plan_digest", "prefix", "decision"])
def test_planner_validation_binds_run_plan_prefix_and_decision(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    frontier = _planner_frontier()
    record = frontier["ai_proposals"][0]
    monkeypatch.setattr(
        validation_module,
        "validate_persisted_proposal_record",
        lambda _record: SimpleNamespace(proposal_type=SimpleNamespace(value="select_registered")),
    )
    assert validation_module._validate_planner(frontier) is record

    if mutation == "run_id":
        record["run_id"] = "run-20260828T000002Z-2222222222222222"
    elif mutation == "plan_digest":
        record["plan_digest"] = "sha256:" + "0" * 64
    elif mutation == "prefix":
        record["planner_state"]["completed_steps"][0]["behavior_id"] = "sandbox.cleanup.v1"
        record["planner_state_digest"] = content_hash(record["planner_state"])
    else:
        frontier["planner_decisions"][0]["selected_behavior_id"] = "sandbox.cleanup.v1"

    with pytest.raises(DefenseFrontierValidationError):
        validation_module._validate_planner(frontier)


def _locked_gate() -> SimpleNamespace:
    assertions = tuple(
        SimpleNamespace(assertion_id=assertion_id, proof=definition[0])
        for assertion_id, definition in gate_module._EXPECTED_ASSERTIONS.items()
    )
    return SimpleNamespace(assertions=assertions)


def _passed_checks() -> dict[str, bool]:
    return {definition[1]: True for definition in gate_module._EXPECTED_ASSERTIONS.values()}


def _run_bundles() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "run_id": f"run-20260828T00000{index}Z-000000000000000{index}",
            "path": f"runs/run-20260828T00000{index}Z-000000000000000{index}",
        }
        for index in range(1, 4)
    )


def _patch_gate_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    validator: Any,
) -> list[tuple[str, ...]]:
    suite_calls: list[tuple[str, ...]] = []

    def passing_suite(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        suite_calls.append(tuple(kwargs["tests"]))
        return {
            "passed": True,
            "tests": gate_module._EXPECTED_CONTRACT_TEST_COUNT,
        }

    monkeypatch.setattr(
        gate_module,
        "_run_helper",
        lambda *_args: {
            "passed": True,
            "exit_code": 0,
            "command": ["{python}", "{helper}"],
            "protocol_valid": True,
        },
    )
    monkeypatch.setattr(
        gate_module,
        "_run_pytest_suite",
        passing_suite,
    )
    monkeypatch.setattr(gate_module, "validate_persisted_frontier", validator)
    monkeypatch.setattr(gate_module, "_acceptance_binding", lambda: {})
    monkeypatch.setattr(
        gate_module,
        "validated_run_bundle",
        lambda _destination, _parent, bundle, **_kwargs: (dict(bundle), Path("manifest")),
    )
    return suite_calls


def _assert_no_passed_verification_report(evidence_dir: Path) -> None:
    report_path = evidence_dir / gate_module.VERIFICATION_REPORT
    if report_path.exists():
        assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is False


def test_gate_never_leaves_a_passed_report_when_final_validation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence_dir = tmp_path / "evidence"
    repository.mkdir()
    evidence_dir.mkdir()
    bundles = _run_bundles()
    calls = 0

    def validate(_repository: Path, _evidence_dir: Path):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _passed_checks(), bundles
        raise DefenseFrontierValidationError("late semantic validation failed")

    suite_calls = _patch_gate_dependencies(monkeypatch, validate)

    outcome = gate_module.run_gate_04(
        _locked_gate(),
        evidence_dir,
        repository_root=repository,
    )

    assert calls == 2
    assert suite_calls == [gate_module._CONTRACT_TEST_SELECTION]
    assert outcome.status == "failed"
    assert outcome.proofs == ()
    assert "late semantic validation failed" in str(outcome.failure_reason)
    _assert_no_passed_verification_report(evidence_dir)


def test_gate_success_publishes_exact_proofs_and_passed_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence_dir = tmp_path / "evidence"
    repository.mkdir()
    evidence_dir.mkdir()
    bundles = _run_bundles()
    calls = 0

    def validate(_repository: Path, _evidence_dir: Path):
        nonlocal calls
        calls += 1
        return _passed_checks(), bundles

    suite_calls = _patch_gate_dependencies(monkeypatch, validate)

    outcome = gate_module.run_gate_04(
        _locked_gate(),
        evidence_dir,
        repository_root=repository,
    )

    assert calls == 2
    assert suite_calls == [gate_module._CONTRACT_TEST_SELECTION]
    assert outcome.status == "passed"
    assert outcome.failure_reason is None
    assert len(outcome.proofs) == 12
    assert {proof["status"] for proof in outcome.proofs} == {"passed"}
    assert len({proof["test_id"] for proof in outcome.proofs}) == 12
    assert {proof["assertion_ids"][0] for proof in outcome.proofs} == set(
        gate_module._EXPECTED_ASSERTIONS
    )
    verification = json.loads(
        (evidence_dir / gate_module.VERIFICATION_REPORT).read_text(encoding="utf-8")
    )
    assert verification["passed"] is True
    assert verification["checks"] == _passed_checks()
    assert verification["run_ids"] == [bundle["run_id"] for bundle in bundles]

    count_drift_dir = tmp_path / "count-drift"
    count_drift_dir.mkdir()
    monkeypatch.setattr(
        gate_module,
        "_run_pytest_suite",
        lambda *_args, **_kwargs: {
            "passed": True,
            "tests": gate_module._EXPECTED_CONTRACT_TEST_COUNT - 1,
        },
    )
    count_drift = gate_module.run_gate_04(
        _locked_gate(),
        count_drift_dir,
        repository_root=repository,
    )
    assert count_drift.status == "failed"
    assert count_drift.proofs == ()
    assert "focused regression suite failed or skipped" in str(count_drift.failure_reason)


def test_gate_04_is_registered_in_product_gate_dispatcher() -> None:
    assert product_gates._WORKFLOWS["GATE-04"] is product_gates._gate_04_workflow


@pytest.mark.parametrize(
    "issue",
    [
        r"validation failed at C:\Users\Example User\Private Runs\result.json",
        r"validation failed at \\bluefire-server\Private Share\result.json",
        "validation failed at /home/example-user/private runs/result.json",
    ],
)
def test_bounded_issue_fully_redacts_absolute_private_paths(issue: str) -> None:
    assert gate_module._bounded_issue(issue) == "validation failure [private-path-redacted]"
