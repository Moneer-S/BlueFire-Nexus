"""Fresh-user bootstrap storage checks; no native runner execution is involved."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

import bluefire.runner_state_directory as state_directory
from bluefire.runner_bootstrap import managed_product_root
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from tests_platform.runner_lifecycle_host_helper import ProcessTestSecretProvider
from tests_platform.test_runner_lifecycle import _fake_bootstrap

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX default state directories")


@pytest.fixture
def fresh_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "new-user"
    home.mkdir(mode=0o750)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    return home


def _manager(root: Path) -> ManagedRunnerLifecycle:
    return ManagedRunnerLifecycle(
        root,
        bootstrap_factory=_fake_bootstrap,
        secret_provider=ProcessTestSecretProvider(),
    )


def test_fresh_user_bootstrap_creates_default_state_parents(fresh_home: Path) -> None:
    root = managed_product_root()
    home_mode = stat.S_IMODE(fresh_home.stat().st_mode)
    manager = _manager(root)
    assert manager.status()["state"] == "unbootstrapped"
    assert not (fresh_home / ".local").exists()

    result = manager.bootstrap(allowed_profile_ids=("sandbox-execute.v1",))

    assert result["state"] == "stopped"
    assert stat.S_IMODE(fresh_home.stat().st_mode) == home_mode
    assert manager.root_marker_path.is_file()
    for directory in (fresh_home / ".local", root.parent, root):
        assert directory.is_dir()
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert directory.stat().st_uid == os.getuid()


def test_existing_state_ancestor_permissions_and_contents_are_preserved(fresh_home: Path) -> None:
    local = fresh_home / ".local"
    local.mkdir(mode=0o755)
    sentinel = local / "user-owned.txt"
    sentinel.write_bytes(b"unchanged")
    before = local.stat()

    manager = _manager(managed_product_root())
    manager.bootstrap(allowed_profile_ids=("sandbox-execute.v1",))

    assert stat.S_IMODE(local.stat().st_mode) == stat.S_IMODE(before.st_mode)
    assert local.stat().st_ino == before.st_ino
    assert sentinel.read_bytes() == b"unchanged"


def test_custom_root_still_requires_existing_parent(fresh_home: Path) -> None:
    root = fresh_home / "custom-missing" / "runner"
    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        _manager(root).bootstrap(allowed_profile_ids=("sandbox-execute.v1",))
    assert not root.parent.exists()


def test_explicit_xdg_state_directory_can_be_initialized(
    fresh_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = fresh_home / "private-state" / "nested"
    monkeypatch.setenv("XDG_STATE_HOME", str(base))
    _manager(managed_product_root()).bootstrap(allowed_profile_ids=("sandbox-execute.v1",))
    assert (base / "bluefire-nexus").is_dir()
    assert stat.S_IMODE(base.stat().st_mode) == 0o700


@pytest.mark.parametrize("dangling", [False, True])
def test_linked_default_ancestor_is_refused_without_target_writes(
    fresh_home: Path, tmp_path: Path, dangling: bool
) -> None:
    outside = tmp_path / "outside"
    if not dangling:
        outside.mkdir()
    (fresh_home / ".local").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        _manager(managed_product_root()).bootstrap(allowed_profile_ids=("sandbox-execute.v1",))
    assert not (outside / "state").exists()


def test_group_writable_creation_parent_is_refused(fresh_home: Path) -> None:
    local = fresh_home / ".local"
    local.mkdir()
    local.chmod(0o770)
    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        _manager(managed_product_root()).bootstrap(allowed_profile_ids=("sandbox-execute.v1",))
    assert stat.S_IMODE(local.stat().st_mode) == 0o770
    assert not (local / "state").exists()


def test_parent_replacement_during_creation_is_detected(
    fresh_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = fresh_home / ".local"
    local.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = os.mkdir
    replaced = False

    def replace_parent(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        nonlocal replaced
        if path == "state" and dir_fd is not None and not replaced:
            replaced = True
            local.rename(fresh_home / ".local-retained")
            local.symlink_to(outside, target_is_directory=True)
        original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(state_directory.os, "mkdir", replace_parent)
    with pytest.raises(RunnerLifecycleError, match="unavailable or unsafe"):
        _manager(managed_product_root()).bootstrap(allowed_profile_ids=("sandbox-execute.v1",))
    assert replaced
    assert not (outside / "state").exists()
    assert not (fresh_home / ".local-retained" / "state" / "bluefire-nexus").exists()


def test_competing_default_directory_creation_is_validated_and_reused(
    fresh_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_mkdir = os.mkdir

    def competing_mkdir(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        original_mkdir(path, mode, dir_fd=dir_fd)
        if dir_fd is not None:
            raise FileExistsError("competing bootstrap created this directory")

    monkeypatch.setattr(state_directory.os, "mkdir", competing_mkdir)
    manager = _manager(managed_product_root())
    assert manager.bootstrap(allowed_profile_ids=("sandbox-execute.v1",))["state"] == "stopped"
    assert manager.root_marker_path.is_file()


def test_creation_parent_owned_by_another_user_is_refused(
    fresh_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_uid = os.getuid()
    monkeypatch.setattr(state_directory.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(OSError, match="not controlled by this user"):
        state_directory.prepare_default_managed_root(managed_product_root())
    assert not (fresh_home / ".local").exists()
