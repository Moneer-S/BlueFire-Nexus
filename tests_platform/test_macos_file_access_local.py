"""Local setup policy tests; no privileged macOS operation is performed here."""

from __future__ import annotations

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import macos_file_access_local as local
from bluefire import macos_file_access_peer as peer


def test_fixed_local_config_is_no_model_approved_and_exactly_scoped():
    config = local._fixed_config()

    assert config.mode.value == "execute"
    assert config.ai.autonomy.value == "off"
    assert not config.ai.enabled
    assert config.active_profile == "macos-file-access.v1"
    assert len(config.runner_profiles) == 1
    profile = config.runner_profiles[0]
    assert profile.platforms == ("macos",)
    assert profile.enabled_actions == local._SUPPORTED_METHODS
    assert profile.approval_required
    assert profile.network_allowlist == ()
    assert not profile.secrets
    assert not profile.native_tool_installations


@pytest.mark.parametrize("version", [(3, 10, 16), (3, 11, 18)])
def test_supervisor_platform_gate_accepts_only_legacy_and_qualification_versions(
    monkeypatch, version
):
    monkeypatch.setattr(local.sys, "platform", "darwin")
    monkeypatch.setattr(local.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(local.sys, "implementation", SimpleNamespace(name="cpython"))
    monkeypatch.setattr(local.sys, "version_info", version)
    monkeypatch.setattr(local.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "getgid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "getegid", lambda: 0, raising=False)
    monkeypatch.setattr(peer, "_supported_runtime", lambda: True)

    local._platform_gate()


@pytest.mark.parametrize("version", [(3, 10, 17), (3, 11, 9), (3, 11, 17), (3, 11, 19)])
def test_supervisor_platform_gate_rejects_unqualified_python_patches(monkeypatch, version):
    monkeypatch.setattr(local.sys, "platform", "darwin")
    monkeypatch.setattr(local.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(local.sys, "implementation", SimpleNamespace(name="cpython"))
    monkeypatch.setattr(local.sys, "version_info", version)
    monkeypatch.setattr(local.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "getgid", lambda: 0, raising=False)
    monkeypatch.setattr(local.os, "getegid", lambda: 0, raising=False)
    monkeypatch.setattr(peer, "_supported_runtime", lambda: True)

    with pytest.raises(RuntimeError, match="root-owned CPython"):
        local._platform_gate()


def test_temporary_numeric_id_recipe_avoids_registered_and_running_ids(monkeypatch):
    monkeypatch.setattr(local, "_registered_ids", lambda: ({60000, 60004}, {60001, 60005}))
    monkeypatch.setattr(local, "_active_ids", lambda: ({60002}, {60003}))
    monkeypatch.setattr(local.secrets, "randbelow", lambda _limit: 0)

    owner, reader = local.temporary_credentials()

    assert owner["effective_uid"] == 60006
    assert reader["effective_uid"] == 60007
    assert owner["effective_uid"] != reader["effective_uid"]
    assert owner["effective_gid"] == reader["effective_gid"] == 60008
    assert owner["groups"] == reader["groups"] == [60008]


def test_temporary_numeric_id_recipe_fails_when_no_unassigned_range_remains(monkeypatch):
    monkeypatch.setattr(local, "_IDENTITY_MIN", 60000)
    monkeypatch.setattr(local, "_IDENTITY_MAX", 60001)
    monkeypatch.setattr(local, "_registered_ids", lambda: (set(), set()))
    monkeypatch.setattr(local, "_active_ids", lambda: (set(), set()))

    with pytest.raises(RuntimeError, match="No unused temporary numeric identities"):
        local.temporary_credentials()


def test_shutdown_projection_keeps_generated_resource_and_does_not_claim_cleanup():
    result = local._shutdown_projection(
        {
            "host_closed": True,
            "descriptor_cleanup_unknown": False,
            "creation_unknown": False,
            "whole_setup_cleanup_proven": False,
            "fixture_removed": False,
        },
        {"workers_closed": True, "namespace_handles_closed": True, "fixture_removed": False},
        {"generation": "file-generation-" + "a" * 32, "mode": "0600"},
    )

    assert result["status"] == "stopped_cleanly"
    assert result["generated_resource"] == {
        "generation": "file-generation-" + "a" * 32,
        "mode_at_shutdown": "0600",
        "state_at_shutdown": "owner_only_hardened",
        "resource_retained": True,
        "fixture_removed": False,
        "whole_setup_cleanup_proven": False,
    }
    assert result["workspace_retained"] is True
    assert result["identity_accounts_created"] is False


def test_shutdown_projection_does_not_hide_host_cleanup_uncertainty():
    result = local._shutdown_projection(
        {
            "host_closed": True,
            "descriptor_cleanup_unknown": True,
            "creation_unknown": False,
        },
        {"workers_closed": True, "namespace_handles_closed": True},
        {"generation": "file-generation-" + "a" * 32, "mode": "0600"},
    )

    assert result["status"] == "cleanup_unknown"
    assert result["generated_resource"]["resource_retained"] is True
    assert result["generated_resource"]["whole_setup_cleanup_proven"] is False


def test_shutdown_binding_uses_only_a_fresh_creator_observation():
    class FailingCreator:
        def review_context(self, _operation):
            raise RuntimeError("creator state is unknown")

    class CurrentCreator:
        def review_context(self, operation):
            assert operation == "baseline"
            return {"binding": {"generation": "file-generation-current", "mode": "0600"}}

    assert local._fresh_shutdown_binding(None) is None
    assert local._fresh_shutdown_binding(FailingCreator()) is None
    assert local._fresh_shutdown_binding(CurrentCreator()) == {
        "generation": "file-generation-current",
        "mode": "0600",
    }


def test_interpreter_is_custodied_before_hash_and_subprocess_probe(monkeypatch, tmp_path):
    calls = []

    class Validation:
        def _parents(self, path):
            calls.append(("parents", path))

        def _protected_file(self, path, digest):
            calls.append(("protected", path, digest))

    executable = tmp_path / "python"
    monkeypatch.setattr(local, "_hash_file", lambda path: calls.append(("hash", path)) or "a" * 64)

    digest = local._verified_interpreter(executable, Validation())

    assert digest == "a" * 64
    assert calls == [
        ("parents", tmp_path),
        ("hash", executable),
        ("protected", executable, "a" * 64),
    ]


def test_reservation_file_requires_private_single_link_regular_file(monkeypatch):
    private = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1, st_size=0)
    monkeypatch.setattr(
        local.os.path, "samestat", lambda left, right: left is private and right is private
    )

    assert local._reservation_file_matches(private, private)
    assert not local._reservation_file_matches(
        SimpleNamespace(**{**vars(private), "st_mode": stat.S_IFREG | 0o620}), private
    )


def test_setup_reservation_serializes_launch_and_refuses_retained_state(monkeypatch, tmp_path):
    held = set()

    class FakeFcntl:
        LOCK_EX = 2
        LOCK_NB = 4
        LOCK_UN = 8

        @staticmethod
        def flock(descriptor, operation):
            identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
            if operation == (FakeFcntl.LOCK_EX | FakeFcntl.LOCK_NB):
                if identity in held:
                    raise BlockingIOError("already locked")
                held.add(identity)
            elif operation == FakeFcntl.LOCK_UN:
                held.discard(identity)

    monkeypatch.setitem(sys.modules, "fcntl", FakeFcntl)
    monkeypatch.setattr(local, "WORKSPACE_PARENT", tmp_path)
    monkeypatch.setattr(local, "_reservation_file_matches", lambda _descriptor, _path: True)
    from bluefire import macos_file_access_workspace_validation as validation

    monkeypatch.setattr(validation, "_descriptor_security", lambda _descriptor: None)
    first = local._acquire_setup_reservation()
    try:
        with pytest.raises(RuntimeError, match="Another protected macOS setup session"):
            local._acquire_setup_reservation()
    finally:
        local._release_setup_reservation(first)

    (tmp_path / "retained-generation").mkdir()
    with pytest.raises(RuntimeError, match="retained macOS workspace"):
        local._acquire_setup_reservation()
    assert (tmp_path / "retained-generation").is_dir()


def test_directory_validation_uses_workspace_validation_keyword_contract(monkeypatch, tmp_path):
    from bluefire import macos_file_access_workspace_validation as validation

    calls = []

    def validate(path, *, owner=0):
        calls.append((path, owner))

    monkeypatch.setattr(validation, "_directory", validate)

    local._validate_directory(tmp_path, owner=60001)

    assert calls == [(tmp_path, 60001)]


def test_workspace_parent_uses_validation_parent_api(monkeypatch, tmp_path):
    from bluefire import macos_file_access_workspace_validation as validation

    root = tmp_path / "protected-workspaces"
    root.mkdir()
    monkeypatch.setattr(local, "WORKSPACE_PARENT", root)
    monkeypatch.setattr(validation, "_parents", lambda path: calls.append(("parents", path)))
    monkeypatch.setattr(
        validation, "_directory", lambda path, *, owner=0: calls.append(("directory", path, owner))
    )
    calls = []
    monkeypatch.setattr(local.stat, "S_IMODE", lambda _mode: 0o711)

    local._ensure_workspace_parent()

    assert calls == [("parents", root.parent), ("directory", root, 0)]


def test_cli_supervisor_requires_fixed_setup_and_rejects_custom_state(monkeypatch):
    calls = []
    monkeypatch.setattr(
        local,
        "run_local_supervisor",
        lambda **kwargs: calls.append(kwargs) or {"status": "stopped_cleanly"},
    )
    args = cli._parser().parse_args(
        [
            "runner",
            "macos-file-setup",
            "--confirm-create-generated-workspace",
            "--port",
            "8123",
            "--no-browser",
        ]
    )

    result = cli._execute(args)

    assert result == {"status": "stopped_cleanly"}
    assert calls == [{"port": 8123, "no_browser": True}]

    args.config = "caller-config.yaml"
    with pytest.raises(ValueError, match="fixed protected product state"):
        cli._execute(args)
