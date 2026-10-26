"""Local setup policy tests; no privileged macOS operation is performed here."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import macos_file_access_contract as namespace_contract
from bluefire import macos_file_access_creator as namespace_creator
from bluefire import macos_file_access_local as local
from bluefire import macos_file_access_namespace as namespace
from bluefire import macos_file_access_peer as peer
from bluefire import macos_file_access_worker as namespace_worker
from bluefire import macos_file_access_workspace_validation as validation


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


def test_setup_failure_carries_only_a_fixed_operation_stage():
    with pytest.raises(local.MacOSSetupFailure) as caught:
        local._at_setup_stage(
            "native_runner_initialization",
            lambda: (_ for _ in ()).throw(
                RuntimeError("The protected macOS setup is unavailable.")
            ),
        )

    assert str(caught.value) == "The protected macOS setup is unavailable."
    assert caught.value.safe_setup_stage == "native_runner_initialization"
    with pytest.raises(ValueError, match="unknown macOS setup diagnostic stage"):
        local._at_setup_stage("/private/path", lambda: None)


def test_package_import_failure_site_uses_only_fixed_code_and_bounded_offsets():
    def raise_on_relative_package_root():
        validation._parents(Path("relative/private-root"))

    with pytest.raises(RuntimeError) as caught:
        raise_on_relative_package_root()
    diagnostic = local._package_import_failure_site(
        caught.value, raise_on_relative_package_root.__code__, validation
    )

    assert diagnostic == ("package_ancestor_path", 1)
    assert str(Path("relative/private-root")) not in json.dumps(diagnostic)

    with pytest.raises(local.MacOSSetupFailure) as wrapped:
        local._at_setup_stage(
            "package_import_custody",
            raise_on_relative_package_root,
            failure_site=lambda exc: local._package_import_failure_site(
                exc, raise_on_relative_package_root.__code__, validation
            ),
        )
    assert wrapped.value.safe_setup_site == "package_ancestor_path"
    assert wrapped.value.safe_setup_offset == 1

    ranges = local._package_import_site_ranges(raise_on_relative_package_root.__code__, validation)
    matched, out_of_bounds = local._package_import_site_for_frame(
        validation._parents.__code__, local._MAX_PACKAGE_SETUP_OFFSET + 1, ranges
    )
    unknown_matched, unknown = local._package_import_site_for_frame(
        (lambda: None).__code__, 1, ranges
    )
    assert matched and out_of_bounds is None
    assert not unknown_matched and unknown is None


def test_package_import_failure_site_prefers_deepest_known_frame():
    def inventory_package_imports():
        validation._parents(Path("relative/private-root"))

    with pytest.raises(RuntimeError) as caught:
        inventory_package_imports()

    assert local._package_import_failure_site(
        caught.value, inventory_package_imports.__code__, validation
    ) == ("package_ancestor_path", 1)


def test_namespace_creation_failure_site_is_fixed_stage_scoped_and_deepest():
    def namespace_create():
        raise RuntimeError("private path and local detail")

    def creator_create():
        namespace_create()

    creator = SimpleNamespace(
        MacOSFileAccessCreator=SimpleNamespace(create=SimpleNamespace(__func__=creator_create))
    )
    namespace = SimpleNamespace(
        SealedMacOSNamespace=SimpleNamespace(
            create=SimpleNamespace(__func__=lambda: None),
            _open_directory=lambda: None,
            _create=namespace_create,
            binding=lambda: None,
        ),
        _root=lambda: None,
        _directory=lambda: None,
        _security=lambda: None,
        _validate_darwin_descriptor_security=lambda: None,
    )
    contract = SimpleNamespace(validate_credentials=lambda: None)
    worker = SimpleNamespace(
        MacOSFileAccessWorker=SimpleNamespace(start=lambda: None, _guard=lambda: None)
    )

    with pytest.raises(RuntimeError) as caught:
        creator_create()

    diagnostic = local._namespace_creation_failure_site(
        caught.value, creator, namespace, contract, worker
    )
    assert diagnostic is not None
    assert diagnostic[0] == "namespace_sealed_resource"
    assert (
        diagnostic[1]
        in local.MACOS_SETUP_DIAGNOSTIC_SITE_OFFSETS["namespace_creation"][diagnostic[0]]
    )
    assert str(Path("private path and local detail")) not in json.dumps(diagnostic)

    failure = local.MacOSSetupFailure(
        "namespace_creation",
        "The protected macOS setup is unavailable.",
        setup_site="namespace_worker_start",
        setup_offset=121,
    )
    assert failure.safe_setup_stage == "namespace_creation"
    assert failure.safe_setup_site == "namespace_worker_start"
    assert failure.safe_setup_offset == 121
    with pytest.raises(ValueError, match="unknown macOS setup diagnostic site"):
        local.MacOSSetupFailure(
            "namespace_creation", "safe", setup_site="namespace_worker_start", setup_offset=122
        )
    with pytest.raises(ValueError, match="unknown macOS setup diagnostic site"):
        local.MacOSSetupFailure(
            "namespace_creation", "safe", setup_site="namespace_worker_start", setup_offset=True
        )
    with pytest.raises(ValueError, match="unknown macOS setup diagnostic site"):
        local.MacOSSetupFailure(
            "package_import_custody", "safe", setup_site="namespace_worker_start", setup_offset=121
        )


@pytest.mark.parametrize(
    ("wall_ms", "monotonic_ns", "last_clock", "site", "offset"),
    [
        (1_000, 4_000, (0, 0), "namespace_worker_guard_wall_window", 8),
        (2_000, 5_000, (0, 0), "namespace_worker_guard_deadline", 10),
        (2_000, 4_000, (2_001, 0), "namespace_worker_guard_wall_clock_order", 12),
        (2_000, 4_000, (0, 4_001), "namespace_worker_guard_monotonic_order", 14),
    ],
)
def test_namespace_worker_guard_refusal_has_fixed_site_diagnostic(
    monkeypatch, wall_ms, monotonic_ns, last_clock, site, offset
):
    owner = object.__new__(namespace_worker.MacOSFileAccessWorker)
    owner._binding = {
        "issued_at_ms": 1_500,
        "expires_at_ms": 3_000,
        "original_deadline_ns": 5_000,
    }
    owner._last_clock = last_clock
    monkeypatch.setattr(namespace_worker.time, "time_ns", lambda: wall_ms * 1_000_000)
    monkeypatch.setattr(namespace_worker, "darwin_clock_ns", lambda: monotonic_ns)

    with pytest.raises(namespace_contract.MacOSFileAccessContractError) as caught:
        owner._guard()

    diagnostic = local._namespace_creation_failure_site(
        caught.value, namespace_creator, namespace, namespace_contract, namespace_worker
    )
    assert diagnostic == (site, offset)
    assert diagnostic[0] in local.MACOS_SETUP_DIAGNOSTIC_SITE_OFFSETS["namespace_creation"]
    assert diagnostic[1] in local.MACOS_SETUP_DIAGNOSTIC_SITE_OFFSETS["namespace_creation"][site]


def test_setup_site_callback_failure_preserves_original_setup_error():
    def fail_operation():
        raise RuntimeError("original guarded failure")

    def fail_diagnostics(_exc):
        raise ValueError("private diagnostic detail")

    with pytest.raises(local.MacOSSetupFailure) as caught:
        local._at_setup_stage(
            "package_import_custody", fail_operation, failure_site=fail_diagnostics
        )

    assert str(caught.value) == "original guarded failure"
    assert caught.value.safe_setup_stage == "package_import_custody"
    assert not hasattr(caught.value, "safe_setup_site")


def test_cli_includes_setup_stage_only_for_typed_macos_setup_failure(monkeypatch):
    args = ["runner", "macos-file-setup", "--confirm-create-generated-workspace"]
    monkeypatch.setattr(
        cli,
        "_execute",
        lambda _args: (_ for _ in ()).throw(
            local.MacOSSetupFailure(
                "package_import_custody",
                "The protected macOS setup is unavailable.",
                setup_site="package_acl_policy",
                setup_offset=33,
            )
        ),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        result = cli.main(args)
    payload = json.loads(output.getvalue())

    assert result == 2
    assert payload == {
        "error": {
            "code": "command_failed",
            "message": "The protected macOS setup is unavailable.",
            "setup_stage": "package_import_custody",
            "setup_site": "package_acl_policy",
            "setup_offset": 33,
        }
    }

    monkeypatch.setattr(
        cli,
        "_execute",
        lambda _args: (_ for _ in ()).throw(
            local.MacOSSetupFailure(
                "namespace_creation",
                "The original sealed Darwin namespace is unavailable.",
                setup_site="namespace_worker_start",
                setup_offset=121,
            )
        ),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        result = cli.main(args)
    assert result == 2
    assert json.loads(output.getvalue()) == {
        "error": {
            "code": "command_failed",
            "message": "The original sealed Darwin namespace is unavailable.",
            "setup_stage": "namespace_creation",
            "setup_site": "namespace_worker_start",
            "setup_offset": 121,
        }
    }

    malformed = local.MacOSSetupFailure(
        "package_import_custody", "The protected macOS setup is unavailable."
    )
    malformed.safe_setup_site = "/private/var/db/private-workspace"
    malformed.safe_setup_offset = 999
    monkeypatch.setattr(cli, "_execute", lambda _args: (_ for _ in ()).throw(malformed))
    output = io.StringIO()
    with redirect_stdout(output):
        result = cli.main(args)
    assert result == 2
    assert json.loads(output.getvalue()) == {
        "error": {
            "code": "command_failed",
            "message": "The protected macOS setup is unavailable.",
            "setup_stage": "package_import_custody",
        }
    }

    monkeypatch.setattr(
        cli,
        "_execute",
        lambda _args: (_ for _ in ()).throw(RuntimeError("legacy command failure")),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        result = cli.main(args)
    assert result == 2
    assert json.loads(output.getvalue()) == {
        "error": {"code": "command_failed", "message": "legacy command failure"}
    }
