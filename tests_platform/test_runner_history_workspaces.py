"""Historical workspace inspection uses local fixtures, never a native runner."""

from __future__ import annotations

import os
import stat
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import runner_history_documents as documents
from bluefire.config import load_config
from bluefire.registry import load_builtin_registry
from bluefire.runner_bootstrap import current_platform
from bluefire.runner_contracts import (
    build_execution_manifest,
    build_runner_profile,
    seal_manifest,
    seal_profile,
)
from bluefire.runner_lifecycle import ManagedRunnerLifecycle, RunnerLifecycleError
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash

ROOT = Path(__file__).resolve().parents[1]
APPROVAL_ID = "approval-" + "a" * 32


@dataclass
class Fixture:
    root: Path
    workspace: Path
    manifest: dict[str, Any]
    profile: dict[str, Any]

    def validate(self) -> documents.HistoricalWorkspace:
        return documents.validate_history_documents(
            self.manifest, self.profile, platform=current_platform(), sandbox=self.root
        )

    def move_profile(self, target: Path) -> None:
        self.profile = seal_profile({**self.profile, "sandbox_root": str(target)})
        self.manifest = seal_manifest(
            {**self.manifest, "policy_digest": self.profile["policy_digest"]}
        )


@pytest.fixture
def workspace(tmp_path: Path) -> Fixture:
    root = tmp_path / "sandbox"
    root.mkdir()
    root = root.resolve(strict=True)
    approval = {
        "approval_id": APPROVAL_ID,
        "approved_by": "local-test-reviewer",
        "approved_at": "2026-08-25T11:59:00Z",
        "expires_at": "2026-08-25T12:05:00Z",
    }
    selected = BlueFireService._isolated_execution_sandbox(root, approval)
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    configured = next(item for item in config.runner_profiles if item.id == "sandbox-execute.v1")
    profile = build_runner_profile(configured, sandbox_root=selected, platform=current_platform())
    action = load_builtin_registry().get_action("endpoint.discovery.system.v1")
    manifest = build_execution_manifest(
        run_id="run-20260825T120000Z-0123456789abcdef",
        step_id="inspect_system",
        behavior_id=action.id,
        action=action,
        runner_profile=profile,
        params={},
        filesystem_scope=(),
        approval_record=approval,
        now=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
    )
    binding = {
        "approval_id": APPROVAL_ID,
        "profile_id": configured.id,
        "workspace_path": str(selected),
    }
    assert (
        BlueFireService._bound_execution_workspace(
            {**binding, "workspace_digest": content_hash(binding)},
            approval_id=APPROVAL_ID,
            profile_id=configured.id,
        )
        == selected
    )
    return Fixture(root, selected, manifest, profile)


def test_service_workspace_is_recognized_without_renewing_expired_history(workspace):
    original = canonical_json_bytes({"manifest": workspace.manifest, "profile": workspace.profile})
    snapshot = workspace.validate()
    assert snapshot.path == workspace.workspace
    snapshot.recheck()
    assert snapshot.binding()["path"] == str(workspace.workspace)
    altered = snapshot.binding()
    altered["directories"].clear()
    assert snapshot.binding()["directories"]
    assert (
        canonical_json_bytes({"manifest": workspace.manifest, "profile": workspace.profile})
        == original
    )
    assert workspace.manifest["approval"]["expires_at"] == "2026-08-25T12:05:00Z"


def test_legacy_exact_root_retains_optional_approval_behavior(workspace):
    workspace.move_profile(workspace.root)
    workspace.manifest = seal_manifest({**workspace.manifest, "approval": None})
    assert workspace.validate().path == workspace.root


@pytest.mark.parametrize(
    "kind",
    [
        "sibling",
        "prefix",
        "nested",
        "ordinary_child",
        "wrong_parent",
        "short_id",
        "uppercase",
        "relative",
        "missing",
    ],
)
def test_supported_shape_never_accepts_arbitrary_descendants(workspace, kind):
    targets = {
        "sibling": workspace.root.parent / "other" / ".bluefire-executions" / APPROVAL_ID,
        "prefix": workspace.root.with_name("sandbox-other") / ".bluefire-executions" / APPROVAL_ID,
        "nested": workspace.workspace / "nested",
        "ordinary_child": workspace.root / APPROVAL_ID,
        "wrong_parent": workspace.root / "other-executions" / APPROVAL_ID,
        "short_id": workspace.workspace.parent / "approval-short",
        "uppercase": workspace.workspace.parent / ("approval-" + "A" * 32),
        "relative": Path(".bluefire-executions") / APPROVAL_ID,
        "missing": workspace.workspace.parent / ("approval-" + "b" * 32),
    }
    target = targets[kind]
    if kind not in {"relative", "missing"}:
        target.mkdir(parents=True, exist_ok=True)
    workspace.move_profile(target)
    with pytest.raises((ValueError, OSError)):
        workspace.validate()


@pytest.mark.parametrize(
    "kind",
    [
        "no_approval",
        "approval_hash",
        "bad_date",
        "reversed_dates",
        "scope",
        "profile_identity",
        "runner_identity",
        "policy_digest",
    ],
)
def test_invalid_history_identity_and_approval_are_still_refused(workspace, kind):
    manifest = deepcopy(workspace.manifest)
    if kind == "no_approval":
        manifest = seal_manifest({**manifest, "approval": None})
    elif kind == "approval_hash":
        manifest["approval"]["request_hash"] = "sha256:" + "f" * 64
    elif kind == "bad_date":
        manifest["approval"]["expires_at"] = "not-a-date"
    elif kind == "reversed_dates":
        manifest["approval"]["expires_at"] = "2026-08-25T11:58:00Z"
        manifest = seal_manifest(manifest)
    elif kind == "scope":
        manifest["target_scope"]["filesystem"] = ["outside-original-review"]
    elif kind == "profile_identity":
        manifest = seal_manifest({**manifest, "runner_profile_id": "another-profile.v1"})
    elif kind == "runner_identity":
        manifest = seal_manifest({**manifest, "runner_id": "another-runner.v1"})
    else:
        manifest = seal_manifest({**manifest, "policy_digest": "sha256:" + "f" * 64})
    workspace.manifest = manifest
    with pytest.raises(ValueError):
        workspace.validate()


@pytest.mark.parametrize("suffix", ["/", "/.", "/../" + APPROVAL_ID])
def test_raw_profile_path_must_match_the_canonical_service_binding(workspace, suffix):
    workspace.profile = seal_profile(
        {**workspace.profile, "sandbox_root": str(workspace.workspace) + suffix}
    )
    workspace.manifest = seal_manifest(
        {**workspace.manifest, "policy_digest": workspace.profile["policy_digest"]}
    )
    with pytest.raises(ValueError):
        workspace.validate()


@pytest.mark.parametrize("reason", ["expired", "scope"])
def test_well_formed_observed_refusal_remains_history_without_new_authority(workspace, reason):
    from bluefire.runner_transport import validate_stored_execute_result
    from tests_platform.test_authenticated_runner_transport import _result

    if reason == "expired":
        workspace.manifest["approval"]["expires_at"] = "2026-08-25T11:59:30Z"
    else:
        workspace.manifest["target_scope"]["filesystem"] = ["outside-profile-scope"]
    workspace.manifest = seal_manifest(workspace.manifest)
    result = _result(workspace.manifest, workspace.profile)
    result.update(
        status="control_blocked",
        error={
            "code": "approval_invalid" if reason == "expired" else "target_scope_blocked",
            "message": "Authored refusal fixture",
        },
    )
    before = canonical_json_bytes(
        {"manifest": workspace.manifest, "profile": workspace.profile, "result": result}
    )
    workspace.validate().recheck()
    assert (
        validate_stored_execute_result(result, workspace.manifest, workspace.profile)["status"]
        == "control_blocked"
    )
    assert (
        canonical_json_bytes(
            {"manifest": workspace.manifest, "profile": workspace.profile, "result": result}
        )
        == before
    )


@pytest.mark.parametrize("component", ["sandbox", "execution_parent", "workspace"])
def test_linked_ancestors_are_refused_even_when_final_target_is_canonical(workspace, component):
    target = {
        "sandbox": workspace.root,
        "execution_parent": workspace.workspace.parent,
        "workspace": workspace.workspace,
    }[component]
    displaced = target.with_name(target.name + "-original")
    target.rename(displaced)
    try:
        target.symlink_to(displaced, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symlinks unavailable: {type(error).__name__}")
    with pytest.raises((ValueError, OSError)):
        workspace.validate()


@pytest.mark.parametrize(
    "component",
    ["sandbox", "execution_parent", "workspace", "receipt_parent", "receipts", "receipt-commits"],
)
def test_review_recheck_rejects_directory_replacement(workspace, component):
    for name in ("receipts", "receipt-commits"):
        (workspace.workspace / ".bluefire" / name).mkdir(parents=True)
    snapshot = workspace.validate()
    target = {
        "sandbox": workspace.root,
        "execution_parent": workspace.workspace.parent,
        "workspace": workspace.workspace,
        "receipt_parent": workspace.workspace / ".bluefire",
        "receipts": workspace.workspace / ".bluefire" / "receipts",
        "receipt-commits": workspace.workspace / ".bluefire" / "receipt-commits",
    }[component]
    target.rename(target.with_name(target.name + "-original"))
    target.mkdir()
    with pytest.raises((ValueError, OSError)):
        snapshot.recheck()


@pytest.mark.parametrize("initially_present", [False, True])
def test_receipt_obligation_and_late_marker_cannot_hide_in_unchanged_workspace(
    workspace, initially_present
):
    receipts = workspace.workspace / ".bluefire" / "receipts"
    if initially_present:
        receipts.mkdir(parents=True)
    snapshot = workspace.validate()
    ManagedRunnerLifecycle._require_no_receipt_obligations(snapshot.path)
    snapshot.recheck()
    receipts.mkdir(parents=True, exist_ok=True)
    marker = receipts / "authored-obligation.json"
    marker.write_text("{}")
    with pytest.raises(RunnerLifecycleError, match="receipt cleanup obligations"):
        ManagedRunnerLifecycle._require_no_receipt_obligations(snapshot.path)
    with pytest.raises(ValueError):
        snapshot.recheck()
    assert marker.read_text() == "{}"


def test_capture_and_recheck_do_not_harden_permissions_or_write_state(workspace, monkeypatch):
    receipts = workspace.workspace / ".bluefire" / "receipts"
    receipts.mkdir(parents=True)
    paths = [
        workspace.root,
        workspace.workspace.parent,
        workspace.workspace,
        receipts.parent,
        receipts,
    ]
    before = {
        path: (path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
        for path in paths
    }
    if os.name != "nt":

        def no_permissions(*_args, **_kwargs):
            raise AssertionError("history inspection must not chmod")

        monkeypatch.setattr(os, "fchmod", no_permissions)
    else:
        original = documents._windows_open_descriptor

        def readonly(path, **kwargs):
            assert kwargs["write_dac"] is False
            assert not kwargs.get("write", False) and not kwargs.get("delete", False)
            return original(path, **kwargs)

        monkeypatch.setattr(documents, "_windows_open_descriptor", readonly)
    workspace.validate().recheck()
    assert before == {
        path: (path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
        for path in paths
    }


def test_full_native_identity_is_not_truncated_to_stat_device(monkeypatch):
    full = (0xFEDCBA9812345678, 0xFEDCBA9812345678FEDCBA9812345678)
    monkeypatch.setattr(documents, "descriptor_identity", lambda _fd, **_kwargs: full)
    monkeypatch.setattr(documents, "_descriptor_mount_identity", lambda _fd: None)
    monkeypatch.setattr(
        documents,
        "os",
        SimpleNamespace(
            fstat=lambda _fd: SimpleNamespace(
                st_mode=stat.S_IFDIR, st_uid=0, st_gid=0, st_mtime_ns=1, st_ctime_ns=2
            )
        ),
    )
    assert documents._directory_state(17)[:2] == full


def test_mount_change_cannot_reuse_same_file_identity(workspace, monkeypatch):
    monkeypatch.setattr(documents, "_descriptor_mount_identity", lambda _fd: 11)
    snapshot = workspace.validate()
    monkeypatch.setattr(documents, "_descriptor_mount_identity", lambda _fd: 12)
    with pytest.raises(ValueError):
        snapshot.recheck()


def test_unrelated_parent_changes_do_not_invalidate_workspace(workspace):
    snapshot = workspace.validate()
    (workspace.root.parent / "unrelated-file.txt").write_text("benign unrelated activity")
    snapshot.recheck()
