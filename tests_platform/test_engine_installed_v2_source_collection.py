"""A stopped V2 worker can retain or honestly decline its saved run."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

import bluefire.engine_installed_v2_source_collection as source_module
from bluefire.engine_installed_v2_authority import InstalledStrixV2ActivationReceipt
from bluefire.engine_installed_v2_source_collection import (
    InstalledStrixV2SourceCollection,
    InstalledStrixV2SourceCollectionError,
    SourceCollectionTerminalReceipt,
)
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
WORKSPACE_FACT = {"device": 1, "inode": 2, "mode": 0o500, "uid": 1001, "gid": 1001}


def _digest(label: str) -> str:
    return content_hash({"test": label})


class _TerminalJournal:
    """Exercise the owner protocol; the protected SQLite journal has its own tests."""

    def __init__(self):
        self._rows = {}

    @property
    def source_identity_ref(self):
        return _digest("protected-journal")

    def retain_role_terminal(self, document):
        ref = document["receipt_ref"]
        if ref in self._rows and self._rows[ref] != document:
            raise ValueError("terminal retry changed")
        self._rows[ref] = document
        return ref

    def reopen_role_terminal(self, source_receipt_ref):
        return self._rows[source_receipt_ref]

    def reopen_latest_role_terminal(self, attempt_id, role, owner_ref):
        for row in self._rows.values():
            if (row["attempt_id"], row["role"], row["owner_ref"]) == (attempt_id, role, owner_ref):
                return row
        return None


def _native_receipts(*, reason="cancelled", exit_code=None):
    observed = {
        "schema_version": "bluefire.strix-worker-runtime-observation.v1",
        "attempt_id": ATTEMPT,
        "plan_ref": _digest("plan"),
        "workspace": WORKSPACE_FACT,
        "workspace_ref": content_hash(WORKSPACE_FACT),
    }
    observed["observation_ref"] = content_hash(observed)
    qualified = {
        "attempt_id": ATTEMPT,
        "resource_claim_ref": _digest("claim"),
        "plan_ref": observed["plan_ref"],
        "native_observation_ref": observed["observation_ref"],
    }
    qualified["receipt_ref"] = content_hash(qualified)
    terminal = {
        "schema_version": "bluefire.strix-worker-runtime-terminal.v1",
        "attempt_id": ATTEMPT,
        "resource_claim_ref": _digest("claim"),
        "plan_ref": observed["plan_ref"],
        "observation_ref": observed["observation_ref"],
        "qualified_receipt_ref": qualified["receipt_ref"],
        "workspace_ref": observed["workspace_ref"],
        "reason": reason,
        "exit_code": exit_code,
        "verified_absent": True,
        "worker_reaped": True,
        "cgroup_empty_and_removed": True,
        "endpoint_absent": True,
        "staging_root_absent": True,
        "identity_released": True,
        "workspace_fd_transferred": True,
    }
    terminal["receipt_ref"] = content_hash(terminal)
    return observed, qualified, terminal


class _Worker:
    def __init__(self, workspace_fd, observed, qualified, terminal):
        self.workspace_fd = workspace_fd
        self._observed = observed
        self.qualified_document = qualified
        self._terminal = terminal
        self.cleanup_uncertain = False

    def observed_document(self):
        return dict(self._observed)

    def terminal_receipt(self):
        return dict(self._terminal)


def _owner(tmp_path, monkeypatch, *, reason="cancelled", exit_code=None):
    monkeypatch.setattr(source_module, "_workspace_identity", lambda _fd: WORKSPACE_FACT)
    observed, qualified, terminal = _native_receipts(reason=reason, exit_code=exit_code)
    workspace = tmp_path / "workspace"
    # Windows cannot open a directory as a regular fd; the presence reader is
    # stubbed in these controller-contract tests. Linux exporter tests use a
    # real pinned directory descriptor.
    workspace.write_bytes(b"")
    fd = os.open(workspace, os.O_RDONLY)
    activation = object.__new__(InstalledStrixV2ActivationReceipt)
    binding_ref = _digest("actual-source-binding")
    for name, value in {
        "role_bindings": (("source_collection", binding_ref),),
        "claim_ref": _digest("claim"),
        "receipt_ref": _digest("activation"),
        "fixed_exec_receipt_ref": qualified["receipt_ref"],
        "controlled_launch_digest": _digest("launch"),
        "runtime_resolution_ref": _digest("runtime"),
    }.items():
        object.__setattr__(activation, name, value)
    transaction_ref = _digest("transaction")
    prelaunch_ref = _digest("prelaunch")
    prelaunch_binding_ref = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-prelaunch-resource-binding.v1",
            "prelaunch_ref": prelaunch_ref,
            "role": "source_collection",
        }
    )
    owner_ref = content_hash(
        {
            "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
            "transaction_ref": transaction_ref,
            "role": "source_collection",
            "binding_ref": prelaunch_binding_ref,
        }
    )
    host_attempt = tmp_path / "host-attempt"
    host_attempt.mkdir()
    worker = _Worker(fd, observed, qualified, terminal)
    store = SimpleNamespace()
    owner = InstalledStrixV2SourceCollection(
        transaction_ref=transaction_ref,
        attempt_id=ATTEMPT,
        prelaunch_ref=prelaunch_ref,
        prelaunch_binding_ref=prelaunch_binding_ref,
        owner_ref=owner_ref,
        activation=activation,
        binding_digest=_digest("binding"),
        delegation_digest=_digest("delegation"),
        host_attempt_directory=host_attempt,
        expected_target="http://bf-target-" + "a" * 32 + ":8080",
        expected_instruction_sha256=_digest("instruction"),
        artifact_store=store,
        terminal_journal=_TerminalJournal(),
        worker_controller=worker,
    )
    return owner, worker, store, fd


def test_cancelled_no_run_retains_verified_absence_and_reopens(tmp_path, monkeypatch):
    owner, _worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(
            source_module, "inspect_retained_strix_export_state", lambda **_: "absent"
        )
        monkeypatch.setattr(
            source_module, "inspect_guest_strix_run_presence", lambda _: "no_run_record"
        )
        terminal = owner.seal_and_observe()
        assert terminal.state == "verified_absent"
        assert terminal.native_qualified["receipt_ref"] == owner._activation.fixed_exec_receipt_ref
        assert owner.reopen_terminal() == terminal
        assert owner.reopen_source_receipt(terminal.receipt_ref) == terminal
        assert owner.source_identity_ref.startswith("sha256:")
        assert owner.seal_and_observe() == terminal
        owner._worker_controller = None
        owner._terminal = None
        assert owner.seal_and_observe() == terminal
        assert owner.cleanup_uncertain is False
    finally:
        os.close(fd)


@pytest.mark.parametrize("exit_code", (0, 2))
def test_completed_success_without_saved_run_remains_unknown(tmp_path, monkeypatch, exit_code):
    owner, _worker, _store, fd = _owner(
        tmp_path, monkeypatch, reason="completed", exit_code=exit_code
    )
    try:
        monkeypatch.setattr(
            source_module, "inspect_retained_strix_export_state", lambda **_: "absent"
        )
        monkeypatch.setattr(
            source_module, "inspect_guest_strix_run_presence", lambda _: "no_run_record"
        )
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="no saved run"):
            owner.seal_and_observe()
        assert owner.cleanup_uncertain is True
        assert owner.reopen_terminal() is None
    finally:
        os.close(fd)


def test_partial_export_cannot_be_declared_absent(tmp_path, monkeypatch):
    owner, _worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(
            source_module, "inspect_retained_strix_export_state", lambda **_: "pending"
        )
        with pytest.raises(source_module.StrixWorkspaceExportUnknown, match="unresolved"):
            owner.seal_and_observe()
        assert owner.cleanup_uncertain is True
        assert owner.reopen_terminal() is None
    finally:
        os.close(fd)


def test_saved_run_publication_reopens_exact_manifest_and_artifacts(tmp_path, monkeypatch):
    owner, worker, store, fd = _owner(tmp_path, monkeypatch, reason="completed", exit_code=0)
    try:
        snapshot = SimpleNamespace(
            attempt_state="completed",
            process_classification="zero_exit",
            to_dict=lambda: {"attempt_state": "completed"},
        )
        selected = "strix_runs/run/run.json"
        exported = SimpleNamespace(
            manifest_ref=_digest("manifest"), snapshot=snapshot, selected_names=(selected,)
        )
        publication_ref = _digest("artifact-publication")
        seal_ref = _digest("source-seal")
        binding = owner._publication_binding(exported, worker._terminal)
        monkeypatch.setattr(owner, "_export", lambda *_: exported)
        monkeypatch.setattr(
            owner,
            "_publish",
            lambda *_: (SimpleNamespace(artifact_publication_ref=publication_ref), seal_ref),
        )
        monkeypatch.setattr(source_module, "reopen_strix_workspace_export", lambda **_: exported)
        store.reopen_attempt = lambda _attempt: SimpleNamespace(
            attempt_id=ATTEMPT,
            artifact_publication_ref=publication_ref,
            source_collection_seal_ref=seal_ref,
            manifest_ref=_digest("artifact-manifest"),
            recovery_eligible=True,
            publication_binding=binding,
            artifacts=(SimpleNamespace(name=selected),),
        )
        receipt = owner.seal_and_observe()
        assert receipt.state == "verified_settled"
        assert receipt.export_manifest_ref == exported.manifest_ref
        assert receipt.artifact_publication_ref == publication_ref
        assert owner.reopen_terminal() == receipt
        assert owner.reopen_artifact_attempt().manifest_ref == _digest("artifact-manifest")
        assert owner.retained_result().snapshot is snapshot
        assert owner.retained_result().artifact_manifest_ref == _digest("artifact-manifest")
        store.reopen_attempt = lambda _attempt: SimpleNamespace(
            artifact_publication_ref=_digest("changed"),
            source_collection_seal_ref=seal_ref,
            publication_binding=binding,
            artifacts=(SimpleNamespace(name=selected),),
        )
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="publication changed"):
            owner.reopen_terminal()
    finally:
        os.close(fd)


def test_qualified_activation_mismatch_refuses_source_seal(tmp_path, monkeypatch):
    owner, worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        worker.qualified_document = {**worker.qualified_document, "receipt_ref": _digest("wrong")}
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="activation changed"):
            owner.seal_and_observe()
        assert owner.cleanup_uncertain is True
        assert owner.reopen_terminal() is None
    finally:
        os.close(fd)


def test_swapped_workspace_descriptor_cannot_claim_no_run(tmp_path, monkeypatch):
    owner, _worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(
            source_module,
            "_workspace_identity",
            lambda _fd: {**WORKSPACE_FACT, "inode": WORKSPACE_FACT["inode"] + 1},
        )
        monkeypatch.setattr(
            source_module, "inspect_retained_strix_export_state", lambda **_: "absent"
        )
        monkeypatch.setattr(
            source_module, "inspect_guest_strix_run_presence", lambda _: "no_run_record"
        )
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="activation changed"):
            owner.seal_and_observe()
        assert owner.reopen_terminal() is None
    finally:
        os.close(fd)


def test_mismatched_native_terminal_refuses_before_publication(tmp_path, monkeypatch):
    owner, worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        worker._terminal["plan_ref"] = _digest("other-plan")
        worker._terminal["receipt_ref"] = content_hash(
            {key: value for key, value in worker._terminal.items() if key != "receipt_ref"}
        )
        monkeypatch.setattr(
            owner,
            "_export",
            lambda *_: pytest.fail("unverified native terminal reached artifact export"),
        )
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="activation changed"):
            owner.seal_and_observe()
        assert owner.reopen_terminal() is None
    finally:
        os.close(fd)


def test_terminal_receipt_detects_native_tampering(tmp_path, monkeypatch):
    owner, _worker, _store, fd = _owner(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(
            source_module, "inspect_retained_strix_export_state", lambda **_: "absent"
        )
        monkeypatch.setattr(
            source_module, "inspect_guest_strix_run_presence", lambda _: "no_run_record"
        )
        receipt = owner.seal_and_observe()
        forged = receipt.document()
        forged["native_terminal"]["verified_absent"] = False
        with pytest.raises(InstalledStrixV2SourceCollectionError, match="unverified"):
            SourceCollectionTerminalReceipt.from_mapping(forged)
    finally:
        os.close(fd)
