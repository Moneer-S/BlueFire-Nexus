"""Stopped native Strix output collection for one installed V2 attempt.

The native worker owns the guest filesystem until verified termination. This
owner copies only reviewed output through the transferred workspace FD, then
publishes an immutable artifact snapshot and a protected terminal receipt.
"""

from __future__ import annotations

import os
import re
import stat
import threading
import time
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .engine_artifact_store import (
    _CONTROLLER_SOURCE_AUTHORITY,
    EngineArtifactPublicationBinding,
    EngineArtifactStore,
    EngineArtifactStoreError,
    ReopenedEngineArtifactAttempt,
    SourceCollectionSeal,
    source_collection_tree_digest,
)
from .engine_installed_v2_authority import InstalledStrixV2ActivationReceipt
from .strix_adapter import StrixRunSnapshot
from .strix_workspace_export import (
    StrixWorkspaceExport,
    StrixWorkspaceExportUnknown,
    export_strix_workspace_run,
    inspect_guest_strix_run_presence,
    inspect_retained_strix_export_state,
    reopen_strix_workspace_export,
)
from .util import content_hash

_SCHEMA = "bluefire.installed-strix-v2-source-collection-terminal.v1"
_ROLE = "source_collection"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_EXPORT_TIMEOUT_SECONDS = 30.0


class InstalledStrixV2SourceCollectionError(RuntimeError):
    """The exact source could not be verified and retained."""


class _WorkerTerminalReader(Protocol):
    @property
    def cleanup_uncertain(self) -> bool: ...

    @property
    def workspace_fd(self) -> int: ...

    @property
    def qualified_document(self) -> Mapping[str, Any] | None: ...

    def observed_document(self) -> Mapping[str, Any] | None: ...

    def terminal_receipt(self) -> Mapping[str, Any] | None: ...


class _TerminalJournal(Protocol):
    @property
    def source_identity_ref(self) -> str: ...

    def retain_role_terminal(self, document: Mapping[str, Any]) -> str: ...

    def reopen_role_terminal(self, source_receipt_ref: str) -> Mapping[str, Any]: ...

    def reopen_latest_role_terminal(
        self, attempt_id: str, role: str, owner_ref: str
    ) -> Mapping[str, Any] | None: ...


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise InstalledStrixV2SourceCollectionError(f"{label} is invalid")
    return value


def _workspace_identity(workspace_fd: int) -> dict[str, int]:
    details = os.fstat(workspace_fd)
    if not stat.S_ISDIR(details.st_mode):
        raise InstalledStrixV2SourceCollectionError("pinned workspace is not a directory")
    return {
        "device": details.st_dev,
        "inode": details.st_ino,
        "mode": stat.S_IMODE(details.st_mode),
        "uid": details.st_uid,
        "gid": details.st_gid,
    }


@dataclass(frozen=True, slots=True, repr=False)
class SourceCollectionTerminalReceipt:
    schema_version: str
    transaction_ref: str
    attempt_id: str
    authority_ref: str
    claim_ref: str
    runtime_activation_ref: str
    prelaunch_binding_ref: str
    resource_ref: str
    owner_ref: str
    role: str
    state: str
    native_observed: Mapping[str, Any]
    native_qualified: Mapping[str, Any]
    native_terminal: Mapping[str, Any]
    export_manifest_ref: str | None
    artifact_publication_ref: str | None
    source_seal_ref: str | None
    evidence_ref: str
    observed_at: str
    receipt_ref: str

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA or self.role != _ROLE:
            raise InstalledStrixV2SourceCollectionError("source terminal schema changed")
        if type(self.attempt_id) is not str or _ATTEMPT.fullmatch(self.attempt_id) is None:
            raise InstalledStrixV2SourceCollectionError("source terminal attempt changed")
        for field in (
            "transaction_ref",
            "authority_ref",
            "claim_ref",
            "runtime_activation_ref",
            "prelaunch_binding_ref",
            "resource_ref",
            "owner_ref",
            "evidence_ref",
            "receipt_ref",
        ):
            _digest(getattr(self, field), f"source terminal {field}")
        if self.state not in {"verified_settled", "verified_absent"}:
            raise InstalledStrixV2SourceCollectionError("source terminal state changed")
        if any(
            type(value) is not dict
            for value in (self.native_observed, self.native_qualified, self.native_terminal)
        ):
            raise InstalledStrixV2SourceCollectionError("native source receipt is unavailable")
        observed = self.native_observed
        qualified = self.native_qualified
        terminal = self.native_terminal
        if (
            observed.get("schema_version") != "bluefire.strix-worker-runtime-observation.v1"
            or terminal.get("schema_version") != "bluefire.strix-worker-runtime-terminal.v1"
            or observed.get("attempt_id") != self.attempt_id
            or terminal.get("attempt_id") != self.attempt_id
            or observed.get("observation_ref")
            != content_hash(
                {key: value for key, value in observed.items() if key != "observation_ref"}
            )
            or qualified.get("receipt_ref")
            != content_hash(
                {key: value for key, value in qualified.items() if key != "receipt_ref"}
            )
            or qualified.get("native_observation_ref") != observed.get("observation_ref")
            or qualified.get("attempt_id") != self.attempt_id
            or qualified.get("resource_claim_ref") != self.claim_ref
            or qualified.get("plan_ref") != observed.get("plan_ref")
            or terminal.get("receipt_ref")
            != content_hash({key: value for key, value in terminal.items() if key != "receipt_ref"})
            or terminal.get("observation_ref") != observed.get("observation_ref")
            or terminal.get("qualified_receipt_ref") != qualified.get("receipt_ref")
            or terminal.get("resource_claim_ref") != self.claim_ref
            or terminal.get("plan_ref") != observed.get("plan_ref")
            or terminal.get("reason") not in {"completed", "cancelled"}
            or terminal.get("workspace_fd_transferred") is not True
            or terminal.get("workspace_ref") != observed.get("workspace_ref")
            or terminal.get("verified_absent") is not True
            or terminal.get("worker_reaped") is not True
            or terminal.get("cgroup_empty_and_removed") is not True
            or terminal.get("endpoint_absent") is not True
            or terminal.get("staging_root_absent") is not True
            or terminal.get("identity_released") is not True
        ):
            raise InstalledStrixV2SourceCollectionError("native source terminal is unverified")
        for value in (
            self.export_manifest_ref,
            self.artifact_publication_ref,
            self.source_seal_ref,
        ):
            if value is not None:
                _digest(value, "source publication")
        if (self.export_manifest_ref is None) != (self.artifact_publication_ref is None):
            raise InstalledStrixV2SourceCollectionError("source export/publication disagrees")
        if (self.artifact_publication_ref is None) != (self.source_seal_ref is None):
            raise InstalledStrixV2SourceCollectionError("source seal/publication disagrees")
        if self.state == "verified_absent" and self.artifact_publication_ref is not None:
            raise InstalledStrixV2SourceCollectionError("absent source has published artifacts")
        if self.state == "verified_settled" and self.artifact_publication_ref is None:
            raise InstalledStrixV2SourceCollectionError("settled source has no publication")
        if self.state == "verified_absent" and terminal.get("reason") != "cancelled":
            exit_code = terminal.get("exit_code")
            if (
                terminal.get("reason") != "completed"
                or type(exit_code) is not int
                or exit_code in {0, 2}
            ):
                raise InstalledStrixV2SourceCollectionError("missing completed run is unknown")
        if self.receipt_ref != content_hash(self.document(include_receipt=False)):
            raise InstalledStrixV2SourceCollectionError("source terminal receipt changed")

    @classmethod
    def create(cls, **values: Any) -> SourceCollectionTerminalReceipt:
        return cls(
            schema_version=_SCHEMA,
            role=_ROLE,
            **values,
            receipt_ref=content_hash({"schema_version": _SCHEMA, "role": _ROLE, **values}),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SourceCollectionTerminalReceipt:
        fields = frozenset(cls.__dataclass_fields__)
        if type(value) is not dict or set(value) != fields:
            raise InstalledStrixV2SourceCollectionError("source terminal fields changed")
        return cls(**value)

    def document(self, *, include_receipt: bool = True) -> dict[str, Any]:
        result = {
            name: (
                dict(value)
                if name in {"native_observed", "native_qualified", "native_terminal"}
                else value
            )
            for name, value in ((item.name, getattr(self, item.name)) for item in fields(self))
        }
        if not include_receipt:
            result.pop("receipt_ref")
        return result


@dataclass(frozen=True, slots=True)
class RetainedStrixV2SourceResult:
    """Saved engine run and artifacts; target effects require separate evidence."""

    snapshot: StrixRunSnapshot
    artifacts: ReopenedEngineArtifactAttempt
    export_manifest_ref: str

    @property
    def artifact_manifest_ref(self) -> str:
        return self.artifacts.manifest_ref


class InstalledStrixV2SourceCollection:
    """Publish only a verified stopped worker's bounded saved run."""

    def __init__(
        self,
        *,
        transaction_ref: str,
        attempt_id: str,
        prelaunch_ref: str,
        prelaunch_binding_ref: str,
        owner_ref: str,
        activation: InstalledStrixV2ActivationReceipt,
        binding_digest: str,
        delegation_digest: str,
        host_attempt_directory: Path,
        expected_target: str,
        expected_instruction_sha256: str,
        artifact_store: EngineArtifactStore,
        terminal_journal: _TerminalJournal,
        worker_controller: _WorkerTerminalReader | None,
    ) -> None:
        if type(attempt_id) is not str or _ATTEMPT.fullmatch(attempt_id) is None:
            raise InstalledStrixV2SourceCollectionError("source attempt is invalid")
        for label, value in (
            ("transaction", transaction_ref),
            ("prelaunch", prelaunch_ref),
            ("prelaunch binding", prelaunch_binding_ref),
            ("owner", owner_ref),
            ("binding", binding_digest),
            ("delegation", delegation_digest),
            ("instruction", expected_instruction_sha256),
        ):
            _digest(value, f"source {label}")
        if not isinstance(activation, InstalledStrixV2ActivationReceipt):
            raise InstalledStrixV2SourceCollectionError("source activation is invalid")
        expected_prelaunch_binding = content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-prelaunch-resource-binding.v1",
                "prelaunch_ref": prelaunch_ref,
                "role": _ROLE,
            }
        )
        expected_owner = content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-resource-owner.v1",
                "transaction_ref": transaction_ref,
                "role": _ROLE,
                "binding_ref": prelaunch_binding_ref,
            }
        )
        if prelaunch_binding_ref != expected_prelaunch_binding or owner_ref != expected_owner:
            raise InstalledStrixV2SourceCollectionError("source owner differs from prelaunch")
        bindings = dict(activation.role_bindings)
        if _ROLE not in bindings:
            raise InstalledStrixV2SourceCollectionError("source activation lacks its resource")
        if (
            not isinstance(host_attempt_directory, Path)
            or not host_attempt_directory.is_absolute()
            or host_attempt_directory.name != attempt_id
            or host_attempt_directory.is_symlink()
            or not host_attempt_directory.is_dir()
        ):
            raise InstalledStrixV2SourceCollectionError("source attempt directory is unavailable")
        if not isinstance(expected_target, str) or not expected_target.startswith("http://"):
            raise InstalledStrixV2SourceCollectionError("source target binding is invalid")
        for name in (
            "retain_role_terminal",
            "reopen_role_terminal",
            "reopen_latest_role_terminal",
        ):
            if not callable(getattr(terminal_journal, name, None)):
                raise InstalledStrixV2SourceCollectionError(
                    "source terminal journal is unavailable"
                )
        _digest(terminal_journal.source_identity_ref, "protected source journal")
        self.transaction_ref = transaction_ref
        self.attempt_id = attempt_id
        self.authority_ref = prelaunch_ref
        self.prelaunch_binding_ref = prelaunch_binding_ref
        self.owner_ref = owner_ref
        self.binding_ref = bindings[_ROLE]
        self._activation = activation
        self._binding_digest = binding_digest
        self._delegation_digest = delegation_digest
        self._host_attempt_directory = host_attempt_directory
        self._expected_target = expected_target
        self._expected_instruction_sha256 = expected_instruction_sha256
        self._artifact_store = artifact_store
        self._terminal_journal = terminal_journal
        self._worker_controller = worker_controller
        self._lock = threading.RLock()
        self._cleanup_uncertain = False
        self._terminal: SourceCollectionTerminalReceipt | None = None

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain

    @property
    def source_identity_ref(self) -> str:
        """Stable protected journal and exact resource identity for replay checks."""

        return content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-source-owner-identity.v1",
                "journal_source_identity_ref": _digest(
                    self._terminal_journal.source_identity_ref, "protected source journal"
                ),
                "transaction_ref": self.transaction_ref,
                "attempt_id": self.attempt_id,
                "prelaunch_binding_ref": self.prelaunch_binding_ref,
                "resource_ref": self.binding_ref,
                "owner_ref": self.owner_ref,
            }
        )

    def _native_terminal(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], int]:
        worker = self._worker_controller
        if worker is None or getattr(worker, "cleanup_uncertain", True) is not False:
            raise InstalledStrixV2SourceCollectionError("native worker terminal is unavailable")
        observed = worker.observed_document()
        qualified = worker.qualified_document
        terminal = worker.terminal_receipt()
        workspace_fd = worker.workspace_fd
        if (
            not isinstance(observed, dict)
            or not isinstance(qualified, dict)
            or not isinstance(terminal, dict)
        ):
            raise InstalledStrixV2SourceCollectionError("native worker receipts are unavailable")
        if type(workspace_fd) is not int or workspace_fd < 0:
            raise InstalledStrixV2SourceCollectionError("pinned workspace is unavailable")
        workspace_fact = _workspace_identity(workspace_fd)
        if (
            observed.get("schema_version") != "bluefire.strix-worker-runtime-observation.v1"
            or observed.get("attempt_id") != self.attempt_id
            or observed.get("workspace") != workspace_fact
            or observed.get("workspace_ref") != content_hash(workspace_fact)
            or observed.get("observation_ref")
            != content_hash(
                {key: value for key, value in observed.items() if key != "observation_ref"}
            )
            or qualified.get("receipt_ref")
            != content_hash(
                {key: value for key, value in qualified.items() if key != "receipt_ref"}
            )
            or terminal.get("receipt_ref")
            != content_hash({key: value for key, value in terminal.items() if key != "receipt_ref"})
            or qualified.get("native_observation_ref") != observed.get("observation_ref")
            or qualified.get("attempt_id") != self.attempt_id
            or qualified.get("resource_claim_ref") != self._activation.claim_ref
            or qualified.get("plan_ref") != observed.get("plan_ref")
            or terminal.get("schema_version") != "bluefire.strix-worker-runtime-terminal.v1"
            or terminal.get("observation_ref") != observed.get("observation_ref")
            or terminal.get("workspace_ref") != observed.get("workspace_ref")
            or terminal.get("attempt_id") != self.attempt_id
            or terminal.get("resource_claim_ref") != self._activation.claim_ref
            or terminal.get("plan_ref") != observed.get("plan_ref")
            or terminal.get("qualified_receipt_ref") != self._activation.fixed_exec_receipt_ref
            or qualified.get("receipt_ref") != self._activation.fixed_exec_receipt_ref
            or terminal.get("reason") not in {"completed", "cancelled"}
            or terminal.get("workspace_fd_transferred") is not True
            or terminal.get("verified_absent") is not True
            or terminal.get("worker_reaped") is not True
            or terminal.get("cgroup_empty_and_removed") is not True
            or terminal.get("endpoint_absent") is not True
            or terminal.get("staging_root_absent") is not True
            or terminal.get("identity_released") is not True
        ):
            raise InstalledStrixV2SourceCollectionError("native worker activation changed")
        return observed, qualified, terminal, workspace_fd

    def _export(
        self, observed: dict[str, Any], terminal: dict[str, Any], workspace_fd: int
    ) -> StrixWorkspaceExport | None:
        state = inspect_retained_strix_export_state(
            attempt_id=self.attempt_id,
            host_attempt_directory=self._host_attempt_directory,
        )
        if state in {"pending", "unknown"}:
            raise StrixWorkspaceExportUnknown("Strix output has unresolved staging")
        reason = terminal.get("reason")
        exit_code = terminal.get("exit_code")
        if reason not in {"completed", "cancelled"}:
            raise InstalledStrixV2SourceCollectionError("native worker outcome is unknown")
        cancellation = reason == "cancelled"
        kwargs = {
            "attempt_id": self.attempt_id,
            "host_attempt_directory": self._host_attempt_directory,
            "native_observed": observed,
            "worker_terminal_ref": terminal["receipt_ref"],
            "expected_target": self._expected_target,
            "expected_instruction_sha256": self._expected_instruction_sha256,
            "process_exit_code": exit_code,
            "cancellation_requested": cancellation,
            "cessation_verified": True,
            "deadline_monotonic": time.monotonic() + _EXPORT_TIMEOUT_SECONDS,
        }
        if state == "published":
            return reopen_strix_workspace_export(**kwargs)
        presence = inspect_guest_strix_run_presence(workspace_fd)
        if presence == "no_run_record":
            if reason == "completed" and exit_code in {0, 2}:
                raise InstalledStrixV2SourceCollectionError("completed worker has no saved run")
            return None
        duplicate = os.dup(workspace_fd)
        try:
            return export_strix_workspace_run(workspace_fd=duplicate, **kwargs)
        finally:
            os.close(duplicate)

    def _publication_binding(
        self, exported: StrixWorkspaceExport, terminal: Mapping[str, Any]
    ) -> EngineArtifactPublicationBinding:
        return EngineArtifactPublicationBinding(
            attempt_id=self.attempt_id,
            binding_digest=self._binding_digest,
            delegation_digest=self._delegation_digest,
            launch_digest=self._activation.controlled_launch_digest,
            runtime_resolution_ref=self._activation.runtime_resolution_ref,
            execution_claim_ref=self._activation.claim_ref,
            worker_outcome_digest=content_hash(
                {
                    "schema_version": "bluefire.installed-strix-v2-worker-outcome.v1",
                    "terminal_ref": terminal["receipt_ref"],
                    "run_snapshot": exported.snapshot.to_dict(),
                }
            ),
        )

    def _require_artifact_store_absent(self) -> None:
        """Treat only the Store's exact missing result as an empty publication."""

        try:
            self._artifact_store.reopen_attempt(self.attempt_id)
        except EngineArtifactStoreError as exc:
            # The Store verifies its protected root before reporting this
            # precise missing state. Pending/corrupt/permission errors remain
            # unknown rather than becoming a no-run claim.
            if str(exc) == "artifact publication is unavailable":
                return
            raise
        raise InstalledStrixV2SourceCollectionError("absent run has artifact publication")

    @staticmethod
    def _require_same_artifacts(
        exported: StrixWorkspaceExport, published: ReopenedEngineArtifactAttempt
    ) -> None:
        reviewed = tuple(item.to_manifest_row() for item in exported.reviewed_files)
        retained = tuple(item.to_manifest_row() for item in published.artifacts)
        if (
            retained != reviewed
            or tuple(item["name"] for item in reviewed) != exported.selected_names
        ):
            raise InstalledStrixV2SourceCollectionError(
                "saved artifacts differ from reviewed Strix output"
            )

    def _publish(self, exported: StrixWorkspaceExport, terminal: dict[str, Any]):
        source = exported.source_run_dir
        details = source.lstat()
        tree_digest = source_collection_tree_digest(source)
        source_receipt_ref = content_hash(
            {
                "schema_version": "bluefire.installed-strix-v2-source-seal-basis.v1",
                "attempt_id": self.attempt_id,
                "native_observation_ref": exported.source_observation_ref,
                "native_terminal_ref": exported.worker_terminal_ref,
                "export_manifest_ref": exported.manifest_ref,
                "source_tree_digest": tree_digest,
                "source_root_device": details.st_dev,
                "source_root_inode": details.st_ino,
                "source_root_mtime_ns": details.st_mtime_ns,
            }
        )
        seal = SourceCollectionSeal.from_mapping(
            {
                "schema_version": "bluefire.engine-source-collection-seal.v1",
                "attempt_id": self.attempt_id,
                "source_root_device": details.st_dev,
                "source_root_inode": details.st_ino,
                "source_root_mtime_ns": details.st_mtime_ns,
                "source_tree_digest": tree_digest,
                "worker_state": "stopped",
                "write_access_revoked": True,
                "controller_receipt_digest": source_receipt_ref,
            },
            _controller_authority=_CONTROLLER_SOURCE_AUTHORITY,
        )
        binding = self._publication_binding(exported, terminal)
        published = self._artifact_store.import_or_reopen(
            attempt_id=self.attempt_id,
            source_run_dir=source,
            source_seal=seal,
            allowed_names=exported.selected_names,
            publication_binding=binding,
        )
        if (
            not published.recovery_eligible
            or published.artifact_publication_ref is None
            or published.publication_binding != binding
        ):
            raise InstalledStrixV2SourceCollectionError("source publication was not retained")
        self._require_same_artifacts(exported, published)
        return published, content_hash(seal.to_dict())

    def seal_and_observe(self) -> SourceCollectionTerminalReceipt:
        with self._lock:
            try:
                reopened = self.reopen_terminal()
                if reopened is not None:
                    self._terminal = reopened
                    self._cleanup_uncertain = False
                    return reopened
                if self._terminal is not None:
                    raise InstalledStrixV2SourceCollectionError(
                        "retained source terminal disappeared"
                    )
                observed, qualified, terminal, workspace_fd = self._native_terminal()
                exported = self._export(observed, terminal, workspace_fd)
                publication_ref: str | None = None
                seal_ref: str | None = None
                export_ref: str | None = None
                if exported is not None:
                    published, seal_ref = self._publish(exported, terminal)
                    publication_ref = published.artifact_publication_ref
                    export_ref = exported.manifest_ref
                else:
                    self._require_artifact_store_absent()
                state = "verified_settled" if exported is not None else "verified_absent"
                evidence_ref = publication_ref or content_hash(
                    {
                        "schema_version": "bluefire.installed-strix-v2-empty-source.v1",
                        "attempt_id": self.attempt_id,
                        "native_terminal_ref": terminal["receipt_ref"],
                        "workspace_ref": observed["workspace_ref"],
                        "export_state": "absent",
                    }
                )
                receipt = SourceCollectionTerminalReceipt.create(
                    transaction_ref=self.transaction_ref,
                    attempt_id=self.attempt_id,
                    authority_ref=self.authority_ref,
                    claim_ref=self._activation.claim_ref,
                    runtime_activation_ref=self._activation.receipt_ref,
                    prelaunch_binding_ref=self.prelaunch_binding_ref,
                    resource_ref=self.binding_ref,
                    owner_ref=self.owner_ref,
                    state=state,
                    native_observed=observed,
                    native_qualified=qualified,
                    native_terminal=terminal,
                    export_manifest_ref=export_ref,
                    artifact_publication_ref=publication_ref,
                    source_seal_ref=seal_ref,
                    evidence_ref=evidence_ref,
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                )
                retained_ref = self._terminal_journal.retain_role_terminal(receipt.document())
                if retained_ref != receipt.receipt_ref:
                    raise InstalledStrixV2SourceCollectionError("source terminal retention changed")
                self._terminal = self._reopen_by_ref(receipt.receipt_ref)
                self._cleanup_uncertain = False
                return self._terminal
            except Exception:
                self._cleanup_uncertain = True
                raise

    def _reopen_by_ref(self, receipt_ref: str) -> SourceCollectionTerminalReceipt:
        row = self._terminal_journal.reopen_role_terminal(receipt_ref)
        receipt = SourceCollectionTerminalReceipt.from_mapping(row)
        if (
            receipt.attempt_id != self.attempt_id
            or receipt.owner_ref != self.owner_ref
            or receipt.transaction_ref != self.transaction_ref
            or receipt.resource_ref != self.binding_ref
            or receipt.runtime_activation_ref != self._activation.receipt_ref
            or receipt.claim_ref != self._activation.claim_ref
            or receipt.authority_ref != self.authority_ref
            or receipt.prelaunch_binding_ref != self.prelaunch_binding_ref
            or receipt.native_qualified.get("receipt_ref")
            != self._activation.fixed_exec_receipt_ref
        ):
            raise InstalledStrixV2SourceCollectionError("source terminal owner changed")
        if receipt.artifact_publication_ref is not None:
            exported = reopen_strix_workspace_export(
                attempt_id=self.attempt_id,
                host_attempt_directory=self._host_attempt_directory,
                native_observed=dict(receipt.native_observed),
                worker_terminal_ref=receipt.native_terminal["receipt_ref"],
                expected_target=self._expected_target,
                expected_instruction_sha256=self._expected_instruction_sha256,
                process_exit_code=receipt.native_terminal.get("exit_code"),
                cancellation_requested=receipt.native_terminal.get("reason") == "cancelled",
                cessation_verified=True,
                deadline_monotonic=time.monotonic() + _EXPORT_TIMEOUT_SECONDS,
            )
            published = self._artifact_store.reopen_attempt(self.attempt_id)
            if (
                exported.manifest_ref != receipt.export_manifest_ref
                or published.artifact_publication_ref != receipt.artifact_publication_ref
                or published.source_collection_seal_ref != receipt.source_seal_ref
                or published.publication_binding
                != self._publication_binding(exported, receipt.native_terminal)
            ):
                raise InstalledStrixV2SourceCollectionError("source publication changed")
            self._require_same_artifacts(exported, published)
        elif (
            inspect_retained_strix_export_state(
                attempt_id=self.attempt_id, host_attempt_directory=self._host_attempt_directory
            )
            != "absent"
        ):
            raise InstalledStrixV2SourceCollectionError("absent source has retained export")
        else:
            self._require_artifact_store_absent()
        return receipt

    def reopen_terminal(self) -> SourceCollectionTerminalReceipt | None:
        with self._lock:
            row = self._terminal_journal.reopen_latest_role_terminal(
                self.attempt_id, _ROLE, self.owner_ref
            )
            if row is None:
                return None
            ref = _digest(row.get("receipt_ref"), "source terminal reference")
            return self._reopen_by_ref(ref)

    def reopen_source_receipt(self, source_receipt_ref: str) -> SourceCollectionTerminalReceipt:
        """Reopen a specific durable source receipt for ProductStore verification."""

        with self._lock:
            return self._reopen_by_ref(_digest(source_receipt_ref, "source terminal reference"))

    def reopen_artifact_attempt(self) -> ReopenedEngineArtifactAttempt | None:
        """Return the exact saved artifact manifest after terminal source validation.

        Saved engine files are engine evidence, not independent target observations
        or proof that the objective was reached.
        """

        with self._lock:
            terminal = self.reopen_terminal()
            if terminal is None:
                raise InstalledStrixV2SourceCollectionError("source terminal is unavailable")
            if terminal.state == "verified_absent":
                return None
            published = self._artifact_store.reopen_attempt(self.attempt_id)
            if (
                published.recovery_eligible is not True
                or published.attempt_id != self.attempt_id
                or published.artifact_publication_ref != terminal.artifact_publication_ref
                or published.source_collection_seal_ref != terminal.source_seal_ref
            ):
                raise InstalledStrixV2SourceCollectionError("source artifact manifest changed")
            _digest(published.manifest_ref, "source artifact manifest")
            return published

    def retained_result(self) -> RetainedStrixV2SourceResult | None:
        """Reopen the saved Strix classification without claiming a target outcome."""

        with self._lock:
            terminal = self.reopen_terminal()
            if terminal is None:
                raise InstalledStrixV2SourceCollectionError("source terminal is unavailable")
            if terminal.state == "verified_absent":
                return None
            exported = reopen_strix_workspace_export(
                attempt_id=self.attempt_id,
                host_attempt_directory=self._host_attempt_directory,
                native_observed=dict(terminal.native_observed),
                worker_terminal_ref=terminal.native_terminal["receipt_ref"],
                expected_target=self._expected_target,
                expected_instruction_sha256=self._expected_instruction_sha256,
                process_exit_code=terminal.native_terminal.get("exit_code"),
                cancellation_requested=terminal.native_terminal.get("reason") == "cancelled",
                cessation_verified=True,
                deadline_monotonic=time.monotonic() + _EXPORT_TIMEOUT_SECONDS,
            )
            artifacts = self.reopen_artifact_attempt()
            if artifacts is None or exported.manifest_ref != terminal.export_manifest_ref:
                raise InstalledStrixV2SourceCollectionError("saved Strix source changed")
            return RetainedStrixV2SourceResult(
                snapshot=exported.snapshot,
                artifacts=artifacts,
                export_manifest_ref=exported.manifest_ref,
            )

    def reopen_run_snapshot(self) -> StrixRunSnapshot | None:
        result = self.retained_result()
        return None if result is None else result.snapshot

    def close(self) -> None:
        self.seal_and_observe()


__all__ = [
    "InstalledStrixV2SourceCollection",
    "InstalledStrixV2SourceCollectionError",
    "RetainedStrixV2SourceResult",
    "SourceCollectionTerminalReceipt",
]
