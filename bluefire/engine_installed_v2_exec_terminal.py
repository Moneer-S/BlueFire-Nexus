"""Protected terminal source for one installed Strix Docker exec attachment."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .engine_docker_custody import DockerCustodyProductStore
from .engine_exec_operation_supervisor import (
    EngineExecOperationSupervisorError,
    ExecLifetimeTerminalReceiptV2,
)
from .linux_exec_supervisor_docker import (
    SupervisorDockerCleanupResult,
    SupervisorDockerContainerIdentity,
)
from .util import content_hash


class InstalledV2ExecAttachmentError(RuntimeError):
    """The installed exec attachment cannot establish its protected scope."""


def _reopen_supervisor_sources(document: Mapping[str, Any]) -> bool:
    pending = document.get("pending_lease_refs")
    operations = document.get("pending_operation_refs")
    saved = document.get("supervisor_close_receipts")
    if (
        type(pending) is not list
        or type(operations) is not list
        or type(saved) is not list
        or len(pending) != len(saved)
        or len(operations) != len(pending)
        or len(pending) > 128
    ):
        return False
    rows: list[tuple[str, str, int]] = []
    operation_rows: list[tuple[str, str, str, int]] = []
    receipts: list[ExecLifetimeTerminalReceiptV2] = []
    try:
        for item in pending:
            if type(item) is not list or len(item) != 3:
                return False
            rows.append((item[0], item[1], item[2]))
        for item in operations:
            if (
                type(item) is not list
                or len(item) != 4
                or type(item[0]) is not str
                or re.fullmatch(r"operation-[0-9a-f]{32}", item[0]) is None
            ):
                return False
            operation_rows.append((item[0], item[1], item[2], item[3]))
        for item in saved:
            if (
                type(item) is not dict
                or item.get("schema_version") != "bluefire.exec-lifetime-terminal-receipt.v2"
            ):
                return False
            receipt = ExecLifetimeTerminalReceiptV2(
                **{key: value for key, value in item.items() if key != "schema_version"}
            )
            if receipt.document() != item:
                return False
            receipts.append(receipt)
    except (TypeError, ValueError, EngineExecOperationSupervisorError):
        return False
    return (
        tuple(sorted(set(rows))) == tuple(rows)
        and tuple(sorted(set(operation_rows))) == tuple(operation_rows)
        and {(item[1], item[2], item[3]) for item in operation_rows} == set(rows)
        and {(item.request_ref, item.lease_ref, item.lease_generation) for item in receipts}
        == set(rows)
        and all(
            item.outcome == "verified_absent"
            and item.background_work_absent is True
            and item.container_absent is True
            for item in receipts
        )
    )


def _valid_cleanup_sources(document: Mapping[str, Any]) -> bool:
    results = document.get("source_results")
    identity = document.get("container_identity_digest")
    if (
        type(results) is not list
        or len(results) != 2
        or not isinstance(identity, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is None
    ):
        return False
    daemons: set[str] = set()
    for item in results:
        if type(item) is not dict or set(item) != set(
            SupervisorDockerCleanupResult.__dataclass_fields__
        ):
            return False
        if (
            item.get("container_id") != document.get("container_id")
            or item.get("container_identity_digest") != identity
            or item.get("live_daemon_proof") is not True
            or item.get("test_provider") is not False
            or item.get("absent_verified") is not True
            or item.get("cleanup_uncertain") is not False
            or type(item.get("stop_sent")) is not bool
            or type(item.get("remove_sent")) is not bool
        ):
            return False
        digests: list[Any] = [
            item.get("daemon_instance_digest"),
            item.get("final_inventory_digest"),
        ]
        for field in ("request_digests", "response_digests"):
            value = item.get(field)
            if type(value) is not list or not 1 <= len(value) <= 20:
                return False
            digests.extend(value)
        if len(item["request_digests"]) != len(item["response_digests"]):
            return False
        if any(
            not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
            for value in digests
        ):
            return False
        daemons.add(item["daemon_instance_digest"])
    return len(daemons) == 1


@dataclass(frozen=True, slots=True, init=False)
class ExecAttachmentTerminalReceiptV2:
    """Source-backed terminal result, built only from live cleanup objects."""

    attempt_id: str
    claim_ref: str
    controller_fence: str
    transaction_ref: str
    owner_ref: str
    owner_binding_ref: str
    container_id: str
    container_identity_digest: str
    supervisor_activation_ref: str
    docker_custody_journal_ref: str
    cancellation_audit_tail_ref: str | None
    pending_lease_refs: tuple[tuple[str, str, int], ...]
    pending_operation_refs: tuple[tuple[str, str, str, int], ...]
    supervisor_close_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...]
    source_results: tuple[SupervisorDockerCleanupResult, SupervisorDockerCleanupResult]
    receipt_ref: str

    @classmethod
    def from_sources(
        cls,
        *,
        attempt_id: str,
        claim_ref: str,
        controller_fence: str,
        transaction_ref: str,
        owner_ref: str,
        owner_binding_ref: str,
        container_identity: SupervisorDockerContainerIdentity,
        supervisor_activation_ref: str,
        docker_custody_journal_ref: str,
        cancellation_audit_tail_ref: str | None,
        pending_lease_refs: tuple[tuple[str, str, int], ...],
        pending_operation_refs: tuple[tuple[str, str, str, int], ...],
        supervisor_close_receipts: tuple[ExecLifetimeTerminalReceiptV2, ...],
        source_results: tuple[SupervisorDockerCleanupResult, SupervisorDockerCleanupResult],
    ) -> ExecAttachmentTerminalReceiptV2:
        if (
            type(container_identity) is not SupervisorDockerContainerIdentity
            or type(source_results) is not tuple
            or len(source_results) != 2
            or any(
                type(item) is not SupervisorDockerCleanupResult
                or item.container_id != container_identity.container_id
                or item.container_identity_digest != container_identity.identity_digest
                or item.live_daemon_proof is not True
                or item.absent_verified is not True
                or item.cleanup_uncertain is not False
                for item in source_results
            )
            or source_results[0].daemon_instance_digest != source_results[1].daemon_instance_digest
            or type(pending_lease_refs) is not tuple
            or type(supervisor_close_receipts) is not tuple
            or len(pending_lease_refs) != len(supervisor_close_receipts)
            or len(pending_lease_refs) > 128
            or tuple(sorted(set(pending_lease_refs))) != pending_lease_refs
            or type(pending_operation_refs) is not tuple
            or len(pending_operation_refs) != len(pending_lease_refs)
            or tuple(sorted(set(pending_operation_refs))) != pending_operation_refs
            or any(
                type(item) is not tuple
                or len(item) != 4
                or type(item[0]) is not str
                or re.fullmatch(r"operation-[0-9a-f]{32}", item[0]) is None
                for item in pending_operation_refs
            )
            or {(item[1], item[2], item[3]) for item in pending_operation_refs}
            != set(pending_lease_refs)
            or any(
                type(item) is not ExecLifetimeTerminalReceiptV2
                for item in supervisor_close_receipts
            )
            or {
                (item.request_ref, item.lease_ref, item.lease_generation)
                for item in supervisor_close_receipts
            }
            != set(pending_lease_refs)
            or any(
                item.outcome != "verified_absent"
                or item.background_work_absent is not True
                or item.container_absent is not True
                for item in supervisor_close_receipts
            )
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal Docker absence is unverified")
        values = {
            "attempt_id": attempt_id,
            "claim_ref": claim_ref,
            "controller_fence": controller_fence,
            "transaction_ref": transaction_ref,
            "owner_ref": owner_ref,
            "owner_binding_ref": owner_binding_ref,
            "container_id": container_identity.container_id,
            "container_identity_digest": container_identity.identity_digest,
            "supervisor_activation_ref": supervisor_activation_ref,
            "docker_custody_journal_ref": docker_custody_journal_ref,
            "cancellation_audit_tail_ref": cancellation_audit_tail_ref,
            "pending_lease_refs": pending_lease_refs,
            "pending_operation_refs": pending_operation_refs,
            "supervisor_close_receipts": supervisor_close_receipts,
            "source_results": source_results,
        }
        document = _terminal_document(values)
        instance = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        object.__setattr__(instance, "receipt_ref", content_hash(document))
        return instance

    @property
    def evidence_ref(self) -> str:
        return self.receipt_ref

    def document(self) -> dict[str, Any]:
        return {
            **_terminal_document(
                {
                    name: getattr(self, name)
                    for name in self.__dataclass_fields__
                    if name != "receipt_ref"
                }
            ),
            "receipt_ref": self.receipt_ref,
        }


def _terminal_document(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.installed-strix-v2-exec-terminal.v1",
        **{
            name: values[name]
            for name in (
                "attempt_id",
                "claim_ref",
                "controller_fence",
                "transaction_ref",
                "owner_ref",
                "owner_binding_ref",
                "container_id",
                "container_identity_digest",
                "supervisor_activation_ref",
                "docker_custody_journal_ref",
                "cancellation_audit_tail_ref",
            )
        },
        "source_results": [
            {
                **asdict(item),
                "request_digests": list(item.request_digests),
                "response_digests": list(item.response_digests),
            }
            if isinstance(item, SupervisorDockerCleanupResult)
            else item
            for item in values["source_results"]
        ],
        "pending_lease_refs": [list(item) for item in values["pending_lease_refs"]],
        "pending_operation_refs": [list(item) for item in values["pending_operation_refs"]],
        "supervisor_close_receipts": [
            item.document() if isinstance(item, ExecLifetimeTerminalReceiptV2) else item
            for item in values["supervisor_close_receipts"]
        ],
    }


@dataclass(frozen=True, slots=True)
class RetainedExecAttachmentTerminalV2:
    receipt_ref: str
    document: Mapping[str, Any]


class _ExecAttachmentTerminalStore:
    """Immutable ProductStore source for one exact exec attachment terminal."""

    _TABLE = "docker_exec_attachment_terminal_v2"
    _UPDATE = (
        "CREATE TRIGGER docker_exec_attachment_terminal_v2_no_update "
        "BEFORE UPDATE ON docker_exec_attachment_terminal_v2 "
        "BEGIN SELECT RAISE(ABORT, 'immutable exec terminal'); END"
    )
    _DELETE = (
        "CREATE TRIGGER docker_exec_attachment_terminal_v2_no_delete "
        "BEFORE DELETE ON docker_exec_attachment_terminal_v2 "
        "BEGIN SELECT RAISE(ABORT, 'immutable exec terminal'); END"
    )

    def __init__(self, store: DockerCustodyProductStore, **binding: str) -> None:
        self._validate_binding(store, binding)
        self._store = store
        self._binding = binding
        with store._connection(write=True) as connection:
            connection.execute(
                f"CREATE TABLE IF NOT EXISTS {self._TABLE} ("
                "attempt_id TEXT NOT NULL, transaction_ref TEXT NOT NULL, "
                "receipt_ref TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, "
                "PRIMARY KEY(attempt_id,transaction_ref))"
            )
            for name, definition in (
                ("docker_exec_attachment_terminal_v2_no_update", self._UPDATE),
                ("docker_exec_attachment_terminal_v2_no_delete", self._DELETE),
            ):
                row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
                ).fetchone()
                if row is None:
                    if connection.execute(f"SELECT 1 FROM {self._TABLE} LIMIT 1").fetchone():
                        raise InstalledV2ExecAttachmentError(
                            "V2 terminal immutability guard is missing"
                        )
                    connection.execute(definition)
            self._read(connection, None)

    @staticmethod
    def _validate_binding(store: DockerCustodyProductStore, binding: Mapping[str, str]) -> None:
        if set(binding) != {
            "attempt_id",
            "claim_ref",
            "controller_fence",
            "transaction_ref",
            "owner_ref",
            "owner_binding_ref",
            "container_id",
        } or not callable(getattr(store, "_connection", None)):
            raise InstalledV2ExecAttachmentError("V2 terminal store binding is incomplete")
        if (
            not isinstance(binding["attempt_id"], str)
            or re.fullmatch(r"engine-attempt-[0-9a-f]{32}", binding["attempt_id"]) is None
            or not isinstance(binding["container_id"], str)
            or re.fullmatch(r"[0-9a-f]{64}", binding["container_id"]) is None
            or any(
                not isinstance(binding[name], str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", binding[name]) is None
                for name in (
                    "claim_ref",
                    "controller_fence",
                    "transaction_ref",
                    "owner_ref",
                    "owner_binding_ref",
                )
            )
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal store identity is invalid")

    @classmethod
    def reopen_existing(
        cls, store: DockerCustodyProductStore, **binding: str
    ) -> _ExecAttachmentTerminalStore:
        cls._validate_binding(store, binding)
        source = object.__new__(cls)
        source._store = store
        source._binding = binding
        return source

    def _read(
        self, connection: Any, receipt_ref: str | None
    ) -> RetainedExecAttachmentTerminalV2 | None:
        for name, definition in (
            ("docker_exec_attachment_terminal_v2_no_update", self._UPDATE),
            ("docker_exec_attachment_terminal_v2_no_delete", self._DELETE),
        ):
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
            ).fetchone()
            if row is None or row[0] != definition:
                raise InstalledV2ExecAttachmentError("V2 terminal immutability guard changed")
        rows = connection.execute(
            f"SELECT receipt_ref,document_json FROM {self._TABLE} "
            "WHERE attempt_id=? AND transaction_ref=?",
            (self._binding["attempt_id"], self._binding["transaction_ref"]),
        ).fetchall()
        if len(rows) > 1:
            raise InstalledV2ExecAttachmentError("V2 terminal source is ambiguous")
        if not rows:
            return None
        saved_ref, encoded = rows[0]
        try:
            document = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise InstalledV2ExecAttachmentError("V2 terminal source changed") from exc
        if (
            type(document) is not dict
            or set(document)
            != {
                "schema_version",
                *self._binding,
                "container_identity_digest",
                "supervisor_activation_ref",
                "docker_custody_journal_ref",
                "cancellation_audit_tail_ref",
                "pending_lease_refs",
                "pending_operation_refs",
                "supervisor_close_receipts",
                "source_results",
                "receipt_ref",
            }
            or document["schema_version"] != "bluefire.installed-strix-v2-exec-terminal.v1"
            or any(document[name] != value for name, value in self._binding.items())
            or document["receipt_ref"] != saved_ref
            or content_hash({key: value for key, value in document.items() if key != "receipt_ref"})
            != saved_ref
            or not _valid_cleanup_sources(document)
            or not _reopen_supervisor_sources(document)
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal source failed replay validation")
        if receipt_ref is not None and saved_ref != receipt_ref:
            return None
        return RetainedExecAttachmentTerminalV2(saved_ref, document)

    def retain(self, receipt: ExecAttachmentTerminalReceiptV2) -> None:
        if type(receipt) is not ExecAttachmentTerminalReceiptV2 or any(
            getattr(receipt, name) != value for name, value in self._binding.items()
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal receipt belongs to another owner")
        document = receipt.document()
        if (
            content_hash({key: value for key, value in document.items() if key != "receipt_ref"})
            != receipt.receipt_ref
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal receipt changed")
        with self._store._connection(write=True) as connection:
            existing = self._read(connection, None)
            if existing is not None:
                if existing.receipt_ref != receipt.receipt_ref:
                    raise InstalledV2ExecAttachmentError("V2 terminal receipt already settled")
                return
            connection.execute(
                f"INSERT INTO {self._TABLE}(attempt_id,transaction_ref,receipt_ref,document_json) "
                "VALUES(?,?,?,?)",
                (
                    self._binding["attempt_id"],
                    self._binding["transaction_ref"],
                    receipt.receipt_ref,
                    json.dumps(document, sort_keys=True, separators=(",", ":")),
                ),
            )
            if self._read(connection, receipt.receipt_ref) is None:
                raise InstalledV2ExecAttachmentError("V2 terminal receipt was not retained")

    def reopen(self, receipt_ref: str | None = None) -> RetainedExecAttachmentTerminalV2 | None:
        if receipt_ref is not None and (
            not isinstance(receipt_ref, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_ref) is None
        ):
            raise InstalledV2ExecAttachmentError("V2 terminal receipt reference is invalid")
        with self._store._connection() as connection:
            return self._read(connection, receipt_ref)


__all__ = [
    "ExecAttachmentTerminalReceiptV2",
    "InstalledV2ExecAttachmentError",
    "RetainedExecAttachmentTerminalV2",
    "_ExecAttachmentTerminalStore",
]
