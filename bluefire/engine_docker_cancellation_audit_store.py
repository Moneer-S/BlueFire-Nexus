"""Durable, attempt-bound cancellation audit for installed Docker exec."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, ContextManager, Protocol

from .engine_docker_exec_cancellation import DockerExecCancellationAuditRecordV2
from .util import content_hash

_TABLE = "docker_exec_cancellation_audit_v2"
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION = re.compile(r"operation-[0-9a-f]{32}\Z")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_ROWS = 2048
_UPDATE_TRIGGER = (
    "CREATE TRIGGER docker_exec_cancellation_audit_v2_no_update "
    "BEFORE UPDATE ON docker_exec_cancellation_audit_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable cancellation audit'); END"
)
_DELETE_TRIGGER = (
    "CREATE TRIGGER docker_exec_cancellation_audit_v2_no_delete "
    "BEFORE DELETE ON docker_exec_cancellation_audit_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable cancellation audit'); END"
)


class CancellationAuditStoreError(RuntimeError):
    """The protected cancellation history cannot be retained or reopened."""


class _Store(Protocol):
    def _connection(self, *, write: bool = False) -> ContextManager[Any]: ...


@dataclass(frozen=True, slots=True)
class RetainedCancellationAuditV2:
    sequence: int
    record: DockerExecCancellationAuditRecordV2
    record_ref: str
    previous_entry_ref: str | None
    entry_ref: str


def _validate_record(record: DockerExecCancellationAuditRecordV2) -> None:
    if type(record) is not DockerExecCancellationAuditRecordV2:
        raise CancellationAuditStoreError("cancellation record type is invalid")
    for name in (
        "admission_digest",
        "custody_plan_digest",
        "network_policy_digest",
        "authority_ref",
        "claim_ref",
        "controller_fence",
    ):
        value = getattr(record, name)
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise CancellationAuditStoreError("cancellation record digest is invalid")
    if (
        not isinstance(record.attempt_id, str)
        or _ATTEMPT.fullmatch(record.attempt_id) is None
        or not isinstance(record.container_id, str)
        or _CONTAINER.fullmatch(record.container_id) is None
        or not isinstance(record.operation_id, str)
        or _OPERATION.fullmatch(record.operation_id) is None
        or not isinstance(record.reason, str)
        or _REASON.fullmatch(record.reason) is None
        or record.phase not in {"requested", "absence_verified", "unknown"}
        or (
            record.monotonic_ns is not None
            and (type(record.monotonic_ns) is not int or record.monotonic_ns < 0)
        )
        or (
            record.issue is not None
            and (not isinstance(record.issue, str) or _REASON.fullmatch(record.issue) is None)
        )
    ):
        raise CancellationAuditStoreError("cancellation record identity or phase is invalid")
    for value in (record.stop_snapshot_digest, record.inspect_snapshot_digest):
        if value is not None and (not isinstance(value, str) or _DIGEST.fullmatch(value) is None):
            raise CancellationAuditStoreError("cancellation observation digest is invalid")
    if record.phase == "requested" and (
        record.issue is not None
        or record.stop_snapshot_digest is not None
        or record.inspect_snapshot_digest is not None
    ):
        raise CancellationAuditStoreError("requested cancellation has premature outcome")
    if record.phase == "absence_verified" and (
        record.issue is not None
        or record.monotonic_ns is None
        or record.stop_snapshot_digest is None
        or record.inspect_snapshot_digest is None
    ):
        raise CancellationAuditStoreError("verified cancellation lacks observations")
    if record.phase == "unknown" and record.issue is None:
        raise CancellationAuditStoreError("unknown cancellation lacks its issue")


class ProductStoreDockerExecCancellationAuditV2:
    """Append-only audit bound to one precommitted resource owner.

    It uses a separate table in ProductStore's database. The row chain and
    immutable triggers are verified on every reopen; a returned record digest
    means that the matching row committed, not merely that it was calculated.
    """

    def __init__(
        self,
        store: _Store,
        *,
        attempt_id: str,
        claim_ref: str,
        controller_fence: str,
        transaction_ref: str,
        owner_ref: str,
        owner_binding_ref: str,
    ) -> None:
        if not isinstance(attempt_id, str) or _ATTEMPT.fullmatch(attempt_id) is None:
            raise CancellationAuditStoreError("cancellation attempt identity is invalid")
        for value in (claim_ref, controller_fence, transaction_ref, owner_ref, owner_binding_ref):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise CancellationAuditStoreError("cancellation owner binding is invalid")
        self._store = store
        self._binding = {
            "attempt_id": attempt_id,
            "claim_ref": claim_ref,
            "controller_fence": controller_fence,
            "transaction_ref": transaction_ref,
            "owner_ref": owner_ref,
            "owner_binding_ref": owner_binding_ref,
        }
        with store._connection(write=True) as connection:
            connection.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "attempt_id TEXT NOT NULL, sequence INTEGER NOT NULL, "
                "record_ref TEXT NOT NULL, entry_ref TEXT NOT NULL UNIQUE, "
                "document_json TEXT NOT NULL, PRIMARY KEY(attempt_id,sequence))"
            )
            for name, definition in (
                ("docker_exec_cancellation_audit_v2_no_update", _UPDATE_TRIGGER),
                ("docker_exec_cancellation_audit_v2_no_delete", _DELETE_TRIGGER),
            ):
                existing = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
                ).fetchone()
                if existing is None:
                    if connection.execute(f"SELECT 1 FROM {_TABLE} LIMIT 1").fetchone():
                        raise CancellationAuditStoreError(
                            "cancellation immutability guard is missing"
                        )
                    connection.execute(definition)
            self._read(connection)

    def _read(self, connection: Any) -> tuple[RetainedCancellationAuditV2, ...]:
        for name, definition in (
            ("docker_exec_cancellation_audit_v2_no_update", _UPDATE_TRIGGER),
            ("docker_exec_cancellation_audit_v2_no_delete", _DELETE_TRIGGER),
        ):
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
            ).fetchone()
            if row is None or row[0] != definition:
                raise CancellationAuditStoreError("cancellation immutability guard changed")
        rows = connection.execute(
            f"SELECT sequence,record_ref,entry_ref,document_json FROM {_TABLE} "
            "WHERE attempt_id=? ORDER BY sequence LIMIT ?",
            (self._binding["attempt_id"], _MAX_ROWS + 1),
        ).fetchall()
        if len(rows) > _MAX_ROWS:
            raise CancellationAuditStoreError("cancellation audit exceeds its bound")
        previous: str | None = None
        result: list[RetainedCancellationAuditV2] = []
        for ordinal, (sequence, record_ref, entry_ref, encoded) in enumerate(rows, 1):
            try:
                document = json.loads(encoded)
            except (TypeError, ValueError) as exc:
                raise CancellationAuditStoreError("cancellation audit is invalid") from exc
            if (
                type(document) is not dict
                or set(document)
                != {"schema_version", "binding", "sequence", "record", "previous_entry_ref"}
                or document["schema_version"] != "bluefire.docker-exec-cancellation-retention.v2"
                or document["binding"] != self._binding
                or type(sequence) is not int
                or sequence != ordinal
                or document["sequence"] != ordinal
                or document["previous_entry_ref"] != previous
                or content_hash(document) != entry_ref
                or content_hash(document["record"]) != record_ref
            ):
                raise CancellationAuditStoreError("cancellation audit chain changed")
            try:
                record = DockerExecCancellationAuditRecordV2(
                    **{
                        key: value
                        for key, value in document["record"].items()
                        if key != "schema_version"
                    }
                )
            except (TypeError, ValueError) as exc:
                raise CancellationAuditStoreError("cancellation audit record changed") from exc
            _validate_record(record)
            if (
                record.to_dict() != document["record"]
                or record.attempt_id != self._binding["attempt_id"]
                or record.claim_ref != self._binding["claim_ref"]
                or record.controller_fence != self._binding["controller_fence"]
            ):
                raise CancellationAuditStoreError("cancellation audit owner changed")
            result.append(
                RetainedCancellationAuditV2(ordinal, record, record_ref, previous, entry_ref)
            )
            previous = entry_ref
        return tuple(result)

    def append(self, record: DockerExecCancellationAuditRecordV2) -> str:
        if (
            type(record) is not DockerExecCancellationAuditRecordV2
            or record.attempt_id != self._binding["attempt_id"]
            or record.claim_ref != self._binding["claim_ref"]
            or record.controller_fence != self._binding["controller_fence"]
        ):
            raise CancellationAuditStoreError("cancellation record belongs to another owner")
        _validate_record(record)
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            if len(rows) >= _MAX_ROWS:
                raise CancellationAuditStoreError("cancellation audit exceeds its bound")
            document = {
                "schema_version": "bluefire.docker-exec-cancellation-retention.v2",
                "binding": self._binding,
                "sequence": len(rows) + 1,
                "record": record.to_dict(),
                "previous_entry_ref": rows[-1].entry_ref if rows else None,
            }
            record_ref = content_hash(record.to_dict())
            connection.execute(
                f"INSERT INTO {_TABLE}(attempt_id,sequence,record_ref,entry_ref,document_json) "
                "VALUES(?,?,?,?,?)",
                (
                    self._binding["attempt_id"],
                    len(rows) + 1,
                    record_ref,
                    content_hash(document),
                    json.dumps(document, sort_keys=True, separators=(",", ":")),
                ),
            )
            self._read(connection)
        return record_ref

    def reopen(self) -> tuple[RetainedCancellationAuditV2, ...]:
        with self._store._connection() as connection:
            return self._read(connection)


__all__ = [
    "CancellationAuditStoreError",
    "ProductStoreDockerExecCancellationAuditV2",
    "RetainedCancellationAuditV2",
]
