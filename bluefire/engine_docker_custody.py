"""Controller-private durable Docker audit and non-authorizing custody journal.

The journal uses ProductStore's pinned private database and transactions.  It
retains full resource identities before an audit receipt can be acknowledged.
Reopening returns evidence for reconciliation, never permission to launch,
promote a pending container, or retry an operation.  Like ProductStore's other
hash chains, this is not an external rollback anchor against database owners.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass, fields, replace
from typing import Any, Mapping, Protocol

from .engine_docker_control import DockerApiOperation, DockerOwnership, DockerPolicy
from .engine_docker_exec_admission import DockerExecAdmissionV2, DockerExecBindingV2
from .engine_docker_proxy import DockerProxyAuditRecord, DockerProxyState
from .util import content_hash

_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_EVENTS = 65536
_MAX_DOCUMENT_BYTES = 128 * 1024
_SCHEMA = "bluefire.engine-docker-custody-event.v1"
_TABLE = "engine_docker_custody_events"
_TRIGGERS = {
    "engine_docker_custody_no_update": (
        "CREATE TRIGGER engine_docker_custody_no_update BEFORE UPDATE ON "
        "engine_docker_custody_events BEGIN SELECT RAISE(ABORT,"
        "'Docker custody events are immutable'); END"
    ),
    "engine_docker_custody_no_delete": (
        "CREATE TRIGGER engine_docker_custody_no_delete BEFORE DELETE ON "
        "engine_docker_custody_events BEGIN SELECT RAISE(ABORT,"
        "'Docker custody events are immutable'); END"
    ),
    "engine_docker_custody_no_replace": (
        "CREATE TRIGGER engine_docker_custody_no_replace BEFORE INSERT ON "
        "engine_docker_custody_events WHEN EXISTS(SELECT 1 FROM "
        "engine_docker_custody_events WHERE attempt_id=NEW.attempt_id AND "
        "(event_sequence=NEW.event_sequence OR event_key=NEW.event_key)) "
        "BEGIN SELECT RAISE(ABORT,'Docker custody events cannot be replaced'); END"
    ),
}


class EngineDockerCustodyError(RuntimeError):
    """The exact retained custody or its append-only history is unavailable."""


class DockerCustodyProductStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def _json(value: Mapping[str, Any]) -> str:
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(result.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise EngineDockerCustodyError("Docker custody document exceeds its bound")
    return result


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineDockerCustodyError("Docker custody digest is invalid")
    return value


def _sequence(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise EngineDockerCustodyError("Docker custody request sequence is invalid")
    return value


def _object(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise EngineDockerCustodyError("Docker custody document exceeds its bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EngineDockerCustodyError("Docker custody document has duplicate keys")
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=pairs)
        if not isinstance(result, dict) or _json(result) != text:
            raise EngineDockerCustodyError("Docker custody document is not canonical")
        return result
    except (ValueError, TypeError, RecursionError) as exc:
        raise EngineDockerCustodyError("Docker custody document is invalid") from exc


@dataclass(frozen=True, slots=True)
class _DecodedDockerProxyState:
    state: DockerProxyState
    retained_digest: str
    admission_unavailable: bool


def _state(
    row: Any,
    admissions: Mapping[str, DockerExecAdmissionV2],
) -> _DecodedDockerProxyState:
    expected = {
        "daemon_instance_digest",
        "pending_container_ids",
        "container_ids",
        "exec_bindings",
        "quarantined_container_ids",
        "quarantined_exec_bindings",
        "generation",
        "reconciliation_required",
    }
    optional = {"v2_exec_bindings", "v2_exec_operation_ids"}
    try:
        if (
            not isinstance(row, dict)
            or not expected.issubset(row)
            or not set(row).issubset(expected | optional)
        ):
            raise ValueError("fields")
        for key in expected - {"daemon_instance_digest", "generation", "reconciliation_required"}:
            if not isinstance(row[key], list):
                raise ValueError("array")
        for key in optional.intersection(row):
            if not isinstance(row[key], list):
                raise ValueError("V2 array")
        for key in ("exec_bindings", "quarantined_exec_bindings"):
            if any(not isinstance(item, list) or len(item) != 2 for item in row[key]):
                raise ValueError("bindings")
        if type(row["reconciliation_required"]) is not bool:
            raise ValueError("flag")
        bindings: list[DockerExecBindingV2] = []
        admission_unavailable = False
        for retained in row.get("v2_exec_bindings", []):
            if not isinstance(retained, dict) or set(retained) != {
                "exec_id",
                "admission",
                "phase",
                "deadline_monotonic_ns",
            }:
                raise ValueError("V2 binding")
            summary = retained["admission"]
            if not isinstance(summary, dict):
                raise ValueError("V2 admission")
            admitted = admissions.get(content_hash(summary))
            if admitted is None:
                admission_unavailable = True
                continue
            if admitted.to_dict() != summary:
                raise ValueError("V2 admission changed")
            bindings.append(
                DockerExecBindingV2(
                    exec_id=retained["exec_id"],
                    admission=admitted,
                    phase=retained["phase"],
                    deadline_monotonic_ns=retained["deadline_monotonic_ns"],
                )
            )
        if admission_unavailable:
            # A retained summary is evidence, not a replacement for the
            # controller's concrete admission. Never reconstruct a live binding
            # or invent its opaque handle after a process restart.
            bindings = []
        state = DockerProxyState(
            ownership=DockerOwnership.create(
                daemon_instance_digest=row["daemon_instance_digest"],
                pending_container_ids=row["pending_container_ids"],
                container_ids=row["container_ids"],
                exec_bindings=tuple(tuple(item) for item in row["exec_bindings"]),
            ),
            quarantined_container_ids=tuple(row["quarantined_container_ids"]),
            quarantined_exec_bindings=tuple(
                tuple(item) for item in row["quarantined_exec_bindings"]
            ),
            generation=row["generation"],
            reconciliation_required=(row["reconciliation_required"] or admission_unavailable),
            v2_exec_bindings=tuple(bindings),
            v2_exec_operation_ids=tuple(row.get("v2_exec_operation_ids", [])),
        )
        return _DecodedDockerProxyState(
            state=state,
            retained_digest=content_hash(row),
            admission_unavailable=admission_unavailable,
        )
    except (ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise EngineDockerCustodyError("Docker retained state is invalid") from exc


def _audit(row: Any) -> DockerProxyAuditRecord:
    try:
        if (
            not isinstance(row, dict)
            or set(row) != {item.name for item in fields(DockerProxyAuditRecord)}
            or type(row["reconciliation_required"]) is not bool
        ):
            raise ValueError("fields")
        return DockerProxyAuditRecord(**row)
    except (ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise EngineDockerCustodyError("Docker retained audit is invalid") from exc


@dataclass(frozen=True, slots=True)
class DockerPreparedOperation:
    request_ref: str
    sequence: int
    operation: str
    request_digest: str
    policy_digest: str
    state_before_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class ReopenedDockerProxyCustody:
    """Read-only recovery evidence, with every incomplete exchange fenced."""

    attempt_id: str
    policy_digest: str
    daemon_instance_digest: str
    state: DockerProxyState
    sequence: int
    audits: tuple[DockerProxyAuditRecord, ...]
    unresolved_operations: tuple[DockerPreparedOperation, ...]
    known_container_ids: tuple[str, ...]
    known_exec_bindings: tuple[tuple[str, str], ...]
    journal_digest: str


class ProductStoreDockerProxyCustody:
    """Append-only audit sink and custody hooks for exactly one admitted policy.

    Pass the same instance as both ``audit`` and ``custody`` to the proxy.
    ``retain`` must precede ``append``; the receipt is returned only after the
    audit transaction commits. A crash between them stays unresolved on reopen.
    The supplied policy binds evidence; this adapter does not admit that policy.
    """

    def __init__(
        self,
        store: DockerCustodyProductStore,
        *,
        policy: DockerPolicy,
        initial_state: DockerProxyState | None = None,
    ) -> None:
        self._store = store
        self._v2_admissions: dict[str, DockerExecAdmissionV2] = {}
        self._attempt_id = policy.attempt_id
        if not isinstance(self._attempt_id, str) or _ATTEMPT.fullmatch(self._attempt_id) is None:
            raise EngineDockerCustodyError("Docker custody attempt identity is invalid")
        self._policy_digest = _digest(policy.policy_digest)
        self._daemon_digest = _digest(policy.daemon_instance_digest)
        with self._store._connection(write=True) as connection:
            connection.execute(
                f"CREATE TABLE IF NOT EXISTS {_TABLE} ("
                "attempt_id TEXT NOT NULL, event_sequence INTEGER NOT NULL, "
                "event_key TEXT NOT NULL, event_digest TEXT NOT NULL UNIQUE, "
                "document_json TEXT NOT NULL, PRIMARY KEY(attempt_id,event_sequence), "
                "UNIQUE(attempt_id,event_key))"
            )
            for name, statement in _TRIGGERS.items():
                existing = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
                ).fetchone()
                if existing is None:
                    # Existing data without its immutability guard is not repaired.
                    if connection.execute(f"SELECT 1 FROM {_TABLE} LIMIT 1").fetchone():
                        raise EngineDockerCustodyError(
                            "Docker custody immutability guard is missing"
                        )
                    connection.execute(statement)
            rows = self._read(connection)
            if not rows:
                if initial_state is None:
                    raise EngineDockerCustodyError("Docker custody initial state is required")
                checked = self._check_state(initial_state)
                self._insert(
                    connection,
                    rows,
                    "binding",
                    "binding",
                    {
                        "attempt_id": self._attempt_id,
                        "policy_digest": self._policy_digest,
                        "daemon_instance_digest": self._daemon_digest,
                        "initial_state": checked.to_dict(),
                    },
                )
            else:
                binding = rows[0]["payload"]
                if initial_state is not None and (
                    self._check_state(initial_state).to_dict() != binding["initial_state"]
                ):
                    raise EngineDockerCustodyError("Docker custody initial state changed")
            self._reopen_rows(self._read(connection))

    def _check_state(self, state: DockerProxyState) -> DockerProxyState:
        if not isinstance(state, DockerProxyState):
            raise EngineDockerCustodyError("Docker custody state is unavailable")
        if state.ownership.daemon_instance_digest != self._daemon_digest:
            raise EngineDockerCustodyError("Docker custody state binds another daemon")
        admissions = dict(self._v2_admissions)
        for binding in state.v2_exec_bindings:
            admitted = binding.admission
            digest = admitted.admission_digest
            existing = admissions.get(digest)
            if existing is not None and existing is not admitted:
                raise EngineDockerCustodyError("Docker V2 admission identity changed")
            admissions[digest] = admitted
        decoded = _state(state.to_dict(), admissions)
        if decoded.admission_unavailable or decoded.state != state:
            raise EngineDockerCustodyError("Docker custody state cannot be reopened exactly")
        self._v2_admissions = admissions
        return decoded.state

    def _read(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        for name, statement in _TRIGGERS.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
            ).fetchone()
            if row is None or row[0] != statement:
                raise EngineDockerCustodyError("Docker custody immutability guard changed")
        rows = connection.execute(
            f"SELECT event_sequence,event_key,event_digest,document_json FROM {_TABLE} "
            "WHERE attempt_id=? ORDER BY event_sequence LIMIT ?",
            (self._attempt_id, _MAX_EVENTS + 1),
        ).fetchall()
        if len(rows) > _MAX_EVENTS:
            raise EngineDockerCustodyError("Docker custody event history exceeds its bound")
        result: list[dict[str, Any]] = []
        previous = None
        keys: set[str] = set()
        for ordinal, row in enumerate(rows, 1):
            document = _object(row[3])
            if (
                set(document)
                != {
                    "schema_version",
                    "attempt_id",
                    "event_sequence",
                    "event_key",
                    "previous_event_digest",
                    "kind",
                    "payload",
                }
                or document["schema_version"] != _SCHEMA
                or document["attempt_id"] != self._attempt_id
                or type(document["event_sequence"]) is not int
                or document["event_sequence"] != ordinal
                or row[0] != ordinal
                or document["event_key"] != row[1]
                or row[1] in keys
                or document["previous_event_digest"] != previous
                or content_hash(document) != row[2]
                or not isinstance(document["payload"], dict)
            ):
                raise EngineDockerCustodyError("Docker custody history failed its chain audit")
            keys.add(row[1])
            previous = row[2]
            result.append(document)
        return result

    def _insert(
        self,
        connection: sqlite3.Connection,
        rows: list[dict[str, Any]],
        kind: str,
        key: str,
        payload: Mapping[str, Any],
    ) -> None:
        existing = next((row for row in rows if row["event_key"] == key), None)
        if existing is not None:
            if existing["kind"] != kind or existing["payload"] != payload:
                raise EngineDockerCustodyError("Docker custody idempotent append changed")
            return
        if len(rows) >= _MAX_EVENTS:
            raise EngineDockerCustodyError("Docker custody event history is full")
        if connection.execute("PRAGMA synchronous").fetchone()[0] < 2:
            raise EngineDockerCustodyError("Docker custody requires durable database commits")
        document = {
            "schema_version": _SCHEMA,
            "attempt_id": self._attempt_id,
            "event_sequence": len(rows) + 1,
            "event_key": key,
            "previous_event_digest": content_hash(rows[-1]) if rows else None,
            "kind": kind,
            "payload": payload,
        }
        connection.execute(
            f"INSERT INTO {_TABLE} "
            "(attempt_id,event_sequence,event_key,event_digest,document_json) VALUES(?,?,?,?,?)",
            (self._attempt_id, len(rows) + 1, key, content_hash(document), _json(document)),
        )

    def _reopen_rows(self, rows: list[dict[str, Any]]) -> ReopenedDockerProxyCustody:
        if not rows or rows[0]["kind"] != "binding" or rows[0]["event_key"] != "binding":
            raise EngineDockerCustodyError("Docker custody binding is missing")
        binding = rows[0]["payload"]
        if (
            set(binding)
            != {"attempt_id", "policy_digest", "daemon_instance_digest", "initial_state"}
            or binding["attempt_id"] != self._attempt_id
            or binding["policy_digest"] != self._policy_digest
            or binding["daemon_instance_digest"] != self._daemon_digest
        ):
            raise EngineDockerCustodyError("Docker custody binding changed")
        decoded = _state(binding["initial_state"], self._v2_admissions)
        state = decoded.state
        persisted_state_digest = decoded.retained_digest
        if state.ownership.daemon_instance_digest != self._daemon_digest:
            raise EngineDockerCustodyError("Docker custody state binds another daemon")
        prepared: dict[int, DockerPreparedOperation] = {}
        retained: dict[str, tuple[DockerProxyAuditRecord, DockerProxyState]] = {}
        audits: list[DockerProxyAuditRecord] = []
        identities: dict[int, str] = {}
        completed: set[int] = set()
        containers: set[str] = set()
        execs: set[tuple[str, str]] = set()
        sequence = 0

        def remember(current: DockerProxyState) -> None:
            containers.update(current.ownership.pending_container_ids)
            containers.update(current.ownership.container_ids)
            containers.update(current.quarantined_container_ids)
            execs.update(current.ownership.exec_bindings)
            execs.update(current.quarantined_exec_bindings)

        remember(state)
        for event in rows[1:]:
            payload = event["payload"]
            if event["kind"] == "prepared":
                try:
                    if set(payload) != {item.name for item in fields(DockerPreparedOperation)}:
                        raise ValueError("fields")
                    operation = DockerPreparedOperation(**payload)
                    _sequence(operation.sequence)
                    for name in (
                        "request_ref",
                        "request_digest",
                        "policy_digest",
                        "state_before_digest",
                    ):
                        _digest(getattr(operation, name))
                    if (
                        operation.operation not in {item.value for item in DockerApiOperation}
                        or operation.policy_digest != self._policy_digest
                        or operation.state_before_digest != persisted_state_digest
                        or operation.sequence != sequence + 1
                        or event["event_key"] != f"prepared:{operation.sequence}"
                    ):
                        raise ValueError("binding")
                except (ValueError, TypeError) as exc:
                    raise EngineDockerCustodyError("Docker prepared operation is invalid") from exc
                prepared[operation.sequence] = operation
                identities[operation.sequence] = operation.request_ref
                sequence = operation.sequence
            elif event["kind"] in {"retained", "audit"}:
                if set(payload) != (
                    {"record", "state"} if event["kind"] == "retained" else {"record"}
                ):
                    raise EngineDockerCustodyError("Docker custody event fields are invalid")
                record = _audit(payload["record"])
                digest = content_hash(record.to_dict())
                key = f"{event['kind']}:{record.sequence}:{record.phase}"
                if (
                    record.policy_digest != self._policy_digest
                    or event["event_key"] != key
                    or identities.get(record.sequence, record.request_ref) != record.request_ref
                    or record.sequence < sequence
                ):
                    raise EngineDockerCustodyError("Docker custody audit binding changed")
                identities[record.sequence] = record.request_ref
                sequence = max(sequence, record.sequence)
                prepared_operation = prepared.get(record.sequence)
                if record.phase != "refused" and (
                    prepared_operation is None
                    or prepared_operation.operation != record.operation
                    or prepared_operation.request_digest != record.request_digest
                    or prepared_operation.state_before_digest != record.state_before_digest
                ):
                    raise EngineDockerCustodyError("Docker custody audit has no prepared operation")
                if record.phase == "published" and not any(
                    prior.sequence == record.sequence
                    and prior.phase == "validated"
                    and prior.outcome == "accepted"
                    and prior.state_after_digest == record.state_after_digest
                    and prior.response_digest == record.response_digest
                    for prior in audits
                ):
                    raise EngineDockerCustodyError("Docker publication has no validated audit")
                if event["kind"] == "retained":
                    decoded = _state(payload["state"], self._v2_admissions)
                    state = decoded.state
                    if state.ownership.daemon_instance_digest != self._daemon_digest:
                        raise EngineDockerCustodyError("Docker custody state binds another daemon")
                    if decoded.retained_digest != record.state_after_digest:
                        raise EngineDockerCustodyError("Docker retained state does not match audit")
                    persisted_state_digest = decoded.retained_digest
                    retained[digest] = (record, state)
                    remember(state)
                else:
                    if digest not in retained:
                        raise EngineDockerCustodyError("Docker audit has no retained custody")
                    audits.append(record)
                    if (
                        record.phase == "published"
                        and record.outcome == "accepted"
                        and not record.reconciliation_required
                    ):
                        completed.add(record.sequence)
                    elif record.phase == "suppressed":
                        completed.discard(record.sequence)
            else:
                raise EngineDockerCustodyError("Docker custody event kind is unsupported")
        unresolved = tuple(
            item for number, item in sorted(prepared.items()) if number not in completed
        )
        acknowledged = {content_hash(item.to_dict()) for item in audits}
        if unresolved or any(digest not in acknowledged for digest in retained):
            state = replace(state, reconciliation_required=True)
        return ReopenedDockerProxyCustody(
            attempt_id=self._attempt_id,
            policy_digest=self._policy_digest,
            daemon_instance_digest=self._daemon_digest,
            state=state,
            sequence=sequence,
            audits=tuple(audits),
            unresolved_operations=unresolved,
            known_container_ids=tuple(sorted(containers)),
            known_exec_bindings=tuple(sorted(execs)),
            journal_digest=content_hash(rows[-1]),
        )

    def prepare(
        self,
        *,
        request_ref: str,
        sequence: int,
        operation: str,
        request_digest: str,
        policy_digest: str,
        state: DockerProxyState,
    ) -> None:
        checked = self._check_state(state)
        item = DockerPreparedOperation(
            _digest(request_ref),
            _sequence(sequence),
            operation,
            _digest(request_digest),
            _digest(policy_digest),
            checked.state_digest,
        )
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            current = self._reopen_rows(rows)
            key = f"prepared:{sequence}"
            existing = any(row["event_key"] == key for row in rows)
            if not existing:
                if sequence != current.sequence + 1:
                    raise EngineDockerCustodyError(
                        "Docker custody request sequence is discontinuous"
                    )
                if (
                    current.state.reconciliation_required
                    or current.state.state_digest != checked.state_digest
                ):
                    raise EngineDockerCustodyError(
                        "Docker custody requires reconciliation before send"
                    )
            self._insert(connection, rows, "prepared", key, item.to_dict())
            self._reopen_rows(self._read(connection))

    def retain(self, record: DockerProxyAuditRecord, state: DockerProxyState) -> None:
        checked = self._check_state(state)
        validated = _audit(record.to_dict())
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            self._reopen_rows(rows)
            self._insert(
                connection,
                rows,
                "retained",
                f"retained:{record.sequence}:{record.phase}",
                {
                    "record": validated.to_dict(),
                    "state": checked.to_dict(),
                },
            )
            self._reopen_rows(self._read(connection))

    def append(self, record: DockerProxyAuditRecord) -> str:
        validated = _audit(record.to_dict())
        with self._store._connection(write=True) as connection:
            rows = self._read(connection)
            self._reopen_rows(rows)
            self._insert(
                connection,
                rows,
                "audit",
                f"audit:{record.sequence}:{record.phase}",
                {
                    "record": validated.to_dict(),
                },
            )
            self._reopen_rows(self._read(connection))
        return content_hash(validated.to_dict())

    def reopen(self) -> ReopenedDockerProxyCustody:
        with self._store._connection() as connection:
            return self._reopen_rows(self._read(connection))


__all__ = [
    "DockerPreparedOperation",
    "EngineDockerCustodyError",
    "ProductStoreDockerProxyCustody",
    "ReopenedDockerProxyCustody",
]
