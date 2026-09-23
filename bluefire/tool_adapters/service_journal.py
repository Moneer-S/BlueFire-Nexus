"""Durable metadata for a future owned-service coordinator; never dispatch effects.

The private database path is setup configuration, not an action parameter. A
committed pending intent requires inspection after interruption. Recording a
result is metadata only: callers still own approval, identity and observation
checks. Neither a checksum nor this journal proves ownership or authenticity.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping
from uuid import uuid4

from ..contracts import ContractError
from ..local_lock import LocalLockError
from ..runner_trust import RunnerTrustError
from ..util import canonical_json_bytes, content_hash
from ..windows_owner_acl import WindowsOwnerAclError
from .service_journal_storage import PrivateJournalStorage
from .service_lifecycle import OwnedUserService
from .service_operation_binding import ServiceOperationBinding

SCHEMA = "bluefire.service-intent-journal.v1"
_APPLICATION_ID = 0x4246534A
_MAX_BYTES = 32 * 1024
_SETUP = ("create_unit", "reload", "enable", "start")
_CLEANUP = ("stop", "disable", "remove_links", "remove_unit", "reload_after_cleanup")
_RESULTS = {"pending", "succeeded", "failed", "unknown"}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_OPERATION_ID = re.compile(r"op-[0-9a-f]{32}")
_FIELDS = {"schema_version", "identity", "identity_digest", "request_id", "revision", "operations"}


def _fail(message: str) -> ContractError:
    return ContractError("service intent journal: " + message)


def _text(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail("invalid identifier")
    return value


def _revision(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 64:
        raise _fail("invalid revision")
    return value


def _next_allowed(history: list[dict[str, Any]]) -> set[str]:
    if history and history[-1]["result"] == "pending":
        return set()
    cleanup = [entry for entry in history if entry["operation"] in _CLEANUP]
    if cleanup:
        last = cleanup[-1]
        index = _CLEANUP.index(last["operation"])
        if last["result"] != "succeeded":
            return {last["operation"]}
        return {_CLEANUP[index + 1]} if index + 1 < len(_CLEANUP) else set()
    allowed = {"stop"}
    if all(entry["result"] == "succeeded" for entry in history) and len(history) < len(_SETUP):
        allowed.add(_SETUP[len(history)])
    return allowed


def _validate(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != _FIELDS:
        raise _fail("invalid record fields")
    if document["schema_version"] != SCHEMA:
        raise _fail("unsupported record schema")
    identity = OwnedUserService.from_mapping(document["identity"])
    if _text(document["identity_digest"], _DIGEST) != identity.digest:
        raise _fail("identity digest mismatch")
    _text(document["request_id"], _REQUEST)
    revision = _revision(document["revision"])
    history = document["operations"]
    if not isinstance(history, list) or len(history) > 32:
        raise _fail("operation history exceeds its bound")
    prefix: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for entry in history:
        if not isinstance(entry, dict) or set(entry) != {"operation_id", "operation", "result"}:
            raise _fail("invalid operation fields")
        identifier = _text(entry["operation_id"], _OPERATION_ID)
        if identifier in identifiers:
            raise _fail("duplicate operation identifier")
        identifiers.add(identifier)
        if not isinstance(entry["operation"], str) or entry["operation"] not in _next_allowed(
            prefix
        ):
            raise _fail("invalid lifecycle transition")
        if not isinstance(entry["result"], str) or entry["result"] not in _RESULTS:
            raise _fail("invalid operation result")
        prefix.append(entry)
    expected = len(history) * 2 - int(bool(history) and history[-1]["result"] == "pending")
    if revision != expected:
        raise _fail("revision does not match operation history")
    if len(canonical_json_bytes(document)) > _MAX_BYTES:
        raise _fail("record exceeds its byte bound")
    return document


def _view(document: dict[str, Any]) -> Mapping[str, Any]:
    # JSON round-trip avoids exposing a caller-mutable retained state object.
    result: dict[str, Any] = json.loads(canonical_json_bytes(document))
    history = result["operations"]
    recovery = "cleanup_required"
    if history and history[-1]["result"] == "pending":
        recovery = "inspection_required"
    elif (
        history
        and history[-1]["operation"] == "reload_after_cleanup"
        and history[-1]["result"] == "succeeded"
    ):
        recovery = "verification_required"
    result["recovery_state"] = recovery
    return result


class ServiceIntentJournal:
    """Private single-resource histories with serialized optimistic revisions.

    ``reserve`` is idempotent only for the same request and exact identity. The
    generated unit nonce remains reserved even after recorded cleanup. This does
    not prove initial resource absence; the coordinator must inspect that. Each
    ``begin`` commits before returning; a future coordinator must call it before
    any effect. ``finish`` records one known completion, including an unknown
    outcome after reconciliation. Reopening never retries or resolves an intent.
    Cleanup retries preserve failed history; creation operations cannot repeat.
    All successful cleanup steps still require an independent observer.
    """

    def __init__(self, path: Path):
        if not isinstance(path, Path) or path.name in {"", ":memory:"}:
            raise _fail("database requires a private filesystem path")
        self._path = path.absolute()
        try:
            self._storage = PrivateJournalStorage(self._path)
        except (OSError, LocalLockError, RunnerTrustError, WindowsOwnerAclError) as exc:
            raise _fail("database requires existing owner-private storage") from exc
        self._path = self._storage.path
        with self._transaction(initialize=True):
            pass

    @contextmanager
    def _transaction(self, *, initialize: bool = False) -> Iterator[sqlite3.Connection]:
        try:
            with self._storage.lease():
                with self._sqlite_transaction(initialize=initialize) as connection:
                    yield connection
        except (
            sqlite3.Error,
            OSError,
            LocalLockError,
            RunnerTrustError,
            WindowsOwnerAclError,
        ) as exc:
            raise _fail("database operation failed") from exc

    @contextmanager
    def _sqlite_transaction(self, *, initialize: bool) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            if not initialize and not self._path.is_file():
                raise _fail("database is missing")
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None
            )
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            objects = connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if initialize and not objects and application_id == 0 and version == 0:
                connection.execute(
                    "CREATE TABLE service_intents (identity_digest TEXT PRIMARY KEY NOT NULL, "
                    "request_id TEXT UNIQUE NOT NULL, unit_nonce TEXT UNIQUE NOT NULL, "
                    "document BLOB NOT NULL, record_hash TEXT NOT NULL)"
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute("PRAGMA user_version=1")
            else:
                if (
                    objects != [("table", "service_intents")]
                    or application_id != _APPLICATION_ID
                    or version != 1
                ):
                    raise _fail("database schema is invalid")
                columns = connection.execute("PRAGMA table_info(service_intents)").fetchall()
                expected = [
                    (0, "identity_digest", "TEXT", 1, None, 1),
                    (1, "request_id", "TEXT", 1, None, 0),
                    (2, "unit_nonce", "TEXT", 1, None, 0),
                    (3, "document", "BLOB", 1, None, 0),
                    (4, "record_hash", "TEXT", 1, None, 0),
                ]
                if columns != expected:
                    raise _fail("database columns are invalid")
            yield connection
            self._storage.check()
            connection.commit()
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    @staticmethod
    def _load(connection: sqlite3.Connection, identity_digest: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT request_id, unit_nonce, length(document), record_hash "
            "FROM service_intents WHERE identity_digest=?",
            (identity_digest,),
        ).fetchone()
        if row is None:
            raise _fail("identity is not reserved")
        request_id, unit_nonce, length, record_hash = row
        if type(length) is not int or not 1 <= length <= _MAX_BYTES:
            raise _fail("stored record exceeds its bound")
        raw = connection.execute(
            "SELECT document FROM service_intents WHERE identity_digest=?", (identity_digest,)
        ).fetchone()[0]
        if type(raw) is not bytes:
            raise _fail("stored record encoding is invalid")
        try:
            document = _validate(json.loads(raw))
            if canonical_json_bytes(document) != raw or content_hash(document) != record_hash:
                raise _fail("stored record integrity mismatch")
            if (
                document["identity_digest"] != identity_digest
                or document["request_id"] != request_id
            ):
                raise _fail("stored identity binding mismatch")
            if document["identity"]["unit_nonce"] != unit_nonce:
                raise _fail("stored resource binding mismatch")
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("stored record is invalid") from exc
        return document

    @staticmethod
    def _save(connection: sqlite3.Connection, document: dict[str, Any]) -> None:
        _validate(document)
        connection.execute(
            "UPDATE service_intents SET document=?,record_hash=? WHERE identity_digest=?",
            (canonical_json_bytes(document), content_hash(document), document["identity_digest"]),
        )

    def reserve(self, identity: OwnedUserService, request_id: str) -> Mapping[str, Any]:
        if not isinstance(identity, OwnedUserService):
            raise _fail("invalid owned-service identity")
        _text(request_id, _REQUEST)
        unit_nonce = identity.to_dict()["unit_nonce"]
        with self._transaction() as connection:
            matches = connection.execute(
                "SELECT identity_digest FROM service_intents "
                "WHERE identity_digest=? OR request_id=? OR unit_nonce=?",
                (identity.digest, request_id, unit_nonce),
            ).fetchall()
            if matches:
                if len(matches) != 1 or matches[0][0] != identity.digest:
                    raise _fail("request or resource nonce is already bound to another identity")
                document = self._load(connection, identity.digest)
                if (
                    document["request_id"] != request_id
                    or document["identity"] != identity.to_dict()
                ):
                    raise _fail("identity is already bound to another request")
            else:
                document = _validate(
                    {
                        "schema_version": SCHEMA,
                        "identity": identity.to_dict(),
                        "identity_digest": identity.digest,
                        "request_id": request_id,
                        "revision": 0,
                        "operations": [],
                    }
                )
                connection.execute(
                    "INSERT INTO service_intents VALUES(?,?,?,?,?)",
                    (
                        identity.digest,
                        request_id,
                        unit_nonce,
                        canonical_json_bytes(document),
                        content_hash(document),
                    ),
                )
        return _view(document)

    def begin(
        self, identity_digest: str, operation: str, expected_revision: int
    ) -> Mapping[str, Any]:
        _text(identity_digest, _DIGEST)
        _revision(expected_revision)
        with self._transaction() as connection:
            document = self._load(connection, identity_digest)
            if document["revision"] != expected_revision:
                raise _fail("stale revision")
            history = document["operations"]
            if not isinstance(operation, str) or operation not in _next_allowed(history):
                raise _fail("operation requires inspection or violates lifecycle order")
            if len(history) >= 32:
                raise _fail("operation history is full")
            history.append(
                {"operation_id": "op-" + uuid4().hex, "operation": operation, "result": "pending"}
            )
            document["revision"] += 1
            self._save(connection, document)
        return _view(document)

    def finish(
        self, identity_digest: str, operation_id: str, result: str, expected_revision: int
    ) -> Mapping[str, Any]:
        _text(identity_digest, _DIGEST)
        _text(operation_id, _OPERATION_ID)
        _revision(expected_revision)
        if not isinstance(result, str) or result not in _RESULTS - {"pending"}:
            raise _fail("completion result must be succeeded, failed or unknown")
        with self._transaction() as connection:
            document = self._load(connection, identity_digest)
            if document["revision"] != expected_revision:
                raise _fail("stale revision")
            history = document["operations"]
            if (
                not history
                or history[-1]["operation_id"] != operation_id
                or history[-1]["result"] != "pending"
            ):
                raise _fail("completion does not match the pending intent")
            history[-1]["result"] = result
            document["revision"] += 1
            self._save(connection, document)
        return _view(document)

    def get(self, identity_digest: str) -> Mapping[str, Any]:
        _text(identity_digest, _DIGEST)
        with self._transaction() as connection:
            document = self._load(connection, identity_digest)
        return _view(document)

    def pending_binding(
        self,
        identity_digest: str,
        expected_revision: int,
        *,
        reviewed_scope_digest: str,
        manager_installation_digest: str,
        payload_installation_digest: str,
    ) -> ServiceOperationBinding:
        """Snapshot one committed pending intent without updating or authorizing it.

        The digests are explicit inputs from future reviewed setup. This read
        neither authenticates them nor locks an effect across the handoff. The
        runner still needs its own durable reservation and live authority checks.
        A reopened pending intent remains inspection-required, never dispatchable
        merely because its binding can be reconstructed.
        """
        _text(identity_digest, _DIGEST)
        _revision(expected_revision)
        with self._transaction() as connection:
            document = self._load(connection, identity_digest)
            history = document["operations"]
            if document["revision"] != expected_revision:
                raise _fail("stale revision")
            if not history or history[-1]["result"] != "pending":
                raise _fail("no pending operation to bind")
            operation = history[-1]
            return ServiceOperationBinding.from_mapping(
                {
                    "schema_version": "bluefire.service-operation-binding.v1",
                    "identity": document["identity"],
                    "identity_digest": identity_digest,
                    "journal_request_id": document["request_id"],
                    "journal_revision": document["revision"],
                    "journal_record_hash": content_hash(document),
                    "operation_id": operation["operation_id"],
                    "operation": operation["operation"],
                    "reviewed_scope_digest": reviewed_scope_digest,
                    "manager_installation_digest": manager_installation_digest,
                    "payload_installation_digest": payload_installation_digest,
                }
            )
