"""Private v18 tenant-generation journals in the existing protected ProductStore.

These tables are deliberately separate from experiments and generic resources.
Only exact controller-owned owner/journal pairs can be read; no public listing,
resource kind, export, scheduling, or execution authority is introduced here.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, Mapping, Protocol, cast

from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json, utc_now
from .util import content_hash

JOURNAL_SCHEMA = "bluefire.tenant-record-generation-journal.v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_JOURNAL_REVISIONS = 4096
_IDENTITY = re.compile(r"^experiment-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
JournalValidator = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class TenantGenerationJournalStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Install private append-only journals inside the v18 migration transaction."""
    if not connection.in_transaction:
        raise ProductStoreError("tenant generation migration requires one transaction")
    statements = (
        """CREATE TABLE IF NOT EXISTS tenant_generation_journal_versions (
            owner_id TEXT NOT NULL CHECK (length(owner_id) = 43
                AND substr(owner_id, 1, 11) = 'experiment-'
                AND substr(owner_id, 12) NOT GLOB '*[^0-9a-f]*'),
            journal_id TEXT NOT NULL CHECK (length(journal_id) = 43
                AND substr(journal_id, 1, 11) = 'experiment-'
                AND substr(journal_id, 12) NOT GLOB '*[^0-9a-f]*'),
            revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 4096),
            document_json TEXT NOT NULL CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) BETWEEN 1 AND 1048576)
                CHECK (json_type(document_json, '$.schema_version') IS 'text'
                    AND json_extract(document_json, '$.schema_version') IS
                    'bluefire.tenant-record-generation-journal.v1')
                CHECK (json_type(document_json, '$.experiment_id') IS 'text'
                    AND json_extract(document_json, '$.experiment_id') IS journal_id)
                CHECK (json_type(document_json, '$.revision') IS 'integer'
                    AND json_extract(document_json, '$.revision') IS revision)
                CHECK (json_type(document_json, '$.inputs_digest') IS 'text'
                    AND length(json_extract(document_json, '$.inputs_digest')) = 71
                    AND substr(json_extract(document_json, '$.inputs_digest'), 1, 7) = 'sha256:'
                    AND substr(json_extract(document_json, '$.inputs_digest'), 8) NOT GLOB '*[^0-9a-f]*'),
            digest TEXT NOT NULL CHECK (length(digest) = 71 AND substr(digest, 1, 7) = 'sha256:'
                AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'),
            prior_digest TEXT CHECK (prior_digest IS NULL OR
                (length(prior_digest) = 71 AND substr(prior_digest, 1, 7) = 'sha256:'
                 AND substr(prior_digest, 8) NOT GLOB '*[^0-9a-f]*')),
            created_at TEXT NOT NULL,
            PRIMARY KEY (owner_id, revision),
            UNIQUE (journal_id, revision),
            UNIQUE (owner_id, digest),
            CHECK ((revision = 1 AND prior_digest IS NULL) OR
                   (revision > 1 AND prior_digest IS NOT NULL))
        )""",
        """CREATE TABLE IF NOT EXISTS tenant_generation_journal_heads (
            owner_id TEXT PRIMARY KEY NOT NULL CHECK (length(owner_id) = 43
                AND substr(owner_id, 1, 11) = 'experiment-'
                AND substr(owner_id, 12) NOT GLOB '*[^0-9a-f]*'),
            journal_id TEXT NOT NULL UNIQUE CHECK (length(journal_id) = 43
                AND substr(journal_id, 1, 11) = 'experiment-'
                AND substr(journal_id, 12) NOT GLOB '*[^0-9a-f]*'),
            inputs_digest TEXT NOT NULL CHECK (length(inputs_digest) = 71
                AND substr(inputs_digest, 1, 7) = 'sha256:'
                AND substr(inputs_digest, 8) NOT GLOB '*[^0-9a-f]*'),
            active_revision INTEGER NOT NULL CHECK (active_revision BETWEEN 1 AND 4096),
            active_digest TEXT NOT NULL CHECK (length(active_digest) = 71
                AND substr(active_digest, 1, 7) = 'sha256:'
                AND substr(active_digest, 8) NOT GLOB '*[^0-9a-f]*'),
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_id, active_revision)
                REFERENCES tenant_generation_journal_versions(owner_id, revision)
        )""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_versions_valid_insert
        BEFORE INSERT ON tenant_generation_journal_versions BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM tenant_generation_journal_versions
                WHERE (owner_id = NEW.owner_id AND
                       (revision = NEW.revision OR digest = NEW.digest))
                   OR (journal_id = NEW.journal_id AND revision = NEW.revision)
            ) THEN RAISE(ABORT, 'tenant journal history cannot be replaced') END;
            SELECT CASE WHEN NEW.revision = 1 AND EXISTS (
                SELECT 1 FROM tenant_generation_journal_versions
                WHERE owner_id = NEW.owner_id OR journal_id = NEW.journal_id
            ) THEN RAISE(ABORT, 'tenant journal owner already has history') END;
            SELECT CASE WHEN NEW.revision > 1 AND NOT EXISTS (
                SELECT 1 FROM tenant_generation_journal_heads
                WHERE owner_id = NEW.owner_id AND journal_id = NEW.journal_id
                  AND active_revision = NEW.revision - 1 AND active_digest = NEW.prior_digest
                  AND inputs_digest = json_extract(NEW.document_json, '$.inputs_digest')
            ) THEN RAISE(ABORT, 'tenant journal does not extend its exact head') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_versions_no_update
        BEFORE UPDATE ON tenant_generation_journal_versions BEGIN
            SELECT RAISE(ABORT, 'tenant journal versions are immutable'); END""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_versions_no_delete
        BEFORE DELETE ON tenant_generation_journal_versions BEGIN
            SELECT RAISE(ABORT, 'tenant journal versions are append-only'); END""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_heads_valid_insert
        BEFORE INSERT ON tenant_generation_journal_heads BEGIN
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM tenant_generation_journal_heads
                WHERE owner_id = NEW.owner_id OR journal_id = NEW.journal_id
            ) THEN RAISE(ABORT, 'tenant journal head cannot be replaced') END;
            SELECT CASE WHEN NEW.active_revision != 1 OR NOT EXISTS (
                SELECT 1 FROM tenant_generation_journal_versions
                WHERE owner_id = NEW.owner_id AND journal_id = NEW.journal_id
                  AND revision = 1 AND digest = NEW.active_digest
                  AND json_extract(document_json, '$.inputs_digest') = NEW.inputs_digest
            ) THEN RAISE(ABORT, 'tenant journal initial head is invalid') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_heads_valid_update
        BEFORE UPDATE ON tenant_generation_journal_heads BEGIN
            SELECT CASE WHEN NEW.owner_id != OLD.owner_id OR NEW.journal_id != OLD.journal_id
                OR NEW.inputs_digest != OLD.inputs_digest
                OR NEW.active_revision != OLD.active_revision + 1 OR NOT EXISTS (
                    SELECT 1 FROM tenant_generation_journal_versions
                    WHERE owner_id = OLD.owner_id AND journal_id = OLD.journal_id
                      AND revision = NEW.active_revision AND digest = NEW.active_digest
                      AND prior_digest = OLD.active_digest
                      AND json_extract(document_json, '$.inputs_digest') = OLD.inputs_digest
                ) THEN RAISE(ABORT, 'tenant journal head transition is invalid') END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS tenant_generation_journal_heads_no_delete
        BEFORE DELETE ON tenant_generation_journal_heads BEGIN
            SELECT RAISE(ABORT, 'tenant journal heads are append-only'); END""",
    )
    for statement in statements:
        connection.execute(statement)


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        raise ProductStoreError(f"tenant generation {label} identity is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"tenant generation {label} digest is invalid")
    return value


def _revision(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_JOURNAL_REVISIONS:
        raise ProductStoreError("tenant generation journal revision is out of bounds")
    return value


def _document(
    journal_id: str, value: Mapping[str, Any], revision: int, validator: JournalValidator
) -> Mapping[str, Any]:
    try:
        document = safe_document(value, context="private tenant generation journal")
        document = safe_document(validator(document), context="private tenant generation journal")
        encoded = canonical_json(document).encode("utf-8")
    except ProductStoreError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise ProductStoreError("tenant generation journal contract is invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != JOURNAL_SCHEMA
        or document.get("experiment_id") != journal_id
        or type(document.get("revision")) is not int
        or document.get("revision") != revision
    ):
        raise ProductStoreError("tenant generation journal identity is mismatched")
    _digest(document.get("inputs_digest"), "protected inputs")
    if not 1 <= len(encoded) <= MAX_DOCUMENT_BYTES:
        raise ProductStoreError("tenant generation journal document exceeds its byte bound")
    return cast(Mapping[str, Any], document)


def _records(
    connection: sqlite3.Connection, owner_id: str, journal_id: str
) -> tuple[sqlite3.Row, list[sqlite3.Row]]:
    if not connection.in_transaction:
        connection.execute("BEGIN")  # One coherent head/history/document read snapshot.
    head = connection.execute(
        "SELECT * FROM tenant_generation_journal_heads WHERE owner_id = ? AND journal_id = ?",
        (owner_id, journal_id),
    ).fetchone()
    if head is None:
        raise ProductStoreError("tenant generation journal was not found")
    rows = connection.execute(
        """SELECT owner_id, journal_id, revision, digest, prior_digest, created_at
           FROM tenant_generation_journal_versions
           WHERE owner_id = ? ORDER BY revision""",
        (owner_id,),
    ).fetchall()
    if not rows or len(rows) != int(head["active_revision"]) or len(rows) > MAX_JOURNAL_REVISIONS:
        raise ProductStoreError("tenant generation journal history is incomplete")
    previous = None
    for revision, row in enumerate(rows, 1):
        valid = (
            row["journal_id"] == journal_id
            and int(row["revision"]) == revision
            and row["prior_digest"] == previous
            and _DIGEST.fullmatch(str(row["digest"])) is not None
        )
        if not valid:
            raise ProductStoreError("tenant generation journal integrity check failed")
        previous = row["digest"]
    if previous != head["active_digest"]:
        raise ProductStoreError("tenant generation journal head digest changed")
    _record(connection, rows[-1], head)  # Exact active bytes, never all history payloads.
    return head, rows


def _record(
    connection: sqlite3.Connection, metadata: sqlite3.Row, head: sqlite3.Row
) -> Mapping[str, Any]:
    row = connection.execute(
        """SELECT * FROM tenant_generation_journal_versions
           WHERE owner_id = ? AND revision = ?""",
        (metadata["owner_id"], metadata["revision"]),
    ).fetchone()
    if row is None:
        raise ProductStoreError("tenant generation journal revision was not found")
    try:
        document = json.loads(row["document_json"])
        valid = (
            canonical_json(document) == row["document_json"]
            and 1 <= len(row["document_json"].encode("utf-8")) <= MAX_DOCUMENT_BYTES
            and content_hash(document) == row["digest"]
            and document.get("schema_version") == JOURNAL_SCHEMA
            and document.get("experiment_id") == row["journal_id"] == head["journal_id"]
            and row["owner_id"] == head["owner_id"]
            and type(document.get("revision")) is int
            and document["revision"] == row["revision"]
            and document.get("inputs_digest") == head["inputs_digest"]
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise ProductStoreError("tenant generation journal integrity check failed") from exc
    if not valid:
        raise ProductStoreError("tenant generation journal integrity check failed")
    return {
        "schema_version": "bluefire.tenant-generation-journal-record.v1",
        "owner_id": row["owner_id"],
        "journal_id": row["journal_id"],
        "revision": row["revision"],
        "digest": row["digest"],
        "prior_digest": row["prior_digest"],
        "document": document,
        "created_at": row["created_at"],
        "active_revision": head["active_revision"],
        "active": row["revision"] == head["active_revision"],
    }


class TenantGenerationJournalStoreMixin:
    """Installed-controller methods only; deliberately no generic/public listing."""

    def _create_tenant_generation_journal(
        self: TenantGenerationJournalStore,
        owner_id: str,
        journal_id: str,
        document: Mapping[str, Any],
        *,
        validator: JournalValidator,
    ) -> Mapping[str, Any]:
        owner, journal = _identity(owner_id, "owner"), _identity(journal_id, "journal")
        payload = _document(journal, document, 1, validator)
        encoded, digest, now = canonical_json(payload), content_hash(payload), utc_now()
        with self._connection(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM tenant_generation_journal_heads WHERE owner_id = ? OR journal_id = ?",
                (owner, journal),
            ).fetchone()
            if existing is not None:
                if existing["owner_id"] != owner or existing["journal_id"] != journal:
                    raise ResourceConflictError("tenant generation owner already has a journal")
                head, rows = _records(connection, owner, journal)
                first = _record(connection, rows[0], head)
                if canonical_json(first["document"]) != encoded or first["digest"] != digest:
                    raise ResourceConflictError("tenant generation initial history changed")
                return first
            try:
                connection.execute(
                    """INSERT INTO tenant_generation_journal_versions
                       (owner_id, journal_id, revision, document_json, digest, prior_digest, created_at)
                       VALUES (?, ?, 1, ?, ?, NULL, ?)""",
                    (owner, journal, encoded, digest, now),
                )
                connection.execute(
                    """INSERT INTO tenant_generation_journal_heads
                       (owner_id, journal_id, inputs_digest, active_revision, active_digest, updated_at)
                       VALUES (?, ?, ?, 1, ?, ?)""",
                    (owner, journal, payload["inputs_digest"], digest, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError(
                    "tenant generation journal creation conflicted"
                ) from exc
            head, rows = _records(connection, owner, journal)
            return _record(connection, rows[0], head)

    def _get_tenant_generation_journal(
        self: TenantGenerationJournalStore,
        owner_id: str,
        journal_id: str,
        *,
        revision: int | None = None,
    ) -> Mapping[str, Any]:
        owner, journal = _identity(owner_id, "owner"), _identity(journal_id, "journal")
        selected = None if revision is None else _revision(revision)
        with self._connection() as connection:
            head, rows = _records(connection, owner, journal)
            selected = int(head["active_revision"]) if selected is None else selected
            if selected > len(rows):
                raise ProductStoreError("tenant generation journal revision was not found")
            return _record(connection, rows[selected - 1], head)

    def _save_tenant_generation_journal(
        self: TenantGenerationJournalStore,
        owner_id: str,
        journal_id: str,
        document: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_digest: str,
        validator: JournalValidator,
    ) -> Mapping[str, Any]:
        owner, journal = _identity(owner_id, "owner"), _identity(journal_id, "journal")
        prior_revision = _revision(expected_revision)
        prior_digest = _digest(expected_digest, "expected head")
        next_revision = _revision(prior_revision + 1)
        payload = _document(journal, document, next_revision, validator)
        encoded, digest, now = canonical_json(payload), content_hash(payload), utc_now()
        with self._connection(write=True) as connection:
            head, rows = _records(connection, owner, journal)
            if head["active_revision"] == next_revision and head["active_digest"] == digest:
                row = rows[-1]
                selected = _record(connection, row, head)
                if (
                    row["prior_digest"] == prior_digest
                    and canonical_json(selected["document"]) == encoded
                ):
                    return selected  # Exact durable acknowledgement retry only.
            if head["active_revision"] != prior_revision or head["active_digest"] != prior_digest:
                raise ResourceConflictError("tenant generation journal CAS preimage changed")
            if payload["inputs_digest"] != head["inputs_digest"]:
                raise ResourceConflictError("tenant generation protected inputs changed")
            try:
                connection.execute(
                    """INSERT INTO tenant_generation_journal_versions
                       (owner_id, journal_id, revision, document_json, digest, prior_digest, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (owner, journal, next_revision, encoded, digest, prior_digest, now),
                )
                cursor = connection.execute(
                    """UPDATE tenant_generation_journal_heads
                       SET active_revision = ?, active_digest = ?, updated_at = ?
                       WHERE owner_id = ? AND journal_id = ? AND active_revision = ? AND active_digest = ?""",
                    (next_revision, digest, now, owner, journal, prior_revision, prior_digest),
                )
                if cursor.rowcount != 1:
                    raise ResourceConflictError("tenant generation journal head lost its CAS")
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError("tenant generation journal append conflicted") from exc
            head, rows = _records(connection, owner, journal)
            return _record(connection, rows[-1], head)

    def _list_tenant_generation_journal_versions(
        self: TenantGenerationJournalStore,
        owner_id: str,
        journal_id: str,
        *,
        limit: int = 100,
    ) -> list[Mapping[str, Any]]:
        owner, journal = _identity(owner_id, "owner"), _identity(journal_id, "journal")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ProductStoreError("tenant generation journal history limit is out of bounds")
        with self._connection() as connection:
            head, rows = _records(connection, owner, journal)
            return [_record(connection, row, head) for row in reversed(rows[-limit:])]
