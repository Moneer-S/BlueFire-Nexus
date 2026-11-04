"""Private immutable v19 tenant action material slots.

Only the installed controller uses these methods. A slot and its v16
preparation (including any approval) commit together on one connection.
There is deliberately no listing, resource kind, public projection, or repair.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, cast

from .engine_action_preparation import (
    EngineWorkspaceAction,
    PreparedEngineActionLimits,
    ProtectedActionFactory,
)
from .local_lock import DatabaseIdentity
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError, ResourceConflictError
from .product_store_serialization import canonical_json
from .util import content_hash

SLOT_SCHEMA = "bluefire.tenant-action-material-slot.v1"
MAX_DOCUMENT_BYTES = 128 * 1024
_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SlotValidator = Callable[[Mapping[str, Any]], Mapping[str, Any]]
_READ_SCOPE: ContextVar[tuple[Path, DatabaseIdentity, int, sqlite3.Connection] | None] = ContextVar(
    "tenant_material_read_scope", default=None
)


class TenantActionMaterialStore(Protocol):
    path: Path
    _database_identity: DatabaseIdentity

    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    def _create_engine_action_preparation_at(
        self,
        connection: sqlite3.Connection,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        workspace_digest: str,
        action: EngineWorkspaceAction,
        limits: PreparedEngineActionLimits | Mapping[str, Any],
        prepared_at: str,
        expires_at: str,
        protected_factory: ProtectedActionFactory,
        approval_request: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...


@contextmanager
def _read_scope(store: TenantActionMaterialStore, connection: sqlite3.Connection) -> Iterator[None]:
    """Reopen retained authority on the transaction's exact pinned database.

    Context and thread identity prevent cross-thread connection reuse. A
    finally reset prevents leakage after refusal, rollback, or factory failure.
    """
    if _READ_SCOPE.get() is not None or not connection.in_transaction:
        raise ProductStoreError("tenant material read scope requires one owning transaction")
    token = _READ_SCOPE.set(
        (store.path, store._database_identity, threading.get_ident(), connection)
    )
    try:
        yield
    finally:
        _READ_SCOPE.reset(token)


def _scoped_read_connection(
    path: Path, identity: DatabaseIdentity, *, write: bool
) -> sqlite3.Connection | None:
    current = _READ_SCOPE.get()
    if current is None:
        return None
    pinned_path, pinned_identity, thread_id, connection = current
    if path != pinned_path:
        return None
    if thread_id != threading.get_ident():
        raise ProductStoreError("tenant material read scope cannot cross threads")
    if identity != pinned_identity:
        raise ProductStoreError("tenant material read scope database identity changed")
    if write:
        raise ProductStoreError("tenant material factory cannot open a nested write")
    if not connection.in_transaction:
        raise ProductStoreError("tenant material read scope lost its transaction")
    return connection


def initialize_schema(connection: sqlite3.Connection) -> None:
    if not connection.in_transaction:
        raise ProductStoreError("tenant material migration requires one transaction")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS tenant_action_material_slots (
          experiment_id TEXT NOT NULL,
          experiment_revision INTEGER NOT NULL CHECK(experiment_revision BETWEEN 1 AND 10000),
          experiment_digest TEXT NOT NULL CHECK(length(experiment_digest)=71
            AND substr(experiment_digest,1,7)='sha256:'
            AND substr(experiment_digest,8) NOT GLOB '*[^0-9a-f]*'),
          action_kind TEXT NOT NULL CHECK(action_kind IN ('start_baseline',
            'review_defense', 'apply_defense', 'repeat_mechanism', 'start_adaptive_search',
            'run_legitimate_use', 'retain_defense', 'rollback_defense')),
          document_json TEXT NOT NULL CHECK(json_valid(document_json))
            CHECK(length(CAST(document_json AS BLOB)) BETWEEN 1 AND 131072)
            CHECK(json_extract(document_json,'$.schema_version') IS
              'bluefire.tenant-action-material-slot.v1')
            CHECK(json_extract(document_json,'$.experiment_id') IS experiment_id)
            CHECK(json_type(document_json,'$.experiment_revision') IS 'integer'
              AND json_extract(document_json,'$.experiment_revision') IS experiment_revision)
            CHECK(json_extract(document_json,'$.experiment_digest') IS experiment_digest)
            CHECK(json_extract(document_json,'$.action_kind') IS action_kind),
          slot_digest TEXT NOT NULL UNIQUE CHECK(length(slot_digest)=71
            AND substr(slot_digest,1,7)='sha256:'
            AND substr(slot_digest,8) NOT GLOB '*[^0-9a-f]*'),
          preparation_ref TEXT NOT NULL UNIQUE CHECK(length(preparation_ref)=71
            AND substr(preparation_ref,1,7)='sha256:'
            AND substr(preparation_ref,8) NOT GLOB '*[^0-9a-f]*'),
          preparation_record_digest TEXT NOT NULL CHECK(length(preparation_record_digest)=71
            AND substr(preparation_record_digest,1,7)='sha256:'
            AND substr(preparation_record_digest,8) NOT GLOB '*[^0-9a-f]*'),
          PRIMARY KEY(experiment_id,experiment_revision,experiment_digest,action_kind),
          FOREIGN KEY(experiment_id,experiment_revision)
            REFERENCES engine_experiment_versions(experiment_id,revision),
          FOREIGN KEY(preparation_ref) REFERENCES engine_action_preparations(request_ref)
        )"""
    )
    for suffix, body in (
        (
            "insert",
            """BEFORE INSERT ON tenant_action_material_slots BEGIN
            SELECT CASE WHEN EXISTS(SELECT 1 FROM tenant_action_material_slots
              WHERE experiment_id=NEW.experiment_id AND experiment_revision=NEW.experiment_revision
              AND experiment_digest=NEW.experiment_digest AND action_kind=NEW.action_kind
              OR slot_digest=NEW.slot_digest OR preparation_ref=NEW.preparation_ref)
              THEN RAISE(ABORT,'tenant material slot cannot be replaced') END;
            SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM engine_action_preparations p
              WHERE p.request_ref=NEW.preparation_ref AND p.record_digest=NEW.preparation_record_digest
              AND p.experiment_id=NEW.experiment_id AND p.experiment_revision=NEW.experiment_revision
              AND p.experiment_digest=NEW.experiment_digest AND p.action_kind=NEW.action_kind
              AND p.prepared_at=json_extract(NEW.document_json,'$.material.prepared_at')
              AND p.expires_at=json_extract(NEW.document_json,'$.material.expires_at')
              AND p.workspace_digest=json_extract(NEW.document_json,'$.workspace_digest'))
              THEN RAISE(ABORT,'tenant material preparation provenance changed') END;
            SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM tenant_generation_journal_heads h
              JOIN tenant_generation_journal_versions v
              ON v.owner_id=h.owner_id AND v.revision=h.active_revision
              WHERE h.owner_id=NEW.experiment_id
              AND h.owner_id=json_extract(NEW.document_json,'$.generation_journal.owner_id')
              AND h.journal_id=json_extract(NEW.document_json,'$.generation_journal.journal_id')
              AND json_type(NEW.document_json,'$.generation_journal.revision') IS 'integer'
              AND h.active_revision=json_extract(NEW.document_json,'$.generation_journal.revision')
              AND h.active_digest=json_extract(NEW.document_json,'$.generation_journal.digest')
              AND v.digest=h.active_digest
              AND h.inputs_digest=json_extract(NEW.document_json,'$.generation_journal.inputs_digest')
              AND h.inputs_digest=json_extract(v.document_json,'$.inputs_digest'))
              THEN RAISE(ABORT,'tenant material journal provenance changed') END; END""",
        ),
        (
            "update",
            """BEFORE UPDATE ON tenant_action_material_slots BEGIN
            SELECT RAISE(ABORT,'tenant material slots are immutable'); END""",
        ),
        (
            "delete",
            """BEFORE DELETE ON tenant_action_material_slots BEGIN
            SELECT RAISE(ABORT,'tenant material slots are append-only'); END""",
        ),
    ):
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS tenant_action_material_slots_no_{suffix} {body}"
        )


def _key(experiment_id: str, revision: int, digest: str, action: str) -> tuple[Any, ...]:
    if (
        not isinstance(experiment_id, str)
        or _ID.fullmatch(experiment_id) is None
        or type(revision) is not int
        or not 1 <= revision <= 10000
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or not isinstance(action, str)
    ):
        raise ProductStoreError("tenant material slot identity is invalid")
    return experiment_id, revision, digest, action


def _document(value: Mapping[str, Any], validator: SlotValidator) -> Mapping[str, Any]:
    try:
        result = safe_document(value, context="private tenant action material")
        checked = validator(result)
        if canonical_json(checked) != canonical_json(result):
            raise ProductStoreError("tenant material document is not canonical")
        if not 1 <= len(canonical_json(result).encode("utf-8")) <= MAX_DOCUMENT_BYTES:
            raise ProductStoreError("tenant material document exceeds its bound")
        return cast(Mapping[str, Any], result)
    except ProductStoreError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise ProductStoreError("tenant material document is invalid") from exc


def _read(connection: sqlite3.Connection, key: tuple[Any, ...]) -> Mapping[str, Any] | None:
    row = connection.execute(
        """SELECT * FROM tenant_action_material_slots WHERE experiment_id=?
        AND experiment_revision=? AND experiment_digest=? AND action_kind=?""",
        key,
    ).fetchone()
    if row is None:
        return None
    try:
        document = json.loads(row["document_json"])
        preparation = connection.execute(
            "SELECT * FROM engine_action_preparations WHERE request_ref=?",
            (row["preparation_ref"],),
        ).fetchone()
        if (
            canonical_json(document) != row["document_json"]
            or content_hash(document) != row["slot_digest"]
            or not 1 <= len(row["document_json"].encode("utf-8")) <= MAX_DOCUMENT_BYTES
            or tuple(
                document[name]
                for name in (
                    "experiment_id",
                    "experiment_revision",
                    "experiment_digest",
                    "action_kind",
                )
            )
            != key
            or preparation is None
            or preparation["record_digest"] != row["preparation_record_digest"]
            or tuple(
                preparation[name]
                for name in (
                    "experiment_id",
                    "experiment_revision",
                    "experiment_digest",
                    "action_kind",
                )
            )
            != key
            or preparation["workspace_digest"] != document["workspace_digest"]
            or preparation["prepared_at"] != document["material"]["prepared_at"]
            or preparation["expires_at"] != document["material"]["expires_at"]
        ):
            raise ProductStoreError("tenant material slot integrity check failed")
    except (ValueError, TypeError, KeyError) as exc:
        raise ProductStoreError("tenant material slot integrity check failed") from exc
    return {
        "document": document,
        "slot_digest": row["slot_digest"],
        "preparation_ref": row["preparation_ref"],
        "preparation_record_digest": row["preparation_record_digest"],
    }


class TenantActionMaterialStoreMixin:
    """Private exact reads and CAS issuance; no public getter or enumeration."""

    def _read_tenant_action_material_slot(
        self: TenantActionMaterialStore,
        *,
        experiment_id: str,
        experiment_revision: int,
        experiment_digest: str,
        action_kind: str,
    ) -> Mapping[str, Any] | None:
        key = _key(experiment_id, experiment_revision, experiment_digest, action_kind)
        with self._connection() as connection:
            if not connection.in_transaction:
                connection.execute("BEGIN")
            return _read(connection, key)

    def _retain_tenant_action_material_preparation(
        self: TenantActionMaterialStore,
        *,
        document: Mapping[str, Any],
        validator: SlotValidator,
        preparation_values: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        checked = _document(document, validator)
        key = _key(
            checked["experiment_id"],
            checked["experiment_revision"],
            checked["experiment_digest"],
            checked["action_kind"],
        )
        with self._connection(write=True) as connection, _read_scope(self, connection):
            existing = _read(connection, key)
            if existing is not None and canonical_json(existing["document"]) != canonical_json(
                checked
            ):
                raise ResourceConflictError("tenant material slot CAS preimage changed")
            if (
                existing is None
                and connection.execute(
                    """SELECT 1 FROM engine_action_preparations WHERE experiment_id=?
                AND experiment_revision=? AND experiment_digest=? AND action_kind=? LIMIT 1""",
                    key,
                ).fetchone()
                is not None
            ):
                raise ResourceConflictError("tenant material cannot adopt an orphan preparation")
            # Validator reopens current runtime/generation/admission even on exact retry.
            _document(checked, validator)
            journal = checked["generation_journal"]
            head = connection.execute(
                """SELECT * FROM tenant_generation_journal_heads
                WHERE owner_id=? AND journal_id=?""",
                (journal["owner_id"], journal["journal_id"]),
            ).fetchone()
            version = (
                None
                if head is None
                else connection.execute(
                    """SELECT document_json,digest FROM tenant_generation_journal_versions
                WHERE owner_id=? AND revision=?""",
                    (journal["owner_id"], journal["revision"]),
                ).fetchone()
            )
            if (
                head is None
                or version is None
                or head["active_revision"] != journal["revision"]
                or head["active_digest"] != journal["digest"]
                or head["inputs_digest"] != journal["inputs_digest"]
                or version["digest"] != journal["digest"]
                or content_hash(json.loads(version["document_json"])) != journal["digest"]
            ):
                raise ResourceConflictError("tenant material generation journal head changed")
            protected = self._create_engine_action_preparation_at(connection, **preparation_values)
            preparation = connection.execute(
                "SELECT record_digest FROM engine_action_preparations WHERE request_ref=?",
                (protected["request_ref"],),
            ).fetchone()
            if preparation is None:
                raise ProductStoreError("tenant material preparation was not retained")
            _document(checked, validator)
            if existing is not None:
                if (
                    existing["preparation_ref"] != protected["request_ref"]
                    or existing["preparation_record_digest"] != preparation["record_digest"]
                ):
                    raise ResourceConflictError("tenant material preparation provenance changed")
                return protected
            # Adoption of an unrelated/orphan preparation is forbidden.
            if protected["prepared_at"] != checked["material"]["prepared_at"]:
                raise ResourceConflictError("tenant material preparation time changed")
            connection.execute(
                """INSERT INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)""",
                (
                    *key,
                    canonical_json(checked),
                    content_hash(checked),
                    protected["request_ref"],
                    preparation["record_digest"],
                ),
            )
            return protected
