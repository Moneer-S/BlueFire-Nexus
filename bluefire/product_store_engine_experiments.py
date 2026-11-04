"""Append-only experiment history in the existing product database.

This module persists canonical experiment documents and their active head.  It
does not schedule work, interpret engine output, or grant execution authority.
Every update is a compare-and-swap against an exact revision and digest.
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
from .util import content_hash, json_clone

_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_LIST_LIMIT = 200
_PUBLIC_AUTHORIZATION_DIGEST_FIELDS = frozenset(
    {
        "authorization_ref",
        "authorization_reference",
        "model_authorization_ref",
        "model_authorization_reference",
        "source_authorization_ref",
    }
)
_RAW_PAYLOAD_FIELDS = frozenset(
    {
        "artifact_bytes",
        "raw_artifact_bytes",
        "raw_artifacts",
        "raw_bytes",
        "raw_log",
        "raw_logs",
        "report_body",
        "report_markdown",
        "transcript",
    }
)

ExperimentValidator = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class EngineExperimentStore(Protocol):
    def _connection(self, *, write: bool = False) -> AbstractContextManager[sqlite3.Connection]: ...

    def get_engine_experiment(
        self, experiment_id: str, *, revision: int | None = None
    ) -> Mapping[str, Any]: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Create the experiment history inside the caller's migration transaction."""

    if not connection.in_transaction:
        raise ProductStoreError("Engine experiment migration requires one transaction.")
    statements = (
        """CREATE TABLE IF NOT EXISTS engine_experiment_versions (
            experiment_id TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK (revision > 0),
            document_json TEXT NOT NULL
                CHECK (json_valid(document_json))
                CHECK (length(CAST(document_json AS BLOB)) <= 1048576),
            digest TEXT NOT NULL
                CHECK (length(digest) = 71 AND substr(digest, 1, 7) = 'sha256:'),
            prior_digest TEXT
                CHECK (
                    prior_digest IS NULL OR
                    (length(prior_digest) = 71 AND substr(prior_digest, 1, 7) = 'sha256:')
                ),
            created_at TEXT NOT NULL,
            PRIMARY KEY (experiment_id, revision),
            UNIQUE (experiment_id, digest),
            CHECK (
                (revision = 1 AND prior_digest IS NULL) OR
                (revision > 1 AND prior_digest IS NOT NULL)
            )
        )""",
        """CREATE TABLE IF NOT EXISTS engine_experiment_heads (
            experiment_id TEXT PRIMARY KEY,
            active_revision INTEGER NOT NULL CHECK (active_revision > 0),
            active_digest TEXT NOT NULL
                CHECK (
                    length(active_digest) = 71 AND
                    substr(active_digest, 1, 7) = 'sha256:'
                ),
            updated_at TEXT NOT NULL,
            FOREIGN KEY (experiment_id, active_revision)
                REFERENCES engine_experiment_versions(experiment_id, revision),
            UNIQUE (experiment_id, active_digest)
        )""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_versions_valid_insert
        BEFORE INSERT ON engine_experiment_versions
        BEGIN
            SELECT CASE
                WHEN NEW.revision = 1 AND EXISTS (
                    SELECT 1 FROM engine_experiment_versions
                    WHERE experiment_id = NEW.experiment_id
                )
                THEN RAISE(ABORT, 'engine experiment already has history')
                WHEN NEW.revision > 1 AND NOT EXISTS (
                    SELECT 1 FROM engine_experiment_heads
                    WHERE experiment_id = NEW.experiment_id
                      AND active_revision = NEW.revision - 1
                      AND active_digest = NEW.prior_digest
                )
                THEN RAISE(ABORT, 'engine experiment version does not extend its head')
            END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_versions_no_update
        BEFORE UPDATE ON engine_experiment_versions
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment versions are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_versions_no_delete
        BEFORE DELETE ON engine_experiment_versions
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment versions are immutable');
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_heads_valid_insert
        BEFORE INSERT ON engine_experiment_heads
        BEGIN
            SELECT CASE WHEN
                NEW.active_revision != 1 OR NOT EXISTS (
                    SELECT 1 FROM engine_experiment_versions
                    WHERE experiment_id = NEW.experiment_id
                      AND revision = 1
                      AND digest = NEW.active_digest
                )
                THEN RAISE(ABORT, 'engine experiment head is invalid')
            END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_heads_valid_update
        BEFORE UPDATE ON engine_experiment_heads
        BEGIN
            SELECT CASE WHEN
                NEW.experiment_id != OLD.experiment_id OR
                NEW.active_revision != OLD.active_revision + 1 OR
                NOT EXISTS (
                    SELECT 1 FROM engine_experiment_versions
                    WHERE experiment_id = OLD.experiment_id
                      AND revision = NEW.active_revision
                      AND digest = NEW.active_digest
                      AND prior_digest = OLD.active_digest
                )
                THEN RAISE(ABORT, 'engine experiment head transition is invalid')
            END;
        END""",
        """CREATE TRIGGER IF NOT EXISTS engine_experiment_heads_no_delete
        BEFORE DELETE ON engine_experiment_heads
        BEGIN
            SELECT RAISE(ABORT, 'engine experiment heads cannot be deleted');
        END""",
        """CREATE INDEX IF NOT EXISTS engine_experiment_heads_updated_idx
            ON engine_experiment_heads(updated_at DESC, experiment_id)""",
    )
    for statement in statements:
        connection.execute(statement)


def _experiment_id(value: Any) -> str:
    if not isinstance(value, str) or _EXPERIMENT_ID.fullmatch(value) is None:
        raise ProductStoreError("engine experiment ID is invalid")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProductStoreError(f"{context} must be an exact sha256 digest")
    return value


def _revision(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProductStoreError(f"{context} must be a positive integer")
    return int(value)


def _safe_engine_document(value: Any) -> Mapping[str, Any]:
    """Return secret-safe JSON while allowing public authorization digests.

    ProductStore's general secret scanner deliberately treats every
    authorization-shaped field as secret-bearing.  Engine records store only a
    public digest reference.  A scrubbed clone is scanned while the exact
    digest remains in the returned canonical document.
    """

    try:
        document = json_clone(value)
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine experiment must contain only JSON values") from exc
    if not isinstance(document, dict):
        raise ProductStoreError("engine experiment must be a JSON object")

    scrubbed = json_clone(document)

    def inspect(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                inspect(child)
            return
        if not isinstance(item, dict):
            return
        for key, child in tuple(item.items()):
            normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower().replace("-", "_")
            if normalized in _RAW_PAYLOAD_FIELDS:
                raise ProductStoreError(
                    "engine experiment stores artifact references, not raw artifact payloads"
                )
            if normalized in _PUBLIC_AUTHORIZATION_DIGEST_FIELDS:
                _digest(child, f"engine experiment {normalized}")
                item[key] = None
                continue
            inspect(child)

    inspect(scrubbed)
    safe_document(scrubbed, context="engine experiment")
    try:
        encoded = canonical_json(document).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine experiment is not canonical JSON") from exc
    if not encoded or len(encoded) > _MAX_DOCUMENT_BYTES:
        raise ProductStoreError(
            f"engine experiment cannot exceed {_MAX_DOCUMENT_BYTES} canonical JSON bytes"
        )
    return cast(Mapping[str, Any], document)


def _validated_document(
    experiment_id: str,
    value: Mapping[str, Any],
    *,
    revision: int,
    validator: ExperimentValidator,
) -> Mapping[str, Any]:
    document = _safe_engine_document(value)
    try:
        document = _safe_engine_document(validator(document))
    except ProductStoreError:
        raise
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("engine experiment failed contract validation") from exc
    if document.get("experiment_id") != experiment_id:
        raise ProductStoreError("engine experiment document identity is mismatched")
    document_revision = document.get("revision")
    if document_revision is not None and document_revision != revision:
        raise ProductStoreError("engine experiment document revision is mismatched")
    schema_version = document.get("schema_version")
    if (
        not isinstance(schema_version, str)
        or not schema_version.startswith("bluefire.")
        or len(schema_version) > 120
    ):
        raise ProductStoreError("engine experiment schema version is invalid")
    return document


def _record_from_row(
    row: sqlite3.Row,
    *,
    active_revision: int,
    active_digest: str | None = None,
) -> Mapping[str, Any]:
    try:
        document = json.loads(row["document_json"])
    except (TypeError, ValueError) as exc:
        raise ProductStoreError("saved engine experiment JSON is invalid") from exc
    canonical = canonical_json(document)
    digest = content_hash(document)
    if canonical != row["document_json"] or digest != row["digest"]:
        raise ProductStoreError("saved engine experiment integrity check failed")
    if not isinstance(document, dict) or document.get("experiment_id") != row["experiment_id"]:
        raise ProductStoreError("saved engine experiment identity is invalid")
    if document.get("revision") is not None and document.get("revision") != int(row["revision"]):
        raise ProductStoreError("saved engine experiment revision is invalid")
    if (
        int(row["revision"]) == active_revision
        and active_digest is not None
        and digest != active_digest
    ):
        raise ProductStoreError("saved engine experiment head digest is invalid")
    return {
        "schema_version": "bluefire.engine-experiment-record.v1",
        "experiment_id": str(row["experiment_id"]),
        "revision": int(row["revision"]),
        "prior_digest": str(row["prior_digest"]) if row["prior_digest"] else None,
        "digest": str(row["digest"]),
        "document": document,
        "created_at": str(row["created_at"]),
        "active": int(row["revision"]) == active_revision,
        "active_revision": active_revision,
    }


class EngineExperimentStoreMixin:
    """ProductStore methods for immutable experiment versions and CAS heads."""

    def create_engine_experiment(
        self: EngineExperimentStore,
        experiment_id: str,
        document: Mapping[str, Any],
        *,
        validator: ExperimentValidator,
    ) -> Mapping[str, Any]:
        identity = _experiment_id(experiment_id)
        payload = _validated_document(identity, document, revision=1, validator=validator)
        encoded = canonical_json(payload)
        digest = content_hash(payload)
        now = utc_now()
        with self._connection(write=True) as connection:
            existing = connection.execute(
                """
                SELECT version.*, head.active_revision, head.active_digest
                FROM engine_experiment_versions AS version
                JOIN engine_experiment_heads AS head USING (experiment_id)
                WHERE version.experiment_id = ? AND version.revision = 1
                """,
                (identity,),
            ).fetchone()
            if existing is not None:
                if existing["digest"] != digest or existing["document_json"] != encoded:
                    raise ResourceConflictError(
                        "engine experiment identity already has different history"
                    )
                return _record_from_row(
                    existing,
                    active_revision=int(existing["active_revision"]),
                    active_digest=str(existing["active_digest"]),
                )
            try:
                connection.execute(
                    """
                    INSERT INTO engine_experiment_versions(
                        experiment_id, revision, document_json, digest, prior_digest, created_at
                    ) VALUES (?, 1, ?, ?, NULL, ?)
                    """,
                    (identity, encoded, digest, now),
                )
                connection.execute(
                    """
                    INSERT INTO engine_experiment_heads(
                        experiment_id, active_revision, active_digest, updated_at
                    ) VALUES (?, 1, ?, ?)
                    """,
                    (identity, digest, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError("engine experiment creation lost a race") from exc
        return self.get_engine_experiment(identity, revision=1)

    def save_engine_experiment(
        self: EngineExperimentStore,
        experiment_id: str,
        document: Mapping[str, Any],
        *,
        expected_revision: int,
        expected_digest: str,
        validator: ExperimentValidator,
    ) -> Mapping[str, Any]:
        identity = _experiment_id(experiment_id)
        prior_revision = _revision(expected_revision, "expected engine experiment revision")
        prior_digest = _digest(expected_digest, "expected engine experiment digest")
        next_revision = prior_revision + 1
        payload = _validated_document(
            identity,
            document,
            revision=next_revision,
            validator=validator,
        )
        encoded = canonical_json(payload)
        digest = content_hash(payload)
        if digest == prior_digest:
            raise ProductStoreError("engine experiment update must change the document")
        now = utc_now()
        with self._connection(write=True) as connection:
            head = connection.execute(
                """
                SELECT active_revision, active_digest
                FROM engine_experiment_heads WHERE experiment_id = ?
                """,
                (identity,),
            ).fetchone()
            if head is None:
                raise ProductStoreError("engine experiment was not found")
            if int(head["active_revision"]) == next_revision and head["active_digest"] == digest:
                replay = connection.execute(
                    """
                    SELECT version.*, head.active_revision, head.active_digest
                    FROM engine_experiment_versions AS version
                    JOIN engine_experiment_heads AS head USING (experiment_id)
                    WHERE version.experiment_id = ? AND version.revision = ?
                      AND version.prior_digest = ? AND version.digest = ?
                    """,
                    (identity, next_revision, prior_digest, digest),
                ).fetchone()
                if replay is not None:
                    return _record_from_row(
                        replay,
                        active_revision=int(replay["active_revision"]),
                        active_digest=str(replay["active_digest"]),
                    )
            if (
                int(head["active_revision"]) != prior_revision
                or head["active_digest"] != prior_digest
            ):
                raise ResourceConflictError("engine experiment changed since its expected revision")
            try:
                connection.execute(
                    """
                    INSERT INTO engine_experiment_versions(
                        experiment_id, revision, document_json, digest, prior_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (identity, next_revision, encoded, digest, prior_digest, now),
                )
                cursor = connection.execute(
                    """
                    UPDATE engine_experiment_heads
                    SET active_revision = ?, active_digest = ?, updated_at = ?
                    WHERE experiment_id = ?
                      AND active_revision = ? AND active_digest = ?
                    """,
                    (
                        next_revision,
                        digest,
                        now,
                        identity,
                        prior_revision,
                        prior_digest,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ResourceConflictError("engine experiment update lost a race") from exc
            if cursor.rowcount != 1:
                raise ResourceConflictError("engine experiment update lost a race")
        return self.get_engine_experiment(identity, revision=next_revision)

    def get_engine_experiment(
        self: EngineExperimentStore,
        experiment_id: str,
        *,
        revision: int | None = None,
    ) -> Mapping[str, Any]:
        identity = _experiment_id(experiment_id)
        exact_revision = (
            _revision(revision, "engine experiment revision") if revision is not None else None
        )
        with self._connection() as connection:
            head = connection.execute(
                """
                SELECT head.active_revision, head.active_digest,
                       active.digest AS stored_active_digest
                FROM engine_experiment_heads AS head
                LEFT JOIN engine_experiment_versions AS active
                  ON active.experiment_id = head.experiment_id
                 AND active.revision = head.active_revision
                WHERE head.experiment_id = ?
                """,
                (identity,),
            ).fetchone()
            if head is None:
                raise ProductStoreError("engine experiment was not found")
            if (
                head["stored_active_digest"] is None
                or head["stored_active_digest"] != head["active_digest"]
            ):
                raise ProductStoreError("saved engine experiment head digest is invalid")
            active_revision = int(head["active_revision"])
            selected = active_revision if exact_revision is None else exact_revision
            row = connection.execute(
                """
                SELECT * FROM engine_experiment_versions
                WHERE experiment_id = ? AND revision = ?
                """,
                (identity, selected),
            ).fetchone()
        if row is None:
            raise ProductStoreError("engine experiment revision was not found")
        return _record_from_row(
            row,
            active_revision=active_revision,
            active_digest=str(head["active_digest"]),
        )

    def list_engine_experiments(
        self: EngineExperimentStore,
        *,
        limit: int = 100,
    ) -> list[Mapping[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_LIST_LIMIT
        ):
            raise ProductStoreError(
                f"engine experiment list limit must be between 1 and {_MAX_LIST_LIMIT}"
            )
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT head.experiment_id, head.active_revision, head.active_digest,
                       head.updated_at, first.created_at,
                       active.digest AS stored_active_digest
                FROM engine_experiment_heads AS head
                LEFT JOIN engine_experiment_versions AS first
                  ON first.experiment_id = head.experiment_id
                 AND first.revision = 1
                LEFT JOIN engine_experiment_versions AS active
                  ON active.experiment_id = head.experiment_id
                 AND active.revision = head.active_revision
                ORDER BY head.updated_at DESC, head.experiment_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        if any(
            row["created_at"] is None
            or row["stored_active_digest"] is None
            or row["active_digest"] != row["stored_active_digest"]
            for row in rows
        ):
            raise ProductStoreError("saved engine experiment head digest is invalid")
        return [
            {
                "schema_version": "bluefire.engine-experiment-head.v1",
                "experiment_id": str(row["experiment_id"]),
                "active_revision": int(row["active_revision"]),
                "active_digest": str(row["active_digest"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def list_engine_experiment_versions(
        self: EngineExperimentStore,
        experiment_id: str,
        *,
        limit: int = 100,
    ) -> list[Mapping[str, Any]]:
        identity = _experiment_id(experiment_id)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_LIST_LIMIT
        ):
            raise ProductStoreError(
                f"engine experiment version limit must be between 1 and {_MAX_LIST_LIMIT}"
            )
        with self._connection() as connection:
            head = connection.execute(
                """SELECT head.active_revision, head.active_digest,
                          active.digest AS stored_active_digest
                   FROM engine_experiment_heads AS head
                   LEFT JOIN engine_experiment_versions AS active
                     ON active.experiment_id = head.experiment_id
                    AND active.revision = head.active_revision
                   WHERE head.experiment_id = ?""",
                (identity,),
            ).fetchone()
            if head is None:
                raise ProductStoreError("engine experiment was not found")
            if (
                head["stored_active_digest"] is None
                or head["stored_active_digest"] != head["active_digest"]
            ):
                raise ProductStoreError("saved engine experiment head digest is invalid")
            rows = connection.execute(
                """
                SELECT experiment_id, revision, digest, prior_digest, created_at
                FROM engine_experiment_versions
                WHERE experiment_id = ?
                ORDER BY revision DESC LIMIT ?
                """,
                (identity, limit),
            ).fetchall()
        active_revision = int(head["active_revision"])
        if not rows:
            raise ProductStoreError("saved engine experiment head digest is invalid")
        return [
            {
                "schema_version": "bluefire.engine-experiment-version.v1",
                "experiment_id": str(row["experiment_id"]),
                "revision": int(row["revision"]),
                "digest": str(row["digest"]),
                "prior_digest": str(row["prior_digest"]) if row["prior_digest"] else None,
                "created_at": str(row["created_at"]),
                "active": int(row["revision"]) == active_revision,
            }
            for row in rows
        ]


__all__ = [
    "EngineExperimentStoreMixin",
    "EngineExperimentStore",
    "ExperimentValidator",
    "initialize_schema",
]
