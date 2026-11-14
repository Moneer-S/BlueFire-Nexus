"""Persistence-only schema for bounded installed Docker exchange captures."""

from __future__ import annotations

import sqlite3


class DockerExecCaptureSchemaError(RuntimeError):
    """A retained capture table or immutability guard is unavailable."""


EXEC_EXCHANGE_TABLE = "docker_exec_exchange_capture_v2"
CONTAINER_INSPECT_TABLE = "docker_container_inspect_capture_v2"
CREATE_EXEC_EXCHANGE_TABLE = (
    "CREATE TABLE IF NOT EXISTS docker_exec_exchange_capture_v2 ("
    "attempt_id TEXT NOT NULL, transaction_ref TEXT NOT NULL, "
    "operation_id TEXT NOT NULL, operation TEXT NOT NULL, "
    "capture_ref TEXT NOT NULL UNIQUE, "
    "document_json TEXT NOT NULL, response_bytes BLOB NOT NULL, "
    "PRIMARY KEY(attempt_id,transaction_ref,operation_id,operation))"
)
CREATE_CONTAINER_INSPECT_TABLE = (
    "CREATE TABLE IF NOT EXISTS docker_container_inspect_capture_v2 ("
    "attempt_id TEXT NOT NULL, transaction_ref TEXT NOT NULL, "
    "capture_sequence INTEGER NOT NULL, capture_ref TEXT NOT NULL UNIQUE, "
    "document_json TEXT NOT NULL, response_bytes BLOB NOT NULL, "
    "PRIMARY KEY(attempt_id,transaction_ref,capture_sequence))"
)
EXEC_EXCHANGE_UPDATE_TRIGGER = (
    "CREATE TRIGGER docker_exec_exchange_capture_v2_no_update "
    "BEFORE UPDATE ON docker_exec_exchange_capture_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable exec capture'); END"
)
EXEC_EXCHANGE_DELETE_TRIGGER = (
    "CREATE TRIGGER docker_exec_exchange_capture_v2_no_delete "
    "BEFORE DELETE ON docker_exec_exchange_capture_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable exec capture'); END"
)
CONTAINER_INSPECT_UPDATE_TRIGGER = (
    "CREATE TRIGGER docker_container_inspect_capture_v2_no_update "
    "BEFORE UPDATE ON docker_container_inspect_capture_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable container inspect capture'); END"
)
CONTAINER_INSPECT_DELETE_TRIGGER = (
    "CREATE TRIGGER docker_container_inspect_capture_v2_no_delete "
    "BEFORE DELETE ON docker_container_inspect_capture_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable container inspect capture'); END"
)

_TABLES = (
    (EXEC_EXCHANGE_TABLE, CREATE_EXEC_EXCHANGE_TABLE),
    (CONTAINER_INSPECT_TABLE, CREATE_CONTAINER_INSPECT_TABLE),
)
_TRIGGERS = (
    (
        EXEC_EXCHANGE_TABLE,
        "docker_exec_exchange_capture_v2_no_update",
        EXEC_EXCHANGE_UPDATE_TRIGGER,
    ),
    (
        EXEC_EXCHANGE_TABLE,
        "docker_exec_exchange_capture_v2_no_delete",
        EXEC_EXCHANGE_DELETE_TRIGGER,
    ),
    (
        CONTAINER_INSPECT_TABLE,
        "docker_container_inspect_capture_v2_no_update",
        CONTAINER_INSPECT_UPDATE_TRIGGER,
    ),
    (
        CONTAINER_INSPECT_TABLE,
        "docker_container_inspect_capture_v2_no_delete",
        CONTAINER_INSPECT_DELETE_TRIGGER,
    ),
)


def require_docker_exec_capture_schema_at(connection: sqlite3.Connection) -> None:
    """Read-only check of exact table definitions and immutable guards."""

    for name, definition in _TABLES:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        if row is None or row[0] != definition.replace(" IF NOT EXISTS", ""):
            raise DockerExecCaptureSchemaError("Docker capture table changed")
    for _table, name, definition in _TRIGGERS:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
        ).fetchone()
        if row is None or row[0] != definition:
            raise DockerExecCaptureSchemaError("Docker capture immutability guard changed")


def initialize_docker_exec_capture_schema_at(connection: sqlite3.Connection) -> None:
    """Idempotent migration step; caller owns the surrounding transaction."""

    for _name, definition in _TABLES:
        connection.execute(definition)
    for table, name, definition in _TRIGGERS:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
        ).fetchone()
        if row is None:
            if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                raise DockerExecCaptureSchemaError("Docker capture immutability guard is missing")
            connection.execute(definition)
        elif row[0] != definition:
            raise DockerExecCaptureSchemaError("Docker capture immutability guard changed")
    require_docker_exec_capture_schema_at(connection)
