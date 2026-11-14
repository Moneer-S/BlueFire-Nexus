"""ProductStore-owned schema for protected installed Docker exec evidence."""

from __future__ import annotations

from typing import Any

from .product_store_errors import ProductStoreError

CANCELLATION_TABLE = "docker_exec_cancellation_audit_v2"
CANCELLATION_CREATE = (
    f"CREATE TABLE IF NOT EXISTS {CANCELLATION_TABLE} ("
    "attempt_id TEXT NOT NULL, sequence INTEGER NOT NULL, "
    "record_ref TEXT NOT NULL, entry_ref TEXT NOT NULL UNIQUE, "
    "document_json TEXT NOT NULL, PRIMARY KEY(attempt_id,sequence))"
)
CANCELLATION_UPDATE = (
    "CREATE TRIGGER docker_exec_cancellation_audit_v2_no_update "
    "BEFORE UPDATE ON docker_exec_cancellation_audit_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable cancellation audit'); END"
)
CANCELLATION_DELETE = (
    "CREATE TRIGGER docker_exec_cancellation_audit_v2_no_delete "
    "BEFORE DELETE ON docker_exec_cancellation_audit_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable cancellation audit'); END"
)

TERMINAL_TABLE = "docker_exec_attachment_terminal_v2"
TERMINAL_CREATE = (
    f"CREATE TABLE IF NOT EXISTS {TERMINAL_TABLE} ("
    "attempt_id TEXT NOT NULL, transaction_ref TEXT NOT NULL, "
    "receipt_ref TEXT NOT NULL UNIQUE, document_json TEXT NOT NULL, "
    "PRIMARY KEY(attempt_id,transaction_ref))"
)
TERMINAL_UPDATE = (
    "CREATE TRIGGER docker_exec_attachment_terminal_v2_no_update "
    "BEFORE UPDATE ON docker_exec_attachment_terminal_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable exec terminal'); END"
)
TERMINAL_DELETE = (
    "CREATE TRIGGER docker_exec_attachment_terminal_v2_no_delete "
    "BEFORE DELETE ON docker_exec_attachment_terminal_v2 "
    "BEGIN SELECT RAISE(ABORT, 'immutable exec terminal'); END"
)


def _initialize_guarded_table(
    connection: Any,
    *,
    table: str,
    create: str,
    update_name: str,
    update_sql: str,
    delete_name: str,
    delete_sql: str,
) -> None:
    connection.execute(create)
    for name, definition in ((update_name, update_sql), (delete_name, delete_sql)):
        existing = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
        ).fetchone()
        if existing is None:
            if connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                raise ProductStoreError(f"{table} immutability guard is missing")
            connection.execute(definition)
        elif existing[0] != definition:
            raise ProductStoreError(f"{table} immutability guard changed")


def initialize_cancellation_schema(connection: Any) -> None:
    _initialize_guarded_table(
        connection,
        table=CANCELLATION_TABLE,
        create=CANCELLATION_CREATE,
        update_name="docker_exec_cancellation_audit_v2_no_update",
        update_sql=CANCELLATION_UPDATE,
        delete_name="docker_exec_cancellation_audit_v2_no_delete",
        delete_sql=CANCELLATION_DELETE,
    )


def initialize_terminal_schema(connection: Any) -> None:
    _initialize_guarded_table(
        connection,
        table=TERMINAL_TABLE,
        create=TERMINAL_CREATE,
        update_name="docker_exec_attachment_terminal_v2_no_update",
        update_sql=TERMINAL_UPDATE,
        delete_name="docker_exec_attachment_terminal_v2_no_delete",
        delete_sql=TERMINAL_DELETE,
    )


def initialize_schema(connection: Any) -> None:
    """Create both guarded tables in the owning ProductStore migration."""

    initialize_cancellation_schema(connection)
    initialize_terminal_schema(connection)


__all__ = [
    "CANCELLATION_CREATE",
    "CANCELLATION_DELETE",
    "CANCELLATION_TABLE",
    "CANCELLATION_UPDATE",
    "TERMINAL_CREATE",
    "TERMINAL_DELETE",
    "TERMINAL_TABLE",
    "TERMINAL_UPDATE",
    "initialize_cancellation_schema",
    "initialize_schema",
    "initialize_terminal_schema",
]
