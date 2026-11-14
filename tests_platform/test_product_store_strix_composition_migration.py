"""Atomic combined engine and retained-authority migrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from bluefire import product_store_strix_composition_schema as schema
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError

TABLES = (
    "strix_composition_resource_events",
    "strix_composition_resource_transactions",
    "strix_composition_historical_records",
    "strix_composition_authority_records",
    "strix_composition_prelaunch_records",
    "strix_model_lease_terminals",
    "strix_controller_receipts",
)
RETAINED_TABLES = (
    "capability_task_dispatch_intents",
    "capability_retained_capture_intents",
    "capability_retained_capture_receipts",
    "capability_recovery_generations",
    "capability_recovery_obligations",
    "capability_recovery_claims",
    "capability_recovery_task_claims",
    "capability_recovery_terminals",
    "capability_receiver_closure_proofs",
    "capability_recovery_closures",
)


def _as_v23(store: ProductStore) -> None:
    with sqlite3.connect(store.path) as connection:
        for table in (*TABLES, *RETAINED_TABLES):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 24")
        connection.execute("INSERT OR IGNORE INTO schema_migrations VALUES (23,'fixture')")


def _old_rows(path: Path) -> dict[str, list[tuple]]:
    with sqlite3.connect(path) as connection:
        return {
            name: connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid').fetchall()
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            if name not in (*TABLES, *RETAINED_TABLES)
            and name != "schema_migrations"
            and not name.startswith("sqlite_")
        }


def test_v23_migration_preserves_old_rows_and_reopens_idempotently(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "product.sqlite")
    store.set_setting("v23-retained", {"retained": True})
    _as_v23(store)
    before = _old_rows(store.path)
    upgraded = ProductStore(store.path)
    assert upgraded.schema_version == SCHEMA_VERSION
    assert _old_rows(store.path) == before
    assert ProductStore(store.path).schema_version == SCHEMA_VERSION
    with sqlite3.connect(store.path) as connection:
        assert all(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
            for table in (*TABLES, *RETAINED_TABLES)
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM schema_migrations WHERE version=?",
                (SCHEMA_VERSION,),
            ).fetchone()[0]
            == 1
        )


def test_v23_migration_ddl_and_marker_roll_back_together(tmp_path: Path, monkeypatch) -> None:
    store = ProductStore(tmp_path / "product.sqlite")
    store.set_setting("v23-retained", {"retained": True})
    _as_v23(store)
    before = _old_rows(store.path)
    original = schema.initialize_schema

    def interrupted(connection):
        original(connection)
        raise OSError("fixture interrupted after private DDL")

    monkeypatch.setattr(schema, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(store.path)
    assert _old_rows(store.path) == before
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 23
        assert not connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'strix_composition_%' OR name LIKE 'capability_recovery_%'"
        ).fetchall()


def test_schema_requires_an_owning_transaction() -> None:
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ProductStoreError, match="owning transaction"):
            schema.initialize_schema(connection)
        assert not connection.execute("SELECT name FROM sqlite_master").fetchall()


def test_resource_event_chain_and_head_cas_reject_direct_tampering() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN")
        schema.initialize_schema(connection)
        connection.execute(
            "INSERT INTO strix_composition_prelaunch_records VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "attempt",
                "job",
                "claim",
                "runtime",
                "admission",
                "authority",
                "binding",
                "delegation",
                "objective",
                "environment",
                "target",
                "scope",
                "schema",
                "{}",
                "prelaunch-digest",
                "now",
            ),
        )
        connection.execute(
            "INSERT INTO strix_composition_resource_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "tx",
                "attempt",
                "authority",
                None,
                "execution",
                None,
                "prepared",
                0,
                None,
                "now",
                "now",
            ),
        )
        connection.execute(
            "INSERT INTO strix_composition_authority_records VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "attempt",
                "job",
                "claim",
                "runtime",
                "admission",
                "authority",
                "activation",
                "tx",
                "resource-receipt",
                "binding",
                "delegation",
                "objective",
                "environment",
                "target",
                "scope",
                "schema",
                "{}",
                "authority-digest",
                "now",
            ),
        )
        event_sql = """INSERT INTO strix_composition_resource_events
            (transaction_ref,tx_sequence,event_type,state,previous_digest,
             document_schema,document_json,event_digest,created_at)
            VALUES ('tx',?,'transition',?,?, 'schema','{}',?,'now')"""
        connection.execute(event_sql, (1, "prepared", None, "event-1"))
        connection.execute("""UPDATE strix_composition_resource_transactions
            SET generation=1,head_event_digest='event-1',state='prepared' WHERE transaction_ref='tx'""")
        for statement in (
            "DELETE FROM strix_composition_prelaunch_records",
            "UPDATE strix_composition_prelaunch_records SET scope_ref='changed'",
            "DELETE FROM strix_composition_authority_records",
            "UPDATE strix_composition_authority_records SET scope_ref='changed'",
            "INSERT OR REPLACE INTO strix_composition_authority_records SELECT * FROM strix_composition_authority_records",
            "DELETE FROM strix_composition_resource_transactions",
            "UPDATE strix_composition_resource_transactions SET authority_ref='changed'",
            "UPDATE strix_composition_resource_transactions SET generation=3",
            "UPDATE strix_composition_resource_events SET event_type='changed'",
            "DELETE FROM strix_composition_resource_events",
            "INSERT OR REPLACE INTO strix_composition_resource_events SELECT * FROM strix_composition_resource_events",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(event_sql, (2, "allocating", "other-chain", "event-2"))
        connection.execute(event_sql, (2, "allocating", "event-1", "event-2"))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("""UPDATE strix_composition_resource_transactions
                SET generation=2,head_event_digest='event-2',state='active'""")
        connection.execute("""UPDATE strix_composition_resource_transactions
            SET generation=2,head_event_digest='event-2',state='allocating'""")
        assert connection.execute(
            "SELECT generation,head_event_digest FROM strix_composition_resource_transactions"
        ).fetchone() == (2, "event-2")
