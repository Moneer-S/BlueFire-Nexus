"""Scratch SQLite migration history only, not original macOS execution proof."""

from __future__ import annotations

import sqlite3

import pytest

from bluefire import product_store as module
from bluefire import product_store_macos_composition as composition
from bluefire import product_store_macos_workspace as workspace
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash

_NEW_TABLES = (
    "capability_macos_file_access_attempts",
    "capability_macos_file_access_events",
    "capability_macos_file_access_closures",
    "capability_macos_workspace_claims",
)
_PRESERVED = (
    "settings",
    "jobs",
    "capability_lineages",
    "capability_grants",
    "capability_grant_events",
    "file_access_enrollments",
    "file_access_setup_imports",
    "file_access_operations",
    "file_access_revisions",
    "file_access_outcomes",
)


def _snapshot(path):
    with sqlite3.connect(path) as connection:
        return {
            table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in _PRESERVED
        }


def _schema(path):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()


@pytest.fixture
def version12(tmp_path, monkeypatch):
    path = tmp_path / "version12.sqlite3"
    with monkeypatch.context() as previous:
        previous.setattr(module, "SCHEMA_VERSION", 12)
        previous.setattr(composition, "initialize_schema", lambda connection: None)
        previous.setattr(workspace, "initialize_schema", lambda connection: None)
        store = ProductStore(path)
        store.set_setting("migration.preserved", {"synthetic": "original setting"})
        job = store.create_job("file_access.operation", {"synthetic": "original control job"})
        document = {"synthetic_migration_history": "opaque; never execution authority"}
        payload = (canonical_json_bytes(document).decode("utf-8"), content_hash(document))
        with store._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO capability_lineages VALUES(?,?,?,?)",
                ("lineage-old", content_hash("synthetic original lineage binding"), *payload),
            )
            connection.execute(
                "INSERT INTO capability_grants VALUES(?,?,?,?,?,?,?)",
                ("grant-old", "lineage-old", "control-old", *payload, 1000, 9000),
            )
            connection.execute(
                "INSERT INTO capability_grant_events(grant_id,status,at_ms) VALUES(?,?,?)",
                ("grant-old", "active", 1000),
            )
            connection.execute(
                "INSERT INTO file_access_enrollments VALUES(?,?,?)", ("enrollment-old", *payload)
            )
            connection.execute(
                "INSERT INTO file_access_setup_imports VALUES(?,?,?,?,?)",
                ("control-old", "enrollment-old", "generation-old", *payload),
            )
            connection.execute(
                "INSERT INTO file_access_operations VALUES(?,?,?,?,?,?)",
                (job["job_id"], "control-old", "enrollment-old", "harden", *payload),
            )
            connection.execute(
                "INSERT INTO file_access_revisions VALUES(?,?,?,?,?)",
                ("control-old", 2, job["job_id"], *payload),
            )
            connection.execute(
                "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES(?,?,?)",
                (job["job_id"], *payload),
            )
        assert store.schema_version == 12
    with sqlite3.connect(path) as connection:
        assert all(
            connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone()
            is None
            for table in _NEW_TABLES
        )
    return path, job, _snapshot(path)


def test_v12_upgrade_preserves_history_without_synthesizing_macos_attempt_receipts(version12):
    path, job, before = version12

    upgraded = ProductStore(path)

    assert upgraded.schema_version == 13
    assert upgraded.get_job(job["job_id"]) == job
    assert _snapshot(path) == before
    with upgraded._connection() as connection:
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [12, 13]
        assert all(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
            for table in _NEW_TABLES
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    reopened = ProductStore(path)
    assert reopened.schema_version == 13 and _snapshot(path) == before
    with reopened._connection() as connection:
        assert all(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
            for table in _NEW_TABLES
        )


@pytest.mark.parametrize("stage", ["composition", "workspace"])
def test_v13_ddl_failure_rolls_back_new_tables_and_version(version12, monkeypatch, stage):
    path, _, before = version12
    schema_before = _schema(path)
    target = composition if stage == "composition" else workspace
    initialize = target.initialize_schema

    def interrupted(connection):
        initialize(connection)
        assert connection.in_transaction
        table = _NEW_TABLES[0] if stage == "composition" else _NEW_TABLES[-1]
        assert (
            connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone()
            is not None
        )
        raise sqlite3.OperationalError("synthetic new-DDL interruption")

    with monkeypatch.context() as failed:
        failed.setattr(target, "initialize_schema", interrupted)
        with pytest.raises(ProductStoreError, match="migration failed safely"):
            ProductStore(path)

    assert _schema(path) == schema_before and _snapshot(path) == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (12,)
    assert ProductStore(path).schema_version == 13
    assert _snapshot(path) == before


def test_v12_code_refuses_v13_before_new_table_ddl(version12, monkeypatch):
    path, _, before = version12
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES(13,'synthetic future version')"
        )
    schema_before = _schema(path)
    calls = []

    def unexpected_ddl(connection):
        calls.append("new table DDL")
        pytest.fail("an older application reached the v13 schema initializers")

    with monkeypatch.context() as older:
        older.setattr(module, "SCHEMA_VERSION", 12)
        older.setattr(composition, "initialize_schema", unexpected_ddl)
        older.setattr(workspace, "initialize_schema", unexpected_ddl)
        with pytest.raises(ProductStoreError, match="schema is newer"):
            ProductStore(path)

    assert calls == []
    assert _schema(path) == schema_before and _snapshot(path) == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (13,)
