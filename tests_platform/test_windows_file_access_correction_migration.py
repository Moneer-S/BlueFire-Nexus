"""Synthetic SQLite history migration only; rows do not establish native proof."""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from bluefire import product_store as module
from bluefire import product_store_file_access as file_access
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash

_TABLE = "file_access_windows_control_evidence"
_PRESERVED = {
    "settings": "SELECT * FROM settings ORDER BY key",
    "jobs": "SELECT * FROM jobs ORDER BY job_id",
    "file_access_enrollments": "SELECT * FROM file_access_enrollments ORDER BY enrollment_id",
    "file_access_setup_imports": "SELECT * FROM file_access_setup_imports ORDER BY control_owner_id",
    "file_access_operations": "SELECT * FROM file_access_operations ORDER BY job_id",
    "file_access_preparations": "SELECT * FROM file_access_preparations ORDER BY job_id",
    "file_access_reconciliations": "SELECT * FROM file_access_reconciliations ORDER BY submission_id",
    "file_access_reconciliation_results": "SELECT * FROM file_access_reconciliation_results ORDER BY submission_id",
    "file_access_task_claims": "SELECT * FROM file_access_task_claims ORDER BY task_id",
    "file_access_task_terminals": "SELECT * FROM file_access_task_terminals ORDER BY task_id",
    "file_access_task_evidence": "SELECT * FROM file_access_task_evidence ORDER BY task_id,stage",
    "file_access_owned_process_closures": "SELECT * FROM file_access_owned_process_closures ORDER BY task_id",
    "file_access_worker_closures": "SELECT * FROM file_access_worker_closures ORDER BY task_id",
    "file_access_outcomes": "SELECT * FROM file_access_outcomes ORDER BY sequence",
    "file_access_revisions": "SELECT * FROM file_access_revisions ORDER BY control_owner_id,revision",
}


def _payload(label):
    document = {"synthetic_migration_fixture": label}
    return canonical_json_bytes(document).decode("utf-8"), content_hash(document)


def _snapshot(path):
    with sqlite3.connect(path) as connection:
        return {name: connection.execute(query).fetchall() for name, query in _PRESERVED.items()}


def _schema(path):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()


def _seed(store):
    store.set_setting("unit.preserved", {"fixture": "original setting"})
    job = store.create_job("file_access.operation", {"fixture": "original durable job"})
    job_id, owner, enrollment, task, submission = (
        job["job_id"],
        "migration-owner",
        "migration-enrollment",
        "migration-task",
        "migration-reconciliation",
    )
    payload = _payload("opaque original history")
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_enrollments VALUES (?,?,?)", (enrollment, *payload)
        )
        connection.execute(
            "INSERT INTO file_access_setup_imports VALUES (?,?,?,?,?)",
            (owner, enrollment, "a" * 32, *payload),
        )
        connection.execute(
            "INSERT INTO file_access_operations VALUES (?,?,?,?,?,?)",
            (job_id, owner, enrollment, "baseline", *payload),
        )
        connection.execute(
            "INSERT INTO file_access_preparations VALUES (?,?,?)", (job_id, *payload)
        )
        connection.execute(
            "INSERT INTO file_access_reconciliations VALUES (?,?,?,?)",
            (submission, job_id, *payload),
        )
        connection.execute(
            "INSERT INTO file_access_reconciliation_results VALUES (?,?,?)", (submission, *payload)
        )
        connection.execute(
            "INSERT INTO file_access_task_claims VALUES (?,?,?,?,?,?)",
            (task, job_id, "read_generated_pair", "sha256:" + "b" * 64, *payload),
        )
        connection.execute(
            "INSERT INTO file_access_task_terminals VALUES (?,?,?)", (task, *payload)
        )
        for stage in ("packet", "ready", "terminal"):
            connection.execute(
                "INSERT INTO file_access_task_evidence VALUES (?,?,?,?)",
                (task, stage, *_payload(stage)),
            )
        connection.execute(
            "INSERT INTO file_access_owned_process_closures VALUES (?,?,?)", (task, *payload)
        )
        connection.execute(
            "INSERT INTO file_access_worker_closures VALUES (?,?,?)", (task, *payload)
        )
        connection.execute(
            "INSERT INTO file_access_outcomes(job_id,document_json,document_digest) VALUES (?,?,?)",
            (job_id, *payload),
        )
        connection.execute(
            "INSERT INTO file_access_revisions VALUES (?,?,?,?,?)", (owner, 2, job_id, *payload)
        )
    return job


@pytest.fixture
def version10(tmp_path, monkeypatch):
    path = tmp_path / "version10.sqlite3"
    with monkeypatch.context() as previous:
        previous.setattr(module, "SCHEMA_VERSION", 10)
        previous.setattr(
            file_access,
            "_TABLES",
            {
                name: definition
                for name, definition in file_access._TABLES.items()
                if name != _TABLE
            },
        )
        store = ProductStore(path)
        job = _seed(store)
        assert store.schema_version == 10
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE name=?", (_TABLE,)).fetchall()
            == []
        )
    return path, job, _snapshot(path)


def _assert_new_schema(store, job_id):
    with store._connection() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(file_access_windows_control_evidence)"
        ).fetchall()
        assert [(row["table"], row["from"], row["to"]) for row in foreign_keys] == [
            ("file_access_operations", "job_id", "job_id")
        ]
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (_TABLE,)
            )
        } == {_TABLE + "_no_update", _TABLE + "_no_delete"}
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with store._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO file_access_windows_control_evidence VALUES (?,?,?,?)",
                ("missing-operation", "dispatch", *_payload("missing")),
            )
    with store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_windows_control_evidence VALUES (?,?,?,?)",
            (job_id, "dispatch", *_payload("new correction evidence")),
        )
    for query in (
        "UPDATE file_access_windows_control_evidence SET stage='replacement' WHERE job_id=?",
        "DELETE FROM file_access_windows_control_evidence WHERE job_id=?",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with store._connection(write=True) as connection:
                connection.execute(query, (job_id,))
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        with store._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO file_access_windows_control_evidence VALUES (?,?,?,?)",
                (job_id, "dispatch", *_payload("duplicate")),
            )


def test_fresh_schema_installs_fk_and_append_only_correction_evidence(tmp_path):
    store = ProductStore(tmp_path / "fresh.sqlite3")
    assert store.schema_version == module.SCHEMA_VERSION
    job = _seed(store)
    _assert_new_schema(store, job["job_id"])
    reopened = ProductStore(store.path)
    assert reopened.schema_version == module.SCHEMA_VERSION
    assert reopened.get_job(job["job_id"]) == job
    with reopened._connection() as connection:
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [module.SCHEMA_VERSION]
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM file_access_windows_control_evidence"
            ).fetchone()[0]
            == 1
        )


def test_version10_upgrade_preserves_all_existing_jobs_history_and_evidence(version10):
    path, job, before = version10
    upgraded = ProductStore(path)
    assert upgraded.schema_version == module.SCHEMA_VERSION
    assert upgraded.get_job(job["job_id"]) == job
    assert _snapshot(path) == before
    _assert_new_schema(upgraded, job["job_id"])
    assert _snapshot(path) == before
    reopened = ProductStore(path)
    with reopened._connection() as connection:
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [10, module.SCHEMA_VERSION]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("failure", [sqlite3.OperationalError, MemoryError])
def test_interrupted_correction_table_and_marker_rollback_atomically(
    version10, monkeypatch, failure
):
    path, job, before = version10
    schema_before = _schema(path)
    initialize = file_access.initialize_schema

    def interrupted(connection):
        initialize(connection)
        assert connection.in_transaction
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
            is not None
        )
        raise failure("synthetic interruption after correction DDL")

    with monkeypatch.context() as interrupted_migration:
        interrupted_migration.setattr(file_access, "initialize_schema", interrupted)
        with pytest.raises(ProductStoreError, match="migration failed safely"):
            ProductStore(path)
    assert _snapshot(path) == before and _schema(path) == schema_before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (10,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE tbl_name=?", (_TABLE,)
            ).fetchall()
            == []
        )
    resumed = ProductStore(path)
    assert resumed.schema_version == module.SCHEMA_VERSION
    assert resumed.get_job(job["job_id"]) == job
    assert _snapshot(path) == before
    _assert_new_schema(resumed, job["job_id"])


def test_future_version_refused_before_any_schema_or_data_mutation(version10):
    path, _, before = version10
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES (?,?)",
            (module.SCHEMA_VERSION + 1, "2026-10-13T00:00:00Z"),
        )
    schema_before = _schema(path)
    digest_before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ProductStoreError, match="schema is newer"):
        ProductStore(path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest_before
    assert _schema(path) == schema_before and _snapshot(path) == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (
            module.SCHEMA_VERSION + 1,
        )
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE tbl_name=?", (_TABLE,)
            ).fetchall()
            == []
        )
