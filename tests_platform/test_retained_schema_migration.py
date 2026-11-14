"""Version 13 databases acquire retained authority tables only on upgrade."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from bluefire import product_store as store_module
from bluefire import product_store_capability_api as capability_api
from bluefire.product_store import ProductStore, ProductStoreError

_NEW_TABLES = frozenset(
    {
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
    }
)


def _without_engine_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recreate historical stores before the external-engine tables existed."""

    for module in (
        store_module.engine_experiment_store,
        store_module.engine_presentation_store,
        store_module.engine_action_store,
        store_module.engine_action_submission_store,
        store_module.engine_execution_claim_store,
        store_module.engine_file_access_store,
        store_module.tenant_generation_journal_store,
        store_module.tenant_action_material_store,
        store_module.strix_runtime_store,
        store_module.strix_issuance_store,
        store_module.strix_composition_schema,
    ):
        monkeypatch.setattr(module, "initialize_schema", lambda connection: None)


def _version13_store(path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict, dict]:
    assert _NEW_TABLES <= capability_api._TABLES.keys()
    with monkeypatch.context() as prior:
        prior.setattr(store_module, "SCHEMA_VERSION", 13)
        _without_engine_schema(prior)
        prior.setattr(
            capability_api,
            "_TABLES",
            {name: ddl for name, ddl in capability_api._TABLES.items() if name not in _NEW_TABLES},
        )
        store = ProductStore(path)
        store.set_setting("migration.retained", {"preserved": "version 13 setting"})
        job = store.create_job("file_access.operation", {"original": "version 13 job"})
        with store._connection() as connection:
            setting_row = dict(
                connection.execute(
                    "SELECT * FROM settings WHERE key='migration.retained'"
                ).fetchone()
            )
            job_row = dict(
                connection.execute("SELECT * FROM jobs WHERE job_id=?", (job["job_id"],)).fetchone()
            )
        assert store.schema_version == 13
    with sqlite3.connect(path) as connection:
        assert all(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            is None
            for table in _NEW_TABLES
        )
    return setting_row, job_row


def test_v13_upgrade_adds_retained_tables_without_synthesizing_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "version13.sqlite3"
    setting_row, job_row = _version13_store(path, monkeypatch)

    upgraded = ProductStore(path)
    assert upgraded.schema_version == store_module.SCHEMA_VERSION
    with upgraded._connection() as connection:
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM settings WHERE key='migration.retained'"
                ).fetchone()
            )
            == setting_row
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM jobs WHERE job_id=?", (job_row["job_id"],)
                ).fetchone()
            )
            == job_row
        )
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [13, store_module.SCHEMA_VERSION]
        assert all(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
            for table in _NEW_TABLES
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    assert ProductStore(path).schema_version == store_module.SCHEMA_VERSION
    with monkeypatch.context() as older:
        older.setattr(store_module, "SCHEMA_VERSION", 13)
        older.setattr(
            capability_api,
            "initialize_schema",
            lambda connection: pytest.fail("older code reached new-table DDL"),
        )
        with pytest.raises(ProductStoreError, match="schema is newer"):
            ProductStore(path)


def test_v14_retained_ddl_failure_leaves_v13_database_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "failed-upgrade.sqlite3"
    setting_row, job_row = _version13_store(path, monkeypatch)
    initialize = capability_api.initialize_schema

    def interrupted(connection: sqlite3.Connection) -> None:
        initialize(connection)
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                ("capability_recovery_generations",),
            ).fetchone()
            is not None
        )
        raise sqlite3.OperationalError("synthetic retained-DDL interruption")

    with monkeypatch.context() as failed:
        failed.setattr(capability_api, "initialize_schema", interrupted)
        with pytest.raises(ProductStoreError, match="migration failed safely"):
            ProductStore(path)

    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 13
        assert all(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            is None
            for table in _NEW_TABLES
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM settings WHERE key='migration.retained'"
                ).fetchone()
            )
            == setting_row
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM jobs WHERE job_id=?", (job_row["job_id"],)
                ).fetchone()
            )
            == job_row
        )


def test_v14_retained_store_upgrades_with_authority_tables_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "retained-v14.sqlite3"
    setting_row, job_row = _version13_store(path, monkeypatch)
    with monkeypatch.context() as prior:
        prior.setattr(store_module, "SCHEMA_VERSION", 14)
        _without_engine_schema(prior)
        old = ProductStore(path)
        assert old.schema_version == 14
        with old._connection() as connection:
            authority_ddl = {
                name: connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
                ).fetchone()[0]
                for name in _NEW_TABLES
            }

    upgraded = ProductStore(path)
    assert upgraded.schema_version == store_module.SCHEMA_VERSION
    with upgraded._connection() as connection:
        assert [
            row[0]
            for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")
        ] == [13, 14, store_module.SCHEMA_VERSION]
        assert all(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
            ).fetchone()[0]
            == ddl
            for name, ddl in authority_ddl.items()
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM settings WHERE key='migration.retained'"
                ).fetchone()
            )
            == setting_row
        )
        assert (
            dict(
                connection.execute(
                    "SELECT * FROM jobs WHERE job_id=?", (job_row["job_id"],)
                ).fetchone()
            )
            == job_row
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
