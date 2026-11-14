"""The installed exec custody tables belong to one ProductStore migration."""

from __future__ import annotations

import sqlite3

import pytest

from bluefire import product_store_docker_exec_capture_schema as capture_schema
from bluefire import product_store_strix_exec_schema as exec_schema
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError

TABLES = (
    exec_schema.CANCELLATION_TABLE,
    exec_schema.TERMINAL_TABLE,
    capture_schema.EXEC_EXCHANGE_TABLE,
    capture_schema.CONTAINER_INSPECT_TABLE,
)


def _saved_v26_without_exec_tables(path) -> None:
    with sqlite3.connect(path) as connection:
        for table in TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 27")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (26, 'fixture')"
        )


def test_v26_upgrade_creates_guarded_exec_tables_and_preserves_work(tmp_path) -> None:
    path = tmp_path / "product.sqlite"
    original = ProductStore(path)
    original.set_setting("saved-work", {"kept": True})
    _saved_v26_without_exec_tables(path)

    upgraded = ProductStore(path)
    assert upgraded.schema_version == SCHEMA_VERSION == 27
    assert upgraded.get_setting("saved-work") == {"kept": True}
    with sqlite3.connect(path) as connection:
        for table in TABLES:
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
        for trigger in (
            "docker_exec_cancellation_audit_v2_no_update",
            "docker_exec_cancellation_audit_v2_no_delete",
            "docker_exec_attachment_terminal_v2_no_update",
            "docker_exec_attachment_terminal_v2_no_delete",
            "docker_exec_exchange_capture_v2_no_update",
            "docker_exec_exchange_capture_v2_no_delete",
            "docker_container_inspect_capture_v2_no_update",
            "docker_container_inspect_capture_v2_no_delete",
        ):
            assert connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND name=?",
                (trigger,),
            ).fetchone() == (trigger,)
    assert ProductStore(path).get_setting("saved-work") == {"kept": True}


def test_exec_schema_upgrade_rolls_back_if_second_table_fails(tmp_path, monkeypatch) -> None:
    path = tmp_path / "product.sqlite"
    original = ProductStore(path)
    original.set_setting("saved-work", {"kept": True})
    _saved_v26_without_exec_tables(path)

    def interrupted(connection):
        exec_schema.initialize_cancellation_schema(connection)
        raise OSError("fixture interrupted before terminal schema")

    monkeypatch.setattr(exec_schema, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT max(version) FROM schema_migrations").fetchone() == (26,)
        assert not any(
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            for table in TABLES
        )
    assert original.get_setting("saved-work") == {"kept": True}
