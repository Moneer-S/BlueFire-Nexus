"""Fixed SQLite selectors preserve parameterization and pre-fetch byte bounds."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from bluefire import product_store_windows_file_access as windows
from bluefire import windows_file_access_native_wire as wire
from bluefire.util import content_hash


def test_import_queries_keep_owner_precedence_and_parameterized_values():
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE file_access_setup_imports (control_owner_id,enrollment_id,generation,document_digest,document_json)"
        )
        selected = "synthetic' OR 1=1 --"
        connection.execute(
            "INSERT INTO file_access_setup_imports VALUES(?,?,?,?,?)",
            (selected, "enrollment-one", "generation", "digest", "{}"),
        )
        assert windows.at(connection, owner_id=selected)["control_owner_id"] == selected
        assert (
            windows.at(connection, enrollment_id="enrollment-one")["control_owner_id"] == selected
        )
        assert windows.at(connection, owner_id="absent", enrollment_id="enrollment-one") is None
        assert windows.at(connection, owner_id="' OR 1=1 --") is None
        assert windows.at(connection) is None
        connection.execute("UPDATE file_access_setup_imports SET document_json=?", ("x" * 65537,))
        assert windows.at(connection, owner_id=selected)["document_json"] is None
        assert windows.at(connection, enrollment_id="enrollment-one")["document_json"] is None


@pytest.mark.parametrize(
    "table,query",
    [
        (
            "file_access_operations",
            "CREATE TABLE file_access_operations (job_id,document_digest,document_json)",
        ),
        (
            "file_access_preparations",
            "CREATE TABLE file_access_preparations (job_id,document_digest,document_json)",
        ),
        (
            "file_access_revisions",
            "CREATE TABLE file_access_revisions (job_id,document_digest,document_json)",
        ),
    ],
)
def test_bounded_queries_preserve_exact_bytes_and_reject_oversized_rows(table, query):
    row = {"synthetic": "bounded"}
    raw = '{"synthetic":"bounded"}'
    digest = content_hash(row)
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(query)
        insert = {
            "file_access_operations": "INSERT INTO file_access_operations VALUES(?,?,?)",
            "file_access_preparations": "INSERT INTO file_access_preparations VALUES(?,?,?)",
            "file_access_revisions": "INSERT INTO file_access_revisions VALUES(?,?,?)",
        }[table]
        selected = "synthetic' OR 1=1 --"
        connection.execute(insert, (selected, digest, raw))
        assert windows._bounded(connection, table, "job_id", selected, len(raw)) == (row, digest)
        with pytest.raises(ValueError):
            windows._bounded(connection, table, "job_id", selected, len(raw) - 1)
        with pytest.raises(ValueError):
            windows._bounded(connection, table, "job_id", "' OR 1=1 --", len(raw))


@pytest.mark.parametrize(
    "table,column",
    [
        ("file_access_task_claims", "job_id"),
        ("file_access_operations", "control_owner_id"),
        ("file_access_operations WHERE 1=1 --", "job_id"),
        ("file_access_revisions", "job_id OR 1=1 --"),
        (None, "job_id"),
        ("file_access_operations", None),
    ],
)
def test_unknown_bounded_selector_is_refused_before_sql(table, column):
    connection = SimpleNamespace(execute=lambda *args: pytest.fail("Unknown selector reached SQL"))
    with pytest.raises(wire.NativeWireError):
        windows._bounded(connection, table, column, "synthetic", 64)
