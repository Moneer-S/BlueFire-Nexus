from __future__ import annotations

import io
import json
import sqlite3
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import bluefire.product_store_tenant_generation_journals as journals
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_bundle_export import export_run_bundle
from bluefire.tenant_record_generation_source import (
    ProductStoreTenantGenerationJournal,
    _validate_journal,
)
from bluefire.util import content_hash
from tests_platform.test_engine_action_submission_store import _accept, _attempt
from tests_platform.test_product_store_engine_experiments import (
    _document as _experiment_document,
)
from tests_platform.test_product_store_engine_experiments import (
    _validator as _experiment_validator,
)
from tests_platform.test_run_bundle_export import finalized

OWNER = "experiment-" + "a" * 32
JOURNAL = "experiment-" + "b" * 32
INPUTS = content_hash({"protected": "fixed-input-identity"})


def _document(
    revision: int = 1, *, journal_id: str = JOURNAL, phase: str = "idle"
) -> dict[str, Any]:
    return {
        "schema_version": journals.JOURNAL_SCHEMA,
        "experiment_id": journal_id,
        "revision": revision,
        "inputs_digest": INPUTS,
        "phase": phase,
        "active": None,
        "operation": None,
        "consumed": [],
        "generation_ids": [],
        "audit_bindings": [],
        "retained_audit": None,
    }


def _create(store: ProductStore, *, owner: str = OWNER, journal: str = JOURNAL):
    return store._create_tenant_generation_journal(
        owner,
        journal,
        _document(journal_id=journal),
        validator=_validate_journal,
    )


def _save(store: ProductStore, head, *, phase="unknown"):
    return store._save_tenant_generation_journal(
        OWNER,
        JOURNAL,
        _document(head["revision"] + 1, phase=phase),
        expected_revision=head["revision"],
        expected_digest=head["digest"],
        validator=_validate_journal,
    )


def test_exact_private_history_restart_and_durable_acknowledgement_retry(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    first = _create(store)
    second = _save(store, first)
    assert first["digest"] == content_hash(_document())
    assert second["prior_digest"] == first["digest"]
    reopened = ProductStore(store.path)
    assert reopened._get_tenant_generation_journal(OWNER, JOURNAL) == second
    historical = reopened._get_tenant_generation_journal(OWNER, JOURNAL, revision=1)
    assert historical["document"] == _document()
    assert historical["active"] is False
    assert reopened._list_tenant_generation_journal_versions(OWNER, JOURNAL) == [second, historical]
    assert _save(reopened, first) == second
    assert _create(reopened)["digest"] == first["digest"]
    assert len(reopened._list_tenant_generation_journal_versions(OWNER, JOURNAL)) == 2
    with pytest.raises(ResourceConflictError, match="CAS"):
        _save(reopened, first, phase="executing")
    with pytest.raises(ProductStoreError, match="not found"):
        reopened._get_tenant_generation_journal("experiment-" + "c" * 32, JOURNAL)


def test_one_journal_per_protected_owner_and_fixed_inputs(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    first = _create(store)
    with pytest.raises(ResourceConflictError, match="already has"):
        _create(store, journal="experiment-" + "c" * 32)
    with pytest.raises(ResourceConflictError, match="already has"):
        _create(store, owner="experiment-" + "d" * 32)
    with pytest.raises(ResourceConflictError, match="initial history"):
        store._create_tenant_generation_journal(
            OWNER,
            JOURNAL,
            {**_document(), "inputs_digest": content_hash("other")},
            validator=_validate_journal,
        )
    with pytest.raises(ResourceConflictError, match="protected inputs"):
        store._save_tenant_generation_journal(
            OWNER,
            JOURNAL,
            {**_document(2), "inputs_digest": content_hash("other")},
            expected_revision=1,
            expected_digest=first["digest"],
            validator=_validate_journal,
        )
    assert store._get_tenant_generation_journal(OWNER, JOURNAL) == first


def test_concurrent_create_and_conflicting_cas_have_one_head(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    stores = [ProductStore(path) for _ in range(4)]
    barrier = threading.Barrier(len(stores))

    def create(store):
        barrier.wait(timeout=10)
        return _create(store)

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        results = list(pool.map(create, stores))
    assert len({result["digest"] for result in results}) == 1
    first = results[0]
    barrier = threading.Barrier(len(stores))

    def change(index):
        barrier.wait(timeout=10)
        try:
            return _save(
                stores[index], first, phase=("unknown", "executing", "cleaned", "running")[index]
            )
        except ResourceConflictError:
            return None

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        updated = list(pool.map(change, range(len(stores))))
    assert sum(value is not None for value in updated) == 1
    history = stores[0]._list_tenant_generation_journal_versions(OWNER, JOURNAL)
    assert [value["revision"] for value in history] == [2, 1]


def test_read_snapshot_remains_coherent_during_separate_store_append(
    tmp_path: Path, monkeypatch
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    first = _create(store)
    writer = ProductStore(store.path)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    original = store._connection
    appended: list[Any] = []

    @contextmanager
    def interleaved_connection(*, write=False):
        with original(write=write) as connection:

            def trace(statement):
                if "SELECT owner_id, journal_id, revision, digest" in statement and not appended:
                    appended.append(_save(writer, first))

            connection.set_trace_callback(trace)
            yield connection

    monkeypatch.setattr(store, "_connection", interleaved_connection)
    assert store._get_tenant_generation_journal(OWNER, JOURNAL) == first
    assert len(appended) == 1
    assert writer._get_tenant_generation_journal(OWNER, JOURNAL) == appended[0]


@pytest.mark.parametrize("recursive", [0, 1])
def test_raw_sql_cannot_replace_mutate_delete_or_reset_journal(
    tmp_path: Path, recursive: int
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    first = _create(store)
    _save(store, first)
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA recursive_triggers={recursive}")
        version = connection.execute(
            "SELECT * FROM tenant_generation_journal_versions WHERE revision=1"
        ).fetchone()
        head = connection.execute("SELECT * FROM tenant_generation_journal_heads").fetchone()
        mutations = [
            (
                "INSERT OR REPLACE INTO tenant_generation_journal_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
                tuple(version),
            ),
            (
                "INSERT OR REPLACE INTO tenant_generation_journal_heads VALUES (?, ?, ?, ?, ?, ?)",
                tuple(head),
            ),
            (
                "INSERT OR REPLACE INTO tenant_generation_journal_heads VALUES (?, ?, ?, 1, ?, ?)",
                (OWNER, JOURNAL, INPUTS, first["digest"], head["updated_at"]),
            ),
            ("UPDATE tenant_generation_journal_versions SET created_at='changed'", ()),
            ("DELETE FROM tenant_generation_journal_versions", ()),
            ("DELETE FROM tenant_generation_journal_heads", ()),
            (
                "UPDATE tenant_generation_journal_heads SET active_revision=1, active_digest=?",
                (first["digest"],),
            ),
            ("UPDATE tenant_generation_journal_heads SET active_revision=4", ()),
            ("UPDATE tenant_generation_journal_heads SET owner_id=?", ("experiment-" + "c" * 32,)),
            (
                "UPDATE tenant_generation_journal_heads SET journal_id=?",
                ("experiment-" + "d" * 32,),
            ),
            (
                "UPDATE tenant_generation_journal_heads SET inputs_digest=?",
                (content_hash("other"),),
            ),
            (
                "INSERT OR REPLACE INTO tenant_generation_journal_versions VALUES (?, ?, 3, ?, ?, ?, ?)",
                (
                    OWNER,
                    JOURNAL,
                    canonical_json(_document(3)),
                    first["digest"],
                    head["active_digest"],
                    head["updated_at"],
                ),
            ),
        ]
        for statement, values in mutations:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement, values)
    assert store._get_tenant_generation_journal(OWNER, JOURNAL)["revision"] == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", None),
        ("experiment_id", None),
        ("revision", None),
        ("revision", True),
        ("revision", 1.0),
        ("inputs_digest", None),
    ],
)
def test_sql_constraints_reject_missing_or_inexact_document_identity(
    tmp_path: Path, field, value
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    malformed = {**_document(), field: value}
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO tenant_generation_journal_versions VALUES (?, ?, 1, ?, ?, NULL, ?)",
                (
                    OWNER,
                    JOURNAL,
                    canonical_json(malformed),
                    content_hash(malformed),
                    "2026-11-04T00:00:00Z",
                ),
            )
    with pytest.raises(ProductStoreError):
        store._create_tenant_generation_journal(
            OWNER, JOURNAL, malformed, validator=lambda value: value
        )


def test_document_bounds_secrets_and_historical_tampering_fail_closed(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with pytest.raises(ProductStoreError, match="byte bound"):
        store._create_tenant_generation_journal(
            OWNER,
            JOURNAL,
            {
                **_document(),
                "retained_audit": {"rows": [{"marker": "x" * journals.MAX_DOCUMENT_BYTES}]},
            },
            validator=_validate_journal,
        )
    with pytest.raises(ProductStoreError, match="environment-variable"):
        store._create_tenant_generation_journal(
            OWNER,
            JOURNAL,
            {**_document(), "operation": {"secret": "plaintext-material"}},
            validator=_validate_journal,
        )
    first = _create(store)
    _save(store, first)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER tenant_generation_journal_versions_no_update")
        connection.execute(
            "UPDATE tenant_generation_journal_versions SET document_json=? WHERE revision=1",
            (canonical_json({**_document(), "phase": "unknown"}),),
        )
    with pytest.raises(ProductStoreError, match="integrity"):
        store._get_tenant_generation_journal(OWNER, JOURNAL, revision=1)
    with pytest.raises(ProductStoreError, match="integrity"):
        store._list_tenant_generation_journal_versions(OWNER, JOURNAL)


def _existing_data(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    with sqlite3.connect(path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            name: sorted(connection.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for (name,) in tables
            if not name.startswith(("tenant_generation_", "sqlite_"))
            and name != "schema_migrations"
        }


def _as_v17(store: ProductStore) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE tenant_generation_journal_heads")
        connection.execute("DROP TABLE tenant_generation_journal_versions")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 18")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations VALUES (17, '2026-11-04T00:00:00Z')"
        )


def test_v17_to_v18_preserves_all_existing_data_including_acceptances(tmp_path: Path) -> None:
    store, _protected, values = _attempt(tmp_path)
    _accept(store, values)
    store.set_setting("migration-proof", {"unchanged": True})
    store.save_resource("model_provider", "migration-provider", {"label": "retained provider"})
    _as_v17(store)
    before = _existing_data(store.path)
    upgraded = ProductStore(store.path)
    assert upgraded.schema_version == SCHEMA_VERSION
    assert SCHEMA_VERSION >= 19
    assert _existing_data(store.path) == before
    assert _create(upgraded)["revision"] == 1
    assert _existing_data(store.path) == before


def test_v18_initializer_failure_rolls_back_tables_and_version_marker(
    tmp_path: Path, monkeypatch
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    store.set_setting("migration-proof", {"unchanged": True})
    _as_v17(store)
    before = _existing_data(store.path)
    original = journals.initialize_schema

    def fail_after_ddl(connection):
        original(connection)
        raise OSError("fixture interruption inside v18 transaction")

    monkeypatch.setattr(journals, "initialize_schema", fail_after_ddl)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(store.path)
    assert _existing_data(store.path) == before
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 17
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'tenant_generation_%'"
            ).fetchall()
            == []
        )


def test_journals_never_appear_in_public_experiment_resource_or_bundle_exports(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    public_id = "experiment-" + "f" * 32
    store.create_engine_experiment(
        public_id, _experiment_document(public_id, revision=1), validator=_experiment_validator
    )
    public_before = (
        store.list_engine_experiments(),
        store.get_engine_experiment(public_id),
        store.list_engine_experiment_versions(public_id),
        store.list_resources("model_provider"),
    )
    runs, run_id = finalized(tmp_path)
    before_bundle = export_run_bundle(runs, run_id)
    journal = ProductStoreTenantGenerationJournal(store, owner_id=public_id, inputs_digest=INPUTS)
    journal.save(journal.read(), phase="unknown")
    public_after = (
        store.list_engine_experiments(),
        store.get_engine_experiment(public_id),
        store.list_engine_experiment_versions(public_id),
        store.list_resources("model_provider"),
    )
    assert public_after == public_before
    assert journal.identity not in json.dumps(public_after)
    for operation in (store.get_engine_experiment, store.list_engine_experiment_versions):
        with pytest.raises(ProductStoreError, match="not found"):
            operation(journal.identity)
    for kind in ("tenant_generation_journal", "tenant-generation-journal", "tenant_generation"):
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.list_resources(kind)
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.get_resource(kind, journal.identity)
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.save_resource(kind, journal.identity, journal.read()["document"])
    after_bundle = export_run_bundle(runs, run_id)
    with (
        zipfile.ZipFile(io.BytesIO(before_bundle)) as before,
        zipfile.ZipFile(io.BytesIO(after_bundle)) as after,
    ):
        assert before.namelist() == after.namelist()
        assert all(before.read(name) == after.read(name) for name in before.namelist())
        assert all(journal.identity.encode() not in after.read(name) for name in after.namelist())


def test_initializer_requires_existing_transaction() -> None:
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ProductStoreError, match="requires one transaction"):
            journals.initialize_schema(connection)
