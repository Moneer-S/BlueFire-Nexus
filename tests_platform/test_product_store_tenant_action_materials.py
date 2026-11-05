from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import copy_context
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

import bluefire.product_store_tenant_action_materials as slots
from bluefire.engine_action_preparation import EngineWorkspaceAction
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_bundle_export import export_run_bundle
from bluefire.tenant_record_generation_source import ProductStoreTenantGenerationJournal
from bluefire.util import content_hash
from tests_platform.test_engine_action_submission_store import _accept, _attempt
from tests_platform.test_product_store_engine_actions import (
    EXPERIMENT_ID,
    WORKSPACE_REF,
    _ActionStore,
    _advance_experiment,
    _attempt_factory,
    _limits,
    _store,
    _times,
)
from tests_platform.test_run_bundle_export import finalized


def _values(store: ProductStore) -> dict[str, Any]:
    current = store.get_engine_experiment(EXPERIMENT_ID)
    prepared_at, expires_at, _ = _times()
    factory, approval = _attempt_factory(cast(_ActionStore, store), prepared_at, expires_at, [])
    return {
        "experiment_id": EXPERIMENT_ID,
        "experiment_revision": current["revision"],
        "experiment_digest": current["digest"],
        "workspace_digest": WORKSPACE_REF,
        "action": EngineWorkspaceAction.START_BASELINE,
        "limits": _limits(),
        "prepared_at": prepared_at,
        "expires_at": expires_at,
        "protected_factory": factory,
        "approval_request": approval,
    }


def _document(store: ProductStore, values: Mapping[str, Any]) -> dict[str, Any]:
    journal = ProductStoreTenantGenerationJournal(
        store, owner_id=EXPERIMENT_ID, inputs_digest=content_hash("fixed protected inputs")
    ).read()
    return {
        "schema_version": slots.SLOT_SCHEMA,
        "experiment_id": values["experiment_id"],
        "experiment_revision": values["experiment_revision"],
        "experiment_digest": values["experiment_digest"],
        "action_kind": values["action"].value,
        "workspace_digest": values["workspace_digest"],
        "material": {"prepared_at": values["prepared_at"], "expires_at": values["expires_at"]},
        "generation_journal": {
            "owner_id": journal["owner_id"],
            "journal_id": journal["journal_id"],
            "revision": journal["revision"],
            "digest": journal["digest"],
            "inputs_digest": journal["document"]["inputs_digest"],
        },
    }


def _validator(value: Mapping[str, Any]) -> Mapping[str, Any]:
    # Storage tests use a small fixed private contract. Production authority
    # validation is exercised by the material-source integration tests.
    if set(value) != {
        "schema_version",
        "experiment_id",
        "experiment_revision",
        "experiment_digest",
        "action_kind",
        "workspace_digest",
        "material",
        "generation_journal",
    }:
        raise ValueError("unexpected private field")
    return value


def _retain(store: ProductStore, document, values):
    return store._retain_tenant_action_material_preparation(
        document=document, validator=_validator, preparation_values=values
    )


def _fixture(tmp_path: Path):
    store = _store(tmp_path)
    values = _values(store)
    document = _document(store, values)
    return store, document, values


def _key(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: document[name]
        for name in ("experiment_id", "experiment_revision", "experiment_digest", "action_kind")
    }


def _counts(store: ProductStore) -> tuple[int, ...]:
    with sqlite3.connect(store.path) as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "tenant_action_material_slots",
                "engine_action_preparations",
                "approval_requests",
            )
        )


def test_private_exact_read_restart_and_immutable_retry(tmp_path: Path) -> None:
    store, document, values = _fixture(tmp_path)
    first = _retain(store, document, values)
    reopened = ProductStore(store.path)
    record = reopened._read_tenant_action_material_slot(**_key(document))
    assert record is not None
    assert record["document"] == document
    assert record["slot_digest"] == content_hash(document)
    assert record["preparation_ref"] == first["request_ref"]
    assert _retain(reopened, document, values) == first
    assert _counts(reopened) == (1, 1, 1)
    changed = {**document, "workspace_digest": content_hash("another workspace")}
    with pytest.raises(ResourceConflictError, match="CAS"):
        _retain(reopened, changed, values)
    assert _counts(reopened) == (1, 1, 1)


@pytest.mark.parametrize("operation", ["update", "delete", "replace"])
def test_sql_rejects_mutation_deletion_and_replacement(tmp_path: Path, operation: str) -> None:
    store, document, values = _fixture(tmp_path)
    _retain(store, document, values)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("SELECT * FROM tenant_action_material_slots").fetchone()
        with pytest.raises(sqlite3.IntegrityError, match="immutable|append-only|replaced"):
            if operation == "update":
                connection.execute(
                    "UPDATE tenant_action_material_slots SET slot_digest=slot_digest"
                )
            elif operation == "delete":
                connection.execute("DELETE FROM tenant_action_material_slots")
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)",
                    row,
                )
    assert _counts(store) == (1, 1, 1)


def test_sql_replace_cannot_delete_another_slot_through_unique_digest(tmp_path: Path) -> None:
    store, document, values = _fixture(tmp_path)
    _retain(store, document, values)
    _advance_experiment(store)
    orphan_values = _values(store)
    orphan_document = _document(store, orphan_values)
    orphan = store.create_engine_action_preparation(**orphan_values)
    with sqlite3.connect(store.path) as connection:
        digest = connection.execute(
            "SELECT slot_digest FROM tenant_action_material_slots"
        ).fetchone()[0]
        record_digest = connection.execute(
            "SELECT record_digest FROM engine_action_preparations WHERE request_ref=?",
            (orphan["request_ref"],),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
            connection.execute(
                "INSERT OR REPLACE INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)",
                (
                    *_key(orphan_document).values(),
                    canonical_json(orphan_document),
                    digest,
                    orphan["request_ref"],
                    record_digest,
                ),
            )
    assert store._read_tenant_action_material_slot(**_key(document)) is not None


def test_existing_orphan_preparation_cannot_be_adopted(tmp_path: Path) -> None:
    store, document, values = _fixture(tmp_path)
    store.create_engine_action_preparation(**values)
    with pytest.raises(ResourceConflictError, match="orphan"):
        _retain(store, document, values)
    assert _counts(store) == (0, 1, 1)


@pytest.mark.parametrize("stage", ["after_preparation", "after_slot"])
def test_crash_rolls_back_slot_preparation_and_approval(
    tmp_path: Path, monkeypatch, stage: str
) -> None:
    store, document, values = _fixture(tmp_path)
    if stage == "after_preparation":
        original = store._create_engine_action_preparation_at

        def interrupted(connection, **arguments):
            original(connection, **arguments)
            raise OSError("fixture crash after preparation and approval")

        monkeypatch.setattr(store, "_create_engine_action_preparation_at", interrupted)
    else:
        original_connection = store._connection

        @contextmanager
        def interrupted_connection(*, write=False):
            with original_connection(write=write) as connection:
                yield connection
                if write:
                    assert (
                        connection.execute(
                            "SELECT COUNT(*) FROM tenant_action_material_slots"
                        ).fetchone()[0]
                        == 1
                    )
                    raise OSError("fixture crash after slot before commit")

        monkeypatch.setattr(store, "_connection", interrupted_connection)
    with pytest.raises(OSError, match="fixture crash"):
        _retain(store, document, values)
    assert _counts(store) == (0, 0, 0)


@pytest.mark.parametrize(
    "field",
    ["schema_version", "experiment_id", "experiment_revision", "experiment_digest", "action_kind"],
)
def test_sql_document_identity_constraints_fail_closed(tmp_path: Path, field: str) -> None:
    store, document, values = _fixture(tmp_path)
    prepared = store.create_engine_action_preparation(**values)
    malformed = {**document, field: None}
    with sqlite3.connect(store.path) as connection:
        record_digest = connection.execute(
            "SELECT record_digest FROM engine_action_preparations WHERE request_ref=?",
            (prepared["request_ref"],),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)",
                (
                    *_key(document).values(),
                    canonical_json(malformed),
                    content_hash(malformed),
                    prepared["request_ref"],
                    record_digest,
                ),
            )
    assert _counts(store) == (0, 1, 1)


@pytest.mark.parametrize("field", ["owner_id", "journal_id", "revision", "digest", "inputs_digest"])
def test_sql_rejects_inexact_generation_journal_provenance(tmp_path: Path, field: str) -> None:
    store, document, values = _fixture(tmp_path)
    prepared = store.create_engine_action_preparation(**values)
    changed = dict(document["generation_journal"])
    changed[field] = {
        "owner_id": "experiment-" + "f" * 32,
        "journal_id": "experiment-" + "e" * 32,
        "revision": 2,
        "digest": content_hash("another journal revision"),
        "inputs_digest": content_hash("another protected input"),
    }[field]
    malformed = {**document, "generation_journal": changed}
    with sqlite3.connect(store.path) as connection:
        record_digest = connection.execute(
            "SELECT record_digest FROM engine_action_preparations WHERE request_ref=?",
            (prepared["request_ref"],),
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError, match="journal"):
            connection.execute(
                "INSERT INTO tenant_action_material_slots VALUES(?,?,?,?,?,?,?,?)",
                (
                    *_key(document).values(),
                    canonical_json(malformed),
                    content_hash(malformed),
                    prepared["request_ref"],
                    record_digest,
                ),
            )
    assert _counts(store) == (0, 1, 1)


@pytest.mark.parametrize("tamper", ["noncanonical", "content", "provenance"])
def test_reopen_rejects_noncanonical_tampered_bytes_or_provenance(
    tmp_path: Path, tamper: str
) -> None:
    store, document, values = _fixture(tmp_path)
    _retain(store, document, values)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER tenant_action_material_slots_no_update")
        if tamper == "provenance":
            connection.execute(
                "UPDATE tenant_action_material_slots SET preparation_record_digest=?",
                (content_hash("other preparation"),),
            )
        else:
            encoded = (
                json.dumps(document, indent=2)
                if tamper == "noncanonical"
                else canonical_json({**document, "workspace_digest": content_hash("tampered")})
            )
            connection.execute(
                "UPDATE tenant_action_material_slots SET document_json=?", (encoded,)
            )
    with pytest.raises(ProductStoreError, match="integrity"):
        store._read_tenant_action_material_slot(**_key(document))


@pytest.mark.parametrize("field", ["secret", "arbitrary_path", "command"])
def test_private_documents_refuse_secrets_and_unrecognized_authority(
    tmp_path: Path, field: str
) -> None:
    store, document, values = _fixture(tmp_path)
    with pytest.raises(ProductStoreError):
        _retain(store, {**document, field: "untrusted authority"}, values)
    assert _counts(store) == (0, 0, 0)
    with pytest.raises(ProductStoreError, match="bound"):
        slots._document({**document, "material": "x" * slots.MAX_DOCUMENT_BYTES}, _validator)


def _existing_data(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    with sqlite3.connect(path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            name: sorted(connection.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for (name,) in tables
            if name not in {"tenant_action_material_slots", "schema_migrations"}
            and not name.startswith("sqlite_")
        }


def _as_v18(store: ProductStore) -> None:
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE tenant_action_material_slots")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 19")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations VALUES(18,'2026-11-04T00:00:00Z')"
        )


def test_v18_to_v19_preserves_existing_acceptances_resources_and_generation_journals(
    tmp_path: Path,
) -> None:
    store, _protected, values = _attempt(tmp_path)
    _accept(store, values)
    ProductStoreTenantGenerationJournal(
        store, owner_id=EXPERIMENT_ID, inputs_digest=content_hash("fixed retained inputs")
    )
    store.set_setting("migration-proof", {"unchanged": True})
    store.save_resource("model_provider", "migration-provider", {"label": "retained provider"})
    _as_v18(store)
    before = _existing_data(store.path)
    upgraded = ProductStore(store.path)
    assert upgraded.schema_version == SCHEMA_VERSION
    assert SCHEMA_VERSION >= 19
    assert _existing_data(store.path) == before
    assert _counts(upgraded)[0] == 0


def test_v19_initializer_interruption_rolls_back_ddl_and_version_marker(
    tmp_path: Path, monkeypatch
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    store.set_setting("migration-proof", {"unchanged": True})
    _as_v18(store)
    before = _existing_data(store.path)
    original = slots.initialize_schema

    def interrupted(connection):
        original(connection)
        raise OSError("fixture crash during v19 migration")

    monkeypatch.setattr(slots, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(store.path)
    assert _existing_data(store.path) == before
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 18
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'tenant_action_material_%'"
            ).fetchall()
            == []
        )


def test_slots_never_appear_in_public_resources_experiments_or_export_bundles(
    tmp_path: Path,
) -> None:
    store, document, values = _fixture(tmp_path)
    before_public = (
        store.list_engine_experiments(),
        store.get_engine_experiment(EXPERIMENT_ID),
        store.list_engine_experiment_versions(EXPERIMENT_ID),
        store.list_resources("model_provider"),
    )
    runs, run_id = finalized(tmp_path / "runs")
    before_bundle = export_run_bundle(runs, run_id)
    _retain(store, document, values)
    after_public = (
        store.list_engine_experiments(),
        store.get_engine_experiment(EXPERIMENT_ID),
        store.list_engine_experiment_versions(EXPERIMENT_ID),
        store.list_resources("model_provider"),
    )
    assert after_public == before_public
    assert slots.SLOT_SCHEMA not in json.dumps(after_public)
    for kind in (
        "tenant_action_material",
        "tenant-action-material-slot",
        "tenant_action_material_slots",
    ):
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.list_resources(kind)
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.get_resource(kind, EXPERIMENT_ID)
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.save_resource(kind, EXPERIMENT_ID, document)
    assert not any(
        name.startswith(("get_tenant_action_material", "list_tenant_action_material"))
        for name in dir(store)
    )
    after_bundle = export_run_bundle(runs, run_id)
    with (
        zipfile.ZipFile(io.BytesIO(before_bundle)) as before,
        zipfile.ZipFile(io.BytesIO(after_bundle)) as after,
    ):
        assert before.namelist() == after.namelist()
        assert all(before.read(name) == after.read(name) for name in before.namelist())
        assert all(slots.SLOT_SCHEMA.encode() not in after.read(name) for name in after.namelist())


def test_initializer_requires_existing_transaction() -> None:
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ProductStoreError, match="requires one transaction"):
            slots.initialize_schema(connection)


def test_read_scope_reuses_same_pinned_database_across_store_instances(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    duplicate = ProductStore(store.path)
    with store._connection(write=True) as owner, slots._read_scope(store, owner):
        owner.execute(
            "INSERT INTO settings VALUES('scope-proof','{\"visible\":true}','2026-11-04T00:00:00Z')"
        )
        with duplicate._connection() as reader:
            assert reader is owner
        assert duplicate.get_setting("scope-proof") == {"visible": True}
        assert (
            duplicate._read_tenant_action_material_slot(
                experiment_id=EXPERIMENT_ID,
                experiment_revision=1,
                experiment_digest=content_hash("not retained"),
                action_kind=EngineWorkspaceAction.START_BASELINE.value,
            )
            is None
        )
    assert slots._READ_SCOPE.get() is None
    assert duplicate.get_setting("scope-proof") == {"visible": True}


def test_read_scope_isolates_unrelated_database_and_refuses_mismatched_identity(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "owner.db")
    unrelated = ProductStore(tmp_path / "unrelated.db")
    with store._connection(write=True) as owner, slots._read_scope(store, owner):
        with unrelated._connection() as reader:
            assert reader is not owner
        volume, identity = store._database_identity
        with pytest.raises(ProductStoreError, match="database identity changed"):
            slots._scoped_read_connection(store.path, (volume, identity + 1), write=False)
    assert slots._READ_SCOPE.get() is None


def test_copied_context_cannot_share_sqlite_connection_across_threads(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    duplicate = ProductStore(store.path)
    with store._connection(write=True) as owner, slots._read_scope(store, owner):
        owner.execute("INSERT INTO settings VALUES('thread-proof','true','2026-11-04T00:00:00Z')")
        copied = copy_context()

        def refused_reader():
            with pytest.raises(ProductStoreError, match="cannot cross threads"):
                slots._scoped_read_connection(
                    duplicate.path, duplicate._database_identity, write=False
                )
            with pytest.raises(ProductStoreError, match="cannot cross threads"):
                duplicate.get_setting("thread-proof")

        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(copied.run, refused_reader).result(timeout=10)
    assert duplicate.get_setting("thread-proof") is True


def test_read_scope_resets_after_failure_and_forbids_nested_writes(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    duplicate = ProductStore(store.path)
    with pytest.raises(OSError, match="fixture refusal"):
        with store._connection(write=True) as owner, slots._read_scope(store, owner):
            with pytest.raises(ProductStoreError, match="nested write"):
                duplicate.set_setting("nested-write", True)
            assert slots._READ_SCOPE.get() is not None
            raise OSError("fixture refusal")
    assert slots._READ_SCOPE.get() is None
    assert duplicate.get_setting("nested-write") is None
    duplicate.set_setting("after-refusal", True)
    assert store.get_setting("after-refusal") is True


def test_read_scope_requires_owning_transaction_and_rejects_transaction_loss(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with store._connection() as reader:
        with pytest.raises(ProductStoreError, match="owning transaction"):
            with slots._read_scope(store, reader):
                pytest.fail("read scope accepted a connection without an owning transaction")
    with store._connection(write=True) as owner, slots._read_scope(store, owner):
        with pytest.raises(ProductStoreError, match="owning transaction"):
            with slots._read_scope(store, owner):
                pytest.fail("read scope accepted nested ownership")
        owner.rollback()
        with pytest.raises(ProductStoreError, match="lost its transaction"):
            with store._connection():
                pytest.fail("read scope accepted a lost transaction")
    assert slots._READ_SCOPE.get() is None
