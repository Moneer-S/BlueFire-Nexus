from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _document(
    experiment_id: str,
    *,
    revision: int,
    state: str = "draft",
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment.v1",
        "experiment_id": experiment_id,
        "revision": revision,
        "objective_ref": _digest("1"),
        "environment_ref": _digest("2"),
        "model_authorization_ref": _digest("3"),
        "state": state,
        "attempts": [],
        "checks": [],
    }


def _validator(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if (
        set(value)
        != {
            "schema_version",
            "experiment_id",
            "revision",
            "objective_ref",
            "environment_ref",
            "model_authorization_ref",
            "state",
            "attempts",
            "checks",
        }
        or value.get("schema_version") != "bluefire.engine-experiment.v1"
    ):
        raise ValueError("unsupported experiment")
    if not all(
        isinstance(value.get(field), str)
        and len(str(value[field])) == 71
        and str(value[field]).startswith("sha256:")
        for field in ("objective_ref", "environment_ref", "model_authorization_ref")
    ):
        raise ValueError("invalid experiment reference")
    if (
        not isinstance(value.get("revision"), int)
        or isinstance(value.get("revision"), bool)
        or not isinstance(value.get("state"), str)
        or not isinstance(value.get("attempts"), list)
        or not isinstance(value.get("checks"), list)
    ):
        raise ValueError("invalid experiment fields")
    return value


def test_engine_experiment_history_survives_restart_and_lists_bounded_heads(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state" / "bluefire.db"
    experiment_id = "experiment-" + "1" * 32
    store = ProductStore(path)

    created = store.create_engine_experiment(
        experiment_id,
        _document(experiment_id, revision=1),
        validator=_validator,
    )
    assert created["revision"] == 1
    assert created["active"] is True
    assert created["document"]["model_authorization_ref"] == _digest("3")

    reopened = ProductStore(path)
    assert reopened.get_engine_experiment(experiment_id) == created
    assert reopened.list_engine_experiments(limit=1) == [
        {
            "schema_version": "bluefire.engine-experiment-head.v1",
            "experiment_id": experiment_id,
            "active_revision": 1,
            "active_digest": created["digest"],
            "created_at": created["created_at"],
            "updated_at": created["created_at"],
        }
    ]


def test_engine_experiment_save_is_append_only_cas_and_exact_retry_is_idempotent(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment_id = "experiment-" + "2" * 32
    first = store.create_engine_experiment(
        experiment_id,
        _document(experiment_id, revision=1),
        validator=_validator,
    )
    next_document = _document(experiment_id, revision=2, state="baseline_complete")

    second = store.save_engine_experiment(
        experiment_id,
        next_document,
        expected_revision=1,
        expected_digest=str(first["digest"]),
        validator=_validator,
    )
    replay = store.save_engine_experiment(
        experiment_id,
        next_document,
        expected_revision=1,
        expected_digest=str(first["digest"]),
        validator=_validator,
    )

    assert replay == second
    assert store.get_engine_experiment(experiment_id)["revision"] == 2
    assert store.get_engine_experiment(experiment_id, revision=1) == {
        **first,
        "active": False,
        "active_revision": 2,
    }
    assert store.list_engine_experiment_versions(experiment_id) == [
        {
            "schema_version": "bluefire.engine-experiment-version.v1",
            "experiment_id": experiment_id,
            "revision": 2,
            "digest": second["digest"],
            "prior_digest": first["digest"],
            "created_at": second["created_at"],
            "active": True,
        },
        {
            "schema_version": "bluefire.engine-experiment-version.v1",
            "experiment_id": experiment_id,
            "revision": 1,
            "digest": first["digest"],
            "prior_digest": None,
            "created_at": first["created_at"],
            "active": False,
        },
    ]

    with pytest.raises(ResourceConflictError, match="expected revision"):
        store.save_engine_experiment(
            experiment_id,
            _document(experiment_id, revision=2, state="different"),
            expected_revision=1,
            expected_digest=str(first["digest"]),
            validator=_validator,
        )


def test_engine_experiment_create_is_idempotent_but_identity_cannot_be_rebound(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment_id = "experiment-" + "3" * 32
    document = _document(experiment_id, revision=1)

    first = store.create_engine_experiment(experiment_id, document, validator=_validator)
    assert store.create_engine_experiment(experiment_id, document, validator=_validator) == first

    with pytest.raises(ResourceConflictError, match="different history"):
        store.create_engine_experiment(
            experiment_id,
            _document(experiment_id, revision=1, state="other"),
            validator=_validator,
        )


def test_engine_experiment_concurrent_cas_has_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    experiment_id = "experiment-" + "4" * 32
    store = ProductStore(path)
    first = store.create_engine_experiment(
        experiment_id, _document(experiment_id, revision=1), validator=_validator
    )
    barrier = threading.Barrier(2)
    records: list[Mapping[str, Any]] = []
    errors: list[Exception] = []

    def save(state: str) -> None:
        candidate = ProductStore(path)
        barrier.wait(timeout=5)
        try:
            records.append(
                candidate.save_engine_experiment(
                    experiment_id,
                    _document(experiment_id, revision=2, state=state),
                    expected_revision=1,
                    expected_digest=str(first["digest"]),
                    validator=_validator,
                )
            )
        except Exception as exc:  # pragma: no branch - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(state,)) for state in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(records) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ResourceConflictError)
    assert ProductStore(path).get_engine_experiment(experiment_id)["digest"] == records[0]["digest"]


def test_engine_experiment_rejects_secrets_raw_payloads_and_bad_contracts(
    tmp_path: Path,
) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    experiment_id = "experiment-" + "5" * 32

    with pytest.raises(TypeError, match="validator"):
        store.create_engine_experiment(  # type: ignore[call-arg]
            experiment_id, _document(experiment_id, revision=1)
        )

    secret = _document(experiment_id, revision=1)
    secret["api_key"] = "plaintext"
    with pytest.raises(ProductStoreError, match="environment-variable reference"):
        store.create_engine_experiment(experiment_id, secret, validator=_validator)

    raw = _document(experiment_id, revision=1)
    raw["raw_artifacts"] = ["engine output"]
    with pytest.raises(ProductStoreError, match="artifact references"):
        store.create_engine_experiment(experiment_id, raw, validator=_validator)

    alternate_raw = _document(experiment_id, revision=1)
    alternate_raw["tool_output"] = "untrusted engine text"
    with pytest.raises(ProductStoreError, match="contract validation"):
        store.create_engine_experiment(experiment_id, alternate_raw, validator=_validator)

    mismatched = _document("experiment-" + "6" * 32, revision=1)
    with pytest.raises(ProductStoreError, match="identity is mismatched"):
        store.create_engine_experiment(experiment_id, mismatched, validator=_validator)

    with pytest.raises(ProductStoreError, match="contract validation"):
        store.create_engine_experiment(
            experiment_id,
            _document(experiment_id, revision=1),
            validator=lambda _value: (_ for _ in ()).throw(ValueError("invalid")),
        )

    oversized = _document(experiment_id, revision=1, state="x" * (1024 * 1024))
    with pytest.raises(ProductStoreError, match="canonical JSON bytes"):
        store.create_engine_experiment(experiment_id, oversized, validator=_validator)


def test_engine_experiment_sql_history_and_head_transitions_are_guarded(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bluefire.db"
    experiment_id = "experiment-" + "7" * 32
    store = ProductStore(path)
    first = store.create_engine_experiment(
        experiment_id, _document(experiment_id, revision=1), validator=_validator
    )

    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("UPDATE engine_experiment_versions SET created_at = 'changed'")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("DELETE FROM engine_experiment_versions")
    with pytest.raises(sqlite3.IntegrityError, match="does not extend"):
        connection.execute(
            """
            INSERT INTO engine_experiment_versions(
                experiment_id, revision, document_json, digest, prior_digest, created_at
            ) VALUES (?, 3, '{}', ?, ?, '2026-11-04T00:00:00Z')
            """,
            (experiment_id, _digest("8"), first["digest"]),
        )
    with pytest.raises(sqlite3.IntegrityError, match="head transition is invalid"):
        connection.execute(
            """UPDATE engine_experiment_heads
               SET active_revision = 2, active_digest = ?
               WHERE experiment_id = ?""",
            (_digest("8"), experiment_id),
        )
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        connection.execute("DELETE FROM engine_experiment_heads")
    connection.close()


def test_engine_experiment_reads_reject_corrupt_head_digest(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    experiment_id = "experiment-" + "8" * 32
    store = ProductStore(path)
    first = store.create_engine_experiment(
        experiment_id, _document(experiment_id, revision=1), validator=_validator
    )
    store.save_engine_experiment(
        experiment_id,
        _document(experiment_id, revision=2, state="baseline_complete"),
        expected_revision=1,
        expected_digest=str(first["digest"]),
        validator=_validator,
    )

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER engine_experiment_heads_valid_update")
    connection.execute(
        "UPDATE engine_experiment_heads SET active_digest = ? WHERE experiment_id = ?",
        (_digest("9"), experiment_id),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ProductStoreError, match="head digest"):
        store.get_engine_experiment(experiment_id)
    with pytest.raises(ProductStoreError, match="head digest"):
        store.get_engine_experiment(experiment_id, revision=1)
    with pytest.raises(ProductStoreError, match="head digest"):
        store.list_engine_experiments()
    with pytest.raises(ProductStoreError, match="head digest"):
        store.list_engine_experiment_versions(experiment_id)


def test_engine_experiment_reads_reject_missing_active_version(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    experiment_id = "experiment-" + "a" * 32
    store = ProductStore(path)
    store.create_engine_experiment(
        experiment_id, _document(experiment_id, revision=1), validator=_validator
    )

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER engine_experiment_versions_no_delete")
    connection.execute(
        "DELETE FROM engine_experiment_versions WHERE experiment_id = ? AND revision = 1",
        (experiment_id,),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ProductStoreError, match="head digest"):
        store.get_engine_experiment(experiment_id)
    with pytest.raises(ProductStoreError, match="head digest"):
        store.list_engine_experiments()
    with pytest.raises(ProductStoreError, match="head digest"):
        store.list_engine_experiment_versions(experiment_id)


def test_engine_experiment_schema_migrates_from_previous_version(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (15, '2026-11-03T00:00:00Z')"
    )
    connection.commit()
    connection.close()

    store = ProductStore(path)
    assert store.schema_version == SCHEMA_VERSION == 19
    experiment_id = "experiment-" + "9" * 32
    assert (
        store.create_engine_experiment(
            experiment_id,
            _document(experiment_id, revision=1),
            validator=_validator,
        )["revision"]
        == 1
    )


@pytest.mark.parametrize("limit", [0, 201, True])
def test_engine_experiment_list_bounds(limit: object, tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    with pytest.raises(ProductStoreError, match="list limit"):
        store.list_engine_experiments(limit=limit)  # type: ignore[arg-type]
