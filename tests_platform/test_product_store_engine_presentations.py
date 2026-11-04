from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.engine_experiment import ENGINE_CAPABILITY_SCOPE_VERSION, EngineExperiment
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from tests_platform.test_engine_experiment import (
    AFTER_SNAPSHOT,
    ENVIRONMENT_REF,
    EXPERIMENT_ID,
    INITIAL_SNAPSHOT,
    OBJECTIVE_REF,
    SCOPE_REF,
    _defense,
    _digest,
)
from tests_platform.test_product_store_engine_jobs import _applied_versions, _validator


def _profile(*, engine_version: str = "1.7.0") -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-presentation-profile.v1",
        "experiment_id": EXPERIMENT_ID,
        "objective": {
            "objective_ref": OBJECTIVE_REF,
            "title": "Protect generated tenant records",
            "summary": "Test the original failure, apply a bounded defense, and retest it.",
        },
        "environment": {
            "environment_ref": ENVIRONMENT_REF,
            "environment_id": "tenant-record-lab",
            "display_name": "Disposable tenant-record lab",
            "platform": "linux",
            "disposable": True,
        },
        "initial_target_snapshot_ref": INITIAL_SNAPSHOT,
        "engine_setup": {
            "engine": {
                "id": "strix",
                "display_name": "Strix",
                "version": engine_version,
                "revision": "7" * 40,
                "package_digest": _digest("7"),
                "sandbox_image_digest": _digest("b"),
            },
            "model": {
                "provider": "provider.test",
                "id": "test-model",
                "data_destination": "https://model.test/v1",
                "authorization_digest": _digest("9"),
                "test_provider": True,
            },
        },
        "authorization": {
            "scope_ref": SCOPE_REF,
            "scope_version": ENGINE_CAPABILITY_SCOPE_VERSION,
            "wall_clock_seconds": 300,
            "action_limit": 20,
            "artifact_byte_limit": 4 * 1024 * 1024,
            "cost_limit_microunits": 1_000_000,
        },
        "limitations": [
            "Controlled test-provider responses only.",
            (
                "Sandbox image and test-provider identities describe prepared setup; "
                "attempt records do not independently attest them."
            ),
        ],
    }


def _target(snapshot_ref: str, captured_at: str, *, name: str) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-target-presentation.v1",
        "experiment_id": EXPERIMENT_ID,
        "snapshot_ref": snapshot_ref,
        "display_name": name,
        "captured_at": captured_at,
    }


def _initial_target() -> dict[str, Any]:
    return _target(
        INITIAL_SNAPSHOT,
        "2026-11-04T12:00:00Z",
        name="Generated tenant-record target",
    )


def _after_target() -> dict[str, Any]:
    return _target(
        AFTER_SNAPSHOT,
        "2026-11-04T12:07:00Z",
        name="Hardened tenant-record target",
    )


def _defense_presentation() -> dict[str, Any]:
    return {
        "schema_version": "bluefire.engine-experiment-defense-presentation.v1",
        "experiment_id": EXPERIMENT_ID,
        "change_id": _defense().change_id,
        "kind": "identity",
        "summary": "Removed the generated engine identity from the fixture reader group.",
    }


def _save_versions(
    store: ProductStore, versions: list[EngineExperiment]
) -> list[Mapping[str, Any]]:
    records = [
        store.create_engine_experiment(
            EXPERIMENT_ID,
            versions[0].to_dict(),
            validator=_validator,
        )
    ]
    for experiment in versions[1:]:
        records.append(
            store.save_engine_experiment(
                EXPERIMENT_ID,
                experiment.to_dict(),
                expected_revision=int(records[-1]["revision"]),
                expected_digest=str(records[-1]["digest"]),
                validator=_validator,
            )
        )
    return records


def _provisioned_store(path: Path) -> tuple[ProductStore, list[Mapping[str, Any]]]:
    store = ProductStore(path)
    store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    versions = _applied_versions()
    store.assert_engine_experiment_presentation_create_ready(versions[0])
    return store, _save_versions(store, versions)


def _register_defense(
    store: ProductStore,
    records: list[Mapping[str, Any]],
) -> None:
    reviewed = records[6]
    store.register_engine_experiment_defense_presentation(
        EXPERIMENT_ID,
        _defense_presentation(),
        expected_revision=int(reviewed["revision"]),
        expected_experiment_digest=str(reviewed["digest"]),
    )


def test_presentation_reopens_exact_historical_revisions_and_unknown_target_is_null(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bluefire.db"
    store, records = _provisioned_store(path)
    _register_defense(store, records)
    applied = records[8]
    reviewed = records[6]
    store.register_engine_experiment_target_presentation(
        EXPERIMENT_ID,
        _after_target(),
        expected_revision=int(reviewed["revision"]),
        expected_experiment_digest=str(reviewed["digest"]),
    )

    reopened = ProductStore(path)
    initial = reopened.get_engine_experiment_presentation(
        EXPERIMENT_ID,
        revision=1,
        experiment_digest=str(records[0]["digest"]),
    )
    unknown = reopened.get_engine_experiment_presentation(
        EXPERIMENT_ID,
        revision=8,
        experiment_digest=str(records[7]["digest"]),
    )
    current = reopened.get_engine_experiment_presentation(
        EXPERIMENT_ID,
        revision=9,
        experiment_digest=str(applied["digest"]),
    )

    assert initial["current_target"] == {
        "snapshot_ref": INITIAL_SNAPSHOT,
        "display_name": "Generated tenant-record target",
        "captured_at": "2026-11-04T12:00:00Z",
    }
    assert initial["defensive_change"] is None
    assert initial["selection"] is None
    assert unknown["current_target"] is None
    assert unknown["defensive_change"]["state"] == "unknown"
    assert current["current_target"]["snapshot_ref"] == AFTER_SNAPSHOT
    assert current["defensive_change"]["state"] == "applied"
    assert current["selection"] is None


def test_create_preflight_accepts_preexisting_initial_capture_but_rejects_future(
    tmp_path: Path,
) -> None:
    experiment = _applied_versions()[0]
    earlier = ProductStore(tmp_path / "earlier.db")
    earlier.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _target(
            INITIAL_SNAPSHOT,
            "2026-11-04T11:59:59Z",
            name="Generated tenant-record target",
        ),
    )
    earlier.assert_engine_experiment_presentation_create_ready(experiment)

    future = ProductStore(tmp_path / "future.db")
    future.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _target(
            INITIAL_SNAPSHOT,
            "2026-11-04T12:00:01Z",
            name="Generated tenant-record target",
        ),
    )
    with pytest.raises(ProductStoreError, match="contract validation"):
        future.assert_engine_experiment_presentation_create_ready(experiment)


def test_preflight_and_reads_fail_closed_for_missing_or_drifted_metadata(
    tmp_path: Path,
) -> None:
    versions = _applied_versions()
    empty = ProductStore(tmp_path / "empty.db")
    with pytest.raises(ProductStoreError, match="profile is missing"):
        empty.assert_engine_experiment_presentation_create_ready(versions[0])

    store, records = _provisioned_store(tmp_path / "missing.db")
    with pytest.raises(ProductStoreError, match="defense presentation is missing"):
        store.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=7,
            experiment_digest=str(records[6]["digest"]),
        )
    _register_defense(store, records)
    with pytest.raises(ProductStoreError, match="current target presentation is missing"):
        store.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=9,
            experiment_digest=str(records[8]["digest"]),
        )
    with pytest.raises(ResourceConflictError, match="anchor changed"):
        store.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=1,
            experiment_digest=_digest("f"),
        )

    drift = ProductStore(tmp_path / "drift.db")
    drift.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(engine_version="9.9.9"),
        _initial_target(),
    )
    drift.assert_engine_experiment_presentation_create_ready(versions[0])
    drift_records = _save_versions(drift, versions[:2])
    with pytest.raises(ProductStoreError, match="attempt setup changed"):
        drift.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=2,
            experiment_digest=str(drift_records[1]["digest"]),
        )


def test_registration_is_exact_idempotent_and_revision_digest_bound(tmp_path: Path) -> None:
    store, records = _provisioned_store(tmp_path / "bluefire.db")
    defense = _defense_presentation()
    reviewed = records[6]
    first = store.register_engine_experiment_defense_presentation(
        EXPERIMENT_ID,
        defense,
        expected_revision=7,
        expected_experiment_digest=str(reviewed["digest"]),
    )
    assert (
        store.register_engine_experiment_defense_presentation(
            EXPERIMENT_ID,
            defense,
            expected_revision=7,
            expected_experiment_digest=str(reviewed["digest"]),
        )
        == first
    )
    changed = copy.deepcopy(defense)
    changed["summary"] = "A different explanation cannot replace the reviewed display record."
    with pytest.raises(ResourceConflictError, match="different metadata"):
        store.register_engine_experiment_defense_presentation(
            EXPERIMENT_ID,
            changed,
            expected_revision=7,
            expected_experiment_digest=str(reviewed["digest"]),
        )
    with pytest.raises(ResourceConflictError, match="anchor changed"):
        store.register_engine_experiment_target_presentation(
            EXPERIMENT_ID,
            _after_target(),
            expected_revision=9,
            expected_experiment_digest=_digest("0"),
        )


def test_transition_metadata_is_ready_before_cas_and_failed_cas_stays_unreachable(
    tmp_path: Path,
) -> None:
    versions = _applied_versions()
    store = ProductStore(tmp_path / "ready.db")
    provisioned = store.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    assert (
        store.provision_engine_experiment_presentation(
            EXPERIMENT_ID,
            _profile(),
            _initial_target(),
        )
        == provisioned
    )
    records = _save_versions(store, versions[:6])
    current = versions[5]
    reviewed = versions[6]

    prepared = store.provision_engine_experiment_transition_presentation(
        current,
        reviewed,
        defense_presentation=_defense_presentation(),
    )
    assert (
        store.provision_engine_experiment_transition_presentation(
            current,
            reviewed,
            defense_presentation=_defense_presentation(),
        )
        == prepared
    )
    store.assert_engine_experiment_presentation_transition_ready(current, reviewed)
    saved_review = store.save_engine_experiment(
        EXPERIMENT_ID,
        reviewed.to_dict(),
        expected_revision=current.revision,
        expected_digest=current.digest,
        validator=_validator,
    )
    reopened = ProductStore(tmp_path / "ready.db")
    assert (
        reopened.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=reviewed.revision,
            experiment_digest=str(saved_review["digest"]),
        )["defensive_change"]["state"]
        == "reviewed"
    )
    assert records[-1]["digest"] == current.digest

    failed = ProductStore(tmp_path / "failed.db")
    failed.provision_engine_experiment_presentation(
        EXPERIMENT_ID,
        _profile(),
        _initial_target(),
    )
    _save_versions(failed, versions[:6])
    failed.provision_engine_experiment_transition_presentation(
        current,
        reviewed,
        defense_presentation=_defense_presentation(),
    )
    alternate_change = replace(_defense(), reviewed_by="another-operator")
    alternate_change.validate()
    alternate = current.review_defense(
        alternate_change,
        timestamp=alternate_change.reviewed_at,
    )
    alternate_record = failed.save_engine_experiment(
        EXPERIMENT_ID,
        alternate.to_dict(),
        expected_revision=current.revision,
        expected_digest=current.digest,
        validator=_validator,
    )
    with pytest.raises(ResourceConflictError, match="expected revision"):
        failed.save_engine_experiment(
            EXPERIMENT_ID,
            reviewed.to_dict(),
            expected_revision=current.revision,
            expected_digest=current.digest,
            validator=_validator,
        )
    with pytest.raises(ProductStoreError, match="no reachable experiment anchor"):
        failed.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=alternate.revision,
            experiment_digest=str(alternate_record["digest"]),
        )
    failed.register_engine_experiment_defense_presentation(
        EXPERIMENT_ID,
        _defense_presentation(),
        expected_revision=alternate.revision,
        expected_experiment_digest=str(alternate_record["digest"]),
    )
    assert (
        failed.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=alternate.revision,
            experiment_digest=str(alternate_record["digest"]),
        )["defensive_change"]["state"]
        == "reviewed"
    )


def test_concurrent_conflicting_provision_has_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    ProductStore(path)
    barrier = threading.Barrier(2)
    successes: list[Mapping[str, Any]] = []
    errors: list[Exception] = []

    def provision(title: str) -> None:
        profile = _profile()
        profile["objective"]["title"] = title
        candidate = ProductStore(path)
        barrier.wait(timeout=5)
        try:
            successes.append(
                candidate.provision_engine_experiment_presentation(
                    EXPERIMENT_ID,
                    profile,
                    _initial_target(),
                )
            )
        except Exception as exc:  # pragma: no branch - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=provision, args=(title,))
        for title in ("First objective", "Second objective")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ResourceConflictError)


def test_sql_immutability_and_digest_tamper_detection(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store, records = _provisioned_store(path)

    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE engine_experiment_presentation_profiles SET registered_at = 'changed'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("DELETE FROM engine_experiment_target_presentations")
    connection.rollback()
    connection.execute("DROP TRIGGER engine_experiment_profiles_no_update")
    profile = _profile()
    profile["objective"]["title"] = "Tampered objective"
    connection.execute(
        """UPDATE engine_experiment_presentation_profiles
           SET document_json = ? WHERE experiment_id = ?""",
        (json.dumps(profile, sort_keys=True, separators=(",", ":")), EXPERIMENT_ID),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ProductStoreError, match="integrity check failed"):
        store.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=1,
            experiment_digest=str(records[0]["digest"]),
        )


def test_registry_digest_detects_anchor_column_tamper(tmp_path: Path) -> None:
    path = tmp_path / "bluefire.db"
    store, records = _provisioned_store(path)
    _register_defense(store, records)

    connection = sqlite3.connect(path)
    connection.execute("DROP TRIGGER engine_experiment_defenses_no_update")
    connection.execute(
        """UPDATE engine_experiment_defense_presentations
           SET registered_experiment_digest = ? WHERE experiment_id = ?""",
        (records[7]["digest"], EXPERIMENT_ID),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ProductStoreError, match="registry integrity check failed"):
        store.get_engine_experiment_presentation(
            EXPERIMENT_ID,
            revision=7,
            experiment_digest=str(records[6]["digest"]),
        )


def test_registration_rejects_private_paths_and_plaintext_secrets(tmp_path: Path) -> None:
    store = ProductStore(tmp_path / "bluefire.db")
    private = _profile()
    private["objective"]["summary"] = r"Inspect C:\Users\operator\private-output.json"
    with pytest.raises(ProductStoreError, match="contract validation"):
        store.provision_engine_experiment_presentation(
            EXPERIMENT_ID,
            private,
            _initial_target(),
        )

    secret = _profile()
    secret["engine_setup"]["model"]["api_key"] = "sk-not-allowed-here"
    with pytest.raises(ProductStoreError, match="fields changed|environment-variable"):
        store.provision_engine_experiment_presentation(
            EXPERIMENT_ID,
            secret,
            _initial_target(),
        )
