from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

import bluefire.product_store_strix_runtime as runtime_store
from bluefire.product_store import SCHEMA_VERSION, ProductStore
from bluefire.product_store_errors import ProductStoreError, ResourceConflictError
from bluefire.product_store_serialization import canonical_json
from bluefire.run_bundle_export import export_run_bundle
from bluefire.strix_adapter import StrixBuildIdentity
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
    REVIEWED_SOURCE_REVISION,
)
from bluefire.util import content_hash
from tests_platform.test_product_store_engine_actions import EXPERIMENT_ID, _store
from tests_platform.test_product_store_tenant_action_materials import (
    _fixture as slot_fixture,
)
from tests_platform.test_product_store_tenant_action_materials import _retain as retain_slot
from tests_platform.test_run_bundle_export import finalized

AUTHORITY_REF = "sha256:" + "a" * 64
QUALIFICATION_REF = "sha256:" + "b" * 64
AUTHORITY_BASIS = "sha256:" + "c" * 64
ATTEMPT_ID = "engine-attempt-" + "d" * 32
CREATED = "2026-11-04T12:01:00Z"
EXPIRES = "2026-11-04T12:31:00Z"


def digest(character: str) -> str:
    return "sha256:" + character * 64


def build() -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=REVIEWED_SOURCE_REVISION,
        source_tree_sha256=digest("1"),
        package_sha256=digest("2"),
        executable_sha256=digest("3"),
        image_reference=(
            "ghcr.io/usestrix/strix-sandbox@"
            "sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30"
        ),
        image_inventory_sha256=digest("4"),
        prompt_upstream_sha256=f"sha256:{REVIEWED_PROMPT_SHA256}",
        prompt_overlay_sha256=f"sha256:{OVERLAY_SHA256}",
        prompt_patched_sha256=f"sha256:{PATCHED_PROMPT_SHA256}",
    )


def authority(
    generation: int = 1,
    *,
    state: str = "active",
    recorded_at: str = CREATED,
) -> dict[str, Any]:
    return {
        "schema_version": "bluefire.strix-runtime-authority.v1",
        "generation": generation,
        "state": state,
        "qualification_manifest_ref": QUALIFICATION_REF,
        "protected_artifact_key": "q" + "e" * 31,
        "installed_bluefire_revision": "f" * 40,
        "strix_build_digest": content_hash(build().to_dict()),
        "threat_review_ref": digest("5"),
        "recorded_at": recorded_at,
        "revocation_reason": None if state == "active" else "owner revoked runtime",
    }


def append_authority(store: ProductStore) -> Mapping[str, Any]:
    return store._append_strix_runtime_authority(
        authority_ref=AUTHORITY_REF,
        authority=authority(),
        authority_basis_ref=AUTHORITY_BASIS,
        expected_previous_event_digest=None,
    )


def reservation(
    store: ProductStore,
    authority_record: Mapping[str, Any],
    *,
    attempt_id: str = ATTEMPT_ID,
) -> dict[str, Any]:
    experiment = store.get_engine_experiment(EXPERIMENT_ID)
    return {
        "schema_version": runtime_store.ADMISSION_RESERVATION_SCHEMA,
        "attempt_id": attempt_id,
        "experiment_id": EXPERIMENT_ID,
        "experiment_revision": experiment["revision"],
        "experiment_digest": experiment["digest"],
        "binding_digest": content_hash({"attempt_id": attempt_id, "role": "binding"}),
        "delegation_digest": digest("7"),
        "objective_ref": digest("8"),
        "environment_ref": digest("9"),
        "authority_ref": AUTHORITY_REF,
        "authority_generation": authority_record["authority"]["generation"],
        "authority_record_digest": authority_record["authority_record_digest"],
        "qualification_ref": QUALIFICATION_REF,
        "target_snapshot_digest": digest("0"),
        "request_digest": content_hash({"attempt_id": attempt_id, "role": "request"}),
        "created_at": CREATED,
        "expires_at": EXPIRES,
    }


def admission(
    store: ProductStore,
    authority_record: Mapping[str, Any],
    *,
    attempt_id: str = ATTEMPT_ID,
) -> dict[str, Any]:
    reserve = reservation(store, authority_record, attempt_id=attempt_id)
    exact_build = build().to_dict()
    result: dict[str, Any] = {
        "schema_version": runtime_store.ADMISSION_RECORD_SCHEMA,
        **{
            name: reserve[name]
            for name in (
                "attempt_id",
                "experiment_id",
                "experiment_revision",
                "experiment_digest",
                "binding_digest",
                "delegation_digest",
                "objective_ref",
                "environment_ref",
                "authority_ref",
                "authority_generation",
                "authority_record_digest",
                "target_snapshot_digest",
            )
        },
        "qualification_ref": QUALIFICATION_REF,
        "build": exact_build,
        "build_digest": content_hash(exact_build),
        "model_id": "controlled-test-provider",
        "budgets": {
            "wall_seconds": 120,
            "max_turns_per_agent": 3,
            "max_model_cost_usd": "1",
        },
        "limits": {
            "memory": "2g",
            "cpus": "2",
            "pids": 512,
            "log_size": "20m",
            "log_files": 2,
        },
        "created_at": CREATED,
        "expires_at": EXPIRES,
    }
    for name in sorted(runtime_store._ADMISSION_FIELDS - set(result)):
        result[name] = content_hash({"attempt_id": attempt_id, "field": name})
    return result


def prepare_reservation(
    store: ProductStore,
    authority_record: Mapping[str, Any],
    *,
    attempt_id: str = ATTEMPT_ID,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    retained = store._reserve_strix_runtime_admission(
        reservation(store, authority_record, attempt_id=attempt_id)
    )
    envelope = store._read_strix_runtime_admission_envelope(attempt_id)
    assert envelope is not None
    preparing = store._append_strix_runtime_admission_event(
        attempt_id=attempt_id,
        state="preparing",
        lifecycle_basis_ref=digest("e"),
        recorded_at="2026-11-04T12:02:00Z",
        expected_head_digest=envelope["lifecycle_head_digest"],
    )
    return retained, preparing


def retain_verified(
    store: ProductStore,
    authority_record: Mapping[str, Any],
    *,
    attempt_id: str = ATTEMPT_ID,
) -> Mapping[str, Any]:
    _retained, preparing = prepare_reservation(store, authority_record, attempt_id=attempt_id)
    return store._retain_verified_strix_runtime_admission(
        document=admission(store, authority_record, attempt_id=attempt_id),
        lifecycle_basis_ref=digest("f"),
        recorded_at="2026-11-04T12:03:00Z",
        expected_head_digest=preparing["event_digest"],
    )


def test_authority_chain_exact_retry_revocation_reactivation_and_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = append_authority(store)
    assert append_authority(store) == first
    assert store._read_current_strix_runtime_authority(AUTHORITY_REF) == first
    assert (
        store._read_strix_runtime_authority_event(
            AUTHORITY_REF, 1, first["authority_record_digest"]
        )
        == first
    )
    revoked = store._append_strix_runtime_authority(
        authority_ref=AUTHORITY_REF,
        authority=authority(2, state="revoked", recorded_at="2026-11-04T12:02:00Z"),
        authority_basis_ref=digest("d"),
        expected_previous_event_digest=first["event_digest"],
    )
    reactivated_authority = authority(3, recorded_at="2026-11-04T12:03:00Z")
    reactivated_authority["protected_artifact_key"] = "r" + "f" * 31
    reactivated = store._append_strix_runtime_authority(
        authority_ref=AUTHORITY_REF,
        authority=reactivated_authority,
        authority_basis_ref=digest("e"),
        expected_previous_event_digest=revoked["event_digest"],
    )
    reopened = ProductStore(store.path)
    assert reopened._read_current_strix_runtime_authority(AUTHORITY_REF) == reactivated
    assert reopened._is_strix_runtime_authority_descendant(
        authority_ref=AUTHORITY_REF,
        ancestor_generation=1,
        ancestor_record_digest=first["authority_record_digest"],
        descendant_generation=3,
        descendant_record_digest=reactivated["authority_record_digest"],
    )


def test_authority_conflicts_gaps_and_changed_revocation_anchors_refuse(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = append_authority(store)
    with pytest.raises(ResourceConflictError):
        store._append_strix_runtime_authority(
            authority_ref=AUTHORITY_REF,
            authority={**authority(), "threat_review_ref": digest("9")},
            authority_basis_ref=AUTHORITY_BASIS,
            expected_previous_event_digest=None,
        )
    with pytest.raises(ResourceConflictError, match="generation"):
        store._append_strix_runtime_authority(
            authority_ref=AUTHORITY_REF,
            authority=authority(3, state="revoked", recorded_at="2026-11-04T12:03:00Z"),
            authority_basis_ref=digest("d"),
            expected_previous_event_digest=first["event_digest"],
        )
    changed = authority(2, state="revoked", recorded_at="2026-11-04T12:02:00Z")
    changed["strix_build_digest"] = digest("f")
    with pytest.raises(ResourceConflictError, match="anchors"):
        store._append_strix_runtime_authority(
            authority_ref=AUTHORITY_REF,
            authority=changed,
            authority_basis_ref=digest("d"),
            expected_previous_event_digest=first["event_digest"],
        )


def test_concurrent_identical_authority_writes_converge(tmp_path: Path) -> None:
    store = _store(tmp_path)
    duplicate = ProductStore(store.path)

    def write(candidate: ProductStore) -> str:
        return cast(
            str,
            candidate._append_strix_runtime_authority(
                authority_ref=AUTHORITY_REF,
                authority=authority(),
                authority_basis_ref=AUTHORITY_BASIS,
                expected_previous_event_digest=None,
            )["event_digest"],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, (store, duplicate)))
    assert results[0] == results[1]
    with sqlite3.connect(store.path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM strix_runtime_authority_events").fetchone()[0]
            == 1
        )


@pytest.mark.parametrize(
    "table",
    [
        "strix_runtime_authority_events",
        "strix_runtime_authority_heads",
        "strix_runtime_admission_reservations",
        "strix_runtime_admission_events",
        "strix_runtime_admission_heads",
        "strix_runtime_admissions",
    ],
)
def test_private_runtime_rows_refuse_raw_update_delete_and_replace(
    tmp_path: Path, table: str
) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(f"SELECT * FROM {table} LIMIT 1").fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(f"UPDATE {table} SET rowid=rowid")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(f"DELETE FROM {table}")
        with pytest.raises(sqlite3.IntegrityError):
            placeholders = ",".join("?" for _ in row)
            connection.execute(f"INSERT OR REPLACE INTO {table} VALUES({placeholders})", row)


def test_reservation_verified_lifecycle_and_exact_retry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    reserved, preparing = prepare_reservation(store, current)
    assert store._reserve_strix_runtime_admission(reservation(store, current)) == reserved
    verified = store._retain_verified_strix_runtime_admission(
        document=admission(store, current),
        lifecycle_basis_ref=digest("f"),
        recorded_at="2026-11-04T12:03:00Z",
        expected_head_digest=preparing["event_digest"],
    )
    assert verified["lifecycle_state"] == "verified"
    retried = store._retain_verified_strix_runtime_admission(
        document=admission(store, current),
        lifecycle_basis_ref=digest("f"),
        recorded_at="2026-11-04T12:03:00Z",
        expected_head_digest=preparing["event_digest"],
    )
    assert retried == verified
    unknown = store._append_strix_runtime_admission_event(
        attempt_id=ATTEMPT_ID,
        state="unknown",
        lifecycle_basis_ref=digest("1"),
        recorded_at="2026-11-04T12:04:00Z",
        expected_head_digest=verified["lifecycle_head_digest"],
    )
    reverified = store._retain_verified_strix_runtime_admission(
        document=admission(store, current),
        lifecycle_basis_ref=digest("2"),
        recorded_at="2026-11-04T12:05:00Z",
        expected_head_digest=unknown["event_digest"],
    )
    revoked = store._append_strix_runtime_admission_event(
        attempt_id=ATTEMPT_ID,
        state="revoked",
        lifecycle_basis_ref=digest("3"),
        recorded_at="2026-11-04T12:06:00Z",
        expected_head_digest=reverified["lifecycle_head_digest"],
    )
    cleaned = store._append_strix_runtime_admission_event(
        attempt_id=ATTEMPT_ID,
        state="cleaned",
        lifecycle_basis_ref=digest("4"),
        recorded_at="2026-11-04T12:07:00Z",
        expected_head_digest=revoked["event_digest"],
    )
    assert cleaned["document"]["state"] == "cleaned"
    with pytest.raises(ResourceConflictError, match="transition"):
        store._append_strix_runtime_admission_event(
            attempt_id=ATTEMPT_ID,
            state="unknown",
            lifecycle_basis_ref=digest("5"),
            recorded_at="2026-11-04T12:08:00Z",
            expected_head_digest=cleaned["event_digest"],
        )


def test_generic_lifecycle_append_cannot_bypass_verified_retention(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    _reserved, preparing = prepare_reservation(store, current)
    with pytest.raises(ProductStoreError, match="exact admission retention"):
        store._append_strix_runtime_admission_event(
            attempt_id=ATTEMPT_ID,
            state="verified",
            lifecycle_basis_ref=digest("f"),
            recorded_at="2026-11-04T12:03:00Z",
            expected_head_digest=preparing["event_digest"],
        )


@pytest.mark.parametrize(
    "operation,recorded_at",
    [
        ("prepare", "2026-11-04T12:00:59Z"),
        ("prepare", EXPIRES),
        ("verify", "2026-11-04T12:00:59Z"),
        ("verify", EXPIRES),
    ],
)
def test_prepare_and_verify_require_reservation_chronology_and_unexpired_lifetime(
    tmp_path: Path, operation: str, recorded_at: str
) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    reserved = store._reserve_strix_runtime_admission(reservation(store, current))
    envelope = store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert envelope is not None
    if operation == "prepare":
        with pytest.raises(ResourceConflictError, match="lifetime"):
            store._append_strix_runtime_admission_event(
                attempt_id=ATTEMPT_ID,
                state="preparing",
                lifecycle_basis_ref=digest("e"),
                recorded_at=recorded_at,
                expected_head_digest=envelope["lifecycle_head_digest"],
            )
    else:
        preparing = store._append_strix_runtime_admission_event(
            attempt_id=ATTEMPT_ID,
            state="preparing",
            lifecycle_basis_ref=digest("e"),
            recorded_at="2026-11-04T12:02:00Z",
            expected_head_digest=envelope["lifecycle_head_digest"],
        )
        with pytest.raises(ResourceConflictError, match="lifetime"):
            store._retain_verified_strix_runtime_admission(
                document=admission(store, current),
                lifecycle_basis_ref=digest("f"),
                recorded_at=recorded_at,
                expected_head_digest=preparing["event_digest"],
            )
    assert reserved["document"]["expires_at"] == EXPIRES
    unchanged = store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert unchanged is not None and unchanged["admission"] is None
    if operation == "prepare":
        assert unchanged == envelope
    else:
        assert unchanged["lifecycle_head_digest"] == preparing["event_digest"]
        assert unchanged["lifecycle_state"] == "preparing"
        assert unchanged["lifecycle_sequence"] == 2


def test_revoked_authority_refuses_new_reservation_and_pending_admission(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    _reserved, preparing = prepare_reservation(store, current)
    store._append_strix_runtime_authority(
        authority_ref=AUTHORITY_REF,
        authority=authority(2, state="revoked", recorded_at="2026-11-04T12:02:30Z"),
        authority_basis_ref=digest("d"),
        expected_previous_event_digest=current["event_digest"],
    )
    with pytest.raises(ResourceConflictError, match="authority changed"):
        store._retain_verified_strix_runtime_admission(
            document=admission(store, current),
            lifecycle_basis_ref=digest("f"),
            recorded_at="2026-11-04T12:03:00Z",
            expected_head_digest=preparing["event_digest"],
        )
    second = reservation(store, current)
    second["attempt_id"] = "engine-attempt-" + "e" * 32
    second["binding_digest"] = digest("f")
    with pytest.raises(ResourceConflictError, match="authority changed"):
        store._reserve_strix_runtime_admission(second)


def test_verified_admission_must_match_authorized_build(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    _reserved, preparing = prepare_reservation(store, current)
    changed = admission(store, current)
    changed_build = {**changed["build"], "package_sha256": digest("9")}
    changed["build"] = changed_build
    changed["build_digest"] = content_hash(changed_build)
    with pytest.raises(ResourceConflictError, match="authority"):
        store._retain_verified_strix_runtime_admission(
            document=changed,
            lifecycle_basis_ref=digest("f"),
            recorded_at="2026-11-04T12:03:00Z",
            expected_head_digest=preparing["event_digest"],
        )


def test_admission_conflicts_stale_authority_and_secret_or_path_fields_refuse(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    _reserved, preparing = prepare_reservation(store, current)
    changed = admission(store, current)
    changed["custody_record_digest"] = digest("9")
    store._retain_verified_strix_runtime_admission(
        document=changed,
        lifecycle_basis_ref=digest("f"),
        recorded_at="2026-11-04T12:03:00Z",
        expected_head_digest=preparing["event_digest"],
    )
    envelope = store._read_strix_runtime_admission_envelope(ATTEMPT_ID)
    assert envelope is not None
    with pytest.raises(ResourceConflictError, match="conflicts"):
        store._retain_verified_strix_runtime_admission(
            document=admission(store, current),
            lifecycle_basis_ref=digest("f"),
            recorded_at="2026-11-04T12:03:00Z",
            expected_head_digest=envelope["lifecycle_head_digest"],
        )
    malformed = admission(store, current)
    malformed["secret"] = "plaintext"  # pragma: allowlist secret
    with pytest.raises(ProductStoreError):
        runtime_store._admission(malformed)
    malformed = admission(store, current)
    malformed["workspace_path"] = "C:/private/runtime"
    with pytest.raises(ProductStoreError):
        runtime_store._admission(malformed)


@pytest.mark.parametrize(
    "shared_field",
    [
        "custody_record_ref",
        "workspace_ref",
        "control_root_ref",
        "artifact_root_ref",
        "network_plan_ref",
        "network_snapshot_ref",
        "network_verification_ref",
        "custody_plan_ref",
    ],
)
def test_two_attempts_cannot_share_runtime_or_custody_identity(
    tmp_path: Path, shared_field: str
) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    first = retain_verified(store, current)
    second_attempt = "engine-attempt-" + "e" * 32
    _reserved, preparing = prepare_reservation(store, current, attempt_id=second_attempt)
    second = admission(store, current, attempt_id=second_attempt)
    first_document = first["admission"]["document"]
    second[shared_field] = first_document[shared_field]
    with pytest.raises((sqlite3.IntegrityError, ResourceConflictError), match="share|unique"):
        store._retain_verified_strix_runtime_admission(
            document=second,
            lifecycle_basis_ref=digest("9"),
            recorded_at="2026-11-04T12:03:00Z",
            expected_head_digest=preparing["event_digest"],
        )


def test_cross_attempt_lifecycle_record_tamper_is_detected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    first = retain_verified(store, current)
    second_attempt = "engine-attempt-" + "e" * 32
    retain_verified(store, current, attempt_id=second_attempt)
    foreign_ref = first["admission"]["admission_record_ref"]
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM strix_runtime_admission_events WHERE attempt_id=? AND state='verified'",
            (second_attempt,),
        ).fetchone()
        document = json.loads(row["document_json"])
        document["admission_record_ref"] = foreign_ref
        event_digest = content_hash(document)
        connection.execute("DROP TRIGGER strix_runtime_admission_events_no_update")
        connection.execute("DROP TRIGGER strix_runtime_admission_heads_valid_update")
        connection.execute(
            """UPDATE strix_runtime_admission_events SET document_json=?,event_digest=?,
            admission_record_ref=? WHERE attempt_id=? AND sequence=?""",
            (
                canonical_json(document),
                event_digest,
                foreign_ref,
                second_attempt,
                row["sequence"],
            ),
        )
        connection.execute(
            """UPDATE strix_runtime_admission_heads SET active_event_digest=?,
            admission_record_ref=? WHERE attempt_id=?""",
            (event_digest, foreign_ref, second_attempt),
        )
    with pytest.raises(ProductStoreError, match="ownership"):
        store._read_strix_runtime_admission_envelope(second_attempt)


def _rewrite_admission_and_lifecycle(
    connection: sqlite3.Connection, document: Mapping[str, Any]
) -> None:
    changed_digest = content_hash(document)
    changed_ref = content_hash(
        {
            "schema_version": "bluefire.strix-runtime-admission-record-ref.v1",
            "attempt_id": ATTEMPT_ID,
            "admission_record_digest": changed_digest,
        }
    )
    connection.execute("DROP TRIGGER strix_runtime_admissions_no_update")
    connection.execute("DROP TRIGGER strix_runtime_admission_events_no_update")
    connection.execute("DROP TRIGGER strix_runtime_admission_heads_valid_update")
    connection.execute(
        """UPDATE strix_runtime_admissions SET document_json=?,
        admission_record_digest=?,admission_record_ref=? WHERE attempt_id=?""",
        (canonical_json(document), changed_digest, changed_ref, ATTEMPT_ID),
    )
    event = connection.execute(
        "SELECT * FROM strix_runtime_admission_events WHERE attempt_id=? AND state='verified'",
        (ATTEMPT_ID,),
    ).fetchone()
    event_document = json.loads(event["document_json"])
    event_document["admission_record_ref"] = changed_ref
    event_digest = content_hash(event_document)
    connection.execute(
        """UPDATE strix_runtime_admission_events SET document_json=?,event_digest=?,
        admission_record_ref=? WHERE attempt_id=? AND sequence=?""",
        (
            canonical_json(event_document),
            event_digest,
            changed_ref,
            ATTEMPT_ID,
            event["sequence"],
        ),
    )
    connection.execute(
        """UPDATE strix_runtime_admission_heads SET active_event_digest=?,
        admission_record_ref=? WHERE attempt_id=?""",
        (event_digest, changed_ref, ATTEMPT_ID),
    )


def test_recomputed_admission_document_attempt_mismatch_is_detected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM strix_runtime_admissions WHERE attempt_id=?", (ATTEMPT_ID,)
        ).fetchone()
        document = json.loads(row["document_json"])
        document["attempt_id"] = "engine-attempt-" + "e" * 32
        _rewrite_admission_and_lifecycle(connection, document)
    with pytest.raises(ProductStoreError, match="integrity"):
        store._read_strix_runtime_admission_envelope(ATTEMPT_ID)


def test_recomputed_admission_provenance_mismatch_is_detected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM strix_runtime_admissions WHERE attempt_id=?", (ATTEMPT_ID,)
        ).fetchone()
        document = json.loads(row["document_json"])
        document["binding_digest"] = digest("9")
        _rewrite_admission_and_lifecycle(connection, document)
    with pytest.raises(ProductStoreError, match="provenance"):
        store._read_strix_runtime_admission_envelope(ATTEMPT_ID)


@pytest.mark.parametrize(
    "table,key_column,new_value",
    [
        ("strix_runtime_authority_heads", "authority_ref", digest("9")),
        ("strix_runtime_admission_heads", "attempt_id", "engine-attempt-" + "e" * 32),
    ],
)
def test_head_owner_key_mutation_is_rejected(
    tmp_path: Path, table: str, key_column: str, new_value: str
) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="invalid"):
            connection.execute(f"UPDATE {table} SET {key_column}=?", (new_value,))


@pytest.mark.parametrize("tamper", ["authority_event", "authority_head", "admission_event"])
def test_dropped_trigger_tampering_is_detected_on_read(tmp_path: Path, tamper: str) -> None:
    store = _store(tmp_path)
    current = append_authority(store)
    retain_verified(store, current)
    with sqlite3.connect(store.path) as connection:
        if tamper == "authority_event":
            connection.execute("DROP TRIGGER strix_runtime_authority_events_no_update")
            connection.execute(
                "UPDATE strix_runtime_authority_events SET event_digest=?",
                (digest("9"),),
            )
        elif tamper == "authority_head":
            connection.execute("DROP TRIGGER strix_runtime_authority_heads_valid_update")
            connection.execute(
                "UPDATE strix_runtime_authority_heads SET active_event_digest=?",
                (digest("9"),),
            )
        else:
            connection.execute("DROP TRIGGER strix_runtime_admission_events_no_update")
            connection.execute(
                "UPDATE strix_runtime_admission_events SET event_digest=? WHERE sequence=2",
                (digest("9"),),
            )
    if tamper.startswith("authority"):
        with pytest.raises(ProductStoreError, match="integrity"):
            store._read_current_strix_runtime_authority(AUTHORITY_REF)
    else:
        with pytest.raises(ProductStoreError, match="integrity"):
            store._read_strix_runtime_admission_envelope(ATTEMPT_ID)


def _as_v19(store: ProductStore) -> None:
    with sqlite3.connect(store.path) as connection:
        for table in (
            "engine_attempt_reconciliation_intents",
            "engine_attempt_pre_dispatch_settlements",
            "engine_attempt_execution_claims",
            "strix_runtime_issuance_records",
            "strix_runtime_admission_heads",
            "strix_runtime_admission_events",
            "strix_runtime_admissions",
            "strix_runtime_admission_reservations",
            "strix_runtime_authority_heads",
            "strix_runtime_authority_events",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DELETE FROM schema_migrations WHERE version >= 20")
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations VALUES(19,'2026-11-04T00:00:00Z')"
        )


def _non_v20_data(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    with sqlite3.connect(path) as connection:
        names = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {
            name: sorted(connection.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for (name,) in names
            if not name.startswith("strix_runtime_")
            and name
            not in {
                "engine_attempt_execution_claims",
                "engine_attempt_pre_dispatch_settlements",
                "engine_attempt_reconciliation_intents",
            }
            and not name.startswith("sqlite_")
            and name != "schema_migrations"
        }


def test_v19_to_v20_preserves_existing_data_and_migration_rolls_back(
    tmp_path: Path, monkeypatch
) -> None:
    store, slot_document, slot_values = slot_fixture(tmp_path)
    retain_slot(store, slot_document, slot_values)
    store.set_setting("v20-proof", {"retained": True})
    _as_v19(store)
    before = _non_v20_data(store.path)
    upgraded = ProductStore(store.path)
    assert SCHEMA_VERSION == upgraded.schema_version == 23
    assert _non_v20_data(store.path) == before

    _as_v19(upgraded)
    original = runtime_store.initialize_schema

    def interrupted(connection):
        original(connection)
        raise OSError("fixture interruption")

    monkeypatch.setattr(runtime_store, "initialize_schema", interrupted)
    with pytest.raises(ProductStoreError, match="migration failed safely"):
        ProductStore(store.path)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 19
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'strix_runtime_%'"
            ).fetchall()
            == []
        )


def test_private_runtime_records_never_enter_public_surfaces_or_run_exports(tmp_path: Path) -> None:
    store = _store(tmp_path)
    before = (
        store.list_engine_experiments(),
        store.get_engine_experiment(EXPERIMENT_ID),
        store.list_resources("model_provider"),
    )
    runs, run_id = finalized(tmp_path / "runs")
    before_bundle = export_run_bundle(runs, run_id)
    current = append_authority(store)
    retain_verified(store, current)
    after = (
        store.list_engine_experiments(),
        store.get_engine_experiment(EXPERIMENT_ID),
        store.list_resources("model_provider"),
    )
    assert before == after
    for kind in ("strix_runtime_authority", "strix_runtime_admission"):
        with pytest.raises(ProductStoreError, match="unsupported"):
            store.list_resources(kind)
    after_bundle = export_run_bundle(runs, run_id)
    with (
        zipfile.ZipFile(io.BytesIO(before_bundle)) as earlier,
        zipfile.ZipFile(io.BytesIO(after_bundle)) as later,
    ):
        assert earlier.namelist() == later.namelist()
        assert all(earlier.read(name) == later.read(name) for name in earlier.namelist())
        assert all(AUTHORITY_REF.encode() not in later.read(name) for name in later.namelist())


def test_future_schema_refuses_before_v20_ddl(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    ProductStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO schema_migrations VALUES(24,'2026-11-04T00:00:00Z')")
        for table in (
            "strix_runtime_issuance_records",
            "strix_runtime_admission_heads",
            "strix_runtime_admission_events",
            "strix_runtime_admissions",
            "strix_runtime_admission_reservations",
            "strix_runtime_authority_heads",
            "strix_runtime_authority_events",
        ):
            connection.execute(f"DROP TABLE {table}")
    with pytest.raises(ProductStoreError, match="newer"):
        ProductStore(path)
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'strix_runtime_%'"
            ).fetchall()
            == []
        )
