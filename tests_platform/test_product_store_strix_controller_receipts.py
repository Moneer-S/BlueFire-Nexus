"""Private receipt-chain and source-boundary checks for installed Strix."""

from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from bluefire import product_store_strix_composition_schema as composition_schema
from bluefire import product_store_strix_controller_receipts as receipts
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_product_store_strix_v2_authority import (
    _prelaunch,
    _prepare_resource_intent,
)

pytest_plugins = ("tests_platform.test_product_store_strix_v2_authority",)


def test_receipt_schema_requires_migration_and_refuses_replacement() -> None:
    connection = sqlite3.connect(":memory:")
    with pytest.raises(ProductStoreError, match="owning migration"):
        receipts.initialize_schema(connection)
    connection.execute("BEGIN")
    composition_schema.initialize_schema(connection)
    receipts.initialize_schema(connection)
    digest = content_hash("source")
    document = json.dumps({"source": "fixture"}, separators=(",", ":"))
    row = (
        "engine-attempt-" + "a" * 32,
        1,
        digest,
        digest,
        digest,
        None,
        "native_observed",
        digest,
        None,
        receipts.RECORD_SCHEMA,
        document,
        content_hash("record"),
        "2026-11-13T00:00:00Z",
    )
    connection.execute(
        "INSERT INTO strix_controller_receipts "
        "(attempt_id,attempt_sequence,claim_ref,prelaunch_ref,transaction_ref,"
        "activation_ref,kind,source_ref,previous_ref,record_schema,record_json,"
        "record_ref,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        row,
    )
    with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
        connection.execute(
            "INSERT OR REPLACE INTO strix_controller_receipts "
            "(attempt_id,attempt_sequence,claim_ref,prelaunch_ref,transaction_ref,"
            "activation_ref,kind,source_ref,previous_ref,record_schema,record_json,"
            "record_ref,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("UPDATE strix_controller_receipts SET kind='controller_call'")
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        connection.execute("DELETE FROM strix_controller_receipts")
    connection.close()


def _observed_packet(attempt: str, plan: str) -> dict:
    observed = {
        "schema_version": "bluefire.strix-worker-runtime-observation.v1",
        "attempt_id": attempt,
        "plan_ref": plan,
    }
    observed["observation_ref"] = content_hash(observed)
    packet = {
        "phase": "observed",
        "sequence": 1,
        "helper_pid": 1234,
        "document": observed,
    }
    packet["packet_digest"] = (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema_version": "bluefire.strix-worker-runtime-ipc.v1",
                    "kind": "observed",
                    "observed": observed,
                }
            )
        ).hexdigest()
    )
    return packet


def test_native_packet_rechecks_canonical_wire_and_source_join() -> None:
    attempt = "engine-attempt-" + "a" * 32
    plan = content_hash("closure-plan")
    packet = _observed_packet(attempt, plan)
    source_ref, source = receipts._native_packet(
        packet,
        phase="observed",
        attempt_id=attempt,
        claim_ref=content_hash("claim"),
        plan_ref=plan,
        observed_ref=None,
        qualified_ref=None,
    )
    assert source_ref == packet["document"]["observation_ref"]
    assert source["document"] == packet["document"]
    with pytest.raises(ProductStoreError, match="packet digest"):
        receipts._native_packet(
            {**packet, "packet_digest": content_hash("other")},
            phase="observed",
            attempt_id=attempt,
            claim_ref=content_hash("claim"),
            plan_ref=plan,
            observed_ref=None,
            qualified_ref=None,
        )
    with pytest.raises(ProductStoreError, match="retained intent"):
        receipts._native_packet(
            packet,
            phase="observed",
            attempt_id=attempt,
            claim_ref=content_hash("claim"),
            plan_ref=content_hash("other-plan"),
            observed_ref=None,
            qualified_ref=None,
        )


def test_receipt_reader_reopens_exact_prelaunch_and_resource_intent(f) -> None:
    prepared = f
    prelaunch = _prelaunch(prepared)
    _prepare_resource_intent(prepared, prelaunch)
    with prepared.store._connection(write=True) as connection:
        receipts.initialize_schema(connection)
    journal = receipts.ProductStoreStrixControllerReceiptJournal(product_store=prepared.store)
    assert (
        journal.reopen(
            attempt_id=prepared.binding.attempt_id,
            claim_ref=prepared.accepted.claim_ref,
            prelaunch_ref=prelaunch.prelaunch_ref,
            transaction_ref=prepared.transaction_ref,
            closure_plan_ref=content_hash("closure-plan"),
            worker_plan_digest=content_hash("worker-plan"),
        )
        == ()
    )
    with pytest.raises(ProductStoreError):
        journal.reopen(
            attempt_id=prepared.binding.attempt_id,
            claim_ref=content_hash("other-claim"),
            prelaunch_ref=prelaunch.prelaunch_ref,
            transaction_ref=prepared.transaction_ref,
            closure_plan_ref=content_hash("closure-plan"),
            worker_plan_digest=content_hash("worker-plan"),
        )

    packet = _observed_packet(prepared.binding.attempt_id, content_hash("closure-plan"))
    source_ref, source = receipts._native_packet(
        packet,
        phase="observed",
        attempt_id=prepared.binding.attempt_id,
        claim_ref=prepared.accepted.claim_ref,
        plan_ref=content_hash("closure-plan"),
        observed_ref=None,
        qualified_ref=None,
    )
    with prepared.store._connection(write=True) as connection:
        retained = journal._append(
            connection,
            attempt_id=prepared.binding.attempt_id,
            claim_ref=prepared.accepted.claim_ref,
            prelaunch_ref=prelaunch.prelaunch_ref,
            transaction_ref=prepared.transaction_ref,
            activation_ref=None,
            kind="native_observed",
            source_ref=source_ref,
            source=source,
        )
    reopened_store = ProductStore(prepared.store.path)
    reopened = receipts.ProductStoreStrixControllerReceiptJournal(product_store=reopened_store)
    assert (
        reopened.reopen(
            attempt_id=prepared.binding.attempt_id,
            claim_ref=prepared.accepted.claim_ref,
            prelaunch_ref=prelaunch.prelaunch_ref,
            transaction_ref=prepared.transaction_ref,
            closure_plan_ref=content_hash("closure-plan"),
            worker_plan_digest=content_hash("worker-plan"),
        )[0].record_ref
        == retained.record_ref
    )
    with prepared.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER strix_controller_receipts_no_update")
        connection.execute(
            "UPDATE strix_controller_receipts SET record_json=? WHERE record_ref=?",
            ('{"modified":true}', retained.record_ref),
        )
    with pytest.raises(ProductStoreError, match="integrity|cannot be decoded"):
        reopened.reopen(
            attempt_id=prepared.binding.attempt_id,
            claim_ref=prepared.accepted.claim_ref,
            prelaunch_ref=prelaunch.prelaunch_ref,
            transaction_ref=prepared.transaction_ref,
            closure_plan_ref=content_hash("closure-plan"),
            worker_plan_digest=content_hash("worker-plan"),
        )
