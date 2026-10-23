"""Authenticated managed correction closure handoff; synthetic producers only."""

from __future__ import annotations

import copy
import json

import pytest

from bluefire import product_store_file_access_managed_closure as managed_closure_store
from bluefire import product_store_file_access_native_evidence as native
from bluefire import windows_file_access_managed_result as managed_result
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_correction_execution as execution_fake
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_baseline_publication import saved as saved
from tests_platform.test_windows_file_access_correction_execution import execution as execution
from tests_platform.test_windows_file_access_correction_reservation import reviewed as reviewed
from tests_platform.test_windows_file_access_pair_provenance import paired as paired
from tests_platform.test_windows_file_access_setup_lifecycle import lifecycle as lifecycle


def _serialized_closure(value):
    owner = value.state.retest_owner
    result = owner.outcome(True).process
    receipt = result.cleanup_receipt
    assert receipt is not None
    original = execution_fake.module.wire._reservation(
        owner.original, execution_fake.module.wire._CORRECTION
    )
    expected = execution_fake.module.wire._document(owner.original._expected)
    trail = native.query(
        value.store,
        original["task_id"],
        original["transport_request_hash"],
        expected,
        at_ms(value.state.wall),
        _protocol=native._Protocol.CORRECTION_V3,
    )
    assert type(trail) is native.CorrectionNativeTaskEvidence
    assert trail.packet_bytes is not None
    assert trail.ready_bytes is not None
    assert trail.terminal_bytes is not None
    proof = receipt.document()
    consume = value.state.remote_client.consume_receipt
    assert consume is not None
    lineage = {
        "schema_version": managed_result.MANAGED_CORRECTION_LINEAGE_SCHEMA,
        "protocol": "correction_v3",
        "task_id": trail.task_id,
        "transport_request_hash": trail.transport_request_hash,
        "claim_digest": trail.claim_digest,
        "packet_digest": proof["packet_digest"],
        "ready_digest": content_hash(
            execution_fake.module.wire._document(
                trail.ready_bytes, execution_fake.module.wire.READY_MAX
            )
        ),
        "terminal_digest": content_hash(
            execution_fake.module.wire._document(
                trail.terminal_bytes, execution_fake.module.wire.TERMINAL_MAX
            )
        ),
        "actual_returncode": trail.actual_returncode,
        "receipt_digest": content_hash(proof),
        "session_nonce": consume["session_nonce"],
        "ack_nonce": consume["ack_nonce"],
        "consume_receipt_digest": content_hash(consume),
    }
    identity = {
        "task_id": trail.task_id,
        "transport_request_hash": trail.transport_request_hash,
        "expected_binding": expected,
        "clock": at_ms(value.state.wall),
    }
    return receipt, lineage, identity


def _authenticated(receipt, lineage):
    closure = object.__new__(managed_result.AuthenticatedManagedCorrectionClosure)
    object.__setattr__(closure, "_receipt", bytes(receipt._raw))
    object.__setattr__(closure, "_packet", bytes(receipt._packet))
    object.__setattr__(closure, "_lineage", canonical_json_bytes(lineage))
    return closure


@pytest.fixture
def recoverable(execution):
    value = execution
    value.state.fault = "retest_persistence"
    execution_fake._abort(value, "retest")
    with pytest.raises(ProductStoreError):
        value.runtime.execute(value.ctx, value.request)
    receipt, lineage, identity = _serialized_closure(value)
    with value.store._connection(write=True) as connection:
        connection.execute("DROP TRIGGER synthetic_retest_failure")
        count = connection.execute(
            "SELECT COUNT(*) FROM file_access_owned_process_closures WHERE task_id=?",
            (identity["task_id"],),
        ).fetchone()[0]
    assert count == 0
    return value, receipt, lineage, identity


def test_managed_closure_is_separate_exact_type_and_reopens_idempotently(recoverable):
    value, receipt, lineage, identity = recoverable
    closure = _authenticated(receipt, lineage)
    with pytest.raises(TypeError):
        managed_result.AuthenticatedManagedCorrectionClosure()
    with pytest.raises(ProductStoreError):
        native.record_cleanup(
            value.store,
            identity["task_id"],
            identity["transport_request_hash"],
            identity["expected_binding"],
            closure,
            identity["clock"],
            _protocol=native._Protocol.CORRECTION_V3,
        )
    with pytest.raises(ProductStoreError):
        managed_closure_store.record_authenticated_managed_correction_closure(
            value.store, **identity, closure=receipt
        )

    joined = managed_closure_store.record_authenticated_managed_correction_closure(
        value.store, **identity, closure=closure
    )
    assert joined.owned_job_cleanup == "verified"
    assert type(joined.native_evidence) is native.CorrectionNativeTaskEvidence
    with value.store._connection() as connection:
        retained = json.loads(
            connection.execute(
                "SELECT document_json FROM file_access_owned_process_closures " "WHERE task_id=?",
                (identity["task_id"],),
            ).fetchone()[0]
        )
    assert retained["managed_lineage_utf8"] == canonical_json_bytes(lineage).decode("utf-8")
    reopened = ProductStore(value.store.path)
    assert (
        managed_closure_store.record_authenticated_managed_correction_closure(
            reopened, **identity, closure=closure
        )
        == joined
    )


def test_managed_closure_rejects_changed_serialized_lineage_without_a_row(recoverable):
    value, receipt, lineage, identity = recoverable
    faults = {
        "claim_digest": "sha256:" + "1" * 64,
        "ready_digest": "sha256:" + "2" * 64,
        "terminal_digest": "sha256:" + "3" * 64,
        "actual_returncode": 4 if lineage["actual_returncode"] == 0 else 0,
        "receipt_digest": "sha256:" + "4" * 64,
        "session_nonce": "5" * 64,
        "ack_nonce": "6" * 64,
        "consume_receipt_digest": "sha256:" + "7" * 64,
    }
    for field, replacement in faults.items():
        changed = copy.deepcopy(lineage)
        changed[field] = replacement
        with pytest.raises(ProductStoreError):
            managed_closure_store.record_authenticated_managed_correction_closure(
                value.store, **identity, closure=_authenticated(receipt, changed)
            )
    changed = {**lineage, "unexpected": True}
    with pytest.raises(ProductStoreError):
        managed_closure_store.record_authenticated_managed_correction_closure(
            value.store, **identity, closure=_authenticated(receipt, changed)
        )
    with value.store._connection() as connection:
        assert not connection.execute(
            "SELECT 1 FROM file_access_owned_process_closures WHERE task_id=?",
            (identity["task_id"],),
        ).fetchone()
