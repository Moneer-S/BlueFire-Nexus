"""Durable one-use Ready consumption for a managed Windows correction."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from . import product_store_file_access_native_evidence as native
from . import windows_file_access_managed_evidence as managed_evidence
from . import windows_file_access_native_wire as wire
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash


def persisted_managed_correction_ready(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    *,
    session_nonce: str,
    ack_nonce: str,
    packet: bytes,
    ready: bytes,
    clock: datetime,
) -> managed_evidence.PersistedManagedCorrectionReady:
    """Commit and return the one exact consume row for the stored Ready."""

    try:
        context = native._context(
            store,
            task_id,
            transport_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        wire._hex(session_nonce, 64)
        wire._hex(ack_nonce, 64)
        with store._connection(write=True) as connection:
            native._recheck(connection, context)
            trail, documents = native._load(connection, context, clock)
            native._require(
                type(trail) is native.CorrectionNativeTaskEvidence
                and trail.packet_bytes == packet
                and trail.ready_bytes == ready
                and trail.terminal_bytes is None
                and set(documents) == {"packet", "ready"}
                and native._cleanup_load(connection, context, clock, trail)[1] is None
            )
            retained = wire.validate_correction_retained_packet(context.original, packet)
            wire.validate_correction_ready(retained, ready)
            row = {
                "schema_version": managed_evidence.READY_CONSUME_SCHEMA,
                "protocol": native._Protocol.CORRECTION_V3.value,
                "task_id": context.task_id,
                "transport_request_hash": context.transport_hash,
                "claim_digest": context.claim_digest,
                "session_nonce": session_nonce,
                "packet_digest": wire._binding(retained)["packet_digest"],
                "ready_digest": content_hash(wire._document(ready, wire.READY_MAX)),
                "ack_nonce": ack_nonce,
                "ready_evidence_digest": documents["ready"][0]["document_digest"],
            }
            previous = native._managed_ready_consume_at(connection, context, trail, documents)
            if previous is None:
                serialized = canonical_json(row)
                native._text_bytes(serialized, managed_evidence.READY_CONSUME_MAX)
                connection.execute(
                    "INSERT INTO file_access_task_evidence VALUES(?,?,?,?)",
                    (
                        context.task_id,
                        managed_evidence.READY_CONSUME_STAGE,
                        serialized,
                        content_hash(row),
                    ),
                )
                trail, documents = native._load(connection, context, clock)
                previous = native._managed_ready_consume_at(connection, context, trail, documents)
            native._require(previous == row)
        receipt = object.__new__(managed_evidence.PersistedManagedCorrectionReady)
        object.__setattr__(receipt, "_raw", canonical_json(previous).encode("utf-8"))
        receipt.document()
        return receipt
    except native._FAILURES:
        raise ProductStoreError(native._ERROR) from None


def load_persisted_managed_correction_ready(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    *,
    packet: bytes,
    ready: bytes,
    clock: datetime,
) -> managed_evidence.PersistedManagedCorrectionReady:
    """Load the exact original Ready consume row without reconstructing it."""

    try:
        context = native._context(
            store,
            task_id,
            transport_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        with store._connection() as connection:
            native._recheck(connection, context)
            trail, documents = native._load(connection, context, clock)
            native._require(trail.packet_bytes == packet and trail.ready_bytes == ready)
            committed = native._managed_ready_consume_at(connection, context, trail, documents)
            native._require(committed is not None)
        receipt = object.__new__(managed_evidence.PersistedManagedCorrectionReady)
        object.__setattr__(receipt, "_raw", canonical_json(committed).encode("utf-8"))
        receipt.document()
        return receipt
    except native._FAILURES:
        raise ProductStoreError(native._ERROR) from None


def validate_persisted_managed_correction_ready(
    store: Any,
    task_id: str,
    transport_hash: str,
    expected_binding: Any,
    receipt: Any,
    *,
    packet: bytes,
    ready: bytes,
    clock: datetime,
) -> managed_evidence.PersistedManagedCorrectionReady:
    """Rejoin an authenticated result to the exact committed consume row."""

    try:
        row = dict(receipt)
        candidate = object.__new__(managed_evidence.PersistedManagedCorrectionReady)
        object.__setattr__(candidate, "_raw", canonical_json(row).encode("utf-8"))
        candidate.document()
        context = native._context(
            store,
            task_id,
            transport_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        with store._connection() as connection:
            native._recheck(connection, context)
            trail, documents = native._load(connection, context, clock)
            native._require(trail.packet_bytes == packet and trail.ready_bytes == ready)
            committed = native._managed_ready_consume_at(connection, context, trail, documents)
            native._require(committed == row)
        return candidate
    except native._FAILURES:
        raise ProductStoreError(native._ERROR) from None
