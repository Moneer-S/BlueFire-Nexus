"""Durable authenticated cleanup closure for one managed correction."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from . import product_store_file_access_native_evidence as native
from . import windows_file_access_managed_evidence as managed_evidence
from . import windows_file_access_native_wire as wire
from .product_store_errors import ProductStoreError
from .product_store_serialization import canonical_json
from .util import content_hash


def record_authenticated_managed_correction_closure(
    store: Any,
    task_id: str,
    transport_request_hash: str,
    expected_binding: Any,
    closure: managed_evidence.AuthenticatedManagedCorrectionClosure,
    clock: datetime,
) -> native.NativeCleanupEvidence:
    """Persist only the exact authenticated closure for the original task."""

    try:
        native._require(
            type(closure) is managed_evidence.AuthenticatedManagedCorrectionClosure
        )
        context = native._context(
            store,
            task_id,
            transport_request_hash,
            expected_binding,
            _protocol=native._Protocol.CORRECTION_V3,
        )
        with store._connection(write=True) as connection:
            native._recheck(connection, context)
            trail, documents = native._load(connection, context, clock)
            consume = native._managed_ready_consume_at(
                connection, context, trail, documents
            )
            native._require(
                consume is not None
                and type(trail) is native.CorrectionNativeTaskEvidence
                and trail.ready_bytes is not None
                and trail.terminal_bytes is not None
                and trail.actual_returncode is not None
            )
            snapshot, previous = native._cleanup_load(
                connection, context, clock, trail
            )
            proof = native._cleanup_validate(
                context, closure._receipt, closure._packet, clock, trail
            )
            lineage = closure.document()
            managed_evidence.validate_native_closure_lineage(
                lineage,
                task_id=context.task_id,
                transport_request_hash=context.transport_hash,
                claim_digest=context.claim_digest,
                packet_digest=proof["packet_digest"],
                ready_digest=content_hash(
                    wire._document(cast(bytes, trail.ready_bytes), wire.READY_MAX)
                ),
                terminal_digest=content_hash(
                    wire._document(cast(bytes, trail.terminal_bytes), wire.TERMINAL_MAX)
                ),
                actual_returncode=trail.actual_returncode,
                cleanup_receipt_digest=content_hash(proof),
                consume_receipt=cast(dict, consume),
            )
            document = {
                "schema_version": native._CLEANUP_SCHEMA,
                "protocol": context.protocol.value,
                "task_id": task_id,
                "transport_request_hash": transport_request_hash,
                "claim_digest": context.claim_digest,
                "packet_digest": proof["packet_digest"],
                "receipt_utf8": closure._receipt.decode("utf-8", "strict"),
                "private_packet_utf8": native._payload(closure._packet, "packet"),
                "managed_lineage_utf8": canonical_json(lineage),
            }
            if previous is not None:
                native._require(previous == document)
                return snapshot
            serialized = canonical_json(document)
            native._text_bytes(serialized, native._ROW_MAX)
            connection.execute(
                "INSERT INTO file_access_owned_process_closures VALUES(?,?,?)",
                (task_id, serialized, content_hash(document)),
            )
            return native._cleanup_load(connection, context, clock, trail)[0]
    except native._FAILURES:
        raise ProductStoreError(native._ERROR) from None
