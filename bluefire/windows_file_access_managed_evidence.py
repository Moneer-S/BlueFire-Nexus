"""Exact durable handoff contracts for one managed Windows correction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import windows_file_access_native_wire as wire
from ._windows_file_access_cleanup_proof import validate_retained_cleanup
from .util import canonical_json_bytes, content_hash

READY_CONSUME_SCHEMA = "bluefire.windows-file-managed-ready-consume.v1"
READY_CONSUME_STAGE = "managed_ready_consume"
READY_CONSUME_MAX = 4096
READY_CONSUME_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "task_id",
        "transport_request_hash",
        "claim_digest",
        "session_nonce",
        "packet_digest",
        "ready_digest",
        "ack_nonce",
        "ready_evidence_digest",
    }
)
MANAGED_CORRECTION_LINEAGE_SCHEMA = (
    "bluefire.windows-file-authenticated-managed-correction-closure.v1"
)
MANAGED_CORRECTION_LINEAGE_MAX = 4096
MANAGED_CORRECTION_LINEAGE_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "task_id",
        "transport_request_hash",
        "claim_digest",
        "packet_digest",
        "ready_digest",
        "terminal_digest",
        "actual_returncode",
        "receipt_digest",
        "session_nonce",
        "ack_nonce",
        "consume_receipt_digest",
    }
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_32 = re.compile(r"^[0-9a-f]{64}$")


class ManagedCorrectionEvidenceError(ValueError):
    """Path- and secret-free refusal for a managed correction handoff."""


def _require(valid: bool) -> None:
    if not valid:
        raise ManagedCorrectionEvidenceError(
            "Managed Windows correction evidence is invalid."
        )


@dataclass(frozen=True, slots=True, init=False)
class PersistedManagedCorrectionReady:
    """Exact in-process proof that the original store committed this Ready."""

    _raw: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Managed correction Ready receipts require the original store")

    def document(self) -> dict[str, Any]:
        _require(type(self) is PersistedManagedCorrectionReady)
        _require(type(self._raw) is bytes and 0 < len(self._raw) <= READY_CONSUME_MAX)
        row = wire._document(self._raw, READY_CONSUME_MAX)
        _require(canonical_json_bytes(row) == self._raw)
        _require(
            set(row) == READY_CONSUME_FIELDS
            and row["schema_version"] == READY_CONSUME_SCHEMA
            and row["protocol"] == "correction_v3"
            and _DIGEST.fullmatch(str(row.get("transport_request_hash"))) is not None
            and row["task_id"] == "execute-" + row["transport_request_hash"][7:]
        )
        for name in (
            "claim_digest",
            "packet_digest",
            "ready_digest",
            "ready_evidence_digest",
        ):
            _require(_DIGEST.fullmatch(str(row.get(name))) is not None)
        _require(
            _HEX_32.fullmatch(str(row.get("session_nonce"))) is not None
            and _HEX_32.fullmatch(str(row.get("ack_nonce"))) is not None
        )
        return row


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedManagedCorrectionClosure:
    """Exact in-process handoff from authenticated result to durable cleanup."""

    _receipt: bytes = field(repr=False)
    _packet: bytes = field(repr=False)
    _lineage: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Managed correction closures require an authenticated transport adapter")

    def document(self) -> dict[str, Any]:
        _require(type(self) is AuthenticatedManagedCorrectionClosure)
        _require(
            type(self._receipt) is bytes
            and type(self._packet) is bytes
            and type(self._lineage) is bytes
            and 0 < len(self._lineage) <= MANAGED_CORRECTION_LINEAGE_MAX
        )
        proof = validate_retained_cleanup(self._receipt, self._packet)
        _require(proof["protocol"] == "correction_v3")
        lineage = wire._document(self._lineage, MANAGED_CORRECTION_LINEAGE_MAX)
        _require(canonical_json_bytes(lineage) == self._lineage)
        _require(
            set(lineage) == MANAGED_CORRECTION_LINEAGE_FIELDS
            and lineage["schema_version"] == MANAGED_CORRECTION_LINEAGE_SCHEMA
            and lineage["protocol"] == "correction_v3"
            and lineage["task_id"] == proof["task_id"]
            and lineage["transport_request_hash"] == proof["transport_request_hash"]
            and lineage["packet_digest"] == proof["packet_digest"]
            and lineage["receipt_digest"] == content_hash(proof)
        )
        for name in (
            "claim_digest",
            "ready_digest",
            "terminal_digest",
            "consume_receipt_digest",
        ):
            _require(_DIGEST.fullmatch(str(lineage.get(name))) is not None)
        _require(
            _HEX_32.fullmatch(str(lineage.get("session_nonce"))) is not None
            and _HEX_32.fullmatch(str(lineage.get("ack_nonce"))) is not None
            and type(lineage.get("actual_returncode")) is int
            and lineage["actual_returncode"] in (0, 4)
        )
        return lineage


def validate_native_closure_lineage(
    lineage: Mapping[str, Any],
    *,
    task_id: str,
    transport_request_hash: str,
    claim_digest: str,
    packet_digest: str,
    ready_digest: str,
    terminal_digest: str,
    actual_returncode: int,
    cleanup_receipt_digest: str,
    consume_receipt: Mapping[str, Any],
) -> None:
    """Bind a stored managed cleanup row to its exact retained public trail."""

    expected = {
        "schema_version": MANAGED_CORRECTION_LINEAGE_SCHEMA,
        "protocol": "correction_v3",
        "task_id": task_id,
        "transport_request_hash": transport_request_hash,
        "claim_digest": claim_digest,
        "packet_digest": packet_digest,
        "ready_digest": ready_digest,
        "terminal_digest": terminal_digest,
        "actual_returncode": actual_returncode,
        "receipt_digest": cleanup_receipt_digest,
        "session_nonce": consume_receipt["session_nonce"],
        "ack_nonce": consume_receipt["ack_nonce"],
        "consume_receipt_digest": content_hash(dict(consume_receipt)),
    }
    _require(dict(lineage) == expected)
