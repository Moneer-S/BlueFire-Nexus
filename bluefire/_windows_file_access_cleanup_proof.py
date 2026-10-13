"""Immutable owned-process closure evidence, never native read or task authority.

Only the trusted Python supervisor constructs this exact type. This is not a
cryptographic boundary against arbitrary in-process code. Historical packet
bytes remain private and require independent original-claim validation by a
consumer; neither their digest nor positive closure authorizes another read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import _windows_file_access_native_contract as contract
from .util import canonical_json_bytes, content_hash

SCHEMA = "bluefire.windows-file-owned-cleanup.v1"
MAX_RECEIPT_BYTES = 4096
_FIELDS = (
    "schema_version provenance protocol task_id transport_request_hash packet_digest "
    "original_requested_at original_expires_at observed_at child_generation_captured "
    "begin_attempted supported_terminal_returncode cleanup settled"
)


@dataclass(frozen=True, slots=True, init=False)
class OwnedCleanupReceipt:
    """Positive physical closure only; no credential, execution or settlement."""

    _raw: bytes = field(repr=False)
    _packet: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Owned cleanup receipts require the trusted process supervisor")

    def document(self) -> dict[str, Any]:
        contract._require(type(self) is OwnedCleanupReceipt)
        return validate_retained_cleanup(self._raw, self._packet)


def validate_retained_cleanup(receipt_bytes: bytes, packet_bytes: bytes) -> dict[str, Any]:
    """Check historical byte consistency only; never construct a producer receipt."""
    contract._require(type(receipt_bytes) is bytes and type(packet_bytes) is bytes)
    row = contract._exact(contract._document(receipt_bytes, MAX_RECEIPT_BYTES), _FIELDS)
    contract._require(canonical_json_bytes(row) == receipt_bytes)
    contract._require(
        row["schema_version"] == SCHEMA
        and row["provenance"] == "runner_owned_cleanup"
        and row["protocol"] in ("reader_v1", "pair_v2")
        and row["cleanup"] == "verified"
        and row["settled"] is False
    )
    for name in ("child_generation_captured", "begin_attempted"):
        contract._require(type(row[name]) is bool)
    contract._require(not row["begin_attempted"] or row["child_generation_captured"])
    code = row["supported_terminal_returncode"]
    contract._require(code is None or (type(code) is int and code in (0, 4)))
    contract._digest(row["transport_request_hash"])
    contract._digest(row["packet_digest"])
    contract._require(row["task_id"] == "execute-" + row["transport_request_hash"][7:])
    requested = contract._time(row["original_requested_at"])
    contract._require(requested < contract._time(row["original_expires_at"]))
    contract._require(contract._time(row["observed_at"], canonical=True) >= requested)
    packet = contract._exact(
        contract._document(packet_bytes),
        "schema_version challenge task_id request_hash manifest profile remaining_ms",
    )
    protocol = contract._PAIR if row["protocol"] == "pair_v2" else contract._V1
    contract._require(
        packet["schema_version"] == protocol.schema("request")
        and packet["task_id"] == row["task_id"]
        and packet["request_hash"] == row["transport_request_hash"]
        and content_hash(packet) == row["packet_digest"]
        and type(packet["manifest"]) is dict
        and packet["manifest"].get("requested_at") == row["original_requested_at"]
        and packet["manifest"].get("expires_at") == row["original_expires_at"]
    )
    return row
