"""Pure retained generated-artifact contracts; no jobs, storage or execution authority."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .capability_packs import RECEIVER_RETAINED_PACK, RETAINED_MATERIALIZE_METHOD
from .capability_resources import (
    MAX_RETAINED_ARTIFACT_BYTES,
    CapabilityContractError,
    exact,
    identifier,
    integer,
)
from .util import content_hash, json_clone

PACK = RECEIVER_RETAINED_PACK
METHOD = RETAINED_MATERIALIZE_METHOD
MAX_BYTES = MAX_RETAINED_ARTIFACT_BYTES
HEX_CHUNK_CHARS = 16 * 1024
MAX_CHUNKS = 32
MAX_ENVELOPE_BYTES = 8192
POLICY = {
    "max_artifacts_per_attempt": 1,
    "max_bytes_per_artifact": MAX_BYTES,
    "max_bytes_per_attempt": MAX_BYTES,
    "data_class": "generated_public_jsonl",
    "producer": "sandbox.collection.stage.v1",
    "output": "bundle",
    "disposition": "sealed_until_run_bundle_deleted",
    "materialization_payload_disposition": "retained_in_existing_task_and_transport_stores_until_those_stores_are_deleted",
    "materialization_payload_copy_reservation": 2,
    "materialization_wire": {
        "encoding": "canonical_hex_chunks",
        "max_chunks": MAX_CHUNKS,
        "max_chunk_chars": HEX_CHUNK_CHARS,
        "max_encoded_chars": 2 * MAX_BYTES,
    },
    "workspace_cleanup": "owned_receipts_only",
    "payload_storage": "fixed_private_child_of_source_run",
    "payload_export": "excluded_metadata_only",
}
FIELDS = {
    "run_id",
    "attempt_id",
    "lineage_id",
    "step_id",
    "artifact",
    "artifact_type",
    "sha256",
    "size_bytes",
}


def source_reference(value: Any) -> dict[str, Any]:
    row = exact(value, FIELDS | {"source_ref"}, "retained artifact source")
    for key in ("run_id", "attempt_id", "lineage_id", "step_id"):
        identifier(row[key], "retained " + key)
    if (
        not re.fullmatch(r"run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}", row["run_id"])
        or not re.fullmatch(r"attempt-[0-9a-f]{32}", row["attempt_id"])
        or row["artifact"] != "bundle"
        or row["artifact_type"] != "artifact.sandbox.bundle.v1"
        or not isinstance(row["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
    ):
        raise CapabilityContractError("retained source is outside the reviewed JSONL contract")
    integer(row["size_bytes"], 1, MAX_BYTES, "retained bytes")
    if row["source_ref"] != content_hash({key: row[key] for key in FIELDS}):
        raise CapabilityContractError("retained source reference changed")
    return dict(json_clone(row))


def validate_bytes(payload: bytes, reference: Mapping[str, Any]) -> None:
    if (
        not isinstance(payload, bytes)
        or len(payload) != reference["size_bytes"]
        or hashlib.sha256(payload).hexdigest() != reference["sha256"]
    ):
        raise CapabilityContractError("retained bytes do not match the exact source")
    # The same closed synthetic-record semantics used by the native receiver.
    from .collection_semantics import parse_collection_semantics

    analysis = parse_collection_semantics(payload)
    if analysis.get("container") != "jsonl":
        raise CapabilityContractError("retained bytes are not generated public JSONL")


def validate_envelope(document):
    if (
        set(document) != {"schema_version", "policy", "artifacts"}
        or document["schema_version"] != "bluefire.retained-artifacts.v1"
        or document["policy"] != POLICY
        or not isinstance(document["artifacts"], list)
        or len(document["artifacts"]) != 1
    ):
        raise CapabilityContractError("retained artifact metadata envelope changed")
    entry = document["artifacts"][0]
    if set(entry) != {
        "source",
        "producer_evidence_id",
        "observation_evidence_id",
        "producer_receipt_ids",
        "payload",
    }:
        raise CapabilityContractError("retained artifact metadata has invalid fields")
    reference = source_reference(entry["source"])
    identifier(entry["producer_evidence_id"], "producer evidence reference")
    identifier(entry["observation_evidence_id"], "observation evidence reference")
    if (
        not isinstance(entry["producer_receipt_ids"], list)
        or len(entry["producer_receipt_ids"]) != 1
        or not isinstance(entry["producer_receipt_ids"][0], str)
        or re.fullmatch(r"[0-9a-f]{64}", entry["producer_receipt_ids"][0]) is None
    ):
        raise CapabilityContractError("retained producer receipt identity changed")
    if entry["payload"] != {
        "path": "retained/bundle.jsonl",
        "sha256": reference["sha256"],
        "size_bytes": reference["size_bytes"],
        "export": "excluded",
    }:
        raise CapabilityContractError("retained payload descriptor changed")
    return entry


def wire_chunks(payload: bytes) -> list[str]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_BYTES:
        raise CapabilityContractError("materialization payload exceeds its reviewed byte bound")
    encoded = payload.hex()
    return [
        encoded[index : index + HEX_CHUNK_CHARS]
        for index in range(0, len(encoded), HEX_CHUNK_CHARS)
    ]
