"""Closed metadata-only runtime facts; never an exemption from provider redaction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .evidence import EvidenceProvenance
from .file_permissions import PERMISSION_FIELDS, permission_fields_valid
from .util import canonical_json_bytes

COUNT_FACTS = frozenset(
    {
        "record_count",
        "retained_record_count",
        "redacted_record_count",
        "empty_record_count",
        "size_bytes",
        "process_count",
        "file_count",
        "entry_count",
        "reported_size_bytes",
    }
)
ENUM_FACTS = {
    "container": {"jsonl", "gzip", "ustar", "tar"},
    "artifact_type": {"file_observation", "collector_observation", "evidence_gap"},
    "observation_kind": {"filesystem", "collection_semantics", "process"},
}


@dataclass(frozen=True, slots=True)
class RuntimeObservationSummary:
    """Immutable, validated serialization of at most 16 x 32 metadata records.

    This supplies only the finite facts already projected by the runtime. The
    original persisted evidence projection and its redaction policy stay intact.
    Hashes and generated record references identify evidence without its body.
    """

    encoded: str

    def __post_init__(self) -> None:
        if not isinstance(self.encoded, str) or len(self.encoded.encode("utf-8")) > 524_288:
            raise ValueError("runtime observation summary exceeds its byte bound")
        value = json.loads(self.encoded)
        if not isinstance(value, list) or len(value) > 512:
            raise ValueError("runtime observation summary exceeds its record bound")
        for row in value:
            if not isinstance(row, dict) or set(row) != {
                "attempt_index",
                "record_id",
                "record_hash",
                "provenance",
                "facts",
            }:
                raise ValueError("runtime observation summary has invalid fields")
            if type(row["attempt_index"]) is not int or not 0 <= row["attempt_index"] <= 2**53:
                raise ValueError("runtime observation attempt index is invalid")
            if not isinstance(row["record_id"], str) or not re.fullmatch(
                r"evidence-[0-9a-f]{20}", row["record_id"]
            ):
                raise ValueError("runtime observation reference is invalid")
            if not isinstance(row["record_hash"], str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", row["record_hash"]
            ):
                raise ValueError("runtime observation hash is invalid")
            provenance = EvidenceProvenance(row["provenance"])
            facts = row["facts"]
            if not isinstance(facts, dict) or set(facts) - (
                COUNT_FACTS | set(ENUM_FACTS) | set(PERMISSION_FIELDS)
            ):
                raise ValueError("runtime observation facts are outside the allowlist")
            for key, field in facts.items():
                if key in COUNT_FACTS and (type(field) is not int or not 0 <= field <= 2**53):
                    raise ValueError("runtime observation count is invalid")
                if key in ENUM_FACTS and (
                    not isinstance(field, str) or field not in ENUM_FACTS[key]
                ):
                    raise ValueError("runtime observation enum is invalid")
            permissions = {key: facts[key] for key in PERMISSION_FIELDS if key in facts}
            if permissions and (
                provenance is not EvidenceProvenance.OBSERVED
                or not (
                    facts.get("artifact_type") == "file_observation"
                    or (
                        facts.get("artifact_type") == "collector_observation"
                        and facts.get("observation_kind") == "filesystem"
                    )
                )
                or not (
                    permission_fields_valid(permissions)
                    or permissions
                    == {
                        "permission_status": "invalid_metadata",
                        "effective_access": "not_evaluated",
                    }
                )
            ):
                raise ValueError("runtime observation permissions are not verified metadata")
        if len(canonical_json_bytes(value)) > 524_288:
            raise ValueError("runtime observation summary exceeds its byte bound")

    @classmethod
    def from_projection(cls, projection: Mapping[str, Any]) -> RuntimeObservationSummary:
        return cls(
            canonical_json_bytes(
                [
                    {
                        "attempt_index": attempt["attempt_index"],
                        "record_id": record["evidence_id"],
                        "record_hash": record["record_hash"],
                        "provenance": record["provenance"],
                        "facts": record["facts"],
                    }
                    for attempt in projection["attempts"]
                    for record in attempt["evidence"]
                ]
            ).decode("utf-8")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.runtime-observation-summary.v1",
            "records": json.loads(self.encoded),
        }
