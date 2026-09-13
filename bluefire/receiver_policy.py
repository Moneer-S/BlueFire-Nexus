"""Fixed lab receiver policies over authenticated, digest-verified public bytes."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

from .collection_semantics import MAX_COLLECTION_BYTES, parse_collection_semantics
from .evidence import EvidenceError
from .util import content_hash

REVIEWED_RECORDS_POLICY = "receiver.reviewed-records.v1"
REDACTED_ONLY_POLICY = "receiver.redacted-only.v1"
POLICY_IDS = (REVIEWED_RECORDS_POLICY, REDACTED_ONLY_POLICY)


@dataclass(frozen=True)
class ReceiverContentPolicy:
    """A named, immutable implementation, never an operator-supplied predicate."""

    policy_id: str

    def __post_init__(self) -> None:
        if self.policy_id not in POLICY_IDS:
            raise ValueError("receiver content policy is unavailable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.receiver-content-policy.v1",
            "policy_id": self.policy_id,
            "authentication": "managed_task_hmac_sha256",
            "schema": "strict_public_synthetic_jsonl",
            "maximum_bytes": MAX_COLLECTION_BYTES,
            "maximum_records": 100,
            "accepted_records": (
                "reviewed_public_values"
                if self.policy_id == REVIEWED_RECORDS_POLICY
                else "every_record_explicitly_redacted"
            ),
        }

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def inspect(self, payload: bytes) -> Mapping[str, Any]:
        """Inspect bytes only; the caller establishes authentication separately."""
        identity: dict[str, Any] = {
            "policy_id": self.policy_id,
            "policy_digest": self.digest,
            "sha256": sha256(payload).hexdigest(),
            "bytes_received": len(payload),
        }
        try:
            # The peer action's reviewed JSONL is supported. USTAR and JSON
            # wrapper containers are deliberately outside this policy version.
            if payload[:1] != b"{":
                raise EvidenceError("unsupported receiver content")
            counts = parse_collection_semantics(payload)
            if counts["container"] != "jsonl":
                raise EvidenceError("unsupported receiver content")
        except EvidenceError:
            return {
                **identity,
                "decision": "invalid_content",
                "reason": "malformed_unsupported_or_incomplete",
                "semantics": None,
            }
        accepted = self.policy_id == REVIEWED_RECORDS_POLICY or (
            counts["redacted_record_count"] == counts["record_count"]
        )
        return {
            **identity,
            "decision": "accepted" if accepted else "policy_refused",
            "reason": "reviewed_content" if accepted else "records_not_all_redacted",
            "semantics": counts,
        }
