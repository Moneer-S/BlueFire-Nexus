"""Canonical filesystem-observation validation for Gate 11 run proof."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping

from .collectors import CollectorError, filesystem_observation_key
from .evidence import EvidenceProvenance, EvidenceRecord

_RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT = re.compile(r"^[0-9a-f]{64}$")
_COLLECTOR_ID = "collector.filesystem.sandbox.v1"
_COLLECTOR_VERSION = "1.0.0"
_PERSISTENCE_ACTION = "sandbox.restricted.persistence-marker.v1"
_CONTENT_FIELDS = {
    "artifact_type",
    "collector_id",
    "mechanism",
    "modified_ns",
    "observation_key",
    "observation_kind",
    "observed_fields",
    "path",
    "sha256",
    "size_bytes",
}
_MISSING = object()


class CrossPlatformObservationValidationError(ValueError):
    """Raised when a persisted filesystem observation is not canonical or bound."""


def _is_utc(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").tzinfo == timezone.utc
    except ValueError:
        return False


def _require(condition: object, message: str) -> None:
    if not condition:
        raise CrossPlatformObservationValidationError(message)


def validate_observed_filesystem_evidence(
    record: EvidenceRecord,
    outer: EvidenceRecord,
    step: Mapping[str, Any],
) -> None:
    """Bind a FilesystemCollector record to one receipt-owning runner artifact."""

    content = record.content
    _require(
        isinstance(content, Mapping) and set(content) == _CONTENT_FIELDS,
        "observed filesystem evidence fields are invalid",
    )
    output = outer.content.get("output")
    path = content.get("path")
    logical = PurePosixPath(path) if isinstance(path, str) else None
    try:
        observation_key = filesystem_observation_key(path) if isinstance(path, str) else None
    except CollectorError:
        observation_key = None
    digest = content.get("sha256")
    size = content.get("size_bytes")
    output_digest = output.get("sha256") if isinstance(output, Mapping) else None
    normalized_output_digest = (
        output_digest.removeprefix("sha256:") if isinstance(output_digest, str) else None
    )
    output_size = output.get("size", _MISSING) if isinstance(output, Mapping) else _MISSING
    observed_fields = content.get("observed_fields")
    receipts = step.get("receipts")
    nested = outer.content.get("runner_evidence")
    nested_details = (
        nested[0].get("details")
        if isinstance(nested, list) and len(nested) == 1 and isinstance(nested[0], Mapping)
        else None
    )
    nested_receipts = (
        nested_details.get("receipt_ids") if isinstance(nested_details, Mapping) else None
    )
    is_persistence = record.action_id == _PERSISTENCE_ACTION
    output_binding_matches = (
        output_digest == f"sha256:{digest}" and output_size is _MISSING
        if is_persistence
        else output_digest == digest and type(output_size) is int and output_size == size
    )
    _require(
        record.provenance is EvidenceProvenance.OBSERVED
        and outer.provenance is EvidenceProvenance.EXECUTED
        and outer.producer == "bluefire-rust-runner"
        and record.producer == _COLLECTOR_ID
        and record.run_id == outer.run_id
        and record.step_id == outer.step_id == step.get("step_id")
        and record.behavior_id == outer.behavior_id == step.get("behavior_id")
        and record.action_id == outer.action_id == step.get("action_id")
        and record.runner_profile_id == outer.runner_profile_id
        and record.environment
        == {
            "environment_type": "disposable",
            "collector_id": _COLLECTOR_ID,
            "collector_version": _COLLECTOR_VERSION,
        }
        and record.parent_evidence_ids == (outer.evidence_id,)
        and step.get("evidence_ids") == [outer.evidence_id, record.evidence_id]
        and record.confidence == 1.0
        and record.limitations == ("independent filesystem metadata and digest observation only",)
        and record.target_scope_ref == outer.target_scope_ref
        and _is_utc(record.timestamp)
        and content.get("artifact_type") == "collector_observation"
        and content.get("collector_id") == _COLLECTOR_ID
        and content.get("mechanism") == "independent-file-handle-read"
        and content.get("observation_kind") == "filesystem"
        and content.get("observation_key") == observation_key
        and isinstance(path, str)
        and bool(path)
        and "\x00" not in path
        and "\\" not in path
        and logical is not None
        and path == logical.as_posix()
        and not logical.is_absolute()
        and all(part not in {"", ".", ".."} for part in logical.parts)
        and isinstance(output, Mapping)
        and path == output.get("artifact")
        and isinstance(digest, str)
        and _RAW_SHA256.fullmatch(digest) is not None
        and normalized_output_digest == digest
        and type(size) is int
        and size > 0
        and output_binding_matches
        and type(content.get("modified_ns")) is int
        and content["modified_ns"] > 0
        and observed_fields == {"path": path, "sha256": digest, "size_bytes": size}
        and isinstance(receipts, list)
        and len(receipts) == 1
        and all(isinstance(item, str) and _RECEIPT.fullmatch(item) for item in receipts)
        and nested_receipts == receipts,
        "observed evidence is not bound to a receipt-owning runner artifact",
    )


__all__ = [
    "CrossPlatformObservationValidationError",
    "validate_observed_filesystem_evidence",
]
