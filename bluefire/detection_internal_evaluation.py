"""Bounded structured matching of a complete independently observed dataset."""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Sequence

from .detections import DetectionCandidate, DetectionError, DetectionPipeline
from .evidence import EvidenceProvenance, EvidenceRecord
from .file_permissions import PERMISSION_FIELDS, permission_fields_valid
from .structured_matcher import invalid_selection_field, lookup, matches_value
from .util import canonical_json_bytes

INTERNAL_LIMITS = {
    "records": 10_000,
    "record_bytes": 16 * 1024 * 1024,
    "field_comparisons": 640_000,
    "comparison_bytes": 64 * 1024 * 1024,
    "value_bytes": 64 * 1024,
    "json_nodes": 100_000,
    "json_depth": 16,
    "deadline_ms": 2_000,
}


def validate_internal_candidate(candidate: DetectionCandidate) -> None:
    if (
        candidate.target_language != "internal"
        or candidate.parser_backend
        != {"name": DetectionPipeline.parser_name, "version": DetectionPipeline.parser_version}
        or not candidate.selection
        or invalid_selection_field(candidate.selection) is not None
    ):
        raise DetectionError("the structured selection or parser identity is invalid")


def execute_internal(
    candidate: DetectionCandidate,
    records: Sequence[EvidenceRecord],
    *,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Return one complete result or refuse; never return a partial match count."""
    validate_internal_candidate(candidate)
    deadline = time.monotonic() + INTERNAL_LIMITS["deadline_ms"] / 1000

    def checkpoint() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise DetectionError("structured evaluation cancelled")
        if time.monotonic() >= deadline:
            raise DetectionError("structured evaluation deadline exceeded")

    checkpoint()
    if len(records) > INTERNAL_LIMITS["records"]:
        raise DetectionError("structured evaluation record limit exceeded")
    encoded_bytes = 0
    comparisons = 0
    comparison_bytes = 0
    json_nodes = 0

    def validate_json(value: Any) -> bytes:
        nonlocal json_nodes
        pending = [(value, 0)]
        while pending:
            checkpoint()
            item, depth = pending.pop()
            json_nodes += 1
            if depth > INTERNAL_LIMITS["json_depth"] or json_nodes > INTERNAL_LIMITS["json_nodes"]:
                raise DetectionError("structured evaluation JSON work limit exceeded")
            if isinstance(item, dict):
                if len(item) + len(pending) > INTERNAL_LIMITS["json_nodes"] - json_nodes:
                    raise DetectionError("structured evaluation JSON work limit exceeded")
                if any(not isinstance(key, str) for key in item):
                    raise DetectionError("structured evaluation object key is invalid")
                pending.extend((entry, depth + 1) for entry in item.values())
            elif isinstance(item, list):
                if len(item) + len(pending) > INTERNAL_LIMITS["json_nodes"] - json_nodes:
                    raise DetectionError("structured evaluation JSON work limit exceeded")
                pending.extend((entry, depth + 1) for entry in item)
            elif item is not None and type(item) not in {str, bool, int, float}:
                raise DetectionError("structured evaluation value is invalid")
            elif type(item) is float and not math.isfinite(item):
                raise DetectionError("structured evaluation number is invalid")
        return canonical_json_bytes(value)

    validate_json(dict(candidate.selection))
    permission_keys = set(PERMISSION_FIELDS).intersection(
        key.partition("|")[0] for key in candidate.selection
    )
    requires_available = False
    for raw_key, expected in candidate.selection.items():
        key, _, operator = raw_key.partition("|")
        if key != "permission_status":
            continue
        checkpoint()
        comparisons += 1
        value_bytes = len(canonical_json_bytes("available")) + len(canonical_json_bytes(expected))
        comparison_bytes += value_bytes
        if (
            comparisons > INTERNAL_LIMITS["field_comparisons"]
            or value_bytes > INTERNAL_LIMITS["value_bytes"]
            or comparison_bytes > INTERNAL_LIMITS["comparison_bytes"]
        ):
            raise DetectionError("structured evaluation permission selector limit exceeded")
        # Use the same parsed field/operator semantics as matching. A substring
        # accepting available must not turn unavailable_windows into a match.
        requires_available |= matches_value("available", expected, operator, strict=True)
        checkpoint()
    available: set[str] = set()
    missing: set[str] = set()
    matched: list[str] = []
    for record in records:
        checkpoint()
        if record.provenance is not EvidenceProvenance.OBSERVED:
            raise DetectionError("structured evaluation requires independently observed evidence")
        if record.confidence != 1.0:
            raise DetectionError("structured evaluation requires conclusive observations")
        encoded_bytes += len(validate_json(dict(record.content)))
        if encoded_bytes > INTERNAL_LIMITS["record_bytes"]:
            raise DetectionError("structured evaluation byte limit exceeded")
        # Known record-kind disagreement excludes unrelated observations before
        # interpreting permission availability on the intended filesystem rows.
        if any(
            key in candidate.selection
            and key in record.content
            and not matches_value(record.content[key], candidate.selection[key], "", strict=True)
            for key in ("artifact_type", "observation_kind")
        ):
            continue
        if permission_keys:
            permissions = {
                key: record.content[key] for key in PERMISSION_FIELDS if key in record.content
            }
            if not permissions:
                missing.update(permission_keys)
                continue
            status = permissions.get("permission_status")
            if status == "available" and set(permissions) != set(PERMISSION_FIELDS):
                missing.update(set(PERMISSION_FIELDS) - set(permissions))
                continue
            if not permission_fields_valid(permissions):
                raise DetectionError("structured evaluation permission facts are invalid")
            if status != "available" and (
                requires_available or permission_keys - {"permission_status", "effective_access"}
            ):
                missing.update(permission_keys - {"effective_access"})
                continue
        record_missing: set[str] = set()
        mismatch = False
        for raw_key, expected in candidate.selection.items():
            checkpoint()
            comparisons += 1
            if comparisons > INTERNAL_LIMITS["field_comparisons"]:
                raise DetectionError("structured evaluation comparison limit exceeded")
            key, _, operator = raw_key.partition("|")
            present, actual = lookup(record.content, key)
            if not present:
                record_missing.add(key)
            else:
                available.add(key)
                if type(expected) is bool and type(actual) is not bool:
                    raise DetectionError("structured evaluation boolean field is invalid")
                value_bytes = len(canonical_json_bytes(actual)) + len(
                    canonical_json_bytes(expected)
                )
                comparison_bytes += value_bytes
                if (
                    value_bytes > INTERNAL_LIMITS["value_bytes"]
                    or comparison_bytes > INTERNAL_LIMITS["comparison_bytes"]
                ):
                    raise DetectionError("structured evaluation comparison byte limit exceeded")
                if not matches_value(actual, expected, operator, strict=True):
                    mismatch = True
        # Conjunction is certainly false if any known field disagrees. Otherwise
        # absent fields leave this record undecidable, even if other records match.
        if not mismatch:
            missing.update(record_missing)
            if not record_missing:
                matched.append(record.evidence_id)
    checkpoint()
    return {
        "evaluated_evidence_ids": [record.evidence_id for record in records],
        "matched_evidence_ids": matched if not missing else [],
        "mapped_fields": sorted({key.partition("|")[0] for key in candidate.selection}),
        "available_fields": sorted(available),
        "missing_fields": sorted(missing),
    }
