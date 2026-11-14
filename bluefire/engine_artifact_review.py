"""On-demand local review of one saved, protected engine artifact.

Private source bodies stay in the artifact store. The response contains only
bounded structural facts unless the saved proof explicitly marks a text item
reviewable. Every read reopens the complete protected publication and compares
its current index with the exact saved attempt index.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .engine_artifact_store import EngineArtifactStore, EngineArtifactStoreError
from .engine_execution_proof_writer import (
    EngineExecutionProofWriterError,
    controller_artifact_index_from_reopened,
)
from .engine_experiment import EngineAttemptEntry

_OUTLINE_BYTE_LIMIT = 64 * 1024
_TEXT_PREVIEW_BYTE_LIMIT = 8 * 1024
_RECOGNIZED_FIELDS = frozenset(
    {"findings", "issues", "vulnerabilities", "observations", "events", "steps",
     "results", "summary", "conclusion", "status"}
)
_TEXT_MEDIA = frozenset(
    {"application/json", "application/x-ndjson", "text/markdown", "text/plain"}
)


def _outline(payload: bytes, media_type: str) -> tuple[dict[str, Any], str | None]:
    """Return finite structural facts without copying private source words."""
    if len(payload) > _OUTLINE_BYTE_LIMIT:
        return {"kind": "large", "line_count": None, "root": None,
                "field_count": None, "recognized_fields": [], "item_count": None}, None
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {"kind": "binary", "line_count": None, "root": None,
                "field_count": None, "recognized_fields": [], "item_count": None}, None
    if any(ord(character) < 32 and character not in "\n\r\t" for character in decoded):
        return {"kind": "binary", "line_count": None, "root": None,
                "field_count": None, "recognized_fields": [], "item_count": None}, None
    lines = len(decoded.splitlines())
    kind = "text"
    root: str | None = None
    field_count: int | None = None
    item_count: int | None = None
    recognized: list[str] = []
    if media_type == "application/json":
        try:
            value = json.loads(decoded)
        except (ValueError, RecursionError):
            kind = "invalid_json"
        else:
            kind = "json"
            root = "object" if isinstance(value, dict) else "array" if isinstance(value, list) else "scalar"
            if isinstance(value, dict):
                field_count = len(value)
                recognized = sorted(_RECOGNIZED_FIELDS.intersection(value))
            elif isinstance(value, list):
                item_count = len(value)
    elif media_type == "application/x-ndjson":
        kind = "jsonl"
        item_count = sum(bool(line.strip()) for line in decoded.splitlines())
    return {"kind": kind, "line_count": lines, "root": root,
            "field_count": field_count, "recognized_fields": recognized,
            "item_count": item_count}, decoded


def review_retained_engine_artifact(
    store: EngineArtifactStore | None,
    *,
    experiment_id: str,
    entry: EngineAttemptEntry,
    saved_artifacts: Sequence[Mapping[str, Any]],
    selected_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Inspect only the selected saved row through its exact retained owner."""
    binding = entry.record.binding
    base: dict[str, Any] = {
        "schema_version": "bluefire.engine-artifact-review.v1",
        "experiment_id": experiment_id,
        "attempt_id": binding.attempt_id,
        "artifact_id": selected_artifact["artifact_id"],
        "manifest_ref": entry.artifact_manifest_ref,
        "sha256": selected_artifact["sha256"],
        "bytes": selected_artifact["bytes"],
        "access": selected_artifact["access"],
    }

    def unavailable(reason: str) -> dict[str, Any]:
        return {**base, "availability": "unavailable", "reason": reason,
                "summary": None, "text": None}

    if store is None:
        return unavailable("reader_not_configured")
    if type(store) is not EngineArtifactStore:
        return unavailable("reader_not_configured")
    try:
        reopened = store.reopen_attempt(binding.attempt_id)
        publication = reopened.publication_binding
        if (
            publication is None
            or publication.attempt_id != binding.attempt_id
            or publication.binding_digest != binding.binding_digest
            or publication.delegation_digest != entry.delegation_digest
            or reopened.manifest_ref != entry.artifact_manifest_ref
        ):
            return unavailable("retained_source_changed")
        index = controller_artifact_index_from_reopened(
            reopened,
            publication_binding=publication,
            artifact_byte_limit=binding.artifact_byte_limit,
        )
        rows = [item.to_dict() for item in index.artifacts]
        if rows != list(saved_artifacts) or index.manifest_ref != entry.artifact_manifest_ref:
            return unavailable("retained_source_changed")
        selected_index = next(
            number for number, row in enumerate(rows)
            if row["artifact_id"] == selected_artifact["artifact_id"]
        )
        if rows[selected_index] != dict(selected_artifact):
            return unavailable("retained_source_changed")
        retained = reopened.artifacts[selected_index]
        summary, decoded = _outline(retained.payload, selected_artifact["media_type"])
        # Only an explicitly reviewable saved proof can release bounded text.
        text = (
            decoded if selected_artifact["access"] == "reviewable"
            and selected_artifact["media_type"] in _TEXT_MEDIA
            and retained.size_bytes <= _TEXT_PREVIEW_BYTE_LIMIT
            else None
        )
        return {**base, "availability": "retained", "reason": None,
                "summary": summary, "text": text}
    except (EngineArtifactStoreError, EngineExecutionProofWriterError, StopIteration):
        return unavailable("retained_source_changed")
