"""Controller-only source checks for installed engine execution proof.

The finalized result writer can use these values only after reopening the
protected artifact publication.  Engine reports and caller-provided indexes
never supply artifact metadata to the product projection.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .engine_artifact_store import (
    V2_MANIFEST_SCHEMA,
    EngineArtifactPublicationBinding,
    EngineArtifactStore,
    ReopenedEngineArtifactAttempt,
)
from .util import content_hash


class EngineExecutionProofWriterError(ValueError):
    """A protected source did not establish a claim in the finalized proof."""


@dataclass(frozen=True, slots=True)
class ControllerArtifactProofRow:
    """One immutable display row from a verified private artifact."""

    artifact_id: str
    attempt_id: str
    name: str
    sha256: str
    bytes: int
    media_type: str
    access: str = "private"

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "attempt_id": self.attempt_id,
            "name": self.name,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "media_type": self.media_type,
            "access": self.access,
        }


@dataclass(frozen=True, slots=True)
class ControllerArtifactIndex:
    """Bounded metadata derived from one reopened protected manifest.

    This value is a projection, not an attestation. Finalization must invoke
    `reopen_controller_artifact_index` against the retained store again.
    """

    manifest_ref: str
    artifacts: tuple[ControllerArtifactProofRow, ...]


def reopen_controller_artifact_index(
    store: EngineArtifactStore,
    *,
    publication_binding: EngineArtifactPublicationBinding,
    artifact_byte_limit: int,
) -> ControllerArtifactIndex:
    """Reopen sealed artifact bytes and derive the product's artifact index.

    `publication_binding` must be constructed from the accepted attempt and
    observed worker outcome by the installed runtime.  This function refuses
    a publication with any different identity, including a legacy v1 bundle.
    """

    if (
        type(store) is not EngineArtifactStore
        or type(publication_binding) is not EngineArtifactPublicationBinding
        or type(artifact_byte_limit) is not int
        or not 0 <= artifact_byte_limit <= 64 * 1024 * 1024
    ):
        raise EngineExecutionProofWriterError("artifact proof source is invalid")
    try:
        reopened = store.reopen_attempt(publication_binding.attempt_id)
        return controller_artifact_index_from_reopened(
            reopened,
            publication_binding=publication_binding,
            artifact_byte_limit=artifact_byte_limit,
        )
    except EngineExecutionProofWriterError:
        raise
    except Exception:
        raise EngineExecutionProofWriterError(
            "artifact proof source could not be reopened"
        ) from None


def controller_artifact_index_from_reopened(
    reopened: ReopenedEngineArtifactAttempt,
    *,
    publication_binding: EngineArtifactPublicationBinding,
    artifact_byte_limit: int,
) -> ControllerArtifactIndex:
    """Derive display rows from bytes already reopened by the protected store."""
    if (
        type(publication_binding) is not EngineArtifactPublicationBinding
        or type(artifact_byte_limit) is not int
        or not 0 <= artifact_byte_limit <= 64 * 1024 * 1024
    ):
        raise EngineExecutionProofWriterError("artifact proof source is invalid")
    return _artifact_index(
        reopened,
        publication_binding=publication_binding,
        artifact_byte_limit=artifact_byte_limit,
    )


def _artifact_index(
    reopened: ReopenedEngineArtifactAttempt,
    *,
    publication_binding: EngineArtifactPublicationBinding,
    artifact_byte_limit: int,
) -> ControllerArtifactIndex:
    if (
        type(reopened) is not ReopenedEngineArtifactAttempt
        or reopened.schema_version != V2_MANIFEST_SCHEMA
        or reopened.recovery_eligible is not True
        or reopened.attempt_id != publication_binding.attempt_id
        or reopened.publication_binding != publication_binding
        or reopened.manifest_ref != content_hash(reopened.to_manifest())
        or reopened.total_bytes > artifact_byte_limit
        or len(reopened.artifacts) > 128
    ):
        raise EngineExecutionProofWriterError("artifact publication binding changed")
    index: list[ControllerArtifactProofRow] = []
    total_bytes = 0
    seen: set[str] = set()
    for item in reopened.artifacts:
        if (
            len(item.payload) != item.size_bytes
            or "sha256:" + hashlib.sha256(item.payload).hexdigest() != item.sha256
        ):
            raise EngineExecutionProofWriterError("retained artifact bytes changed")
        parts = PurePosixPath(item.name).parts
        if not parts or item.name != "/".join(parts):
            raise EngineExecutionProofWriterError("retained artifact name changed")
        label = " › ".join(parts)
        if len(label) > 200:
            suffix = hashlib.sha256(item.name.encode("utf-8")).hexdigest()[:12]
            label = label[:184].rstrip() + "… " + suffix
        if not 0 < len(label) <= 200 or any(ord(char) < 32 for char in label):
            raise EngineExecutionProofWriterError("retained artifact label is invalid")
        artifact_id = (
            "artifact-"
            + content_hash(
                {
                    "schema_version": "bluefire.installed-engine-artifact-identity.v1",
                    "attempt_id": reopened.attempt_id,
                    "name": item.name,
                    "sha256": item.sha256,
                    "bytes": item.size_bytes,
                }
            )[7:39]
        )
        if artifact_id in seen:
            raise EngineExecutionProofWriterError("retained artifact identity repeats")
        seen.add(artifact_id)
        suffix = PurePosixPath(item.name).suffix.lower()
        media_type = {
            ".json": "application/json",
            ".jsonl": "application/x-ndjson",
            ".md": "text/markdown",
            ".txt": "text/plain",
            ".log": "text/plain",
        }.get(suffix, "application/octet-stream")
        index.append(
            ControllerArtifactProofRow(
                artifact_id=artifact_id,
                attempt_id=reopened.attempt_id,
                name=label,
                sha256=item.sha256,
                bytes=item.size_bytes,
                media_type=media_type,
            )
        )
        total_bytes += item.size_bytes
    if total_bytes != reopened.total_bytes:
        raise EngineExecutionProofWriterError("retained artifact byte count changed")
    return ControllerArtifactIndex(reopened.manifest_ref, tuple(index))


__all__ = [
    "controller_artifact_index_from_reopened",
    "ControllerArtifactIndex",
    "ControllerArtifactProofRow",
    "EngineExecutionProofWriterError",
    "reopen_controller_artifact_index",
]
