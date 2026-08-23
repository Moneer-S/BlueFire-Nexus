"""Evidence provenance and independent sandbox observation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .util import content_hash


class EvidenceError(ValueError):
    pass


class EvidenceProvenance(str, Enum):
    SYNTHETIC = "synthetic"
    EXECUTED = "executed"
    OBSERVED = "observed"
    CONTROL_BLOCKED = "control_blocked"
    COUNTERFACTUAL = "counterfactual"
    UNKNOWN = "unknown"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    schema_version: str
    evidence_id: str
    run_id: str
    step_id: str
    behavior_id: str
    action_id: str | None
    provenance: EvidenceProvenance
    producer: str
    runner_profile_id: str | None
    environment: Mapping[str, Any]
    timestamp: str
    parent_evidence_ids: tuple[str, ...]
    content: Mapping[str, Any]
    content_hash: str
    record_hash: str
    confidence: float
    limitations: tuple[str, ...]
    target_scope_ref: str

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        step_id: str,
        behavior_id: str,
        provenance: EvidenceProvenance,
        producer: str,
        content: Mapping[str, Any],
        target_scope_ref: str,
        action_id: str | None = None,
        runner_profile_id: str | None = None,
        environment: Mapping[str, Any] | None = None,
        parent_evidence_ids: Iterable[str] = (),
        confidence: float = 1.0,
        limitations: Iterable[str] = (),
        timestamp: str | None = None,
    ) -> "EvidenceRecord":
        if not 0.0 <= confidence <= 1.0:
            raise EvidenceError("evidence confidence must be between zero and one")
        content_copy = dict(content)
        content_digest = content_hash(content_copy)
        parents = tuple(parent_evidence_ids)
        limitation_rows = tuple(limitations)
        recorded_at = timestamp or _utc_now()
        base = {
            "schema_version": "bluefire.evidence.v1",
            "run_id": run_id,
            "step_id": step_id,
            "behavior_id": behavior_id,
            "action_id": action_id,
            "provenance": provenance,
            "producer": producer,
            "runner_profile_id": runner_profile_id,
            "environment": dict(environment or {}),
            "timestamp": recorded_at,
            "parent_evidence_ids": parents,
            "content": content_copy,
            "content_hash": content_digest,
            "confidence": confidence,
            "limitations": limitation_rows,
            "target_scope_ref": target_scope_ref,
        }
        record_digest = content_hash(base)
        evidence_id = "evidence-" + record_digest.removeprefix("sha256:")[:20]
        return cls(
            schema_version="bluefire.evidence.v1",
            evidence_id=evidence_id,
            run_id=run_id,
            step_id=step_id,
            behavior_id=behavior_id,
            action_id=action_id,
            provenance=provenance,
            producer=producer,
            runner_profile_id=runner_profile_id,
            environment=dict(environment or {}),
            timestamp=recorded_at,
            parent_evidence_ids=parents,
            content=content_copy,
            content_hash=content_digest,
            record_hash=record_digest,
            confidence=confidence,
            limitations=limitation_rows,
            target_scope_ref=target_scope_ref,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "behavior_id": self.behavior_id,
            "action_id": self.action_id,
            "provenance": self.provenance.value,
            "producer": self.producer,
            "runner_profile_id": self.runner_profile_id,
            "environment": dict(self.environment),
            "timestamp": self.timestamp,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "content": dict(self.content),
            "content_hash": self.content_hash,
            "record_hash": self.record_hash,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "target_scope_ref": self.target_scope_ref,
        }


@dataclass(slots=True)
class EvidenceGraph:
    _records: dict[str, EvidenceRecord] = field(default_factory=dict)

    def add(self, record: EvidenceRecord) -> None:
        if record.evidence_id in self._records:
            if self._records[record.evidence_id] != record:
                raise EvidenceError(f"conflicting evidence id: {record.evidence_id}")
            return
        missing = [parent for parent in record.parent_evidence_ids if parent not in self._records]
        if missing:
            raise EvidenceError(f"evidence references unknown parents: {missing}")
        self._records[record.evidence_id] = record

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            self.add(record)

    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records.values())

    def by_step(self, step_id: str) -> tuple[EvidenceRecord, ...]:
        return tuple(record for record in self._records.values() if record.step_id == step_id)


class SandboxObserver:
    """Read-only collector that records declared artifacts under one root."""

    def __init__(self, sandbox_root: str | Path) -> None:
        root = Path(sandbox_root)
        if not root.is_dir():
            raise EvidenceError("sandbox observer root must already exist")
        self.root = root.resolve(strict=True)

    def observe_file(
        self,
        *,
        relative_path: str,
        run_id: str,
        step_id: str,
        behavior_id: str,
        action_id: str,
        runner_profile_id: str,
        parent_evidence_ids: Iterable[str] = (),
    ) -> EvidenceRecord:
        path = self._resolve_file(relative_path)
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        stat = path.stat()
        return EvidenceRecord.create(
            run_id=run_id,
            step_id=step_id,
            behavior_id=behavior_id,
            action_id=action_id,
            provenance=EvidenceProvenance.OBSERVED,
            producer="sandbox-observer.v1",
            runner_profile_id=runner_profile_id,
            environment={"environment_type": "disposable"},
            parent_evidence_ids=parent_evidence_ids,
            content={
                "artifact_type": "file_observation",
                "path": PurePosixPath(relative_path).as_posix(),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
                "modified_ns": stat.st_mtime_ns,
            },
            confidence=1.0,
            limitations=("filesystem observation only; no host telemetry collector attached",),
            target_scope_ref=f"runner-profile:{runner_profile_id}",
        )

    def _resolve_file(self, relative_path: str) -> Path:
        logical = PurePosixPath(relative_path)
        if (
            logical.is_absolute()
            or not logical.parts
            or any(part in {"", ".", ".."} for part in logical.parts)
        ):
            raise EvidenceError("observer paths must be normalized relative paths")
        candidate = self.root.joinpath(*logical.parts)
        current = self.root
        for part in logical.parts:
            current = current / part
            if current.is_symlink():
                raise EvidenceError("observer refuses symbolic-link paths")
        resolved = candidate.resolve(strict=True)
        if self.root not in resolved.parents or not resolved.is_file():
            raise EvidenceError("observed file is outside the sandbox root")
        return resolved


__all__ = [
    "EvidenceError",
    "EvidenceGraph",
    "EvidenceProvenance",
    "EvidenceRecord",
    "SandboxObserver",
]
