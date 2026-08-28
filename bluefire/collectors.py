"""Bounded, attributable evidence collectors and readiness reporting.

Collectors are deliberately separate from the runner boundary. A runner receipt can
prove what the runner reported; only a collector with an independent producer can
create ``observed`` evidence.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)


class CollectorError(ValueError):
    pass


class CollectorReadiness(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CollectorDescriptor:
    id: str
    name: str
    version: str
    kind: str
    capabilities: tuple[str, ...]
    independent_observation: bool
    platforms: tuple[str, ...] = ("any",)
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "kind": self.kind,
            "capabilities": list(self.capabilities),
            "independent_observation": self.independent_observation,
            "platforms": list(self.platforms),
            "requirements": list(self.requirements),
        }


@dataclass(frozen=True, slots=True)
class CollectorHealth:
    collector_id: str
    readiness: CollectorReadiness
    summary: str
    checked_at: str
    details: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "readiness": self.readiness.value,
            "summary": self.summary,
            "checked_at": self.checked_at,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    run_id: str
    step_id: str
    behavior_id: str
    runner_profile_id: str
    target_scope_ref: str
    action_id: str | None = None
    parent_evidence_ids: tuple[str, ...] = ()
    settings: Mapping[str, Any] | None = None
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise CollectorError(
                "collector timeout must be greater than zero and at most 60 seconds"
            )


@dataclass(frozen=True, slots=True)
class CollectionResult:
    descriptor: CollectorDescriptor
    health: CollectorHealth
    records: tuple[EvidenceRecord, ...]
    elapsed_ms: int
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor": self.descriptor.to_dict(),
            "health": self.health.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "elapsed_ms": self.elapsed_ms,
            "limitations": list(self.limitations),
        }


class Collector(Protocol):
    descriptor: CollectorDescriptor

    def health(self) -> CollectorHealth: ...

    def collect(self, request: CollectionRequest) -> CollectionResult: ...


class CollectorRegistry:
    """In-process catalog for built-in and adapter-backed collectors."""

    def __init__(self, collectors: Iterable[Collector] = ()) -> None:
        self._collectors: dict[str, Collector] = {}
        for collector in collectors:
            self.register(collector)

    def register(self, collector: Collector) -> None:
        collector_id = collector.descriptor.id
        if collector_id in self._collectors:
            raise CollectorError(f"duplicate collector id: {collector_id}")
        self._collectors[collector_id] = collector

    def descriptors(self) -> tuple[CollectorDescriptor, ...]:
        return tuple(self._collectors[key].descriptor for key in sorted(self._collectors))

    def health(self) -> tuple[CollectorHealth, ...]:
        return tuple(self._collectors[key].health() for key in sorted(self._collectors))

    def collect(self, collector_id: str, request: CollectionRequest) -> CollectionResult:
        try:
            collector = self._collectors[collector_id]
        except KeyError as exc:
            raise CollectorError(f"unknown collector id: {collector_id}") from exc
        return collector.collect(request)


class FilesystemCollector:
    """Independent, read-only observation of declared files under one sandbox root."""

    descriptor = CollectorDescriptor(
        id="collector.filesystem.sandbox.v1",
        name="Sandbox filesystem observer",
        version="1.0.0",
        kind="filesystem",
        capabilities=("file_metadata", "sha256"),
        independent_observation=True,
    )

    def __init__(
        self,
        sandbox_root: str | Path,
        *,
        max_file_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._observer = SandboxObserver(
            sandbox_root,
            max_file_bytes=max_file_bytes,
            read_timeout_seconds=5.0,
        )

    def health(self) -> CollectorHealth:
        return _health(
            self.descriptor.id,
            CollectorReadiness.READY,
            "Sandbox root is readable",
            {"mode": "read_only", "root_name": self._observer.root.name},
        )

    def collect(self, request: CollectionRequest) -> CollectionResult:
        started = time.monotonic()
        settings = dict(request.settings or {})
        configured = settings.get("paths", ())
        if isinstance(configured, (str, bytes)) or not isinstance(configured, Sequence):
            raise CollectorError("filesystem collector settings.paths must be a list")
        paths = tuple(str(path) for path in configured)
        records: list[EvidenceRecord] = []
        deadline = started + request.timeout_seconds
        for index, relative_path in enumerate(paths):
            if time.monotonic() > deadline:
                for skipped in paths[index:]:
                    records.append(
                        _gap_record(
                            request,
                            self.descriptor.id,
                            "collector_timeout",
                            requested_artifact=skipped,
                        )
                    )
                break
            try:
                observed = self._observer.observe_file(
                    relative_path=relative_path,
                    run_id=request.run_id,
                    step_id=request.step_id,
                    behavior_id=request.behavior_id,
                    action_id=request.action_id or "collector.filesystem.observe.v1",
                    runner_profile_id=request.runner_profile_id,
                    parent_evidence_ids=request.parent_evidence_ids,
                )
                records.append(
                    EvidenceRecord.create(
                        run_id=observed.run_id,
                        step_id=observed.step_id,
                        behavior_id=observed.behavior_id,
                        action_id=observed.action_id,
                        provenance=observed.provenance,
                        producer=self.descriptor.id,
                        runner_profile_id=observed.runner_profile_id,
                        environment={
                            **observed.environment,
                            "collector_id": self.descriptor.id,
                            "collector_version": self.descriptor.version,
                        },
                        timestamp=observed.timestamp,
                        parent_evidence_ids=observed.parent_evidence_ids,
                        content={**observed.content, "collector_id": self.descriptor.id},
                        confidence=observed.confidence,
                        limitations=(
                            "independent filesystem metadata and digest observation only",
                        ),
                        target_scope_ref=observed.target_scope_ref,
                    )
                )
            except (EvidenceError, OSError) as exc:
                records.append(
                    _gap_record(
                        request,
                        self.descriptor.id,
                        _safe_failure_reason(exc),
                        requested_artifact=relative_path,
                    )
                )
        gaps = sum(record.provenance is EvidenceProvenance.UNKNOWN for record in records)
        state = CollectorReadiness.DEGRADED if gaps else CollectorReadiness.READY
        summary = (
            "Collection completed with explicit evidence gaps" if gaps else "Collection completed"
        )
        return CollectionResult(
            descriptor=self.descriptor,
            health=_health(self.descriptor.id, state, summary, {"gap_count": gaps}),
            records=tuple(records),
            elapsed_ms=_elapsed_ms(started),
            limitations=("filesystem metadata and content hash only",),
        )


class JsonLinesFixtureCollector:
    """Read bounded JSONL network/audit fixture logs from a disposable sandbox."""

    descriptor = CollectorDescriptor(
        id="collector.fixture-jsonl.v1",
        name="Disposable fixture log collector",
        version="1.0.0",
        kind="fixture_log",
        capabilities=("network_fixture_logs", "audit_fixture_logs"),
        independent_observation=True,
    )

    def __init__(
        self,
        sandbox_root: str | Path,
        *,
        max_file_bytes: int = 8 * 1024 * 1024,
        max_records: int = 10_000,
    ) -> None:
        root = Path(sandbox_root)
        if not root.is_dir():
            raise CollectorError("fixture collector root must already exist")
        if max_file_bytes <= 0 or max_records <= 0:
            raise CollectorError("fixture collector bounds must be positive")
        self._root = root.resolve(strict=True)
        self._max_file_bytes = max_file_bytes
        self._max_records = max_records

    def health(self) -> CollectorHealth:
        return _health(
            self.descriptor.id,
            CollectorReadiness.READY,
            "Fixture log root is readable",
            {"mode": "read_only", "max_records": self._max_records},
        )

    def collect(self, request: CollectionRequest) -> CollectionResult:
        started = time.monotonic()
        relative_path = str(dict(request.settings or {}).get("relative_path", ""))
        records: list[EvidenceRecord] = []
        try:
            path = self._resolve_file(relative_path)
            if path.stat().st_size > self._max_file_bytes:
                raise CollectorError("fixture log exceeds the configured byte limit")
            deadline = started + request.timeout_seconds
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if time.monotonic() > deadline:
                        raise CollectorError("collector_timeout")
                    if line_number > self._max_records:
                        raise CollectorError("fixture log exceeds the configured record limit")
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if not isinstance(value, Mapping):
                        raise CollectorError("fixture log rows must be JSON objects")
                    records.append(
                        EvidenceRecord.create(
                            run_id=request.run_id,
                            step_id=request.step_id,
                            behavior_id=request.behavior_id,
                            action_id=request.action_id,
                            provenance=EvidenceProvenance.OBSERVED,
                            producer=self.descriptor.id,
                            runner_profile_id=request.runner_profile_id,
                            environment={"environment_type": "disposable"},
                            parent_evidence_ids=request.parent_evidence_ids,
                            content={
                                "artifact_type": "fixture_log_event",
                                "source": PurePosixPath(relative_path).as_posix(),
                                "line_number": line_number,
                                "event": dict(value),
                            },
                            confidence=1.0,
                            limitations=("fixture log observation only",),
                            target_scope_ref=request.target_scope_ref,
                        )
                    )
        except (CollectorError, EvidenceError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            records.append(
                _gap_record(
                    request,
                    self.descriptor.id,
                    _safe_failure_reason(exc),
                    requested_artifact=relative_path or "unspecified fixture log",
                )
            )
        gaps = sum(record.provenance is EvidenceProvenance.UNKNOWN for record in records)
        state = CollectorReadiness.DEGRADED if gaps else CollectorReadiness.READY
        return CollectionResult(
            descriptor=self.descriptor,
            health=_health(
                self.descriptor.id,
                state,
                (
                    "Fixture collection completed"
                    if not gaps
                    else "Fixture collection has an evidence gap"
                ),
                {"gap_count": gaps, "event_count": len(records) - gaps},
            ),
            records=tuple(records),
            elapsed_ms=_elapsed_ms(started),
            limitations=("only explicitly configured disposable fixture logs are collected",),
        )

    def _resolve_file(self, relative_path: str) -> Path:
        logical = PurePosixPath(relative_path)
        if (
            logical.is_absolute()
            or not logical.parts
            or any(part in {"", ".", ".."} for part in logical.parts)
        ):
            raise CollectorError("fixture paths must be normalized relative paths")
        current = self._root
        for part in logical.parts:
            current = current / part
            if current.is_symlink():
                raise CollectorError("fixture collector refuses symbolic-link paths")
        resolved = current.resolve(strict=True)
        if self._root not in resolved.parents or not resolved.is_file():
            raise CollectorError("fixture log is outside the configured root")
        return resolved


class UnavailableCollector:
    """Advertise an optional adapter without pretending it is locally usable."""

    def __init__(self, descriptor: CollectorDescriptor, reason: str) -> None:
        self.descriptor = descriptor
        self._reason = reason

    def health(self) -> CollectorHealth:
        return _health(
            self.descriptor.id,
            CollectorReadiness.UNAVAILABLE,
            self._reason,
            {"requirements": list(self.descriptor.requirements)},
        )

    def collect(self, request: CollectionRequest) -> CollectionResult:
        started = time.monotonic()
        return CollectionResult(
            descriptor=self.descriptor,
            health=self.health(),
            records=(
                _gap_record(
                    request,
                    self.descriptor.id,
                    "collector_unavailable",
                    requested_artifact=self.descriptor.kind,
                ),
            ),
            elapsed_ms=_elapsed_ms(started),
            limitations=(self._reason,),
        )


def optional_collector_descriptors() -> tuple[CollectorDescriptor, ...]:
    """Known adapter contracts that may be configured on suitable runners."""

    return (
        CollectorDescriptor(
            id="collector.sysmon-eventlog.v1",
            name="Sysmon and Windows Event Log adapter",
            version="1.0.0",
            kind="host_audit",
            capabilities=("sysmon", "windows_event_log"),
            independent_observation=True,
            platforms=("windows",),
            requirements=("configured event channels", "least-privilege log access"),
        ),
        CollectorDescriptor(
            id="collector.auditd.v1",
            name="Linux auditd adapter",
            version="1.0.0",
            kind="host_audit",
            capabilities=("auditd",),
            independent_observation=True,
            platforms=("linux",),
            requirements=("auditd", "least-privilege audit-log access"),
        ),
        CollectorDescriptor(
            id="collector.pcap-disposable.v1",
            name="Disposable-range packet capture adapter",
            version="1.0.0",
            kind="network_capture",
            capabilities=("pcap",),
            independent_observation=True,
            requirements=("explicit disposable CIDR", "capture capability"),
        ),
        CollectorDescriptor(
            id="collector.siem-query.v1",
            name="SIEM query adapter",
            version="1.0.0",
            kind="siem",
            capabilities=("bounded_query",),
            independent_observation=True,
            requirements=("configured provider", "read-only credential reference"),
        ),
    )


def _gap_record(
    request: CollectionRequest,
    producer: str,
    reason: str,
    *,
    requested_artifact: str,
) -> EvidenceRecord:
    return EvidenceRecord.create(
        run_id=request.run_id,
        step_id=request.step_id,
        behavior_id=request.behavior_id,
        action_id=request.action_id,
        provenance=EvidenceProvenance.UNKNOWN,
        producer=producer,
        runner_profile_id=request.runner_profile_id,
        environment={"environment_type": "disposable"},
        parent_evidence_ids=request.parent_evidence_ids,
        content={
            "artifact_type": "evidence_gap",
            "requested_artifact": requested_artifact,
            "reason": reason,
        },
        confidence=0.0,
        limitations=("requested observation was not available",),
        target_scope_ref=request.target_scope_ref,
    )


def _safe_failure_reason(exc: BaseException) -> str:
    if isinstance(exc, (CollectorError, EvidenceError)):
        return str(exc)[:300]
    if isinstance(exc, json.JSONDecodeError):
        return "fixture log contains invalid JSON"
    if isinstance(exc, UnicodeError):
        return "fixture log is not valid UTF-8"
    return "collector could not read the requested artifact"


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _health(
    collector_id: str,
    readiness: CollectorReadiness,
    summary: str,
    details: Mapping[str, Any],
) -> CollectorHealth:
    from datetime import datetime, timezone

    return CollectorHealth(
        collector_id=collector_id,
        readiness=readiness,
        summary=summary,
        checked_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        details=dict(details),
    )


__all__ = [
    "CollectionRequest",
    "CollectionResult",
    "Collector",
    "CollectorDescriptor",
    "CollectorError",
    "CollectorHealth",
    "CollectorReadiness",
    "CollectorRegistry",
    "FilesystemCollector",
    "JsonLinesFixtureCollector",
    "UnavailableCollector",
    "optional_collector_descriptors",
]
