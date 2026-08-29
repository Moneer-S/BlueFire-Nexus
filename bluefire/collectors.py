"""Bounded, attributable evidence collectors and readiness reporting.

Collectors are deliberately separate from the runner boundary. A runner receipt can
prove what the runner reported; only a collector with an independent producer can
create ``observed`` evidence.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, replace
from enum import Enum
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)
from .native_collectors import (
    NativeProcessError,
    native_process_readiness,
    observe_native_process,
)
from .util import content_hash, json_clone

_COLLECTOR_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_OBSERVATION_KEY = re.compile(r"^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_COLLECTORS = 32
_MAX_SETTINGS_BYTES = 128 * 1024
_MAX_OBSERVATION_KEY_BYTES = 4_096


def filesystem_observation_key(relative_path: str) -> str:
    """Encode a case-preserving path into the lowercase observation-key grammar."""

    if not isinstance(relative_path, str) or not relative_path:
        raise CollectorError("filesystem observation path is invalid")
    encoded = PurePosixPath(relative_path).as_posix().encode("utf-8").hex()
    key = f"filesystem/path-utf8-{encoded}"
    if len(key.encode("ascii")) > _MAX_OBSERVATION_KEY_BYTES:
        raise CollectorError("filesystem observation key exceeds its byte bound")
    return key


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
    execution_binding: Mapping[str, Any] | None = None
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise CollectorError(
                "collector timeout must be greater than zero and at most 60 seconds"
            )
        if self.execution_binding is not None:
            try:
                binding = json_clone(self.execution_binding)
            except (TypeError, ValueError, RecursionError) as exc:
                raise CollectorError("collector execution binding is invalid") from exc
            if not isinstance(binding, dict) or set(binding) - {"runner_task_id"}:
                raise CollectorError("collector execution binding fields are invalid")
            task_id = binding.get("runner_task_id")
            if task_id is not None and (
                not isinstance(task_id, str)
                or re.fullmatch(r"execute-[0-9a-f]{64}", task_id) is None
            ):
                raise CollectorError("collector runner task binding is invalid")
            object.__setattr__(self, "execution_binding", binding)


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

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CollectionResult":
        """Rehydrate a collector result and refuse altered evidence or health."""

        if not isinstance(value, Mapping) or set(value) != {
            "descriptor",
            "health",
            "records",
            "elapsed_ms",
            "limitations",
        }:
            raise CollectorError("collection result fields do not match the contract")
        descriptor = _descriptor_from_mapping(value.get("descriptor"))
        health = _health_from_mapping(value.get("health"))
        raw_records = value.get("records")
        if not isinstance(raw_records, list) or len(raw_records) > 100_000:
            raise CollectorError("collection result records are invalid")
        try:
            records = tuple(EvidenceRecord.from_mapping(row) for row in raw_records)
        except EvidenceError as exc:
            raise CollectorError(f"collection result evidence is invalid: {exc}") from exc
        elapsed_ms = value.get("elapsed_ms")
        limitations = _string_tuple(value.get("limitations"), "collection limitations", 64, 1_000)
        if (
            health.collector_id != descriptor.id
            or isinstance(elapsed_ms, bool)
            or not isinstance(elapsed_ms, int)
            or elapsed_ms < 0
            or elapsed_ms > 3_600_000
            or any(record.producer != descriptor.id for record in records)
        ):
            raise CollectorError("collection result identity or timing is invalid")
        return cls(
            descriptor=descriptor,
            health=health,
            records=records,
            elapsed_ms=elapsed_ms,
            limitations=limitations,
        )


@dataclass(frozen=True, slots=True)
class CollectorRuntimeSettings:
    """Versioned settings that decide which backends are actually invoked."""

    collectors: Mapping[str, Mapping[str, Any]]
    schema_version: str = "bluefire.collector-runtime-settings.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "bluefire.collector-runtime-settings.v1":
            raise CollectorError("unsupported collector runtime settings version")
        if not isinstance(self.collectors, Mapping) or len(self.collectors) > _MAX_COLLECTORS:
            raise CollectorError("collector runtime settings are invalid")
        normalized: dict[str, dict[str, Any]] = {}
        for collector_id, raw in self.collectors.items():
            if not isinstance(collector_id, str) or _COLLECTOR_ID.fullmatch(collector_id) is None:
                raise CollectorError("collector runtime settings contain an invalid ID")
            if not isinstance(raw, Mapping) or set(raw) != {"enabled", "settings"}:
                raise CollectorError("collector runtime entry fields are invalid")
            enabled = raw.get("enabled")
            settings = raw.get("settings")
            if type(enabled) is not bool or not isinstance(settings, Mapping):
                raise CollectorError("collector runtime entry values are invalid")
            try:
                settings_copy = json_clone(settings)
                encoded = json.dumps(settings_copy, ensure_ascii=False, sort_keys=True).encode(
                    "utf-8"
                )
            except (TypeError, ValueError, RecursionError) as exc:
                raise CollectorError("collector settings must contain bounded JSON values") from exc
            if not isinstance(settings_copy, dict) or len(encoded) > _MAX_SETTINGS_BYTES:
                raise CollectorError("collector settings exceed their byte bound")
            normalized[collector_id] = {
                "enabled": enabled,
                "settings": _freeze_json(settings_copy),
            }
        object.__setattr__(
            self,
            "collectors",
            MappingProxyType(
                {
                    collector_id: MappingProxyType(row)
                    for collector_id, row in sorted(normalized.items())
                }
            ),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CollectorRuntimeSettings":
        if not isinstance(value, Mapping) or set(value) != {"schema_version", "collectors"}:
            raise CollectorError("collector runtime settings fields are invalid")
        collectors = value.get("collectors")
        if not isinstance(collectors, Mapping):
            raise CollectorError("collector runtime settings collectors are invalid")
        return cls(
            collectors=collectors,
            schema_version=str(value.get("schema_version", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "collectors": {
                collector_id: {
                    "enabled": bool(row["enabled"]),
                    "settings": _thaw_json(row["settings"]),
                }
                for collector_id, row in self.collectors.items()
            },
        }

    @property
    def settings_hash(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class CollectionSession:
    """Hashed, replayable record of one configured collector invocation set."""

    settings: CollectorRuntimeSettings
    results: Mapping[str, CollectionResult]

    def __post_init__(self) -> None:
        enabled = {
            collector_id
            for collector_id, row in self.settings.collectors.items()
            if row["enabled"] is True
        }
        if set(self.results) != enabled or any(
            collector_id != result.descriptor.id for collector_id, result in self.results.items()
        ):
            raise CollectorError("collection session results do not match enabled settings")
        run_ids = {record.run_id for result in self.results.values() for record in result.records}
        if len(run_ids) > 1:
            raise CollectorError("collection session evidence spans multiple runs")
        object.__setattr__(self, "results", dict(sorted(self.results.items())))

    def _body(self) -> dict[str, Any]:
        enabled = [
            collector_id
            for collector_id, row in self.settings.collectors.items()
            if row["enabled"] is True
        ]
        disabled = [
            collector_id
            for collector_id, row in self.settings.collectors.items()
            if row["enabled"] is False
        ]
        return {
            "schema_version": "bluefire.collection-session.v1",
            "settings": self.settings.to_dict(),
            "settings_hash": self.settings.settings_hash,
            "enabled_collectors": enabled,
            "disabled_collectors": disabled,
            "results": {
                collector_id: result.to_dict() for collector_id, result in self.results.items()
            },
        }

    def to_dict(self) -> dict[str, Any]:
        body = self._body()
        return {**body, "session_hash": content_hash(body)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CollectionSession":
        expected = {
            "schema_version",
            "settings",
            "settings_hash",
            "enabled_collectors",
            "disabled_collectors",
            "results",
            "session_hash",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CollectorError("collection session fields do not match the contract")
        if value.get("schema_version") != "bluefire.collection-session.v1":
            raise CollectorError("unsupported collection session version")
        raw_settings = value.get("settings")
        raw_results = value.get("results")
        if not isinstance(raw_settings, Mapping) or not isinstance(raw_results, Mapping):
            raise CollectorError("collection session payload is invalid")
        settings = CollectorRuntimeSettings.from_mapping(raw_settings)
        results: dict[str, CollectionResult] = {}
        for collector_id, result in raw_results.items():
            if not isinstance(collector_id, str) or not isinstance(result, Mapping):
                raise CollectorError("collection session result entry is invalid")
            results[collector_id] = CollectionResult.from_mapping(result)
        rebuilt = cls(settings=settings, results=results)
        body = rebuilt._body()
        if (
            value.get("settings_hash") != settings.settings_hash
            or value.get("enabled_collectors") != body["enabled_collectors"]
            or value.get("disabled_collectors") != body["disabled_collectors"]
            or value.get("session_hash") != content_hash(body)
        ):
            raise CollectorError("collection session hashes or settings do not match")
        return rebuilt


class Collector(Protocol):
    descriptor: CollectorDescriptor

    def health(self) -> CollectorHealth: ...

    def collect(self, request: CollectionRequest) -> CollectionResult: ...


class CollectorRegistry:
    """In-process catalog for built-in and adapter-backed collectors."""

    def __init__(self, collectors: Iterable[Collector] = ()) -> None:
        self._collectors: dict[str, Collector] = {}
        self._descriptor_snapshots: dict[str, CollectorDescriptor] = {}
        for collector in collectors:
            self.register(collector)

    def register(self, collector: Collector) -> None:
        descriptor = getattr(collector, "descriptor", None)
        if not isinstance(descriptor, CollectorDescriptor):
            raise CollectorError("collector descriptor is invalid")
        try:
            snapshot = _descriptor_from_mapping(descriptor.to_dict())
        except (AttributeError, TypeError, ValueError) as exc:
            raise CollectorError("collector descriptor is invalid") from exc
        if descriptor != snapshot:
            raise CollectorError("collector descriptor is not an immutable canonical value")
        canonical = _CANONICAL_BUILTIN_DESCRIPTORS.get(snapshot.id)
        canonical_for_type = _CANONICAL_BUILTIN_TYPES.get(type(collector))
        if (canonical is not None and snapshot != canonical) or (
            canonical_for_type is not None and snapshot != canonical_for_type
        ):
            raise CollectorError("collector descriptor differs from its canonical built-in")
        collector_id = snapshot.id
        if collector_id in self._collectors:
            raise CollectorError(f"duplicate collector id: {collector_id}")
        self._collectors[collector_id] = collector
        self._descriptor_snapshots[collector_id] = snapshot

    def descriptors(self) -> tuple[CollectorDescriptor, ...]:
        for collector_id in self._collectors:
            self._assert_descriptor_snapshot(collector_id)
        return tuple(self._descriptor_snapshots[key] for key in sorted(self._collectors))

    def health(self) -> tuple[CollectorHealth, ...]:
        rows: list[CollectorHealth] = []
        for collector_id in sorted(self._collectors):
            self._assert_descriptor_snapshot(collector_id)
            health = self._collectors[collector_id].health()
            self._assert_descriptor_snapshot(collector_id)
            if health.collector_id != collector_id:
                raise CollectorError("collector health identity changed after registration")
            rows.append(health)
        return tuple(rows)

    def authority_snapshot(
        self,
        settings: CollectorRuntimeSettings,
        *,
        expected_sandbox: str | Path,
    ) -> Mapping[str, Any]:
        """Bind exact built-in implementations and stable source identities."""

        self.validate_configuration(settings)
        expected_root = Path(expected_sandbox).resolve(strict=True)
        backends: list[Mapping[str, Any]] = []
        for collector_id, row in settings.collectors.items():
            if row["enabled"] is not True:
                continue
            collector = self._collectors[collector_id]
            self._assert_descriptor_snapshot(collector_id)
            descriptor = self._descriptor_snapshots[collector_id].to_dict()
            implementation_id = f"{type(collector).__module__}.{type(collector).__qualname__}"
            if collector_id == FilesystemCollector.descriptor.id:
                if type(collector) is not FilesystemCollector:
                    raise CollectorError("filesystem collector implementation is not canonical")
                if collector._observer.root != expected_root:
                    raise CollectorError(
                        "filesystem collector is not bound to the expected sandbox"
                    )
                source_authority: Mapping[str, Any] = {
                    "schema_version": "bluefire.filesystem-source-authority.v1",
                    "sandbox_binding": "exact-factory-argument",
                    "max_file_bytes": collector._observer.max_file_bytes,
                    "read_timeout_seconds": collector._observer.read_timeout_seconds,
                    "path_policy": "handle-pinned-contained-no-follow",
                }
            elif collector_id == NativeProcessCollector.descriptor.id:
                if type(collector) is not NativeProcessCollector:
                    raise CollectorError("process collector implementation is not canonical")
                source_authority = {
                    "schema_version": "bluefire.process-source-authority.v1",
                    "authorized_processes": [
                        {
                            "process_id": process_id,
                            "parent_process_id": parent_id,
                            "creation_identity": creation_identity,
                        }
                        for process_id, (parent_id, creation_identity) in sorted(
                            collector._authorized_processes.items()
                        )
                    ],
                }
            elif collector_id == LoopbackReceiverCollector.descriptor.id:
                if type(collector) is not LoopbackReceiverCollector:
                    raise CollectorError("receiver collector implementation is not canonical")
                collector._assert_source_identity()
                source_authority = {
                    "schema_version": "bluefire.receiver-source-authority.v1",
                    "host": collector._host,
                    "port": collector._port,
                    "process_id": collector._process_id,
                    "session_id": collector._session_id,
                }
            else:
                raise CollectorError("collector runtime contains a non-canonical backend")
            backend = {
                "collector_id": collector_id,
                "descriptor": descriptor,
                "descriptor_hash": content_hash(descriptor),
                "implementation_id": implementation_id,
                "source_authority": source_authority,
                "source_authority_hash": content_hash(source_authority),
            }
            backends.append(backend)
        body = {
            "schema_version": "bluefire.collector-registry-authority.v1",
            "settings_hash": settings.settings_hash,
            "backends": backends,
        }
        return {**body, "authority_hash": content_hash(body)}

    def validate_configuration(self, settings: CollectorRuntimeSettings) -> None:
        """Refuse a configured run before effects if a backend is absent or unready."""

        enabled = {
            collector_id
            for collector_id, row in settings.collectors.items()
            if row["enabled"] is True
        }
        unknown = sorted(enabled - set(self._collectors))
        if unknown:
            raise CollectorError("collector runtime settings reference an unknown backend")
        for collector_id, row in settings.collectors.items():
            if row["enabled"] is not True:
                continue
            self._assert_descriptor_snapshot(collector_id)
            health = self._collectors[collector_id].health()
            self._assert_descriptor_snapshot(collector_id)
            if (
                health.collector_id != collector_id
                or health.readiness is not CollectorReadiness.READY
            ):
                raise CollectorError(f"configured collector is not ready: {collector_id}")

    def collect(self, collector_id: str, request: CollectionRequest) -> CollectionResult:
        try:
            collector = self._collectors[collector_id]
        except KeyError as exc:
            raise CollectorError(f"unknown collector id: {collector_id}") from exc
        snapshot = self._assert_descriptor_snapshot(collector_id)
        result = collector.collect(request)
        current = self._assert_descriptor_snapshot(collector_id)
        if current != snapshot or result.descriptor != snapshot:
            raise CollectorError("collector result descriptor changed after registration")
        return result

    def collect_configured(
        self,
        settings: CollectorRuntimeSettings,
        request: CollectionRequest,
        *,
        source_free_gaps: Mapping[str, str] | None = None,
    ) -> CollectionSession:
        """Resolve every enabled backend, explicitly recording any source-free gaps."""

        self.validate_configuration(settings)
        if source_free_gaps is not None and not isinstance(source_free_gaps, Mapping):
            raise CollectorError("collector source gaps are invalid")
        gaps = dict(source_free_gaps or {})
        enabled = {
            collector_id
            for collector_id, row in settings.collectors.items()
            if row["enabled"] is True
        }
        if not set(gaps) <= enabled:
            raise CollectorError("collector source gaps reference a disabled backend")
        if any(
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 300
            or "\x00" in reason
            for reason in gaps.values()
        ):
            raise CollectorError("collector source gap reason is invalid")
        deadline = time.monotonic() + request.timeout_seconds
        results: dict[str, CollectionResult] = {}
        for collector_id, row in settings.collectors.items():
            if row["enabled"] is not True:
                continue
            if collector_id in gaps:
                results[collector_id] = self._configured_gap_result(
                    collector_id,
                    request,
                    reason=gaps[collector_id],
                )
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectorError("configured collector phase exceeded its shared timeout")
            result = self.collect(
                collector_id,
                replace(
                    request,
                    settings=_thaw_json(row["settings"]),
                    timeout_seconds=min(request.timeout_seconds, max(remaining, 0.001)),
                ),
            )
            if time.monotonic() > deadline:
                raise CollectorError("configured collector phase exceeded its shared timeout")
            results[collector_id] = CollectionResult.from_mapping(result.to_dict())
        return CollectionSession(settings=settings, results=results)

    def gap_configured(
        self,
        settings: CollectorRuntimeSettings,
        request: CollectionRequest,
        *,
        reason: str,
    ) -> CollectionSession:
        """Record an attributable gap without reading any configured source."""

        enabled = {
            collector_id
            for collector_id, row in settings.collectors.items()
            if row["enabled"] is True
        }
        if not enabled or not enabled <= set(self._collectors):
            raise CollectorError("collector gap session has no complete registered backend set")
        results = {
            collector_id: self._configured_gap_result(
                collector_id,
                request,
                reason=reason,
            )
            for collector_id in sorted(enabled)
        }
        return CollectionSession(settings=settings, results=results)

    def _configured_gap_result(
        self,
        collector_id: str,
        request: CollectionRequest,
        *,
        reason: str,
    ) -> CollectionResult:
        descriptor = self._assert_descriptor_snapshot(collector_id)
        record = _gap_record(
            request,
            collector_id,
            reason,
            requested_artifact=descriptor.kind,
        )
        return CollectionResult(
            descriptor=descriptor,
            health=_health(
                collector_id,
                CollectorReadiness.DEGRADED,
                "Collector was not invoked because its scheduled effect did not execute",
                {"gap_count": 1, "source_read": False},
            ),
            records=(record,),
            elapsed_ms=0,
            limitations=("scheduled runner effect was not successfully executed",),
        )

    def _assert_descriptor_snapshot(self, collector_id: str) -> CollectorDescriptor:
        collector = self._collectors[collector_id]
        snapshot = self._descriptor_snapshots[collector_id]
        current = getattr(collector, "descriptor", None)
        if current != snapshot:
            raise CollectorError("collector descriptor changed after registration")
        canonical = _CANONICAL_BUILTIN_DESCRIPTORS.get(collector_id)
        canonical_for_type = _CANONICAL_BUILTIN_TYPES.get(type(collector))
        if (canonical is not None and snapshot != canonical) or (
            canonical_for_type is not None and snapshot != canonical_for_type
        ):
            raise CollectorError("collector descriptor differs from its canonical built-in")
        return snapshot


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
                    deadline_monotonic=deadline,
                )
                if time.monotonic() > deadline:
                    raise EvidenceError("observed file read exceeded the collector time limit")
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
                        content={
                            **observed.content,
                            "artifact_type": "collector_observation",
                            "observation_key": filesystem_observation_key(relative_path),
                            "observation_kind": "filesystem",
                            "observed_fields": {
                                "path": observed.content["path"],
                                "size_bytes": observed.content["size_bytes"],
                                "sha256": observed.content["sha256"],
                            },
                            "collector_id": self.descriptor.id,
                            "mechanism": "independent-file-handle-read",
                        },
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


class NativeProcessCollector:
    """Observe one exact live process through a bounded native OS interface."""

    descriptor = CollectorDescriptor(
        id="collector.process.native.v1",
        name="Native process identity observer",
        version="1.0.0",
        kind="process_system",
        capabilities=("process_identity", "parent_identity", "creation_identity"),
        independent_observation=True,
        platforms=("windows", "linux"),
        requirements=("read access to a control-plane-owned process",),
    )

    def __init__(self, authorized_processes: Mapping[int, int]) -> None:
        if (
            not isinstance(authorized_processes, Mapping)
            or not 1 <= len(authorized_processes) <= 64
        ):
            raise CollectorError("native process collector requires bounded owned children")
        normalized: dict[int, tuple[int, str]] = {}
        for process_id, parent_process_id in authorized_processes.items():
            if (
                isinstance(process_id, bool)
                or not isinstance(process_id, int)
                or process_id <= 0
                or isinstance(parent_process_id, bool)
                or not isinstance(parent_process_id, int)
                or parent_process_id <= 0
            ):
                raise CollectorError("native process authorization is invalid")
            try:
                pinned = observe_native_process(
                    process_id,
                    expected_parent_process_id=parent_process_id,
                    timeout_seconds=2.0,
                )
            except (NativeProcessError, OSError, TypeError, ValueError) as exc:
                raise CollectorError(
                    "native process authorization could not pin creation identity"
                ) from exc
            creation_identity = pinned.get("creation_identity")
            if not isinstance(creation_identity, str) or not creation_identity:
                raise CollectorError("native process authorization identity is invalid")
            normalized[process_id] = (parent_process_id, creation_identity)
        self._authorized_processes = normalized

    def health(self) -> CollectorHealth:
        readiness = dict(native_process_readiness())
        ready = readiness.get("ready") is True
        return _health(
            self.descriptor.id,
            CollectorReadiness.READY if ready else CollectorReadiness.UNAVAILABLE,
            "Native process observer is available" if ready else "No native process backend",
            {**readiness, "authorized_process_count": len(self._authorized_processes)},
        )

    def collect(self, request: CollectionRequest) -> CollectionResult:
        started = time.monotonic()
        settings = dict(request.settings or {})
        process_id = settings.get("process_id")
        expected_parent = settings.get("expected_parent_process_id")
        try:
            if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
                raise NativeProcessError(
                    "the requested PID is not an authorized control-plane child"
                )
            if expected_parent is not None and (
                isinstance(expected_parent, bool)
                or not isinstance(expected_parent, int)
                or expected_parent <= 0
            ):
                raise NativeProcessError(
                    "the requested PID is not an authorized control-plane child"
                )
            authorization = self._authorized_processes.get(process_id)
            if authorization is None:
                raise NativeProcessError(
                    "the requested PID is not an authorized control-plane child"
                )
            authorized_parent, creation_identity = authorization
            if expected_parent not in {
                None,
                authorized_parent,
            }:
                raise NativeProcessError(
                    "the requested PID is not an authorized control-plane child"
                )
            observation = observe_native_process(
                process_id,
                expected_parent_process_id=authorized_parent,
                timeout_seconds=request.timeout_seconds,
            )
            if observation.get("creation_identity") != creation_identity:
                raise NativeProcessError(
                    "the authorized process creation identity is no longer current"
                )
            record = EvidenceRecord.create(
                run_id=request.run_id,
                step_id=request.step_id,
                behavior_id=request.behavior_id,
                action_id=request.action_id,
                provenance=EvidenceProvenance.OBSERVED,
                producer=self.descriptor.id,
                runner_profile_id=request.runner_profile_id,
                environment={
                    "environment_type": "disposable",
                    "collector_id": self.descriptor.id,
                    "collector_version": self.descriptor.version,
                    "platform": observation["platform"],
                },
                parent_evidence_ids=request.parent_evidence_ids,
                content={
                    "artifact_type": "collector_observation",
                    "observation_key": "process/native-child",
                    "observation_kind": "process",
                    "source": "process/native-child",
                    "observed_fields": dict(observation),
                    "mechanism": observation["native_api"],
                },
                confidence=1.0,
                limitations=("single exact PID; no host-wide process inventory",),
                target_scope_ref=request.target_scope_ref,
            )
            health = _health(
                self.descriptor.id,
                CollectorReadiness.READY,
                "Native process identity was independently observed",
                {
                    "backend": observation["native_api"],
                    "platform": observation["platform"],
                    "observation_count": 1,
                },
            )
            records = (record,)
        except (NativeProcessError, OSError, TypeError, ValueError) as exc:
            records = (
                _gap_record(
                    request,
                    self.descriptor.id,
                    _safe_failure_reason(exc),
                    requested_artifact="process/native-child",
                ),
            )
            health = _health(
                self.descriptor.id,
                CollectorReadiness.DEGRADED,
                "Native process identity was not available",
                {"gap_count": 1},
            )
        return CollectionResult(
            descriptor=self.descriptor,
            health=health,
            records=records,
            elapsed_ms=_elapsed_ms(started),
            limitations=("read-only observation of one caller-authorized PID",),
        )


class ReceiverObservationSource(Protocol):
    """Path-free observation surface owned by the loopback receiver."""

    @property
    def host(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def process_id(self) -> int: ...

    @property
    def session_id(self) -> str: ...

    @property
    def accepted_artifact_bindings(self) -> tuple[Mapping[str, object], ...]: ...


class LoopbackReceiverCollector:
    """Read authenticated artifact bindings from an independent receiver."""

    descriptor = CollectorDescriptor(
        id="collector.network.loopback-receiver.v1",
        name="Authenticated loopback receiver observer",
        version="1.0.0",
        kind="internal_network",
        capabilities=("authenticated_artifact_binding", "sha256", "byte_count"),
        independent_observation=True,
        platforms=("any",),
        requirements=("managed loopback receiver",),
    )

    def __init__(self, source: ReceiverObservationSource) -> None:
        try:
            host = source.host
            address = ip_address(host)
            port = source.port
            process_id = source.process_id
            session_id = source.session_id
        except (AttributeError, TypeError, ValueError) as exc:
            raise CollectorError("receiver observation source is invalid") from exc
        if (
            not isinstance(host, str)
            or not address.is_loopback
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or isinstance(process_id, bool)
            or not isinstance(process_id, int)
            or process_id <= 0
            or not isinstance(session_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", session_id) is None
        ):
            raise CollectorError("receiver observation source is not a bounded loopback receiver")
        self._source = source
        self._host = host
        self._port = port
        self._process_id = process_id
        self._session_id = session_id

    def _assert_source_identity(self) -> None:
        try:
            current = (
                self._source.host,
                self._source.port,
                self._source.process_id,
                self._source.session_id,
            )
        except (AttributeError, OSError, RuntimeError) as exc:
            raise CollectorError("receiver observation source identity is unavailable") from exc
        if current != (self._host, self._port, self._process_id, self._session_id):
            raise CollectorError("receiver observation source identity changed")

    def health(self) -> CollectorHealth:
        self._assert_source_identity()
        return _health(
            self.descriptor.id,
            CollectorReadiness.READY,
            "Managed loopback receiver observation source is attached",
            {
                "host": self._host,
                "port": self._port,
                "receiver_process_id": self._process_id,
                "mode": "path_free_authenticated_bindings",
            },
        )

    def collect(self, request: CollectionRequest) -> CollectionResult:
        started = time.monotonic()
        settings = dict(request.settings or {})
        expected_task_ids = settings.get("task_ids")
        if expected_task_ids is None:
            expected: set[str] | None = None
        elif (
            isinstance(expected_task_ids, list)
            and len(expected_task_ids) <= 1_000
            and all(isinstance(item, str) and 0 < len(item) <= 200 for item in expected_task_ids)
        ):
            expected = set(expected_task_ids)
        else:
            raise CollectorError("receiver collector settings.task_ids must be a bounded list")
        execution_binding = dict(request.execution_binding or {})
        runner_task_id = execution_binding.get("runner_task_id")
        if runner_task_id is not None:
            if expected is not None and expected != {runner_task_id}:
                raise CollectorError(
                    "receiver collector task IDs do not match the executed runner task"
                )
            expected = {str(runner_task_id)}
        if expected is None:
            raise CollectorError(
                "receiver collector requires an exact task ID or executed runner task binding"
            )
        records: list[EvidenceRecord] = []
        try:
            self._assert_source_identity()
            bindings = self._source.accepted_artifact_bindings
        except CollectorError:
            raise
        except (AttributeError, OSError, RuntimeError) as exc:
            bindings = ()
            source_error: BaseException | None = exc
        else:
            source_error = None
        if len(bindings) > 10_000:
            raise CollectorError("receiver observation source exceeded its record bound")
        for binding in bindings:
            task_id = binding.get("task_id") if isinstance(binding, Mapping) else None
            digest = binding.get("sha256") if isinstance(binding, Mapping) else None
            bytes_received = binding.get("bytes_received") if isinstance(binding, Mapping) else None
            if (
                not isinstance(task_id, str)
                or not task_id
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
                or isinstance(bytes_received, bool)
                or not isinstance(bytes_received, int)
                or bytes_received < 0
            ):
                raise CollectorError("receiver returned an invalid artifact binding")
            if expected is not None and task_id not in expected:
                continue
            records.append(
                EvidenceRecord.create(
                    run_id=request.run_id,
                    step_id=request.step_id,
                    behavior_id=request.behavior_id,
                    action_id=request.action_id,
                    provenance=EvidenceProvenance.OBSERVED,
                    producer=self.descriptor.id,
                    runner_profile_id=request.runner_profile_id,
                    environment={
                        "environment_type": "disposable",
                        "collector_id": self.descriptor.id,
                        "collector_version": self.descriptor.version,
                        "transport": "loopback",
                    },
                    parent_evidence_ids=request.parent_evidence_ids,
                    content={
                        "artifact_type": "collector_observation",
                        "observation_key": (f"network/authenticated-receiver/{task_id}"),
                        "observation_kind": "network",
                        "source": "receiver/authenticated-loopback",
                        "sha256": digest,
                        "size_bytes": bytes_received,
                        "observed_fields": {
                            "task_id": task_id,
                            "sha256": digest,
                            "bytes_received": bytes_received,
                            "receiver_process_id": self._process_id,
                            "receiver_session_id": self._session_id,
                        },
                        "mechanism": "receiver-owned-authenticated-binding",
                    },
                    confidence=1.0,
                    limitations=("loopback receiver bindings only; no packet payload retained",),
                    target_scope_ref=request.target_scope_ref,
                )
            )
        missing = sorted(
            (expected or set())
            - {str(record.content["observed_fields"]["task_id"]) for record in records}
        )
        for task_id in missing:
            records.append(
                _gap_record(
                    request,
                    self.descriptor.id,
                    "expected receiver binding was not observed",
                    requested_artifact=task_id,
                )
            )
        if source_error is not None:
            records.append(
                _gap_record(
                    request,
                    self.descriptor.id,
                    _safe_failure_reason(source_error),
                    requested_artifact="receiver/authenticated-loopback",
                )
            )
        gaps = sum(record.provenance is EvidenceProvenance.UNKNOWN for record in records)
        state = CollectorReadiness.DEGRADED if gaps or not records else CollectorReadiness.READY
        summary = (
            "Authenticated receiver bindings were independently observed"
            if state is CollectorReadiness.READY
            else "Receiver collection has an explicit evidence gap"
        )
        if not records:
            records.append(
                _gap_record(
                    request,
                    self.descriptor.id,
                    "no authenticated receiver binding was observed",
                    requested_artifact="receiver/authenticated-loopback",
                )
            )
            gaps = 1
            state = CollectorReadiness.DEGRADED
        return CollectionResult(
            descriptor=self.descriptor,
            health=_health(
                self.descriptor.id,
                state,
                summary,
                {"observation_count": len(records) - gaps, "gap_count": gaps},
            ),
            records=tuple(records),
            elapsed_ms=_elapsed_ms(started),
            limitations=("path-free authenticated receiver metadata only",),
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


_CANONICAL_BUILTIN_TYPES: Mapping[type[Any], CollectorDescriptor] = MappingProxyType(
    {
        FilesystemCollector: FilesystemCollector.descriptor,
        NativeProcessCollector: NativeProcessCollector.descriptor,
        LoopbackReceiverCollector: LoopbackReceiverCollector.descriptor,
        JsonLinesFixtureCollector: JsonLinesFixtureCollector.descriptor,
    }
)
_CANONICAL_BUILTIN_DESCRIPTORS: Mapping[str, CollectorDescriptor] = MappingProxyType(
    {descriptor.id: descriptor for descriptor in _CANONICAL_BUILTIN_TYPES.values()}
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
            name="Linux audit and runtime log adapter",
            version="1.0.0",
            kind="host_audit",
            capabilities=("auditd", "journald", "runtime_logs"),
            independent_observation=True,
            platforms=("linux",),
            requirements=(
                "bounded audit or journal cursor",
                "least-privilege audit-log access",
            ),
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
        CollectorDescriptor(
            id="collector.cloud-identity-audit.v1",
            name="Cloud identity audit log adapter",
            version="1.0.0",
            kind="cloud_identity_audit",
            capabilities=("bounded_audit_query", "identity_events"),
            independent_observation=True,
            platforms=("cloud",),
            requirements=(
                "configured account or tenant allowlist",
                "read-only credential reference",
            ),
        ),
        CollectorDescriptor(
            id="collector.edr-query.v1",
            name="EDR query adapter",
            version="1.0.0",
            kind="edr",
            capabilities=("registered_query_template", "bounded_pagination"),
            independent_observation=True,
            requirements=("configured provider", "read-only credential reference"),
        ),
    )


def reconcile_observations(
    predicted: Mapping[str, Mapping[str, Any]],
    records: Iterable[EvidenceRecord],
) -> Mapping[str, Any]:
    """Compare declared fields with independently observed collector fields."""

    if not isinstance(predicted, Mapping) or len(predicted) > 10_000:
        raise CollectorError("predicted observation fields are invalid")
    normalized_predictions: dict[str, dict[str, Any]] = {}
    for key, fields in predicted.items():
        if (
            not isinstance(key, str)
            or len(key.encode("utf-8")) > _MAX_OBSERVATION_KEY_BYTES
            or _OBSERVATION_KEY.fullmatch(key) is None
            or not isinstance(fields, Mapping)
        ):
            raise CollectorError("predicted observation entry is invalid")
        try:
            copied = json_clone(fields)
        except (TypeError, ValueError, RecursionError) as exc:
            raise CollectorError("predicted fields must contain finite JSON values") from exc
        if not isinstance(copied, dict) or len(copied) > 256:
            raise CollectorError("predicted observation fields exceed their bound")
        normalized_predictions[key] = copied

    observed: dict[str, list[tuple[dict[str, Any], EvidenceRecord]]] = {}
    for record in records:
        if record.provenance is not EvidenceProvenance.OBSERVED:
            continue
        observation_key = record.content.get("observation_key")
        observed_fields_value = record.content.get("observed_fields")
        if not isinstance(observation_key, str) or not isinstance(observed_fields_value, Mapping):
            continue
        try:
            copied_fields = json_clone(observed_fields_value)
        except (TypeError, ValueError, RecursionError) as exc:
            raise CollectorError("observed fields must contain finite JSON values") from exc
        if not isinstance(copied_fields, dict):
            raise CollectorError("observed fields are invalid")
        observed.setdefault(observation_key, []).append((copied_fields, record))

    comparisons: list[dict[str, Any]] = []
    for observation_key in sorted(set(normalized_predictions) & set(observed)):
        predicted_fields = normalized_predictions[observation_key]
        attempts = sorted(observed[observation_key], key=lambda item: item[1].evidence_id)
        for attempt_index, (observed_fields, record) in enumerate(attempts, start=1):
            predicted_names = set(predicted_fields)
            observed_names = set(observed_fields)
            comparison: dict[str, Any] = {
                "observation_key": observation_key,
                "predicted_fields": predicted_fields,
                "observed_fields": observed_fields,
                "missing_fields": sorted(predicted_names - observed_names),
                "unexpected_fields": sorted(observed_names - predicted_names),
                "mismatched_fields": sorted(
                    name
                    for name in predicted_names & observed_names
                    if predicted_fields[name] != observed_fields[name]
                ),
                "evidence_id": record.evidence_id,
                "content_hash": record.content_hash,
                "record_hash": record.record_hash,
            }
            if len(attempts) > 1:
                comparison["attempt_index"] = attempt_index
                comparison["attempt_count"] = len(attempts)
            comparisons.append(comparison)
    body = {
        "schema_version": "bluefire.collector-reconciliation.v1",
        "predicted_observations": sorted(normalized_predictions),
        "observed_observations": sorted(observed),
        "observation_attempt_counts": {
            key: len(attempts) for key, attempts in sorted(observed.items())
        },
        "missing_observations": sorted(set(normalized_predictions) - set(observed)),
        "unexpected_observations": sorted(set(observed) - set(normalized_predictions)),
        "field_comparisons": comparisons,
    }
    return {**body, "reconciliation_hash": content_hash(body)}


def _descriptor_from_mapping(value: Any) -> CollectorDescriptor:
    expected = {
        "id",
        "name",
        "version",
        "kind",
        "capabilities",
        "independent_observation",
        "platforms",
        "requirements",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CollectorError("collector descriptor fields are invalid")
    collector_id = value.get("id")
    name = value.get("name")
    version = value.get("version")
    kind = value.get("kind")
    if (
        not isinstance(collector_id, str)
        or _COLLECTOR_ID.fullmatch(collector_id) is None
        or not isinstance(name, str)
        or not name
        or len(name) > 200
        or not isinstance(version, str)
        or not version
        or len(version) > 50
        or not isinstance(kind, str)
        or not kind
        or len(kind) > 100
        or type(value.get("independent_observation")) is not bool
    ):
        raise CollectorError("collector descriptor identity is invalid")
    return CollectorDescriptor(
        id=collector_id,
        name=name,
        version=version,
        kind=kind,
        capabilities=_string_tuple(value.get("capabilities"), "capabilities", 64, 100),
        independent_observation=value["independent_observation"],
        platforms=_string_tuple(value.get("platforms"), "platforms", 32, 100),
        requirements=_string_tuple(value.get("requirements"), "requirements", 64, 500),
    )


def _health_from_mapping(value: Any) -> CollectorHealth:
    if not isinstance(value, Mapping) or set(value) != {
        "collector_id",
        "readiness",
        "summary",
        "checked_at",
        "details",
    }:
        raise CollectorError("collector health fields are invalid")
    collector_id = value.get("collector_id")
    summary = value.get("summary")
    checked_at = value.get("checked_at")
    details = value.get("details")
    try:
        readiness = CollectorReadiness(value.get("readiness"))
        details_copy = json_clone(details)
    except (TypeError, ValueError, RecursionError) as exc:
        raise CollectorError("collector health values are invalid") from exc
    if (
        not isinstance(collector_id, str)
        or _COLLECTOR_ID.fullmatch(collector_id) is None
        or not isinstance(summary, str)
        or not summary
        or len(summary) > 500
        or not isinstance(checked_at, str)
        or not checked_at.endswith("Z")
        or len(checked_at) > 40
        or not isinstance(details_copy, dict)
    ):
        raise CollectorError("collector health identity is invalid")
    return CollectorHealth(
        collector_id=collector_id,
        readiness=readiness,
        summary=summary,
        checked_at=checked_at,
        details=details_copy,
    )


def _string_tuple(
    value: Any,
    label: str,
    maximum: int,
    item_maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise CollectorError(f"collector {label} are invalid")
    result = tuple(value)
    if any(
        not isinstance(item, str) or not item or len(item) > item_maximum or "\0" in item
        for item in result
    ) or len(set(result)) != len(result):
        raise CollectorError(f"collector {label} are invalid")
    return result


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


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
    if isinstance(exc, (CollectorError, EvidenceError, NativeProcessError)):
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
    "CollectionSession",
    "Collector",
    "CollectorDescriptor",
    "CollectorError",
    "CollectorHealth",
    "CollectorReadiness",
    "CollectorRegistry",
    "CollectorRuntimeSettings",
    "FilesystemCollector",
    "JsonLinesFixtureCollector",
    "LoopbackReceiverCollector",
    "NativeProcessCollector",
    "ReceiverObservationSource",
    "UnavailableCollector",
    "optional_collector_descriptors",
    "filesystem_observation_key",
    "reconcile_observations",
]
