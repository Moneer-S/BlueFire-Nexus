"""Immutable collector contracts and canonical session serialization.

Adapters re-export these types through ``bluefire.collectors`` for compatibility.
This module does not construct collectors or perform observation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .evidence import EvidenceError, EvidenceRecord
from .util import content_hash, json_clone

_COLLECTOR_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_MAX_COLLECTORS = 32
_MAX_SETTINGS_BYTES = 128 * 1024


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
