"""Engine-neutral identity, lifecycle, and evidence contracts.

This module contains no process, network, model, or defensive-change authority.
It records the immutable admission facts around one externally managed engine
attempt and keeps engine reports distinct from independently checked outcomes.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping

from .util import canonical_json_bytes, content_hash, json_clone, parse_iso8601_datetime


class EngineAttemptContractError(ValueError):
    """Raised when an external-engine record violates its closed contract."""


class AttemptRole(str, Enum):
    BASELINE = "baseline"
    ADAPTIVE_SEARCH = "adaptive_search"


class AttemptState(str, Enum):
    QUEUED = "queued"
    PREFLIGHT = "preflight"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNKNOWN = "unknown"


class EvidenceCategory(str, Enum):
    ENGINE_ASSERTION = "engine_assertion"
    TOOL_RESULT = "tool_result"
    INDEPENDENT_TARGET_EFFECT = "independent_target_effect"
    INDEPENDENT_SECURITY_OUTCOME = "independent_security_outcome"
    LEGITIMATE_USE = "legitimate_use"


class AttemptCompleteness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_ENGINE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^engine-evidence-[0-9a-f]{24}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}$")
_MAX_EVIDENCE_BYTES = 64 * 1024
_MAX_EVIDENCE_DEPTH = 12
_MAX_EVIDENCE_NODES = 1024
_MAX_EVIDENCE_STRING = 4096


class _ControllerEvidenceAuthority:
    __slots__ = ()


_CONTROLLER_EVIDENCE_AUTHORITY = _ControllerEvidenceAuthority()

_TERMINAL_STATES = frozenset(
    {
        AttemptState.COMPLETED,
        AttemptState.PARTIAL,
        AttemptState.FAILED,
        AttemptState.CANCELLED,
        AttemptState.BUDGET_EXHAUSTED,
        AttemptState.UNKNOWN,
    }
)
_TRANSITIONS = {
    AttemptState.QUEUED: frozenset(
        {AttemptState.PREFLIGHT, AttemptState.CANCELLED, AttemptState.FAILED}
    ),
    AttemptState.PREFLIGHT: frozenset(
        {AttemptState.RUNNING, AttemptState.CANCELLED, AttemptState.FAILED}
    ),
    AttemptState.RUNNING: frozenset(
        {
            AttemptState.STOPPING,
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.CANCELLED,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }
    ),
    AttemptState.STOPPING: frozenset(
        {
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.CANCELLED,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }
    ),
}


def _exact(value: Any, fields: frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineAttemptContractError(f"{name} fields do not match the contract")
    return value


def _string(value: Any, name: str, *, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineAttemptContractError(f"{name} is invalid")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineAttemptContractError(f"{name} must be a sha256 digest")
    return value


def _timestamp(value: Any, name: str) -> str:
    result = _string(value, name, maximum=40)
    try:
        parse_iso8601_datetime(result)
    except ValueError as exc:
        raise EngineAttemptContractError(f"{name} is not bounded RFC 3339") from exc
    return result


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineAttemptContractError(f"{name} is outside its bound")
    return int(value)


def _bounded_evidence_content(value: Any) -> dict[str, Any]:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_EVIDENCE_NODES or depth > _MAX_EVIDENCE_DEPTH:
            raise EngineAttemptContractError("engine evidence content is too complex")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int) and not isinstance(item, bool):
            if not -(1 << 63) <= item < (1 << 63):
                raise EngineAttemptContractError("engine evidence integer is outside its bound")
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise EngineAttemptContractError("engine evidence number is not finite")
            return
        if isinstance(item, str):
            if len(item) > _MAX_EVIDENCE_STRING or any(
                ord(character) < 32 and character not in "\t\n\r" for character in item
            ):
                raise EngineAttemptContractError("engine evidence string is invalid")
            return
        if isinstance(item, Mapping):
            if len(item) > 256:
                raise EngineAttemptContractError("engine evidence object is too large")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 128:
                    raise EngineAttemptContractError("engine evidence key is invalid")
                visit(child, depth + 1)
            return
        if isinstance(item, (list, tuple)):
            if len(item) > 256:
                raise EngineAttemptContractError("engine evidence array is too large")
            for child in item:
                visit(child, depth + 1)
            return
        raise EngineAttemptContractError("engine evidence contains a non-JSON value")

    if not isinstance(value, Mapping):
        raise EngineAttemptContractError("engine evidence content must be an object")
    visit(value, 0)
    copy = json_clone(value)
    if not isinstance(copy, dict):
        raise EngineAttemptContractError("engine evidence content must be an object")
    if len(canonical_json_bytes(copy)) > _MAX_EVIDENCE_BYTES:
        raise EngineAttemptContractError("engine evidence content exceeds its byte bound")
    return copy


@dataclass(frozen=True, slots=True)
class EngineAttemptBinding:
    schema_version: str
    experiment_id: str
    attempt_id: str
    run_id: str
    role: AttemptRole
    objective_ref: str
    environment_ref: str
    target_snapshot_ref: str
    scope_ref: str
    scope_version: str
    engine_id: str
    engine_version: str
    engine_revision: str
    engine_package_digest: str
    policy_overlay_digest: str
    model_provider: str
    model_id: str
    model_data_destination: str
    model_authorization_ref: str
    wall_clock_seconds: int
    action_limit: int
    cost_limit_microunits: int
    artifact_byte_limit: int
    created_at: str
    parent_attempt_id: str | None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EngineAttemptBinding":
        fields = frozenset(cls.__dataclass_fields__)
        row = _exact(value, fields, "engine attempt binding")
        experiment_id = _string(row["experiment_id"], "experiment ID", maximum=43)
        attempt_id = _string(row["attempt_id"], "attempt ID", maximum=47)
        run_id = _string(row["run_id"], "run ID", maximum=44)
        if _EXPERIMENT_ID.fullmatch(experiment_id) is None:
            raise EngineAttemptContractError("experiment ID is invalid")
        if _ATTEMPT_ID.fullmatch(attempt_id) is None:
            raise EngineAttemptContractError("attempt ID is invalid")
        if _RUN_ID.fullmatch(run_id) is None:
            raise EngineAttemptContractError("run ID is invalid")
        try:
            role = AttemptRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise EngineAttemptContractError("attempt role is invalid") from exc
        engine_id = _string(row["engine_id"], "engine ID")
        revision = _string(row["engine_revision"], "engine revision", maximum=40)
        if _ENGINE_ID.fullmatch(engine_id) is None or _REVISION.fullmatch(revision) is None:
            raise EngineAttemptContractError("engine identity is invalid")
        provider = _string(row["model_provider"], "model provider")
        if _ENGINE_ID.fullmatch(provider) is None:
            raise EngineAttemptContractError("model provider is invalid")
        parent = row["parent_attempt_id"]
        if parent is not None and (
            not isinstance(parent, str)
            or _ATTEMPT_ID.fullmatch(parent) is None
            or parent == attempt_id
        ):
            raise EngineAttemptContractError("parent attempt ID is invalid")
        if row["schema_version"] != "bluefire.engine-attempt-binding.v1":
            raise EngineAttemptContractError("engine attempt schema version is unsupported")
        return cls(
            schema_version="bluefire.engine-attempt-binding.v1",
            experiment_id=experiment_id,
            attempt_id=attempt_id,
            run_id=run_id,
            role=role,
            objective_ref=_digest(row["objective_ref"], "objective reference"),
            environment_ref=_digest(row["environment_ref"], "environment reference"),
            target_snapshot_ref=_digest(row["target_snapshot_ref"], "target snapshot"),
            scope_ref=_digest(row["scope_ref"], "scope reference"),
            scope_version=_string(row["scope_version"], "scope version", maximum=80),
            engine_id=engine_id,
            engine_version=_string(row["engine_version"], "engine version", maximum=80),
            engine_revision=revision,
            engine_package_digest=_digest(row["engine_package_digest"], "engine package"),
            policy_overlay_digest=_digest(row["policy_overlay_digest"], "policy overlay"),
            model_provider=provider,
            model_id=_string(row["model_id"], "model ID", maximum=160),
            model_data_destination=_string(
                row["model_data_destination"], "model data destination", maximum=200
            ),
            model_authorization_ref=_digest(
                row["model_authorization_ref"], "model authorization reference"
            ),
            wall_clock_seconds=_bounded_int(
                row["wall_clock_seconds"], "wall-clock seconds", 1, 7_200
            ),
            action_limit=_bounded_int(row["action_limit"], "action limit", 1, 512),
            cost_limit_microunits=_bounded_int(
                row["cost_limit_microunits"], "cost limit", 0, 10_000_000_000
            ),
            artifact_byte_limit=_bounded_int(
                row["artifact_byte_limit"], "artifact byte limit", 1, 64 * 1024 * 1024
            ),
            created_at=_timestamp(row["created_at"], "binding creation time"),
            parent_attempt_id=parent,
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    field: (value.value if isinstance(value, Enum) else value)
                    for field, value in (
                        (name, getattr(self, name)) for name in self.__dataclass_fields__
                    )
                }
            )
        )

    @property
    def binding_digest(self) -> str:
        return content_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class EngineAttemptRecord:
    schema_version: str
    binding: EngineAttemptBinding
    binding_digest: str
    state: AttemptState
    upstream_session_id: str | None
    started_at: str | None
    ended_at: str | None
    exit_code: int | None
    completeness: AttemptCompleteness
    exit_reason: str | None
    limitations: tuple[str, ...]

    @classmethod
    def create(cls, binding: EngineAttemptBinding) -> "EngineAttemptRecord":
        return cls(
            schema_version="bluefire.engine-attempt.v1",
            binding=binding,
            binding_digest=binding.binding_digest,
            state=AttemptState.QUEUED,
            upstream_session_id=None,
            started_at=None,
            ended_at=None,
            exit_code=None,
            completeness=AttemptCompleteness.UNKNOWN,
            exit_reason=None,
            limitations=(),
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EngineAttemptRecord":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine attempt record")
        if row["schema_version"] != "bluefire.engine-attempt.v1":
            raise EngineAttemptContractError("engine attempt schema version is unsupported")
        binding = EngineAttemptBinding.from_mapping(row["binding"])
        if row["binding_digest"] != binding.binding_digest:
            raise EngineAttemptContractError("engine attempt binding changed")
        try:
            state = AttemptState(row["state"])
            completeness = AttemptCompleteness(row["completeness"])
        except (TypeError, ValueError) as exc:
            raise EngineAttemptContractError("engine attempt state is invalid") from exc
        session = row["upstream_session_id"]
        if session is not None and (
            not isinstance(session, str) or _OPAQUE_ID.fullmatch(session) is None
        ):
            raise EngineAttemptContractError("upstream session ID is invalid")
        started = (
            None
            if row["started_at"] is None
            else _timestamp(row["started_at"], "attempt start time")
        )
        ended = None if row["ended_at"] is None else _timestamp(row["ended_at"], "attempt end time")
        exit_code = row["exit_code"]
        if exit_code is not None and (
            isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or not -255 <= exit_code <= 255
        ):
            raise EngineAttemptContractError("engine exit code is invalid")
        exit_reason = row["exit_reason"]
        if exit_reason is not None:
            exit_reason = _string(exit_reason, "exit reason", maximum=240)
        raw_limits = row["limitations"]
        if not isinstance(raw_limits, list):
            raise EngineAttemptContractError("attempt limitations are invalid")
        limitations = tuple(_string(item, "attempt limitation", maximum=300) for item in raw_limits)
        if len(limitations) > 32 or len(set(limitations)) != len(limitations):
            raise EngineAttemptContractError("attempt limitations are invalid")
        terminal = state in _TERMINAL_STATES
        requires_started_session = state in {
            AttemptState.RUNNING,
            AttemptState.STOPPING,
            AttemptState.COMPLETED,
            AttemptState.PARTIAL,
            AttemptState.BUDGET_EXHAUSTED,
            AttemptState.UNKNOWN,
        }
        if (
            (requires_started_session and (session is None or started is None))
            or ((session is None) != (started is None))
            or (state in {AttemptState.QUEUED, AttemptState.PREFLIGHT} and session is not None)
            or (terminal and ended is None)
            or (not terminal and ended is not None)
            or (not terminal and (exit_code is not None or exit_reason is not None))
            or (not terminal and completeness is not AttemptCompleteness.UNKNOWN)
            or (
                session is None
                and (exit_code is not None or completeness is not AttemptCompleteness.UNKNOWN)
            )
            or (
                started is not None
                and ended is not None
                and parse_iso8601_datetime(ended) < parse_iso8601_datetime(started)
            )
        ):
            raise EngineAttemptContractError("engine attempt lifecycle fields are inconsistent")
        return cls(
            schema_version="bluefire.engine-attempt.v1",
            binding=binding,
            binding_digest=binding.binding_digest,
            state=state,
            upstream_session_id=session,
            started_at=started,
            ended_at=ended,
            exit_code=exit_code,
            completeness=completeness,
            exit_reason=exit_reason,
            limitations=limitations,
        )

    def transition(
        self,
        state: AttemptState,
        *,
        upstream_session_id: str | None = None,
        timestamp: str | None = None,
        exit_code: int | None = None,
        completeness: AttemptCompleteness = AttemptCompleteness.UNKNOWN,
        exit_reason: str | None = None,
        limitations: Iterable[str] = (),
    ) -> "EngineAttemptRecord":
        if not isinstance(state, AttemptState) or state not in _TRANSITIONS.get(
            self.state, frozenset()
        ):
            raise EngineAttemptContractError("engine attempt state transition is invalid")
        if not isinstance(completeness, AttemptCompleteness):
            raise EngineAttemptContractError("attempt completeness is invalid")
        session = self.upstream_session_id
        if upstream_session_id is not None:
            candidate = _string(upstream_session_id, "upstream session ID", maximum=160)
            if _OPAQUE_ID.fullmatch(candidate) is None:
                raise EngineAttemptContractError("upstream session ID is invalid")
            if session is not None and candidate != session:
                raise EngineAttemptContractError("upstream session identity changed")
            session = candidate
        when = _timestamp(timestamp, "state transition time") if timestamp else None
        started = self.started_at
        ended = self.ended_at
        if state is AttemptState.RUNNING:
            if session is None or when is None:
                raise EngineAttemptContractError("running requires session identity and start time")
            started = when
        if state in _TERMINAL_STATES:
            if when is None:
                raise EngineAttemptContractError("terminal engine state requires an end time")
            ended = when
            if started is not None and parse_iso8601_datetime(when) < parse_iso8601_datetime(
                started
            ):
                raise EngineAttemptContractError("engine attempt ended before it started")
        elif (
            exit_code is not None
            or exit_reason is not None
            or completeness is not AttemptCompleteness.UNKNOWN
        ):
            raise EngineAttemptContractError("nonterminal engine state cannot report an outcome")
        if (session is None) != (started is None):
            raise EngineAttemptContractError(
                "upstream session identity and start time must be recorded together"
            )
        if session is None and (
            exit_code is not None or completeness is not AttemptCompleteness.UNKNOWN
        ):
            raise EngineAttemptContractError(
                "engine process outcome requires a started upstream session"
            )
        if exit_code is not None and (
            isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or not -255 <= exit_code <= 255
        ):
            raise EngineAttemptContractError("engine exit code is invalid")
        reason = None if exit_reason is None else _string(exit_reason, "exit reason", maximum=240)
        limitation_rows = tuple(
            _string(item, "attempt limitation", maximum=300) for item in limitations
        )
        if len(limitation_rows) > 32 or len(set(limitation_rows)) != len(limitation_rows):
            raise EngineAttemptContractError("attempt limitations are invalid")
        return replace(
            self,
            state=state,
            upstream_session_id=session,
            started_at=started,
            ended_at=ended,
            exit_code=exit_code,
            completeness=completeness,
            exit_reason=reason,
            limitations=limitation_rows,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binding": self.binding.to_dict(),
            "binding_digest": self.binding_digest,
            "state": self.state.value,
            "upstream_session_id": self.upstream_session_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "completeness": self.completeness.value,
            "exit_reason": self.exit_reason,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True, init=False)
class EngineEvidenceItem:
    schema_version: str
    evidence_id: str
    attempt_id: str
    run_id: str
    category: EvidenceCategory
    producer: str
    observed_at: str
    content: Mapping[str, Any]
    content_digest: str
    source_artifact_digest: str | None
    parent_evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    _controller_attestation: object | None = field(
        default=None,
        repr=False,
        compare=False,
        init=False,
    )

    @classmethod
    def _admit(
        cls,
        *,
        evidence_id: str,
        attempt_id: str,
        run_id: str,
        category: EvidenceCategory,
        producer: str,
        observed_at: str,
        content: Mapping[str, Any],
        content_digest: str,
        source_artifact_digest: str | None,
        parent_evidence_ids: tuple[str, ...],
        limitations: tuple[str, ...],
        controller_attestation: object | None,
    ) -> "EngineEvidenceItem":
        item = object.__new__(cls)
        values = {
            "schema_version": "bluefire.engine-evidence.v1",
            "evidence_id": evidence_id,
            "attempt_id": attempt_id,
            "run_id": run_id,
            "category": category,
            "producer": producer,
            "observed_at": observed_at,
            "content": content,
            "content_digest": content_digest,
            "source_artifact_digest": source_artifact_digest,
            "parent_evidence_ids": parent_evidence_ids,
            "limitations": limitations,
            "_controller_attestation": controller_attestation,
        }
        for name, value in values.items():
            object.__setattr__(item, name, value)
        return item

    def _require_valid_attestation(self) -> None:
        independent = self.category in {
            EvidenceCategory.INDEPENDENT_TARGET_EFFECT,
            EvidenceCategory.INDEPENDENT_SECURITY_OUTCOME,
            EvidenceCategory.LEGITIMATE_USE,
        }
        if independent and self._controller_attestation is not _CONTROLLER_EVIDENCE_AUTHORITY:
            raise EngineAttemptContractError(
                "independent engine evidence requires controller authority"
            )
        if not independent and self._controller_attestation is not None:
            raise EngineAttemptContractError("upstream evidence has invalid controller authority")

    @classmethod
    def create(
        cls,
        *,
        attempt_id: str,
        run_id: str,
        category: EvidenceCategory,
        producer: str,
        observed_at: str,
        content: Mapping[str, Any],
        source_artifact_digest: str | None = None,
        parent_evidence_ids: Iterable[str] = (),
        limitations: Iterable[str] = (),
        _controller_authority: object | None = None,
    ) -> "EngineEvidenceItem":
        if _ATTEMPT_ID.fullmatch(attempt_id) is None or _RUN_ID.fullmatch(run_id) is None:
            raise EngineAttemptContractError("engine evidence identity is invalid")
        if not isinstance(category, EvidenceCategory):
            raise EngineAttemptContractError("engine evidence category is invalid")
        independent = category in {
            EvidenceCategory.INDEPENDENT_TARGET_EFFECT,
            EvidenceCategory.INDEPENDENT_SECURITY_OUTCOME,
            EvidenceCategory.LEGITIMATE_USE,
        }
        if independent and _controller_authority is not _CONTROLLER_EVIDENCE_AUTHORITY:
            raise EngineAttemptContractError(
                "independent engine evidence requires controller authority"
            )
        content_copy = _bounded_evidence_content(content)
        digest = content_hash(content_copy)
        artifact_digest = (
            None
            if source_artifact_digest is None
            else _digest(source_artifact_digest, "source artifact")
        )
        if not independent and artifact_digest is None:
            raise EngineAttemptContractError(
                "upstream engine evidence requires a retained source artifact"
            )
        parents = tuple(parent_evidence_ids)
        if (
            len(parents) > 64
            or len(set(parents)) != len(parents)
            or any(_EVIDENCE_ID.fullmatch(parent) is None for parent in parents)
        ):
            raise EngineAttemptContractError("parent engine evidence IDs are invalid")
        limits = tuple(_string(item, "evidence limitation", maximum=300) for item in limitations)
        if len(limits) > 32 or len(set(limits)) != len(limits):
            raise EngineAttemptContractError("engine evidence limitations are invalid")
        timestamp = _timestamp(observed_at, "evidence observation time")
        producer_id = _string(producer, "evidence producer")
        base = {
            "attempt_id": attempt_id,
            "run_id": run_id,
            "category": category.value,
            "producer": producer_id,
            "observed_at": timestamp,
            "content_digest": digest,
            "source_artifact_digest": artifact_digest,
            "parent_evidence_ids": parents,
            "limitations": limits,
        }
        evidence_id = "engine-evidence-" + content_hash(base).removeprefix("sha256:")[:24]
        return cls._admit(
            evidence_id=evidence_id,
            attempt_id=attempt_id,
            run_id=run_id,
            category=category,
            producer=producer_id,
            observed_at=timestamp,
            content=content_copy,
            content_digest=digest,
            source_artifact_digest=artifact_digest,
            parent_evidence_ids=parents,
            limitations=limits,
            controller_attestation=(_CONTROLLER_EVIDENCE_AUTHORITY if independent else None),
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        _controller_authority: object | None = None,
    ) -> "EngineEvidenceItem":
        """Rehydrate evidence without upgrading an engine claim to an observation.

        Controller-owned persistence code may pass the private authority for a
        record that it previously admitted. Untrusted engine/API mappings do not
        receive that capability and therefore cannot mint an independent result.
        """

        public_fields = frozenset(
            name for name in cls.__dataclass_fields__ if not name.startswith("_")
        )
        row = _exact(value, public_fields, "engine evidence item")
        if row["schema_version"] != "bluefire.engine-evidence.v1":
            raise EngineAttemptContractError("engine evidence schema version is unsupported")
        try:
            category = EvidenceCategory(row["category"])
        except (TypeError, ValueError) as exc:
            raise EngineAttemptContractError("engine evidence category is invalid") from exc
        raw_parents = row["parent_evidence_ids"]
        raw_limits = row["limitations"]
        if not isinstance(raw_parents, list) or not isinstance(raw_limits, list):
            raise EngineAttemptContractError("engine evidence references are invalid")
        recreated = cls.create(
            attempt_id=row["attempt_id"],
            run_id=row["run_id"],
            category=category,
            producer=row["producer"],
            observed_at=row["observed_at"],
            content=row["content"],
            source_artifact_digest=row["source_artifact_digest"],
            parent_evidence_ids=raw_parents,
            limitations=raw_limits,
            _controller_authority=_controller_authority,
        )
        if (
            row["content_digest"] != recreated.content_digest
            or row["evidence_id"] != recreated.evidence_id
        ):
            raise EngineAttemptContractError("engine evidence content or identity changed")
        return recreated

    def to_dict(self) -> dict[str, Any]:
        self._require_valid_attestation()
        content_copy = _bounded_evidence_content(self.content)
        current_digest = content_hash(content_copy)
        identity = {
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "category": self.category.value,
            "producer": self.producer,
            "observed_at": self.observed_at,
            "content_digest": current_digest,
            "source_artifact_digest": self.source_artifact_digest,
            "parent_evidence_ids": self.parent_evidence_ids,
            "limitations": self.limitations,
        }
        current_evidence_id = (
            "engine-evidence-" + content_hash(identity).removeprefix("sha256:")[:24]
        )
        if current_digest != self.content_digest or current_evidence_id != self.evidence_id:
            raise EngineAttemptContractError("engine evidence changed after admission")
        return dict(
            json_clone(
                {
                    "schema_version": self.schema_version,
                    "evidence_id": self.evidence_id,
                    "attempt_id": self.attempt_id,
                    "run_id": self.run_id,
                    "category": self.category.value,
                    "producer": self.producer,
                    "observed_at": self.observed_at,
                    "content": content_copy,
                    "content_digest": self.content_digest,
                    "source_artifact_digest": self.source_artifact_digest,
                    "parent_evidence_ids": self.parent_evidence_ids,
                    "limitations": self.limitations,
                }
            )
        )
