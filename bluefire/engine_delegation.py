"""Versioned authority for one bounded external-engine attempt.

The delegation is a review document, not a bearer token and not an execution
interface.  It contains no command, script, mount, credential, tool-server, or
defensive-change field.  The trusted controller resolves its digest references
and claims a separately persisted one-time approval before dispatch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, TypeVar

from .engine_attempt_contract import (
    AttemptRole,
    EngineAttemptBinding,
    EngineAttemptContractError,
)
from .util import content_hash, json_clone, parse_iso8601_datetime


class EngineDelegationError(ValueError):
    """Raised when an external-engine delegation is invalid or stale."""


class EngineOperationClass(str, Enum):
    """Reviewed operation families admitted by the first service lab."""

    SERVICE_SURFACE_DISCOVERY = "service_surface_discovery"
    HTTP_AUTHORIZATION_ASSESSMENT = "http_authorization_assessment"


class EngineEffectClass(str, Enum):
    """Maximum effects admitted inside the disposable first service lab."""

    BOUNDED_HTTP_REQUESTS = "bounded_http_requests"
    READ_GENERATED_LAB_RECORDS = "read_generated_lab_records"
    WRITE_ATTEMPT_ARTIFACTS = "write_attempt_artifacts"


_SCHEMA = "bluefire.engine-capability-delegation.v1"
_APPROVAL_SCHEMA = "bluefire.engine-execution-approval-binding.v1"
_STATE_SCHEMA = "bluefire.engine-execution-approval-state.v1"
_PROFILE_BY_ENGINE = {"strix": "engine-worker.strix.v1"}
_MAXIMUM_TIER = "controlled"
_EXPECTED_OPERATIONS = tuple(EngineOperationClass)
_EXPECTED_EFFECTS = tuple(EngineEffectClass)

_DELEGATION_ID = re.compile(r"^engine-delegation-[0-9a-f]{32}$")
_EXPERIMENT_ID = re.compile(r"^experiment-[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_ENGINE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SCOPE_VERSION = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EngineEnum = TypeVar("_EngineEnum", EngineOperationClass, EngineEffectClass)


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EngineDelegationError(f"{label} fields do not match the contract")
    return value


def _text(value: Any, label: str, *, maximum: int = 160) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EngineDelegationError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise EngineDelegationError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    result = _text(value, label, maximum=40)
    try:
        parse_iso8601_datetime(result)
    except ValueError as exc:
        raise EngineDelegationError(f"{label} is not bounded RFC 3339") from exc
    return result


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineDelegationError(f"{label} is outside its bound")
    return int(value)


def _enum_tuple(
    value: Any,
    enum_type: type[_EngineEnum],
    expected: tuple[_EngineEnum, ...],
    label: str,
) -> tuple[_EngineEnum, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise EngineDelegationError(f"{label} must be a canonical list")
    try:
        parsed = tuple(enum_type(item) for item in value)
    except ValueError as exc:
        raise EngineDelegationError(f"{label} contains an unsupported value") from exc
    if parsed != expected:
        raise EngineDelegationError(f"{label} does not match the reviewed v1 capability")
    return parsed


@dataclass(frozen=True, slots=True)
class EngineExecutionApprovalBinding:
    """Exact bridge into the existing one-time approval store."""

    schema_version: str
    delegation_digest: str
    attempt_binding_digest: str
    state_digest: str
    plan_digest: str
    target_scope_digest: str
    profile_id: str
    maximum_tier: str
    run_id: str
    expires_at: str

    def __post_init__(self) -> None:
        if self.schema_version != _APPROVAL_SCHEMA:
            raise EngineDelegationError("engine approval binding schema is unsupported")
        for value, label in (
            (self.delegation_digest, "delegation digest"),
            (self.attempt_binding_digest, "attempt binding digest"),
            (self.state_digest, "approval state digest"),
            (self.plan_digest, "approval plan digest"),
            (self.target_scope_digest, "approval target-scope digest"),
        ):
            _digest(value, label)
        if self.plan_digest != self.delegation_digest:
            raise EngineDelegationError("approval plan does not bind the delegation")
        expected_state = content_hash(
            {
                "schema_version": _STATE_SCHEMA,
                "delegation_digest": self.delegation_digest,
                "attempt_binding_digest": self.attempt_binding_digest,
            }
        )
        if self.state_digest != expected_state:
            raise EngineDelegationError("approval state does not bind delegation and attempt")
        if self.profile_id not in _PROFILE_BY_ENGINE.values():
            raise EngineDelegationError("engine approval profile is unsupported")
        if self.maximum_tier != _MAXIMUM_TIER:
            raise EngineDelegationError("engine approval tier is unsupported")
        if _RUN_ID.fullmatch(self.run_id) is None:
            raise EngineDelegationError("engine approval run ID is invalid")
        _timestamp(self.expires_at, "engine approval expiry")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EngineExecutionApprovalBinding":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine approval binding")
        return cls(**{name: row[name] for name in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, str]:
        return {name: str(getattr(self, name)) for name in self.__dataclass_fields__}

    def store_binding(self) -> dict[str, str]:
        """Return the fields accepted by ProductStore's one-time approval API."""

        return {
            "state_digest": self.state_digest,
            "plan_digest": self.plan_digest,
            "target_scope_digest": self.target_scope_digest,
            "profile_id": self.profile_id,
            "maximum_tier": self.maximum_tier,
        }

    def request_binding(self) -> dict[str, str]:
        """Return every binding passed when creating an approval request."""

        return {
            "run_id": self.run_id,
            **self.store_binding(),
            "expires_at": self.expires_at,
        }

    def validate_approval_record(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        """Check a pending, consumed, or claimed store record against this request."""

        if not isinstance(value, Mapping):
            raise EngineDelegationError("engine approval record is invalid")
        expected = self.request_binding()
        if any(value.get(field) != expected_value for field, expected_value in expected.items()):
            raise EngineDelegationError("engine approval record does not match the exact request")
        return value


@dataclass(frozen=True, slots=True)
class EngineCapabilityDelegation:
    """Immutable capability-level authority for one engine attempt."""

    schema_version: str
    delegation_id: str
    experiment_id: str
    attempt_id: str
    role: AttemptRole
    parent_attempt_id: str | None
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
    model_authorization_ref: str
    model_provider: str
    model_id: str
    model_data_destination: str
    operation_classes: tuple[EngineOperationClass, ...]
    effect_classes: tuple[EngineEffectClass, ...]
    network_policy_digest: str
    custody_plan_digest: str
    wall_clock_seconds: int
    action_limit: int
    cost_limit_microunits: int
    artifact_byte_limit: int
    created_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA:
            raise EngineDelegationError("engine delegation schema is unsupported")
        if _DELEGATION_ID.fullmatch(self.delegation_id) is None:
            raise EngineDelegationError("engine delegation ID is invalid")
        if _EXPERIMENT_ID.fullmatch(self.experiment_id) is None:
            raise EngineDelegationError("engine delegation experiment ID is invalid")
        if _ATTEMPT_ID.fullmatch(self.attempt_id) is None:
            raise EngineDelegationError("engine delegation attempt ID is invalid")
        if not isinstance(self.role, AttemptRole):
            raise EngineDelegationError("engine delegation role is invalid")
        if self.role is AttemptRole.BASELINE:
            if self.parent_attempt_id is not None:
                raise EngineDelegationError("baseline delegation cannot have a parent attempt")
        elif (
            self.parent_attempt_id is None
            or _ATTEMPT_ID.fullmatch(self.parent_attempt_id) is None
            or self.parent_attempt_id == self.attempt_id
        ):
            raise EngineDelegationError("adaptive delegation requires another parent attempt")
        if self.engine_id not in _PROFILE_BY_ENGINE or _ENGINE_ID.fullmatch(self.engine_id) is None:
            raise EngineDelegationError("engine is not admitted by this delegation version")
        if _REVISION.fullmatch(self.engine_revision) is None:
            raise EngineDelegationError("engine revision is invalid")
        _text(self.engine_version, "engine version", maximum=80)
        _text(self.model_id, "model ID", maximum=160)
        _text(self.model_data_destination, "model data destination", maximum=200)
        if _ENGINE_ID.fullmatch(self.model_provider) is None:
            raise EngineDelegationError("model provider is invalid")
        if _SCOPE_VERSION.fullmatch(self.scope_version) is None:
            raise EngineDelegationError("engine scope version is invalid")
        for value, label in (
            (self.objective_ref, "objective reference"),
            (self.environment_ref, "environment reference"),
            (self.target_snapshot_ref, "target snapshot reference"),
            (self.scope_ref, "scope reference"),
            (self.engine_package_digest, "engine package digest"),
            (self.policy_overlay_digest, "policy overlay digest"),
            (self.model_authorization_ref, "model authorization reference"),
            (self.network_policy_digest, "network policy digest"),
            (self.custody_plan_digest, "custody plan digest"),
        ):
            _digest(value, label)
        if self.operation_classes != _EXPECTED_OPERATIONS:
            raise EngineDelegationError("operation classes do not match the reviewed v1 capability")
        if self.effect_classes != _EXPECTED_EFFECTS:
            raise EngineDelegationError("effect classes do not match the reviewed v1 capability")
        _bounded_int(self.wall_clock_seconds, "wall-clock seconds", 1, 7_200)
        _bounded_int(self.action_limit, "action limit", 1, 512)
        _bounded_int(self.cost_limit_microunits, "cost limit", 0, 10_000_000_000)
        _bounded_int(self.artifact_byte_limit, "artifact byte limit", 1, 64 * 1024 * 1024)
        created = parse_iso8601_datetime(_timestamp(self.created_at, "delegation creation time"))
        expires = parse_iso8601_datetime(_timestamp(self.expires_at, "delegation expiry time"))
        duration = (expires - created).total_seconds()
        if duration <= 0 or duration > self.wall_clock_seconds + 600:
            raise EngineDelegationError(
                "delegation expiry is outside the attempt and cleanup bound"
            )

    @classmethod
    def create(
        cls,
        *,
        delegation_id: str,
        experiment_id: str,
        attempt_id: str,
        role: AttemptRole,
        parent_attempt_id: str | None,
        objective_ref: str,
        environment_ref: str,
        target_snapshot_ref: str,
        scope_ref: str,
        scope_version: str,
        engine_id: str,
        engine_version: str,
        engine_revision: str,
        engine_package_digest: str,
        policy_overlay_digest: str,
        model_authorization_ref: str,
        model_provider: str,
        model_id: str,
        model_data_destination: str,
        network_policy_digest: str,
        custody_plan_digest: str,
        wall_clock_seconds: int,
        action_limit: int,
        cost_limit_microunits: int,
        artifact_byte_limit: int,
        created_at: str,
        expires_at: str,
        operation_classes: Iterable[EngineOperationClass] = _EXPECTED_OPERATIONS,
        effect_classes: Iterable[EngineEffectClass] = _EXPECTED_EFFECTS,
    ) -> "EngineCapabilityDelegation":
        return cls(
            schema_version=_SCHEMA,
            delegation_id=delegation_id,
            experiment_id=experiment_id,
            attempt_id=attempt_id,
            role=role,
            parent_attempt_id=parent_attempt_id,
            objective_ref=objective_ref,
            environment_ref=environment_ref,
            target_snapshot_ref=target_snapshot_ref,
            scope_ref=scope_ref,
            scope_version=scope_version,
            engine_id=engine_id,
            engine_version=engine_version,
            engine_revision=engine_revision,
            engine_package_digest=engine_package_digest,
            policy_overlay_digest=policy_overlay_digest,
            model_authorization_ref=model_authorization_ref,
            model_provider=model_provider,
            model_id=model_id,
            model_data_destination=model_data_destination,
            operation_classes=tuple(operation_classes),
            effect_classes=tuple(effect_classes),
            network_policy_digest=network_policy_digest,
            custody_plan_digest=custody_plan_digest,
            wall_clock_seconds=wall_clock_seconds,
            action_limit=action_limit,
            cost_limit_microunits=cost_limit_microunits,
            artifact_byte_limit=artifact_byte_limit,
            created_at=created_at,
            expires_at=expires_at,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EngineCapabilityDelegation":
        row = _exact(value, frozenset(cls.__dataclass_fields__), "engine delegation")
        operations = _enum_tuple(
            row["operation_classes"],
            EngineOperationClass,
            _EXPECTED_OPERATIONS,
            "operation classes",
        )
        effects = _enum_tuple(
            row["effect_classes"],
            EngineEffectClass,
            _EXPECTED_EFFECTS,
            "effect classes",
        )
        try:
            role = AttemptRole(row["role"])
        except (TypeError, ValueError) as exc:
            raise EngineDelegationError("engine delegation role is invalid") from exc
        return cls(
            **{
                **{name: row[name] for name in cls.__dataclass_fields__},
                "role": role,
                "operation_classes": operations,
                "effect_classes": effects,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(
            json_clone(
                {
                    name: (
                        [item.value for item in value]
                        if name in {"operation_classes", "effect_classes"}
                        else value.value if isinstance(value, Enum) else value
                    )
                    for name, value in (
                        (field, getattr(self, field)) for field in self.__dataclass_fields__
                    )
                }
            )
        )

    @property
    def delegation_digest(self) -> str:
        return content_hash(self.to_dict())

    def validate_attempt_binding(
        self, binding: EngineAttemptBinding | Mapping[str, Any]
    ) -> EngineAttemptBinding:
        """Require a canonical attempt binding with exactly the delegated authority."""

        try:
            parsed = EngineAttemptBinding.from_mapping(
                binding.to_dict() if isinstance(binding, EngineAttemptBinding) else binding
            )
        except (EngineAttemptContractError, TypeError) as exc:
            raise EngineDelegationError("engine attempt binding is invalid") from exc
        expected = {
            "experiment_id": self.experiment_id,
            "attempt_id": self.attempt_id,
            "role": self.role.value,
            "parent_attempt_id": self.parent_attempt_id,
            "objective_ref": self.objective_ref,
            "environment_ref": self.environment_ref,
            "target_snapshot_ref": self.target_snapshot_ref,
            "scope_ref": self.scope_ref,
            "scope_version": self.scope_version,
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "engine_revision": self.engine_revision,
            "engine_package_digest": self.engine_package_digest,
            "policy_overlay_digest": self.policy_overlay_digest,
            "model_authorization_ref": self.model_authorization_ref,
            "model_provider": self.model_provider,
            "model_id": self.model_id,
            "model_data_destination": self.model_data_destination,
            "wall_clock_seconds": self.wall_clock_seconds,
            "action_limit": self.action_limit,
            "cost_limit_microunits": self.cost_limit_microunits,
            "artifact_byte_limit": self.artifact_byte_limit,
        }
        actual = parsed.to_dict()
        if any(actual.get(field) != expected_value for field, expected_value in expected.items()):
            raise EngineDelegationError("engine attempt binding exceeds or differs from delegation")
        created = parse_iso8601_datetime(parsed.created_at)
        if not (
            parse_iso8601_datetime(self.created_at)
            <= created
            < parse_iso8601_datetime(self.expires_at)
        ):
            raise EngineDelegationError("engine attempt binding was not created during delegation")
        return parsed

    def approval_binding(
        self, binding: EngineAttemptBinding | Mapping[str, Any]
    ) -> EngineExecutionApprovalBinding:
        parsed = self.validate_attempt_binding(binding)
        state = {
            "schema_version": _STATE_SCHEMA,
            "delegation_digest": self.delegation_digest,
            "attempt_binding_digest": parsed.binding_digest,
        }
        return EngineExecutionApprovalBinding(
            schema_version=_APPROVAL_SCHEMA,
            delegation_digest=self.delegation_digest,
            attempt_binding_digest=parsed.binding_digest,
            state_digest=content_hash(state),
            plan_digest=self.delegation_digest,
            target_scope_digest=self.scope_ref,
            profile_id=_PROFILE_BY_ENGINE[self.engine_id],
            maximum_tier=_MAXIMUM_TIER,
            run_id=parsed.run_id,
            expires_at=self.expires_at,
        )

    def validate_approval_binding(
        self,
        value: EngineExecutionApprovalBinding | Mapping[str, Any],
        binding: EngineAttemptBinding | Mapping[str, Any],
    ) -> EngineExecutionApprovalBinding:
        """Require an approval binding derived from this delegation and attempt."""

        parsed = (
            EngineExecutionApprovalBinding.from_mapping(value.to_dict())
            if isinstance(value, EngineExecutionApprovalBinding)
            else EngineExecutionApprovalBinding.from_mapping(value)
        )
        expected = self.approval_binding(binding)
        if parsed != expected:
            raise EngineDelegationError("engine approval binding does not match delegation")
        return parsed
