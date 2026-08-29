"""Bounded, provider-neutral AI proposal generation.

Providers return untrusted proposal data only.  This module never mutates a
scenario, selects execution authority, or dispatches a runner action.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from .ai_record_validation import DurableProposalRecordError, validate_v3_proposal_record
from .config import (
    AIConfig,
    AIProviderConfig,
    AIProviderKind,
    AIRedactionPolicy,
    AutonomyLevel,
)
from .runner_client import RunnerTransportError, reject_forbidden_execution_keys
from .util import canonical_json_bytes, content_hash, json_clone


class AIProviderError(ValueError):
    """Raised when an AI provider cannot produce a trustworthy proposal."""


class AIProviderTransportError(AIProviderError):
    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


class ProposalType(str, Enum):
    NO_CHANGE = "no_change"
    SELECT_REGISTERED = "select_registered"
    SELECT_NEXT_NODE = "select_next_node"
    CHANGE_PARAMETERS = "change_parameters"
    SELECT_REGISTERED_ACTION = "select_registered_action"
    RETRY_REGISTERED = "retry_registered"
    REQUEST_APPROVAL = "request_approval"
    STOP = "stop"


class ProviderHealthState(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


_STEP_ID = re.compile(r"^[a-z][a-z0-9_]*$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_CONTEXT_BYTES = 524_288
_MAX_RESPONSE_BYTES = 1_048_576
_REDACTED = "[REDACTED]"
_EVIDENCE_REDACTED = "[EVIDENCE CONTENT OMITTED]"
_OUTCOMES = frozenset({"success", "partial", "blocked", "failed"})
_PRIMITIVE_PARAMETER_TYPES = frozenset({"string", "integer", "number", "boolean"})
_MAX_PARAMETER_CHANGES = 16


MUTATING_PROPOSAL_TYPES = frozenset(
    {
        ProposalType.SELECT_REGISTERED,
        ProposalType.SELECT_NEXT_NODE,
        ProposalType.CHANGE_PARAMETERS,
        ProposalType.SELECT_REGISTERED_ACTION,
        ProposalType.RETRY_REGISTERED,
    }
)


PROPOSAL_JSON_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "schema_version": {"const": "bluefire.ai-proposal.v2"},
        "proposal_type": {
            "type": "string",
            "enum": [item.value for item in ProposalType],
        },
        "selected_step_id": {"type": ["string", "null"]},
        "selected_behavior_id": {"type": ["string", "null"]},
        "selected_action_id": {"type": ["string", "null"]},
        "selected_edge": {
            "anyOf": [
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "from_step": {"type": "string"},
                        "outcome": {
                            "type": "string",
                            "enum": sorted(_OUTCOMES),
                        },
                        "to_step": {"type": "string"},
                    },
                    "required": ["from_step", "outcome", "to_step"],
                },
                {"type": "null"},
            ]
        },
        "parameter_changes": {
            "type": "array",
            "maxItems": _MAX_PARAMETER_CHANGES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                    "value": {
                        "type": ["string", "integer", "number", "boolean"],
                    },
                },
                "required": ["name", "value"],
            },
        },
        "rationale": {"type": "string", "minLength": 1, "maxLength": 2_000},
        "alternatives": {
            "type": "array",
            "items": {"type": "string", "maxLength": 200},
            "maxItems": 12,
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "requires_operator_review": {"type": "boolean"},
    },
    "required": [
        "schema_version",
        "proposal_type",
        "selected_step_id",
        "selected_behavior_id",
        "selected_action_id",
        "selected_edge",
        "parameter_changes",
        "rationale",
        "alternatives",
        "confidence",
        "requires_operator_review",
    ],
}

_PROPOSAL_FIELDS = frozenset(PROPOSAL_JSON_SCHEMA["required"])


def _nonempty_string(value: Any, context: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise AIProviderError(f"{context} must contain 1..={maximum} characters")
    return value.strip()


def _optional_identifier(value: Any, context: str, pattern: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    result = _nonempty_string(value, context, maximum=200)
    if not pattern.fullmatch(result):
        raise AIProviderError(f"{context} is not a registered identifier shape")
    return result


def _optional_edge(value: Any, context: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {"from_step", "outcome", "to_step"}:
        raise AIProviderError(f"{context} must be one exact registered edge")
    from_step = _optional_identifier(value["from_step"], f"{context}.from_step", _STEP_ID)
    to_step = _optional_identifier(value["to_step"], f"{context}.to_step", _STEP_ID)
    outcome = value["outcome"]
    if from_step is None or to_step is None or outcome not in _OUTCOMES:
        raise AIProviderError(f"{context} must be one exact registered edge")
    return {"from_step": from_step, "outcome": str(outcome), "to_step": to_step}


def _primitive_parameter_changes(value: Any) -> tuple[tuple[str, Any], ...]:
    if not isinstance(value, list) or len(value) > _MAX_PARAMETER_CHANGES:
        raise AIProviderError(
            f"parameter_changes must be a list with at most {_MAX_PARAMETER_CHANGES} items"
        )
    changes: list[tuple[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != {"name", "value"}:
            raise AIProviderError(f"parameter_changes[{index}] must contain only name and value")
        name = _optional_identifier(item["name"], f"parameter_changes[{index}].name", _STEP_ID)
        assert name is not None
        parameter_value = item["value"]
        if isinstance(parameter_value, str):
            if len(parameter_value) > 200:
                raise AIProviderError(f"parameter_changes[{index}].value exceeds 200 characters")
        elif isinstance(parameter_value, bool):
            pass
        elif isinstance(parameter_value, int):
            if abs(parameter_value) > 9_007_199_254_740_991:
                raise AIProviderError(
                    f"parameter_changes[{index}].value exceeds the safe integer bound"
                )
        elif isinstance(parameter_value, float):
            if not math.isfinite(parameter_value):
                raise AIProviderError(f"parameter_changes[{index}].value must be finite")
        else:
            raise AIProviderError(f"parameter_changes[{index}].value must be a JSON primitive")
        changes.append((name, parameter_value))
    names = [name for name, _value in changes]
    if len(names) != len(set(names)):
        raise AIProviderError("parameter_changes contains duplicate names")
    return tuple(changes)


def _validated_parameter_schemas(
    value: Any,
    *,
    allowed_step_ids: tuple[str, ...],
) -> dict[str, dict[str, dict[str, Any]]]:
    if not isinstance(value, Mapping) or len(value) > 100:
        raise AIProviderError("allowed_parameter_schemas must be a bounded step mapping")
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for step_id, raw_parameters in value.items():
        if (
            not isinstance(step_id, str)
            or step_id not in allowed_step_ids
            or not isinstance(raw_parameters, Mapping)
            or len(raw_parameters) > _MAX_PARAMETER_CHANGES
        ):
            raise AIProviderError("allowed_parameter_schemas contains an invalid step entry")
        parameters: dict[str, dict[str, Any]] = {}
        for name, raw_schema in raw_parameters.items():
            if (
                not isinstance(name, str)
                or not _STEP_ID.fullmatch(name)
                or not isinstance(raw_schema, Mapping)
                or set(raw_schema) != {"type", "enum", "minimum", "maximum"}
            ):
                raise AIProviderError("allowed_parameter_schemas contains an invalid parameter")
            parameter_type = raw_schema["type"]
            enum = raw_schema["enum"]
            minimum = raw_schema["minimum"]
            maximum = raw_schema["maximum"]
            if parameter_type not in _PRIMITIVE_PARAMETER_TYPES:
                raise AIProviderError("AI parameters must use safe primitive schemas")
            if not isinstance(enum, list) or len(enum) > 32:
                raise AIProviderError("AI parameter enum exceeds its bound")
            if parameter_type == "string" and not enum:
                raise AIProviderError("AI string parameters require a closed enum")
            if minimum is not None and (
                isinstance(minimum, bool)
                or not isinstance(minimum, (int, float))
                or not math.isfinite(float(minimum))
            ):
                raise AIProviderError("AI parameter minimum must be finite or null")
            if maximum is not None and (
                isinstance(maximum, bool)
                or not isinstance(maximum, (int, float))
                or not math.isfinite(float(maximum))
            ):
                raise AIProviderError("AI parameter maximum must be finite or null")
            if minimum is not None and maximum is not None and minimum > maximum:
                raise AIProviderError("AI parameter minimum exceeds maximum")
            schema = {
                "type": str(parameter_type),
                "enum": json_clone(enum),
                "minimum": minimum,
                "maximum": maximum,
            }
            for index, enum_value in enumerate(enum):
                _validate_primitive_parameter(
                    enum_value,
                    schema,
                    f"allowed_parameter_schemas.{step_id}.{name}.enum[{index}]",
                    require_enum=False,
                )
            parameters[name] = schema
        result[step_id] = parameters
    return result


def _validate_primitive_parameter(
    value: Any,
    schema: Mapping[str, Any],
    context: str,
    *,
    require_enum: bool = True,
) -> None:
    parameter_type = schema["type"]
    valid = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float))
        and not isinstance(item, bool)
        and math.isfinite(float(item)),
        "boolean": lambda item: isinstance(item, bool),
    }[str(parameter_type)](value)
    if not valid:
        raise AIProviderError(f"{context} does not match its registered primitive type")
    enum = schema["enum"]
    if require_enum and enum and value not in enum:
        raise AIProviderError(f"{context} is not in its registered enum")
    if isinstance(value, str) and len(value) > 200:
        raise AIProviderError(f"{context} exceeds 200 characters")
    if parameter_type in {"integer", "number"}:
        number = float(value)
        if schema["minimum"] is not None and number < float(schema["minimum"]):
            raise AIProviderError(f"{context} is below its registered minimum")
        if schema["maximum"] is not None and number > float(schema["maximum"]):
            raise AIProviderError(f"{context} exceeds its registered maximum")


@dataclass(frozen=True, slots=True)
class AIProposal:
    schema_version: str
    proposal_id: str
    proposal_type: ProposalType
    selected_step_id: str | None
    selected_behavior_id: str | None
    selected_action_id: str | None
    selected_edge: Mapping[str, str] | None
    parameter_changes: tuple[tuple[str, Any], ...]
    rationale: str
    alternatives: tuple[str, ...]
    confidence: float
    requires_operator_review: bool

    @classmethod
    def from_mapping(cls, value: Any) -> "AIProposal":
        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise AIProviderError("AI proposal must be a JSON object")
        try:
            reject_forbidden_execution_keys(value)
        except RunnerTransportError as exc:
            raise AIProviderError("AI proposal contains forbidden executable fields") from exc
        unknown = set(value) - _PROPOSAL_FIELDS
        missing = _PROPOSAL_FIELDS - set(value)
        if unknown or missing:
            raise AIProviderError(
                f"AI proposal fields mismatch; unknown={sorted(unknown)}, missing={sorted(missing)}"
            )
        if value["schema_version"] != "bluefire.ai-proposal.v2":
            raise AIProviderError("AI proposal schema version is unsupported")
        try:
            proposal_type = ProposalType(value["proposal_type"])
        except (TypeError, ValueError) as exc:
            raise AIProviderError("AI proposal type is unsupported") from exc
        selected_step_id = _optional_identifier(
            value["selected_step_id"], "selected_step_id", _STEP_ID
        )
        selected_behavior_id = _optional_identifier(
            value["selected_behavior_id"], "selected_behavior_id", _STABLE_ID
        )
        selected_action_id = _optional_identifier(
            value["selected_action_id"], "selected_action_id", _STABLE_ID
        )
        selected_edge = _optional_edge(value["selected_edge"], "selected_edge")
        parameter_changes = _primitive_parameter_changes(value["parameter_changes"])
        if proposal_type in {
            ProposalType.NO_CHANGE,
            ProposalType.REQUEST_APPROVAL,
            ProposalType.STOP,
        } and (
            selected_edge is not None
            or parameter_changes
            or any(
                item is not None
                for item in (selected_step_id, selected_behavior_id, selected_action_id)
            )
        ):
            raise AIProviderError(f"{proposal_type.value} proposals cannot select graph objects")
        if (
            proposal_type is ProposalType.REQUEST_APPROVAL
            and value["requires_operator_review"] is not True
        ):
            raise AIProviderError("request_approval proposals must require operator review")
        if proposal_type in MUTATING_PROPOSAL_TYPES:
            if selected_step_id is None or selected_behavior_id is None:
                raise AIProviderError(
                    f"{proposal_type.value} proposals require a step and behavior"
                )
        if proposal_type is ProposalType.SELECT_REGISTERED:
            if selected_action_id is not None or selected_edge is not None or parameter_changes:
                raise AIProviderError(
                    "select_registered proposals can select only a step and behavior"
                )
        elif proposal_type is ProposalType.SELECT_NEXT_NODE:
            if selected_action_id is not None or selected_edge is None or parameter_changes:
                raise AIProviderError(
                    "select_next_node proposals require one edge and no action or parameters"
                )
            if selected_step_id != selected_edge["to_step"]:
                raise AIProviderError("selected next-node step must match selected_edge.to_step")
        elif proposal_type is ProposalType.CHANGE_PARAMETERS:
            if selected_action_id is not None or selected_edge is not None or not parameter_changes:
                raise AIProviderError(
                    "change_parameters proposals require primitive parameter changes only"
                )
        elif proposal_type is ProposalType.SELECT_REGISTERED_ACTION:
            if selected_action_id is None or selected_edge is not None or parameter_changes:
                raise AIProviderError(
                    "select_registered_action proposals require exactly one action"
                )
        elif proposal_type is ProposalType.RETRY_REGISTERED:
            if selected_action_id is not None or selected_edge is not None or parameter_changes:
                raise AIProviderError(
                    "retry_registered proposals can select only the eligible retry node"
                )
        raw_alternatives = value["alternatives"]
        if not isinstance(raw_alternatives, list) or len(raw_alternatives) > 12:
            raise AIProviderError("AI proposal alternatives must be a list with at most 12 items")
        alternatives = tuple(
            _nonempty_string(item, f"alternatives[{index}]", maximum=200)
            for index, item in enumerate(raw_alternatives)
        )
        if len(alternatives) != len(set(alternatives)):
            raise AIProviderError("AI proposal alternatives contain duplicates")
        confidence = value["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise AIProviderError("AI proposal confidence must be numeric")
        if not 0.0 <= float(confidence) <= 1.0:
            raise AIProviderError("AI proposal confidence must be between zero and one")
        review = value["requires_operator_review"]
        if not isinstance(review, bool):
            raise AIProviderError("requires_operator_review must be a boolean")
        body = dict(value)
        proposal_id = "proposal-" + content_hash(body).removeprefix("sha256:")[:20]
        return cls(
            schema_version="bluefire.ai-proposal.v2",
            proposal_id=proposal_id,
            proposal_type=proposal_type,
            selected_step_id=selected_step_id,
            selected_behavior_id=selected_behavior_id,
            selected_action_id=selected_action_id,
            selected_edge=selected_edge,
            parameter_changes=parameter_changes,
            rationale=_nonempty_string(value["rationale"], "rationale", maximum=2_000),
            alternatives=alternatives,
            confidence=float(confidence),
            requires_operator_review=review,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "proposal_type": self.proposal_type.value,
            "selected_step_id": self.selected_step_id,
            "selected_behavior_id": self.selected_behavior_id,
            "selected_action_id": self.selected_action_id,
            "selected_edge": dict(self.selected_edge) if self.selected_edge else None,
            "parameter_changes": [
                {"name": name, "value": value} for name, value in self.parameter_changes
            ],
            "rationale": self.rationale,
            "alternatives": list(self.alternatives),
            "confidence": self.confidence,
            "requires_operator_review": self.requires_operator_review,
        }

    @property
    def parameter_change_map(self) -> Mapping[str, Any]:
        return dict(self.parameter_changes)

    @classmethod
    def from_persisted_mapping(cls, value: Any) -> "AIProposal":
        if not isinstance(value, Mapping):
            raise AIProviderError("persisted AI proposal must be a JSON object")
        if set(value) != _PROPOSAL_FIELDS | {"proposal_id"}:
            raise AIProviderError("persisted AI proposal fields are mismatched")
        proposal_id = value.get("proposal_id")
        raw = {key: child for key, child in value.items() if key != "proposal_id"}
        proposal = cls.from_mapping(raw)
        if proposal_id != proposal.proposal_id:
            raise AIProviderError("persisted AI proposal identity is mismatched")
        return proposal


@dataclass(frozen=True, slots=True)
class AIProposalRequest:
    objective: str
    current_state_digest: str
    autonomy: AutonomyLevel
    allowed_step_ids: tuple[str, ...]
    allowed_behavior_ids: tuple[str, ...]
    allowed_action_ids: tuple[str, ...]
    context: Mapping[str, Any]
    allowed_edges: tuple[Mapping[str, str], ...] = ()
    allowed_parameter_schemas: Mapping[str, Mapping[str, Mapping[str, Any]]] = field(
        default_factory=dict
    )
    retryable_step_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        objective = _nonempty_string(self.objective, "objective", maximum=4_000)
        object.__setattr__(self, "objective", objective)
        if not isinstance(self.current_state_digest, str) or not _DIGEST.fullmatch(
            self.current_state_digest
        ):
            raise AIProviderError("current_state_digest must be a SHA-256 content digest")
        if not isinstance(self.autonomy, AutonomyLevel):
            raise AIProviderError("autonomy must be an AutonomyLevel")
        for label, values in (
            ("allowed_step_ids", self.allowed_step_ids),
            ("allowed_behavior_ids", self.allowed_behavior_ids),
            ("allowed_action_ids", self.allowed_action_ids),
        ):
            if not isinstance(values, tuple) or not all(isinstance(item, str) for item in values):
                raise AIProviderError(f"{label} must be a tuple of strings")
        for index, step_id in enumerate(self.allowed_step_ids):
            if not _STEP_ID.fullmatch(step_id):
                raise AIProviderError(f"allowed_step_ids[{index}] is invalid")
        for label, values in (
            ("allowed_behavior_ids", self.allowed_behavior_ids),
            ("allowed_action_ids", self.allowed_action_ids),
        ):
            for index, stable_id in enumerate(values):
                if not _STABLE_ID.fullmatch(stable_id):
                    raise AIProviderError(f"{label}[{index}] is invalid")
        for label, values in (
            ("allowed_step_ids", self.allowed_step_ids),
            ("allowed_behavior_ids", self.allowed_behavior_ids),
            ("allowed_action_ids", self.allowed_action_ids),
        ):
            if len(values) > 1_000:
                raise AIProviderError(f"{label} exceeds the 1,000-item input bound")
            if len(values) != len(set(values)):
                raise AIProviderError(f"{label} contains duplicates")
        clean_edges = tuple(
            _optional_edge(edge, f"allowed_edges[{index}]")
            for index, edge in enumerate(self.allowed_edges)
        )
        if any(edge is None for edge in clean_edges):
            raise AIProviderError("allowed_edges cannot contain null")
        normalized_edges = tuple(dict(edge) for edge in clean_edges if edge is not None)
        if len(normalized_edges) > 16:
            raise AIProviderError("allowed_edges exceeds the 16-item input bound")
        if len({canonical_json_bytes(edge) for edge in normalized_edges}) != len(normalized_edges):
            raise AIProviderError("allowed_edges contains duplicates")
        if any(edge["to_step"] not in self.allowed_step_ids for edge in normalized_edges):
            raise AIProviderError("allowed_edges contains a destination outside allowed_step_ids")
        object.__setattr__(self, "allowed_edges", normalized_edges)
        clean_schemas = _validated_parameter_schemas(
            self.allowed_parameter_schemas,
            allowed_step_ids=self.allowed_step_ids,
        )
        object.__setattr__(self, "allowed_parameter_schemas", clean_schemas)
        if (
            not isinstance(self.retryable_step_ids, tuple)
            or len(self.retryable_step_ids) > 4
            or not all(isinstance(item, str) for item in self.retryable_step_ids)
            or len(self.retryable_step_ids) != len(set(self.retryable_step_ids))
        ):
            raise AIProviderError("retryable_step_ids must be a bounded tuple of step IDs")
        if any(
            not _STEP_ID.fullmatch(step_id) or step_id not in self.allowed_step_ids
            for step_id in self.retryable_step_ids
        ):
            raise AIProviderError("retryable_step_ids contains a step outside the allowlist")
        if not isinstance(self.context, Mapping):
            raise AIProviderError("AI request context must be a JSON object")
        try:
            detached_context = json_clone(self.context)
            context_bytes = canonical_json_bytes(detached_context)
        except (TypeError, ValueError, RecursionError) as exc:
            raise AIProviderError("AI request context must contain finite JSON values") from exc
        if len(context_bytes) > _MAX_CONTEXT_BYTES:
            raise AIProviderError("AI request context exceeds the 512 KiB input bound")
        object.__setattr__(self, "context", detached_context)

    def to_dict(self, policy: AIRedactionPolicy) -> dict[str, Any]:
        return {
            "schema_version": "bluefire.ai-request.v2",
            "objective": self.objective[: policy.max_string_chars],
            "current_state_digest": self.current_state_digest,
            "autonomy": self.autonomy.value,
            "allowed_step_ids": list(self.allowed_step_ids),
            "allowed_behavior_ids": list(self.allowed_behavior_ids),
            "allowed_action_ids": list(self.allowed_action_ids),
            "allowed_edges": [dict(edge) for edge in self.allowed_edges],
            "allowed_parameter_schemas": {
                step_id: {name: dict(schema) for name, schema in parameters.items()}
                for step_id, parameters in self.allowed_parameter_schemas.items()
            },
            "retryable_step_ids": list(self.retryable_step_ids),
            "context": redact_for_model(self.context, policy),
        }

    def validate_proposal(self, proposal: AIProposal) -> None:
        if (
            self.autonomy is AutonomyLevel.OFF
            and proposal.proposal_type is not ProposalType.NO_CHANGE
        ):
            raise AIProviderError("autonomy off permits only a no-change proposal")
        if self.autonomy is AutonomyLevel.ASSIST and not proposal.requires_operator_review:
            raise AIProviderError("Assist proposals must require operator review")
        if proposal.selected_step_id and proposal.selected_step_id not in self.allowed_step_ids:
            raise AIProviderError("AI proposal selected a step outside the request allowlist")
        if (
            proposal.selected_behavior_id
            and proposal.selected_behavior_id not in self.allowed_behavior_ids
        ):
            raise AIProviderError("AI proposal selected a behavior outside the request allowlist")
        if (
            proposal.selected_action_id
            and proposal.selected_action_id not in self.allowed_action_ids
        ):
            raise AIProviderError("AI proposal selected an action outside the request allowlist")
        if proposal.selected_edge and proposal.selected_edge not in self.allowed_edges:
            raise AIProviderError("AI proposal selected an edge outside the request allowlist")
        if proposal.proposal_type is ProposalType.RETRY_REGISTERED and (
            proposal.selected_step_id not in self.retryable_step_ids
        ):
            raise AIProviderError("AI proposal selected a node outside the retry allowlist")
        if proposal.proposal_type is ProposalType.CHANGE_PARAMETERS:
            assert proposal.selected_step_id is not None
            schemas = self.allowed_parameter_schemas.get(proposal.selected_step_id)
            if not schemas:
                raise AIProviderError("AI proposal selected a node with no mutable parameters")
            for name, value in proposal.parameter_changes:
                schema = schemas.get(name)
                if schema is None:
                    raise AIProviderError("AI proposal selected an unregistered parameter")
                _validate_primitive_parameter(value, schema, f"parameter_changes.{name}")


def _validate_persisted_planner_state(
    record: Mapping[str, Any],
    *,
    state_digest: str,
    policy: Mapping[str, Any],
) -> Mapping[str, Any]:
    del state_digest, policy
    try:
        return validate_v3_proposal_record(record)
    except DurableProposalRecordError as exc:
        raise AIProviderError(str(exc)) from exc


def _persisted_list(record: Mapping[str, Any], name: str) -> list[Any]:
    value = record.get(name)
    if not isinstance(value, list):
        raise AIProviderError(f"persisted AI proposal {name} must be a JSON list")
    return value


def validate_persisted_proposal_record(record: Mapping[str, Any]) -> AIProposal:
    """Revalidate an immutable proposal record without trusting its producer."""

    try:
        if not isinstance(record, Mapping):
            raise AIProviderError("persisted AI proposal record must be a JSON object")
        state_digest = record.get("state_digest")
        if not isinstance(state_digest, str):
            raise AIProviderError("persisted AI proposal state digest is invalid")
        try:
            autonomy = AutonomyLevel(record.get("autonomy"))
        except (TypeError, ValueError) as exc:
            raise AIProviderError("persisted AI proposal autonomy is invalid") from exc
        policy = record.get("proposal_policy")
        policy_digest = record.get("proposal_policy_digest")
        if not isinstance(policy, Mapping) or policy_digest != content_hash(policy):
            raise AIProviderError("persisted AI proposal policy digest is mismatched")
        schema_version = record.get("schema_version")
        if schema_version == "bluefire.ai-proposal-record.v3":
            planner_context = _validate_persisted_planner_state(
                record,
                state_digest=state_digest,
                policy=policy,
            )
        elif schema_version == "bluefire.ai-proposal-record.v2":
            if "planner_state" in record or "planner_state_digest" in record:
                raise AIProviderError("legacy AI proposal record has ambiguous planner state")
            planner_context = {}
        else:
            raise AIProviderError("persisted AI proposal record schema is unsupported")
        proposal = AIProposal.from_persisted_mapping(record.get("proposal"))
        if schema_version == "bluefire.ai-proposal-record.v3":
            provider = record.get("provider")
            if (
                not isinstance(provider, Mapping)
                or provider.get("proposal_id") != proposal.proposal_id
            ):
                raise AIProviderError("persisted AI provider proposal identity is mismatched")
        parameter_schemas = record.get("allowed_parameter_schemas")
        if not isinstance(parameter_schemas, Mapping):
            raise AIProviderError("persisted AI parameter schemas must be a JSON object")
        request = AIProposalRequest(
            objective="Revalidate one durable adaptive proposal.",
            current_state_digest=state_digest,
            autonomy=autonomy,
            allowed_step_ids=tuple(_persisted_list(record, "allowed_step_ids")),
            allowed_behavior_ids=tuple(_persisted_list(record, "allowed_behavior_ids")),
            allowed_action_ids=tuple(_persisted_list(record, "allowed_action_ids")),
            allowed_edges=tuple(_persisted_list(record, "allowed_edges")),
            allowed_parameter_schemas=parameter_schemas,
            retryable_step_ids=tuple(_persisted_list(record, "retryable_step_ids")),
            context=planner_context,
        )
        request.validate_proposal(proposal)
        if record.get("proposal_digest") != content_hash(proposal.to_dict()):
            raise AIProviderError("persisted AI proposal digest is mismatched")
        return proposal
    except AIProviderError:
        raise
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        raise AIProviderError("persisted AI proposal record is malformed") from exc


@dataclass(frozen=True, slots=True)
class AIProviderHealth:
    provider_id: str
    state: ProviderHealthState
    credential_available: bool
    fallback_provider_id: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "state": self.state.value,
            "credential_available": self.credential_available,
            "fallback_provider_id": self.fallback_provider_id,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class AIProviderResult:
    requested_provider_id: str
    effective_provider_id: str
    model: str
    proposal: AIProposal
    response_id: str
    attempts: int
    used_fallback: bool
    fallback_reason: str | None
    usage: Mapping[str, int]

    def metadata(self) -> dict[str, Any]:
        return {
            "requested_provider_id": self.requested_provider_id,
            "effective_provider_id": self.effective_provider_id,
            "model": self.model,
            "proposal_id": self.proposal.proposal_id,
            "response_id": self.response_id,
            "attempts": self.attempts,
            "used_fallback": self.used_fallback,
            "fallback_reason": self.fallback_reason,
            "usage": dict(self.usage),
        }


@runtime_checkable
class AIProvider(Protocol):
    config: AIProviderConfig

    def health(self) -> AIProviderHealth: ...

    def propose(self, request: AIProposalRequest) -> AIProviderResult: ...


@runtime_checkable
class AIJSONTransport(Protocol):
    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibAIJSONTransport:
    """Small HTTPS transport with bounded response reads and no ambient cookies."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:  # nosec B310
                status = int(getattr(response, "status", 200))
                response_headers = getattr(response, "headers", None)
                content_type = (
                    response_headers.get_content_type()
                    if response_headers is not None
                    and hasattr(response_headers, "get_content_type")
                    else None
                )
                if content_type != "application/json":
                    raise AIProviderTransportError(
                        "Responses endpoint returned a non-JSON content type",
                        retryable=False,
                    )
                raw_payload = response.read(_MAX_RESPONSE_BYTES + 1)
                if not isinstance(raw_payload, bytes):
                    raise AIProviderTransportError(
                        "Responses endpoint returned a non-bytes body",
                        retryable=False,
                    )
                payload = raw_payload
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code <= 599
            raise AIProviderTransportError(
                f"Responses endpoint returned HTTP {exc.code}", retryable=retryable
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AIProviderTransportError(
                "Responses endpoint could not be reached", retryable=True
            ) from exc
        if not 200 <= status <= 299:
            raise AIProviderTransportError(
                f"Responses endpoint returned HTTP {status}",
                retryable=status == 429 or 500 <= status <= 599,
            )
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise AIProviderTransportError("Responses payload exceeded 1 MiB", retryable=False)
        return payload


def redact_for_model(value: Any, policy: AIRedactionPolicy, *, _key: str = "") -> Any:
    """Return a detached, bounded JSON value governed by the provider data policy."""

    normalized_key = _key.strip().casefold().replace("-", "_")
    if not policy.include_evidence_content and (
        normalized_key == "evidence"
        or normalized_key.startswith("evidence_")
        or normalized_key.endswith("_evidence")
    ):
        return _EVIDENCE_REDACTED
    if policy.enabled and any(
        normalized_key == candidate
        or normalized_key.startswith(candidate + "_")
        or normalized_key.endswith("_" + candidate)
        for candidate in policy.redact_keys
    ):
        return _REDACTED
    if isinstance(value, Mapping):
        return {
            str(key): redact_for_model(child, policy, _key=str(key)) for key, child in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_for_model(child, policy) for child in value]
    if isinstance(value, str) and len(value) > policy.max_string_chars:
        return value[: policy.max_string_chars] + "...[TRUNCATED]"
    return json_clone(value)


class DeterministicOfflineProvider:
    def __init__(self, config: AIProviderConfig) -> None:
        if config.kind is not AIProviderKind.DETERMINISTIC:
            raise AIProviderError("offline provider requires deterministic configuration")
        self.config = config

    def health(self) -> AIProviderHealth:
        return AIProviderHealth(
            provider_id=self.config.id,
            state=ProviderHealthState.READY,
            credential_available=True,
            fallback_provider_id=None,
            message="Deterministic offline provider is ready.",
        )

    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        selected = bool(request.allowed_step_ids and request.allowed_behavior_ids)
        if request.autonomy is AutonomyLevel.OFF:
            proposal_type = ProposalType.NO_CHANGE
            selected = False
            rationale = "Autonomy is off; deterministic planning remains authoritative."
        elif selected:
            proposal_type = ProposalType.SELECT_REGISTERED
            rationale = "Selected the first registered option from the deterministic allowlist."
        else:
            proposal_type = ProposalType.STOP
            rationale = "No registered graph option is available."
        raw = {
            "schema_version": "bluefire.ai-proposal.v2",
            "proposal_type": proposal_type.value,
            "selected_step_id": request.allowed_step_ids[0] if selected else None,
            "selected_behavior_id": request.allowed_behavior_ids[0] if selected else None,
            "selected_action_id": None,
            "selected_edge": None,
            "parameter_changes": [],
            "rationale": rationale,
            "alternatives": list(request.allowed_step_ids[1:4]) if selected else [],
            "confidence": 1.0,
            "requires_operator_review": request.autonomy is AutonomyLevel.ASSIST,
        }
        proposal = AIProposal.from_mapping(raw)
        request.validate_proposal(proposal)
        response_id = (
            "offline-"
            + content_hash(
                {"request": request.to_dict(self.config.redaction), "proposal": raw}
            ).removeprefix("sha256:")[:20]
        )
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            proposal=proposal,
            response_id=response_id,
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class OpenAIResponsesProvider:
    """OpenAI-compatible Responses API provider using strict Structured Outputs."""

    _INSTRUCTIONS = (
        "You are a bounded security-experiment planning assistant. Select only identifiers "
        "present in the request allowlists. Never produce commands, scripts, paths, credentials, "
        "new action IDs, target-scope changes, policy changes, or executable content. Return only "
        "the supplied strict JSON schema."
    )

    def __init__(
        self,
        config: AIProviderConfig,
        *,
        fallback: AIProvider,
        environ: Mapping[str, str] | None = None,
        transport: AIJSONTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if config.kind is not AIProviderKind.OPENAI_RESPONSES:
            raise AIProviderError("Responses provider requires openai_responses configuration")
        if fallback.config.kind is not AIProviderKind.DETERMINISTIC:
            raise AIProviderError("Responses provider fallback must be deterministic")
        self.config = config
        self.fallback = fallback
        self.environ = os.environ if environ is None else environ
        self.transport = transport or UrllibAIJSONTransport()
        self.sleeper = sleeper

    def health(self) -> AIProviderHealth:
        credential_available = bool(self._api_key())
        return AIProviderHealth(
            provider_id=self.config.id,
            state=(
                ProviderHealthState.READY if credential_available else ProviderHealthState.DEGRADED
            ),
            credential_available=credential_available,
            fallback_provider_id=self.fallback.config.id,
            message=(
                "Responses provider is configured."
                if credential_available
                else "Credential reference is unset; deterministic fallback will be used."
            ),
        )

    def build_request(self, request: AIProposalRequest) -> Mapping[str, Any]:
        return {
            "model": self.config.model,
            "instructions": self._INSTRUCTIONS,
            "input": canonical_json_bytes(request.to_dict(self.config.redaction)).decode("utf-8"),
            "max_output_tokens": self.config.max_output_tokens,
            "store": False,
            "parallel_tool_calls": False,
            "tools": [],
            "tool_choice": "none",
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "bluefire_ai_proposal",
                    "strict": True,
                    "schema": json_clone(PROPOSAL_JSON_SCHEMA),
                }
            },
        }

    def propose(self, request: AIProposalRequest) -> AIProviderResult:
        api_key = self._api_key()
        if not api_key:
            return self._fallback(request, attempts=0, reason="credential_unavailable")
        body = canonical_json_bytes(self.build_request(request))
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "bluefire-nexus/0.1",
        }
        attempts = 0
        last_error: AIProviderError | None = None
        for attempt in range(self.config.max_retries + 1):
            attempts += 1
            try:
                payload = self.transport.post(
                    str(self.config.endpoint),
                    headers=headers,
                    body=body,
                    timeout_seconds=float(self.config.timeout_seconds),
                )
                return self._parse_response(payload, request, attempts=attempts)
            except AIProviderTransportError as exc:
                last_error = exc
                if not exc.retryable or attempt >= self.config.max_retries:
                    break
                self.sleeper(min(0.25 * (2**attempt), 2.0))
            except AIProviderError as exc:
                last_error = exc
                break
        reason = (
            "transport_failed"
            if isinstance(last_error, AIProviderTransportError)
            else "response_invalid"
        )
        return self._fallback(request, attempts=attempts, reason=reason)

    def _parse_response(
        self,
        payload: bytes,
        request: AIProposalRequest,
        *,
        attempts: int,
    ) -> AIProviderResult:
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise AIProviderError("Responses payload exceeded 1 MiB")
        response = _strict_json_object(payload, "Responses payload")
        if response.get("status") != "completed" or response.get("error") is not None:
            raise AIProviderError("Responses request did not complete successfully")
        response_id = _nonempty_string(response.get("id"), "response.id", maximum=200)
        model = _nonempty_string(response.get("model"), "response.model", maximum=200)
        output_text = _response_output_text(response)
        proposal_doc = _strict_json_object(output_text.encode("utf-8"), "structured output")
        proposal = AIProposal.from_mapping(proposal_doc)
        request.validate_proposal(proposal)
        usage = _usage(response.get("usage"), self.config.max_output_tokens)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=model,
            proposal=proposal,
            response_id=response_id,
            attempts=attempts,
            used_fallback=False,
            fallback_reason=None,
            usage=usage,
        )

    def _fallback(
        self,
        request: AIProposalRequest,
        *,
        attempts: int,
        reason: str,
    ) -> AIProviderResult:
        result = self.fallback.propose(request)
        return AIProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=result.effective_provider_id,
            model=result.model,
            proposal=result.proposal,
            response_id=result.response_id,
            attempts=attempts + result.attempts,
            used_fallback=True,
            fallback_reason=reason,
            usage=result.usage,
        )

    def _api_key(self) -> str:
        if self.config.api_key is None:
            return ""
        value = self.environ.get(self.config.api_key.env, "")
        if not isinstance(value, str):
            return ""
        value = value.strip()
        if (
            not value
            or len(value) > 4_096
            or any(not 33 <= ord(character) <= 126 for character in value)
        ):
            return ""
        return value


def build_ai_provider(
    config: AIConfig,
    *,
    provider_id: str | None = None,
    environ: Mapping[str, str] | None = None,
    transport: AIJSONTransport | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> AIProvider:
    selected = config.provider(provider_id)
    if selected.kind is AIProviderKind.DETERMINISTIC:
        return DeterministicOfflineProvider(selected)
    fallback = DeterministicOfflineProvider(config.fallback)
    return OpenAIResponsesProvider(
        selected,
        fallback=fallback,
        environ=environ,
        transport=transport,
        sleeper=sleeper,
    )


def ai_runtime_metadata(
    config: AIConfig,
    *,
    autonomy: AutonomyLevel,
    provider_id: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Mapping[str, Any]:
    provider = build_ai_provider(config, provider_id=provider_id, environ=environ)
    application = {
        AutonomyLevel.OFF: "deterministic_only",
        AutonomyLevel.ASSIST: "operator_review_required",
        AutonomyLevel.AUTO: "schema_policy_validated_only",
    }[autonomy]
    return {
        "schema_version": "bluefire.ai-runtime.v1",
        "autonomy": autonomy.value,
        "enabled": autonomy is not AutonomyLevel.OFF,
        "provider": provider.config.runtime_metadata(),
        "health": provider.health().to_dict(),
        "proposal_application": application,
        "trust_boundary": "proposal_schema_then_deterministic_policy",
    }


def _strict_json_object(payload: bytes, label: str) -> Mapping[str, Any]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AIProviderError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AIProviderError(f"{label} must be a JSON object")
    return value


def _response_output_text(response: Mapping[str, Any]) -> str:
    direct = response.get("output_text")
    direct_text = direct if isinstance(direct, str) and direct else None
    extracted: list[str] = []
    output = response.get("output")
    if output is not None:
        if not isinstance(output, list) or len(output) != 1:
            raise AIProviderError("response.output must contain exactly one message")
        item = output[0]
        if not isinstance(item, Mapping) or item.get("type") != "message":
            raise AIProviderError("response.output contains a non-message item")
        content = item.get("content")
        if not isinstance(content, list) or len(content) != 1:
            raise AIProviderError("response message must contain exactly one output block")
        block = content[0]
        if not isinstance(block, Mapping) or block.get("type") != "output_text":
            raise AIProviderError("response message contains a non-text output block")
        text = block.get("text")
        if not isinstance(text, str) or not text:
            raise AIProviderError("response output_text block is invalid")
        extracted.append(text)
    if direct_text and extracted and direct_text != extracted[0]:
        raise AIProviderError("response output_text fields disagree")
    selected = direct_text or (extracted[0] if extracted else None)
    if selected is None:
        raise AIProviderError("response contains no structured output text")
    return selected


def _usage(value: Any, max_output_tokens: int) -> Mapping[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AIProviderError("response.usage must be an object")
    result: dict[str, int] = {}
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        raw = value.get(name)
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise AIProviderError(f"response.usage.{name} must be a non-negative integer")
        result[name] = raw
    if result.get("output_tokens", 0) > max_output_tokens:
        raise AIProviderError("response exceeded the configured output-token budget")
    return result


__all__ = [
    "AIJSONTransport",
    "AIProposal",
    "AIProposalRequest",
    "AIProvider",
    "AIProviderError",
    "AIProviderHealth",
    "AIProviderResult",
    "AIProviderTransportError",
    "DeterministicOfflineProvider",
    "MUTATING_PROPOSAL_TYPES",
    "OpenAIResponsesProvider",
    "PROPOSAL_JSON_SCHEMA",
    "ProposalType",
    "ProviderHealthState",
    "validate_persisted_proposal_record",
    "UrllibAIJSONTransport",
    "ai_runtime_metadata",
    "build_ai_provider",
    "redact_for_model",
]
