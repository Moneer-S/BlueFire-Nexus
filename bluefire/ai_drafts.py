"""Bounded natural-language objective to unsaved typed graph drafting.

Model output is an untrusted graph sketch. It can select only behavior IDs and
primitive parameter values from a request-specific allowlist. Scenario identity,
artifact bindings, provenance, audit metadata, and all execution authority stay
deterministic and outside the model boundary.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

from .ai import (
    AIJSONTransport,
    AIProviderError,
    AIProviderHealth,
    AIProviderTransportError,
    ProviderHealthState,
    UrllibAIJSONTransport,
    redact_for_model,
)
from .config import AIConfig, AIProviderConfig, AIProviderKind, AIRedactionPolicy
from .contracts import (
    BehaviorDefinition,
    ContractError,
    ExecutionState,
    ParameterSpec,
    ParameterType,
    ScenarioDefinition,
    StepOutcome,
)
from .registry import BehaviorRegistry, RegistryError
from .runner_client import RunnerTransportError, reject_forbidden_execution_keys
from .util import canonical_json_bytes, content_hash, json_clone

_STEP_ID = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_MAX_OBJECTIVE_CHARS = 4_000
_MAX_NODES = 16
_MAX_EDGES = 32
_MAX_CATALOG_BEHAVIORS = 256
_MAX_REQUEST_BYTES = 512 * 1024
_MAX_PROVIDER_REQUEST_BYTES = 1024 * 1024
_MAX_DRAFT_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_RESULT_BYTES = 512 * 1024
_MAX_PARAMETERS_PER_STEP = 16
_MAX_PARAMETER_STRING = 500
_MAX_ASSUMPTIONS = 16
_MAX_ASSUMPTION_CHARS = 500
_PRIMITIVE_PARAMETER_TYPES = frozenset(
    {
        ParameterType.STRING,
        ParameterType.INTEGER,
        ParameterType.NUMBER,
        ParameterType.BOOLEAN,
    }
)
_FORBIDDEN_PARAMETER_SEGMENTS = frozenset(
    {
        "action",
        "approval",
        "binary",
        "cmd",
        "command",
        "directory",
        "executable",
        "file",
        "mode",
        "path",
        "payload",
        "policy",
        "profile",
        "runner",
        "scope",
        "script",
        "shell",
        "target",
    }
)
_TOKEN_STOPWORDS = frozenset(
    {
        "and",
        "bluefire",
        "bounded",
        "experiment",
        "inside",
        "only",
        "runner",
        "sandbox",
        "that",
        "the",
        "then",
        "this",
        "with",
    }
)


class AIDraftError(AIProviderError):
    """Raised when a draft request or untrusted graph violates its boundary."""


def _strict_json_object(payload: bytes, context: str) -> Mapping[str, Any]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite value: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AIDraftError(f"{context} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AIDraftError(f"{context} must be a JSON object")
    return value


def _bounded_string(value: Any, context: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise AIDraftError(f"{context} must contain 1..={maximum} characters")
    return value.strip()


def _bounded_int(value: Any, context: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AIDraftError(f"{context} must be between {minimum} and {maximum}")
    return int(value)


def _path_like(value: str) -> bool:
    text = value.strip()
    return bool(
        text.startswith(("/", "\\", "~/", ".\\", "../", "..\\"))
        or re.match(r"^[A-Za-z]:[\\/]", text)
        or "://" in text
        or "/" in text
        or "\\" in text
    )


def _safe_parameter_name(name: str) -> bool:
    segments = {part for part in re.split(r"[^a-z0-9]+", name.casefold()) if part}
    return not bool(segments & _FORBIDDEN_PARAMETER_SEGMENTS)


def _safe_parameter_spec(spec: ParameterSpec) -> bool:
    if (
        spec.type not in _PRIMITIVE_PARAMETER_TYPES
        or not _safe_parameter_name(spec.name)
        or (isinstance(spec.default, str) and _path_like(spec.default))
        or any(isinstance(item, str) and _path_like(item) for item in spec.enum)
    ):
        return False
    return True


def draftable_behavior_catalog(registry: BehaviorRegistry) -> tuple[Mapping[str, Any], ...]:
    """Return a model-safe catalog with no action or execution-authority fields."""

    result: list[Mapping[str, Any]] = []
    for behavior_id in registry.behavior_ids:
        behavior = registry.get_behavior(behavior_id)
        if behavior.execution_state is ExecutionState.METADATA_ONLY:
            continue
        if len(behavior.parameters) > _MAX_PARAMETERS_PER_STEP or any(
            not _safe_parameter_spec(spec) for spec in behavior.parameters
        ):
            continue
        result.append(
            {
                "id": behavior.id,
                "title": behavior.title,
                "purpose": behavior.purpose,
                "inputs": [
                    {
                        "name": spec.name,
                        "type": spec.type,
                        "required": spec.required,
                        "multiple": spec.multiple,
                    }
                    for spec in behavior.inputs
                ],
                "outputs": [
                    {
                        "name": spec.name,
                        "type": spec.type,
                        "multiple": spec.multiple,
                    }
                    for spec in behavior.outputs
                ],
                "parameters": [spec.to_dict() for spec in behavior.parameters],
            }
        )
    if not result:
        raise AIDraftError("no registered non-metadata behaviors are draftable")
    if len(result) > _MAX_CATALOG_BEHAVIORS:
        raise AIDraftError("draftable behavior catalog exceeds its item bound")
    detached = json_clone(result)
    if not isinstance(detached, list):  # pragma: no cover - json_clone invariant
        raise AssertionError("draft behavior catalog did not remain a list")
    return tuple(detached)


@dataclass(frozen=True, slots=True)
class AIGraphDraftRequest:
    objective: str
    behavior_catalog: tuple[Mapping[str, Any], ...]
    max_nodes: int = 8
    max_edges: int = 16

    def __post_init__(self) -> None:
        objective = _bounded_string(self.objective, "draft objective", maximum=_MAX_OBJECTIVE_CHARS)
        max_nodes = _bounded_int(self.max_nodes, "max_nodes", minimum=1, maximum=_MAX_NODES)
        max_edges = _bounded_int(self.max_edges, "max_edges", minimum=0, maximum=_MAX_EDGES)
        if (
            not isinstance(self.behavior_catalog, tuple)
            or not 1 <= len(self.behavior_catalog) <= _MAX_CATALOG_BEHAVIORS
        ):
            raise AIDraftError("behavior_catalog must be a bounded non-empty tuple")
        catalog = tuple(_validate_behavior_descriptor(row) for row in self.behavior_catalog)
        ids = tuple(str(row["id"]) for row in catalog)
        if len(ids) != len(set(ids)):
            raise AIDraftError("behavior_catalog contains duplicate IDs")
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "max_nodes", max_nodes)
        object.__setattr__(self, "max_edges", max_edges)
        object.__setattr__(self, "behavior_catalog", catalog)
        if len(canonical_json_bytes(self.to_dict(AIRedactionPolicy()))) > _MAX_REQUEST_BYTES:
            raise AIDraftError("AI graph draft request exceeds the 512 KiB bound")

    @classmethod
    def from_registry(
        cls,
        *,
        objective: str,
        registry: BehaviorRegistry,
        max_nodes: int = 8,
        max_edges: int = 16,
    ) -> "AIGraphDraftRequest":
        return cls(
            objective=objective,
            behavior_catalog=draftable_behavior_catalog(registry),
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    @property
    def request_id(self) -> str:
        digest = content_hash(
            {
                "objective": self.objective,
                "allowed_behavior_ids": list(self.allowed_behavior_ids),
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
            }
        )
        return "ai-draft-request-" + digest.removeprefix("sha256:")[:20]

    @property
    def allowed_behavior_ids(self) -> tuple[str, ...]:
        return tuple(str(row["id"]) for row in self.behavior_catalog)

    def to_dict(self, policy: AIRedactionPolicy) -> Mapping[str, Any]:
        return {
            "schema_version": "bluefire.ai-graph-draft-request.v1",
            "request_id": self.request_id,
            "objective": redact_for_model(self.objective, policy, _key="objective"),
            "bounds": {"max_nodes": self.max_nodes, "max_edges": self.max_edges},
            "allowed_behaviors": redact_for_model(
                list(self.behavior_catalog), policy, _key="allowed_behaviors"
            ),
        }


def _validate_behavior_descriptor(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "id",
        "title",
        "purpose",
        "inputs",
        "outputs",
        "parameters",
    }:
        raise AIDraftError("behavior_catalog contains an invalid descriptor")
    behavior_id = _bounded_string(value.get("id"), "behavior ID", maximum=200)
    if not _STABLE_ID.fullmatch(behavior_id):
        raise AIDraftError("behavior_catalog contains an invalid behavior ID")
    title = _bounded_string(value.get("title"), f"{behavior_id}.title", maximum=300)
    purpose = _bounded_string(value.get("purpose"), f"{behavior_id}.purpose", maximum=2_000)
    inputs = _validate_artifact_descriptors(value.get("inputs"), f"{behavior_id}.inputs", True)
    outputs = _validate_artifact_descriptors(value.get("outputs"), f"{behavior_id}.outputs", False)
    raw_parameters = value.get("parameters")
    if not isinstance(raw_parameters, list) or len(raw_parameters) > _MAX_PARAMETERS_PER_STEP:
        raise AIDraftError(f"{behavior_id}.parameters exceeds its bound")
    parameters: list[Mapping[str, Any]] = []
    for index, row in enumerate(raw_parameters):
        try:
            spec = ParameterSpec.from_mapping(row, f"{behavior_id}.parameters[{index}]")
        except ContractError as exc:
            raise AIDraftError(str(exc)) from exc
        if not _safe_parameter_spec(spec):
            raise AIDraftError(f"{behavior_id} exposes a non-primitive or authority-like parameter")
        parameters.append(spec.to_dict())
    return {
        "id": behavior_id,
        "title": title,
        "purpose": purpose,
        "inputs": inputs,
        "outputs": outputs,
        "parameters": parameters,
    }


def _validate_artifact_descriptors(value: Any, context: str, include_required: bool) -> list[Any]:
    if not isinstance(value, list) or len(value) > 32:
        raise AIDraftError(f"{context} must be a bounded list")
    expected = {"name", "type", "multiple"} | ({"required"} if include_required else set())
    result: list[Mapping[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != expected:
            raise AIDraftError(f"{context} contains an invalid artifact descriptor")
        name = _bounded_string(row.get("name"), f"{context}.name", maximum=100)
        artifact_type = _bounded_string(row.get("type"), f"{context}.type", maximum=200)
        multiple = row.get("multiple")
        if not isinstance(multiple, bool):
            raise AIDraftError(f"{context}.multiple must be boolean")
        item: dict[str, Any] = {"name": name, "type": artifact_type, "multiple": multiple}
        if include_required:
            required = row.get("required")
            if not isinstance(required, bool):
                raise AIDraftError(f"{context}.required must be boolean")
            item["required"] = required
        result.append(item)
    return result


@dataclass(frozen=True, slots=True)
class AIDraftStep:
    id: str
    behavior_id: str
    parameters: Mapping[str, str | int | float | bool]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "behavior_id": self.behavior_id,
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class AIDraftEdge:
    from_step: str
    outcome: StepOutcome
    to_step: str

    def to_dict(self) -> dict[str, str]:
        return {
            "from_step": self.from_step,
            "outcome": self.outcome.value,
            "to_step": self.to_step,
        }


@dataclass(frozen=True, slots=True)
class AIGraphDraftCandidate:
    schema_version: str
    title: str
    purpose: str
    start: str
    steps: tuple[AIDraftStep, ...]
    edges: tuple[AIDraftEdge, ...]
    rationale: str
    assumptions: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any, request: AIGraphDraftRequest) -> "AIGraphDraftCandidate":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "title",
            "purpose",
            "start",
            "steps",
            "edges",
            "rationale",
            "assumptions",
        }:
            raise AIDraftError("AI graph draft fields do not match the strict contract")
        try:
            reject_forbidden_execution_keys(value)
        except RunnerTransportError as exc:
            raise AIDraftError("AI graph draft contains executable fields") from exc
        try:
            detached = json_clone(value)
            encoded = canonical_json_bytes(detached)
        except (TypeError, ValueError, RecursionError) as exc:
            raise AIDraftError("AI graph draft must contain finite JSON values") from exc
        if len(encoded) > _MAX_DRAFT_BYTES:
            raise AIDraftError("AI graph draft exceeds the 256 KiB output bound")
        if value.get("schema_version") != "bluefire.ai-graph-draft.v1":
            raise AIDraftError("AI graph draft schema version is unsupported")
        title = _bounded_string(value.get("title"), "draft title", maximum=200)
        purpose = _bounded_string(value.get("purpose"), "draft purpose", maximum=2_000)
        start = _bounded_string(value.get("start"), "draft start", maximum=100)
        if not _STEP_ID.fullmatch(start):
            raise AIDraftError("draft start is not a valid step ID")
        catalog = {str(row["id"]): row for row in request.behavior_catalog}
        raw_steps = value.get("steps")
        if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= request.max_nodes:
            raise AIDraftError("draft steps exceed the requested node bound")
        steps: list[AIDraftStep] = []
        for index, row in enumerate(raw_steps):
            if not isinstance(row, Mapping) or set(row) != {"id", "behavior_id", "parameters"}:
                raise AIDraftError(f"draft.steps[{index}] fields are invalid")
            step_id = _bounded_string(row.get("id"), f"draft.steps[{index}].id", maximum=100)
            if not _STEP_ID.fullmatch(step_id):
                raise AIDraftError(f"draft.steps[{index}].id is invalid")
            behavior_id = _bounded_string(
                row.get("behavior_id"), f"draft.steps[{index}].behavior_id", maximum=200
            )
            descriptor = catalog.get(behavior_id)
            if descriptor is None:
                raise AIDraftError("AI graph draft selected a behavior outside the allowlist")
            parameters = _draft_parameters(
                row.get("parameters"), descriptor, f"draft.steps[{index}].parameters"
            )
            steps.append(AIDraftStep(step_id, behavior_id, parameters))
        step_ids = [step.id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise AIDraftError("AI graph draft contains duplicate step IDs")
        if start not in step_ids:
            raise AIDraftError("AI graph draft start does not identify a step")
        raw_edges = value.get("edges")
        if not isinstance(raw_edges, list) or len(raw_edges) > request.max_edges:
            raise AIDraftError("draft edges exceed the requested edge bound")
        edges: list[AIDraftEdge] = []
        for index, row in enumerate(raw_edges):
            if not isinstance(row, Mapping) or set(row) != {
                "from_step",
                "outcome",
                "to_step",
            }:
                raise AIDraftError(f"draft.edges[{index}] fields are invalid")
            source = _bounded_string(
                row.get("from_step"), f"draft.edges[{index}].from_step", maximum=100
            )
            target = _bounded_string(
                row.get("to_step"), f"draft.edges[{index}].to_step", maximum=100
            )
            try:
                outcome = StepOutcome(row.get("outcome"))
            except (TypeError, ValueError) as exc:
                raise AIDraftError(f"draft.edges[{index}].outcome is invalid") from exc
            edges.append(AIDraftEdge(source, outcome, target))
        assumptions = _string_list(
            value.get("assumptions"),
            "draft assumptions",
            maximum_items=_MAX_ASSUMPTIONS,
            maximum_chars=_MAX_ASSUMPTION_CHARS,
        )
        return cls(
            schema_version="bluefire.ai-graph-draft.v1",
            title=title,
            purpose=purpose,
            start=start,
            steps=tuple(steps),
            edges=tuple(edges),
            rationale=_bounded_string(value.get("rationale"), "draft rationale", maximum=4_000),
            assumptions=assumptions,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "title": self.title,
            "purpose": self.purpose,
            "start": self.start,
            "steps": [step.to_dict() for step in self.steps],
            "edges": [edge.to_dict() for edge in self.edges],
            "rationale": self.rationale,
            "assumptions": list(self.assumptions),
        }


def _draft_parameters(
    value: Any, descriptor: Mapping[str, Any], context: str
) -> Mapping[str, str | int | float | bool]:
    if not isinstance(value, Mapping) or len(value) > _MAX_PARAMETERS_PER_STEP:
        raise AIDraftError(f"{context} must be a bounded object")
    raw_specs = descriptor.get("parameters")
    if not isinstance(raw_specs, list):
        raise AIDraftError("behavior descriptor parameters are invalid")
    specs: dict[str, ParameterSpec] = {}
    for index, raw_spec in enumerate(raw_specs):
        try:
            spec = ParameterSpec.from_mapping(raw_spec, f"{context}.spec[{index}]")
        except ContractError as exc:
            raise AIDraftError(str(exc)) from exc
        specs[spec.name] = spec
    if set(value) != set(specs):
        raise AIDraftError(f"{context} must contain exactly the registered primitive parameters")
    result: dict[str, str | int | float | bool] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not _safe_parameter_name(name):
            raise AIDraftError(f"{context} contains an authority-like parameter")
        if isinstance(raw, str) and (
            not raw or len(raw) > _MAX_PARAMETER_STRING or "\x00" in raw or _path_like(raw)
        ):
            raise AIDraftError(f"{context}.{name} contains an invalid or path-like value")
        if isinstance(raw, bool):
            primitive: str | int | float | bool = raw
        elif isinstance(raw, int):
            primitive = raw
        elif isinstance(raw, float) and math.isfinite(raw):
            primitive = raw
        elif isinstance(raw, str):
            primitive = raw
        else:
            raise AIDraftError(f"{context}.{name} must be a finite JSON primitive")
        try:
            specs[name].validate_value(primitive, f"{context}.{name}")
        except ContractError as exc:
            raise AIDraftError(str(exc)) from exc
        result[name] = primitive
    return dict(sorted(result.items()))


def _string_list(
    value: Any, context: str, *, maximum_items: int, maximum_chars: int
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise AIDraftError(f"{context} exceeds its item bound")
    result = tuple(
        _bounded_string(item, f"{context}[{index}]", maximum=maximum_chars)
        for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise AIDraftError(f"{context} contains duplicates")
    return result


def graph_draft_json_schema(request: AIGraphDraftRequest) -> Mapping[str, Any]:
    step_variants: list[Mapping[str, Any]] = []
    for descriptor in request.behavior_catalog:
        properties: dict[str, Any] = {}
        required: list[str] = []
        raw_parameters = descriptor["parameters"]
        if not isinstance(raw_parameters, list):  # pragma: no cover - request invariant
            raise AssertionError("validated descriptor parameters changed type")
        for raw_spec in raw_parameters:
            spec = ParameterSpec.from_mapping(raw_spec)
            properties[spec.name] = _parameter_json_schema(spec)
            required.append(spec.name)
        step_variants.append(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "pattern": _STEP_ID.pattern},
                    "behavior_id": {"const": descriptor["id"]},
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": properties,
                        "required": required,
                    },
                },
                "required": ["id", "behavior_id", "parameters"],
            }
        )
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"const": "bluefire.ai-graph-draft.v1"},
            "title": {"type": "string", "minLength": 1, "maxLength": 200},
            "purpose": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "start": {"type": "string", "pattern": _STEP_ID.pattern},
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": request.max_nodes,
                "items": {"anyOf": step_variants},
            },
            "edges": {
                "type": "array",
                "maxItems": request.max_edges,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "from_step": {"type": "string", "pattern": _STEP_ID.pattern},
                        "outcome": {
                            "type": "string",
                            "enum": [item.value for item in StepOutcome],
                        },
                        "to_step": {"type": "string", "pattern": _STEP_ID.pattern},
                    },
                    "required": ["from_step", "outcome", "to_step"],
                },
            },
            "rationale": {"type": "string", "minLength": 1, "maxLength": 4_000},
            "assumptions": {
                "type": "array",
                "maxItems": _MAX_ASSUMPTIONS,
                "items": {"type": "string", "minLength": 1, "maxLength": 500},
            },
        },
        "required": [
            "schema_version",
            "title",
            "purpose",
            "start",
            "steps",
            "edges",
            "rationale",
            "assumptions",
        ],
    }


def _parameter_json_schema(spec: ParameterSpec) -> Mapping[str, Any]:
    schema: dict[str, Any] = {
        "type": {
            ParameterType.STRING: "string",
            ParameterType.INTEGER: "integer",
            ParameterType.NUMBER: "number",
            ParameterType.BOOLEAN: "boolean",
        }[spec.type]
    }
    if spec.type is ParameterType.STRING:
        schema["maxLength"] = _MAX_PARAMETER_STRING
    if spec.enum:
        schema["enum"] = list(spec.enum)
    if spec.minimum is not None:
        schema["minimum"] = spec.minimum
    if spec.maximum is not None:
        schema["maximum"] = spec.maximum
    return schema


@dataclass(frozen=True, slots=True)
class AIDraftProviderResult:
    requested_provider_id: str
    effective_provider_id: str
    model: str
    draft: AIGraphDraftCandidate
    response_id: str
    attempts: int
    used_fallback: bool
    fallback_reason: str | None
    usage: Mapping[str, int]

    def metadata(self) -> Mapping[str, Any]:
        return {
            "requested_provider_id": self.requested_provider_id,
            "effective_provider_id": self.effective_provider_id,
            "model": self.model,
            "response_id": self.response_id,
            "attempts": self.attempts,
            "used_fallback": self.used_fallback,
            "fallback_reason": self.fallback_reason,
            "usage": dict(self.usage),
        }


@runtime_checkable
class AIDraftProvider(Protocol):
    config: AIProviderConfig

    def health(self) -> AIProviderHealth: ...

    def draft(self, request: AIGraphDraftRequest) -> AIDraftProviderResult: ...


class DeterministicOfflineDraftProvider:
    def __init__(self, config: AIProviderConfig) -> None:
        if config.kind is not AIProviderKind.DETERMINISTIC:
            raise AIDraftError("offline draft provider requires deterministic configuration")
        self.config = config

    def health(self) -> AIProviderHealth:
        return AIProviderHealth(
            provider_id=self.config.id,
            state=ProviderHealthState.READY,
            credential_available=True,
            fallback_provider_id=None,
            message="Deterministic offline graph drafting is ready.",
        )

    def draft(self, request: AIGraphDraftRequest) -> AIDraftProviderResult:
        raw = _offline_graph(request)
        candidate = AIGraphDraftCandidate.from_mapping(raw, request)
        response_id = (
            "offline-draft-"
            + content_hash(
                {"request": request.to_dict(self.config.redaction), "draft": candidate.to_dict()}
            ).removeprefix("sha256:")[:20]
        )
        return AIDraftProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=self.config.model,
            draft=candidate,
            response_id=response_id,
            attempts=1,
            used_fallback=False,
            fallback_reason=None,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )


class OpenAIResponsesDraftProvider:
    """Responses structured-output adapter for untrusted graph sketches."""

    _INSTRUCTIONS = (
        "Draft an unsaved BlueFire scenario sketch for the objective. Select only behavior IDs "
        "and primitive parameter values present in allowed_behaviors. Return nodes and outcome "
        "edges only. Never emit actions, commands, scripts, payloads, paths, artifact bindings, "
        "alternates, runner profiles, target scope, approvals, execution mode, or policy. BlueFire "
        "will derive identity, inputs, provenance, and authority and will reject invalid output. "
        "Return only the supplied strict JSON schema."
    )

    def __init__(
        self,
        config: AIProviderConfig,
        *,
        fallback: DeterministicOfflineDraftProvider,
        environ: Mapping[str, str] | None = None,
        transport: AIJSONTransport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if config.kind is not AIProviderKind.OPENAI_RESPONSES:
            raise AIDraftError("Responses draft provider requires openai_responses configuration")
        self.config = config
        self.fallback = fallback
        self.environ = os.environ if environ is None else environ
        self.transport = transport or UrllibAIJSONTransport()
        self.sleeper = sleeper

    def health(self) -> AIProviderHealth:
        ready = bool(self._api_key())
        return AIProviderHealth(
            provider_id=self.config.id,
            state=ProviderHealthState.READY if ready else ProviderHealthState.DEGRADED,
            credential_available=ready,
            fallback_provider_id=self.fallback.config.id,
            message=(
                "Responses graph drafting is configured."
                if ready
                else "Credential reference is unset; deterministic graph drafting will be used."
            ),
        )

    def build_request(self, request: AIGraphDraftRequest) -> Mapping[str, Any]:
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
                    "name": "bluefire_ai_graph_draft",
                    "strict": True,
                    "schema": json_clone(graph_draft_json_schema(request)),
                }
            },
        }

    def draft(self, request: AIGraphDraftRequest) -> AIDraftProviderResult:
        api_key = self._api_key()
        if not api_key:
            return self._fallback(request, attempts=0, reason="credential_unavailable")
        body = canonical_json_bytes(self.build_request(request))
        if len(body) > _MAX_PROVIDER_REQUEST_BYTES:
            raise AIDraftError("Responses graph draft request exceeds the 1 MiB bound")
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
                return self._parse_response(payload, request, attempts)
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
        self, payload: bytes, request: AIGraphDraftRequest, attempts: int
    ) -> AIDraftProviderResult:
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise AIDraftError("Responses payload exceeds the one-megabyte bound")
        response = _strict_json_object(payload, "Responses payload")
        if response.get("status") != "completed" or response.get("error") is not None:
            raise AIDraftError("Responses graph draft did not complete")
        response_id = _bounded_string(response.get("id"), "response.id", maximum=200)
        model = _bounded_string(response.get("model"), "response.model", maximum=200)
        output_text = _response_output_text(response)
        raw = _strict_json_object(output_text.encode("utf-8"), "structured graph draft")
        draft = AIGraphDraftCandidate.from_mapping(raw, request)
        usage = _usage(response.get("usage"), self.config.max_output_tokens)
        return AIDraftProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=self.config.id,
            model=model,
            draft=draft,
            response_id=response_id,
            attempts=attempts,
            used_fallback=False,
            fallback_reason=None,
            usage=usage,
        )

    def _fallback(
        self, request: AIGraphDraftRequest, *, attempts: int, reason: str
    ) -> AIDraftProviderResult:
        fallback = self.fallback.draft(request)
        return AIDraftProviderResult(
            requested_provider_id=self.config.id,
            effective_provider_id=fallback.effective_provider_id,
            model=fallback.model,
            draft=fallback.draft,
            response_id=fallback.response_id,
            attempts=attempts + fallback.attempts,
            used_fallback=True,
            fallback_reason=reason,
            usage=fallback.usage,
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


def _response_output_text(response: Mapping[str, Any]) -> str:
    direct = response.get("output_text")
    direct_text = direct if isinstance(direct, str) and direct else None
    extracted: list[str] = []
    output = response.get("output")
    if output is not None:
        if not isinstance(output, list) or len(output) != 1:
            raise AIDraftError("response.output must contain exactly one message")
        message = output[0]
        if not isinstance(message, Mapping) or message.get("type") != "message":
            raise AIDraftError("response.output contains a non-message item")
        content = message.get("content")
        if not isinstance(content, list) or len(content) != 1:
            raise AIDraftError("response message must contain exactly one output block")
        block = content[0]
        if not isinstance(block, Mapping) or block.get("type") != "output_text":
            raise AIDraftError("response message contains a non-text output block")
        text = block.get("text")
        if not isinstance(text, str) or not text:
            raise AIDraftError("response output_text block is invalid")
        extracted.append(text)
    if direct_text and extracted and direct_text != extracted[0]:
        raise AIDraftError("response output_text fields disagree")
    selected = direct_text or (extracted[0] if extracted else None)
    if selected is None:
        raise AIDraftError("response contains no structured output text")
    return selected


def _usage(value: Any, max_output_tokens: int) -> Mapping[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AIDraftError("response.usage must be an object")
    result: dict[str, int] = {}
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        raw = value.get(name)
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise AIDraftError(f"response.usage.{name} must be a non-negative integer")
        result[name] = raw
    if result.get("output_tokens", 0) > max_output_tokens:
        raise AIDraftError("response exceeds the configured output-token bound")
    return result


def build_ai_draft_provider(
    config: AIConfig,
    *,
    provider_id: str | None = None,
    environ: Mapping[str, str] | None = None,
    transport: AIJSONTransport | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> AIDraftProvider:
    selected = config.provider(provider_id)
    if selected.kind is AIProviderKind.DETERMINISTIC:
        return DeterministicOfflineDraftProvider(selected)
    fallback = DeterministicOfflineDraftProvider(config.fallback)
    return OpenAIResponsesDraftProvider(
        selected,
        fallback=fallback,
        environ=environ,
        transport=transport,
        sleeper=sleeper,
    )


def _offline_graph(request: AIGraphDraftRequest) -> Mapping[str, Any]:
    catalog = {str(row["id"]): row for row in request.behavior_catalog}
    scores = {
        behavior_id: _objective_score(request.objective, row)
        for behavior_id, row in catalog.items()
    }
    targets = sorted(catalog, key=lambda item: (-scores[item], item))
    targets = [item for item in targets if scores[item] > 0] or _source_behaviors(catalog)
    effective_limit = min(request.max_nodes, request.max_edges + 1)
    ordered: list[str] = []
    visiting: set[str] = set()

    def ensure(behavior_id: str) -> bool:
        if behavior_id in ordered:
            return True
        if behavior_id in visiting or len(ordered) >= effective_limit:
            return False
        visiting.add(behavior_id)
        descriptor = catalog[behavior_id]
        raw_inputs = descriptor.get("inputs")
        if not isinstance(raw_inputs, list):  # pragma: no cover - request invariant
            return False
        for input_spec in raw_inputs:
            if not isinstance(input_spec, Mapping) or not input_spec.get("required"):
                continue
            if _existing_producer(ordered, catalog, input_spec):
                continue
            producers = [
                candidate_id
                for candidate_id, candidate in catalog.items()
                if candidate_id != behavior_id and _descriptor_produces(candidate, input_spec)
            ]
            producers.sort(key=lambda item: (-scores[item], item))
            if not any(ensure(candidate_id) for candidate_id in producers):
                visiting.remove(behavior_id)
                return False
        if len(ordered) >= effective_limit:
            visiting.remove(behavior_id)
            return False
        ordered.append(behavior_id)
        visiting.remove(behavior_id)
        return True

    for target in targets:
        ensure(target)
        if len(ordered) >= effective_limit:
            break
    if not ordered:
        for behavior_id in _source_behaviors(catalog):
            if ensure(behavior_id):
                break
    if not ordered:  # pragma: no cover - draftable built-in catalog always has a source
        raise AIDraftError("offline drafting could not find a graph within the requested bounds")

    step_ids: dict[str, str] = {}
    used: set[str] = set()
    for behavior_id in ordered:
        base = _step_id_for_behavior(behavior_id)
        candidate = base
        suffix = 2
        while candidate in used:
            candidate = f"{base}_{suffix}"
            suffix += 1
        used.add(candidate)
        step_ids[behavior_id] = candidate
    steps = [
        {
            "id": step_ids[behavior_id],
            "behavior_id": behavior_id,
            "parameters": _offline_parameters(catalog[behavior_id]),
        }
        for behavior_id in ordered
    ]
    edges = [
        {
            "from_step": step_ids[source],
            "outcome": StepOutcome.SUCCESS.value,
            "to_step": step_ids[target],
        }
        for source, target in zip(ordered, ordered[1:], strict=False)
    ]
    objective_summary = request.objective.rstrip(". ")
    return {
        "schema_version": "bluefire.ai-graph-draft.v1",
        "title": ("Draft: " + objective_summary)[:200],
        "purpose": objective_summary[:2_000],
        "start": steps[0]["id"],
        "steps": steps,
        "edges": edges,
        "rationale": (
            "Deterministically selected registered behavior contracts by objective terms and "
            "added only prerequisite producers required by their typed artifact interfaces."
        ),
        "assumptions": [
            "This is an unsaved draft; execution mode, scope, profile, policy, and approval remain unset."
        ],
    }


def _objective_score(objective: str, descriptor: Mapping[str, Any]) -> int:
    objective_tokens = _tokens(objective)
    text = " ".join(str(descriptor.get(name, "")) for name in ("id", "title", "purpose"))
    descriptor_tokens = _tokens(text)
    return len(objective_tokens & descriptor_tokens)


def _tokens(value: str) -> set[str]:
    tokens = {
        token.removesuffix("s")
        for token in re.findall(r"[a-z0-9]+", value.casefold())
        if len(token) >= 3
    }
    return tokens - _TOKEN_STOPWORDS


def _source_behaviors(catalog: Mapping[str, Mapping[str, Any]]) -> list[str]:
    result = []
    for behavior_id, descriptor in catalog.items():
        raw_inputs = descriptor.get("inputs")
        if isinstance(raw_inputs, list) and not any(
            isinstance(row, Mapping) and row.get("required") for row in raw_inputs
        ):
            result.append(behavior_id)
    preferred = "endpoint.discovery.system.v1"
    return sorted(result, key=lambda item: (item != preferred, item))


def _existing_producer(
    ordered: Sequence[str],
    catalog: Mapping[str, Mapping[str, Any]],
    input_spec: Mapping[str, Any],
) -> bool:
    return any(_descriptor_produces(catalog[item], input_spec) for item in ordered)


def _descriptor_produces(descriptor: Mapping[str, Any], input_spec: Mapping[str, Any]) -> bool:
    outputs = descriptor.get("outputs")
    return isinstance(outputs, list) and any(
        isinstance(output, Mapping)
        and output.get("type") == input_spec.get("type")
        and output.get("multiple") == input_spec.get("multiple")
        for output in outputs
    )


def _step_id_for_behavior(behavior_id: str) -> str:
    parts = behavior_id.removesuffix(".v1").split(".")
    selected = parts[-2:] if len(parts) >= 2 else parts
    result = re.sub(r"[^a-z0-9_]+", "_", "_".join(selected)).strip("_")
    return result[:90] or "draft_step"


def _offline_parameters(descriptor: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_parameters = descriptor.get("parameters")
    if not isinstance(raw_parameters, list):  # pragma: no cover - request invariant
        raise AssertionError("validated descriptor parameters changed type")
    result: dict[str, Any] = {}
    for raw in raw_parameters:
        spec = ParameterSpec.from_mapping(raw)
        if spec.default is not None:
            value = spec.default
        elif spec.enum:
            value = spec.enum[0]
        elif spec.type is ParameterType.STRING:
            value = "reviewed"
        elif spec.type is ParameterType.INTEGER:
            value = math.ceil(spec.minimum or 0)
        elif spec.type is ParameterType.NUMBER:
            value = float(spec.minimum or 0)
        elif spec.type is ParameterType.BOOLEAN:
            value = False
        else:  # pragma: no cover - descriptor excludes non-primitive specs
            raise AIDraftError("offline drafting encountered a non-primitive parameter")
        spec.validate_value(value)
        result[spec.name] = value
    return result


@dataclass(frozen=True, slots=True)
class AIGraphDraftResult:
    draft_id: str
    scenario: ScenarioDefinition
    rationale: str
    assumptions: tuple[str, ...]
    audit: Mapping[str, Any]

    def to_dict(self) -> Mapping[str, Any]:
        result = {
            "schema_version": "bluefire.ai-graph-draft-result.v1",
            "draft_id": self.draft_id,
            "saved": False,
            "scenario": self.scenario.to_dict(),
            "rationale": self.rationale,
            "assumptions": list(self.assumptions),
            "audit": dict(self.audit),
        }
        if len(canonical_json_bytes(result)) > _MAX_RESULT_BYTES:
            raise AIDraftError("normalized graph draft result exceeds the 512 KiB bound")
        return result


def normalize_ai_graph_draft(
    *,
    request: AIGraphDraftRequest,
    provider_result: AIDraftProviderResult,
    registry: BehaviorRegistry,
) -> AIGraphDraftResult:
    """Derive bindings/identity and validate the complete unsaved scenario."""

    candidate = provider_result.draft
    allowed = set(request.allowed_behavior_ids)
    behaviors: dict[str, BehaviorDefinition] = {}
    for step in candidate.steps:
        if step.behavior_id not in allowed:
            raise AIDraftError("draft selected a behavior outside the request allowlist")
        try:
            behavior = registry.get_behavior(step.behavior_id)
        except RegistryError as exc:
            raise AIDraftError("draft selected an unregistered behavior") from exc
        if behavior.execution_state is ExecutionState.METADATA_ONLY:
            raise AIDraftError("metadata-only behaviors cannot appear in an AI graph draft")
        try:
            behavior.validate_parameters(step.parameters, f"draft step {step.id}.parameters")
        except ContractError as exc:
            raise AIDraftError(str(exc)) from exc
        behaviors[step.id] = behavior

    order, predecessors = _draft_graph_order(candidate)
    order_index = {step_id: index for index, step_id in enumerate(order)}
    candidate_steps = {step.id: step for step in candidate.steps}
    dominators: dict[str, set[str]] = {candidate.start: {candidate.start}}
    for step_id in order[1:]:
        parent_sets = [dominators[parent] for parent in predecessors[step_id]]
        common = set.intersection(*parent_sets) if parent_sets else set()
        dominators[step_id] = common | {step_id}

    normalized_steps: list[Mapping[str, Any]] = []
    binding_count = 0
    for step_id in order:
        draft_step = candidate_steps[step_id]
        behavior = behaviors[step_id]
        bindings: dict[str, Mapping[str, str]] = {}
        possible_sources = sorted(
            dominators[step_id] - {step_id}, key=order_index.__getitem__, reverse=True
        )
        for input_spec in behavior.inputs:
            binding: Mapping[str, str] | None = None
            for source_id in possible_sources:
                source_outputs = sorted(
                    behaviors[source_id].outputs, key=lambda output: output.name
                )
                for output in source_outputs:
                    if (output.type, output.multiple) == (input_spec.type, input_spec.multiple):
                        binding = {"from_step": source_id, "artifact": output.name}
                        break
                if binding is not None:
                    break
            if binding is None and input_spec.required:
                raise AIDraftError(
                    f"draft step {step_id} has no dominating producer for {input_spec.name}"
                )
            if binding is not None:
                bindings[input_spec.name] = binding
                binding_count += 1
        normalized_steps.append(
            {
                "id": draft_step.id,
                "behavior_id": draft_step.behavior_id,
                "parameters": dict(draft_step.parameters),
                "inputs": bindings,
                "alternates": [],
            }
        )
    normalized_edges = sorted(
        (edge.to_dict() for edge in candidate.edges),
        key=lambda row: (
            order_index[row["from_step"]],
            row["outcome"],
            order_index[row["to_step"]],
        ),
    )
    graph_identity = {
        "objective_digest": content_hash(request.objective),
        "start": candidate.start,
        "steps": normalized_steps,
        "edges": normalized_edges,
    }
    identity = content_hash(graph_identity).removeprefix("sha256:")[:20]
    scenario_id = f"scenario.ai-draft-{identity}.v1"
    limitation_rows = tuple(
        dict.fromkeys(
            (
                "Unsaved AI-assisted draft; no mode, profile, scope, approval, policy, or action implementation is selected.",
                *candidate.assumptions,
            )
        )
    )
    raw_scenario = {
        "schema_version": "bluefire.scenario.v1",
        "id": scenario_id,
        "title": candidate.title,
        "purpose": candidate.purpose,
        "start": candidate.start,
        "steps": normalized_steps,
        "edges": normalized_edges,
        "provenance": {
            "source": "BlueFire configured AI drafting boundary",
            "reference": provider_result.response_id,
            "license": "unspecified",
            "derived": True,
            "notes": "Model output was allowlisted, normalized, and deterministically revalidated.",
        },
        "limitations": list(limitation_rows),
    }
    try:
        scenario = ScenarioDefinition.from_mapping(raw_scenario, "AI graph draft scenario")
        registry.validate_scenario(scenario)
    except (ContractError, RegistryError) as exc:
        raise AIDraftError(f"normalized AI graph draft is invalid: {exc}") from exc
    scenario_bytes = len(canonical_json_bytes(scenario.to_dict()))
    if scenario_bytes > _MAX_DRAFT_BYTES:
        raise AIDraftError("normalized scenario exceeds the 256 KiB bound")
    draft_id = (
        "ai-draft-"
        + content_hash(
            {"request_id": request.request_id, "scenario": scenario.to_dict()}
        ).removeprefix("sha256:")[:20]
    )
    selected_behavior_ids = tuple(step.behavior_id for step in scenario.steps)
    audit = {
        "schema_version": "bluefire.ai-graph-draft-audit.v1",
        "unsaved": True,
        "request_id": request.request_id,
        "objective_digest": content_hash(request.objective),
        "provider": dict(provider_result.metadata()),
        "bounds": {
            "max_nodes": request.max_nodes,
            "max_edges": request.max_edges,
            "actual_nodes": len(scenario.steps),
            "actual_edges": len(scenario.edges),
            "scenario_bytes": scenario_bytes,
        },
        "allowlist": {
            "behavior_count": len(request.allowed_behavior_ids),
            "behavior_ids_digest": content_hash(list(request.allowed_behavior_ids)),
        },
        "selected_behavior_ids": list(selected_behavior_ids),
        "parameter_fields": {step.id: sorted(step.parameters) for step in scenario.steps},
        "normalization": {
            "topological_step_order": list(order),
            "artifact_bindings_added": binding_count,
            "scenario_identity_derived": True,
            "provenance_derived": True,
        },
        "validation": {
            "strict_model_schema": True,
            "registered_behaviors_only": True,
            "metadata_behaviors_excluded": True,
            "primitive_parameters_only": True,
            "scenario_contract": True,
            "registry_contract": True,
            "execution_authority_absent": True,
        },
    }
    return AIGraphDraftResult(
        draft_id=draft_id,
        scenario=scenario,
        rationale=candidate.rationale,
        assumptions=limitation_rows,
        audit=audit,
    )


def _draft_graph_order(
    candidate: AIGraphDraftCandidate,
) -> tuple[list[str], Mapping[str, set[str]]]:
    step_ids = {step.id for step in candidate.steps}
    successors: dict[str, set[str]] = defaultdict(set)
    predecessors: dict[str, set[str]] = defaultdict(set)
    edge_keys: set[tuple[str, StepOutcome]] = set()
    for edge in candidate.edges:
        if edge.from_step not in step_ids or edge.to_step not in step_ids:
            raise AIDraftError("draft edge references an unknown step")
        key = (edge.from_step, edge.outcome)
        if key in edge_keys:
            raise AIDraftError("draft contains duplicate outcome routes")
        edge_keys.add(key)
        successors[edge.from_step].add(edge.to_step)
        predecessors[edge.to_step].add(edge.from_step)
    if predecessors[candidate.start]:
        raise AIDraftError("draft start cannot have incoming edges")
    original_order = {step.id: index for index, step in enumerate(candidate.steps)}
    incoming = {step_id: len(predecessors[step_id]) for step_id in step_ids}
    queue = deque(
        sorted(
            (item for item, count in incoming.items() if count == 0), key=original_order.__getitem__
        )
    )
    order: list[str] = []
    while queue:
        current = queue.popleft()
        order.append(current)
        for child in sorted(successors[current], key=original_order.__getitem__):
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)
    if len(order) != len(step_ids):
        raise AIDraftError("draft graph contains a cycle")
    reachable = {candidate.start}
    pending = [candidate.start]
    while pending:
        current = pending.pop()
        for child in successors[current]:
            if child not in reachable:
                reachable.add(child)
                pending.append(child)
    if reachable != step_ids:
        raise AIDraftError("draft graph contains unreachable steps")
    return order, predecessors


__all__ = [
    "AIDraftError",
    "AIDraftProvider",
    "AIDraftProviderResult",
    "AIDraftStep",
    "AIGraphDraftCandidate",
    "AIGraphDraftRequest",
    "AIGraphDraftResult",
    "DeterministicOfflineDraftProvider",
    "OpenAIResponsesDraftProvider",
    "build_ai_draft_provider",
    "draftable_behavior_catalog",
    "graph_draft_json_schema",
    "normalize_ai_graph_draft",
]
