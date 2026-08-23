"""Strict, serializable contracts shared by planning and execution boundaries.

This module intentionally contains no behavior implementation or dispatch logic.
All parsers reject unknown fields so contract changes require a schema revision.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, TypeVar


class ContractError(ValueError):
    """Raised when a serialized control-plane contract is invalid."""


class ExecutionMode(str, Enum):
    SIMULATE = "simulate"
    EXECUTE = "execute"


class StepOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"


class SafetyTier(str, Enum):
    SAFE = "safe"
    CONTROLLED = "controlled"
    RESTRICTED = "restricted"


class ExecutionState(str, Enum):
    SIMULATION = "simulation"
    ACTION = "action"
    METADATA_ONLY = "metadata_only"


class ParameterType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STRING_LIST = "string_list"


_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_T = TypeVar("_T", bound=Enum)
_MISSING = object()


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{context} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise ContractError(f"{context} keys must be strings")
    return value


def _strict_fields(
    data: Mapping[str, Any], *, allowed: Iterable[str], required: Iterable[str], context: str
) -> None:
    allowed_set = set(allowed)
    unknown = set(data) - allowed_set
    missing = set(required) - set(data)
    if unknown:
        raise ContractError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ContractError(f"{context} is missing fields: {', '.join(sorted(missing))}")


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{context} must be a non-empty string")
    return value.strip()


def _optional_string(value: Any, context: str) -> str | None:
    if value is None:
        return None
    return _string(value, context)


def _stable_id(value: Any, context: str) -> str:
    result = _string(value, context)
    if not _STABLE_ID.fullmatch(result):
        raise ContractError(f"{context} must be a lowercase, versioned stable ID")
    return result


def _field_name(value: Any, context: str) -> str:
    result = _string(value, context)
    if not _FIELD_NAME.fullmatch(result):
        raise ContractError(f"{context} must be lowercase snake_case")
    return result


def _namespace(value: Any, context: str) -> str:
    result = _string(value, context)
    if not _NAMESPACE.fullmatch(result):
        raise ContractError(f"{context} must be a lowercase namespace")
    return result


def _strings(value: Any, context: str, *, stable_ids: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ContractError(f"{context} must be a list")
    parser = _stable_id if stable_ids else _string
    result = tuple(parser(item, f"{context}[{index}]") for index, item in enumerate(value))
    if len(result) != len(set(result)):
        raise ContractError(f"{context} contains duplicates")
    return result


def _enum(enum_type: type[_T], value: Any, context: str) -> _T:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        choices = ", ".join(member.value for member in enum_type)
        raise ContractError(f"{context} must be one of: {choices}") from exc


def _bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{context} must be a boolean")
    return value


def _number(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{context} must be a number")
    return float(value)


def _json_value(value: Any, context: str) -> Any:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{context} must contain only finite JSON values") from exc
    return value


def _unique_named(items: Iterable[Any], context: str) -> None:
    names = [item.name for item in items]
    if len(names) != len(set(names)):
        raise ContractError(f"{context} contains duplicate names")


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    source: str
    reference: str
    license: str
    derived: bool
    notes: str = ""

    @classmethod
    def from_mapping(cls, value: Any, context: str = "provenance") -> "SourceProvenance":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"source", "reference", "license", "derived", "notes"},
            required={"source", "reference", "license", "derived"},
            context=context,
        )
        return cls(
            source=_string(data["source"], f"{context}.source"),
            reference=_string(data["reference"], f"{context}.reference"),
            license=_string(data["license"], f"{context}.license"),
            derived=_bool(data["derived"], f"{context}.derived"),
            notes=_optional_string(data.get("notes"), f"{context}.notes") or "",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "reference": self.reference,
            "license": self.license,
            "derived": self.derived,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    name: str
    type: str
    required: bool = True
    multiple: bool = False
    description: str = ""

    @classmethod
    def from_mapping(cls, value: Any, context: str = "artifact") -> "ArtifactSpec":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"name", "type", "required", "multiple", "description"},
            required={"name", "type"},
            context=context,
        )
        return cls(
            name=_field_name(data["name"], f"{context}.name"),
            type=_stable_id(data["type"], f"{context}.type"),
            required=_bool(data.get("required", True), f"{context}.required"),
            multiple=_bool(data.get("multiple", False), f"{context}.multiple"),
            description=_optional_string(data.get("description"), f"{context}.description") or "",
        )

    def signature(self) -> tuple[str, str, bool, bool]:
        return self.name, self.type, self.required, self.multiple

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "multiple": self.multiple,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    from_step: str
    artifact: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "binding") -> "ArtifactBinding":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"from_step", "artifact"},
            required={"from_step", "artifact"},
            context=context,
        )
        return cls(
            from_step=_field_name(data["from_step"], f"{context}.from_step"),
            artifact=_field_name(data["artifact"], f"{context}.artifact"),
        )

    def to_dict(self) -> dict[str, str]:
        return {"from_step": self.from_step, "artifact": self.artifact}


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    name: str
    type: ParameterType
    required: bool = False
    default: Any = None
    enum: tuple[Any, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    description: str = ""

    @classmethod
    def from_mapping(cls, value: Any, context: str = "parameter") -> "ParameterSpec":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "name",
                "type",
                "required",
                "default",
                "enum",
                "minimum",
                "maximum",
                "description",
            },
            required={"name", "type"},
            context=context,
        )
        parameter_type = _enum(ParameterType, data["type"], f"{context}.type")
        enum_values = data.get("enum", [])
        if not isinstance(enum_values, list):
            raise ContractError(f"{context}.enum must be a list")
        minimum = (
            None if data.get("minimum") is None else _number(data["minimum"], f"{context}.minimum")
        )
        maximum = (
            None if data.get("maximum") is None else _number(data["maximum"], f"{context}.maximum")
        )
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ContractError(f"{context}.minimum cannot exceed maximum")
        spec = cls(
            name=_field_name(data["name"], f"{context}.name"),
            type=parameter_type,
            required=_bool(data.get("required", False), f"{context}.required"),
            default=_json_value(data.get("default"), f"{context}.default"),
            enum=tuple(_json_value(item, f"{context}.enum") for item in enum_values),
            minimum=minimum,
            maximum=maximum,
            description=_optional_string(data.get("description"), f"{context}.description") or "",
        )
        if spec.default is not None:
            spec.validate_value(spec.default, f"{context}.default")
        for index, enum_value in enumerate(spec.enum):
            spec.validate_value(enum_value, f"{context}.enum[{index}]")
        return spec

    def validate_value(self, value: Any, context: str | None = None) -> None:
        label = context or self.name
        valid = {
            ParameterType.STRING: lambda item: isinstance(item, str),
            ParameterType.INTEGER: lambda item: isinstance(item, int)
            and not isinstance(item, bool),
            ParameterType.NUMBER: lambda item: isinstance(item, (int, float))
            and not isinstance(item, bool),
            ParameterType.BOOLEAN: lambda item: isinstance(item, bool),
            ParameterType.STRING_LIST: lambda item: isinstance(item, list)
            and all(isinstance(child, str) for child in item),
        }[self.type](value)
        if not valid:
            raise ContractError(f"{label} must have type {self.type.value}")
        if self.enum and value not in self.enum:
            raise ContractError(f"{label} is not an allowed value")
        if self.type in {ParameterType.INTEGER, ParameterType.NUMBER}:
            number = float(value)
            if self.minimum is not None and number < self.minimum:
                raise ContractError(f"{label} is below the minimum")
            if self.maximum is not None and number > self.maximum:
                raise ContractError(f"{label} exceeds the maximum")

    def signature(self) -> tuple[Any, ...]:
        return (
            self.name,
            self.type,
            self.required,
            self.default,
            self.enum,
            self.minimum,
            self.maximum,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "required": self.required,
            "default": self.default,
            "enum": list(self.enum),
            "minimum": self.minimum,
            "maximum": self.maximum,
            "description": self.description,
        }


def _artifact_specs(value: Any, context: str) -> tuple[ArtifactSpec, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{context} must be a list")
    result = tuple(
        ArtifactSpec.from_mapping(item, f"{context}[{index}]") for index, item in enumerate(value)
    )
    _unique_named(result, context)
    return result


def _parameter_specs(value: Any, context: str) -> tuple[ParameterSpec, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{context} must be a list")
    result = tuple(
        ParameterSpec.from_mapping(item, f"{context}[{index}]") for index, item in enumerate(value)
    )
    _unique_named(result, context)
    return result


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    schema_version: str
    id: str
    title: str
    purpose: str
    safety_tier: SafetyTier
    capabilities: tuple[str, ...]
    platforms: tuple[str, ...]
    inputs: tuple[ArtifactSpec, ...]
    outputs: tuple[ArtifactSpec, ...]
    parameters: tuple[ParameterSpec, ...]
    mutates: bool
    cleanup_action_id: str | None
    provenance: SourceProvenance

    @classmethod
    def from_mapping(cls, value: Any, context: str = "action") -> "ActionDefinition":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "schema_version",
                "id",
                "title",
                "purpose",
                "safety_tier",
                "capabilities",
                "platforms",
                "inputs",
                "outputs",
                "parameters",
                "mutates",
                "cleanup_action_id",
                "provenance",
            },
            required={
                "schema_version",
                "id",
                "title",
                "purpose",
                "safety_tier",
                "capabilities",
                "platforms",
                "inputs",
                "outputs",
                "parameters",
                "mutates",
                "provenance",
            },
            context=context,
        )
        if data["schema_version"] != "bluefire.action.v1":
            raise ContractError(f"{context}.schema_version must be bluefire.action.v1")
        platforms = _strings(data["platforms"], f"{context}.platforms")
        if not platforms:
            raise ContractError(f"{context}.platforms cannot be empty")
        for index, platform in enumerate(platforms):
            _namespace(platform, f"{context}.platforms[{index}]")
        capabilities = _strings(data["capabilities"], f"{context}.capabilities")
        if not capabilities:
            raise ContractError(f"{context}.capabilities cannot be empty")
        for index, capability in enumerate(capabilities):
            _namespace(capability, f"{context}.capabilities[{index}]")
        return cls(
            schema_version="bluefire.action.v1",
            id=_stable_id(data["id"], f"{context}.id"),
            title=_string(data["title"], f"{context}.title"),
            purpose=_string(data["purpose"], f"{context}.purpose"),
            safety_tier=_enum(SafetyTier, data["safety_tier"], f"{context}.safety_tier"),
            capabilities=capabilities,
            platforms=platforms,
            inputs=_artifact_specs(data["inputs"], f"{context}.inputs"),
            outputs=_artifact_specs(data["outputs"], f"{context}.outputs"),
            parameters=_parameter_specs(data["parameters"], f"{context}.parameters"),
            mutates=_bool(data["mutates"], f"{context}.mutates"),
            cleanup_action_id=(
                None
                if data.get("cleanup_action_id") is None
                else _stable_id(data["cleanup_action_id"], f"{context}.cleanup_action_id")
            ),
            provenance=SourceProvenance.from_mapping(data["provenance"], f"{context}.provenance"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "title": self.title,
            "purpose": self.purpose,
            "safety_tier": self.safety_tier.value,
            "capabilities": list(self.capabilities),
            "platforms": list(self.platforms),
            "inputs": [spec.to_dict() for spec in self.inputs],
            "outputs": [spec.to_dict() for spec in self.outputs],
            "parameters": [spec.to_dict() for spec in self.parameters],
            "mutates": self.mutates,
            "cleanup_action_id": self.cleanup_action_id,
            "provenance": self.provenance.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class BehaviorDefinition:
    schema_version: str
    id: str
    title: str
    purpose: str
    execution_state: ExecutionState
    safety_tier: SafetyTier
    platforms: tuple[str, ...]
    techniques: tuple[str, ...]
    capabilities: tuple[str, ...]
    inputs: tuple[ArtifactSpec, ...]
    outputs: tuple[ArtifactSpec, ...]
    parameters: tuple[ParameterSpec, ...]
    simulation_id: str | None
    action_ids: tuple[str, ...]
    telemetry: tuple[str, ...]
    detection_hints: tuple[str, ...]
    provenance: SourceProvenance
    limitations: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str = "behavior") -> "BehaviorDefinition":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "schema_version",
                "id",
                "title",
                "purpose",
                "execution_state",
                "safety_tier",
                "platforms",
                "techniques",
                "capabilities",
                "inputs",
                "outputs",
                "parameters",
                "simulation_id",
                "action_ids",
                "telemetry",
                "detection_hints",
                "provenance",
                "limitations",
            },
            required={
                "schema_version",
                "id",
                "title",
                "purpose",
                "execution_state",
                "safety_tier",
                "platforms",
                "techniques",
                "capabilities",
                "inputs",
                "outputs",
                "parameters",
                "action_ids",
                "telemetry",
                "detection_hints",
                "provenance",
                "limitations",
            },
            context=context,
        )
        if data["schema_version"] != "bluefire.behavior.v1":
            raise ContractError(f"{context}.schema_version must be bluefire.behavior.v1")
        state = _enum(ExecutionState, data["execution_state"], f"{context}.execution_state")
        simulation_id = (
            None
            if data.get("simulation_id") is None
            else _stable_id(data["simulation_id"], f"{context}.simulation_id")
        )
        action_ids = _strings(data["action_ids"], f"{context}.action_ids", stable_ids=True)
        if state is ExecutionState.METADATA_ONLY and (simulation_id or action_ids):
            raise ContractError(f"{context} metadata-only behaviors cannot declare execution IDs")
        if state is ExecutionState.SIMULATION and not simulation_id:
            raise ContractError(f"{context} simulation behaviors require simulation_id")
        if state is ExecutionState.ACTION and not action_ids:
            raise ContractError(f"{context} action behaviors require action_ids")
        capabilities = _strings(data["capabilities"], f"{context}.capabilities")
        if not capabilities:
            raise ContractError(f"{context}.capabilities cannot be empty")
        for index, capability in enumerate(capabilities):
            _namespace(capability, f"{context}.capabilities[{index}]")
        platforms = _strings(data["platforms"], f"{context}.platforms")
        if not platforms:
            raise ContractError(f"{context}.platforms cannot be empty")
        for index, platform in enumerate(platforms):
            _namespace(platform, f"{context}.platforms[{index}]")
        return cls(
            schema_version="bluefire.behavior.v1",
            id=_stable_id(data["id"], f"{context}.id"),
            title=_string(data["title"], f"{context}.title"),
            purpose=_string(data["purpose"], f"{context}.purpose"),
            execution_state=state,
            safety_tier=_enum(SafetyTier, data["safety_tier"], f"{context}.safety_tier"),
            platforms=platforms,
            techniques=_strings(data["techniques"], f"{context}.techniques"),
            capabilities=capabilities,
            inputs=_artifact_specs(data["inputs"], f"{context}.inputs"),
            outputs=_artifact_specs(data["outputs"], f"{context}.outputs"),
            parameters=_parameter_specs(data["parameters"], f"{context}.parameters"),
            simulation_id=simulation_id,
            action_ids=action_ids,
            telemetry=_strings(data["telemetry"], f"{context}.telemetry"),
            detection_hints=_strings(data["detection_hints"], f"{context}.detection_hints"),
            provenance=SourceProvenance.from_mapping(data["provenance"], f"{context}.provenance"),
            limitations=_strings(data["limitations"], f"{context}.limitations"),
        )

    def validate_parameters(self, values: Mapping[str, Any], context: str = "parameters") -> None:
        specs = {spec.name: spec for spec in self.parameters}
        unknown = set(values) - set(specs)
        if unknown:
            raise ContractError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
        missing = [
            spec.name for spec in self.parameters if spec.required and spec.name not in values
        ]
        if missing:
            raise ContractError(f"{context} is missing fields: {', '.join(sorted(missing))}")
        for name, value in values.items():
            specs[name].validate_value(value, f"{context}.{name}")

    def io_signature(self) -> tuple[Any, ...]:
        return (
            tuple(spec.signature() for spec in self.inputs),
            tuple(spec.signature() for spec in self.outputs),
            tuple(spec.signature() for spec in self.parameters),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "title": self.title,
            "purpose": self.purpose,
            "execution_state": self.execution_state.value,
            "safety_tier": self.safety_tier.value,
            "platforms": list(self.platforms),
            "techniques": list(self.techniques),
            "capabilities": list(self.capabilities),
            "inputs": [spec.to_dict() for spec in self.inputs],
            "outputs": [spec.to_dict() for spec in self.outputs],
            "parameters": [spec.to_dict() for spec in self.parameters],
            "simulation_id": self.simulation_id,
            "action_ids": list(self.action_ids),
            "telemetry": list(self.telemetry),
            "detection_hints": list(self.detection_hints),
            "provenance": self.provenance.to_dict(),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    id: str
    behavior_id: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    inputs: Mapping[str, ArtifactBinding] = field(default_factory=dict)
    alternates: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Any, context: str = "step") -> "ScenarioStep":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"id", "behavior_id", "parameters", "inputs", "alternates"},
            required={"id", "behavior_id"},
            context=context,
        )
        parameters = _mapping(data.get("parameters", {}), f"{context}.parameters")
        _json_value(parameters, f"{context}.parameters")
        raw_inputs = _mapping(data.get("inputs", {}), f"{context}.inputs")
        inputs: dict[str, ArtifactBinding] = {}
        for name, binding in raw_inputs.items():
            port = _field_name(name, f"{context}.inputs key")
            inputs[port] = ArtifactBinding.from_mapping(binding, f"{context}.inputs.{port}")
        return cls(
            id=_field_name(data["id"], f"{context}.id"),
            behavior_id=_stable_id(data["behavior_id"], f"{context}.behavior_id"),
            parameters=dict(parameters),
            inputs=inputs,
            alternates=_strings(
                data.get("alternates", []), f"{context}.alternates", stable_ids=True
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "behavior_id": self.behavior_id,
            "parameters": dict(self.parameters),
            "inputs": {name: binding.to_dict() for name, binding in self.inputs.items()},
            "alternates": list(self.alternates),
        }


@dataclass(frozen=True, slots=True)
class OutcomeEdge:
    from_step: str
    outcome: StepOutcome
    to_step: str

    @classmethod
    def from_mapping(cls, value: Any, context: str = "edge") -> "OutcomeEdge":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"from_step", "outcome", "to_step"},
            required={"from_step", "outcome", "to_step"},
            context=context,
        )
        return cls(
            from_step=_field_name(data["from_step"], f"{context}.from_step"),
            outcome=_enum(StepOutcome, data["outcome"], f"{context}.outcome"),
            to_step=_field_name(data["to_step"], f"{context}.to_step"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "from_step": self.from_step,
            "outcome": self.outcome.value,
            "to_step": self.to_step,
        }


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    schema_version: str
    id: str
    title: str
    purpose: str
    start: str
    steps: tuple[ScenarioStep, ...]
    edges: tuple[OutcomeEdge, ...]
    provenance: SourceProvenance
    limitations: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: Any, context: str = "scenario") -> "ScenarioDefinition":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "schema_version",
                "id",
                "title",
                "purpose",
                "start",
                "steps",
                "edges",
                "provenance",
                "limitations",
            },
            required={
                "schema_version",
                "id",
                "title",
                "purpose",
                "start",
                "steps",
                "edges",
                "provenance",
            },
            context=context,
        )
        if data["schema_version"] != "bluefire.scenario.v1":
            raise ContractError(f"{context}.schema_version must be bluefire.scenario.v1")
        if not isinstance(data["steps"], list) or not data["steps"]:
            raise ContractError(f"{context}.steps must be a non-empty list")
        if not isinstance(data["edges"], list):
            raise ContractError(f"{context}.edges must be a list")
        steps = tuple(
            ScenarioStep.from_mapping(item, f"{context}.steps[{index}]")
            for index, item in enumerate(data["steps"])
        )
        step_ids = [step.id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise ContractError(f"{context}.steps contains duplicate IDs")
        edges = tuple(
            OutcomeEdge.from_mapping(item, f"{context}.edges[{index}]")
            for index, item in enumerate(data["edges"])
        )
        edge_keys = [(edge.from_step, edge.outcome) for edge in edges]
        if len(edge_keys) != len(set(edge_keys)):
            raise ContractError(f"{context}.edges contains duplicate outcome routes")
        return cls(
            schema_version="bluefire.scenario.v1",
            id=_stable_id(data["id"], f"{context}.id"),
            title=_string(data["title"], f"{context}.title"),
            purpose=_string(data["purpose"], f"{context}.purpose"),
            start=_field_name(data["start"], f"{context}.start"),
            steps=steps,
            edges=edges,
            provenance=SourceProvenance.from_mapping(data["provenance"], f"{context}.provenance"),
            limitations=_strings(data.get("limitations", []), f"{context}.limitations"),
        )

    def step(self, step_id: str) -> ScenarioStep:
        for step in self.steps:
            if step.id == step_id:
                return step
        raise KeyError(step_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "title": self.title,
            "purpose": self.purpose,
            "start": self.start,
            "steps": [step.to_dict() for step in self.steps],
            "edges": [edge.to_dict() for edge in self.edges],
            "provenance": self.provenance.to_dict(),
            "limitations": list(self.limitations),
        }


def _load_yaml_mapping(path: str | Path, context: str) -> Mapping[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - installation error path
        raise RuntimeError("PyYAML is required to load BlueFire YAML contracts") from exc
    source = Path(path)
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractError(f"could not read {context}: {source}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML in {context}: {source}") from exc
    return _mapping(value, context)


def load_scenario(path: str | Path) -> ScenarioDefinition:
    """Load a scenario document without performing registry-dependent checks."""

    return ScenarioDefinition.from_mapping(_load_yaml_mapping(path, "scenario"))


__all__ = [
    "ActionDefinition",
    "ArtifactBinding",
    "ArtifactSpec",
    "BehaviorDefinition",
    "ContractError",
    "ExecutionMode",
    "ExecutionState",
    "OutcomeEdge",
    "ParameterSpec",
    "ParameterType",
    "SafetyTier",
    "ScenarioDefinition",
    "ScenarioStep",
    "SourceProvenance",
    "StepOutcome",
    "load_scenario",
]
