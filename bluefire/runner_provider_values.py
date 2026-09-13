"""Signed provider parameter and result-value validation for the runner adapter."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .runner_client import reject_forbidden_execution_keys
from .util import json_clone

_PROVIDER_ACTION_OUTPUT_SCHEMA = "bluefire.provider-action-output.v1"


class RunnerAdapterError(ValueError):
    """Raised when typed logical artifacts cannot produce a safe runner call."""


def _validate_provider_parameter(spec: Mapping[str, Any], value: Any, context: str) -> None:
    parameter_type = spec.get("type")
    valid = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "string_list": lambda item: (
            isinstance(item, list) and all(isinstance(child, str) for child in item)
        ),
    }.get(str(parameter_type), lambda _item: False)(value)
    if not valid:
        raise RunnerAdapterError(f"{context} does not match the signed provider parameter type")
    allowed = spec.get("enum")
    if isinstance(allowed, list) and allowed and value not in allowed:
        raise RunnerAdapterError(f"{context} is outside the signed provider enum")
    if parameter_type in {"integer", "number"}:
        minimum = spec.get("minimum")
        maximum = spec.get("maximum")
        if minimum is not None and value < minimum:
            raise RunnerAdapterError(f"{context} is below the signed provider minimum")
        if maximum is not None and value > maximum:
            raise RunnerAdapterError(f"{context} exceeds the signed provider maximum")


def _provider_parameters(
    binding: Mapping[str, Any],
    values: Mapping[str, Any],
    *,
    validate: Callable[[Mapping[str, Any], Any, str], None] = _validate_provider_parameter,
) -> dict[str, Any]:
    raw_specs = binding.get("parameters")
    if not isinstance(raw_specs, list):
        raise RunnerAdapterError("provider binding has no signed parameter contract")
    specs = {str(spec.get("name")): spec for spec in raw_specs if isinstance(spec, Mapping)}
    if len(specs) != len(raw_specs) or set(values) - set(specs):
        raise RunnerAdapterError("provider parameters do not match the signed contract")
    missing = [
        name for name, spec in specs.items() if spec.get("required") is True and name not in values
    ]
    if missing:
        raise RunnerAdapterError("provider parameters omit a required signed field")
    result = dict(json_clone(dict(values)))
    for name, value in result.items():
        validate(specs[name], value, f"provider parameter {name}")
    reject_forbidden_execution_keys(result)
    return result


def _provider_output_value(spec: Mapping[str, Any], value: Any, context: str) -> Any:
    artifact_type = spec.get("type")

    def validate_one(item: Any, label: str) -> Mapping[str, Any]:
        if not isinstance(item, Mapping) or item.get("type") != artifact_type:
            raise RunnerAdapterError(f"{label} does not match its signed provider artifact type")
        reject_forbidden_execution_keys(item)
        return dict(json_clone(dict(item)))

    if spec.get("multiple") is True:
        if not isinstance(value, list) or (spec.get("required") is True and not value):
            raise RunnerAdapterError(f"{context} must be a non-empty provider artifact array")
        return [validate_one(item, f"{context}[{index}]") for index, item in enumerate(value)]
    return validate_one(value, context)


def _provider_outputs(
    binding: Mapping[str, Any],
    value: Any,
    *,
    output_value: Callable[[Mapping[str, Any], Any, str], Any] = _provider_output_value,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "outputs"}:
        raise RunnerAdapterError("successful provider result must have exact ABI wrapper fields")
    if value.get("schema_version") != _PROVIDER_ACTION_OUTPUT_SCHEMA:
        raise RunnerAdapterError("successful provider result has an unsupported ABI schema")
    outputs = value.get("outputs")
    if not isinstance(outputs, Mapping):
        raise RunnerAdapterError("successful provider outputs must be an object")
    raw_specs = binding.get("outputs")
    if not isinstance(raw_specs, list):
        raise RunnerAdapterError("provider binding has no signed output contract")
    specs = {str(spec.get("name")): spec for spec in raw_specs if isinstance(spec, Mapping)}
    if len(specs) != len(raw_specs) or set(outputs) - set(specs):
        raise RunnerAdapterError("provider outputs do not match the signed contract")
    missing = [
        name for name, spec in specs.items() if spec.get("required") is True and name not in outputs
    ]
    if missing:
        raise RunnerAdapterError("provider outputs omit a required signed artifact")
    return {
        name: output_value(specs[name], item, f"provider output {name}")
        for name, item in outputs.items()
    }
