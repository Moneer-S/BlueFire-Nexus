"""Small v1 logical input vocabulary shared with the behavior catalog."""

from __future__ import annotations

from typing import Any, Mapping

from ..contracts import ContractError, ParameterSpec, ParameterType


def parameter_specs(value: Any) -> tuple[ParameterSpec, ...]:
    if not isinstance(value, list) or len(value) > 32:
        raise ContractError("adapter parameters must be a list of at most 32 fields")
    try:
        specs = tuple(ParameterSpec.from_mapping(item) for item in value)
    except (OverflowError, TypeError) as exc:
        raise ContractError("adapter parameter schema has invalid numeric values") from exc
    if len({spec.name for spec in specs}) != len(specs):
        raise ContractError("adapter parameter names must be unique")
    for spec in specs:
        if len(spec.enum) > 32:
            raise ContractError("adapter parameters allow at most 32 reviewed choices")
        # V1 deliberately has no unbounded text, list, path, or executable input.
        # Typed artifact bindings remain in the existing action/behavior contract.
        if spec.type == ParameterType.STRING:
            if not spec.enum or len(spec.enum) > 32 or any(len(v) > 128 for v in spec.enum):
                raise ContractError("adapter string parameters require bounded reviewed choices")
        elif spec.type == ParameterType.INTEGER:
            bounds = (spec.minimum, spec.maximum)
            if any(v is None or not float(v).is_integer() or abs(v) > 2**53 - 1 for v in bounds):
                raise ContractError("adapter integer parameters require finite safe integer bounds")
        elif spec.type != ParameterType.BOOLEAN:
            raise ContractError("adapter v1 supports only choices, bounded integers, and booleans")
    return specs


def normalized_parameters(specs: tuple[ParameterSpec, ...], values: Any) -> Mapping[str, Any]:
    if not isinstance(values, Mapping) or set(values) - {spec.name for spec in specs}:
        raise ContractError("adapter request contains unknown parameter fields")
    result = {}
    for spec in specs:
        if spec.name in values:
            value = values[spec.name]
        elif spec.default is not None:
            value = spec.default
        elif spec.required:
            raise ContractError(f"adapter parameter {spec.name} is required")
        else:
            continue
        spec.validate_value(value)
        result[spec.name] = value
    return result
