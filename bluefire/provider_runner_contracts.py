"""Strict control-plane contracts for pure WebAssembly action providers."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Mapping, Sequence

from .util import canonical_json_bytes, content_hash, json_clone


class ProviderRunnerContractError(ValueError):
    """Raised when provider metadata could widen the native runner boundary."""


PROVIDER_BINDING_SCHEMA = "bluefire.runner-provider-execution-binding.v1"
PROVIDER_PROGRAM_SCHEMA = "bluefire.wasm-provider-program.v1"
PROVIDER_ACTION_CONTRACT_SCHEMA = "bluefire.provider-action-contract.v1"
PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA = "bluefire.provider-runtime-action-contract.v1"
PROVIDER_ABI_V1 = "bluefire.provider-abi.v1"
MAX_PROVIDER_ARTIFACT_BYTES = 64 * 1024
MAX_PROVIDER_MODULE_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_SAFE_INTEGER = (1 << 53) - 1

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACKAGE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "catalog_generation",
        "catalog_digest",
        "logical_behavior_id",
        "logical_action_id",
        "package_id",
        "package_version",
        "package_digest",
        "content_digest",
        "program_digest",
        "provider_id",
        "abi_version",
        "artifact_sha256",
        "artifact_size",
        "action_contract_digest",
        "runtime_contract_digest",
        "provider_runtime_contract_digest",
        "inputs",
        "outputs",
        "parameters",
        "capabilities",
        "safety_tier",
        "platforms",
        "mutates",
        "cleanup_action_id",
        "limits",
    }
)
_ARTIFACT_FIELDS = frozenset({"artifact_sha256", "artifact_size", "artifact_hex"})
_IO_SPEC_FIELDS = frozenset({"name", "type", "required", "multiple"})
_PARAMETER_SPEC_FIELDS = frozenset(
    {"name", "type", "required", "default", "enum", "minimum", "maximum"}
)
_PARAMETER_TYPES = frozenset({"string", "integer", "number", "boolean", "string_list"})
_LIMIT_FIELDS = frozenset(
    {
        "max_module_bytes",
        "max_memory_bytes",
        "max_input_bytes",
        "max_output_bytes",
        "fuel",
    }
)
_PLATFORMS = frozenset({"windows", "linux", "macos"})


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProviderRunnerContractError(f"{context} must be exact lowercase SHA-256")
    return value


def _stable_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ProviderRunnerContractError(f"{context} is invalid")
    return value


def _field_name(value: Any, context: str) -> str:
    if not isinstance(value, str) or _FIELD_NAME.fullmatch(value) is None:
        raise ProviderRunnerContractError(f"{context} is invalid")
    return value


def _bounded_json(value: Any, context: str) -> Any:
    try:
        cloned = json_clone(value)
    except (TypeError, ValueError) as exc:
        raise ProviderRunnerContractError(f"{context} is not bounded JSON") from exc
    return cloned


def _valid_provider_bound(value: Any) -> bool:
    return bool(
        value is None
        or (
            not isinstance(value, bool)
            and (
                isinstance(value, int)
                or (isinstance(value, float) and math.isfinite(value) and value.is_integer())
            )
            and -MAX_PROVIDER_SAFE_INTEGER <= value <= MAX_PROVIDER_SAFE_INTEGER
        )
    )


def _valid_signed_parameter_value(parameter_type: str, value: Any) -> bool:
    if parameter_type == "string":
        return isinstance(value, str)
    if parameter_type in {"integer", "number"}:
        # The signed package parser rejects all JSON floating-point values
        # before an ActionDefinition reaches this boundary.
        return isinstance(value, int) and not isinstance(value, bool)
    if parameter_type == "boolean":
        return isinstance(value, bool)
    if parameter_type == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return False


def _within_provider_bounds(
    parameter_type: str,
    value: Any,
    minimum: Any,
    maximum: Any,
) -> bool:
    if parameter_type not in {"integer", "number"}:
        return True
    return bool((minimum is None or value >= minimum) and (maximum is None or value <= maximum))


def _canonical_io_specs(value: Any, context: str, *, allow_empty: bool) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64 or (not allow_empty and not value):
        raise ProviderRunnerContractError(f"{context} must be a bounded array")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != _IO_SPEC_FIELDS:
            raise ProviderRunnerContractError(f"{context}[{index}] has unknown fields")
        name = _field_name(raw.get("name"), f"{context}[{index}].name")
        artifact_type = _stable_id(raw.get("type"), f"{context}[{index}].type")
        required = raw.get("required")
        multiple = raw.get("multiple")
        if name in names or not isinstance(required, bool) or not isinstance(multiple, bool):
            raise ProviderRunnerContractError(f"{context}[{index}] is invalid")
        names.add(name)
        result.append(
            {
                "name": name,
                "type": artifact_type,
                "required": required,
                "multiple": multiple,
            }
        )
    return result


def _canonical_parameters(value: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ProviderRunnerContractError(f"{context} must be a bounded array")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != _PARAMETER_SPEC_FIELDS:
            raise ProviderRunnerContractError(f"{context}[{index}] has unknown fields")
        name = _field_name(raw.get("name"), f"{context}[{index}].name")
        parameter_type = raw.get("type")
        required = raw.get("required")
        enum = raw.get("enum")
        minimum = raw.get("minimum")
        maximum = raw.get("maximum")
        numeric = isinstance(parameter_type, str) and parameter_type in {"integer", "number"}

        # Signed package JSON prohibits floating-point tokens. ActionDefinition
        # currently normalizes signed integer bounds to integral floats, so the
        # runner boundary accepts only that lossless derived representation.
        if (
            name in names
            or not isinstance(parameter_type, str)
            or parameter_type not in _PARAMETER_TYPES
            or not isinstance(required, bool)
            or not isinstance(enum, list)
            or len(enum) > 64
            or (not numeric and (minimum is not None or maximum is not None))
            or not _valid_provider_bound(minimum)
            or not _valid_provider_bound(maximum)
            or (minimum is not None and maximum is not None and minimum > maximum)
        ):
            raise ProviderRunnerContractError(f"{context}[{index}] is invalid")
        default = _bounded_json(raw.get("default"), f"{context}[{index}].default")
        canonical_enum = _bounded_json(enum, f"{context}[{index}].enum")

        if default is not None and (
            not _valid_signed_parameter_value(parameter_type, default)
            or not _within_provider_bounds(parameter_type, default, minimum, maximum)
        ):
            raise ProviderRunnerContractError(f"{context}[{index}].default is invalid")
        enum_keys: set[bytes] = set()
        for enum_index, item in enumerate(canonical_enum):
            if not _valid_signed_parameter_value(
                parameter_type, item
            ) or not _within_provider_bounds(parameter_type, item, minimum, maximum):
                raise ProviderRunnerContractError(
                    f"{context}[{index}].enum[{enum_index}] is invalid"
                )
            encoded = canonical_json_bytes(item)
            if encoded in enum_keys:
                raise ProviderRunnerContractError(f"{context}[{index}].enum contains duplicates")
            enum_keys.add(encoded)
        names.add(name)
        result.append(
            {
                "name": name,
                "type": parameter_type,
                "required": required,
                "default": default,
                "enum": canonical_enum,
                "minimum": minimum,
                "maximum": maximum,
            }
        )
    return result


def _canonical_limits(value: Any, context: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _LIMIT_FIELDS:
        raise ProviderRunnerContractError(f"{context} has invalid fields")
    limits: dict[str, int] = {}
    for field in sorted(_LIMIT_FIELDS):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= (1 << 63) - 1:
            raise ProviderRunnerContractError(f"{context}.{field} is invalid")
        limits[field] = item
    if limits["max_module_bytes"] > MAX_PROVIDER_MODULE_BYTES:
        raise ProviderRunnerContractError(f"{context}.max_module_bytes exceeds the runtime limit")
    return limits


def canonical_provider_binding(value: Mapping[str, Any], *, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _BINDING_FIELDS:
        raise ProviderRunnerContractError(f"{context} must have exact provider-binding fields")
    if value.get("schema_version") != PROVIDER_BINDING_SCHEMA:
        raise ProviderRunnerContractError(f"{context}.schema_version is unsupported")
    generation = value.get("catalog_generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= (1 << 63) - 1
    ):
        raise ProviderRunnerContractError(f"{context}.catalog_generation is invalid")
    identifiers = {
        field: _stable_id(value.get(field), f"{context}.{field}")
        for field in ("logical_behavior_id", "logical_action_id", "provider_id")
    }
    package_id = value.get("package_id")
    package_version = value.get("package_version")
    if (
        not isinstance(package_id, str)
        or len(package_id) > 128
        or _PACKAGE_ID.fullmatch(package_id) is None
    ):
        raise ProviderRunnerContractError(f"{context}.package_id is invalid")
    if (
        not isinstance(package_version, str)
        or len(package_version) > 128
        or _SEMVER.fullmatch(package_version) is None
    ):
        raise ProviderRunnerContractError(f"{context}.package_version is invalid")
    abi_version = value.get("abi_version")
    if abi_version != PROVIDER_ABI_V1:
        raise ProviderRunnerContractError(f"{context}.abi_version is unsupported")
    digests = {
        field: _digest(value.get(field), f"{context}.{field}")
        for field in (
            "catalog_digest",
            "package_digest",
            "content_digest",
            "program_digest",
            "artifact_sha256",
            "action_contract_digest",
            "runtime_contract_digest",
            "provider_runtime_contract_digest",
        )
    }
    artifact_size = value.get("artifact_size")
    if (
        isinstance(artifact_size, bool)
        or not isinstance(artifact_size, int)
        or not 8 <= artifact_size <= MAX_PROVIDER_ARTIFACT_BYTES
    ):
        raise ProviderRunnerContractError(f"{context}.artifact_size is invalid")
    inputs = _canonical_io_specs(value.get("inputs"), f"{context}.inputs", allow_empty=True)
    outputs = _canonical_io_specs(value.get("outputs"), f"{context}.outputs", allow_empty=False)
    parameters = _canonical_parameters(value.get("parameters"), f"{context}.parameters")
    capabilities = value.get("capabilities")
    safety_tier = value.get("safety_tier")
    raw_platforms = value.get("platforms")
    if capabilities != ["native_execution"] or safety_tier != "safe":
        raise ProviderRunnerContractError(f"{context} widens provider capability or safety")
    if (
        not isinstance(raw_platforms, list)
        or not raw_platforms
        or raw_platforms != sorted(set(raw_platforms))
        or not set(raw_platforms).issubset(_PLATFORMS)
    ):
        raise ProviderRunnerContractError(f"{context}.platforms is invalid")
    if value.get("mutates") is not False or value.get("cleanup_action_id") is not None or inputs:
        raise ProviderRunnerContractError(f"{context} must describe a pure input-free provider")
    limits = _canonical_limits(value.get("limits"), f"{context}.limits")
    if artifact_size > limits["max_module_bytes"]:
        raise ProviderRunnerContractError(f"{context} artifact exceeds its module limit")
    program = {
        "schema_version": PROVIDER_PROGRAM_SCHEMA,
        "provider_id": identifiers["provider_id"],
        "action_contract_digest": digests["action_contract_digest"],
    }
    if content_hash(program) != digests["program_digest"]:
        raise ProviderRunnerContractError(f"{context}.program_digest does not match its program")
    action_contract = {
        "schema_version": PROVIDER_ACTION_CONTRACT_SCHEMA,
        "action": {
            "id": identifiers["logical_action_id"],
            "inputs": inputs,
            "outputs": outputs,
            "parameters": parameters,
            "capabilities": ["native.execution"],
            "safety_tier": "safe",
            "platforms": list(raw_platforms),
            "mutates": False,
            "cleanup_action_id": None,
        },
    }
    if content_hash(action_contract) != digests["action_contract_digest"]:
        raise ProviderRunnerContractError(
            f"{context}.action_contract_digest does not match its contract"
        )
    runtime_contract = {
        "schema_version": PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA,
        "logical_action_id": identifiers["logical_action_id"],
        "inputs": inputs,
        "outputs": outputs,
        "parameters": parameters,
        "capabilities": ["native_execution"],
        "safety_tier": "safe",
        "platforms": list(raw_platforms),
        "mutates": False,
        "cleanup_action_id": None,
    }
    if content_hash(runtime_contract) != digests["runtime_contract_digest"]:
        raise ProviderRunnerContractError(
            f"{context}.runtime_contract_digest does not match its contract"
        )
    return {
        "schema_version": PROVIDER_BINDING_SCHEMA,
        "catalog_generation": generation,
        "catalog_digest": digests["catalog_digest"],
        "logical_behavior_id": identifiers["logical_behavior_id"],
        "logical_action_id": identifiers["logical_action_id"],
        "package_id": package_id,
        "package_version": package_version,
        "package_digest": digests["package_digest"],
        "content_digest": digests["content_digest"],
        "program_digest": digests["program_digest"],
        "provider_id": identifiers["provider_id"],
        "abi_version": PROVIDER_ABI_V1,
        "artifact_sha256": digests["artifact_sha256"],
        "artifact_size": artifact_size,
        "action_contract_digest": digests["action_contract_digest"],
        "runtime_contract_digest": digests["runtime_contract_digest"],
        "provider_runtime_contract_digest": digests["provider_runtime_contract_digest"],
        "inputs": inputs,
        "outputs": outputs,
        "parameters": parameters,
        "capabilities": ["native_execution"],
        "safety_tier": "safe",
        "platforms": list(raw_platforms),
        "mutates": False,
        "cleanup_action_id": None,
        "limits": limits,
    }


def canonical_provider_bindings(
    value: Sequence[Mapping[str, Any]], *, context: str
) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > 512:
        raise ProviderRunnerContractError(f"{context} must be a bounded list")
    bindings = [
        canonical_provider_binding(item, context=f"{context}[{index}]")
        for index, item in enumerate(value)
    ]
    pairs = [(item["logical_behavior_id"], item["logical_action_id"]) for item in bindings]
    if len(pairs) != len(set(pairs)):
        raise ProviderRunnerContractError(f"{context} contains duplicate logical bindings")
    identities = {(item["catalog_generation"], item["catalog_digest"]) for item in bindings}
    if len(identities) > 1:
        raise ProviderRunnerContractError(f"{context} spans catalog generations")
    return sorted(
        bindings, key=lambda item: (item["logical_behavior_id"], item["logical_action_id"])
    )


def canonical_provider_artifacts(
    value: Sequence[Mapping[str, Any]], *, context: str
) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > 64:
        raise ProviderRunnerContractError(f"{context} must be a bounded list")
    result: list[dict[str, Any]] = []
    digests: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != _ARTIFACT_FIELDS:
            raise ProviderRunnerContractError(f"{context}[{index}] has unknown fields")
        digest = _digest(raw.get("artifact_sha256"), f"{context}[{index}].artifact_sha256")
        size = raw.get("artifact_size")
        encoded = raw.get("artifact_hex")
        if (
            digest in digests
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 8 <= size <= MAX_PROVIDER_ARTIFACT_BYTES
            or not isinstance(encoded, str)
            or len(encoded) != size * 2
            or any(character not in "0123456789abcdef" for character in encoded)
        ):
            raise ProviderRunnerContractError(f"{context}[{index}] is invalid")
        artifact = bytes.fromhex(encoded)
        if "sha256:" + hashlib.sha256(artifact).hexdigest() != digest:
            raise ProviderRunnerContractError(f"{context}[{index}] digest does not match")
        digests.add(digest)
        result.append(
            {
                "artifact_sha256": digest,
                "artifact_size": size,
                "artifact_hex": encoded,
            }
        )
    result.sort(key=lambda item: item["artifact_sha256"])
    return result


__all__ = [
    "MAX_PROVIDER_ARTIFACT_BYTES",
    "MAX_PROVIDER_MODULE_BYTES",
    "MAX_PROVIDER_SAFE_INTEGER",
    "PROVIDER_ABI_V1",
    "PROVIDER_ACTION_CONTRACT_SCHEMA",
    "PROVIDER_BINDING_SCHEMA",
    "PROVIDER_PROGRAM_SCHEMA",
    "PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA",
    "ProviderRunnerContractError",
    "canonical_provider_artifacts",
    "canonical_provider_binding",
    "canonical_provider_bindings",
]
