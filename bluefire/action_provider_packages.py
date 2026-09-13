"""Strict contracts for independently executable WebAssembly action packages.

This module contains no loader or execution path.  It validates the signed
artifact and the exact runtime contract that a later runner activation may
bind.  Package-controlled paths, imports, entry points, and host effects are
deliberately absent from the schema.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .action_package_errors import ActionPackageError
from .contracts import ActionDefinition, ParameterType, SafetyTier
from .util import canonical_json_bytes, content_hash

ACTION_PACKAGE_V2_SCHEMA = "bluefire.action-package.v2"
ACTION_PACKAGE_PAYLOAD_V2_SCHEMA = "bluefire.action-package-payload.v2"
WASM_PROVIDER_PROGRAM_SCHEMA = "bluefire.wasm-provider-program.v1"
WASM_PROVIDER_ABI_V1 = "bluefire.provider-abi.v1"
PROVIDER_ACTION_CONTRACT_SCHEMA = "bluefire.provider-action-contract.v1"

MAX_PROVIDER_ARTIFACT_BYTES = 64 * 1024
MAX_PROVIDER_MODULE_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_MEMORY_BYTES = 16 * 1024 * 1024
MAX_PROVIDER_JSON_BYTES = 1024 * 1024
MAX_PROVIDER_FUEL = 100_000_000

_MAX_INTEGER = (1 << 63) - 1
_MAX_SAFE_INTEGER = (1 << 53) - 1
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOWER_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")
_WASM_V1_HEADER = b"\0asm\x01\0\0\0"


def _strict_mapping(
    value: Any,
    *,
    context: str,
    fields: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ActionPackageError(f"{context} must contain exactly: {', '.join(sorted(fields))}")
    return value


def _stable_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ActionPackageError(f"{context} must be a stable versioned identifier")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ActionPackageError(f"{context} must be an exact lowercase SHA-256 digest")
    return value


def _positive_integer(value: Any, context: str, *, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= min(maximum, _MAX_INTEGER)
    ):
        raise ActionPackageError(f"{context} must be an integer in 1..={maximum}")
    return int(value)


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    max_module_bytes: int
    max_memory_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    fuel: int

    @classmethod
    def from_mapping(cls, value: Any, context: str) -> "ProviderLimits":
        data = _strict_mapping(
            value,
            context=context,
            fields={
                "max_module_bytes",
                "max_memory_bytes",
                "max_input_bytes",
                "max_output_bytes",
                "fuel",
            },
        )
        result = cls(
            max_module_bytes=_positive_integer(
                data["max_module_bytes"],
                f"{context}.max_module_bytes",
                maximum=MAX_PROVIDER_MODULE_BYTES,
            ),
            max_memory_bytes=_positive_integer(
                data["max_memory_bytes"],
                f"{context}.max_memory_bytes",
                maximum=MAX_PROVIDER_MEMORY_BYTES,
            ),
            max_input_bytes=_positive_integer(
                data["max_input_bytes"],
                f"{context}.max_input_bytes",
                maximum=MAX_PROVIDER_JSON_BYTES,
            ),
            max_output_bytes=_positive_integer(
                data["max_output_bytes"],
                f"{context}.max_output_bytes",
                maximum=MAX_PROVIDER_JSON_BYTES,
            ),
            fuel=_positive_integer(data["fuel"], f"{context}.fuel", maximum=MAX_PROVIDER_FUEL),
        )
        if result.max_memory_bytes < 64 * 1024:
            raise ActionPackageError(f"{context}.max_memory_bytes must allow one WASM page")
        return result

    def to_dict(self) -> dict[str, int]:
        return {
            "max_module_bytes": self.max_module_bytes,
            "max_memory_bytes": self.max_memory_bytes,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "fuel": self.fuel,
        }

    def fits_within(self, hard_limits: "ProviderLimits") -> bool:
        return (
            self.max_module_bytes <= hard_limits.max_module_bytes
            and self.max_memory_bytes <= hard_limits.max_memory_bytes
            and self.max_input_bytes <= hard_limits.max_input_bytes
            and self.max_output_bytes <= hard_limits.max_output_bytes
            and self.fuel <= hard_limits.fuel
        )


@dataclass(frozen=True, slots=True)
class WasmProviderDescriptor:
    kind: str
    provider_id: str
    abi_version: str
    artifact_sha256: str
    artifact_size: int
    limits: ProviderLimits

    @classmethod
    def from_mapping(
        cls, value: Any, context: str = "manifest.provider"
    ) -> "WasmProviderDescriptor":
        data = _strict_mapping(
            value,
            context=context,
            fields={
                "kind",
                "provider_id",
                "abi_version",
                "artifact_sha256",
                "artifact_size",
                "limits",
            },
        )
        if data["kind"] != "wasm":
            raise ActionPackageError(f"{context}.kind must be wasm")
        if data["abi_version"] != WASM_PROVIDER_ABI_V1:
            raise ActionPackageError(f"{context}.abi_version is unsupported")
        artifact_size = _positive_integer(
            data["artifact_size"],
            f"{context}.artifact_size",
            maximum=MAX_PROVIDER_ARTIFACT_BYTES,
        )
        limits = ProviderLimits.from_mapping(data["limits"], f"{context}.limits")
        if artifact_size > limits.max_module_bytes:
            raise ActionPackageError(f"{context}.artifact_size exceeds max_module_bytes")
        return cls(
            kind="wasm",
            provider_id=_stable_id(data["provider_id"], f"{context}.provider_id"),
            abi_version=WASM_PROVIDER_ABI_V1,
            artifact_sha256=_digest(data["artifact_sha256"], f"{context}.artifact_sha256"),
            artifact_size=artifact_size,
            limits=limits,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "provider_id": self.provider_id,
            "abi_version": self.abi_version,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "limits": self.limits.to_dict(),
        }

    def verify_artifact(self, artifact: bytes) -> None:
        if len(artifact) != self.artifact_size:
            raise ActionPackageError("provider artifact size does not match its signed manifest")
        actual = "sha256:" + hashlib.sha256(artifact).hexdigest()
        if actual != self.artifact_sha256:
            raise ActionPackageError("provider artifact digest does not match its signed manifest")


def parse_provider_artifact_hex(value: Any) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > MAX_PROVIDER_ARTIFACT_BYTES * 2
        or _LOWER_HEX.fullmatch(value) is None
    ):
        raise ActionPackageError(
            "payload.artifact_hex must be non-empty canonical lowercase even-length hex"
        )
    artifact = bytes.fromhex(value)
    if not artifact.startswith(_WASM_V1_HEADER):
        raise ActionPackageError("payload.artifact_hex must encode a version-1 WebAssembly module")
    return artifact


def provider_action_contract(action: ActionDefinition) -> dict[str, Any]:
    return {
        "schema_version": PROVIDER_ACTION_CONTRACT_SCHEMA,
        "action": {
            "id": action.id,
            "inputs": [
                {
                    "name": item.name,
                    "type": item.type,
                    "required": item.required,
                    "multiple": item.multiple,
                }
                for item in action.inputs
            ],
            "outputs": [
                {
                    "name": item.name,
                    "type": item.type,
                    "required": item.required,
                    "multiple": item.multiple,
                }
                for item in action.outputs
            ],
            "parameters": [
                {
                    "name": item.name,
                    "type": item.type.value,
                    "required": item.required,
                    "default": item.default,
                    "enum": list(item.enum),
                    "minimum": item.minimum,
                    "maximum": item.maximum,
                }
                for item in action.parameters
            ],
            "capabilities": list(action.capabilities),
            "safety_tier": action.safety_tier.value,
            "platforms": list(action.platforms),
            "mutates": action.mutates,
            "cleanup_action_id": action.cleanup_action_id,
        },
    }


def provider_action_contract_digest(action: ActionDefinition) -> str:
    return content_hash(provider_action_contract(action))


def validate_provider_action(action: ActionDefinition, context: str) -> None:
    if action.safety_tier is not SafetyTier.SAFE:
        raise ActionPackageError(f"{context} provider action must use the safe tier")
    if action.mutates or action.cleanup_action_id is not None:
        raise ActionPackageError(f"{context} provider action must be effect-free")
    if action.inputs:
        raise ActionPackageError(f"{context} provider action cannot accept artifact inputs")
    if action.capabilities != ("native.execution",):
        raise ActionPackageError(
            f"{context} provider action capabilities must be exactly native.execution"
        )
    for parameter in action.parameters:
        numeric = parameter.type in {ParameterType.INTEGER, ParameterType.NUMBER}
        if not numeric and (parameter.minimum is not None or parameter.maximum is not None):
            raise ActionPackageError(
                f"{context} provider parameter {parameter.name} has nonnumeric bounds"
            )
        if numeric:
            # These values enter browser scenario authoring and must survive
            # native JSON parse/stringify without changing the signed contract.
            catalog_values: list[tuple[str, Any]] = []
            if parameter.default is not None:
                catalog_values.append(("default", parameter.default))
            catalog_values.extend(
                (f"enum[{index}]", value) for index, value in enumerate(parameter.enum)
            )
            for field, value in catalog_values:
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
                ):
                    raise ActionPackageError(
                        f"{context} provider parameter {parameter.name} {field} "
                        "is outside the catalog-safe integer range"
                    )
        for bound in (parameter.minimum, parameter.maximum):
            if bound is not None and (
                not float(bound).is_integer()
                or not -_MAX_SAFE_INTEGER <= bound <= _MAX_SAFE_INTEGER
            ):
                raise ActionPackageError(
                    f"{context} provider parameter {parameter.name} has an unsafe numeric bound"
                )
        enum_values: set[bytes] = set()
        for value in parameter.enum:
            encoded = canonical_json_bytes(value)
            if encoded in enum_values:
                raise ActionPackageError(
                    f"{context} provider parameter {parameter.name} enum contains duplicates"
                )
            enum_values.add(encoded)


@dataclass(frozen=True, slots=True)
class WasmProviderProgram:
    schema_version: str
    provider_id: str
    action_contract_digest: str

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        action: ActionDefinition,
        context: str,
    ) -> "WasmProviderProgram":
        data = _strict_mapping(
            value,
            context=context,
            fields={"schema_version", "provider_id", "action_contract_digest"},
        )
        if data["schema_version"] != WASM_PROVIDER_PROGRAM_SCHEMA:
            raise ActionPackageError(f"{context}.schema_version is unsupported")
        validate_provider_action(action, context)
        claimed = _digest(data["action_contract_digest"], f"{context}.action_contract_digest")
        if claimed != provider_action_contract_digest(action):
            raise ActionPackageError(f"{context}.action_contract_digest does not match its action")
        return cls(
            schema_version=WASM_PROVIDER_PROGRAM_SCHEMA,
            provider_id=_stable_id(data["provider_id"], f"{context}.provider_id"),
            action_contract_digest=claimed,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "provider_id": self.provider_id,
            "action_contract_digest": self.action_contract_digest,
        }


@dataclass(frozen=True, slots=True)
class WasmProviderBinding:
    provider_id: str
    abi_version: str
    artifact_sha256: str
    artifact_size: int
    limits: ProviderLimits
    runtime_inventory_contract_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "abi_version": self.abi_version,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "limits": self.limits.to_dict(),
            "runtime_inventory_contract_digest": self.runtime_inventory_contract_digest,
        }


def _runtime_version(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ActionPackageError(f"{context} must be a bounded runtime version")
    return value


def _canonical_provider_runtimes(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 8:
        raise ActionPackageError("runner provider_runtimes must be a bounded list")
    runtimes: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(value):
        context = f"runner provider_runtimes[{index}]"
        fields = {
            "kind",
            "abi_version",
            "runtime_version",
            "readiness",
            "no_host_imports",
            "hard_limits",
            "contract_digest",
        }
        data = _strict_mapping(raw, context=context, fields=fields)
        if data["kind"] != "wasm" or data["abi_version"] != WASM_PROVIDER_ABI_V1:
            raise ActionPackageError(f"{context} identifies an unsupported provider runtime")
        if data["readiness"] not in {"ready", "structural", "unavailable"}:
            raise ActionPackageError(f"{context}.readiness is invalid")
        if data["no_host_imports"] is not True:
            raise ActionPackageError(f"{context}.no_host_imports must be true")
        limits = ProviderLimits.from_mapping(data["hard_limits"], f"{context}.hard_limits")
        contract = {
            "kind": "wasm",
            "abi_version": WASM_PROVIDER_ABI_V1,
            "runtime_version": _runtime_version(
                data["runtime_version"], f"{context}.runtime_version"
            ),
            "readiness": data["readiness"],
            "no_host_imports": True,
            "hard_limits": limits.to_dict(),
        }
        contract_digest = _digest(data["contract_digest"], f"{context}.contract_digest")
        if contract_digest != content_hash(contract):
            raise ActionPackageError(f"{context}.contract_digest does not match its runtime")
        identity = ("wasm", WASM_PROVIDER_ABI_V1)
        if identity in identities:
            raise ActionPackageError("runner provider_runtimes contains a duplicate runtime")
        identities.add(identity)
        runtimes.append({**contract, "contract_digest": contract_digest})
    runtimes.sort(key=lambda item: (str(item["kind"]), str(item["abi_version"])))
    return runtimes


def canonical_activation_runner_inventory(
    inventory: Mapping[str, Any],
) -> tuple[Mapping[str, Any], bytes]:
    """Accept one raw inventory or an exact canonical activation replay."""

    from .runner_inventory import RunnerInventoryAuthorityError, canonical_runner_inventory

    canonical_keys = {
        "schema_version",
        "runner_id",
        "runner_version",
        "action_sdk_version",
        "receipt_protocol",
        "platform",
        "source_digest",
        "actions",
    }
    raw_actions = inventory.get("actions") if isinstance(inventory, Mapping) else None
    keys = set(inventory) if isinstance(inventory, Mapping) else set()
    has_canonical_runtimes = "provider_runtimes" in keys
    expected_keys = canonical_keys | ({"provider_runtimes"} if has_canonical_runtimes else set())
    is_canonical = (
        isinstance(inventory, Mapping)
        and keys == expected_keys
        and isinstance(raw_actions, list)
        and all(
            isinstance(item, Mapping)
            and set(item) == {"action_id", "action_version", "readiness", "contract_digest"}
            for item in raw_actions
        )
    )
    try:
        if not is_canonical:
            canonical = dict(canonical_runner_inventory(inventory))
            runtimes = _canonical_provider_runtimes(inventory.get("provider_runtimes"))
            if "provider_runtimes" in inventory:
                runner_runtimes = canonical.get("provider_runtimes")
                if runner_runtimes is None:
                    # Compatibility bridge for pre-extension runner clients.
                    # Updated clients return and validate these rows themselves.
                    canonical["provider_runtimes"] = runtimes
                elif _canonical_provider_runtimes(runner_runtimes) != runtimes:
                    raise ActionPackageError("runner provider runtime canonicalization changed")
            return canonical, canonical_json_bytes(canonical)

        if not isinstance(raw_actions, list):  # pragma: no cover - canonical shape invariant
            raise ActionPackageError("canonical runner actions must be an array")
        probe = {
            key: inventory[key]
            for key in (
                "schema_version",
                "runner_id",
                "runner_version",
                "action_sdk_version",
                "receipt_protocol",
                "platform",
            )
        }
        probe["actions"] = [
            {
                "action_id": item["action_id"],
                "action_version": item["action_version"],
                "readiness": item["readiness"],
            }
            for item in raw_actions
        ]
        if has_canonical_runtimes:
            probe["provider_runtimes"] = [
                dict(item)
                for item in _canonical_provider_runtimes(inventory.get("provider_runtimes"))
            ]
        validated = canonical_runner_inventory(probe)
        if any(
            validated[key] != inventory[key]
            for key in (
                "schema_version",
                "runner_id",
                "runner_version",
                "action_sdk_version",
                "receipt_protocol",
                "platform",
            )
        ):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        if [
            (item["action_id"], item["action_version"], item["readiness"])
            for item in validated["actions"]
        ] != [
            (item["action_id"], item["action_version"], item["readiness"]) for item in raw_actions
        ]:
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        if _SHA256.fullmatch(str(inventory["source_digest"])) is None or any(
            _SHA256.fullmatch(str(item["contract_digest"])) is None for item in raw_actions
        ):
            raise RunnerInventoryAuthorityError("Runner inventory is invalid or unsupported.")
        canonical = dict(inventory)
        canonical["actions"] = [dict(item) for item in raw_actions]
        if has_canonical_runtimes:
            canonical["provider_runtimes"] = _canonical_provider_runtimes(
                inventory.get("provider_runtimes")
            )
        return canonical, canonical_json_bytes(canonical)
    except ActionPackageError:
        raise
    except (KeyError, RunnerInventoryAuthorityError, TypeError, ValueError) as exc:
        raise ActionPackageError("runner inventory is invalid or unsupported") from exc


def bind_provider_runtime(
    descriptor: WasmProviderDescriptor,
    inventory: Mapping[str, Any],
) -> WasmProviderBinding:
    raw_runtimes = inventory.get("provider_runtimes")
    if not isinstance(raw_runtimes, list):
        raise ActionPackageError("runner inventory has no provider runtime support")
    runtimes = _canonical_provider_runtimes(raw_runtimes)
    runtime = next(
        (
            item
            for item in runtimes
            if item.get("kind") == descriptor.kind
            and item.get("abi_version") == descriptor.abi_version
        ),
        None,
    )
    if runtime is None or runtime.get("readiness") != "ready":
        raise ActionPackageError("runner provider runtime is unavailable")
    hard_limits = ProviderLimits.from_mapping(
        runtime.get("hard_limits"), "runner provider runtime hard_limits"
    )
    if not descriptor.limits.fits_within(hard_limits):
        raise ActionPackageError("package provider limits exceed the runner runtime")
    runtime_digest = _digest(
        runtime.get("contract_digest"), "runner provider runtime contract digest"
    )
    return WasmProviderBinding(
        provider_id=descriptor.provider_id,
        abi_version=descriptor.abi_version,
        artifact_sha256=descriptor.artifact_sha256,
        artifact_size=descriptor.artifact_size,
        limits=descriptor.limits,
        runtime_inventory_contract_digest=runtime_digest,
    )


__all__ = [
    "ACTION_PACKAGE_PAYLOAD_V2_SCHEMA",
    "ACTION_PACKAGE_V2_SCHEMA",
    "MAX_PROVIDER_ARTIFACT_BYTES",
    "PROVIDER_ACTION_CONTRACT_SCHEMA",
    "ProviderLimits",
    "WASM_PROVIDER_ABI_V1",
    "WASM_PROVIDER_PROGRAM_SCHEMA",
    "WasmProviderBinding",
    "WasmProviderDescriptor",
    "WasmProviderProgram",
    "bind_provider_runtime",
    "canonical_activation_runner_inventory",
    "parse_provider_artifact_hex",
    "provider_action_contract",
    "provider_action_contract_digest",
]
