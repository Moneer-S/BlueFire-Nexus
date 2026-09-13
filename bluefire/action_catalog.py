"""Immutable action-catalog generations and exact package execution bindings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .action_packages import (
    ActionProgram,
    VerifiedActionPackageActivation,
    WasmProviderProgram,
)
from .config import RunnerProfile
from .contracts import ActionDefinition, BehaviorDefinition, SafetyTier
from .provider_runner_contracts import (
    PROVIDER_BINDING_SCHEMA,
    PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA,
    canonical_provider_binding,
)
from .registry import BehaviorRegistry, RegistryError
from .util import content_hash


class ActionCatalogError(ValueError):
    """Raised when an active package catalog cannot be reconstructed exactly."""


@dataclass(frozen=True, slots=True)
class ActivatedActionPackage:
    """One active immutable package and the generation that published it."""

    generation: int
    activation: VerifiedActionPackageActivation

    def __post_init__(self) -> None:
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise ActionCatalogError("package activation generation must be positive")
        if self.activation.expected_catalog_generation >= self.generation:
            raise ActionCatalogError("package activation generation does not advance its preflight")


@dataclass(frozen=True, slots=True)
class ActionCatalogSnapshot:
    """One immutable built-in plus active-package registry generation."""

    generation: int
    catalog_digest: str
    registry: BehaviorRegistry
    built_in_catalog_digest: str
    packages: tuple[Mapping[str, Any], ...]
    action_bindings: Mapping[tuple[str, str], Mapping[str, Any]]
    native_action_requirements: Mapping[tuple[str, str], Mapping[str, str]]
    provider_artifacts: Mapping[str, Mapping[str, Any]]
    authority: Mapping[str, Any]

    @classmethod
    def compose(
        cls,
        built_in_registry: BehaviorRegistry,
        *,
        generation: int,
        catalog_digest: str,
        active_packages: Sequence[ActivatedActionPackage] = (),
    ) -> "ActionCatalogSnapshot":
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ActionCatalogError("catalog generation must be a non-negative integer")
        _digest(catalog_digest, "catalog digest")

        built_in_document = {
            "schema_version": "bluefire.built-in-catalog-snapshot.v1",
            "behaviors": [item.to_dict() for item in built_in_registry.behaviors],
            "actions": [item.to_dict() for item in built_in_registry.actions],
        }
        built_in_digest = content_hash(built_in_document)
        ordered = sorted(
            active_packages,
            key=lambda item: item.activation.package.manifest.package_id,
        )
        package_ids: set[str] = set()
        behaviors: list[BehaviorDefinition] = []
        actions: list[ActionDefinition] = []
        bindings: dict[tuple[str, str], Mapping[str, Any]] = {}
        native_requirements: dict[tuple[str, str], Mapping[str, str]] = {}
        provider_artifacts: dict[str, Mapping[str, Any]] = {}
        package_rows: list[Mapping[str, Any]] = []
        for active in ordered:
            activation = active.activation
            package = activation.package
            manifest = package.manifest
            if active.generation > generation:
                raise ActionCatalogError(
                    "active package was published after the catalog generation"
                )
            if manifest.package_id in package_ids:
                raise ActionCatalogError(f"duplicate active package ID: {manifest.package_id}")
            package_ids.add(manifest.package_id)
            opcode_index = {item.package_action_id: item for item in activation.opcode_bindings}
            action_ids = {item.definition.id for item in package.actions}
            provider_runtime = (
                activation.provider_bindings[0] if activation.provider_bindings else None
            )
            if package.provider is None:
                if set(opcode_index) != action_ids or provider_runtime is not None:
                    raise ActionCatalogError("activation opcode bindings do not cover the package")
            elif opcode_index or len(activation.provider_bindings) != 1:
                raise ActionCatalogError("provider activation has an invalid execution binding")
            behaviors.extend(package.behaviors)
            actions.extend(item.definition for item in package.actions)
            package_row: dict[str, Any] = {
                "package_id": manifest.package_id,
                "package_version": manifest.version,
                "package_digest": package.package_digest,
                "content_digest": package.content_digest,
                "publisher_id": package.publisher_id,
                "key_id": package.key_id,
                "signer_fingerprint": package.public_key_fingerprint,
                "activated_generation": active.generation,
                "runner_identity_digest": activation.runner_identity_digest,
                "runner_inventory_digest": activation.runner_inventory_digest,
                "runner_platform": activation.runner_platform,
                "behavior_ids": list(manifest.behavior_ids),
                "action_ids": list(manifest.action_ids),
            }
            if package.provider is not None:
                if provider_runtime is None:  # pragma: no cover - guarded above
                    raise ActionCatalogError("provider activation has no runtime binding")
                if (
                    provider_runtime.provider_id != package.provider.provider_id
                    or provider_runtime.abi_version != package.provider.abi_version
                    or provider_runtime.artifact_sha256 != package.provider.artifact_sha256
                    or provider_runtime.artifact_size != package.provider.artifact_size
                    or provider_runtime.limits != package.provider.limits
                ):
                    raise ActionCatalogError(
                        "provider activation changed its signed package descriptor"
                    )
                package_row["provider"] = {
                    **package.provider.to_dict(),
                    "provider_runtime_contract_digest": (
                        provider_runtime.runtime_inventory_contract_digest
                    ),
                }
                package_row["execution_model"] = "wasm_provider_v1"
                artifact = package.provider_artifact_bytes
                if artifact is None:  # pragma: no cover - verified package invariant
                    raise ActionCatalogError("provider package has no verified artifact")
                if (
                    len(artifact) != package.provider.artifact_size
                    or "sha256:" + hashlib.sha256(artifact).hexdigest()
                    != package.provider.artifact_sha256
                ):
                    raise ActionCatalogError("provider package artifact changed after verification")
                artifact_row = {
                    "artifact_sha256": package.provider.artifact_sha256,
                    "artifact_size": package.provider.artifact_size,
                    "artifact_hex": artifact.hex(),
                }
                existing_artifact = provider_artifacts.get(package.provider.artifact_sha256)
                if existing_artifact is not None and dict(existing_artifact) != artifact_row:
                    raise ActionCatalogError("provider artifact digest has conflicting bytes")
                provider_artifacts[package.provider.artifact_sha256] = MappingProxyType(
                    artifact_row
                )
            package_rows.append(package_row)
            packaged_index = {item.definition.id: item for item in package.actions}
            for behavior in package.behaviors:
                for action_id in behavior.action_ids:
                    packaged_action = packaged_index[action_id]
                    program = packaged_action.program.to_dict()
                    if isinstance(packaged_action.program, ActionProgram):
                        opcode = opcode_index[action_id]
                        step = packaged_action.program.steps[0]
                        if opcode.opcode != step.opcode:
                            raise ActionCatalogError(
                                f"activation opcode binding changed package action {action_id}"
                            )
                        binding: Mapping[str, Any] = {
                            "schema_version": "bluefire.runner-execution-binding.v1",
                            "catalog_generation": generation,
                            "catalog_digest": catalog_digest,
                            "logical_behavior_id": behavior.id,
                            "logical_action_id": action_id,
                            "package_id": manifest.package_id,
                            "package_version": manifest.version,
                            "package_digest": package.package_digest,
                            "content_digest": package.content_digest,
                            "program_digest": content_hash(program),
                            "runner_opcode": step.opcode,
                            "opcode_contract_digest": opcode.contract_digest,
                            "constants": dict(step.constants),
                        }
                    elif isinstance(packaged_action.program, WasmProviderProgram):
                        if provider_runtime is None or package.provider is None:
                            raise ActionCatalogError("provider program has no runtime activation")
                        definition = packaged_action.definition
                        inputs = [_io_spec(item) for item in definition.inputs]
                        outputs = [_io_spec(item) for item in definition.outputs]
                        parameters = [_parameter_spec(item) for item in definition.parameters]
                        runtime_contract = {
                            "schema_version": PROVIDER_RUNTIME_ACTION_CONTRACT_SCHEMA,
                            "logical_action_id": action_id,
                            "inputs": inputs,
                            "outputs": outputs,
                            "parameters": parameters,
                            "capabilities": ["native_execution"],
                            "safety_tier": "safe",
                            "platforms": list(definition.platforms),
                            "mutates": False,
                            "cleanup_action_id": None,
                        }
                        candidate = {
                            "schema_version": PROVIDER_BINDING_SCHEMA,
                            "catalog_generation": generation,
                            "catalog_digest": catalog_digest,
                            "logical_behavior_id": behavior.id,
                            "logical_action_id": action_id,
                            "package_id": manifest.package_id,
                            "package_version": manifest.version,
                            "package_digest": package.package_digest,
                            "content_digest": package.content_digest,
                            "program_digest": content_hash(program),
                            "provider_id": packaged_action.program.provider_id,
                            "abi_version": provider_runtime.abi_version,
                            "artifact_sha256": provider_runtime.artifact_sha256,
                            "artifact_size": provider_runtime.artifact_size,
                            "action_contract_digest": (
                                packaged_action.program.action_contract_digest
                            ),
                            "runtime_contract_digest": content_hash(runtime_contract),
                            "provider_runtime_contract_digest": (
                                provider_runtime.runtime_inventory_contract_digest
                            ),
                            "inputs": inputs,
                            "outputs": outputs,
                            "parameters": parameters,
                            "capabilities": ["native_execution"],
                            "safety_tier": "safe",
                            "platforms": list(definition.platforms),
                            "mutates": False,
                            "cleanup_action_id": None,
                            "limits": provider_runtime.limits.to_dict(),
                        }
                        try:
                            binding = canonical_provider_binding(
                                candidate,
                                context=f"provider binding {behavior.id}/{action_id}",
                            )
                        except ValueError as exc:
                            raise ActionCatalogError(str(exc)) from exc
                    else:  # pragma: no cover - closed parser union
                        raise ActionCatalogError("package action program is unsupported")
                    key = (behavior.id, action_id)
                    if key in bindings:
                        raise ActionCatalogError(
                            f"duplicate package execution binding: {behavior.id}/{action_id}"
                        )
                    bindings[key] = MappingProxyType(binding)
                    if isinstance(packaged_action.program, ActionProgram):
                        native_requirements[key] = MappingProxyType(
                            {
                                "runner_opcode": opcode.opcode,
                                "action_version": opcode.action_version,
                                "contract_digest": opcode.contract_digest,
                            }
                        )

        derived_catalog_digest = content_hash(
            {
                "schema_version": "bluefire.active-action-package-catalog.v1",
                "packages": [
                    {
                        "package_id": item["package_id"],
                        "version": item["package_version"],
                        "package_digest": item["package_digest"],
                        "content_digest": item["content_digest"],
                    }
                    for item in package_rows
                ],
            }
        )
        if derived_catalog_digest != catalog_digest:
            raise ActionCatalogError("active package catalog digest does not match its packages")

        try:
            registry = built_in_registry.extended(behaviors=behaviors, actions=actions)
        except RegistryError as exc:
            raise ActionCatalogError(str(exc)) from exc
        body = {
            "schema_version": "bluefire.action-catalog-authority.v1",
            "generation": generation,
            "catalog_digest": catalog_digest,
            "built_in_catalog_digest": built_in_digest,
            "packages": package_rows,
            "action_bindings": [dict(bindings[key]) for key in sorted(bindings)],
        }
        authority = MappingProxyType({**body, "authority_digest": content_hash(body)})
        return cls(
            generation=generation,
            catalog_digest=catalog_digest,
            registry=registry,
            built_in_catalog_digest=built_in_digest,
            packages=tuple(MappingProxyType(dict(item)) for item in package_rows),
            action_bindings=MappingProxyType(bindings),
            native_action_requirements=MappingProxyType(native_requirements),
            provider_artifacts=MappingProxyType(provider_artifacts),
            authority=authority,
        )

    def execution_binding(
        self,
        behavior_id: str,
        action_id: str,
    ) -> Mapping[str, Any] | None:
        binding = self.action_bindings.get((behavior_id, action_id))
        return dict(binding) if binding is not None else None

    def profile(self, profile: RunnerProfile) -> RunnerProfile:
        """Add only aliases whose exact reviewed opcode is enabled by the profile."""

        enabled = list(profile.enabled_actions)
        blocked = list(profile.blocked_actions)
        for binding in self.action_bindings.values():
            alias = str(binding["logical_action_id"])
            if binding.get("schema_version") == PROVIDER_BINDING_SCHEMA:
                if not _provider_profile_compatible(binding, profile):
                    continue
            else:
                opcode = str(binding["runner_opcode"])
                if opcode not in profile.enabled_actions or opcode in profile.blocked_actions:
                    continue
            if alias not in enabled:
                enabled.append(alias)
        return replace(
            profile,
            enabled_actions=tuple(enabled),
            blocked_actions=tuple(blocked),
        )

    def profile_action_bindings(self, profile: RunnerProfile) -> tuple[Mapping[str, Any], ...]:
        """Return exact native bindings reachable through one effective profile."""

        result = [
            dict(binding)
            for binding in self.action_bindings.values()
            if binding.get("schema_version") != PROVIDER_BINDING_SCHEMA
            and binding["runner_opcode"] in profile.enabled_actions
            and binding["runner_opcode"] not in profile.blocked_actions
        ]
        result.sort(
            key=lambda item: (str(item["logical_behavior_id"]), str(item["logical_action_id"]))
        )
        return tuple(result)

    def profile_provider_bindings(
        self,
        profile: RunnerProfile,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return exact provider bindings reachable through one effective profile."""

        result = [
            dict(binding)
            for binding in self.action_bindings.values()
            if binding.get("schema_version") == PROVIDER_BINDING_SCHEMA
            and binding.get("logical_action_id") in profile.enabled_actions
            and _provider_profile_compatible(binding, profile)
        ]
        result.sort(
            key=lambda item: (str(item["logical_behavior_id"]), str(item["logical_action_id"]))
        )
        return tuple(result)

    def profile_provider_artifacts(
        self,
        profile: RunnerProfile,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return private artifact rows required by one effective runner profile."""

        digests = {
            str(binding["artifact_sha256"]) for binding in self.profile_provider_bindings(profile)
        }
        try:
            return tuple(dict(self.provider_artifacts[digest]) for digest in sorted(digests))
        except KeyError as exc:  # pragma: no cover - composition invariant
            raise ActionCatalogError("provider binding has no private artifact") from exc

    def profile_native_action_requirements(
        self,
        profile: RunnerProfile,
    ) -> tuple[Mapping[str, str], ...]:
        """Return sealed native descriptors for aliases reachable by one profile."""

        result = [
            {
                "logical_behavior_id": key[0],
                "logical_action_id": key[1],
                **dict(requirement),
            }
            for key, requirement in self.native_action_requirements.items()
            if requirement["runner_opcode"] in profile.enabled_actions
            and requirement["runner_opcode"] not in profile.blocked_actions
        ]
        result.sort(key=lambda item: (item["logical_behavior_id"], item["logical_action_id"]))
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            **dict(self.authority),
            "packages": [dict(item) for item in self.packages],
            "action_bindings": [
                dict(self.action_bindings[key]) for key in sorted(self.action_bindings)
            ],
        }


def _digest(value: str, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ActionCatalogError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _io_spec(value: Any) -> dict[str, Any]:
    return {
        "name": value.name,
        "type": value.type,
        "required": value.required,
        "multiple": value.multiple,
    }


def _parameter_spec(value: Any) -> dict[str, Any]:
    return {
        "name": value.name,
        "type": value.type.value,
        "required": value.required,
        "default": value.default,
        "enum": list(value.enum),
        "minimum": value.minimum,
        "maximum": value.maximum,
    }


def _provider_profile_compatible(
    binding: Mapping[str, Any],
    profile: RunnerProfile,
) -> bool:
    return bool(
        binding.get("logical_action_id") not in profile.blocked_actions
        and "native.execution" in profile.capabilities
        and SafetyTier.SAFE in profile.safety_tiers
        and set(binding.get("platforms", ())).intersection(profile.platforms)
    )


__all__ = [
    "ActionCatalogError",
    "ActionCatalogSnapshot",
    "ActivatedActionPackage",
]
