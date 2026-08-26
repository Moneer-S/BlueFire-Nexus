"""Immutable action-catalog generations and exact package execution bindings."""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .action_packages import VerifiedActionPackageActivation
from .config import RunnerProfile
from .contracts import ActionDefinition, BehaviorDefinition
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
            if set(opcode_index) != {item.definition.id for item in package.actions}:
                raise ActionCatalogError("activation opcode bindings do not cover the package")
            behaviors.extend(package.behaviors)
            actions.extend(item.definition for item in package.actions)
            package_rows.append(
                {
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
            )
            packaged_index = {item.definition.id: item for item in package.actions}
            for behavior in package.behaviors:
                for action_id in behavior.action_ids:
                    packaged_action = packaged_index[action_id]
                    opcode = opcode_index[action_id]
                    program = packaged_action.program.to_dict()
                    step = packaged_action.program.steps[0]
                    if opcode.opcode != step.opcode:
                        raise ActionCatalogError(
                            f"activation opcode binding changed package action {action_id}"
                        )
                    binding = {
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
                    key = (behavior.id, action_id)
                    if key in bindings:
                        raise ActionCatalogError(
                            f"duplicate package execution binding: {behavior.id}/{action_id}"
                        )
                    bindings[key] = MappingProxyType(binding)
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
            opcode = str(binding["runner_opcode"])
            alias = str(binding["logical_action_id"])
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
            if binding["runner_opcode"] in profile.enabled_actions
            and binding["runner_opcode"] not in profile.blocked_actions
        ]
        result.sort(
            key=lambda item: (str(item["logical_behavior_id"]), str(item["logical_action_id"]))
        )
        return tuple(result)

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


__all__ = [
    "ActionCatalogError",
    "ActionCatalogSnapshot",
    "ActivatedActionPackage",
]
