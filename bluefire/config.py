"""Canonical two-mode configuration and runner-profile contracts."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    ContractError,
    ExecutionMode,
    SafetyTier,
    _bool,
    _enum,
    _load_yaml_mapping,
    _mapping,
    _namespace,
    _stable_id,
    _strict_fields,
    _string,
    _strings,
)


class ConfigError(ContractError):
    """Raised when canonical configuration is invalid."""


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class EnvironmentType(str, Enum):
    DISPOSABLE = "disposable"
    PERSISTENT_LAB = "persistent_lab"
    CLOUD_LAB = "cloud_lab"
    CUSTOM = "custom"


class CleanupPolicy(str, Enum):
    ALWAYS = "always"
    ON_SUCCESS = "on_success"
    MANUAL = "manual"


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{context} must be a positive integer")
    return int(value)


def _network_allowlist(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{context} must be a list of CIDR networks")
    result: list[str] = []
    for index, raw_network in enumerate(value):
        network_text = _string(raw_network, f"{context}[{index}]")
        if "/" not in network_text:
            raise ConfigError(f"{context}[{index}] must include an explicit CIDR prefix")
        try:
            network = ipaddress.ip_network(network_text, strict=True)
        except ValueError as exc:
            raise ConfigError(f"{context}[{index}] must be a canonical CIDR network") from exc
        result.append(network.with_prefixlen)
    if len(result) != len(set(result)):
        raise ConfigError(f"{context} contains duplicates")
    return tuple(result)


@dataclass(frozen=True, slots=True)
class EnvironmentReference:
    """A reference to an environment variable; the value is never resolved here."""

    env: str

    @classmethod
    def from_mapping(
        cls, value: Any, context: str = "environment reference"
    ) -> "EnvironmentReference":
        data = _mapping(value, context)
        _strict_fields(data, allowed={"env"}, required={"env"}, context=context)
        name = _string(data["env"], f"{context}.env")
        if not _ENV_NAME.fullmatch(name):
            raise ConfigError(f"{context}.env must be an uppercase environment variable name")
        return cls(env=name)

    def to_dict(self) -> dict[str, str]:
        return {"env": self.env}


@dataclass(frozen=True, slots=True)
class RunnerBudgets:
    max_steps: int
    max_seconds: int
    max_artifacts: int
    max_bytes: int

    @classmethod
    def from_mapping(cls, value: Any, context: str = "budgets") -> "RunnerBudgets":
        data = _mapping(value, context)
        fields = {"max_steps", "max_seconds", "max_artifacts", "max_bytes"}
        _strict_fields(data, allowed=fields, required=fields, context=context)
        return cls(
            max_steps=_positive_int(data["max_steps"], f"{context}.max_steps"),
            max_seconds=_positive_int(data["max_seconds"], f"{context}.max_seconds"),
            max_artifacts=_positive_int(data["max_artifacts"], f"{context}.max_artifacts"),
            max_bytes=_positive_int(data["max_bytes"], f"{context}.max_bytes"),
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "max_steps": self.max_steps,
            "max_seconds": self.max_seconds,
            "max_artifacts": self.max_artifacts,
            "max_bytes": self.max_bytes,
        }


@dataclass(frozen=True, slots=True)
class RunnerProfile:
    id: str
    mode: ExecutionMode
    environment_type: EnvironmentType
    platforms: tuple[str, ...]
    runner_binary: EnvironmentReference
    sandbox_root: EnvironmentReference
    scope: tuple[str, ...]
    network_allowlist: tuple[str, ...]
    capabilities: tuple[str, ...]
    safety_tiers: tuple[SafetyTier, ...]
    approval_required: bool
    enabled_actions: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    cleanup_policy: CleanupPolicy
    budgets: RunnerBudgets
    secrets: Mapping[str, EnvironmentReference] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Any, context: str = "runner profile") -> "RunnerProfile":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "id",
                "mode",
                "environment_type",
                "platforms",
                "runner_binary",
                "sandbox_root",
                "scope",
                "network_allowlist",
                "capabilities",
                "safety_tiers",
                "approval_required",
                "enabled_actions",
                "blocked_actions",
                "cleanup_policy",
                "budgets",
                "secrets",
            },
            required={
                "id",
                "mode",
                "environment_type",
                "platforms",
                "runner_binary",
                "sandbox_root",
                "scope",
                "network_allowlist",
                "capabilities",
                "safety_tiers",
                "approval_required",
                "enabled_actions",
                "blocked_actions",
                "cleanup_policy",
                "budgets",
            },
            context=context,
        )
        mode = _enum(ExecutionMode, data["mode"], f"{context}.mode")
        environment_type = _enum(
            EnvironmentType, data["environment_type"], f"{context}.environment_type"
        )
        platforms = _strings(data["platforms"], f"{context}.platforms")
        scope = _strings(data["scope"], f"{context}.scope")
        capabilities = _strings(data["capabilities"], f"{context}.capabilities")
        for index, item in enumerate(platforms):
            _namespace(item, f"{context}.platforms[{index}]")
        for index, item in enumerate(scope):
            _namespace(item, f"{context}.scope[{index}]")
        for index, item in enumerate(capabilities):
            _namespace(item, f"{context}.capabilities[{index}]")
        if not platforms:
            raise ConfigError(f"{context}.platforms cannot be empty")
        if not scope:
            raise ConfigError(f"{context}.scope cannot be empty")
        if not capabilities:
            raise ConfigError(f"{context}.capabilities cannot be empty")
        raw_tiers = data["safety_tiers"]
        if not isinstance(raw_tiers, list) or not raw_tiers:
            raise ConfigError(f"{context}.safety_tiers must be a non-empty list")
        tiers = tuple(
            _enum(SafetyTier, tier, f"{context}.safety_tiers[{index}]")
            for index, tier in enumerate(raw_tiers)
        )
        if len(tiers) != len(set(tiers)):
            raise ConfigError(f"{context}.safety_tiers contains duplicates")
        actions = _strings(data["enabled_actions"], f"{context}.enabled_actions", stable_ids=True)
        blocked_actions = _strings(
            data["blocked_actions"], f"{context}.blocked_actions", stable_ids=True
        )
        # A control-block list is an explicit override of the action allowlist.
        # Keeping an action in both sets lets planning remain type-complete
        # while policy and the Rust runner refuse it before side effects.
        approval_required = _bool(data["approval_required"], f"{context}.approval_required")
        if mode is ExecutionMode.SIMULATE and actions:
            raise ConfigError(f"{context} simulate profiles cannot enable runner actions")
        if mode is ExecutionMode.EXECUTE and not approval_required:
            raise ConfigError(f"{context} execute profiles must require approval")
        raw_secrets = _mapping(data.get("secrets", {}), f"{context}.secrets")
        secrets: dict[str, EnvironmentReference] = {}
        for name, reference in raw_secrets.items():
            key = _namespace(name, f"{context}.secrets key")
            secrets[key] = EnvironmentReference.from_mapping(reference, f"{context}.secrets.{key}")
        return cls(
            id=_stable_id(data["id"], f"{context}.id"),
            mode=mode,
            environment_type=environment_type,
            platforms=platforms,
            runner_binary=EnvironmentReference.from_mapping(
                data["runner_binary"], f"{context}.runner_binary"
            ),
            sandbox_root=EnvironmentReference.from_mapping(
                data["sandbox_root"], f"{context}.sandbox_root"
            ),
            scope=scope,
            network_allowlist=_network_allowlist(
                data["network_allowlist"], f"{context}.network_allowlist"
            ),
            capabilities=capabilities,
            safety_tiers=tiers,
            approval_required=approval_required,
            enabled_actions=actions,
            blocked_actions=blocked_actions,
            cleanup_policy=_enum(
                CleanupPolicy, data["cleanup_policy"], f"{context}.cleanup_policy"
            ),
            budgets=RunnerBudgets.from_mapping(data["budgets"], f"{context}.budgets"),
            secrets=secrets,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mode": self.mode.value,
            "environment_type": self.environment_type.value,
            "platforms": list(self.platforms),
            "runner_binary": self.runner_binary.to_dict(),
            "sandbox_root": self.sandbox_root.to_dict(),
            "scope": list(self.scope),
            "network_allowlist": list(self.network_allowlist),
            "capabilities": list(self.capabilities),
            "safety_tiers": [tier.value for tier in self.safety_tiers],
            "approval_required": self.approval_required,
            "enabled_actions": list(self.enabled_actions),
            "blocked_actions": list(self.blocked_actions),
            "cleanup_policy": self.cleanup_policy.value,
            "budgets": self.budgets.to_dict(),
            "secrets": {name: reference.to_dict() for name, reference in self.secrets.items()},
        }


@dataclass(frozen=True, slots=True)
class BlueFireConfig:
    schema_version: str
    mode: ExecutionMode
    ai_enabled: bool
    active_profile: str
    runner_profiles: tuple[RunnerProfile, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str = "config") -> "BlueFireConfig":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"schema_version", "mode", "ai", "active_profile", "runner_profiles"},
            required={"schema_version", "mode", "ai", "active_profile", "runner_profiles"},
            context=context,
        )
        if data["schema_version"] != "bluefire.config.v1":
            raise ConfigError(f"{context}.schema_version must be bluefire.config.v1")
        ai = _mapping(data["ai"], f"{context}.ai")
        _strict_fields(ai, allowed={"enabled"}, required={"enabled"}, context=f"{context}.ai")
        raw_profiles = data["runner_profiles"]
        if not isinstance(raw_profiles, list) or not raw_profiles:
            raise ConfigError(f"{context}.runner_profiles must be a non-empty list")
        profiles = tuple(
            RunnerProfile.from_mapping(item, f"{context}.runner_profiles[{index}]")
            for index, item in enumerate(raw_profiles)
        )
        profile_ids = [profile.id for profile in profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ConfigError(f"{context}.runner_profiles contains duplicate IDs")
        mode = _enum(ExecutionMode, data["mode"], f"{context}.mode")
        active_profile = _stable_id(data["active_profile"], f"{context}.active_profile")
        profiles_by_id = {profile.id: profile for profile in profiles}
        if active_profile not in profiles_by_id:
            raise ConfigError(f"{context}.active_profile does not exist")
        if profiles_by_id[active_profile].mode is not mode:
            raise ConfigError(f"{context}.active_profile mode does not match top-level mode")
        return cls(
            schema_version="bluefire.config.v1",
            mode=mode,
            ai_enabled=_bool(ai["enabled"], f"{context}.ai.enabled"),
            active_profile=active_profile,
            runner_profiles=profiles,
        )

    @property
    def active_runner_profile(self) -> RunnerProfile:
        for profile in self.runner_profiles:
            if profile.id == self.active_profile:
                return profile
        raise AssertionError("validated active profile is missing")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode.value,
            "ai": {"enabled": self.ai_enabled},
            "active_profile": self.active_profile,
            "runner_profiles": [profile.to_dict() for profile in self.runner_profiles],
        }


def load_config(path: str | Path) -> BlueFireConfig:
    """Load configuration without reading any referenced environment variable."""

    return BlueFireConfig.from_mapping(_load_yaml_mapping(path, "config"))


__all__ = [
    "BlueFireConfig",
    "CleanupPolicy",
    "ConfigError",
    "EnvironmentReference",
    "EnvironmentType",
    "RunnerBudgets",
    "RunnerProfile",
    "load_config",
]
