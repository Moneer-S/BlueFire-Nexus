"""Canonical two-mode configuration and runner-profile contracts."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .contracts import (
    ContractError,
    ExecutionMode,
    SafetyTier,
    _bool,
    _enum,
    _field_name,
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
_MAX_RUNNER_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_RUNNER_ARTIFACTS = 512
_MAX_RUNNER_EXECUTION_SECONDS = 24 * 60 * 60
_MAX_RUNNER_STEPS = 256


class EnvironmentType(str, Enum):
    DISPOSABLE = "disposable"
    PERSISTENT_LAB = "persistent_lab"
    CLOUD_LAB = "cloud_lab"
    CUSTOM = "custom"


class CleanupPolicy(str, Enum):
    ALWAYS = "always"
    ON_SUCCESS = "on_success"
    MANUAL = "manual"


class AutonomyLevel(str, Enum):
    """How model proposals may influence an active plan."""

    OFF = "off"
    ASSIST = "assist"
    AUTO = "auto"


class AIProviderKind(str, Enum):
    DETERMINISTIC = "deterministic"
    OPENAI_RESPONSES = "openai_responses"


def _bounded_int(value: Any, context: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f"{context} must be an integer between {minimum} and {maximum}")
    return int(value)


def _responses_endpoint(value: Any, context: str) -> str:
    endpoint = _string(value, context).rstrip("/")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{context} must be a valid HTTP(S) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError(f"{context} must be an HTTP(S) URL without credentials or query data")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ConfigError(f"{context} must use HTTPS unless it is a loopback endpoint")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError(f"{context} contains an invalid port")
    return endpoint


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


_DEFAULT_REDACT_KEYS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
)


@dataclass(frozen=True, slots=True)
class AIRedactionPolicy:
    enabled: bool = True
    redact_keys: tuple[str, ...] = _DEFAULT_REDACT_KEYS
    max_string_chars: int = 4_000
    include_evidence_content: bool = False

    @classmethod
    def from_mapping(cls, value: Any, context: str = "AI redaction policy") -> "AIRedactionPolicy":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={"enabled", "redact_keys", "max_string_chars", "include_evidence_content"},
            required=set(),
            context=context,
        )
        raw_keys = data.get("redact_keys", list(_DEFAULT_REDACT_KEYS))
        if not isinstance(raw_keys, list):
            raise ConfigError(f"{context}.redact_keys must be a list")
        redact_keys = tuple(
            _field_name(item, f"{context}.redact_keys[{index}]")
            for index, item in enumerate(raw_keys)
        )
        if len(redact_keys) != len(set(redact_keys)):
            raise ConfigError(f"{context}.redact_keys contains duplicates")
        return cls(
            enabled=_bool(data.get("enabled", True), f"{context}.enabled"),
            redact_keys=redact_keys,
            max_string_chars=_bounded_int(
                data.get("max_string_chars", 4_000),
                f"{context}.max_string_chars",
                minimum=64,
                maximum=100_000,
            ),
            include_evidence_content=_bool(
                data.get("include_evidence_content", False),
                f"{context}.include_evidence_content",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "redact_keys": list(self.redact_keys),
            "max_string_chars": self.max_string_chars,
            "include_evidence_content": self.include_evidence_content,
        }


@dataclass(frozen=True, slots=True)
class AIProviderConfig:
    id: str
    kind: AIProviderKind
    model: str
    endpoint: str | None
    api_key: EnvironmentReference | None
    timeout_seconds: int
    max_retries: int
    max_output_tokens: int
    redaction: AIRedactionPolicy

    @classmethod
    def from_mapping(cls, value: Any, context: str = "AI provider") -> "AIProviderConfig":
        data = _mapping(value, context)
        _strict_fields(
            data,
            allowed={
                "id",
                "kind",
                "model",
                "endpoint",
                "api_key",
                "timeout_seconds",
                "max_retries",
                "max_output_tokens",
                "redaction",
            },
            required={"id", "kind", "model"},
            context=context,
        )
        kind = _enum(AIProviderKind, data["kind"], f"{context}.kind")
        endpoint: str | None = None
        api_key: EnvironmentReference | None = None
        if kind is AIProviderKind.OPENAI_RESPONSES:
            if data.get("endpoint") is None or data.get("api_key") is None:
                raise ConfigError(
                    f"{context} OpenAI Responses providers require endpoint and api_key"
                )
            endpoint = _responses_endpoint(data["endpoint"], f"{context}.endpoint")
            api_key = EnvironmentReference.from_mapping(data["api_key"], f"{context}.api_key")
        elif data.get("endpoint") is not None or data.get("api_key") is not None:
            raise ConfigError(
                f"{context} deterministic providers cannot declare endpoint or api_key"
            )
        return cls(
            id=_stable_id(data["id"], f"{context}.id"),
            kind=kind,
            model=_string(data["model"], f"{context}.model"),
            endpoint=endpoint,
            api_key=api_key,
            timeout_seconds=_bounded_int(
                data.get("timeout_seconds", 30),
                f"{context}.timeout_seconds",
                minimum=1,
                maximum=300,
            ),
            max_retries=_bounded_int(
                data.get("max_retries", 2),
                f"{context}.max_retries",
                minimum=0,
                maximum=5,
            ),
            max_output_tokens=_bounded_int(
                data.get("max_output_tokens", 800),
                f"{context}.max_output_tokens",
                minimum=64,
                maximum=16_384,
            ),
            redaction=AIRedactionPolicy.from_mapping(
                data.get("redaction", {}), f"{context}.redaction"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "model": self.model,
            "endpoint": self.endpoint,
            "api_key": self.api_key.to_dict() if self.api_key else None,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_output_tokens": self.max_output_tokens,
            "redaction": self.redaction.to_dict(),
        }

    def runtime_metadata(self) -> dict[str, Any]:
        """Return bundle-safe metadata without endpoint or secret material."""

        return {
            "provider_id": self.id,
            "kind": self.kind.value,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_output_tokens": self.max_output_tokens,
            "credential_reference": self.api_key.env if self.api_key else None,
        }


def deterministic_ai_provider_config() -> AIProviderConfig:
    return AIProviderConfig(
        id="deterministic-offline.v1",
        kind=AIProviderKind.DETERMINISTIC,
        model="deterministic-planner.v1",
        endpoint=None,
        api_key=None,
        timeout_seconds=1,
        max_retries=0,
        max_output_tokens=800,
        redaction=AIRedactionPolicy(),
    )


@dataclass(frozen=True, slots=True)
class AIConfig:
    autonomy: AutonomyLevel
    active_provider: str
    fallback_provider: str
    providers: tuple[AIProviderConfig, ...]

    @classmethod
    def from_mapping(cls, value: Any, context: str = "config.ai") -> "AIConfig":
        data = _mapping(value, context)
        if set(data) == {"enabled"}:
            enabled = _bool(data["enabled"], f"{context}.enabled")
            provider = deterministic_ai_provider_config()
            return cls(
                autonomy=AutonomyLevel.ASSIST if enabled else AutonomyLevel.OFF,
                active_provider=provider.id,
                fallback_provider=provider.id,
                providers=(provider,),
            )
        _strict_fields(
            data,
            allowed={"autonomy", "active_provider", "fallback_provider", "providers"},
            required={"autonomy", "active_provider", "fallback_provider", "providers"},
            context=context,
        )
        raw_providers = data["providers"]
        if not isinstance(raw_providers, list) or not raw_providers:
            raise ConfigError(f"{context}.providers must be a non-empty list")
        providers = tuple(
            AIProviderConfig.from_mapping(item, f"{context}.providers[{index}]")
            for index, item in enumerate(raw_providers)
        )
        provider_ids = [provider.id for provider in providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise ConfigError(f"{context}.providers contains duplicate IDs")
        active_provider = _stable_id(data["active_provider"], f"{context}.active_provider")
        fallback_provider = _stable_id(data["fallback_provider"], f"{context}.fallback_provider")
        providers_by_id = {provider.id: provider for provider in providers}
        if active_provider not in providers_by_id:
            raise ConfigError(f"{context}.active_provider does not exist")
        fallback = providers_by_id.get(fallback_provider)
        if fallback is None:
            raise ConfigError(f"{context}.fallback_provider does not exist")
        if fallback.kind is not AIProviderKind.DETERMINISTIC:
            raise ConfigError(f"{context}.fallback_provider must be deterministic")
        return cls(
            autonomy=_enum(AutonomyLevel, data["autonomy"], f"{context}.autonomy"),
            active_provider=active_provider,
            fallback_provider=fallback_provider,
            providers=providers,
        )

    @property
    def enabled(self) -> bool:
        return self.autonomy is not AutonomyLevel.OFF

    def provider(self, provider_id: str | None = None) -> AIProviderConfig:
        selected = provider_id or self.active_provider
        for provider in self.providers:
            if provider.id == selected:
                return provider
        raise ConfigError(f"unknown AI provider: {selected}")

    @property
    def fallback(self) -> AIProviderConfig:
        return self.provider(self.fallback_provider)

    def to_dict(self) -> dict[str, Any]:
        return {
            "autonomy": self.autonomy.value,
            "active_provider": self.active_provider,
            "fallback_provider": self.fallback_provider,
            "providers": [provider.to_dict() for provider in self.providers],
        }


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
            max_steps=_bounded_int(
                data["max_steps"],
                f"{context}.max_steps",
                minimum=1,
                maximum=_MAX_RUNNER_STEPS,
            ),
            max_seconds=_bounded_int(
                data["max_seconds"],
                f"{context}.max_seconds",
                minimum=1,
                maximum=_MAX_RUNNER_EXECUTION_SECONDS,
            ),
            max_artifacts=_bounded_int(
                data["max_artifacts"],
                f"{context}.max_artifacts",
                minimum=1,
                maximum=_MAX_RUNNER_ARTIFACTS,
            ),
            max_bytes=_bounded_int(
                data["max_bytes"],
                f"{context}.max_bytes",
                minimum=1,
                maximum=_MAX_RUNNER_ARTIFACT_BYTES,
            ),
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
    ai: AIConfig
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
        ai = AIConfig.from_mapping(data["ai"], f"{context}.ai")
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
            ai=ai,
            active_profile=active_profile,
            runner_profiles=profiles,
        )

    @property
    def autonomy(self) -> AutonomyLevel:
        return self.ai.autonomy

    @property
    def ai_enabled(self) -> bool:
        """Compatibility view for v1 callers; true maps to Assist, never Auto."""

        return self.ai.enabled

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
            "ai": self.ai.to_dict(),
            "active_profile": self.active_profile,
            "runner_profiles": [profile.to_dict() for profile in self.runner_profiles],
        }


def load_config(path: str | Path) -> BlueFireConfig:
    """Load configuration without reading any referenced environment variable."""

    return BlueFireConfig.from_mapping(_load_yaml_mapping(path, "config"))


__all__ = [
    "AIConfig",
    "AIProviderConfig",
    "AIProviderKind",
    "AIRedactionPolicy",
    "AutonomyLevel",
    "BlueFireConfig",
    "CleanupPolicy",
    "ConfigError",
    "EnvironmentReference",
    "EnvironmentType",
    "RunnerBudgets",
    "RunnerProfile",
    "deterministic_ai_provider_config",
    "load_config",
]
