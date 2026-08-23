"""Canonical, execution-free contracts for the BlueFire control plane."""

__version__ = "0.1.0"

from .config import (
    BlueFireConfig,
    CleanupPolicy,
    ConfigError,
    EnvironmentReference,
    EnvironmentType,
    RunnerBudgets,
    RunnerProfile,
    load_config,
)
from .contracts import (
    ActionDefinition,
    ArtifactBinding,
    ArtifactSpec,
    BehaviorDefinition,
    ContractError,
    ExecutionMode,
    ExecutionState,
    OutcomeEdge,
    ParameterSpec,
    SafetyTier,
    ScenarioDefinition,
    ScenarioStep,
    SourceProvenance,
    StepOutcome,
    load_scenario,
)
from .plugins import (
    IntegrityRecord,
    PluginManifest,
    PluginManifestError,
    PluginTrust,
    load_plugin_manifest,
)
from .registry import BehaviorRegistry, RegistryError, load_builtin_registry

__all__ = [
    "ActionDefinition",
    "ArtifactBinding",
    "ArtifactSpec",
    "BehaviorDefinition",
    "BehaviorRegistry",
    "BlueFireConfig",
    "CleanupPolicy",
    "ConfigError",
    "ContractError",
    "EnvironmentReference",
    "EnvironmentType",
    "ExecutionMode",
    "ExecutionState",
    "IntegrityRecord",
    "OutcomeEdge",
    "ParameterSpec",
    "PluginManifest",
    "PluginManifestError",
    "PluginTrust",
    "RegistryError",
    "RunnerBudgets",
    "RunnerProfile",
    "SafetyTier",
    "ScenarioDefinition",
    "ScenarioStep",
    "SourceProvenance",
    "StepOutcome",
    "load_builtin_registry",
    "load_config",
    "load_plugin_manifest",
    "load_scenario",
    "__version__",
]
