"""Module abstractions and registry exports."""

from .base import BaseModule
from .contracts import (
    ARTIFACT_TYPES,
    ArtifactSpec,
    CapabilityIOContract,
    consumes,
    is_meaningful_contract,
    normalise_artifact_type,
    produces,
)
from .registry import BUILTIN_MODULE_CLASSES, build_runtime_modules, discover_modules

__all__ = [
    "ARTIFACT_TYPES",
    "ArtifactSpec",
    "BUILTIN_MODULE_CLASSES",
    "BaseModule",
    "CapabilityIOContract",
    "build_runtime_modules",
    "consumes",
    "discover_modules",
    "is_meaningful_contract",
    "normalise_artifact_type",
    "produces",
]
