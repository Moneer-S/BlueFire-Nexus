from __future__ import annotations

from typing import Dict, Type

from .base import BaseModule
from .impl.standard_modules import (
    AntiDetectionModule,
    CommandControlModule,
    DefenseEvasionModule,
    DiscoveryModule,
    ExecutionModule,
    ExfiltrationModule,
    InitialAccessModule,
    IntelligenceModule,
    NetworkObfuscatorModule,
    PersistenceModule,
    ReconnaissanceModule,
    ResourceDevelopmentModule,
)


def discover_modules() -> Dict[str, Type[BaseModule]]:
    """Return built-in module classes registered by module name."""
    module_types: tuple[Type[BaseModule], ...] = (
        CommandControlModule,
        InitialAccessModule,
        DefenseEvasionModule,
        AntiDetectionModule,
        DiscoveryModule,
        IntelligenceModule,
        NetworkObfuscatorModule,
        ResourceDevelopmentModule,
        ReconnaissanceModule,
        ExfiltrationModule,
        PersistenceModule,
        ExecutionModule,
    )
    return {module_type.name: module_type for module_type in module_types}


def build_runtime_modules(
    plugin_modules: Dict[str, Type[BaseModule]] | None = None,
) -> Dict[str, BaseModule]:
    """Instantiate built-in modules and optional plugin modules."""
    module_classes = discover_modules()
    if plugin_modules:
        module_classes.update(plugin_modules)
    return {name: module_cls() for name, module_cls in module_classes.items()}
