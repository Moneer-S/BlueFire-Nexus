from __future__ import annotations

from typing import Dict, Type

from ..plugins import load_plugin_modules
from .base import BaseModule
from .impl.legacy_packs import discover_legacy_modules
from .impl.standard_modules import (
    AntiDetectionModule,
    CollectionModule,
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

# Single source of truth for first-party module classes (ordering = registration order).
BUILTIN_MODULE_CLASSES: tuple[Type[BaseModule], ...] = (
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
    CollectionModule,
)


def discover_modules() -> Dict[str, Type[BaseModule]]:
    """Return built-in module classes registered by module name."""
    return {module_type.name: module_type for module_type in BUILTIN_MODULE_CLASSES}


def build_runtime_modules(
    plugin_modules: Dict[str, Type[BaseModule]] | None = None,
) -> Dict[str, BaseModule]:
    """Instantiate built-in modules and optional plugin modules."""
    module_classes = discover_modules()
    module_classes.update(discover_legacy_modules())
    discovered_plugins = load_plugin_modules()
    if discovered_plugins:
        module_classes.update(discovered_plugins)
    if plugin_modules:
        module_classes.update(plugin_modules)
    return {name: module_cls() for name, module_cls in module_classes.items()}
