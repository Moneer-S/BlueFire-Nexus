"""Module registry shape: standard + legacy module discovery and ordering.

The registry is the single source of truth for which modules a
scenario can reference. These tests pin its shape so accidental
removals or reordering surface immediately rather than at scenario
runtime.
"""

from __future__ import annotations

from src.core.modules.base import BaseModule
from src.core.modules.impl.legacy_packs import discover_legacy_modules
from src.core.modules.registry import (
    BUILTIN_MODULE_CLASSES,
    build_runtime_modules,
    discover_modules,
)


# Expected sets — copy them here as the canonical contract; if an
# intentional addition or removal ships, the test must be updated
# alongside the change.
_EXPECTED_STANDARD_MODULES = frozenset(
    {
        "anti_detection",
        "collection",
        "command_control",
        "credential_access",
        "defense_evasion",
        "discovery",
        "execution",
        "exfiltration",
        "impact",
        "initial_access",
        "intelligence",
        "lateral_movement",
        "network_obfuscator",
        "persistence",
        "privilege_escalation",
        "reconnaissance",
        "resource_development",
    }
)

_EXPECTED_LEGACY_MODULES = frozenset(
    {
        "legacy_actor_profile",
        "legacy_apt28_research",
        "legacy_apt29_research",
        "legacy_apt32_research",
        "legacy_apt38_research",
        "legacy_apt41_research",
        "legacy_capability_summary",
        "legacy_collection",
        "legacy_credential_access",
        "legacy_impact",
        "legacy_lateral_movement",
        "legacy_privilege_escalation",
        "legacy_protocol_research",
        "legacy_stealth_research",
    }
)


def test_discover_modules_returns_all_seventeen_standard_modules() -> None:
    standard = discover_modules()
    names = set(standard.keys())
    assert names == _EXPECTED_STANDARD_MODULES, (
        f"Standard module registry drift; missing="
        f"{_EXPECTED_STANDARD_MODULES - names}, extra="
        f"{names - _EXPECTED_STANDARD_MODULES}"
    )


def test_discover_legacy_modules_returns_all_fourteen_legacy_adapters() -> None:
    legacy = discover_legacy_modules()
    names = set(legacy.keys())
    assert names == _EXPECTED_LEGACY_MODULES, (
        f"Legacy adapter registry drift; missing="
        f"{_EXPECTED_LEGACY_MODULES - names}, extra="
        f"{names - _EXPECTED_LEGACY_MODULES}"
    )


def test_build_runtime_modules_returns_thirty_one_total() -> None:
    runtime = build_runtime_modules()
    assert len(runtime) == 31
    assert set(runtime.keys()) == (
        _EXPECTED_STANDARD_MODULES | _EXPECTED_LEGACY_MODULES
    )


def test_every_runtime_module_is_a_basemodule_subclass_instance() -> None:
    runtime = build_runtime_modules()
    for name, instance in runtime.items():
        assert isinstance(instance, BaseModule), (
            f"runtime module {name!r} is {type(instance).__name__}, "
            "expected a BaseModule subclass instance"
        )


def test_every_runtime_module_has_a_name_matching_its_registry_key() -> None:
    runtime = build_runtime_modules()
    for registry_name, instance in runtime.items():
        instance_name = getattr(instance, "name", None)
        assert instance_name == registry_name, (
            f"registry key {registry_name!r} disagrees with module instance "
            f".name {instance_name!r}"
        )


def test_builtin_module_classes_ordering_is_stable() -> None:
    """The builtin ordering tuple is the source of truth; pin it."""
    expected_order = (
        "command_control",
        "initial_access",
        "defense_evasion",
        "anti_detection",
        "discovery",
        "intelligence",
        "network_obfuscator",
        "resource_development",
        "reconnaissance",
        "exfiltration",
        "persistence",
        "execution",
        "credential_access",
        "lateral_movement",
        "privilege_escalation",
        "impact",
        "collection",
    )
    actual_order = tuple(cls.name for cls in BUILTIN_MODULE_CLASSES)
    assert actual_order == expected_order, (
        f"BUILTIN_MODULE_CLASSES order drifted; got {actual_order}"
    )


def test_no_module_name_collisions_between_standard_and_legacy() -> None:
    standard_names = set(discover_modules())
    legacy_names = set(discover_legacy_modules())
    overlap = standard_names & legacy_names
    assert not overlap, (
        f"standard and legacy module names must not collide; got overlap={overlap}"
    )
