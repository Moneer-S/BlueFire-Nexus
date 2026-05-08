"""Invariant test: every standard module's `attack_techniques`
declaration is the union of its profile catalog's MITRE values.

Multiple modules (PRs #101 / #108 / #109 / #110) already use the
catalog-derived form

    attack_techniques = tuple(
        sorted({profile["mitre"] for profile in _<NAME>_PROFILES.values()})
    )

but the rest hardcoded the tuple, so a profile added to the
catalog could silently lag the class attribute. The class
attribute is what the registry sees as the module's advertised
capability surface — drift means a scenario can call the new
profile and produce a runtime emission that's not in the
declared coverage.

This file pins:

1. Every standard module that has a corresponding ``_<NAME>_PROFILES``
   catalog declares ``attack_techniques`` as exactly the union of
   that catalog's MITRE values.
2. The declared tuple is sorted (deterministic).
3. Classes without a catalog (`InitialAccessModule`,
   `ExecutionModule`, `LegacyWrappedModule`) are explicitly listed
   so the test acknowledges them rather than silently passing.
"""

from __future__ import annotations

from typing import Dict, Tuple, Type

import pytest

from src.core.modules.base import BaseModule
from src.core.modules.impl import standard_modules
from src.core.modules.impl.standard_modules import (
    AntiDetectionModule,
    CollectionModule,
    CommandControlModule,
    CredentialAccessModule,
    DefenseEvasionModule,
    DiscoveryModule,
    ExfiltrationModule,
    ImpactModule,
    IntelligenceModule,
    LateralMovementModule,
    NetworkObfuscatorModule,
    PersistenceModule,
    PrivilegeEscalationModule,
    ReconnaissanceModule,
    ResourceDevelopmentModule,
    _ANTI_DETECTION_PROFILES,
    _COLLECTION_PROFILES,
    _COMMAND_CONTROL_PROFILES,
    _CREDENTIAL_ACCESS_PROFILES,
    _DEFENSE_EVASION_PROFILES,
    _DISCOVERY_PROFILES,
    _EXFILTRATION_PROFILES,
    _IMPACT_PROFILES,
    _INTELLIGENCE_PROFILES,
    _LATERAL_MOVEMENT_PROFILES,
    _NETWORK_OBFUSCATOR_PROFILES,
    _PERSISTENCE_PROFILES,
    _PRIVILEGE_ESCALATION_PROFILES,
    _RECONNAISSANCE_PROFILES,
    _RESOURCE_DEVELOPMENT_PROFILES,
)


# (module class, catalog dict)
_MODULE_TO_CATALOG: Tuple[Tuple[Type[BaseModule], Dict], ...] = (
    (AntiDetectionModule, _ANTI_DETECTION_PROFILES),
    (CollectionModule, _COLLECTION_PROFILES),
    (CommandControlModule, _COMMAND_CONTROL_PROFILES),
    (CredentialAccessModule, _CREDENTIAL_ACCESS_PROFILES),
    (DefenseEvasionModule, _DEFENSE_EVASION_PROFILES),
    (DiscoveryModule, _DISCOVERY_PROFILES),
    (ExfiltrationModule, _EXFILTRATION_PROFILES),
    (ImpactModule, _IMPACT_PROFILES),
    (IntelligenceModule, _INTELLIGENCE_PROFILES),
    (LateralMovementModule, _LATERAL_MOVEMENT_PROFILES),
    (NetworkObfuscatorModule, _NETWORK_OBFUSCATOR_PROFILES),
    (PersistenceModule, _PERSISTENCE_PROFILES),
    (PrivilegeEscalationModule, _PRIVILEGE_ESCALATION_PROFILES),
    (ReconnaissanceModule, _RECONNAISSANCE_PROFILES),
    (ResourceDevelopmentModule, _RESOURCE_DEVELOPMENT_PROFILES),
)


@pytest.mark.parametrize(
    "module_cls,catalog",
    _MODULE_TO_CATALOG,
    ids=lambda v: v.__name__ if hasattr(v, "__name__") else "catalog",
)
def test_attack_techniques_is_exactly_catalog_mitre_union(
    module_cls: Type[BaseModule], catalog: Dict
) -> None:
    """Class attribute = union of catalog MITRE values, sorted.

    Catches the case where a profile is added to the catalog but
    the class attribute is not refreshed — registry-advertised
    capability would lag actual runtime emission.
    """
    declared = tuple(module_cls.attack_techniques)
    expected = tuple(sorted({profile["mitre"] for profile in catalog.values()}))
    assert declared == expected, (
        f"{module_cls.__name__}.attack_techniques drifted from "
        f"its catalog. Declared: {declared}. Expected (catalog union, "
        f"sorted): {expected}."
    )


@pytest.mark.parametrize("module_cls,_catalog", _MODULE_TO_CATALOG)
def test_attack_techniques_tuple_is_sorted(
    module_cls: Type[BaseModule], _catalog: Dict
) -> None:
    """Class attribute is a tuple in sorted order.

    Sorted output keeps registry / coverage / report layouts
    deterministic. Tuple keeps the contract immutable.
    """
    declared = module_cls.attack_techniques
    assert isinstance(declared, tuple), (
        f"{module_cls.__name__}.attack_techniques must be a tuple "
        f"(got {type(declared).__name__})"
    )
    assert list(declared) == sorted(declared), (
        f"{module_cls.__name__}.attack_techniques is not sorted: {declared}"
    )


def test_initial_access_and_execution_modules_acknowledged() -> None:
    """`InitialAccessModule` and `ExecutionModule` use the
    catalog-derived form (PR #109 / PR #110), but they have a
    different shape: ExecutionModule's catalog is keyed on
    interpreter (and includes the explicit T1059 parent fallback);
    InitialAccessModule's catalog uses ``vector`` instead of the
    typical ``technique``/``method`` field name.

    Pin both so a future regression that switches them back to a
    hardcoded tuple (or strips the parent fallback) is caught here
    rather than only at the per-module test layer.
    """
    # Execution: parent T1059 + every interpreter sub-technique.
    expected_execution = tuple(
        sorted(
            {"T1059", *(profile["mitre"] for profile in standard_modules._EXECUTION_INTERPRETER_PROFILES.values())}
        )
    )
    assert standard_modules.ExecutionModule.attack_techniques == expected_execution
    # Initial access (post-PR-#110): pure catalog union. Skip if PR
    # #110 hasn't merged yet (then the bare T1566 tuple is fine).
    initial_access_declared = standard_modules.InitialAccessModule.attack_techniques
    if hasattr(standard_modules, "_INITIAL_ACCESS_PROFILES"):
        expected_initial_access = tuple(
            sorted(
                {profile["mitre"] for profile in standard_modules._INITIAL_ACCESS_PROFILES.values()}
            )
        )
        assert initial_access_declared == expected_initial_access
    else:
        # Pre-#110 baseline: only T1566.
        assert initial_access_declared == ("T1566",)


def test_legacy_wrapped_module_has_dynamic_techniques() -> None:
    """`LegacyWrappedModule` does not declare a class-level
    ``attack_techniques`` tuple — it inherits the BaseModule
    default and the wrapped legacy class supplies coverage at
    runtime. Pin that the class default empty tuple is still empty
    so a future contributor doesn't accidentally hardcode a value
    here.
    """
    # LegacyWrappedModule overrides ``__init__`` to set ``name`` /
    # ``legacy_instance`` etc., but it does not override
    # ``attack_techniques`` at the class level. The BaseModule
    # default is the empty tuple. We accept either an empty tuple
    # or a class-level inheritance of BaseModule's default.
    declared = standard_modules.LegacyWrappedModule.attack_techniques
    assert declared == (), (
        f"LegacyWrappedModule should inherit BaseModule's empty "
        f"attack_techniques; got {declared}"
    )
