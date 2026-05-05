"""Per-actor differentiation for APT28 / APT32 / APT38 / APT41 adapters.

Each actor adapter must expose its own technique surface and emit an
actor-distinct detection signature so downstream Sigma drafts and
report tables can distinguish the actor pack used to produce them.
"""

from __future__ import annotations

from typing import Type

import pytest

from src.core.modules.impl.legacy_packs import (
    LegacyApt28ResearchModule,
    LegacyApt32ResearchModule,
    LegacyApt38ResearchModule,
    LegacyApt41ResearchModule,
    LegacyGenericActorTechniqueModule,
)


_ACTOR_CLASSES: list[Type[LegacyGenericActorTechniqueModule]] = [
    LegacyApt28ResearchModule,
    LegacyApt32ResearchModule,
    LegacyApt38ResearchModule,
    LegacyApt41ResearchModule,
]


def _lab_simulate_context() -> dict:
    """Minimal lab-simulate config that lets each actor pack execute."""
    return {
        "run_id": "actor-test-run",
        "config": {
            "general": {"dry_run": True},
            "modules": {
                "legacy": {
                    "enable_all_lab_capabilities": True,
                    "lab_confirmation": True,
                    "global_mode": "simulate",
                    "actor_pack": {
                        "enabled": True,
                        "mode": "simulate",
                        "lab_confirmation": True,
                        "capabilities": {
                            actor: {"enabled": True, "mode": "simulate"}
                            for actor in ("apt28", "apt32", "apt38", "apt41")
                        },
                    },
                }
            },
        },
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


def test_each_actor_has_distinct_signature() -> None:
    signatures = {cls.actor_signature for cls in _ACTOR_CLASSES}
    assert len(signatures) == len(_ACTOR_CLASSES), (
        f"Actor signatures must be distinct, got {signatures}"
    )
    assert "" not in signatures, "Every per-actor adapter must set actor_signature"


def test_each_actor_has_distinct_attack_techniques() -> None:
    surfaces = {cls.__name__: tuple(cls.attack_techniques) for cls in _ACTOR_CLASSES}
    surface_values = list(surfaces.values())
    assert len(set(surface_values)) == len(surface_values), (
        f"Actor attack_techniques tuples must differ between actors: {surfaces}"
    )
    for name, surface in surfaces.items():
        assert surface, f"{name} must declare a non-empty attack_techniques tuple"


@pytest.mark.parametrize("cls", _ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_actor_emits_actor_signature_and_refined_mitre(
    cls: Type[LegacyGenericActorTechniqueModule],
) -> None:
    module = cls()
    result = module.execute(
        {"tactic": "execution", "technique": "powershell", "target": "lab-user"},
        _lab_simulate_context(),
    )
    assert result.status == "success"
    selection = result.detection_hints["detection"]["selection"]
    assert selection["legacy.actor_signature"] == cls.actor_signature
    # Refined per-actor mapping should not collapse back to the bare T1059
    # parent — each per-actor subclass picks a sub-technique.
    assert result.techniques, f"{cls.__name__} produced no techniques"
    emitted = result.techniques[0]
    assert emitted.startswith("T1059"), (
        f"{cls.__name__} mapped 'execution' tactic to {emitted!r}, "
        "expected a T1059 family technique"
    )


def test_each_actor_has_distinct_aka_aliases() -> None:
    """`aka` is a defender-facing list of vendor-report aliases per actor."""
    aliases = {cls.actor_name: tuple(cls.aka) for cls in _ACTOR_CLASSES}
    for actor_name, aka in aliases.items():
        assert aka, f"{actor_name} must declare at least one alias in aka"
    # Each actor's alias tuple must be distinct from the others (no
    # accidental copy-paste of one actor's vendor names onto another).
    distinct_alias_tuples = {tuple(sorted(aka)) for aka in aliases.values()}
    assert len(distinct_alias_tuples) == len(aliases), (
        f"Per-actor aka tuples must be distinct: {aliases}"
    )


@pytest.mark.parametrize("cls", _ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_actor_emits_aka_in_detection_selection(
    cls: Type[LegacyGenericActorTechniqueModule],
) -> None:
    module = cls()
    result = module.execute(
        {"tactic": "execution", "technique": "powershell", "target": "lab-user"},
        _lab_simulate_context(),
    )
    selection = result.detection_hints["detection"]["selection"]
    assert selection["legacy.actor_aka"] == list(cls.aka)


@pytest.mark.parametrize("cls", _ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_actor_emits_tactic_specific_logsource(
    cls: Type[LegacyGenericActorTechniqueModule],
) -> None:
    """Per-tactic logsource replaces the old generic threat_intelligence."""
    module = cls()
    result = module.execute(
        {"tactic": "command_and_control", "technique": "https", "target": "lab-host"},
        _lab_simulate_context(),
    )
    logsource = result.detection_hints["logsource"]
    assert logsource["category"] == "network_connection"
    assert logsource["product"] == "host"


def test_apt29_emits_actor_signature_and_aka() -> None:
    """APT29 has its own execute path; signature + aka must still appear."""
    from src.core.modules.impl.legacy_packs import LegacyApt29ResearchModule

    module = LegacyApt29ResearchModule()
    result = module.execute(
        {"technique": "phishing", "target": "lab-user"},
        _lab_simulate_context(),
    )
    selection = result.detection_hints["detection"]["selection"]
    assert selection["legacy.actor_signature"] == "cozy_bear_dukes"
    assert "Cozy Bear" in selection["legacy.actor_aka"]


def test_generic_base_still_produces_generic_signature() -> None:
    """The generic base class must remain functional and signature-free."""
    base = LegacyGenericActorTechniqueModule()
    assert base.actor_signature == ""
    result = base.execute(
        {"tactic": "execution", "technique": "powershell", "target": "lab-user"},
        _lab_simulate_context(),
    )
    assert result.status == "success"
    selection = result.detection_hints["detection"]["selection"]
    assert "legacy.actor_signature" not in selection, (
        "Base class must not emit an actor_signature when none is configured"
    )
