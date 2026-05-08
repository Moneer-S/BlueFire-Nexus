"""Legacy actor adapters: unrecognized tactic / technique markers.

Loop C audit (legacy_* adapter behavior depth) surfaced two
silent-fallback gaps in the legacy actor adapters:

1. ``LegacyGenericActorTechniqueModule`` (the base for the
   APT28/32/38/41 adapters) silently fell back to T1589 (Gather
   Victim Identity Information) when the operator passed a
   tactic outside the per-actor ``_TACTIC_TO_TECHNIQUE`` map.
   That left a recon-coded artifact for what was actually an
   unrecognised tactic — the defender reading the rule had no
   indication the request was off-spec.

2. ``LegacyApt29ResearchModule`` has three named techniques
   (phishing / powershell / process_hollowing) plus a DNS-C2
   research fallback. Operators who passed an unknown technique
   silently landed in the DNS-C2 branch with no marker.

This file pins both fallback paths now surface
``unrecognized_legacy_tactic`` /
``unrecognized_legacy_technique`` markers in the detection hint
plus a ``needs_operator_review`` flag mirroring PR #105's
``LegacyWrappedModule`` honest-framing pattern.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from src.core.modules.impl.legacy_packs import (
    LegacyApt28ResearchModule,
    LegacyApt29ResearchModule,
    LegacyApt32ResearchModule,
    LegacyApt38ResearchModule,
    LegacyApt41ResearchModule,
)


def _lab_simulate_context() -> Dict[str, Any]:
    """Lab-mode context with the actor pack enabled in simulate mode."""
    return {
        "run_id": "legacy-actor-dispatch-test",
        "config": {
            "modules": {
                "legacy": {
                    "enabled": True,
                    "default_mode": "simulate",
                    "actor_pack": {
                        "enabled": True,
                        "default_mode": "simulate",
                        "capabilities": {
                            "apt28": {"enabled": True},
                            "apt29": {"enabled": True},
                            "apt32": {"enabled": True},
                            "apt38": {"enabled": True},
                            "apt41": {"enabled": True},
                        },
                    },
                }
            }
        },
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


_GENERIC_ACTOR_CLASSES = (
    LegacyApt28ResearchModule,
    LegacyApt32ResearchModule,
    LegacyApt38ResearchModule,
    LegacyApt41ResearchModule,
)


@pytest.mark.parametrize("cls", _GENERIC_ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_generic_actor_unrecognized_tactic_surfaces_marker(cls) -> None:
    """A tactic outside the per-actor `_TACTIC_TO_TECHNIQUE` map
    surfaces ``unrecognized_legacy_tactic`` and
    ``needs_operator_review`` in the detection hint, plus
    ``unrecognized_legacy_tactic`` in telemetry details.
    """
    module = cls()
    result = module.execute(
        {
            "tactic": "definitely_not_a_real_tactic_zzz",
            "technique": "noop",
            "target": "lab-host",
        },
        _lab_simulate_context(),
    )
    assert result.status == "success"
    assert (
        result.detection_hints.get("unrecognized_legacy_tactic")
        == "definitely_not_a_real_tactic_zzz"
    )
    assert result.detection_hints.get("needs_operator_review") is True
    # Telemetry detail snapshot too.
    assert result.telemetry, f"{cls.__name__} produced no telemetry"
    assert (
        result.telemetry[0].details.get("unrecognized_legacy_tactic")
        == "definitely_not_a_real_tactic_zzz"
    )


@pytest.mark.parametrize("cls", _GENERIC_ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_generic_actor_unrecognized_tactic_uses_t0000_not_t1589(cls) -> None:
    """The fallback MITRE for an unrecognised tactic is T0000 (the
    project-wide "no canonical technique" placeholder used by
    LegacyWrappedModule). Was T1589 (Gather Victim Identity
    Information), which produced misleading recon-coded artifacts.
    """
    module = cls()
    result = module.execute(
        {"tactic": "totally_unknown_tactic", "technique": "x"},
        _lab_simulate_context(),
    )
    assert result.techniques == ["T0000"], cls.__name__
    assert result.detection_hints.get("mitre_technique") == "T0000", cls.__name__


@pytest.mark.parametrize("cls", _GENERIC_ACTOR_CLASSES, ids=lambda c: c.__name__)
def test_generic_actor_recognized_tactic_does_not_set_marker(cls) -> None:
    """Recognised tactics (initial_access / execution /
    defense_evasion / command_and_control) keep the historic clean
    behaviour — no `unrecognized_*` marker, no
    ``needs_operator_review`` flag.
    """
    module = cls()
    result = module.execute(
        {"tactic": "execution", "technique": "powershell", "target": "lab-host"},
        _lab_simulate_context(),
    )
    assert "unrecognized_legacy_tactic" not in result.detection_hints
    assert "needs_operator_review" not in result.detection_hints
    # Real per-actor sub-technique should fire.
    assert result.techniques and result.techniques[0] != "T0000"


def test_apt29_unrecognized_technique_surfaces_marker() -> None:
    """`LegacyApt29ResearchModule` has three named techniques
    (phishing / powershell / process_hollowing); anything else
    falls through to the DNS-C2 research fallback. The fallback
    now surfaces ``unrecognized_legacy_technique`` so the operator
    can see they hit the fallback path rather than one of the
    named branches.
    """
    module = LegacyApt29ResearchModule()
    result = module.execute(
        {"technique": "totally_made_up_technique_zzz", "target": "lab-host"},
        _lab_simulate_context(),
    )
    assert result.status == "success"
    # Falls through to DNS-C2 -> T1071.004.
    assert result.techniques == ["T1071.004"]
    # Marker is set.
    assert (
        result.detection_hints.get("unrecognized_legacy_technique")
        == "totally_made_up_technique_zzz"
    )
    assert result.detection_hints.get("needs_operator_review") is True


@pytest.mark.parametrize(
    "technique",
    ["phishing", "powershell", "process_hollowing"],
)
def test_apt29_recognized_technique_does_not_set_marker(technique: str) -> None:
    """Recognised techniques don't surface the fallback marker."""
    module = LegacyApt29ResearchModule()
    result = module.execute(
        {"technique": technique, "target": "lab-host"},
        _lab_simulate_context(),
    )
    assert "unrecognized_legacy_technique" not in result.detection_hints
    assert "needs_operator_review" not in result.detection_hints


def test_apt29_default_technique_phishing_does_not_set_marker() -> None:
    """No technique param -> default "phishing" -> no fallback marker."""
    module = LegacyApt29ResearchModule()
    result = module.execute({"target": "lab-host"}, _lab_simulate_context())
    assert "unrecognized_legacy_technique" not in result.detection_hints
    assert result.techniques == ["T1566"]
