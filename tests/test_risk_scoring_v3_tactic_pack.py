"""Risk scoring v3: tactic-aware base for tactic_pack legacy adapters.

PR #104 (risk scoring v2) introduced ``_TACTIC_BASE_SCORES`` so a
successful standard ``impact`` step scores ~85 ("critical"), a
successful ``exfiltration`` step scores ~75 ("high"), and a
successful ``reconnaissance`` step stays at ~25 ("low"). The v2
patch only handled the **standard module** branch.

The legacy ``tactic_pack`` adapters (``legacy_credential_access`` /
``legacy_lateral_movement`` / ``legacy_privilege_escalation`` /
``legacy_impact`` / ``legacy_collection``) wrap the same tactics
as their standard-module siblings. Before v3, every tactic_pack
result used the fixed ``actor_pack``-equivalent base of 55, so a
successful ``legacy_impact`` (T1486 ransomware) step scored the
same as a successful ``legacy_collection`` step — both ended up
medium where impact should be critical.

This file pins the v3 tactic-aware base for tactic_pack:

1. tactic_pack + capability matching a tactic name -> use the
   tactic-aware base (impact 85, exfiltration 75, ...).
2. tactic_pack + unknown capability -> fall back to the historic
   pack base (60).
3. Other packs (actor / c2 / stealth) keep their fixed bases.
4. The mode bonus and capability bonus still stack on top, so
   legacy emulate-mode results still surface higher than legacy
   simulate-mode results.
5. The rationale list explicitly names ``tactic_base=<name>``
   when the v3 path fires so a reviewer can see why the score
   landed where it did.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

import pytest

from src.core.models import ModuleResult, TelemetryEvent
from src.core.risk import _PACK_BASE_SCORES, _TACTIC_BASE_SCORES, score_module_result


def _legacy_result(
    *,
    module: str,
    pack: str,
    capability: str,
    mode: str = "simulate",
    techniques: list[str] | None = None,
    status: str = "success",
) -> ModuleResult:
    """Build a ModuleResult that looks like a tactic_pack adapter run."""
    return ModuleResult(
        status=status,
        module=module,
        message="ok",
        techniques=techniques or ["T1486"],
        artifacts={
            "legacy": {
                "pack": pack,
                "capability": capability,
                "mode": mode,
                "payload": {},
            }
        },
        detection_hints={},
        telemetry=[],
    )


@pytest.mark.parametrize(
    "capability,expected_tactic_base",
    [
        ("credential_access", 65),
        ("lateral_movement", 65),
        ("privilege_escalation", 70),
        ("impact", 85),
        ("collection", 55),
    ],
)
def test_tactic_pack_uses_tactic_aware_base(
    capability: str, expected_tactic_base: int
) -> None:
    """For tactic_pack, capability matching a known tactic name uses
    the v2 tactic-aware base instead of the fixed pack base.
    """
    result = _legacy_result(
        module=f"legacy_{capability}",
        pack="tactic_pack",
        capability=capability,
    )
    risk = score_module_result(result)
    # Score = tactic_base + capability_bonus(=6 default for unknown
    # capability bonus key, since the tactic name doesn't appear in
    # _CAPABILITY_BONUS) + mode_bonus(=0 for simulate) + status(=0).
    expected_score = expected_tactic_base + 6
    assert risk["score"] == expected_score, (capability, risk)
    assert "tactic_base=" + capability in risk["rationale"]
    assert "pack=tactic_pack" in risk["rationale"]


def test_tactic_pack_impact_emulate_scores_critical() -> None:
    """A legacy_impact emulate-mode result should score critically.

    impact tactic base (85) + capability bonus (6) + emulate bonus
    (18) = 109, clamped to 100. Severity = critical.
    """
    result = _legacy_result(
        module="legacy_impact",
        pack="tactic_pack",
        capability="impact",
        mode="emulate",
        techniques=["T1486"],
    )
    risk = score_module_result(result)
    assert risk["score"] == 100, risk
    assert risk["severity"] == "critical"
    assert "mode=emulate" in risk["rationale"]


def test_tactic_pack_collection_simulate_scores_medium() -> None:
    """legacy_collection simulate-mode is mid-chain, not critical.

    collection tactic base (55) + capability bonus (6) + simulate
    (0) + status success (0) = 61, severity medium.
    """
    result = _legacy_result(
        module="legacy_collection",
        pack="tactic_pack",
        capability="collection",
    )
    risk = score_module_result(result)
    assert risk["score"] == 61, risk
    assert risk["severity"] == "medium"


def test_tactic_pack_unknown_capability_falls_back_to_pack_base() -> None:
    """Defensive: if a tactic_pack adapter ships with a capability
    name that isn't in _TACTIC_BASE_SCORES, fall back to the pack
    base (60) rather than crashing or scoring at 0.
    """
    result = _legacy_result(
        module="legacy_unknown_tactic",
        pack="tactic_pack",
        capability="completely_made_up_tactic",
    )
    risk = score_module_result(result)
    expected = _PACK_BASE_SCORES["tactic_pack"] + 6  # default capability bonus
    assert risk["score"] == expected, risk
    # Old-style rationale (no tactic_base since capability didn't match).
    assert "tactic_base=" not in " ".join(risk["rationale"])
    assert "pack=tactic_pack" in risk["rationale"]
    assert "capability=completely_made_up_tactic" in risk["rationale"]


def test_actor_pack_unaffected_by_v3_path() -> None:
    """actor_pack adapters keep using the fixed pack base (55).

    actor_pack base (55) + apt29 capability bonus (8) + emulate
    (18) = 81, severity high.
    """
    result = ModuleResult(
        status="success",
        module="legacy_actor_profile",
        message="ok",
        techniques=["T1589"],
        artifacts={
            "legacy": {
                "pack": "actor_pack",
                "capability": "apt29",
                "mode": "emulate",
                "payload": {},
            }
        },
        detection_hints={},
        telemetry=[],
    )
    risk = score_module_result(result)
    # actor_pack base 55 + apt29 capability bonus 8 + emulate 18 = 81
    assert risk["score"] == 81
    assert risk["severity"] == "high"
    # No tactic_base in rationale — actor_pack didn't go down the v3 path.
    assert all(not r.startswith("tactic_base=") for r in risk["rationale"])


def test_c2_and_stealth_packs_unaffected_by_v3_path() -> None:
    """c2_pack and stealth_pack adapters also keep their fixed bases."""
    for pack, base in (("c2_pack", 62), ("stealth_pack", 68)):
        result = ModuleResult(
            status="success",
            module=f"legacy_{pack}",
            message="ok",
            techniques=["T1071.001"],
            artifacts={
                "legacy": {
                    "pack": pack,
                    "capability": "dns_tunneling",
                    "mode": "simulate",
                    "payload": {},
                }
            },
            detection_hints={},
            telemetry=[],
        )
        risk = score_module_result(result)
        # base + dns_tunneling capability bonus (10) + simulate (0)
        assert risk["score"] == base + 10, (pack, risk)
        assert all(not r.startswith("tactic_base=") for r in risk["rationale"])


def test_v3_legacy_impact_now_higher_than_legacy_collection() -> None:
    """End-to-end ordering: legacy_impact > legacy_collection at parity.

    Pre-v3 both scored ~61 (55 base + 6 capability bonus). Post-v3
    legacy_impact uses tactic_base=85 (impact) and legacy_collection
    uses tactic_base=55 (collection), so impact > collection by ~30
    points reflecting the actual defender impact gap.
    """
    impact = score_module_result(
        _legacy_result(
            module="legacy_impact", pack="tactic_pack", capability="impact"
        )
    )
    collection = score_module_result(
        _legacy_result(
            module="legacy_collection",
            pack="tactic_pack",
            capability="collection",
        )
    )
    assert impact["score"] > collection["score"]
    assert impact["score"] - collection["score"] >= 25
    assert impact["severity"] in {"critical", "high"}


def test_v3_legacy_recon_does_not_apply_to_tactic_pack() -> None:
    """tactic_pack does NOT cover reconnaissance / discovery (those
    are not in the legacy tactic_pack adapter set). Defensive: even
    if a future tactic_pack adapter ships with `capability:
    reconnaissance` we'd want it to score at the recon base (25),
    not at the historic actor-pack 55.
    """
    result = _legacy_result(
        module="legacy_recon_hypothetical",
        pack="tactic_pack",
        capability="reconnaissance",
    )
    risk = score_module_result(result)
    # tactic_base=25 + capability bonus (default 6) + simulate (0) = 31
    assert risk["score"] == 31
    assert risk["severity"] == "low"
    assert "tactic_base=reconnaissance" in risk["rationale"]


def test_rationale_lists_tactic_base_first_for_visibility() -> None:
    """The rationale ordering for tactic_pack v3 path:

    pack=tactic_pack, tactic_base=<name>, mode=<mode>

    This makes the per-tactic base visible in dashboards/reports
    that surface the rationale, so a defender reviewing the score
    immediately sees why a legacy_impact run is critical.
    """
    result = _legacy_result(
        module="legacy_impact",
        pack="tactic_pack",
        capability="impact",
        mode="emulate",
    )
    risk = score_module_result(result)
    rationale = risk["rationale"]
    # pack listed first, tactic_base immediately after, mode last.
    assert rationale[0] == "pack=tactic_pack"
    assert rationale[1] == "tactic_base=impact"
    assert rationale[-1] == "mode=emulate"
