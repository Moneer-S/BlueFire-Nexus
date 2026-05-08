"""Risk-scoring helpers — direct unit coverage.

These tests exercise the score / severity logic in
``src/core/risk.py`` directly so the function's edge cases
(non-legacy modules, runtime warnings, blocked/errored statuses,
clamping at 0/100, severity bands) are pinned at the helper level
rather than indirectly through reporting tests.
"""

from __future__ import annotations

import pytest

from src.core.models import ModuleResult
from src.core.risk import score_module_result, severity_from_score


def _result(
    *,
    status: str = "success",
    techniques: list[str] | None = None,
    artifacts: dict | None = None,
    detection_hints: dict | None = None,
) -> ModuleResult:
    return ModuleResult(
        status=status,
        module="probe",
        message="",
        techniques=list(techniques or []),
        artifacts=dict(artifacts or {}),
        detection_hints=dict(detection_hints or {}),
        telemetry=[],
    )


# ---------------------------------------------------------------------------
# severity_from_score band boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "low"),
        (44, "low"),
        (45, "medium"),
        (69, "medium"),
        (70, "high"),
        (84, "high"),
        (85, "critical"),
        (100, "critical"),
    ],
)
def test_severity_band_boundaries(score: int, expected: str) -> None:
    assert severity_from_score(score) == expected


# ---------------------------------------------------------------------------
# Standard (non-legacy) module path
# ---------------------------------------------------------------------------


def test_standard_module_with_no_techniques_scores_low() -> None:
    risk = score_module_result(_result(status="success", techniques=[]))
    assert risk["pack"] == ""
    assert risk["capability"] == ""
    assert risk["mode"] == "simulate"
    assert risk["score"] == 35
    assert risk["severity"] == "low"
    assert "standard-module" in risk["rationale"]


def test_standard_module_score_grows_with_techniques_capped_at_4() -> None:
    """Score adds up to 20 (4 × 5) for techniques on a non-legacy result."""
    risk = score_module_result(_result(techniques=["T1059", "T1083", "T1071", "T1041"]))
    assert risk["score"] == 35 + 20
    risk_extra = score_module_result(
        _result(techniques=["T1059", "T1083", "T1071", "T1041", "T1486", "T1566"])
    )
    assert risk_extra["score"] == 55  # cap kicks in at 4 techniques


# ---------------------------------------------------------------------------
# Legacy adapter scoring path
# ---------------------------------------------------------------------------


def test_legacy_actor_pack_simulate_uses_pack_base_plus_capability() -> None:
    risk = score_module_result(
        _result(
            artifacts={
                "legacy": {
                    "pack": "actor_pack",
                    "capability": "apt29",
                    "mode": "simulate",
                    "payload": {},
                }
            }
        )
    )
    # 55 (actor_pack) + 8 (apt29) + 0 (simulate) = 63
    assert risk["pack"] == "actor_pack"
    assert risk["capability"] == "apt29"
    assert risk["mode"] == "simulate"
    assert risk["score"] == 63
    assert risk["severity"] == "medium"


def test_legacy_emulate_mode_adds_bonus() -> None:
    risk = score_module_result(
        _result(
            artifacts={
                "legacy": {
                    "pack": "actor_pack",
                    "capability": "apt29",
                    "mode": "emulate",
                    "payload": {},
                }
            }
        )
    )
    # 55 + 8 + 18 (emulate bonus) = 81
    assert risk["score"] == 81
    assert risk["severity"] == "high"


def test_runtime_warning_adds_ten() -> None:
    risk = score_module_result(
        _result(
            artifacts={
                "legacy": {
                    "pack": "stealth_pack",
                    "capability": "anti_detection_legacy",
                    "mode": "emulate",
                    "payload": {"runtime_warning": "evasion call failed"},
                }
            }
        )
    )
    # 68 + 13 + 18 + 10 (runtime_warning) = 109 -> clamped to 100
    assert risk["score"] == 100
    assert risk["severity"] == "critical"
    assert risk["runtime_warning"] is True


# ---------------------------------------------------------------------------
# Status deltas + clamping
# ---------------------------------------------------------------------------


def test_blocked_status_subtracts_twelve() -> None:
    risk = score_module_result(
        _result(
            status="blocked",
            artifacts={
                "legacy": {
                    "pack": "actor_pack",
                    "capability": "apt29",
                    "mode": "simulate",
                    "payload": {},
                }
            },
        )
    )
    # 55 + 8 + 0 - 12 (blocked) = 51
    assert risk["score"] == 51


def test_error_status_subtracts_fifteen_and_clamps_to_zero() -> None:
    """An errored standard module with no techniques should clamp at 0."""
    risk = score_module_result(_result(status="error", techniques=[]))
    # 35 + 0 - 15 = 20 (above 0, no clamp needed)
    assert risk["score"] == 20
    assert risk["severity"] == "low"


def test_score_never_exceeds_one_hundred() -> None:
    """Every legacy combination plus runtime warning + emulate must clamp at 100."""
    risk = score_module_result(
        _result(
            status="partial_success",
            artifacts={
                "legacy": {
                    "pack": "stealth_pack",
                    "capability": "anti_detection_legacy",
                    "mode": "emulate",
                    "payload": {"runtime_warning": "x"},
                }
            },
        )
    )
    assert risk["score"] == 100


# ---------------------------------------------------------------------------
# Hint fallback (legacy adapters that surface pack/cap via detection_hints)
# ---------------------------------------------------------------------------


def test_legacy_pack_falls_back_to_detection_hints() -> None:
    risk = score_module_result(
        _result(
            detection_hints={
                "legacy_pack": "c2_pack",
                "legacy_capability": "dns_tunneling",
                "legacy_mode": "simulate",
            },
        )
    )
    # 62 (c2_pack) + 10 (dns_tunneling) + 0 = 72
    assert risk["score"] == 72
    assert risk["pack"] == "c2_pack"
    assert risk["capability"] == "dns_tunneling"


# ---------------------------------------------------------------------------
# Tactic-aware base score (risk scoring v2)
# ---------------------------------------------------------------------------
#
# Pre-v2 behaviour: every standard-module result landed at score
# 35-55 ("low" / "medium") regardless of tactic. A successful
# `impact` step (T1486 ransomware encryption) scored the same as
# a successful `discovery` step (T1083 file enumeration). The
# tactic-aware base elevates end-of-chain destructive tactics so
# the risk_summary / dashboard reflects defender-impact severity.


def _tactic_result(module: str, *, status: str = "success", techniques: int = 1):
    return ModuleResult(
        status=status,
        module=module,
        message="",
        techniques=[f"T100{i}" for i in range(techniques)],
        artifacts={},
        detection_hints={},
        telemetry=[],
    )


def test_impact_module_scores_critical_severity() -> None:
    """A successful `impact` step (e.g. ransomware) must surface
    as `critical`, not `low`."""
    risk = score_module_result(_tactic_result("impact"))
    # tactic_base 85 + 5 (1 technique) + 0 (success) = 90 -> critical
    assert risk["score"] == 90
    assert risk["severity"] == "critical"
    assert "tactic_base=impact" in risk["rationale"]


def test_exfiltration_module_scores_high_severity() -> None:
    """A successful `exfiltration` step must surface as `high`."""
    risk = score_module_result(_tactic_result("exfiltration"))
    # tactic_base 75 + 5 (1 technique) + 0 (success) = 80 -> high
    assert risk["score"] == 80
    assert risk["severity"] == "high"
    assert "tactic_base=exfiltration" in risk["rationale"]


def test_discovery_module_scores_low_severity() -> None:
    """A successful `discovery` step (low defender impact) stays low."""
    risk = score_module_result(_tactic_result("discovery"))
    # tactic_base 35 + 5 (1 technique) + 0 (success) = 40 -> low
    assert risk["score"] == 40
    assert risk["severity"] == "low"
    assert "tactic_base=discovery" in risk["rationale"]


def test_reconnaissance_module_scores_lower_than_initial_access() -> None:
    """Pre-foothold tactics must score below post-foothold tactics."""
    recon = score_module_result(_tactic_result("reconnaissance"))
    initial = score_module_result(_tactic_result("initial_access"))
    assert recon["score"] < initial["score"]
    assert recon["severity"] == "low"
    assert initial["severity"] == "medium"


def test_credential_access_scores_higher_than_discovery() -> None:
    """Credential access enables lateral movement; weighted higher."""
    discovery = score_module_result(_tactic_result("discovery"))
    cred = score_module_result(_tactic_result("credential_access"))
    assert discovery["score"] < cred["score"]


def test_privilege_escalation_scores_higher_than_persistence() -> None:
    """Privilege elevation is a higher-impact step than persistence
    establishment (privilege grants persistence access too)."""
    persistence = score_module_result(_tactic_result("persistence"))
    priv_esc = score_module_result(_tactic_result("privilege_escalation"))
    assert persistence["score"] < priv_esc["score"]


def test_impact_outscores_exfiltration_outscores_discovery() -> None:
    """The full end-to-end ordering operators rely on for
    'this run had a critical step' triage."""
    discovery = score_module_result(_tactic_result("discovery"))
    exfil = score_module_result(_tactic_result("exfiltration"))
    impact = score_module_result(_tactic_result("impact"))
    assert discovery["score"] < exfil["score"] < impact["score"]
    assert discovery["severity"] == "low"
    assert exfil["severity"] == "high"
    assert impact["severity"] == "critical"


def test_standard_module_rationale_carries_matters_because() -> None:
    """Standard modules surface a defender-facing 'why this matters' line.

    The audit lens is "risk rationale should mention why the step
    matters." ``tactic_base=<tactic>`` says what tactic produced
    the score; ``matters_because=<text>`` says why a defender
    should care, in chain-position language a reader without
    MITRE ATT&CK fluency understands.
    """
    impact = score_module_result(_tactic_result("impact"))
    assert "matters_because=destructive endgame" in impact["rationale"]

    exfil = score_module_result(_tactic_result("exfiltration"))
    assert "matters_because=data leaves perimeter" in exfil["rationale"]

    cred = score_module_result(_tactic_result("credential_access"))
    assert "matters_because=enables lateral expansion" in cred["rationale"]

    recon = score_module_result(_tactic_result("reconnaissance"))
    assert "matters_because=pre-foothold target scoping" in recon["rationale"]


def test_unknown_standard_module_rationale_omits_matters_because() -> None:
    """An out-of-tree module (no tactic_base entry) gets no synthesised reason.

    Stable shape: the rationale always carries ``standard-module``
    for unknown modules; the ``matters_because`` line only surfaces
    when the module name maps to a documented tactic. Out-of-tree
    callers don't suddenly get a fabricated reason.
    """
    result = ModuleResult(
        status="success",
        module="unknown_module_xyz",
        message="",
        techniques=["T1234"],
        artifacts={},
        detection_hints={},
        telemetry=[],
    )
    risk = score_module_result(result)
    assert "standard-module" in risk["rationale"]
    assert not any(r.startswith("matters_because=") for r in risk["rationale"])


def test_legacy_tactic_pack_rationale_carries_matters_because() -> None:
    """The tactic_pack legacy path surfaces ``matters_because`` too.

    Pin the same defender-facing rationale on the legacy adapter
    branch so a defender triaging a legacy_impact emulate run sees
    the same chain-position context as the standard impact run.
    """
    result = ModuleResult(
        status="success",
        module="legacy_impact",
        message="",
        techniques=["T1486"],
        artifacts={
            "legacy": {
                "pack": "tactic_pack",
                "capability": "impact",
                "mode": "emulate",
            }
        },
        detection_hints={},
        telemetry=[],
    )
    risk = score_module_result(result)
    assert "tactic_base=impact" in risk["rationale"]
    assert "matters_because=destructive endgame" in risk["rationale"]


def test_blocked_impact_step_does_not_score_critical() -> None:
    """A blocked / failed step is not the same as a successful one;
    the status delta must dampen the tactic base so a defender
    triaging the report does not see a blocked-but-attempted impact
    as a successful encryption."""
    blocked = score_module_result(_tactic_result("impact", status="blocked"))
    success = score_module_result(_tactic_result("impact", status="success"))
    # blocked subtracts 12 from the tactic-aware base
    assert blocked["score"] == success["score"] - 12
    # Even with the dampener, impact stays in critical band — it
    # was attempted, just blocked. A defender should still treat
    # the blocked attempt as serious.
    assert blocked["severity"] in ("high", "critical")


def test_errored_recon_step_drops_to_low_severity() -> None:
    """A pre-foothold tactic + error status floors the score so
    failed reconnaissance does not pollute the risk_summary."""
    risk = score_module_result(_tactic_result("reconnaissance", status="error"))
    # tactic_base 25 + 5 (1 technique) - 15 (error) = 15 -> low
    assert risk["score"] == 15
    assert risk["severity"] == "low"


def test_unknown_module_name_falls_back_to_historic_default() -> None:
    """A module name not in the tactic map keeps the historic 35
    default base, preserving behaviour for out-of-tree callers."""
    risk = score_module_result(_tactic_result("totally_custom_module"))
    # 35 (default) + 5 (1 technique) + 0 (success) = 40
    assert risk["score"] == 40
    assert "standard-module" in risk["rationale"]
    # And no `tactic_base=` rationale because no match
    assert not any(r.startswith("tactic_base=") for r in risk["rationale"])


def test_legacy_module_branch_unchanged_by_tactic_base() -> None:
    """A legacy module result whose `module` field happens to match
    a tactic name (e.g. `legacy_credential_access`) must NOT trigger
    the tactic-aware path because the legacy branch is selected by
    `pack` presence in artifacts. Verify the pack branch still wins."""
    risk = score_module_result(
        ModuleResult(
            status="success",
            module="legacy_credential_access",  # would match tactic if path didn't gate
            message="",
            techniques=["T1003.001"],
            artifacts={
                "legacy": {
                    "pack": "actor_pack",
                    "capability": "apt29",
                    "mode": "simulate",
                    "payload": {},
                }
            },
            detection_hints={},
            telemetry=[],
        )
    )
    # Pack branch: 55 + 8 + 0 = 63
    assert risk["score"] == 63
    assert "pack=actor_pack" in risk["rationale"]
    # tactic_base must NOT appear; legacy path took precedence
    assert not any(r.startswith("tactic_base=") for r in risk["rationale"])


def test_techniques_bonus_caps_at_four_for_tactic_base_path() -> None:
    """The +5-per-technique bonus stays capped at 20 (4 techniques)
    for tactic-aware results too, so a module emitting 8 techniques
    does not silently drift to score 105."""
    risk = score_module_result(_tactic_result("discovery", techniques=8))
    # tactic_base 35 + min(20, 8*5)=20 = 55 -> medium
    assert risk["score"] == 55
    assert risk["severity"] == "medium"
