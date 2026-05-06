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
