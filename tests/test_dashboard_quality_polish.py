"""Static dashboard quality polish — pre-rc2.

Three small product polishes on the static run viewer + top-level
aggregator. None changes the layout fundamentally; each tightens
how the page reads to a fresh user / SOC analyst.

Pinned invariants:

1. **Header severity badge.** When the manifest's risk block
   carries a non-zero count in any severity tier, a top-level
   severity badge appears in the header alongside the
   ``overall_status`` / ``dry_run`` / ``ai:`` badges. This
   surfaces severity at the same scan-weight as status, so an
   operator does not need to scroll to the risk-summary table to
   see "this run had a critical finding".
2. **Detection drafts maturity caveat.** The Detection drafts
   section header carries an explicit maturity caveat (Sigma
   most mature, YARA-L medium, SPL draft / starter) so the
   per-run dashboard cannot be read as "production detections
   ready to deploy".
3. **Local-only contract reminder.** Both the per-run viewer's
   header card AND the top-level aggregator's header card
   surface the "no server, no JavaScript, no external assets,
   no network calls" promise inline (instead of leaving it only
   in the muted footer).
4. The legacy invariants (no ``<script>``, no external
   ``<link>`` / ``<img>`` / ``http://`` / ``https://``) survive
   the changes.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.core.reporting.output_index import (
    build_index_rows,
    render_output_index_html,
)
from src.core.reporting.viewer import (
    _highest_risk_tier,
    render_html,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manifest_with_risk(severity_counts: Dict[str, int]) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "run": {
            "run_id": "run-test",
            "scenario_name": "Test scenario",
            "overall_status": "success",
            "module_count": 1,
        },
        "safety": {"dry_run": True},
        "detections": {"total": 3, "engine_counts": {"sigma": 1, "yara_l": 1, "spl": 1}, "per_step": []},
        "risk": {
            "risk_summary": {
                tier: int(severity_counts.get(tier, 0))
                for tier in ("critical", "high", "medium", "low")
            },
            "modules": [],
        },
    }


# ---------------------------------------------------------------------------
# 1. _highest_risk_tier helper
# ---------------------------------------------------------------------------


def test_highest_risk_tier_returns_first_non_zero_in_priority_order() -> None:
    manifest = _manifest_with_risk({"critical": 1, "high": 2, "medium": 3, "low": 4})
    assert _highest_risk_tier(manifest) == "critical"


def test_highest_risk_tier_skips_zero_counts() -> None:
    manifest = _manifest_with_risk({"critical": 0, "high": 0, "medium": 1, "low": 0})
    assert _highest_risk_tier(manifest) == "medium"


def test_highest_risk_tier_returns_low_when_only_low_set() -> None:
    manifest = _manifest_with_risk({"low": 2})
    assert _highest_risk_tier(manifest) == "low"


def test_highest_risk_tier_returns_empty_when_all_zero() -> None:
    manifest = _manifest_with_risk({})
    assert _highest_risk_tier(manifest) == ""


def test_highest_risk_tier_returns_empty_when_no_risk_block() -> None:
    manifest = {"schema_version": 1, "run": {"run_id": "x"}}
    assert _highest_risk_tier(manifest) == ""


def test_highest_risk_tier_handles_non_int_values() -> None:
    manifest = {
        "schema_version": 1,
        "run": {"run_id": "x"},
        "risk": {"risk_summary": {"critical": "two", "high": 1}},
    }
    # Non-int "two" coerces to 0; high=1 survives.
    assert _highest_risk_tier(manifest) == "high"


# ---------------------------------------------------------------------------
# 2. Header severity badge
# ---------------------------------------------------------------------------


def test_header_renders_severity_badge_when_risk_has_critical() -> None:
    manifest = _manifest_with_risk({"critical": 1})
    html = render_html(manifest)
    # Locate the header section.
    header = html.split("</header>", 1)[0]
    assert "badge-error" in header  # critical maps to badge-error
    assert ">critical<" in header


def test_header_renders_severity_badge_when_risk_has_only_low() -> None:
    manifest = _manifest_with_risk({"low": 3})
    html = render_html(manifest)
    header = html.split("</header>", 1)[0]
    # low maps to badge-success
    assert "badge-success" in header
    assert ">low<" in header


def test_header_omits_severity_badge_when_risk_block_empty() -> None:
    manifest = _manifest_with_risk({})
    html = render_html(manifest)
    header = html.split("</header>", 1)[0]
    # No severity word in the header.
    for tier in ("critical", "high", "medium", "low"):
        assert f">{tier}<" not in header, (
            f"unexpected severity badge for empty risk block: {tier}"
        )


def test_header_omits_severity_badge_when_no_risk_block() -> None:
    manifest = {
        "schema_version": 1,
        "run": {"run_id": "x", "scenario_name": "x", "overall_status": "success"},
    }
    html = render_html(manifest)
    header = html.split("</header>", 1)[0]
    for tier in ("critical", "high", "medium", "low"):
        assert f">{tier}<" not in header


# ---------------------------------------------------------------------------
# 3. Detection drafts maturity caveat
# ---------------------------------------------------------------------------


def test_detection_drafts_section_carries_maturity_caveat() -> None:
    """Dashboard cannot read as 'production detections ready to deploy'."""
    manifest = _manifest_with_risk({})
    html = render_html(manifest)
    # Locate the Detection drafts section.
    match = re.search(
        r'<section class="card"><h2>Detection drafts</h2>.*?</section>',
        html,
        re.DOTALL,
    )
    assert match is not None, "Detection drafts section missing"
    section = match.group(0)
    assert "Drafts" in section and "not production detections" in section, (
        f"maturity caveat missing in detection-drafts section: {section[:300]}"
    )
    assert "Sigma" in section and "YARA-L" in section and "SPL" in section, (
        "per-engine maturity hierarchy missing"
    )


def test_detection_drafts_empty_state_unchanged() -> None:
    """No detection drafts -> 'No detection drafts generated.' unchanged."""
    manifest = {
        "schema_version": 1,
        "run": {"run_id": "x", "scenario_name": "x", "overall_status": "success"},
        "detections": {"total": 0, "engine_counts": {}, "per_step": []},
    }
    html = render_html(manifest)
    match = re.search(
        r'<section class="card"><h2>Detection drafts</h2>.*?</section>',
        html,
        re.DOTALL,
    )
    assert match is not None
    section = match.group(0)
    assert "No detection drafts generated" in section
    # Empty state should NOT carry the maturity caveat (no drafts to caveat).
    assert "not production detections" not in section


# ---------------------------------------------------------------------------
# 4. Local-only contract reminder in viewer + aggregator
# ---------------------------------------------------------------------------


def test_viewer_header_carries_local_only_promise() -> None:
    manifest = _manifest_with_risk({})
    html = render_html(manifest)
    header = html.split("</header>", 1)[0]
    # The phrasing must match the README's dashboard description so
    # the two pages reinforce each other.
    assert "no server" in header
    assert "no JavaScript" in header
    assert "no external" in header
    assert "no network calls" in header


def test_aggregator_header_carries_local_only_promise() -> None:
    """Aggregator header shows the same local-only promise."""
    rows = build_index_rows  # ensure import works
    _ = rows
    html = render_output_index_html([])
    # Empty rows list still surfaces the promise (it's in the header
    # card, not gated on having runs).
    assert "no server" in html
    assert "no JavaScript" in html
    assert "no external" in html
    assert "no network calls" in html


# ---------------------------------------------------------------------------
# 5. Local-only invariants survive
# ---------------------------------------------------------------------------


def test_viewer_remains_self_contained_after_polish() -> None:
    manifest = _manifest_with_risk({"critical": 1})
    html = render_html(manifest)
    assert "<script" not in html
    assert "<svg" not in html
    assert "<canvas" not in html
    # No external schemes (no http://, no https:// in href / src).
    assert 'http://' not in html
    assert 'https://' not in html
    assert "<link " not in html
    assert "<iframe" not in html


def test_aggregator_remains_self_contained_after_polish() -> None:
    html = render_output_index_html([])
    assert "<script" not in html
    assert "<svg" not in html
    assert "<canvas" not in html
    assert 'http://' not in html
    assert 'https://' not in html
    assert "<link " not in html
    assert "<iframe" not in html
