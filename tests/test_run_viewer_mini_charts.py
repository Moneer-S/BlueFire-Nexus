"""Pure-CSS mini-charts in the static run viewer.

P2 of the release/demo polish backlog (after the top-level
aggregator landed in a separate PR): the KPI counters and the
telemetry summary are now backed by deterministic horizontal bar
charts rendered with inline CSS — no JavaScript, no external
assets, no SVG library, no canvas. The width of each bar is
clamped to ``[1, 100]`` percent and cast through ``int`` so a
maliciously-shaped manifest cannot inject arbitrary CSS.

Pinned invariants:

1. **Pure-CSS / no JS.** No ``<script>`` / ``<svg>`` / ``<canvas>``
   anywhere in the output.
2. **No external assets.** No ``<link>``, no remote ``<img>``, no
   CDN reference.
3. **Deterministic.** The same input renders the same output —
   the helper sorts mapping keys alphabetically before emitting
   rows.
4. **Width clamping.** Every emitted ``style="width: NN%;"``
   resolves to an integer in ``[1, 100]``, regardless of input.
5. **Empty-state graceful.** Manifests without telemetry / steps
   render a coherent page (no orphan ``<h3>`` headers, no
   broken ``style=""`` placeholders).
6. **HTML escape.** Module names with HTML metacharacters are
   escaped, not interpreted.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.core.reporting.viewer import (
    _bar_width_pct,
    _module_status_counts,
    _render_bar_chart,
    render_html,
)


# ---------------------------------------------------------------------------
# 1. _bar_width_pct — clamping and overflow guard
# ---------------------------------------------------------------------------


def test_bar_width_pct_handles_zero_max() -> None:
    """Zero max implies an empty mapping; renderer returns the floor (1)."""
    assert _bar_width_pct(0, 0) == 1
    assert _bar_width_pct(5, 0) == 1


def test_bar_width_pct_handles_zero_value() -> None:
    """Zero value still surfaces a 1% sliver so the row is visible."""
    assert _bar_width_pct(0, 100) == 1


def test_bar_width_pct_clamps_overflow() -> None:
    """Inputs that round above 100 are capped at 100."""
    assert _bar_width_pct(200, 100) == 100


def test_bar_width_pct_returns_integer() -> None:
    """Width is always an integer so the inline style attribute stays clean."""
    width = _bar_width_pct(50, 100)
    assert isinstance(width, int)
    assert width == 50


def test_bar_width_pct_handles_non_numeric_input() -> None:
    """Any non-numeric input falls back to the safe 1% sliver."""
    assert _bar_width_pct("abc", 100) == 1
    assert _bar_width_pct(50, "abc") == 1
    assert _bar_width_pct(None, None) == 1


def test_bar_width_pct_proportional_for_typical_inputs() -> None:
    assert _bar_width_pct(25, 100) == 25
    assert _bar_width_pct(50, 200) == 25
    assert _bar_width_pct(1, 1000) == 1  # rounds to 0 then floored to 1


# ---------------------------------------------------------------------------
# 2. _render_bar_chart — pure renderer
# ---------------------------------------------------------------------------


def test_render_bar_chart_returns_empty_string_for_empty_input() -> None:
    assert _render_bar_chart({}) == ""


def test_render_bar_chart_emits_one_row_per_key() -> None:
    out = _render_bar_chart({"a": 1, "b": 2, "c": 3})
    # Three .bar-row entries.
    assert out.count('class="bar-row') == 3
    # Sorted alphabetically.
    a_pos = out.index(">a<")
    b_pos = out.index(">b<")
    c_pos = out.index(">c<")
    assert a_pos < b_pos < c_pos


def test_render_bar_chart_widths_are_proportional() -> None:
    out = _render_bar_chart({"small": 10, "big": 100})
    matches = re.findall(r'style="width: (\d+)%;"', out)
    assert sorted(matches) == ["10", "100"]


def test_render_bar_chart_skips_negative_values() -> None:
    out = _render_bar_chart({"good": 5, "bad": -1})
    # Only the "good" key rendered; "bad" is filtered out.
    assert "<code>good</code>" in out
    assert "<code>bad</code>" not in out


def test_render_bar_chart_skips_non_numeric_values() -> None:
    out = _render_bar_chart({"good": 5, "weird": "abc"})
    assert "<code>good</code>" in out
    assert "<code>weird</code>" not in out


def test_render_bar_chart_escapes_html_in_keys() -> None:
    out = _render_bar_chart({"<script>": 1})
    assert "<script>1</script>" not in out
    assert "&lt;script&gt;" in out


def test_render_bar_chart_emits_aria_label() -> None:
    """Each bar's track carries an aria-label so screen readers can read it."""
    out = _render_bar_chart({"alpha": 7})
    assert 'aria-label="alpha: 7"' in out


def test_render_bar_chart_marks_zero_rows_with_empty_class() -> None:
    out = _render_bar_chart({"alpha": 0, "beta": 5})
    # Each row's start is the preceding ``<div class="bar-row...``
    # opening — locate it by walking back from the row's label.
    alpha_idx = out.index(">alpha<")
    alpha_row_start = out.rfind('<div class="bar-row', 0, alpha_idx)
    alpha_row_end = out.find("</div>", alpha_idx)
    alpha_row = out[alpha_row_start:alpha_row_end]
    assert "bar-row-empty" in alpha_row
    beta_idx = out.index(">beta<")
    beta_row_start = out.rfind('<div class="bar-row', 0, beta_idx)
    beta_row_end = out.find("</div>", beta_idx)
    beta_row = out[beta_row_start:beta_row_end]
    assert "bar-row-empty" not in beta_row


def test_render_bar_chart_applies_fill_class() -> None:
    out = _render_bar_chart({"alpha": 1}, fill_class="bar-fill-success")
    assert "bar-fill bar-fill-success" in out


# ---------------------------------------------------------------------------
# 3. _module_status_counts — input shape tolerance
# ---------------------------------------------------------------------------


def test_module_status_counts_empty_manifest() -> None:
    assert _module_status_counts({}) == {
        "success": 0,
        "blocked": 0,
        "error": 0,
        "skipped": 0,
    }


def test_module_status_counts_canonical_statuses() -> None:
    manifest = {
        "steps": [
            {"status": "success"},
            {"status": "success"},
            {"status": "blocked"},
            {"status": "error"},
            {"status": "failure"},  # treated as error
            {"status": "weird"},  # treated as skipped
        ]
    }
    counts = _module_status_counts(manifest)
    assert counts == {"success": 2, "blocked": 1, "error": 2, "skipped": 1}


def test_module_status_counts_handles_non_list_steps() -> None:
    """An invalid ``steps`` field returns the zero-everywhere baseline."""
    manifest = {"steps": "not a list"}
    counts = _module_status_counts(manifest)
    assert counts == {"success": 0, "blocked": 0, "error": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# 4. render_html — end-to-end mini-chart integration
# ---------------------------------------------------------------------------


def _make_manifest(
    *,
    by_type: Dict[str, int] = None,
    by_module: Dict[str, int] = None,
    statuses: list = None,
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "run": {
            "run_id": "run-test",
            "scenario_name": "Test",
            "overall_status": "success",
            "module_count": len(statuses) if statuses else 0,
        },
        "steps": [
            {"step_id": f"s{i}", "status": status, "module": "m", "name": "n"}
            for i, status in enumerate(statuses or [], start=1)
        ],
        "telemetry": {
            "event_count": (
                sum((by_type or {}).values()) + sum((by_module or {}).values())
            ),
            "events_by_type": by_type or {},
            "events_by_module": by_module or {},
            "path": "telemetry.jsonl",
        },
    }


def test_render_html_includes_telemetry_bar_chart() -> None:
    manifest = _make_manifest(
        by_type={"process_event": 5, "network_event": 2},
        by_module={"discovery": 4, "credential_access": 3},
    )
    html = render_html(manifest)
    # CSS class is present and referenced from the chart sections.
    assert ".bar-chart" in html  # CSS rule
    assert 'class="bar-chart"' in html  # markup
    # Both type and module charts render their respective rows.
    assert "process_event" in html
    assert "network_event" in html
    assert "discovery" in html
    assert "credential_access" in html


def test_render_html_module_status_chart_renders_when_steps_present() -> None:
    manifest = _make_manifest(statuses=["success", "success", "blocked", "error"])
    html = render_html(manifest)
    assert "Module status" in html
    # Tier-specific fill classes surface.
    assert "bar-fill-success" in html
    assert "bar-fill-warning" in html
    assert "bar-fill-danger" in html
    assert "bar-fill-muted" in html


def test_render_html_no_module_status_chart_when_no_steps() -> None:
    """A manifest without steps must not render the Module status card."""
    manifest = _make_manifest()
    html = render_html(manifest)
    assert "Module status" not in html


def test_render_html_no_javascript_introduced() -> None:
    """Mini-charts must not introduce <script>, <canvas>, or <svg>."""
    manifest = _make_manifest(
        by_type={"a": 1, "b": 2},
        by_module={"m": 1},
        statuses=["success", "blocked"],
    )
    html = render_html(manifest)
    assert "<script" not in html
    assert "<canvas" not in html
    assert "<svg" not in html


def test_render_html_no_external_assets_for_charts() -> None:
    manifest = _make_manifest(by_type={"a": 1}, statuses=["success"])
    html = render_html(manifest)
    # Some legitimate <a href> for artifact links exist; what we
    # forbid is external scheme references.
    assert "http://" not in html
    assert "https://" not in html
    assert "cdn." not in html


def test_render_html_bar_widths_are_clamped() -> None:
    manifest = _make_manifest(by_type={"a": 1, "b": 100, "c": 200})
    html = render_html(manifest)
    widths = re.findall(r'style="width: (\d+)%;"', html)
    assert widths, "expected at least one bar width"
    for w in widths:
        n = int(w)
        assert 1 <= n <= 100, f"bar width {w} out of [1,100] clamp"


def test_render_html_escapes_malicious_module_name_in_chart() -> None:
    """A module name with HTML metacharacters cannot escape escaping."""
    manifest = _make_manifest(by_module={"<script>alert(1)</script>": 1})
    html = render_html(manifest)
    assert "<script>alert(1)</script>" not in html


def test_render_html_telemetry_with_only_one_dimension() -> None:
    """Manifests with by_type but no by_module (or vice versa) still render."""
    manifest = _make_manifest(by_type={"a": 1, "b": 2})
    html = render_html(manifest)
    assert "By type" in html
    assert "By module" not in html


def test_render_html_telemetry_event_count_zero_falls_back_cleanly() -> None:
    """A run with zero events keeps the existing 'No telemetry events recorded' state."""
    manifest = {
        "schema_version": 1,
        "run": {"run_id": "run-x", "scenario_name": "x", "module_count": 0},
        "telemetry": {"event_count": 0},
    }
    html = render_html(manifest)
    assert "No telemetry events recorded" in html
    # No bar chart in this branch.
    assert 'class="bar-chart"' not in html


def test_render_html_inline_style_only_uses_safe_keys() -> None:
    """Sanity check: every inline style we add stays within our allowed keys."""
    manifest = _make_manifest(by_type={"a": 1}, statuses=["success"])
    html = render_html(manifest)
    inline_styles = re.findall(r'style="([^"]+)"', html)
    for s in inline_styles:
        # Each declaration is a key:value pair; we only emit
        # width/display/gap/flex-wrap/min-width/flex/margin-top.
        for decl in s.split(";"):
            decl = decl.strip()
            if not decl:
                continue
            key, _, _ = decl.partition(":")
            key = key.strip().lower()
            assert key in {
                "width",
                "display",
                "gap",
                "flex-wrap",
                "min-width",
                "flex",
                "margin-top",
            }, f"unexpected inline-style key {key!r} in: {s}"
