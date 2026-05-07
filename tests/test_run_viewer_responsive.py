"""Viewer responsive-layout polish — release-candidate pass.

Pinned invariants:

1. The rendered HTML wraps the body in ``<main>`` so the inline
   ``main { max-width: 1280px; ... }`` rule can centre the
   content on wide monitors without squeezing the page on a
   phone.
2. The CSS includes a ``@media (max-width: 600px)`` rule so the
   dashboard reflows on narrow viewports (smaller padding,
   smaller headings, narrower KPI grid).
3. Tables are wrapped in a horizontally-scrollable container so
   a wide propagation / risk table on a phone scrolls inside
   the card instead of pushing the whole page sideways.
4. The local-only invariants from earlier polish PRs still
   hold (no `<script>`, no external assets, no network).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.core.reporting.manifest import build_manifest
from src.core.reporting.viewer import render_html


def _populated_manifest(run_dir: Path) -> Dict[str, Any]:
    return build_manifest(
        run_id="run-resp",
        run_dir=run_dir,
        scenario_name="Responsive fixture",
        overall_status="success",
        steps=[
            {
                "step_id": "s1",
                "module": "execution",
                "name": "Step",
                "status": "success",
                "techniques": ["T1059"],
                "artifacts": {},
                "detections": {},
            },
        ],
    )


def test_render_html_wraps_body_in_main(tmp_path: Path) -> None:
    """The rendered document wraps content in <main> so the CSS
    width cap can centre the dashboard on wide monitors.
    """
    html = render_html(_populated_manifest(tmp_path))
    body_open = html.find("<body>")
    main_open = html.find("<main>", body_open)
    main_close = html.find("</main>", main_open)
    assert body_open > 0
    assert main_open > body_open
    assert main_close > main_open


def test_render_html_contains_max_width_rule_for_main(tmp_path: Path) -> None:
    """The inline CSS pins a max-width on <main> for readability."""
    html = render_html(_populated_manifest(tmp_path))
    assert "main { max-width: 1280px" in html


def test_render_html_contains_narrow_viewport_media_query(tmp_path: Path) -> None:
    """The CSS adds a phone-sized breakpoint at 600px."""
    html = render_html(_populated_manifest(tmp_path))
    assert "@media (max-width: 600px)" in html
    # The breakpoint narrows the body padding so the dashboard
    # is usable on phones.
    assert "body { padding: 12px" in html


def test_render_html_table_card_uses_horizontal_scroll(tmp_path: Path) -> None:
    """Cards that contain a <table> get an overflow-x: auto wrapper."""
    html = render_html(_populated_manifest(tmp_path))
    assert ".card table { display: block; overflow-x: auto" in html


def test_render_html_polish_does_not_introduce_external_assets(tmp_path: Path) -> None:
    """Defence-in-depth: the polish PR must not introduce a <link>,
    <script>, or external URL.
    """
    html = render_html(_populated_manifest(tmp_path))
    assert "<script" not in html
    assert "<link " not in html
    for forbidden in ("http://", "https://", "ftp://", "ws://", "wss://"):
        assert forbidden not in html


def test_render_html_polish_keeps_required_meta_tags(tmp_path: Path) -> None:
    """The viewport meta tag survives the polish so the responsive
    layout actually responds — without it phones render at zoomed-out
    desktop width.
    """
    html = render_html(_populated_manifest(tmp_path))
    assert 'name="viewport"' in html
    assert "width=device-width" in html
    assert 'name="referrer"' in html
