"""Viewer risk-rationale rendering tests.

`build_risk_summary` already includes the per-module ``rationale``
list (e.g. ``["pack=tactic_pack", "tactic_base=impact",
"mode=emulate"]``) in the risk_summary.json — but the static
viewer didn't surface it. An operator triaging a critical risk
score had to open the JSON to learn *why* the score landed where
it did.

This file pins:
1. The viewer's risk-summary table now has a ``why`` column that
   joins the rationale entries into a comma-separated string.
2. The rationale is HTML-escaped (no XSS leak from a future
   profile that puts unsafe characters in a rationale string).
3. Empty / missing rationale keeps the column empty without
   breaking layout.
4. The rationale surfaces the v3 ``tactic_base=...`` marker for
   tactic_pack legacy adapters so operators see the per-tactic
   base reflected in the table.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

from src.core.reporting.viewer import _render_risk, write_viewer


def _manifest_with_modules(modules: list[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "run": {"run_id": "r", "scenario_name": "s", "overall_status": "success"},
        "safety": {},
        "steps": [],
        "propagation_edges": [],
        "attack_coverage": [],
        "telemetry": {"path": "telemetry.jsonl", "total": 0, "by_event_type": [], "by_module": []},
        "detections": {"total": 0, "by_engine": [], "by_step": []},
        "reports": {},
        "risk": {
            "risk_summary": {
                "critical": sum(1 for m in modules if m.get("severity") == "critical"),
                "high": sum(1 for m in modules if m.get("severity") == "high"),
                "medium": sum(1 for m in modules if m.get("severity") == "medium"),
                "low": sum(1 for m in modules if m.get("severity") == "low"),
            },
            "average_score": (
                sum(m.get("score", 0) for m in modules) / len(modules) if modules else 0
            ),
            "modules": modules,
        },
        "copilot": {"present": False},
        "legacy_controls": {},
        "warnings": [],
        "errors": [],
        "blocked_steps": [],
        "module_keys": [],
    }


def test_viewer_risk_table_renders_rationale_column() -> None:
    manifest = _manifest_with_modules(
        [
            {
                "module": "impact:ransomware",
                "severity": "critical",
                "score": 100,
                "mode": "emulate",
                "rationale": ["pack=tactic_pack", "tactic_base=impact", "mode=emulate"],
            }
        ]
    )
    html = _render_risk(manifest)
    # Header column present
    assert "<th>why</th>" in html
    # All three rationale tokens surface in the rendered cell.
    assert "pack=tactic_pack" in html
    assert "tactic_base=impact" in html
    assert "mode=emulate" in html


def test_viewer_risk_rationale_is_html_escaped() -> None:
    """A future profile contributor could put `<` or `>` in a
    rationale string. The renderer must HTML-escape so the column
    can't break the table or inject script tags.
    """
    manifest = _manifest_with_modules(
        [
            {
                "module": "evil",
                "severity": "high",
                "score": 80,
                "mode": "simulate",
                "rationale": ['pack=evil<script>alert("x")</script>'],
            }
        ]
    )
    html = _render_risk(manifest)
    # Raw script must not appear.
    assert "<script>" not in html
    # Escaped form does.
    assert "&lt;script&gt;" in html


def test_viewer_risk_rationale_missing_is_blank() -> None:
    """Pre-v3 reports without rationale (e.g. exported from earlier
    runs) shouldn't throw or render junk — column is just empty.
    """
    manifest = _manifest_with_modules(
        [
            {
                "module": "noscale",
                "severity": "low",
                "score": 25,
                "mode": "simulate",
                # no rationale key at all
            }
        ]
    )
    html = _render_risk(manifest)
    assert "<th>why</th>" in html
    # Row should still render with the empty ``why`` cell.
    assert '<code>noscale</code>' in html


def test_viewer_risk_rationale_handles_non_list_value() -> None:
    """Defensive: if a future caller writes ``rationale`` as a
    string instead of a list, the cell still renders without
    crashing (treated as empty)."""
    manifest = _manifest_with_modules(
        [
            {
                "module": "weird",
                "severity": "medium",
                "score": 60,
                "mode": "simulate",
                "rationale": "not-a-list",
            }
        ]
    )
    html = _render_risk(manifest)
    assert '<code>weird</code>' in html
    # Garbage rationale is NOT propagated into the cell.
    assert "not-a-list" not in html


def test_viewer_end_to_end_includes_rationale_in_index_html(
    tmp_path: Path,
) -> None:
    """End-to-end: writing the viewer for a manifest with rationale
    surfaces it in the on-disk ``index.html``.
    """
    run_dir = tmp_path / "run-with-rationale"
    run_dir.mkdir()
    manifest = _manifest_with_modules(
        [
            {
                "module": "impact:ransomware",
                "severity": "critical",
                "score": 100,
                "mode": "emulate",
                "rationale": ["pack=tactic_pack", "tactic_base=impact", "mode=emulate"],
            },
            {
                "module": "discovery:files",
                "severity": "low",
                "score": 30,
                "mode": "simulate",
                "rationale": ["tactic_base=discovery"],
            },
        ]
    )
    write_viewer(run_dir, manifest)
    html = (run_dir / "index.html").read_text(encoding="utf-8")
    assert "tactic_base=impact" in html
    assert "tactic_base=discovery" in html
    # Both rows present.
    assert "impact:ransomware" in html
    assert "discovery:files" in html


def test_viewer_risk_rationale_column_class_is_muted() -> None:
    """The rationale column uses the muted text style so it's
    visible but doesn't visually compete with the severity badge."""
    manifest = _manifest_with_modules(
        [
            {
                "module": "x",
                "severity": "high",
                "score": 75,
                "mode": "simulate",
                "rationale": ["tactic_base=impact"],
            }
        ]
    )
    html = _render_risk(manifest)
    # The cell uses the documented `muted` class.
    assert re.search(r'<td class="muted">tactic_base=impact</td>', html)
