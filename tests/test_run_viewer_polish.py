"""Viewer polish regression tests.

Pinned invariants from the demo-readiness viewer-polish PR:

1. **Risk summary renders before the scenario timeline.** Operators
   triaging a problem run see severity totals + the per-module
   table without scrolling past a 12-row procedural list.
2. **Severity column uses coloured badges**, mirroring the status-
   badge palette so the visual hierarchy of failures is
   immediate.
3. **Timeline notes column** surfaces the message text only on
   non-success rows (blocked / error / failure / partial_success)
   so success boilerplate does not dominate the column. Truncated
   to a single line + 200 chars for compactness.
4. **Artifact links** drop the redundant trailing
   ``(<code>path</code>)`` — when the link text is the same as
   the href, repeating it adds noise.
5. **Existing structural invariants from the prior viewer tests
   still hold**: no scripts, no external assets, escape
   discipline, schema-version banner, etc. (Re-asserted in
   ``test_run_viewer.py``; this file pins only the new polish
   behaviours.)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.core.reporting.manifest import build_manifest
from src.core.reporting.viewer import render_html


def _populated_manifest(
    run_dir: Path,
    *,
    include_blocked_step: bool = False,
) -> Dict[str, Any]:
    """Manifest fixture with risk summary populated."""
    steps: List[Dict[str, Any]] = [
        {
            "step_id": "step-success",
            "module": "execution",
            "name": "Success step",
            "status": "success",
            "message": "Simulated execution.",
            "techniques": ["T1059"],
            "artifacts": {},
            "detections": {},
        },
    ]
    if include_blocked_step:
        steps.append(
            {
                "step_id": "step-blocked",
                "module": "impact",
                "name": "Blocked impact",
                "status": "blocked",
                "message": "lab confirmation required for emulate mode",
                "techniques": [],
                "artifacts": {},
                "detections": {},
            }
        )
    return build_manifest(
        run_id="run-polish",
        run_dir=run_dir,
        scenario_name="Polish fixture",
        overall_status="success",
        steps=steps,
        risk_summary_payload={
            "risk_summary": {"critical": 0, "high": 1, "medium": 1, "low": 2},
            "average_score": 50.0,
            "modules": [
                {
                    "module": "execution",
                    "severity": "low",
                    "score": 10,
                    "mode": "simulate",
                },
                {
                    "module": "impact",
                    "severity": "high",
                    "score": 80,
                    "mode": "simulate",
                },
                {
                    "module": "exfiltration",
                    "severity": "medium",
                    "score": 50,
                    "mode": "simulate",
                },
                {
                    "module": "credential_access",
                    "severity": "critical",
                    "score": 95,
                    "mode": "simulate",
                },
            ],
        },
    )


# ---------------------------------------------------------------------------
# 1. Risk summary section appears before the scenario timeline
# ---------------------------------------------------------------------------


def test_risk_summary_renders_before_scenario_timeline(tmp_path: Path) -> None:
    """The Risk summary <h2> appears earlier in the document than
    the Scenario timeline <h2>.

    Defends the deliberate section ordering: triage starts with
    severity totals, not with a procedural step list.
    """
    html = render_html(_populated_manifest(tmp_path))
    risk_pos = html.find("<h2>Risk summary</h2>")
    timeline_pos = html.find("<h2>Scenario timeline</h2>")
    assert risk_pos > 0, "Risk summary section missing"
    assert timeline_pos > 0, "Scenario timeline section missing"
    assert risk_pos < timeline_pos, (
        f"Risk summary should render before scenario timeline; "
        f"got risk@{risk_pos}, timeline@{timeline_pos}"
    )


# ---------------------------------------------------------------------------
# 2. Severity badges in the per-module risk table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_class",
    [
        ("critical", "badge-error"),
        ("high", "badge-error"),
        ("medium", "badge-blocked"),
        ("low", "badge-success"),
    ],
)
def test_risk_module_severity_renders_as_coloured_badge(
    tmp_path: Path, severity: str, expected_class: str
) -> None:
    """Each documented severity gets the right coloured badge class."""
    html = render_html(_populated_manifest(tmp_path))
    # The risk-summary table renders the severity inside a span
    # with the documented class. Find the row for any module that
    # has this severity and assert the class is set correctly.
    snippet = f'<span class="badge {expected_class}">{severity}</span>'
    assert snippet in html, (
        f"missing severity badge for {severity}; expected snippet {snippet!r}"
    )


def test_risk_module_severity_unknown_falls_back_to_skipped(
    tmp_path: Path,
) -> None:
    """An unrecognised severity uses the muted skipped style.

    Defensive: an upstream bug or an external risk-summary file
    with non-standard severity values does not crash; it gets a
    visibly distinct (muted) badge.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["risk"]["modules"].append(
        {"module": "exotic", "severity": "rotating-yellow", "score": 0, "mode": ""}
    )
    html = render_html(manifest)
    assert '<span class="badge badge-skipped">rotating-yellow</span>' in html


# ---------------------------------------------------------------------------
# 3. Timeline "notes" column behaviour
# ---------------------------------------------------------------------------


def test_timeline_includes_notes_column_header(tmp_path: Path) -> None:
    """The new column appears in the table header."""
    html = render_html(_populated_manifest(tmp_path))
    # Find the timeline section by its <h2> and assert the notes
    # header is in the same card (between the section and the next
    # </section>).
    section_start = html.find("<h2>Scenario timeline</h2>")
    section_end = html.find("</section>", section_start)
    assert section_start > 0 and section_end > section_start
    section = html[section_start:section_end]
    assert "<th>notes</th>" in section


def test_timeline_renders_message_only_for_non_success_rows(tmp_path: Path) -> None:
    """Success rows show a dash (mdash) in the notes column.

    A blocked row surfaces the message text inline so an operator
    can triage without opening report.json.
    """
    html = render_html(
        _populated_manifest(tmp_path, include_blocked_step=True)
    )
    # The blocked row's notes column carries the message text.
    assert "lab confirmation required for emulate mode" in html
    # The success row's notes column is rendered as the mdash
    # placeholder. (We can't easily target a specific cell, but
    # we can assert the success message itself is NOT rendered
    # as a notes cell — the success row's "Simulated execution."
    # message is boilerplate and would clutter the column.)
    assert "Simulated execution." not in html


def test_timeline_notes_truncated_to_first_line(tmp_path: Path) -> None:
    """A multi-line message renders as the first line only.

    Defends the "compact column" contract — long stack traces or
    multi-paragraph diagnostics do not break the table.
    """
    manifest = _populated_manifest(tmp_path)
    manifest["steps"].append(
        {
            "step_id": "step-multi",
            "module": "x",
            "name": "Multi-line failure",
            "status": "failure",
            "message": "first line of error\nsecond line that should not appear\n",
            "techniques": [],
            "artifacts": {},
            "detections": {},
        }
    )
    html = render_html(manifest)
    assert "first line of error" in html
    assert "second line that should not appear" not in html


def test_timeline_notes_truncated_to_200_chars(tmp_path: Path) -> None:
    """A pathologically long single-line message is truncated."""
    manifest = _populated_manifest(tmp_path)
    long_message = "x" * 500
    manifest["steps"].append(
        {
            "step_id": "step-long",
            "module": "x",
            "name": "Long failure",
            "status": "error",
            "message": long_message,
            "techniques": [],
            "artifacts": {},
            "detections": {},
        }
    )
    html = render_html(manifest)
    # Truncated value present, but not the full 500-char message.
    assert "x" * 200 in html
    assert "x" * 201 not in html


# ---------------------------------------------------------------------------
# 4. Artifact links — no redundant path repetition
# ---------------------------------------------------------------------------


def test_artifact_links_do_not_repeat_path_outside_link_text(
    tmp_path: Path,
) -> None:
    """The artifact-list rows render as a single <a><code>path</code></a>.

    The previous version rendered ``<a href="report.md">report.md</a>
    (<code>report.md</code>)`` — the trailing path repeat added
    noise without adding information. Pin the polished form.
    """
    manifest = build_manifest(
        run_id="r",
        run_dir=tmp_path,
        scenario_name="r",
        overall_status="success",
        steps=[],
        report_path=str(tmp_path / "report.md"),
    )
    # Touch the report file so its relative path resolves.
    (tmp_path / "report.md").write_text("# r", encoding="utf-8")
    html = render_html(manifest)
    # Find the artifacts section and assert the row format.
    section_start = html.find("<h2>Artifacts</h2>")
    section_end = html.find("</section>", section_start)
    assert section_start > 0 and section_end > section_start
    section = html[section_start:section_end]
    # Polished form: <a href="report.md"><code>report.md</code></a>
    assert '<a href="report.md"><code>report.md</code></a>' in section
    # The redundant trailing form must NOT appear.
    assert '(<code>report.md</code>)' not in section


# ---------------------------------------------------------------------------
# 5. Empty / degraded states still render gracefully
# ---------------------------------------------------------------------------


def test_empty_manifest_still_renders_without_risk_section(tmp_path: Path) -> None:
    """A manifest with no risk payload omits the section silently."""
    manifest = build_manifest(run_id="empty", run_dir=tmp_path, steps=[])
    html = render_html(manifest)
    # No risk section since there is no risk payload.
    assert "<h2>Risk summary</h2>" not in html
    # But the page still renders.
    assert "<html" in html
    assert "</html>" in html


def test_blocked_step_warning_banner_still_appears_in_header(tmp_path: Path) -> None:
    """The PR #72 blocked-step banner survives the polish reorder."""
    html = render_html(
        _populated_manifest(tmp_path, include_blocked_step=True)
    )
    assert "blocked step" in html.lower()
    assert "step-blocked" in html
