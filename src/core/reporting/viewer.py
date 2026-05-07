"""Static HTML report viewer.

Generates a single ``index.html`` per run from the run's
``manifest.json`` (and the on-disk artifacts the manifest
points at). The output is fully self-contained — no external
JS, no external CSS, no network requests, no server needed.
Operators open the file with ``file://`` and get a readable
local dashboard.

Design rules
------------

- **Pure Python rendering.** No build step, no JS framework, no
  server. Plain HTML + inline CSS.
- **No external assets.** All CSS lives inline in a ``<style>``
  block. No ``<link>``, no ``<script src="...">``, no ``<img
  src="http...">``. The viewer must work fully offline (no network
  call ever).
- **Safe HTML escaping.** Every value rendered into the page is
  passed through ``html.escape`` so a maliciously-shaped scenario
  name or module message cannot inject markup.
- **Deterministic output.** Same manifest → same HTML, byte for
  byte. Tests assert on substring presence, not on document
  structure. Iteration order over dicts uses sorted keys where
  the order matters for diffing.
- **Local paths only.** Links to artifacts are relative
  ``href="report.md"`` etc. — the viewer assumes the operator
  opens ``index.html`` from inside the run directory. Absolute
  paths are not embedded.

The viewer reads the manifest (already a stable JSON shape from
PR #71) and renders ten sections in a deliberate order:

1. Header — scenario name, run id, status, mode/safety badges,
   provider/model attribution if AI artifacts exist.
2. KPI grid — top-line counts (steps / techniques / detection
   drafts / telemetry events / blocked steps).
3. **Risk summary** — surfaced early so operators triaging a run
   see severity totals + top-module table without scrolling
   past the timeline.
4. Scenario timeline — ordered steps with module name, status,
   ATT&CK techniques, message column for blocked / error steps.
5. Propagation graph (table) — source → target step, kind.
6. ATT&CK coverage — technique → emitting steps.
7. Telemetry summary — counts by type and module.
8. Detection drafts — counts by engine + per-step paths.
9. Copilot — provider attribution, network/fallback flags, link
   to the artifact file (template/offline output is clearly
   labelled).
10. Artifact links — quick links to report.md / report.json /
    risk_summary.json / telemetry.jsonl / detections directory.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# Schema version of the viewer's input. Should track the manifest
# schema_version so an unexpected version surfaces as a visible
# warning in the rendered page rather than silently rendering a
# malformed dashboard.
VIEWER_INPUT_SCHEMA_VERSION = 1


# Inline CSS. Neutral palette, dark accents, readable body text.
# Kept compact so the rendered HTML stays diffable in tests.
_VIEWER_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f8f9fa;
  --bg-card: #ffffff;
  --bg-code: #f1f3f5;
  --fg: #212529;
  --muted: #6c757d;
  --accent: #0d6efd;
  --success: #198754;
  --warning: #fd7e14;
  --danger: #dc3545;
  --border: #dee2e6;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1e1e1e;
    --bg-card: #2a2a2a;
    --bg-code: #1a1a1a;
    --fg: #e0e0e0;
    --muted: #9aa0a6;
    --accent: #4ea3ff;
    --success: #4ade80;
    --warning: #fbbf24;
    --danger: #f87171;
    --border: #3a3a3a;
  }
}
body {
  margin: 0;
  padding: 24px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  background: var(--bg);
  color: var(--fg);
}
/* Cap content width on very wide monitors so the dashboard stays
   readable. Body itself fills the viewport for the dark/light
   background; the wrapper inside main centres the content. */
main { max-width: 1280px; margin: 0 auto; }
h1, h2, h3 { margin: 0 0 8px 0; }
h1 { font-size: 22px; }
h2 { font-size: 18px; margin-top: 24px; }
h3 { font-size: 15px; }
section { margin-top: 24px; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 16px;
}
/* Wrap tables in a horizontal-scroll region so a wide table on a
   narrow phone doesn't push the rest of the page sideways. The
   table itself still fills the wrapper's width on desktop. */
.card table { display: block; overflow-x: auto; max-width: 100%; }
table { border-collapse: collapse; width: 100%; }
th, td {
  text-align: left;
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  font-size: 13px;
}
th { font-weight: 600; color: var(--muted); }
code, .mono {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  background: var(--bg-code);
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 12px;
}
.muted { color: var(--muted); }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  margin-right: 4px;
  border: 1px solid var(--border);
}
.badge-success { color: var(--success); border-color: var(--success); }
.badge-blocked { color: var(--warning); border-color: var(--warning); }
.badge-error { color: var(--danger); border-color: var(--danger); }
.badge-skipped { color: var(--muted); border-color: var(--muted); }
.badge-mode { background: var(--bg-code); }
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-top: 12px;
}
.kpi { background: var(--bg-code); padding: 10px; border-radius: 4px; }
.kpi-label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
.kpi-value { font-size: 18px; font-weight: 600; margin-top: 4px; }
.warning-banner {
  background: var(--warning);
  color: #000;
  padding: 10px 16px;
  border-radius: 4px;
  margin-bottom: 16px;
}
.error-banner {
  background: var(--danger);
  color: #fff;
  padding: 10px 16px;
  border-radius: 4px;
  margin-bottom: 16px;
}
ul { padding-left: 20px; margin: 4px 0; }
/* Pure-CSS bar chart for telemetry / status counters. The
   coloured fill width is set inline via ``style="width: NN%"``;
   render-time renderer clamps the value to [1, 100] and casts
   through ``int`` so a maliciously-shaped manifest cannot inject
   arbitrary CSS. */
.bar-chart {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-top: 4px;
}
.bar-row {
  display: grid;
  grid-template-columns: minmax(80px, 180px) 1fr 32px;
  align-items: center;
  gap: 8px;
}
.bar-label {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 12px;
  overflow-wrap: break-word;
}
.bar-track {
  background: var(--bg-code);
  border-radius: 2px;
  height: 14px;
  overflow: hidden;
}
.bar-fill {
  display: block;
  height: 100%;
  background: var(--accent);
  border-radius: 2px;
  min-width: 2px;
}
.bar-fill-success { background: var(--success); }
.bar-fill-warning { background: var(--warning); }
.bar-fill-danger  { background: var(--danger); }
.bar-fill-muted   { background: var(--muted); }
.bar-value {
  color: var(--muted);
  font-size: 12px;
  text-align: right;
}
.bar-row-empty .bar-fill {
  background: transparent;
  border: 1px dashed var(--border);
}
.footnote {
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--muted);
}
@media (max-width: 600px) {
  body { padding: 12px; }
  h1 { font-size: 18px; }
  h2 { font-size: 16px; }
  .card { padding: 12px; }
  .kpi-grid { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
}
"""


def _esc(value: Any) -> str:
    """HTML-escape any value for safe inline rendering."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _status_badge(status: str) -> str:
    """Render a per-step / overall status as a coloured badge."""
    canonical = (status or "").lower()
    cls = "badge-skipped"
    if canonical == "success":
        cls = "badge-success"
    elif canonical == "blocked":
        cls = "badge-blocked"
    elif canonical in {"error", "failure"}:
        cls = "badge-error"
    return f'<span class="badge {cls}">{_esc(status or "unknown")}</span>'


def _render_header(manifest: Mapping[str, Any]) -> str:
    """Section 1 — header with scenario / run id / status badges."""
    run = manifest.get("run") or {}
    safety = manifest.get("safety") or {}
    copilot = manifest.get("copilot") or {}
    blocked = manifest.get("blocked_steps") or []
    errors = manifest.get("errors") or []

    badges: List[str] = [_status_badge(str(run.get("overall_status", "")))]
    if safety.get("dry_run"):
        badges.append('<span class="badge badge-mode">dry_run</span>')
    if copilot.get("present"):
        if copilot.get("network_disabled"):
            badges.append('<span class="badge badge-mode">ai: offline</span>')
        else:
            badges.append('<span class="badge badge-mode">ai: live</span>')
        if copilot.get("fallback_used"):
            badges.append('<span class="badge badge-blocked">fallback used</span>')

    parts: List[str] = []
    parts.append('<header class="card">')
    title = run.get("scenario_name") or run.get("run_id", "BlueFire run")
    parts.append(f"<h1>{_esc(title)}</h1>")
    parts.append('<div class="muted">')
    parts.append(f'run_id <code>{_esc(run.get("run_id", ""))}</code>')
    started = run.get("started_at")
    finished = run.get("finished_at")
    if started:
        parts.append(f' &middot; started {_esc(started)}')
    if finished:
        parts.append(f' &middot; finished {_esc(finished)}')
    parts.append("</div>")
    parts.append(f'<div style="margin-top: 8px;">{"".join(badges)}</div>')
    if blocked:
        parts.append(
            '<div class="warning-banner">'
            f"{len(blocked)} blocked step(s): "
            f"{_esc(', '.join(blocked))}"
            "</div>"
        )
    if errors:
        parts.append(
            '<div class="error-banner">'
            f"{len(errors)} error(s): {_esc('; '.join(errors))}"
            "</div>"
        )
    if copilot.get("present"):
        provider = copilot.get("provider") or "template"
        model = copilot.get("model") or ""
        parts.append('<div class="muted" style="margin-top: 8px;">')
        parts.append(
            f'AI provider: <code>{_esc(provider)}</code>'
            f' &middot; model <code>{_esc(model or "default")}</code>'
        )
        if copilot.get("fallback_used"):
            parts.append(
                f' &middot; fallback fired (primary: '
                f'<code>{_esc(copilot.get("provider"))}</code>)'
            )
        parts.append("</div>")
    parts.append("</header>")
    return "".join(parts)


def _render_kpi_grid(manifest: Mapping[str, Any]) -> str:
    """Top-line counters surface above the timeline so operators see at-a-glance state.

    The headline numbers live in the KPI grid; immediately below
    them sits a compact "module status" mini-chart that splits
    the step total into success / blocked / error / skipped bars
    so the operator can see the shape of the run without
    scrolling to the timeline.
    """
    run = manifest.get("run") or {}
    detections = manifest.get("detections") or {}
    telemetry = manifest.get("telemetry") or {}
    coverage = manifest.get("attack_coverage") or []
    blocked = manifest.get("blocked_steps") or []

    pairs: List[tuple[str, str]] = [
        ("steps", str(run.get("module_count", 0))),
        ("techniques", str(len(coverage))),
        ("detection drafts", str(detections.get("total", 0))),
        ("telemetry events", str(telemetry.get("event_count", 0))),
        ("blocked steps", str(len(blocked))),
    ]
    cells: List[str] = []
    for label, value in pairs:
        cells.append(
            f'<div class="kpi"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value">{_esc(value)}</div></div>'
        )
    grid = f'<div class="kpi-grid">{"".join(cells)}</div>'

    status_counts = _module_status_counts(manifest)
    if not any(status_counts.values()):
        return grid
    # Render each tier as its own bar-chart row with a tier-coloured
    # fill so success / blocked / error read immediately.
    max_count = max(status_counts.values()) or 0
    tier_fill = {
        "success": "bar-fill-success",
        "blocked": "bar-fill-warning",
        "error": "bar-fill-danger",
        "skipped": "bar-fill-muted",
    }
    rows: List[str] = []
    for tier in ("success", "blocked", "error", "skipped"):
        value = status_counts[tier]
        width = _bar_width_pct(value, max_count)
        empty_cls = " bar-row-empty" if value == 0 else ""
        rows.append(
            f'<div class="bar-row{empty_cls}">'
            f'<span class="bar-label"><code>{_esc(tier)}</code></span>'
            f'<span class="bar-track" role="img" '
            f'aria-label="{_esc(tier)}: {_esc(value)}">'
            f'<span class="bar-fill {tier_fill[tier]}" '
            f'style="width: {width}%;"></span></span>'
            f'<span class="bar-value">{_esc(value)}</span>'
            "</div>"
        )
    chart = (
        '<div class="card" style="margin-top: 12px;">'
        '<h3 style="margin-top: 0;">Module status</h3>'
        f'<div class="bar-chart">{"".join(rows)}</div>'
        "</div>"
    )
    return grid + chart


def _render_timeline(manifest: Mapping[str, Any]) -> str:
    """Section 4 — ordered scenario timeline.

    Columns: # / step_id / module / name / status / techniques /
    notes. The "notes" column carries the step's ``message`` when
    it is non-empty AND meaningful — i.e. failure / blocked /
    error states; success messages are usually boilerplate
    ("Simulated X technique on Y") and would clutter the table.
    Defenders triaging a problem run can see the explanation
    inline instead of cross-referencing report.json.
    """
    steps = manifest.get("steps") or []
    if not steps:
        return ""
    rows: List[str] = []
    rows.append(
        "<thead><tr>"
        "<th>#</th><th>step_id</th><th>module</th><th>name</th>"
        "<th>status</th><th>techniques</th><th>notes</th>"
        "</tr></thead>"
    )
    body: List[str] = []
    for index, step in enumerate(steps, start=1):
        techniques = step.get("techniques") or []
        techniques_html = ", ".join(f"<code>{_esc(t)}</code>" for t in techniques) or "&mdash;"
        # Surface message text only on non-success rows so success
        # boilerplate doesn't dominate the column. Truncated to one
        # line + 200 chars to keep the table compact.
        message = ""
        status = str(step.get("status") or "").lower()
        raw_message = step.get("message") or ""
        if status in {"blocked", "error", "failure", "partial_success"} and raw_message:
            message = str(raw_message).splitlines()[0][:200]
        notes_html = _esc(message) if message else "&mdash;"
        body.append(
            "<tr>"
            f"<td>{index}</td>"
            f'<td><code>{_esc(step.get("step_id"))}</code></td>'
            f'<td><code>{_esc(step.get("module"))}</code></td>'
            f'<td>{_esc(step.get("name"))}</td>'
            f'<td>{_status_badge(str(step.get("status", "")))}</td>'
            f"<td>{techniques_html}</td>"
            f"<td>{notes_html}</td>"
            "</tr>"
        )
    rows.append(f'<tbody>{"".join(body)}</tbody>')
    return (
        '<section class="card"><h2>Scenario timeline</h2>'
        f'<table>{"".join(rows)}</table></section>'
    )


def _render_propagation(manifest: Mapping[str, Any]) -> str:
    """Section 3 — propagation graph (table)."""
    edges = manifest.get("propagation_edges") or []
    if not edges:
        return (
            '<section class="card"><h2>Propagation</h2>'
            '<div class="muted">No step-to-step propagation in this run.</div>'
            "</section>"
        )
    rows: List[str] = [
        "<thead><tr><th>from step</th><th>to step</th><th>module</th><th>kind</th></tr></thead>"
    ]
    body: List[str] = []
    for edge in edges:
        body.append(
            "<tr>"
            f'<td><code>{_esc(edge.get("from_step"))}</code></td>'
            f'<td><code>{_esc(edge.get("to_step"))}</code></td>'
            f'<td><code>{_esc(edge.get("to_module"))}</code></td>'
            f'<td><code>{_esc(edge.get("kind"))}</code></td>'
            "</tr>"
        )
    rows.append(f'<tbody>{"".join(body)}</tbody>')
    return (
        '<section class="card"><h2>Propagation</h2>'
        f'<table>{"".join(rows)}</table></section>'
    )


def _render_attack_coverage(manifest: Mapping[str, Any]) -> str:
    """Section 4 — ATT&CK technique coverage."""
    coverage = manifest.get("attack_coverage") or []
    if not coverage:
        return (
            '<section class="card"><h2>ATT&amp;CK coverage</h2>'
            '<div class="muted">No techniques emitted.</div></section>'
        )
    rows: List[str] = [
        "<thead><tr><th>technique</th><th>emitting steps</th></tr></thead>"
    ]
    body: List[str] = []
    for entry in coverage:
        steps = entry.get("steps") or []
        steps_html = ", ".join(f"<code>{_esc(s)}</code>" for s in steps)
        body.append(
            f'<tr><td><code>{_esc(entry.get("technique"))}</code></td>'
            f"<td>{steps_html}</td></tr>"
        )
    rows.append(f'<tbody>{"".join(body)}</tbody>')
    return (
        '<section class="card"><h2>ATT&amp;CK coverage</h2>'
        f'<table>{"".join(rows)}</table></section>'
    )


def _bar_width_pct(count: int, max_count: int) -> int:
    """Return the bar fill width as an integer percentage in ``[1, 100]``.

    The renderer drops the fill into ``style="width: NN%"`` and we
    clamp to ``int`` to guarantee no exotic value can leak into the
    style attribute. Zero counts still surface a 1% sliver so the
    row's track is visually distinguishable from a missing row.
    """
    try:
        max_val = int(max_count or 0)
        value = int(count or 0)
    except (TypeError, ValueError):
        return 1
    if max_val <= 0 or value <= 0:
        return 1
    pct = round(value / max_val * 100)
    return max(1, min(int(pct), 100))


def _render_bar_chart(
    counts: Mapping[str, Any],
    *,
    fill_class: str = "",
) -> str:
    """Render a deterministic horizontal bar chart from a mapping.

    Sorts keys alphabetically (matches the previous ``<ul>``
    rendering so reviewers diffing the page see the same row
    order). Skips entries whose count cannot be coerced to a
    non-negative int. Empty mapping returns an empty string so
    the caller can branch on truthiness.
    """
    if not counts:
        return ""
    pairs: List[tuple[str, int]] = []
    for key in sorted(str(k) for k in counts.keys()):
        raw = counts.get(key)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value < 0:
            continue
        pairs.append((key, value))
    if not pairs:
        return ""
    max_count = max((value for _, value in pairs), default=0)
    fill_cls = f" {fill_class}" if fill_class else ""
    rows: List[str] = []
    for key, value in pairs:
        width = _bar_width_pct(value, max_count)
        empty_cls = " bar-row-empty" if value == 0 else ""
        rows.append(
            f'<div class="bar-row{empty_cls}">'
            f'<span class="bar-label" title="{_esc(key)}"><code>{_esc(key)}</code></span>'
            f'<span class="bar-track" role="img" '
            f'aria-label="{_esc(key)}: {_esc(value)}">'
            f'<span class="bar-fill{fill_cls}" style="width: {width}%;"></span></span>'
            f'<span class="bar-value">{_esc(value)}</span>'
            "</div>"
        )
    return f'<div class="bar-chart">{"".join(rows)}</div>'


def _module_status_counts(manifest: Mapping[str, Any]) -> Dict[str, int]:
    """Tally per-step status counts from a manifest."""
    counts: Dict[str, int] = {"success": 0, "blocked": 0, "error": 0, "skipped": 0}
    steps = manifest.get("steps")
    if not isinstance(steps, list):
        return counts
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        status = str(step.get("status") or "").lower()
        if status == "success":
            counts["success"] += 1
        elif status == "blocked":
            counts["blocked"] += 1
        elif status in {"error", "failure"}:
            counts["error"] += 1
        else:
            counts["skipped"] += 1
    return counts


def _render_telemetry(manifest: Mapping[str, Any]) -> str:
    """Section 5 — telemetry summary."""
    telemetry = manifest.get("telemetry") or {}
    if telemetry.get("event_count", 0) == 0 and not telemetry.get("path"):
        return (
            '<section class="card"><h2>Telemetry</h2>'
            '<div class="muted">No telemetry events recorded.</div></section>'
        )
    by_type = telemetry.get("events_by_type") or {}
    by_module = telemetry.get("events_by_module") or {}
    parts: List[str] = ['<section class="card"><h2>Telemetry</h2>']
    parts.append(
        f'<p class="muted">{_esc(telemetry.get("event_count", 0))} events &middot; '
        f'<a href="{_esc(telemetry.get("path") or "telemetry.jsonl")}">'
        f'{_esc(telemetry.get("path") or "telemetry.jsonl")}</a></p>'
    )
    if telemetry.get("error"):
        parts.append(
            '<div class="warning-banner">'
            f'{_esc(telemetry["error"])}</div>'
        )
    by_type_chart = _render_bar_chart(by_type)
    by_module_chart = _render_bar_chart(by_module)
    if by_type_chart or by_module_chart:
        parts.append('<div style="display: flex; gap: 32px; flex-wrap: wrap;">')
        if by_type_chart:
            parts.append(
                '<div style="flex: 1 1 320px; min-width: 280px;">'
                "<h3>By type</h3>"
                f"{by_type_chart}"
                "</div>"
            )
        if by_module_chart:
            parts.append(
                '<div style="flex: 1 1 320px; min-width: 280px;">'
                "<h3>By module</h3>"
                f"{by_module_chart}"
                "</div>"
            )
        parts.append("</div>")
    parts.append("</section>")
    return "".join(parts)


def _render_detections(manifest: Mapping[str, Any]) -> str:
    """Section 6 — detection drafts."""
    detections = manifest.get("detections") or {}
    total = detections.get("total", 0)
    counts = detections.get("engine_counts") or {}
    per_step = detections.get("per_step") or []
    if total == 0:
        return (
            '<section class="card"><h2>Detection drafts</h2>'
            '<div class="muted">No detection drafts generated.</div></section>'
        )
    parts: List[str] = ['<section class="card"><h2>Detection drafts</h2>']
    summary = " &middot; ".join(
        f"{_esc(engine)}={_esc(counts[engine])}" for engine in sorted(counts)
    )
    parts.append(
        f'<p class="muted">{_esc(total)} total &middot; {summary}</p>'
    )
    if per_step:
        parts.append("<table><thead><tr><th>step</th><th>engine</th><th>paths</th></tr></thead><tbody>")
        for entry in per_step:
            engines = entry.get("engines") or {}
            for engine in sorted(engines):
                paths = engines[engine] or []
                paths_html = "<br>".join(
                    f'<a href="{_esc(p)}">{_esc(p)}</a>' for p in paths
                )
                parts.append(
                    "<tr>"
                    f'<td><code>{_esc(entry.get("step_id"))}</code></td>'
                    f'<td><code>{_esc(engine)}</code></td>'
                    f"<td>{paths_html}</td>"
                    "</tr>"
                )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _severity_badge(severity: str) -> str:
    """Render a per-module severity as a coloured badge.

    Mirrors the status-badge palette so an operator can scan the
    risk-summary table and the timeline together with consistent
    cues. Unknown severities fall back to the muted skipped
    style.
    """
    canonical = (severity or "").lower()
    cls = "badge-skipped"
    if canonical == "critical":
        cls = "badge-error"
    elif canonical == "high":
        cls = "badge-error"
    elif canonical == "medium":
        cls = "badge-blocked"
    elif canonical == "low":
        cls = "badge-success"
    return f'<span class="badge {cls}">{_esc(severity or "unknown")}</span>'


def _render_risk(manifest: Mapping[str, Any]) -> str:
    """Section 3 — risk summary (rendered before the timeline).

    Operators triaging a problem run want severity totals + the
    top-module table without scrolling past the timeline. The
    severity column uses the coloured badge palette so the
    visual hierarchy of failures is immediate.
    """
    risk = manifest.get("risk")
    if not isinstance(risk, Mapping):
        return ""
    summary = risk.get("risk_summary") or {}
    modules = risk.get("modules") or []
    parts: List[str] = ['<section class="card"><h2>Risk summary</h2>']
    parts.append(
        '<div class="muted">'
        f'critical={_esc(summary.get("critical", 0))} '
        f'high={_esc(summary.get("high", 0))} '
        f'medium={_esc(summary.get("medium", 0))} '
        f'low={_esc(summary.get("low", 0))} &middot; '
        f'avg score {_esc(risk.get("average_score", 0))}'
        "</div>"
    )
    if modules:
        parts.append("<table><thead><tr>"
                     "<th>module</th><th>severity</th><th>score</th><th>mode</th>"
                     "</tr></thead><tbody>")
        for entry in modules:
            parts.append(
                "<tr>"
                f'<td><code>{_esc(entry.get("module"))}</code></td>'
                f'<td>{_severity_badge(str(entry.get("severity") or ""))}</td>'
                f'<td>{_esc(entry.get("score"))}</td>'
                f'<td>{_esc(entry.get("mode"))}</td>'
                "</tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _render_copilot(manifest: Mapping[str, Any]) -> str:
    """Section 8 — copilot artifact summary."""
    copilot = manifest.get("copilot") or {}
    if not copilot.get("present"):
        return (
            '<section class="card"><h2>AI copilot</h2>'
            '<div class="muted">No copilot artifacts in this run.</div></section>'
        )
    parts: List[str] = ['<section class="card"><h2>AI copilot</h2>']
    provider = copilot.get("provider") or "template"
    model = copilot.get("model") or ""
    network_disabled = copilot.get("network_disabled")
    fallback_used = copilot.get("fallback_used")
    network_label = "offline (template / no network)" if network_disabled else "live (network)"
    parts.append(
        '<ul>'
        f'<li>provider: <code>{_esc(provider)}</code></li>'
        f'<li>model: <code>{_esc(model or "default")}</code></li>'
        f'<li>generated_at: <code>{_esc(copilot.get("generated_at") or "")}</code></li>'
        f'<li>network state: {_esc(network_label)}</li>'
        f'<li>fallback used: <code>{_esc(bool(fallback_used)).lower()}</code></li>'
        "</ul>"
    )
    if copilot.get("path"):
        parts.append(
            f'<p>Artifact: <a href="{_esc(copilot["path"])}">{_esc(copilot["path"])}</a></p>'
        )
    if copilot.get("error"):
        parts.append(
            f'<div class="warning-banner">copilot error: {_esc(copilot["error"])}</div>'
        )
    if network_disabled:
        parts.append(
            '<div class="muted">Output is template/offline — no live model call was made.</div>'
        )
    parts.append("</section>")
    return "".join(parts)


def _render_artifact_links(manifest: Mapping[str, Any]) -> str:
    """Section 9 — quick links to the canonical artifacts.

    Each canonical artifact is rendered as either an active link
    (when actually present in the run) or an inert "not present"
    line. Closes Codex P2 from PR #72 sweep: ``detections/`` and
    ``manifest.json`` were previously hardcoded as present, so
    runs without detection drafts (non-success
    ``execute_operation`` calls) rendered a clickable link to a
    missing directory.
    """
    reports = manifest.get("reports") or {}
    telemetry = manifest.get("telemetry") or {}
    detections = manifest.get("detections") or {}
    detections_total = int(detections.get("total") or 0)
    # The viewer's own artifact (``index.html``) is always present
    # by definition — if this code is rendering, the file is being
    # written — so the manifest link is only present when the
    # manifest file itself exists. We can check that via the
    # schema_version field's presence as a proxy: the manifest
    # MUST always carry it.
    manifest_present = bool(manifest.get("schema_version"))
    items: List[tuple[str, Optional[str]]] = [
        ("report.md", reports.get("report_md")),
        ("report.json", reports.get("report_json")),
        ("risk_summary.json", reports.get("risk_summary_json")),
        ("telemetry.jsonl", telemetry.get("path")),
        ("manifest.json", "manifest.json" if manifest_present else None),
        ("detections/", "detections" if detections_total > 0 else None),
    ]
    rendered: List[str] = []
    for label, path in items:
        if not path:
            rendered.append(
                f'<li class="muted">{_esc(label)} &mdash; not present</li>'
            )
            continue
        # Drop the trailing redundant ``(<code>path</code>)`` —
        # when the link text and the path are the same, repeating
        # the path adds noise without adding information. Show
        # the path as a code-styled link directly.
        rendered.append(
            f'<li><a href="{_esc(path)}"><code>{_esc(label)}</code></a></li>'
        )
    return (
        '<section class="card"><h2>Artifacts</h2>'
        f'<ul>{"".join(rendered)}</ul></section>'
    )


def render_html(manifest: Mapping[str, Any]) -> str:
    """Render the full HTML document for a single run.

    Pure function: takes a manifest dict, returns the HTML string.
    Tests can call this without disk I/O. The :func:`write_viewer`
    helper persists the result and keeps the manifest <-> HTML
    contract in one place.
    """
    if not isinstance(manifest, Mapping):
        manifest = {}

    schema_version = manifest.get("schema_version")
    schema_warning = ""
    if schema_version and schema_version != VIEWER_INPUT_SCHEMA_VERSION:
        schema_warning = (
            '<div class="warning-banner">'
            f"manifest.schema_version is {_esc(schema_version)}, viewer expects "
            f"{VIEWER_INPUT_SCHEMA_VERSION}. Some sections may render incorrectly."
            "</div>"
        )

    # Section order is deliberate: risk summary surfaces above
    # the timeline so triage starts with severity, not with a
    # 12-row procedural table.
    body_parts: List[str] = []
    body_parts.append(_render_header(manifest))
    body_parts.append(_render_kpi_grid(manifest))
    body_parts.append(schema_warning)
    body_parts.append(_render_risk(manifest))
    body_parts.append(_render_timeline(manifest))
    body_parts.append(_render_propagation(manifest))
    body_parts.append(_render_attack_coverage(manifest))
    body_parts.append(_render_telemetry(manifest))
    body_parts.append(_render_detections(manifest))
    body_parts.append(_render_copilot(manifest))
    body_parts.append(_render_artifact_links(manifest))

    body = "".join(part for part in body_parts if part)

    title = manifest.get("run", {}).get("scenario_name") or manifest.get("run", {}).get(
        "run_id", "BlueFire run"
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    footnote = (
        '<div class="footnote">Generated locally by BlueFire Nexus. '
        f"No network calls. No external assets. {_esc(generated_at)}</div>"
    )
    # Wrap the whole body in <main> so the CSS max-width caps
    # readable column width on wide monitors without squeezing
    # the dashboard on phones (the @media rule narrows padding
    # at <= 600px). Footnote stays inside main for centring.
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>BlueFire run: {_esc(title)}</title>"
        f"<style>{_VIEWER_CSS}</style>"
        "</head>"
        f"<body><main>{body}{footnote}</main></body></html>\n"
    )


def write_viewer(
    run_dir: Path,
    manifest: Mapping[str, Any],
    *,
    filename: str = "index.html",
) -> Path:
    """Persist the rendered HTML alongside the manifest.

    Returns the path to the written file. Idempotent — the call
    overwrites any prior ``index.html`` in the run dir.
    """
    target = Path(run_dir) / filename
    target.write_text(render_html(manifest), encoding="utf-8")
    return target


def write_viewer_for_run(
    run_dir: Path,
    *,
    manifest_filename: str = "manifest.json",
    output_filename: str = "index.html",
) -> Path:
    """Read ``run_dir/manifest.json`` and write ``run_dir/index.html``.

    Convenience wrapper for the CLI / orchestrator: takes a path,
    loads the manifest, renders the HTML, and writes it back to
    the same directory. Raises ``FileNotFoundError`` when the
    manifest is missing — the operator gets a clean error rather
    than a silently-empty page.
    """
    manifest_path = Path(run_dir) / manifest_filename
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"manifest not found at {manifest_path}; run the scenario first or "
            "build a manifest before generating the viewer"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return write_viewer(run_dir, manifest, filename=output_filename)


__all__ = [
    "VIEWER_INPUT_SCHEMA_VERSION",
    "render_html",
    "write_viewer",
    "write_viewer_for_run",
]
