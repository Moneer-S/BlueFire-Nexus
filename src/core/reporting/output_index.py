"""Top-level static aggregator for the local output directory.

Per-run dashboards live at ``output/<run_id>/index.html`` (PR #72).
This module renders a sibling ``output/index.html`` that lists
*every* run an operator has on disk, newest first, with quick
links into each run's viewer / manifest / report. It is the
browser equivalent of the ``list-runs`` CLI command.

Design rules (mirror :mod:`src.core.reporting.viewer`)
------------------------------------------------------

- **Pure Python rendering.** No build step, no JS framework, no
  server. Plain HTML + inline CSS.
- **No external assets.** All CSS lives inline in a ``<style>``
  block. No ``<link>``, no ``<script src>``, no remote ``<img>``.
  The aggregator must render fully offline (no network call ever).
- **Safe HTML escaping.** Every value rendered into the page is
  passed through ``html.escape``. URL components are passed
  through ``urllib.parse.quote`` first so a maliciously-shaped
  directory name cannot inject markup or break out of the run
  bundle.
- **Path-traversal guard.** Each row's ``run_dir`` must resolve
  to a descendant of the output root before any ``href`` is
  emitted. Rows whose ``run_dir`` would escape (a symlink, a
  manually-edited manifest, etc.) are dropped entirely so the
  aggregator never points outside its own bundle.
- **Graceful degradation.** Runs without a manifest still render
  with sentinel placeholders. Missing per-artifact files (e.g.
  no ``risk_summary.json``) simply do not appear in the artifact
  links column for that row.
- **Local paths only.** ``href`` values are POSIX-style relative
  paths (``run-id/index.html``) so the file works after the
  ``output/`` directory is moved or zipped.
"""

from __future__ import annotations

import html
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from .run_discovery import list_runs


# Schema version of the aggregator's input. Independent of the
# per-run viewer's :data:`VIEWER_INPUT_SCHEMA_VERSION` since the
# aggregator only consumes ``manifest.json`` keys that have been
# stable since PR #71.
OUTPUT_INDEX_SCHEMA_VERSION = 1


_AGGREGATOR_CSS = """
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
main { max-width: 1280px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 8px 0; }
h2 { font-size: 18px; margin: 24px 0 8px 0; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 16px;
}
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
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
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
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-top: 12px;
}
.kpi { background: var(--bg-code); padding: 10px; border-radius: 4px; }
.kpi-label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
.kpi-value { font-size: 18px; font-weight: 600; margin-top: 4px; }
.empty {
  padding: 24px;
  text-align: center;
  color: var(--muted);
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


def _quote_path(value: str) -> str:
    """Return a URL-encoded relative path safe for ``href``.

    ``urllib.parse.quote`` keeps the forward slash so the run dir
    separator stays intact; the escaped result is then HTML-
    escaped at the call site for embedding in attributes.
    """
    return quote(value, safe="/")


def _status_badge(status: str) -> str:
    """Render a per-run status as a coloured badge."""
    canonical = (status or "").lower()
    cls = "badge-skipped"
    if canonical == "success":
        cls = "badge-success"
    elif canonical == "blocked":
        cls = "badge-blocked"
    elif canonical in {"error", "failure"}:
        cls = "badge-error"
    return f'<span class="badge {cls}">{_esc(status or "unknown")}</span>'


def _severity_badge(severity: str) -> str:
    """Render a per-run highest-severity tier as a coloured badge."""
    canonical = (severity or "").lower()
    cls = "badge-skipped"
    if canonical in {"critical", "high"}:
        cls = "badge-error"
    elif canonical == "medium":
        cls = "badge-blocked"
    elif canonical == "low":
        cls = "badge-success"
    return f'<span class="badge {cls}">{_esc(severity or "unknown")}</span>'


def _read_manifest(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Best-effort load of ``run_dir/manifest.json``.

    Mirrors :func:`run_discovery._read_manifest` but is duplicated
    locally so the aggregator does not reach into a private
    helper and can read keys ``list_runs`` does not surface
    (notably ``risk`` / ``detections``).
    """
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _highest_severity(manifest: Optional[Mapping[str, Any]]) -> str:
    """Return the highest non-zero severity tier from a manifest's risk block.

    Returns one of ``critical`` / ``high`` / ``medium`` / ``low``,
    or an empty string when no risk block is present or all
    counters are zero.
    """
    if not isinstance(manifest, Mapping):
        return ""
    risk = manifest.get("risk")
    if not isinstance(risk, Mapping):
        return ""
    summary = risk.get("risk_summary")
    if not isinstance(summary, Mapping):
        return ""
    for tier in ("critical", "high", "medium", "low"):
        try:
            count = int(summary.get(tier, 0) or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            return tier
    return ""


def _is_within(parent: Path, child: Path) -> bool:
    """Return True iff ``child`` resolves to a descendant of ``parent``.

    Mirrors :func:`run_discovery._is_within` so the aggregator
    shares the same path-containment guard as ``find_run_dir``.
    """
    try:
        parent_resolved = parent.resolve()
        child_resolved = child.resolve()
    except OSError:
        return False
    try:
        child_resolved.relative_to(parent_resolved)
    except ValueError:
        return False
    return True


def build_index_rows(output_root: Path) -> List[Dict[str, Any]]:
    """Enrich :func:`list_runs` rows with aggregator-specific fields.

    Adds ``href`` (POSIX-relative, run-dir-name based),
    ``severity`` (highest non-zero risk tier or ``""``),
    ``has_report_md`` / ``has_risk_summary`` / ``has_manifest_json``
    flags so the renderer can build a stable artifact-link list
    without re-statting on the hot path.

    Rows whose ``run_dir`` resolves outside ``output_root`` are
    dropped entirely as a path-traversal guard. ``list_runs``
    only enumerates direct children of the output root, so this
    filter is defensive against symlinked / hand-edited setups.
    """
    output_root = Path(output_root)
    rows: List[Dict[str, Any]] = []
    for raw in list_runs(output_root):
        run_dir = Path(raw.get("run_dir") or "")
        if not run_dir.exists() or not _is_within(output_root, run_dir):
            continue
        # ``run_dir.name`` is the on-disk directory name. We use
        # that as the base for relative links because the manifest
        # ``run_id`` field can diverge (sanitisation, manual edits).
        dir_name = run_dir.name
        manifest = _read_manifest(run_dir)
        severity = _highest_severity(manifest)
        rows.append(
            {
                **raw,
                "dir_name": dir_name,
                "href": f"{_quote_path(dir_name)}/",
                "viewer_href": (
                    f"{_quote_path(dir_name)}/index.html"
                    if raw.get("has_viewer")
                    else ""
                ),
                "manifest_href": (
                    f"{_quote_path(dir_name)}/manifest.json"
                    if (run_dir / "manifest.json").exists()
                    else ""
                ),
                "report_href": (
                    f"{_quote_path(dir_name)}/report.md"
                    if (run_dir / "report.md").exists()
                    else ""
                ),
                "risk_href": (
                    f"{_quote_path(dir_name)}/risk_summary.json"
                    if (run_dir / "risk_summary.json").exists()
                    else ""
                ),
                "severity": severity,
            }
        )
    return rows


def _render_kpi_grid(rows: List[Dict[str, Any]]) -> str:
    """Top-level summary counters across all listed runs."""
    total = len(rows)
    successes = sum(1 for row in rows if str(row.get("overall_status")).lower() == "success")
    blocked = sum(1 for row in rows if str(row.get("overall_status")).lower() == "blocked")
    errored = sum(
        1 for row in rows if str(row.get("overall_status")).lower() in {"error", "failure"}
    )
    with_viewer = sum(1 for row in rows if row.get("has_viewer"))
    pairs: List[tuple[str, str]] = [
        ("runs", str(total)),
        ("success", str(successes)),
        ("blocked", str(blocked)),
        ("error", str(errored)),
        ("with viewer", str(with_viewer)),
    ]
    cells: List[str] = []
    for label, value in pairs:
        cells.append(
            f'<div class="kpi"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value">{_esc(value)}</div></div>'
        )
    return f'<div class="kpi-grid">{"".join(cells)}</div>'


def _render_artifact_links(row: Mapping[str, Any]) -> str:
    """Compact "viewer / manifest / report / risk" link list per row."""
    parts: List[str] = []
    if row.get("viewer_href"):
        parts.append(
            f'<a href="{_esc(row["viewer_href"])}">viewer</a>'
        )
    if row.get("manifest_href"):
        parts.append(
            f'<a href="{_esc(row["manifest_href"])}">manifest</a>'
        )
    if row.get("report_href"):
        parts.append(
            f'<a href="{_esc(row["report_href"])}">report</a>'
        )
    if row.get("risk_href"):
        parts.append(
            f'<a href="{_esc(row["risk_href"])}">risk</a>'
        )
    return " &middot; ".join(parts) if parts else '<span class="muted">&mdash;</span>'


def _render_runs_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return (
            '<section class="card"><div class="empty">'
            "No runs yet. Run a scenario, e.g. "
            "<code>python -m src.run_scenario --profile apt29_credential_access</code>, "
            "then refresh this page."
            "</div></section>"
        )
    head = (
        "<thead><tr>"
        "<th>run</th><th>scenario</th><th>status</th>"
        "<th>severity</th><th>started</th>"
        "<th>steps</th><th>artifacts</th>"
        "</tr></thead>"
    )
    body_rows: List[str] = []
    for row in rows:
        # The "run" column is a link to the per-run viewer when
        # one is present, else a link to the run directory listing
        # (which the operator's browser renders via file://).
        if row.get("viewer_href"):
            run_cell = (
                f'<a href="{_esc(row["viewer_href"])}">'
                f'<code>{_esc(row.get("run_id", row.get("dir_name", "")))}</code></a>'
            )
        else:
            run_cell = f'<code>{_esc(row.get("run_id", row.get("dir_name", "")))}</code>'
        scenario = row.get("scenario_name") or ""
        scenario_cell = _esc(scenario) if scenario else '<span class="muted">&mdash;</span>'
        started = row.get("started_at") or ""
        started_cell = _esc(started) if started else '<span class="muted">&mdash;</span>'
        body_rows.append(
            "<tr>"
            f"<td>{run_cell}</td>"
            f"<td>{scenario_cell}</td>"
            f"<td>{_status_badge(str(row.get('overall_status') or ''))}</td>"
            f"<td>{_severity_badge(str(row.get('severity') or ''))}</td>"
            f"<td>{started_cell}</td>"
            f"<td>{_esc(row.get('module_count', 0))}</td>"
            f"<td>{_render_artifact_links(row)}</td>"
            "</tr>"
        )
    return (
        '<section class="card"><h2>Runs</h2>'
        f'<table>{head}<tbody>{"".join(body_rows)}</tbody></table></section>'
    )


def render_output_index_html(rows: List[Dict[str, Any]]) -> str:
    """Render the top-level aggregator HTML from a list of enriched rows.

    Pure function: takes a list (typically from
    :func:`build_index_rows`), returns the HTML string. Tests can
    call this without disk I/O.
    """
    rows = list(rows or [])
    body_parts: List[str] = []
    body_parts.append('<header class="card">')
    body_parts.append("<h1>BlueFire runs</h1>")
    body_parts.append(
        '<div class="muted">'
        "Local index of every run in this output directory. "
        "Open per-run dashboards via the link in the run column."
        "</div>"
    )
    body_parts.append(_render_kpi_grid(rows))
    # Same local-only contract reminder as the per-run viewer:
    # an operator opening this page from `file://` immediately
    # sees the no-server / no-JS / no-network promise.
    body_parts.append(
        '<div class="muted" style="margin-top: 8px; font-size: 12px;">'
        "Static page &middot; no server, no JavaScript, no external "
        "assets, no network calls. Move the entire <code>output/</code> "
        "directory and links keep resolving (links are relative)."
        "</div>"
    )
    body_parts.append("</header>")
    body_parts.append(_render_runs_table(rows))

    body = "".join(body_parts)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    footnote = (
        '<div class="footnote">Generated locally by BlueFire Nexus. '
        f"No network calls. No external assets. {_esc(generated_at)}</div>"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        "<title>BlueFire runs</title>"
        f"<style>{_AGGREGATOR_CSS}</style>"
        "</head>"
        f"<body><main>{body}{footnote}</main></body></html>\n"
    )


def write_output_index(
    output_root: Path,
    *,
    filename: str = "index.html",
) -> Path:
    """Persist the rendered aggregator HTML at ``output_root/index.html``.

    Convenience wrapper for the orchestrator / CLI: enumerates
    runs under the output root, renders the aggregator HTML, and
    writes it back to disk. The output root is created if it does
    not already exist (the orchestrator may call this on a fresh
    install before any runs have completed).

    Returns the path to the written file. Idempotent — the call
    overwrites any prior aggregator at the same location.
    """
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    rows = build_index_rows(output_root)
    target = output_root / filename
    target.write_text(render_output_index_html(rows), encoding="utf-8")
    return target


__all__ = [
    "OUTPUT_INDEX_SCHEMA_VERSION",
    "build_index_rows",
    "render_output_index_html",
    "write_output_index",
]
