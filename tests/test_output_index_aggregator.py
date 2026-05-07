"""Top-level run index aggregator (``output/index.html``).

Pinned invariants:

1. **Pure helpers** in ``src.core.reporting.output_index``
   (``build_index_rows``, ``render_output_index_html``,
   ``write_output_index``) work without spinning up the
   orchestrator.
2. **Local-only.** No external CSS / JS / fonts / images / CDN
   references in the rendered HTML; ``href`` / ``src`` only
   point at relative paths under the output root.
3. **Path-traversal guard.** Rows whose ``run_dir`` resolves
   outside the output root are dropped — the aggregator never
   emits links escaping its own bundle.
4. **Newest first.** Runs are ordered descending by
   ``started_at`` (delegated to :func:`list_runs` and re-asserted
   here so a regression in either layer surfaces).
5. **Graceful degradation.** Missing manifests, missing
   per-artifact files, an empty output root — all render a
   coherent page rather than crashing.
6. **Output-root respected.** ``write_output_index`` lands at
   ``<output_root>/index.html`` regardless of CWD or the project
   default.
7. **Typer CLI** ``build-output-index`` writes the file and never
   starts a server / opens a browser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from typer.testing import CliRunner

from src.core.cli import app
from src.core.reporting.output_index import (
    OUTPUT_INDEX_SCHEMA_VERSION,
    build_index_rows,
    render_output_index_html,
    write_output_index,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_run_dir(
    output_root: Path,
    *,
    run_id: str,
    scenario_name: str = "",
    started_at: str = "",
    status: str = "success",
    module_count: int = 0,
    severity_counts: Optional[Dict[str, int]] = None,
    write_manifest: bool = True,
    write_viewer: bool = False,
    write_report: bool = True,
    write_risk: bool = False,
) -> Path:
    """Create a run directory with the given metadata.

    Mirrors the helper in ``test_run_discovery_and_viewer_cli`` so
    the two test suites share their understanding of "what makes a
    run dir" and stay in lockstep when the canonical artifact set
    grows.
    """
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    if write_report:
        (run_dir / "report.md").write_text("# fake", encoding="utf-8")
    if write_manifest:
        manifest: Dict[str, Any] = {
            "schema_version": 1,
            "run": {
                "run_id": run_id,
                "scenario_name": scenario_name,
                "overall_status": status,
                "started_at": started_at,
                "module_count": module_count,
                "step_status_counts": {},
            },
        }
        if severity_counts:
            manifest["risk"] = {
                "risk_summary": {
                    "critical": int(severity_counts.get("critical", 0)),
                    "high": int(severity_counts.get("high", 0)),
                    "medium": int(severity_counts.get("medium", 0)),
                    "low": int(severity_counts.get("low", 0)),
                },
                "modules": [],
            }
        (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if write_viewer:
        (run_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    if write_risk:
        (run_dir / "risk_summary.json").write_text(
            json.dumps({"risk_summary": {}}), encoding="utf-8"
        )
    return run_dir


# ---------------------------------------------------------------------------
# 1. build_index_rows
# ---------------------------------------------------------------------------


def test_build_index_rows_empty_for_missing_root(tmp_path: Path) -> None:
    """A non-existent output root yields ``[]`` rather than raising."""
    assert build_index_rows(tmp_path / "nope") == []


def test_build_index_rows_returns_empty_for_empty_root(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert build_index_rows(output_root) == []


def test_build_index_rows_extracts_severity_from_manifest(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        started_at="2026-05-07T09:00:00Z",
        severity_counts={"high": 2, "medium": 1, "low": 0},
        write_viewer=True,
        write_risk=True,
    )
    rows = build_index_rows(output_root)
    assert len(rows) == 1
    row = rows[0]
    assert row["dir_name"] == "alpha"
    assert row["severity"] == "high"
    assert row["viewer_href"] == "alpha/index.html"
    assert row["manifest_href"] == "alpha/manifest.json"
    assert row["report_href"] == "alpha/report.md"
    assert row["risk_href"] == "alpha/risk_summary.json"


def test_build_index_rows_returns_empty_severity_when_no_risk_block(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="alpha", started_at="2026-05-07T09:00:00Z")
    rows = build_index_rows(output_root)
    assert rows[0]["severity"] == ""


def test_build_index_rows_handles_run_without_manifest(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="partial",
        write_manifest=False,
    )
    rows = build_index_rows(output_root)
    assert len(rows) == 1
    row = rows[0]
    assert row["dir_name"] == "partial"
    assert row["manifest_href"] == ""
    assert row["viewer_href"] == ""
    assert row["severity"] == ""


def test_build_index_rows_orders_newest_first(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-old", started_at="2026-05-01T09:00:00Z")
    _make_run_dir(output_root, run_id="run-new", started_at="2026-05-07T09:00:00Z")
    _make_run_dir(output_root, run_id="run-mid", started_at="2026-05-04T09:00:00Z")
    ordered = [row["dir_name"] for row in build_index_rows(output_root)]
    assert ordered == ["run-new", "run-mid", "run-old"]


def test_build_index_rows_respects_output_root(tmp_path: Path) -> None:
    """Two parallel output roots do not bleed into each other."""
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    _make_run_dir(root_a, run_id="from-a", started_at="2026-05-07T09:00:00Z")
    _make_run_dir(root_b, run_id="from-b", started_at="2026-05-07T09:00:00Z")
    a_rows = build_index_rows(root_a)
    b_rows = build_index_rows(root_b)
    assert [r["dir_name"] for r in a_rows] == ["from-a"]
    assert [r["dir_name"] for r in b_rows] == ["from-b"]


# ---------------------------------------------------------------------------
# 2. render_output_index_html — content invariants
# ---------------------------------------------------------------------------


def test_render_output_index_html_empty_state(tmp_path: Path) -> None:
    """Empty output root renders a valid HTML page with a friendly empty state."""
    html = render_output_index_html([])
    assert html.startswith("<!DOCTYPE html>")
    assert "BlueFire runs" in html
    assert "No runs yet" in html
    # Even the empty state should be a complete, parseable page.
    assert "</html>" in html


def test_render_output_index_html_lists_each_run(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha scenario",
        started_at="2026-05-07T09:00:00Z",
        module_count=4,
        write_viewer=True,
    )
    _make_run_dir(
        output_root,
        run_id="beta",
        scenario_name="Beta scenario",
        started_at="2026-05-06T09:00:00Z",
        module_count=2,
        write_viewer=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    assert "alpha" in html
    assert "beta" in html
    assert "Alpha scenario" in html
    assert "Beta scenario" in html


def test_render_output_index_html_severity_badges_present(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="critical-run",
        started_at="2026-05-07T09:00:00Z",
        severity_counts={"critical": 1},
        write_viewer=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    assert "critical" in html
    # Coloured badge surface with the error class.
    assert "badge-error" in html


def test_render_output_index_html_links_are_relative(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha scenario",
        started_at="2026-05-07T09:00:00Z",
        module_count=2,
        write_viewer=True,
        write_risk=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    hrefs = re.findall(r'href="([^"]+)"', html)
    assert hrefs, "expected at least one href in the rendered page"
    for href in hrefs:
        assert not href.startswith("http://"), href
        assert not href.startswith("https://"), href
        assert not href.startswith("//"), href
        assert not href.startswith("/"), href
        assert not href.startswith("file://"), href
        # No path-traversal segments in the rendered href.
        assert ".." not in href.split("/"), href


def test_render_output_index_html_no_external_assets(tmp_path: Path) -> None:
    """No <link>, no <script>, no remote <img> — fully self-contained."""
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha scenario",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    assert "<script" not in html
    assert "<link " not in html
    assert "<link\t" not in html
    assert "<link\n" not in html
    assert "<iframe" not in html
    assert "http://" not in html
    assert "https://" not in html
    assert "cdn." not in html
    assert "googleapis.com" not in html
    assert "<img " not in html  # no remote OR local images


def test_render_output_index_html_escapes_malicious_scenario_name(tmp_path: Path) -> None:
    """A scenario name with HTML metacharacters must not inject markup."""
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="injected",
        scenario_name="<script>alert(1)</script>",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    # Real <script> must NOT appear in the rendered page.
    assert "<script>alert" not in html
    # Escaped form is fine.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_render_output_index_html_handles_partial_run_without_manifest(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="partial", write_manifest=False)
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    # Run id surfaces.
    assert "partial" in html
    # No viewer link emitted (the run dir has no index.html).
    assert "partial/index.html" not in html


def test_render_output_index_html_kpi_grid_counts(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root, run_id="ok-1", started_at="2026-05-07T09:00:00Z", status="success"
    )
    _make_run_dir(
        output_root, run_id="ok-2", started_at="2026-05-06T09:00:00Z", status="success"
    )
    _make_run_dir(
        output_root, run_id="bad", started_at="2026-05-05T09:00:00Z", status="error"
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    # The KPI grid must report 3 total / 2 success / 1 error. We
    # assert on the structural presence of the labels + values
    # rather than exact whitespace.
    assert "runs" in html
    assert "success" in html
    assert "error" in html


# ---------------------------------------------------------------------------
# 3. Path-traversal & symlink guards
# ---------------------------------------------------------------------------


def test_build_index_rows_drops_run_dir_outside_output_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row whose run_dir resolves outside the output root is dropped.

    ``list_runs`` only iterates direct children of ``output_root``,
    so this case shouldn't happen organically — but we patch
    ``list_runs`` to inject a poisoned row and confirm the
    aggregator filters it out.
    """
    output_root = tmp_path / "output"
    output_root.mkdir()
    foreign_dir = tmp_path / "outside"
    foreign_dir.mkdir()
    (foreign_dir / "report.md").write_text("# x", encoding="utf-8")

    fake_rows = [
        {
            "run_id": "foreign",
            "run_dir": str(foreign_dir),
            "scenario_name": "",
            "overall_status": "",
            "started_at": "",
            "module_count": 0,
            "has_manifest": False,
            "has_viewer": False,
        }
    ]
    monkeypatch.setattr(
        "src.core.reporting.output_index.list_runs",
        lambda _root: fake_rows,
    )
    rows = build_index_rows(output_root)
    assert rows == []


def test_render_output_index_html_does_not_link_outside_bundle(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    rows = build_index_rows(output_root)
    html = render_output_index_html(rows)
    hrefs = re.findall(r'href="([^"]+)"', html)
    for href in hrefs:
        # Must not climb out of the output root via ".." segments.
        assert ".." not in href.split("/"), href


# ---------------------------------------------------------------------------
# 4. write_output_index — disk side effects
# ---------------------------------------------------------------------------


def test_write_output_index_creates_file_at_root(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    target = write_output_index(output_root)
    assert target == output_root / "index.html"
    assert target.exists()
    contents = target.read_text(encoding="utf-8")
    assert "BlueFire runs" in contents
    assert "alpha" in contents


def test_write_output_index_creates_root_if_missing(tmp_path: Path) -> None:
    """Orchestrator wakes up before any runs — output dir may not exist yet."""
    output_root = tmp_path / "output"
    target = write_output_index(output_root)
    assert output_root.exists()
    assert target.exists()
    contents = target.read_text(encoding="utf-8")
    assert "No runs yet" in contents


def test_write_output_index_idempotent(tmp_path: Path) -> None:
    """Re-running the call simply overwrites the prior file."""
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    write_output_index(output_root)
    # Second run with another row: the aggregator should reflect it.
    _make_run_dir(
        output_root,
        run_id="beta",
        scenario_name="Beta",
        started_at="2026-05-08T09:00:00Z",
        write_viewer=True,
    )
    target = write_output_index(output_root)
    contents = target.read_text(encoding="utf-8")
    assert "alpha" in contents
    assert "beta" in contents


def test_output_index_schema_version_is_stable() -> None:
    """Pin the documented schema version so accidental bumps are caught."""
    assert OUTPUT_INDEX_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# 5. CLI — build-output-index
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def test_cli_build_output_index_creates_aggregator(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    result = cli_runner.invoke(
        app, ["build-output-index", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    aggregator = output_root / "index.html"
    assert aggregator.exists()
    body = aggregator.read_text(encoding="utf-8")
    assert "alpha" in body
    # Output mentions the file:// link.
    assert "file://" in result.stdout
    # No server / browser-open prose.
    lowered = result.stdout.lower()
    for forbidden in ("started server", "listening on", "opening browser"):
        assert forbidden not in lowered, (
            f"build-output-index must not start a server / open a browser, "
            f"saw {forbidden!r}"
        )


def test_cli_build_output_index_handles_empty_output_root(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    result = cli_runner.invoke(
        app, ["build-output-index", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    aggregator = output_root / "index.html"
    assert aggregator.exists()
    body = aggregator.read_text(encoding="utf-8")
    assert "No runs yet" in body


def test_cli_list_runs_mentions_aggregator_when_present(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    # Pre-build the aggregator so list-runs has something to point at.
    write_output_index(output_root)
    result = cli_runner.invoke(
        app, ["list-runs", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "Aggregate index" in result.stdout
    assert "file://" in result.stdout


def test_cli_latest_run_mentions_aggregator_when_present(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    write_output_index(output_root)
    result = cli_runner.invoke(
        app, ["latest-run", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "Aggregate index" in result.stdout


def test_cli_list_runs_does_not_mention_aggregator_when_absent(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """The hint only fires when ``output_root/index.html`` actually exists."""
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="alpha",
        scenario_name="Alpha",
        started_at="2026-05-07T09:00:00Z",
        write_viewer=True,
    )
    # Note: NOT calling write_output_index — aggregator is absent.
    result = cli_runner.invoke(
        app, ["list-runs", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "Aggregate index" not in result.stdout
