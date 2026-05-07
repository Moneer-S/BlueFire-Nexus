"""Run-discovery helpers + viewer CLI commands.

P3 of the local report viewer phase: the CLI needs to enumerate
runs under the output root and feed them to the viewer (P2). This
file pins both halves:

- Pure helpers in ``src/core/reporting/run_discovery.py``
  (``list_runs``, ``latest_run``, ``find_run_dir``).
- Typer commands in ``src/core/cli.py``: ``list-runs``,
  ``latest-run``, ``show-run``, ``build-report-view``.

Pinned invariants:

1. **Local-only.** No commands open a network socket, start a
   server, or auto-open a browser.
2. **Output-root resolution.** Helpers honour
   ``general.output_root`` / ``BLUEFIRE_OUTPUT_ROOT`` via the
   shared resolver, and the CLI flag ``--output-root`` overrides
   for ad-hoc discovery.
3. **Manifest-first metadata.** When a run has a ``manifest.json``,
   helpers read scenario name / status / start time from it.
   Runs without a manifest still surface (filesystem ctime
   fallback) so partial / errored runs are visible.
4. **Newest first.** ``list_runs`` orders results descending by
   ``started_at``.
5. **find_run_dir resolves by directory name OR manifest run_id.**
6. **CLI no-runs path** prints a clean message rather than crashing.
7. **CLI build-report-view** writes ``index.html`` next to the
   existing manifest and never starts a server.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from src.core.cli import app
from src.core.reporting.run_discovery import (
    find_run_dir,
    latest_run,
    list_runs,
)


# ---------------------------------------------------------------------------
# Helpers — build a fake run directory with a manifest.json
# ---------------------------------------------------------------------------


def _make_run_dir(
    output_root: Path,
    *,
    run_id: str,
    scenario_name: str = "",
    started_at: str = "",
    status: str = "success",
    module_count: int = 0,
    write_manifest: bool = True,
    write_viewer: bool = False,
) -> Path:
    """Create a run directory with the given metadata.

    Useful for table-driven tests that exercise list_runs ordering
    / metadata extraction without spinning up the orchestrator.
    """
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    # Always create at least one canonical artifact so _is_run_dir
    # returns True even when no manifest is present.
    (run_dir / "report.md").write_text("# fake", encoding="utf-8")
    if write_manifest:
        manifest = {
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
        (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if write_viewer:
        (run_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    return run_dir


# ---------------------------------------------------------------------------
# 1. list_runs — ordering, metadata, filesystem fallback
# ---------------------------------------------------------------------------


def test_list_runs_returns_empty_for_missing_output_root(tmp_path: Path) -> None:
    """A non-existent output root yields ``[]`` rather than raising."""
    assert list_runs(tmp_path / "does-not-exist") == []


def test_list_runs_returns_empty_for_empty_output_root(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert list_runs(output_root) == []


def test_list_runs_extracts_metadata_from_manifest(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="run-alpha",
        scenario_name="Alpha scenario",
        started_at="2026-05-07T10:00:00Z",
        status="success",
        module_count=12,
        write_viewer=True,
    )
    runs = list_runs(output_root)
    assert len(runs) == 1
    row = runs[0]
    assert row["run_id"] == "run-alpha"
    assert row["scenario_name"] == "Alpha scenario"
    assert row["overall_status"] == "success"
    assert row["started_at"] == "2026-05-07T10:00:00Z"
    assert row["module_count"] == 12
    assert row["has_manifest"] is True
    assert row["has_viewer"] is True


def test_list_runs_orders_newest_first_by_started_at(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-old", started_at="2026-05-01T09:00:00Z")
    _make_run_dir(output_root, run_id="run-new", started_at="2026-05-07T09:00:00Z")
    _make_run_dir(output_root, run_id="run-mid", started_at="2026-05-04T09:00:00Z")
    ordered = [row["run_id"] for row in list_runs(output_root)]
    assert ordered == ["run-new", "run-mid", "run-old"]


def test_list_runs_includes_runs_without_manifest(tmp_path: Path) -> None:
    """Partial runs (no manifest yet) still surface so operators can debug them."""
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-good", started_at="2026-05-07T09:00:00Z")
    # A "partial" run has no manifest but has a report.md.
    _make_run_dir(
        output_root,
        run_id="run-partial",
        write_manifest=False,
        started_at="",
    )
    runs = list_runs(output_root)
    ids = {row["run_id"] for row in runs}
    assert "run-good" in ids
    assert "run-partial" in ids
    partial = next(row for row in runs if row["run_id"] == "run-partial")
    assert partial["has_manifest"] is False
    # started_at fell back to filesystem ctime — non-empty string.
    assert partial["started_at"]


def test_list_runs_skips_non_run_directories(tmp_path: Path) -> None:
    """A random subdirectory without canonical artifacts is ignored.

    Defends against accidental discovery of operator-side stuff
    (notes, scratch dirs) under the output root.
    """
    output_root = tmp_path / "output"
    output_root.mkdir()
    (output_root / "notes").mkdir()
    (output_root / "notes" / "scratch.txt").write_text("not a run", encoding="utf-8")
    _make_run_dir(output_root, run_id="real-run", started_at="2026-05-07T09:00:00Z")
    runs = list_runs(output_root)
    assert [row["run_id"] for row in runs] == ["real-run"]


def test_list_runs_handles_unreadable_manifest_gracefully(tmp_path: Path) -> None:
    """An invalid manifest.json falls back to filesystem-only metadata."""
    output_root = tmp_path / "output"
    run_dir = _make_run_dir(output_root, run_id="bad", started_at="should-be-ignored")
    (run_dir / "manifest.json").write_text("not valid json", encoding="utf-8")
    runs = list_runs(output_root)
    assert len(runs) == 1
    row = runs[0]
    assert row["run_id"] == "bad"
    assert row["has_manifest"] is False
    assert row["scenario_name"] == ""


# ---------------------------------------------------------------------------
# 2. latest_run / find_run_dir
# ---------------------------------------------------------------------------


def test_latest_run_returns_none_for_empty_root(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert latest_run(output_root) is None


def test_latest_run_returns_newest_entry(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="old", started_at="2026-05-01T09:00:00Z")
    _make_run_dir(output_root, run_id="new", started_at="2026-05-07T09:00:00Z")
    latest = latest_run(output_root)
    assert latest is not None
    assert latest["run_id"] == "new"


def test_find_run_dir_resolves_by_directory_name(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="alpha")
    found = find_run_dir(output_root, "alpha")
    assert found is not None
    assert found.name == "alpha"


def test_find_run_dir_resolves_by_manifest_run_id(tmp_path: Path) -> None:
    """The directory name and the manifest's run_id can diverge.

    When they do, find_run_dir falls back to the manifest's
    canonical run_id field.
    """
    output_root = tmp_path / "output"
    run_dir = output_root / "sanitised-name"
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("# x", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "run": {
            "run_id": "original-run-id",
            "scenario_name": "x",
            "started_at": "2026-05-07T09:00:00Z",
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    found = find_run_dir(output_root, "original-run-id")
    assert found is not None
    assert found.name == "sanitised-name"


def test_find_run_dir_returns_none_for_missing_run(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    assert find_run_dir(output_root, "nope") is None


# ---------------------------------------------------------------------------
# 3. Typer CLI: list-runs / latest-run / show-run / build-report-view
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner() -> CliRunner:
    """Plain Typer test runner.

    Recent Click versions removed ``mix_stderr``; the runner's
    default already exposes ``result.stdout`` (and ``result.stderr``
    when present) so assertions read either / both streams.
    """
    return CliRunner()


def test_cli_list_runs_with_no_runs_prints_friendly_message(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(app, ["list-runs", "--output-root", str(output_root)])
    assert result.exit_code == 0
    assert "No runs found" in result.stdout


def test_cli_list_runs_renders_table_for_existing_runs(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="run-cli",
        scenario_name="CLI test",
        started_at="2026-05-07T09:00:00Z",
        module_count=5,
        write_viewer=True,
    )
    result = cli_runner.invoke(app, ["list-runs", "--output-root", str(output_root)])
    assert result.exit_code == 0
    assert "run-cli" in result.stdout
    assert "CLI test" in result.stdout
    # The "viewer" column reads "yes" when index.html exists.
    assert "yes" in result.stdout


def test_cli_latest_run_prints_detail_table(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="latest",
        scenario_name="Latest scenario",
        started_at="2026-05-07T09:00:00Z",
    )
    result = cli_runner.invoke(app, ["latest-run", "--output-root", str(output_root)])
    assert result.exit_code == 0
    assert "latest" in result.stdout
    assert "Latest scenario" in result.stdout


def test_cli_latest_run_with_no_runs_prints_friendly_message(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(app, ["latest-run", "--output-root", str(output_root)])
    assert result.exit_code == 0
    assert "No runs found" in result.stdout


def test_cli_show_run_for_existing_run(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="show",
        scenario_name="Show scenario",
        started_at="2026-05-07T09:00:00Z",
    )
    result = cli_runner.invoke(
        app, ["show-run", "show", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "Show scenario" in result.stdout


def test_cli_show_run_unknown_run_id_returns_error(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app, ["show-run", "nonexistent", "--output-root", str(output_root)]
    )
    assert result.exit_code != 0
    # The error message goes to stderr by default with Typer's BadParameter.
    combined = (result.stdout or "") + (result.stderr or "")
    assert "Run not found" in combined or "nonexistent" in combined


def test_cli_build_report_view_writes_index_html(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    run_dir = _make_run_dir(
        output_root,
        run_id="build",
        scenario_name="Build viewer",
        started_at="2026-05-07T09:00:00Z",
    )
    # Sanity: no viewer yet.
    assert not (run_dir / "index.html").exists()
    result = cli_runner.invoke(
        app, ["build-report-view", "build", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout
    # Viewer was written.
    assert (run_dir / "index.html").exists()
    body = (run_dir / "index.html").read_text(encoding="utf-8")
    assert "Build viewer" in body
    # The CLI never starts a server / opens a browser — assert no
    # "Started server", "Listening on", or "Opening" prose appears.
    # (The output may say "no server required" — explicitly negate
    # only the active forms.)
    lowered = result.stdout.lower()
    for forbidden in ("started server", "listening on", "opening browser"):
        assert forbidden not in lowered, (
            f"build-report-view should not start a server / open a browser, "
            f"saw {forbidden!r} in output"
        )


def test_cli_build_report_view_unknown_run_id_returns_error(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app,
        ["build-report-view", "definitely-nope", "--output-root", str(output_root)],
    )
    assert result.exit_code != 0


def test_cli_build_report_view_run_without_manifest_errors_cleanly(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """A run dir without a manifest cannot produce a viewer.

    The CLI surfaces a clean Typer error message, not a stack
    trace, so operators see what to fix.
    """
    output_root = tmp_path / "output"
    _make_run_dir(
        output_root,
        run_id="partial",
        write_manifest=False,
    )
    result = cli_runner.invoke(
        app, ["build-report-view", "partial", "--output-root", str(output_root)]
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "manifest not found" in combined or "manifest" in combined.lower()
