"""CLI UX polish regression tests.

Pinned invariants from the demo-readiness CLI-polish PR:

1. **Friendly empty-state messages.** ``list-runs`` and
   ``latest-run`` invoked against an empty output root print a
   helpful next-step instead of just a yellow line. The
   suggested command is the canonical README quickstart so
   operators know what to do next.

2. **Next-step hints surface a file:// link.** ``latest-run`` /
   ``show-run`` print a copy-paste ``file://`` link to
   ``index.html`` after the detail table when the viewer is
   present.

3. **Improved error messages.** ``show-run`` and
   ``build-report-view`` with an unknown ``run_id`` now mention
   ``list-runs`` so operators know the discovery path.

4. **Help text contains an examples block.** Every viewer CLI
   command's docstring now carries at least one example line so
   ``--help`` shows usage without forcing a docs lookup.

5. **build-report-view printed output** carries a ``file://``
   link plus the explicit "no server required" line so the
   local-only contract is visible at the moment of use.

6. **Existing CLI tests still pass.** No behaviour regression
   in command resolution, exit codes, or table content.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from src.core.cli import app


# ---------------------------------------------------------------------------
# Helpers — minimal fixture run dir
# ---------------------------------------------------------------------------


def _make_minimal_run(
    output_root: Path,
    *,
    run_id: str,
    write_viewer: bool = True,
) -> Path:
    """Build a minimal run directory the discovery helper accepts."""
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# r", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "scenario_name": "Polish fixture",
            "overall_status": "success",
            "started_at": "2026-05-07T09:00:00Z",
            "module_count": 1,
            "step_status_counts": {"success": 1},
        },
        "safety": {"dry_run": True, "max_runtime": 3600, "allowed_subnets": [], "allowed_domains": []},
        "steps": [],
        "propagation_edges": [],
        "attack_coverage": [],
        "telemetry": {"path": None, "event_count": 0, "events_by_type": {}, "events_by_module": {}},
        "detections": {"engine_counts": {}, "total": 0, "per_step": []},
        "reports": {"report_md": "report.md", "report_json": None, "risk_summary_json": None},
        "risk": None,
        "copilot": {
            "present": False,
            "provider": None,
            "model": None,
            "generated_at": None,
            "network_disabled": None,
            "fallback_used": None,
            "error": None,
            "path": None,
            "run_summary": None,
        },
        "legacy_controls": None,
        "warnings": [],
        "errors": [],
        "blocked_steps": [],
        "module_keys": [],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if write_viewer:
        (run_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    return run_dir


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# 1. Friendly empty-state messages with quickstart hint
# ---------------------------------------------------------------------------


def test_list_runs_empty_state_suggests_quickstart_command(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """The empty-state message points at `python -m src.run_scenario`."""
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app, ["list-runs", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "No runs found" in result.stdout
    # The suggested next command is the canonical README quickstart.
    assert "python -m src.run_scenario" in result.stdout
    assert "apt29_credential_access" in result.stdout


def test_latest_run_empty_state_suggests_quickstart_command(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app, ["latest-run", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    assert "No runs found" in result.stdout
    assert "python -m src.run_scenario" in result.stdout


# ---------------------------------------------------------------------------
# 2. Next-step hints — file:// link when viewer is present
# ---------------------------------------------------------------------------


def test_latest_run_prints_file_uri_when_viewer_present(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """Operators get a copy-paste browser-ready link from the CLI."""
    output_root = tmp_path / "output"
    _make_minimal_run(output_root, run_id="run-with-viewer", write_viewer=True)
    result = cli_runner.invoke(
        app,
        ["latest-run", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    # The hint includes a file:// URI so the operator can paste it
    # straight into a browser.
    assert "file://" in result.stdout
    assert "index.html" in result.stdout


def test_latest_run_suggests_build_report_view_when_viewer_missing(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """When manifest exists but viewer doesn't, the hint suggests build-report-view."""
    output_root = tmp_path / "output"
    _make_minimal_run(output_root, run_id="manifest-only", write_viewer=False)
    result = cli_runner.invoke(
        app,
        ["latest-run", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert "build-report-view" in result.stdout
    assert "manifest-only" in result.stdout


def test_show_run_prints_file_uri_when_viewer_present(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_minimal_run(output_root, run_id="run-show", write_viewer=True)
    result = cli_runner.invoke(
        app,
        ["show-run", "run-show", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert "file://" in result.stdout


# ---------------------------------------------------------------------------
# 3. Improved error messages
# ---------------------------------------------------------------------------


def test_show_run_unknown_id_error_mentions_list_runs(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """The error message tells the operator how to find valid run ids."""
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app, ["show-run", "nope", "--output-root", str(output_root)]
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "list-runs" in combined


def test_build_report_view_unknown_id_error_mentions_list_runs(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    result = cli_runner.invoke(
        app, ["build-report-view", "nope", "--output-root", str(output_root)]
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "list-runs" in combined


def test_build_report_view_missing_manifest_error_suggests_running_scenario(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """If a run dir exists but has no manifest, the error tells the operator
    to run the scenario first.
    """
    output_root = tmp_path / "output"
    run_dir = output_root / "no-manifest"
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("# r", encoding="utf-8")
    result = cli_runner.invoke(
        app,
        ["build-report-view", "no-manifest", "--output-root", str(output_root)],
    )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    # Either the FileNotFoundError chained message OR the hint
    # surfaces in stderr — accept any reasonable phrasing.
    assert "manifest" in combined.lower()


# ---------------------------------------------------------------------------
# 4. Help text carries example invocations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["list-runs", "latest-run", "show-run", "build-report-view"],
)
def test_viewer_cli_help_contains_examples_section(
    cli_runner: CliRunner, command: str
) -> None:
    """``--help`` for every viewer command shows at least one example."""
    result = cli_runner.invoke(app, [command, "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    body = result.stdout
    # Every viewer command's docstring includes the literal
    # "Examples:" header so ``--help`` rendering picks it up.
    assert "Examples:" in body or "examples:" in body.lower()
    # And at least one full ``python -m`` invocation appears in
    # the help output. (Typer wraps the docstring in the help
    # body so the example line surfaces verbatim.)
    assert "python -m src.core.cli" in body or "python -m src.run_scenario" in body


# ---------------------------------------------------------------------------
# 5. build-report-view output mentions file:// + no-server contract
# ---------------------------------------------------------------------------


def test_build_report_view_output_includes_file_uri_and_no_server_note(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_minimal_run(output_root, run_id="run-bv", write_viewer=False)
    result = cli_runner.invoke(
        app,
        ["build-report-view", "run-bv", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0, result.stdout
    out = result.stdout
    assert "file://" in out
    # The "no server required" / self-contained note still appears.
    assert "self-contained" in out.lower() or "no server" in out.lower()
