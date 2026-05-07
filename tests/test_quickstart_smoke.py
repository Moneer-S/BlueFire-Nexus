"""Quickstart workflow smoke test.

Pinned invariants:

1. **`run_scenario --output-json` produces JSON-only stdout.** No
   advisory rich tables, no legacy-activation summary, no log
   prefixes mixed in. Operators piping the command through
   ``jq`` (per the README quickstart) get a clean stream.
2. **The default profile (``apt29_credential_access``) succeeds**
   end-to-end with no extra flags. Status is ``success``.
3. **All canonical artifacts ship together** for the default
   quickstart profile: manifest.json, index.html, report.md,
   report.json, risk_summary.json, telemetry.jsonl, plus
   detection drafts when expected.
4. **Both `manifest_path` and `viewer_path` surface** in the
   JSON payload and resolve to existing files.
5. **The CLI viewer commands see the run.** ``list-runs`` /
   ``latest-run`` / ``show-run`` / ``build-report-view`` all
   discover the freshly-completed run when invoked with the
   matching ``--output-root`` flag.

These are the exact commands an operator would run after a
fresh clone. A break here is a demo-readiness regression.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from src.core.cli import app


# Project root resolves to the repo working directory. Tests run
# python -m src.run_scenario as a child process so we exercise the
# real script entry point that operators invoke from a fresh
# clone, not just internal Python APIs.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_quickstart_subprocess(
    *,
    output_root: Path,
    profile: str = "apt29_credential_access",
) -> subprocess.CompletedProcess:
    """Spawn ``python -m src.run_scenario`` against an isolated output root.

    Mirrors the README quickstart command exactly, but routes
    output under ``output_root`` via the documented
    ``BLUEFIRE_OUTPUT_ROOT`` env var so tests do not pollute the
    project's ``output/`` tree.
    """
    env = os.environ.copy()
    env["BLUEFIRE_OUTPUT_ROOT"] = str(output_root)
    return subprocess.run(
        [sys.executable, "-m", "src.run_scenario", "--profile", profile, "--output-json"],
        cwd=str(_PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


# ---------------------------------------------------------------------------
# 1. --output-json gives JSON-only stdout
# ---------------------------------------------------------------------------


def test_output_json_stdout_parses_as_a_single_json_object(tmp_path: Path) -> None:
    """The README's ``... --output-json | jq`` workflow must work.

    Defends the contract: running the canonical quickstart
    command produces exactly one JSON object on stdout — no
    rich table noise, no log prefix lines, no activation
    summary banner mixed in.
    """
    completed = _run_quickstart_subprocess(output_root=tmp_path / "output")
    assert completed.returncode == 0, (
        f"run_scenario exited {completed.returncode}\nstderr:\n{completed.stderr}"
    )
    # Exactly one JSON value on stdout (no concatenated objects, no
    # leading log lines).
    data = json.loads(completed.stdout)
    assert isinstance(data, dict)
    assert data["status"] == "success"
    # Run id round-trips.
    assert data["run_id"]
    # Steps were executed.
    assert isinstance(data["steps"], list)
    assert len(data["steps"]) > 0


def test_output_json_advisory_output_lands_on_stderr(tmp_path: Path) -> None:
    """Logging / rich advisory output goes to stderr, not stdout.

    Defends against accidentally re-introducing a Console.print
    on stdout after the JSON-only fix.
    """
    completed = _run_quickstart_subprocess(output_root=tmp_path / "output")
    # The Python logging module prints to stderr by default; the
    # bluefire_nexus initialisation log line ("BlueFire-Nexus
    # initialized with N modules.") appears in stderr.
    assert "BlueFire-Nexus initialized" in completed.stderr
    # And NOT in stdout (which is JSON only).
    assert "BlueFire-Nexus initialized" not in completed.stdout


# ---------------------------------------------------------------------------
# 2. Default profile succeeds and produces every canonical artifact
# ---------------------------------------------------------------------------


def test_default_quickstart_run_produces_all_canonical_artifacts(
    tmp_path: Path,
) -> None:
    """Everything an operator expects to find under output/<run_id>/."""
    output_root = tmp_path / "output"
    completed = _run_quickstart_subprocess(output_root=output_root)
    assert completed.returncode == 0, completed.stderr
    data = json.loads(completed.stdout)
    run_dir = Path(data["output_dir"])

    # The README's "Example output" tree enumerates these. A
    # missing artifact is a demo-readiness regression.
    expected = [
        "manifest.json",
        "index.html",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
        "detections",
        "copilot_narrative.md",
    ]
    for relative in expected:
        assert (run_dir / relative).exists(), (
            f"missing canonical artifact: {relative}"
        )


def test_quickstart_run_payload_carries_manifest_and_viewer_paths(
    tmp_path: Path,
) -> None:
    """Both ``manifest_path`` and ``viewer_path`` are returned and resolve.

    Operators automating with the JSON output need stable keys
    pointing at the dashboard-ready files.
    """
    completed = _run_quickstart_subprocess(output_root=tmp_path / "output")
    data = json.loads(completed.stdout)
    assert data.get("manifest_path"), data
    assert data.get("viewer_path"), data
    assert Path(data["manifest_path"]).exists()
    assert Path(data["viewer_path"]).exists()


def test_quickstart_run_manifest_round_trips_through_json(tmp_path: Path) -> None:
    """The manifest written for the quickstart run is valid JSON."""
    completed = _run_quickstart_subprocess(output_root=tmp_path / "output")
    data = json.loads(completed.stdout)
    manifest_path = Path(data["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Documented top-level keys.
    for key in (
        "schema_version",
        "run",
        "safety",
        "steps",
        "propagation_edges",
        "attack_coverage",
        "telemetry",
        "detections",
        "reports",
        "copilot",
    ):
        assert key in manifest, f"manifest missing top-level key {key!r}"


# ---------------------------------------------------------------------------
# 3. CLI viewer commands see the run after orchestration
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def test_quickstart_run_visible_via_cli_list_runs(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """``list-runs`` immediately discovers the just-finished run."""
    output_root = tmp_path / "output"
    completed = _run_quickstart_subprocess(output_root=output_root)
    assert completed.returncode == 0
    data = json.loads(completed.stdout)
    run_id = data["run_id"]

    # COLUMNS keeps rich's table from truncating long fields.
    result = cli_runner.invoke(
        app,
        ["list-runs", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert run_id in result.stdout


def test_quickstart_run_visible_via_cli_latest_run(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    completed = _run_quickstart_subprocess(output_root=output_root)
    assert completed.returncode == 0
    data = json.loads(completed.stdout)
    run_id = data["run_id"]

    result = cli_runner.invoke(
        app,
        ["latest-run", "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert run_id in result.stdout


def test_quickstart_build_report_view_regenerates_index_html(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """Operators can regenerate index.html on demand for any run."""
    output_root = tmp_path / "output"
    completed = _run_quickstart_subprocess(output_root=output_root)
    assert completed.returncode == 0
    data = json.loads(completed.stdout)
    run_id = data["run_id"]
    viewer_path = Path(data["viewer_path"])

    # Delete the index and regenerate via the CLI.
    viewer_path.unlink()
    assert not viewer_path.exists()
    result = cli_runner.invoke(
        app,
        ["build-report-view", run_id, "--output-root", str(output_root)],
        env={"COLUMNS": "200"},
    )
    assert result.exit_code == 0
    assert viewer_path.exists()


# ---------------------------------------------------------------------------
# 4. --help output for both entry points stays sane
# ---------------------------------------------------------------------------


def test_run_scenario_help_text_mentions_output_json_and_profile() -> None:
    """README's documented flags must surface in ``--help`` output."""
    completed = subprocess.run(
        [sys.executable, "-m", "src.run_scenario", "--help"],
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0
    combined = completed.stdout + completed.stderr
    for flag in ("--profile", "--scenario-file", "--output-json", "--run-id"):
        assert flag in combined, f"--help missing flag {flag!r}"


def test_core_cli_help_text_lists_viewer_commands() -> None:
    """The four viewer commands are exposed at the top-level CLI."""
    completed = subprocess.run(
        [sys.executable, "-m", "src.core.cli", "--help"],
        cwd=str(_PROJECT_ROOT),
        env={**os.environ, "COLUMNS": "200"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0
    combined = completed.stdout + completed.stderr
    for command in ("list-runs", "latest-run", "show-run", "build-report-view"):
        assert command in combined, f"core.cli --help missing command {command!r}"
