"""Codex/Bugbot sweep regression tests for the demo-readiness batch (#77-#81).

Three real findings, all P1, all fixed in this sweep:

1. **(PR #79)** ``_next_steps_hint`` and ``build-report-view``
   called ``Path.as_uri()`` on a path that may be relative. The
   default output root is ``Path("output")`` (relative), so
   running ``latest-run`` / ``show-run`` / ``build-report-view``
   from the project directory crashed with ``ValueError: relative
   path can't be expressed as a file URI`` — *after* the detail
   table had been rendered, so the operator saw a broken
   command at the moment they expected the viewer link.

2. **(PR #79)** Same bug in ``build-report-view`` — the file
   was written successfully but the trailing ``file://`` print
   raised, leaving the operator with a non-zero exit and a
   confusing traceback.

3. **(PR #80)** ``validate_run_bundle`` accepted any
   ``<a href>`` whose resolved path existed, regardless of
   whether the path sat under ``run_dir``. A href like
   ``../shared/report.md`` or ``/tmp/file`` would resolve out
   of the bundle and silently pass validation, contradicting
   the validator's "self-contained bundle" contract.

The fixes:

- New ``_file_uri(path)`` helper resolves to absolute before
  formatting as a ``file://`` URI. Both ``_next_steps_hint`` and
  ``build_report_view_cmd`` use it.
- ``validate_run_bundle`` adds a ``relative_to(run_dir_resolved)``
  check so a link's resolved target must sit under the run
  directory. Out-of-bundle links count as broken.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from src.core.cli import app
from src.core.reporting.run_discovery import validate_run_bundle


# ---------------------------------------------------------------------------
# 1. _next_steps_hint / latest-run / show-run no longer crash on relative paths
# ---------------------------------------------------------------------------


def _make_run_with_viewer(output_root: Path, run_id: str) -> Path:
    """Create a minimal run dir that has both a manifest and an index.html."""
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# r", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "scenario_name": "Sweep fixture",
            "overall_status": "success",
            "started_at": "2026-05-07T09:00:00Z",
            "module_count": 1,
            "step_status_counts": {"success": 1},
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "index.html").write_text(
        '<html><body><a href="report.md">report</a></body></html>',
        encoding="utf-8",
    )
    return run_dir


def test_latest_run_with_relative_output_root_does_not_crash(
    tmp_path: Path,
) -> None:
    """The default output root is relative; latest-run must still print a URI.

    Reproduces the original Codex P1: previously raised
    ``ValueError: relative path can't be expressed as a file URI``
    after rendering the detail table.
    """
    # Build the fixture INSIDE tmp_path so we have a relative
    # path when invoking the CLI from tmp_path.
    output_root = tmp_path / "output"
    _make_run_with_viewer(output_root, "run-rel")

    runner = CliRunner()
    # Use the output_root as a relative path so the bug
    # reproduces. Run from tmp_path so relative resolution
    # succeeds.
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["latest-run", "--output-root", "output"],
            env={"COLUMNS": "200"},
        )
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    # The file:// URI is rendered (with absolute path inside it).
    assert "file://" in result.stdout
    # The original ValueError text MUST NOT surface.
    assert "relative path can't be expressed as a file URI" not in result.stdout


def test_show_run_with_relative_output_root_does_not_crash(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    _make_run_with_viewer(output_root, "run-rel-show")
    runner = CliRunner()
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["show-run", "run-rel-show", "--output-root", "output"],
            env={"COLUMNS": "200"},
        )
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    assert "file://" in result.stdout


def test_build_report_view_with_relative_output_root_does_not_crash(
    tmp_path: Path,
) -> None:
    """``build-report-view`` writes the viewer THEN prints the URI.

    Original Codex P1: file write succeeded, but the trailing
    ``Path.as_uri()`` call raised on a relative path so the
    command exited non-zero with a stack trace, masking the
    successful write.
    """
    output_root = tmp_path / "output"
    run_dir = output_root / "run-rel-build"
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("# r", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "run": {
            "run_id": "run-rel-build",
            "scenario_name": "Sweep fixture",
            "overall_status": "success",
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    runner = CliRunner()
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["build-report-view", "run-rel-build", "--output-root", "output"],
            env={"COLUMNS": "200"},
        )
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    assert "file://" in result.stdout
    # Viewer was written (the success that the previous bug masked).
    assert (run_dir / "index.html").exists()


# ---------------------------------------------------------------------------
# 2. validate_run_bundle rejects out-of-bundle hrefs
# ---------------------------------------------------------------------------


def _make_validator_run(
    output_root: Path,
    *,
    run_id: str,
    extra_href: str = "",
) -> Path:
    """Create a run dir + bundle artifacts. Optionally inject an
    extra <a href> into index.html for traversal-bypass tests.
    """
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    for filename in (
        "manifest.json",
        "report.md",
        "report.json",
        "risk_summary.json",
        "telemetry.jsonl",
    ):
        (run_dir / filename).write_text(
            "{}" if filename.endswith(".json") else "ok",
            encoding="utf-8",
        )
    extra_link_html = (
        f'<a href="{extra_href}">extra</a>' if extra_href else ""
    )
    (run_dir / "index.html").write_text(
        f'<html><body><a href="report.md">r</a>{extra_link_html}</body></html>',
        encoding="utf-8",
    )
    return run_dir


def test_validate_run_bundle_rejects_parent_traversal_link(tmp_path: Path) -> None:
    """``../shared/...`` href fails validation even when the file exists.

    Reproduces the Codex P1 from PR #80 sweep: previous
    behaviour resolved ``run_dir / "../shared/leak.txt"`` and
    accepted any href whose target existed on disk, regardless
    of whether it lived under run_dir.
    """
    # Sibling directory holding the file the malicious href
    # points to. The validator must NOT accept this link.
    sibling = tmp_path / "shared"
    sibling.mkdir()
    (sibling / "leak.txt").write_text("secret", encoding="utf-8")

    output_root = tmp_path / "output"
    run_dir = _make_validator_run(
        output_root, run_id="r-traversal", extra_href="../../shared/leak.txt"
    )
    report = validate_run_bundle(run_dir)
    assert report["ok"] is False, report
    assert "../../shared/leak.txt" in report["broken_links"]


def test_validate_run_bundle_rejects_absolute_path_link(tmp_path: Path) -> None:
    """Absolute ``href="/tmp/leak.txt"`` is rejected even when the file exists.

    Same defence: the bundle must be self-contained.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "leak.txt"
    target.write_text("secret", encoding="utf-8")

    output_root = tmp_path / "output"
    run_dir = _make_validator_run(
        output_root, run_id="r-abs", extra_href=str(target)
    )
    report = validate_run_bundle(run_dir)
    assert report["ok"] is False, report
    # The href is the absolute string we passed.
    assert any(
        Path(broken).resolve() == target.resolve()
        or broken == str(target)
        for broken in report["broken_links"]
    ), report["broken_links"]


def test_validate_run_bundle_accepts_in_bundle_relative_links(tmp_path: Path) -> None:
    """A href that resolves under run_dir is still accepted.

    Defence-in-depth: the new traversal guard must not break
    legitimate in-bundle links.
    """
    output_root = tmp_path / "output"
    run_dir = _make_validator_run(
        output_root, run_id="r-clean"
    )  # only the in-bundle "report.md" link
    report = validate_run_bundle(run_dir)
    assert report["ok"] is True, report
    assert report["broken_links"] == []
