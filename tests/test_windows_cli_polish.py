"""Windows CLI polish — pre-rc1 release-blocker fixes.

Two bugs caught during the fresh-clone Windows smoke run:

1. **Em-dash mojibake.** Source had ``—`` (U+2014) in user-facing
   strings (``"BlueFire runs ({n} total — newest first)"``,
   ``"No server required — the page is fully self-contained."``,
   ``"Viewer missing — regenerate it with..."``). Windows
   terminals using ``cp1252`` / ``cp437`` cannot decode those code
   points and render them as ``�`` (the Unicode replacement
   glyph). The fix replaces every em-dash in user-facing text
   with ASCII ``-``.

2. **file:// URL wrapping.** ``_next_steps_hint`` and the
   ``build-report-view`` / ``build-output-index`` print sites
   used ``[green]Open viewer:[/] {file_uri(...)}`` on a single
   line. Rich's word-wrap (default 80 cols) can break the URL
   across two terminal rows, which makes the URL
   un-copy-pasteable. The fix prints the label and the URL on
   separate lines and emits the URL with ``no_wrap=True`` /
   ``overflow="ignore"``.

Pinned invariants:

1. ``src/core/cli.py`` contains zero non-ASCII characters.
2. ``list-runs`` / ``latest-run`` / ``show-run`` /
   ``build-report-view`` / ``build-output-index`` stdout and
   stderr contain no replacement character ``�``.
3. The viewer ``file://`` URI surfaces on a line of its own
   (separator-only contents on the URI line), never as
   ``label: file://...``.
4. The "no server required" message uses ASCII ``-``, not em-dash.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from src.core.cli import app


# ---------------------------------------------------------------------------
# 1. Source-level invariants
# ---------------------------------------------------------------------------


def test_cli_module_source_is_ascii_only() -> None:
    """``src/core/cli.py`` source contains only 7-bit ASCII characters.

    Em-dash / smart quotes / non-breaking space all render as
    ``�`` on Windows non-UTF-8 terminals. Pin source-level
    cleanliness so a future contributor cannot reintroduce one
    via copy-paste from a docs draft.
    """
    cli_path = Path(__file__).resolve().parents[1] / "src" / "core" / "cli.py"
    source = cli_path.read_text(encoding="utf-8")
    bad = [
        (i, ch)
        for i, line in enumerate(source.splitlines(), 1)
        for ch in line
        if ord(ch) > 127
    ]
    assert not bad, (
        "non-ASCII char in cli.py:\n"
        + "\n".join(f"  line {i}: U+{ord(ch):04X}" for i, ch in bad)
    )


# ---------------------------------------------------------------------------
# 2. CliRunner-based output checks
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def _make_run_dir(
    output_root: Path,
    *,
    run_id: str,
    scenario_name: str = "Test",
    started_at: str = "2026-05-08T00:00:00Z",
) -> Path:
    """Helper mirrored from existing CLI test files."""
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# fake", encoding="utf-8")
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run": {
                    "run_id": run_id,
                    "scenario_name": scenario_name,
                    "overall_status": "success",
                    "started_at": started_at,
                    "module_count": 1,
                    "step_status_counts": {},
                },
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    return run_dir


def test_list_runs_output_has_no_replacement_char(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-test-1")
    result = cli_runner.invoke(
        app, ["list-runs", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "�" not in combined
    # Em-dash itself must also be absent (would render as the
    # replacement glyph on Windows non-UTF-8).
    assert "—" not in combined


def test_latest_run_output_has_no_replacement_char(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-test-latest")
    result = cli_runner.invoke(
        app, ["latest-run", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "�" not in combined
    assert "—" not in combined


def test_latest_run_prints_file_uri_on_its_own_line(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """The ``file://`` URL must appear on a standalone line.

    Operators copy/click the URL; if rich wraps it across two
    terminal rows it becomes un-copy-pasteable. The fix puts the
    label on one line and the URI on the next.
    """
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-uri-line")
    result = cli_runner.invoke(
        app, ["latest-run", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    out = result.stdout
    # Find lines containing file://
    file_lines = [line for line in out.splitlines() if "file://" in line]
    assert file_lines, f"no file:// URI in output: {out}"
    # On at least one of those lines, the URI should be the entire
    # line content (after stripping leading whitespace) so copy
    # / triple-click yields just the URL. Rich strips ANSI on the
    # CliRunner so we don't have to handle escape codes here.
    standalone = [
        line for line in file_lines
        if line.lstrip().startswith("file://")
    ]
    assert standalone, (
        "expected at least one line where file:// URI starts the line; "
        f"got file_lines={file_lines!r}"
    )


def test_show_run_output_has_no_replacement_char(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-show-test")
    result = cli_runner.invoke(
        app, ["show-run", "run-show-test", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "�" not in combined
    assert "—" not in combined


def test_build_report_view_output_has_no_replacement_char(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    run_dir = _make_run_dir(output_root, run_id="run-build-rv")
    # The build-report-view writes index.html from manifest. Our
    # _make_run_dir already wrote one, so the call should succeed.
    result = cli_runner.invoke(
        app,
        ["build-report-view", "run-build-rv", "--output-root", str(output_root)],
    )
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    combined = (result.stdout or "") + (result.stderr or "")
    assert "�" not in combined
    assert "—" not in combined
    # "No server required" message uses ASCII dash, not em-dash.
    assert "No server required" in combined
    # The new shape spells "No server required - the page..." (a
    # space-dash-space). The replacement char check above already
    # guards against em-dash; assert the explicit ASCII form too.
    assert "No server required - the page" in combined


def test_build_report_view_prints_uri_on_its_own_line(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-build-line")
    result = cli_runner.invoke(
        app,
        ["build-report-view", "run-build-line", "--output-root", str(output_root)],
    )
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    file_lines = [line for line in result.stdout.splitlines() if "file://" in line]
    assert file_lines
    standalone = [
        line for line in file_lines if line.lstrip().startswith("file://")
    ]
    assert standalone, (
        f"file:// URI must start a line; got file_lines={file_lines!r}"
    )


def test_build_output_index_output_has_no_replacement_char(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir(parents=True, exist_ok=True)
    result = cli_runner.invoke(
        app, ["build-output-index", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0, result.stdout + (result.stderr or "")
    combined = (result.stdout or "") + (result.stderr or "")
    assert "�" not in combined
    assert "—" not in combined


def test_build_output_index_prints_uri_on_its_own_line(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir(parents=True, exist_ok=True)
    result = cli_runner.invoke(
        app, ["build-output-index", "--output-root", str(output_root)]
    )
    assert result.exit_code == 0
    file_lines = [line for line in result.stdout.splitlines() if "file://" in line]
    assert file_lines
    standalone = [
        line for line in file_lines if line.lstrip().startswith("file://")
    ]
    assert standalone


# ---------------------------------------------------------------------------
# 3. Subprocess-level smoke (Windows-friendly)
# ---------------------------------------------------------------------------


def test_subprocess_latest_run_output_has_no_replacement_char(
    tmp_path: Path,
) -> None:
    """End-to-end: CliRunner cooks ANSI; subprocess captures the real bytes.

    A subprocess invocation more closely matches the Windows
    operator path that surfaced the bug. We force ``COLUMNS=240``
    + ``NO_COLOR=1`` for cross-platform stability (matching the
    pattern in ``test_cli_ux_polish.py``).
    """
    output_root = tmp_path / "output"
    _make_run_dir(output_root, run_id="run-subproc-1")
    env = dict(os.environ)
    env["COLUMNS"] = "240"
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.core.cli",
            "latest-run",
            "--output-root",
            str(output_root),
        ],
        capture_output=True,
        text=True,
        env=env,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "�" not in combined
    assert "—" not in combined
