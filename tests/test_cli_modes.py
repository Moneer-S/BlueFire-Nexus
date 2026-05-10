"""CLI integration for the explain-mode / mode-plan commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from src.core.cli import app


_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
_FIN7_SCENARIO = _SCENARIOS_DIR / "fin7_initial_access_to_c2.yaml"


# ---------------------------------------------------------------------------
# explain-mode
# ---------------------------------------------------------------------------


def test_explain_mode_simulate_renders_panel() -> None:
    """``explain-mode simulate`` exits cleanly with a panel that
    surfaces the mode name and the dry_run override."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "simulate"])
    assert result.exit_code == 0, result.stdout
    assert "Mode: simulate" in result.stdout
    assert "general.dry_run" in result.stdout
    assert "True" in result.stdout


def test_explain_mode_live_lab_surfaces_warnings() -> None:
    """The live-lab panel must surface its loud warnings so an
    operator sees them before configuring the run."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "live-lab"])
    assert result.exit_code == 0, result.stdout
    assert "live-lab" in result.stdout
    assert "Warnings:" in result.stdout
    assert "isolated" in result.stdout.lower() or "lab" in result.stdout.lower()


def test_explain_mode_json_emits_documented_shape() -> None:
    """``--json`` returns a stable dict shape so automation can
    pipe stdout through ``json.loads``."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "emulate", "--json"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert {
        "name",
        "description",
        "required_gates",
        "config_overrides",
        "side_effects",
        "warnings",
        "safe_for_unattended",
    }.issubset(parsed.keys())
    assert parsed["name"] == "emulate"
    assert parsed["safe_for_unattended"] is False


def test_explain_mode_accepts_aliases() -> None:
    """Aliases (``sim`` / ``lab``) resolve to canonical modes."""

    runner = CliRunner()
    sim_result = runner.invoke(app, ["explain-mode", "sim"])
    lab_result = runner.invoke(app, ["explain-mode", "lab"])
    assert sim_result.exit_code == 0
    assert lab_result.exit_code == 0
    assert "Mode: simulate" in sim_result.stdout
    assert "live-lab" in lab_result.stdout


def test_explain_mode_rejects_unknown_with_clear_error() -> None:
    """Unknown mode names exit non-zero with a helpful error."""

    runner = CliRunner()
    result = runner.invoke(app, ["explain-mode", "production"])
    assert result.exit_code != 0
    assert "Unknown mode" in result.stdout or "Unknown mode" in result.stderr


# ---------------------------------------------------------------------------
# mode-plan
# ---------------------------------------------------------------------------


def test_mode_plan_simulate_against_fin7_renders_tree() -> None:
    """``mode-plan`` exits cleanly and renders a tree containing
    the scenario name and the simulate config overrides."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "simulate"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Mode plan:" in result.stdout
    assert "FIN7" in result.stdout
    assert "general.dry_run" in result.stdout
    # FIN7 is no-legacy in simulate, so no required gates land.
    assert "(none)" in result.stdout


def test_mode_plan_default_mode_is_simulate() -> None:
    """When the operator omits ``--mode``, the plan defaults to the
    safest mode (simulate)."""

    runner = CliRunner()
    result = runner.invoke(app, ["mode-plan", str(_FIN7_SCENARIO)])
    assert result.exit_code == 0, result.stdout
    assert "simulate" in result.stdout


def test_mode_plan_live_lab_surfaces_warnings_section() -> None:
    """Live-lab mode plan must include a warnings section so the
    operator reads the cautions before applying the config patch."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "live-lab"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Warnings" in result.stdout
    assert "NOT safe for unattended" in result.stdout


def test_mode_plan_json_emits_documented_shape() -> None:
    """``--json`` returns the structured plan dict for automation."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "mode-plan",
            str(_FIN7_SCENARIO),
            "--mode",
            "emulate",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert {
        "mode",
        "scenario_name",
        "scenario_id",
        "step_count",
        "modules",
        "legacy_packs",
        "config_overrides",
        "required_gates",
        "warnings",
        "side_effects",
        "safe_for_unattended",
    }.issubset(parsed.keys())
    assert parsed["mode"] == "emulate"
    assert parsed["scenario_name"] == "FIN7 initial access to C2"
    assert parsed["step_count"] == 7
    assert parsed["safe_for_unattended"] is False


def test_mode_plan_rejects_unknown_mode_with_clear_error() -> None:
    """Unknown mode → non-zero exit, useful error message."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", str(_FIN7_SCENARIO), "--mode", "nonexistent"],
    )
    assert result.exit_code != 0
    output = (result.stdout or "") + (result.stderr or "")
    assert "Unknown mode" in output


def test_mode_plan_rejects_missing_scenario() -> None:
    """A non-existent scenario file → non-zero exit with a helpful
    error from typer's ``exists=True`` validator."""

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["mode-plan", "scenarios/no_such_scenario.yaml", "--mode", "simulate"],
    )
    assert result.exit_code != 0
