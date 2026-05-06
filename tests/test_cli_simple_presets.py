"""CLI integration for the new simple-mode preset commands."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from src.core.cli import app


def test_simple_presets_command_lists_all_presets() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["simple-presets"])
    assert result.exit_code == 0
    for name in (
        "local_safe",
        "lab_legacy_enabled",
        "ai_enabled",
        "ai_disabled",
        "strict_local",
    ):
        assert name in result.stdout


def test_apply_simple_preset_preview_only_does_not_write_config(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    # Run apply with --preview-only; the config file should NOT be
    # changed.
    result = runner.invoke(
        app,
        ["apply-simple-preset", "local_safe", "--config", str(cfg_path), "--preview-only"],
    )
    assert result.exit_code == 0
    assert "preview-only" in result.stdout
    # ConfigManager creates the file on first read; preview-only must
    # leave the master legacy toggle at its default (`False`) without
    # adding a fresh write of the preset overrides on top.
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    legacy = raw["modules"]["legacy"]
    assert legacy.get("enable_all_lab_capabilities", False) is False


def test_apply_simple_preset_persists_overrides(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app, ["apply-simple-preset", "lab_legacy_enabled", "--config", str(cfg_path)]
    )
    assert result.exit_code == 0
    assert "Persisted" in result.stdout
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    legacy = raw["modules"]["legacy"]
    assert legacy["enable_all_lab_capabilities"] is True
    assert legacy["global_mode"] == "simulate"
    # Emulate stays gated.
    assert legacy.get("global_lab_acknowledged", False) is False


def test_apply_simple_preset_rejects_unknown_preset(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app, ["apply-simple-preset", "definitely-not-a-preset", "--config", str(cfg_path)]
    )
    assert result.exit_code != 0
    # typer's BadParameter formatting routes the message via stderr
    # in some versions; check the combined `output` instead so this
    # passes regardless.
    combined = (result.stdout or "") + (result.output or "")
    assert "definitely-not-a-preset" in combined
