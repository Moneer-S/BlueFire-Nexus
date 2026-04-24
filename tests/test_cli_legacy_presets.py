from pathlib import Path

from typer.testing import CliRunner

from src.core.cli import app


def test_legacy_presets_command_lists_profiles() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["legacy-presets"])
    assert result.exit_code == 0
    assert "safe-baseline" in result.stdout
    assert "full-simulate" in result.stdout
    assert "full-emulate" in result.stdout


def test_run_operation_accepts_legacy_preset_override(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "run-operation",
            "--module",
            "legacy_protocol_research",
            "--payload",
            '{"protocol":"dns_tunneling","endpoint":"exfil.example.lab"}',
            "--config",
            str(cfg_path),
            "--legacy-preset",
            "c2-sim",
        ],
    )
    assert result.exit_code == 0
    assert "Active preset: c2-simulate" in result.stdout
    assert '"status": "success"' in result.stdout


def test_legacy_apply_preset_preview_only_does_not_persist(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "legacy-apply-preset",
            "full-emulate",
            "--config",
            str(cfg_path),
            "--preview-only",
        ],
    )
    assert result.exit_code == 0
    assert "Previewed legacy preset" in result.stdout
    assert "Active preset: full-emulate" in result.stdout

    # Config file should remain default-safe when preview-only is used.
    persisted = runner.invoke(app, ["legacy-controls", "--config", str(cfg_path)])
    assert persisted.exit_code == 0
    assert "Active preset: none" in persisted.stdout


def test_legacy_apply_preset_persists_when_not_preview(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "legacy-apply-preset",
            "c2-sim",
            "--config",
            str(cfg_path),
        ],
    )
    assert result.exit_code == 0
    assert "Applied and saved legacy preset" in result.stdout

    persisted = runner.invoke(app, ["legacy-controls", "--config", str(cfg_path)])
    assert persisted.exit_code == 0
    assert "Active preset: c2-simulate" in persisted.stdout

