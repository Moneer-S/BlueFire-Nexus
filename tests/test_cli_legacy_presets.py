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

