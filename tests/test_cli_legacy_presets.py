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


def test_legacy_guided_presets_and_risk_ladder_commands() -> None:
    runner = CliRunner()
    guided = runner.invoke(app, ["legacy-guided-presets"])
    assert guided.exit_code == 0
    assert "safe-evaluati" in guided.stdout
    assert "detection-reg" in guided.stdout
    ladder = runner.invoke(app, ["legacy-risk-ladder"])
    assert ladder.exit_code == 0
    assert "safe-baseline" in ladder.stdout
    assert "full-emulate" in ladder.stdout


def test_legacy_recommend_preset_apply_updates_runtime_controls(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "legacy-recommend-preset",
            "protocol",
            "--config",
            str(cfg_path),
            "--apply",
        ],
    )
    assert result.exit_code == 0
    assert "Recommended preset: c2-simulate" in result.stdout
    assert "Applied recommended preset" in result.stdout
    assert "Active preset: c2-simulate" in result.stdout


def test_legacy_recommend_preset_save_persists_to_config(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "legacy-recommend-preset",
            "safe",
            "--config",
            str(cfg_path),
            "--save",
        ],
    )
    assert result.exit_code == 0
    assert "Recommended preset: safe-baseline" in result.stdout
    assert "Applied and saved recommended preset" in result.stdout

    persisted = runner.invoke(app, ["legacy-controls", "--config", str(cfg_path)])
    assert persisted.exit_code == 0
    assert "Active preset: safe-baseline" in persisted.stdout


def test_legacy_scenario_recommendation_and_apply(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "id: proto",
                "name: Proto Focus",
                "objective: protocol tuning validation",
                "attack_coverage: ['T1071.004']",
                "steps:",
                "  - id: p1",
                "    name: protocol",
                "    module: legacy_protocol_research",
                "    params:",
                "      protocol: dns_tunneling",
            ]
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "legacy-scenario-recommendation",
            str(scenario_path),
            "--apply",
            "--config",
            str(cfg_path),
        ],
    )
    assert result.exit_code == 0
    assert "Recommended preset: c2-simulate" in result.stdout
    assert "Applied scenario recommendation" in result.stdout
    assert "Active preset: c2-simulate" in result.stdout


def test_run_operation_manual_pack_sets_manual_active_preset(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    result = runner.invoke(
        app,
        [
            "run-operation",
            "--module",
            "legacy_stealth_research",
            "--payload",
            '{"capability":"anti_forensic","target":"host-a"}',
            "--config",
            str(cfg_path),
            "--legacy-pack",
            "stealth_pack",
            "--legacy-mode",
            "simulate",
        ],
    )
    assert result.exit_code == 0
    assert "Active preset: stealth_pack-manual" in result.stdout
    assert '"status": "success"' in result.stdout


def test_legacy_recommend_preset_unknown_objective_falls_back_to_safe_profile() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "legacy-recommend-preset",
            "unknown-objective",
        ],
    )
    assert result.exit_code == 0
    assert "Objective: safe-evaluation" in result.stdout
    assert "Recommended preset: safe-baseline" in result.stdout


def test_show_risk_summary_command_outputs_metrics(tmp_path: Path) -> None:
    runner = CliRunner()
    risk_path = tmp_path / "risk_summary.json"
    risk_path.write_text(
        "\n".join(
            [
                "{",
                '  "risk_summary": {"critical": 1, "high": 0, "medium": 1, "low": 0},',
                '  "average_score": 71.5,',
                '  "max_score": 88,',
                '  "min_score": 55,',
                '  "module_count": 2,',
                '  "modules": [',
                (
                    '    {"module":"legacy_protocol_research:s1","severity":"critical",'
                    '"score":88,"pack":"c2_pack","capability":"dns_tunneling","mode":"emulate"},'
                ),
                (
                    '    {"module":"execution:s2","severity":"medium","score":55,'
                    '"pack":"","capability":"","mode":"simulate"}'
                ),
                "  ]",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "risk-summary",
            str(risk_path),
            "--top",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert "Risk summary" in result.stdout
    assert "dns_tunneling" in result.stdout
    assert "critical" in result.stdout


def test_legacy_risk_posture_command_renders_current_posture(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg_path = tmp_path / "config.yaml"
    seed = runner.invoke(
        app,
        [
            "legacy-apply-preset",
            "c2-sim",
            "--config",
            str(cfg_path),
        ],
    )
    assert seed.exit_code == 0
    result = runner.invoke(
        app,
        [
            "legacy-risk-posture",
            "--config",
            str(cfg_path),
        ],
    )
    assert result.exit_code == 0
    assert "Legacy activation risk posture" in result.stdout
    assert "active_preset" in result.stdout
    assert "c2-simulate" in result.stdout


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
