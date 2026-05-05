from pathlib import Path

from src.core.bluefire_nexus import BlueFireNexus


def test_execute_operation_returns_risk_summary_path(tmp_path) -> None:
    nexus = BlueFireNexus(str(tmp_path / "config.yaml"))
    result = nexus.execute_operation(
        "execution",
        {
            "command": "echo hello",
            "network_touch": False,
        },
    )
    assert result["status"] == "success"
    risk_summary_path = result.get("risk_summary_path")
    assert risk_summary_path
    payload = Path(risk_summary_path).read_text(encoding="utf-8")
    assert '"risk_summary"' in payload
    assert '"module_count": 1' in payload


def test_run_scenario_returns_risk_summary_path(tmp_path) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        "\n".join(
            [
                "id: tiny",
                "name: Tiny",
                "objective: quick check",
                "attack_coverage: ['T1059']",
                "steps:",
                "  - id: s1",
                "    name: execute",
                "    module: execution",
                "    params:",
                "      command: echo hi",
            ]
        ),
        encoding="utf-8",
    )
    nexus = BlueFireNexus(str(tmp_path / "config.yaml"))
    result = nexus.run_scenario_file(str(Path(scenario_path)))
    assert result["status"] in {"success", "partial_success"}
    risk_summary_path = result.get("risk_summary_path")
    assert risk_summary_path
    payload = Path(risk_summary_path).read_text(encoding="utf-8")
    assert '"risk_summary"' in payload

