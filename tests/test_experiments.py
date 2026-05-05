from pathlib import Path

from src.core.experiments import run_experiment_series


def test_run_experiment_series_generates_results(tmp_path: Path):
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: mini",
                "name: Mini Scenario",
                "objective: test",
                "attack_coverage: ['T0001']",
                "steps:",
                "  - id: step-1",
                "    name: execute",
                "    module: execution",
                "    params:",
                "      command: echo hi",
            ]
        ),
        encoding="utf-8",
    )

    results = run_experiment_series(str(scenario), iterations=2)
    assert results["runs"] == 2
    assert results["successes"] + results["failures"] == 2
    assert results["output_file"]
    assert "results" in results
    assert len(results["results"]) == 2
    assert "detection_efficacy" in results
