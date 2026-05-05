from __future__ import annotations

from pathlib import Path

from src.core.experiments import run_experiment


class _FakeNexus:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, dict | None]] = []

    def run_scenario_file(
        self,
        scenario_path: str,
        run_id: str | None = None,
        step_param_overrides: dict | None = None,
    ) -> dict:
        self.calls.append((scenario_path, run_id, step_param_overrides))
        return {
            "status": "success",
            "steps": [
                {"status": "success", "detections": {"sigma": ["rule-1"]}},
            ],
        }


def test_run_experiment_applies_jitter_as_step_overrides(tmp_path: Path) -> None:
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

    nexus = _FakeNexus()
    run_experiment(nexus, str(scenario), runs=2, seed=7, jitter=True)

    assert len(nexus.calls) == 2
    assert nexus.calls[0][2] in (None, {})
    second_overrides = nexus.calls[1][2] or {}
    assert "step-1" in second_overrides
    step_params = second_overrides["step-1"]
    assert step_params["mutation_applied"] is True
    assert "mutation_variant" in step_params
