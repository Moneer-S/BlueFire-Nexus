from pathlib import Path

from src.core.scenario import load_scenario


def test_scenario_files_load() -> None:
    scenario_dir = Path("scenarios")
    files = list(scenario_dir.glob("*.yaml"))
    assert files
    for file_path in files:
        scenario = load_scenario(file_path)
        assert scenario.name
        assert scenario.steps


def test_legacy_flagship_scenario_contains_new_modules() -> None:
    scenario = load_scenario(Path("scenarios/legacy_flagship_blended.yaml"))
    modules = [step.module for step in scenario.steps]
    assert "legacy_actor_profile" in modules
    assert "legacy_protocol_research" in modules
    assert "legacy_stealth_research" in modules
