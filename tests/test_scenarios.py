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
