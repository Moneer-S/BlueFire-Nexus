from pathlib import Path

import pytest

from bluefire.cli import _parser, _scenario_payload


def test_scenario_cli_accepts_packaged_id_or_explicit_path() -> None:
    parser = _parser()
    by_id = parser.parse_args(
        [
            "scenario",
            "run",
            "--scenario-id",
            "scenario.restricted.persistence-canary.v1",
        ]
    )
    assert _scenario_payload(by_id)["scenario_id"] == ("scenario.restricted.persistence-canary.v1")

    path = Path(__file__).resolve().parents[1] / "scenarios" / "sandbox_research_chain.yaml"
    by_path = parser.parse_args(["scenario", "run", str(path)])
    assert _scenario_payload(by_path)["scenario"]["id"] == ("scenario.sandbox.research.chain.v1")


def test_scenario_cli_requires_exactly_one_reference() -> None:
    parser = _parser()
    missing = parser.parse_args(["scenario", "validate"])
    with pytest.raises(ValueError, match="exactly one"):
        _scenario_payload(missing)

    both = parser.parse_args(
        [
            "scenario",
            "run",
            "scenarios/sandbox_research_chain.yaml",
            "--scenario-id",
            "scenario.sandbox.research.chain.v1",
        ]
    )
    with pytest.raises(ValueError, match="exactly one"):
        _scenario_payload(both)
