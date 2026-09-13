from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ("endpoint_lab_selective_collection.yaml", "endpoint_lab_archive_collection.yaml")


@pytest.mark.parametrize("asset", ASSETS)
def test_lab_collection_is_typed_bounded_and_uses_existing_profile(asset: str) -> None:
    scenario = load_scenario(ROOT / "scenarios" / asset)
    assert (ROOT / "scenarios" / asset).read_bytes() == (
        ROOT / "bluefire/data" / asset
    ).read_bytes()
    registry = load_builtin_registry()
    registry.validate_scenario(scenario)
    profile = next(
        row
        for row in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if row.id == "sandbox-execute.v1"
    )
    plan = DeterministicPlanner(registry).compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile
    )
    assert len(plan.steps) <= profile.budgets.max_steps
    assert scenario.step("discover_processes").parameters == {"record_limit": 20}
    assert scenario.step("inspect_lab_material").inputs["identity_material"].from_step == (
        "seed_lab_material"
    )
    assert plan.steps[-1].action_id == "sandbox.cleanup.v1"


def test_companions_change_collection_method_for_the_same_security_question() -> None:
    selective, archive = [load_scenario(ROOT / "scenarios" / asset) for asset in ASSETS]
    assert selective.purpose == archive.purpose
    assert selective.id != archive.id
    for step in selective.steps[:6]:
        assert step.to_dict() == archive.step(step.id).to_dict()
    assert selective.step("stage_collection").behavior_id == "sandbox.collection.stage.v1"
    assert archive.step("stage_collection").behavior_id == "sandbox.archive.tar.v1"
    assert selective.step("select_records").inputs["fixture"].from_step == "transform_fixture"
    assert archive.step("enumerate_files").inputs["workspace"].from_step == "create_fixture"
    assert archive.step("enumerate_files").parameters == {"record_limit": 20, "max_depth": 2}
