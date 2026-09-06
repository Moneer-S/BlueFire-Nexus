from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.config import load_config
from bluefire.contracts import ExecutionMode, load_scenario
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError
from bluefire.simulation import SimulationRegistry

ROOT = Path(__file__).resolve().parents[1]
METHODS = ("sandbox.collection.records.v1", "sandbox.collection.archive.v1")
ASSETS = ("endpoint_lab_collection_methods.yaml", "endpoint_lab_benign_collection.yaml")
DIGEST = "a" * 64


def _plan(asset: str = ASSETS[0]):
    registry = load_builtin_registry()
    scenario = load_scenario(ROOT / "scenarios" / asset)
    profile = next(
        row
        for row in load_config(ROOT / "config/bluefire.example.yaml").runner_profiles
        if row.id == "sandbox-execute.v1"
    )
    return scenario, DeterministicPlanner(registry).compile(
        scenario, mode=ExecutionMode.EXECUTE, profile=profile
    )


def _source():
    return {
        "records": [
            {
                "type": "artifact.sandbox.discovery.records.v1",
                "kind": "file",
                "path": "fixtures/transformed.jsonl",
                "record_count": 8,
                "sha256": DIGEST,
            }
        ]
    }


@pytest.mark.parametrize("asset", ASSETS)
def test_collection_scenarios_preserve_compatible_method_contract_and_cleanup(asset: str):
    scenario, plan = _plan(asset)
    registry = load_builtin_registry()
    assert METHODS[1] in registry.compatible_behaviors(METHODS[0])
    assert (ROOT / "scenarios" / asset).read_bytes() == (
        ROOT / "bluefire/data" / asset
    ).read_bytes()
    assert len(plan.steps) == 9
    assert plan.steps[-1].action_id == "sandbox.cleanup.v1"
    assert scenario.step("stage_collection").inputs["records"].from_step == "select_records"
    assert scenario.step("select_records").inputs["fixture"].from_step == "transform_fixture"
    alternate = replace(
        scenario,
        steps=tuple(
            replace(step, behavior_id=METHODS[1]) if step.id == "stage_collection" else step
            for step in scenario.steps
        ),
    )
    registry.validate_scenario(alternate)


def test_benign_case_changes_actual_transformation_without_removing_collection():
    attack, _ = _plan()
    benign, _ = _plan(ASSETS[1])
    assert attack.purpose == benign.purpose
    for step in attack.steps:
        if step.id == "transform_fixture":
            assert step.parameters == {"redact_values": False}
            assert benign.step(step.id).parameters == {"redact_values": True}
        else:
            assert step.to_dict() == benign.step(step.id).to_dict()


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("variant", ("primary", "heldout"))
def test_adapter_binds_both_methods_to_exact_source_and_destination(method: str, variant: str):
    _, plan = _plan()
    step = replace(
        next(row for row in plan.steps if row.step_id == "stage_collection"),
        action_id=method,
        behavior_id=method,
        parameters={"stage_variant": variant},
    )
    adapter = RunnerActionAdapter()
    source = _source()
    request = adapter.adapt(step, bound_inputs=source, receipt_ids=())
    extension = "tar" if method == METHODS[1] else "jsonl"
    directory = "staged/variation" if variant == "heldout" else "staged/collection"
    path = f"{directory}/bundle.{extension}"
    assert request.params == {
        "input": "fixtures/transformed.jsonl",
        "expected_sha256": DIGEST,
        "stage_variant": variant,
    }
    assert request.filesystem_scope == ("fixtures/transformed.jsonl", directory)
    assert request.observable_paths == (path,)
    output = {
        "artifact": path,
        "container": "ustar" if extension == "tar" else "jsonl",
        "source_sha256": DIGEST,
        "input_count": 1,
        "sha256": "b" * 64,
        "size": 1024,
    }
    materialized = adapter.logical_outputs(
        step, bound_inputs=source, runner_output=output, receipt_ids=("c" * 64,)
    )
    assert materialized["bundle"]["type"] == "artifact.sandbox.collection.v1"
    assert materialized["bundle"]["source_sha256"] == DIGEST
    for field, invalid in (
        ("source_sha256", "d" * 64),
        ("input_count", True),
        ("size", True),
        ("artifact", "staged/unapproved.jsonl"),
    ):
        with pytest.raises(RunnerAdapterError):
            adapter.logical_outputs(
                step, bound_inputs=source, runner_output={**output, field: invalid}, receipt_ids=()
            )
    for field, invalid in (
        ("sha256", "sha256:" + DIGEST),
        ("path", "fixtures/input.jsonl"),
        ("record_count", True),
    ):
        changed = {"records": [{**source["records"][0], field: invalid}]}
        with pytest.raises(RunnerAdapterError):
            adapter.adapt(step, bound_inputs=changed, receipt_ids=())


@pytest.mark.parametrize("asset", ASSETS)
def test_full_synthetic_chain_and_method_swap_remain_explicitly_side_effect_free(asset: str):
    _, plan = _plan(asset)
    for method in METHODS:
        artifacts = {}
        for step in plan.steps:
            if step.step_id == "stage_collection":
                step = replace(
                    step, action_id=method, behavior_id=method, simulation_id=f"simulation.{method}"
                )
            inputs = {
                name: artifacts[binding["from_step"]][binding["artifact"]]
                for name, binding in step.inputs.items()
            }
            result = SimulationRegistry().execute(step, bound_inputs=inputs)
            assert result.details["side_effects_started"] is False
            artifacts[step.step_id] = result.artifacts
        bundle = artifacts["stage_collection"]["bundle"]
        assert bundle["type"] == "artifact.sandbox.collection.v1"
        assert bundle["path"].startswith("synthetic/")
        assert "sha256" not in bundle
