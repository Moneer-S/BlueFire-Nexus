from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from bluefire.config import load_config
from bluefire.contracts import ExecutionMode, ScenarioDefinition
from bluefire.orchestrator import Orchestrator
from bluefire.planner import DeterministicPlanner
from bluefire.registry import load_builtin_registry
from bluefire.runner_adapter import RunnerActionAdapter
from bluefire.runner_contracts import build_execution_manifest, build_runner_profile

ROOT = Path(__file__).resolve().parents[1]


def test_gate11_cancellation_plan_profile_scope_matches_its_manifest_scope(
    tmp_path: Path,
) -> None:
    action_id = "sandbox.execution.process-tree-cancellation-witness.v1"
    control_parent = ".bluefire-cancellation-witness-v1"
    registry = load_builtin_registry()
    config = load_config(ROOT / "config" / "bluefire.example.yaml")
    profile = next(
        item
        for item in config.runner_profiles
        if item.id == "gate11-windows-cancellation-witness.v1"
    )
    scenario = ScenarioDefinition.from_mapping(
        {
            "schema_version": "bluefire.scenario.v1",
            "id": "scenario.process-tree-cancellation.v1",
            "title": "Process cancellation witness",
            "purpose": "Exercise the fixed Windows cancellation witness.",
            "start": "witness",
            "steps": [{"id": "witness", "behavior_id": action_id}],
            "edges": [],
            "provenance": {
                "source": "BlueFire test fixture",
                "reference": "focused runner scope regression",
                "license": "MIT",
                "derived": False,
            },
        }
    )
    plan = DeterministicPlanner(registry).compile(
        scenario,
        mode=ExecutionMode.EXECUTE,
        profile=profile,
    )
    step = plan.steps[0]
    adapted = RunnerActionAdapter().adapt(step, bound_inputs={}, receipt_ids=())
    profile_scope = Orchestrator._filesystem_scope(plan)
    runner_profile = build_runner_profile(
        profile,
        sandbox_root=tmp_path / "sandbox",
        platform="windows",
        filesystem_scope=profile_scope,
    )
    now = datetime.now(timezone.utc)
    manifest = build_execution_manifest(
        run_id="run-20261022T120000Z-abcdef0123456789",
        step_id=step.step_id,
        behavior_id=step.behavior_id,
        action=registry.get_action(action_id),
        runner_profile=runner_profile,
        params=adapted.params,
        filesystem_scope=adapted.filesystem_scope,
        network_destinations=adapted.network_destinations,
        approval_record={
            "approved_by": "scope-regression-test",
            "approved_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        },
        timeout_ms=15_000,
        now=now,
    )

    assert tuple(manifest["target_scope"]["filesystem"]) == (control_parent,)
    assert tuple(runner_profile["target_scope"]["filesystem"]) == (control_parent,)
    assert tuple(profile_scope) == tuple(manifest["target_scope"]["filesystem"])
    assert not {"fixtures", "staged", "exports", "restricted", "observability"} & set(profile_scope)
