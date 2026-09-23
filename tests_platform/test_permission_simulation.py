from __future__ import annotations

import pytest

from bluefire.contracts import SafetyTier
from bluefire.planner import PlanStep
from bluefire.simulation import SimulationError, SimulationRegistry


def _step(mode: str = "0660", **parameters: str) -> PlanStep:
    values = {"mode": mode, **parameters}
    return PlanStep(
        step_id="permission",
        behavior_id="sandbox.permission.relax.v1",
        action_id="sandbox.permission.chmod.v1",
        simulation_id="simulation.sandbox.permission.relax.v1",
        parameters=values,
        inputs={"fixture": {"from_step": "transform", "artifact": "fixture"}},
        expected_outputs=("fixture",),
        required_capabilities=("filesystem.read", "filesystem.write", "process.spawn"),
        safety_tier=SafetyTier.CONTROLLED,
        alternates=(),
    )


def _fixture() -> dict[str, object]:
    return {
        "type": "artifact.sandbox.fixture.v1",
        "path": "synthetic/fixtures/transformed.jsonl",
        "record_count": 6,
        "content_hash": "sha256:" + "a" * 64,
        "redact_values": True,
    }


def test_permission_simulation_is_synthetic_and_preserves_fixture() -> None:
    result = SimulationRegistry().execute(_step(), bound_inputs={"fixture": _fixture()})
    fixture = result.artifacts["fixture"]
    assert fixture["type"] == "artifact.sandbox.fixture.v1"
    assert fixture["path"] == "synthetic/fixtures/transformed.jsonl"
    assert fixture["permission_change"] == {
        "requested_mode": "0660",
        "before_mode": "0644",
        "after_mode": "0660",
        "permission_bits_observed": False,
        "external_tool_invoked": False,
    }
    assert any("no filesystem mode was observed" in item for item in result.limitations)
    assert result.details["side_effects_started"] is False


@pytest.mark.parametrize("mode", ["0641", "0700", "0660.0", 660])
def test_permission_simulation_rejects_unreviewed_modes(mode: object) -> None:
    with pytest.raises(SimulationError):
        SimulationRegistry().execute(_step(mode), bound_inputs={"fixture": _fixture()})


def test_permission_simulation_rejects_non_fixture_input() -> None:
    with pytest.raises(SimulationError):
        SimulationRegistry().execute(
            _step(),
            bound_inputs={
                "fixture": {
                    "type": "artifact.other.v1",
                    "path": "synthetic/fixtures/transformed.jsonl",
                }
            },
        )
