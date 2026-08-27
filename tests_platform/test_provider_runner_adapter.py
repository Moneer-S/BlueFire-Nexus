from __future__ import annotations

import copy

import pytest

from bluefire.contracts import SafetyTier
from bluefire.planner import PlanStep
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError

ACTION_ID = "independent.portable-probe.v1"
BEHAVIOR_ID = "independent.portable-provider.v1"


def _binding() -> dict[str, object]:
    return {
        "schema_version": "bluefire.runner-provider-execution-binding.v1",
        "logical_behavior_id": BEHAVIOR_ID,
        "logical_action_id": ACTION_ID,
        "parameters": [
            {
                "name": "label",
                "type": "string",
                "required": True,
                "default": None,
                "enum": ["release"],
                "minimum": None,
                "maximum": None,
            }
        ],
        "outputs": [
            {
                "name": "result",
                "type": "artifact.provider.portable-probe.v1",
                "required": True,
                "multiple": False,
            }
        ],
    }


def _step(*, parameters: dict[str, object] | None = None) -> PlanStep:
    return PlanStep(
        step_id="provider-step",
        behavior_id=BEHAVIOR_ID,
        action_id=ACTION_ID,
        simulation_id=None,
        parameters={"label": "release"} if parameters is None else parameters,
        inputs={},
        expected_outputs=("result",),
        required_capabilities=("native.execution",),
        safety_tier=SafetyTier.SAFE,
        alternates=(),
        execution_binding=_binding(),
    )


def test_provider_adapter_passes_only_signed_typed_parameters() -> None:
    adapted = RunnerActionAdapter().adapt(
        _step(),
        bound_inputs={},
        receipt_ids=(),
    )

    assert adapted.params == {"label": "release"}
    assert adapted.filesystem_scope == ()
    assert adapted.network_destinations == ()
    assert adapted.observable_paths == ()


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        ({}, "required"),
        ({"label": "other"}, "enum"),
        ({"label": 7}, "type"),
        ({"label": "release", "command": "whoami"}, "signed contract"),
    ],
)
def test_provider_adapter_refuses_unsigned_or_mistyped_parameters(
    parameters: dict[str, object], message: str
) -> None:
    with pytest.raises(RunnerAdapterError, match=message):
        RunnerActionAdapter().adapt(
            _step(parameters=parameters),
            bound_inputs={},
            receipt_ids=(),
        )


def test_provider_adapter_maps_only_declared_typed_outputs() -> None:
    output = {
        "result": {
            "type": "artifact.provider.portable-probe.v1",
            "provider": "independent",
            "status": "ready",
        }
    }

    assert (
        RunnerActionAdapter().logical_outputs(
            _step(),
            bound_inputs={},
            runner_output=output,
            receipt_ids=(),
        )
        == output
    )

    substituted = copy.deepcopy(output)
    substituted["result"]["type"] = "artifact.provider.substituted.v1"
    with pytest.raises(RunnerAdapterError, match="artifact type"):
        RunnerActionAdapter().logical_outputs(
            _step(),
            bound_inputs={},
            runner_output=substituted,
            receipt_ids=(),
        )


def test_provider_adapter_refuses_host_inputs_and_cleanup_receipts() -> None:
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError, match="no host artifact inputs"):
        adapter.adapt(_step(), bound_inputs={"input": {}}, receipt_ids=())
    with pytest.raises(RunnerAdapterError, match="cleanup receipts"):
        adapter.adapt(_step(), bound_inputs={}, receipt_ids=("0" * 64,))
