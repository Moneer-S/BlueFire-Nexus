"""Fixed Darwin adapter fakes without a runner, process or report path."""

from copy import deepcopy

import pytest

from bluefire import macos_file_access_method as method
from bluefire.contracts import SafetyTier
from bluefire.planner import PlanStep
from bluefire.runner_adapter import RunnerActionAdapter, RunnerAdapterError
from tests_platform import test_macos_file_access_composition_bridge as cases

creator_fake = cases.creator_fake
original = cases.original
attempt = cases.attempt


def step(action_id, parameters=None):
    return PlanStep(
        step_id="step",
        behavior_id=action_id,
        action_id=action_id,
        simulation_id=None,
        parameters={} if parameters is None else parameters,
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=SafetyTier.CONTROLLED,
        alternates=(),
    )


def test_adapter_connects_all_three_metadata_methods_without_native_cleanup_receipts(attempt):
    adapter = RunnerActionAdapter()
    artifacts = {}
    for operation, action in zip(
        ("probe", "verify_owner", "close_attempt"), method.METHODS, strict=True
    ):
        inputs = (
            {}
            if operation == "probe"
            else {
                "probe" if operation == "verify_owner" else "workspace": artifacts[
                    "probe" if operation == "verify_owner" else "workspace"
                ]
            }
        )
        adapted = adapter.adapt(step(action), bound_inputs=inputs, receipt_ids=[])
        assert adapted.params == {}
        assert (
            adapted.filesystem_scope
            == adapted.observable_paths
            == adapted.network_destinations
            == ()
        )
        frame = attempt.frame(operation)
        receipt = attempt.dispatch(frame)
        output = (
            {"attempt_closure": receipt}
            if operation == "close_attempt"
            else {
                "macos_receipt": receipt,
                "observation": method.observation(
                    frame, receipt, observed_at_ms=attempt.state["wall"]
                ),
            }
        )
        artifacts.update(
            adapter.logical_outputs(
                step(action), bound_inputs=inputs, runner_output=output, receipt_ids=[]
            )
        )
    assert set(artifacts) == {"probe", "workspace", "verification", "closure"}
    assert artifacts["closure"]["attempt_closure"]["attempt_artifacts"] == "not_created"
    assert not artifacts["closure"]["attempt_closure"]["whole_enrollment_cleanup"]
    assert len(attempt.state["calls"]) == 2


@pytest.mark.parametrize(
    "action",
    [
        "macos.file_access.probe.v1",
        "macos.file_access.verify_owner.v1",
        "macos.file_access.close_attempt.v1",
    ],
    ids=["probe", "verify_owner", "close_attempt"],
)
def test_adapter_wraps_macos_request_errors_and_refuses_native_receipt_inputs(action):
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError):
        adapter.adapt(
            step(action, {"path": "exports/report.json"}), bound_inputs={}, receipt_ids=[]
        )
    with pytest.raises(RunnerAdapterError):
        adapter.adapt(step(action), bound_inputs={}, receipt_ids=["1" * 64])
    with pytest.raises(RunnerAdapterError):
        adapter.adapt(
            step(action),
            bound_inputs={"probe": {"type": "artifact.file_access.probe.v1"}},
            receipt_ids=[],
        )


@pytest.mark.parametrize("change", ["native_receipt", "report", "receipt_ids"])
def test_adapter_wraps_macos_output_errors_instead_of_reinterpreting_native_reports(
    attempt, change
):
    adapter = RunnerActionAdapter()
    frame = attempt.frame()
    receipt = attempt.dispatch(frame)
    output = {
        "macos_receipt": receipt,
        "observation": method.observation(frame, receipt, observed_at_ms=attempt.state["wall"]),
    }
    output = deepcopy(output)
    receipts = []
    if change == "native_receipt":
        output["macos_receipt"]["state"] = "unknown"
    elif change == "report":
        output = {"report": {"path": "exports/report.json"}}
    else:
        receipts = ["1" * 64]
    with pytest.raises(RunnerAdapterError):
        adapter.logical_outputs(
            step(method.PROBE_ACTION), bound_inputs={}, runner_output=output, receipt_ids=receipts
        )


def test_metadata_close_does_not_weaken_existing_native_cleanup_receipt_requirement():
    adapter = RunnerActionAdapter()
    assert adapter.adapt(step(method.CLOSE_ACTION), bound_inputs={}, receipt_ids=[]).params == {}
    with pytest.raises(RunnerAdapterError):
        adapter.adapt(
            step("sandbox.cleanup.v1", {"verify_removal": True}), bound_inputs={}, receipt_ids=[]
        )
