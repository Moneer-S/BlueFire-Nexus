from __future__ import annotations

from typing import Any, Mapping, Sequence

import pytest

from bluefire.contracts import SafetyTier
from bluefire.planner import PlanStep
from bluefire.runner_adapter import AdaptedAction, RunnerActionAdapter, RunnerAdapterError

ACTION_IDS = {
    "sandbox.fixture.create.v1",
    "sandbox.fixture.transform.v1",
    "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1",
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
    "sandbox.cleanup.v1",
}
CONTROLLED_ACTIONS = {
    "sandbox.collection.stage.v1",
    "sandbox.network.loopback.v1",
    "sandbox.export.local.v1",
}
RECEIPT_CREATE = "a" * 64
RECEIPT_STAGE = "b" * 64


def _step(action_id: str, parameters: Mapping[str, Any] | None = None) -> PlanStep:
    return PlanStep(
        step_id="step",
        behavior_id=action_id,
        action_id=action_id,
        simulation_id=None,
        parameters=dict(parameters or {}),
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=(SafetyTier.CONTROLLED if action_id in CONTROLLED_ACTIONS else SafetyTier.SAFE),
        alternates=(),
    )


@pytest.mark.parametrize(
    ("action_id", "parameters", "bound_inputs", "receipt_ids", "expected"),
    [
        pytest.param(
            "sandbox.fixture.create.v1",
            {"record_count": 8},
            {},
            (),
            AdaptedAction(
                params={"path": "fixtures/input.txt", "content_template": "telemetry-seed"},
                filesystem_scope=("fixtures/input.txt",),
                observable_paths=("fixtures/input.txt",),
            ),
            id="fixture-create",
        ),
        pytest.param(
            "sandbox.fixture.transform.v1",
            {"redact_values": True},
            {"workspace": {"fixture_path": "fixtures/input.txt"}},
            (RECEIPT_CREATE,),
            AdaptedAction(
                params={
                    "input": "fixtures/input.txt",
                    "output": "fixtures/transformed.txt",
                    "transform": "uppercase-ascii",
                },
                filesystem_scope=("fixtures/input.txt", "fixtures/transformed.txt"),
                observable_paths=("fixtures/transformed.txt",),
            ),
            id="fixture-transform",
        ),
        pytest.param(
            "sandbox.discovery.list.v1",
            {"record_limit": 7},
            {"fixture": {"path": "fixtures/transformed.txt"}},
            (),
            AdaptedAction(
                params={"path": "fixtures", "max_entries": 7},
                filesystem_scope=("fixtures",),
            ),
            id="discovery-list",
        ),
        pytest.param(
            "sandbox.discovery.metadata.v1",
            {"record_limit": 7},
            {"fixture": {"path": "fixtures/transformed.txt"}},
            (),
            AdaptedAction(
                params={"path": "fixtures/transformed.txt"},
                filesystem_scope=("fixtures/transformed.txt",),
            ),
            id="discovery-metadata",
        ),
        pytest.param(
            "sandbox.collection.stage.v1",
            {"bundle_format": "jsonl"},
            {
                "records": [
                    {"path": "fixtures/transformed.txt"},
                    {"path": "fixtures/input.txt"},
                ]
            },
            (),
            AdaptedAction(
                params={
                    "inputs": ["fixtures/transformed.txt", "fixtures/input.txt"],
                    "destination_directory": "staged",
                },
                filesystem_scope=(
                    "fixtures/transformed.txt",
                    "fixtures/input.txt",
                    "staged",
                ),
                observable_paths=("staged/000-transformed.txt",),
            ),
            id="collection-stage",
        ),
        pytest.param(
            "sandbox.network.loopback.v1",
            {"port": 4317},
            {"bundle": {"path": "staged/000-transformed.txt"}},
            (),
            AdaptedAction(
                params={
                    "artifact": "staged/000-transformed.txt",
                    "destination": {"host": "127.0.0.1", "port": 4317},
                },
                filesystem_scope=("staged/000-transformed.txt",),
                network_destinations=({"host": "127.0.0.1", "port": 4317},),
            ),
            id="network-loopback",
        ),
        pytest.param(
            "sandbox.export.local.v1",
            {"retention_label": "ephemeral"},
            {"bundle": {"path": "staged/000-transformed.txt"}},
            (),
            AdaptedAction(
                params={
                    "source": "staged/000-transformed.txt",
                    "destination": "exports/bundle.bin",
                },
                filesystem_scope=("staged/000-transformed.txt", "exports/bundle.bin"),
                observable_paths=("exports/bundle.bin",),
            ),
            id="export-local",
        ),
        pytest.param(
            "sandbox.cleanup.v1",
            {"verify_removal": True},
            {},
            (RECEIPT_CREATE, RECEIPT_STAGE, RECEIPT_CREATE),
            AdaptedAction(
                params={"receipt_ids": [RECEIPT_STAGE, RECEIPT_CREATE]},
                filesystem_scope=(),
            ),
            id="cleanup",
        ),
    ],
)
def test_all_reviewed_actions_have_exact_runner_parameter_shapes(
    action_id: str,
    parameters: Mapping[str, Any],
    bound_inputs: Mapping[str, Any],
    receipt_ids: Sequence[str],
    expected: AdaptedAction,
) -> None:
    adapter = RunnerActionAdapter()
    assert adapter.action_ids == ACTION_IDS
    assert (
        adapter.adapt(
            _step(action_id, parameters),
            bound_inputs=bound_inputs,
            receipt_ids=receipt_ids,
        )
        == expected
    )


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "../outside.txt",
        "fixtures/../../outside.txt",
        "/absolute/outside.txt",
        "C:/absolute/outside.txt",
        r"fixtures\outside.txt",
        "fixtures//outside.txt",
        "fixtures/./outside.txt",
    ],
)
def test_artifact_paths_must_be_normalized_relative_sandbox_paths(path: str) -> None:
    with pytest.raises(RunnerAdapterError, match="normalized relative path|non-empty runner path"):
        RunnerActionAdapter().adapt(
            _step("sandbox.fixture.transform.v1"),
            bound_inputs={"workspace": {"fixture_path": path}},
            receipt_ids=(),
        )


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "localhost", "example.test"])
def test_network_translation_refuses_non_literal_loopback_before_connect(host: str) -> None:
    with pytest.raises(RunnerAdapterError, match="literal loopback"):
        RunnerActionAdapter().adapt(
            _step("sandbox.network.loopback.v1", {"port": 4317}),
            bound_inputs={"bundle": {"path": "staged/bundle.bin"}},
            receipt_ids=(),
            loopback_host=host,
        )


@pytest.mark.parametrize("port", [True, 0, 65536, "4317"])
def test_network_translation_rejects_invalid_ports(port: object) -> None:
    with pytest.raises(RunnerAdapterError, match="port must be an integer"):
        RunnerActionAdapter().adapt(
            _step("sandbox.network.loopback.v1", {"port": port}),
            bound_inputs={"bundle": {"path": "staged/bundle.bin"}},
            receipt_ids=(),
        )


def test_stage_and_cleanup_require_runner_owned_inputs() -> None:
    adapter = RunnerActionAdapter()
    with pytest.raises(RunnerAdapterError, match="records must contain"):
        adapter.adapt(
            _step("sandbox.collection.stage.v1"),
            bound_inputs={"records": []},
            receipt_ids=(),
        )
    with pytest.raises(RunnerAdapterError, match="runner-issued receipt"):
        adapter.adapt(
            _step("sandbox.cleanup.v1"),
            bound_inputs={},
            receipt_ids=(),
        )
    with pytest.raises(RunnerAdapterError, match="64 lowercase hexadecimal"):
        adapter.adapt(
            _step("sandbox.cleanup.v1"),
            bound_inputs={},
            receipt_ids=("untrusted-receipt",),
        )
