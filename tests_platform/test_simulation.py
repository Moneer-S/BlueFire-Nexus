from __future__ import annotations

from typing import Any, Mapping

import pytest

from bluefire.contracts import SafetyTier, StepOutcome
from bluefire.planner import PlanStep
from bluefire.simulation import SimulationError, SimulationRegistry
from bluefire.util import content_hash


def _step(
    action_id: str,
    simulation_id: str,
    parameters: Mapping[str, Any] | None = None,
) -> PlanStep:
    return PlanStep(
        step_id="step",
        behavior_id=action_id,
        action_id=action_id,
        simulation_id=simulation_id,
        parameters=dict(parameters or {}),
        inputs={},
        expected_outputs=(),
        required_capabilities=(),
        safety_tier=SafetyTier.SAFE,
        alternates=(),
    )


def test_new_discovery_and_archive_simulations_are_pure_and_typed() -> None:
    registry = SimulationRegistry()
    system = registry.execute(
        _step("endpoint.discovery.system.v1", "simulation.endpoint.discovery.system.v1"),
        bound_inputs={},
    )
    processes = registry.execute(
        _step(
            "endpoint.discovery.processes.v1",
            "simulation.endpoint.discovery.processes.v1",
            {"record_limit": 1},
        ),
        bound_inputs={},
    )
    recursive = registry.execute(
        _step(
            "sandbox.discovery.recursive.v1",
            "simulation.sandbox.discovery.recursive.v1",
        ),
        bound_inputs={
            "workspace": {
                "root": "synthetic/fixtures",
                "fixture_path": "synthetic/fixtures/input.jsonl",
            }
        },
    )
    archive = registry.execute(
        _step("sandbox.archive.tar.v1", "simulation.sandbox.archive.tar.v1"),
        bound_inputs={"records": recursive.artifacts["records"]},
    )

    assert all(
        result.outcome is StepOutcome.SUCCESS for result in (system, processes, recursive, archive)
    )
    assert system.artifacts["system"]["type"] == "artifact.endpoint.system-profile.v1"
    assert len(processes.artifacts["processes"]["entries"]) == 1
    assert recursive.artifacts["records"][0]["kind"] == "file"
    assert archive.artifacts["bundle"]["type"] == "artifact.sandbox.archive.v1"
    assert all(result.details["side_effects_started"] is False for result in (system, archive))


def test_restricted_canary_simulation_is_labeled_synthetic() -> None:
    result = SimulationRegistry().execute(
        _step(
            "sandbox.restricted.persistence-marker.v1",
            "simulation.sandbox.restricted.persistence-marker.v1",
            {"label": "persistence_detection_canary"},
        ),
        bound_inputs={},
    )

    assert result.outcome is StepOutcome.SUCCESS
    assert result.artifacts["marker"]["synthetic"] is True
    assert result.artifacts["workspace"]["root"] == "synthetic/restricted"
    assert result.details["side_effects_started"] is False


def test_fixture_discovery_and_collection_preserve_count_and_hash_semantics() -> None:
    registry = SimulationRegistry()
    created = registry.execute(
        _step(
            "sandbox.fixture.create.v1",
            "simulation.sandbox.fixture.create.v1",
            {"record_count": 3},
        ),
        bound_inputs={},
    )
    workspace = created.artifacts["workspace"]
    expected_records = [
        {
            "record_id": f"synthetic-{index:03}",
            "synthetic": True,
            "template": "telemetry-seed",
            "value": f"telemetry-value-{index:03}",
        }
        for index in range(1, 4)
    ]
    assert workspace["fixture_path"] == "synthetic/fixtures/input.jsonl"
    assert workspace["record_count"] == 3
    assert workspace["content_hash"] == content_hash(expected_records)

    transformed = registry.execute(
        _step(
            "sandbox.fixture.transform.v1",
            "simulation.sandbox.fixture.transform.v1",
            {"redact_values": True},
        ),
        bound_inputs={"workspace": workspace},
    ).artifacts["fixture"]
    expected_transform_hash = content_hash(
        {
            "source_content_hash": workspace["content_hash"],
            "record_count": 3,
            "redact_values": True,
            "transform": "canonical-reviewed-jsonl-v1",
        }
    )
    assert transformed["record_count"] == 3
    assert transformed["redact_values"] is True
    assert transformed["content_hash"] == expected_transform_hash

    for simulation_id, method in (
        ("simulation.sandbox.discovery.list.v1", "list"),
        ("simulation.sandbox.discovery.metadata.v1", "metadata"),
    ):
        discovered = registry.execute(
            _step(simulation_id.removeprefix("simulation."), simulation_id),
            bound_inputs={"fixture": transformed},
        ).artifacts["records"]
        assert discovered == [
            {
                "type": "artifact.sandbox.discovery.records.v1",
                "path": "synthetic/fixtures/transformed.jsonl",
                "kind": "file",
                "method": method,
                "synthetic": True,
                "record_count": 3,
                "content_hash": expected_transform_hash,
                "redact_values": True,
            }
        ]

        for bundle_format in ("jsonl", "json"):
            bundle = registry.execute(
                _step(
                    "sandbox.collection.stage.v1",
                    "simulation.sandbox.collection.stage.v1",
                    {"bundle_format": bundle_format},
                ),
                bound_inputs={"records": discovered},
            ).artifacts["bundle"]
            assert bundle["path"] == f"synthetic/staged/bundle.{bundle_format}"
            assert bundle["record_count"] == 3
            assert bundle["format"] == bundle_format
            assert bundle["content_hash"] == content_hash(
                {
                    "source_content_hash": expected_transform_hash,
                    "record_count": 3,
                    "format": bundle_format,
                }
            )


def test_export_simulation_requires_and_preserves_the_bound_bundle_hash() -> None:
    registry = SimulationRegistry()
    digest = content_hash({"synthetic": "bundle"})
    result = registry.execute(
        _step(
            "sandbox.export.local.v1",
            "simulation.sandbox.export.local.v1",
            {"retention_label": "review"},
        ),
        bound_inputs={"bundle": {"content_hash": digest}},
    )
    assert result.artifacts["receipt"]["would_export"] == digest

    with pytest.raises(SimulationError, match="bundle.content_hash must be a non-empty digest"):
        registry.execute(
            _step("sandbox.export.local.v1", "simulation.sandbox.export.local.v1"),
            bound_inputs={"bundle": {}},
        )


def test_network_simulation_requires_and_preserves_the_bound_bundle_hash() -> None:
    registry = SimulationRegistry()
    digest = content_hash({"synthetic": "bundle"})
    result = registry.execute(
        _step(
            "sandbox.network.loopback.v1",
            "simulation.sandbox.network.loopback.v1",
            {"port": 4317},
        ),
        bound_inputs={"bundle": {"content_hash": digest}},
    )
    assert result.artifacts["receipt"]["would_send"] == digest

    with pytest.raises(SimulationError, match="bundle.content_hash must be a non-empty digest"):
        registry.execute(
            _step("sandbox.network.loopback.v1", "simulation.sandbox.network.loopback.v1"),
            bound_inputs={"bundle": {}},
        )


@pytest.mark.parametrize("value", [True, 0, 101, "3"])
def test_fixture_create_simulation_rejects_coercible_or_out_of_range_counts(
    value: object,
) -> None:
    with pytest.raises(SimulationError, match="record_count must be an integer"):
        SimulationRegistry().execute(
            _step(
                "sandbox.fixture.create.v1",
                "simulation.sandbox.fixture.create.v1",
                {"record_count": value},
            ),
            bound_inputs={},
        )


@pytest.mark.parametrize(
    ("action_id", "simulation_id", "parameters", "bound_inputs", "message"),
    [
        (
            "sandbox.fixture.transform.v1",
            "simulation.sandbox.fixture.transform.v1",
            {"redact_values": "true"},
            {
                "workspace": {
                    "fixture_path": "synthetic/fixtures/input.jsonl",
                    "record_count": 3,
                    "content_hash": "sha256:source",
                }
            },
            "redact_values must be a boolean",
        ),
        (
            "sandbox.collection.stage.v1",
            "simulation.sandbox.collection.stage.v1",
            {"bundle_format": "yaml"},
            {
                "records": [
                    {
                        "path": "synthetic/fixtures/transformed.jsonl",
                        "kind": "file",
                        "record_count": 3,
                        "content_hash": "sha256:source",
                    }
                ]
            },
            "bundle_format is not a reviewed choice",
        ),
        (
            "sandbox.network.loopback.v1",
            "simulation.sandbox.network.loopback.v1",
            {"port": 1023},
            {"bundle": {"content_hash": "sha256:bundle"}},
            "port must be an integer",
        ),
    ],
)
def test_semantic_simulations_reject_unreviewed_parameter_shapes(
    action_id: str,
    simulation_id: str,
    parameters: Mapping[str, Any],
    bound_inputs: Mapping[str, Any],
    message: str,
) -> None:
    with pytest.raises(SimulationError, match=message):
        SimulationRegistry().execute(
            _step(action_id, simulation_id, parameters),
            bound_inputs=bound_inputs,
        )
