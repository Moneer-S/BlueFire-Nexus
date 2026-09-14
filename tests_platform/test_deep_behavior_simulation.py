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
        step_id="deep-behavior-step",
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


def _bundle(*, bundle_format: str = "jsonl", size: int = 129) -> dict[str, Any]:
    return {
        "type": "artifact.sandbox.bundle.v1",
        "path": f"synthetic/staged/bundle.{bundle_format}",
        "content_hash": content_hash({"fixture": "public", "format": bundle_format}),
        "size": size,
    }


@pytest.mark.parametrize(
    ("behavior_id", "simulation_id", "telemetry"),
    [
        (
            "sandbox.credential.peer-challenge.v1",
            "simulation.sandbox.credential.peer-challenge.v1",
            "sandbox.credential.peer_challenge_attempted",
        ),
        (
            "sandbox.peer.handoff.v1",
            "simulation.sandbox.peer.handoff.v1",
            "sandbox.peer.handoff_attempted",
        ),
    ],
)
def test_peer_simulations_are_typed_and_never_claim_a_transfer(
    behavior_id: str, simulation_id: str, telemetry: str
) -> None:
    bundle = _bundle()
    result = SimulationRegistry().execute(
        _step(
            behavior_id,
            simulation_id,
            {"port": 4318},
        ),
        bound_inputs={"bundle": bundle},
    )

    assert result.outcome is StepOutcome.SUCCESS
    assert result.telemetry == (telemetry,)
    assert result.details["side_effects_started"] is False
    receipt = result.artifacts["receipt"]
    assert receipt["type"] == "artifact.sandbox.peer-handoff.receipt.v2"
    assert receipt["transport"] == "simulated_authenticated_loopback"
    assert receipt["artifact"] == bundle["path"]
    assert receipt["content_hash"] == bundle["content_hash"]
    assert receipt["size"] == bundle["size"]
    assert receipt["destination"] == {"host": "127.0.0.1", "port": 4318}
    assert receipt["would_authenticate"] is True
    assert receipt["receiver_stored"] is False
    assert receipt["synthetic"] is True
    assert receipt["lab_authorization"]["challenge_verified"] is False
    assert receipt["lab_authorization"]["raw_credential_exposed"] is False
    assert len(receipt["lab_authorization"]["credential_handle"]) == 64
    assert receipt["lab_peers"]["distinct_processes"] is False
    assert receipt["lab_peers"]["source_process_id"] is None
    assert receipt["lab_peers"]["destination_process_id"] is None
    assert receipt["lab_peers"]["receiver_mode"] == "disposable_peer"
    assert receipt["lab_peers"]["transfer_acknowledged"] is False
    assert any("No peer was contacted" in item for item in result.limitations)


@pytest.mark.parametrize("representation", ["canonical", "chunked_hex"])
def test_observability_variant_simulation_preserves_bounded_equivalence_metadata(
    representation: str,
) -> None:
    bundle = _bundle(size=129)
    result = SimulationRegistry().execute(
        _step(
            "sandbox.observability.variant.v1",
            "simulation.sandbox.observability.variant.v1",
            {"representation": representation},
        ),
        bound_inputs={"bundle": bundle},
    )

    variant = result.artifacts["variant"]
    encoded_size = int(bundle["size"]) * 2
    expected_size = encoded_size + (
        (encoded_size - 1) // 64 if representation == "chunked_hex" else 0
    )
    assert result.outcome is StepOutcome.SUCCESS
    assert result.telemetry == ("sandbox.observability.variant_created",)
    assert result.details["side_effects_started"] is False
    assert variant["path"] == "synthetic/observability/variant.bin"
    assert variant["representation"] == representation
    assert variant["source_path"] == bundle["path"]
    assert variant["source_content_hash"] == bundle["content_hash"]
    assert variant["source_size"] == bundle["size"]
    assert variant["size"] == expected_size
    assert variant["equivalence_verified"] is True
    assert variant["synthetic"] is True
    assert variant["content_hash"].startswith("sha256:")
    assert any("No representation file was created" in item for item in result.limitations)


@pytest.mark.parametrize(
    ("action_id", "simulation_id", "parameters", "message"),
    [
        (
            "sandbox.peer.handoff.v1",
            "simulation.sandbox.peer.handoff.v1",
            {"port": 4317, "host": "127.0.0.1"},
            "peer handoff simulation contains unreviewed parameters",
        ),
        (
            "sandbox.observability.variant.v1",
            "simulation.sandbox.observability.variant.v1",
            {"representation": "compressed"},
            "representation is not a reviewed choice",
        ),
    ],
)
def test_new_simulation_adapters_reject_unreviewed_shapes(
    action_id: str,
    simulation_id: str,
    parameters: Mapping[str, Any],
    message: str,
) -> None:
    with pytest.raises(SimulationError, match=message):
        SimulationRegistry().execute(
            _step(action_id, simulation_id, parameters),
            bound_inputs={"bundle": _bundle()},
        )


@pytest.mark.parametrize(
    "bundle",
    [
        {},
        {
            "type": "artifact.sandbox.bundle.v1",
            "path": "synthetic/staged/bundle.jsonl",
            "content_hash": "sha256:short",
            "size": 1,
        },
        {
            "type": "artifact.sandbox.bundle.v1",
            "path": "synthetic/elsewhere/bundle.jsonl",
            "content_hash": content_hash({"fixture": "public"}),
            "size": 1,
        },
    ],
)
def test_new_simulation_adapters_require_the_fixed_typed_bundle(
    bundle: Mapping[str, Any],
) -> None:
    with pytest.raises(SimulationError):
        SimulationRegistry().execute(
            _step(
                "sandbox.peer.handoff.v1",
                "simulation.sandbox.peer.handoff.v1",
            ),
            bound_inputs={"bundle": bundle},
        )
