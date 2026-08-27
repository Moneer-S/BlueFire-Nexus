from __future__ import annotations

from pathlib import Path

from bluefire.contracts import load_scenario

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = ROOT / "scenarios"
PACKAGED_SCENARIO_ROOT = ROOT / "bluefire" / "data"


def test_packaged_defaults_match_checkout_examples() -> None:
    pairs = [
        (
            ROOT / "config" / "bluefire.example.yaml",
            ROOT / "bluefire" / "data" / "bluefire.example.yaml",
        )
    ]
    pairs.extend(
        (scenario, ROOT / "bluefire" / "data" / scenario.name)
        for scenario in sorted((ROOT / "scenarios").glob("*.yaml"))
    )
    for checkout, packaged in pairs:
        assert packaged.read_bytes() == checkout.read_bytes()


def test_product_ships_seven_scenarios_in_both_resource_trees() -> None:
    checkout_names = {path.name for path in SCENARIO_ROOT.glob("*.yaml")}
    packaged_names = {
        path.name for path in PACKAGED_SCENARIO_ROOT.glob("*.yaml") if path.name in checkout_names
    }

    assert len(checkout_names) == 7
    assert packaged_names == checkout_names
    assert "operator_representative_validation.yaml" in checkout_names


def test_operator_scenario_keeps_the_reviewed_ten_step_order() -> None:
    scenario = load_scenario(SCENARIO_ROOT / "operator_representative_validation.yaml")
    assert scenario.id == "scenario.operator.representative-validation.v1"
    assert tuple(step.behavior_id for step in scenario.steps) == (
        "sandbox.execution.native-canary.v1",
        "sandbox.identity-material.seed.v1",
        "sandbox.identity-material.inspect.v1",
        "sandbox.fixture.create.v1",
        "sandbox.fixture.transform.v1",
        "sandbox.discovery.metadata.v1",
        "sandbox.collection.stage.v1",
        "sandbox.observability.variant.v1",
        "sandbox.peer.handoff.v1",
        "sandbox.cleanup.v1",
    )
    peer_bundle = scenario.step("handoff_to_peer").inputs["bundle"]
    assert (peer_bundle.from_step, peer_bundle.artifact) == ("stage_records", "bundle")
