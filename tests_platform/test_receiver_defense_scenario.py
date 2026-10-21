from pathlib import Path

from bluefire.contracts import load_scenario
from bluefire.receiver_defense_workflow import redaction_step
from tests_platform.test_receiver_defense_jobs import setup as setup

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "scenarios" / "receiver_defense_validation.yaml"


def test_packaged_receiver_validation_scenario_is_retained_redaction_eligible(setup):
    service, access, runner, sessions, base_request = setup
    scenario = load_scenario(SCENARIO_PATH)
    document = scenario.to_dict()
    service.registry.validate_scenario(scenario)

    assert scenario.id == "scenario.receiver-defense.redaction-validation.v1"
    assert any(item["id"] == scenario.id for item in service.scenarios()["scenarios"])
    handoff = next(step for step in document["steps"] if step["id"] == "handoff_to_receiver")
    assert (
        redaction_step(
            document,
            {
                "stage_step_id": handoff["inputs"]["bundle"]["from_step"],
                "handoff_step_id": handoff["id"],
            },
        )
        == "transform_fixture"
    )

    saved = service.save_scenario_version({"scenario": document})["scenario"]
    request = {
        **base_request,
        "selection": {
            "kind": "saved_scenario",
            "scenario_id": saved["scenario_id"],
            "version": saved["version"],
            "digest": saved["digest"],
        },
        "workflow": "retained_redaction",
    }
    context = service.receiver_defense_context(request)

    assert context["eligible"], context["reasons"]
    assert context["control"]["redaction_step_id"] == "transform_fixture"
    assert context["handoff"]["stage_step_id"] == "stage_records"
    assert not sessions and not access.calls and runner.execute_calls == 0
