"""Durable engine-experiment explanations use saved summaries and no capabilities."""

import copy
import json

import pytest

from bluefire.ai_assistance import GRAPH, PURPOSE
from bluefire.application_errors import APIError
from bluefire.engine_experiment_service import EngineExperimentServiceError
from bluefire.util import content_hash
from tests_platform.test_engine_experiment_assistance import _context, _workspace
from tests_platform.test_graph_ai_jobs import setup as setup


@pytest.fixture
def explanation(setup, monkeypatch):
    service, access, body = setup
    experiment, workspace, selected = _workspace("engine_attempt")
    captured = _context(experiment, workspace, selected)
    current = {"value": copy.deepcopy(captured)}

    def engine_context(experiment_id, selection):
        if experiment_id != selected["experiment_id"] or selection != selected:
            raise EngineExperimentServiceError(
                "engine_assistance_context_unavailable", "Saved context changed."
            )
        return copy.deepcopy(current["value"])

    monkeypatch.setattr(
        service.engine_experiment_service, "assistance_context_request", engine_context
    )
    body.update(
        selection=copy.deepcopy(selected),
        context_digest=captured["context_digest"],
        message="Explain the saved engine experiment evidence and unknowns.",
    )
    supplied, options = [], {"steps": [], "after": lambda: None}

    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        assert purpose == PURPOSE
        access.calls.append(purpose)
        supplied.append(json.loads(wire.get("input") or wire["messages"][1]["content"]))
        options["after"]()
        output = json.dumps(
            {
                "message": "Saved engine assertions remain separate from independent observations.",
                "steps": options["steps"],
            }
        )
        response = {"id": "engine-context-unit-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": output}}
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=output,
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    monkeypatch.setattr(access, "post", post)
    return service, access, body, captured, current, supplied, options


def finished(service, body):
    value = service.submit_assistance_turn(body)
    service.job_controller.wait(value["job"]["job_id"], timeout=15)
    return service.assistance_turn(value["job"]["job_id"])


@pytest.mark.parametrize("autonomy", ["assist", "auto", "off"])
def test_durable_engine_explanation_has_no_capabilities_or_children(explanation, autonomy):
    service, access, body, captured, _, supplied, _ = explanation
    body["autonomy"] = autonomy
    result = finished(service, body)

    assert result["job"]["state"] == "completed"
    assert result["turn"]["status"] == ("off" if autonomy == "off" else "completed")
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert result["job"]["request"]["context"] == captured
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == ([] if autonomy == "off" else [PURPOSE])
    if supplied:
        assert supplied[0]["selected"] == captured["selected"]
        assert supplied[0]["reference_summary"]["proof_scope"] == "saved_engine_experiment_only"
        assert (
            supplied[0]["reference_summary"]["provider"]
            == captured["reference_summary"]["provider"]
        )
        assert supplied[0]["reference_summary"]["selected_record"]["kind"] == "engine_attempt"
        assert supplied[0]["capabilities"] == []
        serialized = json.dumps(supplied[0], sort_keys=True)
        for private in ("artifact_manifest", "raw_output", "sk-this-must-never-appear"):
            assert private not in serialized
    assert not result["job"]["progress"].get("children")


def test_provider_cannot_forge_engine_execution_or_plan(explanation):
    service, access, body, _, _, _, options = explanation
    options["steps"] = [
        {"capability_id": GRAPH, "detector_ref": "none", "reason": "Run another graph."}
    ]
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["turn"]["results"] == [] and result["turn"]["active_child"] is None
    assert access.calls == [PURPOSE] and not result["job"]["progress"].get("children")


def test_tampered_engine_selection_is_refused_before_provider(explanation):
    service, access, body, *_ = explanation
    body["selection"] = {**body["selection"], "raw_output": "unsupported"}
    with pytest.raises(APIError, match="exact saved engine-experiment"):
        service.submit_assistance_turn(body)
    assert access.calls == []


def test_newer_valid_engine_context_is_refused_before_provider(explanation):
    service, access, body, captured, current, *_ = explanation
    changed = copy.deepcopy(captured)
    changed["reference_summary"]["workflow_state"] = "review_defense"
    changed["context_digest"] = content_hash(
        {key: value for key, value in changed.items() if key != "context_digest"}
    )
    current["value"] = changed

    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["turn"]["active_child"] is None and access.calls == []


def test_changed_context_withholds_provider_answer_and_reopens_blocked(explanation):
    service, access, body, captured, current, _, options = explanation

    def change_after_provider():
        changed = copy.deepcopy(captured)
        changed["reference_summary"]["workflow_state"] = "review_defense"
        changed["context_digest"] = content_hash(
            {key: value for key, value in changed.items() if key != "context_digest"}
        )
        current["value"] = changed

    options["after"] = change_after_provider
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["job"]["request"]["context"] == captured
    assert "Saved engine assertions" not in json.dumps(result["job"]["progress"])
    assert result["turn"]["active_child"] is None and access.calls == [PURPOSE]
    reopened = service.assistance_turn(result["job"]["job_id"])
    assert reopened["turn"]["status"] == "blocked" and access.calls == [PURPOSE]
