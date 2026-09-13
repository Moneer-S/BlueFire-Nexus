"""Receiver planning and enrollment contracts; no service or provider effects."""

import copy
import json
import threading

import pytest

from bluefire.ai_assistance import (
    COMPARE,
    CREATE,
    GRAPH,
    RECEIVER_INSPECT,
    RECEIVER_TEST,
    REVISE,
    RUN,
    suggest_plan,
    validate_plan,
)
from bluefire.ai_assistance import (
    OUTPUT_SCHEMA as PLANNER_SCHEMA,
)
from bluefire.ai_receiver_inspection import OUTPUT_SCHEMA, PURPOSE, format_request
from bluefire.ai_wire import AIProviderError, AIProviderTransportError
from bluefire.prepared_lab_enrollment import enroll, enrollment_document, read_enrollment
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ai_receiver_inspection import Access, phases, provider

__all__ = ["provider"]


def capabilities(*ids):
    return {name: {"id": name, "title": name, "available": True} for name in ids}


def step(capability, detector_ref="none"):
    return {
        "capability_id": capability,
        "detector_ref": detector_ref,
        "reason": "Use native review.",
    }


@pytest.mark.parametrize("capability", [RECEIVER_TEST, RECEIVER_INSPECT])
def test_both_dialects_plan_only_supplied_receiver_capability(provider, capability):
    context = {
        "selected": {
            "kind": "receiver_scenario" if capability == RECEIVER_TEST else "receiver_test"
        },
        "capabilities": list(capabilities(capability).values()),
        "limitations": ["Unit contract; no receiver effect occurred."],
    }
    before = copy.deepcopy(context)
    access = Access(
        value={"message": "Use the native receiver review.", "steps": [step(capability)]}
    )
    result = suggest_plan(
        config=provider,
        access=access,
        context=context,
        message="Compare this saved receiver test.",
        cancel=threading.Event(),
    )
    assert len(access.calls) == 1
    assert result["plan"] == [{"step_id": "step-1", **step(capability), "title": capability}]
    body = json.loads(access.calls[0][1])
    schema = body.get("text", {}).get("format") or body["response_format"]["json_schema"]
    assert schema["schema"] == PLANNER_SCHEMA and schema["strict"] is True
    instructions = body.get("instructions") or body["messages"][0]["content"]
    assert "no-effect test owner" in instructions
    assert "separate explicit native action with effects" in instructions
    assert (
        "every receiver phase Execute needs its own fresh ordinary native approval" in instructions
    )
    assert "Assistant Auto does not waive" in instructions
    assert body.get("tools", []) == [] and body.get("tool_choice", "none") == "none"
    assert context == before


@pytest.mark.parametrize("capability", [RECEIVER_TEST, RECEIVER_INSPECT])
@pytest.mark.parametrize("reference", ["selected", "revised", "invented", None])
def test_receiver_plan_requires_no_detector_reference(capability, reference):
    with pytest.raises(AIProviderError):
        validate_plan(
            {"message": "Plan", "steps": [step(capability, reference)]}, capabilities(capability)
        )


@pytest.mark.parametrize("capability", [RECEIVER_TEST, RECEIVER_INSPECT])
@pytest.mark.parametrize(
    "other", [REVISE, COMPARE, GRAPH, RUN, CREATE, RECEIVER_TEST, RECEIVER_INSPECT]
)
@pytest.mark.parametrize("reverse", [False, True])
def test_receiver_cannot_be_combined_or_repeated(capability, other, reverse):
    steps = [step(capability), step(other, "selected" if other in {REVISE, COMPARE} else "none")]
    with pytest.raises(AIProviderError):
        validate_plan(
            {"message": "Plan", "steps": steps[::-1] if reverse else steps},
            capabilities(capability, other),
        )


@pytest.mark.parametrize("capability", [RECEIVER_TEST, RECEIVER_INSPECT])
@pytest.mark.parametrize("unavailable", ["missing", "false"])
def test_receiver_capability_is_not_exposed_without_application_availability(
    capability, unavailable
):
    offered = capabilities(capability) if unavailable == "false" else {}
    if offered:
        offered[capability]["available"] = False
    with pytest.raises(AIProviderError):
        validate_plan({"message": "Plan", "steps": [step(capability)]}, offered)


def test_unknown_capability_is_not_admitted_even_if_context_accidentally_offers_it():
    with pytest.raises(AIProviderError):
        validate_plan(
            {"message": "Plan", "steps": [step("receiver.execute_without_review")]},
            capabilities("receiver.execute_without_review"),
        )


def test_existing_plan_composition_and_empty_advice_remain_supported():
    steps = [step(REVISE, "selected"), step(COMPARE, "revised")]
    result = validate_plan({"message": "Plan", "steps": steps}, capabilities(REVISE, COMPARE))
    assert [item["capability_id"] for item in result["plan"]] == [REVISE, COMPARE]
    for capability in (GRAPH, RUN, CREATE):
        assert (
            validate_plan(
                {"message": "Plan", "steps": [step(capability)]}, capabilities(capability)
            )["plan"][0]["capability_id"]
            == capability
        )
    assert validate_plan({"message": "No available action", "steps": []}, {})["plan"] == []


def test_both_dialects_enroll_exact_receiver_schema_and_keep_existing_purposes(provider):
    enrollment = enroll(provider, "explicit_endpoint")
    body = format_request(provider, phases=phases(), offered_next_phase="protected")
    assert enrollment.validate_body(body) == (PURPOSE, content_hash(OUTPUT_SCHEMA))
    assert tuple(name for name, _ in enrollment.schemas) == (
        "bluefire_ai_graph_draft",
        "bluefire_ai_proposal",
        "bluefire_connection_check",
        "bluefire_detection_source_creation",
        "bluefire_detection_source_revision",
        "bluefire_experiment_assistance",
        "bluefire_graph_step_edit",
        "bluefire_method_comparison",
        "bluefire_receiver_defense_inspection",
        "bluefire_run_evidence_inspection",
    )
    assert ("bluefire_experiment_assistance", content_hash(PLANNER_SCHEMA)) in enrollment.schemas
    assert read_enrollment(enrollment_document(enrollment)) == enrollment
    assert enrollment.config == provider


@pytest.mark.parametrize("change", ["schema", "purpose", "tools", "tokens", "strict", "model"])
def test_receiver_enrollment_rejects_modified_contract_without_transport(provider, change):
    enrollment = enroll(provider, "explicit_endpoint")
    body = json.loads(format_request(provider, phases=phases(), offered_next_phase=None))
    spec = body.get("text", {}).get("format") or body["response_format"]["json_schema"]
    if change == "schema":
        spec["schema"]["properties"]["next_phase"]["enum"].append("baseline")
    elif change == "purpose":
        spec["name"] = "receiver.execute_without_review"
    elif change == "tools":
        body["tools"] = [{"type": "function", "name": "prepare_receiver"}]
    elif change == "tokens":
        body["max_output_tokens" if "input" in body else "max_completion_tokens"] = (
            provider.max_output_tokens + 1
        )
    elif change == "strict":
        spec["strict"] = False
    elif change == "model":
        body["model"] = "unselected-model"
    with pytest.raises(AIProviderTransportError):
        enrollment.validate_body(canonical_json_bytes(body))
