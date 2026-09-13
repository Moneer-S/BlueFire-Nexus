"""Mocked provider work validates exact contextual edits; no target effects or model calls."""

import copy
import json
import threading

import pytest

from bluefire.ai_assistance import PURPOSE as ASSISTANCE
from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.contracts import ContractError, SourceProvenance, load_scenario
from bluefire.graph_ai_edit import PURPOSE
from bluefire.util import content_hash
from tests_platform.test_graph_ai_jobs import ROOT, acceptance, proposed
from tests_platform.test_graph_ai_jobs import setup as setup


def selected():
    graph = load_scenario(ROOT / "scenarios/endpoint_lab_collection_methods.yaml").to_dict()
    graph["title"] = "Unsaved operator graph"
    # A field unrelated to the requested edit must never enter model context.
    graph["steps"][2]["parameters"]["record_limit"] = 13
    return {
        "kind": "graph",
        "base_scenario": None,
        "edit_step": {"scenario": graph, "step_id": "create_fixture", "dirty": True},
    }


def configure(service, access, body, monkeypatch, output=None):
    context = service.assistance_graph_context(selected=selected())
    body.update(
        selection=context["selected"],
        context_digest=context["context_digest"],
        message="Use six records in the selected step.",
    )
    original = access.post
    supplied = []

    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        payload = json.loads(wire.get("input") or wire["messages"][1]["content"])
        supplied.append((purpose, payload))
        if purpose == ASSISTANCE:
            return original(
                config, body=body, timeout_seconds=timeout_seconds, cancel_event=cancel_event
            )
        assert purpose == PURPOSE
        access.calls.append(purpose)
        access.entered.set()
        if access.hold is not None:
            assert access.hold.wait(10)
        if cancel_event is not None and cancel_event.is_set():
            raise AIProviderCancelled()
        result = (
            output
            if output is not None
            else {
                "parameters": [{"name": "record_count", "value": 6}],
                "rationale": "Six bounded records address the objective.",
                "assumptions": ["Requires native review."],
            }
        )
        encoded = result if isinstance(result, str) else json.dumps(result)
        response = {"id": "mock-step-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": encoded},
                    }
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=encoded,
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    monkeypatch.setattr(access, "post", post)
    return context, supplied


def test_dirty_selected_step_preserves_full_graph_requires_review_and_retries_exactly(
    setup, monkeypatch
):
    service, access, body = setup
    context, supplied = configure(service, access, body, monkeypatch)
    parent, child, proposal = proposed(service, body)
    assert proposal["edit_source"]["digest"] == content_hash(selected()["edit_step"]["scenario"])
    restored = copy.deepcopy(proposal["scenario"])
    restored["id"] = selected()["edit_step"]["scenario"]["id"]
    assert restored["steps"][0]["parameters"]["record_count"] == 6
    restored["steps"][0]["parameters"]["record_count"] = 8
    assert restored == selected()["edit_step"]["scenario"]
    assert (
        len(restored["steps"]) > 8
    )  # Context editing does not truncate a graph to new-draft bounds.
    for _, payload in supplied:
        assert "discover_processes" not in json.dumps(payload)
        assert "record_limit" not in json.dumps(payload)
        assert "edges" not in json.dumps(payload)
    assert len(supplied) == 2
    assert service.graph_ai_job(child["job_id"])["application"] is None
    decision = acceptance(proposal)
    saved = service.review_graph_ai(child["job_id"], decision)
    assert service.review_graph_ai(child["job_id"], decision) == saved
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert access.calls == [ASSISTANCE, PURPOSE]
    assert (
        service.product_store.get_scenario(saved["application"]["scenario_id"])["document"]
        == proposal["scenario"]
    )
    assert context["selected"]["base_scenario"] is None


@pytest.mark.parametrize(
    "mutation", ["other_step", "route", "input", "method", "purpose", "authority"]
)
def test_native_step_review_refuses_nonparameter_mutations(setup, monkeypatch, mutation):
    service, access, body = setup
    configure(service, access, body, monkeypatch)
    _, child, proposal = proposed(service, body)
    changed = copy.deepcopy(proposal["scenario"])
    if mutation == "other_step":
        changed["steps"][2]["parameters"]["record_limit"] = 14
    elif mutation == "route":
        changed["edges"].pop()
    elif mutation == "input":
        changed["steps"][-1]["inputs"] = {}
    elif mutation == "method":
        changed["steps"][0]["behavior_id"] = "sandbox.cleanup.v1"
    elif mutation == "purpose":
        changed["purpose"] += " changed"
    else:
        changed["approval"] = True
    with pytest.raises(APIError):
        service.review_graph_ai(child["job_id"], acceptance(proposal, changed))
    assert service.graph_ai_job(child["job_id"])["application"] is None


@pytest.mark.parametrize(
    "patch",
    [
        [{"name": "record_count", "value": True}],
        [{"name": "record_count", "value": 999999}],
        [{"name": "command", "value": "execute"}],
        [{"name": "record_count", "value": 6}, {"name": "record_count", "value": 7}],
    ],
)
def test_invalid_provider_patch_fails_without_publication(setup, monkeypatch, patch):
    service, access, body = setup
    configure(
        service,
        access,
        body,
        monkeypatch,
        {"parameters": patch, "rationale": "Change", "assumptions": []},
    )
    parent = service.submit_assistance_turn(body)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "failed"
    assert service.graph_ai_job(child["job_id"])["proposal"] is None


def test_changed_source_cannot_reuse_prepared_context_and_post_is_read_only(setup):
    from tests_platform.test_api import request, running_server

    service, access, body = setup
    original = selected()
    with running_server(service, max_request_body=262144) as (server, _):
        status, _, raw = request(server, "POST", "/api/v1/assistance/graph-context", body=original)
        assert status == 200, raw
        context = json.loads(raw)
        body.update(selection=copy.deepcopy(original), context_digest=context["context_digest"])
        body["selection"]["edit_step"]["scenario"]["steps"][2]["parameters"]["record_limit"] = 14
        status, _, raw = request(server, "POST", "/api/v1/assistance/turns", body=body)
        assert status == 202, raw
        job = service.job_controller.wait(json.loads(raw)["job"]["job_id"], timeout=15)
        assert job["state"] == "failed"
        assert "changed" in job["progress"]["operation_error"]
    assert not access.calls


def test_contextual_patch_cancellation_retains_uuid_without_publication(setup, monkeypatch):
    service, access, body = setup
    configure(service, access, body, monkeypatch)
    access.hold = threading.Event()
    parent = service.submit_assistance_turn(body)["job"]
    assert access.entered.wait(10)
    service.cancel_job(parent["job_id"])
    access.hold.set()
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "cancelled"
    assert service.graph_ai_job(child["job_id"])["proposal"] is None
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert access.calls == [ASSISTANCE, PURPOSE]


def test_optional_provenance_notes_round_trip_without_weakening_required_fields():
    original = {"source": "fixture", "reference": "fixture", "license": "MIT", "derived": True}
    document = SourceProvenance.from_mapping(original).to_dict()
    assert document["notes"] == ""
    assert SourceProvenance.from_mapping(document).to_dict() == document
    for field in ("source", "reference", "license"):
        with pytest.raises(ContractError):
            SourceProvenance.from_mapping({**document, field: ""})


def test_duplicate_provider_fields_do_not_publish_a_step_proposal(setup, monkeypatch):
    service, access, body = setup
    configure(
        service,
        access,
        body,
        monkeypatch,
        '{"parameters":[{"name":"record_count","value":5}],"parameters":[{"name":"record_count","value":6}],"rationale":"Change","assumptions":[]}',
    )
    parent = service.submit_assistance_turn(body)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "failed"
    assert service.graph_ai_job(child["job_id"])["proposal"] is None
