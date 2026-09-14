"""Actual durable graph capability through both provider dialects, without effects."""

import copy
import json
import threading
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from bluefire.ai_assistance import PURPOSE
from bluefire.ai_provider_access import ProviderReadiness
from bluefire.ai_wire import AIProviderCancelled
from bluefire.application_errors import APIError
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.graph_ai_context import GRAPH
from bluefire.product_store_errors import ProductStoreError
from bluefire.service import BlueFireService
from bluefire.util import content_hash
from tests_platform.ai_live_authorization_support import authorize_service
from tests_platform.test_ai_drafts import _model_draft

ROOT = Path(__file__).resolve().parents[1]


class Access:
    def __init__(self):
        self.calls = []
        self.hold = None
        self.entered = threading.Event()
        self.invalid = False

    def readiness(self, config):
        return ProviderReadiness(True, "not_required", "ready", "Pure registered graph fixture")

    def post(self, config, *, body, timeout_seconds, cancel_event=None):
        request = json.loads(body)
        purpose = (
            request.get("text", {}).get("format") or request["response_format"]["json_schema"]
        )["name"]
        self.calls.append(purpose)
        if purpose == PURPOSE:
            output = {
                "message": "Create a separate registered proposal for native review.",
                "steps": [
                    {
                        "capability_id": GRAPH,
                        "detector_ref": "none",
                        "reason": "Use the current registered catalog.",
                    }
                ],
            }
        else:
            assert purpose == "bluefire_ai_graph_draft"
            self.entered.set()
            if self.hold is not None:
                assert self.hold.wait(10)
            if cancel_event is not None and cancel_event.is_set():
                raise AIProviderCancelled()
            output = {"unregistered": True} if self.invalid else _model_draft()
        response = {"id": "graph-unit-response", "model": config.model}
        if config.kind.value == "chat_completions":
            response.update(
                choices=[
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(output)},
                    }
                ],
                usage={"prompt_tokens": 20, "completion_tokens": 40},
            )
        else:
            response.update(
                status="completed",
                output_text=json.dumps(output),
                usage={"input_tokens": 20, "output_tokens": 40},
            )
        return json.dumps(response).encode()

    def close(self):
        pass


@pytest.fixture(params=["openai_responses", "chat_completions"])
def setup(tmp_path, request):
    access = Access()
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(
        {
            "id": "provider.graph-test.v1",
            "kind": request.param,
            "model": "unit-model",
            "endpoint": "http://127.0.0.1:8765/v1/"
            + ("responses" if request.param == "openai_responses" else "chat/completions"),
        }
    )
    service._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        service.config.ai.fallback_provider,
        (provider, *service.config.ai.providers),
    )
    authorize_service(service, provider)
    context = service.assistance_graph_context()
    body = {
        "submission_id": str(uuid.uuid4()),
        "selection": context["selected"],
        "context_digest": context["context_digest"],
        "message": "Propose a registered fixture experiment for review.",
        "autonomy": "assist",
        "provider_id": provider.id,
    }
    yield service, access, body
    if access.hold is not None:
        access.hold.set()
    service.close()


def proposed(service, body):
    parent = service.submit_assistance_turn(body)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    assert parent["state"] == "completed", parent
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "completed", child
    return parent, child, service.graph_ai_job(child["job_id"])["proposal"]


def acceptance(proposal, scenario=None):
    scenario = copy.deepcopy(scenario or proposal["scenario"])
    return {
        "decision": "accept",
        "proposal_digest": proposal["proposal_digest"],
        "scenario": scenario,
        "reviewed_digest": content_hash(scenario),
    }


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_graph_journey_requires_native_review_and_retains_exact_separate_save(setup, autonomy):
    service, access, body = setup
    body["autonomy"] = autonomy
    parent, child, proposal = proposed(service, body)
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["selected"] == {"kind": "graph", "base_scenario": None}
    assert view["status"] == "awaiting_review" and view["next_action"]["kind"] == "review_graph"
    with pytest.raises(ProductStoreError):
        service.product_store.get_scenario(proposal["scenario"]["id"])
    edited = copy.deepcopy(proposal["scenario"])
    edited["title"] = "Operator reviewed title"
    body_review = acceptance(proposal, edited)
    receipt = service.review_graph_ai(child["job_id"], body_review)["application"]
    assert receipt["operator_modified"] is True and receipt["version"] == 1
    assert service.review_graph_ai(child["job_id"], body_review)["application"] == receipt
    assert service.graph_ai_job(child["job_id"])["proposal"] == proposal
    view = service.assistance_turn(parent["job_id"])["turn"]
    assert view["status"] == "completed" and view["results"][0]["execution_state"] == "not_run"
    assert view["results"][0]["kind"] == "graph_saved"
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]
    assert service.store.list_runs() == []


def test_off_admission_and_failed_provider_never_fallback_or_save(setup):
    service, access, body = setup
    off = {**body, "autonomy": "off"}
    parent = service.submit_assistance_turn(off)["job"]
    service.job_controller.wait(parent["job_id"], timeout=15)
    assert (
        service.assistance_turn(parent["job_id"])["turn"]["status"] == "off" and access.calls == []
    )
    access.invalid = True
    body["submission_id"] = str(uuid.uuid4())
    parent = service.submit_assistance_turn(body)["job"]
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "failed" and "proposal" not in child["progress"]
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]


@pytest.mark.parametrize("change", ["provider", "catalog", "base"])
def test_acceptance_refuses_changed_authoritative_context(setup, change, monkeypatch):
    service, _, body = setup
    if change == "base":
        saved = service.product_store.list_scenarios()[0]
        selected = {key: saved[key] for key in ("scenario_id", "version", "digest")}
        context = service.assistance_graph_context(selected)
        body.update(selection=context["selected"], context_digest=context["context_digest"])
    _, child, proposal = proposed(service, body)
    if change == "provider":
        config = service._runtime_ai_config
        service._runtime_ai_config = replace(
            config,
            providers=tuple(
                (
                    replace(provider, model="changed")
                    if provider.id == body["provider_id"]
                    else provider
                )
                for provider in config.providers
            ),
        )
    elif change == "catalog":
        snapshot = service._catalog_snapshot
        replacement = copy.copy(snapshot.registry)
        old = replacement.get_behavior
        monkeypatch.setattr(
            replacement,
            "get_behavior",
            lambda identifier: replace(old(identifier), title=old(identifier).title + " changed"),
        )
        monkeypatch.setattr(
            service,
            "_load_action_catalog_snapshot",
            lambda *args: replace(snapshot, registry=replacement),
        )
    else:
        changed = copy.deepcopy(saved["document"])
        changed["title"] += " manually changed"
        service.product_store.save_scenario(changed)
    with pytest.raises((APIError, ProductStoreError)):
        service.review_graph_ai(child["job_id"], acceptance(proposal))
    assert service.graph_ai_job(child["job_id"])["application"] is None


def test_parent_stop_during_provider_and_after_proposal_prevents_save(setup):
    service, access, body = setup
    access.hold = threading.Event()
    parent = service.submit_assistance_turn(body)["job"]
    assert access.entered.wait(10)
    assert service.active_jobs()["jobs"] == []
    service.cancel_job(parent["job_id"])
    access.hold.set()
    parent = service.job_controller.wait(parent["job_id"], timeout=15)
    child = service.job_controller.wait(
        parent["progress"]["children"]["step-1"]["job_id"], timeout=15
    )
    assert child["state"] == "cancelled" and "proposal" not in child["progress"]
    body["submission_id"] = str(uuid.uuid4())
    parent, child, proposal = proposed(service, body)
    service.cancel_job(parent["job_id"])
    with pytest.raises((APIError, ProductStoreError)):
        service.review_graph_ai(child["job_id"], acceptance(proposal))


def test_atomic_save_rolls_back_if_receipt_write_fails(setup, monkeypatch):
    import bluefire.graph_ai_jobs as module

    service, access, body = setup
    _, child, proposal = proposed(service, body)
    original = module.patch

    def fail_receipt(*args):
        raise RuntimeError("bounded commit fault")

    monkeypatch.setattr(module, "patch", fail_receipt)
    with pytest.raises(RuntimeError, match="bounded commit fault"):
        service.review_graph_ai(child["job_id"], acceptance(proposal))
    with pytest.raises(ProductStoreError):
        service.product_store.get_scenario(proposal["scenario"]["id"])
    monkeypatch.setattr(module, "patch", original)
    assert (
        service.review_graph_ai(child["job_id"], acceptance(proposal))["application"]["version"]
        == 1
    )
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]


def test_validate_is_read_only_and_reject_is_final_without_save(setup):
    service, access, body = setup
    parent, child, proposal = proposed(service, body)
    edit = copy.deepcopy(proposal["scenario"])
    edit["steps"][0]["parameters"]["record_count"] = 7
    validated = service.validate_graph_ai(
        child["job_id"], {"proposal_digest": proposal["proposal_digest"], "scenario": edit}
    )
    assert validated["reviewed_digest"] == content_hash(edit)
    assert validated["validation"] == {"valid": True}
    assert service.graph_ai_job(child["job_id"])["application"] is None
    rejected = {"decision": "reject", "proposal_digest": proposal["proposal_digest"]}
    service.review_graph_ai(child["job_id"], rejected)
    assert (
        service.review_graph_ai(child["job_id"], rejected)["job"]["progress"]["decision"]
        == rejected
    )
    with pytest.raises(APIError):
        service.review_graph_ai(child["job_id"], acceptance(proposal))
    assert service.assistance_turn(parent["job_id"])["turn"]["status"] == "blocked"
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]


def test_parent_stop_wins_held_native_acceptance(setup, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    service, _, body = setup
    parent, child, proposal = proposed(service, body)
    entered, release = threading.Event(), threading.Event()
    original = service.graph_ai.validate

    def held(*args):
        value = original(*args)
        entered.set()
        assert release.wait(10)
        return value

    monkeypatch.setattr(service.graph_ai, "validate", held)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(service.review_graph_ai, child["job_id"], acceptance(proposal))
        assert entered.wait(10)
        try:
            service.cancel_job(parent["job_id"])
        finally:
            release.set()
        with pytest.raises((APIError, ProductStoreError)):
            future.result(timeout=10)
    with pytest.raises(ProductStoreError):
        service.product_store.get_scenario(proposal["scenario"]["id"])
    assert service.graph_ai_job(child["job_id"])["application"] is None


def test_receipt_recovery_after_process_reopen_never_calls_model(setup):
    service, access, body = setup
    parent, child, proposal = proposed(service, body)
    review = acceptance(proposal)
    receipt = service.review_graph_ai(child["job_id"], review)["application"]
    database, runs = service.product_store.path, service.store.root
    service.close()
    reopened = BlueFireService(
        project_root=ROOT, runs_dir=runs, product_db_path=database, ai_provider_access=access
    )
    try:
        assert reopened.review_graph_ai(child["job_id"], review)["application"] == receipt
        assert (
            reopened.assistance_turn(parent["job_id"])["turn"]["results"][0]["digest"]
            == receipt["digest"]
        )
        assert reopened.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
        assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]
    finally:
        reopened.close()


@pytest.mark.parametrize("mutation", ["behavior", "identity", "digest", "authority"])
def test_review_refuses_authority_identity_and_digest_substitution(setup, mutation):
    service, _, body = setup
    _, child, proposal = proposed(service, body)
    request = acceptance(proposal)
    if mutation == "behavior":
        request["scenario"]["steps"][0]["behavior_id"] = "arbitrary.shell.v1"
    elif mutation == "identity":
        request["scenario"]["id"] = "existing.operator.graph.v1"
    elif mutation == "authority":
        request["scenario"]["approval"] = True
    else:
        request["reviewed_digest"] = "sha256:" + "0" * 64
    with pytest.raises((APIError, ValueError)):
        service.review_graph_ai(child["job_id"], request)
    assert service.graph_ai_job(child["job_id"])["application"] is None


def test_native_validation_http_reports_invalid_edit_and_missing_receipt(setup):
    from tests_platform.test_api import request, running_server

    service, access, body = setup
    _, child, proposal = proposed(service, body)
    edit = copy.deepcopy(proposal["scenario"])
    edit["edges"][0]["to_step"] = "missing_target"
    with running_server(service, max_request_body=262144) as (server, _):
        status, _, raw = request(
            server,
            "POST",
            f"/api/v1/ai/graph-jobs/{child['job_id']}/validate",
            body={"proposal_digest": proposal["proposal_digest"], "scenario": edit},
        )
        assert status == 422, raw
        assert json.loads(raw)["error"]["code"] == "graph_validation_refused"
        status, _, raw = request(server, "GET", "/api/v1/ai/graph-jobs/job-" + "0" * 32)
        assert status == 404, raw
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]


def test_reference_summary_comes_from_exact_saved_graph_and_is_supplied_to_model(
    setup, monkeypatch
):
    service, access, body = setup
    saved = service.product_store.list_scenarios()[0]
    context = service.assistance_graph_context(
        {key: saved[key] for key in ("scenario_id", "version", "digest")}
    )
    body.update(selection=context["selected"], context_digest=context["context_digest"])
    original = access.post
    inputs = []

    def capture(config, **kwargs):
        wire = json.loads(kwargs["body"])
        inputs.append(json.loads(wire.get("input") or wire["messages"][1]["content"]))
        return original(config, **kwargs)

    monkeypatch.setattr(access, "post", capture)
    proposed(service, body)
    assert inputs[0]["reference_summary"]["title"] == saved["title"][:200]
    assert "Saved reference summary" in inputs[1]["objective"]
    assert context["reference_summary"]["behavior_ids"]


def test_multiline_objective_retains_exact_request_and_recovery_id(setup):
    service, access, body = setup
    body["message"] = (
        "Create a registered fixture.\r\nThen transform it.\n\tKeep the graph separate for review."
    )
    parent, child, _ = proposed(service, body)
    assert parent["request"]["submitted_request"] == body
    assert service.assistance_turn(parent["job_id"])["job"]["request"]["submitted_request"] == body
    assert child["request"]["submitted_request"]["message"] == body["message"]
    assert service.submit_assistance_turn(body)["job"]["job_id"] == parent["job_id"]
    assert access.calls == [PURPOSE, "bluefire_ai_graph_draft"]


def test_other_controls_are_refused_without_provider_access(setup):
    service, access, body = setup
    for character in ("\x00", "\x07", "\x7f", "\x85"):
        with pytest.raises(APIError):
            service.submit_assistance_turn({**body, "message": "Text" + character + "text"})
    assert access.calls == []


@pytest.mark.parametrize("kind", ["openai_responses", "chat_completions"])
def test_process_loss_after_proposal_publication_recovers_native_review_without_model(
    tmp_path, kind
):
    import subprocess
    import sys

    database, marker = tmp_path / "crash.sqlite3", tmp_path / "published.json"
    program = r"""
import json, os, sys, uuid
from pathlib import Path
from bluefire.config import AIConfig, AIProviderConfig, AutonomyLevel
from bluefire.service import BlueFireService
from tests_platform.ai_live_authorization_support import authorize_service
from tests_platform.test_graph_ai_jobs import Access
database, marker, kind = sys.argv[1:]
service = BlueFireService(project_root=Path.cwd(), runs_dir=Path(database).parent / 'runs', product_db_path=database, ai_provider_access=Access())
provider = AIProviderConfig.from_mapping({'id':'provider.graph-crash.v1','kind':kind,'model':'unit-model','endpoint':'http://127.0.0.1:8765/v1/' + ('responses' if kind == 'openai_responses' else 'chat/completions')})
service._runtime_ai_config = AIConfig(AutonomyLevel.OFF,provider.id,service.config.ai.fallback_provider,(provider,*service.config.ai.providers))
authorize_service(service, provider)
original = service.graph_ai._propose
def crash_after_publication(ctx, request):
    original(ctx, request)
    Path(marker).write_text(json.dumps({'parent_id':request['assistance_turn']['parent_job_id'],'child_id':ctx.job_id,'provider':provider.to_dict()}), encoding='utf-8')
    os._exit(77)
service.graph_ai._propose = crash_after_publication
context = service.assistance_graph_context()
body = {'submission_id':str(uuid.uuid4()),'selection':context['selected'],'context_digest':context['context_digest'],'message':'Propose a registered graph for review.','autonomy':'assist','provider_id':provider.id}
parent = service.submit_assistance_turn(body)['job']
service.job_controller.wait(parent['job_id'], timeout=15)
child = service.product_store.get_job(parent['job_id'])['progress']['children']['step-1']['job_id']
service.job_controller.wait(child, timeout=15)
raise AssertionError('Expected owned test process loss')
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(database), str(marker), kind],
        cwd=ROOT,
        capture_output=True,
        timeout=40,
        check=False,
    )
    assert process.returncode == 77, process.stderr.decode(errors="replace")
    retained = json.loads(marker.read_text(encoding="utf-8"))
    access = Access()
    reopened = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=database,
        ai_provider_access=access,
    )
    provider = AIProviderConfig.from_mapping(retained["provider"])
    reopened._runtime_ai_config = AIConfig(
        AutonomyLevel.OFF,
        provider.id,
        reopened.config.ai.fallback_provider,
        (provider, *reopened.config.ai.providers),
    )
    try:
        response = reopened.graph_ai_job(retained["child_id"])
        assert response["job"]["state"] == "interrupted" and response["review_ready"] is True
        assert (
            reopened.assistance_turn(retained["parent_id"])["turn"]["status"] == "awaiting_review"
        )
        receipt = reopened.review_graph_ai(retained["child_id"], acceptance(response["proposal"]))[
            "application"
        ]
        assert receipt["version"] == 1 and access.calls == []
        assert (
            reopened.assistance_turn(retained["parent_id"])["turn"]["results"][0]["execution_state"]
            == "not_run"
        )
        assert reopened.graph_ai_job(retained["child_id"])["review_ready"] is False
    finally:
        reopened.close()
