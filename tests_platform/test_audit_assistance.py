"""Existing durable Assistant turns explain minimized audit facts without effects."""

import json
import threading
from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire.ai_assistance import GRAPH, PURPOSE
from bluefire.ai_wire import AIProviderCancelled
from bluefire.assistance_audit_context import context, selection
from bluefire.product_store_errors import ProductStoreError
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_audit_reviews import save_review
from tests_platform.test_graph_ai_jobs import setup as setup
from tests_platform.test_s3_access_jobs import NOW, SyntheticExecutor, through_baseline
from tests_platform.test_s3_audit_reviews import import_request


@pytest.fixture
def audit(setup, monkeypatch):
    service, access, body = setup
    executor = SyntheticExecutor()
    service.s3_access = S3AccessJobs(service, executor, clock=lambda: NOW)
    owner = through_baseline(service.s3_access)
    review = save_review(service.s3_access, owner, import_request(service.s3_access, owner))
    chosen = {
        "kind": "s3_audit_review",
        "workflow_job_id": owner,
        "review_id": review["review_id"],
        "review_digest": review["review_digest"],
    }
    native = context(service, chosen)
    body.update(
        selection=chosen,
        context_digest=native["context_digest"],
        message="Explain what this review establishes and what remains unknown.",
    )
    supplied = []
    options = {"steps": [], "after": lambda: None}

    def post(config, *, body, timeout_seconds, cancel_event=None):
        wire = json.loads(body)
        purpose = (wire.get("text", {}).get("format") or wire["response_format"]["json_schema"])[
            "name"
        ]
        assert purpose == PURPOSE
        access.calls.append(purpose)
        supplied.append(json.loads(wire.get("input") or wire["messages"][1]["content"]))
        access.entered.set()
        if access.hold is not None:
            assert access.hold.wait(10)
        if cancel_event is not None and cancel_event.is_set():
            raise AIProviderCancelled()
        options["after"]()
        output = json.dumps(
            {
                "message": "One imported record matches the synthetic read. Collection and effective access remain unproven.",
                "steps": options["steps"],
            }
        )
        response = {"id": "audit-unit-response", "model": config.model}
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
    for method in ("environments", "readiness", "execute"):
        monkeypatch.setattr(
            executor,
            method,
            lambda *_args, **_kwargs: pytest.fail("Unexpected cloud/runtime contact"),
        )
    return service, access, body, native, supplied, options


def finished(service, body):
    envelope = service.submit_assistance_turn(body)
    service.job_controller.wait(envelope["job"]["job_id"], timeout=15)
    return service.assistance_turn(envelope["job"]["job_id"])


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_saved_audit_uses_one_existing_turn_without_dispatch(audit, autonomy):
    service, access, body, native, supplied, _ = audit
    body["autonomy"] = autonomy
    before = deepcopy(service.product_store.get_job(body["selection"]["workflow_job_id"]))
    result = finished(service, body)
    assert result["job"]["state"] == "completed", result
    assert result["turn"]["status"] == "completed"
    assert result["turn"]["can_start_new_turn"] is True
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert result["turn"]["selected"] == native["selected"]
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == [PURPOSE]
    assert service.product_store.get_job(body["selection"]["workflow_job_id"]) == before
    model = supplied[0]
    assert model["capabilities"] == []
    assert model["reference_summary"]["runner_source"] == "synthetic"
    assert model["reference_summary"]["collection_provenance"] == "operator_import"
    assert model["reference_summary"]["independent_collection_proven"] is False
    assert model["reference_summary"]["reads"][0]["status"] == "matched"
    for field in (
        "requestID",
        "awsRegion",
        "bucketName",
        "principalId",
        "Records",
        "raw_sha256",
        "audit_event_ids",
    ):
        assert field not in json.dumps(model)


def test_off_retains_context_without_provider_call(audit):
    service, access, body, *_ = audit
    body["autonomy"] = "off"
    result = finished(service, body)
    assert result["turn"]["status"] == "off" and not access.calls


def test_model_cannot_dispatch_another_capability(audit):
    service, access, body, _, _, options = audit
    options["steps"] = [
        {"capability_id": GRAPH, "detector_ref": "none", "reason": "Create another graph."}
    ]
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["turn"]["results"] == [] and result["turn"]["active_child"] is None
    assert access.calls == [PURPOSE]


@pytest.mark.parametrize("change", ["source", "provider"])
def test_source_and_provider_rechecked_before_retaining_response(audit, change):
    service, _, body, _, _, options = audit

    def alter():
        if change == "source":
            with service.product_store._connection(write=True) as connection:
                connection.execute(
                    "UPDATE jobs SET state = 'failed' WHERE job_id = ?",
                    (body["selection"]["review_id"],),
                )
        else:
            config = service._runtime_ai_config
            service._runtime_ai_config = replace(
                config,
                providers=tuple(
                    (
                        replace(provider, model="changed-model")
                        if provider.id == body["provider_id"]
                        else provider
                    )
                    for provider in config.providers
                ),
            )

    options["after"] = alter
    result = finished(service, body)
    assert result["job"]["state"] == "failed"
    assert "One imported record" not in result["turn"]["message"]
    assert result["turn"]["results"] == []


@pytest.mark.parametrize("change", ["source", "provider"])
def test_final_validation_failure_never_publishes_audit_answer(audit, monkeypatch, change):
    service, access, body, *_ = audit
    assistance = service.assistance
    advance = assistance._advance
    observed = []

    def changed_at_final_check(parent_id, **kwargs):
        observed.append(deepcopy(service.product_store.get_job(parent_id)["progress"]))
        if change == "source":
            with service.product_store._connection(write=True) as connection:
                connection.execute(
                    "UPDATE jobs SET state = 'failed' WHERE job_id = ?",
                    (body["selection"]["review_id"],),
                )
        else:
            config = service._runtime_ai_config
            service._runtime_ai_config = replace(
                config,
                providers=tuple(
                    (
                        replace(provider, model="changed-at-final-check")
                        if provider.id == body["provider_id"]
                        else provider
                    )
                    for provider in config.providers
                ),
            )
        return advance(parent_id, **kwargs)

    monkeypatch.setattr(assistance, "_advance", changed_at_final_check)
    result = finished(service, body)
    assert result["job"]["state"] == "failed"
    assert result["turn"]["status"] == "blocked"
    assert result["turn"]["results"] == [] and result["turn"]["active_child"] is None
    assert "One imported record" not in result["turn"]["message"]
    assert all("One imported record" not in json.dumps(progress) for progress in observed)
    assert "One imported record" not in json.dumps(result["job"]["progress"])
    retry = service.submit_assistance_turn(body)
    assert retry["job"]["job_id"] == result["job"]["job_id"]
    assert retry["turn"]["status"] == "blocked" and access.calls == [PURPOSE]


def test_audit_selection_requires_exact_ids_and_no_untrusted_fields(audit):
    service, _, body, *_ = audit
    chosen = body["selection"]
    for change in (
        {"review_id": "job-" + "f" * 32},
        {"workflow_job_id": "job-" + "e" * 32},
        {"review_digest": "sha256:" + "0" * 64},
    ):
        with pytest.raises(ProductStoreError):
            context(service, {**chosen, **change})
    with pytest.raises(ProductStoreError):
        selection({**chosen, "instructions": "untrusted"})


def test_cancellation_at_final_validation_does_not_publish_audit_answer(audit, monkeypatch):
    service, access, body, *_ = audit
    advance = service.assistance._advance

    def cancelled_after_validation(parent_id, **kwargs):
        advance(parent_id, **kwargs)
        service.cancel_job(parent_id)

    monkeypatch.setattr(service.assistance, "_advance", cancelled_after_validation)
    result = finished(service, body)
    assert result["job"]["state"] == "cancelled"
    assert result["turn"]["status"] == "cancelled"
    assert "One imported record" not in result["turn"]["message"]
    assert "One imported record" not in json.dumps(result["job"]["progress"])
    assert access.calls == [PURPOSE]


def test_cancellation_and_retry_do_not_repeat_analysis(audit):
    service, access, body, *_ = audit
    access.hold = threading.Event()
    result = service.submit_assistance_turn(body)
    assert access.entered.wait(10)
    service.cancel_job(result["job"]["job_id"])
    access.hold.set()
    service.job_controller.wait(result["job"]["job_id"], timeout=15)
    retained = service.submit_assistance_turn(body)
    assert retained["turn"]["status"] == "cancelled" and access.calls == [PURPOSE]
