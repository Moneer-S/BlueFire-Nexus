"""Local application receipts and model doubles, not cloud or paid-model evidence."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from bluefire import product_store_s3_access as records
from bluefire import s3_audit_workflow as workflow
from bluefire.ai_assistance import GRAPH, PURPOSE
from bluefire.assistance_audit_context import COLLECTED_SUMMARY_SCHEMA, context
from bluefire.product_store_errors import ProductStoreError
from bluefire.s3_access_jobs import S3AccessJobs
from bluefire.s3_audit_reviews import list_reviews
from tests_platform.test_graph_ai_jobs import setup as setup
from tests_platform.test_s3_access_jobs import NOW, stage, through_baseline
from tests_platform.test_s3_audit_workflow_jobs import ReceiptExecutor

ANSWER = "Authenticated retrieval remains incomplete; integrity and effective access are unproven."


@pytest.fixture
def collected(setup, monkeypatch):
    service, access, body = setup
    monkeypatch.setattr(workflow, "DISPATCH_RELEASED", True)
    executor = ReceiptExecutor()
    service.s3_access = S3AccessJobs(service, executor, clock=lambda: NOW)
    owner = through_baseline(service.s3_access)
    stage(service.s3_access, owner, "audit_baseline")
    review = list_reviews(service.s3_access, owner)["collections"][0]
    selected = {
        "kind": "s3_audit_review",
        "workflow_job_id": owner,
        "review_id": review["review_id"],
        "review_digest": review["review_digest"],
    }
    native = context(service, selected)
    body.update(
        selection=selected,
        context_digest=native["context_digest"],
        message="Explain the collected evidence and its limits.",
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
        output = json.dumps({"message": ANSWER, "steps": options["steps"]})
        response = {"id": "collected-audit-unit-response", "model": config.model}
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
    for name in ("environments", "readiness", "execute", "recover_original"):
        monkeypatch.setattr(
            executor, name, lambda *_args, **_kwargs: pytest.fail("Unexpected runtime contact")
        )
    return service, access, body, native, supplied, options


def finished(service, body):
    envelope = service.submit_assistance_turn(body)
    service.job_controller.wait(envelope["job"]["job_id"], timeout=15)
    return service.assistance_turn(envelope["job"]["job_id"])


@pytest.mark.parametrize("autonomy", ["assist", "auto"])
def test_collected_explanation_is_minimized_read_only_and_exactly_once(collected, autonomy):
    service, access, body, native, supplied, _options = collected
    body["autonomy"] = autonomy
    before = deepcopy(service.product_store.get_job(body["selection"]["workflow_job_id"]))
    result = finished(service, body)
    assert result["job"]["state"] == "completed"
    assert result["turn"]["message"] == ANSWER
    assert result["turn"]["plan"] == result["turn"]["results"] == []
    assert result["turn"]["active_child"] is None
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == [PURPOSE]
    assert service.product_store.get_job(body["selection"]["workflow_job_id"]) == before
    assert context(service, body["selection"]) == native
    summary = supplied[0]["reference_summary"]
    assert summary == native["reference_summary"]
    assert summary["schema_version"] == COLLECTED_SUMMARY_SCHEMA
    assert summary["collection_provenance"] == "authenticated_source_retrieval"
    assert summary["reported_delivery_state"] == "incomplete"
    assert summary["source_event_count"] == summary["collected_file_count"] == 0
    assert [(row["reader"], row["purpose"]) for row in summary["reads"]] == [
        ("probe", "primary"),
        ("legitimate", "primary"),
        ("legitimate", "health"),
    ]
    assert all(row["full_object_bytes_proven"] is False for row in summary["reads"])
    assert all(
        summary[key] is False
        for key in (
            "raw_bytes_retained",
            "log_integrity_proven",
            "independent_collection_proven",
            "effective_access_claim",
        )
    )
    assert supplied[0]["capabilities"] == []
    for field in (
        "request_id",
        "run_id",
        "audit_event_ids",
        "bucket",
        "arn:",
        "original_pair",
        "receipt",
        "discovery",
        "profile",
        "reservation_digest",
    ):
        assert field not in json.dumps(summary).replace("discovery_truncated", "truncated")


def test_collected_context_off_makes_no_model_call(collected):
    service, access, body, *_ = collected
    body["autonomy"] = "off"
    result = finished(service, body)
    assert result["turn"]["status"] == "off" and access.calls == []


def test_collected_context_rejects_model_requested_action(collected):
    service, access, body, _native, _supplied, options = collected
    options["steps"] = [
        {"capability_id": GRAPH, "detector_ref": "none", "reason": "Start another action."}
    ]
    result = finished(service, body)
    assert result["job"]["state"] == "failed" and result["turn"]["status"] == "blocked"
    assert result["turn"]["results"] == [] and result["turn"]["active_child"] is None
    assert access.calls == [PURPOSE]


def mutate_source(service, body):
    with service.product_store._connection(write=True) as connection:
        child = records.job_at(service.product_store, connection, body["selection"]["review_id"])
        retained = deepcopy(child["progress"]["collected_review"])
        retained["reservation_digest"] = "sha256:" + "f" * 64
        records.patch(connection, child, {"collected_review": retained})


@pytest.mark.parametrize("timing", ["provider_response", "final_publication"])
@pytest.mark.parametrize("changed", ["source", "provider"])
def test_collected_source_and_provider_rechecked_before_answer_publication(
    collected, monkeypatch, timing, changed
):
    service, access, body, _native, _supplied, options = collected

    def alter():
        if changed == "source":
            mutate_source(service, body)
        else:
            config = service._runtime_ai_config
            service._runtime_ai_config = replace(
                config,
                providers=tuple(
                    replace(row, model="changed-model") if row.id == body["provider_id"] else row
                    for row in config.providers
                ),
            )

    if timing == "provider_response":
        options["after"] = alter
    else:
        original = service.assistance._advance

        def changed_at_publication(parent_id, **kwargs):
            alter()
            return original(parent_id, **kwargs)

        monkeypatch.setattr(service.assistance, "_advance", changed_at_publication)
    result = finished(service, body)
    assert result["job"]["state"] == "failed"
    assert ANSWER not in json.dumps(result)
    assert result["turn"]["results"] == [] and result["turn"]["active_child"] is None
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == [PURPOSE]


def test_changed_collected_review_digest_refuses_before_model(collected):
    service, access, body, *_ = collected
    with pytest.raises(ProductStoreError):
        context(service, {**body["selection"], "review_digest": "sha256:" + "0" * 64})
    mutate_source(service, body)
    with pytest.raises(ProductStoreError):
        context(service, body["selection"])
    assert access.calls == []


def test_cancelled_collected_answer_is_not_published_or_repeated(collected, monkeypatch):
    service, access, body, *_ = collected
    original = service.assistance._advance

    def cancel_at_publication(parent_id, **kwargs):
        original(parent_id, **kwargs)
        service.cancel_job(parent_id)

    monkeypatch.setattr(service.assistance, "_advance", cancel_at_publication)
    result = finished(service, body)
    assert result["job"]["state"] == "cancelled"
    assert ANSWER not in json.dumps(result)
    assert service.submit_assistance_turn(body)["job"]["job_id"] == result["job"]["job_id"]
    assert access.calls == [PURPOSE]
