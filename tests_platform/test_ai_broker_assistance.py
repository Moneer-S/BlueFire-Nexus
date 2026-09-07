"""Assistance and its native children use the actual fixed-schema broker channel."""

import copy
import threading
import uuid
from pathlib import Path

import pytest

from bluefire.ai_assistance import OUTPUT_SCHEMA, PURPOSE
from bluefire.ai_wire import AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes
from tests_platform import test_ai_broker_channel as support
from tests_platform.test_assistance_turns import Access
from tests_platform.test_detection_ai_jobs import decision_body
from tests_platform.test_detection_evaluations import query_candidate
from tests_platform.test_method_comparison_jobs import source_run

pair = support.pair
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_connected_turn_uses_enrolled_provider_for_each_typed_capability(
    tmp_path, pair, kind, monkeypatch
):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    composite = Access()

    def response(url, *, headers, body, timeout_seconds):
        return composite.post(provider, body=body, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(transport, "post", response)
    service = BlueFireService(
        project_root=ROOT,
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )
    try:
        run_id = source_run(service, tmp_path)
        candidate_id = query_candidate(service, "size_bytes > 0")
        context = service.assistance_context(run_id, candidate_id)
        body = {
            "submission_id": str(uuid.uuid4()),
            "context_digest": context["context_digest"],
            "run_id": run_id,
            "candidate_id": candidate_id,
            "candidate_resource_digest": context["selected"]["candidate_resource_digest"],
            "message": "Improve this saved rule, evaluate it, then compare the other method.",
            "case_role": "attack",
            "provider_id": provider.id,
            "autonomy": "assist",
        }
        parent = service.submit_assistance_turn(body)["job"]
        parent = service.job_controller.wait(parent["job_id"], timeout=15)
        assert parent["state"] == "completed", parent
        detection = service.job_controller.wait(
            parent["progress"]["children"]["step-1"]["job_id"], timeout=15
        )
        assert detection["state"] == "completed", detection
        assert not detection["progress"].get("application")
        accepted = service.decide_detection_ai_revision(
            detection["job_id"], decision_body(detection)
        )
        assert (
            service.job_controller.wait(accepted["application_job"]["job_id"], timeout=15)["state"]
            == "completed"
        )
        parent = service.product_store.get_job(parent["job_id"])
        method = service.job_controller.wait(
            parent["progress"]["children"]["step-2"]["job_id"], timeout=15
        )
        assert method["state"] == "completed" and "decision" not in method["progress"]
        assert composite.calls == [
            PURPOSE,
            "bluefire_detection_source_revision",
            "bluefire_method_comparison",
        ]
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
@pytest.mark.parametrize("change", ["schema", "purpose", "tools"])
def test_assistance_broker_refuses_schema_or_authority_substitution(pair, kind, change):
    provider, _, access, transport, worker, errors = support.start(pair, kind)
    schema = copy.deepcopy(OUTPUT_SCHEMA)
    if change == "schema":
        schema["properties"]["steps"]["maxItems"] += 1
    body = structured_request(
        provider,
        instructions="Unit context",
        input_text="{}",
        name="unregistered_assistance" if change == "purpose" else PURPOSE,
        schema=schema,
    )
    if change == "tools":
        body["tools"] = [{"type": "unregistered_tool"}]
    try:
        with pytest.raises(AIProviderTransportError):
            access.post(
                provider,
                body=canonical_json_bytes(body),
                timeout_seconds=1,
                cancel_event=threading.Event(),
            )
        assert transport.requests == []
    finally:
        access.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []
