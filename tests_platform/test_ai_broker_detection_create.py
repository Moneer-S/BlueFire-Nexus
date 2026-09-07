"""Actual fixed-purpose broker frames for initial creation; portable fixtures only."""

import copy
import threading
import uuid

import pytest

from bluefire.ai_assistance import PURPOSE as PLAN_PURPOSE
from bluefire.ai_broker_contract import schema_identity
from bluefire.ai_detection_create import OUTPUT_SCHEMA, PURPOSE
from bluefire.ai_wire import AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind, AutonomyLevel
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_ai_broker_channel as support
from tests_platform.test_detection_create_jobs import Access, decision, proposal
from tests_platform.test_detection_evaluations import observed_run

pair = support.pair


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_initial_creation_uses_enrolled_purpose_and_reviewed_actual_evaluation(
    tmp_path, pair, kind, monkeypatch
):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    response_fixture = Access()
    service = BlueFireService(
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )

    def response(url, *, headers, body, timeout_seconds):
        assert (
            url == provider.endpoint and headers["Authorization"] == "Bearer synthetic-broker-only"
        )
        identity = schema_identity(body, kind)
        assert identity in enrollment.schemas
        return response_fixture.post(provider, body=body, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(transport, "post", response)
    try:
        assert service._runtime_ai_config.autonomy is AutonomyLevel.OFF
        assert (PURPOSE, content_hash(OUTPUT_SCHEMA)) in enrollment.schemas
        run_id, rows = observed_run(service, tmp_path)
        source = service.detection_creation_source({"run_id": run_id})
        chosen = {
            "kind": "run_detection",
            "run_id": run_id,
            "source_binding_digest": source["source_binding_digest"],
            "behavior_id": rows[0].behavior_id,
            "target_language": "sqlite",
            "case_role": "benign",
        }
        context = service.detection_creation_context(
            {k: v for k, v in chosen.items() if k != "kind"}
        )
        request = {
            "submission_id": str(uuid.uuid4()),
            "selection": chosen,
            "context_digest": context["context_digest"],
            "message": "Create a development rule from the supplied observed shapes.",
            "autonomy": "assist",
            "provider_id": provider.id,
        }
        parent_id, native = proposal((service, response_fixture, request))
        assert not service.product_store.list_resources("detection")
        accepted = service.review_detection_create(
            native["job"]["job_id"], decision(service, native)
        )
        done = service.job_controller.wait(accepted["application_job"]["job_id"], timeout=20)
        assert done["state"] == "completed", done
        assert service.assistance_turn(parent_id)["turn"]["status"] == "completed"
        assert response_fixture.calls == [PLAN_PURPOSE, PURPOSE]
        assert worker.is_alive()
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
@pytest.mark.parametrize("change", ["schema", "purpose", "tools"])
def test_creation_enrollment_refuses_wider_schemas_purpose_or_tools(pair, kind, change):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    schema, purpose = copy.deepcopy(OUTPUT_SCHEMA), PURPOSE
    if change == "schema":
        schema["properties"]["source"]["maxLength"] += 1
    elif change == "purpose":
        purpose = "unregistered_initial_creation"
    body = structured_request(
        provider, instructions="Unit fixture", input_text="{}", name=purpose, schema=schema
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
        assert not transport.requests and worker.is_alive()
    finally:
        access.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []
