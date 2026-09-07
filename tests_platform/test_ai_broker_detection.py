"""Actual broker framing and Detection AI jobs over portable memory sockets.

Local unit run/candidate fixtures do not establish native or installed-lab proof.
"""

from __future__ import annotations

import copy
import json
import threading
import uuid

import pytest

from bluefire.ai_broker_contract import schema_identity
from bluefire.ai_detection_revision import _OUTPUT_SCHEMA
from bluefire.ai_wire import AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind, AutonomyLevel
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_ai_broker_channel as support
from tests_platform.test_ai_wire_runtime import _envelope
from tests_platform.test_detection_evaluations import observed_run, query_candidate

pair = support.pair
PURPOSE = "bluefire_detection_source_revision"
SQL = "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_normal_detection_job_crosses_enrolled_broker_and_requires_review(
    tmp_path, pair, kind, monkeypatch
):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    config = product_config(enrollment)
    assert config.ai.autonomy is AutonomyLevel.OFF
    service = BlueFireService(
        config=config,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )

    def response(url, *, headers, body, timeout_seconds):
        assert (
            url == provider.endpoint and headers["Authorization"] == "Bearer synthetic-broker-only"
        )
        assert schema_identity(body, kind) == (PURPOSE, content_hash(_OUTPUT_SCHEMA))
        payload = json.loads(body)
        context = json.loads(
            payload["input"]
            if kind is AIProviderKind.OPENAI_RESPONSES
            else payload["messages"][1]["content"]
        )
        transport.requests.append(payload)
        assert context["development_case"] is True
        return canonical_json_bytes(
            _envelope(
                kind,
                {
                    "source": SQL,
                    "reason": "Exercise the reviewed source workflow using actual unit collector records.",
                    "evidence_refs": [context["observations"][0]["evidence_id"]],
                    "limitations": [
                        "Portable unit fixture; not independent detection quality evidence."
                    ],
                },
            )
        )

    monkeypatch.setattr(transport, "post", response)
    try:
        assert (PURPOSE, content_hash(_OUTPUT_SCHEMA)) in enrollment.schemas
        candidate_id = query_candidate(service)
        run_id, records = observed_run(service, tmp_path)
        parent = service.detection_candidate(candidate_id)["candidate"]
        request = {
            "submission_id": str(uuid.uuid4()),
            "run_id": run_id,
            "parent_resource_digest": parent["digest"],
            "question": "Review this unit collector schema.",
            "case_role": "attack",
            "provider_id": provider.id,
            "autonomy": "assist",
        }
        submitted = service.submit_detection_ai_revision(candidate_id, request)["job"]
        job = service.job_controller.wait(submitted["job_id"], timeout=5)
        assert job["state"] == "completed", job
        proposal = job["progress"]["proposal"]
        assert job["request"]["autonomy"] == "assist"
        assert service._runtime_ai_config.autonomy is AutonomyLevel.OFF
        assert proposal["source"] == SQL and proposal["evidence_refs"] == [records[0].evidence_id]
        assert proposal["provider"]["provider_id"] == provider.id and len(transport.requests) == 1
        assert "application" not in job["progress"] and "decision" not in job["progress"]
        assert service.detection_candidate(candidate_id)["candidate"]["digest"] == parent["digest"]
        decision = service.decide_detection_ai_revision(
            job["job_id"],
            {
                "proposal_digest": proposal["proposal_digest"],
                "parent_resource_digest": parent["digest"],
                "decision": "accept",
                "reviewed_by": "unit-reviewer",
            },
        )
        application = service.job_controller.wait(decision["application_job"]["job_id"], timeout=5)
        assert application["state"] == "completed", application
        assert application["progress"]["application"]["development_case"] is True
        assert application["progress"]["application"]["candidate_id"] != candidate_id
        assert len(transport.requests) == 1 and worker.is_alive()
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
@pytest.mark.parametrize("change", ["schema", "purpose", "tools"])
def test_detection_enrollment_does_not_admit_modified_schema_or_arbitrary_operation(
    pair, kind, change
):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    schema = copy.deepcopy(_OUTPUT_SCHEMA)
    purpose = PURPOSE
    if change == "schema":
        schema["properties"]["source"]["maxLength"] += 1
    elif change == "purpose":
        purpose = "unregistered_detection_operation"
    value = structured_request(
        provider, instructions="Unit context", input_text="{}", name=purpose, schema=schema
    )
    if change == "tools":
        value["tools"] = [{"type": "unregistered_tool"}]
    try:
        with pytest.raises(AIProviderTransportError):
            access.post(
                provider,
                body=canonical_json_bytes(value),
                timeout_seconds=1,
                cancel_event=threading.Event(),
            )
        assert transport.requests == [] and worker.is_alive()
        assert tuple(name for name, _digest in enrollment.schemas) == (
            "bluefire_ai_graph_draft",
            "bluefire_ai_proposal",
            "bluefire_connection_check",
            "bluefire_detection_source_revision",
            "bluefire_experiment_assistance",
            "bluefire_method_comparison",
            "bluefire_run_evidence_inspection",
        )
    finally:
        access.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []
