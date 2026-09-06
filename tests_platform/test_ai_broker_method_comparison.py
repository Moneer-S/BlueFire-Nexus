"""Fixed method-choice enrollment through actual portable broker frames."""

import copy
import json
import threading
import uuid

import pytest

from bluefire.ai_broker_contract import schema_identity
from bluefire.ai_method_comparison import OUTPUT_SCHEMA, PURPOSE
from bluefire.ai_wire import AIProviderTransportError, structured_request
from bluefire.config import AIProviderKind
from bluefire.prepared_lab_enrollment import product_config
from bluefire.runner_lifecycle import ManagedRunnerLifecycle
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_ai_broker_channel as support
from tests_platform.test_ai_wire_runtime import _envelope
from tests_platform.test_detection_evaluations import query_candidate
from tests_platform.test_method_comparison_jobs import decision, source_run

pair = support.pair


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
def test_method_job_uses_fixed_enrolled_schema(tmp_path, pair, kind, monkeypatch):
    provider, enrollment, access, transport, worker, errors = support.start(pair, kind)
    service = BlueFireService(
        config=product_config(enrollment),
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
        runner_lifecycle=ManagedRunnerLifecycle(tmp_path / "managed"),
        ai_provider_access=access,
    )

    def response(url, *, headers, body, timeout_seconds):
        assert schema_identity(body, kind) == (PURPOSE, content_hash(OUTPUT_SCHEMA))
        payload = json.loads(body)
        context = json.loads(payload.get("input") or payload["messages"][1]["content"])
        transport.requests.append(payload)
        return canonical_json_bytes(
            _envelope(
                kind,
                {
                    "option_id": context["options"][0]["option_id"],
                    "reason": "Compare the registered input-compatible method.",
                    "evidence_refs": [context["observations"][0]["evidence_id"]],
                    "limitations": ["Portable fixtures, no native evidence claim."],
                },
            )
        )

    monkeypatch.setattr(transport, "post", response)
    try:
        run_id = source_run(service, tmp_path)
        candidate_id = query_candidate(service)
        selected = service.method_comparison_context(run_id)
        body = {
            "submission_id": str(uuid.uuid4()),
            "source_binding_digest": selected["source_binding_digest"],
            "selected_step_id": "stage_collection",
            "candidate_id": candidate_id,
            "candidate_resource_digest": service.detection_candidate(candidate_id)["candidate"][
                "digest"
            ],
            "question": "Compare the same rule on the other method.",
            "source_case_role": "attack",
            "provider_id": provider.id,
            "autonomy": "assist",
        }
        job = service.submit_method_comparison(run_id, body)["job"]
        job = service.job_controller.wait(job["job_id"], timeout=15)
        assert job["state"] == "completed", job
        assert len(transport.requests) == 1 and "decision" not in job["progress"]
        accepted = service.decide_method_comparison(job["job_id"], decision(job))
        result = service.job_controller.wait(accepted["replay_job"]["job_id"], timeout=15)
        assert result["state"] == "completed" and "comparison" in result["progress"]
    finally:
        service.close()
        worker.join(3)
    assert not worker.is_alive() and errors == []


@pytest.mark.parametrize("kind", [AIProviderKind.CHAT_COMPLETIONS, AIProviderKind.OPENAI_RESPONSES])
@pytest.mark.parametrize("change", ["schema", "purpose", "tools"])
def test_schema_purpose_and_tools_substitutions_refused(pair, kind, change):
    provider, _, access, transport, worker, errors = support.start(pair, kind)
    schema = copy.deepcopy(OUTPUT_SCHEMA)
    if change == "schema":
        schema["properties"]["reason"]["maxLength"] += 1
    body = structured_request(
        provider,
        instructions="Unit context",
        input_text="{}",
        name="unregistered_method_operation" if change == "purpose" else PURPOSE,
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
