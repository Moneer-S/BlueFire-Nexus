from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from bluefire.ai import AIProviderTransportError
from bluefire.ai_drafts import (
    AIDraftError,
    AIGraphDraftCandidate,
    AIGraphDraftRequest,
    DeterministicOfflineDraftProvider,
    OpenAIResponsesDraftProvider,
    build_ai_draft_provider,
    graph_draft_json_schema,
    normalize_ai_graph_draft,
)
from bluefire.api import APIError
from bluefire.config import load_config
from bluefire.contracts import ExecutionState, ScenarioDefinition
from bluefire.registry import load_builtin_registry
from bluefire.service import BlueFireService
from bluefire.util import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "bluefire.example.yaml"


class FakeTransport:
    def __init__(self, *responses: bytes | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _request(*, max_nodes: int = 6, max_edges: int = 8) -> AIGraphDraftRequest:
    return AIGraphDraftRequest.from_registry(
        objective="Create a synthetic fixture, transform it, and inspect its records.",
        registry=load_builtin_registry(),
        max_nodes=max_nodes,
        max_edges=max_edges,
    )


def _model_draft() -> Mapping[str, Any]:
    return {
        "schema_version": "bluefire.ai-graph-draft.v1",
        "title": "Create and transform a bounded fixture",
        "purpose": "Prepare a typed fixture and normalize it for later inspection.",
        "start": "create_fixture",
        "steps": [
            {
                "id": "create_fixture",
                "behavior_id": "sandbox.fixture.create.v1",
                "parameters": {"record_count": 4},
            },
            {
                "id": "transform_fixture",
                "behavior_id": "sandbox.fixture.transform.v1",
                "parameters": {"redact_values": True},
            },
        ],
        "edges": [
            {
                "from_step": "create_fixture",
                "outcome": "success",
                "to_step": "transform_fixture",
            }
        ],
        "rationale": "Both nodes are registered and their typed artifacts connect.",
        "assumptions": ["The operator will review this unsaved draft."],
    }


def _response(draft: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "id": "resp_draft_test_123",
            "model": "gpt-4o-mini",
            "status": "completed",
            "error": None,
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": canonical_json_bytes(draft).decode("utf-8"),
                        }
                    ],
                }
            ],
            "usage": {"input_tokens": 100, "output_tokens": 120, "total_tokens": 220},
        }
    )


def test_deterministic_offline_draft_is_stable_registered_typed_and_unsaved() -> None:
    registry = load_builtin_registry()
    request = _request()
    config = load_config(CONFIG_PATH).ai
    provider = build_ai_draft_provider(
        config,
        provider_id="deterministic-offline.v1",
    )
    assert isinstance(provider, DeterministicOfflineDraftProvider)

    first_provider_result = provider.draft(request)
    second_provider_result = provider.draft(request)
    first = normalize_ai_graph_draft(
        request=request,
        provider_result=first_provider_result,
        registry=registry,
    ).to_dict()
    second = normalize_ai_graph_draft(
        request=request,
        provider_result=second_provider_result,
        registry=registry,
    ).to_dict()

    assert first == second
    assert first["saved"] is False
    scenario = first["scenario"]
    registry.validate_scenario(ScenarioDefinition.from_mapping(scenario))
    assert 1 <= len(scenario["steps"]) <= request.max_nodes
    assert len(scenario["edges"]) <= request.max_edges
    for step in scenario["steps"]:
        behavior = registry.get_behavior(step["behavior_id"])
        assert behavior.execution_state is not ExecutionState.METADATA_ONLY
        behavior.validate_parameters(step["parameters"])
        assert not {"action_id", "command", "path", "profile", "scope", "policy"} & set(step)
    assert first["audit"]["validation"] == {
        "strict_model_schema": True,
        "registered_behaviors_only": True,
        "metadata_behaviors_excluded": True,
        "primitive_parameters_only": True,
        "scenario_contract": True,
        "registry_contract": True,
        "execution_authority_absent": True,
    }


def test_openai_responses_draft_uses_dynamic_strict_schema_and_credential_reference() -> None:
    registry = load_builtin_registry()
    request = _request()
    config = load_config(CONFIG_PATH).ai
    transport = FakeTransport(_response(_model_draft()))
    provider = build_ai_draft_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )
    assert isinstance(provider, OpenAIResponsesDraftProvider)

    provider_result = provider.draft(request)
    result = normalize_ai_graph_draft(
        request=request,
        provider_result=provider_result,
        registry=registry,
    ).to_dict()

    assert provider_result.used_fallback is False
    assert result["scenario"]["steps"][1]["inputs"] == {
        "workspace": {"from_step": "create_fixture", "artifact": "workspace"}
    }
    call = transport.calls[0]
    assert call["url"] == "https://api.openai.com/v1/responses"
    assert call["headers"]["Authorization"] == (
        "Bearer unit-test-key-value"  # pragma: allowlist secret
    )
    body = json.loads(call["body"])
    assert body["store"] is False
    assert body["tools"] == []
    assert body["tool_choice"] == "none"
    assert body["text"]["format"]["strict"] is True
    schema = body["text"]["format"]["schema"]
    assert schema == graph_draft_json_schema(request)
    model_input = json.loads(body["input"])
    for behavior in model_input["allowed_behaviors"]:
        assert not {
            "action_ids",
            "simulation_id",
            "capabilities",
            "safety_tier",
            "profile",
            "scope",
            "policy",
        } & set(behavior)
    serialized_result = json.dumps(result, sort_keys=True)
    assert "unit-test-key-value" not in serialized_result  # pragma: allowlist secret


def test_invalid_or_unregistered_model_output_falls_back_without_partial_parsing() -> None:
    request = _request()
    config = load_config(CONFIG_PATH).ai
    invalid = dict(_model_draft())
    invalid["steps"] = [
        {
            "id": "unsafe",
            "behavior_id": "research.persistence.change.v1",
            "parameters": {"command": "run anything"},
        }
    ]
    invalid["start"] = "unsafe"
    invalid["edges"] = []
    transport = FakeTransport(_response(invalid))
    provider = build_ai_draft_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
    )

    result = provider.draft(request)

    assert result.used_fallback is True
    assert result.fallback_reason == "response_invalid"
    assert result.effective_provider_id == "deterministic-offline.v1"
    assert all(step.behavior_id in request.allowed_behavior_ids for step in result.draft.steps)
    assert "command" not in json.dumps(result.draft.to_dict(), sort_keys=True)


def test_transport_retry_exhaustion_and_missing_credential_fall_back_offline() -> None:
    request = _request()
    config = load_config(CONFIG_PATH).ai
    retryable = AIProviderTransportError("temporary failure", retryable=True)
    transport = FakeTransport(retryable, retryable, retryable)
    sleeps: list[float] = []
    provider = build_ai_draft_provider(
        config,
        provider_id="openai-responses.v1",
        environ={"OPENAI_API_KEY": "unit-test-key-value"},  # pragma: allowlist secret
        transport=transport,
        sleeper=sleeps.append,
    )
    failed_over = provider.draft(request)
    assert failed_over.used_fallback is True
    assert failed_over.fallback_reason == "transport_failed"
    assert failed_over.attempts == 4
    assert sleeps == [0.25, 0.5]

    unused = FakeTransport(_response(_model_draft()))
    unavailable = build_ai_draft_provider(
        config,
        provider_id="openai-responses.v1",
        environ={},
        transport=unused,
    )
    offline = unavailable.draft(request)
    assert offline.used_fallback is True
    assert offline.fallback_reason == "credential_unavailable"
    assert unused.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda draft: draft["steps"][0]["parameters"].update(record_count="four"),
        lambda draft: draft["steps"][0]["parameters"].update(record_count=[4]),
        lambda draft: draft["steps"][0].update(action_id="sandbox.fixture.create.v1"),
        lambda draft: draft.update(profile_id="sandbox-execute.v1"),
    ],
)
def test_draft_contract_rejects_wrong_types_and_execution_authority(mutation) -> None:
    request = _request()
    draft = json.loads(json.dumps(_model_draft()))
    mutation(draft)
    with pytest.raises(AIDraftError):
        AIGraphDraftCandidate.from_mapping(draft, request)


def test_draft_contract_rejects_path_like_primitive_values() -> None:
    request = _request()
    draft = dict(_model_draft())
    draft["start"] = "marker"
    draft["steps"] = [
        {
            "id": "marker",
            "behavior_id": "sandbox.restricted.persistence-marker.v1",
            "parameters": {"label": "restricted/persistence-marker.json"},
        }
    ]
    draft["edges"] = []

    with pytest.raises(AIDraftError, match="path-like"):
        AIGraphDraftCandidate.from_mapping(draft, request)


def test_draft_request_enforces_node_edge_and_objective_bounds() -> None:
    registry = load_builtin_registry()
    with pytest.raises(AIDraftError):
        AIGraphDraftRequest.from_registry(
            objective="x" * 4_001,
            registry=registry,
        )
    with pytest.raises(AIDraftError):
        AIGraphDraftRequest.from_registry(
            objective="bounded objective",
            registry=registry,
            max_nodes=17,
        )
    with pytest.raises(AIDraftError):
        AIGraphDraftRequest.from_registry(
            objective="bounded objective",
            registry=registry,
            max_edges=33,
        )


def test_service_returns_audit_rich_unsaved_draft_without_creating_a_scenario_version(
    tmp_path: Path,
) -> None:
    service = BlueFireService(
        project_root=ROOT,
        runs_dir=tmp_path / "runs",
        product_db_path=tmp_path / "product.sqlite3",
    )
    try:
        before = service.scenario_versions()
        result = service.draft_ai_graph(
            {
                "objective": "Create a fixture and inspect its records.",
                "provider_id": "deterministic-offline.v1",
                "max_nodes": 5,
                "max_edges": 5,
            }
        )
        after = service.scenario_versions()

        assert result["saved"] is False
        assert result["draft_id"].startswith("ai-draft-")
        assert result["audit"]["provider"]["effective_provider_id"] == ("deterministic-offline.v1")
        assert result["audit"]["validation"]["registry_contract"] is True
        assert before == after

        with pytest.raises(APIError) as unknown:
            service.draft_ai_graph({"objective": "safe", "save": True})
        assert unknown.value.status == 400
        assert unknown.value.code == "ai_draft_request_invalid"

        with pytest.raises(APIError) as blank_provider:
            service.draft_ai_graph({"objective": "safe", "provider_id": " "})
        assert blank_provider.value.status == 400
        assert blank_provider.value.code == "ai_draft_provider_invalid"
    finally:
        service.close()
